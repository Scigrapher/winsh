// Package keys loads and uses SSH keys for winsh's built-in client: public
// keys from an agent (Pageant or ssh-agent) or from files in ~/.ssh, plus the
// verification side needed to check a server's host key.
//
// Private keys are only ever read from unencrypted files.  Encrypted key files
// are refused with a message pointing at the agent, because the safe way to
// protect a key is to keep it in an agent rather than to teach this client a
// passphrase UI, a password-based KDF, and a memory-zeroing discipline it
// cannot guarantee once the key has reached the Go heap.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"winsh/internal/agent"
)

// PubKey is a parsed public key.
type PubKey struct {
	Algo    string
	Blob    []byte
	Comment string
}

// Fingerprint returns the OpenSSH-style SHA256 fingerprint.
func (k PubKey) Fingerprint() string {
	sum := sha256.Sum256(k.Blob)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

// Signer produces a signature for the SSH userauth exchange.
type Signer interface {
	Pub() PubKey
	// Sign returns an SSH signature blob: string(algorithm) || string(sig).
	// Sign returns an SSH signature blob: string(algorithm) || string(sig).
	// algo names the signature algorithm to produce, as listed by
	// AllowedAlgos; the empty string means "whichever you prefer".
	Sign(algo string, msg []byte) ([]byte, error)
	// Source describes where the key came from, for diagnostics.
	Source() string
	// AllowedAlgos lists the signature algorithms this key can produce, in
	// preference order.
	AllowedAlgos() []string
}

// ---------- agent-backed signers ----------

// AgentSigner signs through an agent such as Pageant, so winsh never sees the
// private key.
type AgentSigner struct {
	Client   *agent.Client
	Identity agent.Identity
}

// Pub implements Signer.
func (s *AgentSigner) Pub() PubKey {
	return PubKey{Algo: s.Identity.Algo, Blob: s.Identity.Blob, Comment: s.Identity.Comment}
}

// Source implements Signer.
func (s *AgentSigner) Source() string {
	return "agent:" + s.Client.Name() + " (" + s.Identity.Comment + ")"
}

// AllowedAlgos implements Signer.
func (s *AgentSigner) AllowedAlgos() []string { return algosFor(s.Identity.Algo) }

// Sign implements Signer.
// Sign implements Signer by asking the agent to do it, so winsh never sees the
// private key.
func (s *AgentSigner) Sign(algo string, msg []byte) ([]byte, error) {
	return s.Client.SignWithAlgo(s.Identity.Blob, msg, algo)
}

// FromAgent lists an agent's usable keys as signers.
func FromAgent(c *agent.Client) ([]Signer, error) {
	ids, err := c.Identities()
	if err != nil {
		return nil, err
	}
	var out []Signer
	for _, id := range ids {
		if !supportedAlgo(id.Algo) {
			continue
		}
		out = append(out, &AgentSigner{Client: c, Identity: id})
	}
	return out, nil
}

func supportedAlgo(a string) bool {
	switch a {
	case "ssh-ed25519", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	}
	return false
}

// algosFor expands a key type into the signature algorithms it may offer.
func algosFor(a string) []string {
	switch a {
	case "ssh-rsa":
		return []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
	default:
		return []string{a}
	}
}

// ---------- file-backed signers ----------

// FileSigner holds an unencrypted private key loaded from disk.
type FileSigner struct {
	Key    crypto.PrivateKey
	Public PubKey
	Origin string
}

// Pub implements Signer.
func (s *FileSigner) Pub() PubKey { return s.Public }

// Source implements Signer.
func (s *FileSigner) Source() string { return "file:" + s.Origin }

// AllowedAlgos implements Signer.
func (s *FileSigner) AllowedAlgos() []string { return algosFor(s.Public.Algo) }

// Sign implements Signer.
// SignatureAlgo reports the algorithm named inside an SSH signature blob, as
// produced by Sign. A caller that asked for one algorithm and got another has
// a bug that looks exactly like a server that dislikes the key, so it is worth
// being able to ask.
func SignatureAlgo(sig []byte) string {
	if len(sig) < 4 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(sig[:4]))
	if n < 1 || n > 64 || 4+n > len(sig) {
		return ""
	}
	return string(sig[4 : 4+n])
}

func (s *FileSigner) Sign(algo string, msg []byte) ([]byte, error) {
	switch key := s.Key.(type) {
	case ed25519.PrivateKey:
		return wrapSig("ssh-ed25519", ed25519.Sign(key, msg)), nil
	case *rsa.PrivateKey:
		// Honour the algorithm the caller asked for. Modern servers reject
		// ssh-rsa (SHA-1) outright, so the caller normally names an RSA SHA-2
		// variant; the fallback keeps single-argument callers working.
		chosen := algo
		switch chosen {
		case "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa":
		default:
			if algs := s.AllowedAlgos(); len(algs) > 0 {
				chosen = algs[0]
			} else {
				chosen = "rsa-sha2-256"
			}
		}
		algoName, hash, digest := rsaDigest(chosen, msg)
		sig, err := rsa.SignPKCS1v15(nil, key, hash, digest)
		if err != nil {
			return nil, fmt.Errorf("keys: rsa sign: %w", err)
		}
		return wrapSig(algoName, sig), nil
	case *ecdsa.PrivateKey:
		digest, err := ecdsaDigest(key.Curve, msg)
		if err != nil {
			return nil, err
		}
		r, sv, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, fmt.Errorf("keys: ecdsa sign: %w", err)
		}
		var sig []byte
		sig = appendMPInt(sig, r)
		sig = appendMPInt(sig, sv)
		return wrapSig(s.Public.Algo, sig), nil
	}
	return nil, fmt.Errorf("keys: unsupported private key type %T", s.Key)
}

func rsaDigest(algo string, msg []byte) (string, crypto.Hash, []byte) {
	switch algo {
	case "rsa-sha2-512":
		sum := sha512.Sum512(msg)
		return "rsa-sha2-512", crypto.SHA512, sum[:]
	case "ssh-rsa":
		sum := sha1.Sum(msg)
		return "ssh-rsa", crypto.SHA1, sum[:]
	default:
		sum := sha256.Sum256(msg)
		return "rsa-sha2-256", crypto.SHA256, sum[:]
	}
}

func ecdsaDigest(curve elliptic.Curve, msg []byte) ([]byte, error) {
	switch curve {
	case elliptic.P256():
		sum := sha256.Sum256(msg)
		return sum[:], nil
	case elliptic.P384():
		sum := sha512.Sum384(msg)
		return sum[:], nil
	case elliptic.P521():
		sum := sha512.Sum512(msg)
		return sum[:], nil
	}
	return nil, fmt.Errorf("keys: unsupported curve %v", curve)
}

// ---------- host-key verification ----------

// ErrHostKeyRejected reports a host that failed verification.
var ErrHostKeyRejected = errors.New("keys: host key verification failed")

// ErrSHA1HostKeys is returned for legacy ssh-rsa host keys.  Requiring SHA-2
// signatures by default is a deliberate security choice: a terminal session
// that silently trusts a broken hash is an attacker's dream.
var ErrSHA1HostKeys = errors.New("keys: server offered a SHA-1 (ssh-rsa) host key, which winsh refuses by default")

// VerifyHostKey checks an SSH signature blob against a host key.
func VerifyHostKey(pub PubKey, msg, sigBlob []byte, allowSHA1 bool) error {
	r := &strReader{b: sigBlob}
	algoBytes, ok := r.str()
	if !ok {
		return errors.New("keys: malformed signature blob")
	}
	algo := string(algoBytes)
	body, ok := r.str()
	if !ok {
		return errors.New("keys: malformed signature body")
	}
	switch algo {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		if pub.Algo != algo {
			return fmt.Errorf("%w: algorithm mismatch %s vs %s", ErrHostKeyRejected, algo, pub.Algo)
		}
		key, err := ed25519PublicKey(pub.Blob)
		if err != nil {
			return err
		}
		if len(body) != ed25519.SignatureSize || !ed25519.Verify(key, msg, body) {
			return fmt.Errorf("%w: ed25519", ErrHostKeyRejected)
		}
		return nil
	case "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa":
		if algo == "ssh-rsa" && !allowSHA1 {
			return ErrSHA1HostKeys
		}
		if pub.Algo != "ssh-rsa" && pub.Algo != algo {
			return fmt.Errorf("%w: algorithm mismatch %s vs %s", ErrHostKeyRejected, algo, pub.Algo)
		}
		key, err := rsaPublicKey(pub.Blob)
		if err != nil {
			return err
		}
		_, hash, digest := rsaDigest(algo, msg)
		if err := rsa.VerifyPKCS1v15(key, hash, digest, body); err != nil {
			return fmt.Errorf("%w: rsa: %v", ErrHostKeyRejected, err)
		}
		return nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ecdsa-sha2-nistp256@openssh.com":
		if pub.Algo != algo {
			return fmt.Errorf("%w: algorithm mismatch %s vs %s", ErrHostKeyRejected, algo, pub.Algo)
		}
		key, curve, err := ecdsaPublicKey(pub.Blob)
		if err != nil {
			return err
		}
		digest, err := ecdsaDigest(curve, msg)
		if err != nil {
			return err
		}
		sr := &strReader{b: body}
		rb, ok := sr.mpint()
		if !ok {
			return errors.New("keys: malformed ecdsa signature")
		}
		sb, ok := sr.mpint()
		if !ok {
			return errors.New("keys: malformed ecdsa signature")
		}
		if !ecdsa.Verify(key, digest, rb, sb) {
			return fmt.Errorf("%w: ecdsa", ErrHostKeyRejected)
		}
		return nil
	}
	return fmt.Errorf("%w: unsupported signature algorithm %s", ErrHostKeyRejected, algo)
}

// ---------- public blob parsing ----------

func ed25519PublicKey(blob []byte) (ed25519.PublicKey, error) {
	r := &strReader{b: blob}
	if _, ok := r.str(); !ok {
		return nil, errors.New("keys: malformed ed25519 blob")
	}
	k, ok := r.str()
	if !ok || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("keys: malformed ed25519 public key")
	}
	return ed25519.PublicKey(k), nil
}

func rsaPublicKey(blob []byte) (*rsa.PublicKey, error) {
	r := &strReader{b: blob}
	if _, ok := r.str(); !ok {
		return nil, errors.New("keys: malformed rsa blob")
	}
	e, ok := r.mpint()
	if !ok {
		return nil, errors.New("keys: malformed rsa exponent")
	}
	n, ok := r.mpint()
	if !ok || n.Sign() <= 0 {
		return nil, errors.New("keys: malformed rsa modulus")
	}
	if e.BitLen() > 31 {
		return nil, errors.New("keys: absurd rsa exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func ecdsaPublicKey(blob []byte) (*ecdsa.PublicKey, elliptic.Curve, error) {
	r := &strReader{b: blob}
	if _, ok := r.str(); !ok {
		return nil, nil, errors.New("keys: malformed ecdsa blob")
	}
	curveName, ok := r.str()
	if !ok {
		return nil, nil, errors.New("keys: malformed ecdsa curve")
	}
	var curve elliptic.Curve
	switch string(curveName) {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf("keys: unsupported curve %q", curveName)
	}
	point, ok := r.str()
	if !ok {
		return nil, nil, errors.New("keys: malformed ecdsa point")
	}
	x, y := elliptic.Unmarshal(curve, point)
	if x == nil {
		return nil, nil, errors.New("keys: malformed ecdsa point encoding")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, curve, nil
}

// ParsePublicBlob decodes a public-key blob.
func ParsePublicBlob(blob []byte) (PubKey, error) {
	algo, err := agent.AlgoOf(blob)
	if err != nil {
		return PubKey{}, err
	}
	if !supportedAlgo(algo) {
		return PubKey{}, fmt.Errorf("keys: unsupported key algorithm %q", algo)
	}
	return PubKey{Algo: algo, Blob: append([]byte(nil), blob...)}, nil
}

// ---------- private key files ----------

// DefaultPaths returns the conventional key files under a home directory.
func DefaultPaths(home string) []string {
	if home == "" {
		return nil
	}
	names := []string{"id_ed25519", "id_ecdsa", "id_rsa", "identity"}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(home, ".ssh", n))
	}
	return out
}

// LoadFiles loads unencrypted private keys, skipping unusable ones and
// explaining why in notes.
func LoadFiles(paths []string) (signers []Signer, notes []string) {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s, err := parsePrivateKey(data, p)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", filepath.Base(p), err))
			continue
		}
		signers = append(signers, s)
	}
	return signers, notes
}

const opensshMagic = "openssh-key-v1\x00"

func parsePrivateKey(data []byte, path string) (Signer, error) {
	text := string(data)
	switch {
	case strings.Contains(text, "BEGIN OPENSSH PRIVATE KEY"):
		return parseOpenSSHFormat(data, path)
	case strings.Contains(text, "BEGIN RSA PRIVATE KEY"),
		strings.Contains(text, "BEGIN PRIVATE KEY"),
		strings.Contains(text, "BEGIN EC PRIVATE KEY"):
		return parsePEM(data, path)
	case strings.Contains(text, "PPK-VERSION"):
		return nil, errors.New("PuTTY .ppk files are not supported; load the key into Pageant instead")
	}
	return nil, errors.New("not a recognised private key file")
}

func parsePEM(data []byte, path string) (Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("malformed PEM")
	}
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, errors.New("passphrase-protected key: load it into Pageant or ssh-agent instead")
	}
	der := block.Bytes
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return &FileSigner{
			Key:    key,
			Public: PubKey{Algo: "ssh-rsa", Blob: buildRSABlob(key.N, key.E), Comment: filepath.Base(path)},
			Origin: path,
		}, nil
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := parsed.(type) {
		case *rsa.PrivateKey:
			return &FileSigner{
				Key:    key,
				Public: PubKey{Algo: "ssh-rsa", Blob: buildRSABlob(key.N, key.E), Comment: filepath.Base(path)},
				Origin: path,
			}, nil
		case ed25519.PrivateKey:
			pub, ok := key.Public().(ed25519.PublicKey)
			if !ok {
				return nil, errors.New("keys: bad ed25519 public part")
			}
			return &FileSigner{
				Key:    key,
				Public: PubKey{Algo: "ssh-ed25519", Blob: buildEd25519Blob(pub), Comment: filepath.Base(path)},
				Origin: path,
			}, nil
		case *ecdsa.PrivateKey:
			algo, blob, err := ecdsaPublicFromPrivate(key)
			if err != nil {
				return nil, err
			}
			return &FileSigner{Key: key, Public: PubKey{Algo: algo, Blob: blob, Comment: filepath.Base(path)}, Origin: path}, nil
		}
		return nil, fmt.Errorf("keys: unsupported PKCS#8 key type %T", parsed)
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		algo, blob, err := ecdsaPublicFromPrivate(key)
		if err != nil {
			return nil, err
		}
		return &FileSigner{Key: key, Public: PubKey{Algo: algo, Blob: blob, Comment: filepath.Base(path)}, Origin: path}, nil
	}
	return nil, errors.New("keys: could not parse private key DER")
}

func ecdsaPublicFromPrivate(key *ecdsa.PrivateKey) (string, []byte, error) {
	blob, err := ecdsaBlobFor(key.Curve, key.X, key.Y)
	if err != nil {
		return "", nil, err
	}
	return "ecdsa-sha2-" + curveSuffix(key.Curve), blob, nil
}

func curveSuffix(c elliptic.Curve) string {
	switch c {
	case elliptic.P384():
		return "nistp384"
	case elliptic.P521():
		return "nistp521"
	}
	return "nistp256"
}

func ecdsaBlobFor(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {
	switch curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return nil, errors.New("keys: unsupported curve")
	}
	suffix := curveSuffix(curve)
	var blob []byte
	blob = appendString(blob, []byte("ecdsa-sha2-"+suffix))
	blob = appendString(blob, []byte(suffix))
	blob = appendString(blob, elliptic.Marshal(curve, x, y))
	return blob, nil
}

func parseOpenSSHFormat(data []byte, path string) (Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("keys: malformed OPENSSH private key PEM")
	}
	b := block.Bytes
	if len(b) < len(opensshMagic) || string(b[:len(opensshMagic)]) != opensshMagic {
		return nil, errors.New("keys: not an openssh-key-v1 file")
	}
	r := &strReader{b: b[len(opensshMagic):]}
	cipherName, ok := r.str()
	if !ok {
		return nil, errors.New("keys: truncated openssh key")
	}
	kdfName, ok := r.str()
	if !ok {
		return nil, errors.New("keys: truncated openssh key")
	}
	if _, ok := r.str(); !ok { // kdf options
		return nil, errors.New("keys: truncated openssh key")
	}
	if string(cipherName) != "none" || string(kdfName) != "none" {
		return nil, errors.New("passphrase-protected key: load it into Pageant or ssh-agent instead")
	}
	nkeys, ok := r.uint32()
	if !ok || nkeys == 0 || nkeys > 64 {
		return nil, errors.New("keys: bad key count")
	}
	if _, ok := r.str(); !ok { // public key
		return nil, errors.New("keys: truncated openssh key")
	}
	privBlob, ok := r.str()
	if !ok {
		return nil, errors.New("keys: truncated openssh key")
	}
	pr := &strReader{b: privBlob}
	check1, ok := pr.uint32()
	if !ok {
		return nil, errors.New("keys: truncated private section")
	}
	check2, ok := pr.uint32()
	if !ok || check1 != check2 {
		return nil, errors.New("keys: private section check mismatch")
	}
	kt, ok := pr.str()
	if !ok {
		return nil, errors.New("keys: truncated private section")
	}
	switch string(kt) {
	case "ssh-ed25519":
		pub, ok := pr.str()
		if !ok {
			return nil, errors.New("keys: truncated ed25519 key")
		}
		priv, ok := pr.str()
		if !ok || len(priv) != ed25519.PrivateKeySize {
			return nil, errors.New("keys: bad ed25519 key length")
		}
		return &FileSigner{
			Key:    ed25519.PrivateKey(append([]byte(nil), priv...)),
			Public: PubKey{Algo: "ssh-ed25519", Blob: buildEd25519Blob(append([]byte(nil), pub...)), Comment: filepath.Base(path)},
			Origin: path,
		}, nil
	case "ssh-rsa":
		n, ok := pr.mpint()
		if !ok {
			return nil, errors.New("keys: truncated rsa key")
		}
		e, ok := pr.mpint()
		if !ok {
			return nil, errors.New("keys: truncated rsa key")
		}
		d, ok := pr.mpint()
		if !ok {
			return nil, errors.New("keys: truncated rsa key")
		}
		if _, ok := pr.mpint(); !ok { // iqu, recomputed by Go
			return nil, errors.New("keys: truncated rsa key")
		}
		p, ok := pr.mpint()
		if !ok {
			return nil, errors.New("keys: truncated rsa key")
		}
		q, ok := pr.mpint()
		if !ok {
			return nil, errors.New("keys: truncated rsa key")
		}
		if e.BitLen() > 31 {
			return nil, errors.New("keys: absurd rsa exponent")
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("keys: rsa key failed validation: %w", err)
		}
		return &FileSigner{
			Key:    key,
			Public: PubKey{Algo: "ssh-rsa", Blob: buildRSABlob(n, int(e.Int64())), Comment: filepath.Base(path)},
			Origin: path,
		}, nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		if _, ok := pr.str(); !ok { // curve name
			return nil, errors.New("keys: truncated ecdsa key")
		}
		if _, ok := pr.str(); !ok { // point
			return nil, errors.New("keys: truncated ecdsa key")
		}
		dBytes, ok := pr.str()
		if !ok {
			return nil, errors.New("keys: truncated ecdsa key")
		}
		var curve elliptic.Curve
		switch string(kt) {
		case "ecdsa-sha2-nistp384":
			curve = elliptic.P384()
		case "ecdsa-sha2-nistp521":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		key := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(dBytes)}
		key.PublicKey.Curve = curve
		key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(dBytes)
		if key.PublicKey.X == nil {
			return nil, errors.New("keys: bad ecdsa private scalar")
		}
		blob, err := ecdsaBlobFor(curve, key.PublicKey.X, key.PublicKey.Y)
		if err != nil {
			return nil, err
		}
		return &FileSigner{Key: key, Public: PubKey{Algo: string(kt), Blob: blob, Comment: filepath.Base(path)}, Origin: path}, nil
	}
	return nil, fmt.Errorf("keys: unsupported openssh key type %q", kt)
}

// ---------- wire helpers ----------

func buildEd25519Blob(pub ed25519.PublicKey) []byte {
	var blob []byte
	blob = appendString(blob, []byte("ssh-ed25519"))
	blob = appendString(blob, pub)
	return blob
}

func buildRSABlob(n *big.Int, e int) []byte {
	var blob []byte
	blob = appendString(blob, []byte("ssh-rsa"))
	blob = appendMPInt(blob, big.NewInt(int64(e)))
	blob = appendMPInt(blob, n)
	return blob
}

func wrapSig(algo string, sig []byte) []byte {
	var out []byte
	out = appendString(out, []byte(algo))
	out = appendString(out, sig)
	return out
}

// appendString writes an SSH string.
func appendString(dst, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	dst = append(dst, l[:]...)
	return append(dst, s...)
}

// appendMPInt writes an SSH mpint: two's complement, minimally encoded.
func appendMPInt(dst []byte, v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return appendString(dst, nil)
	}
	if v.Sign() < 0 {
		// Negative mpints are not valid for the fields winsh encodes.
		return appendString(dst, nil)
	}
	b := v.Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return appendString(dst, b)
}

// strReader reads SSH strings, mpints and uint32s with bounds checks, so a
// hostile file or agent reply can never cause an out-of-range read.
type strReader struct {
	b   []byte
	off int
}

func (r *strReader) uint32() (uint32, bool) {
	if r.off < 0 || r.off+4 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, true
}

func (r *strReader) str() ([]byte, bool) {
	n, ok := r.uint32()
	if !ok || uint64(n) > uint64(len(r.b)-r.off) {
		return nil, false
	}
	out := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return out, true
}

func (r *strReader) mpint() (*big.Int, bool) {
	b, ok := r.str()
	if !ok {
		return nil, false
	}
	if len(b) > 512 {
		return nil, false
	}
	if len(b) == 0 {
		return new(big.Int), true
	}
	if b[0]&0x80 != 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}
