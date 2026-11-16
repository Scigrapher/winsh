package ssh

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"winsh/internal/keys"
)

// Algorithm preferences.  Everything listed here is a deliberate security
// choice: curve25519 for key exchange, AES-CTR for confidentiality,
// HMAC-SHA2 for integrity, and SHA-2 or Ed25519 host keys.  There is no CBC
// mode, no RC4, no MD5, and no SHA-1 MAC; a server that can only offer those
// is refused rather than silently downgraded.
//
// curve25519-sha256 (and its libssh predecessor) has been supported by
// OpenSSH since 6.0 and by every other server winsh targets, so narrowing the
// key-exchange list to it costs nothing in practice and removes a large amount
// of Diffie-Hellman and ECDSA code from the trusted computing base.
var (
	kexAlgorithms     = []string{"curve25519-sha256", "curve25519-sha256@libssh.org"}
	hostKeyAlgorithms = []string{"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256"}
	cipherAlgorithms  = []string{"aes256-ctr", "aes128-ctr"}
	macAlgorithms     = []string{
		"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512", "hmac-sha2-256",
	}

	// RFC 9142 and RFC 8308 capability markers.  They are advertised by
	// appending them to kex_algorithms, and they are never selected as the key
	// exchange algorithm itself, so they stay out of kexAlgorithms above.
	extInfoClient = "ext-info-c"
	strictClient  = "kex-strict-c-v00@openssh.com"
	strictServer  = "kex-strict-s-v00@openssh.com"
)

// kex performs the initial key exchange and installs the resulting keys.
func (c *Client) kex() error {
	cookie := make([]byte, 16)
	if err := randomBytes(cookie); err != nil {
		return err
	}
	var o builder
	o.byte_(msgKexInit)
	o.raw(cookie)
	o.strs(append(append([]string(nil), kexAlgorithms...), extInfoClient, strictClient))
	o.strs(hostKeyAlgorithms)
	o.strs(cipherAlgorithms)
	o.strs(cipherAlgorithms)
	o.strs(macAlgorithms)
	o.strs(macAlgorithms)
	o.strs([]string{"none"})
	o.strs([]string{"none"})
	o.strs(nil)
	o.strs(nil)
	o.boolv(false)
	o.uint32(0)
	clientKexInit := o.b

	if err := c.writePacket(clientKexInit); err != nil {
		return err
	}
	serverKexInit, err := c.expect(msgKexInit)
	if err != nil {
		return err
	}

	// The payload begins with the message type, which expect() deliberately
	// leaves in place so that callers can match on it.
	m := &msg{b: serverKexInit[1:]}
	if _, ok := m.fixed(16); !ok { // cookie: byte[16], not a string
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, len(serverKexInit)))
	}
	serverKex, ok := m.nameList()
	if !ok {
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, len(serverKexInit)))
	}
	serverHostKeys, ok := m.nameList()
	if !ok {
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, len(serverKexInit)))
	}
	serverCiphersC2S, ok := m.nameList()
	if !ok {
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, 40))
	}
	serverCiphersS2C, ok := m.nameList()
	if !ok {
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, 40))
	}
	serverMacsC2S, ok := m.nameList()
	if !ok {
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, 40))
	}
	serverMacsS2C, ok := m.nameList()
	if !ok {
		return fmt.Errorf("%w (server KEXINIT begins %s)", m.err, hexDump(serverKexInit, 40))
	}

	// RFC 9142 strict key exchange is offered by appending the markers to the
	// kex_algorithms list; the peer accepts by doing the same.  It matters here
	// because it decides whether the MAC packet counter restarts at keying.
	c.kexStrict = containsString(serverKex, strictServer)
	if c.kexStrict {
		c.log("peer supports RFC 9142 strict key exchange")
	}

	_, err = c.negotiate(serverKex, serverHostKeys, serverCiphersC2S, serverCiphersS2C, serverMacsC2S, serverMacsS2C)
	if err != nil {
		return err
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ssh: x25519 keygen: %w", err)
	}
	qc := priv.PublicKey().Bytes()

	var init builder
	init.byte_(msgKexEcdhInit)
	init.str(qc)
	if err := c.writePacket(init.b); err != nil {
		return err
	}
	reply, err := c.expect(msgKexEcdhReply)
	if err != nil {
		return err
	}
	r := &msg{b: reply[1:]}
	hostKeyBlob, ok := r.str()
	if !ok {
		return r.err
	}
	qs, ok := r.str()
	if !ok {
		return r.err
	}
	sig, ok := r.str()
	if !ok {
		return r.err
	}
	if len(qs) != 32 {
		return errors.New("ssh: bad X25519 public value")
	}
	peer, err := ecdh.X25519().NewPublicKey(qs)
	if err != nil {
		return fmt.Errorf("ssh: peer x25519 key: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return fmt.Errorf("ssh: x25519 ecdh: %w", err)
	}

	// The exchange hash binds both KEXINIT payloads, the host key, both public
	// values, and the shared secret.  It becomes the session id and is the
	// exact byte string the host key must sign.
	// K, the shared secret, appears in two places: inside the exchange hash, and
	// at the front of every key-derivation hash.  In both it is an mpint, which
	// per RFC 4251 means a four-byte length followed by the value with a leading
	// zero byte when the high bit is set.  Deriving from the raw 32 bytes instead
	// produces a session whose host-key signature verifies perfectly -- because
	// the exchange hash was built correctly -- and whose very first encrypted
	// packet the server rejects as corrupt.  Encoding K once and handing the same
	// bytes to both consumers is what keeps them honest.
	kEnc := mpintBytes(shared)
	h := exchangeHash(c.localVersion, c.remoteVersion, clientKexInit, serverKexInit,
		hostKeyBlob, qc, qs, kEnc)
	if len(c.sessionID) == 0 {
		c.sessionID = append([]byte(nil), h...)
	}

	pub, err := keys.ParsePublicBlob(hostKeyBlob)
	if err != nil {
		return fmt.Errorf("ssh: host key: %w", err)
	}
	if verr := c.verifyHostKey(pub, h, sig); verr != nil {
		return verr
	}
	c.hostKey = pub

	if err := c.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	// The MAC packet counter is incremented for every packet in a direction.
	// What happens to it at keying is the part implementations disagree on:
	// OpenSSH only resets it when the peer negotiated RFC 9142 strict key
	// exchange, and otherwise carries on counting from the very first packet of
	// the connection.  Starting from zero unconditionally MACs the first
	// encrypted packet with the wrong number, and OpenSSH reacts by closing the
	// connection without sending so much as a DISCONNECT.
	if c.kexStrict {
		c.sendSeq = 0
	}

	c.log("sent NEWKEYS")
	if _, err := c.expect(msgNewKeys); err != nil {
		return err
	}
	c.log("received NEWKEYS")
	if c.kexStrict {
		c.recvSeq = 0
	}
	if err := c.installKeys(kEnc, h); err != nil {
		return err
	}
	c.log("keys installed (send %s/%s, recv %s/%s)", c.outCipherName, c.outMacName, c.inCipherName, c.inMacName)
	return nil
}

type negotiated struct {
	kex, hostKey string
	// Each direction is chosen independently, from the proposal of whichever
	// end sends it.  One shared choice for both directions is not what RFC 4253
	// says and not what OpenSSH does: the server may well send aes128-ctr while
	// we send aes256-ctr.
	outCipher, inCipher string
	outMac, inMac       string
}

// pickFirst returns the first entry of order that also appears in allowed.
func pickFirst(order, allowed []string, label string) (string, error) {
	for _, a := range order {
		for _, b := range allowed {
			if a == b {
				return a, nil
			}
		}
	}
	return "", fmt.Errorf("%w: no overlap for %s (server offers %v)", ErrUnsupported, label, allowed)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// negotiate works out what each side will use.
//
// The rule is subtle and it is the one place where a reasonable-looking
// implementation goes wrong: for BOTH directions the algorithm is the first
// entry of the CLIENT's proposal for that direction that the server also offers
// for that direction.  It is not "each side picks from its own list" -- doing
// that gives the client aes256-ctr one way and aes128-ctr the other, which the
// server then disagrees with, and every packet after NEWKEYS is unreadable with
// no diagnostic beyond a closed socket.  OpenSSH expresses this as
// match_list(client, server), called once per direction.
func (c *Client) negotiate(serverKex, serverHostKey,
	serverCiphersC2S, serverCiphersS2C, serverMacsC2S, serverMacsS2C []string) (*negotiated, error) {
	n := &negotiated{}
	var err error
	if n.kex, err = pickFirst(kexAlgorithms, serverKex, "key exchange"); err != nil {
		return nil, err
	}
	if n.hostKey, err = pickFirst(hostKeyAlgorithms, serverHostKey, "host key"); err != nil {
		return nil, err
	}
	if n.outCipher, err = pickFirst(cipherAlgorithms, serverCiphersC2S, "client-to-server cipher"); err != nil {
		return nil, err
	}
	if n.inCipher, err = pickFirst(cipherAlgorithms, serverCiphersS2C, "server-to-client cipher"); err != nil {
		return nil, err
	}
	if n.outMac, err = pickFirst(macAlgorithms, serverMacsC2S, "client-to-server MAC"); err != nil {
		return nil, err
	}
	if n.inMac, err = pickFirst(macAlgorithms, serverMacsS2C, "server-to-client MAC"); err != nil {
		return nil, err
	}
	c.kexAlgo, c.hostKeyAlgo = n.kex, n.hostKey
	c.outCipherName, c.inCipherName = n.outCipher, n.inCipher
	c.outMacName, c.inMacName = n.outMac, n.inMac
	c.log("negotiated kex=%s hostkey=%s c2s=%s/%s s2c=%s/%s",
		n.kex, n.hostKey, n.outCipher, n.outMac, n.inCipher, n.inMac)
	return n, nil
}

// installKeys derives the per-direction IV, encryption key, and MAC key and
// switches the connection to encrypted framing.
func (c *Client) installKeys(kEnc, exchHash []byte) error {
	derive := func(label byte) []byte {
		return hashExpand(kEnc, exchHash, c.sessionID, label)
	}
	// newDirection builds one half-connection.  The labels are the RFC 4253
	// letters: A/B are the client-to-server and server-to-client IVs, C/D the
	// encryption keys, E/F the MAC keys.
	// The tag and key lengths come from the suite itself, and the material is
	// taken from the front of a 64-byte derivation. That is safe because the
	// expansion is prefix-stable: Kn = HASH(K||H||K1||...||Kn-1), so a shorter
	// need is always a prefix of a longer one, which is what lets winsh and
	// OpenSSH agree even though OpenSSH derives every key to the maximum width
	// either direction requires.
	newDirection := func(cipherName, macName string, keyLabel, ivLabel, macLabel byte) (*direction, error) {
		var keyLen int
		switch cipherName {
		case "aes256-ctr":
			keyLen = 32
		case "aes128-ctr":
			keyLen = 16
		default:
			return nil, fmt.Errorf("%w: unsupported cipher %q", ErrUnsupported, cipherName)
		}
		spec, ok := lookupMAC(macName)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported MAC %q", ErrUnsupported, macName)
		}
		return newCTRDirection(derive(keyLabel)[:keyLen], derive(ivLabel)[:16],
			macName, derive(macLabel)[:spec.size])
	}
	out, err := newDirection(c.outCipherName, c.outMacName, 'C', 'A', 'E')
	if err != nil {
		return err
	}
	in, err := newDirection(c.inCipherName, c.inMacName, 'D', 'B', 'F')
	if err != nil {
		return err
	}
	c.out, c.in = out, in
	return nil
}

// mpintBytes encodes a non-negative integer as an SSH mpint: a four-byte
// length followed by the value in big-endian order, with leading zero bytes
// removed and a single zero byte prepended when the high bit of the value is
// set, so that the reader does not interpret it as negative. Both adjustments
// are required: this is the exact encoding used for the shared secret in the
// exchange hash and in every key-derivation hash, and a peer that strips while
// we do not produces a session whose host key still verifies and whose first
// encrypted packet is refused.
func mpintBytes(v []byte) []byte {
	b := v
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 1 && b[0] == 0 {
		return []byte{0, 0, 0, 0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	out := make([]byte, 4+len(b))
	binaryPutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// hashExpand implements the SSH key-derivation loop of RFC 4253 section 7.2:
// K1 = HASH(K || H || X || session_id), K2 = HASH(K || H || K1), and so on
// until enough material exists.
func hashExpand(shared, exchHash, sessionID []byte, label byte) []byte {
	newHash := func() hash.Hash { return sha256.New() }
	h := newHash()
	h.Write(shared)
	h.Write(exchHash)
	h.Write([]byte{label})
	h.Write(sessionID)
	out := h.Sum(nil)
	for len(out) < 64 {
		h = newHash()
		h.Write(shared)
		h.Write(exchHash)
		h.Write(out)
		out = append(out, h.Sum(nil)...)
	}
	return out
}

func exchangeHash(vC, vS string, iC, iS, kS, qc, qs, kEnc []byte) []byte {
	h := sha256.New()
	str := func(b []byte) {
		var l [4]byte
		binaryPutUint32(l[:], uint32(len(b)))
		h.Write(l[:])
		h.Write(b)
	}
	str([]byte(vC))
	str([]byte(vS))
	str(iC)
	str(iS)
	str(kS)
	str(qc)
	str(qs)
	// K arrives already mpint-encoded, so it is written raw: str() would add a
	// second length and the host-key signature over the exchange hash would then
	// fail against a server that is telling the truth.
	h.Write(kEnc)
	return h.Sum(nil)
}

// newCTRDirection builds one half-connection's cipher and MAC state.
func newCTRDirection(key, iv []byte, macName string, macKey []byte) (*direction, error) {
	spec, ok := lookupMAC(macName)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported MAC %q", ErrUnsupported, macName)
	}
	// Only AES-128 and AES-256 in counter mode are offered, and the check is
	// here rather than only at the call site because crypto/aes also accepts
	// 24-byte keys: without it, AES-192 could arrive by accident through any
	// future caller and nobody would notice.
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("ssh: refusing a cipher key of %d bytes", len(key))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("ssh: refusing a cipher IV of %d bytes", len(iv))
	}
	blk, err := aes_NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ssh: aes: %w", err)
	}
	if len(macKey) < spec.size {
		return nil, fmt.Errorf("ssh: MAC %s needs %d key bytes, got %d", macName, spec.size, len(macKey))
	}
	return &direction{
		ctr:       newCTRStream(blk, iv),
		mac:       spec.f(macKey[:spec.size]),
		blockSize: 16,
		etm:       spec.etm,
	}, nil
}
