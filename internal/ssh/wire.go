// Package ssh is winsh's own SSH client, used to bootstrap a mosh session
// without depending on an external ssh(1) -- which is what makes direct use of
// Pageant and ~/.ssh keys possible.
//
// It is deliberately narrow.  It implements only the algorithms a modern
// OpenSSH server negotiates anyway (curve25519-sha256 or ecdh-sha2-nistp256
// key exchange, AES-GCM or AES-CTR with HMAC-SHA2 confidentiality, and
// Ed25519/RSA-SHA2/ECDSA host keys), plus publickey, password, and
// keyboard-interactive authentication.  What it does not implement is refused
// rather than quietly weakened: there is no CBC mode, no RC4, no MD5, no
// SHA-1 host keys by default, and host key verification is mandatory.
//
// The Go standard library supplies every primitive (crypto/ecdh for X25519,
// crypto/aes for the bulk cipher); the framing and message formats here are
// written from the IETF secsh specifications, and no third-party SSH code is
// used.
package ssh

import (
	"errors"
	"strings"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"

	"winsh/internal/textsafe"
)

// SSH message numbers used here.
const (
	msgDisconnect = 1
	msgIgnore     = 2
	msgDebug      = 4
	// SSH2_MSG_EXT_INFO, RFC 8308: an announcement, never a reply.
	msgExtInfo              = 7 // RFC 8308 SSH_MSG_EXT_INFO
	msgUnimplemented        = 3
	msgServiceRequest       = 5
	msgServiceAccept        = 6
	msgKexInit              = 20
	msgNewKeys              = 21
	msgKexEcdhInit          = 30
	msgKexEcdhReply         = 31
	msgKexDhInit            = 34
	msgKexDhGroup16Reply    = 33
	msgUserAuthRequest      = 50
	msgUserAuthFailure      = 51
	msgUserAuthSuccess      = 52
	msgUserAuthBanner       = 53
	msgUserAuthInfoRequest  = 60
	msgUserAuthInfoResponse = 61
	msgGlobalRequest        = 80
	msgChannelOpen          = 90
	msgRequestFailure       = 82
	msgChannelOpenConfirm   = 91
	msgChannelOpenFailure   = 92
	msgChannelWindowAdjust  = 93
	msgChannelData          = 94
	msgChannelExtendedData  = 95
	msgChannelEOF           = 96
	msgChannelClose         = 97
	msgChannelSuccess       = 99
	msgChannelFailure       = 100
	msgChannelRequest       = 98
)

// Disconnect reason codes worth surfacing.
const (
	disconnectHostNotVerifiable = 3
	disconnectProtocolError     = 2
	disconnectNoMoreAuth        = 14
)

// Error is a protocol-level failure with the SSH context attached.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("ssh: protocol error %d: %s", e.Code, textsafe.Line(e.Message, 4096))
}

// builder accumulates SSH wire types.
type builder struct{ b []byte }

func (o *builder) byte_(v byte) { o.b = append(o.b, v) }
func (o *builder) boolv(v bool) {
	if v {
		o.b = append(o.b, 1)
	} else {
		o.b = append(o.b, 0)
	}
}
func (o *builder) uint32(v uint32) {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	o.b = append(o.b, t[:]...)
}
func (o *builder) uint64(v uint64) {
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], v)
	o.b = append(o.b, t[:]...)
}
func (o *builder) raw(v []byte) { o.b = append(o.b, v...) }
func (o *builder) str(s []byte) { o.uint32(uint32(len(s))); o.b = append(o.b, s...) }

// strs writes an SSH name-list.
//
// A name-list is ONE string whose contents are the names separated by commas
// (RFC 4253 section 5.2).  It is not a sequence of length-prefixed strings, and
// writing it that way produces a KEXINIT that a real server accepts only
// because it can still read the type byte and the cookie.
func (o *builder) strs(list []string) {
	o.str([]byte(strings.Join(list, ",")))
}
func (o *builder) mpint(v *big.Int) {
	if v == nil || v.Sign() == 0 {
		o.str(nil)
		return
	}
	if v.Sign() < 0 {
		// Two's-complement negatives are not needed for any field winsh
		// encodes; refusing is safer than getting the encoding wrong.
		o.str(nil)
		return
	}
	b := v.Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	o.str(b)
}

// msg is a reader over an SSH payload.
type msg struct {
	b   []byte
	off int
	err error
}

func (m *msg) fail(s string) {
	if m.err == nil {
		m.err = fmt.Errorf("ssh: malformed message: %s", s)
	}
}

func (m *msg) byte_() (byte, bool) {
	if m.off+1 > len(m.b) {
		m.fail("byte past end")
		return 0, false
	}
	v := m.b[m.off]
	m.off++
	return v, true
}

func (m *msg) uint32() (uint32, bool) {
	if m.off+4 > len(m.b) {
		m.fail("uint32 past end")
		return 0, false
	}
	v := binary.BigEndian.Uint32(m.b[m.off : m.off+4])
	m.off += 4
	return v, true
}

func (m *msg) uint64() (uint64, bool) {
	if m.off+8 > len(m.b) {
		m.fail("uint64 past end")
		return 0, false
	}
	v := binary.BigEndian.Uint64(m.b[m.off : m.off+8])
	m.off += 8
	return v, true
}

func (m *msg) str() ([]byte, bool) {
	n, ok := m.uint32()
	if !ok || uint64(n) > uint64(len(m.b)-m.off) {
		m.fail("string length")
		return nil, false
	}
	if n > 1<<24 {
		m.fail("absurd string length")
		return nil, false
	}
	out := m.b[m.off : m.off+int(n)]
	m.off += int(n)
	return out, true
}

// fixed reads n raw bytes that are NOT length-prefixed.
//
// Most variable-length fields in SSH are strings, but a few are declared as
// byte[n] and carry no length field at all.  The KEXINIT cookie is the one that
// bites: reading it as a string consumes four bytes of the cookie as a bogus
// length, and the parse then dies on "string length" against a perfectly
// ordinary server.  Keeping the distinction in a named method stops it from
// being gotten wrong at each call site.
func (m *msg) fixed(n int) ([]byte, bool) {
	if n < 0 || m.off+n > len(m.b) {
		m.fail("fixed field past end")
		return nil, false
	}
	out := m.b[m.off : m.off+n]
	m.off += n
	return out, true
}

// nameList reads an SSH name-list: one string of comma-separated names.
//
// The previous version here parsed the contents as a sequence of length-prefixed
// strings, which is a different encoding entirely.  Against a real server the
// inner read ran straight off the end and, because the error was recorded on the
// inner reader and never copied out, the caller received a nil list together
// with a nil error and happily negotiated "no common algorithms" against a
// server offering plenty.  Both halves of that are fixed: the encoding is the
// documented one, and a genuine parse failure is reported on the outer message.
func (m *msg) nameList() ([]string, bool) {
	blob, ok := m.str()
	if !ok {
		return nil, false
	}
	if len(blob) == 0 {
		return nil, true
	}
	return strings.Split(string(blob), ","), true
}

func (m *msg) mpint() (*big.Int, bool) {
	b, ok := m.str()
	if !ok {
		return nil, false
	}
	if len(b) > 1024 {
		m.fail("absurd mpint")
		return nil, false
	}
	if len(b) == 0 {
		return new(big.Int), true
	}
	if b[0]&0x80 != 0 {
		m.fail("negative mpint")
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}

func (m *msg) boolv() (bool, bool) {
	b, ok := m.byte_()
	return b != 0, ok
}

// ---------- cipher suites ----------

// direction holds the crypto state for one half of the connection.
// direction holds the crypto state for one half of the connection.
//
// etm says which of the two SSH MAC families is in use, and it is not a
// detail: plain hmac-sha2-* is an "encrypt-and-MAC" suite, meaning the tag is
// computed over the PLAINTEXT packet, while the -etm@openssh.com variants are
// "encrypt-then-MAC" and tag the CIPHERTEXT. Getting the two confused is
// undetectable against a peer that makes the same mistake and fatal against one
// that does not. winsh prefers the ETM variants; the plain ones remain for
// servers that do not offer them.
type direction struct {
	ctr cipher.Stream
	mac hash.Hash
	etm bool
	// blockSize is the cipher's block size, which decides how the packet
	// has to be padded. It is 16 for every AES-CTR suite winsh offers.
	blockSize int
}

// aes_NewCipher, newCTRStream, newHMAC256 and newHMAC512 are the only places
// the SSH code touches cipher constructors, which keeps the algorithm choices
// auditable in one spot.

func aes_NewCipher(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }

func newCTRStream(blk cipher.Block, iv []byte) cipher.Stream {
	return cipher.NewCTR(blk, iv)
}

// randomBytes fills b from the system CSPRNG.
func randomBytes(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("ssh: entropy: %w", err)
	}
	return nil
}

// macSpec describes one of the four HMAC suites winsh will negotiate.
type macSpec struct {
	name string
	f    func(key []byte) hash.Hash
	size int
	etm  bool
}

// lookupMAC turns a negotiated MAC name into its construction parameters.
func lookupMAC(name string) (macSpec, bool) {
	switch name {
	case "hmac-sha2-512-etm@openssh.com":
		return macSpec{name, newHMAC512, 64, true}, true
	case "hmac-sha2-256-etm@openssh.com":
		return macSpec{name, newHMAC256, 32, true}, true
	case "hmac-sha2-512":
		return macSpec{name, newHMAC512, 64, false}, true
	case "hmac-sha2-256":
		return macSpec{name, newHMAC256, 32, false}, true
	}
	return macSpec{}, false
}

func newHMAC256(key []byte) hash.Hash { return hmac.New(sha256.New, key) }

func newHMAC512(key []byte) hash.Hash { return hmac.New(sha512.New, key) }

// hexDump renders up to n bytes of b as hex, for error messages that need to
// show what actually arrived.  It is bounded so a hostile peer cannot make
// winsh print megabytes.
func hexDump(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	const digits = "0123456789abcdef"
	out := make([]byte, 0, n*3)
	for i := 0; i < n; i++ {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, digits[b[i]>>4], digits[b[i]&0xf])
	}
	if len(b) > n {
		out = append(out, '.', '.', '.')
	}
	return string(out)
}

var errNotEnoughData = errors.New("ssh: short read")
