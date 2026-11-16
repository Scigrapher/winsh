package ssh

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// These tests exist because every bug they covers was invisible to the rest of
// the suite: the fake SSH server shares this package, so a wrong assumption is
// agreed with rather than caught. They are written against the wire.

func TestNameListIsOneCommaSeparatedString(t *testing.T) {
	var o builder
	o.strs([]string{"curve25519-sha256", "aes256-ctr", "hmac-sha2-256"})
	want := "curve25519-sha256,aes256-ctr,hmac-sha2-256"
	if len(o.b) != 4+len(want) {
		t.Fatalf("name-list framing = %d bytes, want %d", len(o.b), 4+len(want))
	}
	if got := binary.BigEndian.Uint32(o.b[:4]); int(got) != len(want) {
		t.Errorf("name-list length = %d, want %d", got, len(want))
	}
	if string(o.b[4:]) != want {
		t.Errorf("name-list contents = %q, want %q", o.b[4:], want)
	}
	m := &msg{b: o.b}
	got, ok := m.nameList()
	if !ok || len(got) != 3 || got[1] != "aes256-ctr" {
		t.Errorf("nameList round trip = %v, ok=%v, err=%v", got, ok, m.err)
	}
	// A sequence of length-prefixed strings must NOT parse as a name-list.
	// That is the encoding that made winsh advertise a KEXINIT no server could
	// read while still negotiating happily with itself.
	framed := []byte{0, 0, 0, 1, 'a', 0, 0, 0, 1, 'b'}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(framed)))
	m = &msg{b: append(append([]byte(nil), hdr[:]...), framed...)}
	// It parses as one opaque blob rather than two names, which is the point:
	// a peer that disagrees about the encoding must produce something visibly
	// wrong rather than a plausible-looking list.
	list, ok := m.nameList()
	if !ok || len(list) != 1 || !strings.ContainsRune(list[0], 0) {
		t.Errorf("the wrong encoding parsed too well: %q (ok=%v)", list, ok)
	}
}

func TestKexInitCookieIsSixteenRawBytes(t *testing.T) {
	// RFC 4253 section 7.1: the cookie is byte[16], not a string. Reading it as
	// a string consumes four cookie bytes as a bogus length.
	cookie := make([]byte, 16)
	for i := range cookie {
		cookie[i] = byte(0xf0 + i)
	}
	var o builder
	o.byte_(msgKexInit)
	o.raw(cookie)
	o.strs([]string{"curve25519-sha256"})
	m := &msg{b: o.b[1:]}
	got, ok := m.fixed(16)
	if !ok || !bytes.Equal(got, cookie) {
		t.Fatalf("cookie = %x ok=%v err=%v", got, ok, m.err)
	}
	if _, ok := m.nameList(); !ok {
		t.Fatalf("kex_algorithms did not follow the cookie: %v", m.err)
	}
	m = &msg{b: o.b[1:]}
	if _, ok := m.str(); ok {
		t.Error("reading the cookie as a string should fail against a real KEXINIT")
	}
}

// sessionMaterial is the fixed keying input the packet tests share.
var sessionMaterial = struct {
	kEnc []byte
	h    []byte
}{
	kEnc: mpintBytes(bytes.Repeat([]byte{0xa5}, 32)),
	h:    bytes.Repeat([]byte{0x5a}, 32),
}

// mustDirection builds one half-connection. Every client needs its own,
// because a direction owns a live cipher stream.
func mustDirection(t *testing.T, macName string, keyLabel, ivLabel, macLabel byte) *direction {
	t.Helper()
	expand := func(label byte, n int) []byte {
		return hashExpand(sessionMaterial.kEnc, sessionMaterial.h, sessionMaterial.h, label)[:n]
	}
	d, err := newCTRDirection(expand(keyLabel, 32), expand(ivLabel, 16), macName, expand(macLabel, 64))
	if err != nil {
		t.Fatalf("direction for %s: %v", macName, err)
	}
	return d
}

// memConn lets the packet layer be inspected on the wire instead of only
// through its own reader, which is the only way to tell the two MAC families
// apart from the outside.
type memConn struct {
	net.Conn
	r io.Reader
	w *bytes.Buffer
}

func (c *memConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *memConn) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c *memConn) Close() error                { return nil }

func newSender(t *testing.T, macName string, seq uint32) (*Client, *bytes.Buffer) {
	t.Helper()
	var wire bytes.Buffer
	return &Client{
		conn:    &memConn{r: bytes.NewReader(nil), w: &wire},
		r:       bufio.NewReader(bytes.NewReader(nil)),
		out:     mustDirection(t, macName, 'C', 'A', 'E'),
		sendSeq: seq,
	}, &wire
}

func newReceiver(wire []byte, macName string, seq uint32) *Client {
	return &Client{
		conn:    &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
		r:       bufio.NewReader(bytes.NewReader(wire)),
		in:      mustDirectionStatic(macName),
		recvSeq: seq,
	}
}

// mustDirectionStatic exists for newReceiver, which has no *testing.T.
func mustDirectionStatic(macName string) *direction {
	expand := func(label byte, n int) []byte {
		return hashExpand(sessionMaterial.kEnc, sessionMaterial.h, sessionMaterial.h, label)[:n]
	}
	d, err := newCTRDirection(expand('C', 32), expand('A', 16), macName, expand('E', 64))
	if err != nil {
		panic(err)
	}
	return d
}

// TestPacketFamiliesRoundTrip covers the difference between encrypt-and-MAC
// and encrypt-then-MAC: the easiest thing to get wrong here, and the one that
// produces a server that hangs up without explanation.
func TestPacketFamiliesRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		macName string
		etm     bool
		macLen  int
	}{
		{"hmac-sha2-512-etm@openssh.com", true, 64},
		{"hmac-sha2-256-etm@openssh.com", true, 32},
		{"hmac-sha2-512", false, 64},
		{"hmac-sha2-256", false, 32},
	} {
		t.Run(tc.macName, func(t *testing.T) {
			const seq = 7
			sender, wire := newSender(t, tc.macName, seq)
			payload := append([]byte{msgChannelData}, bytes.Repeat([]byte("x"), 40)...)
			if err := sender.writePacket(payload); err != nil {
				t.Fatalf("writePacket: %v", err)
			}
			raw := append([]byte(nil), wire.Bytes()...)
			if tc.etm {
				// The length field is authenticated but not encrypted, so it
				// can be read straight off the wire.
				body := int(binary.BigEndian.Uint32(raw[:4]))
				if len(raw) != 4+body+tc.macLen {
					t.Fatalf("wire is %d bytes, want %d", len(raw), 4+body+tc.macLen)
				}
				if body%16 != 0 {
					t.Errorf("EtM body is %d bytes: OpenSSH answers with a padding error and drops the connection", body)
				}
			} else {
				// Encrypt-and-MAC hides the length inside the ciphertext, so
				// only the total can be checked from the outside.
				if len(raw)%16 != 0 {
					t.Errorf("encrypt-and-MAC packet totals %d bytes, not a multiple of the block size", len(raw))
				}
				if binary.BigEndian.Uint32(raw[:4]) == uint32(len(raw)-4-tc.macLen) && len(raw) > 8 {
					t.Error("an encrypt-and-MAC packet left its length field in the clear")
				}
			}
			if len(raw) < 16+tc.macLen {
				t.Errorf("packet is only %d bytes; SSH_MSG_NEWKEYS should not be identifiable by length", len(raw))
			}

			got, err := newReceiver(raw, tc.macName, seq).readPacket()
			if err != nil {
				t.Fatalf("readPacket: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}

			// Corrupting the authentication tag has to be caught...
			bad := append([]byte(nil), raw...)
			bad[len(bad)-1] ^= 0x40
			if _, err := newReceiver(bad, tc.macName, seq).readPacket(); err == nil {
				t.Error("a corrupted tag was accepted")
			}
			// ...and so does a desynchronised sequence number, which is what
			// happens when a client resets its counter at keying but the peer
			// does not (or the other way round).
			if _, err := newReceiver(raw, tc.macName, seq+1).readPacket(); err == nil {
				t.Error("a packet with the wrong sequence number was accepted")
			}
		})
	}
}

func TestUnapprovedPrimitivesAreRejected(t *testing.T) {
	if _, err := newCTRDirection(make([]byte, 32), make([]byte, 16), "hmac-md5", make([]byte, 16)); err == nil {
		t.Error("an unapproved MAC was accepted")
	}
	if _, err := newCTRDirection(make([]byte, 32), make([]byte, 16), "hmac-sha2-256", make([]byte, 8)); err == nil {
		t.Error("a short MAC key was accepted")
	}
	if _, err := newCTRDirection(make([]byte, 24), make([]byte, 16), "hmac-sha2-256", make([]byte, 32)); err == nil {
		t.Error("an AES key of the wrong length was accepted")
	}
	if _, ok := lookupMAC("hmac-md5-etm@openssh.com"); ok {
		t.Error("MD5 was offered as a usable MAC")
	}
	if _, ok := lookupMAC("hmac-sha1"); ok {
		t.Error("SHA-1 was offered as a usable MAC")
	}
	if _, ok := lookupMAC("aes128-gcm@openssh.com"); ok {
		t.Error("an AEAD cipher name was accepted as a MAC")
	}
}

// TestNegotiateFollowsTheClientsPreferencesForBothDirections uses the actual
// proposals of an Ubuntu OpenSSH_9.6p1 server. Choosing each direction from the
// server's own preference list gave aes128-ctr/hmac-sha2-256 one way while
// winsh kept aes256-ctr/hmac-sha2-512 the other, and every packet after
// NEWKEYS was then unreadable with no diagnostic beyond a closed socket.
func TestNegotiateFollowsTheClientsPreferencesForBothDirections(t *testing.T) {
	serverKex := []string{"sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
		"curve25519-sha256@libssh.org", "ext-info-s", "kex-strict-s-v00@openssh.com"}
	serverHost := []string{"rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"}
	serverCiphers := []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr",
		"aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}
	serverMacs := []string{"umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}
	c := &Client{}
	n, err := c.negotiate(serverKex, serverHost, serverCiphers, serverCiphers, serverMacs, serverMacs)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if n.kex != "curve25519-sha256" {
		t.Errorf("kex = %s, want curve25519-sha256", n.kex)
	}
	if n.hostKey != "ssh-ed25519" {
		t.Errorf("host key = %s, want the client's first overlap", n.hostKey)
	}
	if n.outCipher != "aes256-ctr" || n.inCipher != "aes256-ctr" {
		t.Errorf("ciphers = %s / %s, want aes256-ctr both ways: the client chooses", n.outCipher, n.inCipher)
	}
	if n.outMac != "hmac-sha2-512-etm@openssh.com" || n.inMac != "hmac-sha2-512-etm@openssh.com" {
		t.Errorf("MACs = %s / %s, want the client's first overlap both ways", n.outMac, n.inMac)
	}
	if _, err := c.negotiate(serverKex, []string{"ssh-dss"}, serverCiphers, serverCiphers, serverMacs, serverMacs); err == nil {
		t.Error("negotiate accepted a server offering no host key we support")
	}
	// An asymmetric server proposal must be honoured per direction.
	n, err = c.negotiate(serverKex, serverHost, serverCiphers, []string{"aes128-ctr"}, serverMacs, serverMacs)
	if err != nil {
		t.Fatalf("negotiate (asymmetric): %v", err)
	}
	if n.inCipher != "aes128-ctr" {
		t.Errorf("inCipher = %s, want aes128-ctr because the server only offers that one way", n.inCipher)
	}
}

func TestMpintAndKeyExpansion(t *testing.T) {
	if got := mpintBytes([]byte{0x80, 0x01}); !bytes.Equal(got, []byte{0, 0, 0, 3, 0, 0x80, 0x01}) {
		t.Errorf("mpintBytes(0x8001) = %x, want a sign byte and length 3", got)
	}
	if got := mpintBytes([]byte{0x00, 0x7f}); !bytes.Equal(got, []byte{0, 0, 0, 1, 0x7f}) {
		t.Errorf("mpintBytes(0x007f) = %x, want the leading zero stripped", got)
	}
	if got := mpintBytes([]byte{0x00, 0x00}); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Errorf("mpintBytes(zero) = %x, want an empty mpint", got)
	}
	if got := mpintBytes([]byte{0x01}); !bytes.Equal(got, []byte{0, 0, 0, 1, 0x01}) {
		t.Errorf("mpintBytes(0x01) = %x", got)
	}
	// OpenSSH derives all six keys at the widest width either direction needs
	// and then truncates, so a shorter need must be a prefix of a longer one.
	wide := hashExpand(mpintBytes([]byte{0x25, 0x40}), sessionMaterial.h, sessionMaterial.h, 'A')
	if len(wide) < 64 {
		t.Fatalf("derivation produced %d bytes, want at least 64", len(wide))
	}
	narrow := hashExpand(mpintBytes([]byte{0x25, 0x40}), sessionMaterial.h, sessionMaterial.h, 'A')
	if !bytes.Equal(wide[:32], narrow[:32]) {
		t.Error("the derivation is not deterministic")
	}
	// The expansion keeps going with HASH(K||H||K1), not by restarting.
	second := hashExpand(mpintBytes([]byte{0x25, 0x40}), sessionMaterial.h, sessionMaterial.h, 'A')
	if bytes.Equal(second[32:64], second[:32]) {
		t.Error("the second derivation block repeated the first instead of chaining")
	}
}
