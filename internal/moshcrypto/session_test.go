package moshcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func keyFromHex(t *testing.T, s string) Key {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != KeyLength {
		t.Fatalf("bad test key %q", s)
	}
	var k Key
	copy(k[:], b)
	return k
}

func TestKeyParseAndPrint(t *testing.T) {
	k := keyFromHex(t, "000102030405060708090a0b0c0d0e0f")
	p := k.Printable()
	if len(p) != PrintableKeyLength {
		t.Fatalf("printable length = %d", len(p))
	}
	back, err := ParseKey(p)
	if err != nil {
		t.Fatalf("ParseKey(%q): %v", p, err)
	}
	if !back.Equal(k) {
		t.Fatalf("round trip mismatch")
	}
}

func TestKeyRejectsBadInput(t *testing.T) {
	bad := []string{
		"",
		"AAAAAAAAAAAAAAAAAAAAA",      // 21 characters
		"AAAAAAAAAAAAAAAAAAAAAAA",    // 23 characters
		"AAAAAAAAAAAAAAAAAAAA--",     // outside the base64 alphabet
		"AAAAAAAAAAAAAAAAAAAA=",      // padding smuggled in
		"AAAAAAABAAAAAAAAAAAAAAAA==", // non-canonical tail
		"AAAA-AAAAAAAAAAAAAAAAAAA",   // URL-safe alphabet
		"aaaaaaaaaaaaaaaaaaaaa-",
	}
	for _, s := range bad {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("ParseKey(%q) accepted an invalid key", s)
		}
	}
}

func TestKeyStringIsRedacted(t *testing.T) {
	k := keyFromHex(t, "000102030405060708090a0b0c0d0e0f")
	if got := k.String(); got == k.Printable() || bytes.Contains([]byte(got), k[:]) {
		t.Fatalf("Key.String leaked the key material: %q", got)
	}
}

func TestRandomKeysDifferAndAreCanonical(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		k, err := NewKey()
		if err != nil {
			t.Fatalf("NewKey: %v", err)
		}
		p := k.Printable()
		if seen[p] {
			t.Fatalf("duplicate key generated: %s", p)
		}
		seen[p] = true
		if _, err := ParseKey(p); err != nil {
			t.Fatalf("generated key rejected: %v", err)
		}
	}
}

func TestSessionRoundTripAndWireFormat(t *testing.T) {
	k := keyFromHex(t, "000102030405060708090a0b0c0d0e0f")
	s, err := NewSession(k)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	payload := []byte("mosh frame payload")
	datagram, err := s.Encrypt(7, payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(datagram) != NonceWordLength+len(payload)+TagSize {
		t.Fatalf("datagram length = %d, want %d", len(datagram), NonceWordLength+len(payload)+TagSize)
	}
	// The leading nonce octets are the eight most significant bytes of the
	// nonce: four zero bytes then the sequence in network order.
	want := []byte{0, 0, 0, 0, 0, 0, 0, 7}
	if !bytes.Equal(datagram[:8], want) {
		t.Fatalf("nonce prefix = %x, want %x", datagram[:8], want)
	}
	word, plain, err := s.Decrypt(datagram)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if word != 7 || !bytes.Equal(plain, payload) {
		t.Fatalf("round trip = (%d, %q)", word, plain)
	}
}

func TestSessionDirectionBit(t *testing.T) {
	k := keyFromHex(t, "11111111111111111111111111111111")
	s, _ := NewSession(k)
	defer s.Destroy()
	const clientWord = uint64(1<<63 | 42)
	dg, err := s.Encrypt(clientWord, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	word, _, err := s.Decrypt(dg)
	if err != nil {
		t.Fatal(err)
	}
	if word != clientWord {
		t.Fatalf("word = %x want %x", word, clientWord)
	}
	if !WordDirection(word) || WordSequence(word) != 42 {
		t.Fatalf("direction/sequence split wrong for %x", word)
	}
}

func TestSessionRejectsTampering(t *testing.T) {
	k := keyFromHex(t, "22222222222222222222222222222222")
	s, _ := NewSession(k)
	defer s.Destroy()
	dg, err := s.Encrypt(1, []byte("a very important packet"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit in the ciphertext body and in the tag, and truncate.
	edits := map[string]func([]byte){
		"ciphertext bit":  func(b []byte) { b[9] ^= 1 },
		"tag bit":         func(b []byte) { b[len(b)-1] ^= 0x80 },
		"nonce increment": func(b []byte) { b[7]++ },
		"short":           func(b []byte) {},
	}
	for name, f := range edits {
		cp := append([]byte(nil), dg...)
		if name == "short" {
			cp = cp[:NonceWordLength+TagSize-1]
		} else {
			f(cp)
		}
		if _, _, err := s.Decrypt(cp); err == nil {
			t.Errorf("%s: tamper accepted", name)
		}
	}
}

func TestSessionWrongKeyFailsSilently(t *testing.T) {
	k1 := keyFromHex(t, "33333333333333333333333333333333")
	k2 := keyFromHex(t, "44444444444444444444444444444444")
	s1, _ := NewSession(k1)
	s2, _ := NewSession(k2)
	defer s1.Destroy()
	defer s2.Destroy()
	dg, _ := s1.Encrypt(0, []byte("secret"))
	if _, _, err := s2.Decrypt(dg); err == nil {
		t.Fatalf("wrong key decrypted a packet")
	}
}

// TestBackendParity checks that the Windows CNG backend and the Go standard
// library produce identical ciphertext, so choosing one over the other is a
// performance decision and never a correctness one.
func TestBackendParity(t *testing.T) {
	k := keyFromHex(t, "55555555555555555555555555555555")
	payloads := [][]byte{
		nil,
		{0},
		[]byte("short"),
		make([]byte, 16),
		bytes.Repeat([]byte("abcdefgh"), 33),
	}
	var results [][]byte
	for _, useSystem := range []bool{true, false} {
		prev := UseSystemCrypto(useSystem)
		s, err := NewSession(k)
		if err != nil {
			t.Fatalf("NewSession(%v): %v", useSystem, err)
		}
		if useSystem && s.Backend() == "go/crypto-aes" {
			t.Logf("note: CNG unavailable, backend is %s", s.Backend())
		}
		var got [][]byte
		for i, p := range payloads {
			dg, err := s.Encrypt(uint64(i)*1000+1, p)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got = append(got, dg)
			// And it must open with the same session.
			_, plain, err := s.Decrypt(dg)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(plain, p) && !(len(plain) == 0 && len(p) == 0) {
				t.Fatalf("round trip mismatch for payload %d", i)
			}
		}
		s.Destroy()
		UseSystemCrypto(prev)
		results = append(results, got...)
	}
	// results holds two identical halves.
	half := len(results) / 2
	for i := 0; i < half; i++ {
		if !bytes.Equal(results[i], results[i+half]) {
			t.Fatalf("backend divergence on payload %d:\n cng=%x\n std=%x", i, results[i], results[i+half])
		}
	}
}

func TestOCBRejectsBadNonceLength(t *testing.T) {
	k := keyFromHex(t, "66666666666666666666666666666666")
	o, err := NewOCB(k[:])
	if err != nil {
		t.Fatal(err)
	}
	defer o.Destroy()
	dst := make([]byte, TagSize)
	if err := o.Seal(dst, nil, nil, nil); err == nil {
		t.Fatalf("empty nonce accepted")
	}
	if err := o.Seal(dst, make([]byte, 16), nil, nil); err == nil {
		t.Fatalf("oversized nonce accepted")
	}
	if _, err := NewOCB(make([]byte, 32)); err == nil {
		t.Fatalf("256-bit key accepted; the mosh suite is AES-128-OCB only")
	}
}

func TestOCBDestroyIsIdempotentAndFailsClosed(t *testing.T) {
	k := keyFromHex(t, "77777777777777777777777777777777")
	o, _ := NewOCB(k[:])
	o.Destroy()
	o.Destroy()
	if err := o.Seal(make([]byte, TagSize), []byte{1, 2, 3}, nil, nil); err == nil {
		t.Fatalf("destroyed context still encrypts")
	}
}
