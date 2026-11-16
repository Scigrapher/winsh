package moshcrypto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// This file implements the packet-level cipher suite that the mosh protocol
// calls AES-128-OCB: a 128-bit key carried out of band as 22 printable base64
// octets, and a 96-bit nonce whose low 64 bits hold a direction bit plus a
// strictly increasing sequence number.

// KeyLength is the cipher suite's key size in octets.
const KeyLength = 16

// NonceWordLength is the number of octets that travel in front of every
// ciphertext: the eight most significant bytes of the nonce.  The four
// leading nonce octets are always zero and are not transmitted.
const NonceWordLength = 8

// AddedBytes is the per-packet expansion of the cipher suite (the OCB tag).
const AddedBytes = TagSize

// ReceiveMTU is the largest datagram the reference implementation accepts.
const ReceiveMTU = 2048

// PrintableKeyLength is the length of a key as printed by mosh-server.
const PrintableKeyLength = 22

// maxBlocksPerKey is the lifetime data limit for one key.  OCB's security
// bound degrades with the square of the number of blocks processed, so the
// key is retired well before that; mosh uses 2^47 blocks and winsh keeps the
// same limit so that the two clients behave identically.
const maxBlocksPerKey = uint64(1) << 47

// ErrBadKey reports a key string that is not a valid mosh key.
var ErrBadKey = errors.New("moshcrypto: invalid key")

// Key is a mosh session key.
//
// String is deliberately redacted: a key must never reach a log, a terminal,
// or an error message by accident.  Use Printable when the value is being
// handed to a user or to another process on purpose.
type Key [KeyLength]byte

// String returns a redacted form; it is not the key.
func (k Key) String() string { return "moshcrypto.Key{***}" }

// Equal compares keys in constant time.
func (k Key) Equal(other Key) bool {
	return subtle.ConstantTimeCompare(k[:], other[:]) == 1
}

// Wipe erases the key.  It is best-effort: copies made earlier are unaffected.
func (k *Key) Wipe() {
	for i := range k {
		k[i] = 0
	}
}

// ParseKey decodes the 22-character printable form of a key.
//
// The check is strict: the input must be exactly 22 characters from the
// standard base64 alphabet and must re-encode to the same 22 characters, so
// non-canonical encodings (which could smuggle a second key past a string
// comparison) are rejected.
func ParseKey(printable string) (Key, error) {
	var k Key
	if len(printable) != PrintableKeyLength {
		return k, fmt.Errorf("%w: expected %d characters, got %d", ErrBadKey, PrintableKeyLength, len(printable))
	}
	decoded, err := base64.StdEncoding.DecodeString(printable + "==")
	if err != nil {
		return k, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if len(decoded) != KeyLength {
		return k, fmt.Errorf("%w: decoded to %d octets", ErrBadKey, len(decoded))
	}
	copy(k[:], decoded)
	if k.Printable() != printable {
		return k, fmt.Errorf("%w: not the canonical encoding", ErrBadKey)
	}
	return k, nil
}

// Printable returns the 22-character form that mosh-server prints and that
// --key accepts.
func (k Key) Printable() string {
	return base64.StdEncoding.EncodeToString(k[:])[:PrintableKeyLength]
}

// NewKey generates a fresh session key from the operating-system entropy
// source (BCryptGenRandom on Windows).
func NewKey() (Key, error) {
	var k Key
	if err := systemRandom(k[:]); err != nil {
		return k, fmt.Errorf("moshcrypto: key generation: %w", err)
	}
	return k, nil
}

// Session is the packet cipher for one key.  The same key protects both
// directions, so the block budget is shared.  A Session is not safe for
// concurrent use; winsh drives it from a single network goroutine.
type Session struct {
	ocb    *OCB
	blocks uint64
}

// NewSession creates a cipher session for k.
func NewSession(k Key) (*Session, error) {
	o, err := NewOCB(k[:])
	if err != nil {
		return nil, err
	}
	return &Session{ocb: o}, nil
}

// Backend names the AES implementation in use.
func (s *Session) Backend() string { return s.ocb.Backend() }

// Destroy wipes session key material.
func (s *Session) Destroy() {
	if s == nil {
		return
	}
	s.ocb.Destroy()
	s.blocks = 0
}

// nonceFor builds the 12-octet nonce from the 64-bit direction/sequence word.
func nonceFor(word uint64) [12]byte {
	var n [12]byte
	for i := 0; i < 8; i++ {
		n[4+i] = byte(word >> uint(8*(7-i)))
	}
	return n
}

// WordDirection reports the direction bit of a nonce word.
func WordDirection(word uint64) bool { return word>>63 != 0 }

// WordSequence masks off the direction bit.
func WordSequence(word uint64) uint64 { return word & 0x7fffffffffffffff }

// Encrypt seals payload under the given nonce word and returns
// nonce-word(8) || ciphertext || tag, which is exactly the form that travels
// in a UDP datagram.
func (s *Session) Encrypt(word uint64, payload []byte) ([]byte, error) {
	if s == nil || s.ocb == nil {
		return nil, errors.New("moshcrypto: session destroyed")
	}
	n := nonceFor(word)
	out := make([]byte, NonceWordLength+len(payload)+TagSize)
	copy(out, n[4:])
	if err := s.ocb.Seal(out[NonceWordLength:], n[:], nil, payload); err != nil {
		return nil, err
	}
	s.blocks += uint64(len(payload) / BlockSize)
	if len(payload)%BlockSize != 0 {
		s.blocks++
	}
	if s.blocks >= maxBlocksPerKey {
		return out, ErrKeyLimit
	}
	return out, nil
}

// Decrypt opens a datagram body, returning the nonce word and the plaintext.
// It never distinguishes "wrong key" from "corrupted" to the caller.
func (s *Session) Decrypt(datagram []byte) (uint64, []byte, error) {
	if s == nil || s.ocb == nil {
		return 0, nil, errors.New("moshcrypto: session destroyed")
	}
	if len(datagram) < NonceWordLength+TagSize {
		return 0, nil, ErrOpen
	}
	var word uint64
	for i := 0; i < NonceWordLength; i++ {
		word = word<<8 | uint64(datagram[i])
	}
	n := nonceFor(word)
	body := datagram[NonceWordLength:]
	out := make([]byte, len(body)-TagSize)
	if err := s.ocb.Open(out, n[:], nil, body); err != nil {
		return 0, nil, err
	}
	return word, out, nil
}
