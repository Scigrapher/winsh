package moshcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sync/atomic"
)

// blockCipher is the minimal 128-bit block-cipher interface the OCB mode
// built in this package needs.  Keeping it tiny means the mode can be tested
// against either backend and audited without pulling in a provider stack.
type blockCipher interface {
	EncryptBlock(dst, src []byte) error
	DecryptBlock(dst, src []byte) error
	Destroy()
	Backend() string
}

// preferCNG mirrors the "--use-system-crypto" default: winsh asks the
// operating system for AES first because CNG's implementation is
// FIPS-validated and uses AES-NI.  Tests flip it to compare backends.
var preferCNG atomic.Bool

func init() { preferCNG.Store(true) }

// UseSystemCrypto selects or deselects the Windows CNG backend.  It returns
// the previous value.  Selecting false forces the Go standard library.
func UseSystemCrypto(v bool) bool { return preferCNG.Swap(v) }

// SystemCryptoInUse reports which backend new sessions will use.
func SystemCryptoInUse() bool { return preferCNG.Load() }

// newBlockCipher builds an AES implementation for key, preferring CNG.  If
// the CNG path fails for any reason it degrades to the standard library
// rather than failing the session: both paths are constant-time and are
// checked against the same vectors by the test suite.
func newBlockCipher(key []byte) (blockCipher, error) {
	if preferCNG.Load() {
		if c, err := newSystemBlockCipher(key); err == nil {
			return c, nil
		}
	}
	return newStdlibBlockCipher(key)
}

// BackendName describes the backend that would be chosen right now; it is
// reported by "winsh --diagnostics".
func BackendName() string {
	if !preferCNG.Load() {
		return "go/crypto-aes"
	}
	c, err := newSystemBlockCipher(make([]byte, 16))
	if err != nil {
		return "go/crypto-aes (cng unavailable)"
	}
	name := c.Backend()
	c.Destroy()
	return name
}

type stdlibCipher struct{ b cipher.Block }

func newStdlibBlockCipher(key []byte) (blockCipher, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("moshcrypto: aes: %w", err)
	}
	return &stdlibCipher{b: b}, nil
}

func (c *stdlibCipher) EncryptBlock(dst, src []byte) error {
	if len(dst) < aes.BlockSize || len(src) < aes.BlockSize {
		return fmt.Errorf("moshcrypto: short block buffer")
	}
	c.b.Encrypt(dst, src)
	return nil
}

func (c *stdlibCipher) DecryptBlock(dst, src []byte) error {
	if len(dst) < aes.BlockSize || len(src) < aes.BlockSize {
		return fmt.Errorf("moshcrypto: short block buffer")
	}
	c.b.Decrypt(dst, src)
	return nil
}

func (c *stdlibCipher) Destroy()        {}
func (c *stdlibCipher) Backend() string { return "go/crypto-aes" }
