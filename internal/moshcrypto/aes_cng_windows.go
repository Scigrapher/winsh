//go:build windows

package moshcrypto

import (
	"fmt"

	"winsh/internal/cng"
)

// cngCipher is the Windows CNG (bcrypt.dll) AES backend.  ECB chaining is
// used on purpose: OCB supplies its own offsets, so winsh needs raw blocks
// and nothing else.  The key object lives for the session's lifetime and is
// zeroed on Destroy.
type cngCipher struct {
	alg *cng.Algorithm
	key *cng.Key
}

func newSystemBlockCipher(key []byte) (blockCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("moshcrypto: AES key of %d bytes", len(key))
	}
	if !cng.Available() {
		return nil, fmt.Errorf("moshcrypto: bcrypt.dll unavailable")
	}
	alg, err := cng.OpenAlgorithm(cng.AESAlgorithm, "")
	if err != nil {
		return nil, err
	}
	if err := alg.SetChainingMode(cng.ChainingModeECB); err != nil {
		alg.Close()
		return nil, err
	}
	k, err := alg.GenerateSymmetricKey(key)
	if err != nil {
		alg.Close()
		return nil, err
	}
	return &cngCipher{alg: alg, key: k}, nil
}

func (c *cngCipher) EncryptBlock(dst, src []byte) error {
	if len(dst) < 16 || len(src) < 16 {
		return fmt.Errorf("moshcrypto: short block buffer")
	}
	n, err := c.key.Encrypt(dst[:16], src[:16], nil)
	if err != nil {
		return fmt.Errorf("moshcrypto: cng encrypt: %w", err)
	}
	if n != 16 {
		return fmt.Errorf("moshcrypto: cng produced %d bytes", n)
	}
	return nil
}

func (c *cngCipher) DecryptBlock(dst, src []byte) error {
	if len(dst) < 16 || len(src) < 16 {
		return fmt.Errorf("moshcrypto: short block buffer")
	}
	n, err := c.key.Decrypt(dst[:16], src[:16], nil)
	if err != nil {
		return fmt.Errorf("moshcrypto: cng decrypt: %w", err)
	}
	if n != 16 {
		return fmt.Errorf("moshcrypto: cng produced %d bytes", n)
	}
	return nil
}

func (c *cngCipher) Destroy() {
	if c == nil {
		return
	}
	if c.key != nil {
		c.key.Destroy()
	}
	if c.alg != nil {
		c.alg.Close()
	}
}

func (c *cngCipher) Backend() string { return "windows/cng-bcrypt-aes" }
