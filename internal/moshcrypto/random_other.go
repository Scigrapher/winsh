//go:build !windows

package moshcrypto

import "crypto/rand"

// systemRandom falls back to the Go standard library CSPRNG off Windows.
func systemRandom(b []byte) error {
	_, err := rand.Read(b)
	return err
}
