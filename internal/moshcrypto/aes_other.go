//go:build !windows

package moshcrypto

import "errors"

// There is no operating-system AES backend outside Windows; callers get the
// Go standard library implementation.  This file exists so the selection
// logic stays uniform across build targets.

func newSystemBlockCipher(key []byte) (blockCipher, error) {
	return nil, errors.New("moshcrypto: no system backend on this platform")
}
