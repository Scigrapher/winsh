//go:build windows

package moshcrypto

import "winsh/internal/cng"

// systemRandom draws entropy from the Windows preferred RNG, which is seeded
// from the OS entropy sources rather than from a userspace PRNG.
func systemRandom(b []byte) error { return cng.Random(b) }
