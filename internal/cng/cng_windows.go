// Package cng provides a thin, dependency-free binding to the Windows
// Cryptography Next Generation (CNG) API in bcrypt.dll.
//
// winsh prefers operating-system cryptographic code over Go's own
// implementation because the CNG primitives are FIPS-validated and use
// AES-NI when the CPU offers it.  Every entry point here is a direct,
// unadorned syscall: policy (which algorithm, which mode) lives in the
// callers, not here, so that the security-relevant decisions stay auditable
// in one place.
//
// Only Windows builds link this package; on other platforms callers fall
// back to the Go standard library, which keeps the unit tests portable.
package cng

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	bcrypt             = syscall.NewLazyDLL("bcrypt.dll")
	procOpenAlg        = bcrypt.NewProc("BCryptOpenAlgorithmProvider")
	procCloseAlg       = bcrypt.NewProc("BCryptCloseAlgorithmProvider")
	procSetProperty    = bcrypt.NewProc("BCryptSetProperty")
	procGetProperty    = bcrypt.NewProc("BCryptGetProperty")
	procGenSymKey      = bcrypt.NewProc("BCryptGenerateSymmetricKey")
	procDestroyKey     = bcrypt.NewProc("BCryptDestroyKey")
	procEncrypt        = bcrypt.NewProc("BCryptEncrypt")
	procDecrypt        = bcrypt.NewProc("BCryptDecrypt")
	procHash           = bcrypt.NewProc("BCryptHash")
	procCreateHash     = bcrypt.NewProc("BCryptCreateHash")
	procHashData       = bcrypt.NewProc("BCryptHashData")
	procFinishHash     = bcrypt.NewProc("BCryptFinishHash")
	procDestroyHash    = bcrypt.NewProc("BCryptDestroyHash")
	procGenerateRandom = bcrypt.NewProc("BCryptGenRandom")
	procSecretDataZero = bcrypt.NewProc("BCryptZeroSecret")
)

// CNG algorithm identifiers.
const (
	AESAlgorithm               = "AES"
	ChaCha20Poly1305Alg        = "Chacha20Poly1305"
	Sha256Algorithm            = "SHA256"
	Sha384Algorithm            = "SHA384"
	Sha512Algorithm            = "SHA512"
	HMACAlgorithmSuffix        = "_HMAC"
	ChainingModeProperty       = "ChainingMode"
	ChainingModeECB            = "ChainingModeECB"
	ChainingModeCBC            = "ChainingModeCBC"
	ChainingModeCTR            = "ChainingModeCTR"
	ChainingModeGCM            = "ChainingModeGCM"
	ObjectLengthProperty       = "ObjectLength"
	HashLengthProperty         = "HashLength"
	BlockLengthProperty        = "BlockLength"
	KeyLengthProperty          = "KeyLength"
	BcryptBufferLengthProperty = "BufferLength"
)

const (
	flagHMAC                  = 0x00000008 // BCRYPT_ALG_HANDLE_HMAC_FLAG
	flagNoKeyObject           = 0x00000010 // BCRYPT_NO_KEY_VALIDATION (unused; documented for clarity)
	flagUseSystemPreferredRNG = 0x00000002 // BCRYPT_USE_SYSTEM_PREFERRED_RNG
	flagSecure                = 0x00000040 // BCRYPT_SECURE_MEMORY? (unused)
	flagPadPKCS1              = 0x00000001
)

// NTSTATUS values that matter.
const (
	statusSuccess = 0x00000000
)

func utf16Ptr(s string) *uint16 {
	// syscall.UTF16PtrFromString never fails for the constant identifiers used
	// here, but handle the error defensively: a bad identifier must not panic.
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

func ntstatus(r uintptr) error {
	if r == statusSuccess {
		return nil
	} // A nonzero status is a failure; the value is reported verbatim.
	return fmt.Errorf("bcrypt status 0x%08x", uint32(r))
}

// Algorithm is an opened CNG algorithm provider.
type Algorithm struct {
	handle syscall.Handle
}

// OpenAlgorithm opens an algorithm provider by identifier, e.g. AESAlgorithm.
// An empty implementation string selects the default provider.
func OpenAlgorithm(id, implementation string) (*Algorithm, error) {
	if utf16Ptr(id) == nil {
		return nil, errors.New("cng: invalid algorithm identifier")
	}
	var h syscall.Handle
	var impl *uint16
	if implementation != "" {
		impl = utf16Ptr(implementation)
		if impl == nil {
			return nil, errors.New("cng: invalid provider identifier")
		}
	}
	r, _, _ := procOpenAlg.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(utf16Ptr(id))),
		uintptr(unsafe.Pointer(impl)),
		0)
	if err := ntstatus(r); err != nil {
		return nil, fmt.Errorf("BCryptOpenAlgorithmProvider(%s): %w", id, err)
	}
	a := &Algorithm{handle: h}
	runtime.SetFinalizer(a, func(a *Algorithm) { a.Close() })
	return a, nil
}

// OpenAlgorithmHMAC opens a hash algorithm for HMAC use.
func OpenAlgorithmHMAC(hashID string) (*Algorithm, error) {
	return OpenAlgorithm(hashID+HMACAlgorithmSuffix, "")
}

// SetProperty sets a provider property.
func (a *Algorithm) SetProperty(name, value string) error {
	v := utf16Ptr(value)
	if v == nil {
		return errors.New("cng: invalid property value")
	}
	r, _, _ := procSetProperty.Call(
		uintptr(a.handle),
		uintptr(unsafe.Pointer(utf16Ptr(name))),
		uintptr(unsafe.Pointer(v)),
		uintptr(2*len(value)),
		0)
	return ntstatus(r)
}

// SetChainingMode selects the block-cipher chaining mode.
func (a *Algorithm) SetChainingMode(mode string) error {
	return a.SetProperty(ChainingModeProperty, mode)
}

// GetUint reads an unsigned integer property from the provider.
func (a *Algorithm) GetUint(name string) (uint32, error) {
	var got uint32
	var cb uint32
	r, _, _ := procGetProperty.Call(
		uintptr(a.handle),
		uintptr(unsafe.Pointer(utf16Ptr(name))),
		uintptr(unsafe.Pointer(&got)),
		uintptr(unsafe.Sizeof(got)),
		uintptr(unsafe.Pointer(&cb)),
		0)
	if err := ntstatus(r); err != nil {
		return 0, fmt.Errorf("BCryptGetProperty(%s): %w", name, err)
	}
	return got, nil
}

// ObjectLength returns the size of the key-object buffer the provider wants.
func (a *Algorithm) ObjectLength() (int, error) {
	n, err := a.GetUint(ObjectLengthProperty)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// Close releases the provider handle.
func (a *Algorithm) Close() error {
	if a.handle == 0 {
		return nil
	}
	h := a.handle
	a.handle = 0
	r, _, _ := procCloseAlg.Call(uintptr(h), 0)
	runtime.SetFinalizer(a, nil)
	return ntstatus(r)
}

// Key is an opened symmetric key.
type Key struct {
	alg       *Algorithm
	handle    syscall.Handle
	keyObj    []byte
	secret    []byte
	destroyed bool
}

// GenerateSymmetricKey creates a symmetric key object from secret bytes.
func (a *Algorithm) GenerateSymmetricKey(secret []byte) (*Key, error) {
	objLen, err := a.ObjectLength()
	if err != nil {
		objLen = 0 // Some providers require no key object at all.
	}
	k := &Key{alg: a, secret: append([]byte(nil), secret...)}
	if objLen > 0 {
		k.keyObj = make([]byte, objLen)
	}
	var objPtr *byte
	if len(k.keyObj) > 0 {
		objPtr = &k.keyObj[0]
	}
	var sp *byte
	if len(secret) > 0 {
		sp = &secret[0]
	}
	r, _, _ := procGenSymKey.Call(
		uintptr(a.handle),
		uintptr(unsafe.Pointer(&k.handle)),
		uintptr(unsafe.Pointer(objPtr)),
		uintptr(objLen),
		uintptr(unsafe.Pointer(sp)),
		uintptr(len(secret)),
		0)
	if err := ntstatus(r); err != nil {
		return nil, fmt.Errorf("BCryptGenerateSymmetricKey: %w", err)
	}
	runtime.SetFinalizer(k, func(k *Key) { k.Destroy() })
	return k, nil
}

// Destroy wipes the key material and releases the key handle.  It is safe to
// call more than once.
func (k *Key) Destroy() {
	if k == nil || k.destroyed {
		return
	}
	k.destroyed = true
	if k.handle != 0 {
		procDestroyKey.Call(uintptr(k.handle))
		k.handle = 0
	}
	for _, b := range [][]byte{k.secret, k.keyObj} {
		for i := range b {
			b[i] = 0
		}
	}
	runtime.SetFinalizer(k, nil)
}

func (k *Key) crypt(proc *syscall.LazyProc, dst, src, iv []byte) (int, error) {
	if k.destroyed || k.handle == 0 {
		return 0, errors.New("cng: use of destroyed key")
	}
	if len(src) == 0 {
		return 0, nil
	}
	if len(dst) < len(src) {
		return 0, fmt.Errorf("cng: output buffer too small (%d < %d)", len(dst), len(src))
	}
	var ivPtr *byte
	if len(iv) > 0 {
		ivPtr = &iv[0]
	}
	var written uint32
	r, _, _ := proc.Call(
		uintptr(k.handle),
		uintptr(unsafe.Pointer(&src[0])),
		uintptr(len(src)),
		0, // no padding info
		uintptr(unsafe.Pointer(ivPtr)),
		uintptr(len(iv)),
		uintptr(unsafe.Pointer(&dst[0])),
		uintptr(len(dst)),
		uintptr(unsafe.Pointer(&written)),
		0)
	if err := ntstatus(r); err != nil {
		return 0, err
	}
	return int(written), nil
}

// EncryptBlockOrStream encrypts src into dst using the configured mode.
func (k *Key) Encrypt(dst, src, iv []byte) (int, error) {
	return k.crypt(procEncrypt, dst, src, iv)
}

// DecryptBlockOrStream decrypts src into dst using the configured mode.
func (k *Key) Decrypt(dst, src, iv []byte) (int, error) {
	return k.crypt(procDecrypt, dst, src, iv)
}

// Hash computes a one-shot CNG hash.
func Hash(algID string, data []byte) ([]byte, error) {
	a, err := OpenAlgorithm(algID, "")
	if err != nil {
		return nil, err
	}
	defer a.Close()
	hashLen, err := a.GetUint(HashLengthProperty)
	if err != nil {
		return nil, err
	}
	out := make([]byte, hashLen)
	var dp *byte
	if len(data) > 0 {
		dp = &data[0]
	}
	r, _, _ := procHash.Call(
		uintptr(a.handle),
		uintptr(unsafe.Pointer(dp)),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(hashLen),
		0)
	if err := ntstatus(r); err != nil {
		return nil, err
	}
	return out, nil
}

// Random fills b with random bytes from the system preferred RNG, which is
// backed by the Windows entropy sources.
func Random(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	r, _, _ := procGenerateRandom.Call(
		0,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		flagUseSystemPreferredRNG)
	return ntstatus(r)
}

// Available reports whether bcrypt.dll and the exports winsh needs can be
// resolved.  Callers use it to choose between the operating-system and
// standard-library backends.
func Available() bool {
	for _, p := range []*syscall.LazyProc{procOpenAlg, procGenSymKey, procEncrypt, procDecrypt, procGenerateRandom} {
		if err := p.Find(); err != nil {
			return false
		}
	}
	return true
}
