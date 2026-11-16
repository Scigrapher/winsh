package moshcrypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// This file implements the OCB authenticated-encryption mode exactly as
// specified in RFC 7253 (which is byte-for-byte the algorithm published as
// draft-krovetz-ocb-03, the version mosh's AES-128-OCB cipher suite uses).
//
// It is written from the specification's pseudocode.  The unit tests in
// ocb_test.go check it
// against the published Appendix-A vectors and cross-check the Windows CNG
// and Go standard-library AES backends against each other.
//
// winsh only needs the byte-aligned, 128-bit-tag variant, so that is what is
// implemented; the code refuses anything else instead of silently producing
// the wrong answer.

// BlockSize is OCB's block size, fixed by AES.
const BlockSize = 16

// TagSize is the authentication tag length in octets that the mosh cipher
// suite uses (128 bits).
const TagSize = 16

// MaximumNonce is the longest nonce OCB accepts: 120 bits, which is what
// mosh uses.
const MaximumNonce = 15

var (
	// ErrOpen is returned when authentication fails.  Callers must treat it
	// identically to a parse failure: never distinguish "wrong key" from
	// "corrupted packet" to a remote peer.
	ErrOpen = errors.New("moshcrypto: authentication failed")
	// ErrKeyLimit is returned once a key has encrypted the maximum amount of
	// data OCB tolerates (RFC 7253 section 5).
	ErrKeyLimit = errors.New("moshcrypto: key has encrypted too much data")
)

// stretchDelimiterMask is the mask of the "1" delimiter bit in the stretched
// nonce.  It exists as a variable only so the debug test can probe it.
var stretchDelimiterMask byte = 0x01

// OCB is an AES-OCB128 context bound to one key.  It is not safe for
// concurrent use by multiple goroutines; winsh uses it from a single
// network goroutine.
type OCB struct {
	c       blockCipher
	lStar   [BlockSize]byte
	lDollar [BlockSize]byte
	l       [][BlockSize]byte
	key     []byte
}

// NewOCB creates a context for a 128-bit key, the only key size the mosh
// cipher suite defines.
func NewOCB(key []byte) (*OCB, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("moshcrypto: OCB key must be 16 octets, got %d", len(key))
	}
	c, err := newBlockCipher(key)
	if err != nil {
		return nil, err
	}
	o := &OCB{c: c, key: append([]byte(nil), key...)}
	if err := c.EncryptBlock(o.lStar[:], make([]byte, BlockSize)); err != nil {
		c.Destroy()
		return nil, err
	}
	doubleInto(&o.lDollar, &o.lStar)
	// l[i] = double^(i+1)(L_$): the RFC numbers the per-block offsets starting
	// one doubling past L_$.
	o.l = make([][BlockSize]byte, 64)
	doubleInto(&o.l[0], &o.lDollar)
	for i := 1; i < len(o.l); i++ {
		doubleInto(&o.l[i], &o.l[i-1])
	}
	return o, nil
}

// Destroy wipes key material.  It is idempotent.
func (o *OCB) Destroy() {
	if o == nil {
		return
	}
	if o.c != nil {
		o.c.Destroy()
		o.c = nil
	}
	for i := range o.key {
		o.key[i] = 0
	}
}

// Backend names the AES implementation in use, e.g. "windows/cng-bcrypt-aes".
func (o *OCB) Backend() string {
	if o == nil || o.c == nil {
		return "destroyed"
	}
	return o.c.Backend()
}

// doubleInto computes the GF(2^128) doubling defined in RFC 7253 section 2.
func doubleInto(dst *[BlockSize]byte, src *[BlockSize]byte) {
	carry := src[0] >> 7
	for i := 0; i < BlockSize-1; i++ {
		dst[i] = src[i]<<1 | src[i+1]>>7
	}
	dst[BlockSize-1] = src[BlockSize-1] << 1
	if carry != 0 {
		dst[BlockSize-1] ^= 0x87 // the x^128 + x^7 + x^2 + x + 1 reduction
	}
}

func ntz(i int) int {
	n := 0
	for i&1 == 0 {
		i >>= 1
		n++
	}
	return n
}

// hash implements RFC 7253 section 4.1 (HASH), used for associated data.
func (o *OCB) hash(dst *[BlockSize]byte, ad []byte) {
	for i := range dst {
		(*dst)[i] = 0
	}
	var offset [BlockSize]byte
	var block [BlockSize]byte
	var in [BlockSize]byte
	m := len(ad) / BlockSize
	for i := 1; i <= m; i++ {
		for j := range offset {
			offset[j] ^= o.l[ntz(i)][j]
		}
		src := ad[(i-1)*BlockSize : i*BlockSize]
		for j := range in {
			in[j] = src[j] ^ offset[j]
		}
		if err := o.c.EncryptBlock(block[:], in[:]); err != nil {
			// A block-cipher failure here means the backend is broken;
			// surface it as an authentication failure via the caller.
			return
		}
		for j := range dst {
			(*dst)[j] ^= block[j]
		}
	}
	tail := ad[m*BlockSize:]
	if len(tail) > 0 {
		for j := range offset {
			offset[j] ^= o.lStar[j]
		}
		padded := make([]byte, BlockSize)
		copy(padded, tail)
		padded[len(tail)] = 0x80
		for j := range in {
			in[j] = padded[j] ^ offset[j]
		}
		if err := o.c.EncryptBlock(block[:], in[:]); err != nil {
			return
		}
		for j := range dst {
			(*dst)[j] ^= block[j]
		}
	}
}

// stretch builds Offset_0 for a byte-aligned nonce, following the RFC's
// "Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N".
func (o *OCB) stretch(nonce []byte) (*[BlockSize]byte, error) {
	if len(nonce) == 0 || len(nonce) > MaximumNonce {
		return nil, fmt.Errorf("moshcrypto: OCB nonce must be 1..%d octets", MaximumNonce)
	}
	// RFC 7253: Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N.
	// TAGLEN is 128, so the leading seven bits are zero; N is byte-aligned, so the
	// delimiter bit is the high bit of the octet just before N, and N ends flush
	// with the block.
	var nb [BlockSize]byte
	// The delimiter bit sits at bit index 127-8*len(nonce).  Its exact
	// position within that octet is pinned by the published test vectors.
	nb[BlockSize-1-len(nonce)] |= stretchDelimiterMask
	copy(nb[BlockSize-len(nonce):], nonce)

	bottom := int(nb[BlockSize-1] & 0x3F)
	kn := nb
	kn[BlockSize-1] &= 0xC0
	var ktop [BlockSize]byte
	if err := o.c.EncryptBlock(ktop[:], kn[:]); err != nil {
		return nil, err
	}
	var stretch [BlockSize + 8]byte
	copy(stretch[:], ktop[:])
	// RFC 7253: Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]), i.e. the
	// first eight octets XOR the *shifted-by-one* window, not the second half.
	for i := 0; i < 8; i++ {
		stretch[BlockSize+i] = ktop[i] ^ ktop[i+1]
	}
	// Offset_0 is the 128-bit window Stretch[bottom, bottom+128), which is not
	// byte aligned in general, so it has to be reassembled bit by bit.  bottom
	// is at most 63, so the window always fits in the 24-octet stretch.
	var offset [BlockSize]byte
	byteShift, bitShift := bottom/8, bottom%8
	for i := 0; i < BlockSize; i++ {
		v := stretch[byteShift+i] << uint(bitShift)
		if bitShift != 0 {
			v |= stretch[byteShift+i+1] >> uint(8-bitShift)
		}
		offset[i] = v
	}
	return &offset, nil
}

// Seal encrypts and authenticates plaintext, appending ciphertext||tag to dst.
// dst must have room for len(plaintext)+TagSize bytes.  Nonce reuse under one
// key destroys both confidentiality and authenticity: callers must use a
// fresh nonce every time.
func (o *OCB) Seal(dst, nonce, ad, plaintext []byte) error {
	if o == nil || o.c == nil {
		return ErrOpen
	}
	if len(dst) < len(plaintext)+TagSize {
		return errors.New("moshcrypto: Seal needs room for ciphertext plus tag")
	}
	offset, err := o.stretch(nonce)
	if err != nil {
		return err
	}
	var adSum [BlockSize]byte
	if len(ad) > 0 {
		o.hash(&adSum, ad)
	} else {
		adSum = [BlockSize]byte{}
	}

	var checksum [BlockSize]byte
	var nextOffset, block, in [BlockSize]byte
	m := len(plaintext) / BlockSize
	for i := 1; i <= m; i++ {
		for j := range nextOffset {
			nextOffset[j] = offset[j] ^ o.l[ntz(i)][j]
		}
		*offset = nextOffset
		src := plaintext[(i-1)*BlockSize : i*BlockSize]
		for j := range in {
			in[j] = src[j] ^ offset[j]
		}
		if err := o.c.EncryptBlock(block[:], in[:]); err != nil {
			return err
		}
		out := dst[(i-1)*BlockSize : i*BlockSize]
		for j := range out {
			out[j] = block[j] ^ offset[j]
		}
		for j := range checksum {
			checksum[j] ^= src[j]
		}
	}
	tail := plaintext[m*BlockSize:]
	var tagOffset [BlockSize]byte
	if len(tail) > 0 {
		for j := range tagOffset {
			tagOffset[j] = offset[j] ^ o.lStar[j]
		}
		var pad [BlockSize]byte
		if err := o.c.EncryptBlock(pad[:], tagOffset[:]); err != nil {
			return err
		}
		out := dst[m*BlockSize:]
		for j := range tail {
			out[j] = tail[j] ^ pad[j]
		}
		for j, x := range tail {
			checksum[j] ^= x
		}
		checksum[len(tail)] ^= 0x80
	} else {
		tagOffset = *offset
	}
	var tagInput [BlockSize]byte
	for j := range tagInput {
		tagInput[j] = checksum[j] ^ tagOffset[j] ^ o.lDollar[j]
	}
	var tag [BlockSize]byte
	if err := o.c.EncryptBlock(tag[:], tagInput[:]); err != nil {
		return err
	}
	for j := range adSum {
		tag[j] ^= adSum[j]
	}
	copy(dst[len(plaintext):], tag[:TagSize])
	return nil
}

// Open verifies and decrypts ciphertext||tag, writing the plaintext to dst.
// It returns ErrOpen if the tag does not verify; dst is untouched in that
// case.
func (o *OCB) Open(dst, nonce, ad, ciphertext []byte) error {
	if o == nil || o.c == nil {
		return ErrOpen
	}
	if len(ciphertext) < TagSize {
		return ErrOpen
	}
	body := ciphertext[:len(ciphertext)-TagSize]
	got := ciphertext[len(ciphertext)-TagSize:]
	if len(dst) < len(body) {
		return errors.New("moshcrypto: Open needs room for the plaintext")
	}
	offset, err := o.stretch(nonce)
	if err != nil {
		return err
	}
	var adSum [BlockSize]byte
	if len(ad) > 0 {
		o.hash(&adSum, ad)
	} else {
		adSum = [BlockSize]byte{}
	}

	var checksum [BlockSize]byte
	var nextOffset, block, in [BlockSize]byte
	m := len(body) / BlockSize
	for i := 1; i <= m; i++ {
		for j := range nextOffset {
			nextOffset[j] = offset[j] ^ o.l[ntz(i)][j]
		}
		*offset = nextOffset
		src := body[(i-1)*BlockSize : i*BlockSize]
		for j := range in {
			in[j] = src[j] ^ offset[j]
		}
		if err := o.c.DecryptBlock(block[:], in[:]); err != nil {
			return err
		}
		out := dst[(i-1)*BlockSize : i*BlockSize]
		for j := range out {
			out[j] = block[j] ^ offset[j]
		}
		for j := range checksum {
			checksum[j] ^= out[j]
		}
	}
	tail := body[m*BlockSize:]
	var tagOffset [BlockSize]byte
	if len(tail) > 0 {
		for j := range tagOffset {
			tagOffset[j] = offset[j] ^ o.lStar[j]
		}
		var pad [BlockSize]byte
		if err := o.c.EncryptBlock(pad[:], tagOffset[:]); err != nil {
			return err
		}
		out := dst[m*BlockSize:]
		for j := range tail {
			out[j] = tail[j] ^ pad[j]
		}
		for j, x := range out[:len(tail)] {
			checksum[j] ^= x
		}
		checksum[len(tail)] ^= 0x80
	} else {
		tagOffset = *offset
	}
	var tagInput [BlockSize]byte
	for j := range tagInput {
		tagInput[j] = checksum[j] ^ tagOffset[j] ^ o.lDollar[j]
	}
	var tag [BlockSize]byte
	if err := o.c.EncryptBlock(tag[:], tagInput[:]); err != nil {
		return err
	}
	for j := range adSum {
		tag[j] ^= adSum[j]
	}
	if subtle.ConstantTimeCompare(tag[:TagSize], got) != 1 {
		for i := range dst[:len(body)] {
			dst[i] = 0
		}
		return ErrOpen
	}
	return nil
}
