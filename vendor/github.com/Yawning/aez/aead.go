// aead.go - crypto/cipher.AEAD wrapper
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package aez

import (
	"crypto/cipher"
	"errors"
)

var errOpen = errors.New("aez: Message authentication failed")

const (
	aeadNonceSize = 16
	aeadOverhead  = 16
)

// AeadAEZ is AEZ wrapped in the crypto/cipher.AEAD interface.  It expects
// a 16 byte nonce, and uses a 16 byte tag, per the recommended defaults in
// the specification.
//
// The AEZ primitive itself supports a vector of authenticated data, variable
// length nonces, and variable length authentication tags.  Users who require
// such functionality should investigate the one-shot Encrypt/Decrypt calls
// instead.
type AeadAEZ struct {
	key [extractedKeySize]byte
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (a *AeadAEZ) NonceSize() int {
	return aeadNonceSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (a *AeadAEZ) Overhead() int {
	return aeadOverhead
}

// Reset clears the sensitive keying material from the datastructure such
// that it will no longer be in memory.
func (a *AeadAEZ) Reset() {
	memwipe(a.key[:])
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice.  The nonce must be NonceSize() bytes long.
//
// The nonce additionally should be unique for all time, for a given key,
// however the AEZ primitive does provide nonce-reuse misuse-resistance,
// see the paper for more details (MRAE).
func (a *AeadAEZ) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != aeadNonceSize {
		panic("aez: incorrect nonce length given to AEZ")
	}

	var ad [][]byte
	if additionalData != nil {
		ad = append(ad, additionalData)
	}
	// WARNING: The AEAD interface expects plaintext/dst overlap to be allowed.
	c := Encrypt(a.key[:], nonce, ad, aeadOverhead, plaintext, nil)
	dst = append(dst, c...)

	return dst
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
func (a *AeadAEZ) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != aeadNonceSize {
		panic("aez: incorrect nonce length given to AEZ")
	}

	var ad [][]byte
	if additionalData != nil {
		ad = append(ad, additionalData)
	}
	// WARNING: The AEAD interface expects ciphertext/dst overlap to be allowed.
	d, ok := Decrypt(a.key[:], nonce, ad, aeadOverhead, ciphertext, nil)
	if !ok {
		return nil, errOpen
	}
	dst = append(dst, d...)

	return dst, nil
}

// New returns AEZ wrapped in a new cipher.AEAD instance, with the recommended
// nonce and tag lengths.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, errors.New("aez: Invalid key size")
	}
	a := new(AeadAEZ)
	extract(key, &a.key)
	return a, nil
}
