package lnencrypt

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lntest/channels"
	"github.com/lightningnetwork/lnd/lntest/mock"
)

var (
	privKey, _ = btcec.PrivKeyFromBytes(btcec.S256(),
		channels.AlicesPrivKey)
)

// TestEncryptDecryptPayload tests that given a static key, we're able to
// properly decrypt and encrypted payload. We also test that we'll reject a
// ciphertext that has been modified.
func TestEncryptDecryptPayload(t *testing.T) {
	t.Parallel()

	payloadCases := []struct {
		// plaintext is the string that we'll be encrypting.
		plaintext []byte

		// mutator allows a test case to modify the ciphertext before
		// we attempt to decrypt it.
		mutator func(*[]byte)

		// valid indicates if this test should pass or fail.
		valid bool
	}{
		// Proper payload, should decrypt.
		{
			plaintext: []byte("payload test plain text"),
			mutator:   nil,
			valid:     true,
		},

		// Mutator modifies cipher text, shouldn't decrypt.
		{
			plaintext: []byte("payload test plain text"),
			mutator: func(p *[]byte) {
				// Flip a byte in the payload to render it invalid.
				(*p)[0] ^= 1
			},
			valid: false,
		},

		// Cipher text is too small, shouldn't decrypt.
		{
			plaintext: []byte("payload test plain text"),
			mutator: func(p *[]byte) {
				// Modify the cipher text to be zero length.
				*p = []byte{}
			},
			valid: false,
		},
	}

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	for i, payloadCase := range payloadCases {
		var cipherBuffer bytes.Buffer

		// First, we'll encrypt the passed payload with our scheme.
		payloadReader := bytes.NewBuffer(payloadCase.plaintext)
		err := EncryptPayloadToWriter(
			*payloadReader, &cipherBuffer, keyRing,
		)
		if err != nil {
			t.Fatalf("unable encrypt paylaod: %v", err)
		}

		// If we have a mutator, then we'll wrong the mutator over the
		// cipher text, then reset the main buffer and re-write the new
		// cipher text.
		if payloadCase.mutator != nil {
			cipherText := cipherBuffer.Bytes()

			payloadCase.mutator(&cipherText)

			cipherBuffer.Reset()
			cipherBuffer.Write(cipherText)
		}

		plaintext, err := DecryptPayloadFromReader(&cipherBuffer, keyRing)

		switch {
		// If this was meant to be a valid decryption, but we failed,
		// then we'll return an error.
		case err != nil && payloadCase.valid:
			t.Fatalf("unable to decrypt valid payload case %v", i)

		// If this was meant to be an invalid decryption, and we didn't
		// fail, then we'll return an error.
		case err == nil && !payloadCase.valid:
			t.Fatalf("payload was invalid yet was able to decrypt")
		}

		// Only if this case was mean to be valid will we ensure the
		// resulting decrypted plaintext matches the original input.
		if payloadCase.valid &&
			!bytes.Equal(plaintext, payloadCase.plaintext) {
			t.Fatalf("#%v: expected %v, got %v: ", i,
				payloadCase.plaintext, plaintext)
		}
	}
}

// TestInvalidKeyEncryption tests that encryption fails if we're unable to
// obtain a valid key.
func TestInvalidKeyEncryption(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	keyRing := &mock.SecretKeyRing{}
	keyRing.Fail = true
	err := EncryptPayloadToWriter(b, &b, keyRing)
	if err == nil {
		t.Fatalf("expected error due to fail key gen")
	}
}

// TestInvalidKeyDecrytion tests that decryption fails if we're unable to
// obtain a valid key.
func TestInvalidKeyDecrytion(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	keyRing := &mock.SecretKeyRing{}
	keyRing.Fail = true
	_, err := DecryptPayloadFromReader(&b, keyRing)
	if err == nil {
		t.Fatalf("expected error due to fail key gen")
	}
}
