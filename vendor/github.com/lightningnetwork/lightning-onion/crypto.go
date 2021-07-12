package sphinx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/aead/chacha20"
	"github.com/btcsuite/btcd/btcec"
)

const (
	// HMACSize is the length of the HMACs used to verify the integrity of
	// the onion. Any value lower than 32 will truncate the HMAC both
	// during onion creation as well as during the verification.
	HMACSize = 32
)

// Hash256 is a statically sized, 32-byte array, typically containing
// the output of a SHA256 hash.
type Hash256 [sha256.Size]byte

// SingleKeyECDH is an abstraction interface that hides the implementation of an
// ECDH operation against a specific private key. We use this abstraction for
// the long term keys which we eventually want to be able to keep in a hardware
// wallet or HSM.
type SingleKeyECDH interface {
	// PubKey returns the public key of the private key that is abstracted
	// away by the interface.
	PubKey() *btcec.PublicKey

	// ECDH performs a scalar multiplication (ECDH-like operation) between
	// the abstracted private key and a remote public key. The output
	// returned will be the sha256 of the resulting shared point serialized
	// in compressed format.
	ECDH(pubKey *btcec.PublicKey) ([32]byte, error)
}

// PrivKeyECDH is an implementation of the SingleKeyECDH in which we do have the
// full private key. This can be used to wrap a temporary key to conform to the
// SingleKeyECDH interface.
type PrivKeyECDH struct {
	// PrivKey is the private key that is used for the ECDH operation.
	PrivKey *btcec.PrivateKey
}

// PubKey returns the public key of the private key that is abstracted away by
// the interface.
//
// NOTE: This is part of the SingleKeyECDH interface.
func (p *PrivKeyECDH) PubKey() *btcec.PublicKey {
	return p.PrivKey.PubKey()
}

// ECDH performs a scalar multiplication (ECDH-like operation) between the
// abstracted private key and a remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//  sx := k*P
//  s := sha256(sx.SerializeCompressed())
//
// NOTE: This is part of the SingleKeyECDH interface.
func (p *PrivKeyECDH) ECDH(pub *btcec.PublicKey) ([32]byte, error) {
	s := &btcec.PublicKey{}
	s.X, s.Y = btcec.S256().ScalarMult(pub.X, pub.Y, p.PrivKey.D.Bytes())

	return sha256.Sum256(s.SerializeCompressed()), nil
}

// DecryptedError contains the decrypted error message and its sender.
type DecryptedError struct {
	// Sender is the node that sent the error. Note that a node may occur in
	// the path multiple times. If that is the case, the sender pubkey does
	// not tell the caller on which visit the error occurred.
	Sender *btcec.PublicKey

	// SenderIdx is the position of the error sending node in the path.
	// Index zero is the self node. SenderIdx allows to distinguish between
	// errors from nodes that occur in the path multiple times.
	SenderIdx int

	// Message is the decrypted error message.
	Message []byte
}

// zeroHMAC is the special HMAC value that allows the final node to determine
// if it is the payment destination or not.
var zeroHMAC [HMACSize]byte

// calcMac calculates HMAC-SHA-256 over the message using the passed secret key
// as input to the HMAC.
func calcMac(key [keyLen]byte, msg []byte) [HMACSize]byte {
	hmac := hmac.New(sha256.New, key[:])
	hmac.Write(msg)
	h := hmac.Sum(nil)

	var mac [HMACSize]byte
	copy(mac[:], h[:HMACSize])

	return mac
}

// xor computes the byte wise XOR of a and b, storing the result in dst. Only
// the frist `min(len(a), len(b))` bytes will be xor'd.
func xor(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// generateKey generates a new key for usage in Sphinx packet
// construction/processing based off of the denoted keyType. Within Sphinx
// various keys are used within the same onion packet for padding generation,
// MAC generation, and encryption/decryption.
func generateKey(keyType string, sharedKey *Hash256) [keyLen]byte {
	mac := hmac.New(sha256.New, []byte(keyType))
	mac.Write(sharedKey[:])
	h := mac.Sum(nil)

	var key [keyLen]byte
	copy(key[:], h[:keyLen])

	return key
}

// generateCipherStream generates a stream of cryptographic psuedo-random bytes
// intended to be used to encrypt a message using a one-time-pad like
// construction.
func generateCipherStream(key [keyLen]byte, numBytes uint) []byte {
	var (
		nonce [8]byte
	)
	cipher, err := chacha20.NewCipher(nonce[:], key[:])
	if err != nil {
		panic(err)
	}
	output := make([]byte, numBytes)
	cipher.XORKeyStream(output, output)

	return output
}

// computeBlindingFactor for the next hop given the ephemeral pubKey and
// sharedSecret for this hop. The blinding factor is computed as the
// sha-256(pubkey || sharedSecret).
func computeBlindingFactor(hopPubKey *btcec.PublicKey,
	hopSharedSecret []byte) Hash256 {

	sha := sha256.New()
	sha.Write(hopPubKey.SerializeCompressed())
	sha.Write(hopSharedSecret)

	var hash Hash256
	copy(hash[:], sha.Sum(nil))
	return hash
}

// blindGroupElement blinds the group element P by performing scalar
// multiplication of the group element by blindingFactor: blindingFactor * P.
func blindGroupElement(hopPubKey *btcec.PublicKey, blindingFactor []byte) *btcec.PublicKey {
	newX, newY := btcec.S256().ScalarMult(hopPubKey.X, hopPubKey.Y, blindingFactor[:])
	return &btcec.PublicKey{btcec.S256(), newX, newY}
}

// blindBaseElement blinds the groups's generator G by performing scalar base
// multiplication using the blindingFactor: blindingFactor * G.
func blindBaseElement(blindingFactor []byte) *btcec.PublicKey {
	newX, newY := btcec.S256().ScalarBaseMult(blindingFactor)
	return &btcec.PublicKey{btcec.S256(), newX, newY}
}

// sharedSecretGenerator is an interface that abstracts away exactly *how* the
// shared secret for each hop is generated.
//
// TODO(roasbef): rename?
type sharedSecretGenerator interface {
	// generateSharedSecret given a public key, generates a shared secret
	// using private data of the underlying sharedSecretGenerator.
	generateSharedSecret(dhKey *btcec.PublicKey) (Hash256, error)
}

// generateSharedSecret generates the shared secret by given ephemeral key.
func (r *Router) generateSharedSecret(dhKey *btcec.PublicKey) (Hash256, error) {
	var sharedSecret Hash256

	// Ensure that the public key is on our curve.
	if !btcec.S256().IsOnCurve(dhKey.X, dhKey.Y) {
		return sharedSecret, ErrInvalidOnionKey
	}

	// Compute our shared secret.
	return r.onionKey.ECDH(dhKey)
}

// onionEncrypt obfuscates the data with compliance with BOLT#4. As we use a
// stream cipher, calling onionEncrypt on an already encrypted piece of data
// will decrypt it.
func onionEncrypt(sharedSecret *Hash256, data []byte) []byte {
	p := make([]byte, len(data))

	ammagKey := generateKey("ammag", sharedSecret)
	streamBytes := generateCipherStream(ammagKey, uint(len(data)))
	xor(p, data, streamBytes)

	return p
}

// onionErrorLength is the expected length of the onion error message.
// Including padding, all messages on the wire should be 256 bytes. We then add
// the size of the sha256 HMAC as well.
const onionErrorLength = 2 + 2 + 256 + sha256.Size

// DecryptError attempts to decrypt the passed encrypted error response. The
// onion failure is encrypted in backward manner, starting from the node where
// error have occurred. As a result, in order to decrypt the error we need get
// all shared secret and apply decryption in the reverse order. A structure is
// returned that contains the decrypted error message and information on the
// sender.
func (o *OnionErrorDecrypter) DecryptError(encryptedData []byte) (
	*DecryptedError, error) {

	// Ensure the error message length is as expected.
	if len(encryptedData) != onionErrorLength {
		return nil, fmt.Errorf("invalid error length: "+
			"expected %v got %v", onionErrorLength,
			len(encryptedData))
	}

	sharedSecrets, err := generateSharedSecrets(
		o.circuit.PaymentPath,
		o.circuit.SessionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v",
			err)
	}

	var (
		sender      int
		msg         []byte
		dummySecret Hash256
	)
	copy(dummySecret[:], bytes.Repeat([]byte{1}, 32))

	// We'll iterate a constant amount of hops to ensure that we don't give
	// away an timing information pertaining to the position in the route
	// that the error emanated from.
	for i := 0; i < NumMaxHops; i++ {
		var sharedSecret Hash256

		// If we've already found the sender, then we'll use our dummy
		// secret to continue decryption attempts to fill out the rest
		// of the loop. Otherwise, we'll use the next shared secret in
		// line.
		if sender != 0 || i > len(sharedSecrets)-1 {
			sharedSecret = dummySecret
		} else {
			sharedSecret = sharedSecrets[i]
		}

		// With the shared secret, we'll now strip off a layer of
		// encryption from the encrypted error payload.
		encryptedData = onionEncrypt(&sharedSecret, encryptedData)

		// Next, we'll need to separate the data, from the MAC itself
		// so we can reconstruct and verify it.
		expectedMac := encryptedData[:sha256.Size]
		data := encryptedData[sha256.Size:]

		// With the data split, we'll now re-generate the MAC using its
		// specified key.
		umKey := generateKey("um", &sharedSecret)
		h := hmac.New(sha256.New, umKey[:])
		h.Write(data)

		// If the MAC matches up, then we've found the sender of the
		// error and have also obtained the fully decrypted message.
		realMac := h.Sum(nil)
		if hmac.Equal(realMac, expectedMac) && sender == 0 {
			sender = i + 1
			msg = data
		}
	}

	// If the sender index is still zero, then we haven't found the sender,
	// meaning we've failed to decrypt.
	if sender == 0 {
		return nil, errors.New("unable to retrieve onion failure")
	}

	return &DecryptedError{
		SenderIdx: sender,
		Sender:    o.circuit.PaymentPath[sender-1],
		Message:   msg,
	}, nil
}

// EncryptError is used to make data obfuscation using the generated shared
// secret.
//
// In context of Lightning Network is either used by the nodes in order to make
// initial obfuscation with the creation of the hmac or by the forwarding nodes
// for backward failure obfuscation of the onion failure blob. By obfuscating
// the onion failure on every node in the path we are adding additional step of
// the security and barrier for malware nodes to retrieve valuable information.
// The reason for using onion obfuscation is to not give
// away to the nodes in the payment path the information about the exact
// failure and its origin.
func (o *OnionErrorEncrypter) EncryptError(initial bool, data []byte) []byte {
	if initial {
		umKey := generateKey("um", &o.sharedSecret)
		hash := hmac.New(sha256.New, umKey[:])
		hash.Write(data)
		h := hash.Sum(nil)
		data = append(h, data...)
	}

	return onionEncrypt(&o.sharedSecret, data)
}
