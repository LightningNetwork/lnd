package sphinx

import (
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// OnionErrorEncrypter is a struct that's used to implement onion error
// encryption as defined within BOLT0004.
type OnionErrorEncrypter struct {
	sharedSecret Hash256
}

// NewOnionErrorEncrypter creates new instance of the onion encrypter backed by
// the passed router, with encryption to be doing using the passed
// ephemeralKey.
func NewOnionErrorEncrypter(router *Router,
	ephemeralKey *btcec.PublicKey) (*OnionErrorEncrypter, error) {

	sharedSecret, err := router.generateSharedSecret(ephemeralKey)
	if err != nil {
		return nil, err
	}

	return &OnionErrorEncrypter{
		sharedSecret: sharedSecret,
	}, nil
}

// Encode writes the encrypter's shared secret to the provided io.Writer.
func (o *OnionErrorEncrypter) Encode(w io.Writer) error {
	_, err := w.Write(o.sharedSecret[:])
	return err
}

// Decode restores the encrypter's share secret from the provided io.Reader.
func (o *OnionErrorEncrypter) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, o.sharedSecret[:])
	return err
}

// Circuit is used encapsulate the data which is needed for data deobfuscation.
type Circuit struct {
	// SessionKey is the key which have been used during generation of the
	// shared secrets.
	SessionKey *btcec.PrivateKey

	// PaymentPath is the pub keys of the nodes in the payment path.
	PaymentPath []*btcec.PublicKey
}

// Decode initializes the circuit from the byte stream.
func (c *Circuit) Decode(r io.Reader) error {
	var keyLength [1]byte
	if _, err := r.Read(keyLength[:]); err != nil {
		return err
	}

	sessionKeyData := make([]byte, uint8(keyLength[0]))
	if _, err := r.Read(sessionKeyData[:]); err != nil {
		return err
	}

	c.SessionKey, _ = btcec.PrivKeyFromBytes(btcec.S256(), sessionKeyData)
	var pathLength [1]byte
	if _, err := r.Read(pathLength[:]); err != nil {
		return err
	}
	c.PaymentPath = make([]*btcec.PublicKey, uint8(pathLength[0]))

	for i := 0; i < len(c.PaymentPath); i++ {
		var pubKeyData [btcec.PubKeyBytesLenCompressed]byte
		if _, err := r.Read(pubKeyData[:]); err != nil {
			return err
		}

		pubKey, err := btcec.ParsePubKey(pubKeyData[:], btcec.S256())
		if err != nil {
			return err
		}
		c.PaymentPath[i] = pubKey
	}

	return nil
}

// Encode writes converted circuit in the byte stream.
func (c *Circuit) Encode(w io.Writer) error {
	var keyLength [1]byte
	keyLength[0] = uint8(len(c.SessionKey.Serialize()))
	if _, err := w.Write(keyLength[:]); err != nil {
		return err
	}

	if _, err := w.Write(c.SessionKey.Serialize()); err != nil {
		return err
	}

	var pathLength [1]byte
	pathLength[0] = uint8(len(c.PaymentPath))
	if _, err := w.Write(pathLength[:]); err != nil {
		return err
	}

	for _, pubKey := range c.PaymentPath {
		if _, err := w.Write(pubKey.SerializeCompressed()); err != nil {
			return err
		}
	}

	return nil
}

// OnionErrorDecrypter is a struct that's used to decrypt onion errors in
// response to failed HTLC routing attempts according to BOLT#4.
type OnionErrorDecrypter struct {
	circuit *Circuit
}

// NewOnionErrorDecrypter creates new instance of onion decrypter.
func NewOnionErrorDecrypter(circuit *Circuit) *OnionErrorDecrypter {
	return &OnionErrorDecrypter{
		circuit: circuit,
	}
}
