package sphinx

import (
	"crypto/rand"

	"github.com/aead/chacha20"
	"github.com/btcsuite/btcd/btcec"
)

// PacketFiller is a function type to be specified by the caller to provide a
// stream of random bytes derived from a CSPRNG to fill out the starting packet
// in order to ensure we don't leak information on the true route length to the
// receiver. The packet filler may also use the session key to generate a set
// of filler bytes if it wishes to be deterministic.
type PacketFiller func(*btcec.PrivateKey, *[routingInfoSize]byte) error

// RandPacketFiller is a packet filler that reads a set of random bytes from a
// CSPRNG.
func RandPacketFiller(_ *btcec.PrivateKey, mixHeader *[routingInfoSize]byte) error {
	// Read out random bytes to fill out the rest of the starting packet
	// after the hop payload for the final node. This mitigates a privacy
	// leak that may reveal a lower bound on the true path length to the
	// receiver.
	if _, err := rand.Read(mixHeader[:]); err != nil {
		return err
	}

	return nil
}

// BlankPacketFiller is a packet filler that doesn't attempt to fill out the
// packet at all. It should ONLY be used for generating test vectors or other
// instances that required deterministic packet generation.
func BlankPacketFiller(_ *btcec.PrivateKey, _ *[routingInfoSize]byte) error {
	return nil
}

// DeterministicPacketFiller is a packet filler that generates a deterministic
// set of filler bytes by using chacha20 with a key derived from the session
// key.
func DeterministicPacketFiller(sessionKey *btcec.PrivateKey,
	mixHeader *[routingInfoSize]byte) error {

	// First, we'll generate a new key that'll be used to generate some
	// random bytes for our padding purposes. To derive this new key, we
	// essentially calculate: HMAC("pad", sessionKey).
	var sessionKeyBytes Hash256
	copy(sessionKeyBytes[:], sessionKey.Serialize())
	paddingKey := generateKey("pad", &sessionKeyBytes)

	// Now that we have our target key, we'll use chacha20 to generate a
	// series of random bytes directly into the passed mixHeader packet.
	var nonce [8]byte
	padCipher, err := chacha20.NewCipher(nonce[:], paddingKey[:])
	if err != nil {
		return err
	}
	padCipher.XORKeyStream(mixHeader[:], mixHeader[:])

	return nil
}
