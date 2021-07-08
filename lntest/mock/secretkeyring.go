package mock

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"

	"github.com/lightningnetwork/lnd/keychain"
)

// SecretKeyRing is a mock implementation of the SecretKeyRing interface.
type SecretKeyRing struct {
	RootKey *btcec.PrivateKey
	Fail    bool
}

// DeriveNextKey currently returns dummy values.
func (s *SecretKeyRing) DeriveNextKey(keyFam keychain.KeyFamily) (
	keychain.KeyDescriptor, error) {

	return keychain.KeyDescriptor{
		PubKey: s.RootKey.PubKey(),
	}, nil
}

// DeriveKey currently returns dummy values.
func (s *SecretKeyRing) DeriveKey(keyLoc keychain.KeyLocator) (keychain.KeyDescriptor,
	error) {
	if s.Fail {
		return keychain.KeyDescriptor{}, fmt.Errorf("fail")
	}
	return keychain.KeyDescriptor{
		PubKey: s.RootKey.PubKey(),
	}, nil
}

// DerivePrivKey currently returns dummy values.
func (s *SecretKeyRing) DerivePrivKey(keyDesc keychain.KeyDescriptor) (*btcec.PrivateKey,
	error) {
	return s.RootKey, nil
}

// ECDH currently returns dummy values.
func (s *SecretKeyRing) ECDH(_ keychain.KeyDescriptor, pubKey *btcec.PublicKey) ([32]byte,
	error) {

	return [32]byte{}, nil
}

// SignDigest signs the passed digest and ignores the KeyDescriptor.
func (s *SecretKeyRing) SignDigest(_ keychain.KeyDescriptor,
	digest [32]byte) (*btcec.Signature, error) {

	return s.RootKey.Sign(digest[:])
}

// SignDigestCompact signs the passed digest.
func (s *SecretKeyRing) SignDigestCompact(_ keychain.KeyDescriptor,
	digest [32]byte) ([]byte, error) {

	return btcec.SignCompact(btcec.S256(), s.RootKey, digest[:], true)
}
