package keychain

import "github.com/roasbeef/btcd/btcec"

const (
	// KeyDerivationVersion is the version of the key derivation schema
	// defined below. We use a version as this means that we'll be able to
	// accept new seed in the future and be able to discern if the software
	// is compatible with the version of the seed.
	KeyDerivationVersion = 0

	// BIP0043Purpose is the "purpose" value that we'll use for the first
	// version or our key derivation scheme. All keys are expected to be
	// derived from this purpose, then the particular coin type of the
	// chain where the keys are to be used.  Slightly adhering to BIP0043
	// allows us to not deviate too far from a widely used standard, and
	// also fits into existing implementations of the BIP's template.
	//
	// NOTE: BRICK SQUUUUUAD.
	BIP0043Purpose = 1017
)

// KeyFamily represents a "family" of keys that will be used within various
// contracts created by lnd. These families are meant to be distinct branches
// within the HD key chain of the backing wallet. Usage of key families within
// the interface below are strict in order to promote integrability and the
// ability to restore all keys given a user master seed backup.
//
// The key derivation in this file follows the following hierarchy based on
// BIP43:
//
//   * m/1017'/coinType'/keyFamily/0/index
type KeyFamily uint32

const (
	// KeyFamilyMultiSig are keys to be used within multi-sig scripts.
	KeyFamilyMultiSig KeyFamily = 0

	// KeyFamilyRevocationBase are keys that are used within channels to
	// create revocation basepoints that the remote party will use to
	// create revocation keys for us.
	KeyFamilyRevocationBase = 1

	// KeyFamilyHtlcBase are keys used within channels that will be
	// combined with per-state randomness to produce public keys that will
	// be used in HTLC scripts.
	KeyFamilyHtlcBase KeyFamily = 2

	// KeyFamilyPaymentBase are keys used within channels that will be
	// combined with per-state randomness to produce public keys that will
	// be used in scripts that pay directly to us without any delay.
	KeyFamilyPaymentBase KeyFamily = 3

	// KeyFamilyDelayBase are keys used within channels that will be
	// combined with per-state randomness to produce public keys that will
	// be used in scripts that pay to us, but require a CSV delay before we
	// can sweep the funds.
	KeyFamilyDelayBase KeyFamily = 4

	// KeyFamilyRevocationRoot is a family of keys which will be used to
	// derive the root of a revocation tree for a particular channel.
	KeyFamilyRevocationRoot KeyFamily = 5

	// KeyFamilyNodeKey is a family of keys that will be used to derive
	// keys that will be advertised on the network to represent our current
	// "identity" within the network. Peers will need our latest node key
	// in order to establish a transport session with us on the Lightning
	// p2p level (BOLT-0008).
	KeyFamilyNodeKey KeyFamily = 6
)

// KeyLocator is a two-tuple that can be used to derive *any* key that has ever
// been used under the key derivation mechanisms described in this file.
// Version 0 of our key derivation schema uses the following BIP43-like
// derivation:
//
//   * m/201'/coinType'/keyFamily/0/index
//
// Our purpose is 201 (chosen arbitrary for now), and the coin type will vary
// based on which coin/chain the channels are being created on. The key family
// are actually just individual "accounts" in the nomenclature of BIP43. By
// default we assume a branch of 0 (external). Finally, the key index (which
// will vary per channel and use case) is the final element which allows us to
// deterministically derive keys.
type KeyLocator struct {
	// TODO(roasbeef); add the key scope as well??

	// Family is the family of key being identified.
	Family KeyFamily

	// Index is the precise index of the key being identified.
	Index uint32
}

// IsEmpty returns true if a KeyLocator is "empty". This may be the case where we
// learn of a key from a remote party for a contract, but don't know the
// precise details of its derivation (as we don't know the private key!).
func (k KeyLocator) IsEmpty() bool {
	return k.Family == 0 && k.Index == 0
}

// KeyDescriptor wraps a KeyLocator and also optionally includes a public key.
// Either the KeyLocator must be non-empty, or the public key pointer be
// non-nil. This will be used by the KeyRing interface to lookup arbitrary
// private keys, and also within the SignDescriptor struct to locate precisely
// which keys should be used for signing.
type KeyDescriptor struct {
	// KeyLocator is the internal KeyLocator of the descriptor.
	KeyLocator

	// PubKey is an optional public key that fully describes a target key.
	// If this is nil, the KeyLocator MUST NOT be empty.
	PubKey *btcec.PublicKey
}

// KeyRing is the primary interface that will be used to perform public
// derivation of various keys used within the peer-to-peer network, and also
// within any created contracts. All derivation required by the KeyRing is
// based off of public derivation, so a system with only an extended public key
// (for the particular purpose+family) can derive this set of keys.
type KeyRing interface {
	// DeriveNextKey attempts to derive the *next* key within the key
	// family (account in BIP43) specified. This method should return the
	// next external child within this branch.
	DeriveNextKey(keyFam KeyFamily) (KeyDescriptor, error)

	// DeriveKey attempts to derive an arbitrary key specified by the
	// passed KeyLocator. This may be used in several recovery scenarios,
	// or when manually rotating something like our current default node
	// key.
	DeriveKey(keyLoc KeyLocator) (KeyDescriptor, error)
}

// SecretKeyRing is a similar to the regular KeyRing interface, but it is also
// able to derive *private keys*. As this is a super-set of the regular
// KeyRing, we also expect the SecretKeyRing to implement the fully KeyRing
// interface. The methods in this struct may be used to extract the node key in
// order to accept inbound network connections, or to do manual signing for
// recovery purposes.
type SecretKeyRing interface {
	KeyRing

	// DerivePrivKey attempts to derive the private key that corresponds to
	// the passed key descriptor.
	DerivePrivKey(keyDesc KeyDescriptor) (*btcec.PrivateKey, error)

	// ScalarMult performs a scalar multiplication (ECDH-like operation)
	// between the target key descriptor and remote public key. The output
	// returned will be the sha256 of the resulting shared point serialized
	// in compressed format. If k is our private key, and P is the public
	// key, we perform the following operation:
	//
	//  sx := k*P
	//  s := sha256(sx.SerializeCompressed())
	ScalarMult(keyDesc KeyDescriptor, pubKey *btcec.PublicKey) ([]byte, error)
}

// TODO(roasbeef): extend to actually support scalar mult of key?
//  * would allow to push in initial handshake auth into interface as well
