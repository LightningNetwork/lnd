package bakery

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"golang.org/x/crypto/nacl/box"
	"gopkg.in/errgo.v1"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

type caveatRecord struct {
	RootKey   []byte
	Condition string
}

// caveatJSON defines the format of a V1 JSON-encoded third party caveat id.
type caveatJSON struct {
	ThirdPartyPublicKey *PublicKey
	FirstPartyPublicKey *PublicKey
	Nonce               []byte
	Id                  string
}

// encodeCaveat encrypts a third-party caveat with the given condtion
// and root key. The thirdPartyInfo key holds information about the
// third party we're encrypting the caveat for; the key is the
// public/private key pair of the party that's adding the caveat.
//
// The caveat will be encoded according to the version information
// found in thirdPartyInfo.
func encodeCaveat(
	condition string,
	rootKey []byte,
	thirdPartyInfo ThirdPartyInfo,
	key *KeyPair,
	ns *checkers.Namespace,
) ([]byte, error) {
	switch thirdPartyInfo.Version {
	case Version0, Version1:
		return encodeCaveatV1(condition, rootKey, &thirdPartyInfo.PublicKey, key)
	case Version2:
		return encodeCaveatV2(condition, rootKey, &thirdPartyInfo.PublicKey, key)
	default:
		// Version 3 or later - use V3.
		return encodeCaveatV3(condition, rootKey, &thirdPartyInfo.PublicKey, key, ns)
	}
}

// encodeCaveatV1 creates a JSON-encoded third-party caveat
// with the given condtion and root key. The thirdPartyPubKey key
// represents the public key of the third party we're encrypting
// the caveat for; the key is the public/private key pair of the party
// that's adding the caveat.
func encodeCaveatV1(
	condition string,
	rootKey []byte,
	thirdPartyPubKey *PublicKey,
	key *KeyPair,
) ([]byte, error) {
	var nonce [NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errgo.Notef(err, "cannot generate random number for nonce")
	}
	plain := caveatRecord{
		RootKey:   rootKey,
		Condition: condition,
	}
	plainData, err := json.Marshal(&plain)
	if err != nil {
		return nil, errgo.Notef(err, "cannot marshal %#v", &plain)
	}
	sealed := box.Seal(nil, plainData, &nonce, thirdPartyPubKey.boxKey(), key.Private.boxKey())
	id := caveatJSON{
		ThirdPartyPublicKey: thirdPartyPubKey,
		FirstPartyPublicKey: &key.Public,
		Nonce:               nonce[:],
		Id:                  base64.StdEncoding.EncodeToString(sealed),
	}
	data, err := json.Marshal(id)
	if err != nil {
		return nil, errgo.Notef(err, "cannot marshal %#v", id)
	}
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(buf, data)
	return buf, nil
}

// encodeCaveatV2 creates a version 2 third-party caveat.
func encodeCaveatV2(
	condition string,
	rootKey []byte,
	thirdPartyPubKey *PublicKey,
	key *KeyPair,
) ([]byte, error) {
	return encodeCaveatV2V3(Version2, condition, rootKey, thirdPartyPubKey, key, nil)
}

// encodeCaveatV3 creates a version 3 third-party caveat.
func encodeCaveatV3(
	condition string,
	rootKey []byte,
	thirdPartyPubKey *PublicKey,
	key *KeyPair,
	ns *checkers.Namespace,
) ([]byte, error) {
	return encodeCaveatV2V3(Version3, condition, rootKey, thirdPartyPubKey, key, ns)
}

const publicKeyPrefixLen = 4

// version3CaveatMinLen holds an underestimate of the
// minimum length of a version 3 caveat.
const version3CaveatMinLen = 1 + 4 + 32 + 24 + box.Overhead + 1

// encodeCaveatV3 creates a version 2 or version 3 third-party caveat.
//
// The format has the following packed binary fields (note
// that all fields up to and including the nonce are the same
// as the v2 format):
//
// 	version 2 or 3 [1 byte]
// 	first 4 bytes of third-party Curve25519 public key [4 bytes]
// 	first-party Curve25519 public key [32 bytes]
// 	nonce [24 bytes]
// 	encrypted secret part [rest of message]
//
// The encrypted part encrypts the following fields
// with box.Seal:
//
// 	version 2 or 3 [1 byte]
// 	length of root key [n: uvarint]
// 	root key [n bytes]
// 	length of encoded namespace [n: uvarint] (Version 3 only)
// 	encoded namespace [n bytes] (Version 3 only)
// 	condition [rest of encrypted part]
func encodeCaveatV2V3(
	version Version,
	condition string,
	rootKey []byte,
	thirdPartyPubKey *PublicKey,
	key *KeyPair,
	ns *checkers.Namespace,
) ([]byte, error) {

	var nsData []byte
	if version >= Version3 {
		data, err := ns.MarshalText()
		if err != nil {
			return nil, errgo.Mask(err)
		}
		nsData = data
	}
	// dataLen is our estimate of how long the data will be.
	// As we always use append, this doesn't have to be strictly
	// accurate but it's nice to avoid allocations.
	dataLen := 0 +
		1 + // version
		publicKeyPrefixLen +
		KeyLen +
		NonceLen +
		box.Overhead +
		1 + // version
		uvarintLen(uint64(len(rootKey))) +
		len(rootKey) +
		uvarintLen(uint64(len(nsData))) +
		len(nsData) +
		len(condition)

	var nonce [NonceLen]byte = uuidGen.Next()

	data := make([]byte, 0, dataLen)
	data = append(data, byte(version))
	data = append(data, thirdPartyPubKey.Key[:publicKeyPrefixLen]...)
	data = append(data, key.Public.Key[:]...)
	data = append(data, nonce[:]...)
	secret := encodeSecretPartV2V3(version, condition, rootKey, nsData)
	return box.Seal(data, secret, &nonce, thirdPartyPubKey.boxKey(), key.Private.boxKey()), nil
}

// encodeSecretPartV2V3 creates a version 2 or version 3 secret part of the third party
// caveat. The returned data is not encrypted.
//
// The format has the following packed binary fields:
// version 2 or 3 [1 byte]
// root key length [n: uvarint]
// root key [n bytes]
// namespace length [n: uvarint] (v3 only)
// namespace [n bytes] (v3 only)
// predicate [rest of message]
func encodeSecretPartV2V3(version Version, condition string, rootKey, nsData []byte) []byte {
	data := make([]byte, 0, 1+binary.MaxVarintLen64+len(rootKey)+len(condition))
	data = append(data, byte(version)) // version
	data = appendUvarint(data, uint64(len(rootKey)))
	data = append(data, rootKey...)
	if version >= Version3 {
		data = appendUvarint(data, uint64(len(nsData)))
		data = append(data, nsData...)
	}
	data = append(data, condition...)
	return data
}

// decodeCaveat attempts to decode caveat by decrypting the encrypted part
// using key.
func decodeCaveat(key *KeyPair, caveat []byte) (*ThirdPartyCaveatInfo, error) {
	if len(caveat) == 0 {
		return nil, errgo.New("empty third party caveat")
	}
	switch caveat[0] {
	case byte(Version2):
		return decodeCaveatV2V3(Version2, key, caveat)
	case byte(Version3):
		if len(caveat) < version3CaveatMinLen {
			// If it has the version 3 caveat tag and it's too short, it's
			// almost certainly an id, not an encrypted payload.
			return nil, errgo.Newf("caveat id payload not provided for caveat id %q", caveat)
		}
		return decodeCaveatV2V3(Version3, key, caveat)
	case 'e':
		// 'e' will be the first byte if the caveatid is a base64 encoded JSON object.
		return decodeCaveatV1(key, caveat)
	default:
		return nil, errgo.Newf("caveat has unsupported version %d", caveat[0])
	}
}

// decodeCaveatV1 attempts to decode a base64 encoded JSON id. This
// encoding is nominally version -1.
func decodeCaveatV1(key *KeyPair, caveat []byte) (*ThirdPartyCaveatInfo, error) {
	data := make([]byte, (3*len(caveat)+3)/4)
	n, err := base64.StdEncoding.Decode(data, caveat)
	if err != nil {
		return nil, errgo.Notef(err, "cannot base64-decode caveat")
	}
	data = data[:n]
	var wrapper caveatJSON
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal caveat %q", data)
	}
	if !bytes.Equal(key.Public.Key[:], wrapper.ThirdPartyPublicKey.Key[:]) {
		return nil, errgo.New("public key mismatch")
	}
	if wrapper.FirstPartyPublicKey == nil {
		return nil, errgo.New("target service public key not specified")
	}
	// The encrypted string is base64 encoded in the JSON representation.
	secret, err := base64.StdEncoding.DecodeString(wrapper.Id)
	if err != nil {
		return nil, errgo.Notef(err, "cannot base64-decode encrypted data")
	}
	var nonce [NonceLen]byte
	if copy(nonce[:], wrapper.Nonce) < NonceLen {
		return nil, errgo.Newf("nonce too short %x", wrapper.Nonce)
	}
	c, ok := box.Open(nil, secret, &nonce, wrapper.FirstPartyPublicKey.boxKey(), key.Private.boxKey())
	if !ok {
		return nil, errgo.Newf("cannot decrypt caveat %#v", wrapper)
	}
	var record caveatRecord
	if err := json.Unmarshal(c, &record); err != nil {
		return nil, errgo.Notef(err, "cannot decode third party caveat record")
	}
	return &ThirdPartyCaveatInfo{
		Condition:           []byte(record.Condition),
		FirstPartyPublicKey: *wrapper.FirstPartyPublicKey,
		ThirdPartyKeyPair:   *key,
		RootKey:             record.RootKey,
		Caveat:              caveat,
		Version:             Version1,
		Namespace:           legacyNamespace(),
	}, nil
}

// decodeCaveatV2V3 decodes a version 2 or version 3 caveat.
func decodeCaveatV2V3(version Version, key *KeyPair, caveat []byte) (*ThirdPartyCaveatInfo, error) {
	origCaveat := caveat
	if len(caveat) < 1+publicKeyPrefixLen+KeyLen+NonceLen+box.Overhead {
		return nil, errgo.New("caveat id too short")
	}
	caveat = caveat[1:] // skip version (already checked)

	publicKeyPrefix, caveat := caveat[:publicKeyPrefixLen], caveat[publicKeyPrefixLen:]
	if !bytes.Equal(key.Public.Key[:publicKeyPrefixLen], publicKeyPrefix) {
		return nil, errgo.New("public key mismatch")
	}

	var firstPartyPub PublicKey
	copy(firstPartyPub.Key[:], caveat[:KeyLen])
	caveat = caveat[KeyLen:]

	var nonce [NonceLen]byte
	copy(nonce[:], caveat[:NonceLen])
	caveat = caveat[NonceLen:]

	data, ok := box.Open(nil, caveat, &nonce, firstPartyPub.boxKey(), key.Private.boxKey())
	if !ok {
		return nil, errgo.Newf("cannot decrypt caveat id")
	}
	rootKey, ns, condition, err := decodeSecretPartV2V3(version, data)
	if err != nil {
		return nil, errgo.Notef(err, "invalid secret part")
	}
	return &ThirdPartyCaveatInfo{
		Condition:           condition,
		FirstPartyPublicKey: firstPartyPub,
		ThirdPartyKeyPair:   *key,
		RootKey:             rootKey,
		Caveat:              origCaveat,
		Version:             version,
		Namespace:           ns,
	}, nil
}

func decodeSecretPartV2V3(version Version, data []byte) (rootKey []byte, ns *checkers.Namespace, condition []byte, err error) {
	fail := func(err error) ([]byte, *checkers.Namespace, []byte, error) {
		return nil, nil, nil, err
	}
	if len(data) < 1 {
		return fail(errgo.New("secret part too short"))
	}
	gotVersion, data := data[0], data[1:]
	if version != Version(gotVersion) {
		return fail(errgo.Newf("unexpected secret part version, got %d want %d", gotVersion, version))
	}

	l, n := binary.Uvarint(data)
	if n <= 0 || uint64(n)+l > uint64(len(data)) {
		return fail(errgo.Newf("invalid root key length"))
	}
	data = data[n:]
	rootKey, data = data[:l], data[l:]

	if version >= Version3 {
		var nsData []byte
		var ns1 checkers.Namespace

		l, n = binary.Uvarint(data)
		if n <= 0 || uint64(n)+l > uint64(len(data)) {
			return fail(errgo.Newf("invalid namespace length"))
		}
		data = data[n:]
		nsData, data = data[:l], data[l:]
		if err := ns1.UnmarshalText(nsData); err != nil {
			return fail(errgo.Notef(err, "cannot unmarshal namespace"))
		}
		ns = &ns1
	} else {
		ns = legacyNamespace()
	}
	return rootKey, ns, data, nil
}

// appendUvarint appends n to data encoded as a variable-length
// unsigned integer.
func appendUvarint(data []byte, n uint64) []byte {
	// Ensure the capacity is sufficient. If our space calculations when
	// allocating data were correct, this should never happen,
	// but be defensive just in case.
	for need := uvarintLen(n); cap(data)-len(data) < need; {
		data1 := append(data[0:cap(data)], 0)
		data = data1[0:len(data)]
	}
	nlen := binary.PutUvarint(data[len(data):cap(data)], n)
	return data[0 : len(data)+nlen]
}

// uvarintLen returns the number of bytes that n will require
// when encoded with binary.PutUvarint.
func uvarintLen(n uint64) int {
	len := 1
	n >>= 7
	for ; n > 0; n >>= 7 {
		len++
	}
	return len
}
