package aezeed

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
	"time"

	"github.com/Yawning/aez"
	"github.com/kkdai/bstream"

	"golang.org/x/crypto/scrypt"
)

const (
	// CipherSeedVersion is the current version of the aezeed scheme as
	// defined in this package. This version indicates the following
	// parameters for the deciphered cipher seed: a 1 byte version, 2 bytes
	// for the Bitcoin Days Genesis timestamp, and 16 bytes for entropy. It
	// also governs how the cipher seed should be enciphered. In this
	// version we take the deciphered seed, create a 5 byte salt, use that
	// with an optional passphrase to generate a 32-byte key (via scrypt),
	// then encipher with aez (using the salt and version as AD). The final
	// enciphered seed is: version || ciphertext || salt.
	CipherSeedVersion uint8 = 0

	// DecipheredCipherSeedSize is the size of the plaintext seed resulting
	// from deciphering the cipher seed. The size consists of the
	// following:
	//
	//  * 1 byte version || 2 bytes timestamp || 16 bytes of entropy.
	//
	// The version is used by wallets to know how to re-derive relevant
	// addresses, the 2 byte timestamp a BDG (Bitcoin Days Genesis) offset,
	// and finally, the 16 bytes to be used to generate the HD wallet seed.
	DecipheredCipherSeedSize = 19

	// EncipheredCipherSeedSize is the size of the fully encoded+enciphered
	// cipher seed. We first obtain the enciphered plaintext seed by
	// carrying out the enciphering as governed in the current version. We
	// then take that enciphered seed (now 19+4=23 bytes due to ciphertext
	// expansion, essentially a checksum) and prepend a version, then
	// append the salt, and then take a checksum of everything. The
	// checksum allows us to verify that the user input the correct set of
	// words, then we can verify the passphrase due to the internal MAC
	// equiv.  The final breakdown is:
	//
	//  * 1 byte version || 23 byte enciphered seed || 5 byte salt || 4 byte checksum
	//
	// With CipherSeedVersion we encipher as follows: we use
	// scrypt(n=32768, r=8, p=1) to derive a 32-byte key from an optional
	// user passphrase. We then encipher the plaintext seed using a value
	// of tau (with aez) of 8-bytes (so essentially a 32-bit MAC).  When
	// enciphering, we include the version and scrypt salt as the AD.  This
	// gives us a total of 33 bytes. These 33 bytes fit cleanly into 24
	// mnemonic words.
	EncipheredCipherSeedSize = 33

	// CipherTextExpansion is the number of bytes that will be added as
	// redundancy for the enciphering scheme implemented by aez. This can
	// be seen as the size of the equivalent MAC.
	CipherTextExpansion = 4

	// EntropySize is the number of bytes of entropy we'll use the generate
	// the seed.
	EntropySize = 16

	// NumMnemonicWords is the number of words that an encoded cipher seed
	// will result in.
	NumMnemonicWords = 24

	// saltSize is the size of the salt we'll generate to use with scrypt
	// to generate a key for use within aez from the user's passphrase. The
	// role of the salt is to make the creation of rainbow tables
	// infeasible.
	saltSize = 5

	// adSize is the size of the encoded associated data that will be
	// passed into aez when enciphering and deciphering the seed. The AD
	// itself (associated data) is just the CipherSeedVersion and salt.
	adSize = 6

	// checkSumSize is the size of the checksum applied to the final
	// encoded ciphertext.
	checkSumSize = 4

	// keyLen is the size of the key that we'll use for encryption with
	// aez.
	keyLen = 32

	// BitsPerWord is the number of bits each word in the wordlist encodes.
	// We encode our mnemonic using 24 words, so 264 bits (33 bytes).
	BitsPerWord = 11

	// saltOffset is the index within an enciphered cipherseed that marks
	// the start of the salt.
	saltOffset = EncipheredCipherSeedSize - checkSumSize - saltSize

	// checkSumSize is the index within an enciphered cipher seed that
	// marks the start of the checksum.
	checkSumOffset = EncipheredCipherSeedSize - checkSumSize
)

var (
	// Below at the default scrypt parameters that are tied to
	// CipherSeedVersion zero.
	scryptN = 32768
	scryptR = 8
	scryptP = 1

	// crcTable is a table that presents the polynomial we'll use for
	// computing our checksum.
	crcTable = crc32.MakeTable(crc32.Castagnoli)

	// defaultPassphrase is the default passphrase that will be used for
	// encryption in the case that the user chooses not to specify their
	// own passphrase.
	defaultPassphrase = []byte("aezeed")
)

var (
	// BitcoinGenesisDate is the timestamp of Bitcoin's genesis block.
	// We'll use this value in order to create a compact birthday for the
	// seed. The birthday will be interested as the number of days since
	// the genesis date. We refer to this time period as ABE (after Bitcoin
	// era).
	BitcoinGenesisDate = time.Unix(1231006505, 0)
)

// CipherSeed is a fully decoded instance of the aezeed scheme. At a high
// level, the encoded cipherseed is the enciphering of: a version byte, a set
// of bytes for a timestamp, the entropy which will be used to directly
// construct the HD seed, and finally a checksum over the rest. This scheme was
// created as the widely used schemes in the space lack two critical traits: a
// version byte, and a birthday timestamp. The version allows us to modify the
// details of the scheme in the future, and the birthday gives wallets a limit
// of how far back in the chain they'll need to start scanning. We also add an
// external version to the enciphering plaintext seed. With this addition,
// seeds are able to be "upgraded" (to diff params, or entirely diff crypt),
// while maintaining the semantics of the plaintext seed.
//
// The core of the scheme is the usage of aez to carefully control the size of
// the final encrypted seed. With the current parameters, this scheme can be
// encoded using a 24 word mnemonic. We use 4 bytes of ciphertext expansion
// when enciphering the raw seed, giving us the equivalent of 40-bit MAC (as we
// check for a particular seed version). Using the external 4 byte checksum,
// we're able to ensure that the user input the correct set of words.  Finally,
// the password in the scheme is optional. If not specified, "aezeed" will be
// used as the password. Otherwise, the addition of the password means that
// users can encrypt the raw "plaintext" seed under distinct passwords to
// produce unique mnemonic phrases.
type CipherSeed struct {
	// InternalVersion is the version of the plaintext cipherseed. This is
	// to be used by wallets to determine if the seed version is compatible
	// with the derivation schemes they know.
	InternalVersion uint8

	// Birthday is the time that the seed was created. This is expressed as
	// the number of days since the timestamp in the Bitcoin genesis block.
	// We use days as seconds gives us wasted granularity. The oldest seed
	// that we can encode using this format is through the date 2188.
	Birthday uint16

	// Entropy is a set of bytes generated via a CSPRNG. This is the value
	// that should be used to directly generate the HD root, as defined
	// within BIP0032.
	Entropy [EntropySize]byte

	// salt is the salt that was used to generate the key from the user's
	// specified passphrase.
	salt [saltSize]byte
}

// New generates a new CipherSeed instance from an optional source of entropy.
// If the entropy isn't provided, then a set of random bytes will be used in
// place. The final argument should be the time at which the seed was created.
func New(internalVersion uint8, entropy *[EntropySize]byte,
	now time.Time) (*CipherSeed, error) {

	// TODO(roasbeef): pass randomness source? to make fully determinsitc?

	// If a set of entropy wasn't provided, then we'll read a set of bytes
	// from the CSPRNG of our operating platform.
	var seed [EntropySize]byte
	if entropy == nil {
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
	} else {
		// Otherwise, we'll copy the set of bytes.
		copy(seed[:], entropy[:])
	}

	// To compute our "birthday", we'll first use the current time, then
	// subtract that from the Bitcoin Genesis Date. We'll then convert that
	// value to days.
	birthday := uint16(now.Sub(BitcoinGenesisDate) / (time.Hour * 24))

	c := &CipherSeed{
		InternalVersion: internalVersion,
		Birthday:        birthday,
		Entropy:         seed,
	}

	// Next, we'll read a random salt that will be used with scrypt to
	// eventually derive our key.
	if _, err := rand.Read(c.salt[:]); err != nil {
		return nil, err
	}

	return c, nil
}

// encode attempts to encode the target cipherSeed into the passed io.Writer
// instance.
func (c *CipherSeed) encode(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, c.InternalVersion)
	if err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, c.Birthday); err != nil {
		return err
	}

	if _, err := w.Write(c.Entropy[:]); err != nil {
		return err
	}

	return nil
}

// decode attempts to decode an encoded cipher seed instance into the target
// CipherSeed struct.
func (c *CipherSeed) decode(r io.Reader) error {
	err := binary.Read(r, binary.BigEndian, &c.InternalVersion)
	if err != nil {
		return err
	}

	if err := binary.Read(r, binary.BigEndian, &c.Birthday); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, c.Entropy[:]); err != nil {
		return err
	}

	return nil
}

// encodeAD returns the fully encoded associated data for use when performing
// our current enciphering operation. The AD is: version || salt.
func encodeAD(version uint8, salt [saltSize]byte) [adSize]byte {
	var ad [adSize]byte
	ad[0] = byte(version)
	copy(ad[1:], salt[:])

	return ad
}

// extractAD extracts an associated data from a fully encoded and enciphered
// cipher seed. This is to be used when attempting to decrypt an enciphered
// cipher seed.
func extractAD(encipheredSeed [EncipheredCipherSeedSize]byte) [adSize]byte {
	var ad [adSize]byte
	ad[0] = encipheredSeed[0]

	copy(ad[1:], encipheredSeed[saltOffset:checkSumOffset])

	return ad
}

// encipher takes a fully populated cipherseed instance, and enciphers the
// encoded seed, then appends a randomly generated seed used to stretch the
// passphrase out into an appropriate key, then computes a checksum over the
// preceding.
func (c *CipherSeed) encipher(pass []byte) ([EncipheredCipherSeedSize]byte, error) {
	var cipherSeedBytes [EncipheredCipherSeedSize]byte

	// If the passphrase wasn't provided, then we'll use the string
	// "aezeed" in place.
	passphrase := pass
	if len(passphrase) == 0 {
		passphrase = defaultPassphrase
	}

	// With our salt pre-generated, we'll now run the password through a
	// KDF to obtain the key we'll use for encryption.
	key, err := scrypt.Key(
		passphrase, c.salt[:], scryptN, scryptR, scryptP, keyLen,
	)
	if err != nil {
		return cipherSeedBytes, err
	}

	// Next, we'll encode the serialized plaintext cipherseed into a buffer
	// that we'll use for encryption.
	var seedBytes bytes.Buffer
	if err := c.encode(&seedBytes); err != nil {
		return cipherSeedBytes, err
	}

	// With our plaintext seed encoded, we'll now construct the AD that
	// will be passed to the encryption operation. This ensures to
	// authenticate both the salt and the external version.
	ad := encodeAD(CipherSeedVersion, c.salt)

	// With all items assembled, we'll now encipher the plaintext seed
	// with our AD, key, and MAC size.
	cipherSeed := seedBytes.Bytes()
	cipherText := aez.Encrypt(
		key, nil, [][]byte{ad[:]}, CipherTextExpansion, cipherSeed, nil,
	)

	// Finally, we'll pack the {version || ciphertext || salt || checksum}
	// seed into a byte slice for encoding as a mnemonic.
	cipherSeedBytes[0] = byte(CipherSeedVersion)
	copy(cipherSeedBytes[1:saltOffset], cipherText)
	copy(cipherSeedBytes[saltOffset:], c.salt[:])

	// With the seed mostly assembled, we'll now compute a checksum all the
	// contents.
	checkSum := crc32.Checksum(cipherSeedBytes[:checkSumOffset], crcTable)

	// With our checksum computed, we can finish encoding the full cipher
	// seed.
	var checkSumBytes [4]byte
	binary.BigEndian.PutUint32(checkSumBytes[:], checkSum)
	copy(cipherSeedBytes[checkSumOffset:], checkSumBytes[:])

	return cipherSeedBytes, nil
}

// cipherTextToMnemonic converts the aez ciphertext appended with the salt to a
// 24-word mnemonic pass phrase.
func cipherTextToMnemonic(cipherText [EncipheredCipherSeedSize]byte) (Mnemonic, error) {
	var words [NumMnemonicWords]string

	// First, we'll convert the ciphertext itself into a bitstream for easy
	// manipulation.
	cipherBits := bstream.NewBStreamReader(cipherText[:])

	// With our bitstream obtained, we'll read 11 bits at a time, then use
	// that to index into our word list to obtain the next word.
	for i := 0; i < NumMnemonicWords; i++ {
		index, err := cipherBits.ReadBits(BitsPerWord)
		if err != nil {
			return Mnemonic{}, err
		}

		words[i] = DefaultWordList[index]
	}

	return words, nil
}

// ToMnemonic maps the final enciphered cipher seed to a human readable 24-word
// mnemonic phrase. The password is optional, as if it isn't specified aezeed
// will be used in its place.
func (c *CipherSeed) ToMnemonic(pass []byte) (Mnemonic, error) {
	// First, we'll convert the valid seed triple into an aez cipher text
	// with our KDF salt appended to it.
	cipherText, err := c.encipher(pass)
	if err != nil {
		return Mnemonic{}, err
	}

	// Now that we have our cipher text, we'll convert it into a mnemonic
	// phrase.
	return cipherTextToMnemonic(cipherText)
}

// Encipher maps the cipher seed to an aez ciphertext using an optional
// passphrase.
func (c *CipherSeed) Encipher(pass []byte) ([EncipheredCipherSeedSize]byte, error) {
	return c.encipher(pass)
}

// BirthdayTime returns the cipher seed's internal birthday format as a native
// golang Time struct.
func (c *CipherSeed) BirthdayTime() time.Time {
	offset := time.Duration(c.Birthday) * 24 * time.Hour
	return BitcoinGenesisDate.Add(offset)
}

// Mnemonic is a 24-word passphrase as of CipherSeedVersion zero. This
// passphrase encodes an encrypted seed triple (version, birthday, entropy).
// Additionally, we also encode the salt used with scrypt to derive the key
// that the cipher text is encrypted with, and the version which tells us how
// to decipher the seed.
type Mnemonic [NumMnemonicWords]string

// mnemonicToCipherText converts a 24-word mnemonic phrase into a 33 byte
// cipher text.
//
// NOTE: This assumes that all words have already been checked to be amongst
// our word list.
func mnemonicToCipherText(mnemonic *Mnemonic) [EncipheredCipherSeedSize]byte {
	var cipherText [EncipheredCipherSeedSize]byte

	// We'll now perform the reverse mapping to that of
	// cipherTextToMnemonic: we'll get the index of the word, then write
	// out that index to the bit stream.
	cipherBits := bstream.NewBStreamWriter(EncipheredCipherSeedSize)
	for _, word := range mnemonic {
		// Using the reverse word map, we'll locate the index of this
		// word within the word list.
		index := uint64(ReverseWordMap[word])

		// With the index located, we'll now write this out to the
		// bitstream, appending to what's already there.
		cipherBits.WriteBits(index, BitsPerWord)
	}

	copy(cipherText[:], cipherBits.Bytes())

	return cipherText
}

// ToCipherSeed attempts to map the mnemonic to the original cipher text byte
// slice. Then we'll attempt to decrypt the ciphertext using aez with the
// passed passphrase, using the last 5 bytes of the ciphertext as a salt for
// the KDF.
func (m *Mnemonic) ToCipherSeed(pass []byte) (*CipherSeed, error) {
	// First, we'll attempt to decipher the mnemonic by mapping back into
	// our byte slice and applying our deciphering scheme.
	plainSeed, err := m.Decipher(pass)
	if err != nil {
		return nil, err
	}

	// If decryption was successful, then we'll decode into a fresh
	// CipherSeed struct.
	var c CipherSeed
	if err := c.decode(bytes.NewReader(plainSeed[:])); err != nil {
		return nil, err
	}

	return &c, nil
}

// decipherCipherSeed attempts to decipher the passed cipher seed ciphertext
// using the passed passphrase. This function is the opposite of
// the encipher method.
func decipherCipherSeed(cipherSeedBytes [EncipheredCipherSeedSize]byte,
	pass []byte) ([DecipheredCipherSeedSize]byte, error) {

	var plainSeed [DecipheredCipherSeedSize]byte

	// Before we do anything, we'll ensure that the version is one that we
	// understand. Otherwise, we won't be able to decrypt, or even parse
	// the cipher seed.
	if uint8(cipherSeedBytes[0]) != CipherSeedVersion {
		return plainSeed, ErrIncorrectVersion
	}

	// Next, we'll slice off the salt from the pass cipher seed, then
	// snip off the end of the cipher seed, ignoring the version, and
	// finally the checksum.
	salt := cipherSeedBytes[saltOffset : saltOffset+saltSize]
	cipherSeed := cipherSeedBytes[1:saltOffset]
	checksum := cipherSeedBytes[checkSumOffset:]

	// Before we perform any crypto operations, we'll re-create and verify
	// the checksum to ensure that the user input the proper set of words.
	freshChecksum := crc32.Checksum(cipherSeedBytes[:checkSumOffset], crcTable)
	if freshChecksum != binary.BigEndian.Uint32(checksum) {
		return plainSeed, ErrIncorrectMnemonic
	}

	// With the salt separated from the cipher text, we'll now obtain the
	// key used for encryption.
	key, err := scrypt.Key(pass, salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return plainSeed, err
	}

	// We'll also extract the AD that will be required to properly pass the
	// MAC check.
	ad := extractAD(cipherSeedBytes)

	// With the key, we'll attempt to decrypt the plaintext. If the
	// ciphertext was altered, or the passphrase is incorrect, then we'll
	// error out.
	plainSeedBytes, ok := aez.Decrypt(
		key, nil, [][]byte{ad[:]}, CipherTextExpansion, cipherSeed, nil,
	)
	if !ok {
		return plainSeed, ErrInvalidPass
	}
	copy(plainSeed[:], plainSeedBytes)

	return plainSeed, nil

}

// Decipher attempts to decipher the encoded mnemonic by first mapping to the
// original chipertext, then applying our deciphering scheme. ErrInvalidPass
// will be returned if the passphrase is incorrect.
func (m *Mnemonic) Decipher(pass []byte) ([DecipheredCipherSeedSize]byte, error) {

	// Before we attempt to map the mnemonic back to the original
	// ciphertext, we'll ensure that all the word are actually a part of
	// the current default word list.
	wordDict := make(map[string]struct{}, len(DefaultWordList))
	for _, word := range DefaultWordList {
		wordDict[word] = struct{}{}
	}

	for i, word := range m {
		if _, ok := wordDict[word]; !ok {
			emptySeed := [DecipheredCipherSeedSize]byte{}
			return emptySeed, ErrUnknownMnenomicWord{
				Word:  word,
				Index: uint8(i),
			}
		}
	}

	// If the passphrase wasn't provided, then we'll use the string
	// "aezeed" in place.
	passphrase := pass
	if len(passphrase) == 0 {
		passphrase = defaultPassphrase
	}

	// Next, we'll map the mnemonic phrase back into the original cipher
	// text.
	cipherText := mnemonicToCipherText(m)

	// Finally, we'll attempt to decipher the enciphered seed. The result
	// will be the raw seed minus the ciphertext expansion, external
	// version, and salt.
	return decipherCipherSeed(cipherText, passphrase)
}

// ChangePass takes an existing mnemonic, and passphrase for said mnemonic and
// re-enciphers the plaintext cipher seed into a brand new mnemonic. This can
// be used to allow users to re-encrypt the same seed with multiple pass
// phrases, or just change the passphrase on an existing seed.
func (m *Mnemonic) ChangePass(oldPass, newPass []byte) (Mnemonic, error) {
	var newmnemonic Mnemonic

	// First, we'll try to decrypt the current mnemonic using the existing
	// passphrase. If this fails, then we can't proceed any further.
	cipherSeed, err := m.ToCipherSeed(oldPass)
	if err != nil {
		return newmnemonic, err
	}

	// If the deciperhing was successful, then we'll now re-encipher using
	// the new user provided passphrase.
	return cipherSeed.ToMnemonic(newPass)
}
