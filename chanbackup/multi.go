package chanbackup

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnencrypt"
	"github.com/lightningnetwork/lnd/lnwire"
)

// MultiBackupVersion denotes the version of the multi channel static channel
// backup. Based on this version, we know how to encode/decode packed/unpacked
// versions of multi backups.
type MultiBackupVersion byte

const (
	// DefaultMultiVersion is the default version of the multi channel
	// backup. The serialized format for this version is simply: version ||
	// numBackups || SCBs...
	DefaultMultiVersion = 0

	// NilMultiSizePacked is the size of a "nil" packed Multi (45 bytes).
	// This consists of the 24 byte chacha nonce, the 16 byte MAC, one byte
	// for the version, and 4 bytes to signal zero entries.
	NilMultiSizePacked = 24 + 16 + 1 + 4
)

// Multi is a form of static channel backup that is amenable to being
// serialized in a single file. Rather than a series of ciphertexts, a
// multi-chan backup is a single ciphertext of all static channel backups
// concatenated. This form factor gives users a single blob that they can use
// to safely copy/obtain at anytime to backup their channels.
type Multi struct {
	// Version is the version that should be observed when attempting to
	// pack the multi backup.
	Version MultiBackupVersion

	// StaticBackups is the set of single channel backups that this multi
	// backup is comprised of.
	StaticBackups []Single
}

// PackToWriter packs (encrypts+serializes) the target set of static channel
// backups into a single AEAD ciphertext into the passed io.Writer. This is the
// opposite of UnpackFromReader. The plaintext form of a multi-chan backup is
// the following: a 4 byte integer denoting the number of serialized static
// channel backups serialized, a series of serialized static channel backups
// concatenated. To pack this payload, we then apply our chacha20 AEAD to the
// entire payload, using the 24-byte nonce as associated data.
func (m Multi) PackToWriter(w io.Writer, keyRing keychain.KeyRing) error {
	// The only version that we know how to pack atm is version 0. Attempts
	// to pack any other version will result in an error.
	switch m.Version {
	case DefaultMultiVersion:
		break

	default:
		return fmt.Errorf("unable to pack unknown multi-version "+
			"of %v", m.Version)
	}

	var multiBackupBuffer bytes.Buffer

	// First, we'll write out the version of this multi channel baackup.
	err := lnwire.WriteElements(&multiBackupBuffer, byte(m.Version))
	if err != nil {
		return err
	}

	// Now that we've written out the version of this multi-pack format,
	// we'll now write the total number of backups to expect after this
	// point.
	numBackups := uint32(len(m.StaticBackups))
	err = lnwire.WriteElements(&multiBackupBuffer, numBackups)
	if err != nil {
		return err
	}

	// Next, we'll serialize the raw plaintext version of each of the
	// backup into the intermediate buffer.
	for _, chanBackup := range m.StaticBackups {
		err := chanBackup.Serialize(&multiBackupBuffer)
		if err != nil {
			return fmt.Errorf("unable to serialize backup "+
				"for %v: %v", chanBackup.FundingOutpoint, err)
		}
	}

	// With the plaintext multi backup assembled, we'll now encrypt it
	// directly to the passed writer.
	return lnencrypt.EncryptPayloadToWriter(multiBackupBuffer, w, keyRing)
}

// UnpackFromReader attempts to unpack (decrypt+deserialize) a packed
// multi-chan backup form the passed io.Reader. If we're unable to decrypt the
// any portion of the multi-chan backup, an error will be returned.
func (m *Multi) UnpackFromReader(r io.Reader, keyRing keychain.KeyRing) error {
	// We'll attempt to read the entire packed backup, and also decrypt it
	// using the passed key ring which is expected to be able to derive the
	// encryption keys.
	plaintextBackup, err := lnencrypt.DecryptPayloadFromReader(r, keyRing)
	if err != nil {
		return err
	}
	backupReader := bytes.NewReader(plaintextBackup)

	// Now that we've decrypted the payload successfully, we can parse out
	// each of the individual static channel backups.

	// First, we'll need to read the version of this multi-back up so we
	// can know how to unpack each of the individual SCB's.
	var multiVersion byte
	err = lnwire.ReadElements(backupReader, &multiVersion)
	if err != nil {
		return err
	}

	m.Version = MultiBackupVersion(multiVersion)
	switch m.Version {

	// The default version is simply a set of serialized SCB's with the
	// number of total SCB's prepended to the front of the byte slice.
	case DefaultMultiVersion:
		// First, we'll need to read out the total number of backups
		// that've been serialized into this multi-chan backup. Each
		// backup is the same size, so we can continue until we've
		// parsed out everything.
		var numBackups uint32
		err = lnwire.ReadElements(backupReader, &numBackups)
		if err != nil {
			return err
		}

		// We'll continue to parse out each backup until we've read all
		// that was indicated from the length prefix.
		for ; numBackups != 0; numBackups-- {
			// Attempt to parse out the net static channel backup,
			// if it's been malformed, then we'll return with an
			// error
			var chanBackup Single
			err := chanBackup.Deserialize(backupReader)
			if err != nil {
				return err
			}

			// Collect the next valid chan backup into the main
			// multi backup slice.
			m.StaticBackups = append(m.StaticBackups, chanBackup)
		}

	default:
		return fmt.Errorf("unable to unpack unknown multi-version "+
			"of %v", multiVersion)
	}

	return nil
}

// TODO(roasbeef): new key ring interface?
//  * just returns key given params?

// PackedMulti represents a raw fully packed (serialized+encrypted)
// multi-channel static channel backup.
type PackedMulti []byte

// Unpack attempts to unpack (decrypt+desrialize) the target packed
// multi-channel back up. If we're unable to fully unpack this back, then an
// error will be returned.
func (p *PackedMulti) Unpack(keyRing keychain.KeyRing) (*Multi, error) {
	var m Multi

	packedReader := bytes.NewReader(*p)
	if err := m.UnpackFromReader(packedReader, keyRing); err != nil {
		return nil, err
	}

	return &m, nil
}

// TODO(roasbsef): fuzz parsing
