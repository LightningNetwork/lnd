package onionfile

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnencrypt"
	"github.com/lightningnetwork/lnd/tor"
)

var (
	// ErrEncryptedTorPrivateKey is thrown when a tor private key is
	// encrypted, but the user requested an unencrypted key.
	ErrEncryptedTorPrivateKey = errors.New("it appears the Tor private key " +
		"is encrypted but you didn't pass the --tor.encryptkey flag. " +
		"Please restart lnd with the --tor.encryptkey flag or delete " +
		"the Tor key file for regeneration")
)

// OnionFile is a file-based implementation of the OnionStore interface that
// stores an onion service's private key.
type OnionFile struct {
	privateKeyPath string
	privateKeyPerm os.FileMode
	encryptKey     bool
	keyRing        keychain.KeyRing
}

// A compile-time constraint to ensure OnionFile satisfies the OnionStore
// interface.
var _ tor.OnionStore = (*OnionFile)(nil)

// NewOnionFile creates a file-based implementation of the OnionStore interface
// to store an onion service's private key.
func NewOnionFile(privateKeyPath string, privateKeyPerm os.FileMode,
	encryptKey bool, keyRing keychain.KeyRing) *OnionFile {

	return &OnionFile{
		privateKeyPath: privateKeyPath,
		privateKeyPerm: privateKeyPerm,
		encryptKey:     encryptKey,
		keyRing:        keyRing,
	}
}

// StorePrivateKey stores the private key at its expected path. It also
// encrypts the key before storing it if requested.
func (f *OnionFile) StorePrivateKey(_ tor.OnionType, privateKey []byte) error {
	var b bytes.Buffer
	var privateKeyContent []byte
	payload := bytes.NewBuffer(privateKey)

	if f.encryptKey {
		err := lnencrypt.EncryptPayloadToWriter(*payload, &b, f.keyRing)
		if err != nil {
			return err
		}
		privateKeyContent = b.Bytes()
	} else {
		privateKeyContent = privateKey
	}

	err := ioutil.WriteFile(
		f.privateKeyPath, privateKeyContent, f.privateKeyPerm,
	)
	if err != nil {
		return fmt.Errorf("unable to write private key "+
			"to file: %v", err)
	}
	return nil
}

// PrivateKey retrieves the private key from its expected path. If the file does
// not exist, then ErrNoPrivateKey is returned.
func (f *OnionFile) PrivateKey(_ tor.OnionType) ([]byte, error) {
	// Try to read the Tor private key to pass into the AddOnion call
	if _, err := os.Stat(f.privateKeyPath); !errors.Is(err, os.ErrNotExist) {
		privateKeyContent, err := ioutil.ReadFile(f.privateKeyPath)
		if err != nil {
			return nil, err
		}

		// If the privateKey doesn't start with either v2 or v3 key params
		// it's likely encrypted.
		if !bytes.HasPrefix(privateKeyContent, []byte(tor.V2KeyParam)) &&
			!bytes.HasPrefix(privateKeyContent, []byte(tor.V3KeyParam)) {
			// If the privateKeyContent is encrypted but --tor.encryptkey
			// wasn't set we return an error
			if !f.encryptKey {
				return nil, ErrEncryptedTorPrivateKey
			}
			// Attempt to decrypt the key
			reader := bytes.NewReader(privateKeyContent)
			privateKeyContent, err = lnencrypt.DecryptPayloadFromReader(reader, f.keyRing)
			if err != nil {
				return nil, err
			}
		}
		return privateKeyContent, nil
	}
	return nil, tor.ErrNoPrivateKey
}

// DeletePrivateKey removes the file containing the private key.
func (f *OnionFile) DeletePrivateKey(_ tor.OnionType) error {
	return os.Remove(f.privateKeyPath)
}
