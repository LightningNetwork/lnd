package lnencrypt

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lightningnetwork/lnd/keychain"
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

// ReadTorPrivateKey reads the Tor private key from disk and returns the
// contents. If the file is encrypted it also decrypts the file
// before returning.
func ReadTorPrivateKey(keyPath string, encryptKey bool, keyRing keychain.KeyRing) (
	string, error) {

	// Try to read the Tor private key to pass into the AddOnion call
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		privateKeyContent, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return "", err
		}

		// If the privateKey doesn't start with either v2 or v3 key params
		// it's likely encrypted.
		if !bytes.HasPrefix(privateKeyContent, []byte(tor.V2KeyParam)) &&
			!bytes.HasPrefix(privateKeyContent, []byte(tor.V3KeyParam)) {
			// If the privateKeyContent is encrypted but --tor.encryptkey
			// wasn't set we return an error
			if !encryptKey {
				return "", ErrEncryptedTorPrivateKey
			}
			// Attempt to decrypt the key
			reader := bytes.NewReader(privateKeyContent)
			privateKeyContent, err = DecryptPayloadFromReader(reader, keyRing)
			if err != nil {
				return "", err
			}
		}
		return string(privateKeyContent), nil
	}
	// If the file doesn't exist return an empty string so one is created.
	return "", nil
}

// WriteTorPrivateKey encrypts the Tor private key to the given keyRing
// then writes the encrypted contents to disk.
func WriteTorPrivateKey(keyPath, privateKey string,
	keyRing keychain.KeyRing) error {

	var b bytes.Buffer
	payload := bytes.NewBuffer([]byte(privateKey))
	err := EncryptPayloadToWriter(*payload, &b, keyRing)
	if err != nil {
		return err
	}
	privateKeyContent := b.Bytes()
	err = ioutil.WriteFile(keyPath, privateKeyContent, 0600)
	if err != nil {
		return fmt.Errorf("unable to write private key "+
			"to file: %v", err)
	}
	return nil
}
