package onionfile

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lntest/channels"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/tor"
)

// TestOnionFile tests that the OnionFile implementation of the OnionStore
// interface behaves as expected.
func TestOnionFile(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "onion_store")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}

	privateKey := []byte("RSA1024 hide_me_plz")
	privateKeyPath := filepath.Join(tempDir, "secret")

	// Create a new file-based onion store. A private key should not exist
	// yet.
	onionFile := NewOnionFile(privateKeyPath, 0600, false, &mock.SecretKeyRing{})
	if _, err := onionFile.PrivateKey(tor.V2); err != tor.ErrNoPrivateKey {
		t.Fatalf("expected ErrNoPrivateKey, got \"%v\"", err)
	}

	// Store the private key and ensure what's stored matches.
	if err := onionFile.StorePrivateKey(tor.V2, privateKey); err != nil {
		t.Fatalf("unable to store private key: %v", err)
	}
	storePrivateKey, err := onionFile.PrivateKey(tor.V2)
	if err != nil {
		t.Fatalf("unable to retrieve private key: %v", err)
	}
	if !bytes.Equal(storePrivateKey, privateKey) {
		t.Fatalf("expected private key \"%v\", got \"%v\"",
			string(privateKey), string(storePrivateKey))
	}

	// Finally, delete the private key. We should no longer be able to
	// retrieve it.
	if err := onionFile.DeletePrivateKey(tor.V2); err != nil {
		t.Fatalf("unable to delete private key: %v", err)
	}
	if _, err := onionFile.PrivateKey(tor.V2); err != tor.ErrNoPrivateKey {
		t.Fatal("found deleted private key")
	}

	// Create a new file-based onion store that encrypts the key this time
	// to ensure that an encrypted key is properly handled.
	testPrivKeyBytes := channels.AlicesPrivKey
	testPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(),
		testPrivKeyBytes)
	keyRing := &mock.SecretKeyRing{
		RootKey: testPrivKey,
	}

	encryptedOnionFile := NewOnionFile(
		privateKeyPath, 0600, true, keyRing,
	)

	if err = encryptedOnionFile.StorePrivateKey(tor.V2, privateKey); err != nil {
		t.Fatalf("unable to store encrypted private key: %v", err)
	}

	storedPrivateKey, err := encryptedOnionFile.PrivateKey(tor.V2)
	if err != nil {
		t.Fatalf("unable to retrieve encrypted private key: %v", err)
	}
	if !bytes.Equal(storedPrivateKey, privateKey) {
		t.Fatalf("expected private key \"%v\", got \"%v\"",
			string(privateKey), string(storePrivateKey))
	}

	if err := encryptedOnionFile.DeletePrivateKey(tor.V2); err != nil {
		t.Fatalf("unable to delete private key: %v", err)
	}
}
