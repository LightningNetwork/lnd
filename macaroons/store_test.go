package macaroons_test

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/macaroons"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/stretchr/testify/require"
)

var (
	defaultRootKeyIDContext = macaroons.ContextWithRootKeyID(
		context.Background(), macaroons.DefaultRootKeyID,
	)
)

// newTestStore creates a new bolt DB in a temporary directory and then
// initializes a root key storage for that DB.
func newTestStore(t *testing.T) (string, func(), *macaroons.RootKeyStorage) {
	tempDir, err := ioutil.TempDir("", "macaroonstore-")
	require.NoError(t, err)

	cleanup, store := openTestStore(t, tempDir)
	cleanup2 := func() {
		cleanup()
		_ = os.RemoveAll(tempDir)
	}

	return tempDir, cleanup2, store
}

// openTestStore opens an existing bolt DB and then initializes a root key
// storage for that DB.
func openTestStore(t *testing.T, tempDir string) (func(),
	*macaroons.RootKeyStorage) {

	db, err := kvdb.Create(
		kvdb.BoltBackendName, path.Join(tempDir, "weks.db"), true,
		kvdb.DefaultDBTimeout,
	)
	require.NoError(t, err)

	store, err := macaroons.NewRootKeyStorage(db)
	if err != nil {
		_ = db.Close()
		t.Fatalf("Error creating root key store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
		_ = db.Close()
	}

	return cleanup, store
}

// TestStore tests the normal use cases of the store like creating, unlocking,
// reading keys and closing it.
func TestStore(t *testing.T) {
	tempDir, cleanup, store := newTestStore(t)
	defer cleanup()

	_, _, err := store.RootKey(context.TODO())
	require.Equal(t, macaroons.ErrStoreLocked, err)

	_, err = store.Get(context.TODO(), nil)
	require.Equal(t, macaroons.ErrStoreLocked, err)

	pw := []byte("weks")
	err = store.CreateUnlock(&pw)
	require.NoError(t, err)

	// Check ErrContextRootKeyID is returned when no root key ID found in
	// context.
	_, _, err = store.RootKey(context.TODO())
	require.Equal(t, macaroons.ErrContextRootKeyID, err)

	// Check ErrMissingRootKeyID is returned when empty root key ID is used.
	emptyKeyID := make([]byte, 0)
	badCtx := macaroons.ContextWithRootKeyID(context.TODO(), emptyKeyID)
	_, _, err = store.RootKey(badCtx)
	require.Equal(t, macaroons.ErrMissingRootKeyID, err)

	// Create a context with illegal root key ID value.
	encryptedKeyID := []byte("enckey")
	badCtx = macaroons.ContextWithRootKeyID(context.TODO(), encryptedKeyID)
	_, _, err = store.RootKey(badCtx)
	require.Equal(t, macaroons.ErrKeyValueForbidden, err)

	// Create a context with root key ID value.
	key, id, err := store.RootKey(defaultRootKeyIDContext)
	require.NoError(t, err)

	rootID := id
	require.Equal(t, macaroons.DefaultRootKeyID, rootID)

	key2, err := store.Get(defaultRootKeyIDContext, id)
	require.NoError(t, err)
	require.Equal(t, key, key2)

	badpw := []byte("badweks")
	err = store.CreateUnlock(&badpw)
	require.Equal(t, macaroons.ErrAlreadyUnlocked, err)

	_ = store.Close()
	_ = store.Backend.Close()

	// Between here and the re-opening of the store, it's possible to get
	// a double-close, but that's not such a big deal since the tests will
	// fail anyway in that case.
	_, store = openTestStore(t, tempDir)

	err = store.CreateUnlock(&badpw)
	require.Equal(t, snacl.ErrInvalidPassword, err)

	err = store.CreateUnlock(nil)
	require.Equal(t, macaroons.ErrPasswordRequired, err)

	_, _, err = store.RootKey(defaultRootKeyIDContext)
	require.Equal(t, macaroons.ErrStoreLocked, err)

	_, err = store.Get(defaultRootKeyIDContext, nil)
	require.Equal(t, macaroons.ErrStoreLocked, err)

	err = store.CreateUnlock(&pw)
	require.NoError(t, err)

	key, err = store.Get(defaultRootKeyIDContext, rootID)
	require.NoError(t, err)
	require.Equal(t, key, key2)

	key, id, err = store.RootKey(defaultRootKeyIDContext)
	require.NoError(t, err)
	require.Equal(t, key, key2)
	require.Equal(t, rootID, id)
}

// TestStoreGenerateNewRootKey tests that a root key can be replaced with a new
// one in the store without changing the password.
func TestStoreGenerateNewRootKey(t *testing.T) {
	_, cleanup, store := newTestStore(t)
	defer cleanup()

	// The store must be unlocked to replace the root key.
	err := store.GenerateNewRootKey()
	require.Equal(t, macaroons.ErrStoreLocked, err)

	// Unlock the store and read the current key.
	pw := []byte("weks")
	err = store.CreateUnlock(&pw)
	require.NoError(t, err)
	oldRootKey, _, err := store.RootKey(defaultRootKeyIDContext)
	require.NoError(t, err)

	// Replace the root key with a new random key.
	err = store.GenerateNewRootKey()
	require.NoError(t, err)

	// Finally, read the root key from the DB and compare it to the one
	// we got returned earlier. This makes sure that the encryption/
	// decryption of the key in the DB worked as expected too.
	newRootKey, _, err := store.RootKey(defaultRootKeyIDContext)
	require.NoError(t, err)
	require.NotEqual(t, oldRootKey, newRootKey)
}

// TestStoreChangePassword tests that the password for the store can be changed
// without changing the root key.
func TestStoreChangePassword(t *testing.T) {
	tempDir, cleanup, store := newTestStore(t)
	defer cleanup()

	// The store must be unlocked to replace the root key.
	err := store.ChangePassword(nil, nil)
	require.Equal(t, macaroons.ErrStoreLocked, err)

	// Unlock the DB and read the current root key. This will need to stay
	// the same after changing the password for the test to succeed.
	pw := []byte("weks")
	err = store.CreateUnlock(&pw)
	require.NoError(t, err)
	rootKey, _, err := store.RootKey(defaultRootKeyIDContext)
	require.NoError(t, err)

	// Both passwords must be set.
	err = store.ChangePassword(nil, nil)
	require.Equal(t, macaroons.ErrPasswordRequired, err)

	// Make sure that an error is returned if we try to change the password
	// without the correct old password.
	wrongPw := []byte("wrong")
	newPw := []byte("newpassword")
	err = store.ChangePassword(wrongPw, newPw)
	require.Equal(t, snacl.ErrInvalidPassword, err)

	// Now really do change the password.
	err = store.ChangePassword(pw, newPw)
	require.NoError(t, err)

	// Close the store. This will close the underlying DB and we need to
	// create a new store instance. Let's make sure we can't use it again
	// after closing.
	err = store.Close()
	require.NoError(t, err)
	err = store.Backend.Close()
	require.NoError(t, err)

	err = store.CreateUnlock(&newPw)
	require.Error(t, err)

	// Let's open it again and try unlocking with the new password.
	_, store = openTestStore(t, tempDir)
	err = store.CreateUnlock(&newPw)
	require.NoError(t, err)

	// Finally read the root key from the DB using the new password and
	// make sure the root key stayed the same.
	rootKeyDb, _, err := store.RootKey(defaultRootKeyIDContext)
	require.NoError(t, err)
	require.Equal(t, rootKey, rootKeyDb)
}
