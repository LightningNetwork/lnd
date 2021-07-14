package macaroons_test

import (
	"context"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

var (
	testOperation = bakery.Op{
		Entity: "testEntity",
		Action: "read",
	}
	testOperationURI = bakery.Op{
		Entity: macaroons.PermissionEntityCustomURI,
		Action: "SomeMethod",
	}
	defaultPw = []byte("hello")
)

// setupTestRootKeyStorage creates a dummy root key storage by
// creating a temporary macaroons.db and initializing it with the
// default password of 'hello'. Only the path to the temporary
// DB file is returned, because the service will open the file
// and read the store on its own.
func setupTestRootKeyStorage(t *testing.T) (string, kvdb.Backend) {
	tempDir, err := ioutil.TempDir("", "macaroonstore-")
	if err != nil {
		t.Fatalf("Error creating temp dir: %v", err)
	}
	db, err := kvdb.Create(
		kvdb.BoltBackendName, path.Join(tempDir, "macaroons.db"), true,
		kvdb.DefaultDBTimeout,
	)
	if err != nil {
		t.Fatalf("Error opening store DB: %v", err)
	}
	store, err := macaroons.NewRootKeyStorage(db)
	if err != nil {
		db.Close()
		t.Fatalf("Error creating root key store: %v", err)
	}
	defer store.Close()
	err = store.CreateUnlock(&defaultPw)
	if err != nil {
		t.Fatalf("error creating unlock: %v", err)
	}
	return tempDir, db
}

// TestNewService tests the creation of the macaroon service.
func TestNewService(t *testing.T) {
	// First, initialize a dummy DB file with a store that the service
	// can read from. Make sure the file is removed in the end.
	tempDir, db := setupTestRootKeyStorage(t)
	defer os.RemoveAll(tempDir)

	// Second, create the new service instance, unlock it and pass in a
	// checker that we expect it to add to the bakery.
	service, err := macaroons.NewService(
		db, "lnd", false, macaroons.IPLockChecker,
	)
	if err != nil {
		t.Fatalf("Error creating new service: %v", err)
	}
	defer service.Close()
	err = service.CreateUnlock(&defaultPw)
	if err != nil {
		t.Fatalf("Error unlocking root key storage: %v", err)
	}

	// Third, check if the created service can bake macaroons.
	_, err = service.NewMacaroon(context.TODO(), nil, testOperation)
	if err != macaroons.ErrMissingRootKeyID {
		t.Fatalf("Received %v instead of ErrMissingRootKeyID", err)
	}

	macaroon, err := service.NewMacaroon(
		context.TODO(), macaroons.DefaultRootKeyID, testOperation,
	)
	if err != nil {
		t.Fatalf("Error creating macaroon from service: %v", err)
	}
	if macaroon.Namespace().String() != "std:" {
		t.Fatalf("The created macaroon has an invalid namespace: %s",
			macaroon.Namespace().String())
	}

	// Finally, check if the service has been initialized correctly and
	// the checker has been added.
	var checkerFound = false
	checker := service.Checker.FirstPartyCaveatChecker.(*checkers.Checker)
	for _, info := range checker.Info() {
		if info.Name == "ipaddr" &&
			info.Prefix == "" &&
			info.Namespace == "std" {
			checkerFound = true
		}
	}
	if !checkerFound {
		t.Fatalf("Checker '%s' not found in service.", "ipaddr")
	}
}

// TestValidateMacaroon tests the validation of a macaroon that is in an
// incoming context.
func TestValidateMacaroon(t *testing.T) {
	// First, initialize the service and unlock it.
	tempDir, db := setupTestRootKeyStorage(t)
	defer os.RemoveAll(tempDir)
	service, err := macaroons.NewService(
		db, "lnd", false, macaroons.IPLockChecker,
	)
	if err != nil {
		t.Fatalf("Error creating new service: %v", err)
	}
	defer service.Close()

	err = service.CreateUnlock(&defaultPw)
	if err != nil {
		t.Fatalf("Error unlocking root key storage: %v", err)
	}

	// Then, create a new macaroon that we can serialize.
	macaroon, err := service.NewMacaroon(
		context.TODO(), macaroons.DefaultRootKeyID, testOperation,
		testOperationURI,
	)
	if err != nil {
		t.Fatalf("Error creating macaroon from service: %v", err)
	}
	macaroonBinary, err := macaroon.M().MarshalBinary()
	if err != nil {
		t.Fatalf("Error serializing macaroon: %v", err)
	}

	// Because the macaroons are always passed in a context, we need to
	// mock one that has just the serialized macaroon as a value.
	md := metadata.New(map[string]string{
		"macaroon": hex.EncodeToString(macaroonBinary),
	})
	mockContext := metadata.NewIncomingContext(context.Background(), md)

	// Finally, validate the macaroon against the required permissions.
	err = service.ValidateMacaroon(
		mockContext, []bakery.Op{testOperation}, "FooMethod",
	)
	if err != nil {
		t.Fatalf("Error validating the macaroon: %v", err)
	}

	// If the macaroon has the method specific URI permission, the list of
	// required entity/action pairs is irrelevant.
	err = service.ValidateMacaroon(
		mockContext, []bakery.Op{{Entity: "irrelevant"}}, "SomeMethod",
	)
	if err != nil {
		t.Fatalf("Error validating the macaroon: %v", err)
	}
}

// TestListMacaroonIDs checks that ListMacaroonIDs returns the expected result.
func TestListMacaroonIDs(t *testing.T) {
	// First, initialize a dummy DB file with a store that the service
	// can read from. Make sure the file is removed in the end.
	tempDir, db := setupTestRootKeyStorage(t)
	defer os.RemoveAll(tempDir)

	// Second, create the new service instance, unlock it and pass in a
	// checker that we expect it to add to the bakery.
	service, err := macaroons.NewService(
		db, "lnd", false, macaroons.IPLockChecker,
	)
	require.NoError(t, err, "Error creating new service")
	defer service.Close()

	err = service.CreateUnlock(&defaultPw)
	require.NoError(t, err, "Error unlocking root key storage")

	// Third, make 3 new macaroons with different root key IDs.
	expectedIDs := [][]byte{{1}, {2}, {3}}
	for _, v := range expectedIDs {
		_, err := service.NewMacaroon(context.TODO(), v, testOperation)
		require.NoError(t, err, "Error creating macaroon from service")
	}

	// Finally, check that calling List return the expected values.
	ids, _ := service.ListMacaroonIDs(context.TODO())
	require.Equal(t, expectedIDs, ids, "root key IDs mismatch")
}

// TestDeleteMacaroonID removes the specific root key ID.
func TestDeleteMacaroonID(t *testing.T) {
	ctxb := context.Background()

	// First, initialize a dummy DB file with a store that the service
	// can read from. Make sure the file is removed in the end.
	tempDir, db := setupTestRootKeyStorage(t)
	defer os.RemoveAll(tempDir)

	// Second, create the new service instance, unlock it and pass in a
	// checker that we expect it to add to the bakery.
	service, err := macaroons.NewService(
		db, "lnd", false, macaroons.IPLockChecker,
	)
	require.NoError(t, err, "Error creating new service")
	defer service.Close()

	err = service.CreateUnlock(&defaultPw)
	require.NoError(t, err, "Error unlocking root key storage")

	// Third, checks that removing encryptedKeyID returns an error.
	encryptedKeyID := []byte("enckey")
	_, err = service.DeleteMacaroonID(ctxb, encryptedKeyID)
	require.Equal(t, macaroons.ErrDeletionForbidden, err)

	// Fourth, checks that removing DefaultKeyID returns an error.
	_, err = service.DeleteMacaroonID(ctxb, macaroons.DefaultRootKeyID)
	require.Equal(t, macaroons.ErrDeletionForbidden, err)

	// Fifth, checks that removing empty key id returns an error.
	_, err = service.DeleteMacaroonID(ctxb, []byte{})
	require.Equal(t, macaroons.ErrMissingRootKeyID, err)

	// Sixth, checks that removing a non-existed key id returns nil.
	nonExistedID := []byte("test-non-existed")
	deletedID, err := service.DeleteMacaroonID(ctxb, nonExistedID)
	require.NoError(t, err, "deleting macaroon ID got an error")
	require.Nil(t, deletedID, "deleting non-existed ID should return nil")

	// Seventh, make 3 new macaroons with different root key IDs, and delete
	// one.
	expectedIDs := [][]byte{{1}, {2}, {3}}
	for _, v := range expectedIDs {
		_, err := service.NewMacaroon(ctxb, v, testOperation)
		require.NoError(t, err, "Error creating macaroon from service")
	}
	deletedID, err = service.DeleteMacaroonID(ctxb, expectedIDs[0])
	require.NoError(t, err, "deleting macaroon ID got an error")

	// Finally, check that the ID is deleted.
	require.Equal(t, expectedIDs[0], deletedID, "expected ID to be removed")
	ids, _ := service.ListMacaroonIDs(ctxb)
	require.Equal(t, expectedIDs[1:], ids, "root key IDs mismatch")
}
