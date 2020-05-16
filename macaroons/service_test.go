package macaroons_test

import (
	"context"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/macaroons"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc/metadata"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

var (
	testOperation = bakery.Op{
		Entity: "testEntity",
		Action: "read",
	}
	defaultPw = []byte("hello")
)

// setupTestRootKeyStorage creates a dummy root key storage by
// creating a temporary macaroons.db and initializing it with the
// default password of 'hello'. Only the path to the temporary
// DB file is returned, because the service will open the file
// and read the store on its own.
func setupTestRootKeyStorage(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "macaroonstore-")
	if err != nil {
		t.Fatalf("Error creating temp dir: %v", err)
	}
	bboltOpts := &bbolt.Options{
		NoFreelistSync: true,
	}
	db, err := kvdb.Create(
		kvdb.BoltBackendName, path.Join(tempDir, "macaroons.db"),
		bboltOpts,
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
	return tempDir
}

// TestNewService tests the creation of the macaroon service.
func TestNewService(t *testing.T) {
	// First, initialize a dummy DB file with a store that the service
	// can read from. Make sure the file is removed in the end.
	tempDir := setupTestRootKeyStorage(t)
	defer os.RemoveAll(tempDir)

	// Second, create the new service instance, unlock it and pass in a
	// checker that we expect it to add to the bakery.
	service, err := macaroons.NewService(tempDir, macaroons.IPLockChecker)
	if err != nil {
		t.Fatalf("Error creating new service: %v", err)
	}
	defer service.Close()
	err = service.CreateUnlock(&defaultPw)
	if err != nil {
		t.Fatalf("Error unlocking root key storage: %v", err)
	}

	// Third, check if the created service can bake macaroons.
	macaroon, err := service.Oven.NewMacaroon(
		context.TODO(), bakery.LatestVersion, nil, testOperation,
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
	tempDir := setupTestRootKeyStorage(t)
	defer os.RemoveAll(tempDir)
	service, err := macaroons.NewService(tempDir, macaroons.IPLockChecker)
	if err != nil {
		t.Fatalf("Error creating new service: %v", err)
	}
	defer service.Close()

	err = service.CreateUnlock(&defaultPw)
	if err != nil {
		t.Fatalf("Error unlocking root key storage: %v", err)
	}

	// Then, create a new macaroon that we can serialize.
	macaroon, err := service.Oven.NewMacaroon(
		context.TODO(), bakery.LatestVersion, nil, testOperation,
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
	err = service.ValidateMacaroon(mockContext, []bakery.Op{testOperation})
	if err != nil {
		t.Fatalf("Error validating the macaroon: %v", err)
	}
}
