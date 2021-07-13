package htlcswitch

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lntest/mock"
)

const (
	cltv uint32 = 100000
)

// tempDecayedLogPath creates a new temporary database path to back a single
// decayed log instance.
func tempDecayedLogPath(t *testing.T) string {
	dir, err := ioutil.TempDir("", "decayedlog")
	if err != nil {
		t.Fatalf("unable to create temporary decayed log dir: %v", err)
	}

	return dir
}

// startup sets up the DecayedLog and possibly the garbage collector.
func startup(dbPath string, notifier bool) (sphinx.ReplayLog,
	*mock.ChainNotifier, *sphinx.HashPrefix, error) {

	cfg := &kvdb.BoltConfig{
		DBTimeout: time.Second,
	}
	backend, err := NewBoltBackendCreator(dbPath, "sphinxreplay.db")(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create temporary "+
			"decayed log db: %v", err)
	}

	var log sphinx.ReplayLog
	var chainNotifier *mock.ChainNotifier
	if notifier {

		// Create the MockNotifier which triggers the garbage collector
		chainNotifier = &mock.ChainNotifier{
			SpendChan: make(chan *chainntnfs.SpendDetail),
			EpochChan: make(chan *chainntnfs.BlockEpoch, 1),
			ConfChan:  make(chan *chainntnfs.TxConfirmation),
		}

		// Initialize the DecayedLog object
		log = NewDecayedLog(backend, chainNotifier)
	} else {
		// Initialize the DecayedLog object
		log = NewDecayedLog(backend, nil)
	}

	// Open the channeldb (start the garbage collector)
	err = log.Start()
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a HashPrefix identifier for a packet. Instead of actually
	// generating an ECDH secret and hashing it, simulate with random bytes.
	// This is used as a key to retrieve the cltv value.
	var hashedSecret sphinx.HashPrefix
	_, err = rand.Read(hashedSecret[:])
	if err != nil {
		return nil, nil, nil, err
	}

	return log, chainNotifier, &hashedSecret, nil
}

// shutdown deletes the temporary directory that the test database uses
// and handles closing the database.
func shutdown(dir string, d sphinx.ReplayLog) {
	d.Stop()
	os.RemoveAll(dir)
}

// TestDecayedLogGarbageCollector tests the ability of the garbage collector
// to delete expired cltv values every time a block is received. Expired cltv
// values are cltv values that are < current block height.
func TestDecayedLogGarbageCollector(t *testing.T) {
	t.Parallel()

	dbPath := tempDecayedLogPath(t)

	d, notifier, hashedSecret, err := startup(dbPath, true)
	if err != nil {
		t.Fatalf("Unable to start up DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d)

	// Store <hashedSecret, cltv> in the sharedHashBucket.
	err = d.Put(hashedSecret, cltv)
	if err != nil {
		t.Fatalf("Unable to store in channeldb: %v", err)
	}

	// Wait for database write (GC is in a goroutine)
	time.Sleep(500 * time.Millisecond)

	// Send block notifications to garbage collector. The garbage collector
	// should remove the entry by block 100001.

	// Send block 100000
	notifier.EpochChan <- &chainntnfs.BlockEpoch{
		Height: 100000,
	}

	// Assert that hashedSecret is still in the sharedHashBucket
	val, err := d.Get(hashedSecret)
	if err != nil {
		t.Fatalf("Get failed - received an error upon Get: %v", err)
	}

	if val != cltv {
		t.Fatalf("GC incorrectly deleted CLTV")
	}

	// Send block 100001 (expiry block)
	notifier.EpochChan <- &chainntnfs.BlockEpoch{
		Height: 100001,
	}

	// Wait for database write (GC is in a goroutine)
	time.Sleep(500 * time.Millisecond)

	// Assert that hashedSecret is not in the sharedHashBucket
	_, err = d.Get(hashedSecret)
	if err == nil {
		t.Fatalf("CLTV was not deleted")
	}
	if err != sphinx.ErrLogEntryNotFound {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}
}

// TestDecayedLogPersistentGarbageCollector tests the persistence property of
// the garbage collector. The garbage collector will be restarted immediately and
// a block that expires the stored CLTV value will be sent to the ChainNotifier.
// We test that this causes the <hashedSecret, CLTV> pair to be deleted even
// on GC restarts.
func TestDecayedLogPersistentGarbageCollector(t *testing.T) {
	t.Parallel()

	dbPath := tempDecayedLogPath(t)

	d, _, hashedSecret, err := startup(dbPath, true)
	if err != nil {
		t.Fatalf("Unable to start up DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d)

	// Store <hashedSecret, cltv> in the sharedHashBucket
	if err = d.Put(hashedSecret, cltv); err != nil {
		t.Fatalf("Unable to store in channeldb: %v", err)
	}

	// The hash prefix should be retrievable from the decayed log.
	_, err = d.Get(hashedSecret)
	if err != nil {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}

	// Shut down DecayedLog and the garbage collector along with it.
	d.Stop()

	d2, notifier2, _, err := startup(dbPath, true)
	if err != nil {
		t.Fatalf("Unable to restart DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d2)

	// Check that the hash prefix still exists in the new db instance.
	_, err = d2.Get(hashedSecret)
	if err != nil {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}

	// Send a block notification to the garbage collector that expires
	// the stored CLTV.
	notifier2.EpochChan <- &chainntnfs.BlockEpoch{
		Height: int32(100001),
	}

	// Wait for database write (GC is in a goroutine)
	time.Sleep(500 * time.Millisecond)

	// Assert that hashedSecret is not in the sharedHashBucket
	_, err = d2.Get(hashedSecret)
	if err != sphinx.ErrLogEntryNotFound {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}
}

// TestDecayedLogInsertionAndRetrieval inserts a cltv value into the
// sharedHashBucket and then deletes it and finally asserts that we can no
// longer retrieve it.
func TestDecayedLogInsertionAndDeletion(t *testing.T) {
	t.Parallel()

	dbPath := tempDecayedLogPath(t)

	d, _, hashedSecret, err := startup(dbPath, false)
	if err != nil {
		t.Fatalf("Unable to start up DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d)

	// Store <hashedSecret, cltv> in the sharedHashBucket.
	err = d.Put(hashedSecret, cltv)
	if err != nil {
		t.Fatalf("Unable to store in channeldb: %v", err)
	}

	// Delete hashedSecret from the sharedHashBucket.
	err = d.Delete(hashedSecret)
	if err != nil {
		t.Fatalf("Unable to delete from channeldb: %v", err)
	}

	// Assert that hashedSecret is not in the sharedHashBucket
	_, err = d.Get(hashedSecret)
	if err == nil {
		t.Fatalf("CLTV was not deleted")
	}
	if err != sphinx.ErrLogEntryNotFound {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}
}

// TestDecayedLogStartAndStop tests for persistence. The DecayedLog is started,
// a cltv value is stored in the sharedHashBucket, and then it the DecayedLog
// is stopped. The DecayedLog is then started up again and we test that the
// cltv value is indeed still stored in the sharedHashBucket. We then delete
// the cltv value and check that it persists upon startup.
func TestDecayedLogStartAndStop(t *testing.T) {
	t.Parallel()

	dbPath := tempDecayedLogPath(t)

	d, _, hashedSecret, err := startup(dbPath, false)
	if err != nil {
		t.Fatalf("Unable to start up DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d)

	// Store <hashedSecret, cltv> in the sharedHashBucket.
	err = d.Put(hashedSecret, cltv)
	if err != nil {
		t.Fatalf("Unable to store in channeldb: %v", err)
	}

	// Shutdown the DecayedLog's channeldb
	d.Stop()

	d2, _, hashedSecret2, err := startup(dbPath, false)
	if err != nil {
		t.Fatalf("Unable to restart DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d2)

	// Retrieve the stored cltv value given the hashedSecret key.
	value, err := d2.Get(hashedSecret)
	if err != nil {
		t.Fatalf("Unable to retrieve from channeldb: %v", err)
	}

	// Check that the original cltv value matches the retrieved cltv
	// value.
	if cltv != value {
		t.Fatalf("Value retrieved doesn't match value stored")
	}

	// Delete hashedSecret from sharedHashBucket
	err = d2.Delete(hashedSecret2)
	if err != nil {
		t.Fatalf("Unable to delete from channeldb: %v", err)
	}

	// Shutdown the DecayedLog's channeldb
	d2.Stop()

	d3, _, hashedSecret3, err := startup(dbPath, false)
	if err != nil {
		t.Fatalf("Unable to restart DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d3)

	// Assert that hashedSecret is not in the sharedHashBucket
	_, err = d3.Get(hashedSecret3)
	if err == nil {
		t.Fatalf("CLTV was not deleted")
	}
	if err != sphinx.ErrLogEntryNotFound {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}
}

// TestDecayedLogStorageAndRetrieval stores a cltv value and then retrieves it
// via the nested sharedHashBucket and finally asserts that the original stored
// and retrieved cltv values are equal.
func TestDecayedLogStorageAndRetrieval(t *testing.T) {
	t.Parallel()

	dbPath := tempDecayedLogPath(t)

	d, _, hashedSecret, err := startup(dbPath, false)
	if err != nil {
		t.Fatalf("Unable to start up DecayedLog: %v", err)
	}
	defer shutdown(dbPath, d)

	// Store <hashedSecret, cltv> in the sharedHashBucket
	err = d.Put(hashedSecret, cltv)
	if err != nil {
		t.Fatalf("Unable to store in channeldb: %v", err)
	}

	// Retrieve the stored cltv value given the hashedSecret key.
	value, err := d.Get(hashedSecret)
	if err != nil {
		t.Fatalf("Unable to retrieve from channeldb: %v", err)
	}

	// If the original cltv value does not match the value retrieved,
	// then the test failed.
	if cltv != value {
		t.Fatalf("Value retrieved doesn't match value stored")
	}
}
