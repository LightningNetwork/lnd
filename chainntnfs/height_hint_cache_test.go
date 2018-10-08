package chainntnfs

import (
	"bytes"
	"io/ioutil"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
)

func initHintCache(t *testing.T, disable bool,
	pruneInterval, pruneTimeout time.Duration) *HeightHintCache {

	t.Helper()

	tempDir, err := ioutil.TempDir("", "kek")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}
	db, err := channeldb.Open(tempDir)
	if err != nil {
		t.Fatalf("unable to create db: %v", err)
	}
	hintCache, err := NewHeightHintCache(
		db, disable, pruneInterval, pruneTimeout,
	)
	if err != nil {
		t.Fatalf("unable to create hint cache: %v", err)
	}

	err = hintCache.Start()
	if err != nil {
		t.Fatalf("unable to start hint cache: %v", err)
	}

	return hintCache
}

// TestHeightHintCacheConfirms ensures that the height hint cache properly
// caches confirm hints for transactions.
func TestHeightHintCacheConfirms(t *testing.T) {
	t.Parallel()

	hintCache := initHintCache(
		t, false, DefaultHintPruneInterval, DefaultHintPruneTimeout,
	)
	defer hintCache.Stop()

	// Querying for a transaction hash not found within the cache should
	// return an error indication so.
	var unknownHash chainhash.Hash
	_, err := hintCache.QueryConfirmHint(unknownHash)
	if err != ErrConfirmHintNotFound {
		t.Fatalf("expected ErrConfirmHintNotFound, got: %v", err)
	}

	// Now, we'll create some transaction hashes and commit them to the
	// cache with the same confirm hint.
	const height = 100
	const numHashes = 5
	txHashes := make([]chainhash.Hash, numHashes)
	for i := 0; i < numHashes; i++ {
		var txHash chainhash.Hash
		copy(txHash[:], bytes.Repeat([]byte{byte(i)}, 32))
		txHashes[i] = txHash
	}

	if err := hintCache.CommitConfirmHint(height, txHashes...); err != nil {
		t.Fatalf("unable to add entries to cache: %v", err)
	}

	// With the hashes committed, we'll now query the cache to ensure that
	// we're able to properly retrieve the confirm hints.
	for _, txHash := range txHashes {
		confirmHint, err := hintCache.QueryConfirmHint(txHash)
		if err != nil {
			t.Fatalf("unable to query for hint: %v", err)
		}
		if confirmHint != height {
			t.Fatalf("expected confirm hint %d, got %d", height,
				confirmHint)
		}
	}

	// We'll also attempt to purge all of them in a single database
	// transaction.
	if err := hintCache.PurgeConfirmHint(txHashes...); err != nil {
		t.Fatalf("unable to remove confirm hints: %v", err)
	}

	// Finally, we'll attempt to query for each hash. We should expect not
	// to find a hint for any of them.
	for _, txHash := range txHashes {
		_, err := hintCache.QueryConfirmHint(txHash)
		if err != ErrConfirmHintNotFound {
			t.Fatalf("expected ErrConfirmHintNotFound, got :%v", err)
		}
	}
}

// TestHeightHintCacheSpends ensures that the height hint cache properly caches
// spend hints for outpoints.
func TestHeightHintCacheSpends(t *testing.T) {
	t.Parallel()

	hintCache := initHintCache(
		t, false, DefaultHintPruneInterval, DefaultHintPruneTimeout,
	)
	defer hintCache.Stop()

	// Querying for an outpoint not found within the cache should return an
	// error indication so.
	var unknownOutPoint wire.OutPoint
	_, err := hintCache.QuerySpendHint(unknownOutPoint)
	if err != ErrSpendHintNotFound {
		t.Fatalf("expected ErrSpendHintNotFound, got: %v", err)
	}

	// Now, we'll create some outpoints and commit them to the cache with
	// the same spend hint.
	const height = 100
	const numOutpoints = 5
	var txHash chainhash.Hash
	copy(txHash[:], bytes.Repeat([]byte{0xFF}, 32))
	outpoints := make([]wire.OutPoint, numOutpoints)
	for i := uint32(0); i < numOutpoints; i++ {
		outpoints[i] = wire.OutPoint{Hash: txHash, Index: i}
	}

	if err := hintCache.CommitSpendHint(height, outpoints...); err != nil {
		t.Fatalf("unable to add entry to cache: %v", err)
	}

	// With the outpoints committed, we'll now query the cache to ensure
	// that we're able to properly retrieve the confirm hints.
	for _, op := range outpoints {
		spendHint, err := hintCache.QuerySpendHint(op)
		if err != nil {
			t.Fatalf("unable to query for hint: %v", err)
		}
		if spendHint != height {
			t.Fatalf("expected spend hint %d, got %d", height,
				spendHint)
		}
	}

	// We'll also attempt to purge all of them in a single database
	// transaction.
	if err := hintCache.PurgeSpendHint(outpoints...); err != nil {
		t.Fatalf("unable to remove spend hint: %v", err)
	}

	// Finally, we'll attempt to query for each outpoint. We should expect
	// not to find a hint for any of them.
	for _, op := range outpoints {
		_, err = hintCache.QuerySpendHint(op)
		if err != ErrSpendHintNotFound {
			t.Fatalf("expected ErrSpendHintNotFound, got: %v", err)
		}
	}
}

// TestHeightHintCacheDisabled asserts that a disabled height hint cache never
// returns spend or confirm hints that are committed.
func TestHeightHintCacheDisabled(t *testing.T) {
	t.Parallel()

	const height uint32 = 100

	// Create a disabled height hint cache.
	hintCache := initHintCache(
		t, true, DefaultHintPruneInterval, DefaultHintPruneTimeout,
	)

	// Querying a disabled cache w/ no spend hint should return not found.
	var outpoint wire.OutPoint
	_, err := hintCache.QuerySpendHint(outpoint)
	if err != ErrSpendHintNotFound {
		t.Fatalf("expected ErrSpendHintNotFound, got: %v", err)
	}

	// Commit a spend hint to the disabled cache, which should be a noop.
	if err := hintCache.CommitSpendHint(height, outpoint); err != nil {
		t.Fatalf("unable to commit spend hint: %v", err)
	}

	// Querying a disabled cache after commit noop should return not found.
	_, err = hintCache.QuerySpendHint(outpoint)
	if err != ErrSpendHintNotFound {
		t.Fatalf("expected ErrSpendHintNotFound, got: %v", err)
	}

	// Reenable the cache, this time actually committing a spend hint.
	hintCache.disabled = false
	if err := hintCache.CommitSpendHint(height, outpoint); err != nil {
		t.Fatalf("unable to commit spend hint: %v", err)
	}

	// Disable the cache again, spend hint should not be found.
	hintCache.disabled = true
	_, err = hintCache.QuerySpendHint(outpoint)
	if err != ErrSpendHintNotFound {
		t.Fatalf("expected ErrSpendHintNotFound, got: %v", err)
	}

	// Querying a disabled cache w/ no conf hint should return not found.
	var txid chainhash.Hash
	_, err = hintCache.QueryConfirmHint(txid)
	if err != ErrConfirmHintNotFound {
		t.Fatalf("expected ErrConfirmHintNotFound, got: %v", err)
	}

	// Commit a conf hint to the disabled cache, which should be a noop.
	if err := hintCache.CommitConfirmHint(height, txid); err != nil {
		t.Fatalf("unable to commit spend hint: %v", err)
	}

	// Querying a disabled cache after commit noop should return not found.
	_, err = hintCache.QueryConfirmHint(txid)
	if err != ErrConfirmHintNotFound {
		t.Fatalf("expected ErrConfirmHintNotFound, got: %v", err)
	}

	// Reenable the cache, this time actually committing a conf hint.
	hintCache.disabled = false
	if err := hintCache.CommitConfirmHint(height, txid); err != nil {
		t.Fatalf("unable to commit spend hint: %v", err)
	}

	// Disable the cache again, conf hint should not be found.
	hintCache.disabled = true
	_, err = hintCache.QueryConfirmHint(txid)
	if err != ErrConfirmHintNotFound {
		t.Fatalf("expected ErrConfirmHintNotFound, got: %v", err)
	}
}

// TestHeightHintCacheZombiePurge verifies the behavior of the height hint
// cache's garbage collection, and checks that we continue to delay pruning of
// entries that we are still updating or querying.
func TestHeightHintCacheZombiePurge(t *testing.T) {
	t.Parallel()

	const interval = 3 * time.Second
	const timeout = 2 * time.Second
	const tolerance = 200 * time.Millisecond

	hintCache := initHintCache(t, false, interval, timeout)
	defer hintCache.Stop()

	// With the cache started, we'll construct all relevant timers here so
	// that they are as synchronized with the hint cache's garbage
	// collection as much as possible.
	//
	// The three timers fire:
	//  before1: before first gc cycle
	//  after1: after first gc cycle
	//  before2: before the second gc cylce
	//  at2: concurrently with the second pruning
	//  after3: after the third gc cycle
	before1 := time.After(interval - tolerance)
	after1 := time.After(interval + tolerance)
	before2 := time.After(2*interval - tolerance)
	at2 := time.After(2 * interval)
	after3 := time.After(3*interval + tolerance)

	const height = 100
	const numHashes = 6
	txHashes := make([]chainhash.Hash, numHashes)
	for i := 0; i < numHashes; i++ {
		var txHash chainhash.Hash
		copy(txHash[:], bytes.Repeat([]byte{byte(i)}, 32))
		txHashes[i] = txHash
	}

	const numOutpoints = 6
	var txHash chainhash.Hash
	copy(txHash[:], bytes.Repeat([]byte{0xFF}, 32))
	outpoints := make([]wire.OutPoint, numOutpoints)
	for i := uint32(0); i < numOutpoints; i++ {
		outpoints[i] = wire.OutPoint{Hash: txHash, Index: i}
	}

	if err := hintCache.CommitConfirmHint(height, txHashes...); err != nil {
		t.Fatalf("unable to add entries to cache: %v", err)
	}
	if err := hintCache.CommitSpendHint(height, outpoints...); err != nil {
		t.Fatalf("unable to add outpoints to cache: %v", err)
	}

	<-before1

	// Simulate registration that happens shortly after startup.
	for i := 0; i < numHashes/2; i++ {
		_, err := hintCache.QueryConfirmHint(txHashes[i])
		if err != nil {
			t.Fatalf("unable to query for conf hint: %v", err)
		}
	}
	for i := 0; i < numOutpoints/2; i++ {
		_, err := hintCache.QuerySpendHint(outpoints[i])
		if err != nil {
			t.Fatalf("unable to query for spend hint: %v", err)
		}
	}

	<-after1

	// The latter half should be purged, as they were not queried before the
	// prune timeout.
	for i := numHashes / 2; i < numHashes; i++ {
		_, err := hintCache.QueryConfirmHint(txHashes[i])
		if err != ErrConfirmHintNotFound {
			t.Fatalf("unexpected error when querying for "+
				"pruned confirm hint, want: %v, got: %v",
				ErrConfirmHintNotFound, err)
		}
	}
	for i := numOutpoints / 2; i < numOutpoints; i++ {
		_, err := hintCache.QuerySpendHint(outpoints[i])
		if err != ErrSpendHintNotFound {
			t.Fatalf("unexpected error when querying for "+
				"pruned spend hint, want: %v, got %v",
				ErrSpendHintNotFound, err)
		}
	}

	// To make sure the first half didn't get cleaned up, we'll query each
	// of them. This will reset the timeout for each.
	for i := 0; i < numHashes/2; i++ {
		_, err := hintCache.QueryConfirmHint(txHashes[i])
		if err != nil {
			t.Fatalf("unable to query for conf hint: %v", err)
		}
	}

	for i := 0; i < numOutpoints/2; i++ {
		_, err := hintCache.QuerySpendHint(outpoints[i])
		if err != nil {
			t.Fatalf("unable to query for spend hint: %v", err)
		}
	}

	<-before2

	// Just before starting the second gc cycle, update the heights for our
	// first half of spend and conf hints. This should cause all of these
	// hints to survive the cycle.
	err := hintCache.CommitConfirmHint(height+1, txHashes[:len(txHashes)/2]...)
	if err != nil {
		t.Fatalf("unable to add entries to cache: %v", err)
	}
	err = hintCache.CommitSpendHint(height+1, outpoints[:len(outpoints)/2]...)
	if err != nil {
		t.Fatalf("unable to add outpoints to cache: %v", err)
	}

	<-at2

	// As soon as the second cycle ends, query to make sure the first half
	// didn't get cleaned up. This will reset the timeouts, but they should
	// expire again in time to get cleaned up in the third cycle.
	for i := 0; i < numHashes/2; i++ {
		_, err := hintCache.QueryConfirmHint(txHashes[i])
		if err != nil {
			t.Fatalf("unable to query for conf hint: %v", err)
		}
	}

	for i := 0; i < numOutpoints/2; i++ {
		_, err := hintCache.QuerySpendHint(outpoints[i])
		if err != nil {
			t.Fatalf("unable to query for spend hint: %v", err)
		}
	}

	<-after3

	// Verify that the first half has now been removed after the third
	// cycle.
	for i := 0; i < numHashes/2; i++ {
		_, err := hintCache.QueryConfirmHint(txHashes[i])
		if err != ErrConfirmHintNotFound {
			t.Fatalf("unexpected error when querying for "+
				"pruned confirm hint, want: %v, got: %v",
				ErrConfirmHintNotFound, err)
		}
	}

	for i := 0; i < numOutpoints/2; i++ {
		_, err := hintCache.QuerySpendHint(outpoints[i])
		if err != ErrSpendHintNotFound {
			t.Fatalf("unexpected error when querying for "+
				"pruned spend hint, want: %v, got %v",
				ErrSpendHintNotFound, err)
		}
	}
}
