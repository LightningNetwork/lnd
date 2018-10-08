// +build debug

package bitcoindnotify

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
)

func initHintCache(t *testing.T) *chainntnfs.HeightHintCache {
	t.Helper()

	tempDir, err := ioutil.TempDir("", "kek")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}
	db, err := channeldb.Open(tempDir)
	if err != nil {
		t.Fatalf("unable to create db: %v", err)
	}
	hintCache, err := chainntnfs.NewHeightHintCache(
		db, true, DefaultHintPruneInterval, DefaultHintPruneTimeout,
	)
	if err != nil {
		t.Fatalf("unable to create hint cache: %v", err)
	}

	return hintCache
}

// setUpNotifier is a helper function to start a new notifier backed by a
// bitcoind driver.
func setUpNotifier(t *testing.T, bitcoindConn *chain.BitcoindConn,
	spendHintCache chainntnfs.SpendHintCache,
	confirmHintCache chainntnfs.ConfirmHintCache) *BitcoindNotifier {

	t.Helper()

	notifier := New(bitcoindConn, spendHintCache, confirmHintCache)
	if err := notifier.Start(); err != nil {
		t.Fatalf("unable to start notifier: %v", err)
	}

	return notifier
}

// syncNotifierWithMiner is a helper method that attempts to wait until the
// notifier is synced (in terms of the chain) with the miner.
func syncNotifierWithMiner(t *testing.T, notifier *BitcoindNotifier,
	miner *rpctest.Harness) uint32 {

	t.Helper()

	_, minerHeight, err := miner.Node.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to retrieve miner's current height: %v", err)
	}

	timeout := time.After(10 * time.Second)
	for {
		_, bitcoindHeight, err := notifier.chainConn.GetBestBlock()
		if err != nil {
			t.Fatalf("unable to retrieve bitcoind's current "+
				"height: %v", err)
		}

		if bitcoindHeight == minerHeight {
			return uint32(bitcoindHeight)
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-timeout:
			t.Fatalf("timed out waiting to sync notifier")
		}
	}
}

// TestHistoricalConfDetailsTxIndex ensures that we correctly retrieve
// historical confirmation details using the backend node's txindex.
func TestHistoricalConfDetailsTxIndex(t *testing.T) {
	miner, tearDown := chainntnfs.NewMiner(
		t, []string{"--txindex"}, true, 25,
	)
	defer tearDown()

	bitcoindConn, cleanUp := chainntnfs.NewBitcoindBackend(
		t, miner.P2PAddress(), true,
	)
	defer cleanUp()

	hintCache := initHintCache(t)

	notifier := setUpNotifier(t, bitcoindConn, hintCache, hintCache)
	defer notifier.Stop()

	syncNotifierWithMiner(t, notifier, miner)

	// A transaction unknown to the node should not be found within the
	// txindex even if it is enabled, so we should not proceed with any
	// fallback methods.
	var zeroHash chainhash.Hash
	_, txStatus, err := notifier.historicalConfDetails(&zeroHash, 0, 0)
	if err != nil {
		t.Fatalf("unable to retrieve historical conf details: %v", err)
	}

	switch txStatus {
	case chainntnfs.TxNotFoundIndex:
	case chainntnfs.TxNotFoundManually:
		t.Fatal("should not have proceeded with fallback method, but did")
	default:
		t.Fatal("should not have found non-existent transaction, but did")
	}

	// Now, we'll create a test transaction, confirm it, and attempt to
	// retrieve its confirmation details.
	txid, _, err := chainntnfs.GetTestTxidAndScript(miner)
	if err != nil {
		t.Fatalf("unable to create tx: %v", err)
	}
	if err := chainntnfs.WaitForMempoolTx(miner, txid); err != nil {
		t.Fatal(err)
	}

	// The transaction should be found in the mempool at this point.
	_, txStatus, err = notifier.historicalConfDetails(txid, 0, 0)
	if err != nil {
		t.Fatalf("unable to retrieve historical conf details: %v", err)
	}

	// Since it has yet to be included in a block, it should have been found
	// within the mempool.
	switch txStatus {
	case chainntnfs.TxFoundMempool:
	default:
		t.Fatal("should have found the transaction within the "+
			"mempool, but did not: %v", txStatus)
	}

	if _, err := miner.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Ensure the notifier and miner are synced to the same height to ensure
	// the txindex includes the transaction just mined.
	syncNotifierWithMiner(t, notifier, miner)

	_, txStatus, err = notifier.historicalConfDetails(txid, 0, 0)
	if err != nil {
		t.Fatalf("unable to retrieve historical conf details: %v", err)
	}

	// Since the backend node's txindex is enabled and the transaction has
	// confirmed, we should be able to retrieve it using the txindex.
	switch txStatus {
	case chainntnfs.TxFoundIndex:
	default:
		t.Fatal("should have found the transaction within the " +
			"txindex, but did not")
	}
}

// TestHistoricalConfDetailsNoTxIndex ensures that we correctly retrieve
// historical confirmation details using the set of fallback methods when the
// backend node's txindex is disabled.
func TestHistoricalConfDetailsNoTxIndex(t *testing.T) {
	miner, tearDown := chainntnfs.NewMiner(t, nil, true, 25)
	defer tearDown()

	bitcoindConn, cleanUp := chainntnfs.NewBitcoindBackend(
		t, miner.P2PAddress(), false,
	)
	defer cleanUp()

	hintCache := initHintCache(t)

	notifier := setUpNotifier(t, bitcoindConn, hintCache, hintCache)
	defer notifier.Stop()

	// Since the node has its txindex disabled, we fall back to scanning the
	// chain manually. A transaction unknown to the network should not be
	// found.
	var zeroHash chainhash.Hash
	broadcastHeight := syncNotifierWithMiner(t, notifier, miner)
	_, txStatus, err := notifier.historicalConfDetails(
		&zeroHash, uint32(broadcastHeight), uint32(broadcastHeight),
	)
	if err != nil {
		t.Fatalf("unable to retrieve historical conf details: %v", err)
	}

	switch txStatus {
	case chainntnfs.TxNotFoundManually:
	case chainntnfs.TxNotFoundIndex:
		t.Fatal("should have proceeded with fallback method, but did not")
	default:
		t.Fatal("should not have found non-existent transaction, but did")
	}

	// Now, we'll create a test transaction and attempt to retrieve its
	// confirmation details. In order to fall back to manually scanning the
	// chain, the transaction must be in the chain and not contain any
	// unspent outputs. To ensure this, we'll create a transaction with only
	// one output, which we will manually spend. The backend node's
	// transaction index should also be disabled, which we've already
	// ensured above.
	output, pkScript := chainntnfs.CreateSpendableOutput(t, miner)
	spendTx := chainntnfs.CreateSpendTx(t, output, pkScript)
	spendTxHash, err := miner.Node.SendRawTransaction(spendTx, true)
	if err != nil {
		t.Fatalf("unable to broadcast tx: %v", err)
	}
	if err := chainntnfs.WaitForMempoolTx(miner, spendTxHash); err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}
	if _, err := miner.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Ensure the notifier and miner are synced to the same height to ensure
	// we can find the transaction when manually scanning the chain.
	currentHeight := syncNotifierWithMiner(t, notifier, miner)
	_, txStatus, err = notifier.historicalConfDetails(
		&output.Hash, uint32(broadcastHeight), uint32(currentHeight),
	)
	if err != nil {
		t.Fatalf("unable to retrieve historical conf details: %v", err)
	}

	// Since the backend node's txindex is disabled and the transaction has
	// confirmed, we should be able to find it by falling back to scanning
	// the chain manually.
	switch txStatus {
	case chainntnfs.TxFoundManually:
	default:
		t.Fatal("should have found the transaction by manually " +
			"scanning the chain, but did not")
	}
}
