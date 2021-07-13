package itest

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
)

var (
	harnessNetParams = &chaincfg.RegressionNetParams

	// lndExecutable is the full path to the lnd binary.
	lndExecutable = flag.String(
		"lndexec", itestLndBinary, "full path to lnd binary",
	)
)

const (
	testFeeBase         = 1e+6
	defaultCSV          = lntest.DefaultCSV
	defaultTimeout      = lntest.DefaultTimeout
	minerMempoolTimeout = lntest.MinerMempoolTimeout
	channelOpenTimeout  = lntest.ChannelOpenTimeout
	channelCloseTimeout = lntest.ChannelCloseTimeout
	itestLndBinary      = "../../lnd-itest"
	anchorSize          = 330
	noFeeLimitMsat      = math.MaxInt64

	AddrTypeWitnessPubkeyHash = lnrpc.AddressType_WITNESS_PUBKEY_HASH
	AddrTypeNestedPubkeyHash  = lnrpc.AddressType_NESTED_PUBKEY_HASH
)

// harnessTest wraps a regular testing.T providing enhanced error detection
// and propagation. All error will be augmented with a full stack-trace in
// order to aid in debugging. Additionally, any panics caused by active
// test cases will also be handled and represented as fatals.
type harnessTest struct {
	t *testing.T

	// testCase is populated during test execution and represents the
	// current test case.
	testCase *testCase

	// lndHarness is a reference to the current network harness. Will be
	// nil if not yet set up.
	lndHarness *lntest.NetworkHarness
}

// newHarnessTest creates a new instance of a harnessTest from a regular
// testing.T instance.
func newHarnessTest(t *testing.T, net *lntest.NetworkHarness) *harnessTest {
	return &harnessTest{t, nil, net}
}

// Skipf calls the underlying testing.T's Skip method, causing the current test
// to be skipped.
func (h *harnessTest) Skipf(format string, args ...interface{}) {
	h.t.Skipf(format, args...)
}

// Fatalf causes the current active test case to fail with a fatal error. All
// integration tests should mark test failures solely with this method due to
// the error stack traces it produces.
func (h *harnessTest) Fatalf(format string, a ...interface{}) {
	if h.lndHarness != nil {
		h.lndHarness.SaveProfilesPages(h.t)
	}

	stacktrace := errors.Wrap(fmt.Sprintf(format, a...), 1).ErrorStack()

	if h.testCase != nil {
		h.t.Fatalf("Failed: (%v): exited with error: \n"+
			"%v", h.testCase.name, stacktrace)
	} else {
		h.t.Fatalf("Error outside of test: %v", stacktrace)
	}
}

// RunTestCase executes a harness test case. Any errors or panics will be
// represented as fatal.
func (h *harnessTest) RunTestCase(testCase *testCase) {

	h.testCase = testCase
	defer func() {
		h.testCase = nil
	}()

	defer func() {
		if err := recover(); err != nil {
			description := errors.Wrap(err, 2).ErrorStack()
			h.t.Fatalf("Failed: (%v) panicked with: \n%v",
				h.testCase.name, description)
		}
	}()

	testCase.test(h.lndHarness, h)
}

func (h *harnessTest) Logf(format string, args ...interface{}) {
	h.t.Logf(format, args...)
}

func (h *harnessTest) Log(args ...interface{}) {
	h.t.Log(args...)
}

func (h *harnessTest) getLndBinary() string {
	binary := itestLndBinary
	lndExec := ""
	if lndExecutable != nil && *lndExecutable != "" {
		lndExec = *lndExecutable
	}
	if lndExec == "" && runtime.GOOS == "windows" {
		// Windows (even in a bash like environment like git bash as on
		// Travis) doesn't seem to like relative paths to exe files...
		currentDir, err := os.Getwd()
		if err != nil {
			h.Fatalf("unable to get working directory: %v", err)
		}
		targetPath := filepath.Join(currentDir, "../../lnd-itest.exe")
		binary, err = filepath.Abs(targetPath)
		if err != nil {
			h.Fatalf("unable to get absolute path: %v", err)
		}
	} else if lndExec != "" {
		binary = lndExec
	}

	return binary
}

type testCase struct {
	name string
	test func(net *lntest.NetworkHarness, t *harnessTest)
}

// waitForTxInMempool polls until finding one transaction in the provided
// miner's mempool. An error is returned if *one* transaction isn't found within
// the given timeout.
func waitForTxInMempool(miner *rpcclient.Client,
	timeout time.Duration) (*chainhash.Hash, error) {

	txs, err := waitForNTxsInMempool(miner, 1, timeout)
	if err != nil {
		return nil, err
	}

	return txs[0], err
}

// waitForNTxsInMempool polls until finding the desired number of transactions
// in the provided miner's mempool. An error is returned if this number is not
// met after the given timeout.
func waitForNTxsInMempool(miner *rpcclient.Client, n int,
	timeout time.Duration) ([]*chainhash.Hash, error) {

	breakTimeout := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var err error
	var mempool []*chainhash.Hash
	for {
		select {
		case <-breakTimeout:
			return nil, fmt.Errorf("wanted %v, found %v txs "+
				"in mempool: %v", n, len(mempool), mempool)
		case <-ticker.C:
			mempool, err = miner.GetRawMempool()
			if err != nil {
				return nil, err
			}

			if len(mempool) == n {
				return mempool, nil
			}
		}
	}
}

// mineBlocks mine 'num' of blocks and check that blocks are present in
// node blockchain. numTxs should be set to the number of transactions
// (excluding the coinbase) we expect to be included in the first mined block.
func mineBlocks(t *harnessTest, net *lntest.NetworkHarness,
	num uint32, numTxs int) []*wire.MsgBlock {

	// If we expect transactions to be included in the blocks we'll mine,
	// we wait here until they are seen in the miner's mempool.
	var txids []*chainhash.Hash
	var err error
	if numTxs > 0 {
		txids, err = waitForNTxsInMempool(
			net.Miner.Client, numTxs, minerMempoolTimeout,
		)
		if err != nil {
			t.Fatalf("unable to find txns in mempool: %v", err)
		}
	}

	blocks := make([]*wire.MsgBlock, num)

	blockHashes, err := net.Miner.Client.Generate(num)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	for i, blockHash := range blockHashes {
		block, err := net.Miner.Client.GetBlock(blockHash)
		if err != nil {
			t.Fatalf("unable to get block: %v", err)
		}

		blocks[i] = block
	}

	// Finally, assert that all the transactions were included in the first
	// block.
	for _, txid := range txids {
		assertTxInBlock(t, blocks[0], txid)
	}

	return blocks
}

func assertTxInBlock(t *harnessTest, block *wire.MsgBlock, txid *chainhash.Hash) {
	for _, tx := range block.Transactions {
		sha := tx.TxHash()
		if bytes.Equal(txid[:], sha[:]) {
			return
		}
	}

	t.Fatalf("tx was not included in block")
}

func assertWalletUnspent(t *harnessTest, node *lntest.HarnessNode, out *lnrpc.OutPoint) {
	t.t.Helper()

	err := wait.NoError(func() error {
		ctxt, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		unspent, err := node.ListUnspent(ctxt, &lnrpc.ListUnspentRequest{})
		if err != nil {
			return err
		}

		err = errors.New("tx with wanted txhash never found")
		for _, utxo := range unspent.Utxos {
			if !bytes.Equal(utxo.Outpoint.TxidBytes, out.TxidBytes) {
				continue
			}

			err = errors.New("wanted output is not a wallet utxo")
			if utxo.Outpoint.OutputIndex != out.OutputIndex {
				continue
			}

			return nil
		}

		return err
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("outpoint %s not unspent by %s's wallet: %v", out,
			node.Name(), err)
	}
}
