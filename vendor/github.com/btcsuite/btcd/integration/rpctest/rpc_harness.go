// Copyright (c) 2016-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpctest

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// These constants define the minimum and maximum p2p and rpc port
	// numbers used by a test harness.  The min port is inclusive while the
	// max port is exclusive.
	minPeerPort = 10000
	maxPeerPort = 35000
	minRPCPort  = maxPeerPort
	maxRPCPort  = 60000

	// BlockVersion is the default block version used when generating
	// blocks.
	BlockVersion = 4
)

var (
	// current number of active test nodes.
	numTestInstances = 0

	// processID is the process ID of the current running process.  It is
	// used to calculate ports based upon it when launching an rpc
	// harnesses.  The intent is to allow multiple process to run in
	// parallel without port collisions.
	//
	// It should be noted however that there is still some small probability
	// that there will be port collisions either due to other processes
	// running or simply due to the stars aligning on the process IDs.
	processID = os.Getpid()

	// testInstances is a private package-level slice used to keep track of
	// all active test harnesses. This global can be used to perform
	// various "joins", shutdown several active harnesses after a test,
	// etc.
	testInstances = make(map[string]*Harness)

	// Used to protest concurrent access to above declared variables.
	harnessStateMtx sync.RWMutex
)

// HarnessTestCase represents a test-case which utilizes an instance of the
// Harness to exercise functionality.
type HarnessTestCase func(r *Harness, t *testing.T)

// Harness fully encapsulates an active btcd process to provide a unified
// platform for creating rpc driven integration tests involving btcd. The
// active btcd node will typically be run in simnet mode in order to allow for
// easy generation of test blockchains.  The active btcd process is fully
// managed by Harness, which handles the necessary initialization, and teardown
// of the process along with any temporary directories created as a result.
// Multiple Harness instances may be run concurrently, in order to allow for
// testing complex scenarios involving multiple nodes. The harness also
// includes an in-memory wallet to streamline various classes of tests.
type Harness struct {
	// ActiveNet is the parameters of the blockchain the Harness belongs
	// to.
	ActiveNet *chaincfg.Params

	Node     *rpcclient.Client
	node     *node
	handlers *rpcclient.NotificationHandlers

	wallet *memWallet

	testNodeDir    string
	maxConnRetries int
	nodeNum        int

	sync.Mutex
}

// New creates and initializes new instance of the rpc test harness.
// Optionally, websocket handlers and a specified configuration may be passed.
// In the case that a nil config is passed, a default configuration will be
// used.
//
// NOTE: This function is safe for concurrent access.
func New(activeNet *chaincfg.Params, handlers *rpcclient.NotificationHandlers,
	extraArgs []string) (*Harness, error) {

	harnessStateMtx.Lock()
	defer harnessStateMtx.Unlock()

	// Add a flag for the appropriate network type based on the provided
	// chain params.
	switch activeNet.Net {
	case wire.MainNet:
		// No extra flags since mainnet is the default
	case wire.TestNet3:
		extraArgs = append(extraArgs, "--testnet")
	case wire.TestNet:
		extraArgs = append(extraArgs, "--regtest")
	case wire.SimNet:
		extraArgs = append(extraArgs, "--simnet")
	default:
		return nil, fmt.Errorf("rpctest.New must be called with one " +
			"of the supported chain networks")
	}

	testDir, err := baseDir()
	if err != nil {
		return nil, err
	}

	harnessID := strconv.Itoa(numTestInstances)
	nodeTestData, err := ioutil.TempDir(testDir, "harness-"+harnessID)
	if err != nil {
		return nil, err
	}

	certFile := filepath.Join(nodeTestData, "rpc.cert")
	keyFile := filepath.Join(nodeTestData, "rpc.key")
	if err := genCertPair(certFile, keyFile); err != nil {
		return nil, err
	}

	wallet, err := newMemWallet(activeNet, uint32(numTestInstances))
	if err != nil {
		return nil, err
	}

	miningAddr := fmt.Sprintf("--miningaddr=%s", wallet.coinbaseAddr)
	extraArgs = append(extraArgs, miningAddr)

	config, err := newConfig("rpctest", certFile, keyFile, extraArgs)
	if err != nil {
		return nil, err
	}

	// Generate p2p+rpc listening addresses.
	config.listen, config.rpcListen = generateListeningAddresses()

	// Create the testing node bounded to the simnet.
	node, err := newNode(config, nodeTestData)
	if err != nil {
		return nil, err
	}

	nodeNum := numTestInstances
	numTestInstances++

	if handlers == nil {
		handlers = &rpcclient.NotificationHandlers{}
	}

	// If a handler for the OnFilteredBlock{Connected,Disconnected} callback
	// callback has already been set, then create a wrapper callback which
	// executes both the currently registered callback and the mem wallet's
	// callback.
	if handlers.OnFilteredBlockConnected != nil {
		obc := handlers.OnFilteredBlockConnected
		handlers.OnFilteredBlockConnected = func(height int32, header *wire.BlockHeader, filteredTxns []*btcutil.Tx) {
			wallet.IngestBlock(height, header, filteredTxns)
			obc(height, header, filteredTxns)
		}
	} else {
		// Otherwise, we can claim the callback ourselves.
		handlers.OnFilteredBlockConnected = wallet.IngestBlock
	}
	if handlers.OnFilteredBlockDisconnected != nil {
		obd := handlers.OnFilteredBlockDisconnected
		handlers.OnFilteredBlockDisconnected = func(height int32, header *wire.BlockHeader) {
			wallet.UnwindBlock(height, header)
			obd(height, header)
		}
	} else {
		handlers.OnFilteredBlockDisconnected = wallet.UnwindBlock
	}

	h := &Harness{
		handlers:       handlers,
		node:           node,
		maxConnRetries: 20,
		testNodeDir:    nodeTestData,
		ActiveNet:      activeNet,
		nodeNum:        nodeNum,
		wallet:         wallet,
	}

	// Track this newly created test instance within the package level
	// global map of all active test instances.
	testInstances[h.testNodeDir] = h

	return h, nil
}

// SetUp initializes the rpc test state. Initialization includes: starting up a
// simnet node, creating a websockets client and connecting to the started
// node, and finally: optionally generating and submitting a testchain with a
// configurable number of mature coinbase outputs coinbase outputs.
//
// NOTE: This method and TearDown should always be called from the same
// goroutine as they are not concurrent safe.
func (h *Harness) SetUp(createTestChain bool, numMatureOutputs uint32) error {
	// Start the btcd node itself. This spawns a new process which will be
	// managed
	if err := h.node.start(); err != nil {
		return err
	}
	if err := h.connectRPCClient(); err != nil {
		return err
	}

	h.wallet.Start()

	// Filter transactions that pay to the coinbase associated with the
	// wallet.
	filterAddrs := []btcutil.Address{h.wallet.coinbaseAddr}
	if err := h.Node.LoadTxFilter(true, filterAddrs, nil); err != nil {
		return err
	}

	// Ensure btcd properly dispatches our registered call-back for each new
	// block. Otherwise, the memWallet won't function properly.
	if err := h.Node.NotifyBlocks(); err != nil {
		return err
	}

	// Create a test chain with the desired number of mature coinbase
	// outputs.
	if createTestChain && numMatureOutputs != 0 {
		numToGenerate := (uint32(h.ActiveNet.CoinbaseMaturity) +
			numMatureOutputs)
		_, err := h.Node.Generate(numToGenerate)
		if err != nil {
			return err
		}
	}

	// Block until the wallet has fully synced up to the tip of the main
	// chain.
	_, height, err := h.Node.GetBestBlock()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Millisecond * 100)
	for range ticker.C {
		walletHeight := h.wallet.SyncedHeight()
		if walletHeight == height {
			break
		}
	}
	ticker.Stop()

	return nil
}

// tearDown stops the running rpc test instance.  All created processes are
// killed, and temporary directories removed.
//
// This function MUST be called with the harness state mutex held (for writes).
func (h *Harness) tearDown() error {
	if h.Node != nil {
		h.Node.Shutdown()
	}

	if err := h.node.shutdown(); err != nil {
		return err
	}

	if err := os.RemoveAll(h.testNodeDir); err != nil {
		return err
	}

	delete(testInstances, h.testNodeDir)

	return nil
}

// TearDown stops the running rpc test instance. All created processes are
// killed, and temporary directories removed.
//
// NOTE: This method and SetUp should always be called from the same goroutine
// as they are not concurrent safe.
func (h *Harness) TearDown() error {
	harnessStateMtx.Lock()
	defer harnessStateMtx.Unlock()

	return h.tearDown()
}

// connectRPCClient attempts to establish an RPC connection to the created btcd
// process belonging to this Harness instance. If the initial connection
// attempt fails, this function will retry h.maxConnRetries times, backing off
// the time between subsequent attempts. If after h.maxConnRetries attempts,
// we're not able to establish a connection, this function returns with an
// error.
func (h *Harness) connectRPCClient() error {
	var client *rpcclient.Client
	var err error

	rpcConf := h.node.config.rpcConnConfig()
	for i := 0; i < h.maxConnRetries; i++ {
		if client, err = rpcclient.New(&rpcConf, h.handlers); err != nil {
			time.Sleep(time.Duration(i) * 50 * time.Millisecond)
			continue
		}
		break
	}

	if client == nil {
		return fmt.Errorf("connection timeout")
	}

	h.Node = client
	h.wallet.SetRPCClient(client)
	return nil
}

// NewAddress returns a fresh address spendable by the Harness' internal
// wallet.
//
// This function is safe for concurrent access.
func (h *Harness) NewAddress() (btcutil.Address, error) {
	return h.wallet.NewAddress()
}

// ConfirmedBalance returns the confirmed balance of the Harness' internal
// wallet.
//
// This function is safe for concurrent access.
func (h *Harness) ConfirmedBalance() btcutil.Amount {
	return h.wallet.ConfirmedBalance()
}

// SendOutputs creates, signs, and finally broadcasts a transaction spending
// the harness' available mature coinbase outputs creating new outputs
// according to targetOutputs.
//
// This function is safe for concurrent access.
func (h *Harness) SendOutputs(targetOutputs []*wire.TxOut,
	feeRate btcutil.Amount) (*chainhash.Hash, error) {

	return h.wallet.SendOutputs(targetOutputs, feeRate)
}

// SendOutputsWithoutChange creates and sends a transaction that pays to the
// specified outputs while observing the passed fee rate and ignoring a change
// output. The passed fee rate should be expressed in sat/b.
//
// This function is safe for concurrent access.
func (h *Harness) SendOutputsWithoutChange(targetOutputs []*wire.TxOut,
	feeRate btcutil.Amount) (*chainhash.Hash, error) {

	return h.wallet.SendOutputsWithoutChange(targetOutputs, feeRate)
}

// CreateTransaction returns a fully signed transaction paying to the specified
// outputs while observing the desired fee rate. The passed fee rate should be
// expressed in satoshis-per-byte. The transaction being created can optionally
// include a change output indicated by the change boolean. Any unspent outputs
// selected as inputs for the crafted transaction are marked as unspendable in
// order to avoid potential double-spends by future calls to this method. If the
// created transaction is cancelled for any reason then the selected inputs MUST
// be freed via a call to UnlockOutputs. Otherwise, the locked inputs won't be
// returned to the pool of spendable outputs.
//
// This function is safe for concurrent access.
func (h *Harness) CreateTransaction(targetOutputs []*wire.TxOut,
	feeRate btcutil.Amount, change bool) (*wire.MsgTx, error) {

	return h.wallet.CreateTransaction(targetOutputs, feeRate, change)
}

// UnlockOutputs unlocks any outputs which were previously marked as
// unspendabe due to being selected to fund a transaction via the
// CreateTransaction method.
//
// This function is safe for concurrent access.
func (h *Harness) UnlockOutputs(inputs []*wire.TxIn) {
	h.wallet.UnlockOutputs(inputs)
}

// RPCConfig returns the harnesses current rpc configuration. This allows other
// potential RPC clients created within tests to connect to a given test
// harness instance.
func (h *Harness) RPCConfig() rpcclient.ConnConfig {
	return h.node.config.rpcConnConfig()
}

// P2PAddress returns the harness' P2P listening address. This allows potential
// peers (such as SPV peers) created within tests to connect to a given test
// harness instance.
func (h *Harness) P2PAddress() string {
	return h.node.config.listen
}

// GenerateAndSubmitBlock creates a block whose contents include the passed
// transactions and submits it to the running simnet node. For generating
// blocks with only a coinbase tx, callers can simply pass nil instead of
// transactions to be mined. Additionally, a custom block version can be set by
// the caller. A blockVersion of -1 indicates that the current default block
// version should be used. An uninitialized time.Time should be used for the
// blockTime parameter if one doesn't wish to set a custom time.
//
// This function is safe for concurrent access.
func (h *Harness) GenerateAndSubmitBlock(txns []*btcutil.Tx, blockVersion int32,
	blockTime time.Time) (*btcutil.Block, error) {
	return h.GenerateAndSubmitBlockWithCustomCoinbaseOutputs(txns,
		blockVersion, blockTime, []wire.TxOut{})
}

// GenerateAndSubmitBlockWithCustomCoinbaseOutputs creates a block whose
// contents include the passed coinbase outputs and transactions and submits
// it to the running simnet node. For generating blocks with only a coinbase tx,
// callers can simply pass nil instead of transactions to be mined.
// Additionally, a custom block version can be set by the caller. A blockVersion
// of -1 indicates that the current default block version should be used. An
// uninitialized time.Time should be used for the blockTime parameter if one
// doesn't wish to set a custom time. The mineTo list of outputs will be added
// to the coinbase; this is not checked for correctness until the block is
// submitted; thus, it is the caller's responsibility to ensure that the outputs
// are correct. If the list is empty, the coinbase reward goes to the wallet
// managed by the Harness.
//
// This function is safe for concurrent access.
func (h *Harness) GenerateAndSubmitBlockWithCustomCoinbaseOutputs(
	txns []*btcutil.Tx, blockVersion int32, blockTime time.Time,
	mineTo []wire.TxOut) (*btcutil.Block, error) {

	h.Lock()
	defer h.Unlock()

	if blockVersion == -1 {
		blockVersion = BlockVersion
	}

	prevBlockHash, prevBlockHeight, err := h.Node.GetBestBlock()
	if err != nil {
		return nil, err
	}
	mBlock, err := h.Node.GetBlock(prevBlockHash)
	if err != nil {
		return nil, err
	}
	prevBlock := btcutil.NewBlock(mBlock)
	prevBlock.SetHeight(prevBlockHeight)

	// Create a new block including the specified transactions
	newBlock, err := CreateBlock(prevBlock, txns, blockVersion,
		blockTime, h.wallet.coinbaseAddr, mineTo, h.ActiveNet)
	if err != nil {
		return nil, err
	}

	// Submit the block to the simnet node.
	if err := h.Node.SubmitBlock(newBlock, nil); err != nil {
		return nil, err
	}

	return newBlock, nil
}

// generateListeningAddresses returns two strings representing listening
// addresses designated for the current rpc test. If there haven't been any
// test instances created, the default ports are used. Otherwise, in order to
// support multiple test nodes running at once, the p2p and rpc port are
// incremented after each initialization.
func generateListeningAddresses() (string, string) {
	localhost := "127.0.0.1"

	portString := func(minPort, maxPort int) string {
		port := minPort + numTestInstances + ((20 * processID) %
			(maxPort - minPort))
		return strconv.Itoa(port)
	}

	p2p := net.JoinHostPort(localhost, portString(minPeerPort, maxPeerPort))
	rpc := net.JoinHostPort(localhost, portString(minRPCPort, maxRPCPort))
	return p2p, rpc
}

// baseDir is the directory path of the temp directory for all rpctest files.
func baseDir() (string, error) {
	dirPath := filepath.Join(os.TempDir(), "btcd", "rpctest")
	err := os.MkdirAll(dirPath, 0755)
	return dirPath, err
}
