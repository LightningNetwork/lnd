package lntest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/kvdb/etcd"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/grpclog"
)

// DefaultCSV is the CSV delay (remotedelay) we will start our test nodes with.
const DefaultCSV = 4

// NodeOption is a function for updating a node's configuration.
type NodeOption func(*NodeConfig)

// NetworkHarness is an integration testing harness for the lightning network.
// The harness by default is created with two active nodes on the network:
// Alice and Bob.
type NetworkHarness struct {
	netParams *chaincfg.Params

	// currentTestCase holds the name for the currently run test case.
	currentTestCase string

	// lndBinary is the full path to the lnd binary that was specifically
	// compiled with all required itest flags.
	lndBinary string

	// Miner is a reference to a running full node that can be used to create
	// new blocks on the network.
	Miner *rpctest.Harness

	// BackendCfg houses the information necessary to use a node as LND
	// chain backend, such as rpc configuration, P2P information etc.
	BackendCfg BackendConfig

	activeNodes map[int]*HarnessNode

	nodesByPub map[string]*HarnessNode

	// Alice and Bob are the initial seeder nodes that are automatically
	// created to be the initial participants of the test network.
	Alice *HarnessNode
	Bob   *HarnessNode

	// dbBackend sets the database backend to use.
	dbBackend DatabaseBackend

	// Channel for transmitting stderr output from failed lightning node
	// to main process.
	lndErrorChan chan error

	// feeService is a web service that provides external fee estimates to
	// lnd.
	feeService *feeService

	quit chan struct{}

	mtx sync.Mutex
}

type DatabaseBackend int

const (
	BackendBbolt DatabaseBackend = iota
	BackendEtcd
)

// NewNetworkHarness creates a new network test harness.
// TODO(roasbeef): add option to use golang's build library to a binary of the
// current repo. This will save developers from having to manually `go install`
// within the repo each time before changes
func NewNetworkHarness(r *rpctest.Harness, b BackendConfig, lndBinary string,
	dbBackend DatabaseBackend) (*NetworkHarness, error) {

	feeService := startFeeService()

	n := NetworkHarness{
		activeNodes:  make(map[int]*HarnessNode),
		nodesByPub:   make(map[string]*HarnessNode),
		lndErrorChan: make(chan error),
		netParams:    r.ActiveNet,
		Miner:        r,
		BackendCfg:   b,
		feeService:   feeService,
		quit:         make(chan struct{}),
		lndBinary:    lndBinary,
		dbBackend:    dbBackend,
	}
	return &n, nil
}

// LookUpNodeByPub queries the set of active nodes to locate a node according
// to its public key. The second value will be true if the node was found, and
// false otherwise.
func (n *NetworkHarness) LookUpNodeByPub(pubStr string) (*HarnessNode, error) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	node, ok := n.nodesByPub[pubStr]
	if !ok {
		return nil, fmt.Errorf("unable to find node")
	}

	return node, nil
}

// ProcessErrors returns a channel used for reporting any fatal process errors.
// If any of the active nodes within the harness' test network incur a fatal
// error, that error is sent over this channel.
func (n *NetworkHarness) ProcessErrors() <-chan error {
	return n.lndErrorChan
}

// fakeLogger is a fake grpclog.Logger implementation. This is used to stop
// grpc's logger from printing directly to stdout.
type fakeLogger struct{}

func (f *fakeLogger) Fatal(args ...interface{})                 {}
func (f *fakeLogger) Fatalf(format string, args ...interface{}) {}
func (f *fakeLogger) Fatalln(args ...interface{})               {}
func (f *fakeLogger) Print(args ...interface{})                 {}
func (f *fakeLogger) Printf(format string, args ...interface{}) {}
func (f *fakeLogger) Println(args ...interface{})               {}

// SetUp starts the initial seeder nodes within the test harness. The initial
// node's wallets will be funded wallets with ten 1 BTC outputs each. Finally
// rpc clients capable of communicating with the initial seeder nodes are
// created. Nodes are initialized with the given extra command line flags, which
// should be formatted properly - "--arg=value".
func (n *NetworkHarness) SetUp(t *testing.T,
	testCase string, lndArgs []string) error {

	// Swap out grpc's default logger with out fake logger which drops the
	// statements on the floor.
	grpclog.SetLogger(&fakeLogger{})
	n.currentTestCase = testCase

	// Start the initial seeder nodes within the test network, then connect
	// their respective RPC clients.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n.Alice = n.NewNode(t, "Alice", lndArgs)
	}()
	go func() {
		defer wg.Done()
		n.Bob = n.NewNode(t, "Bob", lndArgs)
	}()
	wg.Wait()

	// First, make a connection between the two nodes. This will wait until
	// both nodes are fully started since the Connect RPC is guarded behind
	// the server.Started() flag that waits for all subsystems to be ready.
	ctxb := context.Background()
	n.ConnectNodes(ctxb, t, n.Alice, n.Bob)

	// Load up the wallets of the seeder nodes with 10 outputs of 1 BTC
	// each.
	addrReq := &lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	}
	clients := []lnrpc.LightningClient{n.Alice, n.Bob}
	for _, client := range clients {
		for i := 0; i < 10; i++ {
			resp, err := client.NewAddress(ctxb, addrReq)
			if err != nil {
				return err
			}
			addr, err := btcutil.DecodeAddress(resp.Address, n.netParams)
			if err != nil {
				return err
			}
			addrScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return err
			}

			output := &wire.TxOut{
				PkScript: addrScript,
				Value:    btcutil.SatoshiPerBitcoin,
			}
			_, err = n.Miner.SendOutputs([]*wire.TxOut{output}, 7500)
			if err != nil {
				return err
			}
		}
	}

	// We generate several blocks in order to give the outputs created
	// above a good number of confirmations.
	if _, err := n.Miner.Client.Generate(10); err != nil {
		return err
	}

	// Now we want to wait for the nodes to catch up.
	ctxt, cancel := context.WithTimeout(ctxb, DefaultTimeout)
	defer cancel()
	if err := n.Alice.WaitForBlockchainSync(ctxt); err != nil {
		return err
	}
	if err := n.Bob.WaitForBlockchainSync(ctxt); err != nil {
		return err
	}

	// Now block until both wallets have fully synced up.
	expectedBalance := int64(btcutil.SatoshiPerBitcoin * 10)
	balReq := &lnrpc.WalletBalanceRequest{}
	balanceTicker := time.NewTicker(time.Millisecond * 200)
	defer balanceTicker.Stop()
	balanceTimeout := time.After(DefaultTimeout)
out:
	for {
		select {
		case <-balanceTicker.C:
			aliceResp, err := n.Alice.WalletBalance(ctxb, balReq)
			if err != nil {
				return err
			}
			bobResp, err := n.Bob.WalletBalance(ctxb, balReq)
			if err != nil {
				return err
			}

			if aliceResp.ConfirmedBalance == expectedBalance &&
				bobResp.ConfirmedBalance == expectedBalance {
				break out
			}
		case <-balanceTimeout:
			return fmt.Errorf("balances not synced after deadline")
		}
	}

	return nil
}

// TearDown tears down all active nodes within the test lightning network.
func (n *NetworkHarness) TearDown() error {
	for _, node := range n.activeNodes {
		if err := n.ShutdownNode(node); err != nil {
			return err
		}
	}

	return nil
}

// Stop stops the test harness.
func (n *NetworkHarness) Stop() {
	close(n.lndErrorChan)
	close(n.quit)

	n.feeService.stop()
}

// extraArgsEtcd returns extra args for configuring LND to use an external etcd
// database (for remote channel DB and wallet DB).
func extraArgsEtcd(etcdCfg *etcd.Config, name string, cluster bool) []string {
	extraArgs := []string{
		"--db.backend=etcd",
		fmt.Sprintf("--db.etcd.host=%v", etcdCfg.Host),
		fmt.Sprintf("--db.etcd.user=%v", etcdCfg.User),
		fmt.Sprintf("--db.etcd.pass=%v", etcdCfg.Pass),
		fmt.Sprintf("--db.etcd.namespace=%v", etcdCfg.Namespace),
	}

	if etcdCfg.InsecureSkipVerify {
		extraArgs = append(extraArgs, "--db.etcd.insecure_skip_verify")

	}

	if cluster {
		extraArgs = append(extraArgs, "--cluster.enable-leader-election")
		extraArgs = append(
			extraArgs, fmt.Sprintf("--cluster.id=%v", name),
		)
	}

	return extraArgs
}

// NewNodeWithSeedEtcd starts a new node with seed that'll use an external
// etcd database as its (remote) channel and wallet DB. The passsed cluster
// flag indicates that we'd like the node to join the cluster leader election.
func (n *NetworkHarness) NewNodeWithSeedEtcd(name string, etcdCfg *etcd.Config,
	password []byte, entropy []byte, statelessInit, cluster bool) (
	*HarnessNode, []string, []byte, error) {

	// We don't want to use the embedded etcd instance.
	const dbBackend = BackendBbolt

	extraArgs := extraArgsEtcd(etcdCfg, name, cluster)
	return n.newNodeWithSeed(
		name, extraArgs, password, entropy, statelessInit, dbBackend,
	)
}

// NewNodeWithSeedEtcd starts a new node with seed that'll use an external
// etcd database as its (remote) channel and wallet DB. The passsed cluster
// flag indicates that we'd like the node to join the cluster leader election.
// If the wait flag is false then we won't wait until RPC is available (this is
// useful when the node is not expected to become the leader right away).
func (n *NetworkHarness) NewNodeEtcd(name string, etcdCfg *etcd.Config,
	password []byte, cluster, wait bool) (*HarnessNode, error) {

	// We don't want to use the embedded etcd instance.
	const dbBackend = BackendBbolt

	extraArgs := extraArgsEtcd(etcdCfg, name, cluster)
	return n.newNode(name, extraArgs, true, password, dbBackend, wait)
}

// NewNode fully initializes a returns a new HarnessNode bound to the
// current instance of the network harness. The created node is running, but
// not yet connected to other nodes within the network.
func (n *NetworkHarness) NewNode(t *testing.T,
	name string, extraArgs []string) *HarnessNode {

	node, err := n.newNode(
		name, extraArgs, false, nil, n.dbBackend, true,
	)
	require.NoErrorf(t, err, "unable to create new node for %s", name)

	return node
}

// NewNodeWithSeed fully initializes a new HarnessNode after creating a fresh
// aezeed. The provided password is used as both the aezeed password and the
// wallet password. The generated mnemonic is returned along with the
// initialized harness node.
func (n *NetworkHarness) NewNodeWithSeed(name string, extraArgs []string,
	password []byte, statelessInit bool) (*HarnessNode, []string, []byte,
	error) {

	return n.newNodeWithSeed(
		name, extraArgs, password, nil, statelessInit, n.dbBackend,
	)
}

func (n *NetworkHarness) newNodeWithSeed(name string, extraArgs []string,
	password, entropy []byte, statelessInit bool, dbBackend DatabaseBackend) (
	*HarnessNode, []string, []byte, error) {

	node, err := n.newNode(
		name, extraArgs, true, password, dbBackend, true,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	ctxb := context.Background()

	// Create a request to generate a new aezeed. The new seed will have the
	// same password as the internal wallet.
	genSeedReq := &lnrpc.GenSeedRequest{
		AezeedPassphrase: password,
		SeedEntropy:      entropy,
	}

	ctxt, cancel := context.WithTimeout(ctxb, DefaultTimeout)
	defer cancel()

	var genSeedResp *lnrpc.GenSeedResponse
	if err := wait.NoError(func() error {
		genSeedResp, err = node.GenSeed(ctxt, genSeedReq)
		return err
	}, DefaultTimeout); err != nil {
		return nil, nil, nil, err
	}

	// With the seed created, construct the init request to the node,
	// including the newly generated seed.
	initReq := &lnrpc.InitWalletRequest{
		WalletPassword:     password,
		CipherSeedMnemonic: genSeedResp.CipherSeedMnemonic,
		AezeedPassphrase:   password,
		StatelessInit:      statelessInit,
	}

	// Pass the init request via rpc to finish unlocking the node. This will
	// also initialize the macaroon-authenticated LightningClient.
	response, err := node.Init(ctxb, initReq)
	if err != nil {
		return nil, nil, nil, err
	}

	// With the node started, we can now record its public key within the
	// global mapping.
	n.RegisterNode(node)

	// In stateless initialization mode we get a macaroon back that we have
	// to return to the test, otherwise gRPC calls won't be possible since
	// there are no macaroon files created in that mode.
	// In stateful init the admin macaroon will just be nil.
	return node, genSeedResp.CipherSeedMnemonic, response.AdminMacaroon, nil
}

// RestoreNodeWithSeed fully initializes a HarnessNode using a chosen mnemonic,
// password, recovery window, and optionally a set of static channel backups.
// After providing the initialization request to unlock the node, this method
// will finish initializing the LightningClient such that the HarnessNode can
// be used for regular rpc operations.
func (n *NetworkHarness) RestoreNodeWithSeed(name string, extraArgs []string,
	password []byte, mnemonic []string, recoveryWindow int32,
	chanBackups *lnrpc.ChanBackupSnapshot,
	opts ...NodeOption) (*HarnessNode, error) {

	node, err := n.newNode(
		name, extraArgs, true, password, n.dbBackend, true, opts...,
	)
	if err != nil {
		return nil, err
	}

	initReq := &lnrpc.InitWalletRequest{
		WalletPassword:     password,
		CipherSeedMnemonic: mnemonic,
		AezeedPassphrase:   password,
		RecoveryWindow:     recoveryWindow,
		ChannelBackups:     chanBackups,
	}

	_, err = node.Init(context.Background(), initReq)
	if err != nil {
		return nil, err
	}

	// With the node started, we can now record its public key within the
	// global mapping.
	n.RegisterNode(node)

	return node, nil
}

// newNode initializes a new HarnessNode, supporting the ability to initialize a
// wallet with or without a seed. If hasSeed is false, the returned harness node
// can be used immediately. Otherwise, the node will require an additional
// initialization phase where the wallet is either created or restored.
func (n *NetworkHarness) newNode(name string, extraArgs []string, hasSeed bool,
	password []byte, dbBackend DatabaseBackend, wait bool, opts ...NodeOption) (
	*HarnessNode, error) {

	cfg := &NodeConfig{
		Name:              name,
		LogFilenamePrefix: n.currentTestCase,
		HasSeed:           hasSeed,
		Password:          password,
		BackendCfg:        n.BackendCfg,
		NetParams:         n.netParams,
		ExtraArgs:         extraArgs,
		FeeURL:            n.feeService.url,
		DbBackend:         dbBackend,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	node, err := newNode(*cfg)
	if err != nil {
		return nil, err
	}

	// Put node in activeNodes to ensure Shutdown is called even if Start
	// returns an error.
	n.mtx.Lock()
	n.activeNodes[node.NodeID] = node
	n.mtx.Unlock()

	err = node.start(n.lndBinary, n.lndErrorChan, wait)
	if err != nil {
		return nil, err
	}

	// If this node is to have a seed, it will need to be unlocked or
	// initialized via rpc. Delay registering it with the network until it
	// can be driven via an unlocked rpc connection.
	if node.Cfg.HasSeed {
		return node, nil
	}

	// With the node started, we can now record its public key within the
	// global mapping.
	n.RegisterNode(node)

	return node, nil
}

// RegisterNode records a new HarnessNode in the NetworkHarnesses map of known
// nodes. This method should only be called with nodes that have successfully
// retrieved their public keys via FetchNodeInfo.
func (n *NetworkHarness) RegisterNode(node *HarnessNode) {
	n.mtx.Lock()
	n.nodesByPub[node.PubKeyStr] = node
	n.mtx.Unlock()
}

func (n *NetworkHarness) connect(ctx context.Context,
	req *lnrpc.ConnectPeerRequest, a *HarnessNode) error {

	syncTimeout := time.After(DefaultTimeout)
tryconnect:
	if _, err := a.ConnectPeer(ctx, req); err != nil {
		// If the chain backend is still syncing, retry.
		if strings.Contains(err.Error(), lnd.ErrServerNotActive.Error()) ||
			strings.Contains(err.Error(), "i/o timeout") {

			select {
			case <-time.After(100 * time.Millisecond):
				goto tryconnect
			case <-syncTimeout:
				return fmt.Errorf("chain backend did not " +
					"finish syncing")
			}
		}
		return err
	}

	return nil
}

// EnsureConnected will try to connect to two nodes, returning no error if they
// are already connected. If the nodes were not connected previously, this will
// behave the same as ConnectNodes. If a pending connection request has already
// been made, the method will block until the two nodes appear in each other's
// peers list, or until the 15s timeout expires.
func (n *NetworkHarness) EnsureConnected(ctx context.Context,
	t *testing.T, a, b *HarnessNode) {

	// errConnectionRequested is used to signal that a connection was
	// requested successfully, which is distinct from already being
	// connected to the peer.
	errConnectionRequested := errors.New("connection request in progress")

	tryConnect := func(a, b *HarnessNode) error {
		ctxt, cancel := context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
		bInfo, err := b.GetInfo(ctxt, &lnrpc.GetInfoRequest{})
		if err != nil {
			return err
		}

		req := &lnrpc.ConnectPeerRequest{
			Addr: &lnrpc.LightningAddress{
				Pubkey: bInfo.IdentityPubkey,
				Host:   b.Cfg.P2PAddr(),
			},
		}

		var predErr error
		err = wait.Predicate(func() bool {
			ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
			defer cancel()

			err := n.connect(ctx, req, a)
			switch {
			// Request was successful, wait for both to display the
			// connection.
			case err == nil:
				predErr = errConnectionRequested
				return true

			// If the two are already connected, we return early
			// with no error.
			case strings.Contains(
				err.Error(), "already connected to peer",
			):
				predErr = nil
				return true

			default:
				predErr = err
				return false
			}

		}, DefaultTimeout)
		if err != nil {
			return fmt.Errorf("connection not succeeded within 15 "+
				"seconds: %v", predErr)
		}

		return predErr
	}

	aErr := tryConnect(a, b)
	bErr := tryConnect(b, a)
	switch {
	// If both reported already being connected to each other, we can exit
	// early.
	case aErr == nil && bErr == nil:

	// Return any critical errors returned by either alice.
	case aErr != nil && aErr != errConnectionRequested:
		t.Fatalf(
			"ensure connection between %s and %s failed "+
				"with error from %s: %v",
			a.Cfg.Name, b.Cfg.Name, a.Cfg.Name, aErr,
		)

	// Return any critical errors returned by either bob.
	case bErr != nil && bErr != errConnectionRequested:
		t.Fatalf("ensure connection between %s and %s failed "+
			"with error from %s: %v",
			a.Cfg.Name, b.Cfg.Name, b.Cfg.Name, bErr,
		)

	// Otherwise one or both requested a connection, so we wait for the
	// peers lists to reflect the connection.
	default:
	}

	findSelfInPeerList := func(a, b *HarnessNode) bool {
		// If node B is seen in the ListPeers response from node A,
		// then we can exit early as the connection has been fully
		// established.
		ctxt, cancel := context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
		resp, err := b.ListPeers(ctxt, &lnrpc.ListPeersRequest{})
		if err != nil {
			return false
		}

		for _, peer := range resp.Peers {
			if peer.PubKey == a.PubKeyStr {
				return true
			}
		}

		return false
	}

	err := wait.Predicate(func() bool {
		return findSelfInPeerList(a, b) && findSelfInPeerList(b, a)
	}, DefaultTimeout)

	require.NoErrorf(
		t, err, "unable to connect %s to %s, "+
			"got error: peers not connected within %v seconds",
		a.Cfg.Name, b.Cfg.Name, DefaultTimeout,
	)
}

// ConnectNodes establishes an encrypted+authenticated p2p connection from node
// a towards node b. The function will return a non-nil error if the connection
// was unable to be established.
//
// NOTE: This function may block for up to 15-seconds as it will not return
// until the new connection is detected as being known to both nodes.
func (n *NetworkHarness) ConnectNodes(ctx context.Context, t *testing.T,
	a, b *HarnessNode) {

	bobInfo, err := b.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	require.NoErrorf(
		t, err, "unable to connect %s to %s, got error: %v",
		a.Cfg.Name, b.Cfg.Name, err,
	)

	req := &lnrpc.ConnectPeerRequest{
		Addr: &lnrpc.LightningAddress{
			Pubkey: bobInfo.IdentityPubkey,
			Host:   b.Cfg.P2PAddr(),
		},
	}

	err = n.connect(ctx, req, a)
	require.NoErrorf(
		t, err, "unable to connect %s to %s, got error: %v",
		a.Cfg.Name, b.Cfg.Name, err,
	)

	err = wait.Predicate(func() bool {
		// If node B is seen in the ListPeers response from node A,
		// then we can exit early as the connection has been fully
		// established.
		resp, err := a.ListPeers(ctx, &lnrpc.ListPeersRequest{})
		if err != nil {
			return false
		}

		for _, peer := range resp.Peers {
			if peer.PubKey == b.PubKeyStr {
				return true
			}
		}

		return false
	}, DefaultTimeout)

	require.NoErrorf(
		t, err, "unable to connect %s to %s, "+
			"got error: peers not connected within %v seconds",
		a.Cfg.Name, b.Cfg.Name, DefaultTimeout,
	)
}

// DisconnectNodes disconnects node a from node b by sending RPC message
// from a node to b node
func (n *NetworkHarness) DisconnectNodes(ctx context.Context, a, b *HarnessNode) error {
	bobInfo, err := b.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return err
	}

	req := &lnrpc.DisconnectPeerRequest{
		PubKey: bobInfo.IdentityPubkey,
	}

	if _, err := a.DisconnectPeer(ctx, req); err != nil {
		return err
	}

	return nil
}

// RestartNode attempts to restart a lightning node by shutting it down
// cleanly, then restarting the process. This function is fully blocking. Upon
// restart, the RPC connection to the node will be re-attempted, continuing iff
// the connection attempt is successful. If the callback parameter is non-nil,
// then the function will be executed after the node shuts down, but *before*
// the process has been started up again.
//
// This method can be useful when testing edge cases such as a node broadcast
// and invalidated prior state, or persistent state recovery, simulating node
// crashes, etc. Additionally, each time the node is restarted, the caller can
// pass a set of SCBs to pass in via the Unlock method allowing them to restore
// channels during restart.
func (n *NetworkHarness) RestartNode(node *HarnessNode, callback func() error,
	chanBackups ...*lnrpc.ChanBackupSnapshot) error {

	err := n.RestartNodeNoUnlock(node, callback)
	if err != nil {
		return err
	}

	// If the node doesn't have a password set, then we can exit here as we
	// don't need to unlock it.
	if len(node.Cfg.Password) == 0 {
		return nil
	}

	// Otherwise, we'll unlock the wallet, then complete the final steps
	// for the node initialization process.
	unlockReq := &lnrpc.UnlockWalletRequest{
		WalletPassword: node.Cfg.Password,
	}
	if len(chanBackups) != 0 {
		unlockReq.ChannelBackups = chanBackups[0]
		unlockReq.RecoveryWindow = 1000
	}

	return node.Unlock(context.Background(), unlockReq)
}

// RestartNodeNoUnlock attempts to restart a lightning node by shutting it down
// cleanly, then restarting the process. In case the node was setup with a seed,
// it will be left in the unlocked state. This function is fully blocking. If
// the callback parameter is non-nil, then the function will be executed after
// the node shuts down, but *before* the process has been started up again.
func (n *NetworkHarness) RestartNodeNoUnlock(node *HarnessNode,
	callback func() error) error {

	if err := node.stop(); err != nil {
		return err
	}

	if callback != nil {
		if err := callback(); err != nil {
			return err
		}
	}

	return node.start(n.lndBinary, n.lndErrorChan, true)
}

// SuspendNode stops the given node and returns a callback that can be used to
// start it again.
func (n *NetworkHarness) SuspendNode(node *HarnessNode) (func() error, error) {
	if err := node.stop(); err != nil {
		return nil, err
	}

	restart := func() error {
		return node.start(n.lndBinary, n.lndErrorChan, true)
	}

	return restart, nil
}

// ShutdownNode stops an active lnd process and returns when the process has
// exited and any temporary directories have been cleaned up.
func (n *NetworkHarness) ShutdownNode(node *HarnessNode) error {
	if err := node.shutdown(); err != nil {
		return err
	}

	delete(n.activeNodes, node.NodeID)
	return nil
}

// KillNode kills the node (but won't wait for the node process to stop).
func (n *NetworkHarness) KillNode(node *HarnessNode) error {
	return node.kill()
}

// StopNode stops the target node, but doesn't yet clean up its directories.
// This can be used to temporarily bring a node down during a test, to be later
// started up again.
func (n *NetworkHarness) StopNode(node *HarnessNode) error {
	return node.stop()
}

// SaveProfilesPages hits profiles pages of all active nodes and writes it to
// disk using a similar naming scheme as to the regular set of logs.
func (n *NetworkHarness) SaveProfilesPages() {
	// Only write gorutine dumps if flag is active.
	if !(*goroutineDump) {
		return
	}

	for _, node := range n.activeNodes {
		if err := saveProfilesPage(node); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

// saveProfilesPage saves the profiles page for the given node to file.
func saveProfilesPage(node *HarnessNode) error {
	resp, err := http.Get(
		fmt.Sprintf(
			"http://localhost:%d/debug/pprof/goroutine?debug=1",
			node.Cfg.ProfilePort,
		),
	)
	if err != nil {
		return fmt.Errorf("failed to get profile page "+
			"(node_id=%d, name=%s): %v",
			node.NodeID, node.Cfg.Name, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read profile page "+
			"(node_id=%d, name=%s): %v",
			node.NodeID, node.Cfg.Name, err)
	}

	fileName := fmt.Sprintf(
		"pprof-%d-%s-%s.log", node.NodeID, node.Cfg.Name,
		hex.EncodeToString(node.PubKey[:logPubKeyBytes]),
	)

	logFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create file for profile page "+
			"(node_id=%d, name=%s): %v",
			node.NodeID, node.Cfg.Name, err)
	}
	defer logFile.Close()

	_, err = logFile.Write(body)
	if err != nil {
		return fmt.Errorf("failed to save profile page "+
			"(node_id=%d, name=%s): %v",
			node.NodeID, node.Cfg.Name, err)
	}
	return nil
}

// WaitForTxInMempool blocks until the target txid is seen in the mempool. If
// the transaction isn't seen within the network before the passed timeout,
// then an error is returned.
func (n *NetworkHarness) WaitForTxInMempool(ctx context.Context,
	txid chainhash.Hash) error {

	// Return immediately if harness has been torn down.
	select {
	case <-n.quit:
		return fmt.Errorf("NetworkHarness has been torn down")
	default:
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var mempool []*chainhash.Hash
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wanted %v, found %v txs "+
				"in mempool: %v", txid, len(mempool), mempool)

		case <-ticker.C:
			var err error
			mempool, err = n.Miner.Client.GetRawMempool()
			if err != nil {
				return err
			}

			for _, mempoolTx := range mempool {
				if *mempoolTx == txid {
					return nil
				}
			}
		}
	}
}

// OpenChannelParams houses the params to specify when opening a new channel.
type OpenChannelParams struct {
	// Amt is the local amount being put into the channel.
	Amt btcutil.Amount

	// PushAmt is the amount that should be pushed to the remote when the
	// channel is opened.
	PushAmt btcutil.Amount

	// Private is a boolan indicating whether the opened channel should be
	// private.
	Private bool

	// SpendUnconfirmed is a boolean indicating whether we can utilize
	// unconfirmed outputs to fund the channel.
	SpendUnconfirmed bool

	// MinHtlc is the htlc_minimum_msat value set when opening the channel.
	MinHtlc lnwire.MilliSatoshi

	// RemoteMaxHtlcs is the remote_max_htlcs value set when opening the
	// channel, restricting the number of concurrent HTLCs the remote party
	// can add to a commitment.
	RemoteMaxHtlcs uint16

	// FundingShim is an optional funding shim that the caller can specify
	// in order to modify the channel funding workflow.
	FundingShim *lnrpc.FundingShim

	// SatPerVByte is the amount of satoshis to spend in chain fees per virtual
	// byte of the transaction.
	SatPerVByte btcutil.Amount

	// CommitmentType is the commitment type that should be used for the
	// channel to be opened.
	CommitmentType lnrpc.CommitmentType
}

// OpenChannel attempts to open a channel between srcNode and destNode with the
// passed channel funding parameters. If the passed context has a timeout, then
// if the timeout is reached before the channel pending notification is
// received, an error is returned. The confirmed boolean determines whether we
// should fund the channel with confirmed outputs or not.
func (n *NetworkHarness) OpenChannel(ctx context.Context,
	srcNode, destNode *HarnessNode, p OpenChannelParams) (
	lnrpc.Lightning_OpenChannelClient, error) {

	// Wait until srcNode and destNode have the latest chain synced.
	// Otherwise, we may run into a check within the funding manager that
	// prevents any funding workflows from being kicked off if the chain
	// isn't yet synced.
	if err := srcNode.WaitForBlockchainSync(ctx); err != nil {
		return nil, fmt.Errorf("unable to sync srcNode chain: %v", err)
	}
	if err := destNode.WaitForBlockchainSync(ctx); err != nil {
		return nil, fmt.Errorf("unable to sync destNode chain: %v", err)
	}

	minConfs := int32(1)
	if p.SpendUnconfirmed {
		minConfs = 0
	}

	openReq := &lnrpc.OpenChannelRequest{
		NodePubkey:         destNode.PubKey[:],
		LocalFundingAmount: int64(p.Amt),
		PushSat:            int64(p.PushAmt),
		Private:            p.Private,
		MinConfs:           minConfs,
		SpendUnconfirmed:   p.SpendUnconfirmed,
		MinHtlcMsat:        int64(p.MinHtlc),
		RemoteMaxHtlcs:     uint32(p.RemoteMaxHtlcs),
		FundingShim:        p.FundingShim,
		SatPerByte:         int64(p.SatPerVByte),
		CommitmentType:     p.CommitmentType,
	}

	respStream, err := srcNode.OpenChannel(ctx, openReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel between "+
			"alice and bob: %v", err)
	}

	chanOpen := make(chan struct{})
	errChan := make(chan error)
	go func() {
		// Consume the "channel pending" update. This waits until the node
		// notifies us that the final message in the channel funding workflow
		// has been sent to the remote node.
		resp, err := respStream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		if _, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanPending); !ok {
			errChan <- fmt.Errorf("expected channel pending update, "+
				"instead got %v", resp)
			return
		}

		close(chanOpen)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before chan pending "+
			"update sent: %v", err)
	case err := <-errChan:
		return nil, err
	case <-chanOpen:
		return respStream, nil
	}
}

// OpenPendingChannel attempts to open a channel between srcNode and destNode with the
// passed channel funding parameters. If the passed context has a timeout, then
// if the timeout is reached before the channel pending notification is
// received, an error is returned.
func (n *NetworkHarness) OpenPendingChannel(ctx context.Context,
	srcNode, destNode *HarnessNode, amt btcutil.Amount,
	pushAmt btcutil.Amount) (*lnrpc.PendingUpdate, error) {

	// Wait until srcNode and destNode have blockchain synced
	if err := srcNode.WaitForBlockchainSync(ctx); err != nil {
		return nil, fmt.Errorf("unable to sync srcNode chain: %v", err)
	}
	if err := destNode.WaitForBlockchainSync(ctx); err != nil {
		return nil, fmt.Errorf("unable to sync destNode chain: %v", err)
	}

	openReq := &lnrpc.OpenChannelRequest{
		NodePubkey:         destNode.PubKey[:],
		LocalFundingAmount: int64(amt),
		PushSat:            int64(pushAmt),
		Private:            false,
	}

	respStream, err := srcNode.OpenChannel(ctx, openReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel between "+
			"alice and bob: %v", err)
	}

	chanPending := make(chan *lnrpc.PendingUpdate)
	errChan := make(chan error)
	go func() {
		// Consume the "channel pending" update. This waits until the node
		// notifies us that the final message in the channel funding workflow
		// has been sent to the remote node.
		resp, err := respStream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		pendingResp, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
		if !ok {
			errChan <- fmt.Errorf("expected channel pending update, "+
				"instead got %v", resp)
			return
		}

		chanPending <- pendingResp.ChanPending
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before chan pending " +
			"update sent")
	case err := <-errChan:
		return nil, err
	case pendingChan := <-chanPending:
		return pendingChan, nil
	}
}

// WaitForChannelOpen waits for a notification that a channel is open by
// consuming a message from the past open channel stream. If the passed context
// has a timeout, then if the timeout is reached before the channel has been
// opened, then an error is returned.
func (n *NetworkHarness) WaitForChannelOpen(ctx context.Context,
	openChanStream lnrpc.Lightning_OpenChannelClient) (*lnrpc.ChannelPoint, error) {

	errChan := make(chan error)
	respChan := make(chan *lnrpc.ChannelPoint)
	go func() {
		resp, err := openChanStream.Recv()
		if err != nil {
			errChan <- fmt.Errorf("unable to read rpc resp: %v", err)
			return
		}
		fundingResp, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanOpen)
		if !ok {
			errChan <- fmt.Errorf("expected channel open update, "+
				"instead got %v", resp)
			return
		}

		respChan <- fundingResp.ChanOpen.ChannelPoint
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached while waiting for " +
			"channel open")
	case err := <-errChan:
		return nil, err
	case chanPoint := <-respChan:
		return chanPoint, nil
	}
}

// CloseChannel attempts to close the channel indicated by the
// passed channel point, initiated by the passed lnNode. If the passed context
// has a timeout, an error is returned if that timeout is reached before the
// channel close is pending.
func (n *NetworkHarness) CloseChannel(ctx context.Context,
	lnNode *HarnessNode, cp *lnrpc.ChannelPoint,
	force bool) (lnrpc.Lightning_CloseChannelClient, *chainhash.Hash, error) {

	// Create a channel outpoint that we can use to compare to channels
	// from the ListChannelsResponse.
	txidHash, err := getChanPointFundingTxid(cp)
	if err != nil {
		return nil, nil, err
	}
	fundingTxID, err := chainhash.NewHash(txidHash)
	if err != nil {
		return nil, nil, err
	}
	chanPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: cp.OutputIndex,
	}

	// We'll wait for *both* nodes to read the channel as active if we're
	// performing a cooperative channel closure.
	if !force {
		timeout := DefaultTimeout
		listReq := &lnrpc.ListChannelsRequest{}

		// We define two helper functions, one two locate a particular
		// channel, and the other to check if a channel is active or
		// not.
		filterChannel := func(node *HarnessNode,
			op wire.OutPoint) (*lnrpc.Channel, error) {
			listResp, err := node.ListChannels(ctx, listReq)
			if err != nil {
				return nil, err
			}

			for _, c := range listResp.Channels {
				if c.ChannelPoint == op.String() {
					return c, nil
				}
			}

			return nil, fmt.Errorf("unable to find channel")
		}
		activeChanPredicate := func(node *HarnessNode) func() bool {
			return func() bool {
				channel, err := filterChannel(node, chanPoint)
				if err != nil {
					return false
				}

				return channel.Active
			}
		}

		// Next, we'll fetch the target channel in order to get the
		// harness node that will be receiving the channel close request.
		targetChan, err := filterChannel(lnNode, chanPoint)
		if err != nil {
			return nil, nil, err
		}
		receivingNode, err := n.LookUpNodeByPub(targetChan.RemotePubkey)
		if err != nil {
			return nil, nil, err
		}

		// Before proceeding, we'll ensure that the channel is active
		// for both nodes.
		err = wait.Predicate(activeChanPredicate(lnNode), timeout)
		if err != nil {
			return nil, nil, fmt.Errorf("channel of closing " +
				"node not active in time")
		}
		err = wait.Predicate(activeChanPredicate(receivingNode), timeout)
		if err != nil {
			return nil, nil, fmt.Errorf("channel of receiving " +
				"node not active in time")
		}
	}

	closeReq := &lnrpc.CloseChannelRequest{
		ChannelPoint: cp,
		Force:        force,
	}
	closeRespStream, err := lnNode.CloseChannel(ctx, closeReq)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to close channel: %v", err)
	}

	errChan := make(chan error)
	fin := make(chan *chainhash.Hash)
	go func() {
		// Consume the "channel close" update in order to wait for the closing
		// transaction to be broadcast, then wait for the closing tx to be seen
		// within the network.
		closeResp, err := closeRespStream.Recv()
		if err != nil {
			errChan <- fmt.Errorf("unable to recv() from close "+
				"stream: %v", err)
			return
		}
		pendingClose, ok := closeResp.Update.(*lnrpc.CloseStatusUpdate_ClosePending)
		if !ok {
			errChan <- fmt.Errorf("expected channel close update, "+
				"instead got %v", pendingClose)
			return
		}

		closeTxid, err := chainhash.NewHash(pendingClose.ClosePending.Txid)
		if err != nil {
			errChan <- fmt.Errorf("unable to decode closeTxid: "+
				"%v", err)
			return
		}
		if err := n.WaitForTxInMempool(ctx, *closeTxid); err != nil {
			errChan <- fmt.Errorf("error while waiting for "+
				"broadcast tx: %v", err)
			return
		}
		fin <- closeTxid
	}()

	// Wait until either the deadline for the context expires, an error
	// occurs, or the channel close update is received.
	select {
	case err := <-errChan:
		return nil, nil, err
	case closeTxid := <-fin:
		return closeRespStream, closeTxid, nil
	}
}

// WaitForChannelClose waits for a notification from the passed channel close
// stream that the node has deemed the channel has been fully closed. If the
// passed context has a timeout, then if the timeout is reached before the
// notification is received then an error is returned.
func (n *NetworkHarness) WaitForChannelClose(ctx context.Context,
	closeChanStream lnrpc.Lightning_CloseChannelClient) (*chainhash.Hash, error) {

	errChan := make(chan error)
	updateChan := make(chan *lnrpc.CloseStatusUpdate_ChanClose)
	go func() {
		closeResp, err := closeChanStream.Recv()
		if err != nil {
			errChan <- err
			return
		}

		closeFin, ok := closeResp.Update.(*lnrpc.CloseStatusUpdate_ChanClose)
		if !ok {
			errChan <- fmt.Errorf("expected channel close update, "+
				"instead got %v", closeFin)
			return
		}

		updateChan <- closeFin
	}()

	// Wait until either the deadline for the context expires, an error
	// occurs, or the channel close update is received.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before update sent")
	case err := <-errChan:
		return nil, err
	case update := <-updateChan:
		return chainhash.NewHash(update.ChanClose.ClosingTxid)
	}
}

// AssertChannelExists asserts that an active channel identified by the
// specified channel point exists from the point-of-view of the node. It takes
// an optional set of check functions which can be used to make further
// assertions using channel's values. These functions are responsible for
// failing the test themselves if they do not pass.
// nolint: interfacer
func (n *NetworkHarness) AssertChannelExists(ctx context.Context,
	node *HarnessNode, chanPoint *wire.OutPoint,
	checks ...func(*lnrpc.Channel)) error {

	req := &lnrpc.ListChannelsRequest{}

	return wait.NoError(func() error {
		resp, err := node.ListChannels(ctx, req)
		if err != nil {
			return fmt.Errorf("unable fetch node's channels: %v", err)
		}

		for _, channel := range resp.Channels {
			if channel.ChannelPoint == chanPoint.String() {
				// First check whether our channel is active,
				// failing early if it is not.
				if !channel.Active {
					return fmt.Errorf("channel %s inactive",
						chanPoint)
				}

				// Apply any additional checks that we would
				// like to verify.
				for _, check := range checks {
					check(channel)
				}

				return nil
			}
		}

		return fmt.Errorf("channel %s not found", chanPoint)
	}, DefaultTimeout)
}

// DumpLogs reads the current logs generated by the passed node, and returns
// the logs as a single string. This function is useful for examining the logs
// of a particular node in the case of a test failure.
// Logs from lightning node being generated with delay - you should
// add time.Sleep() in order to get all logs.
func (n *NetworkHarness) DumpLogs(node *HarnessNode) (string, error) {
	logFile := fmt.Sprintf("%v/simnet/lnd.log", node.Cfg.LogDir)

	buf, err := ioutil.ReadFile(logFile)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// SendCoins attempts to send amt satoshis from the internal mining node to the
// targeted lightning node using a P2WKH address. 6 blocks are mined after in
// order to confirm the transaction.
func (n *NetworkHarness) SendCoins(ctx context.Context, t *testing.T,
	amt btcutil.Amount, target *HarnessNode) {

	err := n.sendCoins(
		ctx, amt, target, lnrpc.AddressType_WITNESS_PUBKEY_HASH,
		true,
	)
	require.NoErrorf(t, err, "unable to send coins for %s", target.Cfg.Name)
}

// SendCoinsUnconfirmed sends coins from the internal mining node to the target
// lightning node using a P2WPKH address. No blocks are mined after, so the
// transaction remains unconfirmed.
func (n *NetworkHarness) SendCoinsUnconfirmed(ctx context.Context,
	t *testing.T, amt btcutil.Amount, target *HarnessNode) {

	err := n.sendCoins(
		ctx, amt, target, lnrpc.AddressType_WITNESS_PUBKEY_HASH,
		false,
	)
	require.NoErrorf(
		t, err, "unable to send unconfirmed coins for %s",
		target.Cfg.Name,
	)
}

// SendCoinsNP2WKH attempts to send amt satoshis from the internal mining node
// to the targeted lightning node using a NP2WKH address.
func (n *NetworkHarness) SendCoinsNP2WKH(ctx context.Context,
	t *testing.T, amt btcutil.Amount, target *HarnessNode) {

	err := n.sendCoins(
		ctx, amt, target, lnrpc.AddressType_NESTED_PUBKEY_HASH,
		true,
	)
	require.NoErrorf(
		t, err, "unable to send NP2WKH coins for %s",
		target.Cfg.Name,
	)
}

// sendCoins attempts to send amt satoshis from the internal mining node to the
// targeted lightning node. The confirmed boolean indicates whether the
// transaction that pays to the target should confirm.
func (n *NetworkHarness) sendCoins(ctx context.Context, amt btcutil.Amount,
	target *HarnessNode, addrType lnrpc.AddressType,
	confirmed bool) error {

	balReq := &lnrpc.WalletBalanceRequest{}
	initialBalance, err := target.WalletBalance(ctx, balReq)
	if err != nil {
		return err
	}

	// First, obtain an address from the target lightning node, preferring
	// to receive a p2wkh address s.t the output can immediately be used as
	// an input to a funding transaction.
	addrReq := &lnrpc.NewAddressRequest{
		Type: addrType,
	}
	resp, err := target.NewAddress(ctx, addrReq)
	if err != nil {
		return err
	}
	addr, err := btcutil.DecodeAddress(resp.Address, n.netParams)
	if err != nil {
		return err
	}
	addrScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

	// Generate a transaction which creates an output to the target
	// pkScript of the desired amount.
	output := &wire.TxOut{
		PkScript: addrScript,
		Value:    int64(amt),
	}
	_, err = n.Miner.SendOutputs([]*wire.TxOut{output}, 7500)
	if err != nil {
		return err
	}

	// Encode the pkScript in hex as this the format that it will be
	// returned via rpc.
	expPkScriptStr := hex.EncodeToString(addrScript)

	// Now, wait for ListUnspent to show the unconfirmed transaction
	// containing the correct pkscript.
	err = wait.NoError(func() error {
		// Since neutrino doesn't support unconfirmed outputs, skip
		// this check.
		if target.Cfg.BackendCfg.Name() == "neutrino" {
			return nil
		}

		req := &lnrpc.ListUnspentRequest{}
		resp, err := target.ListUnspent(ctx, req)
		if err != nil {
			return err
		}

		// When using this method, there should only ever be on
		// unconfirmed transaction.
		if len(resp.Utxos) != 1 {
			return fmt.Errorf("number of unconfirmed utxos "+
				"should be 1, found %d", len(resp.Utxos))
		}

		// Assert that the lone unconfirmed utxo contains the same
		// pkscript as the output generated above.
		pkScriptStr := resp.Utxos[0].PkScript
		if strings.Compare(pkScriptStr, expPkScriptStr) != 0 {
			return fmt.Errorf("pkscript mismatch, want: %s, "+
				"found: %s", expPkScriptStr, pkScriptStr)
		}

		return nil
	}, DefaultTimeout)
	if err != nil {
		return fmt.Errorf("unconfirmed utxo was not found in "+
			"ListUnspent: %v", err)
	}

	// If the transaction should remain unconfirmed, then we'll wait until
	// the target node's unconfirmed balance reflects the expected balance
	// and exit.
	if !confirmed {
		expectedBalance := btcutil.Amount(initialBalance.UnconfirmedBalance) + amt
		return target.WaitForBalance(expectedBalance, false)
	}

	// Otherwise, we'll generate 6 new blocks to ensure the output gains a
	// sufficient number of confirmations and wait for the balance to
	// reflect what's expected.
	if _, err := n.Miner.Client.Generate(6); err != nil {
		return err
	}

	expectedBalance := btcutil.Amount(initialBalance.ConfirmedBalance) + amt
	return target.WaitForBalance(expectedBalance, true)
}

func (n *NetworkHarness) SetFeeEstimate(fee chainfee.SatPerKWeight) {
	n.feeService.setFee(fee)
}

func (n *NetworkHarness) SetFeeEstimateWithConf(
	fee chainfee.SatPerKWeight, conf uint32) {

	n.feeService.setFeeWithConf(fee, conf)
}

// CopyFile copies the file src to dest.
func CopyFile(dest, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dest)
	if err != nil {
		return err
	}

	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}

	return d.Close()
}

// FileExists returns true if the file at path exists.
func FileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}

// copyAll copies all files and directories from srcDir to dstDir recursively.
// Note that this function does not support links.
func copyAll(dstDir, srcDir string) error {
	entries, err := ioutil.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		info, err := os.Stat(srcPath)
		if err != nil {
			return err
		}

		if info.IsDir() {
			err := os.Mkdir(dstPath, info.Mode())
			if err != nil && !os.IsExist(err) {
				return err
			}

			err = copyAll(dstPath, srcPath)
			if err != nil {
				return err
			}
		} else if err := CopyFile(dstPath, srcPath); err != nil {
			return err
		}
	}

	return nil
}

// BackupDb creates a backup of the current database.
func (n *NetworkHarness) BackupDb(hn *HarnessNode) error {
	if hn.backupDbDir != "" {
		return errors.New("backup already created")
	}

	// Backup files.
	tempDir, err := ioutil.TempDir("", "past-state")
	if err != nil {
		return fmt.Errorf("unable to create temp db folder: %v", err)
	}

	if err := copyAll(tempDir, hn.DBDir()); err != nil {
		return fmt.Errorf("unable to copy database files: %v", err)
	}

	hn.backupDbDir = tempDir

	return nil
}

// RestoreDb restores a database backup.
func (n *NetworkHarness) RestoreDb(hn *HarnessNode) error {
	if hn.backupDbDir == "" {
		return errors.New("no database backup created")
	}

	// Restore files.
	if err := copyAll(hn.DBDir(), hn.backupDbDir); err != nil {
		return fmt.Errorf("unable to copy database files: %v", err)
	}

	if err := os.RemoveAll(hn.backupDbDir); err != nil {
		return fmt.Errorf("unable to remove backup dir: %v", err)
	}
	hn.backupDbDir = ""

	return nil
}
