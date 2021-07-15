package lntest

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnrpc/watchtowerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/wtclientrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

const (
	// defaultNodePort is the start of the range for listening ports of
	// harness nodes. Ports are monotonically increasing starting from this
	// number and are determined by the results of nextAvailablePort().
	defaultNodePort = 5555

	// logPubKeyBytes is the number of bytes of the node's PubKey that will
	// be appended to the log file name. The whole PubKey is too long and
	// not really necessary to quickly identify what node produced which
	// log file.
	logPubKeyBytes = 4

	// trickleDelay is the amount of time in milliseconds between each
	// release of announcements by AuthenticatedGossiper to the network.
	trickleDelay = 50

	// listenerFormat is the format string that is used to generate local
	// listener addresses.
	listenerFormat = "127.0.0.1:%d"

	// NeutrinoBackendName is the name of the neutrino backend.
	NeutrinoBackendName = "neutrino"
)

var (
	// numActiveNodes is the number of active nodes within the test network.
	numActiveNodes    = 0
	numActiveNodesMtx sync.Mutex

	// lastPort is the last port determined to be free for use by a new
	// node. It should be used atomically.
	lastPort uint32 = defaultNodePort

	// logOutput is a flag that can be set to append the output from the
	// seed nodes to log files.
	logOutput = flag.Bool("logoutput", false,
		"log output from node n to file output-n.log")

	// logSubDir is the default directory where the logs are written to if
	// logOutput is true.
	logSubDir = flag.String("logdir", ".", "default dir to write logs to")

	// goroutineDump is a flag that can be set to dump the active
	// goroutines of test nodes on failure.
	goroutineDump = flag.Bool("goroutinedump", false,
		"write goroutine dump from node n to file pprof-n.log")

	// btcdExecutable is the full path to the btcd binary.
	btcdExecutable = flag.String(
		"btcdexec", "", "full path to btcd binary",
	)
)

// NextAvailablePort returns the first port that is available for listening by
// a new node. It panics if no port is found and the maximum available TCP port
// is reached.
func NextAvailablePort() int {
	port := atomic.AddUint32(&lastPort, 1)
	for port < 65535 {
		// If there are no errors while attempting to listen on this
		// port, close the socket and return it as available. While it
		// could be the case that some other process picks up this port
		// between the time the socket is closed and it's reopened in
		// the harness node, in practice in CI servers this seems much
		// less likely than simply some other process already being
		// bound at the start of the tests.
		addr := fmt.Sprintf(listenerFormat, port)
		l, err := net.Listen("tcp4", addr)
		if err == nil {
			err := l.Close()
			if err == nil {
				return int(port)
			}
		}
		port = atomic.AddUint32(&lastPort, 1)
	}

	// No ports available? Must be a mistake.
	panic("no ports available for listening")
}

// ApplyPortOffset adds the given offset to the lastPort variable, making it
// possible to run the tests in parallel without colliding on the same ports.
func ApplyPortOffset(offset uint32) {
	_ = atomic.AddUint32(&lastPort, offset)
}

// GetLogDir returns the passed --logdir flag or the default value if it wasn't
// set.
func GetLogDir() string {
	if logSubDir != nil && *logSubDir != "" {
		return *logSubDir
	}
	return "."
}

// GetBtcdBinary returns the full path to the binary of the custom built btcd
// executable or an empty string if none is set.
func GetBtcdBinary() string {
	if btcdExecutable != nil {
		return *btcdExecutable
	}

	return ""
}

// GenerateBtcdListenerAddresses is a function that returns two listener
// addresses with unique ports and should be used to overwrite rpctest's default
// generator which is prone to use colliding ports.
func GenerateBtcdListenerAddresses() (string, string) {
	return fmt.Sprintf(listenerFormat, NextAvailablePort()),
		fmt.Sprintf(listenerFormat, NextAvailablePort())
}

// generateListeningPorts returns four ints representing ports to listen on
// designated for the current lightning network test. This returns the next
// available ports for the p2p, rpc, rest and profiling services.
func generateListeningPorts(cfg *NodeConfig) {
	if cfg.P2PPort == 0 {
		cfg.P2PPort = NextAvailablePort()
	}
	if cfg.RPCPort == 0 {
		cfg.RPCPort = NextAvailablePort()
	}
	if cfg.RESTPort == 0 {
		cfg.RESTPort = NextAvailablePort()
	}
	if cfg.ProfilePort == 0 {
		cfg.ProfilePort = NextAvailablePort()
	}
}

// BackendConfig is an interface that abstracts away the specific chain backend
// node implementation.
type BackendConfig interface {
	// GenArgs returns the arguments needed to be passed to LND at startup
	// for using this node as a chain backend.
	GenArgs() []string

	// ConnectMiner is called to establish a connection to the test miner.
	ConnectMiner() error

	// DisconnectMiner is called to disconnect the miner.
	DisconnectMiner() error

	// Name returns the name of the backend type.
	Name() string
}

type NodeConfig struct {
	Name string

	// LogFilenamePrefix is is used to prefix node log files. Can be used
	// to store the current test case for simpler postmortem debugging.
	LogFilenamePrefix string

	BackendCfg BackendConfig
	NetParams  *chaincfg.Params
	BaseDir    string
	ExtraArgs  []string

	DataDir        string
	LogDir         string
	TLSCertPath    string
	TLSKeyPath     string
	AdminMacPath   string
	ReadMacPath    string
	InvoiceMacPath string

	HasSeed  bool
	Password []byte

	P2PPort     int
	RPCPort     int
	RESTPort    int
	ProfilePort int

	AcceptKeySend bool
	AcceptAMP     bool

	FeeURL string

	DbBackend DatabaseBackend
}

func (cfg NodeConfig) P2PAddr() string {
	return fmt.Sprintf(listenerFormat, cfg.P2PPort)
}

func (cfg NodeConfig) RPCAddr() string {
	return fmt.Sprintf(listenerFormat, cfg.RPCPort)
}

func (cfg NodeConfig) RESTAddr() string {
	return fmt.Sprintf(listenerFormat, cfg.RESTPort)
}

// DBDir returns the holding directory path of the graph database.
func (cfg NodeConfig) DBDir() string {
	return filepath.Join(cfg.DataDir, "graph", cfg.NetParams.Name)
}

func (cfg NodeConfig) DBPath() string {
	return filepath.Join(cfg.DBDir(), "channel.db")
}

func (cfg NodeConfig) ChanBackupPath() string {
	return filepath.Join(
		cfg.DataDir, "chain", "bitcoin",
		fmt.Sprintf(
			"%v/%v", cfg.NetParams.Name,
			chanbackup.DefaultBackupFileName,
		),
	)
}

// genArgs generates a slice of command line arguments from the lightning node
// config struct.
func (cfg NodeConfig) genArgs() []string {
	var args []string

	switch cfg.NetParams {
	case &chaincfg.TestNet3Params:
		args = append(args, "--bitcoin.testnet")
	case &chaincfg.SimNetParams:
		args = append(args, "--bitcoin.simnet")
	case &chaincfg.RegressionNetParams:
		args = append(args, "--bitcoin.regtest")
	}

	backendArgs := cfg.BackendCfg.GenArgs()
	args = append(args, backendArgs...)
	args = append(args, "--bitcoin.active")
	args = append(args, "--nobootstrap")
	args = append(args, "--debuglevel=debug")
	args = append(args, "--bitcoin.defaultchanconfs=1")
	args = append(args, fmt.Sprintf("--db.batch-commit-interval=%v", 10*time.Millisecond))
	args = append(args, fmt.Sprintf("--bitcoin.defaultremotedelay=%v", DefaultCSV))
	args = append(args, fmt.Sprintf("--rpclisten=%v", cfg.RPCAddr()))
	args = append(args, fmt.Sprintf("--restlisten=%v", cfg.RESTAddr()))
	args = append(args, fmt.Sprintf("--restcors=https://%v", cfg.RESTAddr()))
	args = append(args, fmt.Sprintf("--listen=%v", cfg.P2PAddr()))
	args = append(args, fmt.Sprintf("--externalip=%v", cfg.P2PAddr()))
	args = append(args, fmt.Sprintf("--logdir=%v", cfg.LogDir))
	args = append(args, fmt.Sprintf("--datadir=%v", cfg.DataDir))
	args = append(args, fmt.Sprintf("--tlscertpath=%v", cfg.TLSCertPath))
	args = append(args, fmt.Sprintf("--tlskeypath=%v", cfg.TLSKeyPath))
	args = append(args, fmt.Sprintf("--configfile=%v", cfg.DataDir))
	args = append(args, fmt.Sprintf("--adminmacaroonpath=%v", cfg.AdminMacPath))
	args = append(args, fmt.Sprintf("--readonlymacaroonpath=%v", cfg.ReadMacPath))
	args = append(args, fmt.Sprintf("--invoicemacaroonpath=%v", cfg.InvoiceMacPath))
	args = append(args, fmt.Sprintf("--trickledelay=%v", trickleDelay))
	args = append(args, fmt.Sprintf("--profile=%d", cfg.ProfilePort))

	if !cfg.HasSeed {
		args = append(args, "--noseedbackup")
	}

	if cfg.ExtraArgs != nil {
		args = append(args, cfg.ExtraArgs...)
	}

	if cfg.AcceptKeySend {
		args = append(args, "--accept-keysend")
	}

	if cfg.AcceptAMP {
		args = append(args, "--accept-amp")
	}

	if cfg.DbBackend == BackendEtcd {
		args = append(args, "--db.backend=etcd")
		args = append(args, "--db.etcd.embedded")
		args = append(
			args, fmt.Sprintf(
				"--db.etcd.embedded_client_port=%v",
				NextAvailablePort(),
			),
		)
		args = append(
			args, fmt.Sprintf(
				"--db.etcd.embedded_peer_port=%v",
				NextAvailablePort(),
			),
		)
	}

	if cfg.FeeURL != "" {
		args = append(args, "--feeurl="+cfg.FeeURL)
	}

	return args
}

// HarnessNode represents an instance of lnd running within our test network
// harness. Each HarnessNode instance also fully embeds an RPC client in
// order to pragmatically drive the node.
type HarnessNode struct {
	Cfg *NodeConfig

	// NodeID is a unique identifier for the node within a NetworkHarness.
	NodeID int

	// PubKey is the serialized compressed identity public key of the node.
	// This field will only be populated once the node itself has been
	// started via the start() method.
	PubKey    [33]byte
	PubKeyStr string

	cmd     *exec.Cmd
	pidFile string
	logFile *os.File

	// processExit is a channel that's closed once it's detected that the
	// process this instance of HarnessNode is bound to has exited.
	processExit chan struct{}

	chanWatchRequests chan *chanWatchRequest

	// For each outpoint, we'll track an integer which denotes the number of
	// edges seen for that channel within the network. When this number
	// reaches 2, then it means that both edge advertisements has propagated
	// through the network.
	openChans   map[wire.OutPoint]int
	openClients map[wire.OutPoint][]chan struct{}

	closedChans  map[wire.OutPoint]struct{}
	closeClients map[wire.OutPoint][]chan struct{}

	quit chan struct{}
	wg   sync.WaitGroup

	lnrpc.LightningClient

	lnrpc.WalletUnlockerClient

	invoicesrpc.InvoicesClient

	// SignerClient cannot be embedded because the name collisions of the
	// methods SignMessage and VerifyMessage.
	SignerClient signrpc.SignerClient

	// conn is the underlying connection to the grpc endpoint of the node.
	conn *grpc.ClientConn

	// RouterClient, WalletKitClient, WatchtowerClient cannot be embedded,
	// because a name collision would occur with LightningClient.
	RouterClient     routerrpc.RouterClient
	WalletKitClient  walletrpc.WalletKitClient
	Watchtower       watchtowerrpc.WatchtowerClient
	WatchtowerClient wtclientrpc.WatchtowerClientClient

	// backupDbDir is the path where a database backup is stored, if any.
	backupDbDir string
}

// Assert *HarnessNode implements the lnrpc.LightningClient interface.
var _ lnrpc.LightningClient = (*HarnessNode)(nil)
var _ lnrpc.WalletUnlockerClient = (*HarnessNode)(nil)
var _ invoicesrpc.InvoicesClient = (*HarnessNode)(nil)

// newNode creates a new test lightning node instance from the passed config.
func newNode(cfg NodeConfig) (*HarnessNode, error) {
	if cfg.BaseDir == "" {
		var err error
		cfg.BaseDir, err = ioutil.TempDir("", "lndtest-node")
		if err != nil {
			return nil, err
		}
	}
	cfg.DataDir = filepath.Join(cfg.BaseDir, "data")
	cfg.LogDir = filepath.Join(cfg.BaseDir, "log")
	cfg.TLSCertPath = filepath.Join(cfg.DataDir, "tls.cert")
	cfg.TLSKeyPath = filepath.Join(cfg.DataDir, "tls.key")

	networkDir := filepath.Join(
		cfg.DataDir, "chain", "bitcoin", cfg.NetParams.Name,
	)
	cfg.AdminMacPath = filepath.Join(networkDir, "admin.macaroon")
	cfg.ReadMacPath = filepath.Join(networkDir, "readonly.macaroon")
	cfg.InvoiceMacPath = filepath.Join(networkDir, "invoice.macaroon")

	generateListeningPorts(&cfg)

	// Run all tests with accept keysend. The keysend code is very isolated
	// and it is highly unlikely that it would affect regular itests when
	// enabled.
	cfg.AcceptKeySend = true

	numActiveNodesMtx.Lock()
	nodeNum := numActiveNodes
	numActiveNodes++
	numActiveNodesMtx.Unlock()

	return &HarnessNode{
		Cfg:               &cfg,
		NodeID:            nodeNum,
		chanWatchRequests: make(chan *chanWatchRequest),
		openChans:         make(map[wire.OutPoint]int),
		openClients:       make(map[wire.OutPoint][]chan struct{}),

		closedChans:  make(map[wire.OutPoint]struct{}),
		closeClients: make(map[wire.OutPoint][]chan struct{}),
	}, nil
}

// NewMiner creates a new miner using btcd backend. The logDir specifies the
// miner node's log dir. When tests finished, during clean up, its logs are
// copied to a file specified as logFilename.
func NewMiner(logDir, logFilename string, netParams *chaincfg.Params,
	handler *rpcclient.NotificationHandlers,
	btcdBinary string) (*rpctest.Harness, func() error, error) {

	args := []string{
		"--rejectnonstd",
		"--txindex",
		"--nowinservice",
		"--nobanning",
		"--debuglevel=debug",
		"--logdir=" + logDir,
		"--trickleinterval=100ms",
	}

	miner, err := rpctest.New(netParams, handler, args, btcdBinary)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"unable to create mining node: %v", err,
		)
	}

	cleanUp := func() error {
		if err := miner.TearDown(); err != nil {
			return fmt.Errorf(
				"failed to tear down miner, got error: %s", err,
			)
		}

		// After shutting down the miner, we'll make a copy of the log
		// file before deleting the temporary log dir.
		logFile := fmt.Sprintf("%s/%s/btcd.log", logDir, netParams.Name)
		copyPath := fmt.Sprintf("%s/../%s", logDir, logFilename)
		err := CopyFile(filepath.Clean(copyPath), logFile)
		if err != nil {
			return fmt.Errorf("unable to copy file: %v", err)
		}

		if err = os.RemoveAll(logDir); err != nil {
			return fmt.Errorf(
				"cannot remove dir %s: %v", logDir, err,
			)
		}
		return nil
	}

	return miner, cleanUp, nil
}

// DBPath returns the filepath to the channeldb database file for this node.
func (hn *HarnessNode) DBPath() string {
	return hn.Cfg.DBPath()
}

// DBDir returns the path for the directory holding channeldb file(s).
func (hn *HarnessNode) DBDir() string {
	return hn.Cfg.DBDir()
}

// Name returns the name of this node set during initialization.
func (hn *HarnessNode) Name() string {
	return hn.Cfg.Name
}

// TLSCertStr returns the path where the TLS certificate is stored.
func (hn *HarnessNode) TLSCertStr() string {
	return hn.Cfg.TLSCertPath
}

// TLSKeyStr returns the path where the TLS key is stored.
func (hn *HarnessNode) TLSKeyStr() string {
	return hn.Cfg.TLSKeyPath
}

// ChanBackupPath returns the fielpath to the on-disk channels.backup file for
// this node.
func (hn *HarnessNode) ChanBackupPath() string {
	return hn.Cfg.ChanBackupPath()
}

// AdminMacPath returns the filepath to the admin.macaroon file for this node.
func (hn *HarnessNode) AdminMacPath() string {
	return hn.Cfg.AdminMacPath
}

// ReadMacPath returns the filepath to the readonly.macaroon file for this node.
func (hn *HarnessNode) ReadMacPath() string {
	return hn.Cfg.ReadMacPath
}

// InvoiceMacPath returns the filepath to the invoice.macaroon file for this
// node.
func (hn *HarnessNode) InvoiceMacPath() string {
	return hn.Cfg.InvoiceMacPath
}

// Start launches a new process running lnd. Additionally, the PID of the
// launched process is saved in order to possibly kill the process forcibly
// later.
//
// This may not clean up properly if an error is returned, so the caller should
// call shutdown() regardless of the return value.
func (hn *HarnessNode) start(lndBinary string, lndError chan<- error,
	wait bool) error {

	hn.quit = make(chan struct{})

	args := hn.Cfg.genArgs()
	hn.cmd = exec.Command(lndBinary, args...)

	// Redirect stderr output to buffer
	var errb bytes.Buffer
	hn.cmd.Stderr = &errb

	// Make sure the log file cleanup function is initialized, even
	// if no log file is created.
	var finalizeLogfile = func() {
		if hn.logFile != nil {
			hn.logFile.Close()
		}
	}

	// If the logoutput flag is passed, redirect output from the nodes to
	// log files.
	if *logOutput {
		dir := GetLogDir()
		fileName := fmt.Sprintf("%s/%d-%s-%s-%s.log", dir, hn.NodeID,
			hn.Cfg.LogFilenamePrefix, hn.Cfg.Name,
			hex.EncodeToString(hn.PubKey[:logPubKeyBytes]))

		// If the node's PubKey is not yet initialized, create a
		// temporary file name. Later, after the PubKey has been
		// initialized, the file can be moved to its final name with
		// the PubKey included.
		if bytes.Equal(hn.PubKey[:4], []byte{0, 0, 0, 0}) {
			fileName = fmt.Sprintf("%s/%d-%s-%s-tmp__.log", dir,
				hn.NodeID, hn.Cfg.LogFilenamePrefix,
				hn.Cfg.Name)

			// Once the node has done its work, the log file can be
			// renamed.
			finalizeLogfile = func() {
				if hn.logFile != nil {
					hn.logFile.Close()

					pubKeyHex := hex.EncodeToString(
						hn.PubKey[:logPubKeyBytes],
					)
					newFileName := fmt.Sprintf("%s/"+
						"%d-%s-%s-%s.log",
						dir, hn.NodeID,
						hn.Cfg.LogFilenamePrefix,
						hn.Cfg.Name, pubKeyHex)
					err := os.Rename(fileName, newFileName)
					if err != nil {
						fmt.Printf("could not rename "+
							"%s to %s: %v\n",
							fileName, newFileName,
							err)
					}
				}
			}
		}

		// Create file if not exists, otherwise append.
		file, err := os.OpenFile(fileName,
			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return err
		}

		// Pass node's stderr to both errb and the file.
		w := io.MultiWriter(&errb, file)
		hn.cmd.Stderr = w

		// Pass the node's stdout only to the file.
		hn.cmd.Stdout = file

		// Let the node keep a reference to this file, such
		// that we can add to it if necessary.
		hn.logFile = file
	}

	if err := hn.cmd.Start(); err != nil {
		return err
	}

	// Launch a new goroutine which that bubbles up any potential fatal
	// process errors to the goroutine running the tests.
	hn.processExit = make(chan struct{})
	hn.wg.Add(1)
	go func() {
		defer hn.wg.Done()

		err := hn.cmd.Wait()
		if err != nil {
			lndError <- errors.Errorf("%v\n%v\n", err, errb.String())
		}

		// Signal any onlookers that this process has exited.
		close(hn.processExit)

		// Make sure log file is closed and renamed if necessary.
		finalizeLogfile()
	}()

	// Write process ID to a file.
	if err := hn.writePidFile(); err != nil {
		hn.cmd.Process.Kill()
		return err
	}

	// We may want to skip waiting for the node to come up (eg. the node
	// is waiting to become the leader).
	if !wait {
		return nil
	}

	// Since Stop uses the LightningClient to stop the node, if we fail to get a
	// connected client, we have to kill the process.
	useMacaroons := !hn.Cfg.HasSeed
	conn, err := hn.ConnectRPC(useMacaroons)
	if err != nil {
		hn.cmd.Process.Kill()
		return err
	}

	if err := hn.waitUntilStarted(conn, DefaultTimeout); err != nil {
		return err
	}

	// If the node was created with a seed, we will need to perform an
	// additional step to unlock the wallet. The connection returned will
	// only use the TLS certs, and can only perform operations necessary to
	// unlock the daemon.
	if hn.Cfg.HasSeed {
		hn.WalletUnlockerClient = lnrpc.NewWalletUnlockerClient(conn)
		return nil
	}

	return hn.initLightningClient(conn)
}

// waitUntilStarted waits until the wallet state flips from "WAITING_TO_START".
func (hn *HarnessNode) waitUntilStarted(conn grpc.ClientConnInterface,
	timeout time.Duration) error {

	stateClient := lnrpc.NewStateClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stateStream, err := stateClient.SubscribeState(
		ctx, &lnrpc.SubscribeStateRequest{},
	)
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		for {
			resp, err := stateStream.Recv()
			if err != nil {
				errChan <- err
			}

			if resp.State != lnrpc.WalletState_WAITING_TO_START {
				close(started)
				return
			}
		}
	}()

	select {

	case <-started:
	case err = <-errChan:

	case <-time.After(timeout):
		return fmt.Errorf("WaitUntilLeader timed out")
	}

	return err
}

// WaitUntilLeader attempts to finish the start procedure by initiating an RPC
// connection and setting up the wallet unlocker client. This is needed when
// a node that has recently been started was waiting to become the leader and
// we're at the point when we expect that it is the leader now (awaiting unlock).
func (hn *HarnessNode) WaitUntilLeader(timeout time.Duration) error {
	var (
		conn    *grpc.ClientConn
		connErr error
	)

	startTs := time.Now()
	if err := wait.NoError(func() error {
		conn, connErr = hn.ConnectRPC(!hn.Cfg.HasSeed)
		return connErr
	}, timeout); err != nil {
		return err
	}
	timeout -= time.Since(startTs)

	if err := hn.waitUntilStarted(conn, timeout); err != nil {
		return err
	}

	// If the node was created with a seed, we will need to perform an
	// additional step to unlock the wallet. The connection returned will
	// only use the TLS certs, and can only perform operations necessary to
	// unlock the daemon.
	if hn.Cfg.HasSeed {
		hn.WalletUnlockerClient = lnrpc.NewWalletUnlockerClient(conn)
		return nil
	}

	return hn.initLightningClient(conn)
}

// initClientWhenReady waits until the main gRPC server is detected as active,
// then complete the normal HarnessNode gRPC connection creation. This can be
// used it a node has just been unlocked, or has its wallet state initialized.
func (hn *HarnessNode) initClientWhenReady(timeout time.Duration) error {
	var (
		conn    *grpc.ClientConn
		connErr error
	)
	if err := wait.NoError(func() error {
		conn, connErr = hn.ConnectRPC(true)
		return connErr
	}, timeout); err != nil {
		return err
	}

	return hn.initLightningClient(conn)
}

// Init initializes a harness node by passing the init request via rpc. After
// the request is submitted, this method will block until a
// macaroon-authenticated RPC connection can be established to the harness node.
// Once established, the new connection is used to initialize the
// LightningClient and subscribes the HarnessNode to topology changes.
func (hn *HarnessNode) Init(ctx context.Context,
	initReq *lnrpc.InitWalletRequest) (*lnrpc.InitWalletResponse, error) {

	ctxt, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	response, err := hn.InitWallet(ctxt, initReq)
	if err != nil {
		return nil, err
	}

	// Wait for the wallet to finish unlocking, such that we can connect to
	// it via a macaroon-authenticated rpc connection.
	var conn *grpc.ClientConn
	if err = wait.Predicate(func() bool {
		// If the node has been initialized stateless, we need to pass
		// the macaroon to the client.
		if initReq.StatelessInit {
			adminMac := &macaroon.Macaroon{}
			err := adminMac.UnmarshalBinary(response.AdminMacaroon)
			if err != nil {
				return false
			}
			conn, err = hn.ConnectRPCWithMacaroon(adminMac)
			return err == nil
		}

		// Normal initialization, we expect a macaroon to be in the
		// file system.
		conn, err = hn.ConnectRPC(true)
		return err == nil
	}, DefaultTimeout); err != nil {
		return nil, err
	}

	return response, hn.initLightningClient(conn)
}

// InitChangePassword initializes a harness node by passing the change password
// request via RPC. After the request is submitted, this method will block until
// a macaroon-authenticated RPC connection can be established to the harness
// node. Once established, the new connection is used to initialize the
// LightningClient and subscribes the HarnessNode to topology changes.
func (hn *HarnessNode) InitChangePassword(ctx context.Context,
	chngPwReq *lnrpc.ChangePasswordRequest) (*lnrpc.ChangePasswordResponse,
	error) {

	ctxt, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	response, err := hn.ChangePassword(ctxt, chngPwReq)
	if err != nil {
		return nil, err
	}

	// Wait for the wallet to finish unlocking, such that we can connect to
	// it via a macaroon-authenticated rpc connection.
	var conn *grpc.ClientConn
	if err = wait.Predicate(func() bool {
		// If the node has been initialized stateless, we need to pass
		// the macaroon to the client.
		if chngPwReq.StatelessInit {
			adminMac := &macaroon.Macaroon{}
			err := adminMac.UnmarshalBinary(response.AdminMacaroon)
			if err != nil {
				return false
			}
			conn, err = hn.ConnectRPCWithMacaroon(adminMac)
			return err == nil
		}

		// Normal initialization, we expect a macaroon to be in the
		// file system.
		conn, err = hn.ConnectRPC(true)
		return err == nil
	}, DefaultTimeout); err != nil {
		return nil, err
	}

	return response, hn.initLightningClient(conn)
}

// Unlock attempts to unlock the wallet of the target HarnessNode. This method
// should be called after the restart of a HarnessNode that was created with a
// seed+password. Once this method returns, the HarnessNode will be ready to
// accept normal gRPC requests and harness command.
func (hn *HarnessNode) Unlock(ctx context.Context,
	unlockReq *lnrpc.UnlockWalletRequest) error {

	ctxt, _ := context.WithTimeout(ctx, DefaultTimeout)

	// Otherwise, we'll need to unlock the node before it's able to start
	// up properly.
	if _, err := hn.UnlockWallet(ctxt, unlockReq); err != nil {
		return err
	}

	// Now that the wallet has been unlocked, we'll wait for the RPC client
	// to be ready, then establish the normal gRPC connection.
	return hn.initClientWhenReady(DefaultTimeout)
}

// initLightningClient constructs the grpc LightningClient from the given client
// connection and subscribes the harness node to graph topology updates.
// This method also spawns a lightning network watcher for this node,
// which watches for topology changes.
func (hn *HarnessNode) initLightningClient(conn *grpc.ClientConn) error {
	// Construct the LightningClient that will allow us to use the
	// HarnessNode directly for normal rpc operations.
	hn.conn = conn
	hn.LightningClient = lnrpc.NewLightningClient(conn)
	hn.InvoicesClient = invoicesrpc.NewInvoicesClient(conn)
	hn.RouterClient = routerrpc.NewRouterClient(conn)
	hn.WalletKitClient = walletrpc.NewWalletKitClient(conn)
	hn.Watchtower = watchtowerrpc.NewWatchtowerClient(conn)
	hn.WatchtowerClient = wtclientrpc.NewWatchtowerClientClient(conn)
	hn.SignerClient = signrpc.NewSignerClient(conn)

	// Set the harness node's pubkey to what the node claims in GetInfo.
	// Since the RPC might not be immediately active, we wrap the call in a
	// wait.NoError.
	if err := wait.NoError(hn.FetchNodeInfo, DefaultTimeout); err != nil {
		return err
	}

	// Due to a race condition between the ChannelRouter starting and us
	// making the subscription request, it's possible for our graph
	// subscription to fail. To ensure we don't start listening for updates
	// until then, we'll create a dummy subscription to ensure we can do so
	// successfully before proceeding. We use a dummy subscription in order
	// to not consume an update from the real one.
	err := wait.NoError(func() error {
		req := &lnrpc.GraphTopologySubscription{}
		ctx, cancelFunc := context.WithCancel(context.Background())
		topologyClient, err := hn.SubscribeChannelGraph(ctx, req)
		if err != nil {
			return err
		}

		// We'll wait to receive an error back within a one second
		// timeout. This is needed since creating the client's stream is
		// independent of the graph subscription being created. The
		// stream is closed from the server's side upon an error.
		errChan := make(chan error, 1)
		go func() {
			if _, err := topologyClient.Recv(); err != nil {
				errChan <- err
			}
		}()

		select {
		case err = <-errChan:
		case <-time.After(time.Second):
		}

		cancelFunc()
		return err
	}, DefaultTimeout)
	if err != nil {
		return err
	}

	// Launch the watcher that will hook into graph related topology change
	// from the PoV of this node.
	hn.wg.Add(1)
	subscribed := make(chan error)
	go hn.lightningNetworkWatcher(subscribed)

	return <-subscribed
}

// FetchNodeInfo queries an unlocked node to retrieve its public key.
func (hn *HarnessNode) FetchNodeInfo() error {
	// Obtain the lnid of this node for quick identification purposes.
	ctxb := context.Background()
	info, err := hn.GetInfo(ctxb, &lnrpc.GetInfoRequest{})
	if err != nil {
		return err
	}

	hn.PubKeyStr = info.IdentityPubkey

	pubkey, err := hex.DecodeString(info.IdentityPubkey)
	if err != nil {
		return err
	}
	copy(hn.PubKey[:], pubkey)

	return nil
}

// AddToLog adds a line of choice to the node's logfile. This is useful
// to interleave test output with output from the node.
func (hn *HarnessNode) AddToLog(line string) error {
	// If this node was not set up with a log file, just return early.
	if hn.logFile == nil {
		return nil
	}
	if _, err := hn.logFile.WriteString(line); err != nil {
		return err
	}
	return nil
}

// writePidFile writes the process ID of the running lnd process to a .pid file.
func (hn *HarnessNode) writePidFile() error {
	filePath := filepath.Join(hn.Cfg.BaseDir, fmt.Sprintf("%v.pid", hn.NodeID))

	pid, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer pid.Close()

	_, err = fmt.Fprintf(pid, "%v\n", hn.cmd.Process.Pid)
	if err != nil {
		return err
	}

	hn.pidFile = filePath
	return nil
}

// ReadMacaroon waits a given duration for the macaroon file to be created. If
// the file is readable within the timeout, its content is de-serialized as a
// macaroon and returned.
func (hn *HarnessNode) ReadMacaroon(macPath string, timeout time.Duration) (
	*macaroon.Macaroon, error) {

	// Wait until macaroon file is created and has valid content before
	// using it.
	var mac *macaroon.Macaroon
	err := wait.NoError(func() error {
		macBytes, err := ioutil.ReadFile(macPath)
		if err != nil {
			return fmt.Errorf("error reading macaroon file: %v", err)
		}

		newMac := &macaroon.Macaroon{}
		if err = newMac.UnmarshalBinary(macBytes); err != nil {
			return fmt.Errorf("error unmarshalling macaroon "+
				"file: %v", err)
		}
		mac = newMac

		return nil
	}, timeout)

	return mac, err
}

// ConnectRPCWithMacaroon uses the TLS certificate and given macaroon to
// create a gRPC client connection.
func (hn *HarnessNode) ConnectRPCWithMacaroon(mac *macaroon.Macaroon) (
	*grpc.ClientConn, error) {

	// Wait until TLS certificate is created and has valid content before
	// using it, up to 30 sec.
	var tlsCreds credentials.TransportCredentials
	err := wait.NoError(func() error {
		var err error
		tlsCreds, err = credentials.NewClientTLSFromFile(
			hn.Cfg.TLSCertPath, "",
		)
		return err
	}, DefaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("error reading TLS cert: %v", err)
	}

	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(tlsCreds),
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	if mac == nil {
		return grpc.DialContext(ctx, hn.Cfg.RPCAddr(), opts...)
	}
	macCred := macaroons.NewMacaroonCredential(mac)
	opts = append(opts, grpc.WithPerRPCCredentials(macCred))

	return grpc.DialContext(ctx, hn.Cfg.RPCAddr(), opts...)
}

// ConnectRPC uses the TLS certificate and admin macaroon files written by the
// lnd node to create a gRPC client connection.
func (hn *HarnessNode) ConnectRPC(useMacs bool) (*grpc.ClientConn, error) {
	// If we don't want to use macaroons, just pass nil, the next method
	// will handle it correctly.
	if !useMacs {
		return hn.ConnectRPCWithMacaroon(nil)
	}

	// If we should use a macaroon, always take the admin macaroon as a
	// default.
	mac, err := hn.ReadMacaroon(hn.Cfg.AdminMacPath, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	return hn.ConnectRPCWithMacaroon(mac)
}

// SetExtraArgs assigns the ExtraArgs field for the node's configuration. The
// changes will take effect on restart.
func (hn *HarnessNode) SetExtraArgs(extraArgs []string) {
	hn.Cfg.ExtraArgs = extraArgs
}

// cleanup cleans up all the temporary files created by the node's process.
func (hn *HarnessNode) cleanup() error {
	if hn.backupDbDir != "" {
		err := os.RemoveAll(hn.backupDbDir)
		if err != nil {
			return fmt.Errorf("unable to remove backup dir: %v", err)
		}
	}

	return os.RemoveAll(hn.Cfg.BaseDir)
}

// Stop attempts to stop the active lnd process.
func (hn *HarnessNode) stop() error {
	// Do nothing if the process is not running.
	if hn.processExit == nil {
		return nil
	}

	// If start() failed before creating a client, we will just wait for the
	// child process to die.
	if hn.LightningClient != nil {
		// Don't watch for error because sometimes the RPC connection gets
		// closed before a response is returned.
		req := lnrpc.StopRequest{}
		ctx := context.Background()
		_, err := hn.LightningClient.StopDaemon(ctx, &req)
		if err != nil {
			return err
		}
	}

	// Wait for lnd process and other goroutines to exit.
	select {
	case <-hn.processExit:
	case <-time.After(DefaultTimeout * 2):
		return fmt.Errorf("process did not exit")
	}

	close(hn.quit)
	hn.wg.Wait()

	hn.quit = nil
	hn.processExit = nil
	hn.LightningClient = nil
	hn.WalletUnlockerClient = nil
	hn.Watchtower = nil
	hn.WatchtowerClient = nil

	// Close any attempts at further grpc connections.
	if hn.conn != nil {
		err := hn.conn.Close()
		if err != nil {
			return fmt.Errorf("error attempting to stop grpc client: %v", err)
		}
	}

	return nil
}

// shutdown stops the active lnd process and cleans up any temporary directories
// created along the way.
func (hn *HarnessNode) shutdown() error {
	if err := hn.stop(); err != nil {
		return err
	}
	if err := hn.cleanup(); err != nil {
		return err
	}
	return nil
}

// kill kills the lnd process
func (hn *HarnessNode) kill() error {
	return hn.cmd.Process.Kill()
}

// closeChanWatchRequest is a request to the lightningNetworkWatcher to be
// notified once it's detected within the test Lightning Network, that a
// channel has either been added or closed.
type chanWatchRequest struct {
	chanPoint wire.OutPoint

	chanOpen bool

	eventChan chan struct{}
}

// getChanPointFundingTxid returns the given channel point's funding txid in
// raw bytes.
func getChanPointFundingTxid(chanPoint *lnrpc.ChannelPoint) ([]byte, error) {
	var txid []byte

	// A channel point's funding txid can be get/set as a byte slice or a
	// string. In the case it is a string, decode it.
	switch chanPoint.GetFundingTxid().(type) {
	case *lnrpc.ChannelPoint_FundingTxidBytes:
		txid = chanPoint.GetFundingTxidBytes()
	case *lnrpc.ChannelPoint_FundingTxidStr:
		s := chanPoint.GetFundingTxidStr()
		h, err := chainhash.NewHashFromStr(s)
		if err != nil {
			return nil, err
		}

		txid = h[:]
	}

	return txid, nil
}

func checkChanPointInGraph(ctx context.Context,
	node *HarnessNode, chanPoint wire.OutPoint) bool {

	ctxt, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	chanGraph, err := node.DescribeGraph(ctxt, &lnrpc.ChannelGraphRequest{})
	if err != nil {
		return false
	}

	targetChanPoint := chanPoint.String()
	for _, chanEdge := range chanGraph.Edges {
		candidateChanPoint := chanEdge.ChanPoint
		if targetChanPoint == candidateChanPoint {
			return true
		}
	}

	return false
}

// lightningNetworkWatcher is a goroutine which is able to dispatch
// notifications once it has been observed that a target channel has been
// closed or opened within the network. In order to dispatch these
// notifications, the GraphTopologySubscription client exposed as part of the
// gRPC interface is used.
func (hn *HarnessNode) lightningNetworkWatcher(subscribed chan error) {
	defer hn.wg.Done()

	graphUpdates := make(chan *lnrpc.GraphTopologyUpdate)
	hn.wg.Add(1)
	go func() {
		defer hn.wg.Done()

		req := &lnrpc.GraphTopologySubscription{}
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()
		topologyClient, err := hn.SubscribeChannelGraph(ctx, req)
		if err != nil {
			msg := fmt.Sprintf("%s(%d): unable to create topology "+
				"client: %v (%s)", hn.Name(), hn.NodeID, err,
				time.Now().String())
			subscribed <- fmt.Errorf(msg)
			return
		}
		close(subscribed)

		for {
			update, err := topologyClient.Recv()
			if err == io.EOF {
				return
			} else if err != nil {
				return
			}

			select {
			case graphUpdates <- update:
			case <-hn.quit:
				return
			}
		}
	}()

	for {
		select {

		// A new graph update has just been received, so we'll examine
		// the current set of registered clients to see if we can
		// dispatch any requests.
		case graphUpdate := <-graphUpdates:
			// For each new channel, we'll increment the number of
			// edges seen by one.
			for _, newChan := range graphUpdate.ChannelUpdates {
				txidHash, _ := getChanPointFundingTxid(newChan.ChanPoint)
				txid, _ := chainhash.NewHash(txidHash)
				op := wire.OutPoint{
					Hash:  *txid,
					Index: newChan.ChanPoint.OutputIndex,
				}
				hn.openChans[op]++

				// For this new channel, if the number of edges
				// seen is less than two, then the channel
				// hasn't been fully announced yet.
				if numEdges := hn.openChans[op]; numEdges < 2 {
					continue
				}

				// Otherwise, we'll notify all the registered
				// clients and remove the dispatched clients.
				for _, eventChan := range hn.openClients[op] {
					close(eventChan)
				}
				delete(hn.openClients, op)
			}

			// For each channel closed, we'll mark that we've
			// detected a channel closure while lnd was pruning the
			// channel graph.
			for _, closedChan := range graphUpdate.ClosedChans {
				txidHash, _ := getChanPointFundingTxid(closedChan.ChanPoint)
				txid, _ := chainhash.NewHash(txidHash)
				op := wire.OutPoint{
					Hash:  *txid,
					Index: closedChan.ChanPoint.OutputIndex,
				}
				hn.closedChans[op] = struct{}{}

				// As the channel has been closed, we'll notify
				// all register clients.
				for _, eventChan := range hn.closeClients[op] {
					close(eventChan)
				}
				delete(hn.closeClients, op)
			}

		// A new watch request, has just arrived. We'll either be able
		// to dispatch immediately, or need to add the client for
		// processing later.
		case watchRequest := <-hn.chanWatchRequests:
			targetChan := watchRequest.chanPoint

			// TODO(roasbeef): add update type also, checks for
			// multiple of 2
			if watchRequest.chanOpen {
				// If this is an open request, then it can be
				// dispatched if the number of edges seen for
				// the channel is at least two.
				if numEdges := hn.openChans[targetChan]; numEdges >= 2 {
					close(watchRequest.eventChan)
					continue
				}

				// Before we add the channel to our set of open
				// clients, we'll check to see if the channel
				// is already in the channel graph of the
				// target node. This lets us handle the case
				// where a node has already seen a channel
				// before a notification has been requested,
				// causing us to miss it.
				chanFound := checkChanPointInGraph(
					context.Background(), hn, targetChan,
				)
				if chanFound {
					close(watchRequest.eventChan)
					continue
				}

				// Otherwise, we'll add this to the list of
				// watch open clients for this out point.
				hn.openClients[targetChan] = append(
					hn.openClients[targetChan],
					watchRequest.eventChan,
				)
				continue
			}

			// If this is a close request, then it can be
			// immediately dispatched if we've already seen a
			// channel closure for this channel.
			if _, ok := hn.closedChans[targetChan]; ok {
				close(watchRequest.eventChan)
				continue
			}

			// Otherwise, we'll add this to the list of close watch
			// clients for this out point.
			hn.closeClients[targetChan] = append(
				hn.closeClients[targetChan],
				watchRequest.eventChan,
			)

		case <-hn.quit:
			return
		}
	}
}

// WaitForNetworkChannelOpen will block until a channel with the target
// outpoint is seen as being fully advertised within the network. A channel is
// considered "fully advertised" once both of its directional edges has been
// advertised within the test Lightning Network.
func (hn *HarnessNode) WaitForNetworkChannelOpen(ctx context.Context,
	op *lnrpc.ChannelPoint) error {

	eventChan := make(chan struct{})

	txidHash, err := getChanPointFundingTxid(op)
	if err != nil {
		return err
	}
	txid, err := chainhash.NewHash(txidHash)
	if err != nil {
		return err
	}

	hn.chanWatchRequests <- &chanWatchRequest{
		chanPoint: wire.OutPoint{
			Hash:  *txid,
			Index: op.OutputIndex,
		},
		eventChan: eventChan,
		chanOpen:  true,
	}

	select {
	case <-eventChan:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("channel not opened before timeout")
	}
}

// WaitForNetworkChannelClose will block until a channel with the target
// outpoint is seen as closed within the network. A channel is considered
// closed once a transaction spending the funding outpoint is seen within a
// confirmed block.
func (hn *HarnessNode) WaitForNetworkChannelClose(ctx context.Context,
	op *lnrpc.ChannelPoint) error {

	eventChan := make(chan struct{})

	txidHash, err := getChanPointFundingTxid(op)
	if err != nil {
		return err
	}
	txid, err := chainhash.NewHash(txidHash)
	if err != nil {
		return err
	}

	hn.chanWatchRequests <- &chanWatchRequest{
		chanPoint: wire.OutPoint{
			Hash:  *txid,
			Index: op.OutputIndex,
		},
		eventChan: eventChan,
		chanOpen:  false,
	}

	select {
	case <-eventChan:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("channel not closed before timeout")
	}
}

// WaitForBlockchainSync waits for the target node to be fully synchronized with
// the blockchain. If the passed context object has a set timeout, it will
// continually poll until the timeout has elapsed. In the case that the chain
// isn't synced before the timeout is up, this function will return an error.
func (hn *HarnessNode) WaitForBlockchainSync(ctx context.Context) error {
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()

	for {
		resp, err := hn.GetInfo(ctx, &lnrpc.GetInfoRequest{})
		if err != nil {
			return err
		}
		if resp.SyncedToChain {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout while waiting for " +
				"blockchain sync")
		case <-hn.quit:
			return nil
		case <-ticker.C:
		}
	}
}

// WaitForBalance waits until the node sees the expected confirmed/unconfirmed
// balance within their wallet.
func (hn *HarnessNode) WaitForBalance(expectedBalance btcutil.Amount, confirmed bool) error {
	ctx := context.Background()
	req := &lnrpc.WalletBalanceRequest{}

	var lastBalance btcutil.Amount
	doesBalanceMatch := func() bool {
		balance, err := hn.WalletBalance(ctx, req)
		if err != nil {
			return false
		}

		if confirmed {
			lastBalance = btcutil.Amount(balance.ConfirmedBalance)
			return btcutil.Amount(balance.ConfirmedBalance) == expectedBalance
		}

		lastBalance = btcutil.Amount(balance.UnconfirmedBalance)
		return btcutil.Amount(balance.UnconfirmedBalance) == expectedBalance
	}

	err := wait.Predicate(doesBalanceMatch, DefaultTimeout)
	if err != nil {
		return fmt.Errorf("balances not synced after deadline: "+
			"expected %v, only have %v", expectedBalance, lastBalance)
	}

	return nil
}
