// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	flags "github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tor"
)

const (
	defaultConfigFilename     = "lnd.conf"
	defaultDataDirname        = "data"
	defaultChainSubDirname    = "chain"
	defaultGraphSubDirname    = "graph"
	defaultTLSCertFilename    = "tls.cert"
	defaultTLSKeyFilename     = "tls.key"
	defaultAdminMacFilename   = "admin.macaroon"
	defaultReadMacFilename    = "readonly.macaroon"
	defaultInvoiceMacFilename = "invoice.macaroon"
	defaultLogLevel           = "info"
	defaultLogDirname         = "logs"
	defaultLogFilename        = "lnd.log"
	defaultRPCPort            = 10009
	defaultRESTPort           = 8080
	defaultPeerPort           = 9735
	defaultRPCHost            = "localhost"
	defaultMaxPendingChannels = 1
	defaultNoEncryptWallet    = false
	defaultTrickleDelay       = 30 * 1000
	defaultMaxLogFiles        = 3
	defaultMaxLogFileSize     = 10

	defaultTorSOCKSPort            = 9050
	defaultTorDNSHost              = "soa.nodes.lightning.directory"
	defaultTorDNSPort              = 53
	defaultTorControlPort          = 9051
	defaultTorV2PrivateKeyFilename = "v2_onion_private_key"

	defaultBroadcastDelta = 10

	// minTimeLockDelta is the minimum timelock we require for incoming
	// HTLCs on our channels.
	minTimeLockDelta = 4

	defaultAlias = ""
	defaultColor = "#3399FF"
)

var (
	defaultLndDir     = btcutil.AppDataDir("lnd", false)
	defaultConfigFile = filepath.Join(defaultLndDir, defaultConfigFilename)
	defaultDataDir    = filepath.Join(defaultLndDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(defaultLndDir, defaultLogDirname)

	defaultTLSCertPath = filepath.Join(defaultLndDir, defaultTLSCertFilename)
	defaultTLSKeyPath  = filepath.Join(defaultLndDir, defaultTLSKeyFilename)

	defaultAdminMacPath   = filepath.Join(defaultLndDir, defaultAdminMacFilename)
	defaultReadMacPath    = filepath.Join(defaultLndDir, defaultReadMacFilename)
	defaultInvoiceMacPath = filepath.Join(defaultLndDir, defaultInvoiceMacFilename)

	defaultBtcdDir         = btcutil.AppDataDir("btcd", false)
	defaultBtcdRPCCertFile = filepath.Join(defaultBtcdDir, "rpc.cert")

	defaultLtcdDir         = btcutil.AppDataDir("ltcd", false)
	defaultLtcdRPCCertFile = filepath.Join(defaultLtcdDir, "rpc.cert")

	defaultBitcoindDir  = btcutil.AppDataDir("bitcoin", false)
	defaultLitecoindDir = btcutil.AppDataDir("litecoin", false)

	defaultTorSOCKS            = net.JoinHostPort("localhost", strconv.Itoa(defaultTorSOCKSPort))
	defaultTorDNS              = net.JoinHostPort(defaultTorDNSHost, strconv.Itoa(defaultTorDNSPort))
	defaultTorControl          = net.JoinHostPort("localhost", strconv.Itoa(defaultTorControlPort))
	defaultTorV2PrivateKeyPath = filepath.Join(defaultLndDir, defaultTorV2PrivateKeyFilename)
)

type chainConfig struct {
	Active   bool   `long:"active" description:"If the chain should be active or not."`
	ChainDir string `long:"chaindir" description:"The directory to store the chain's data within."`

	Node string `long:"node" description:"The blockchain interface to use." choice:"btcd" choice:"bitcoind" choice:"neutrino" choice:"ltcd" choice:"litecoind"`

	MainNet  bool `long:"mainnet" description:"Use the main network"`
	TestNet3 bool `long:"testnet" description:"Use the test network"`
	SimNet   bool `long:"simnet" description:"Use the simulation test network"`
	RegTest  bool `long:"regtest" description:"Use the regression test network"`

	DefaultNumChanConfs int                 `long:"defaultchanconfs" description:"The default number of confirmations a channel must have before it's considered open. If this is not set, we will scale the value according to the channel size."`
	DefaultRemoteDelay  int                 `long:"defaultremotedelay" description:"The default number of blocks we will require our channel counterparty to wait before accessing its funds in case of unilateral close. If this is not set, we will scale the value according to the channel size."`
	MinHTLC             lnwire.MilliSatoshi `long:"minhtlc" description:"The smallest HTLC we are willing to forward on our channels, in millisatoshi"`
	BaseFee             lnwire.MilliSatoshi `long:"basefee" description:"The base fee in millisatoshi we will charge for forwarding payments on our channels"`
	FeeRate             lnwire.MilliSatoshi `long:"feerate" description:"The fee rate used when forwarding payments on our channels. The total fee charged is basefee + (amount * feerate / 1000000), where amount is the forwarded amount."`
	TimeLockDelta       uint32              `long:"timelockdelta" description:"The CLTV delta we will subtract from a forwarded HTLC's timelock value"`
}

type neutrinoConfig struct {
	AddPeers     []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	ConnectPeers []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	MaxPeers     int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	BanDuration  time.Duration `long:"banduration" description:"How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second"`
	BanThreshold uint32        `long:"banthreshold" description:"Maximum allowed ban score before disconnecting and banning misbehaving peers."`
}

type btcdConfig struct {
	Dir        string `long:"dir" description:"The base directory that contains the node's data, logs, configuration file, etc."`
	RPCHost    string `long:"rpchost" description:"The daemon's rpc listening address. If a port is omitted, then the default port for the selected chain parameters will be used."`
	RPCUser    string `long:"rpcuser" description:"Username for RPC connections"`
	RPCPass    string `long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	RPCCert    string `long:"rpccert" description:"File containing the daemon's certificate file"`
	RawRPCCert string `long:"rawrpccert" description:"The raw bytes of the daemon's PEM-encoded certificate chain which will be used to authenticate the RPC connection."`
}

type bitcoindConfig struct {
	Dir     string `long:"dir" description:"The base directory that contains the node's data, logs, configuration file, etc."`
	RPCHost string `long:"rpchost" description:"The daemon's rpc listening address. If a port is omitted, then the default port for the selected chain parameters will be used."`
	RPCUser string `long:"rpcuser" description:"Username for RPC connections"`
	RPCPass string `long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	ZMQPath string `long:"zmqpath" description:"The path to the ZMQ socket providing at least raw blocks. Raw transactions can be handled as well."`
}

type autoPilotConfig struct {
	Active         bool    `long:"active" description:"If the autopilot agent should be active or not."`
	MaxChannels    int     `long:"maxchannels" description:"The maximum number of channels that should be created"`
	Allocation     float64 `long:"allocation" description:"The percentage of total funds that should be committed to automatic channel establishment"`
	MinChannelSize int64   `long:"minchansize" description:"The smallest channel that the autopilot agent should create"`
	MaxChannelSize int64   `long:"maxchansize" description:"The largest channel that the autopilot agent should create"`
}

type torConfig struct {
	Active           bool   `long:"active" description:"Allow outbound and inbound connections to be routed through Tor"`
	SOCKS            string `long:"socks" description:"The host:port that Tor's exposed SOCKS5 proxy is listening on"`
	DNS              string `long:"dns" description:"The DNS server as host:port that Tor will use for SRV queries - NOTE must have TCP resolution enabled"`
	StreamIsolation  bool   `long:"streamisolation" description:"Enable Tor stream isolation by randomizing user credentials for each connection."`
	Control          string `long:"control" description:"The host:port that Tor is listening on for Tor control connections"`
	V2               bool   `long:"v2" description:"Automatically set up a v2 onion service to listen for inbound connections"`
	V2PrivateKeyPath string `long:"v2privatekeypath" description:"The path to the private key of the onion service being created"`
	V3               bool   `long:"v3" description:"Use a v3 onion service to listen for inbound connections"`
}

// config defines the configuration options for lnd.
//
// See loadConfig for further details regarding the configuration
// loading+parsing process.
type config struct {
	ShowVersion bool `short:"V" long:"version" description:"Display version information and exit"`

	LndDir         string `long:"lnddir" description:"The base directory that contains lnd's data, logs, configuration file, etc."`
	ConfigFile     string `long:"C" long:"configfile" description:"Path to configuration file"`
	DataDir        string `short:"b" long:"datadir" description:"The directory to store lnd's data within"`
	TLSCertPath    string `long:"tlscertpath" description:"Path to write the TLS certificate for lnd's RPC and REST services"`
	TLSKeyPath     string `long:"tlskeypath" description:"Path to write the TLS private key for lnd's RPC and REST services"`
	TLSExtraIP     string `long:"tlsextraip" description:"Adds an extra ip to the generated certificate"`
	TLSExtraDomain string `long:"tlsextradomain" description:"Adds an extra domain to the generated certificate"`
	NoMacaroons    bool   `long:"no-macaroons" description:"Disable macaroon authentication"`
	AdminMacPath   string `long:"adminmacaroonpath" description:"Path to write the admin macaroon for lnd's RPC and REST services if it doesn't exist"`
	ReadMacPath    string `long:"readonlymacaroonpath" description:"Path to write the read-only macaroon for lnd's RPC and REST services if it doesn't exist"`
	InvoiceMacPath string `long:"invoicemacaroonpath" description:"Path to the invoice-only macaroon for lnd's RPC and REST services if it doesn't exist"`
	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	// We'll parse these 'raw' string arguments into real net.Addrs in the
	// loadConfig function. We need to expose the 'raw' strings so the
	// command line library can access them.
	// Only the parsed net.Addrs should be used!
	RawRPCListeners  []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
	RawRESTListeners []string `long:"restlisten" description:"Add an interface/port/socket to listen for REST connections"`
	RawListeners     []string `long:"listen" description:"Add an interface/port to listen for peer connections"`
	RawExternalIPs   []string `long:"externalip" description:"Add an ip:port to the list of local addresses we claim to listen on to peers. If a port is not specified, the default (9735) will be used regardless of other parameters"`
	RPCListeners     []net.Addr
	RESTListeners    []net.Addr
	Listeners        []net.Addr
	ExternalIPs      []net.Addr
	DisableListen    bool `long:"nolisten" description:"Disable listening for incoming peer connections"`
	NAT              bool `long:"nat" description:"Toggle NAT traversal support (using either UPnP or NAT-PMP) to automatically advertise your external IP address to the network -- NOTE this does not support devices behind multiple NATs"`

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	CPUProfile string `long:"cpuprofile" description:"Write CPU profile to the specified file"`

	Profile string `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65535"`

	DebugHTLC          bool `long:"debughtlc" description:"Activate the debug htlc mode. With the debug HTLC mode, all payments sent use a pre-determined R-Hash. Additionally, all HTLCs sent to a node with the debug HTLC R-Hash are immediately settled in the next available state transition."`
	UnsafeDisconnect   bool `long:"unsafe-disconnect" description:"Allows the rpcserver to intentionally disconnect from peers with open channels. USED FOR TESTING ONLY."`
	UnsafeReplay       bool `long:"unsafe-replay" description:"Causes a link to replay the adds on its commitment txn after starting up, this enables testing of the sphinx replay logic."`
	MaxPendingChannels int  `long:"maxpendingchannels" description:"The maximum number of incoming pending channels permitted per peer."`

	Bitcoin      *chainConfig    `group:"Bitcoin" namespace:"bitcoin"`
	BtcdMode     *btcdConfig     `group:"btcd" namespace:"btcd"`
	BitcoindMode *bitcoindConfig `group:"bitcoind" namespace:"bitcoind"`
	NeutrinoMode *neutrinoConfig `group:"neutrino" namespace:"neutrino"`

	Litecoin      *chainConfig    `group:"Litecoin" namespace:"litecoin"`
	LtcdMode      *btcdConfig     `group:"ltcd" namespace:"ltcd"`
	LitecoindMode *bitcoindConfig `group:"litecoind" namespace:"litecoind"`

	Autopilot *autoPilotConfig `group:"Autopilot" namespace:"autopilot"`

	Tor *torConfig `group:"Tor" namespace:"tor"`

	Hodl *hodl.Config `group:"hodl" namespace:"hodl"`

	NoNetBootstrap bool `long:"nobootstrap" description:"If true, then automatic network bootstrapping will not be attempted."`

	NoEncryptWallet bool `long:"noencryptwallet" description:"If set, wallet will be encrypted using the default passphrase."`

	TrickleDelay int `long:"trickledelay" description:"Time in milliseconds between each release of announcements to the network"`

	Alias       string `long:"alias" description:"The node alias. Used as a moniker by peers and intelligence services"`
	Color       string `long:"color" description:"The color of the node in hex format (i.e. '#3399FF'). Used to customize node appearance in intelligence services"`
	MinChanSize int64  `long:"minchansize" description:"The smallest channel size (in satoshis) that we should accept. Incoming channels smaller than this will be rejected"`

	NoChanUpdates bool `long:"nochanupdates" description:"If specified, lnd will not request real-time channel updates from connected peers. This option should be used by routing nodes to save bandwidth."`

	net tor.Net
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
func loadConfig() (*config, error) {
	defaultCfg := config{
		LndDir:         defaultLndDir,
		ConfigFile:     defaultConfigFile,
		DataDir:        defaultDataDir,
		DebugLevel:     defaultLogLevel,
		TLSCertPath:    defaultTLSCertPath,
		TLSKeyPath:     defaultTLSKeyPath,
		AdminMacPath:   defaultAdminMacPath,
		InvoiceMacPath: defaultInvoiceMacPath,
		ReadMacPath:    defaultReadMacPath,
		LogDir:         defaultLogDir,
		MaxLogFiles:    defaultMaxLogFiles,
		MaxLogFileSize: defaultMaxLogFileSize,
		Bitcoin: &chainConfig{
			MinHTLC:       defaultBitcoinMinHTLCMSat,
			BaseFee:       defaultBitcoinBaseFeeMSat,
			FeeRate:       defaultBitcoinFeeRate,
			TimeLockDelta: defaultBitcoinTimeLockDelta,
			Node:          "btcd",
		},
		BtcdMode: &btcdConfig{
			Dir:     defaultBtcdDir,
			RPCHost: defaultRPCHost,
			RPCCert: defaultBtcdRPCCertFile,
		},
		BitcoindMode: &bitcoindConfig{
			Dir:     defaultBitcoindDir,
			RPCHost: defaultRPCHost,
		},
		Litecoin: &chainConfig{
			MinHTLC:       defaultLitecoinMinHTLCMSat,
			BaseFee:       defaultLitecoinBaseFeeMSat,
			FeeRate:       defaultLitecoinFeeRate,
			TimeLockDelta: defaultLitecoinTimeLockDelta,
			Node:          "ltcd",
		},
		LtcdMode: &btcdConfig{
			Dir:     defaultLtcdDir,
			RPCHost: defaultRPCHost,
			RPCCert: defaultLtcdRPCCertFile,
		},
		LitecoindMode: &bitcoindConfig{
			Dir:     defaultLitecoindDir,
			RPCHost: defaultRPCHost,
		},
		MaxPendingChannels: defaultMaxPendingChannels,
		NoEncryptWallet:    defaultNoEncryptWallet,
		Autopilot: &autoPilotConfig{
			MaxChannels:    5,
			Allocation:     0.6,
			MinChannelSize: int64(minChanFundingSize),
			MaxChannelSize: int64(maxFundingAmount),
		},
		TrickleDelay: defaultTrickleDelay,
		Alias:        defaultAlias,
		Color:        defaultColor,
		MinChanSize:  int64(minChanFundingSize),
		Tor: &torConfig{
			SOCKS:            defaultTorSOCKS,
			DNS:              defaultTorDNS,
			Control:          defaultTorControl,
			V2PrivateKeyPath: defaultTorV2PrivateKeyPath,
		},
		net: &tor.ClearNet{},
	}

	// Pre-parse the command line options to pick up an alternative config
	// file.
	preCfg := defaultCfg
	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", version())
		os.Exit(0)
	}

	// If the provided lnd directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	lndDir := cleanAndExpandPath(preCfg.LndDir)
	configFilePath := cleanAndExpandPath(preCfg.ConfigFile)
	if lndDir != defaultLndDir {
		// If the config file path has not been modified by the user,
		// then we'll use the default config file path. However, if the
		// user has modified their lnddir, then we should assume they
		// intend to use the config file within it.
		if configFilePath == defaultConfigFile {
			preCfg.ConfigFile = filepath.Join(lndDir, defaultConfigFilename)
		}
		preCfg.DataDir = filepath.Join(lndDir, defaultDataDirname)
		preCfg.TLSCertPath = filepath.Join(lndDir, defaultTLSCertFilename)
		preCfg.TLSKeyPath = filepath.Join(lndDir, defaultTLSKeyFilename)
		preCfg.AdminMacPath = filepath.Join(lndDir, defaultAdminMacFilename)
		preCfg.InvoiceMacPath = filepath.Join(lndDir, defaultInvoiceMacFilename)
		preCfg.ReadMacPath = filepath.Join(lndDir, defaultReadMacFilename)
		preCfg.LogDir = filepath.Join(lndDir, defaultLogDirname)
		preCfg.Tor.V2PrivateKeyPath = filepath.Join(lndDir, defaultTorV2PrivateKeyFilename)
	}

	// Create the lnd directory if it doesn't already exist.
	funcName := "loadConfig"
	if err := os.MkdirAll(lndDir, 0700); err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: Failed to create lnd directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	if err := flags.IniParse(cfg.ConfigFile, &cfg); err != nil {
		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	if _, err := flags.Parse(&cfg); err != nil {
		return nil, err
	}

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	cfg.TLSCertPath = cleanAndExpandPath(cfg.TLSCertPath)
	cfg.TLSKeyPath = cleanAndExpandPath(cfg.TLSKeyPath)
	cfg.AdminMacPath = cleanAndExpandPath(cfg.AdminMacPath)
	cfg.ReadMacPath = cleanAndExpandPath(cfg.ReadMacPath)
	cfg.InvoiceMacPath = cleanAndExpandPath(cfg.InvoiceMacPath)
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.BtcdMode.Dir = cleanAndExpandPath(cfg.BtcdMode.Dir)
	cfg.LtcdMode.Dir = cleanAndExpandPath(cfg.LtcdMode.Dir)
	cfg.BitcoindMode.Dir = cleanAndExpandPath(cfg.BitcoindMode.Dir)
	cfg.LitecoindMode.Dir = cleanAndExpandPath(cfg.LitecoindMode.Dir)
	cfg.Tor.V2PrivateKeyPath = cleanAndExpandPath(cfg.Tor.V2PrivateKeyPath)

	// Ensure that the user didn't attempt to specify negative values for
	// any of the autopilot params.
	if cfg.Autopilot.MaxChannels < 0 {
		str := "%s: autopilot.maxchannels must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	if cfg.Autopilot.Allocation < 0 {
		str := "%s: autopilot.allocation must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	if cfg.Autopilot.MinChannelSize < 0 {
		str := "%s: autopilot.minchansize must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	if cfg.Autopilot.MaxChannelSize < 0 {
		str := "%s: autopilot.maxchansize must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// Ensure that the specified values for the min and max channel size
	// don't are within the bounds of the normal chan size constraints.
	if cfg.Autopilot.MinChannelSize < int64(minChanFundingSize) {
		cfg.Autopilot.MinChannelSize = int64(minChanFundingSize)
	}
	if cfg.Autopilot.MaxChannelSize > int64(maxFundingAmount) {
		cfg.Autopilot.MaxChannelSize = int64(maxFundingAmount)
	}

	// Validate the Tor config parameters.
	socks, err := lncfg.ParseAddressString(
		cfg.Tor.SOCKS, strconv.Itoa(defaultTorSOCKSPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, err
	}
	cfg.Tor.SOCKS = socks.String()

	// We'll only attempt to normalize and resolve the DNS host if it hasn't
	// changed, as it doesn't need to be done for the default.
	if cfg.Tor.DNS != defaultTorDNS {
		dns, err := lncfg.ParseAddressString(
			cfg.Tor.DNS, strconv.Itoa(defaultTorDNSPort),
			cfg.net.ResolveTCPAddr,
		)
		if err != nil {
			return nil, err
		}
		cfg.Tor.DNS = dns.String()
	}

	control, err := lncfg.ParseAddressString(
		cfg.Tor.Control, strconv.Itoa(defaultTorControlPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, err
	}
	cfg.Tor.Control = control.String()

	switch {
	case cfg.Tor.V2 && cfg.Tor.V3:
		return nil, errors.New("either tor.v2 or tor.v3 can be set, " +
			"but not both")
	case cfg.DisableListen && (cfg.Tor.V2 || cfg.Tor.V3):
		return nil, errors.New("listening must be enabled when " +
			"enabling inbound connections over Tor")
	case cfg.Tor.Active && (!cfg.Tor.V2 && !cfg.Tor.V3):
		// If an onion service version wasn't selected, we'll assume the
		// user is only interested in outbound connections over Tor.
		// Therefore, we'll disable listening in order to avoid
		// inadvertent leaks.
		cfg.DisableListen = true
	}

	// Set up the network-related functions that will be used throughout
	// the daemon. We use the standard Go "net" package functions by
	// default. If we should be proxying all traffic through Tor, then
	// we'll use the Tor proxy specific functions in order to avoid leaking
	// our real information.
	if cfg.Tor.Active {
		cfg.net = &tor.ProxyNet{
			SOCKS:           cfg.Tor.SOCKS,
			DNS:             cfg.Tor.DNS,
			StreamIsolation: cfg.Tor.StreamIsolation,
		}
	}

	if cfg.DisableListen && cfg.NAT {
		return nil, errors.New("NAT traversal cannot be used when " +
			"listening is disabled")
	}

	// Determine the active chain configuration and its parameters.
	switch {
	// At this moment, multiple active chains are not supported.
	case cfg.Litecoin.Active && cfg.Bitcoin.Active:
		str := "%s: Currently both Bitcoin and Litecoin cannot be " +
			"active together"
		return nil, fmt.Errorf(str, funcName)

	// Either Bitcoin must be active, or Litecoin must be active.
	// Otherwise, we don't know which chain we're on.
	case !cfg.Bitcoin.Active && !cfg.Litecoin.Active:
		return nil, fmt.Errorf("%s: either bitcoin.active or "+
			"litecoin.active must be set to 1 (true)", funcName)

	case cfg.Litecoin.Active:
		if cfg.Litecoin.SimNet {
			str := "%s: simnet mode for litecoin not currently supported"
			return nil, fmt.Errorf(str, funcName)
		}
		if cfg.Litecoin.RegTest {
			str := "%s: regnet mode for litecoin not currently supported"
			return nil, fmt.Errorf(str, funcName)
		}

		if cfg.Litecoin.TimeLockDelta < minTimeLockDelta {
			return nil, fmt.Errorf("timelockdelta must be at least %v",
				minTimeLockDelta)
		}

		// Multiple networks can't be selected simultaneously.  Count
		// number of network flags passed; assign active network params
		// while we're at it.
		numNets := 0
		var ltcParams litecoinNetParams
		if cfg.Litecoin.MainNet {
			numNets++
			ltcParams = litecoinMainNetParams
		}
		if cfg.Litecoin.TestNet3 {
			numNets++
			ltcParams = litecoinTestNetParams
		}
		if numNets > 1 {
			str := "%s: The mainnet, testnet, and simnet params " +
				"can't be used together -- choose one of the " +
				"three"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		// The target network must be provided, otherwise, we won't
		// know how to initialize the daemon.
		if numNets == 0 {
			str := "%s: either --litecoin.mainnet, or " +
				"litecoin.testnet must be specified"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		if cfg.Litecoin.MainNet && cfg.DebugHTLC {
			str := "%s: debug-htlc mode cannot be used " +
				"on litecoin mainnet"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		// The litecoin chain is the current active chain. However
		// throughout the codebase we required chaincfg.Params. So as a
		// temporary hack, we'll mutate the default net params for
		// bitcoin with the litecoin specific information.
		applyLitecoinParams(&activeNetParams, &ltcParams)

		switch cfg.Litecoin.Node {
		case "ltcd":
			err := parseRPCParams(cfg.Litecoin, cfg.LtcdMode,
				litecoinChain, funcName)
			if err != nil {
				err := fmt.Errorf("unable to load RPC "+
					"credentials for ltcd: %v", err)
				return nil, err
			}
		case "litecoind":
			if cfg.Litecoin.SimNet {
				return nil, fmt.Errorf("%s: litecoind does not "+
					"support simnet", funcName)
			}
			err := parseRPCParams(cfg.Litecoin, cfg.LitecoindMode,
				litecoinChain, funcName)
			if err != nil {
				err := fmt.Errorf("unable to load RPC "+
					"credentials for litecoind: %v", err)
				return nil, err
			}
		default:
			str := "%s: only ltcd and litecoind mode supported for " +
				"litecoin at this time"
			return nil, fmt.Errorf(str, funcName)
		}

		cfg.Litecoin.ChainDir = filepath.Join(cfg.DataDir,
			defaultChainSubDirname,
			litecoinChain.String())

		// Finally we'll register the litecoin chain as our current
		// primary chain.
		registeredChains.RegisterPrimaryChain(litecoinChain)
		maxFundingAmount = maxLtcFundingAmount
		maxPaymentMSat = maxLtcPaymentMSat

	case cfg.Bitcoin.Active:
		// Multiple networks can't be selected simultaneously.  Count
		// number of network flags passed; assign active network params
		// while we're at it.
		numNets := 0
		if cfg.Bitcoin.MainNet {
			numNets++
			activeNetParams = bitcoinMainNetParams
		}
		if cfg.Bitcoin.TestNet3 {
			numNets++
			activeNetParams = bitcoinTestNetParams
		}
		if cfg.Bitcoin.RegTest {
			numNets++
			activeNetParams = regTestNetParams
		}
		if cfg.Bitcoin.SimNet {
			numNets++
			activeNetParams = bitcoinSimNetParams
		}
		if numNets > 1 {
			str := "%s: The mainnet, testnet, regtest, and " +
				"simnet params can't be used together -- " +
				"choose one of the four"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		// The target network must be provided, otherwise, we won't
		// know how to initialize the daemon.
		if numNets == 0 {
			str := "%s: either --bitcoin.mainnet, or " +
				"bitcoin.testnet, bitcoin.simnet, or bitcoin.regtest " +
				"must be specified"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		if cfg.Bitcoin.MainNet && cfg.DebugHTLC {
			str := "%s: debug-htlc mode cannot be used " +
				"on bitcoin mainnet"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		if cfg.Bitcoin.Node == "neutrino" && cfg.Bitcoin.MainNet {
			str := "%s: neutrino isn't yet supported for " +
				"bitcoin's mainnet"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}

		if cfg.Bitcoin.TimeLockDelta < minTimeLockDelta {
			return nil, fmt.Errorf("timelockdelta must be at least %v",
				minTimeLockDelta)
		}

		switch cfg.Bitcoin.Node {
		case "btcd":
			err := parseRPCParams(
				cfg.Bitcoin, cfg.BtcdMode, bitcoinChain, funcName,
			)
			if err != nil {
				err := fmt.Errorf("unable to load RPC "+
					"credentials for btcd: %v", err)
				return nil, err
			}
		case "bitcoind":
			if cfg.Bitcoin.SimNet {
				return nil, fmt.Errorf("%s: bitcoind does not "+
					"support simnet", funcName)
			}

			err := parseRPCParams(
				cfg.Bitcoin, cfg.BitcoindMode, bitcoinChain, funcName,
			)
			if err != nil {
				err := fmt.Errorf("unable to load RPC "+
					"credentials for bitcoind: %v", err)
				return nil, err
			}
		case "neutrino":
			// No need to get RPC parameters.
		default:
			str := "%s: only btcd, bitcoind, and neutrino mode " +
				"supported for bitcoin at this time"
			return nil, fmt.Errorf(str, funcName)
		}

		cfg.Bitcoin.ChainDir = filepath.Join(cfg.DataDir,
			defaultChainSubDirname,
			bitcoinChain.String())

		// Finally we'll register the bitcoin chain as our current
		// primary chain.
		registeredChains.RegisterPrimaryChain(bitcoinChain)
	}

	// Ensure that the user didn't attempt to specify negative values for
	// any of the autopilot params.
	if cfg.Autopilot.MaxChannels < 0 {
		str := "%s: autopilot.maxchannels must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	if cfg.Autopilot.Allocation < 0 {
		str := "%s: autopilot.allocation must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	if cfg.Autopilot.MinChannelSize < 0 {
		str := "%s: autopilot.minchansize must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	if cfg.Autopilot.MaxChannelSize < 0 {
		str := "%s: autopilot.maxchansize must be non-negative"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// Ensure that the specified values for the min and max channel size
	// don't are within the bounds of the normal chan size constraints.
	if cfg.Autopilot.MinChannelSize < int64(minChanFundingSize) {
		cfg.Autopilot.MinChannelSize = int64(minChanFundingSize)
	}
	if cfg.Autopilot.MaxChannelSize > int64(maxFundingAmount) {
		cfg.Autopilot.MaxChannelSize = int64(maxFundingAmount)
	}

	// Validate profile port number.
	if cfg.Profile != "" {
		profilePort, err := strconv.Atoi(cfg.Profile)
		if err != nil || profilePort < 1024 || profilePort > 65535 {
			str := "%s: The profile port must be between 1024 and 65535"
			err := fmt.Errorf(str, funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, err
		}
	}

	// At this point, we'll save the base data directory in order to ensure
	// we don't store the macaroon database within any of the chain
	// namespaced directories.
	macaroonDatabaseDir = cfg.DataDir

	// If a custom macaroon directory wasn't specified and the data
	// directory has changed from the default path, then we'll also update
	// the path for the macaroons to be generated.
	if cfg.DataDir != defaultDataDir && cfg.AdminMacPath == defaultAdminMacPath {
		cfg.AdminMacPath = filepath.Join(
			cfg.DataDir, defaultAdminMacFilename,
		)
	}
	if cfg.DataDir != defaultDataDir && cfg.ReadMacPath == defaultReadMacPath {
		cfg.ReadMacPath = filepath.Join(
			cfg.DataDir, defaultReadMacFilename,
		)
	}
	if cfg.DataDir != defaultDataDir && cfg.InvoiceMacPath == defaultInvoiceMacPath {
		cfg.InvoiceMacPath = filepath.Join(
			cfg.DataDir, defaultInvoiceMacFilename,
		)
	}

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = filepath.Join(cfg.LogDir,
		registeredChains.PrimaryChain().String(),
		normalizeNetwork(activeNetParams.Name))

	// Initialize logging at the default logging level.
	initLogRotator(
		filepath.Join(cfg.LogDir, defaultLogFilename),
		cfg.MaxLogFileSize, cfg.MaxLogFiles,
	)

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, err
	}

	// At least one RPCListener is required. So listen on localhost per
	// default.
	if len(cfg.RawRPCListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRPCPort)
		cfg.RawRPCListeners = append(cfg.RawRPCListeners, addr)
	}

	// Listen on localhost if no REST listeners were specified.
	if len(cfg.RawRESTListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRESTPort)
		cfg.RawRESTListeners = append(cfg.RawRESTListeners, addr)
	}

	// Listen on the default interface/port if no listeners were specified.
	// An empty address string means default interface/address, which on
	// most unix systems is the same as 0.0.0.0.
	if len(cfg.RawListeners) == 0 {
		addr := fmt.Sprintf(":%d", defaultPeerPort)
		cfg.RawListeners = append(cfg.RawListeners, addr)
	}

	// For each of the RPC listeners (REST+gRPC), we'll ensure that users
	// have specified a safe combo for authentication. If not, we'll bail
	// out with an error.
	err = lncfg.EnforceSafeAuthentication(
		cfg.RPCListeners, !cfg.NoMacaroons,
	)
	if err != nil {
		return nil, err
	}
	err = lncfg.EnforceSafeAuthentication(
		cfg.RESTListeners, !cfg.NoMacaroons,
	)
	if err != nil {
		return nil, err
	}

	// Add default port to all RPC listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListeners, err = lncfg.NormalizeAddresses(
		cfg.RawRPCListeners, strconv.Itoa(defaultRPCPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, err
	}

	// Add default port to all REST listener addresses if needed and remove
	// duplicate addresses.
	cfg.RESTListeners, err = lncfg.NormalizeAddresses(
		cfg.RawRESTListeners, strconv.Itoa(defaultRESTPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, err
	}

	// Remove the listening addresses specified if listening is disabled.
	if cfg.DisableListen {
		ltndLog.Infof("Listening on the p2p interface is disabled!")
		cfg.Listeners = nil
		cfg.ExternalIPs = nil
	} else {

		// Add default port to all listener addresses if needed and remove
		// duplicate addresses.
		cfg.Listeners, err = lncfg.NormalizeAddresses(
			cfg.RawListeners, strconv.Itoa(defaultPeerPort),
			cfg.net.ResolveTCPAddr,
		)
		if err != nil {
			return nil, err
		}

		// Add default port to all external IP addresses if needed and remove
		// duplicate addresses.
		cfg.ExternalIPs, err = lncfg.NormalizeAddresses(
			cfg.RawExternalIPs, strconv.Itoa(defaultPeerPort),
			cfg.net.ResolveTCPAddr,
		)
		if err != nil {
			return nil, err
		}

		// For the p2p port it makes no sense to listen to an Unix socket.
		// Also, we would need to refactor the brontide listener to support
		// that.
		for _, p2pListener := range cfg.Listeners {
			if lncfg.IsUnix(p2pListener) {
				err := fmt.Errorf("unix socket addresses cannot be "+
					"used for the p2p connection listener: %s",
					p2pListener)
				return nil, err
			}
		}
	}

	// Finally, ensure that we are only listening on localhost if Tor
	// inbound support is enabled.
	if cfg.Tor.V2 || cfg.Tor.V3 {
		for _, addr := range cfg.Listeners {
			if lncfg.IsLoopback(addr.String()) {
				continue
			}

			return nil, errors.New("lnd must *only* be listening " +
				"on localhost when running with Tor inbound " +
				"support enabled")
		}
	}

	// Warn about missing config file only after all other configuration is
	// done.  This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		ltndLog.Warnf("%v", configFileError)
	}

	return &cfg, nil
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string

		user, err := user.Current()
		if err == nil {
			homeDir = user.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly. An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any delimiters, treat it as
	// the log level for all subsystems.
	if !strings.Contains(debugLevel, ",") && !strings.Contains(debugLevel, "=") {
		// Validate debug log level.
		if !validLogLevel(debugLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, debugLevel)
		}

		// Change the logging level for all subsystems.
		setLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while detecting
	// issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsystems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

// validLogLevel returns whether or not logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	switch logLevel {
	case "trace":
		fallthrough
	case "debug":
		fallthrough
	case "info":
		fallthrough
	case "warn":
		fallthrough
	case "error":
		fallthrough
	case "critical":
		fallthrough
	case "off":
		return true
	}
	return false
}

// supportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func supportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice.
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsystems for stable display.
	sort.Strings(subsystems)
	return subsystems
}

// noiseDial is a factory function which creates a connmgr compliant dialing
// function by returning a closure which includes the server's identity key.
func noiseDial(idPriv *btcec.PrivateKey) func(net.Addr) (net.Conn, error) {
	return func(a net.Addr) (net.Conn, error) {
		lnAddr := a.(*lnwire.NetAddress)
		return brontide.Dial(idPriv, lnAddr, cfg.net.Dial)
	}
}

func parseRPCParams(cConfig *chainConfig, nodeConfig interface{}, net chainCode,
	funcName string) error {

	// First, we'll check our node config to make sure the RPC parameters
	// were set correctly. We'll also determine the path to the conf file
	// depending on the backend node.
	var daemonName, confDir, confFile string
	switch conf := nodeConfig.(type) {
	case *btcdConfig:
		// If both RPCUser and RPCPass are set, we assume those
		// credentials are good to use.
		if conf.RPCUser != "" && conf.RPCPass != "" {
			return nil
		}

		// Get the daemon name for displaying proper errors.
		switch net {
		case bitcoinChain:
			daemonName = "btcd"
		case litecoinChain:
			daemonName = "ltcd"
		}

		switch net {
		case bitcoinChain:
			confDir = conf.Dir
			confFile = "btcd"
		case litecoinChain:
			confDir = conf.Dir
			confFile = "ltcd"
		}
	case *bitcoindConfig:
		// If all of RPCUser, RPCPass, and ZMQPath are set, we assume
		// those parameters are good to use.
		if conf.RPCUser != "" && conf.RPCPass != "" && conf.ZMQPath != "" {
			return nil
		}

		// Get the daemon name for displaying proper errors.
		switch net {
		case bitcoinChain:
			daemonName = "bitcoind"
		case litecoinChain:
			daemonName = "litecoind"
		}

		switch net {
		case bitcoinChain:
			confDir = conf.Dir
			confFile = "bitcoin"
		case litecoinChain:
			confDir = conf.Dir
			confFile = "litecoin"
		}
	}

	// If we're in simnet mode, then the running btcd instance won't read
	// the RPC credentials from the configuration. So if lnd wasn't
	// specified the parameters, then we won't be able to start.
	if cConfig.SimNet {
		str := "%v: rpcuser and rpcpass must be set to your btcd " +
			"node's RPC parameters for simnet mode"
		return fmt.Errorf(str, funcName)
	}

	fmt.Println("Attempting automatic RPC configuration to " + daemonName)

	confFile = filepath.Join(confDir, fmt.Sprintf("%v.conf", confFile))
	switch cConfig.Node {
	case "btcd", "ltcd":
		nConf := nodeConfig.(*btcdConfig)
		rpcUser, rpcPass, err := extractBtcdRPCParams(confFile)
		if err != nil {
			return fmt.Errorf("unable to extract RPC credentials:"+
				" %v, cannot start w/o RPC connection",
				err)
		}
		if nConf.RPCUser == "" {
			nConf.RPCUser = rpcUser
		}
		if nConf.RPCPass == "" {
			nConf.RPCPass = rpcPass
		}
	case "bitcoind", "litecoind":
		nConf := nodeConfig.(*bitcoindConfig)
		rpcUser, rpcPass, zmqPath, err := extractBitcoindRPCParams(confFile)
		if err != nil {
			return fmt.Errorf("unable to extract RPC credentials:"+
				" %v, cannot start w/o RPC connection",
				err)
		}
		if nConf.RPCUser == "" {
			nConf.RPCUser = rpcUser
		}
		if nConf.RPCPass == "" {
			nConf.RPCPass = rpcPass
		}
		if nConf.ZMQPath == "" {
			nConf.ZMQPath = zmqPath
		}
	}

	fmt.Printf("Automatically obtained %v's RPC credentials\n", daemonName)
	return nil
}

// extractBtcdRPCParams attempts to extract the RPC credentials for an existing
// btcd instance. The passed path is expected to be the location of btcd's
// application data directory on the target system.
func extractBtcdRPCParams(btcdConfigPath string) (string, string, error) {
	// First, we'll open up the btcd configuration file found at the target
	// destination.
	btcdConfigFile, err := os.Open(btcdConfigPath)
	if err != nil {
		return "", "", err
	}
	defer btcdConfigFile.Close()

	// With the file open extract the contents of the configuration file so
	// we can attempt to locate the RPC credentials.
	configContents, err := ioutil.ReadAll(btcdConfigFile)
	if err != nil {
		return "", "", err
	}

	// Attempt to locate the RPC user using a regular expression. If we
	// don't have a match for our regular expression then we'll exit with
	// an error.
	rpcUserRegexp, err := regexp.Compile(`(?m)^\s*rpcuser\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", err
	}
	userSubmatches := rpcUserRegexp.FindSubmatch(configContents)
	if userSubmatches == nil {
		return "", "", fmt.Errorf("unable to find rpcuser in config")
	}

	// Similarly, we'll use another regular expression to find the set
	// rpcpass (if any). If we can't find the pass, then we'll exit with an
	// error.
	rpcPassRegexp, err := regexp.Compile(`(?m)^\s*rpcpass\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", err
	}
	passSubmatches := rpcPassRegexp.FindSubmatch(configContents)
	if passSubmatches == nil {
		return "", "", fmt.Errorf("unable to find rpcuser in config")
	}

	return string(userSubmatches[1]), string(passSubmatches[1]), nil
}

// extractBitcoindParams attempts to extract the RPC credentials for an
// existing bitcoind node instance. The passed path is expected to be the
// location of bitcoind's bitcoin.conf on the target system. The routine looks
// for a cookie first, optionally following the datadir configuration option in
// the bitcoin.conf. If it doesn't find one, it looks for rpcuser/rpcpassword.
func extractBitcoindRPCParams(bitcoindConfigPath string) (string, string, string, error) {

	// First, we'll open up the bitcoind configuration file found at the
	// target destination.
	bitcoindConfigFile, err := os.Open(bitcoindConfigPath)
	if err != nil {
		return "", "", "", err
	}
	defer bitcoindConfigFile.Close()

	// With the file open extract the contents of the configuration file so
	// we can attempt to locate the RPC credentials.
	configContents, err := ioutil.ReadAll(bitcoindConfigFile)
	if err != nil {
		return "", "", "", err
	}

	// First, we look for the ZMQ path for raw blocks. If raw transactions
	// are sent over this interface, we can also get unconfirmed txs.
	zmqPathRE, err := regexp.Compile(`(?m)^\s*zmqpubrawblock\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", err
	}
	zmqPathSubmatches := zmqPathRE.FindSubmatch(configContents)
	if len(zmqPathSubmatches) < 2 {
		return "", "", "", fmt.Errorf("unable to find zmqpubrawblock in config")
	}

	// Next, we'll try to find an auth cookie. We need to detect the chain
	// by seeing if one is specified in the configuration file.
	dataDir := path.Dir(bitcoindConfigPath)
	dataDirRE, err := regexp.Compile(`(?m)^\s*datadir\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", err
	}
	dataDirSubmatches := dataDirRE.FindSubmatch(configContents)
	if dataDirSubmatches != nil {
		dataDir = string(dataDirSubmatches[1])
	}

	chainDir := "/"
	switch activeNetParams.Params.Name {
	case "testnet3":
		chainDir = "/testnet3/"
	case "testnet4":
		chainDir = "/testnet4/"
	case "regtest":
		chainDir = "/regtest/"
	}

	cookie, err := ioutil.ReadFile(dataDir + chainDir + ".cookie")
	if err == nil {
		splitCookie := strings.Split(string(cookie), ":")
		if len(splitCookie) == 2 {
			return splitCookie[0], splitCookie[1],
				string(zmqPathSubmatches[1]), nil
		}
	}

	// We didn't find a cookie, so we attempt to locate the RPC user using
	// a regular expression. If we  don't have a match for our regular
	// expression then we'll exit with an error.
	rpcUserRegexp, err := regexp.Compile(`(?m)^\s*rpcuser\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", err
	}
	userSubmatches := rpcUserRegexp.FindSubmatch(configContents)
	if userSubmatches == nil {
		return "", "", "", fmt.Errorf("unable to find rpcuser in config")
	}

	// Similarly, we'll use another regular expression to find the set
	// rpcpass (if any). If we can't find the pass, then we'll exit with an
	// error.
	rpcPassRegexp, err := regexp.Compile(`(?m)^\s*rpcpassword\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", err
	}
	passSubmatches := rpcPassRegexp.FindSubmatch(configContents)
	if passSubmatches == nil {
		return "", "", "", fmt.Errorf("unable to find rpcpassword in config")
	}

	return string(userSubmatches[1]), string(passSubmatches[1]),
		string(zmqPathSubmatches[1]), nil
}

// normalizeNetwork returns the common name of a network type used to create
// file paths. This allows differently versioned networks to use the same path.
func normalizeNetwork(network string) string {
	if strings.HasPrefix(network, "testnet") {
		return "testnet"
	}

	return network
}
