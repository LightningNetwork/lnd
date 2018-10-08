package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainntnfs/bitcoindnotify"
	"github.com/lightningnetwork/lnd/chainntnfs/btcdnotify"
	"github.com/lightningnetwork/lnd/chainntnfs/neutrinonotify"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/chainview"
)

const (
	defaultBitcoinMinHTLCMSat   = lnwire.MilliSatoshi(1000)
	defaultBitcoinBaseFeeMSat   = lnwire.MilliSatoshi(1000)
	defaultBitcoinFeeRate       = lnwire.MilliSatoshi(1)
	defaultBitcoinTimeLockDelta = 144

	defaultLitecoinMinHTLCMSat   = lnwire.MilliSatoshi(1000)
	defaultLitecoinBaseFeeMSat   = lnwire.MilliSatoshi(1000)
	defaultLitecoinFeeRate       = lnwire.MilliSatoshi(1)
	defaultLitecoinTimeLockDelta = 576
	defaultLitecoinDustLimit     = btcutil.Amount(54600)

	// defaultBitcoinStaticFeePerKW is the fee rate of 50 sat/vbyte
	// expressed in sat/kw.
	defaultBitcoinStaticFeePerKW = lnwallet.SatPerKWeight(12500)

	// defaultLitecoinStaticFeePerKW is the fee rate of 200 sat/vbyte
	// expressed in sat/kw.
	defaultLitecoinStaticFeePerKW = lnwallet.SatPerKWeight(50000)

	// btcToLtcConversionRate is a fixed ratio used in order to scale up
	// payments when running on the Litecoin chain.
	btcToLtcConversionRate = 60
)

// defaultBtcChannelConstraints is the default set of channel constraints that are
// meant to be used when initially funding a Bitcoin channel.
//
// TODO(halseth): make configurable at startup?
var defaultBtcChannelConstraints = channeldb.ChannelConstraints{
	DustLimit:        lnwallet.DefaultDustLimit(),
	MaxAcceptedHtlcs: lnwallet.MaxHTLCNumber / 2,
}

// defaultLtcChannelConstraints is the default set of channel constraints that are
// meant to be used when initially funding a Litecoin channel.
var defaultLtcChannelConstraints = channeldb.ChannelConstraints{
	DustLimit:        defaultLitecoinDustLimit,
	MaxAcceptedHtlcs: lnwallet.MaxHTLCNumber / 2,
}

// chainCode is an enum-like structure for keeping track of the chains
// currently supported within lnd.
type chainCode uint32

const (
	// bitcoinChain is Bitcoin's testnet chain.
	bitcoinChain chainCode = iota

	// litecoinChain is Litecoin's testnet chain.
	litecoinChain
)

// String returns a string representation of the target chainCode.
func (c chainCode) String() string {
	switch c {
	case bitcoinChain:
		return "bitcoin"
	case litecoinChain:
		return "litecoin"
	default:
		return "kekcoin"
	}
}

// chainControl couples the three primary interfaces lnd utilizes for a
// particular chain together. A single chainControl instance will exist for all
// the chains lnd is currently active on.
type chainControl struct {
	chainIO lnwallet.BlockChainIO

	feeEstimator lnwallet.FeeEstimator

	signer lnwallet.Signer

	msgSigner lnwallet.MessageSigner

	chainNotifier chainntnfs.ChainNotifier

	chainView chainview.FilteredChainView

	wallet *lnwallet.LightningWallet

	routingPolicy htlcswitch.ForwardingPolicy
}

// newChainControlFromConfig attempts to create a chainControl instance
// according to the parameters in the passed lnd configuration. Currently two
// branches of chainControl instances exist: one backed by a running btcd
// full-node, and the other backed by a running neutrino light client instance.
func newChainControlFromConfig(cfg *config, chanDB *channeldb.DB,
	privateWalletPw, publicWalletPw []byte, birthday time.Time,
	recoveryWindow uint32,
	wallet *wallet.Wallet) (*chainControl, func(), error) {

	// Set the RPC config from the "home" chain. Multi-chain isn't yet
	// active, so we'll restrict usage to a particular chain for now.
	homeChainConfig := cfg.Bitcoin
	if registeredChains.PrimaryChain() == litecoinChain {
		homeChainConfig = cfg.Litecoin
	}
	ltndLog.Infof("Primary chain is set to: %v",
		registeredChains.PrimaryChain())

	cc := &chainControl{}

	switch registeredChains.PrimaryChain() {
	case bitcoinChain:
		cc.routingPolicy = htlcswitch.ForwardingPolicy{
			MinHTLC:       cfg.Bitcoin.MinHTLC,
			BaseFee:       cfg.Bitcoin.BaseFee,
			FeeRate:       cfg.Bitcoin.FeeRate,
			TimeLockDelta: cfg.Bitcoin.TimeLockDelta,
		}
		cc.feeEstimator = lnwallet.StaticFeeEstimator{
			FeePerKW: defaultBitcoinStaticFeePerKW,
		}
	case litecoinChain:
		cc.routingPolicy = htlcswitch.ForwardingPolicy{
			MinHTLC:       cfg.Litecoin.MinHTLC,
			BaseFee:       cfg.Litecoin.BaseFee,
			FeeRate:       cfg.Litecoin.FeeRate,
			TimeLockDelta: cfg.Litecoin.TimeLockDelta,
		}
		cc.feeEstimator = lnwallet.StaticFeeEstimator{
			FeePerKW: defaultLitecoinStaticFeePerKW,
		}
	default:
		return nil, nil, fmt.Errorf("Default routing policy for "+
			"chain %v is unknown", registeredChains.PrimaryChain())
	}

	walletConfig := &btcwallet.Config{
		PrivatePass:    privateWalletPw,
		PublicPass:     publicWalletPw,
		Birthday:       birthday,
		RecoveryWindow: recoveryWindow,
		DataDir:        homeChainConfig.ChainDir,
		NetParams:      activeNetParams.Params,
		FeeEstimator:   cc.feeEstimator,
		CoinType:       activeNetParams.CoinType,
		Wallet:         wallet,
	}

	var (
		err     error
		cleanUp func()
	)

	// Initialize disabled height hint cache within the chain directory.
	hintCache, err := chainntnfs.NewHeightHintCache(
		chanDB, true,
		chainntnfs.DefaultHintPruneInterval,
		chainntnfs.DefaultHintPruneTimeout,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize height hint "+
			"cache: %v", err)
	}

	// If spv mode is active, then we'll be using a distinct set of
	// chainControl interfaces that interface directly with the p2p network
	// of the selected chain.
	switch homeChainConfig.Node {
	case "neutrino":
		// First we'll open the database file for neutrino, creating
		// the database if needed. We append the normalized network name
		// here to match the behavior of btcwallet.
		neutrinoDbPath := filepath.Join(homeChainConfig.ChainDir,
			normalizeNetwork(activeNetParams.Name))

		// Ensure that the neutrino db path exists.
		if err := os.MkdirAll(neutrinoDbPath, 0700); err != nil {
			return nil, nil, err
		}

		dbName := filepath.Join(neutrinoDbPath, "neutrino.db")
		nodeDatabase, err := walletdb.Create("bdb", dbName)
		if err != nil {
			return nil, nil, err
		}

		// With the database open, we can now create an instance of the
		// neutrino light client. We pass in relevant configuration
		// parameters required.
		config := neutrino.Config{
			DataDir:      neutrinoDbPath,
			Database:     nodeDatabase,
			ChainParams:  *activeNetParams.Params,
			AddPeers:     cfg.NeutrinoMode.AddPeers,
			ConnectPeers: cfg.NeutrinoMode.ConnectPeers,
			Dialer: func(addr net.Addr) (net.Conn, error) {
				return cfg.net.Dial(addr.Network(), addr.String())
			},
			NameResolver: func(host string) ([]net.IP, error) {
				addrs, err := cfg.net.LookupHost(host)
				if err != nil {
					return nil, err
				}

				ips := make([]net.IP, 0, len(addrs))
				for _, strIP := range addrs {
					ip := net.ParseIP(strIP)
					if ip == nil {
						continue
					}

					ips = append(ips, ip)
				}

				return ips, nil
			},
		}
		neutrino.MaxPeers = 8
		neutrino.BanDuration = 5 * time.Second
		svc, err := neutrino.NewChainService(config)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create neutrino: %v", err)
		}
		svc.Start()

		// Next we'll create the instances of the ChainNotifier and
		// FilteredChainView interface which is backed by the neutrino
		// light client.
		cc.chainNotifier, err = neutrinonotify.New(
			svc, hintCache,
		)
		if err != nil {
			return nil, nil, err
		}
		cc.chainView, err = chainview.NewCfFilteredChainView(svc)
		if err != nil {
			return nil, nil, err
		}

		// Finally, we'll set the chain source for btcwallet, and
		// create our clean up function which simply closes the
		// database.
		walletConfig.ChainSource = chain.NewNeutrinoClient(
			activeNetParams.Params, svc,
		)
		cleanUp = func() {
			svc.Stop()
			nodeDatabase.Close()
		}
	case "bitcoind", "litecoind":
		var bitcoindMode *bitcoindConfig
		switch {
		case cfg.Bitcoin.Active:
			bitcoindMode = cfg.BitcoindMode
		case cfg.Litecoin.Active:
			bitcoindMode = cfg.LitecoindMode
		}
		// Otherwise, we'll be speaking directly via RPC and ZMQ to a
		// bitcoind node. If the specified host for the btcd/ltcd RPC
		// server already has a port specified, then we use that
		// directly. Otherwise, we assume the default port according to
		// the selected chain parameters.
		var bitcoindHost string
		if strings.Contains(bitcoindMode.RPCHost, ":") {
			bitcoindHost = bitcoindMode.RPCHost
		} else {
			// The RPC ports specified in chainparams.go assume
			// btcd, which picks a different port so that btcwallet
			// can use the same RPC port as bitcoind. We convert
			// this back to the btcwallet/bitcoind port.
			rpcPort, err := strconv.Atoi(activeNetParams.rpcPort)
			if err != nil {
				return nil, nil, err
			}
			rpcPort -= 2
			bitcoindHost = fmt.Sprintf("%v:%d",
				bitcoindMode.RPCHost, rpcPort)
			if cfg.Bitcoin.Active && cfg.Bitcoin.RegTest {
				conn, err := net.Dial("tcp", bitcoindHost)
				if err != nil || conn == nil {
					rpcPort = 18443
					bitcoindHost = fmt.Sprintf("%v:%d",
						bitcoindMode.RPCHost,
						rpcPort)
				} else {
					conn.Close()
				}
			}
		}

		// Establish the connection to bitcoind and create the clients
		// required for our relevant subsystems.
		bitcoindConn, err := chain.NewBitcoindConn(
			activeNetParams.Params, bitcoindHost,
			bitcoindMode.RPCUser, bitcoindMode.RPCPass,
			bitcoindMode.ZMQPubRawBlock, bitcoindMode.ZMQPubRawTx,
			100*time.Millisecond,
		)
		if err != nil {
			return nil, nil, err
		}

		if err := bitcoindConn.Start(); err != nil {
			return nil, nil, fmt.Errorf("unable to connect to "+
				"bitcoind: %v", err)
		}

		cc.chainNotifier = bitcoindnotify.New(
			bitcoindConn, hintCache,
		)
		cc.chainView = chainview.NewBitcoindFilteredChainView(bitcoindConn)
		walletConfig.ChainSource = bitcoindConn.NewBitcoindClient()

		// If we're not in regtest mode, then we'll attempt to use a
		// proper fee estimator for testnet.
		rpcConfig := &rpcclient.ConnConfig{
			Host:                 bitcoindHost,
			User:                 bitcoindMode.RPCUser,
			Pass:                 bitcoindMode.RPCPass,
			DisableConnectOnNew:  true,
			DisableAutoReconnect: false,
			DisableTLS:           true,
			HTTPPostMode:         true,
		}
		if cfg.Bitcoin.Active && !cfg.Bitcoin.RegTest {
			ltndLog.Infof("Initializing bitcoind backed fee estimator")

			// Finally, we'll re-initialize the fee estimator, as
			// if we're using bitcoind as a backend, then we can
			// use live fee estimates, rather than a statically
			// coded value.
			fallBackFeeRate := lnwallet.SatPerKVByte(25 * 1000)
			cc.feeEstimator, err = lnwallet.NewBitcoindFeeEstimator(
				*rpcConfig, fallBackFeeRate.FeePerKWeight(),
			)
			if err != nil {
				return nil, nil, err
			}
			if err := cc.feeEstimator.Start(); err != nil {
				return nil, nil, err
			}
		} else if cfg.Litecoin.Active {
			ltndLog.Infof("Initializing litecoind backed fee estimator")

			// Finally, we'll re-initialize the fee estimator, as
			// if we're using litecoind as a backend, then we can
			// use live fee estimates, rather than a statically
			// coded value.
			fallBackFeeRate := lnwallet.SatPerKVByte(25 * 1000)
			cc.feeEstimator, err = lnwallet.NewBitcoindFeeEstimator(
				*rpcConfig, fallBackFeeRate.FeePerKWeight(),
			)
			if err != nil {
				return nil, nil, err
			}
			if err := cc.feeEstimator.Start(); err != nil {
				return nil, nil, err
			}
		}
	case "btcd", "ltcd":
		// Otherwise, we'll be speaking directly via RPC to a node.
		//
		// So first we'll load btcd/ltcd's TLS cert for the RPC
		// connection. If a raw cert was specified in the config, then
		// we'll set that directly. Otherwise, we attempt to read the
		// cert from the path specified in the config.
		var btcdMode *btcdConfig
		switch {
		case cfg.Bitcoin.Active:
			btcdMode = cfg.BtcdMode
		case cfg.Litecoin.Active:
			btcdMode = cfg.LtcdMode
		}
		var rpcCert []byte
		if btcdMode.RawRPCCert != "" {
			rpcCert, err = hex.DecodeString(btcdMode.RawRPCCert)
			if err != nil {
				return nil, nil, err
			}
		} else {
			certFile, err := os.Open(btcdMode.RPCCert)
			if err != nil {
				return nil, nil, err
			}
			rpcCert, err = ioutil.ReadAll(certFile)
			if err != nil {
				return nil, nil, err
			}
			if err := certFile.Close(); err != nil {
				return nil, nil, err
			}
		}

		// If the specified host for the btcd/ltcd RPC server already
		// has a port specified, then we use that directly. Otherwise,
		// we assume the default port according to the selected chain
		// parameters.
		var btcdHost string
		if strings.Contains(btcdMode.RPCHost, ":") {
			btcdHost = btcdMode.RPCHost
		} else {
			btcdHost = fmt.Sprintf("%v:%v", btcdMode.RPCHost,
				activeNetParams.rpcPort)
		}

		btcdUser := btcdMode.RPCUser
		btcdPass := btcdMode.RPCPass
		rpcConfig := &rpcclient.ConnConfig{
			Host:                 btcdHost,
			Endpoint:             "ws",
			User:                 btcdUser,
			Pass:                 btcdPass,
			Certificates:         rpcCert,
			DisableTLS:           false,
			DisableConnectOnNew:  true,
			DisableAutoReconnect: false,
		}
		cc.chainNotifier, err = btcdnotify.New(
			rpcConfig, hintCache,
		)
		if err != nil {
			return nil, nil, err
		}

		// Finally, we'll create an instance of the default chain view to be
		// used within the routing layer.
		cc.chainView, err = chainview.NewBtcdFilteredChainView(*rpcConfig)
		if err != nil {
			srvrLog.Errorf("unable to create chain view: %v", err)
			return nil, nil, err
		}

		// Create a special websockets rpc client for btcd which will be used
		// by the wallet for notifications, calls, etc.
		chainRPC, err := chain.NewRPCClient(activeNetParams.Params, btcdHost,
			btcdUser, btcdPass, rpcCert, false, 20)
		if err != nil {
			return nil, nil, err
		}

		walletConfig.ChainSource = chainRPC

		// If we're not in simnet or regtest mode, then we'll attempt
		// to use a proper fee estimator for testnet.
		if !cfg.Bitcoin.SimNet && !cfg.Litecoin.SimNet &&
			!cfg.Bitcoin.RegTest && !cfg.Litecoin.RegTest {

			ltndLog.Infof("Initializing btcd backed fee estimator")

			// Finally, we'll re-initialize the fee estimator, as
			// if we're using btcd as a backend, then we can use
			// live fee estimates, rather than a statically coded
			// value.
			fallBackFeeRate := lnwallet.SatPerKVByte(25 * 1000)
			cc.feeEstimator, err = lnwallet.NewBtcdFeeEstimator(
				*rpcConfig, fallBackFeeRate.FeePerKWeight(),
			)
			if err != nil {
				return nil, nil, err
			}
			if err := cc.feeEstimator.Start(); err != nil {
				return nil, nil, err
			}
		}
	default:
		return nil, nil, fmt.Errorf("unknown node type: %s",
			homeChainConfig.Node)
	}

	wc, err := btcwallet.New(*walletConfig)
	if err != nil {
		fmt.Printf("unable to create wallet controller: %v\n", err)
		return nil, nil, err
	}

	cc.msgSigner = wc
	cc.signer = wc
	cc.chainIO = wc

	// Select the default channel constraints for the primary chain.
	channelConstraints := defaultBtcChannelConstraints
	if registeredChains.PrimaryChain() == litecoinChain {
		channelConstraints = defaultLtcChannelConstraints
	}

	keyRing := keychain.NewBtcWalletKeyRing(
		wc.InternalWallet(), activeNetParams.CoinType,
	)

	// Create, and start the lnwallet, which handles the core payment
	// channel logic, and exposes control via proxy state machines.
	walletCfg := lnwallet.Config{
		Database:           chanDB,
		Notifier:           cc.chainNotifier,
		WalletController:   wc,
		Signer:             cc.signer,
		FeeEstimator:       cc.feeEstimator,
		SecretKeyRing:      keyRing,
		ChainIO:            cc.chainIO,
		DefaultConstraints: channelConstraints,
		NetParams:          *activeNetParams.Params,
	}
	lnWallet, err := lnwallet.NewLightningWallet(walletCfg)
	if err != nil {
		fmt.Printf("unable to create wallet: %v\n", err)
		return nil, nil, err
	}
	if err := lnWallet.Startup(); err != nil {
		fmt.Printf("unable to start wallet: %v\n", err)
		return nil, nil, err
	}

	ltndLog.Info("LightningWallet opened")

	cc.wallet = lnWallet

	return cc, cleanUp, nil
}

var (
	// bitcoinTestnetGenesis is the genesis hash of Bitcoin's testnet
	// chain.
	bitcoinTestnetGenesis = chainhash.Hash([chainhash.HashSize]byte{
		0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
		0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
		0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
		0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
	})

	// bitcoinMainnetGenesis is the genesis hash of Bitcoin's main chain.
	bitcoinMainnetGenesis = chainhash.Hash([chainhash.HashSize]byte{
		0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
		0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
		0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
		0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// litecoinTestnetGenesis is the genesis hash of Litecoin's testnet4
	// chain.
	litecoinTestnetGenesis = chainhash.Hash([chainhash.HashSize]byte{
		0xa0, 0x29, 0x3e, 0x4e, 0xeb, 0x3d, 0xa6, 0xe6,
		0xf5, 0x6f, 0x81, 0xed, 0x59, 0x5f, 0x57, 0x88,
		0x0d, 0x1a, 0x21, 0x56, 0x9e, 0x13, 0xee, 0xfd,
		0xd9, 0x51, 0x28, 0x4b, 0x5a, 0x62, 0x66, 0x49,
	})

	// litecoinMainnetGenesis is the genesis hash of Litecoin's main chain.
	litecoinMainnetGenesis = chainhash.Hash([chainhash.HashSize]byte{
		0xe2, 0xbf, 0x04, 0x7e, 0x7e, 0x5a, 0x19, 0x1a,
		0xa4, 0xef, 0x34, 0xd3, 0x14, 0x97, 0x9d, 0xc9,
		0x98, 0x6e, 0x0f, 0x19, 0x25, 0x1e, 0xda, 0xba,
		0x59, 0x40, 0xfd, 0x1f, 0xe3, 0x65, 0xa7, 0x12,
	})

	// chainMap is a simple index that maps a chain's genesis hash to the
	// chainCode enum for that chain.
	chainMap = map[chainhash.Hash]chainCode{
		bitcoinTestnetGenesis:  bitcoinChain,
		litecoinTestnetGenesis: litecoinChain,

		bitcoinMainnetGenesis:  bitcoinChain,
		litecoinMainnetGenesis: litecoinChain,
	}

	// chainDNSSeeds is a map of a chain's hash to the set of DNS seeds
	// that will be use to bootstrap peers upon first startup.
	//
	// The first item in the array is the primary host we'll use to attempt
	// the SRV lookup we require. If we're unable to receive a response
	// over UDP, then we'll fall back to manual TCP resolution. The second
	// item in the array is a special A record that we'll query in order to
	// receive the IP address of the current authoritative DNS server for
	// the network seed.
	//
	// TODO(roasbeef): extend and collapse these and chainparams.go into
	// struct like chaincfg.Params
	chainDNSSeeds = map[chainhash.Hash][][2]string{
		bitcoinMainnetGenesis: {
			{
				"nodes.lightning.directory",
				"soa.nodes.lightning.directory",
			},
		},

		bitcoinTestnetGenesis: {
			{
				"test.nodes.lightning.directory",
				"soa.nodes.lightning.directory",
			},
		},

		litecoinMainnetGenesis: {
			{
				"ltc.nodes.lightning.directory",
				"soa.nodes.lightning.directory",
			},
		},
	}
)

// chainRegistry keeps track of the current chains
type chainRegistry struct {
	sync.RWMutex

	activeChains map[chainCode]*chainControl
	netParams    map[chainCode]*bitcoinNetParams

	primaryChain chainCode
}

// newChainRegistry creates a new chainRegistry.
func newChainRegistry() *chainRegistry {
	return &chainRegistry{
		activeChains: make(map[chainCode]*chainControl),
		netParams:    make(map[chainCode]*bitcoinNetParams),
	}
}

// RegisterChain assigns an active chainControl instance to a target chain
// identified by its chainCode.
func (c *chainRegistry) RegisterChain(newChain chainCode, cc *chainControl) {
	c.Lock()
	c.activeChains[newChain] = cc
	c.Unlock()
}

// LookupChain attempts to lookup an active chainControl instance for the
// target chain.
func (c *chainRegistry) LookupChain(targetChain chainCode) (*chainControl, bool) {
	c.RLock()
	cc, ok := c.activeChains[targetChain]
	c.RUnlock()
	return cc, ok
}

// LookupChainByHash attempts to look up an active chainControl which
// corresponds to the passed genesis hash.
func (c *chainRegistry) LookupChainByHash(chainHash chainhash.Hash) (*chainControl, bool) {
	c.RLock()
	defer c.RUnlock()

	targetChain, ok := chainMap[chainHash]
	if !ok {
		return nil, ok
	}

	cc, ok := c.activeChains[targetChain]
	return cc, ok
}

// RegisterPrimaryChain sets a target chain as the "home chain" for lnd.
func (c *chainRegistry) RegisterPrimaryChain(cc chainCode) {
	c.Lock()
	defer c.Unlock()

	c.primaryChain = cc
}

// PrimaryChain returns the primary chain for this running lnd instance. The
// primary chain is considered the "home base" while the other registered
// chains are treated as secondary chains.
func (c *chainRegistry) PrimaryChain() chainCode {
	c.RLock()
	defer c.RUnlock()

	return c.primaryChain
}

// ActiveChains returns a slice containing the active chains.
func (c *chainRegistry) ActiveChains() []chainCode {
	c.RLock()
	defer c.RUnlock()

	chains := make([]chainCode, 0, len(c.activeChains))
	for activeChain := range c.activeChains {
		chains = append(chains, activeChain)
	}

	return chains
}

// NumActiveChains returns the total number of active chains.
func (c *chainRegistry) NumActiveChains() uint32 {
	c.RLock()
	defer c.RUnlock()

	return uint32(len(c.activeChains))
}
