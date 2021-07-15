// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package lnd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof" // Blank import to set up profiling HTTP handlers.
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	proxy "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/headerfs"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"

	"github.com/lightningnetwork/lnd/autopilot"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/chanacceptor"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/monitoring"
	"github.com/lightningnetwork/lnd/rpcperms"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/lightningnetwork/lnd/walletunlocker"
	"github.com/lightningnetwork/lnd/watchtower"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
)

// AdminAuthOptions returns a list of DialOptions that can be used to
// authenticate with the RPC server with admin capabilities.
// skipMacaroons=true should be set if we don't want to include macaroons with
// the auth options. This is needed for instance for the WalletUnlocker
// service, which must be usable also before macaroons are created.
//
// NOTE: This should only be called after the RPCListener has signaled it is
// ready.
func AdminAuthOptions(cfg *Config, skipMacaroons bool) ([]grpc.DialOption, error) {
	creds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read TLS cert: %v", err)
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	// Get the admin macaroon if macaroons are active.
	if !skipMacaroons && !cfg.NoMacaroons {
		// Load the adming macaroon file.
		macBytes, err := ioutil.ReadFile(cfg.AdminMacPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read macaroon "+
				"path (check the network setting!): %v", err)
		}

		mac := &macaroon.Macaroon{}
		if err = mac.UnmarshalBinary(macBytes); err != nil {
			return nil, fmt.Errorf("unable to decode macaroon: %v",
				err)
		}

		// Now we append the macaroon credentials to the dial options.
		cred := macaroons.NewMacaroonCredential(mac)
		opts = append(opts, grpc.WithPerRPCCredentials(cred))
	}

	return opts, nil
}

// GrpcRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own gRPC server onto lnd's main
// grpc.Server instance.
type GrpcRegistrar interface {
	// RegisterGrpcSubserver is called for each net.Listener on which lnd
	// creates a grpc.Server instance. External subservers implementing this
	// method can then register their own gRPC server structs to the main
	// server instance.
	RegisterGrpcSubserver(*grpc.Server) error
}

// RestRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own REST mux onto lnd's main
// proxy.ServeMux instance.
type RestRegistrar interface {
	// RegisterRestSubserver is called after lnd creates the main
	// proxy.ServeMux instance. External subservers implementing this method
	// can then register their own REST proxy stubs to the main server
	// instance.
	RegisterRestSubserver(context.Context, *proxy.ServeMux, string,
		[]grpc.DialOption) error
}

// RPCSubserverConfig is a struct that can be used to register an external
// subserver with the custom permissions that map to the gRPC server that is
// going to be registered with the GrpcRegistrar.
type RPCSubserverConfig struct {
	// Registrar is a callback that is invoked for each net.Listener on
	// which lnd creates a grpc.Server instance.
	Registrar GrpcRegistrar

	// Permissions is the permissions required for the external subserver.
	// It is a map between the full HTTP URI of each RPC and its required
	// macaroon permissions. If multiple action/entity tuples are specified
	// per URI, they are all required. See rpcserver.go for a list of valid
	// action and entity values.
	Permissions map[string][]bakery.Op

	// MacaroonValidator is a custom macaroon validator that should be used
	// instead of the default lnd validator. If specified, the custom
	// validator is used for all URIs specified in the above Permissions
	// map.
	MacaroonValidator macaroons.MacaroonValidator
}

// ListenerWithSignal is a net.Listener that has an additional Ready channel that
// will be closed when a server starts listening.
type ListenerWithSignal struct {
	net.Listener

	// Ready will be closed by the server listening on Listener.
	Ready chan struct{}
}

// ListenerCfg is a wrapper around custom listeners that can be passed to lnd
// when calling its main method.
type ListenerCfg struct {
	// RPCListener can be set to the listener to use for the RPC server. If
	// nil a regular network listener will be created.
	RPCListener *ListenerWithSignal

	// ExternalRPCSubserverCfg is optional and specifies the registration
	// callback and permissions to register external gRPC subservers.
	ExternalRPCSubserverCfg *RPCSubserverConfig

	// ExternalRestRegistrar is optional and specifies the registration
	// callback to register external REST subservers.
	ExternalRestRegistrar RestRegistrar
}

var errStreamIsolationWithDirectConnections = errors.New(
	"direct connections cannot be used while stream isolation is enabled",
)

// Main is the true entry point for lnd. It accepts a fully populated and
// validated main configuration struct and an optional listener config struct.
// This function starts all main system components then blocks until a signal
// is received on the shutdownChan at which point everything is shut down again.
func Main(cfg *Config, lisCfg ListenerCfg, interceptor signal.Interceptor) error {
	defer func() {
		ltndLog.Info("Shutdown complete\n")
		err := cfg.LogWriter.Close()
		if err != nil {
			ltndLog.Errorf("Could not close log rotator: %v", err)
		}
	}()

	// Show version at startup.
	ltndLog.Infof("Version: %s commit=%s, build=%s, logging=%s, debuglevel=%s",
		build.Version(), build.Commit, build.Deployment,
		build.LoggingType, cfg.DebugLevel)

	var network string
	switch {
	case cfg.Bitcoin.TestNet3 || cfg.Litecoin.TestNet3:
		network = "testnet"

	case cfg.Bitcoin.MainNet || cfg.Litecoin.MainNet:
		network = "mainnet"

	case cfg.Bitcoin.SimNet || cfg.Litecoin.SimNet:
		network = "simnet"

	case cfg.Bitcoin.RegTest || cfg.Litecoin.RegTest:
		network = "regtest"

	case cfg.Bitcoin.SigNet:
		network = "signet"
	}

	ltndLog.Infof("Active chain: %v (network=%v)",
		strings.Title(cfg.registeredChains.PrimaryChain().String()),
		network,
	)

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			ltndLog.Infof("Pprof listening on %v", cfg.Profile)
			fmt.Println(http.ListenAndServe(cfg.Profile, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			err := fmt.Errorf("unable to create CPU profile: %v",
				err)
			ltndLog.Error(err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Run configuration dependent DB pre-initialization. Note that this
	// needs to be done early and once during the startup process, before
	// any DB access.
	if err := cfg.DB.Init(ctx, cfg.localDatabaseDir()); err != nil {
		return err
	}

	// Only process macaroons if --no-macaroons isn't set.
	serverOpts, restDialOpts, restListen, cleanUp, err := getTLSConfig(cfg)
	if err != nil {
		err := fmt.Errorf("unable to load TLS credentials: %v", err)
		ltndLog.Error(err)
		return err
	}

	defer cleanUp()

	// Initialize a new block cache.
	blockCache := blockcache.NewBlockCache(cfg.BlockCacheSize)

	// Before starting the wallet, we'll create and start our Neutrino
	// light client instance, if enabled, in order to allow it to sync
	// while the rest of the daemon continues startup.
	mainChain := cfg.Bitcoin
	if cfg.registeredChains.PrimaryChain() == chainreg.LitecoinChain {
		mainChain = cfg.Litecoin
	}
	var neutrinoCS *neutrino.ChainService
	if mainChain.Node == "neutrino" {
		neutrinoBackend, neutrinoCleanUp, err := initNeutrinoBackend(
			cfg, mainChain.ChainDir, blockCache,
		)
		if err != nil {
			err := fmt.Errorf("unable to initialize neutrino "+
				"backend: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer neutrinoCleanUp()
		neutrinoCS = neutrinoBackend
	}

	var (
		walletInitParams = WalletUnlockParams{
			// In case we do auto-unlock, we need to be able to send
			// into the channel without blocking so we buffer it.
			MacResponseChan: make(chan []byte, 1),
		}
		privateWalletPw = lnwallet.DefaultPrivatePassphrase
		publicWalletPw  = lnwallet.DefaultPublicPassphrase
	)

	// If the user didn't request a seed, then we'll manually assume a
	// wallet birthday of now, as otherwise the seed would've specified
	// this information.
	walletInitParams.Birthday = time.Now()

	// If we have chosen to start with a dedicated listener for the
	// rpc server, we set it directly.
	var grpcListeners []*ListenerWithSignal
	if lisCfg.RPCListener != nil {
		grpcListeners = []*ListenerWithSignal{lisCfg.RPCListener}
	} else {
		// Otherwise we create listeners from the RPCListeners defined
		// in the config.
		for _, grpcEndpoint := range cfg.RPCListeners {
			// Start a gRPC server listening for HTTP/2
			// connections.
			lis, err := lncfg.ListenOnAddress(grpcEndpoint)
			if err != nil {
				ltndLog.Errorf("unable to listen on %s",
					grpcEndpoint)
				return err
			}
			defer lis.Close()

			grpcListeners = append(
				grpcListeners, &ListenerWithSignal{
					Listener: lis,
					Ready:    make(chan struct{}),
				})
		}
	}

	// Create a new RPC interceptor that we'll add to the GRPC server. This
	// will be used to log the API calls invoked on the GRPC server.
	interceptorChain := rpcperms.NewInterceptorChain(
		rpcsLog, cfg.NoMacaroons,
	)
	if err := interceptorChain.Start(); err != nil {
		return err
	}
	defer func() {
		err := interceptorChain.Stop()
		if err != nil {
			ltndLog.Warnf("error stopping RPC interceptor "+
				"chain: %v", err)
		}
	}()

	rpcServerOpts := interceptorChain.CreateServerOpts()
	serverOpts = append(serverOpts, rpcServerOpts...)

	grpcServer := grpc.NewServer(serverOpts...)
	defer grpcServer.Stop()

	// We'll also register the RPC interceptor chain as the StateServer, as
	// it can be used to query for the current state of the wallet.
	lnrpc.RegisterStateServer(grpcServer, interceptorChain)

	// Register the WalletUnlockerService with the GRPC server.
	pwService := createWalletUnlockerService(cfg)
	lnrpc.RegisterWalletUnlockerServer(grpcServer, pwService)

	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	rpcServer := newRPCServer(
		cfg, interceptorChain, lisCfg.ExternalRPCSubserverCfg,
		lisCfg.ExternalRestRegistrar,
		interceptor,
	)

	err = rpcServer.RegisterWithGrpcServer(grpcServer)
	if err != nil {
		return err
	}

	// Now that both the WalletUnlocker and LightningService have been
	// registered with the GRPC server, we can start listening.
	err = startGrpcListen(cfg, grpcServer, grpcListeners)
	if err != nil {
		return err
	}

	// Now start the REST proxy for our gRPC server above. We'll ensure
	// we direct LND to connect to its loopback address rather than a
	// wildcard to prevent certificate issues when accessing the proxy
	// externally.
	stopProxy, err := startRestProxy(
		cfg, rpcServer, restDialOpts, restListen,
	)
	if err != nil {
		return err
	}
	defer stopProxy()

	// Start leader election if we're running on etcd. Continuation will be
	// blocked until this instance is elected as the current leader or
	// shutting down.
	elected := false
	if cfg.Cluster.EnableLeaderElection {
		electionCtx, cancelElection := context.WithCancel(ctx)

		go func() {
			<-interceptor.ShutdownChannel()
			cancelElection()
		}()

		ltndLog.Infof("Using %v leader elector",
			cfg.Cluster.LeaderElector)

		leaderElector, err := cfg.Cluster.MakeLeaderElector(
			electionCtx, cfg.DB,
		)
		if err != nil {
			return err
		}

		defer func() {
			if !elected {
				return
			}

			ltndLog.Infof("Attempting to resign from leader role "+
				"(%v)", cfg.Cluster.ID)

			if err := leaderElector.Resign(); err != nil {
				ltndLog.Errorf("Leader elector failed to "+
					"resign: %v", err)
			}
		}()

		ltndLog.Infof("Starting leadership campaign (%v)",
			cfg.Cluster.ID)

		if err := leaderElector.Campaign(electionCtx); err != nil {
			ltndLog.Errorf("Leadership campaign failed: %v", err)
			return err
		}

		elected = true
		ltndLog.Infof("Elected as leader (%v)", cfg.Cluster.ID)
	}

	localChanDB, remoteChanDB, cleanUp, err := initializeDatabases(ctx, cfg)
	switch {
	case err == channeldb.ErrDryRunMigrationOK:
		ltndLog.Infof("%v, exiting", err)
		return nil
	case err != nil:
		return fmt.Errorf("unable to open databases: %v", err)
	}

	defer cleanUp()

	var loaderOpt btcwallet.LoaderOption
	if cfg.Cluster.EnableLeaderElection {
		// The wallet loader will attempt to use/create the wallet in
		// the replicated remote DB if we're running in a clustered
		// environment. This will ensure that all members of the cluster
		// have access to the same wallet state.
		loaderOpt = btcwallet.LoaderWithExternalWalletDB(
			remoteChanDB.Backend,
		)
	} else {
		// When "running locally", LND will use the bbolt wallet.db to
		// store the wallet located in the chain data dir, parametrized
		// by the active network.
		chainConfig := cfg.Bitcoin
		if cfg.registeredChains.PrimaryChain() == chainreg.LitecoinChain {
			chainConfig = cfg.Litecoin
		}

		dbDirPath := btcwallet.NetworkDir(
			chainConfig.ChainDir, cfg.ActiveNetParams.Params,
		)
		loaderOpt = btcwallet.LoaderWithLocalWalletDB(
			dbDirPath, !cfg.SyncFreelist, cfg.DB.Bolt.DBTimeout,
		)
	}

	pwService.SetLoaderOpts([]btcwallet.LoaderOption{loaderOpt})
	walletExists, err := pwService.WalletExists()
	if err != nil {
		return err
	}

	if !walletExists {
		interceptorChain.SetWalletNotCreated()
	} else {
		interceptorChain.SetWalletLocked()
	}

	// If we've started in auto unlock mode, then a wallet should already
	// exist because we don't want to enable the RPC unlocker in that case
	// for security reasons (an attacker could inject their seed since the
	// RPC is unauthenticated). Only if the user explicitly wants to allow
	// wallet creation we don't error out here.
	if cfg.WalletUnlockPasswordFile != "" && !walletExists &&
		!cfg.WalletUnlockAllowCreate {

		return fmt.Errorf("wallet unlock password file was specified " +
			"but wallet does not exist; initialize the wallet " +
			"before using auto unlocking")
	}

	// What wallet mode are we running in? We've already made sure the no
	// seed backup and auto unlock aren't both set during config parsing.
	switch {
	// No seed backup means we're also using the default password.
	case cfg.NoSeedBackup:
		// We continue normally, the default password has already been
		// set above.

	// A password for unlocking is provided in a file.
	case cfg.WalletUnlockPasswordFile != "" && walletExists:
		ltndLog.Infof("Attempting automatic wallet unlock with " +
			"password provided in file")
		pwBytes, err := ioutil.ReadFile(cfg.WalletUnlockPasswordFile)
		if err != nil {
			return fmt.Errorf("error reading password from file "+
				"%s: %v", cfg.WalletUnlockPasswordFile, err)
		}

		// Remove any newlines at the end of the file. The lndinit tool
		// won't ever write a newline but maybe the file was provisioned
		// by another process or user.
		pwBytes = bytes.TrimRight(pwBytes, "\r\n")

		// We have the password now, we can ask the unlocker service to
		// do the unlock for us.
		unlockedWallet, unloadWalletFn, err := pwService.LoadAndUnlock(
			pwBytes, 0,
		)
		if err != nil {
			return fmt.Errorf("error unlocking wallet with "+
				"password from file: %v", err)
		}

		defer func() {
			if err := unloadWalletFn(); err != nil {
				ltndLog.Errorf("Could not unload wallet: %v",
					err)
			}
		}()

		privateWalletPw = pwBytes
		publicWalletPw = pwBytes
		walletInitParams.Wallet = unlockedWallet
		walletInitParams.UnloadWallet = unloadWalletFn

	// If none of the automatic startup options are selected, we fall back
	// to the default behavior of waiting for the wallet creation/unlocking
	// over RPC.
	default:
		params, err := waitForWalletPassword(
			cfg, pwService, []btcwallet.LoaderOption{loaderOpt},
			interceptor.ShutdownChannel(),
		)
		if err != nil {
			err := fmt.Errorf("unable to set up wallet password "+
				"listeners: %v", err)
			ltndLog.Error(err)
			return err
		}

		walletInitParams = *params
		privateWalletPw = walletInitParams.Password
		publicWalletPw = walletInitParams.Password
		defer func() {
			if err := walletInitParams.UnloadWallet(); err != nil {
				ltndLog.Errorf("Could not unload wallet: %v", err)
			}
		}()

		if walletInitParams.RecoveryWindow > 0 {
			ltndLog.Infof("Wallet recovery mode enabled with "+
				"address lookahead of %d addresses",
				walletInitParams.RecoveryWindow)
		}
	}

	var macaroonService *macaroons.Service
	if !cfg.NoMacaroons {
		// Create the macaroon authentication/authorization service.
		macaroonService, err = macaroons.NewService(
			cfg.networkDir, "lnd", walletInitParams.StatelessInit,
			cfg.DB.Bolt.DBTimeout, macaroons.IPLockChecker,
		)
		if err != nil {
			err := fmt.Errorf("unable to set up macaroon "+
				"authentication: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer macaroonService.Close()

		// Try to unlock the macaroon store with the private password.
		// Ignore ErrAlreadyUnlocked since it could be unlocked by the
		// wallet unlocker.
		err = macaroonService.CreateUnlock(&privateWalletPw)
		if err != nil && err != macaroons.ErrAlreadyUnlocked {
			err := fmt.Errorf("unable to unlock macaroons: %v", err)
			ltndLog.Error(err)
			return err
		}

		// In case we actually needed to unlock the wallet, we now need
		// to create an instance of the admin macaroon and send it to
		// the unlocker so it can forward it to the user. In no seed
		// backup mode, there's nobody listening on the channel and we'd
		// block here forever.
		if !cfg.NoSeedBackup {
			adminMacBytes, err := bakeMacaroon(
				ctx, macaroonService, adminPermissions(),
			)
			if err != nil {
				return err
			}

			// The channel is buffered by one element so writing
			// should not block here.
			walletInitParams.MacResponseChan <- adminMacBytes
		}

		// If the user requested a stateless initialization, no macaroon
		// files should be created.
		if !walletInitParams.StatelessInit &&
			!fileExists(cfg.AdminMacPath) &&
			!fileExists(cfg.ReadMacPath) &&
			!fileExists(cfg.InvoiceMacPath) {

			// Create macaroon files for lncli to use if they don't
			// exist.
			err = genMacaroons(
				ctx, macaroonService, cfg.AdminMacPath,
				cfg.ReadMacPath, cfg.InvoiceMacPath,
			)
			if err != nil {
				err := fmt.Errorf("unable to create macaroons "+
					"%v", err)
				ltndLog.Error(err)
				return err
			}
		}

		// As a security service to the user, if they requested
		// stateless initialization and there are macaroon files on disk
		// we log a warning.
		if walletInitParams.StatelessInit {
			msg := "Found %s macaroon on disk (%s) even though " +
				"--stateless_init was requested. Unencrypted " +
				"state is accessible by the host system. You " +
				"should change the password and use " +
				"--new_mac_root_key with --stateless_init to " +
				"clean up and invalidate old macaroons."

			if fileExists(cfg.AdminMacPath) {
				ltndLog.Warnf(msg, "admin", cfg.AdminMacPath)
			}
			if fileExists(cfg.ReadMacPath) {
				ltndLog.Warnf(msg, "readonly", cfg.ReadMacPath)
			}
			if fileExists(cfg.InvoiceMacPath) {
				ltndLog.Warnf(msg, "invoice", cfg.InvoiceMacPath)
			}
		}

		// We add the macaroon service to our RPC interceptor. This
		// will start checking macaroons against permissions on every
		// RPC invocation.
		interceptorChain.AddMacaroonService(macaroonService)
	}

	// Now that the wallet password has been provided, transition the RPC
	// state into Unlocked.
	interceptorChain.SetWalletUnlocked()

	// Since calls to the WalletUnlocker service wait for a response on the
	// macaroon channel, we close it here to make sure they return in case
	// we did not return the admin macaroon above. This will be the case if
	// --no-macaroons is used.
	close(walletInitParams.MacResponseChan)

	// With the information parsed from the configuration, create valid
	// instances of the pertinent interfaces required to operate the
	// Lightning Network Daemon.
	//
	// When we create the chain control, we need storage for the height
	// hints and also the wallet itself, for these two we want them to be
	// replicated, so we'll pass in the remote channel DB instance.
	chainControlCfg := &chainreg.Config{
		Bitcoin:                     cfg.Bitcoin,
		Litecoin:                    cfg.Litecoin,
		PrimaryChain:                cfg.registeredChains.PrimaryChain,
		HeightHintCacheQueryDisable: cfg.HeightHintCacheQueryDisable,
		NeutrinoMode:                cfg.NeutrinoMode,
		BitcoindMode:                cfg.BitcoindMode,
		LitecoindMode:               cfg.LitecoindMode,
		BtcdMode:                    cfg.BtcdMode,
		LtcdMode:                    cfg.LtcdMode,
		LocalChanDB:                 localChanDB,
		RemoteChanDB:                remoteChanDB,
		PrivateWalletPw:             privateWalletPw,
		PublicWalletPw:              publicWalletPw,
		Birthday:                    walletInitParams.Birthday,
		RecoveryWindow:              walletInitParams.RecoveryWindow,
		Wallet:                      walletInitParams.Wallet,
		NeutrinoCS:                  neutrinoCS,
		ActiveNetParams:             cfg.ActiveNetParams,
		FeeURL:                      cfg.FeeURL,
		Dialer: func(addr string) (net.Conn, error) {
			return cfg.net.Dial("tcp", addr, cfg.ConnectionTimeout)
		},
		BlockCacheSize: cfg.BlockCacheSize,
		LoaderOptions: []btcwallet.LoaderOption{
			loaderOpt,
		},
	}

	// Parse coin selection strategy.
	switch cfg.CoinSelectionStrategy {
	case "largest":
		chainControlCfg.CoinSelectionStrategy = wallet.CoinSelectionLargest

	case "random":
		chainControlCfg.CoinSelectionStrategy = wallet.CoinSelectionRandom

	default:
		return fmt.Errorf("unknown coin selection strategy %v",
			cfg.CoinSelectionStrategy)
	}

	activeChainControl, cleanup, err := chainreg.NewChainControl(
		chainControlCfg, blockCache,
	)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		err := fmt.Errorf("unable to create chain control: %v", err)
		ltndLog.Error(err)
		return err
	}

	// Finally before we start the server, we'll register the "holy
	// trinity" of interface for our current "home chain" with the active
	// chainRegistry interface.
	primaryChain := cfg.registeredChains.PrimaryChain()
	cfg.registeredChains.RegisterChain(primaryChain, activeChainControl)

	// TODO(roasbeef): add rotation
	idKeyDesc, err := activeChainControl.KeyRing.DeriveKey(
		keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	)
	if err != nil {
		err := fmt.Errorf("error deriving node key: %v", err)
		ltndLog.Error(err)
		return err
	}

	if cfg.Tor.StreamIsolation && cfg.Tor.DirectConnections {
		return errStreamIsolationWithDirectConnections
	}

	if cfg.Tor.Active {
		if cfg.Tor.DirectConnections {
			srvrLog.Info("Onion services are accessible via Tor! NOTE: " +
				"Traffic to clearnet services is not routed via Tor.")
		} else {
			srvrLog.Infof("Proxying all network traffic via Tor "+
				"(stream_isolation=%v)! NOTE: Ensure the backend node "+
				"is proxying over Tor as well", cfg.Tor.StreamIsolation)
		}
	}

	// If the watchtower client should be active, open the client database.
	// This is done here so that Close always executes when lndMain returns.
	var towerClientDB *wtdb.ClientDB
	if cfg.WtClient.Active {
		var err error
		towerClientDB, err = wtdb.OpenClientDB(
			cfg.localDatabaseDir(), cfg.DB.Bolt.DBTimeout,
		)
		if err != nil {
			err := fmt.Errorf("unable to open watchtower client "+
				"database: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer towerClientDB.Close()
	}

	// If tor is active and either v2 or v3 onion services have been specified,
	// make a tor controller and pass it into both the watchtower server and
	// the regular lnd server.
	var torController *tor.Controller
	if cfg.Tor.Active && (cfg.Tor.V2 || cfg.Tor.V3) {
		torController = tor.NewController(
			cfg.Tor.Control, cfg.Tor.TargetIPAddress, cfg.Tor.Password,
		)

		// Start the tor controller before giving it to any other subsystems.
		if err := torController.Start(); err != nil {
			err := fmt.Errorf("unable to initialize tor controller: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer func() {
			if err := torController.Stop(); err != nil {
				ltndLog.Errorf("error stopping tor controller: %v", err)
			}
		}()
	}

	var tower *watchtower.Standalone
	if cfg.Watchtower.Active {
		// Segment the watchtower directory by chain and network.
		towerDBDir := filepath.Join(
			cfg.Watchtower.TowerDir,
			cfg.registeredChains.PrimaryChain().String(),
			lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
		)

		towerDB, err := wtdb.OpenTowerDB(
			towerDBDir, cfg.DB.Bolt.DBTimeout,
		)
		if err != nil {
			err := fmt.Errorf("unable to open watchtower "+
				"database: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer towerDB.Close()

		towerKeyDesc, err := activeChainControl.KeyRing.DeriveKey(
			keychain.KeyLocator{
				Family: keychain.KeyFamilyTowerID,
				Index:  0,
			},
		)
		if err != nil {
			err := fmt.Errorf("error deriving tower key: %v", err)
			ltndLog.Error(err)
			return err
		}

		wtCfg := &watchtower.Config{
			BlockFetcher:   activeChainControl.ChainIO,
			DB:             towerDB,
			EpochRegistrar: activeChainControl.ChainNotifier,
			Net:            cfg.net,
			NewAddress: func() (btcutil.Address, error) {
				return activeChainControl.Wallet.NewAddress(
					lnwallet.WitnessPubKey, false,
					lnwallet.DefaultAccountName,
				)
			},
			NodeKeyECDH: keychain.NewPubKeyECDH(
				towerKeyDesc, activeChainControl.KeyRing,
			),
			PublishTx: activeChainControl.Wallet.PublishTransaction,
			ChainHash: *cfg.ActiveNetParams.GenesisHash,
		}

		// If there is a tor controller (user wants auto hidden services), then
		// store a pointer in the watchtower config.
		if torController != nil {
			wtCfg.TorController = torController
			wtCfg.WatchtowerKeyPath = cfg.Tor.WatchtowerKeyPath

			switch {
			case cfg.Tor.V2:
				wtCfg.Type = tor.V2
			case cfg.Tor.V3:
				wtCfg.Type = tor.V3
			}
		}

		wtConfig, err := cfg.Watchtower.Apply(wtCfg, lncfg.NormalizeAddresses)
		if err != nil {
			err := fmt.Errorf("unable to configure watchtower: %v",
				err)
			ltndLog.Error(err)
			return err
		}

		tower, err = watchtower.New(wtConfig)
		if err != nil {
			err := fmt.Errorf("unable to create watchtower: %v", err)
			ltndLog.Error(err)
			return err
		}
	}

	// Initialize the ChainedAcceptor.
	chainedAcceptor := chanacceptor.NewChainedAcceptor()

	// Set up the core server which will listen for incoming peer
	// connections.
	server, err := newServer(
		cfg, cfg.Listeners, localChanDB, remoteChanDB, towerClientDB,
		activeChainControl, &idKeyDesc, walletInitParams.ChansToRestore,
		chainedAcceptor, torController,
	)
	if err != nil {
		err := fmt.Errorf("unable to create server: %v", err)
		ltndLog.Error(err)
		return err
	}

	// Set up an autopilot manager from the current config. This will be
	// used to manage the underlying autopilot agent, starting and stopping
	// it at will.
	atplCfg, err := initAutoPilot(server, cfg.Autopilot, mainChain, cfg.ActiveNetParams)
	if err != nil {
		err := fmt.Errorf("unable to initialize autopilot: %v", err)
		ltndLog.Error(err)
		return err
	}

	atplManager, err := autopilot.NewManager(atplCfg)
	if err != nil {
		err := fmt.Errorf("unable to create autopilot manager: %v", err)
		ltndLog.Error(err)
		return err
	}
	if err := atplManager.Start(); err != nil {
		err := fmt.Errorf("unable to start autopilot manager: %v", err)
		ltndLog.Error(err)
		return err
	}
	defer atplManager.Stop()

	// Now we have created all dependencies necessary to populate and
	// start the RPC server.
	err = rpcServer.addDeps(
		server, macaroonService, cfg.SubRPCServers, atplManager,
		server.invoices, tower, chainedAcceptor,
	)
	if err != nil {
		err := fmt.Errorf("unable to add deps to RPC server: %v", err)
		ltndLog.Error(err)
		return err
	}
	if err := rpcServer.Start(); err != nil {
		err := fmt.Errorf("unable to start RPC server: %v", err)
		ltndLog.Error(err)
		return err
	}
	defer rpcServer.Stop()

	// We transition the RPC state to Active, as the RPC server is up.
	interceptorChain.SetRPCActive()

	// If we're not in regtest or simnet mode, We'll wait until we're fully
	// synced to continue the start up of the remainder of the daemon. This
	// ensures that we don't accept any possibly invalid state transitions, or
	// accept channels with spent funds.
	if !(cfg.Bitcoin.RegTest || cfg.Bitcoin.SimNet ||
		cfg.Litecoin.RegTest || cfg.Litecoin.SimNet) {

		_, bestHeight, err := activeChainControl.ChainIO.GetBestBlock()
		if err != nil {
			err := fmt.Errorf("unable to determine chain tip: %v",
				err)
			ltndLog.Error(err)
			return err
		}

		ltndLog.Infof("Waiting for chain backend to finish sync, "+
			"start_height=%v", bestHeight)

		for {
			if !interceptor.Alive() {
				return nil
			}

			synced, _, err := activeChainControl.Wallet.IsSynced()
			if err != nil {
				err := fmt.Errorf("unable to determine if "+
					"wallet is synced: %v", err)
				ltndLog.Error(err)
				return err
			}

			if synced {
				break
			}

			time.Sleep(time.Second * 1)
		}

		_, bestHeight, err = activeChainControl.ChainIO.GetBestBlock()
		if err != nil {
			err := fmt.Errorf("unable to determine chain tip: %v",
				err)
			ltndLog.Error(err)
			return err
		}

		ltndLog.Infof("Chain backend is fully synced (end_height=%v)!",
			bestHeight)
	}

	// With all the relevant chains initialized, we can finally start the
	// server itself.
	if err := server.Start(); err != nil {
		err := fmt.Errorf("unable to start server: %v", err)
		ltndLog.Error(err)
		return err
	}
	defer server.Stop()

	// Now that the server has started, if the autopilot mode is currently
	// active, then we'll start the autopilot agent immediately. It will be
	// stopped together with the autopilot service.
	if cfg.Autopilot.Active {
		if err := atplManager.StartAgent(); err != nil {
			err := fmt.Errorf("unable to start autopilot agent: %v",
				err)
			ltndLog.Error(err)
			return err
		}
	}

	if cfg.Watchtower.Active {
		if err := tower.Start(); err != nil {
			err := fmt.Errorf("unable to start watchtower: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer tower.Stop()
	}

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-interceptor.ShutdownChannel()
	return nil
}

// getTLSConfig returns a TLS configuration for the gRPC server and credentials
// and a proxy destination for the REST reverse proxy.
func getTLSConfig(cfg *Config) ([]grpc.ServerOption, []grpc.DialOption,
	func(net.Addr) (net.Listener, error), func(), error) {

	// Ensure we create TLS key and certificate if they don't exist.
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		rpcsLog.Infof("Generating TLS certificates...")
		err := cert.GenCertPair(
			"lnd autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rpcsLog.Infof("Done generating TLS certificates")
	}

	certData, parsedCert, err := cert.LoadCert(
		cfg.TLSCertPath, cfg.TLSKeyPath,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// We check whether the certifcate we have on disk match the IPs and
	// domains specified by the config. If the extra IPs or domains have
	// changed from when the certificate was created, we will refresh the
	// certificate if auto refresh is active.
	refresh := false
	if cfg.TLSAutoRefresh {
		refresh, err = cert.IsOutdated(
			parsedCert, cfg.TLSExtraIPs,
			cfg.TLSExtraDomains, cfg.TLSDisableAutofill,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		ltndLog.Info("TLS certificate is expired or outdated, " +
			"generating a new one")

		err := os.Remove(cfg.TLSCertPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		err = os.Remove(cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		rpcsLog.Infof("Renewing TLS certificates...")
		err = cert.GenCertPair(
			"lnd autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rpcsLog.Infof("Done renewing TLS certificates")

		// Reload the certificate data.
		certData, _, err = cert.LoadCert(
			cfg.TLSCertPath, cfg.TLSKeyPath,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	tlsCfg := cert.TLSConfFromCert(certData)

	restCreds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// If Let's Encrypt is enabled, instantiate autocert to request/renew
	// the certificates.
	cleanUp := func() {}
	if cfg.LetsEncryptDomain != "" {
		ltndLog.Infof("Using Let's Encrypt certificate for domain %v",
			cfg.LetsEncryptDomain)

		manager := autocert.Manager{
			Cache:      autocert.DirCache(cfg.LetsEncryptDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.LetsEncryptDomain),
		}

		srv := &http.Server{
			Addr:    cfg.LetsEncryptListen,
			Handler: manager.HTTPHandler(nil),
		}
		shutdownCompleted := make(chan struct{})
		cleanUp = func() {
			err := srv.Shutdown(context.Background())
			if err != nil {
				ltndLog.Errorf("Autocert listener shutdown "+
					" error: %v", err)

				return
			}
			<-shutdownCompleted
			ltndLog.Infof("Autocert challenge listener stopped")
		}

		go func() {
			ltndLog.Infof("Autocert challenge listener started "+
				"at %v", cfg.LetsEncryptListen)

			err := srv.ListenAndServe()
			if err != http.ErrServerClosed {
				ltndLog.Errorf("autocert http: %v", err)
			}
			close(shutdownCompleted)
		}()

		getCertificate := func(h *tls.ClientHelloInfo) (
			*tls.Certificate, error) {

			lecert, err := manager.GetCertificate(h)
			if err != nil {
				ltndLog.Errorf("GetCertificate: %v", err)
				return &certData, nil
			}

			return lecert, err
		}

		// The self-signed tls.cert remains available as fallback.
		tlsCfg.GetCertificate = getCertificate
	}

	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	// For our REST dial options, we'll still use TLS, but also increase
	// the max message size that we'll decode to allow clients to hit
	// endpoints which return more data such as the DescribeGraph call.
	// We set this to 200MiB atm. Should be the same value as maxMsgRecvSize
	// in cmd/lncli/main.go.
	restDialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(restCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200),
		),
	}

	// Return a function closure that can be used to listen on a given
	// address with the current TLS config.
	restListen := func(addr net.Addr) (net.Listener, error) {
		// For restListen we will call ListenOnAddress if TLS is
		// disabled.
		if cfg.DisableRestTLS {
			return lncfg.ListenOnAddress(addr)
		}

		return lncfg.TLSListenOnAddress(addr, tlsCfg)
	}

	return serverOpts, restDialOpts, restListen, cleanUp, nil
}

// fileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// bakeMacaroon creates a new macaroon with newest version and the given
// permissions then returns it binary serialized.
func bakeMacaroon(ctx context.Context, svc *macaroons.Service,
	permissions []bakery.Op) ([]byte, error) {

	mac, err := svc.NewMacaroon(
		ctx, macaroons.DefaultRootKeyID, permissions...,
	)
	if err != nil {
		return nil, err
	}

	return mac.M().MarshalBinary()
}

// genMacaroons generates three macaroon files; one admin-level, one for
// invoice access and one read-only. These can also be used to generate more
// granular macaroons.
func genMacaroons(ctx context.Context, svc *macaroons.Service,
	admFile, roFile, invoiceFile string) error {

	// First, we'll generate a macaroon that only allows the caller to
	// access invoice related calls. This is useful for merchants and other
	// services to allow an isolated instance that can only query and
	// modify invoices.
	invoiceMacBytes, err := bakeMacaroon(ctx, svc, invoicePermissions)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(invoiceFile, invoiceMacBytes, 0644)
	if err != nil {
		_ = os.Remove(invoiceFile)
		return err
	}

	// Generate the read-only macaroon and write it to a file.
	roBytes, err := bakeMacaroon(ctx, svc, readPermissions)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(roFile, roBytes, 0644); err != nil {
		_ = os.Remove(roFile)
		return err
	}

	// Generate the admin macaroon and write it to a file.
	admBytes, err := bakeMacaroon(ctx, svc, adminPermissions())
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(admFile, admBytes, 0600); err != nil {
		_ = os.Remove(admFile)
		return err
	}

	return nil
}

// adminPermissions returns a list of all permissions in a safe way that doesn't
// modify any of the source lists.
func adminPermissions() []bakery.Op {
	admin := make([]bakery.Op, len(readPermissions)+len(writePermissions))
	copy(admin[:len(readPermissions)], readPermissions)
	copy(admin[len(readPermissions):], writePermissions)
	return admin
}

// WalletUnlockParams holds the variables used to parameterize the unlocking of
// lnd's wallet after it has already been created.
type WalletUnlockParams struct {
	// Password is the public and private wallet passphrase.
	Password []byte

	// Birthday specifies the approximate time that this wallet was created.
	// This is used to bound any rescans on startup.
	Birthday time.Time

	// RecoveryWindow specifies the address lookahead when entering recovery
	// mode. A recovery will be attempted if this value is non-zero.
	RecoveryWindow uint32

	// Wallet is the loaded and unlocked Wallet. This is returned
	// from the unlocker service to avoid it being unlocked twice (once in
	// the unlocker service to check if the password is correct and again
	// later when lnd actually uses it). Because unlocking involves scrypt
	// which is resource intensive, we want to avoid doing it twice.
	Wallet *wallet.Wallet

	// ChansToRestore a set of static channel backups that should be
	// restored before the main server instance starts up.
	ChansToRestore walletunlocker.ChannelsToRecover

	// UnloadWallet is a function for unloading the wallet, which should
	// be called on shutdown.
	UnloadWallet func() error

	// StatelessInit signals that the user requested the daemon to be
	// initialized stateless, which means no unencrypted macaroons should be
	// written to disk.
	StatelessInit bool

	// MacResponseChan is the channel for sending back the admin macaroon to
	// the WalletUnlocker service.
	MacResponseChan chan []byte
}

// createWalletUnlockerService creates a WalletUnlockerService from the passed
// config.
func createWalletUnlockerService(cfg *Config) *walletunlocker.UnlockerService {
	chainConfig := cfg.Bitcoin
	if cfg.registeredChains.PrimaryChain() == chainreg.LitecoinChain {
		chainConfig = cfg.Litecoin
	}

	// The macaroonFiles are passed to the wallet unlocker so they can be
	// deleted and recreated in case the root macaroon key is also changed
	// during the change password operation.
	macaroonFiles := []string{
		cfg.AdminMacPath, cfg.ReadMacPath, cfg.InvoiceMacPath,
	}

	return walletunlocker.New(
		chainConfig.ChainDir, cfg.ActiveNetParams.Params,
		!cfg.SyncFreelist, macaroonFiles, cfg.DB.Bolt.DBTimeout,
		cfg.ResetWalletTransactions, nil,
	)
}

// startGrpcListen starts the GRPC server on the passed listeners.
func startGrpcListen(cfg *Config, grpcServer *grpc.Server,
	listeners []*ListenerWithSignal) error {

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	for _, lis := range listeners {
		wg.Add(1)
		go func(lis *ListenerWithSignal) {
			rpcsLog.Infof("RPC server listening on %s", lis.Addr())

			// Close the ready chan to indicate we are listening.
			close(lis.Ready)

			wg.Done()
			_ = grpcServer.Serve(lis)
		}(lis)
	}

	// If Prometheus monitoring is enabled, start the Prometheus exporter.
	if cfg.Prometheus.Enabled() {
		err := monitoring.ExportPrometheusMetrics(
			grpcServer, cfg.Prometheus,
		)
		if err != nil {
			return err
		}
	}

	// Wait for gRPC servers to be up running.
	wg.Wait()

	return nil
}

// startRestProxy starts the given REST proxy on the listeners found in the
// config.
func startRestProxy(cfg *Config, rpcServer *rpcServer, restDialOpts []grpc.DialOption,
	restListen func(net.Addr) (net.Listener, error)) (func(), error) {

	// We use the first RPC listener as the destination for our REST proxy.
	// If the listener is set to listen on all interfaces, we replace it
	// with localhost, as we cannot dial it directly.
	restProxyDest := cfg.RPCListeners[0].String()
	switch {
	case strings.Contains(restProxyDest, "0.0.0.0"):
		restProxyDest = strings.Replace(
			restProxyDest, "0.0.0.0", "127.0.0.1", 1,
		)

	case strings.Contains(restProxyDest, "[::]"):
		restProxyDest = strings.Replace(
			restProxyDest, "[::]", "[::1]", 1,
		)
	}

	var shutdownFuncs []func()
	shutdown := func() {
		for _, shutdownFn := range shutdownFuncs {
			shutdownFn()
		}
	}

	// Start a REST proxy for our gRPC server.
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	shutdownFuncs = append(shutdownFuncs, cancel)

	// We'll set up a proxy that will forward REST calls to the GRPC
	// server.
	//
	// The default JSON marshaler of the REST proxy only sets OrigName to
	// true, which instructs it to use the same field names as specified in
	// the proto file and not switch to camel case. What we also want is
	// that the marshaler prints all values, even if they are falsey.
	customMarshalerOption := proxy.WithMarshalerOption(
		proxy.MIMEWildcard, &proxy.JSONPb{
			OrigName:     true,
			EmitDefaults: true,
		},
	)
	mux := proxy.NewServeMux(customMarshalerOption)

	// Register our services with the REST proxy.
	err := lnrpc.RegisterWalletUnlockerHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return nil, err
	}

	err = lnrpc.RegisterStateHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return nil, err
	}

	err = rpcServer.RegisterWithRestProxy(
		ctx, mux, restDialOpts, restProxyDest,
	)
	if err != nil {
		return nil, err
	}

	// Wrap the default grpc-gateway handler with the WebSocket handler.
	restHandler := lnrpc.NewWebSocketProxy(
		mux, rpcsLog, cfg.WSPingInterval, cfg.WSPongWait,
		lnrpc.LndClientStreamingURIs,
	)

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	// Now spin up a network listener for each requested port and start a
	// goroutine that serves REST with the created mux there.
	for _, restEndpoint := range cfg.RESTListeners {
		lis, err := restListen(restEndpoint)
		if err != nil {
			ltndLog.Errorf("gRPC proxy unable to listen on %s",
				restEndpoint)
			return nil, err
		}

		shutdownFuncs = append(shutdownFuncs, func() {
			err := lis.Close()
			if err != nil {
				rpcsLog.Errorf("Error closing listener: %v",
					err)
			}
		})

		wg.Add(1)
		go func() {
			rpcsLog.Infof("gRPC proxy started at %s", lis.Addr())

			// Create our proxy chain now. A request will pass
			// through the following chain:
			// req ---> CORS handler --> WS proxy --->
			//   REST proxy --> gRPC endpoint
			corsHandler := allowCORS(restHandler, cfg.RestCORS)

			wg.Done()
			err := http.Serve(lis, corsHandler)
			if err != nil && !lnrpc.IsClosedConnError(err) {
				rpcsLog.Error(err)
			}
		}()
	}

	// Wait for REST servers to be up running.
	wg.Wait()

	return shutdown, nil
}

// waitForWalletPassword blocks until a password is provided by the user to
// this RPC server.
func waitForWalletPassword(cfg *Config,
	pwService *walletunlocker.UnlockerService,
	loaderOpts []btcwallet.LoaderOption, shutdownChan <-chan struct{}) (
	*WalletUnlockParams, error) {

	// Wait for user to provide the password.
	ltndLog.Infof("Waiting for wallet encryption password. Use `lncli " +
		"create` to create a wallet, `lncli unlock` to unlock an " +
		"existing wallet, or `lncli changepassword` to change the " +
		"password of an existing wallet and unlock it.")

	// We currently don't distinguish between getting a password to be used
	// for creation or unlocking, as a new wallet db will be created if
	// none exists when creating the chain control.
	select {

	// The wallet is being created for the first time, we'll check to see
	// if the user provided any entropy for seed creation. If so, then
	// we'll create the wallet early to load the seed.
	case initMsg := <-pwService.InitMsgs:
		password := initMsg.Passphrase
		cipherSeed := initMsg.WalletSeed
		recoveryWindow := initMsg.RecoveryWindow

		// Before we proceed, we'll check the internal version of the
		// seed. If it's greater than the current key derivation
		// version, then we'll return an error as we don't understand
		// this.
		if cipherSeed.InternalVersion != keychain.KeyDerivationVersion {
			return nil, fmt.Errorf("invalid internal "+
				"seed version %v, current version is %v",
				cipherSeed.InternalVersion,
				keychain.KeyDerivationVersion)
		}

		loader, err := btcwallet.NewWalletLoader(
			cfg.ActiveNetParams.Params, recoveryWindow,
			loaderOpts...,
		)
		if err != nil {
			return nil, err
		}

		// With the seed, we can now use the wallet loader to create
		// the wallet, then pass it back to avoid unlocking it again.
		birthday := cipherSeed.BirthdayTime()
		newWallet, err := loader.CreateNewWallet(
			password, password, cipherSeed.Entropy[:], birthday,
		)
		if err != nil {
			// Don't leave the file open in case the new wallet
			// could not be created for whatever reason.
			if err := loader.UnloadWallet(); err != nil {
				ltndLog.Errorf("Could not unload new "+
					"wallet: %v", err)
			}
			return nil, err
		}

		// For new wallets, the ResetWalletTransactions flag is a no-op.
		if cfg.ResetWalletTransactions {
			ltndLog.Warnf("Ignoring reset-wallet-transactions " +
				"flag for new wallet as it has no effect")
		}

		return &WalletUnlockParams{
			Password:        password,
			Birthday:        birthday,
			RecoveryWindow:  recoveryWindow,
			Wallet:          newWallet,
			ChansToRestore:  initMsg.ChanBackups,
			UnloadWallet:    loader.UnloadWallet,
			StatelessInit:   initMsg.StatelessInit,
			MacResponseChan: pwService.MacResponseChan,
		}, nil

	// The wallet has already been created in the past, and is simply being
	// unlocked. So we'll just return these passphrases.
	case unlockMsg := <-pwService.UnlockMsgs:
		// Resetting the transactions is something the user likely only
		// wants to do once so we add a prominent warning to the log to
		// remind the user to turn off the setting again after
		// successful completion.
		if cfg.ResetWalletTransactions {
			ltndLog.Warnf("Dropped all transaction history from " +
				"on-chain wallet. Remember to disable " +
				"reset-wallet-transactions flag for next " +
				"start of lnd")
		}

		return &WalletUnlockParams{
			Password:        unlockMsg.Passphrase,
			RecoveryWindow:  unlockMsg.RecoveryWindow,
			Wallet:          unlockMsg.Wallet,
			ChansToRestore:  unlockMsg.ChanBackups,
			UnloadWallet:    unlockMsg.UnloadWallet,
			StatelessInit:   unlockMsg.StatelessInit,
			MacResponseChan: pwService.MacResponseChan,
		}, nil

	// If we got a shutdown signal we just return with an error immediately
	case <-shutdownChan:
		return nil, fmt.Errorf("shutting down")
	}
}

// initializeDatabases extracts the current databases that we'll use for normal
// operation in the daemon. Two databases are returned: one remote and one
// local. However, only if the replicated database is active will the remote
// database point to a unique database. Otherwise, the local and remote DB will
// both point to the same local database. A function closure that closes all
// opened databases is also returned.
func initializeDatabases(ctx context.Context,
	cfg *Config) (*channeldb.DB, *channeldb.DB, func(), error) {

	ltndLog.Infof("Opening the main database, this might take a few " +
		"minutes...")

	if cfg.DB.Backend == lncfg.BoltBackend {
		ltndLog.Infof("Opening bbolt database, sync_freelist=%v, "+
			"auto_compact=%v", cfg.DB.Bolt.SyncFreelist,
			cfg.DB.Bolt.AutoCompact)
	}

	startOpenTime := time.Now()

	databaseBackends, err := cfg.DB.GetBackends(ctx, cfg.localDatabaseDir())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to obtain database "+
			"backends: %v", err)
	}

	// If the remoteDB is nil, then we'll just open a local DB as normal,
	// having the remote and local pointer be the exact same instance.
	var (
		localChanDB, remoteChanDB *channeldb.DB
		closeFuncs                []func()
	)
	if databaseBackends.RemoteDB == nil {
		// Open the channeldb, which is dedicated to storing channel,
		// and network related metadata.
		localChanDB, err = channeldb.CreateWithBackend(
			databaseBackends.LocalDB,
			channeldb.OptionSetRejectCacheSize(cfg.Caches.RejectCacheSize),
			channeldb.OptionSetChannelCacheSize(cfg.Caches.ChannelCacheSize),
			channeldb.OptionSetBatchCommitInterval(cfg.DB.BatchCommitInterval),
			channeldb.OptionDryRunMigration(cfg.DryRunMigration),
		)
		switch {
		case err == channeldb.ErrDryRunMigrationOK:
			return nil, nil, nil, err

		case err != nil:
			err := fmt.Errorf("unable to open local channeldb: %v", err)
			ltndLog.Error(err)
			return nil, nil, nil, err
		}

		closeFuncs = append(closeFuncs, func() {
			localChanDB.Close()
		})

		remoteChanDB = localChanDB
	} else {
		ltndLog.Infof("Database replication is available! Creating " +
			"local and remote channeldb instances")

		// Otherwise, we'll open two instances, one for the state we
		// only need locally, and the other for things we want to
		// ensure are replicated.
		localChanDB, err = channeldb.CreateWithBackend(
			databaseBackends.LocalDB,
			channeldb.OptionSetRejectCacheSize(cfg.Caches.RejectCacheSize),
			channeldb.OptionSetChannelCacheSize(cfg.Caches.ChannelCacheSize),
			channeldb.OptionSetBatchCommitInterval(cfg.DB.BatchCommitInterval),
			channeldb.OptionDryRunMigration(cfg.DryRunMigration),
		)
		switch {
		// As we want to allow both versions to get thru the dry run
		// migration, we'll only exit the second time here once the
		// remote instance has had a time to migrate as well.
		case err == channeldb.ErrDryRunMigrationOK:
			ltndLog.Infof("Local DB dry run migration successful")

		case err != nil:
			err := fmt.Errorf("unable to open local channeldb: %v", err)
			ltndLog.Error(err)
			return nil, nil, nil, err
		}

		closeFuncs = append(closeFuncs, func() {
			localChanDB.Close()
		})

		ltndLog.Infof("Opening replicated database instance...")

		remoteChanDB, err = channeldb.CreateWithBackend(
			databaseBackends.RemoteDB,
			channeldb.OptionDryRunMigration(cfg.DryRunMigration),
			channeldb.OptionSetBatchCommitInterval(cfg.DB.BatchCommitInterval),
		)
		switch {
		case err == channeldb.ErrDryRunMigrationOK:
			return nil, nil, nil, err

		case err != nil:
			localChanDB.Close()

			err := fmt.Errorf("unable to open remote channeldb: %v", err)
			ltndLog.Error(err)
			return nil, nil, nil, err
		}

		closeFuncs = append(closeFuncs, func() {
			remoteChanDB.Close()
		})
	}

	openTime := time.Since(startOpenTime)
	ltndLog.Infof("Database now open (time_to_open=%v)!", openTime)

	cleanUp := func() {
		for _, closeFunc := range closeFuncs {
			closeFunc()
		}
	}

	return localChanDB, remoteChanDB, cleanUp, nil
}

// initNeutrinoBackend inits a new instance of the neutrino light client
// backend given a target chain directory to store the chain state.
func initNeutrinoBackend(cfg *Config, chainDir string,
	blockCache *blockcache.BlockCache) (*neutrino.ChainService,
	func(), error) {

	// Both channel validation flags are false by default but their meaning
	// is the inverse of each other. Therefore both cannot be true. For
	// every other case, the neutrino.validatechannels overwrites the
	// routing.assumechanvalid value.
	if cfg.NeutrinoMode.ValidateChannels && cfg.Routing.AssumeChannelValid {
		return nil, nil, fmt.Errorf("can't set both " +
			"neutrino.validatechannels and routing." +
			"assumechanvalid to true at the same time")
	}
	cfg.Routing.AssumeChannelValid = !cfg.NeutrinoMode.ValidateChannels

	// First we'll open the database file for neutrino, creating the
	// database if needed. We append the normalized network name here to
	// match the behavior of btcwallet.
	dbPath := filepath.Join(
		chainDir, lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// Ensure that the neutrino db path exists.
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		return nil, nil, err
	}

	dbName := filepath.Join(dbPath, "neutrino.db")
	db, err := walletdb.Create(
		"bdb", dbName, !cfg.SyncFreelist, cfg.DB.Bolt.DBTimeout,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create neutrino "+
			"database: %v", err)
	}

	headerStateAssertion, err := parseHeaderStateAssertion(
		cfg.NeutrinoMode.AssertFilterHeader,
	)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	// With the database open, we can now create an instance of the
	// neutrino light client. We pass in relevant configuration parameters
	// required.
	config := neutrino.Config{
		DataDir:      dbPath,
		Database:     db,
		ChainParams:  *cfg.ActiveNetParams.Params,
		AddPeers:     cfg.NeutrinoMode.AddPeers,
		ConnectPeers: cfg.NeutrinoMode.ConnectPeers,
		Dialer: func(addr net.Addr) (net.Conn, error) {
			dialAddr := addr
			if tor.IsOnionFakeIP(addr) {
				// Because the Neutrino address manager only
				// knows IP addresses, we need to turn any fake
				// tcp6 address that actually encodes an Onion
				// v2 address back into the hostname
				// representation before we can pass it to the
				// dialer.
				var err error
				dialAddr, err = tor.FakeIPToOnionHost(addr)
				if err != nil {
					return nil, err
				}
			}

			return cfg.net.Dial(
				dialAddr.Network(), dialAddr.String(),
				cfg.ConnectionTimeout,
			)
		},
		NameResolver: func(host string) ([]net.IP, error) {
			if tor.IsOnionHost(host) {
				// Neutrino internally uses btcd's address
				// manager which only operates on an IP level
				// and does not understand onion hosts. We need
				// to turn an onion host into a fake
				// representation of an IP address to make it
				// possible to connect to a block filter backend
				// that serves on an Onion v2 hidden service.
				fakeIP, err := tor.OnionHostToFakeIP(host)
				if err != nil {
					return nil, err
				}

				return []net.IP{fakeIP}, nil
			}

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
		AssertFilterHeader: headerStateAssertion,
		BlockCache:         blockCache.Cache,
		BroadcastTimeout:   cfg.NeutrinoMode.BroadcastTimeout,
		PersistToDisk:      cfg.NeutrinoMode.PersistFilters,
	}

	neutrino.MaxPeers = 8
	neutrino.BanDuration = time.Hour * 48
	neutrino.UserAgentName = cfg.NeutrinoMode.UserAgentName
	neutrino.UserAgentVersion = cfg.NeutrinoMode.UserAgentVersion

	neutrinoCS, err := neutrino.NewChainService(config)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("unable to create neutrino light "+
			"client: %v", err)
	}

	if err := neutrinoCS.Start(); err != nil {
		db.Close()
		return nil, nil, err
	}

	cleanUp := func() {
		if err := neutrinoCS.Stop(); err != nil {
			ltndLog.Infof("Unable to stop neutrino light client: %v", err)
		}
		db.Close()
	}

	return neutrinoCS, cleanUp, nil
}

// parseHeaderStateAssertion parses the user-specified neutrino header state
// into a headerfs.FilterHeader.
func parseHeaderStateAssertion(state string) (*headerfs.FilterHeader, error) {
	if len(state) == 0 {
		return nil, nil
	}

	split := strings.Split(state, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("header state assertion %v in "+
			"unexpected format, expected format height:hash", state)
	}

	height, err := strconv.ParseUint(split[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid filter header height: %v", err)
	}

	hash, err := chainhash.NewHashFromStr(split[1])
	if err != nil {
		return nil, fmt.Errorf("invalid filter header hash: %v", err)
	}

	return &headerfs.FilterHeader{
		Height:     uint32(height),
		FilterHash: *hash,
	}, nil
}
