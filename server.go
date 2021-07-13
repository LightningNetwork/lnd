package lnd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image/color"
	"math/big"
	prand "math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/go-errors/errors"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/autopilot"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/chanacceptor"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/chanfitness"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channelnotifier"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/feature"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/healthcheck"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/nat"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/peer"
	"github.com/lightningnetwork/lnd/peernotifier"
	"github.com/lightningnetwork/lnd/pool"
	"github.com/lightningnetwork/lnd/queue"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/routing/localchans"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/subscribe"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/lightningnetwork/lnd/ticker"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/lightningnetwork/lnd/walletunlocker"
	"github.com/lightningnetwork/lnd/watchtower/blob"
	"github.com/lightningnetwork/lnd/watchtower/wtclient"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
)

const (
	// defaultMinPeers is the minimum number of peers nodes should always be
	// connected to.
	defaultMinPeers = 3

	// defaultStableConnDuration is a floor under which all reconnection
	// attempts will apply exponential randomized backoff. Connections
	// durations exceeding this value will be eligible to have their
	// backoffs reduced.
	defaultStableConnDuration = 10 * time.Minute

	// numInstantInitReconnect specifies how many persistent peers we should
	// always attempt outbound connections to immediately. After this value
	// is surpassed, the remaining peers will be randomly delayed using
	// maxInitReconnectDelay.
	numInstantInitReconnect = 10

	// maxInitReconnectDelay specifies the maximum delay in seconds we will
	// apply in attempting to reconnect to persistent peers on startup. The
	// value used or a particular peer will be chosen between 0s and this
	// value.
	maxInitReconnectDelay = 30
)

var (
	// ErrPeerNotConnected signals that the server has no connection to the
	// given peer.
	ErrPeerNotConnected = errors.New("peer is not connected")

	// ErrServerNotActive indicates that the server has started but hasn't
	// fully finished the startup process.
	ErrServerNotActive = errors.New("server is still in the process of " +
		"starting")

	// ErrServerShuttingDown indicates that the server is in the process of
	// gracefully exiting.
	ErrServerShuttingDown = errors.New("server is shutting down")

	// validColorRegexp is a regexp that lets you check if a particular
	// color string matches the standard hex color format #RRGGBB.
	validColorRegexp = regexp.MustCompile("^#[A-Fa-f0-9]{6}$")

	// MaxFundingAmount is a soft-limit of the maximum channel size
	// currently accepted within the Lightning Protocol. This is
	// defined in BOLT-0002, and serves as an initial precautionary limit
	// while implementations are battle tested in the real world.
	//
	// At the moment, this value depends on which chain is active. It is set
	// to the value under the Bitcoin chain as default.
	//
	// TODO(roasbeef): add command line param to modify
	MaxFundingAmount = funding.MaxBtcFundingAmount
)

// errPeerAlreadyConnected is an error returned by the server when we're
// commanded to connect to a peer, but they're already connected.
type errPeerAlreadyConnected struct {
	peer *peer.Brontide
}

// Error returns the human readable version of this error type.
//
// NOTE: Part of the error interface.
func (e *errPeerAlreadyConnected) Error() string {
	return fmt.Sprintf("already connected to peer: %v", e.peer)
}

// server is the main server of the Lightning Network Daemon. The server houses
// global state pertaining to the wallet, database, and the rpcserver.
// Additionally, the server is also used as a central messaging bus to interact
// with any of its companion objects.
type server struct {
	active   int32 // atomic
	stopping int32 // atomic

	start sync.Once
	stop  sync.Once

	cfg *Config

	// identityECDH is an ECDH capable wrapper for the private key used
	// to authenticate any incoming connections.
	identityECDH keychain.SingleKeyECDH

	// nodeSigner is an implementation of the MessageSigner implementation
	// that's backed by the identity private key of the running lnd node.
	nodeSigner *netann.NodeSigner

	chanStatusMgr *netann.ChanStatusManager

	// listenAddrs is the list of addresses the server is currently
	// listening on.
	listenAddrs []net.Addr

	// torController is a client that will communicate with a locally
	// running Tor server. This client will handle initiating and
	// authenticating the connection to the Tor server, automatically
	// creating and setting up onion services, etc.
	torController *tor.Controller

	// natTraversal is the specific NAT traversal technique used to
	// automatically set up port forwarding rules in order to advertise to
	// the network that the node is accepting inbound connections.
	natTraversal nat.Traversal

	// lastDetectedIP is the last IP detected by the NAT traversal technique
	// above. This IP will be watched periodically in a goroutine in order
	// to handle dynamic IP changes.
	lastDetectedIP net.IP

	mu         sync.RWMutex
	peersByPub map[string]*peer.Brontide

	inboundPeers  map[string]*peer.Brontide
	outboundPeers map[string]*peer.Brontide

	peerConnectedListeners    map[string][]chan<- lnpeer.Peer
	peerDisconnectedListeners map[string][]chan<- struct{}

	persistentPeers        map[string]bool
	persistentPeersBackoff map[string]time.Duration
	persistentConnReqs     map[string][]*connmgr.ConnReq
	persistentRetryCancels map[string]chan struct{}

	// peerErrors keeps a set of peer error buffers for peers that have
	// disconnected from us. This allows us to track historic peer errors
	// over connections. The string of the peer's compressed pubkey is used
	// as a key for this map.
	peerErrors map[string]*queue.CircularBuffer

	// ignorePeerTermination tracks peers for which the server has initiated
	// a disconnect. Adding a peer to this map causes the peer termination
	// watcher to short circuit in the event that peers are purposefully
	// disconnected.
	ignorePeerTermination map[*peer.Brontide]struct{}

	// scheduledPeerConnection maps a pubkey string to a callback that
	// should be executed in the peerTerminationWatcher the prior peer with
	// the same pubkey exits.  This allows the server to wait until the
	// prior peer has cleaned up successfully, before adding the new peer
	// intended to replace it.
	scheduledPeerConnection map[string]func()

	cc *chainreg.ChainControl

	fundingMgr *funding.Manager

	localChanDB *channeldb.DB

	remoteChanDB *channeldb.DB

	htlcSwitch *htlcswitch.Switch

	interceptableSwitch *htlcswitch.InterceptableSwitch

	invoices *invoices.InvoiceRegistry

	channelNotifier *channelnotifier.ChannelNotifier

	peerNotifier *peernotifier.PeerNotifier

	htlcNotifier *htlcswitch.HtlcNotifier

	witnessBeacon contractcourt.WitnessBeacon

	breachArbiter *breachArbiter

	missionControl *routing.MissionControl

	chanRouter *routing.ChannelRouter

	controlTower routing.ControlTower

	authGossiper *discovery.AuthenticatedGossiper

	localChanMgr *localchans.Manager

	utxoNursery *utxoNursery

	sweeper *sweep.UtxoSweeper

	chainArb *contractcourt.ChainArbitrator

	sphinx *hop.OnionProcessor

	towerClient wtclient.Client

	anchorTowerClient wtclient.Client

	connMgr *connmgr.ConnManager

	sigPool *lnwallet.SigPool

	writePool *pool.Write

	readPool *pool.Read

	// featureMgr dispatches feature vectors for various contexts within the
	// daemon.
	featureMgr *feature.Manager

	// currentNodeAnn is the node announcement that has been broadcast to
	// the network upon startup, if the attributes of the node (us) has
	// changed since last start.
	currentNodeAnn *lnwire.NodeAnnouncement

	// chansToRestore is the set of channels that upon starting, the server
	// should attempt to restore/recover.
	chansToRestore walletunlocker.ChannelsToRecover

	// chanSubSwapper is a sub-system that will ensure our on-disk channel
	// backups are consistent at all times. It interacts with the
	// channelNotifier to be notified of newly opened and closed channels.
	chanSubSwapper *chanbackup.SubSwapper

	// chanEventStore tracks the behaviour of channels and their remote peers to
	// provide insights into their health and performance.
	chanEventStore *chanfitness.ChannelEventStore

	hostAnn *netann.HostAnnouncer

	// livelinessMonitor monitors that lnd has access to critical resources.
	livelinessMonitor *healthcheck.Monitor

	customMessageServer *subscribe.Server

	quit chan struct{}

	wg sync.WaitGroup
}

type CustomMessage struct {
	Peer [33]byte
	Msg  *lnwire.Custom
}

// parseAddr parses an address from its string format to a net.Addr.
func parseAddr(address string, netCfg tor.Net) (net.Addr, error) {
	var (
		host string
		port int
	)

	// Split the address into its host and port components.
	h, p, err := net.SplitHostPort(address)
	if err != nil {
		// If a port wasn't specified, we'll assume the address only
		// contains the host so we'll use the default port.
		host = address
		port = defaultPeerPort
	} else {
		// Otherwise, we'll note both the host and ports.
		host = h
		portNum, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		port = portNum
	}

	if tor.IsOnionHost(host) {
		return &tor.OnionAddr{OnionService: host, Port: port}, nil
	}

	// If the host is part of a TCP address, we'll use the network
	// specific ResolveTCPAddr function in order to resolve these
	// addresses over Tor in order to prevent leaking your real IP
	// address.
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	return netCfg.ResolveTCPAddr("tcp", hostPort)
}

// noiseDial is a factory function which creates a connmgr compliant dialing
// function by returning a closure which includes the server's identity key.
func noiseDial(idKey keychain.SingleKeyECDH,
	netCfg tor.Net, timeout time.Duration) func(net.Addr) (net.Conn, error) {

	return func(a net.Addr) (net.Conn, error) {
		lnAddr := a.(*lnwire.NetAddress)
		return brontide.Dial(idKey, lnAddr, timeout, netCfg.Dial)
	}
}

// newServer creates a new instance of the server which is to listen using the
// passed listener address.
func newServer(cfg *Config, listenAddrs []net.Addr,
	localChanDB, remoteChanDB *channeldb.DB,
	towerClientDB wtclient.DB, cc *chainreg.ChainControl,
	nodeKeyDesc *keychain.KeyDescriptor,
	chansToRestore walletunlocker.ChannelsToRecover,
	chanPredicate chanacceptor.ChannelAcceptor,
	torController *tor.Controller) (*server, error) {

	var (
		err           error
		nodeKeyECDH   = keychain.NewPubKeyECDH(*nodeKeyDesc, cc.KeyRing)
		nodeKeySigner = keychain.NewPubKeyDigestSigner(
			*nodeKeyDesc, cc.KeyRing,
		)
	)

	listeners := make([]net.Listener, len(listenAddrs))
	for i, listenAddr := range listenAddrs {
		// Note: though brontide.NewListener uses ResolveTCPAddr, it
		// doesn't need to call the general lndResolveTCP function
		// since we are resolving a local address.
		listeners[i], err = brontide.NewListener(
			nodeKeyECDH, listenAddr.String(),
		)
		if err != nil {
			return nil, err
		}
	}

	var serializedPubKey [33]byte
	copy(serializedPubKey[:], nodeKeyECDH.PubKey().SerializeCompressed())

	// Initialize the sphinx router, placing it's persistent replay log in
	// the same directory as the channel graph database. We don't need to
	// replicate this data, so we'll store it locally.
	replayLog := htlcswitch.NewDecayedLog(
		cfg.localDatabaseDir(), defaultSphinxDbName, cfg.DB.Bolt,
		cc.ChainNotifier,
	)
	sphinxRouter := sphinx.NewRouter(
		nodeKeyECDH, cfg.ActiveNetParams.Params, replayLog,
	)

	writeBufferPool := pool.NewWriteBuffer(
		pool.DefaultWriteBufferGCInterval,
		pool.DefaultWriteBufferExpiryInterval,
	)

	writePool := pool.NewWrite(
		writeBufferPool, cfg.Workers.Write, pool.DefaultWorkerTimeout,
	)

	readBufferPool := pool.NewReadBuffer(
		pool.DefaultReadBufferGCInterval,
		pool.DefaultReadBufferExpiryInterval,
	)

	readPool := pool.NewRead(
		readBufferPool, cfg.Workers.Read, pool.DefaultWorkerTimeout,
	)

	featureMgr, err := feature.NewManager(feature.Config{
		NoTLVOnion:        cfg.ProtocolOptions.LegacyOnion(),
		NoStaticRemoteKey: cfg.ProtocolOptions.NoStaticRemoteKey(),
		NoAnchors:         cfg.ProtocolOptions.NoAnchorCommitments(),
		NoWumbo:           !cfg.ProtocolOptions.Wumbo(),
	})
	if err != nil {
		return nil, err
	}

	registryConfig := invoices.RegistryConfig{
		FinalCltvRejectDelta:        lncfg.DefaultFinalCltvRejectDelta,
		HtlcHoldDuration:            invoices.DefaultHtlcHoldDuration,
		Clock:                       clock.NewDefaultClock(),
		AcceptKeySend:               cfg.AcceptKeySend,
		AcceptAMP:                   cfg.AcceptAMP,
		GcCanceledInvoicesOnStartup: cfg.GcCanceledInvoicesOnStartup,
		GcCanceledInvoicesOnTheFly:  cfg.GcCanceledInvoicesOnTheFly,
		KeysendHoldTime:             cfg.KeysendHoldTime,
	}

	s := &server{
		cfg:            cfg,
		localChanDB:    localChanDB,
		remoteChanDB:   remoteChanDB,
		cc:             cc,
		sigPool:        lnwallet.NewSigPool(cfg.Workers.Sig, cc.Signer),
		writePool:      writePool,
		readPool:       readPool,
		chansToRestore: chansToRestore,

		channelNotifier: channelnotifier.New(remoteChanDB),

		identityECDH: nodeKeyECDH,
		nodeSigner:   netann.NewNodeSigner(nodeKeySigner),

		listenAddrs: listenAddrs,

		// TODO(roasbeef): derive proper onion key based on rotation
		// schedule
		sphinx: hop.NewOnionProcessor(sphinxRouter),

		torController: torController,

		persistentPeers:         make(map[string]bool),
		persistentPeersBackoff:  make(map[string]time.Duration),
		persistentConnReqs:      make(map[string][]*connmgr.ConnReq),
		persistentRetryCancels:  make(map[string]chan struct{}),
		peerErrors:              make(map[string]*queue.CircularBuffer),
		ignorePeerTermination:   make(map[*peer.Brontide]struct{}),
		scheduledPeerConnection: make(map[string]func()),

		peersByPub:                make(map[string]*peer.Brontide),
		inboundPeers:              make(map[string]*peer.Brontide),
		outboundPeers:             make(map[string]*peer.Brontide),
		peerConnectedListeners:    make(map[string][]chan<- lnpeer.Peer),
		peerDisconnectedListeners: make(map[string][]chan<- struct{}),

		customMessageServer: subscribe.NewServer(),

		featureMgr: featureMgr,
		quit:       make(chan struct{}),
	}

	s.witnessBeacon = &preimageBeacon{
		wCache:      remoteChanDB.NewWitnessCache(),
		subscribers: make(map[uint64]*preimageSubscriber),
	}

	currentHash, currentHeight, err := s.cc.ChainIO.GetBestBlock()
	if err != nil {
		return nil, err
	}

	expiryWatcher := invoices.NewInvoiceExpiryWatcher(
		clock.NewDefaultClock(), cfg.Invoices.HoldExpiryDelta,
		uint32(currentHeight), currentHash, cc.ChainNotifier,
	)
	s.invoices = invoices.NewRegistry(
		remoteChanDB, expiryWatcher, &registryConfig,
	)

	s.htlcNotifier = htlcswitch.NewHtlcNotifier(time.Now)

	s.htlcSwitch, err = htlcswitch.New(htlcswitch.Config{
		DB: remoteChanDB,
		LocalChannelClose: func(pubKey []byte,
			request *htlcswitch.ChanClose) {

			peer, err := s.FindPeerByPubStr(string(pubKey))
			if err != nil {
				srvrLog.Errorf("unable to close channel, peer"+
					" with %v id can't be found: %v",
					pubKey, err,
				)
				return
			}

			peer.HandleLocalCloseChanReqs(request)
		},
		FwdingLog:              remoteChanDB.ForwardingLog(),
		SwitchPackager:         channeldb.NewSwitchPackager(),
		ExtractErrorEncrypter:  s.sphinx.ExtractErrorEncrypter,
		FetchLastChannelUpdate: s.fetchLastChanUpdate(),
		Notifier:               s.cc.ChainNotifier,
		HtlcNotifier:           s.htlcNotifier,
		FwdEventTicker:         ticker.New(htlcswitch.DefaultFwdEventInterval),
		LogEventTicker:         ticker.New(htlcswitch.DefaultLogInterval),
		AckEventTicker:         ticker.New(htlcswitch.DefaultAckInterval),
		AllowCircularRoute:     cfg.AllowCircularRoute,
		RejectHTLC:             cfg.RejectHTLC,
		Clock:                  clock.NewDefaultClock(),
		HTLCExpiry:             htlcswitch.DefaultHTLCExpiry,
	}, uint32(currentHeight))
	if err != nil {
		return nil, err
	}
	s.interceptableSwitch = htlcswitch.NewInterceptableSwitch(s.htlcSwitch)

	chanStatusMgrCfg := &netann.ChanStatusConfig{
		ChanStatusSampleInterval: cfg.ChanStatusSampleInterval,
		ChanEnableTimeout:        cfg.ChanEnableTimeout,
		ChanDisableTimeout:       cfg.ChanDisableTimeout,
		OurPubKey:                nodeKeyECDH.PubKey(),
		MessageSigner:            s.nodeSigner,
		IsChannelActive:          s.htlcSwitch.HasActiveLink,
		ApplyChannelUpdate:       s.applyChannelUpdate,
		DB:                       remoteChanDB,
		Graph:                    localChanDB.ChannelGraph(),
	}

	chanStatusMgr, err := netann.NewChanStatusManager(chanStatusMgrCfg)
	if err != nil {
		return nil, err
	}
	s.chanStatusMgr = chanStatusMgr

	// If enabled, use either UPnP or NAT-PMP to automatically configure
	// port forwarding for users behind a NAT.
	if cfg.NAT {
		srvrLog.Info("Scanning local network for a UPnP enabled device")

		discoveryTimeout := time.Duration(10 * time.Second)

		ctx, cancel := context.WithTimeout(
			context.Background(), discoveryTimeout,
		)
		defer cancel()
		upnp, err := nat.DiscoverUPnP(ctx)
		if err == nil {
			s.natTraversal = upnp
		} else {
			// If we were not able to discover a UPnP enabled device
			// on the local network, we'll fall back to attempting
			// to discover a NAT-PMP enabled device.
			srvrLog.Errorf("Unable to discover a UPnP enabled "+
				"device on the local network: %v", err)

			srvrLog.Info("Scanning local network for a NAT-PMP " +
				"enabled device")

			pmp, err := nat.DiscoverPMP(discoveryTimeout)
			if err != nil {
				err := fmt.Errorf("unable to discover a "+
					"NAT-PMP enabled device on the local "+
					"network: %v", err)
				srvrLog.Error(err)
				return nil, err
			}

			s.natTraversal = pmp
		}
	}

	// If we were requested to automatically configure port forwarding,
	// we'll use the ports that the server will be listening on.
	externalIPStrings := make([]string, len(cfg.ExternalIPs))
	for idx, ip := range cfg.ExternalIPs {
		externalIPStrings[idx] = ip.String()
	}
	if s.natTraversal != nil {
		listenPorts := make([]uint16, 0, len(listenAddrs))
		for _, listenAddr := range listenAddrs {
			// At this point, the listen addresses should have
			// already been normalized, so it's safe to ignore the
			// errors.
			_, portStr, _ := net.SplitHostPort(listenAddr.String())
			port, _ := strconv.Atoi(portStr)

			listenPorts = append(listenPorts, uint16(port))
		}

		ips, err := s.configurePortForwarding(listenPorts...)
		if err != nil {
			srvrLog.Errorf("Unable to automatically set up port "+
				"forwarding using %s: %v",
				s.natTraversal.Name(), err)
		} else {
			srvrLog.Infof("Automatically set up port forwarding "+
				"using %s to advertise external IP",
				s.natTraversal.Name())
			externalIPStrings = append(externalIPStrings, ips...)
		}
	}

	// If external IP addresses have been specified, add those to the list
	// of this server's addresses.
	externalIPs, err := lncfg.NormalizeAddresses(
		externalIPStrings, strconv.Itoa(defaultPeerPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, err
	}

	selfAddrs := make([]net.Addr, 0, len(externalIPs))
	selfAddrs = append(selfAddrs, externalIPs...)

	// As the graph can be obtained at anytime from the network, we won't
	// replicate it, and instead it'll only be stored locally.
	chanGraph := localChanDB.ChannelGraph()

	// We'll now reconstruct a node announcement based on our current
	// configuration so we can send it out as a sort of heart beat within
	// the network.
	//
	// We'll start by parsing the node color from configuration.
	color, err := parseHexColor(cfg.Color)
	if err != nil {
		srvrLog.Errorf("unable to parse color: %v\n", err)
		return nil, err
	}

	// If no alias is provided, default to first 10 characters of public
	// key.
	alias := cfg.Alias
	if alias == "" {
		alias = hex.EncodeToString(serializedPubKey[:10])
	}
	nodeAlias, err := lnwire.NewNodeAlias(alias)
	if err != nil {
		return nil, err
	}
	selfNode := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           time.Now(),
		Addresses:            selfAddrs,
		Alias:                nodeAlias.String(),
		Features:             s.featureMgr.Get(feature.SetNodeAnn),
		Color:                color,
	}
	copy(selfNode.PubKeyBytes[:], nodeKeyECDH.PubKey().SerializeCompressed())

	// Based on the disk representation of the node announcement generated
	// above, we'll generate a node announcement that can go out on the
	// network so we can properly sign it.
	nodeAnn, err := selfNode.NodeAnnouncement(false)
	if err != nil {
		return nil, fmt.Errorf("unable to gen self node ann: %v", err)
	}

	// With the announcement generated, we'll sign it to properly
	// authenticate the message on the network.
	authSig, err := netann.SignAnnouncement(
		s.nodeSigner, nodeKeyECDH.PubKey(), nodeAnn,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate signature for "+
			"self node announcement: %v", err)
	}
	selfNode.AuthSigBytes = authSig.Serialize()
	nodeAnn.Signature, err = lnwire.NewSigFromRawSignature(
		selfNode.AuthSigBytes,
	)
	if err != nil {
		return nil, err
	}

	// Finally, we'll update the representation on disk, and update our
	// cached in-memory version as well.
	if err := chanGraph.SetSourceNode(selfNode); err != nil {
		return nil, fmt.Errorf("can't set self node: %v", err)
	}
	s.currentNodeAnn = nodeAnn

	// The router will get access to the payment ID sequencer, such that it
	// can generate unique payment IDs.
	sequencer, err := htlcswitch.NewPersistentSequencer(remoteChanDB)
	if err != nil {
		return nil, err
	}

	queryBandwidth := func(edge *channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi {
		cid := lnwire.NewChanIDFromOutPoint(&edge.ChannelPoint)
		link, err := s.htlcSwitch.GetLink(cid)
		if err != nil {
			// If the link isn't online, then we'll report
			// that it has zero bandwidth to the router.
			return 0
		}

		// If the link is found within the switch, but it isn't
		// yet eligible to forward any HTLCs, then we'll treat
		// it as if it isn't online in the first place.
		if !link.EligibleToForward() {
			return 0
		}

		// If our link isn't currently in a state where it can
		// add another outgoing htlc, treat the link as unusable.
		if err := link.MayAddOutgoingHtlc(); err != nil {
			return 0
		}

		// Otherwise, we'll return the current best estimate
		// for the available bandwidth for the link.
		return link.Bandwidth()
	}

	// Instantiate mission control with config from the sub server.
	//
	// TODO(joostjager): When we are further in the process of moving to sub
	// servers, the mission control instance itself can be moved there too.
	routingConfig := routerrpc.GetRoutingConfig(cfg.SubRPCServers.RouterRPC)

	estimatorCfg := routing.ProbabilityEstimatorCfg{
		AprioriHopProbability: routingConfig.AprioriHopProbability,
		PenaltyHalfLife:       routingConfig.PenaltyHalfLife,
		AprioriWeight:         routingConfig.AprioriWeight,
	}

	s.missionControl, err = routing.NewMissionControl(
		remoteChanDB, selfNode.PubKeyBytes,
		&routing.MissionControlConfig{
			ProbabilityEstimatorCfg: estimatorCfg,
			MaxMcHistory:            routingConfig.MaxMcHistory,
			MinFailureRelaxInterval: routing.DefaultMinFailureRelaxInterval,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("can't create mission control: %v", err)
	}

	srvrLog.Debugf("Instantiating payment session source with config: "+
		"AttemptCost=%v + %v%%, MinRouteProbability=%v",
		int64(routingConfig.AttemptCost),
		float64(routingConfig.AttemptCostPPM)/10000,
		routingConfig.MinRouteProbability)

	pathFindingConfig := routing.PathFindingConfig{
		AttemptCost: lnwire.NewMSatFromSatoshis(
			routingConfig.AttemptCost,
		),
		AttemptCostPPM: routingConfig.AttemptCostPPM,
		MinProbability: routingConfig.MinRouteProbability,
	}

	paymentSessionSource := &routing.SessionSource{
		Graph:             chanGraph,
		MissionControl:    s.missionControl,
		QueryBandwidth:    queryBandwidth,
		PathFindingConfig: pathFindingConfig,
	}

	paymentControl := channeldb.NewPaymentControl(remoteChanDB)

	s.controlTower = routing.NewControlTower(paymentControl)

	strictPruning := (cfg.Bitcoin.Node == "neutrino" ||
		cfg.Routing.StrictZombiePruning)
	s.chanRouter, err = routing.New(routing.Config{
		Graph:               chanGraph,
		Chain:               cc.ChainIO,
		ChainView:           cc.ChainView,
		Payer:               s.htlcSwitch,
		Control:             s.controlTower,
		MissionControl:      s.missionControl,
		SessionSource:       paymentSessionSource,
		ChannelPruneExpiry:  routing.DefaultChannelPruneExpiry,
		GraphPruneInterval:  time.Hour,
		FirstTimePruneDelay: routing.DefaultFirstTimePruneDelay,
		QueryBandwidth:      queryBandwidth,
		AssumeChannelValid:  cfg.Routing.AssumeChannelValid,
		NextPaymentID:       sequencer.NextID,
		PathFindingConfig:   pathFindingConfig,
		Clock:               clock.NewDefaultClock(),
		StrictZombiePruning: strictPruning,
	})
	if err != nil {
		return nil, fmt.Errorf("can't create router: %v", err)
	}

	chanSeries := discovery.NewChanSeries(s.localChanDB.ChannelGraph())
	gossipMessageStore, err := discovery.NewMessageStore(s.remoteChanDB)
	if err != nil {
		return nil, err
	}
	waitingProofStore, err := channeldb.NewWaitingProofStore(s.remoteChanDB)
	if err != nil {
		return nil, err
	}

	s.authGossiper = discovery.New(discovery.Config{
		Router:            s.chanRouter,
		Notifier:          s.cc.ChainNotifier,
		ChainHash:         *s.cfg.ActiveNetParams.GenesisHash,
		Broadcast:         s.BroadcastMessage,
		ChanSeries:        chanSeries,
		NotifyWhenOnline:  s.NotifyWhenOnline,
		NotifyWhenOffline: s.NotifyWhenOffline,
		SelfNodeAnnouncement: func(refresh bool) (lnwire.NodeAnnouncement, error) {
			return s.genNodeAnnouncement(refresh)
		},
		ProofMatureDelta:        0,
		TrickleDelay:            time.Millisecond * time.Duration(cfg.TrickleDelay),
		RetransmitTicker:        ticker.New(time.Minute * 30),
		RebroadcastInterval:     time.Hour * 24,
		WaitingProofStore:       waitingProofStore,
		MessageStore:            gossipMessageStore,
		AnnSigner:               s.nodeSigner,
		RotateTicker:            ticker.New(discovery.DefaultSyncerRotationInterval),
		HistoricalSyncTicker:    ticker.New(cfg.HistoricalSyncInterval),
		NumActiveSyncers:        cfg.NumGraphSyncPeers,
		MinimumBatchSize:        10,
		SubBatchDelay:           time.Second * 5,
		IgnoreHistoricalFilters: cfg.IgnoreHistoricalGossipFilters,
		PinnedSyncers:           cfg.Gossip.PinnedSyncers,
		MaxChannelUpdateBurst:   cfg.Gossip.MaxChannelUpdateBurst,
		ChannelUpdateInterval:   cfg.Gossip.ChannelUpdateInterval,
	},
		nodeKeyECDH.PubKey(),
	)

	s.localChanMgr = &localchans.Manager{
		ForAllOutgoingChannels:    s.chanRouter.ForAllOutgoingChannels,
		PropagateChanPolicyUpdate: s.authGossiper.PropagateChanPolicyUpdate,
		UpdateForwardingPolicies:  s.htlcSwitch.UpdateForwardingPolicies,
		FetchChannel:              s.remoteChanDB.FetchChannel,
	}

	utxnStore, err := newNurseryStore(s.cfg.ActiveNetParams.GenesisHash, remoteChanDB)
	if err != nil {
		srvrLog.Errorf("unable to create nursery store: %v", err)
		return nil, err
	}

	srvrLog.Tracef("Sweeper batch window duration: %v",
		sweep.DefaultBatchWindowDuration)

	sweeperStore, err := sweep.NewSweeperStore(
		remoteChanDB, s.cfg.ActiveNetParams.GenesisHash,
	)
	if err != nil {
		srvrLog.Errorf("unable to create sweeper store: %v", err)
		return nil, err
	}

	s.sweeper = sweep.New(&sweep.UtxoSweeperConfig{
		FeeEstimator:   cc.FeeEstimator,
		GenSweepScript: newSweepPkScriptGen(cc.Wallet),
		Signer:         cc.Wallet.Cfg.Signer,
		Wallet:         cc.Wallet,
		NewBatchTimer: func() <-chan time.Time {
			return time.NewTimer(sweep.DefaultBatchWindowDuration).C
		},
		Notifier:             cc.ChainNotifier,
		Store:                sweeperStore,
		MaxInputsPerTx:       sweep.DefaultMaxInputsPerTx,
		MaxSweepAttempts:     sweep.DefaultMaxSweepAttempts,
		NextAttemptDeltaFunc: sweep.DefaultNextAttemptDeltaFunc,
		MaxFeeRate:           sweep.DefaultMaxFeeRate,
		FeeRateBucketSize:    sweep.DefaultFeeRateBucketSize,
	})

	s.utxoNursery = newUtxoNursery(&NurseryConfig{
		ChainIO:             cc.ChainIO,
		ConfDepth:           1,
		FetchClosedChannels: remoteChanDB.FetchClosedChannels,
		FetchClosedChannel:  remoteChanDB.FetchClosedChannel,
		Notifier:            cc.ChainNotifier,
		PublishTransaction:  cc.Wallet.PublishTransaction,
		Store:               utxnStore,
		SweepInput:          s.sweeper.SweepInput,
	})

	// Construct a closure that wraps the htlcswitch's CloseLink method.
	closeLink := func(chanPoint *wire.OutPoint,
		closureType htlcswitch.ChannelCloseType) {
		// TODO(conner): Properly respect the update and error channels
		// returned by CloseLink.

		// Instruct the switch to close the channel.  Provide no close out
		// delivery script or target fee per kw because user input is not
		// available when the remote peer closes the channel.
		s.htlcSwitch.CloseLink(chanPoint, closureType, 0, nil)
	}

	// We will use the following channel to reliably hand off contract
	// breach events from the ChannelArbitrator to the breachArbiter,
	contractBreaches := make(chan *ContractBreachEvent, 1)

	s.chainArb = contractcourt.NewChainArbitrator(contractcourt.ChainArbitratorConfig{
		ChainHash:              *s.cfg.ActiveNetParams.GenesisHash,
		IncomingBroadcastDelta: lncfg.DefaultIncomingBroadcastDelta,
		OutgoingBroadcastDelta: lncfg.DefaultOutgoingBroadcastDelta,
		NewSweepAddr:           newSweepPkScriptGen(cc.Wallet),
		PublishTx:              cc.Wallet.PublishTransaction,
		DeliverResolutionMsg: func(msgs ...contractcourt.ResolutionMsg) error {
			for _, msg := range msgs {
				err := s.htlcSwitch.ProcessContractResolution(msg)
				if err != nil {
					return err
				}
			}
			return nil
		},
		IncubateOutputs: func(chanPoint wire.OutPoint,
			outHtlcRes *lnwallet.OutgoingHtlcResolution,
			inHtlcRes *lnwallet.IncomingHtlcResolution,
			broadcastHeight uint32) error {

			var (
				inRes  []lnwallet.IncomingHtlcResolution
				outRes []lnwallet.OutgoingHtlcResolution
			)
			if inHtlcRes != nil {
				inRes = append(inRes, *inHtlcRes)
			}
			if outHtlcRes != nil {
				outRes = append(outRes, *outHtlcRes)
			}

			return s.utxoNursery.IncubateOutputs(
				chanPoint, outRes, inRes,
				broadcastHeight,
			)
		},
		PreimageDB:   s.witnessBeacon,
		Notifier:     cc.ChainNotifier,
		Signer:       cc.Wallet.Cfg.Signer,
		FeeEstimator: cc.FeeEstimator,
		ChainIO:      cc.ChainIO,
		MarkLinkInactive: func(chanPoint wire.OutPoint) error {
			chanID := lnwire.NewChanIDFromOutPoint(&chanPoint)
			s.htlcSwitch.RemoveLink(chanID)
			return nil
		},
		IsOurAddress: cc.Wallet.IsOurAddress,
		ContractBreach: func(chanPoint wire.OutPoint,
			breachRet *lnwallet.BreachRetribution,
			markClosed func() error) error {

			// processACK will handle the breachArbiter ACKing the
			// event.
			finalErr := make(chan error, 1)
			processACK := func(brarErr error) {
				if brarErr != nil {
					finalErr <- brarErr
					return
				}

				// If the breachArbiter successfully handled
				// the event, we can mark the channel closed.
				finalErr <- markClosed()
			}

			event := &ContractBreachEvent{
				ChanPoint:         chanPoint,
				ProcessACK:        processACK,
				BreachRetribution: breachRet,
			}

			// Send the contract breach event to the breachArbiter.
			select {
			case contractBreaches <- event:
			case <-s.quit:
				return ErrServerShuttingDown
			}

			// We'll wait for a final error to be available, either
			// from the breachArbiter or from our markClosed
			// function closure.
			select {
			case err := <-finalErr:
				return err
			case <-s.quit:
				return ErrServerShuttingDown
			}
		},
		DisableChannel: func(chanPoint wire.OutPoint) error {
			return s.chanStatusMgr.RequestDisable(chanPoint, false)
		},
		Sweeper:                       s.sweeper,
		Registry:                      s.invoices,
		NotifyClosedChannel:           s.channelNotifier.NotifyClosedChannelEvent,
		OnionProcessor:                s.sphinx,
		PaymentsExpirationGracePeriod: cfg.PaymentsExpirationGracePeriod,
		IsForwardedHTLC:               s.htlcSwitch.IsForwardedHTLC,
		Clock:                         clock.NewDefaultClock(),
	}, remoteChanDB)

	s.breachArbiter = newBreachArbiter(&BreachConfig{
		CloseLink:          closeLink,
		DB:                 remoteChanDB,
		Estimator:          s.cc.FeeEstimator,
		GenSweepScript:     newSweepPkScriptGen(cc.Wallet),
		Notifier:           cc.ChainNotifier,
		PublishTransaction: cc.Wallet.PublishTransaction,
		ContractBreaches:   contractBreaches,
		Signer:             cc.Wallet.Cfg.Signer,
		Store:              newRetributionStore(remoteChanDB),
	})

	// Select the configuration and furnding parameters for Bitcoin or
	// Litecoin, depending on the primary registered chain.
	primaryChain := cfg.registeredChains.PrimaryChain()
	chainCfg := cfg.Bitcoin
	minRemoteDelay := funding.MinBtcRemoteDelay
	maxRemoteDelay := funding.MaxBtcRemoteDelay
	if primaryChain == chainreg.LitecoinChain {
		chainCfg = cfg.Litecoin
		minRemoteDelay = funding.MinLtcRemoteDelay
		maxRemoteDelay = funding.MaxLtcRemoteDelay
	}

	var chanIDSeed [32]byte
	if _, err := rand.Read(chanIDSeed[:]); err != nil {
		return nil, err
	}

	s.fundingMgr, err = funding.NewFundingManager(funding.Config{
		NoWumboChans:       !cfg.ProtocolOptions.Wumbo(),
		IDKey:              nodeKeyECDH.PubKey(),
		Wallet:             cc.Wallet,
		PublishTransaction: cc.Wallet.PublishTransaction,
		UpdateLabel: func(hash chainhash.Hash, label string) error {
			return cc.Wallet.LabelTransaction(hash, label, true)
		},
		Notifier:     cc.ChainNotifier,
		FeeEstimator: cc.FeeEstimator,
		SignMessage: func(pubKey *btcec.PublicKey,
			msg []byte) (input.Signature, error) {

			if pubKey.IsEqual(nodeKeyECDH.PubKey()) {
				return s.nodeSigner.SignMessage(pubKey, msg)
			}

			return cc.MsgSigner.SignMessage(pubKey, msg)
		},
		CurrentNodeAnnouncement: func() (lnwire.NodeAnnouncement, error) {
			return s.genNodeAnnouncement(true)
		},
		SendAnnouncement: s.authGossiper.ProcessLocalAnnouncement,
		NotifyWhenOnline: s.NotifyWhenOnline,
		TempChanIDSeed:   chanIDSeed,
		FindChannel: func(chanID lnwire.ChannelID) (
			*channeldb.OpenChannel, error) {

			dbChannels, err := remoteChanDB.FetchAllChannels()
			if err != nil {
				return nil, err
			}

			for _, channel := range dbChannels {
				if chanID.IsChanPoint(&channel.FundingOutpoint) {
					return channel, nil
				}
			}

			return nil, fmt.Errorf("unable to find channel")
		},
		DefaultRoutingPolicy: cc.RoutingPolicy,
		DefaultMinHtlcIn:     cc.MinHtlcIn,
		NumRequiredConfs: func(chanAmt btcutil.Amount,
			pushAmt lnwire.MilliSatoshi) uint16 {
			// For large channels we increase the number
			// of confirmations we require for the
			// channel to be considered open. As it is
			// always the responder that gets to choose
			// value, the pushAmt is value being pushed
			// to us. This means we have more to lose
			// in the case this gets re-orged out, and
			// we will require more confirmations before
			// we consider it open.
			// TODO(halseth): Use Litecoin params in case
			// of LTC channels.

			// In case the user has explicitly specified
			// a default value for the number of
			// confirmations, we use it.
			defaultConf := uint16(chainCfg.DefaultNumChanConfs)
			if defaultConf != 0 {
				return defaultConf
			}

			minConf := uint64(3)
			maxConf := uint64(6)

			// If this is a wumbo channel, then we'll require the
			// max amount of confirmations.
			if chanAmt > MaxFundingAmount {
				return uint16(maxConf)
			}

			// If not we return a value scaled linearly
			// between 3 and 6, depending on channel size.
			// TODO(halseth): Use 1 as minimum?
			maxChannelSize := uint64(
				lnwire.NewMSatFromSatoshis(MaxFundingAmount))
			stake := lnwire.NewMSatFromSatoshis(chanAmt) + pushAmt
			conf := maxConf * uint64(stake) / maxChannelSize
			if conf < minConf {
				conf = minConf
			}
			if conf > maxConf {
				conf = maxConf
			}
			return uint16(conf)
		},
		RequiredRemoteDelay: func(chanAmt btcutil.Amount) uint16 {
			// We scale the remote CSV delay (the time the
			// remote have to claim funds in case of a unilateral
			// close) linearly from minRemoteDelay blocks
			// for small channels, to maxRemoteDelay blocks
			// for channels of size MaxFundingAmount.
			// TODO(halseth): Litecoin parameter for LTC.

			// In case the user has explicitly specified
			// a default value for the remote delay, we
			// use it.
			defaultDelay := uint16(chainCfg.DefaultRemoteDelay)
			if defaultDelay > 0 {
				return defaultDelay
			}

			// If this is a wumbo channel, then we'll require the
			// max value.
			if chanAmt > MaxFundingAmount {
				return maxRemoteDelay
			}

			// If not we scale according to channel size.
			delay := uint16(btcutil.Amount(maxRemoteDelay) *
				chanAmt / MaxFundingAmount)
			if delay < minRemoteDelay {
				delay = minRemoteDelay
			}
			if delay > maxRemoteDelay {
				delay = maxRemoteDelay
			}
			return delay
		},
		WatchNewChannel: func(channel *channeldb.OpenChannel,
			peerKey *btcec.PublicKey) error {

			// First, we'll mark this new peer as a persistent peer
			// for re-connection purposes. If the peer is not yet
			// tracked or the user hasn't requested it to be perm,
			// we'll set false to prevent the server from continuing
			// to connect to this peer even if the number of
			// channels with this peer is zero.
			s.mu.Lock()
			pubStr := string(peerKey.SerializeCompressed())
			if _, ok := s.persistentPeers[pubStr]; !ok {
				s.persistentPeers[pubStr] = false
			}
			s.mu.Unlock()

			// With that taken care of, we'll send this channel to
			// the chain arb so it can react to on-chain events.
			return s.chainArb.WatchNewChannel(channel)
		},
		ReportShortChanID: func(chanPoint wire.OutPoint) error {
			cid := lnwire.NewChanIDFromOutPoint(&chanPoint)
			return s.htlcSwitch.UpdateShortChanID(cid)
		},
		RequiredRemoteChanReserve: func(chanAmt,
			dustLimit btcutil.Amount) btcutil.Amount {

			// By default, we'll require the remote peer to maintain
			// at least 1% of the total channel capacity at all
			// times. If this value ends up dipping below the dust
			// limit, then we'll use the dust limit itself as the
			// reserve as required by BOLT #2.
			reserve := chanAmt / 100
			if reserve < dustLimit {
				reserve = dustLimit
			}

			return reserve
		},
		RequiredRemoteMaxValue: func(chanAmt btcutil.Amount) lnwire.MilliSatoshi {
			// By default, we'll allow the remote peer to fully
			// utilize the full bandwidth of the channel, minus our
			// required reserve.
			reserve := lnwire.NewMSatFromSatoshis(chanAmt / 100)
			return lnwire.NewMSatFromSatoshis(chanAmt) - reserve
		},
		RequiredRemoteMaxHTLCs: func(chanAmt btcutil.Amount) uint16 {
			if cfg.DefaultRemoteMaxHtlcs > 0 {
				return cfg.DefaultRemoteMaxHtlcs
			}

			// By default, we'll permit them to utilize the full
			// channel bandwidth.
			return uint16(input.MaxHTLCNumber / 2)
		},
		ZombieSweeperInterval:         1 * time.Minute,
		ReservationTimeout:            10 * time.Minute,
		MinChanSize:                   btcutil.Amount(cfg.MinChanSize),
		MaxChanSize:                   btcutil.Amount(cfg.MaxChanSize),
		MaxPendingChannels:            cfg.MaxPendingChannels,
		RejectPush:                    cfg.RejectPush,
		MaxLocalCSVDelay:              chainCfg.MaxLocalDelay,
		NotifyOpenChannelEvent:        s.channelNotifier.NotifyOpenChannelEvent,
		OpenChannelPredicate:          chanPredicate,
		NotifyPendingOpenChannelEvent: s.channelNotifier.NotifyPendingOpenChannelEvent,
		EnableUpfrontShutdown:         cfg.EnableUpfrontShutdown,
		RegisteredChains:              cfg.registeredChains,
		MaxAnchorsCommitFeeRate: chainfee.SatPerKVByte(
			s.cfg.MaxCommitFeeRateAnchors * 1000).FeePerKWeight(),
	})
	if err != nil {
		return nil, err
	}

	// Next, we'll assemble the sub-system that will maintain an on-disk
	// static backup of the latest channel state.
	chanNotifier := &channelNotifier{
		chanNotifier: s.channelNotifier,
		addrs:        s.remoteChanDB,
	}
	backupFile := chanbackup.NewMultiFile(cfg.BackupFilePath)
	startingChans, err := chanbackup.FetchStaticChanBackups(s.remoteChanDB)
	if err != nil {
		return nil, err
	}
	s.chanSubSwapper, err = chanbackup.NewSubSwapper(
		startingChans, chanNotifier, s.cc.KeyRing, backupFile,
	)
	if err != nil {
		return nil, err
	}

	// Assemble a peer notifier which will provide clients with subscriptions
	// to peer online and offline events.
	s.peerNotifier = peernotifier.New()

	// Create a channel event store which monitors all open channels.
	s.chanEventStore = chanfitness.NewChannelEventStore(&chanfitness.Config{
		SubscribeChannelEvents: func() (subscribe.Subscription, error) {
			return s.channelNotifier.SubscribeChannelEvents()
		},
		SubscribePeerEvents: func() (subscribe.Subscription, error) {
			return s.peerNotifier.SubscribePeerEvents()
		},
		GetOpenChannels: s.remoteChanDB.FetchAllOpenChannels,
		Clock:           clock.NewDefaultClock(),
		ReadFlapCount:   s.remoteChanDB.ReadFlapCount,
		WriteFlapCount:  s.remoteChanDB.WriteFlapCounts,
		FlapCountTicker: ticker.New(chanfitness.FlapCountFlushRate),
	})

	if cfg.WtClient.Active {
		policy := wtpolicy.DefaultPolicy()

		if cfg.WtClient.SweepFeeRate != 0 {
			// We expose the sweep fee rate in sat/vbyte, but the
			// tower protocol operations on sat/kw.
			sweepRateSatPerVByte := chainfee.SatPerKVByte(
				1000 * cfg.WtClient.SweepFeeRate,
			)
			policy.SweepFeeRate = sweepRateSatPerVByte.FeePerKWeight()
		}

		if err := policy.Validate(); err != nil {
			return nil, err
		}

		// authDial is the wrapper around the btrontide.Dial for the
		// watchtower.
		authDial := func(localKey keychain.SingleKeyECDH,
			netAddr *lnwire.NetAddress,
			dialer tor.DialFunc) (wtserver.Peer, error) {

			return brontide.Dial(
				localKey, netAddr, cfg.ConnectionTimeout, dialer,
			)
		}

		s.towerClient, err = wtclient.New(&wtclient.Config{
			Signer:         cc.Wallet.Cfg.Signer,
			NewAddress:     newSweepPkScriptGen(cc.Wallet),
			SecretKeyRing:  s.cc.KeyRing,
			Dial:           cfg.net.Dial,
			AuthDial:       authDial,
			DB:             towerClientDB,
			Policy:         policy,
			ChainHash:      *s.cfg.ActiveNetParams.GenesisHash,
			MinBackoff:     10 * time.Second,
			MaxBackoff:     5 * time.Minute,
			ForceQuitDelay: wtclient.DefaultForceQuitDelay,
		})
		if err != nil {
			return nil, err
		}

		// Copy the policy for legacy channels and set the blob flag
		// signalling support for anchor channels.
		anchorPolicy := policy
		anchorPolicy.TxPolicy.BlobType |=
			blob.Type(blob.FlagAnchorChannel)

		s.anchorTowerClient, err = wtclient.New(&wtclient.Config{
			Signer:         cc.Wallet.Cfg.Signer,
			NewAddress:     newSweepPkScriptGen(cc.Wallet),
			SecretKeyRing:  s.cc.KeyRing,
			Dial:           cfg.net.Dial,
			AuthDial:       authDial,
			DB:             towerClientDB,
			Policy:         anchorPolicy,
			ChainHash:      *s.cfg.ActiveNetParams.GenesisHash,
			MinBackoff:     10 * time.Second,
			MaxBackoff:     5 * time.Minute,
			ForceQuitDelay: wtclient.DefaultForceQuitDelay,
		})
		if err != nil {
			return nil, err
		}
	}

	if len(cfg.ExternalHosts) != 0 {
		advertisedIPs := make(map[string]struct{})
		for _, addr := range s.currentNodeAnn.Addresses {
			advertisedIPs[addr.String()] = struct{}{}
		}

		s.hostAnn = netann.NewHostAnnouncer(netann.HostAnnouncerConfig{
			Hosts:         cfg.ExternalHosts,
			RefreshTicker: ticker.New(defaultHostSampleInterval),
			LookupHost: func(host string) (net.Addr, error) {
				return lncfg.ParseAddressString(
					host, strconv.Itoa(defaultPeerPort),
					cfg.net.ResolveTCPAddr,
				)
			},
			AdvertisedIPs:  advertisedIPs,
			AnnounceNewIPs: netann.IPAnnouncer(s.genNodeAnnouncement),
		})
	}

	// Create a set of health checks using our configured values. If a
	// health check has been disabled by setting attempts to 0, our monitor
	// will not run it.
	chainHealthCheck := healthcheck.NewObservation(
		"chain backend",
		cc.HealthCheck,
		cfg.HealthChecks.ChainCheck.Interval,
		cfg.HealthChecks.ChainCheck.Timeout,
		cfg.HealthChecks.ChainCheck.Backoff,
		cfg.HealthChecks.ChainCheck.Attempts,
	)

	diskCheck := healthcheck.NewObservation(
		"disk space",
		func() error {
			free, err := healthcheck.AvailableDiskSpaceRatio(
				cfg.LndDir,
			)
			if err != nil {
				return err
			}

			// If we have more free space than we require,
			// we return a nil error.
			if free > cfg.HealthChecks.DiskCheck.RequiredRemaining {
				return nil
			}

			return fmt.Errorf("require: %v free space, got: %v",
				cfg.HealthChecks.DiskCheck.RequiredRemaining,
				free)
		},
		cfg.HealthChecks.DiskCheck.Interval,
		cfg.HealthChecks.DiskCheck.Timeout,
		cfg.HealthChecks.DiskCheck.Backoff,
		cfg.HealthChecks.DiskCheck.Attempts,
	)

	tlsHealthCheck := healthcheck.NewObservation(
		"tls",
		func() error {
			_, parsedCert, err := cert.LoadCert(
				cfg.TLSCertPath, cfg.TLSKeyPath,
			)
			if err != nil {
				return err
			}

			// If the current time is passed the certificate's
			// expiry time, then it is considered expired
			if time.Now().After(parsedCert.NotAfter) {
				return fmt.Errorf("TLS certificate is expired as of %v", parsedCert.NotAfter)
			}

			// If the certificate is not outdated, no error needs to
			// be returned
			return nil
		},
		cfg.HealthChecks.TLSCheck.Interval,
		cfg.HealthChecks.TLSCheck.Timeout,
		cfg.HealthChecks.TLSCheck.Backoff,
		cfg.HealthChecks.TLSCheck.Attempts,
	)

	// If we have not disabled all of our health checks, we create a
	// liveliness monitor with our configured checks.
	s.livelinessMonitor = healthcheck.NewMonitor(
		&healthcheck.Config{
			Checks: []*healthcheck.Observation{
				chainHealthCheck, diskCheck, tlsHealthCheck,
			},
			Shutdown: srvrLog.Criticalf,
		},
	)

	// Create the connection manager which will be responsible for
	// maintaining persistent outbound connections and also accepting new
	// incoming connections
	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners:      listeners,
		OnAccept:       s.InboundPeerConnected,
		RetryDuration:  time.Second * 5,
		TargetOutbound: 100,
		Dial: noiseDial(
			nodeKeyECDH, s.cfg.net, s.cfg.ConnectionTimeout,
		),
		OnConnection: s.OutboundPeerConnected,
	})
	if err != nil {
		return nil, err
	}
	s.connMgr = cmgr

	return s, nil
}

// Started returns true if the server has been started, and false otherwise.
// NOTE: This function is safe for concurrent access.
func (s *server) Started() bool {
	return atomic.LoadInt32(&s.active) != 0
}

// cleaner is used to aggregate "cleanup" functions during an operation that
// starts several subsystems. In case one of the subsystem fails to start
// and a proper resource cleanup is required, the "run" method achieves this
// by running all these added "cleanup" functions
type cleaner []func() error

// add is used to add a cleanup function to be called when
// the run function is executed
func (c cleaner) add(cleanup func() error) cleaner {
	return append(c, cleanup)
}

// run is used to run all the previousely added cleanup functions
func (c cleaner) run() {
	for i := len(c) - 1; i >= 0; i-- {
		if err := c[i](); err != nil {
			srvrLog.Infof("Cleanup failed: %v", err)
		}
	}
}

// Start starts the main daemon server, all requested listeners, and any helper
// goroutines.
// NOTE: This function is safe for concurrent access.
func (s *server) Start() error {
	var startErr error

	// If one sub system fails to start, the following code ensures that the
	// previous started ones are stopped. It also ensures a proper wallet
	// shutdown which is important for releasing its resources (boltdb, etc...)
	cleanup := cleaner{}

	s.start.Do(func() {
		if err := s.customMessageServer.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.customMessageServer.Stop)

		if s.torController != nil {
			if err := s.createNewHiddenService(); err != nil {
				startErr = err
				return
			}
			cleanup = cleanup.add(s.torController.Stop)
		}

		if s.natTraversal != nil {
			s.wg.Add(1)
			go s.watchExternalIP()
		}

		if s.hostAnn != nil {
			if err := s.hostAnn.Start(); err != nil {
				startErr = err
				return
			}
			cleanup = cleanup.add(s.hostAnn.Stop)
		}

		if s.livelinessMonitor != nil {
			if err := s.livelinessMonitor.Start(); err != nil {
				startErr = err
				return
			}
			cleanup = cleanup.add(s.livelinessMonitor.Stop)
		}

		// Start the notification server. This is used so channel
		// management goroutines can be notified when a funding
		// transaction reaches a sufficient number of confirmations, or
		// when the input for the funding transaction is spent in an
		// attempt at an uncooperative close by the counterparty.
		if err := s.sigPool.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.sigPool.Stop)

		if err := s.writePool.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.writePool.Stop)

		if err := s.readPool.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.readPool.Stop)

		if err := s.cc.ChainNotifier.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.cc.ChainNotifier.Stop)

		if err := s.channelNotifier.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.channelNotifier.Stop)

		if err := s.peerNotifier.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(func() error {
			return s.peerNotifier.Stop()
		})
		if err := s.htlcNotifier.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.htlcNotifier.Stop)

		if err := s.sphinx.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.sphinx.Stop)

		if s.towerClient != nil {
			if err := s.towerClient.Start(); err != nil {
				startErr = err
				return
			}
			cleanup = cleanup.add(s.towerClient.Stop)
		}
		if s.anchorTowerClient != nil {
			if err := s.anchorTowerClient.Start(); err != nil {
				startErr = err
				return
			}
			cleanup = cleanup.add(s.anchorTowerClient.Stop)
		}

		if err := s.htlcSwitch.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.htlcSwitch.Stop)

		if err := s.sweeper.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.sweeper.Stop)

		if err := s.utxoNursery.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.utxoNursery.Stop)

		if err := s.chainArb.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.chainArb.Stop)

		if err := s.breachArbiter.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.breachArbiter.Stop)

		if err := s.authGossiper.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.authGossiper.Stop)

		if err := s.chanRouter.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.chanRouter.Stop)

		if err := s.fundingMgr.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.fundingMgr.Stop)

		if err := s.invoices.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.invoices.Stop)

		if err := s.chanStatusMgr.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.chanStatusMgr.Stop)

		if err := s.chanEventStore.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(func() error {
			s.chanEventStore.Stop()
			return nil
		})

		// Before we start the connMgr, we'll check to see if we have
		// any backups to recover. We do this now as we want to ensure
		// that have all the information we need to handle channel
		// recovery _before_ we even accept connections from any peers.
		chanRestorer := &chanDBRestorer{
			db:         s.remoteChanDB,
			secretKeys: s.cc.KeyRing,
			chainArb:   s.chainArb,
		}
		if len(s.chansToRestore.PackedSingleChanBackups) != 0 {
			err := chanbackup.UnpackAndRecoverSingles(
				s.chansToRestore.PackedSingleChanBackups,
				s.cc.KeyRing, chanRestorer, s,
			)
			if err != nil {
				startErr = fmt.Errorf("unable to unpack single "+
					"backups: %v", err)
				return
			}
		}
		if len(s.chansToRestore.PackedMultiChanBackup) != 0 {
			err := chanbackup.UnpackAndRecoverMulti(
				s.chansToRestore.PackedMultiChanBackup,
				s.cc.KeyRing, chanRestorer, s,
			)
			if err != nil {
				startErr = fmt.Errorf("unable to unpack chan "+
					"backup: %v", err)
				return
			}
		}

		if err := s.chanSubSwapper.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.chanSubSwapper.Stop)

		s.connMgr.Start()
		cleanup = cleanup.add(func() error {
			s.connMgr.Stop()
			return nil
		})

		// With all the relevant sub-systems started, we'll now attempt
		// to establish persistent connections to our direct channel
		// collaborators within the network. Before doing so however,
		// we'll prune our set of link nodes found within the database
		// to ensure we don't reconnect to any nodes we no longer have
		// open channels with.
		if err := s.remoteChanDB.PruneLinkNodes(); err != nil {
			startErr = err
			return
		}
		if err := s.establishPersistentConnections(); err != nil {
			startErr = err
			return
		}

		// setSeedList is a helper function that turns multiple DNS seed
		// server tuples from the command line or config file into the
		// data structure we need and does a basic formal sanity check
		// in the process.
		setSeedList := func(tuples []string, genesisHash chainhash.Hash) {
			if len(tuples) == 0 {
				return
			}

			result := make([][2]string, len(tuples))
			for idx, tuple := range tuples {
				tuple = strings.TrimSpace(tuple)
				if len(tuple) == 0 {
					return
				}

				servers := strings.Split(tuple, ",")
				if len(servers) > 2 || len(servers) == 0 {
					srvrLog.Warnf("Ignoring invalid DNS "+
						"seed tuple: %v", servers)
					return
				}

				copy(result[idx][:], servers)
			}

			chainreg.ChainDNSSeeds[genesisHash] = result
		}

		// Let users overwrite the DNS seed nodes. We only allow them
		// for bitcoin mainnet/testnet and litecoin mainnet, all other
		// combinations will just be ignored.
		if s.cfg.Bitcoin.Active && s.cfg.Bitcoin.MainNet {
			setSeedList(
				s.cfg.Bitcoin.DNSSeeds,
				chainreg.BitcoinMainnetGenesis,
			)
		}
		if s.cfg.Bitcoin.Active && s.cfg.Bitcoin.TestNet3 {
			setSeedList(
				s.cfg.Bitcoin.DNSSeeds,
				chainreg.BitcoinTestnetGenesis,
			)
		}
		if s.cfg.Bitcoin.Active && s.cfg.Bitcoin.SigNet {
			setSeedList(
				s.cfg.Bitcoin.DNSSeeds,
				chainreg.BitcoinSignetGenesis,
			)
		}
		if s.cfg.Litecoin.Active && s.cfg.Litecoin.MainNet {
			setSeedList(
				s.cfg.Litecoin.DNSSeeds,
				chainreg.LitecoinMainnetGenesis,
			)
		}

		// If network bootstrapping hasn't been disabled, then we'll
		// configure the set of active bootstrappers, and launch a
		// dedicated goroutine to maintain a set of persistent
		// connections.
		if !s.cfg.NoNetBootstrap &&
			!(s.cfg.Bitcoin.SimNet || s.cfg.Litecoin.SimNet) &&
			!(s.cfg.Bitcoin.RegTest || s.cfg.Litecoin.RegTest) {

			bootstrappers, err := initNetworkBootstrappers(s)
			if err != nil {
				startErr = err
				return
			}

			s.wg.Add(1)
			go s.peerBootstrapper(defaultMinPeers, bootstrappers)
		} else {
			srvrLog.Infof("Auto peer bootstrapping is disabled")
		}

		// Set the active flag now that we've completed the full
		// startup.
		atomic.StoreInt32(&s.active, 1)
	})

	if startErr != nil {
		cleanup.run()
	}
	return startErr
}

// Stop gracefully shutsdown the main daemon server. This function will signal
// any active goroutines, or helper objects to exit, then blocks until they've
// all successfully exited. Additionally, any/all listeners are closed.
// NOTE: This function is safe for concurrent access.
func (s *server) Stop() error {
	s.stop.Do(func() {
		atomic.StoreInt32(&s.stopping, 1)

		close(s.quit)

		// Shutdown the wallet, funding manager, and the rpc server.
		s.chanStatusMgr.Stop()
		if err := s.cc.ChainNotifier.Stop(); err != nil {
			srvrLog.Warnf("Unable to stop ChainNotifier: %v", err)
		}
		if err := s.chanRouter.Stop(); err != nil {
			srvrLog.Warnf("failed to stop chanRouter: %v", err)
		}
		if err := s.htlcSwitch.Stop(); err != nil {
			srvrLog.Warnf("failed to stop htlcSwitch: %v", err)
		}
		if err := s.sphinx.Stop(); err != nil {
			srvrLog.Warnf("failed to stop sphinx: %v", err)
		}
		if err := s.utxoNursery.Stop(); err != nil {
			srvrLog.Warnf("failed to stop utxoNursery: %v", err)
		}
		if err := s.breachArbiter.Stop(); err != nil {
			srvrLog.Warnf("failed to stop breachArbiter: %v", err)
		}
		if err := s.authGossiper.Stop(); err != nil {
			srvrLog.Warnf("failed to stop authGossiper: %v", err)
		}
		if err := s.chainArb.Stop(); err != nil {
			srvrLog.Warnf("failed to stop chainArb: %v", err)
		}
		if err := s.sweeper.Stop(); err != nil {
			srvrLog.Warnf("failed to stop sweeper: %v", err)
		}
		if err := s.channelNotifier.Stop(); err != nil {
			srvrLog.Warnf("failed to stop channelNotifier: %v", err)
		}
		if err := s.peerNotifier.Stop(); err != nil {
			srvrLog.Warnf("failed to stop peerNotifier: %v", err)
		}
		if err := s.htlcNotifier.Stop(); err != nil {
			srvrLog.Warnf("failed to stop htlcNotifier: %v", err)
		}
		s.connMgr.Stop()
		if err := s.invoices.Stop(); err != nil {
			srvrLog.Warnf("failed to stop invoices: %v", err)
		}
		if err := s.fundingMgr.Stop(); err != nil {
			srvrLog.Warnf("failed to stop fundingMgr: %v", err)
		}
		if err := s.chanSubSwapper.Stop(); err != nil {
			srvrLog.Warnf("failed to stop chanSubSwapper: %v", err)
		}
		s.chanEventStore.Stop()

		// Disconnect from each active peers to ensure that
		// peerTerminationWatchers signal completion to each peer.
		for _, peer := range s.Peers() {
			err := s.DisconnectPeer(peer.IdentityKey())
			if err != nil {
				srvrLog.Warnf("could not disconnect peer: %v"+
					"received error: %v", peer.IdentityKey(),
					err,
				)
			}
		}

		// Now that all connections have been torn down, stop the tower
		// client which will reliably flush all queued states to the
		// tower. If this is halted for any reason, the force quit timer
		// will kick in and abort to allow this method to return.
		if s.towerClient != nil {
			if err := s.towerClient.Stop(); err != nil {
				srvrLog.Warnf("Unable to shut down tower "+
					"client: %v", err)
			}
		}
		if s.anchorTowerClient != nil {
			if err := s.anchorTowerClient.Stop(); err != nil {
				srvrLog.Warnf("Unable to shut down anchor "+
					"tower client: %v", err)
			}
		}

		if s.hostAnn != nil {
			if err := s.hostAnn.Stop(); err != nil {
				srvrLog.Warnf("unable to shut down host "+
					"annoucner: %v", err)
			}
		}

		if s.livelinessMonitor != nil {
			if err := s.livelinessMonitor.Stop(); err != nil {
				srvrLog.Warnf("unable to shutdown liveliness "+
					"monitor: %v", err)
			}
		}

		// Wait for all lingering goroutines to quit.
		s.wg.Wait()

		s.sigPool.Stop()
		s.writePool.Stop()
		s.readPool.Stop()
	})

	return nil
}

// Stopped returns true if the server has been instructed to shutdown.
// NOTE: This function is safe for concurrent access.
func (s *server) Stopped() bool {
	return atomic.LoadInt32(&s.stopping) != 0
}

// configurePortForwarding attempts to set up port forwarding for the different
// ports that the server will be listening on.
//
// NOTE: This should only be used when using some kind of NAT traversal to
// automatically set up forwarding rules.
func (s *server) configurePortForwarding(ports ...uint16) ([]string, error) {
	ip, err := s.natTraversal.ExternalIP()
	if err != nil {
		return nil, err
	}
	s.lastDetectedIP = ip

	externalIPs := make([]string, 0, len(ports))
	for _, port := range ports {
		if err := s.natTraversal.AddPortMapping(port); err != nil {
			srvrLog.Debugf("Unable to forward port %d: %v", port, err)
			continue
		}

		hostIP := fmt.Sprintf("%v:%d", ip, port)
		externalIPs = append(externalIPs, hostIP)
	}

	return externalIPs, nil
}

// removePortForwarding attempts to clear the forwarding rules for the different
// ports the server is currently listening on.
//
// NOTE: This should only be used when using some kind of NAT traversal to
// automatically set up forwarding rules.
func (s *server) removePortForwarding() {
	forwardedPorts := s.natTraversal.ForwardedPorts()
	for _, port := range forwardedPorts {
		if err := s.natTraversal.DeletePortMapping(port); err != nil {
			srvrLog.Errorf("Unable to remove forwarding rules for "+
				"port %d: %v", port, err)
		}
	}
}

// watchExternalIP continuously checks for an updated external IP address every
// 15 minutes. Once a new IP address has been detected, it will automatically
// handle port forwarding rules and send updated node announcements to the
// currently connected peers.
//
// NOTE: This MUST be run as a goroutine.
func (s *server) watchExternalIP() {
	defer s.wg.Done()

	// Before exiting, we'll make sure to remove the forwarding rules set
	// up by the server.
	defer s.removePortForwarding()

	// Keep track of the external IPs set by the user to avoid replacing
	// them when detecting a new IP.
	ipsSetByUser := make(map[string]struct{})
	for _, ip := range s.cfg.ExternalIPs {
		ipsSetByUser[ip.String()] = struct{}{}
	}

	forwardedPorts := s.natTraversal.ForwardedPorts()

	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
out:
	for {
		select {
		case <-ticker.C:
			// We'll start off by making sure a new IP address has
			// been detected.
			ip, err := s.natTraversal.ExternalIP()
			if err != nil {
				srvrLog.Debugf("Unable to retrieve the "+
					"external IP address: %v", err)
				continue
			}

			// Periodically renew the NAT port forwarding.
			for _, port := range forwardedPorts {
				err := s.natTraversal.AddPortMapping(port)
				if err != nil {
					srvrLog.Warnf("Unable to automatically "+
						"re-create port forwarding using %s: %v",
						s.natTraversal.Name(), err)
				} else {
					srvrLog.Debugf("Automatically re-created "+
						"forwarding for port %d using %s to "+
						"advertise external IP",
						port, s.natTraversal.Name())
				}
			}

			if ip.Equal(s.lastDetectedIP) {
				continue
			}

			srvrLog.Infof("Detected new external IP address %s", ip)

			// Next, we'll craft the new addresses that will be
			// included in the new node announcement and advertised
			// to the network. Each address will consist of the new
			// IP detected and one of the currently advertised
			// ports.
			var newAddrs []net.Addr
			for _, port := range forwardedPorts {
				hostIP := fmt.Sprintf("%v:%d", ip, port)
				addr, err := net.ResolveTCPAddr("tcp", hostIP)
				if err != nil {
					srvrLog.Debugf("Unable to resolve "+
						"host %v: %v", addr, err)
					continue
				}

				newAddrs = append(newAddrs, addr)
			}

			// Skip the update if we weren't able to resolve any of
			// the new addresses.
			if len(newAddrs) == 0 {
				srvrLog.Debug("Skipping node announcement " +
					"update due to not being able to " +
					"resolve any new addresses")
				continue
			}

			// Now, we'll need to update the addresses in our node's
			// announcement in order to propagate the update
			// throughout the network. We'll only include addresses
			// that have a different IP from the previous one, as
			// the previous IP is no longer valid.
			currentNodeAnn, err := s.genNodeAnnouncement(false)
			if err != nil {
				srvrLog.Debugf("Unable to retrieve current "+
					"node announcement: %v", err)
				continue
			}
			for _, addr := range currentNodeAnn.Addresses {
				host, _, err := net.SplitHostPort(addr.String())
				if err != nil {
					srvrLog.Debugf("Unable to determine "+
						"host from address %v: %v",
						addr, err)
					continue
				}

				// We'll also make sure to include external IPs
				// set manually by the user.
				_, setByUser := ipsSetByUser[addr.String()]
				if setByUser || host != s.lastDetectedIP.String() {
					newAddrs = append(newAddrs, addr)
				}
			}

			// Then, we'll generate a new timestamped node
			// announcement with the updated addresses and broadcast
			// it to our peers.
			newNodeAnn, err := s.genNodeAnnouncement(
				true, netann.NodeAnnSetAddrs(newAddrs),
			)
			if err != nil {
				srvrLog.Debugf("Unable to generate new node "+
					"announcement: %v", err)
				continue
			}

			err = s.BroadcastMessage(nil, &newNodeAnn)
			if err != nil {
				srvrLog.Debugf("Unable to broadcast new node "+
					"announcement to peers: %v", err)
				continue
			}

			// Finally, update the last IP seen to the current one.
			s.lastDetectedIP = ip
		case <-s.quit:
			break out
		}
	}
}

// initNetworkBootstrappers initializes a set of network peer bootstrappers
// based on the server, and currently active bootstrap mechanisms as defined
// within the current configuration.
func initNetworkBootstrappers(s *server) ([]discovery.NetworkPeerBootstrapper, error) {
	srvrLog.Infof("Initializing peer network bootstrappers!")

	var bootStrappers []discovery.NetworkPeerBootstrapper

	// First, we'll create an instance of the ChannelGraphBootstrapper as
	// this can be used by default if we've already partially seeded the
	// network.
	chanGraph := autopilot.ChannelGraphFromDatabase(s.localChanDB.ChannelGraph())
	graphBootstrapper, err := discovery.NewGraphBootstrapper(chanGraph)
	if err != nil {
		return nil, err
	}
	bootStrappers = append(bootStrappers, graphBootstrapper)

	// If this isn't simnet mode, then one of our additional bootstrapping
	// sources will be the set of running DNS seeds.
	if !s.cfg.Bitcoin.SimNet || !s.cfg.Litecoin.SimNet {
		dnsSeeds, ok := chainreg.ChainDNSSeeds[*s.cfg.ActiveNetParams.GenesisHash]

		// If we have a set of DNS seeds for this chain, then we'll add
		// it as an additional bootstrapping source.
		if ok {
			srvrLog.Infof("Creating DNS peer bootstrapper with "+
				"seeds: %v", dnsSeeds)

			dnsBootStrapper := discovery.NewDNSSeedBootstrapper(
				dnsSeeds, s.cfg.net, s.cfg.ConnectionTimeout,
			)
			bootStrappers = append(bootStrappers, dnsBootStrapper)
		}
	}

	return bootStrappers, nil
}

// peerBootstrapper is a goroutine which is tasked with attempting to establish
// and maintain a target minimum number of outbound connections. With this
// invariant, we ensure that our node is connected to a diverse set of peers
// and that nodes newly joining the network receive an up to date network view
// as soon as possible.
func (s *server) peerBootstrapper(numTargetPeers uint32,
	bootstrappers []discovery.NetworkPeerBootstrapper) {

	defer s.wg.Done()

	// ignore is a set used to keep track of peers already retrieved from
	// our bootstrappers in order to avoid duplicates.
	ignore := make(map[autopilot.NodeID]struct{})

	// We'll start off by aggressively attempting connections to peers in
	// order to be a part of the network as soon as possible.
	s.initialPeerBootstrap(ignore, numTargetPeers, bootstrappers)

	// Once done, we'll attempt to maintain our target minimum number of
	// peers.
	//
	// We'll use a 15 second backoff, and double the time every time an
	// epoch fails up to a ceiling.
	backOff := time.Second * 15

	// We'll create a new ticker to wake us up every 15 seconds so we can
	// see if we've reached our minimum number of peers.
	sampleTicker := time.NewTicker(backOff)
	defer sampleTicker.Stop()

	// We'll use the number of attempts and errors to determine if we need
	// to increase the time between discovery epochs.
	var epochErrors uint32 // To be used atomically.
	var epochAttempts uint32

	for {
		select {
		// The ticker has just woken us up, so we'll need to check if
		// we need to attempt to connect our to any more peers.
		case <-sampleTicker.C:
			// Obtain the current number of peers, so we can gauge
			// if we need to sample more peers or not.
			s.mu.RLock()
			numActivePeers := uint32(len(s.peersByPub))
			s.mu.RUnlock()

			// If we have enough peers, then we can loop back
			// around to the next round as we're done here.
			if numActivePeers >= numTargetPeers {
				continue
			}

			// If all of our attempts failed during this last back
			// off period, then will increase our backoff to 5
			// minute ceiling to avoid an excessive number of
			// queries
			//
			// TODO(roasbeef): add reverse policy too?

			if epochAttempts > 0 &&
				atomic.LoadUint32(&epochErrors) >= epochAttempts {

				sampleTicker.Stop()

				backOff *= 2
				if backOff > bootstrapBackOffCeiling {
					backOff = bootstrapBackOffCeiling
				}

				srvrLog.Debugf("Backing off peer bootstrapper to "+
					"%v", backOff)
				sampleTicker = time.NewTicker(backOff)
				continue
			}

			atomic.StoreUint32(&epochErrors, 0)
			epochAttempts = 0

			// Since we know need more peers, we'll compute the
			// exact number we need to reach our threshold.
			numNeeded := numTargetPeers - numActivePeers

			srvrLog.Debugf("Attempting to obtain %v more network "+
				"peers", numNeeded)

			// With the number of peers we need calculated, we'll
			// query the network bootstrappers to sample a set of
			// random addrs for us.
			s.mu.RLock()
			ignoreList := make(map[autopilot.NodeID]struct{})
			for _, peer := range s.peersByPub {
				nID := autopilot.NewNodeID(peer.IdentityKey())
				ignoreList[nID] = struct{}{}
			}
			s.mu.RUnlock()

			peerAddrs, err := discovery.MultiSourceBootstrap(
				ignoreList, numNeeded*2, bootstrappers...,
			)
			if err != nil {
				srvrLog.Errorf("Unable to retrieve bootstrap "+
					"peers: %v", err)
				continue
			}

			// Finally, we'll launch a new goroutine for each
			// prospective peer candidates.
			for _, addr := range peerAddrs {
				epochAttempts++

				go func(a *lnwire.NetAddress) {
					// TODO(roasbeef): can do AS, subnet,
					// country diversity, etc
					errChan := make(chan error, 1)
					s.connectToPeer(
						a, errChan,
						s.cfg.ConnectionTimeout,
					)
					select {
					case err := <-errChan:
						if err == nil {
							return
						}

						srvrLog.Errorf("Unable to "+
							"connect to %v: %v",
							a, err)
						atomic.AddUint32(&epochErrors, 1)
					case <-s.quit:
					}
				}(addr)
			}
		case <-s.quit:
			return
		}
	}
}

// bootstrapBackOffCeiling is the maximum amount of time we'll wait between
// failed attempts to locate a set of bootstrap peers. We'll slowly double our
// query back off each time we encounter a failure.
const bootstrapBackOffCeiling = time.Minute * 5

// initialPeerBootstrap attempts to continuously connect to peers on startup
// until the target number of peers has been reached. This ensures that nodes
// receive an up to date network view as soon as possible.
func (s *server) initialPeerBootstrap(ignore map[autopilot.NodeID]struct{},
	numTargetPeers uint32, bootstrappers []discovery.NetworkPeerBootstrapper) {

	// We'll start off by waiting 2 seconds between failed attempts, then
	// double each time we fail until we hit the bootstrapBackOffCeiling.
	var delaySignal <-chan time.Time
	delayTime := time.Second * 2

	// As want to be more aggressive, we'll use a lower back off celling
	// then the main peer bootstrap logic.
	backOffCeiling := bootstrapBackOffCeiling / 5

	for attempts := 0; ; attempts++ {
		// Check if the server has been requested to shut down in order
		// to prevent blocking.
		if s.Stopped() {
			return
		}

		// We can exit our aggressive initial peer bootstrapping stage
		// if we've reached out target number of peers.
		s.mu.RLock()
		numActivePeers := uint32(len(s.peersByPub))
		s.mu.RUnlock()

		if numActivePeers >= numTargetPeers {
			return
		}

		if attempts > 0 {
			srvrLog.Debugf("Waiting %v before trying to locate "+
				"bootstrap peers (attempt #%v)", delayTime,
				attempts)

			// We've completed at least one iterating and haven't
			// finished, so we'll start to insert a delay period
			// between each attempt.
			delaySignal = time.After(delayTime)
			select {
			case <-delaySignal:
			case <-s.quit:
				return
			}

			// After our delay, we'll double the time we wait up to
			// the max back off period.
			delayTime *= 2
			if delayTime > backOffCeiling {
				delayTime = backOffCeiling
			}
		}

		// Otherwise, we'll request for the remaining number of peers
		// in order to reach our target.
		peersNeeded := numTargetPeers - numActivePeers
		bootstrapAddrs, err := discovery.MultiSourceBootstrap(
			ignore, peersNeeded, bootstrappers...,
		)
		if err != nil {
			srvrLog.Errorf("Unable to retrieve initial bootstrap "+
				"peers: %v", err)
			continue
		}

		// Then, we'll attempt to establish a connection to the
		// different peer addresses retrieved by our bootstrappers.
		var wg sync.WaitGroup
		for _, bootstrapAddr := range bootstrapAddrs {
			wg.Add(1)
			go func(addr *lnwire.NetAddress) {
				defer wg.Done()

				errChan := make(chan error, 1)
				go s.connectToPeer(
					addr, errChan, s.cfg.ConnectionTimeout,
				)

				// We'll only allow this connection attempt to
				// take up to 3 seconds. This allows us to move
				// quickly by discarding peers that are slowing
				// us down.
				select {
				case err := <-errChan:
					if err == nil {
						return
					}
					srvrLog.Errorf("Unable to connect to "+
						"%v: %v", addr, err)
				// TODO: tune timeout? 3 seconds might be *too*
				// aggressive but works well.
				case <-time.After(3 * time.Second):
					srvrLog.Tracef("Skipping peer %v due "+
						"to not establishing a "+
						"connection within 3 seconds",
						addr)
				case <-s.quit:
				}
			}(bootstrapAddr)
		}

		wg.Wait()
	}
}

// createNewHiddenService automatically sets up a v2 or v3 onion service in
// order to listen for inbound connections over Tor.
func (s *server) createNewHiddenService() error {
	// Determine the different ports the server is listening on. The onion
	// service's virtual port will map to these ports and one will be picked
	// at random when the onion service is being accessed.
	listenPorts := make([]int, 0, len(s.listenAddrs))
	for _, listenAddr := range s.listenAddrs {
		port := listenAddr.(*net.TCPAddr).Port
		listenPorts = append(listenPorts, port)
	}

	// Once the port mapping has been set, we can go ahead and automatically
	// create our onion service. The service's private key will be saved to
	// disk in order to regain access to this service when restarting `lnd`.
	onionCfg := tor.AddOnionConfig{
		VirtualPort: defaultPeerPort,
		TargetPorts: listenPorts,
		Store:       tor.NewOnionFile(s.cfg.Tor.PrivateKeyPath, 0600),
	}

	switch {
	case s.cfg.Tor.V2:
		onionCfg.Type = tor.V2
	case s.cfg.Tor.V3:
		onionCfg.Type = tor.V3
	}

	addr, err := s.torController.AddOnion(onionCfg)
	if err != nil {
		return err
	}

	// Now that the onion service has been created, we'll add the onion
	// address it can be reached at to our list of advertised addresses.
	newNodeAnn, err := s.genNodeAnnouncement(
		true, func(currentAnn *lnwire.NodeAnnouncement) {
			currentAnn.Addresses = append(currentAnn.Addresses, addr)
		},
	)
	if err != nil {
		return fmt.Errorf("unable to generate new node "+
			"announcement: %v", err)
	}

	// Finally, we'll update the on-disk version of our announcement so it
	// will eventually propagate to nodes in the network.
	selfNode := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           time.Unix(int64(newNodeAnn.Timestamp), 0),
		Addresses:            newNodeAnn.Addresses,
		Alias:                newNodeAnn.Alias.String(),
		Features: lnwire.NewFeatureVector(
			newNodeAnn.Features, lnwire.Features,
		),
		Color:        newNodeAnn.RGBColor,
		AuthSigBytes: newNodeAnn.Signature.ToSignatureBytes(),
	}
	copy(selfNode.PubKeyBytes[:], s.identityECDH.PubKey().SerializeCompressed())
	if err := s.localChanDB.ChannelGraph().SetSourceNode(selfNode); err != nil {
		return fmt.Errorf("can't set self node: %v", err)
	}

	return nil
}

// genNodeAnnouncement generates and returns the current fully signed node
// announcement. If refresh is true, then the time stamp of the announcement
// will be updated in order to ensure it propagates through the network.
func (s *server) genNodeAnnouncement(refresh bool,
	modifiers ...netann.NodeAnnModifier) (lnwire.NodeAnnouncement, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	// If we don't need to refresh the announcement, then we can return a
	// copy of our cached version.
	if !refresh {
		return *s.currentNodeAnn, nil
	}

	// Always update the timestamp when refreshing to ensure the update
	// propagates.
	modifiers = append(modifiers, netann.NodeAnnSetTimestamp)

	// Otherwise, we'll sign a new update after applying all of the passed
	// modifiers.
	err := netann.SignNodeAnnouncement(
		s.nodeSigner, s.identityECDH.PubKey(), s.currentNodeAnn,
		modifiers...,
	)
	if err != nil {
		return lnwire.NodeAnnouncement{}, err
	}

	return *s.currentNodeAnn, nil
}

type nodeAddresses struct {
	pubKey    *btcec.PublicKey
	addresses []net.Addr
}

// establishPersistentConnections attempts to establish persistent connections
// to all our direct channel collaborators. In order to promote liveness of our
// active channels, we instruct the connection manager to attempt to establish
// and maintain persistent connections to all our direct channel counterparties.
func (s *server) establishPersistentConnections() error {
	// nodeAddrsMap stores the combination of node public keys and addresses
	// that we'll attempt to reconnect to. PubKey strings are used as keys
	// since other PubKey forms can't be compared.
	nodeAddrsMap := map[string]*nodeAddresses{}

	// Iterate through the list of LinkNodes to find addresses we should
	// attempt to connect to based on our set of previous connections. Set
	// the reconnection port to the default peer port.
	linkNodes, err := s.remoteChanDB.FetchAllLinkNodes()
	if err != nil && err != channeldb.ErrLinkNodesNotFound {
		return err
	}
	for _, node := range linkNodes {
		pubStr := string(node.IdentityPub.SerializeCompressed())
		nodeAddrs := &nodeAddresses{
			pubKey:    node.IdentityPub,
			addresses: node.Addresses,
		}
		nodeAddrsMap[pubStr] = nodeAddrs
	}

	// After checking our previous connections for addresses to connect to,
	// iterate through the nodes in our channel graph to find addresses
	// that have been added via NodeAnnouncement messages.
	chanGraph := s.localChanDB.ChannelGraph()
	sourceNode, err := chanGraph.SourceNode()
	if err != nil {
		return err
	}

	// TODO(roasbeef): instead iterate over link nodes and query graph for
	// each of the nodes.
	selfPub := s.identityECDH.PubKey().SerializeCompressed()
	err = sourceNode.ForEachChannel(nil, func(
		tx kvdb.RTx,
		chanInfo *channeldb.ChannelEdgeInfo,
		policy, _ *channeldb.ChannelEdgePolicy) error {

		// If the remote party has announced the channel to us, but we
		// haven't yet, then we won't have a policy. However, we don't
		// need this to connect to the peer, so we'll log it and move on.
		if policy == nil {
			srvrLog.Warnf("No channel policy found for "+
				"ChannelPoint(%v): ", chanInfo.ChannelPoint)
		}

		// We'll now fetch the peer opposite from us within this
		// channel so we can queue up a direct connection to them.
		channelPeer, err := chanInfo.FetchOtherNode(tx, selfPub)
		if err != nil {
			return fmt.Errorf("unable to fetch channel peer for "+
				"ChannelPoint(%v): %v", chanInfo.ChannelPoint,
				err)
		}

		pubStr := string(channelPeer.PubKeyBytes[:])

		// Add all unique addresses from channel
		// graph/NodeAnnouncements to the list of addresses we'll
		// connect to for this peer.
		addrSet := make(map[string]net.Addr)
		for _, addr := range channelPeer.Addresses {
			switch addr.(type) {
			case *net.TCPAddr:
				addrSet[addr.String()] = addr

			// We'll only attempt to connect to Tor addresses if Tor
			// outbound support is enabled.
			case *tor.OnionAddr:
				if s.cfg.Tor.Active {
					addrSet[addr.String()] = addr
				}
			}
		}

		// If this peer is also recorded as a link node, we'll add any
		// additional addresses that have not already been selected.
		linkNodeAddrs, ok := nodeAddrsMap[pubStr]
		if ok {
			for _, lnAddress := range linkNodeAddrs.addresses {
				switch lnAddress.(type) {
				case *net.TCPAddr:
					addrSet[lnAddress.String()] = lnAddress

				// We'll only attempt to connect to Tor
				// addresses if Tor outbound support is enabled.
				case *tor.OnionAddr:
					if s.cfg.Tor.Active {
						addrSet[lnAddress.String()] = lnAddress
					}
				}
			}
		}

		// Construct a slice of the deduped addresses.
		var addrs []net.Addr
		for _, addr := range addrSet {
			addrs = append(addrs, addr)
		}

		n := &nodeAddresses{
			addresses: addrs,
		}
		n.pubKey, err = channelPeer.PubKey()
		if err != nil {
			return err
		}

		nodeAddrsMap[pubStr] = n
		return nil
	})
	if err != nil && err != channeldb.ErrGraphNoEdgesFound {
		return err
	}

	// Acquire and hold server lock until all persistent connection requests
	// have been recorded and sent to the connection manager.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Iterate through the combined list of addresses from prior links and
	// node announcements and attempt to reconnect to each node.
	var numOutboundConns int
	for pubStr, nodeAddr := range nodeAddrsMap {
		// Add this peer to the set of peers we should maintain a
		// persistent connection with. We set the value to false to
		// indicate that we should not continue to reconnect if the
		// number of channels returns to zero, since this peer has not
		// been requested as perm by the user.
		s.persistentPeers[pubStr] = false
		if _, ok := s.persistentPeersBackoff[pubStr]; !ok {
			s.persistentPeersBackoff[pubStr] = s.cfg.MinBackoff
		}

		for _, address := range nodeAddr.addresses {
			// Create a wrapper address which couples the IP and
			// the pubkey so the brontide authenticated connection
			// can be established.
			lnAddr := &lnwire.NetAddress{
				IdentityKey: nodeAddr.pubKey,
				Address:     address,
			}
			srvrLog.Debugf("Attempting persistent connection to "+
				"channel peer %v", lnAddr)

			// Send the persistent connection request to the
			// connection manager, saving the request itself so we
			// can cancel/restart the process as needed.
			connReq := &connmgr.ConnReq{
				Addr:      lnAddr,
				Permanent: true,
			}

			s.persistentConnReqs[pubStr] = append(
				s.persistentConnReqs[pubStr], connReq)

			// We'll connect to the first 10 peers immediately, then
			// randomly stagger any remaining connections if the
			// stagger initial reconnect flag is set. This ensures
			// that mobile nodes or nodes with a small number of
			// channels obtain connectivity quickly, but larger
			// nodes are able to disperse the costs of connecting to
			// all peers at once.
			if numOutboundConns < numInstantInitReconnect ||
				!s.cfg.StaggerInitialReconnect {

				go s.connMgr.Connect(connReq)
			} else {
				go s.delayInitialReconnect(connReq)
			}
		}

		numOutboundConns++
	}

	return nil
}

// delayInitialReconnect will attempt a reconnection using the passed connreq
// after sampling a value for the delay between 0s and the
// maxInitReconnectDelay.
//
// NOTE: This method MUST be run as a goroutine.
func (s *server) delayInitialReconnect(connReq *connmgr.ConnReq) {
	delay := time.Duration(prand.Intn(maxInitReconnectDelay)) * time.Second
	select {
	case <-time.After(delay):
		s.connMgr.Connect(connReq)
	case <-s.quit:
	}
}

// prunePersistentPeerConnection removes all internal state related to
// persistent connections to a peer within the server. This is used to avoid
// persistent connection retries to peers we do not have any open channels with.
func (s *server) prunePersistentPeerConnection(compressedPubKey [33]byte) {
	pubKeyStr := string(compressedPubKey[:])

	s.mu.Lock()
	if perm, ok := s.persistentPeers[pubKeyStr]; ok && !perm {
		delete(s.persistentPeers, pubKeyStr)
		delete(s.persistentPeersBackoff, pubKeyStr)
		s.cancelConnReqs(pubKeyStr, nil)
		s.mu.Unlock()

		srvrLog.Infof("Pruned peer %x from persistent connections, "+
			"peer has no open channels", compressedPubKey)

		return
	}
	s.mu.Unlock()
}

// BroadcastMessage sends a request to the server to broadcast a set of
// messages to all peers other than the one specified by the `skips` parameter.
// All messages sent via BroadcastMessage will be queued for lazy delivery to
// the target peers.
//
// NOTE: This function is safe for concurrent access.
func (s *server) BroadcastMessage(skips map[route.Vertex]struct{},
	msgs ...lnwire.Message) error {

	srvrLog.Debugf("Broadcasting %v messages", len(msgs))

	// Filter out peers found in the skips map. We synchronize access to
	// peersByPub throughout this process to ensure we deliver messages to
	// exact set of peers present at the time of invocation.
	s.mu.RLock()
	peers := make([]*peer.Brontide, 0, len(s.peersByPub))
	for _, sPeer := range s.peersByPub {
		if skips != nil {
			if _, ok := skips[sPeer.PubKey()]; ok {
				srvrLog.Tracef("Skipping %x in broadcast",
					sPeer.PubKey())
				continue
			}
		}

		peers = append(peers, sPeer)
	}
	s.mu.RUnlock()

	// Iterate over all known peers, dispatching a go routine to enqueue
	// all messages to each of peers.
	var wg sync.WaitGroup
	for _, sPeer := range peers {
		// Dispatch a go routine to enqueue all messages to this peer.
		wg.Add(1)
		s.wg.Add(1)
		go func(p lnpeer.Peer) {
			defer s.wg.Done()
			defer wg.Done()

			p.SendMessageLazy(false, msgs...)
		}(sPeer)
	}

	// Wait for all messages to have been dispatched before returning to
	// caller.
	wg.Wait()

	return nil
}

// NotifyWhenOnline can be called by other subsystems to get notified when a
// particular peer comes online. The peer itself is sent across the peerChan.
//
// NOTE: This function is safe for concurrent access.
func (s *server) NotifyWhenOnline(peerKey [33]byte,
	peerChan chan<- lnpeer.Peer) {

	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute the target peer's identifier.
	pubStr := string(peerKey[:])

	// Check if peer is connected.
	peer, ok := s.peersByPub[pubStr]
	if ok {
		// Connected, can return early.
		srvrLog.Debugf("Notifying that peer %x is online", peerKey)

		select {
		case peerChan <- peer:
		case <-s.quit:
		}

		return
	}

	// Not connected, store this listener such that it can be notified when
	// the peer comes online.
	s.peerConnectedListeners[pubStr] = append(
		s.peerConnectedListeners[pubStr], peerChan,
	)
}

// NotifyWhenOffline delivers a notification to the caller of when the peer with
// the given public key has been disconnected. The notification is signaled by
// closing the channel returned.
func (s *server) NotifyWhenOffline(peerPubKey [33]byte) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := make(chan struct{})

	// If the peer is already offline, we can immediately trigger the
	// notification.
	peerPubKeyStr := string(peerPubKey[:])
	if _, ok := s.peersByPub[peerPubKeyStr]; !ok {
		srvrLog.Debugf("Notifying that peer %x is offline", peerPubKey)
		close(c)
		return c
	}

	// Otherwise, the peer is online, so we'll keep track of the channel to
	// trigger the notification once the server detects the peer
	// disconnects.
	s.peerDisconnectedListeners[peerPubKeyStr] = append(
		s.peerDisconnectedListeners[peerPubKeyStr], c,
	)

	return c
}

// FindPeer will return the peer that corresponds to the passed in public key.
// This function is used by the funding manager, allowing it to update the
// daemon's local representation of the remote peer.
//
// NOTE: This function is safe for concurrent access.
func (s *server) FindPeer(peerKey *btcec.PublicKey) (*peer.Brontide, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pubStr := string(peerKey.SerializeCompressed())

	return s.findPeerByPubStr(pubStr)
}

// FindPeerByPubStr will return the peer that corresponds to the passed peerID,
// which should be a string representation of the peer's serialized, compressed
// public key.
//
// NOTE: This function is safe for concurrent access.
func (s *server) FindPeerByPubStr(pubStr string) (*peer.Brontide, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.findPeerByPubStr(pubStr)
}

// findPeerByPubStr is an internal method that retrieves the specified peer from
// the server's internal state using.
func (s *server) findPeerByPubStr(pubStr string) (*peer.Brontide, error) {
	peer, ok := s.peersByPub[pubStr]
	if !ok {
		return nil, ErrPeerNotConnected
	}

	return peer, nil
}

// nextPeerBackoff computes the next backoff duration for a peer's pubkey using
// exponential backoff. If no previous backoff was known, the default is
// returned.
func (s *server) nextPeerBackoff(pubStr string,
	startTime time.Time) time.Duration {

	// Now, determine the appropriate backoff to use for the retry.
	backoff, ok := s.persistentPeersBackoff[pubStr]
	if !ok {
		// If an existing backoff was unknown, use the default.
		return s.cfg.MinBackoff
	}

	// If the peer failed to start properly, we'll just use the previous
	// backoff to compute the subsequent randomized exponential backoff
	// duration. This will roughly double on average.
	if startTime.IsZero() {
		return computeNextBackoff(backoff, s.cfg.MaxBackoff)
	}

	// The peer succeeded in starting. If the connection didn't last long
	// enough to be considered stable, we'll continue to back off retries
	// with this peer.
	connDuration := time.Since(startTime)
	if connDuration < defaultStableConnDuration {
		return computeNextBackoff(backoff, s.cfg.MaxBackoff)
	}

	// The peer succeed in starting and this was stable peer, so we'll
	// reduce the timeout duration by the length of the connection after
	// applying randomized exponential backoff. We'll only apply this in the
	// case that:
	//   reb(curBackoff) - connDuration > cfg.MinBackoff
	relaxedBackoff := computeNextBackoff(backoff, s.cfg.MaxBackoff) - connDuration
	if relaxedBackoff > s.cfg.MinBackoff {
		return relaxedBackoff
	}

	// Lastly, if reb(currBackoff) - connDuration <= cfg.MinBackoff, meaning
	// the stable connection lasted much longer than our previous backoff.
	// To reward such good behavior, we'll reconnect after the default
	// timeout.
	return s.cfg.MinBackoff
}

// shouldDropConnection determines if our local connection to a remote peer
// should be dropped in the case of concurrent connection establishment. In
// order to deterministically decide which connection should be dropped, we'll
// utilize the ordering of the local and remote public key. If we didn't use
// such a tie breaker, then we risk _both_ connections erroneously being
// dropped.
func shouldDropLocalConnection(local, remote *btcec.PublicKey) bool {
	localPubBytes := local.SerializeCompressed()
	remotePubPbytes := remote.SerializeCompressed()

	// The connection that comes from the node with a "smaller" pubkey
	// should be kept. Therefore, if our pubkey is "greater" than theirs, we
	// should drop our established connection.
	return bytes.Compare(localPubBytes, remotePubPbytes) > 0
}

// InboundPeerConnected initializes a new peer in response to a new inbound
// connection.
//
// NOTE: This function is safe for concurrent access.
func (s *server) InboundPeerConnected(conn net.Conn) {
	// Exit early if we have already been instructed to shutdown, this
	// prevents any delayed callbacks from accidentally registering peers.
	if s.Stopped() {
		return
	}

	nodePub := conn.(*brontide.Conn).RemotePub()
	pubStr := string(nodePub.SerializeCompressed())

	s.mu.Lock()
	defer s.mu.Unlock()

	// If we already have an outbound connection to this peer, then ignore
	// this new connection.
	if _, ok := s.outboundPeers[pubStr]; ok {
		srvrLog.Debugf("Already have outbound connection for %x, "+
			"ignoring inbound connection",
			nodePub.SerializeCompressed())

		conn.Close()
		return
	}

	// If we already have a valid connection that is scheduled to take
	// precedence once the prior peer has finished disconnecting, we'll
	// ignore this connection.
	if _, ok := s.scheduledPeerConnection[pubStr]; ok {
		srvrLog.Debugf("Ignoring connection, peer already scheduled")
		conn.Close()
		return
	}

	srvrLog.Infof("New inbound connection from %v", conn.RemoteAddr())

	// Check to see if we already have a connection with this peer. If so,
	// we may need to drop our existing connection. This prevents us from
	// having duplicate connections to the same peer. We forgo adding a
	// default case as we expect these to be the only error values returned
	// from findPeerByPubStr.
	connectedPeer, err := s.findPeerByPubStr(pubStr)
	switch err {
	case ErrPeerNotConnected:
		// We were unable to locate an existing connection with the
		// target peer, proceed to connect.
		s.cancelConnReqs(pubStr, nil)
		s.peerConnected(conn, nil, true)

	case nil:
		// We already have a connection with the incoming peer. If the
		// connection we've already established should be kept and is
		// not of the same type of the new connection (inbound), then
		// we'll close out the new connection s.t there's only a single
		// connection between us.
		localPub := s.identityECDH.PubKey()
		if !connectedPeer.Inbound() &&
			!shouldDropLocalConnection(localPub, nodePub) {

			srvrLog.Warnf("Received inbound connection from "+
				"peer %v, but already have outbound "+
				"connection, dropping conn", connectedPeer)
			conn.Close()
			return
		}

		// Otherwise, if we should drop the connection, then we'll
		// disconnect our already connected peer.
		srvrLog.Debugf("Disconnecting stale connection to %v",
			connectedPeer)

		s.cancelConnReqs(pubStr, nil)

		// Remove the current peer from the server's internal state and
		// signal that the peer termination watcher does not need to
		// execute for this peer.
		s.removePeer(connectedPeer)
		s.ignorePeerTermination[connectedPeer] = struct{}{}
		s.scheduledPeerConnection[pubStr] = func() {
			s.peerConnected(conn, nil, true)
		}
	}
}

// OutboundPeerConnected initializes a new peer in response to a new outbound
// connection.
// NOTE: This function is safe for concurrent access.
func (s *server) OutboundPeerConnected(connReq *connmgr.ConnReq, conn net.Conn) {
	// Exit early if we have already been instructed to shutdown, this
	// prevents any delayed callbacks from accidentally registering peers.
	if s.Stopped() {
		return
	}

	nodePub := conn.(*brontide.Conn).RemotePub()
	pubStr := string(nodePub.SerializeCompressed())

	s.mu.Lock()
	defer s.mu.Unlock()

	// If we already have an inbound connection to this peer, then ignore
	// this new connection.
	if _, ok := s.inboundPeers[pubStr]; ok {
		srvrLog.Debugf("Already have inbound connection for %x, "+
			"ignoring outbound connection",
			nodePub.SerializeCompressed())

		if connReq != nil {
			s.connMgr.Remove(connReq.ID())
		}
		conn.Close()
		return
	}
	if _, ok := s.persistentConnReqs[pubStr]; !ok && connReq != nil {
		srvrLog.Debugf("Ignoring canceled outbound connection")
		s.connMgr.Remove(connReq.ID())
		conn.Close()
		return
	}

	// If we already have a valid connection that is scheduled to take
	// precedence once the prior peer has finished disconnecting, we'll
	// ignore this connection.
	if _, ok := s.scheduledPeerConnection[pubStr]; ok {
		srvrLog.Debugf("Ignoring connection, peer already scheduled")

		if connReq != nil {
			s.connMgr.Remove(connReq.ID())
		}

		conn.Close()
		return
	}

	srvrLog.Infof("Established connection to: %x@%v", pubStr,
		conn.RemoteAddr())

	if connReq != nil {
		// A successful connection was returned by the connmgr.
		// Immediately cancel all pending requests, excluding the
		// outbound connection we just established.
		ignore := connReq.ID()
		s.cancelConnReqs(pubStr, &ignore)
	} else {
		// This was a successful connection made by some other
		// subsystem. Remove all requests being managed by the connmgr.
		s.cancelConnReqs(pubStr, nil)
	}

	// If we already have a connection with this peer, decide whether or not
	// we need to drop the stale connection. We forgo adding a default case
	// as we expect these to be the only error values returned from
	// findPeerByPubStr.
	connectedPeer, err := s.findPeerByPubStr(pubStr)
	switch err {
	case ErrPeerNotConnected:
		// We were unable to locate an existing connection with the
		// target peer, proceed to connect.
		s.peerConnected(conn, connReq, false)

	case nil:
		// We already have a connection with the incoming peer. If the
		// connection we've already established should be kept and is
		// not of the same type of the new connection (outbound), then
		// we'll close out the new connection s.t there's only a single
		// connection between us.
		localPub := s.identityECDH.PubKey()
		if connectedPeer.Inbound() &&
			shouldDropLocalConnection(localPub, nodePub) {

			srvrLog.Warnf("Established outbound connection to "+
				"peer %v, but already have inbound "+
				"connection, dropping conn", connectedPeer)
			if connReq != nil {
				s.connMgr.Remove(connReq.ID())
			}
			conn.Close()
			return
		}

		// Otherwise, _their_ connection should be dropped. So we'll
		// disconnect the peer and send the now obsolete peer to the
		// server for garbage collection.
		srvrLog.Debugf("Disconnecting stale connection to %v",
			connectedPeer)

		// Remove the current peer from the server's internal state and
		// signal that the peer termination watcher does not need to
		// execute for this peer.
		s.removePeer(connectedPeer)
		s.ignorePeerTermination[connectedPeer] = struct{}{}
		s.scheduledPeerConnection[pubStr] = func() {
			s.peerConnected(conn, connReq, false)
		}
	}
}

// UnassignedConnID is the default connection ID that a request can have before
// it actually is submitted to the connmgr.
// TODO(conner): move into connmgr package, or better, add connmgr method for
// generating atomic IDs
const UnassignedConnID uint64 = 0

// cancelConnReqs stops all persistent connection requests for a given pubkey.
// Any attempts initiated by the peerTerminationWatcher are canceled first.
// Afterwards, each connection request removed from the connmgr. The caller can
// optionally specify a connection ID to ignore, which prevents us from
// canceling a successful request. All persistent connreqs for the provided
// pubkey are discarded after the operationjw.
func (s *server) cancelConnReqs(pubStr string, skip *uint64) {
	// First, cancel any lingering persistent retry attempts, which will
	// prevent retries for any with backoffs that are still maturing.
	if cancelChan, ok := s.persistentRetryCancels[pubStr]; ok {
		close(cancelChan)
		delete(s.persistentRetryCancels, pubStr)
	}

	// Next, check to see if we have any outstanding persistent connection
	// requests to this peer. If so, then we'll remove all of these
	// connection requests, and also delete the entry from the map.
	connReqs, ok := s.persistentConnReqs[pubStr]
	if !ok {
		return
	}

	for _, connReq := range connReqs {
		// Atomically capture the current request identifier.
		connID := connReq.ID()

		// Skip any zero IDs, this indicates the request has not
		// yet been schedule.
		if connID == UnassignedConnID {
			continue
		}

		// Skip a particular connection ID if instructed.
		if skip != nil && connID == *skip {
			continue
		}

		s.connMgr.Remove(connID)
	}

	delete(s.persistentConnReqs, pubStr)
}

// handleCustomMessage dispatches an incoming custom peers message to
// subscribers.
func (s *server) handleCustomMessage(peer [33]byte, msg *lnwire.Custom) error {
	srvrLog.Debugf("Custom message received: peer=%x, type=%d",
		peer, msg.Type)

	return s.customMessageServer.SendUpdate(&CustomMessage{
		Peer: peer,
		Msg:  msg,
	})
}

// SubscribeCustomMessages subscribes to a stream of incoming custom peer
// messages.
func (s *server) SubscribeCustomMessages() (*subscribe.Client, error) {
	return s.customMessageServer.Subscribe()
}

// peerConnected is a function that handles initialization a newly connected
// peer by adding it to the server's global list of all active peers, and
// starting all the goroutines the peer needs to function properly. The inbound
// boolean should be true if the peer initiated the connection to us.
func (s *server) peerConnected(conn net.Conn, connReq *connmgr.ConnReq,
	inbound bool) {

	brontideConn := conn.(*brontide.Conn)
	addr := conn.RemoteAddr()
	pubKey := brontideConn.RemotePub()

	srvrLog.Infof("Finalizing connection to %x@%s, inbound=%v",
		pubKey.SerializeCompressed(), addr, inbound)

	peerAddr := &lnwire.NetAddress{
		IdentityKey: pubKey,
		Address:     addr,
		ChainNet:    s.cfg.ActiveNetParams.Net,
	}

	// With the brontide connection established, we'll now craft the feature
	// vectors to advertise to the remote node.
	initFeatures := s.featureMgr.Get(feature.SetInit)
	legacyFeatures := s.featureMgr.Get(feature.SetLegacyGlobal)

	// Lookup past error caches for the peer in the server. If no buffer is
	// found, create a fresh buffer.
	pkStr := string(peerAddr.IdentityKey.SerializeCompressed())
	errBuffer, ok := s.peerErrors[pkStr]
	if !ok {
		var err error
		errBuffer, err = queue.NewCircularBuffer(peer.ErrorBufferSize)
		if err != nil {
			srvrLog.Errorf("unable to create peer %v", err)
			return
		}
	}

	// Now that we've established a connection, create a peer, and it to the
	// set of currently active peers. Configure the peer with the incoming
	// and outgoing broadcast deltas to prevent htlcs from being accepted or
	// offered that would trigger channel closure. In case of outgoing
	// htlcs, an extra block is added to prevent the channel from being
	// closed when the htlc is outstanding and a new block comes in.
	pCfg := peer.Config{
		Conn:                    brontideConn,
		ConnReq:                 connReq,
		Addr:                    peerAddr,
		Inbound:                 inbound,
		Features:                initFeatures,
		LegacyFeatures:          legacyFeatures,
		OutgoingCltvRejectDelta: lncfg.DefaultOutgoingCltvRejectDelta,
		ChanActiveTimeout:       s.cfg.ChanEnableTimeout,
		ErrorBuffer:             errBuffer,
		WritePool:               s.writePool,
		ReadPool:                s.readPool,
		Switch:                  s.htlcSwitch,
		InterceptSwitch:         s.interceptableSwitch,
		ChannelDB:               s.remoteChanDB,
		ChannelGraph:            s.localChanDB.ChannelGraph(),
		ChainArb:                s.chainArb,
		AuthGossiper:            s.authGossiper,
		ChanStatusMgr:           s.chanStatusMgr,
		ChainIO:                 s.cc.ChainIO,
		FeeEstimator:            s.cc.FeeEstimator,
		Signer:                  s.cc.Wallet.Cfg.Signer,
		SigPool:                 s.sigPool,
		Wallet:                  s.cc.Wallet,
		ChainNotifier:           s.cc.ChainNotifier,
		RoutingPolicy:           s.cc.RoutingPolicy,
		Sphinx:                  s.sphinx,
		WitnessBeacon:           s.witnessBeacon,
		Invoices:                s.invoices,
		ChannelNotifier:         s.channelNotifier,
		HtlcNotifier:            s.htlcNotifier,
		TowerClient:             s.towerClient,
		AnchorTowerClient:       s.anchorTowerClient,
		DisconnectPeer:          s.DisconnectPeer,
		GenNodeAnnouncement:     s.genNodeAnnouncement,

		PrunePersistentPeerConnection: s.prunePersistentPeerConnection,

		FetchLastChanUpdate: s.fetchLastChanUpdate(),

		FundingManager: s.fundingMgr,

		Hodl:                    s.cfg.Hodl,
		UnsafeReplay:            s.cfg.UnsafeReplay,
		MaxOutgoingCltvExpiry:   s.cfg.MaxOutgoingCltvExpiry,
		MaxChannelFeeAllocation: s.cfg.MaxChannelFeeAllocation,
		CoopCloseTargetConfs:    s.cfg.CoopCloseTargetConfs,
		MaxAnchorsCommitFeeRate: chainfee.SatPerKVByte(
			s.cfg.MaxCommitFeeRateAnchors * 1000).FeePerKWeight(),
		ChannelCommitInterval:  s.cfg.ChannelCommitInterval,
		ChannelCommitBatchSize: s.cfg.ChannelCommitBatchSize,
		HandleCustomMessage:    s.handleCustomMessage,
		Quit:                   s.quit,
	}

	copy(pCfg.PubKeyBytes[:], peerAddr.IdentityKey.SerializeCompressed())
	copy(pCfg.ServerPubKey[:], s.identityECDH.PubKey().SerializeCompressed())

	p := peer.NewBrontide(pCfg)

	// TODO(roasbeef): update IP address for link-node
	//  * also mark last-seen, do it one single transaction?

	s.addPeer(p)

	// Once we have successfully added the peer to the server, we can
	// delete the previous error buffer from the server's map of error
	// buffers.
	delete(s.peerErrors, pkStr)

	// Dispatch a goroutine to asynchronously start the peer. This process
	// includes sending and receiving Init messages, which would be a DOS
	// vector if we held the server's mutex throughout the procedure.
	s.wg.Add(1)
	go s.peerInitializer(p)
}

// addPeer adds the passed peer to the server's global state of all active
// peers.
func (s *server) addPeer(p *peer.Brontide) {
	if p == nil {
		return
	}

	// Ignore new peers if we're shutting down.
	if s.Stopped() {
		p.Disconnect(ErrServerShuttingDown)
		return
	}

	// Track the new peer in our indexes so we can quickly look it up either
	// according to its public key, or its peer ID.
	// TODO(roasbeef): pipe all requests through to the
	// queryHandler/peerManager

	pubSer := p.IdentityKey().SerializeCompressed()
	pubStr := string(pubSer)

	s.peersByPub[pubStr] = p

	if p.Inbound() {
		s.inboundPeers[pubStr] = p
	} else {
		s.outboundPeers[pubStr] = p
	}

	// Inform the peer notifier of a peer online event so that it can be reported
	// to clients listening for peer events.
	var pubKey [33]byte
	copy(pubKey[:], pubSer)

	s.peerNotifier.NotifyPeerOnline(pubKey)
}

// peerInitializer asynchronously starts a newly connected peer after it has
// been added to the server's peer map. This method sets up a
// peerTerminationWatcher for the given peer, and ensures that it executes even
// if the peer failed to start. In the event of a successful connection, this
// method reads the negotiated, local feature-bits and spawns the appropriate
// graph synchronization method. Any registered clients of NotifyWhenOnline will
// be signaled of the new peer once the method returns.
//
// NOTE: This MUST be launched as a goroutine.
func (s *server) peerInitializer(p *peer.Brontide) {
	defer s.wg.Done()

	// Avoid initializing peers while the server is exiting.
	if s.Stopped() {
		return
	}

	// Create a channel that will be used to signal a successful start of
	// the link. This prevents the peer termination watcher from beginning
	// its duty too early.
	ready := make(chan struct{})

	// Before starting the peer, launch a goroutine to watch for the
	// unexpected termination of this peer, which will ensure all resources
	// are properly cleaned up, and re-establish persistent connections when
	// necessary. The peer termination watcher will be short circuited if
	// the peer is ever added to the ignorePeerTermination map, indicating
	// that the server has already handled the removal of this peer.
	s.wg.Add(1)
	go s.peerTerminationWatcher(p, ready)

	// Start the peer! If an error occurs, we Disconnect the peer, which
	// will unblock the peerTerminationWatcher.
	if err := p.Start(); err != nil {
		p.Disconnect(fmt.Errorf("unable to start peer: %v", err))
		return
	}

	// Otherwise, signal to the peerTerminationWatcher that the peer startup
	// was successful, and to begin watching the peer's wait group.
	close(ready)

	pubStr := string(p.IdentityKey().SerializeCompressed())

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if there are listeners waiting for this peer to come online.
	srvrLog.Debugf("Notifying that peer %v is online", p)
	for _, peerChan := range s.peerConnectedListeners[pubStr] {
		select {
		case peerChan <- p:
		case <-s.quit:
			return
		}
	}
	delete(s.peerConnectedListeners, pubStr)
}

// peerTerminationWatcher waits until a peer has been disconnected unexpectedly,
// and then cleans up all resources allocated to the peer, notifies relevant
// sub-systems of its demise, and finally handles re-connecting to the peer if
// it's persistent. If the server intentionally disconnects a peer, it should
// have a corresponding entry in the ignorePeerTermination map which will cause
// the cleanup routine to exit early. The passed `ready` chan is used to
// synchronize when WaitForDisconnect should begin watching on the peer's
// waitgroup. The ready chan should only be signaled if the peer starts
// successfully, otherwise the peer should be disconnected instead.
//
// NOTE: This MUST be launched as a goroutine.
func (s *server) peerTerminationWatcher(p *peer.Brontide, ready chan struct{}) {
	defer s.wg.Done()

	p.WaitForDisconnect(ready)

	srvrLog.Debugf("Peer %v has been disconnected", p)

	// If the server is exiting then we can bail out early ourselves as all
	// the other sub-systems will already be shutting down.
	if s.Stopped() {
		return
	}

	// Next, we'll cancel all pending funding reservations with this node.
	// If we tried to initiate any funding flows that haven't yet finished,
	// then we need to unlock those committed outputs so they're still
	// available for use.
	s.fundingMgr.CancelPeerReservations(p.PubKey())

	pubKey := p.IdentityKey()

	// We'll also inform the gossiper that this peer is no longer active,
	// so we don't need to maintain sync state for it any longer.
	s.authGossiper.PruneSyncState(p.PubKey())

	// Tell the switch to remove all links associated with this peer.
	// Passing nil as the target link indicates that all links associated
	// with this interface should be closed.
	//
	// TODO(roasbeef): instead add a PurgeInterfaceLinks function?
	links, err := s.htlcSwitch.GetLinksByInterface(p.PubKey())
	if err != nil && err != htlcswitch.ErrNoLinksFound {
		srvrLog.Errorf("Unable to get channel links for %v: %v", p, err)
	}

	for _, link := range links {
		s.htlcSwitch.RemoveLink(link.ChanID())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If there were any notification requests for when this peer
	// disconnected, we can trigger them now.
	srvrLog.Debugf("Notifying that peer %v is offline", p)
	pubStr := string(pubKey.SerializeCompressed())
	for _, offlineChan := range s.peerDisconnectedListeners[pubStr] {
		close(offlineChan)
	}
	delete(s.peerDisconnectedListeners, pubStr)

	// If the server has already removed this peer, we can short circuit the
	// peer termination watcher and skip cleanup.
	if _, ok := s.ignorePeerTermination[p]; ok {
		delete(s.ignorePeerTermination, p)

		pubKey := p.PubKey()
		pubStr := string(pubKey[:])

		// If a connection callback is present, we'll go ahead and
		// execute it now that previous peer has fully disconnected. If
		// the callback is not present, this likely implies the peer was
		// purposefully disconnected via RPC, and that no reconnect
		// should be attempted.
		connCallback, ok := s.scheduledPeerConnection[pubStr]
		if ok {
			delete(s.scheduledPeerConnection, pubStr)
			connCallback()
		}
		return
	}

	// First, cleanup any remaining state the server has regarding the peer
	// in question.
	s.removePeer(p)

	// Next, check to see if this is a persistent peer or not.
	_, ok := s.persistentPeers[pubStr]
	if ok {
		// We'll only need to re-launch a connection request if one
		// isn't already currently pending.
		if _, ok := s.persistentConnReqs[pubStr]; ok {
			return
		}

		// We'll ensure that we locate an advertised address to use
		// within the peer's address for reconnection purposes.
		//
		// TODO(roasbeef): use them all?
		if p.Inbound() {
			advertisedAddr, err := s.fetchNodeAdvertisedAddr(pubKey)
			switch {
			// We found an advertised address, so use it.
			case err == nil:
				p.SetAddress(advertisedAddr)

			// The peer doesn't have an advertised address.
			case err == errNoAdvertisedAddr:
				// Fall back to the existing peer address if
				// we're not accepting connections over Tor.
				if s.torController == nil {
					break
				}

				// If we are, the peer's address won't be known
				// to us (we'll see a private address, which is
				// the address used by our onion service to dial
				// to lnd), so we don't have enough information
				// to attempt a reconnect.
				srvrLog.Debugf("Ignoring reconnection attempt "+
					"to inbound peer %v without "+
					"advertised address", p)
				return

			// We came across an error retrieving an advertised
			// address, log it, and fall back to the existing peer
			// address.
			default:
				srvrLog.Errorf("Unable to retrieve advertised "+
					"address for node %x: %v", p.PubKey(),
					err)
			}
		}

		// Otherwise, we'll launch a new connection request in order to
		// attempt to maintain a persistent connection with this peer.
		connReq := &connmgr.ConnReq{
			Addr:      p.NetAddress(),
			Permanent: true,
		}
		s.persistentConnReqs[pubStr] = append(
			s.persistentConnReqs[pubStr], connReq)

		// Record the computed backoff in the backoff map.
		backoff := s.nextPeerBackoff(pubStr, p.StartTime())
		s.persistentPeersBackoff[pubStr] = backoff

		// Initialize a retry canceller for this peer if one does not
		// exist.
		cancelChan, ok := s.persistentRetryCancels[pubStr]
		if !ok {
			cancelChan = make(chan struct{})
			s.persistentRetryCancels[pubStr] = cancelChan
		}

		// We choose not to wait group this go routine since the Connect
		// call can stall for arbitrarily long if we shutdown while an
		// outbound connection attempt is being made.
		go func() {
			srvrLog.Debugf("Scheduling connection re-establishment to "+
				"persistent peer %v in %s", p, backoff)

			select {
			case <-time.After(backoff):
			case <-cancelChan:
				return
			case <-s.quit:
				return
			}

			srvrLog.Debugf("Attempting to re-establish persistent "+
				"connection to peer %v", p)

			s.connMgr.Connect(connReq)
		}()
	}
}

// removePeer removes the passed peer from the server's state of all active
// peers.
func (s *server) removePeer(p *peer.Brontide) {
	if p == nil {
		return
	}

	srvrLog.Debugf("removing peer %v", p)

	// As the peer is now finished, ensure that the TCP connection is
	// closed and all of its related goroutines have exited.
	p.Disconnect(fmt.Errorf("server: disconnecting peer %v", p))

	// If this peer had an active persistent connection request, remove it.
	if p.ConnReq() != nil {
		s.connMgr.Remove(p.ConnReq().ID())
	}

	// Ignore deleting peers if we're shutting down.
	if s.Stopped() {
		return
	}

	pKey := p.PubKey()
	pubSer := pKey[:]
	pubStr := string(pubSer)

	delete(s.peersByPub, pubStr)

	if p.Inbound() {
		delete(s.inboundPeers, pubStr)
	} else {
		delete(s.outboundPeers, pubStr)
	}

	// Copy the peer's error buffer across to the server if it has any items
	// in it so that we can restore peer errors across connections.
	if p.ErrorBuffer().Total() > 0 {
		s.peerErrors[pubStr] = p.ErrorBuffer()
	}

	// Inform the peer notifier of a peer offline event so that it can be
	// reported to clients listening for peer events.
	var pubKey [33]byte
	copy(pubKey[:], pubSer)

	s.peerNotifier.NotifyPeerOffline(pubKey)
}

// ConnectToPeer requests that the server connect to a Lightning Network peer
// at the specified address. This function will *block* until either a
// connection is established, or the initial handshake process fails.
//
// NOTE: This function is safe for concurrent access.
func (s *server) ConnectToPeer(addr *lnwire.NetAddress,
	perm bool, timeout time.Duration) error {

	targetPub := string(addr.IdentityKey.SerializeCompressed())

	// Acquire mutex, but use explicit unlocking instead of defer for
	// better granularity.  In certain conditions, this method requires
	// making an outbound connection to a remote peer, which requires the
	// lock to be released, and subsequently reacquired.
	s.mu.Lock()

	// Ensure we're not already connected to this peer.
	peer, err := s.findPeerByPubStr(targetPub)
	if err == nil {
		s.mu.Unlock()
		return &errPeerAlreadyConnected{peer: peer}
	}

	// Peer was not found, continue to pursue connection with peer.

	// If there's already a pending connection request for this pubkey,
	// then we ignore this request to ensure we don't create a redundant
	// connection.
	if reqs, ok := s.persistentConnReqs[targetPub]; ok {
		srvrLog.Warnf("Already have %d persistent connection "+
			"requests for %x@%v, connecting anyway.", len(reqs),
			targetPub, addr)
	}

	// If there's not already a pending or active connection to this node,
	// then instruct the connection manager to attempt to establish a
	// persistent connection to the peer.
	srvrLog.Debugf("Connecting to %x@%v", targetPub, addr)
	if perm {
		connReq := &connmgr.ConnReq{
			Addr:      addr,
			Permanent: true,
		}

		// Since the user requested a permanent connection, we'll set
		// the entry to true which will tell the server to continue
		// reconnecting even if the number of channels with this peer is
		// zero.
		s.persistentPeers[targetPub] = true
		if _, ok := s.persistentPeersBackoff[targetPub]; !ok {
			s.persistentPeersBackoff[targetPub] = s.cfg.MinBackoff
		}
		s.persistentConnReqs[targetPub] = append(
			s.persistentConnReqs[targetPub], connReq,
		)
		s.mu.Unlock()

		go s.connMgr.Connect(connReq)

		return nil
	}
	s.mu.Unlock()

	// If we're not making a persistent connection, then we'll attempt to
	// connect to the target peer. If the we can't make the connection, or
	// the crypto negotiation breaks down, then return an error to the
	// caller.
	errChan := make(chan error, 1)
	s.connectToPeer(addr, errChan, timeout)

	select {
	case err := <-errChan:
		return err
	case <-s.quit:
		return ErrServerShuttingDown
	}
}

// connectToPeer establishes a connection to a remote peer. errChan is used to
// notify the caller if the connection attempt has failed. Otherwise, it will be
// closed.
func (s *server) connectToPeer(addr *lnwire.NetAddress,
	errChan chan<- error, timeout time.Duration) {

	conn, err := brontide.Dial(
		s.identityECDH, addr, timeout, s.cfg.net.Dial,
	)
	if err != nil {
		srvrLog.Errorf("Unable to connect to %v: %v", addr, err)
		select {
		case errChan <- err:
		case <-s.quit:
		}
		return
	}

	close(errChan)

	s.OutboundPeerConnected(nil, conn)
}

// DisconnectPeer sends the request to server to close the connection with peer
// identified by public key.
//
// NOTE: This function is safe for concurrent access.
func (s *server) DisconnectPeer(pubKey *btcec.PublicKey) error {
	pubBytes := pubKey.SerializeCompressed()
	pubStr := string(pubBytes)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check that were actually connected to this peer. If not, then we'll
	// exit in an error as we can't disconnect from a peer that we're not
	// currently connected to.
	peer, err := s.findPeerByPubStr(pubStr)
	if err == ErrPeerNotConnected {
		return fmt.Errorf("peer %x is not connected", pubBytes)
	}

	srvrLog.Infof("Disconnecting from %v", peer)

	s.cancelConnReqs(pubStr, nil)

	// If this peer was formerly a persistent connection, then we'll remove
	// them from this map so we don't attempt to re-connect after we
	// disconnect.
	delete(s.persistentPeers, pubStr)
	delete(s.persistentPeersBackoff, pubStr)

	// Remove the current peer from the server's internal state and signal
	// that the peer termination watcher does not need to execute for this
	// peer.
	s.removePeer(peer)
	s.ignorePeerTermination[peer] = struct{}{}

	return nil
}

// OpenChannel sends a request to the server to open a channel to the specified
// peer identified by nodeKey with the passed channel funding parameters.
//
// NOTE: This function is safe for concurrent access.
func (s *server) OpenChannel(
	req *funding.InitFundingMsg) (chan *lnrpc.OpenStatusUpdate, chan error) {

	// The updateChan will have a buffer of 2, since we expect a ChanPending
	// + a ChanOpen update, and we want to make sure the funding process is
	// not blocked if the caller is not reading the updates.
	req.Updates = make(chan *lnrpc.OpenStatusUpdate, 2)
	req.Err = make(chan error, 1)

	// First attempt to locate the target peer to open a channel with, if
	// we're unable to locate the peer then this request will fail.
	pubKeyBytes := req.TargetPubkey.SerializeCompressed()
	s.mu.RLock()
	peer, ok := s.peersByPub[string(pubKeyBytes)]
	if !ok {
		s.mu.RUnlock()

		req.Err <- fmt.Errorf("peer %x is not online", pubKeyBytes)
		return req.Updates, req.Err
	}
	req.Peer = peer
	s.mu.RUnlock()

	// We'll wait until the peer is active before beginning the channel
	// opening process.
	select {
	case <-peer.ActiveSignal():
	case <-peer.QuitSignal():
		req.Err <- fmt.Errorf("peer %x disconnected", pubKeyBytes)
		return req.Updates, req.Err
	case <-s.quit:
		req.Err <- ErrServerShuttingDown
		return req.Updates, req.Err
	}

	// If the fee rate wasn't specified, then we'll use a default
	// confirmation target.
	if req.FundingFeePerKw == 0 {
		estimator := s.cc.FeeEstimator
		feeRate, err := estimator.EstimateFeePerKW(6)
		if err != nil {
			req.Err <- err
			return req.Updates, req.Err
		}
		req.FundingFeePerKw = feeRate
	}

	// Spawn a goroutine to send the funding workflow request to the funding
	// manager. This allows the server to continue handling queries instead
	// of blocking on this request which is exported as a synchronous
	// request to the outside world.
	go s.fundingMgr.InitFundingWorkflow(req)

	return req.Updates, req.Err
}

// Peers returns a slice of all active peers.
//
// NOTE: This function is safe for concurrent access.
func (s *server) Peers() []*peer.Brontide {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]*peer.Brontide, 0, len(s.peersByPub))
	for _, peer := range s.peersByPub {
		peers = append(peers, peer)
	}

	return peers
}

// parseHexColor takes a hex string representation of a color in the
// form "#RRGGBB", parses the hex color values, and returns a color.RGBA
// struct of the same color.
func parseHexColor(colorStr string) (color.RGBA, error) {
	// Check if the hex color string is a valid color representation.
	if !validColorRegexp.MatchString(colorStr) {
		return color.RGBA{}, errors.New("Color must be specified " +
			"using a hexadecimal value in the form #RRGGBB")
	}

	// Decode the hex color string to bytes.
	// The resulting byte array is in the form [R, G, B].
	colorBytes, err := hex.DecodeString(colorStr[1:])
	if err != nil {
		return color.RGBA{}, err
	}

	return color.RGBA{R: colorBytes[0], G: colorBytes[1], B: colorBytes[2]}, nil
}

// computeNextBackoff uses a truncated exponential backoff to compute the next
// backoff using the value of the exiting backoff. The returned duration is
// randomized in either direction by 1/20 to prevent tight loops from
// stabilizing.
func computeNextBackoff(currBackoff, maxBackoff time.Duration) time.Duration {
	// Double the current backoff, truncating if it exceeds our maximum.
	nextBackoff := 2 * currBackoff
	if nextBackoff > maxBackoff {
		nextBackoff = maxBackoff
	}

	// Using 1/10 of our duration as a margin, compute a random offset to
	// avoid the nodes entering connection cycles.
	margin := nextBackoff / 10

	var wiggle big.Int
	wiggle.SetUint64(uint64(margin))
	if _, err := rand.Int(rand.Reader, &wiggle); err != nil {
		// Randomizing is not mission critical, so we'll just return the
		// current backoff.
		return nextBackoff
	}

	// Otherwise add in our wiggle, but subtract out half of the margin so
	// that the backoff can tweaked by 1/20 in either direction.
	return nextBackoff + (time.Duration(wiggle.Uint64()) - margin/2)
}

// errNoAdvertisedAddr is an error returned when we attempt to retrieve the
// advertised address of a node, but they don't have one.
var errNoAdvertisedAddr = errors.New("no advertised address found")

// fetchNodeAdvertisedAddr attempts to fetch an advertised address of a node.
func (s *server) fetchNodeAdvertisedAddr(pub *btcec.PublicKey) (net.Addr, error) {
	vertex, err := route.NewVertexFromBytes(pub.SerializeCompressed())
	if err != nil {
		return nil, err
	}

	node, err := s.localChanDB.ChannelGraph().FetchLightningNode(nil, vertex)
	if err != nil {
		return nil, err
	}

	if len(node.Addresses) == 0 {
		return nil, errNoAdvertisedAddr
	}

	return node.Addresses[0], nil
}

// fetchLastChanUpdate returns a function which is able to retrieve our latest
// channel update for a target channel.
func (s *server) fetchLastChanUpdate() func(lnwire.ShortChannelID) (
	*lnwire.ChannelUpdate, error) {

	ourPubKey := s.identityECDH.PubKey().SerializeCompressed()
	return func(cid lnwire.ShortChannelID) (*lnwire.ChannelUpdate, error) {
		info, edge1, edge2, err := s.chanRouter.GetChannelByID(cid)
		if err != nil {
			return nil, err
		}

		return netann.ExtractChannelUpdate(
			ourPubKey[:], info, edge1, edge2,
		)
	}
}

// applyChannelUpdate applies the channel update to the different sub-systems of
// the server.
func (s *server) applyChannelUpdate(update *lnwire.ChannelUpdate) error {
	errChan := s.authGossiper.ProcessLocalAnnouncement(update)
	select {
	case err := <-errChan:
		return err
	case <-s.quit:
		return ErrServerShuttingDown
	}
}

// SendCustomMessage sends a custom message to the peer with the specified
// pubkey.
func (s *server) SendCustomMessage(peerPub [33]byte, msgType lnwire.MessageType,
	data []byte) error {

	peer, err := s.FindPeerByPubStr(string(peerPub[:]))
	if err != nil {
		return err
	}

	// We'll wait until the peer is active.
	select {
	case <-peer.ActiveSignal():
	case <-peer.QuitSignal():
		return fmt.Errorf("peer %x disconnected", peerPub)
	case <-s.quit:
		return ErrServerShuttingDown
	}

	msg, err := lnwire.NewCustom(msgType, data)
	if err != nil {
		return err
	}

	// Send the message as low-priority. For now we assume that all
	// application-defined message are low priority.
	return peer.SendMessageLazy(true, msg)
}

// newSweepPkScriptGen creates closure that generates a new public key script
// which should be used to sweep any funds into the on-chain wallet.
// Specifically, the script generated is a version 0, pay-to-witness-pubkey-hash
// (p2wkh) output.
func newSweepPkScriptGen(
	wallet lnwallet.WalletController) func() ([]byte, error) {

	return func() ([]byte, error) {
		sweepAddr, err := wallet.NewAddress(
			lnwallet.WitnessPubKey, false, lnwallet.DefaultAccountName,
		)
		if err != nil {
			return nil, err
		}

		return txscript.PayToAddrScript(sweepAddr)
	}
}
