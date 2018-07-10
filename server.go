package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/color"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/bbolt"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/autopilot"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/nat"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/connmgr"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"golang.org/x/net/context"
)

const (
	// defaultMinPeers is the minimum number of peers nodes should always be
	// connected to.
	defaultMinPeers = 3

	// defaultBackoff is the starting point for exponential backoff for
	// reconnecting to persistent peers.
	defaultBackoff = time.Second

	// maximumBackoff is the largest backoff we will permit when
	// reattempting connections to persistent peers.
	maximumBackoff = time.Hour
)

var (
	// ErrPeerNotConnected signals that the server has no connection to the
	// given peer.
	ErrPeerNotConnected = errors.New("peer is not connected")

	// ErrServerShuttingDown indicates that the server is in the process of
	// gracefully exiting.
	ErrServerShuttingDown = errors.New("server is shutting down")
)

// server is the main server of the Lightning Network Daemon. The server houses
// global state pertaining to the wallet, database, and the rpcserver.
// Additionally, the server is also used as a central messaging bus to interact
// with any of its companion objects.
type server struct {
	started  int32 // atomic
	shutdown int32 // atomic

	// identityPriv is the private key used to authenticate any incoming
	// connections.
	identityPriv *btcec.PrivateKey

	// nodeSigner is an implementation of the MessageSigner implementation
	// that's backed by the identity private key of the running lnd node.
	nodeSigner *nodeSigner

	// lightningID is the sha256 of the public key corresponding to our
	// long-term identity private key.
	lightningID [32]byte

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
	peersByPub map[string]*peer

	inboundPeers  map[string]*peer
	outboundPeers map[string]*peer

	peerConnectedListeners map[string][]chan<- struct{}
	peerSequence           map[string]byte

	persistentPeers        map[string]struct{}
	persistentPeersBackoff map[string]time.Duration
	persistentConnReqs     map[string][]*connmgr.ConnReq
	persistentRetryCancels map[string]chan struct{}

	// ignorePeerTermination tracks peers for which the server has initiated
	// a disconnect. Adding a peer to this map causes the peer termination
	// watcher to short circuit in the event that peers are purposefully
	// disconnected.
	ignorePeerTermination map[*peer]struct{}

	// scheduledPeerConnection maps a pubkey string to a callback that
	// should be executed in the peerTerminationWatcher the prior peer with
	// the same pubkey exits.  This allows the server to wait until the
	// prior peer has cleaned up successfully, before adding the new peer
	// intended to replace it.
	scheduledPeerConnection map[string]func()

	cc *chainControl

	fundingMgr *fundingManager

	chanDB *channeldb.DB

	htlcSwitch *htlcswitch.Switch

	invoices *invoiceRegistry

	witnessBeacon contractcourt.WitnessBeacon

	breachArbiter *breachArbiter

	chanRouter *routing.ChannelRouter

	authGossiper *discovery.AuthenticatedGossiper

	utxoNursery *utxoNursery

	chainArb *contractcourt.ChainArbitrator

	sphinx *htlcswitch.OnionProcessor

	connMgr *connmgr.ConnManager

	// globalFeatures feature vector which affects HTLCs and thus are also
	// advertised to other nodes.
	globalFeatures *lnwire.FeatureVector

	// currentNodeAnn is the node announcement that has been broadcast to
	// the network upon startup, if the attributes of the node (us) has
	// changed since last start.
	currentNodeAnn *lnwire.NodeAnnouncement

	quit chan struct{}

	wg sync.WaitGroup
}

// parseAddr parses an address from its string format to a net.Addr.
func parseAddr(address string) (net.Addr, error) {
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
	return cfg.net.ResolveTCPAddr("tcp", hostPort)
}

// newServer creates a new instance of the server which is to listen using the
// passed listener address.
func newServer(listenAddrs []net.Addr, chanDB *channeldb.DB, cc *chainControl,
	privKey *btcec.PrivateKey) (*server, error) {

	var err error

	listeners := make([]net.Listener, len(listenAddrs))
	for i, listenAddr := range listenAddrs {
		// Note: though brontide.NewListener uses ResolveTCPAddr, it
		// doesn't need to call the general lndResolveTCP function
		// since we are resolving a local address.
		listeners[i], err = brontide.NewListener(
			privKey, listenAddr.String(),
		)
		if err != nil {
			return nil, err
		}
	}

	globalFeatures := lnwire.NewRawFeatureVector()

	var serializedPubKey [33]byte
	copy(serializedPubKey[:], privKey.PubKey().SerializeCompressed())

	// Initialize the sphinx router, placing it's persistent replay log in
	// the same directory as the channel graph database.
	graphDir := chanDB.Path()
	sharedSecretPath := filepath.Join(graphDir, "sphinxreplay.db")
	replayLog := htlcswitch.NewDecayedLog(sharedSecretPath, cc.chainNotifier)
	sphinxRouter := sphinx.NewRouter(privKey, activeNetParams.Params, replayLog)

	s := &server{
		chanDB: chanDB,
		cc:     cc,

		invoices: newInvoiceRegistry(chanDB),

		identityPriv: privKey,
		nodeSigner:   newNodeSigner(privKey),

		listenAddrs: listenAddrs,

		// TODO(roasbeef): derive proper onion key based on rotation
		// schedule
		sphinx:      htlcswitch.NewOnionProcessor(sphinxRouter),
		lightningID: sha256.Sum256(serializedPubKey[:]),

		persistentPeers:         make(map[string]struct{}),
		persistentPeersBackoff:  make(map[string]time.Duration),
		persistentConnReqs:      make(map[string][]*connmgr.ConnReq),
		persistentRetryCancels:  make(map[string]chan struct{}),
		ignorePeerTermination:   make(map[*peer]struct{}),
		scheduledPeerConnection: make(map[string]func()),

		peersByPub:             make(map[string]*peer),
		inboundPeers:           make(map[string]*peer),
		outboundPeers:          make(map[string]*peer),
		peerConnectedListeners: make(map[string][]chan<- struct{}),
		peerSequence:           make(map[string]byte),

		globalFeatures: lnwire.NewFeatureVector(globalFeatures,
			lnwire.GlobalFeatures),
		quit: make(chan struct{}),
	}

	s.witnessBeacon = &preimageBeacon{
		invoices:    s.invoices,
		wCache:      chanDB.NewWitnessCache(),
		subscribers: make(map[uint64]*preimageSubscriber),
	}

	// If the debug HTLC flag is on, then we invoice a "master debug"
	// invoice which all outgoing payments will be sent and all incoming
	// HTLCs with the debug R-Hash immediately settled.
	if cfg.DebugHTLC {
		kiloCoin := btcutil.Amount(btcutil.SatoshiPerBitcoin * 1000)
		s.invoices.AddDebugInvoice(kiloCoin, *debugPre)
		srvrLog.Debugf("Debug HTLC invoice inserted, preimage=%x, hash=%x",
			debugPre[:], debugHash[:])
	}

	_, currentHeight, err := s.cc.chainIO.GetBestBlock()
	if err != nil {
		return nil, err
	}

	s.htlcSwitch, err = htlcswitch.New(htlcswitch.Config{
		DB:      chanDB,
		SelfKey: s.identityPriv.PubKey(),
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

			select {
			case peer.localCloseChanReqs <- request:
				srvrLog.Infof("Local close channel request "+
					"delivered to peer: %x", pubKey[:])
			case <-peer.quit:
				srvrLog.Errorf("Unable to deliver local close "+
					"channel request to peer %x, err: %v",
					pubKey[:], err)
			}
		},
		FwdingLog:              chanDB.ForwardingLog(),
		SwitchPackager:         channeldb.NewSwitchPackager(),
		ExtractErrorEncrypter:  s.sphinx.ExtractErrorEncrypter,
		FetchLastChannelUpdate: fetchLastChanUpdate(s, serializedPubKey),
		Notifier:               s.cc.chainNotifier,
	}, uint32(currentHeight))
	if err != nil {
		return nil, err
	}

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
				err := fmt.Errorf("Unable to discover a "+
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
	externalIpStrings := make([]string, len(cfg.ExternalIPs))
	for idx, ip := range cfg.ExternalIPs {
		externalIpStrings[idx] = ip.String()
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
			externalIpStrings = append(externalIpStrings, ips...)
		}
	}

	// If external IP addresses have been specified, add those to the list
	// of this server's addresses.
	externalIPs, err := lncfg.NormalizeAddresses(
		externalIpStrings, strconv.Itoa(defaultPeerPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, err
	}
	selfAddrs := make([]net.Addr, 0, len(externalIPs))
	for _, ip := range externalIPs {
		selfAddrs = append(selfAddrs, ip)
	}

	// If we were requested to route connections through Tor and to
	// automatically create an onion service, we'll initiate our Tor
	// controller and establish a connection to the Tor server.
	//
	// NOTE: v3 onion services cannot be created automatically yet. In the
	// future, this will be expanded to do so.
	if cfg.Tor.Active && cfg.Tor.V2 {
		s.torController = tor.NewController(cfg.Tor.Control)
	}

	chanGraph := chanDB.ChannelGraph()

	// Parse node color from configuration.
	color, err := parseHexColor(cfg.Color)
	if err != nil {
		srvrLog.Errorf("unable to parse color: %v\n", err)
		return nil, err
	}

	// If no alias is provided, default to first 10 characters of public key
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
		Features:             s.globalFeatures,
		Color:                color,
	}
	copy(selfNode.PubKeyBytes[:], privKey.PubKey().SerializeCompressed())

	// If our information has changed since our last boot, then we'll
	// re-sign our node announcement so a fresh authenticated version of it
	// can be propagated throughout the network upon startup.
	//
	// TODO(roasbeef): don't always set timestamp above to _now.
	nodeAnn := &lnwire.NodeAnnouncement{
		Timestamp: uint32(selfNode.LastUpdate.Unix()),
		Addresses: selfNode.Addresses,
		NodeID:    selfNode.PubKeyBytes,
		Alias:     nodeAlias,
		Features:  selfNode.Features.RawFeatureVector,
		RGBColor:  color,
	}
	authSig, err := discovery.SignAnnouncement(
		s.nodeSigner, s.identityPriv.PubKey(), nodeAnn,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate signature for "+
			"self node announcement: %v", err)
	}

	selfNode.AuthSigBytes = authSig.Serialize()
	s.currentNodeAnn = nodeAnn

	if err := chanGraph.SetSourceNode(selfNode); err != nil {
		return nil, fmt.Errorf("can't set self node: %v", err)
	}

	nodeAnn.Signature, err = lnwire.NewSigFromRawSignature(selfNode.AuthSigBytes)
	if err != nil {
		return nil, err
	}
	s.chanRouter, err = routing.New(routing.Config{
		Graph:     chanGraph,
		Chain:     cc.chainIO,
		ChainView: cc.chainView,
		SendToSwitch: func(firstHopPub [33]byte,
			htlcAdd *lnwire.UpdateAddHTLC,
			circuit *sphinx.Circuit) ([32]byte, error) {

			// Using the created circuit, initialize the error
			// decrypter so we can parse+decode any failures
			// incurred by this payment within the switch.
			errorDecryptor := &htlcswitch.SphinxErrorDecrypter{
				OnionErrorDecrypter: sphinx.NewOnionErrorDecrypter(circuit),
			}

			return s.htlcSwitch.SendHTLC(firstHopPub, htlcAdd, errorDecryptor)
		},
		ChannelPruneExpiry: time.Duration(time.Hour * 24 * 14),
		GraphPruneInterval: time.Duration(time.Hour),
		QueryBandwidth: func(edge *channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi {
			// If we aren't on either side of this edge, then we'll
			// just thread through the capacity of the edge as we
			// know it.
			if !bytes.Equal(edge.NodeKey1Bytes[:], selfNode.PubKeyBytes[:]) &&
				!bytes.Equal(edge.NodeKey2Bytes[:], selfNode.PubKeyBytes[:]) {

				return lnwire.NewMSatFromSatoshis(edge.Capacity)
			}

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

			// Otherwise, we'll return the current best estimate
			// for the available bandwidth for the link.
			return link.Bandwidth()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("can't create router: %v", err)
	}

	s.authGossiper, err = discovery.New(discovery.Config{
		Router:     s.chanRouter,
		Notifier:   s.cc.chainNotifier,
		ChainHash:  *activeNetParams.GenesisHash,
		Broadcast:  s.BroadcastMessage,
		ChanSeries: &chanSeries{s.chanDB.ChannelGraph()},
		SendToPeer: s.SendToPeer,
		FindPeer: func(pub *btcec.PublicKey) (lnpeer.Peer, error) {
			return s.FindPeer(pub)
		},
		NotifyWhenOnline: s.NotifyWhenOnline,
		ProofMatureDelta: 0,
		TrickleDelay:     time.Millisecond * time.Duration(cfg.TrickleDelay),
		RetransmitDelay:  time.Minute * 30,
		DB:               chanDB,
		AnnSigner:        s.nodeSigner,
	},
		s.identityPriv.PubKey(),
	)
	if err != nil {
		return nil, err
	}

	utxnStore, err := newNurseryStore(activeNetParams.GenesisHash, chanDB)
	if err != nil {
		srvrLog.Errorf("unable to create nursery store: %v", err)
		return nil, err
	}

	s.utxoNursery = newUtxoNursery(&NurseryConfig{
		ChainIO:   cc.chainIO,
		ConfDepth: 1,
		DB:        chanDB,
		Estimator: cc.feeEstimator,
		GenSweepScript: func() ([]byte, error) {
			return newSweepPkScript(cc.wallet)
		},
		Notifier:           cc.chainNotifier,
		PublishTransaction: cc.wallet.PublishTransaction,
		Signer:             cc.wallet.Cfg.Signer,
		Store:              utxnStore,
	})

	// Construct a closure that wraps the htlcswitch's CloseLink method.
	closeLink := func(chanPoint *wire.OutPoint,
		closureType htlcswitch.ChannelCloseType) {
		// TODO(conner): Properly respect the update and error channels
		// returned by CloseLink.
		s.htlcSwitch.CloseLink(chanPoint, closureType, 0)
	}

	// We will use the following channel to reliably hand off contract
	// breach events from the ChannelArbitrator to the breachArbiter,
	contractBreaches := make(chan *ContractBreachEvent, 1)

	s.chainArb = contractcourt.NewChainArbitrator(contractcourt.ChainArbitratorConfig{
		ChainHash: *activeNetParams.GenesisHash,
		// TODO(roasbeef): properly configure
		//  * needs to be << or specified final hop time delta
		BroadcastDelta: defaultBroadcastDelta,
		NewSweepAddr: func() ([]byte, error) {
			return newSweepPkScript(cc.wallet)
		},
		PublishTx: cc.wallet.PublishTransaction,
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
			commitRes *lnwallet.CommitOutputResolution,
			outHtlcRes *lnwallet.OutgoingHtlcResolution,
			inHtlcRes *lnwallet.IncomingHtlcResolution) error {

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
				chanPoint, commitRes, outRes, inRes,
			)
		},
		PreimageDB:   s.witnessBeacon,
		Notifier:     cc.chainNotifier,
		Signer:       cc.wallet.Cfg.Signer,
		FeeEstimator: cc.feeEstimator,
		ChainIO:      cc.chainIO,
		MarkLinkInactive: func(chanPoint wire.OutPoint) error {
			chanID := lnwire.NewChanIDFromOutPoint(&chanPoint)
			return s.htlcSwitch.RemoveLink(chanID)
		},
		IsOurAddress: func(addr btcutil.Address) bool {
			_, err := cc.wallet.GetPrivKey(addr)
			return err == nil
		},
		ContractBreach: func(chanPoint wire.OutPoint,
			breachRet *lnwallet.BreachRetribution) error {
			event := &ContractBreachEvent{
				ChanPoint:         chanPoint,
				ProcessACK:        make(chan error, 1),
				BreachRetribution: breachRet,
			}

			// Send the contract breach event to the breachArbiter.
			select {
			case contractBreaches <- event:
			case <-s.quit:
				return ErrServerShuttingDown
			}

			// Wait for the breachArbiter to ACK the event.
			select {
			case err := <-event.ProcessACK:
				return err
			case <-s.quit:
				return ErrServerShuttingDown
			}
		},
	}, chanDB)

	s.breachArbiter = newBreachArbiter(&BreachConfig{
		CloseLink: closeLink,
		DB:        chanDB,
		Estimator: s.cc.feeEstimator,
		GenSweepScript: func() ([]byte, error) {
			return newSweepPkScript(cc.wallet)
		},
		Notifier:           cc.chainNotifier,
		PublishTransaction: cc.wallet.PublishTransaction,
		ContractBreaches:   contractBreaches,
		Signer:             cc.wallet.Cfg.Signer,
		Store:              newRetributionStore(chanDB),
	})

	// Create the connection manager which will be responsible for
	// maintaining persistent outbound connections and also accepting new
	// incoming connections
	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners:      listeners,
		OnAccept:       s.InboundPeerConnected,
		RetryDuration:  time.Second * 5,
		TargetOutbound: 100,
		Dial:           noiseDial(s.identityPriv),
		OnConnection:   s.OutboundPeerConnected,
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
	return atomic.LoadInt32(&s.started) != 0
}

// Start starts the main daemon server, all requested listeners, and any helper
// goroutines.
// NOTE: This function is safe for concurrent access.
func (s *server) Start() error {
	// Already running?
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return nil
	}

	if s.torController != nil {
		if err := s.initTorController(); err != nil {
			return err
		}
	}

	if s.natTraversal != nil {
		s.wg.Add(1)
		go s.watchExternalIP()
	}

	// Start the notification server. This is used so channel management
	// goroutines can be notified when a funding transaction reaches a
	// sufficient number of confirmations, or when the input for the
	// funding transaction is spent in an attempt at an uncooperative close
	// by the counterparty.
	if err := s.cc.chainNotifier.Start(); err != nil {
		return err
	}
	if err := s.sphinx.Start(); err != nil {
		return err
	}
	if err := s.htlcSwitch.Start(); err != nil {
		return err
	}
	if err := s.utxoNursery.Start(); err != nil {
		return err
	}
	if err := s.chainArb.Start(); err != nil {
		return err
	}
	if err := s.breachArbiter.Start(); err != nil {
		return err
	}
	if err := s.authGossiper.Start(); err != nil {
		return err
	}
	if err := s.chanRouter.Start(); err != nil {
		return err
	}
	s.connMgr.Start()

	// With all the relevant sub-systems started, we'll now attempt to
	// establish persistent connections to our direct channel collaborators
	// within the network.
	if err := s.establishPersistentConnections(); err != nil {
		return err
	}

	// If network bootstrapping hasn't been disabled, then we'll configure
	// the set of active bootstrappers, and launch a dedicated goroutine to
	// maintain a set of persistent connections.
	if !cfg.NoNetBootstrap && !(cfg.Bitcoin.SimNet || cfg.Litecoin.SimNet) &&
		!(cfg.Bitcoin.RegTest || cfg.Litecoin.RegTest) {

		bootstrappers, err := initNetworkBootstrappers(s)
		if err != nil {
			return err
		}

		s.wg.Add(1)
		go s.peerBootstrapper(defaultMinPeers, bootstrappers)
	} else {
		srvrLog.Infof("Auto peer bootstrapping is disabled")
	}

	return nil
}

// Stop gracefully shutsdown the main daemon server. This function will signal
// any active goroutines, or helper objects to exit, then blocks until they've
// all successfully exited. Additionally, any/all listeners are closed.
// NOTE: This function is safe for concurrent access.
func (s *server) Stop() error {
	// Bail if we're already shutting down.
	if !atomic.CompareAndSwapInt32(&s.shutdown, 0, 1) {
		return nil
	}

	close(s.quit)

	if s.torController != nil {
		s.torController.Stop()
	}

	// Shutdown the wallet, funding manager, and the rpc server.
	s.cc.chainNotifier.Stop()
	s.chanRouter.Stop()
	s.htlcSwitch.Stop()
	s.sphinx.Stop()
	s.utxoNursery.Stop()
	s.breachArbiter.Stop()
	s.authGossiper.Stop()
	s.chainArb.Stop()
	s.cc.wallet.Shutdown()
	s.cc.chainView.Stop()
	s.connMgr.Stop()
	s.cc.feeEstimator.Stop()

	// Disconnect from each active peers to ensure that
	// peerTerminationWatchers signal completion to each peer.
	for _, peer := range s.Peers() {
		s.DisconnectPeer(peer.addr.IdentityKey)
	}

	// Wait for all lingering goroutines to quit.
	s.wg.Wait()

	return nil
}

// Stopped returns true if the server has been instructed to shutdown.
// NOTE: This function is safe for concurrent access.
func (s *server) Stopped() bool {
	return atomic.LoadInt32(&s.shutdown) != 0
}

// configurePortForwarding attempts to set up port forwarding for the diffrent
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

// watchExternalIP continously checks for an updated external IP address every
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
	for _, ip := range cfg.ExternalIPs {
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
			// announcement in order to propogate the update
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
				true, lnwire.UpdateNodeAnnAddrs(newAddrs),
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
	chanGraph := autopilot.ChannelGraphFromDatabase(s.chanDB.ChannelGraph())
	graphBootstrapper, err := discovery.NewGraphBootstrapper(chanGraph)
	if err != nil {
		return nil, err
	}
	bootStrappers = append(bootStrappers, graphBootstrapper)

	// If this isn't simnet mode, then one of our additional bootstrapping
	// sources will be the set of running DNS seeds.
	if !cfg.Bitcoin.SimNet || !cfg.Litecoin.SimNet {
		dnsSeeds, ok := chainDNSSeeds[*activeNetParams.GenesisHash]

		// If we have a set of DNS seeds for this chain, then we'll add
		// it as an additional bootstrapping source.
		if ok {
			srvrLog.Infof("Creating DNS peer bootstrapper with "+
				"seeds: %v", dnsSeeds)

			dnsBootStrapper := discovery.NewDNSSeedBootstrapper(
				dnsSeeds, cfg.net,
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
	const backOffCeiling = time.Minute * 5
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
				if backOff > backOffCeiling {
					backOff = backOffCeiling
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
				nID := autopilot.NewNodeID(peer.addr.IdentityKey)
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
					s.connectToPeer(a, errChan)
					select {
					case err := <-errChan:
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

// initialPeerBootstrap attempts to continuously connect to peers on startup
// until the target number of peers has been reached. This ensures that nodes
// receive an up to date network view as soon as possible.
func (s *server) initialPeerBootstrap(ignore map[autopilot.NodeID]struct{},
	numTargetPeers uint32, bootstrappers []discovery.NetworkPeerBootstrapper) {

	var wg sync.WaitGroup

	for {
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

		// Otherwise, we'll request for the remaining number of peers in
		// order to reach our target.
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
		for _, bootstrapAddr := range bootstrapAddrs {
			wg.Add(1)
			go func(addr *lnwire.NetAddress) {
				defer wg.Done()

				errChan := make(chan error, 1)
				go s.connectToPeer(addr, errChan)

				// We'll only allow this connection attempt to
				// take up to 3 seconds. This allows us to move
				// quickly by discarding peers that are slowing
				// us down.
				select {
				case err := <-errChan:
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

// initTorController initiliazes the Tor controller backed by lnd and
// automatically sets up a v2 onion service in order to listen for inbound
// connections over Tor.
func (s *server) initTorController() error {
	if err := s.torController.Start(); err != nil {
		return err
	}

	// Determine the different ports the server is listening on. The onion
	// service's virtual port will map to these ports and one will be picked
	// at random when the onion service is being accessed.
	listenPorts := make(map[int]struct{})
	for _, listenAddr := range s.listenAddrs {
		// At this point, the listen addresses should have already been
		// normalized, so it's safe to ignore the errors.
		_, portStr, _ := net.SplitHostPort(listenAddr.String())
		port, _ := strconv.Atoi(portStr)
		listenPorts[port] = struct{}{}
	}

	// Once the port mapping has been set, we can go ahead and automatically
	// create our onion service. The service's private key will be saved to
	// disk in order to regain access to this service when restarting `lnd`.
	virtToTargPorts := tor.VirtToTargPorts{defaultPeerPort: listenPorts}
	onionServiceAddrs, err := s.torController.AddOnionV2(
		cfg.Tor.V2PrivateKeyPath, virtToTargPorts,
	)
	if err != nil {
		return err
	}

	// Now that the onion service has been created, we'll add the different
	// onion addresses it can be reached at to our list of advertised
	// addresses.
	for _, addr := range onionServiceAddrs {
		s.currentNodeAnn.Addresses = append(
			s.currentNodeAnn.Addresses, addr,
		)
	}

	return nil
}

// genNodeAnnouncement generates and returns the current fully signed node
// announcement. If refresh is true, then the time stamp of the announcement
// will be updated in order to ensure it propagates through the network.
func (s *server) genNodeAnnouncement(refresh bool,
	updates ...func(*lnwire.NodeAnnouncement)) (lnwire.NodeAnnouncement, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	if !refresh {
		return *s.currentNodeAnn, nil
	}

	for _, update := range updates {
		update(s.currentNodeAnn)
	}

	newStamp := uint32(time.Now().Unix())
	if newStamp <= s.currentNodeAnn.Timestamp {
		newStamp = s.currentNodeAnn.Timestamp + 1
	}

	s.currentNodeAnn.Timestamp = newStamp
	sig, err := discovery.SignAnnouncement(
		s.nodeSigner, s.identityPriv.PubKey(), s.currentNodeAnn,
	)
	if err != nil {
		return lnwire.NodeAnnouncement{}, err
	}

	s.currentNodeAnn.Signature, err = lnwire.NewSigFromSignature(sig)
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
// to all our direct channel collaborators.  In order to promote liveness of
// our active channels, we instruct the connection manager to attempt to
// establish and maintain persistent connections to all our direct channel
// counterparties.
func (s *server) establishPersistentConnections() error {
	// nodeAddrsMap stores the combination of node public keys and
	// addresses that we'll attempt to reconnect to. PubKey strings are
	// used as keys since other PubKey forms can't be compared.
	nodeAddrsMap := map[string]*nodeAddresses{}

	// Iterate through the list of LinkNodes to find addresses we should
	// attempt to connect to based on our set of previous connections. Set
	// the reconnection port to the default peer port.
	linkNodes, err := s.chanDB.FetchAllLinkNodes()
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
	chanGraph := s.chanDB.ChannelGraph()
	sourceNode, err := chanGraph.SourceNode()
	if err != nil {
		return err
	}
	// TODO(roasbeef): instead iterate over link nodes and query graph for
	// each of the nodes.
	err = sourceNode.ForEachChannel(nil, func(
		_ *bolt.Tx,
		_ *channeldb.ChannelEdgeInfo,
		policy, _ *channeldb.ChannelEdgePolicy) error {

		pubStr := string(policy.Node.PubKeyBytes[:])

		// Add addresses from channel graph/NodeAnnouncements to the
		// list of addresses we'll connect to. If there are duplicates
		// that have different ports specified, the port from the
		// channel graph should supersede the port from the link node.
		var addrs []net.Addr
		linkNodeAddrs, ok := nodeAddrsMap[pubStr]
		if ok {
			for _, lnAddress := range linkNodeAddrs.addresses {
				var addrHost string
				switch addr := lnAddress.(type) {
				case *net.TCPAddr:
					addrHost = addr.IP.String()
				case *tor.OnionAddr:
					addrHost = addr.OnionService
				default:
					continue
				}

				var addrMatched bool
				for _, polAddress := range policy.Node.Addresses {
					switch addr := polAddress.(type) {
					case *net.TCPAddr:
						if addr.IP.String() == addrHost {
							addrMatched = true
							addrs = append(addrs, addr)
						}
					case *tor.OnionAddr:
						if addr.OnionService == addrHost {
							addrMatched = true
							addrs = append(addrs, addr)
						}
					}
				}
				if !addrMatched {
					addrs = append(addrs, lnAddress)
				}
			}
		} else {
			for _, addr := range policy.Node.Addresses {
				switch addr.(type) {
				case *net.TCPAddr, *tor.OnionAddr:
					addrs = append(addrs, addr)
				}
			}
		}

		n := &nodeAddresses{
			addresses: addrs,
		}
		n.pubKey, err = policy.Node.PubKey()
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
	for pubStr, nodeAddr := range nodeAddrsMap {
		// Add this peer to the set of peers we should maintain a
		// persistent connection with.
		s.persistentPeers[pubStr] = struct{}{}
		if _, ok := s.persistentPeersBackoff[pubStr]; !ok {
			s.persistentPeersBackoff[pubStr] = defaultBackoff
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

			go s.connMgr.Connect(connReq)
		}
	}

	return nil
}

// BroadcastMessage sends a request to the server to broadcast a set of
// messages to all peers other than the one specified by the `skips` parameter.
//
// NOTE: This function is safe for concurrent access.
func (s *server) BroadcastMessage(skips map[routing.Vertex]struct{},
	msgs ...lnwire.Message) error {

	srvrLog.Debugf("Broadcasting %v messages", len(msgs))

	// Filter out peers found in the skips map. We synchronize access to
	// peersByPub throughout this process to ensure we deliver messages to
	// exact set of peers present at the time of invocation.
	s.mu.RLock()
	peers := make([]*peer, 0, len(s.peersByPub))
	for _, sPeer := range s.peersByPub {
		if skips != nil {
			if _, ok := skips[sPeer.pubKeyBytes]; ok {
				srvrLog.Tracef("Skipping %x in broadcast",
					sPeer.pubKeyBytes[:])
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
		go s.sendPeerMessages(sPeer, msgs, &wg)
	}

	// Wait for all messages to have been dispatched before returning to
	// caller.
	wg.Wait()

	return nil
}

// SendToPeer send a message to the server telling it to send the specific set
// of message to a particular peer. If the peer connect be found, then this
// method will return a non-nil error.
//
// NOTE: This function is safe for concurrent access.
func (s *server) SendToPeer(target *btcec.PublicKey,
	msgs ...lnwire.Message) error {

	// Compute the target peer's identifier.
	targetPubBytes := target.SerializeCompressed()

	srvrLog.Tracef("Attempting to send msgs %v to: %x",
		len(msgs), targetPubBytes)

	// Lookup intended target in peersByPub, returning an error to the
	// caller if the peer is unknown.  Access to peersByPub is synchronized
	// here to ensure we consider the exact set of peers present at the
	// time of invocation.
	s.mu.RLock()
	targetPeer, err := s.findPeerByPubStr(string(targetPubBytes))
	s.mu.RUnlock()
	if err == ErrPeerNotConnected {
		srvrLog.Errorf("unable to send message to %x, "+
			"peer is not connected", targetPubBytes)
		return err
	}

	// Send messages to the peer and get the error channels that will be
	// signaled by the peer's write handler.
	errChans := s.sendPeerMessages(targetPeer, msgs, nil)

	// With the server's shared lock released, we now handle all of the
	// errors being returned from the target peer's write handler.
	for _, errChan := range errChans {
		select {
		case err := <-errChan:
			return err
		case <-targetPeer.quit:
			return ErrPeerExiting
		case <-s.quit:
			return ErrServerShuttingDown
		}
	}

	return nil
}

// NotifyWhenOnline can be called by other subsystems to get notified when a
// particular peer comes online.
//
// NOTE: This function is safe for concurrent access.
func (s *server) NotifyWhenOnline(peer *btcec.PublicKey,
	connectedChan chan<- struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute the target peer's identifier.
	pubStr := string(peer.SerializeCompressed())

	// Check if peer is connected.
	_, ok := s.peersByPub[pubStr]
	if ok {
		// Connected, can return early.
		srvrLog.Debugf("Notifying that peer %x is online",
			peer.SerializeCompressed())
		close(connectedChan)
		return
	}

	// Not connected, store this listener such that it can be notified when
	// the peer comes online.
	s.peerConnectedListeners[pubStr] = append(
		s.peerConnectedListeners[pubStr], connectedChan)
}

// sendPeerMessages enqueues a list of messages into the outgoingQueue of the
// `targetPeer`.  This method supports additional broadcast-level
// synchronization by using the additional `wg` to coordinate a particular
// broadcast. Since this method will wait for the return error from sending
// each message, it should be run as a goroutine (see comment below) and
// the error ignored if used for broadcasting messages, where the result
// from sending the messages is not of importance.
//
// NOTE: This method must be invoked with a non-nil `wg` if it is spawned as a
// go routine--both `wg` and the server's WaitGroup should be incremented
// beforehand.  If this method is not spawned as a go routine, the provided
// `wg` should be nil, and the server's WaitGroup should not be tracking this
// invocation.
func (s *server) sendPeerMessages(
	targetPeer *peer,
	msgs []lnwire.Message,
	wg *sync.WaitGroup) []chan error {

	// If a WaitGroup is provided, we assume that this method was spawned
	// as a go routine, and that it is being tracked by both the server's
	// WaitGroup, as well as the broadcast-level WaitGroup `wg`. In this
	// event, we defer a call to Done on both WaitGroups to 1) ensure that
	// server will be able to shutdown after its go routines exit, and 2)
	// so the server can return to the caller of BroadcastMessage.
	isBroadcast := wg != nil
	if isBroadcast {
		defer s.wg.Done()
		defer wg.Done()
	}

	// We queue each message, creating a slice of error channels that
	// can be inspected after every message is successfully added to
	// the queue.
	var errChans []chan error
	for _, msg := range msgs {
		// If this is not broadcast, create error channels to provide
		// synchronous feedback regarding the delivery of the message to
		// a specific peer.
		var errChan chan error
		if !isBroadcast {
			errChan = make(chan error, 1)
			errChans = append(errChans, errChan)
		}

		targetPeer.queueMsg(msg, errChan)
	}

	return errChans
}

// FindPeer will return the peer that corresponds to the passed in public key.
// This function is used by the funding manager, allowing it to update the
// daemon's local representation of the remote peer.
//
// NOTE: This function is safe for concurrent access.
func (s *server) FindPeer(peerKey *btcec.PublicKey) (*peer, error) {
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
func (s *server) FindPeerByPubStr(pubStr string) (*peer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.findPeerByPubStr(pubStr)
}

// findPeerByPubStr is an internal method that retrieves the specified peer from
// the server's internal state using.
func (s *server) findPeerByPubStr(pubStr string) (*peer, error) {
	peer, ok := s.peersByPub[pubStr]
	if !ok {
		return nil, ErrPeerNotConnected
	}

	return peer, nil
}

// peerTerminationWatcher waits until a peer has been disconnected unexpectedly,
// and then cleans up all resources allocated to the peer, notifies relevant
// sub-systems of its demise, and finally handles re-connecting to the peer if
// it's persistent. If the server intentionally disconnects a peer, it should
// have a corresponding entry in the ignorePeerTermination map which will cause
// the cleanup routine to exit early.
//
// NOTE: This MUST be launched as a goroutine.
func (s *server) peerTerminationWatcher(p *peer) {
	defer s.wg.Done()

	p.WaitForDisconnect()

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

	pubKey := p.addr.IdentityKey

	// We'll also inform the gossiper that this peer is no longer active,
	// so we don't need to maintain sync state for it any longer.
	s.authGossiper.PruneSyncState(pubKey)

	// Tell the switch to remove all links associated with this peer.
	// Passing nil as the target link indicates that all links associated
	// with this interface should be closed.
	//
	// TODO(roasbeef): instead add a PurgeInterfaceLinks function?
	links, err := p.server.htlcSwitch.GetLinksByInterface(p.pubKeyBytes)
	if err != nil {
		srvrLog.Errorf("unable to get channel links: %v", err)
	}

	for _, link := range links {
		err := p.server.htlcSwitch.RemoveLink(link.ChanID())
		if err != nil {
			srvrLog.Errorf("unable to remove channel link: %v",
				err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
	pubStr := string(pubKey.SerializeCompressed())
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
		if p.inbound {
			advertisedAddr, err := s.fetchNodeAdvertisedAddr(
				pubKey,
			)
			if err != nil {
				srvrLog.Errorf("Unable to retrieve advertised "+
					"address for node %x: %v",
					pubKey.SerializeCompressed(), err)
			} else {
				p.addr.Address = advertisedAddr
			}
		}

		// Otherwise, we'll launch a new connection request in order to
		// attempt to maintain a persistent connection with this peer.
		connReq := &connmgr.ConnReq{
			Addr:      p.addr,
			Permanent: true,
		}
		s.persistentConnReqs[pubStr] = append(
			s.persistentConnReqs[pubStr], connReq)

		// Record the computed backoff in the backoff map.
		backoff := s.nextPeerBackoff(pubStr)
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

// nextPeerBackoff computes the next backoff duration for a peer's pubkey using
// exponential backoff. If no previous backoff was known, the default is
// returned.
func (s *server) nextPeerBackoff(pubStr string) time.Duration {
	// Now, determine the appropriate backoff to use for the retry.
	backoff, ok := s.persistentPeersBackoff[pubStr]
	if !ok {
		// If an existing backoff was unknown, use the default.
		return defaultBackoff
	}

	// Otherwise, use a previous backoff to compute the
	// subsequent randomized exponential backoff duration.
	return computeNextBackoff(backoff)
}

// shouldRequestGraphSync returns true if the servers deems it necessary that
// we sync channel graph state with the remote peer. This method is used to
// avoid _always_ syncing channel graph state with each peer that connects.
//
// NOTE: This MUST be called with the server's mutex held.
func (s *server) shouldRequestGraphSync() bool {
	// Initially, we'll only request a graph sync iff we have less than two
	// peers.
	return len(s.peersByPub) <= 2
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

	srvrLog.Infof("finalizing connection to %x, inbound=%v",
		pubKey.SerializeCompressed(), inbound)

	peerAddr := &lnwire.NetAddress{
		IdentityKey: pubKey,
		Address:     addr,
		ChainNet:    activeNetParams.Net,
	}

	// With the brontide connection established, we'll now craft the local
	// feature vector to advertise to the remote node.
	localFeatures := lnwire.NewRawFeatureVector()

	// We'll signal that we understand the data loss protection feature,
	// and also that we support the new gossip query features.
	localFeatures.Set(lnwire.DataLossProtectOptional)
	localFeatures.Set(lnwire.GossipQueriesOptional)

	// We'll only request a full channel graph sync if we detect that that
	// we aren't fully synced yet.
	if s.shouldRequestGraphSync() {
		// TODO(roasbeef): only do so if gossiper doesn't have active
		// peers?
		localFeatures.Set(lnwire.InitialRoutingSync)
	}

	// Now that we've established a connection, create a peer, and it to
	// the set of currently active peers.
	p, err := newPeer(conn, connReq, s, peerAddr, inbound, localFeatures)
	if err != nil {
		srvrLog.Errorf("unable to create peer %v", err)
		return
	}

	// TODO(roasbeef): update IP address for link-node
	//  * also mark last-seen, do it one single transaction?

	// Attempt to start the peer, if we're unable to do so, then disconnect
	// this peer.
	if err := p.Start(); err != nil {
		p.Disconnect(errors.Errorf("unable to start peer: %v", err))
		return
	}

	s.addPeer(p)
}

// shouldDropConnection determines if our local connection to a remote peer
// should be dropped in the case of concurrent connection establishment. In
// order to deterministically decide which connection should be dropped, we'll
// utilize the ordering of the local and remote public key. If we didn't use
// such a tie breaker, then we risk _both_ connections erroneously being
// dropped.
func (s *server) shouldDropLocalConnection(local, remote *btcec.PublicKey) bool {
	localPubBytes := local.SerializeCompressed()
	remotePubPbytes := remote.SerializeCompressed()

	// The connection that comes from the node with a "smaller" pubkey
	// should be kept. Therefore, if our pubkey is "greater" than theirs, we
	// should drop our established connection.
	supposedToDrop := bytes.Compare(localPubBytes, remotePubPbytes) > 0

	pubStr := string(remotePubPbytes)

	// Lookup the current sequence number for this peer. If no entry is
	// found, we start in state 0. We take the states mod 3 so that we
	// the sequence eventually terminates, without making assumptions about
	// the starting states of the peers.
	state := s.peerSequence[pubStr]
	s.peerSequence[pubStr] = (state + 1) % 3

	// Stay honest to the protocol only if we are in state 0.
	stayHonest := state == 0

	return supposedToDrop == stayHonest
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
		// connection we've already established should be kept, then
		// we'll close out this connection s.t there's only a single
		// connection between us.
		localPub := s.identityPriv.PubKey()
		if !s.shouldDropLocalConnection(localPub, nodePub) {
			srvrLog.Warnf("Received inbound connection from "+
				"peer %x, but already connected, dropping conn",
				nodePub.SerializeCompressed())
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
		srvrLog.Debugf("Ignoring cancelled outbound connection")
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

	srvrLog.Infof("Established connection to: %v", conn.RemoteAddr())

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
		// We already have a connection open with the target peer.
		// If our (this) connection should be dropped, then we'll do
		// so, in order to ensure we don't have any duplicate
		// connections.
		localPub := s.identityPriv.PubKey()
		if s.shouldDropLocalConnection(localPub, nodePub) {
			srvrLog.Warnf("Established outbound connection to "+
				"peer %x, but already connected, dropping conn",
				nodePub.SerializeCompressed())
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

// addPeer adds the passed peer to the server's global state of all active
// peers.
func (s *server) addPeer(p *peer) {
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

	pubStr := string(p.addr.IdentityKey.SerializeCompressed())

	s.peersByPub[pubStr] = p

	if p.inbound {
		s.inboundPeers[pubStr] = p
	} else {
		s.outboundPeers[pubStr] = p
	}

	// Launch a goroutine to watch for the unexpected termination of this
	// peer, which will ensure all resources are properly cleaned up, and
	// re-establish persistent connections when necessary. The peer
	// termination watcher will be short circuited if the peer is ever
	// added to the ignorePeerTermination map, indicating that the server
	// has already handled the removal of this peer.
	s.wg.Add(1)
	go s.peerTerminationWatcher(p)

	switch {
	// If the remote peer knows of the new gossip queries feature, then
	// we'll create a new gossipSyncer in the AuthenticatedGossiper for it.
	case p.remoteLocalFeatures.HasFeature(lnwire.GossipQueriesOptional):
		srvrLog.Infof("Negotiated chan series queries with %x",
			p.pubKeyBytes[:])

		// We'll only request channel updates from the remote peer if
		// its enabled in the config, or we're already getting updates
		// from enough peers.
		//
		// TODO(roasbeef): craft s.t. we only get updates from a few
		// peers
		recvUpdates := !cfg.NoChanUpdates
		go s.authGossiper.InitSyncState(p, recvUpdates)

	// If the remote peer has the initial sync feature bit set, then we'll
	// being the synchronization protocol to exchange authenticated channel
	// graph edges/vertexes, but only if they don't know of the new gossip
	// queries.
	case p.remoteLocalFeatures.HasFeature(lnwire.InitialRoutingSync):
		srvrLog.Infof("Requesting full table sync with %x",
			p.pubKeyBytes[:])

		go s.authGossiper.SynchronizeNode(p)
	}

	// Check if there are listeners waiting for this peer to come online.
	for _, con := range s.peerConnectedListeners[pubStr] {
		close(con)
	}
	delete(s.peerConnectedListeners, pubStr)
}

// removePeer removes the passed peer from the server's state of all active
// peers.
func (s *server) removePeer(p *peer) {
	if p == nil {
		return
	}

	srvrLog.Debugf("removing peer %v", p)

	// As the peer is now finished, ensure that the TCP connection is
	// closed and all of its related goroutines have exited.
	p.Disconnect(fmt.Errorf("server: disconnecting peer %v", p))

	// If this peer had an active persistent connection request, remove it.
	if p.connReq != nil {
		s.connMgr.Remove(p.connReq.ID())
	}

	// Ignore deleting peers if we're shutting down.
	if s.Stopped() {
		return
	}

	pubStr := string(p.addr.IdentityKey.SerializeCompressed())

	delete(s.peersByPub, pubStr)

	if p.inbound {
		delete(s.inboundPeers, pubStr)
	} else {
		delete(s.outboundPeers, pubStr)
	}
}

// openChanReq is a message sent to the server in order to request the
// initiation of a channel funding workflow to the peer with either the
// specified relative peer ID, or a global lightning  ID.
type openChanReq struct {
	targetPubkey *btcec.PublicKey

	chainHash chainhash.Hash

	localFundingAmt  btcutil.Amount
	remoteFundingAmt btcutil.Amount

	pushAmt lnwire.MilliSatoshi

	fundingFeePerVSize lnwallet.SatPerVByte

	private bool

	minHtlc lnwire.MilliSatoshi

	remoteCsvDelay uint16

	// TODO(roasbeef): add ability to specify channel constraints as well

	updates chan *lnrpc.OpenStatusUpdate
	err     chan error
}

// ConnectToPeer requests that the server connect to a Lightning Network peer
// at the specified address. This function will *block* until either a
// connection is established, or the initial handshake process fails.
//
// NOTE: This function is safe for concurrent access.
func (s *server) ConnectToPeer(addr *lnwire.NetAddress, perm bool) error {

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
		return fmt.Errorf("already connected to peer: %v", peer)
	}

	// Peer was not found, continue to pursue connection with peer.

	// If there's already a pending connection request for this pubkey,
	// then we ignore this request to ensure we don't create a redundant
	// connection.
	if reqs, ok := s.persistentConnReqs[targetPub]; ok {
		srvrLog.Warnf("Already have %d persistent connection "+
			"requests for %v, connecting anyway.", len(reqs), addr)
	}

	// If there's not already a pending or active connection to this node,
	// then instruct the connection manager to attempt to establish a
	// persistent connection to the peer.
	srvrLog.Debugf("Connecting to %v", addr)
	if perm {
		connReq := &connmgr.ConnReq{
			Addr:      addr,
			Permanent: true,
		}

		s.persistentPeers[targetPub] = struct{}{}
		if _, ok := s.persistentPeersBackoff[targetPub]; !ok {
			s.persistentPeersBackoff[targetPub] = defaultBackoff
		}
		s.persistentConnReqs[targetPub] = append(
			s.persistentConnReqs[targetPub], connReq)
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
	s.connectToPeer(addr, errChan)

	select {
	case err := <-errChan:
		return err
	case <-s.quit:
		return ErrServerShuttingDown
	}

	return nil
}

// connectToPeer establishes a connection to a remote peer. errChan is used to
// notify the caller if the connection attempt has failed. Otherwise, it will be
// closed.
func (s *server) connectToPeer(addr *lnwire.NetAddress, errChan chan<- error) {
	conn, err := brontide.Dial(s.identityPriv, addr, cfg.net.Dial)
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
func (s *server) OpenChannel(nodeKey *btcec.PublicKey,
	localAmt btcutil.Amount, pushAmt, minHtlc lnwire.MilliSatoshi,
	fundingFeePerVSize lnwallet.SatPerVByte, private bool,
	remoteCsvDelay uint16) (chan *lnrpc.OpenStatusUpdate, chan error) {

	// The updateChan will have a buffer of 2, since we expect a
	// ChanPending + a ChanOpen update, and we want to make sure the
	// funding process is not blocked if the caller is not reading the
	// updates.
	updateChan := make(chan *lnrpc.OpenStatusUpdate, 2)
	errChan := make(chan error, 1)

	var (
		targetPeer  *peer
		pubKeyBytes []byte
		err         error
	)

	// If the user is targeting the peer by public key, then we'll need to
	// convert that into a string for our map. Otherwise, we expect them to
	// target by peer ID instead.
	if nodeKey != nil {
		pubKeyBytes = nodeKey.SerializeCompressed()
	}

	// First attempt to locate the target peer to open a channel with, if
	// we're unable to locate the peer then this request will fail.
	s.mu.RLock()
	if peer, ok := s.peersByPub[string(pubKeyBytes)]; ok {
		targetPeer = peer
	}
	s.mu.RUnlock()

	if targetPeer == nil {
		errChan <- fmt.Errorf("peer is not connected NodeKey(%x)", pubKeyBytes)
		return updateChan, errChan
	}

	// If the fee rate wasn't specified, then we'll use a default
	// confirmation target.
	if fundingFeePerVSize == 0 {
		estimator := s.cc.feeEstimator
		fundingFeePerVSize, err = estimator.EstimateFeePerVSize(6)
		if err != nil {
			errChan <- err
			return updateChan, errChan
		}
	}

	// Spawn a goroutine to send the funding workflow request to the
	// funding manager. This allows the server to continue handling queries
	// instead of blocking on this request which is exported as a
	// synchronous request to the outside world.
	req := &openChanReq{
		targetPubkey:       nodeKey,
		chainHash:          *activeNetParams.GenesisHash,
		localFundingAmt:    localAmt,
		fundingFeePerVSize: fundingFeePerVSize,
		pushAmt:            pushAmt,
		private:            private,
		minHtlc:            minHtlc,
		remoteCsvDelay:     remoteCsvDelay,
		updates:            updateChan,
		err:                errChan,
	}

	// TODO(roasbeef): pass in chan that's closed if/when funding succeeds
	// so can track as persistent peer?
	go s.fundingMgr.initFundingWorkflow(targetPeer.addr, req)

	return updateChan, errChan
}

// Peers returns a slice of all active peers.
//
// NOTE: This function is safe for concurrent access.
func (s *server) Peers() []*peer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]*peer, 0, len(s.peersByPub))
	for _, peer := range s.peersByPub {
		peers = append(peers, peer)
	}

	return peers
}

// parseHexColor takes a hex string representation of a color in the
// form "#RRGGBB", parses the hex color values, and returns a color.RGBA
// struct of the same color.
func parseHexColor(colorStr string) (color.RGBA, error) {
	if len(colorStr) != 7 || colorStr[0] != '#' {
		return color.RGBA{}, errors.New("Color must be in format #RRGGBB")
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
func computeNextBackoff(currBackoff time.Duration) time.Duration {
	// Double the current backoff, truncating if it exceeds our maximum.
	nextBackoff := 2 * currBackoff
	if nextBackoff > maximumBackoff {
		nextBackoff = maximumBackoff
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

// fetchNodeAdvertisedAddr attempts to fetch an advertised address of a node.
func (s *server) fetchNodeAdvertisedAddr(pub *btcec.PublicKey) (net.Addr, error) {
	node, err := s.chanDB.ChannelGraph().FetchLightningNode(pub)
	if err != nil {
		return nil, err
	}

	if len(node.Addresses) == 0 {
		return nil, errors.New("no advertised addresses found")
	}

	return node.Addresses[0], nil
}
