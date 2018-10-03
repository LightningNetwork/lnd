package main

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/ticker"
)

var (
	numNodes int32

	// ErrPeerExiting signals that the peer received a disconnect request.
	ErrPeerExiting = fmt.Errorf("peer exiting")
)

const (
	// pingInterval is the interval at which ping messages are sent.
	pingInterval = 1 * time.Minute

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute

	// writeMessageTimeout is the timeout used when writing a message to peer.
	writeMessageTimeout = 50 * time.Second

	// outgoingQueueLen is the buffer size of the channel which houses
	// messages to be sent across the wire, requested by objects outside
	// this struct.
	outgoingQueueLen = 50
)

// outgoingMsg packages an lnwire.Message to be sent out on the wire, along with
// a buffered channel which will be sent upon once the write is complete. This
// buffered channel acts as a semaphore to be used for synchronization purposes.
type outgoingMsg struct {
	msg     lnwire.Message
	errChan chan error // MUST be buffered.
}

// newChannelMsg packages a channeldb.OpenChannel with a channel that allows
// the receiver of the request to report when the funding transaction has been
// confirmed and the channel creation process completed.
type newChannelMsg struct {
	channel *channeldb.OpenChannel
	err     chan error
}

// closeMsgs is a wrapper struct around any wire messages that deal with the
// cooperative channel closure negotiation process. This struct includes the
// raw channel ID targeted along with the original message.
type closeMsg struct {
	cid lnwire.ChannelID
	msg lnwire.Message
}

// chanSnapshotReq is a message sent by outside subsystems to a peer in order
// to gain a snapshot of the peer's currently active channels.
type chanSnapshotReq struct {
	resp chan []*channeldb.ChannelSnapshot
}

// peer is an active peer on the Lightning Network. This struct is responsible
// for managing any channel state related to this peer. To do so, it has
// several helper goroutines to handle events such as HTLC timeouts, new
// funding workflow, and detecting an uncooperative closure of any active
// channels.
// TODO(roasbeef): proper reconnection logic
type peer struct {
	// MUST be used atomically.
	started    int32
	disconnect int32

	// The following fields are only meant to be used *atomically*
	bytesReceived uint64
	bytesSent     uint64

	// pingTime is a rough estimate of the RTT (round-trip-time) between us
	// and the connected peer. This time is expressed in micro seconds.
	// To be used atomically.
	// TODO(roasbeef): also use a WMA or EMA?
	pingTime int64

	// pingLastSend is the Unix time expressed in nanoseconds when we sent
	// our last ping message.  To be used atomically.
	pingLastSend int64

	connReq *connmgr.ConnReq
	conn    net.Conn

	addr        *lnwire.NetAddress
	pubKeyBytes [33]byte

	// startTime is the time this peer connection was successfully
	// established. It will be zero for peers that did not successfully
	// Start().
	startTime time.Time

	inbound bool

	// sendQueue is the channel which is used to queue outgoing to be
	// written onto the wire. Note that this channel is unbuffered.
	sendQueue chan outgoingMsg

	// outgoingQueue is a buffered channel which allows second/third party
	// objects to queue messages to be sent out on the wire.
	outgoingQueue chan outgoingMsg

	// activeChannels is a map which stores the state machines of all
	// active channels. Channels are indexed into the map by the txid of
	// the funding transaction which opened the channel.
	activeChanMtx  sync.RWMutex
	activeChannels map[lnwire.ChannelID]*lnwallet.LightningChannel

	// newChannels is used by the fundingManager to send fully opened
	// channels to the source peer which handled the funding workflow.
	newChannels chan *newChannelMsg

	// activeChanCloses is a map that keep track of all the active
	// cooperative channel closures that are active. Any channel closing
	// messages are directed to one of these active state machines. Once
	// the channel has been closed, the state machine will be delete from
	// the map.
	activeChanCloses map[lnwire.ChannelID]*channelCloser

	// localCloseChanReqs is a channel in which any local requests to close
	// a particular channel are sent over.
	localCloseChanReqs chan *htlcswitch.ChanClose

	// linkFailures receives all reported channel failures from the switch,
	// and instructs the channelManager to clean remaining channel state.
	linkFailures chan linkFailureReport

	// chanCloseMsgs is a channel that any message related to channel
	// closures are sent over. This includes lnwire.Shutdown message as
	// well as lnwire.ClosingSigned messages.
	chanCloseMsgs chan *closeMsg

	server *server

	// localFeatures is the set of local features that we advertised to the
	// remote node.
	localFeatures *lnwire.RawFeatureVector

	// remoteLocalFeatures is the local feature vector received from the
	// peer during the connection handshake.
	remoteLocalFeatures *lnwire.FeatureVector

	// remoteGlobalFeatures is the global feature vector received from the
	// peer during the connection handshake.
	remoteGlobalFeatures *lnwire.FeatureVector

	// failedChannels is a set that tracks channels we consider `failed`.
	// This is a temporary measure until we have implemented real failure
	// handling at the link level, to handle the case where we reconnect to
	// a peer and try to re-sync a failed channel, triggering a disconnect
	// loop.
	// TODO(halseth): remove when link failure is properly handled.
	failedChannels map[lnwire.ChannelID]struct{}

	// writeBuf is a buffer that we'll re-use in order to encode wire
	// messages to write out directly on the socket. By re-using this
	// buffer, we avoid needing to allocate more memory each time a new
	// message is to be sent to a peer.
	writeBuf [lnwire.MaxMessagePayload]byte

	queueQuit chan struct{}
	quit      chan struct{}
	wg        sync.WaitGroup

	// NOTE: The following are only for backwards compatibility.

	// downgradedGQ indicates if we are attempting to downgrade our
	// advertised support for gossip queries to optional, even though we
	// require it.
	downgradedGQ bool

	// downgradedDLP indicates if we are attempting to downgrade our
	// advertised support for gossip queries to optional, even though we
	// require it.
	downgradedDLP bool

	// initComplete will be set true before the peer exits if the init
	// handoff occured without failure.
	initComplete bool

	// remoteSupportsOptGQ indicates whether or not the remote peer
	// advertised optional gossip query support.
	//
	// NOTE: Only valid if initComplete is true.
	remoteSupportsOptGQ bool

	// remoteSupportsOptDLP indicates whether or not the remote peer
	// advertised optional data loss protection support.
	//
	// NOTE: Only valid if initComplete is true.
	remoteSupportsOptDLP bool
}

// A compile-time check to ensure that peer satisfies the lnpeer.Peer interface.
var _ lnpeer.Peer = (*peer)(nil)

// newPeer creates a new peer from an establish connection object, and a
// pointer to the main server.
func newPeer(conn net.Conn, connReq *connmgr.ConnReq, server *server,
	addr *lnwire.NetAddress, inbound bool,
	localFeatures *lnwire.RawFeatureVector,
	downgradedGQ, downgradeDLP bool) (*peer, error) {

	nodePub := addr.IdentityKey

	p := &peer{
		conn: conn,
		addr: addr,

		inbound: inbound,
		connReq: connReq,

		server: server,

		localFeatures: localFeatures,

		downgradedGQ:  downgradedGQ,
		downgradedDLP: downgradeDLP,

		sendQueue:     make(chan outgoingMsg),
		outgoingQueue: make(chan outgoingMsg),

		activeChannels: make(map[lnwire.ChannelID]*lnwallet.LightningChannel),
		newChannels:    make(chan *newChannelMsg, 1),

		activeChanCloses:   make(map[lnwire.ChannelID]*channelCloser),
		localCloseChanReqs: make(chan *htlcswitch.ChanClose),
		linkFailures:       make(chan linkFailureReport),
		chanCloseMsgs:      make(chan *closeMsg),
		failedChannels:     make(map[lnwire.ChannelID]struct{}),

		queueQuit: make(chan struct{}),
		quit:      make(chan struct{}),
	}
	copy(p.pubKeyBytes[:], nodePub.SerializeCompressed())

	return p, nil
}

// Start starts all helper goroutines the peer needs for normal operations.  In
// the case this peer has already been started, then this function is a loop.
func (p *peer) Start() error {
	if atomic.AddInt32(&p.started, 1) != 1 {
		return nil
	}

	peerLog.Tracef("Peer %v starting", p)

	// Exchange local and global features, the init message should be very
	// first between two nodes.
	if err := p.sendInitMsg(); err != nil {
		return fmt.Errorf("unable to send init msg: %v", err)
	}

	// Before we launch any of the helper goroutines off the peer struct,
	// we'll first ensure proper adherence to the p2p protocol. The init
	// message MUST be sent before any other message.
	readErr := make(chan error, 1)
	msgChan := make(chan lnwire.Message, 1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		msg, err := p.readNextMessage()
		if err != nil {
			readErr <- err
			msgChan <- nil
			return
		}
		readErr <- nil
		msgChan <- msg
	}()

	select {
	// In order to avoid blocking indefinitely, we'll give the other peer
	// an upper timeout of 15 seconds to respond before we bail out early.
	case <-time.After(time.Second * 15):
		return fmt.Errorf("peer did not complete handshake within 5 " +
			"seconds")
	case err := <-readErr:
		if err != nil {
			return fmt.Errorf("unable to read init msg: %v", err)
		}
	}

	// Once the init message arrives, we can parse it so we can figure out
	// the negotiation of features for this session.
	msg := <-msgChan
	if msg, ok := msg.(*lnwire.Init); ok {
		if err := p.handleInitMsg(msg); err != nil {
			return err
		}
	} else {
		return errors.New("very first message between nodes " +
			"must be init message")
	}

	// Fetch and then load all the active channels we have with this remote
	// peer from the database.
	activeChans, err := p.server.chanDB.FetchOpenChannels(p.addr.IdentityKey)
	if err != nil {
		peerLog.Errorf("unable to fetch active chans "+
			"for peer %v: %v", p, err)
		return err
	}

	if len(activeChans) == 0 {
		p.server.prunePersistentPeerConnection(p.pubKeyBytes)
	}

	// Next, load all the active channels we have with this peer,
	// registering them with the switch and launching the necessary
	// goroutines required to operate them.
	peerLog.Debugf("Loaded %v active channels from database with "+
		"NodeKey(%x)", len(activeChans), p.PubKey())

	if err := p.loadActiveChannels(activeChans); err != nil {
		return fmt.Errorf("unable to load channels: %v", err)
	}

	p.startTime = time.Now()

	p.wg.Add(5)
	go p.queueHandler()
	go p.writeHandler()
	go p.readHandler()
	go p.channelManager()
	go p.pingHandler()

	return nil
}

// initGossipSync initializes either a gossip syncer or an initial routing
// dump, depending on the negotiated synchronization method.
func (p *peer) initGossipSync() {
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

		// Register the this peer's for gossip syncer with the gossiper.
		// This is blocks synchronously to ensure the gossip syncer is
		// registered with the gossiper before attempting to read
		// messages from the remote peer.
		p.server.authGossiper.InitSyncState(p, recvUpdates)

	// If the remote peer has the initial sync feature bit set, then we'll
	// being the synchronization protocol to exchange authenticated channel
	// graph edges/vertexes, but only if they don't know of the new gossip
	// queries.
	case p.remoteLocalFeatures.HasFeature(lnwire.InitialRoutingSync):
		srvrLog.Infof("Requesting full table sync with %x",
			p.pubKeyBytes[:])

		go p.server.authGossiper.SynchronizeNode(p)
	}
}

// QuitSignal is a method that should return a channel which will be sent upon
// or closed once the backing peer exits. This allows callers using the
// interface to cancel any processing in the event the backing implementation
// exits.
//
// NOTE: Part of the lnpeer.Peer interface.
func (p *peer) QuitSignal() <-chan struct{} {
	return p.quit
}

// loadActiveChannels creates indexes within the peer for tracking all active
// channels returned by the database.
func (p *peer) loadActiveChannels(chans []*channeldb.OpenChannel) error {
	var activePublicChans []wire.OutPoint
	for _, dbChan := range chans {
		lnChan, err := lnwallet.NewLightningChannel(
			p.server.cc.signer, p.server.witnessBeacon, dbChan,
		)
		if err != nil {
			return err
		}

		chanPoint := &dbChan.FundingOutpoint

		chanID := lnwire.NewChanIDFromOutPoint(chanPoint)

		peerLog.Infof("NodeKey(%x) loading ChannelPoint(%v)",
			p.PubKey(), chanPoint)

		// Skip adding any permanently irreconcilable channels to the
		// htlcswitch.
		if dbChan.ChanStatus() != channeldb.Default {
			peerLog.Warnf("ChannelPoint(%v) has status %v, won't "+
				"start.", chanPoint, dbChan.ChanStatus())
			lnChan.Stop()
			continue
		}

		// Also skip adding any channel marked as `failed` for this
		// session.
		if _, ok := p.failedChannels[chanID]; ok {
			peerLog.Warnf("ChannelPoint(%v) is failed, won't "+
				"start.", chanPoint)
			lnChan.Stop()
			continue
		}

		_, currentHeight, err := p.server.cc.chainIO.GetBestBlock()
		if err != nil {
			lnChan.Stop()
			return err
		}

		// Before we register this new link with the HTLC Switch, we'll
		// need to fetch its current link-layer forwarding policy from
		// the database.
		graph := p.server.chanDB.ChannelGraph()
		info, p1, p2, err := graph.FetchChannelEdgesByOutpoint(chanPoint)
		if err != nil && err != channeldb.ErrEdgeNotFound {
			lnChan.Stop()
			return err
		}

		// We'll filter out our policy from the directional channel
		// edges based whom the edge connects to. If it doesn't connect
		// to us, then we know that we were the one that advertised the
		// policy.
		//
		// TODO(roasbeef): can add helper method to get policy for
		// particular channel.
		var selfPolicy *channeldb.ChannelEdgePolicy
		if info != nil && bytes.Equal(info.NodeKey1Bytes[:],
			p.server.identityPriv.PubKey().SerializeCompressed()) {

			selfPolicy = p1
		} else {
			selfPolicy = p2
		}

		// If we don't yet have an advertised routing policy, then
		// we'll use the current default, otherwise we'll translate the
		// routing policy into a forwarding policy.
		var forwardingPolicy *htlcswitch.ForwardingPolicy
		if selfPolicy != nil {
			forwardingPolicy = &htlcswitch.ForwardingPolicy{
				MinHTLC:       selfPolicy.MinHTLC,
				BaseFee:       selfPolicy.FeeBaseMSat,
				FeeRate:       selfPolicy.FeeProportionalMillionths,
				TimeLockDelta: uint32(selfPolicy.TimeLockDelta),
			}
		} else {
			peerLog.Warnf("Unable to find our forwarding policy "+
				"for channel %v, using default values",
				chanPoint)
			forwardingPolicy = &p.server.cc.routingPolicy
		}

		peerLog.Tracef("Using link policy of: %v",
			spew.Sdump(forwardingPolicy))

		// Register this new channel link with the HTLC Switch. This is
		// necessary to properly route multi-hop payments, and forward
		// new payments triggered by RPC clients.
		chainEvents, err := p.server.chainArb.SubscribeChannelEvents(
			*chanPoint,
		)
		if err != nil {
			lnChan.Stop()
			return err
		}

		// Create the link and add it to the switch.
		err = p.addLink(
			chanPoint, lnChan, forwardingPolicy, chainEvents,
			currentHeight, true,
		)
		if err != nil {
			lnChan.Stop()
			return fmt.Errorf("unable to add link %v to switch: %v",
				chanPoint, err)
		}

		p.activeChanMtx.Lock()
		p.activeChannels[chanID] = lnChan
		p.activeChanMtx.Unlock()

		// To ensure we can route through this channel now that the peer
		// is back online, we'll attempt to send an update to enable it.
		// This will only be used for non-pending public channels, as
		// they are the only ones capable of routing.
		chanIsPublic := dbChan.ChannelFlags&lnwire.FFAnnounceChannel != 0
		if chanIsPublic && !dbChan.IsPending {
			activePublicChans = append(activePublicChans, *chanPoint)
		}
	}

	// As a final measure we launch a goroutine that will ensure the newly
	// loaded public channels are not currently disabled, as that will make
	// us skip it during path finding.
	go func() {
		for _, chanPoint := range activePublicChans {
			// Set the channel disabled=false by sending out a new
			// ChannelUpdate. If this channel is already active,
			// the update won't be sent.
			err := p.server.announceChanStatus(chanPoint, false)
			if err != nil && err != channeldb.ErrEdgeNotFound {
				srvrLog.Errorf("Unable to enable channel %v: %v",
					chanPoint, err)
			}
		}
	}()

	return nil
}

// addLink creates and adds a new link from the specified channel.
func (p *peer) addLink(chanPoint *wire.OutPoint,
	lnChan *lnwallet.LightningChannel,
	forwardingPolicy *htlcswitch.ForwardingPolicy,
	chainEvents *contractcourt.ChainEventSubscription,
	currentHeight int32, syncStates bool) error {

	// onChannelFailure will be called by the link in case the channel
	// fails for some reason.
	onChannelFailure := func(chanID lnwire.ChannelID,
		shortChanID lnwire.ShortChannelID,
		linkErr htlcswitch.LinkFailureError) {

		failure := linkFailureReport{
			chanPoint:   *chanPoint,
			chanID:      chanID,
			shortChanID: shortChanID,
			linkErr:     linkErr,
		}

		select {
		case p.linkFailures <- failure:
		case <-p.quit:
		case <-p.server.quit:
		}
	}

	linkCfg := htlcswitch.ChannelLinkConfig{
		Peer:                   p,
		DecodeHopIterators:     p.server.sphinx.DecodeHopIterators,
		ExtractErrorEncrypter:  p.server.sphinx.ExtractErrorEncrypter,
		FetchLastChannelUpdate: p.server.fetchLastChanUpdate(),
		DebugHTLC:              cfg.DebugHTLC,
		HodlMask:               cfg.Hodl.Mask(),
		Registry:               p.server.invoices,
		Switch:                 p.server.htlcSwitch,
		Circuits:               p.server.htlcSwitch.CircuitModifier(),
		ForwardPackets:         p.server.htlcSwitch.ForwardPackets,
		FwrdingPolicy:          *forwardingPolicy,
		FeeEstimator:           p.server.cc.feeEstimator,
		PreimageCache:          p.server.witnessBeacon,
		ChainEvents:            chainEvents,
		UpdateContractSignals: func(signals *contractcourt.ContractSignals) error {
			return p.server.chainArb.UpdateContractSignals(
				*chanPoint, signals,
			)
		},
		OnChannelFailure:    onChannelFailure,
		SyncStates:          syncStates,
		BatchTicker:         ticker.New(50 * time.Millisecond),
		FwdPkgGCTicker:      ticker.New(time.Minute),
		BatchSize:           10,
		UnsafeReplay:        cfg.UnsafeReplay,
		MinFeeUpdateTimeout: htlcswitch.DefaultMinLinkFeeUpdateTimeout,
		MaxFeeUpdateTimeout: htlcswitch.DefaultMaxLinkFeeUpdateTimeout,
	}

	link := htlcswitch.NewChannelLink(linkCfg, lnChan)

	// Before adding our new link, purge the switch of any pending or live
	// links going by the same channel id. If one is found, we'll shut it
	// down to ensure that the mailboxes are only ever under the control of
	// one link.
	p.server.htlcSwitch.RemoveLink(link.ChanID())

	// With the channel link created, we'll now notify the htlc switch so
	// this channel can be used to dispatch local payments and also
	// passively forward payments.
	return p.server.htlcSwitch.AddLink(link)
}

// WaitForDisconnect waits until the peer has disconnected. A peer may be
// disconnected if the local or remote side terminating the connection, or an
// irrecoverable protocol error has been encountered. This method will only
// begin watching the peer's waitgroup after the ready channel or the peer's
// quit channel are signaled. The ready channel should only be signaled if a
// call to Start returns no error. Otherwise, if the peer fails to start,
// calling Disconnect will signal the quit channel and the method will not
// block, since no goroutines were spawned.
func (p *peer) WaitForDisconnect(ready chan struct{}) {
	select {
	case <-ready:
	case <-p.quit:
	}

	p.wg.Wait()
}

// Disconnect terminates the connection with the remote peer. Additionally, a
// signal is sent to the server and htlcSwitch indicating the resources
// allocated to the peer can now be cleaned up.
func (p *peer) Disconnect(reason error) {
	if !atomic.CompareAndSwapInt32(&p.disconnect, 0, 1) {
		return
	}

	peerLog.Infof("Disconnecting %s, reason: %v", p, reason)

	// Ensure that the TCP connection is properly closed before continuing.
	p.conn.Close()

	close(p.quit)
}

// String returns the string representation of this peer.
func (p *peer) String() string {
	return p.conn.RemoteAddr().String()
}

// readNextMessage reads, and returns the next message on the wire along with
// any additional raw payload.
func (p *peer) readNextMessage() (lnwire.Message, error) {
	noiseConn, ok := p.conn.(*brontide.Conn)
	if !ok {
		return nil, fmt.Errorf("brontide.Conn required to read messages")
	}

	// First we'll read the next _full_ message. We do this rather than
	// reading incrementally from the stream as the Lightning wire protocol
	// is message oriented and allows nodes to pad on additional data to
	// the message stream.
	rawMsg, err := noiseConn.ReadNextMessage()
	atomic.AddUint64(&p.bytesReceived, uint64(len(rawMsg)))
	if err != nil {
		return nil, err
	}

	// Next, create a new io.Reader implementation from the raw message,
	// and use this to decode the message directly from.
	msgReader := bytes.NewReader(rawMsg)
	nextMsg, err := lnwire.ReadMessage(msgReader, 0)
	if err != nil {
		return nil, err
	}

	p.logWireMessage(nextMsg, true)

	return nextMsg, nil
}

// msgStream implements a goroutine-safe, in-order stream of messages to be
// delivered via closure to a receiver. These messages MUST be in order due to
// the nature of the lightning channel commitment and gossiper state machines.
// TODO(conner): use stream handler interface to abstract out stream
// state/logging
type msgStream struct {
	streamShutdown int32 // To be used atomically.

	peer *peer

	apply func(lnwire.Message)

	startMsg string
	stopMsg  string

	msgCond *sync.Cond
	msgs    []lnwire.Message

	mtx sync.Mutex

	bufSize      uint32
	producerSema chan struct{}

	wg   sync.WaitGroup
	quit chan struct{}
}

// newMsgStream creates a new instance of a chanMsgStream for a particular
// channel identified by its channel ID. bufSize is the max number of messages
// that should be buffered in the internal queue. Callers should set this to a
// sane value that avoids blocking unnecessarily, but doesn't allow an
// unbounded amount of memory to be allocated to buffer incoming messages.
func newMsgStream(p *peer, startMsg, stopMsg string, bufSize uint32,
	apply func(lnwire.Message)) *msgStream {

	stream := &msgStream{
		peer:         p,
		apply:        apply,
		startMsg:     startMsg,
		stopMsg:      stopMsg,
		producerSema: make(chan struct{}, bufSize),
		quit:         make(chan struct{}),
	}
	stream.msgCond = sync.NewCond(&stream.mtx)

	// Before we return the active stream, we'll populate the producer's
	// semaphore channel. We'll use this to ensure that the producer won't
	// attempt to allocate memory in the queue for an item until it has
	// sufficient extra space.
	for i := uint32(0); i < bufSize; i++ {
		stream.producerSema <- struct{}{}
	}

	return stream
}

// Start starts the chanMsgStream.
func (ms *msgStream) Start() {
	ms.wg.Add(1)
	go ms.msgConsumer()
}

// Stop stops the chanMsgStream.
func (ms *msgStream) Stop() {
	// TODO(roasbeef): signal too?

	close(ms.quit)

	// Now that we've closed the channel, we'll repeatedly signal the msg
	// consumer until we've detected that it has exited.
	for atomic.LoadInt32(&ms.streamShutdown) == 0 {
		ms.msgCond.Signal()
		time.Sleep(time.Millisecond * 100)
	}

	ms.wg.Wait()
}

// msgConsumer is the main goroutine that streams messages from the peer's
// readHandler directly to the target channel.
func (ms *msgStream) msgConsumer() {
	defer ms.wg.Done()
	defer peerLog.Tracef(ms.stopMsg)
	defer atomic.StoreInt32(&ms.streamShutdown, 1)

	peerLog.Tracef(ms.startMsg)

	for {
		// First, we'll check our condition. If the queue of messages
		// is empty, then we'll wait until a new item is added.
		ms.msgCond.L.Lock()
		for len(ms.msgs) == 0 {
			ms.msgCond.Wait()

			// If we woke up in order to exit, then we'll do so.
			// Otherwise, we'll check the message queue for any new
			// items.
			select {
			case <-ms.peer.quit:
				ms.msgCond.L.Unlock()
				return
			case <-ms.quit:
				ms.msgCond.L.Unlock()
				return
			default:
			}
		}

		// Grab the message off the front of the queue, shifting the
		// slice's reference down one in order to remove the message
		// from the queue.
		msg := ms.msgs[0]
		ms.msgs[0] = nil // Set to nil to prevent GC leak.
		ms.msgs = ms.msgs[1:]

		ms.msgCond.L.Unlock()

		ms.apply(msg)

		// We've just successfully processed an item, so we'll signal
		// to the producer that a new slot in the buffer. We'll use
		// this to bound the size of the buffer to avoid allowing it to
		// grow indefinitely.
		select {
		case ms.producerSema <- struct{}{}:
		case <-ms.peer.quit:
			return
		case <-ms.quit:
			return
		}
	}
}

// AddMsg adds a new message to the msgStream. This function is safe for
// concurrent access.
func (ms *msgStream) AddMsg(msg lnwire.Message, quit chan struct{}) {
	// First, we'll attempt to receive from the producerSema struct. This
	// acts as a sempahore to prevent us from indefinitely buffering
	// incoming items from the wire. Either the msg queue isn't full, and
	// we'll not block, or the queue is full, and we'll block until either
	// we're signalled to quit, or a slot is freed up.
	select {
	case <-ms.producerSema:
	case <-quit:
		return
	case <-ms.quit:
		return
	}

	// Next, we'll lock the condition, and add the message to the end of
	// the message queue.
	ms.msgCond.L.Lock()
	ms.msgs = append(ms.msgs, msg)
	ms.msgCond.L.Unlock()

	// With the message added, we signal to the msgConsumer that there are
	// additional messages to consume.
	ms.msgCond.Signal()
}

// newChanMsgStream is used to create a msgStream between the peer and
// particular channel link in the htlcswitch.  We utilize additional
// synchronization with the fundingManager to ensure we don't attempt to
// dispatch a message to a channel before it is fully active. A reference to the
// channel this stream forwards to his held in scope to prevent unnecessary
// lookups.
func newChanMsgStream(p *peer, cid lnwire.ChannelID) *msgStream {

	var chanLink htlcswitch.ChannelLink

	return newMsgStream(p,
		fmt.Sprintf("Update stream for ChannelID(%x) created", cid[:]),
		fmt.Sprintf("Update stream for ChannelID(%x) exiting", cid[:]),
		1000,
		func(msg lnwire.Message) {
			_, isChanSycMsg := msg.(*lnwire.ChannelReestablish)

			// If this is the chanSync message, then we'll deliver
			// it immediately to the active link.
			if !isChanSycMsg {
				// We'll send a message to the funding manager
				// and wait iff an active funding process for
				// this channel hasn't yet completed.  We do
				// this in order to account for the following
				// scenario: we send the funding locked message
				// to the other side, they immediately send a
				// channel update message, but we haven't yet
				// sent the channel to the channelManager.
				err := p.server.fundingMgr.waitUntilChannelOpen(
					cid, p.quit,
				)
				if err != nil {
					// If we have a non-nil error, then the
					// funding manager is shutting down, s
					// we can exit here without attempting
					// to deliver the message.
					return
				}
			}

			// In order to avoid unnecessarily delivering message
			// as the peer is exiting, we'll check quickly to see
			// if we need to exit.
			select {
			case <-p.quit:
				return
			default:
			}

			// Dispatch the commitment update message to the proper
			// active goroutine dedicated to this channel.
			if chanLink == nil {
				link, err := p.server.htlcSwitch.GetLink(cid)
				if err != nil {
					peerLog.Errorf("recv'd update for unknown "+
						"channel %v from %v", cid, p)
					return
				}
				chanLink = link
			}

			// In order to avoid unnecessarily delivering message
			// as the peer is exiting, we'll check quickly to see
			// if we need to exit.
			select {
			case <-p.quit:
				return
			default:
			}

			chanLink.HandleChannelUpdate(msg)
		},
	)
}

// newDiscMsgStream is used to setup a msgStream between the peer and the
// authenticated gossiper. This stream should be used to forward all remote
// channel announcements.
func newDiscMsgStream(p *peer) *msgStream {
	return newMsgStream(p,
		"Update stream for gossiper created",
		"Update stream for gossiper exited",
		1000,
		func(msg lnwire.Message) {
			p.server.authGossiper.ProcessRemoteAnnouncement(msg, p)
		},
	)
}

// readHandler is responsible for reading messages off the wire in series, then
// properly dispatching the handling of the message to the proper subsystem.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) readHandler() {
	defer p.wg.Done()

	// We'll stop the timer after a new messages is received, and also
	// reset it after we process the next message.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		err := fmt.Errorf("Peer %s no answer for %s -- disconnecting",
			p, idleTimeout)
		p.Disconnect(err)
	})

	// Initialize our negotiated gossip sync method before reading
	// messages off the wire. When using gossip queries, this ensures
	// a gossip syncer is active by the time query messages arrive.
	//
	// TODO(conner): have peer store gossip syncer directly and bypass
	// gossiper?
	p.initGossipSync()

	discStream := newDiscMsgStream(p)
	discStream.Start()
	defer discStream.Stop()

	chanMsgStreams := make(map[lnwire.ChannelID]*msgStream)
out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		nextMsg, err := p.readNextMessage()
		idleTimer.Stop()
		if err != nil {
			peerLog.Infof("unable to read message from %v: %v",
				p, err)

			switch err.(type) {
			// If this is just a message we don't yet recognize,
			// we'll continue processing as normal as this allows
			// us to introduce new messages in a forwards
			// compatible manner.
			case *lnwire.UnknownMessage:
				idleTimer.Reset(idleTimeout)
				continue

			// If they sent us an address type that we don't yet
			// know of, then this isn't a dire error, so we'll
			// simply continue parsing the remainder of their
			// messages.
			case *lnwire.ErrUnknownAddrType:
				idleTimer.Reset(idleTimeout)
				continue

			// If the error we encountered wasn't just a message we
			// didn't recognize, then we'll stop all processing s
			// this is a fatal error.
			default:
				break out
			}
		}

		var (
			isChanUpdate bool
			targetChan   lnwire.ChannelID
		)

		switch msg := nextMsg.(type) {
		case *lnwire.Pong:
			// When we receive a Pong message in response to our
			// last ping message, we'll use the time in which we
			// sent the ping message to measure a rough estimate of
			// round trip time.
			pingSendTime := atomic.LoadInt64(&p.pingLastSend)
			delay := (time.Now().UnixNano() - pingSendTime) / 1000
			atomic.StoreInt64(&p.pingTime, delay)

		case *lnwire.Ping:
			pongBytes := make([]byte, msg.NumPongBytes)
			p.queueMsg(lnwire.NewPong(pongBytes), nil)

		case *lnwire.OpenChannel:
			p.server.fundingMgr.processFundingOpen(msg, p)
		case *lnwire.AcceptChannel:
			p.server.fundingMgr.processFundingAccept(msg, p)
		case *lnwire.FundingCreated:
			p.server.fundingMgr.processFundingCreated(msg, p)
		case *lnwire.FundingSigned:
			p.server.fundingMgr.processFundingSigned(msg, p)
		case *lnwire.FundingLocked:
			p.server.fundingMgr.processFundingLocked(msg, p)

		case *lnwire.Shutdown:
			select {
			case p.chanCloseMsgs <- &closeMsg{msg.ChannelID, msg}:
			case <-p.quit:
				break out
			}
		case *lnwire.ClosingSigned:
			select {
			case p.chanCloseMsgs <- &closeMsg{msg.ChannelID, msg}:
			case <-p.quit:
				break out
			}

		case *lnwire.Error:
			key := p.addr.IdentityKey

			switch {
			// In the case of an all-zero channel ID we want to
			// forward the error to all channels with this peer.
			case msg.ChanID == lnwire.ConnectionWideID:
				for chanID, chanStream := range chanMsgStreams {
					chanStream.AddMsg(nextMsg, p.quit)

					// Also marked this channel as failed,
					// so we won't try to restart it on
					// reconnect with this peer.
					p.failedChannels[chanID] = struct{}{}
				}

			// If the channel ID for the error message corresponds
			// to a pending channel, then the funding manager will
			// handle the error.
			case p.server.fundingMgr.IsPendingChannel(msg.ChanID, key):
				p.server.fundingMgr.processFundingError(msg, key)

			// If not we hand the error to the channel link for
			// this channel.
			default:
				isChanUpdate = true
				targetChan = msg.ChanID

				// Also marked this channel as failed, so we
				// won't try to restart it on reconnect with
				// this peer.
				p.failedChannels[targetChan] = struct{}{}
			}

		// TODO(roasbeef): create ChanUpdater interface for the below
		case *lnwire.UpdateAddHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.UpdateFulfillHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.UpdateFailMalformedHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.UpdateFailHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.RevokeAndAck:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.CommitSig:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.UpdateFee:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.ChannelReestablish:
			isChanUpdate = true
			targetChan = msg.ChanID

		case *lnwire.ChannelUpdate,
			*lnwire.ChannelAnnouncement,
			*lnwire.NodeAnnouncement,
			*lnwire.AnnounceSignatures,
			*lnwire.GossipTimestampRange,
			*lnwire.QueryShortChanIDs,
			*lnwire.QueryChannelRange,
			*lnwire.ReplyChannelRange,
			*lnwire.ReplyShortChanIDsEnd:

			discStream.AddMsg(msg, p.quit)

		default:
			peerLog.Errorf("unknown message %v received from peer "+
				"%v", uint16(msg.MsgType()), p)
		}

		if isChanUpdate {
			// If this is a channel update, then we need to feed it
			// into the channel's in-order message stream.
			chanStream, ok := chanMsgStreams[targetChan]
			if !ok {
				// If a stream hasn't yet been created, then
				// we'll do so, add it to the map, and finally
				// start it.
				chanStream = newChanMsgStream(p, targetChan)
				chanMsgStreams[targetChan] = chanStream
				chanStream.Start()
				defer chanStream.Stop()
			}

			// With the stream obtained, add the message to the
			// stream so we can continue processing message.
			chanStream.AddMsg(nextMsg, p.quit)
		}

		idleTimer.Reset(idleTimeout)
	}

	p.Disconnect(errors.New("read handler closed"))

	peerLog.Tracef("readHandler for peer %v done", p)
}

// messageSummary returns a human-readable string that summarizes a
// incoming/outgoing message. Not all messages will have a summary, only those
// which have additional data that can be informative at a glance.
func messageSummary(msg lnwire.Message) string {
	switch msg := msg.(type) {
	case *lnwire.Init:
		// No summary.
		return ""

	case *lnwire.OpenChannel:
		return fmt.Sprintf("temp_chan_id=%x, chain=%v, csv=%v, amt=%v, "+
			"push_amt=%v, reserve=%v, flags=%v",
			msg.PendingChannelID[:], msg.ChainHash,
			msg.CsvDelay, msg.FundingAmount, msg.PushAmount,
			msg.ChannelReserve, msg.ChannelFlags)

	case *lnwire.AcceptChannel:
		return fmt.Sprintf("temp_chan_id=%x, reserve=%v, csv=%v, num_confs=%v",
			msg.PendingChannelID[:], msg.ChannelReserve, msg.CsvDelay,
			msg.MinAcceptDepth)

	case *lnwire.FundingCreated:
		return fmt.Sprintf("temp_chan_id=%x, chan_point=%v",
			msg.PendingChannelID[:], msg.FundingPoint)

	case *lnwire.FundingSigned:
		return fmt.Sprintf("chan_id=%v", msg.ChanID)

	case *lnwire.FundingLocked:
		return fmt.Sprintf("chan_id=%v, next_point=%x",
			msg.ChanID, msg.NextPerCommitmentPoint.SerializeCompressed())

	case *lnwire.Shutdown:
		return fmt.Sprintf("chan_id=%v, script=%x", msg.ChannelID,
			msg.Address[:])

	case *lnwire.ClosingSigned:
		return fmt.Sprintf("chan_id=%v, fee_sat=%v", msg.ChannelID,
			msg.FeeSatoshis)

	case *lnwire.UpdateAddHTLC:
		return fmt.Sprintf("chan_id=%v, id=%v, amt=%v, expiry=%v, hash=%x",
			msg.ChanID, msg.ID, msg.Amount, msg.Expiry, msg.PaymentHash[:])

	case *lnwire.UpdateFailHTLC:
		return fmt.Sprintf("chan_id=%v, id=%v, reason=%x", msg.ChanID,
			msg.ID, msg.Reason)

	case *lnwire.UpdateFulfillHTLC:
		return fmt.Sprintf("chan_id=%v, id=%v, pre_image=%x",
			msg.ChanID, msg.ID, msg.PaymentPreimage[:])

	case *lnwire.CommitSig:
		return fmt.Sprintf("chan_id=%v, num_htlcs=%v", msg.ChanID,
			len(msg.HtlcSigs))

	case *lnwire.RevokeAndAck:
		return fmt.Sprintf("chan_id=%v, rev=%x, next_point=%x",
			msg.ChanID, msg.Revocation[:],
			msg.NextRevocationKey.SerializeCompressed())

	case *lnwire.UpdateFailMalformedHTLC:
		return fmt.Sprintf("chan_id=%v, id=%v, fail_code=%v",
			msg.ChanID, msg.ID, msg.FailureCode)

	case *lnwire.Error:
		return fmt.Sprintf("chan_id=%v, err=%v", msg.ChanID, string(msg.Data))

	case *lnwire.AnnounceSignatures:
		return fmt.Sprintf("chan_id=%v, short_chan_id=%v", msg.ChannelID,
			msg.ShortChannelID.ToUint64())

	case *lnwire.ChannelAnnouncement:
		return fmt.Sprintf("chain_hash=%v, short_chan_id=%v",
			msg.ChainHash, msg.ShortChannelID.ToUint64())

	case *lnwire.ChannelUpdate:
		return fmt.Sprintf("chain_hash=%v, short_chan_id=%v, flag=%v, "+
			"update_time=%v", msg.ChainHash,
			msg.ShortChannelID.ToUint64(), msg.Flags,
			time.Unix(int64(msg.Timestamp), 0))

	case *lnwire.NodeAnnouncement:
		return fmt.Sprintf("node=%x, update_time=%v",
			msg.NodeID, time.Unix(int64(msg.Timestamp), 0))

	case *lnwire.Ping:
		// No summary.
		return ""

	case *lnwire.Pong:
		// No summary.
		return ""

	case *lnwire.UpdateFee:
		return fmt.Sprintf("chan_id=%v, fee_update_sat=%v",
			msg.ChanID, int64(msg.FeePerKw))

	case *lnwire.ChannelReestablish:
		return fmt.Sprintf("next_local_height=%v, remote_tail_height=%v",
			msg.NextLocalCommitHeight, msg.RemoteCommitTailHeight)

	case *lnwire.ReplyShortChanIDsEnd:
		return fmt.Sprintf("chain_hash=%v, complete=%v", msg.ChainHash,
			msg.Complete)

	case *lnwire.ReplyChannelRange:
		return fmt.Sprintf("complete=%v, encoding=%v, num_chans=%v",
			msg.Complete, msg.EncodingType, len(msg.ShortChanIDs))

	case *lnwire.QueryShortChanIDs:
		return fmt.Sprintf("chain_hash=%v, encoding=%v, num_chans=%v",
			msg.ChainHash, msg.EncodingType, len(msg.ShortChanIDs))

	case *lnwire.QueryChannelRange:
		return fmt.Sprintf("chain_hash=%v, start_height=%v, "+
			"num_blocks=%v", msg.ChainHash, msg.FirstBlockHeight,
			msg.NumBlocks)

	case *lnwire.GossipTimestampRange:
		return fmt.Sprintf("chain_hash=%v, first_stamp=%v, "+
			"stamp_range=%v", msg.ChainHash,
			time.Unix(int64(msg.FirstTimestamp), 0),
			msg.TimestampRange)

	}

	return ""
}

// logWireMessage logs the receipt or sending of particular wire message. This
// function is used rather than just logging the message in order to produce
// less spammy log messages in trace mode by setting the 'Curve" parameter to
// nil. Doing this avoids printing out each of the field elements in the curve
// parameters for secp256k1.
func (p *peer) logWireMessage(msg lnwire.Message, read bool) {
	summaryPrefix := "Received"
	if !read {
		summaryPrefix = "Sending"
	}

	peerLog.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = "(" + summary + ")"
		}

		preposition := "to"
		if read {
			preposition = "from"
		}

		return fmt.Sprintf("%v %v%s %v %s", summaryPrefix,
			msg.MsgType(), summary, preposition, p)
	}))

	switch m := msg.(type) {
	case *lnwire.ChannelReestablish:
		if m.LocalUnrevokedCommitPoint != nil {
			m.LocalUnrevokedCommitPoint.Curve = nil
		}
	case *lnwire.RevokeAndAck:
		m.NextRevocationKey.Curve = nil
	case *lnwire.AcceptChannel:
		m.FundingKey.Curve = nil
		m.RevocationPoint.Curve = nil
		m.PaymentPoint.Curve = nil
		m.DelayedPaymentPoint.Curve = nil
		m.HtlcPoint.Curve = nil
		m.FirstCommitmentPoint.Curve = nil
	case *lnwire.OpenChannel:
		m.FundingKey.Curve = nil
		m.RevocationPoint.Curve = nil
		m.PaymentPoint.Curve = nil
		m.DelayedPaymentPoint.Curve = nil
		m.HtlcPoint.Curve = nil
		m.FirstCommitmentPoint.Curve = nil
	case *lnwire.FundingLocked:
		m.NextPerCommitmentPoint.Curve = nil
	}

	prefix := "readMessage from"
	if !read {
		prefix = "writeMessage to"
	}

	peerLog.Tracef(prefix+" %v: %v", p, newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
}

// writeMessage writes the target lnwire.Message to the remote peer.
func (p *peer) writeMessage(msg lnwire.Message) error {
	// Simply exit if we're shutting down.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return ErrPeerExiting
	}

	p.logWireMessage(msg, false)

	// We'll re-slice of static write buffer to allow this new message to
	// utilize all available space. We also ensure we cap the capacity of
	// this new buffer to the static buffer which is sized for the largest
	// possible protocol message.
	b := bytes.NewBuffer(p.writeBuf[0:0:len(p.writeBuf)])

	// With the temp buffer created and sliced properly (length zero, full
	// capacity), we'll now encode the message directly into this buffer.
	n, err := lnwire.WriteMessage(b, msg, 0)
	atomic.AddUint64(&p.bytesSent, uint64(n))

	p.conn.SetWriteDeadline(time.Now().Add(writeMessageTimeout))

	// Finally, write the message itself in a single swoop.
	_, err = p.conn.Write(b.Bytes())
	return err
}

// writeHandler is a goroutine dedicated to reading messages off of an incoming
// queue, and writing them out to the wire. This goroutine coordinates with the
// queueHandler in order to ensure the incoming message queue is quickly
// drained.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) writeHandler() {
	var exitErr error

out:
	for {
		select {
		case outMsg := <-p.sendQueue:
			switch outMsg.msg.(type) {
			// If we're about to send a ping message, then log the
			// exact time in which we send the message so we can
			// use the delay as a rough estimate of latency to the
			// remote peer.
			case *lnwire.Ping:
				// TODO(roasbeef): do this before the write?
				// possibly account for processing within func?
				now := time.Now().UnixNano()
				atomic.StoreInt64(&p.pingLastSend, now)
			}

			// Write out the message to the socket, responding with
			// error if `errChan` is non-nil. The `errChan` allows
			// callers to optionally synchronize sends with the
			// writeHandler.
			err := p.writeMessage(outMsg.msg)
			if outMsg.errChan != nil {
				outMsg.errChan <- err
			}

			if err != nil {
				exitErr = fmt.Errorf("unable to write "+
					"message: %v", err)
				break out
			}

		case <-p.quit:
			exitErr = ErrPeerExiting
			break out
		}
	}

	p.wg.Done()

	p.Disconnect(exitErr)

	peerLog.Tracef("writeHandler for peer %v done", p)
}

// queueHandler is responsible for accepting messages from outside subsystems
// to be eventually sent out on the wire by the writeHandler.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) queueHandler() {
	defer p.wg.Done()

	// pendingMsgs will hold all messages waiting to be added
	// to the sendQueue.
	pendingMsgs := list.New()

	for {
		// Examine the front of the queue.
		elem := pendingMsgs.Front()
		if elem != nil {
			// There's an element on the queue, try adding
			// it to the sendQueue. We also watch for
			// messages on the outgoingQueue, in case the
			// writeHandler cannot accept messages on the
			// sendQueue.
			select {
			case p.sendQueue <- elem.Value.(outgoingMsg):
				pendingMsgs.Remove(elem)
			case msg := <-p.outgoingQueue:
				pendingMsgs.PushBack(msg)
			case <-p.quit:
				return
			}
		} else {
			// If there weren't any messages to send to the
			// writeHandler, then we'll accept a new message
			// into the queue from outside sub-systems.
			select {
			case msg := <-p.outgoingQueue:
				pendingMsgs.PushBack(msg)
			case <-p.quit:
				return
			}
		}
	}
}

// pingHandler is responsible for periodically sending ping messages to the
// remote peer in order to keep the connection alive and/or determine if the
// connection is still active.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) pingHandler() {
	defer p.wg.Done()

	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	// TODO(roasbeef): make dynamic in order to create fake cover traffic
	const numPingBytes = 16

out:
	for {
		select {
		case <-pingTicker.C:
			p.queueMsg(lnwire.NewPing(numPingBytes), nil)
		case <-p.quit:
			break out
		}
	}
}

// PingTime returns the estimated ping time to the peer in microseconds.
func (p *peer) PingTime() int64 {
	return atomic.LoadInt64(&p.pingTime)
}

// queueMsg queues a new lnwire.Message to be eventually sent out on the
// wire. It returns an error if we failed to queue the message. An error
// is sent on errChan if the message fails being sent to the peer, or
// nil otherwise.
func (p *peer) queueMsg(msg lnwire.Message, errChan chan error) {
	select {
	case p.outgoingQueue <- outgoingMsg{msg, errChan}:
	case <-p.quit:
		peerLog.Tracef("Peer shutting down, could not enqueue msg.")
		if errChan != nil {
			errChan <- ErrPeerExiting
		}
	}
}

// ChannelSnapshots returns a slice of channel snapshots detailing all
// currently active channels maintained with the remote peer.
func (p *peer) ChannelSnapshots() []*channeldb.ChannelSnapshot {
	p.activeChanMtx.RLock()
	defer p.activeChanMtx.RUnlock()

	snapshots := make([]*channeldb.ChannelSnapshot, 0, len(p.activeChannels))
	for _, activeChan := range p.activeChannels {
		// We'll only return a snapshot for channels that are
		// *immedately* available for routing payments over.
		if activeChan.RemoteNextRevocation() == nil {
			continue
		}

		snapshot := activeChan.StateSnapshot()
		snapshots = append(snapshots, snapshot)
	}

	return snapshots
}

// genDeliveryScript returns a new script to be used to send our funds to in
// the case of a cooperative channel close negotiation.
func (p *peer) genDeliveryScript() ([]byte, error) {
	deliveryAddr, err := p.server.cc.wallet.NewAddress(
		lnwallet.WitnessPubKey, false,
	)
	if err != nil {
		return nil, err
	}
	peerLog.Infof("Delivery addr for channel close: %v",
		deliveryAddr)

	return txscript.PayToAddrScript(deliveryAddr)
}

// channelManager is goroutine dedicated to handling all requests/signals
// pertaining to the opening, cooperative closing, and force closing of all
// channels maintained with the remote peer.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) channelManager() {
	defer p.wg.Done()

out:
	for {
		select {
		// A new channel has arrived which means we've just completed a
		// funding workflow. We'll initialize the necessary local
		// state, and notify the htlc switch of a new link.
		case newChanReq := <-p.newChannels:
			newChan := newChanReq.channel
			chanPoint := &newChan.FundingOutpoint
			chanID := lnwire.NewChanIDFromOutPoint(chanPoint)

			// Make sure this channel is not already active.
			p.activeChanMtx.Lock()
			if currentChan, ok := p.activeChannels[chanID]; ok {
				peerLog.Infof("Already have ChannelPoint(%v), "+
					"ignoring.", chanPoint)

				p.activeChanMtx.Unlock()
				close(newChanReq.err)

				// If we're being sent a new channel, and our
				// existing channel doesn't have the next
				// revocation, then we need to update the
				// current existing channel.
				if currentChan.RemoteNextRevocation() != nil {
					continue
				}

				peerLog.Infof("Processing retransmitted "+
					"FundingLocked for ChannelPoint(%v)",
					chanPoint)

				nextRevoke := newChan.RemoteNextRevocation
				err := currentChan.InitNextRevocation(nextRevoke)
				if err != nil {
					peerLog.Errorf("unable to init chan "+
						"revocation: %v", err)
					continue
				}

				continue
			}

			// If not already active, we'll add this channel to the
			// set of active channels, so we can look it up later
			// easily according to its channel ID.
			lnChan, err := lnwallet.NewLightningChannel(
				p.server.cc.signer, p.server.witnessBeacon,
				newChan,
			)
			if err != nil {
				p.activeChanMtx.Unlock()
				err := fmt.Errorf("unable to create "+
					"LightningChannel: %v", err)
				peerLog.Errorf(err.Error())

				newChanReq.err <- err
				continue
			}

			p.activeChannels[chanID] = lnChan
			p.activeChanMtx.Unlock()

			peerLog.Infof("New channel active ChannelPoint(%v) "+
				"with NodeKey(%x)", chanPoint, p.PubKey())

			// Next, we'll assemble a ChannelLink along with the
			// necessary items it needs to function.
			//
			// TODO(roasbeef): panic on below?
			_, currentHeight, err := p.server.cc.chainIO.GetBestBlock()
			if err != nil {
				err := fmt.Errorf("unable to get best "+
					"block: %v", err)
				peerLog.Errorf(err.Error())

				lnChan.Stop()
				newChanReq.err <- err
				continue
			}
			chainEvents, err := p.server.chainArb.SubscribeChannelEvents(
				*chanPoint,
			)
			if err != nil {
				err := fmt.Errorf("unable to subscribe to "+
					"chain events: %v", err)
				peerLog.Errorf(err.Error())

				lnChan.Stop()
				newChanReq.err <- err
				continue
			}

			// We'll query the localChanCfg of the new channel to
			// determine the minimum HTLC value that can be
			// forwarded. For fees we'll use the default values, as
			// they currently are always set to the default values
			// at initial channel creation.
			fwdMinHtlc := lnChan.FwdMinHtlc()
			defaultPolicy := p.server.cc.routingPolicy
			forwardingPolicy := &htlcswitch.ForwardingPolicy{
				MinHTLC:       fwdMinHtlc,
				BaseFee:       defaultPolicy.BaseFee,
				FeeRate:       defaultPolicy.FeeRate,
				TimeLockDelta: defaultPolicy.TimeLockDelta,
			}

			// Create the link and add it to the switch.
			err = p.addLink(
				chanPoint, lnChan, forwardingPolicy,
				chainEvents, currentHeight, false,
			)
			if err != nil {
				err := fmt.Errorf("can't register new channel "+
					"link(%v) with NodeKey(%x)", chanPoint,
					p.PubKey())
				peerLog.Errorf(err.Error())

				lnChan.Stop()
				newChanReq.err <- err
				continue
			}

			close(newChanReq.err)

		// We've just received a local request to close an active
		// channel. If will either kick of a cooperative channel
		// closure negotiation, or be a notification of a breached
		// contract that should be abandoned.
		case req := <-p.localCloseChanReqs:
			p.handleLocalCloseReq(req)

		// We've received a link failure from a link that was added to
		// the switch. This will initiate the teardown of the link, and
		// initiate any on-chain closures if necessary.
		case failure := <-p.linkFailures:
			p.handleLinkFailure(failure)

		// We've received a new cooperative channel closure related
		// message from the remote peer, we'll use this message to
		// advance the chan closer state machine.
		case closeMsg := <-p.chanCloseMsgs:
			// We'll now fetch the matching closing state machine
			// in order to continue, or finalize the channel
			// closure process.
			chanCloser, err := p.fetchActiveChanCloser(closeMsg.cid)
			if err != nil {
				// If the channel is not known to us, we'll
				// simply ignore this message.
				if err == ErrChannelNotFound {
					continue
				}

				peerLog.Errorf("Unable to respond to remote "+
					"close msg: %v", err)

				errMsg := &lnwire.Error{
					ChanID: closeMsg.cid,
					Data:   lnwire.ErrorData(err.Error()),
				}
				p.queueMsg(errMsg, nil)
				continue
			}

			// Next, we'll process the next message using the
			// target state machine. We'll either continue
			// negotiation, or halt.
			msgs, closeFin, err := chanCloser.ProcessCloseMsg(
				closeMsg.msg,
			)
			if err != nil {
				err := fmt.Errorf("unable to process close "+
					"msg: %v", err)
				peerLog.Error(err)

				// As the negotiations failed, we'll reset the
				// channel state to ensure we act to on-chain
				// events as normal.
				chanCloser.cfg.channel.ResetState()

				if chanCloser.CloseRequest() != nil {
					chanCloser.CloseRequest().Err <- err
				}
				delete(p.activeChanCloses, closeMsg.cid)
				continue
			}

			// Queue any messages to the remote peer that need to
			// be sent as a part of this latest round of
			// negotiations.
			for _, msg := range msgs {
				p.queueMsg(msg, nil)
			}

			// If we haven't finished close negotiations, then
			// we'll continue as we can't yet finalize the closure.
			if !closeFin {
				continue
			}

			// Otherwise, we've agreed on a closing fee! In this
			// case, we'll wrap up the channel closure by notifying
			// relevant sub-systems and launching a goroutine to
			// wait for close tx conf.
			p.finalizeChanClosure(chanCloser)
		case <-p.quit:

			// As, we've been signalled to exit, we'll reset all
			// our active channel back to their default state.
			p.activeChanMtx.Lock()
			for _, channel := range p.activeChannels {
				channel.ResetState()
			}
			p.activeChanMtx.Unlock()

			break out
		}
	}
}

// fetchActiveChanCloser attempts to fetch the active chan closer state machine
// for the target channel ID. If the channel isn't active an error is returned.
// Otherwise, either an existing state machine will be returned, or a new one
// will be created.
func (p *peer) fetchActiveChanCloser(chanID lnwire.ChannelID) (*channelCloser, error) {
	// First, we'll ensure that we actually know of the target channel. If
	// not, we'll ignore this message.
	p.activeChanMtx.RLock()
	channel, ok := p.activeChannels[chanID]
	p.activeChanMtx.RUnlock()
	if !ok {
		return nil, ErrChannelNotFound
	}

	// We'll attempt to look up the matching state machine, if we can't
	// find one then this means that the remote party is initiating a
	// cooperative channel closure.
	chanCloser, ok := p.activeChanCloses[chanID]
	if !ok {
		// If we need to create a chan closer for the first time, then
		// we'll check to ensure that the channel is even in the proper
		// state to allow a co-op channel closure.
		if len(channel.ActiveHtlcs()) != 0 {
			return nil, fmt.Errorf("cannot co-op close " +
				"channel w/ active htlcs")
		}

		// We'll create a valid closing state machine in order to
		// respond to the initiated cooperative channel closure.
		deliveryAddr, err := p.genDeliveryScript()
		if err != nil {
			peerLog.Errorf("unable to gen delivery script: %v", err)

			return nil, fmt.Errorf("close addr unavailable")
		}

		// In order to begin fee negotiations, we'll first compute our
		// target ideal fee-per-kw. We'll set this to a lax value, as
		// we weren't the ones that initiated the channel closure.
		feePerKw, err := p.server.cc.feeEstimator.EstimateFeePerKW(6)
		if err != nil {
			peerLog.Errorf("unable to query fee estimator: %v", err)

			return nil, fmt.Errorf("unable to estimate fee")
		}

		_, startingHeight, err := p.server.cc.chainIO.GetBestBlock()
		if err != nil {
			peerLog.Errorf("unable to obtain best block: %v", err)
			return nil, fmt.Errorf("cannot obtain best block")
		}

		chanCloser = newChannelCloser(
			chanCloseCfg{
				channel:           channel,
				unregisterChannel: p.server.htlcSwitch.RemoveLink,
				broadcastTx:       p.server.cc.wallet.PublishTransaction,
				disableChannel: func(op wire.OutPoint) error {
					return p.server.announceChanStatus(op,
						true)
				},
				quit: p.quit,
			},
			deliveryAddr,
			feePerKw,
			uint32(startingHeight),
			nil,
		)
		p.activeChanCloses[chanID] = chanCloser
	}

	return chanCloser, nil
}

// handleLocalCloseReq kicks-off the workflow to execute a cooperative or
// forced unilateral closure of the channel initiated by a local subsystem.
func (p *peer) handleLocalCloseReq(req *htlcswitch.ChanClose) {
	chanID := lnwire.NewChanIDFromOutPoint(req.ChanPoint)

	p.activeChanMtx.RLock()
	channel, ok := p.activeChannels[chanID]
	p.activeChanMtx.RUnlock()
	if !ok {
		err := fmt.Errorf("unable to close channel, ChannelID(%v) is "+
			"unknown", chanID)
		peerLog.Errorf(err.Error())
		req.Err <- err
		return
	}

	switch req.CloseType {

	// A type of CloseRegular indicates that the user has opted to close
	// out this channel on-chain, so we execute the cooperative channel
	// closure workflow.
	case htlcswitch.CloseRegular:
		// First, we'll fetch a fresh delivery address that we'll use
		// to send the funds to in the case of a successful
		// negotiation.
		deliveryAddr, err := p.genDeliveryScript()
		if err != nil {
			peerLog.Errorf(err.Error())
			req.Err <- err
			return
		}

		// Next, we'll create a new channel closer state machine to
		// handle the close negotiation.
		_, startingHeight, err := p.server.cc.chainIO.GetBestBlock()
		if err != nil {
			peerLog.Errorf(err.Error())
			req.Err <- err
			return
		}

		chanCloser := newChannelCloser(
			chanCloseCfg{
				channel:           channel,
				unregisterChannel: p.server.htlcSwitch.RemoveLink,
				broadcastTx:       p.server.cc.wallet.PublishTransaction,
				disableChannel: func(op wire.OutPoint) error {
					return p.server.announceChanStatus(op,
						true)
				},
				quit: p.quit,
			},
			deliveryAddr,
			req.TargetFeePerKw,
			uint32(startingHeight),
			req,
		)
		p.activeChanCloses[chanID] = chanCloser

		// Finally, we'll initiate the channel shutdown within the
		// chanCloser, and send the shutdown message to the remote
		// party to kick things off.
		shutdownMsg, err := chanCloser.ShutdownChan()
		if err != nil {
			peerLog.Errorf(err.Error())
			req.Err <- err
			delete(p.activeChanCloses, chanID)

			// As we were unable to shutdown the channel, we'll
			// return it back to its normal state.
			channel.ResetState()
			return
		}

		p.queueMsg(shutdownMsg, nil)

	// A type of CloseBreach indicates that the counterparty has breached
	// the channel therefore we need to clean up our local state.
	case htlcswitch.CloseBreach:
		// TODO(roasbeef): no longer need with newer beach logic?
		peerLog.Infof("ChannelPoint(%v) has been breached, wiping "+
			"channel", req.ChanPoint)
		if err := p.WipeChannel(req.ChanPoint); err != nil {
			peerLog.Infof("Unable to wipe channel after detected "+
				"breach: %v", err)
			req.Err <- err
			return
		}
		return
	}
}

// linkFailureReport is sent to the channelManager whenever a link that was
// added to the switch reports a link failure, and is forced to exit. The report
// houses the necessary information to cleanup the channel state, send back the
// error message, and force close if necessary.
type linkFailureReport struct {
	chanPoint   wire.OutPoint
	chanID      lnwire.ChannelID
	shortChanID lnwire.ShortChannelID
	linkErr     htlcswitch.LinkFailureError
}

// handleLinkFailure processes a link failure report when a link in the switch
// fails. It handles facilitates removal of all channel state within the peer,
// force closing the channel depending on severity, and sending the error
// message back to the remote party.
func (p *peer) handleLinkFailure(failure linkFailureReport) {
	// We begin by wiping the link, which will remove it from the switch,
	// such that it won't be attempted used for any more updates.
	//
	// TODO(halseth): should introduce a way to atomically stop/pause the
	// link and cancel back any adds in its mailboxes such that we can
	// safely force close without the link being added again and updates
	// being applied.
	if err := p.WipeChannel(&failure.chanPoint); err != nil {
		peerLog.Errorf("Unable to wipe link for chanpoint=%v",
			failure.chanPoint)
		return
	}

	// If the error encountered was severe enough, we'll now force close the
	// channel to prevent readding it to the switch in the future.
	if failure.linkErr.ForceClose {
		peerLog.Warnf("Force closing link(%v)",
			failure.shortChanID)

		closeTx, err := p.server.chainArb.ForceCloseContract(
			failure.chanPoint,
		)
		if err != nil {
			peerLog.Errorf("unable to force close "+
				"link(%v): %v", failure.shortChanID, err)
		} else {
			peerLog.Infof("channel(%v) force "+
				"closed with txid %v",
				failure.shortChanID, closeTx.TxHash())
		}
	}

	// Send an error to the peer, why we failed the channel.
	if failure.linkErr.ShouldSendToPeer() {
		// If SendData is set, send it to the peer. If not, we'll use
		// the standard error messages in the payload. We only include
		// sendData in the cases where the error data does not contain
		// sensitive information.
		data := []byte(failure.linkErr.Error())
		if failure.linkErr.SendData != nil {
			data = failure.linkErr.SendData
		}
		err := p.SendMessage(true, &lnwire.Error{
			ChanID: failure.chanID,
			Data:   data,
		})
		if err != nil {
			peerLog.Errorf("unable to send msg to "+
				"remote peer: %v", err)
		}
	}
}

// finalizeChanClosure performs the final clean up steps once the cooperative
// closure transaction has been fully broadcast. The finalized closing state
// machine should be passed in. Once the transaction has been sufficiently
// confirmed, the channel will be marked as fully closed within the database,
// and any clients will be notified of updates to the closing state.
func (p *peer) finalizeChanClosure(chanCloser *channelCloser) {
	closeReq := chanCloser.CloseRequest()

	// First, we'll clear all indexes related to the channel in question.
	chanPoint := chanCloser.cfg.channel.ChannelPoint()
	if err := p.WipeChannel(chanPoint); err != nil {
		if closeReq != nil {
			closeReq.Err <- err
		}
	}

	chanCloser.cfg.channel.Stop()

	// Next, we'll launch a goroutine which will request to be notified by
	// the ChainNotifier once the closure transaction obtains a single
	// confirmation.
	notifier := p.server.cc.chainNotifier

	// If any error happens during waitForChanToClose, forward it to
	// closeReq. If this channel closure is not locally initiated, closeReq
	// will be nil, so just ignore the error.
	errChan := make(chan error, 1)
	if closeReq != nil {
		errChan = closeReq.Err
	}

	closingTx, err := chanCloser.ClosingTx()
	if err != nil {
		if closeReq != nil {
			peerLog.Error(err)
			closeReq.Err <- err
		}
	}

	closingTxid := closingTx.TxHash()

	// If this is a locally requested shutdown, update the caller with a
	// new event detailing the current pending state of this request.
	if closeReq != nil {
		closeReq.Updates <- &lnrpc.CloseStatusUpdate{
			Update: &lnrpc.CloseStatusUpdate_ClosePending{
				ClosePending: &lnrpc.PendingUpdate{
					Txid: closingTxid[:],
				},
			},
		}
	}

	go waitForChanToClose(chanCloser.negotiationHeight, notifier, errChan,
		chanPoint, &closingTxid, closingTx.TxOut[0].PkScript, func() {

			// Respond to the local subsystem which requested the
			// channel closure.
			if closeReq != nil {
				closeReq.Updates <- &lnrpc.CloseStatusUpdate{
					Update: &lnrpc.CloseStatusUpdate_ChanClose{
						ChanClose: &lnrpc.ChannelCloseUpdate{
							ClosingTxid: closingTxid[:],
							Success:     true,
						},
					},
				}
			}
		})
}

// waitForChanToClose uses the passed notifier to wait until the channel has
// been detected as closed on chain and then concludes by executing the
// following actions: the channel point will be sent over the settleChan, and
// finally the callback will be executed. If any error is encountered within
// the function, then it will be sent over the errChan.
func waitForChanToClose(bestHeight uint32, notifier chainntnfs.ChainNotifier,
	errChan chan error, chanPoint *wire.OutPoint,
	closingTxID *chainhash.Hash, closeScript []byte, cb func()) {

	peerLog.Infof("Waiting for confirmation of cooperative close of "+
		"ChannelPoint(%v) with txid: %v", chanPoint,
		closingTxID)

	// TODO(roasbeef): add param for num needed confs
	confNtfn, err := notifier.RegisterConfirmationsNtfn(
		closingTxID, closeScript, 1, bestHeight,
	)
	if err != nil {
		if errChan != nil {
			errChan <- err
		}
		return
	}

	// In the case that the ChainNotifier is shutting down, all subscriber
	// notification channels will be closed, generating a nil receive.
	height, ok := <-confNtfn.Confirmed
	if !ok {
		return
	}

	// The channel has been closed, remove it from any active indexes, and
	// the database state.
	peerLog.Infof("ChannelPoint(%v) is now closed at "+
		"height %v", chanPoint, height.BlockHeight)

	// Finally, execute the closure call back to mark the confirmation of
	// the transaction closing the contract.
	cb()
}

// WipeChannel removes the passed channel point from all indexes associated with
// the peer, and the switch.
func (p *peer) WipeChannel(chanPoint *wire.OutPoint) error {
	chanID := lnwire.NewChanIDFromOutPoint(chanPoint)

	p.activeChanMtx.Lock()
	if channel, ok := p.activeChannels[chanID]; ok {
		channel.Stop()
		delete(p.activeChannels, chanID)
	}
	p.activeChanMtx.Unlock()

	// Instruct the HtlcSwitch to close this link as the channel is no
	// longer active.
	p.server.htlcSwitch.RemoveLink(chanID)

	return nil
}

// handleInitMsg handles the incoming init message which contains global and
// local features vectors. If feature vectors are incompatible then disconnect.
func (p *peer) handleInitMsg(msg *lnwire.Init) error {
	p.remoteLocalFeatures = lnwire.NewFeatureVector(msg.LocalFeatures,
		lnwire.LocalFeatures)
	p.remoteGlobalFeatures = lnwire.NewFeatureVector(msg.GlobalFeatures,
		lnwire.GlobalFeatures)

	// Ensure that the we understand all of the remote node's local,
	// required feature bits.
	unknownLocalFeatures := p.remoteLocalFeatures.UnknownRequiredFeatures()
	if len(unknownLocalFeatures) > 0 {
		err := fmt.Errorf("Peer set unknown local feature bits: %v",
			unknownLocalFeatures)
		return err
	}

	// Ensure that the we understand all of the remote node's global,
	// required feature bits.
	unknownGlobalFeatures := p.remoteGlobalFeatures.UnknownRequiredFeatures()
	if len(unknownGlobalFeatures) > 0 {
		err := fmt.Errorf("Peer set unknown global feature bits: %v",
			unknownGlobalFeatures)
		return err
	}

	// Record whether or not the remote node supports optional gossip
	// queries. In the case that we are configured to require it, this
	// information can be used to downgrade our advertised level in case the
	// remote peer doesn't understand the required gossip queries feature
	// bit.
	p.remoteSupportsOptGQ = p.remoteLocalFeatures.IsSet(
		lnwire.GossipQueriesOptional,
	)

	// Record whether or not the remote node supports optional data loss
	// protection. In the case that we are configured to require it, this
	// information can be used to downgrade our advertised level in case the
	// remote peer doesn't understand the required data loss protection
	// feature bit.
	p.remoteSupportsOptDLP = p.remoteLocalFeatures.IsSet(
		lnwire.GossipQueriesOptional,
	)

	// If we are attempting a downgraded gossip queries connection, this
	// implies that we are trying to advertise gossip queries as required.
	// If the remote peer claims they no longer support optional gossip
	// queries (after previously saying they did), we will disconnect the
	// peer to maintain that we require gossip queries.
	if p.downgradedGQ && !p.remoteSupportsOptGQ {
		err := fmt.Errorf("Downgraded peer does not support " +
			"gossip queries, though we require")
		return err
	}

	// If we are attempting a downgraded data loss protection connection,
	// this implies that we are trying to advertise data loss protection as
	// required. If the remote peer claims they no longer support optional
	// data loss protection (after previously saying they did), we will
	// disconnect the peer to maintain that we require data loss protection.
	if p.downgradedDLP && p.remoteSupportsOptDLP {
		err := fmt.Errorf("Downgraded peer does not support " +
			"data loss protection, though we require")
		return err
	}

	// If we have succeeded in all of the standard checks and passed the
	// downgrade checks, we will mark the peer has having completed the init
	// handshake. If this is the first time this occurs with a peer and we
	// are requiring support for either, the values of remoteSupportsOptGQ
	// and remoteSupportsOptDLP will be used to downgrade the our advertised
	// feature bit for either on subsequent connections.
	p.initComplete = true

	return nil
}

// sendInitMsg sends init message to remote peer which contains our currently
// supported local and global features.
func (p *peer) sendInitMsg() error {
	msg := lnwire.NewInitMessage(
		p.server.globalFeatures.RawFeatureVector,
		p.localFeatures,
	)

	return p.writeMessage(msg)
}

// SendMessage sends a variadic number of message to remote peer. The first
// argument denotes if the method should block until the message has been sent
// to the remote peer.
//
// NOTE: Part of the lnpeer.Peer interface.
func (p *peer) SendMessage(sync bool, msgs ...lnwire.Message) error {
	// Add all incoming messages to the outgoing queue. A list of error
	// chans is populated for each message if the caller requested a sync
	// send.
	var errChans []chan error
	for _, msg := range msgs {
		// If a sync send was requested, create an error chan to listen
		// for an ack from the writeHandler.
		var errChan chan error
		if sync {
			errChan = make(chan error, 1)
			errChans = append(errChans, errChan)
		}

		p.queueMsg(msg, errChan)
	}

	// Wait for all replies from the writeHandler. For async sends, this
	// will be a NOP as the list of error chans is nil.
	for _, errChan := range errChans {
		select {
		case err := <-errChan:
			return err
		case <-p.quit:
			return ErrPeerExiting
		}
	}

	return nil
}

// PubKey returns the pubkey of the peer in compressed serialized format.
//
// NOTE: Part of the lnpeer.Peer interface.
func (p *peer) PubKey() [33]byte {
	return p.pubKeyBytes
}

// IdentityKey returns the public key of the remote peer.
//
// NOTE: Part of the lnpeer.Peer interface.
func (p *peer) IdentityKey() *btcec.PublicKey {
	return p.addr.IdentityKey
}

// Address returns the network address of the remote peer.
//
// NOTE: Part of the lnpeer.Peer interface.
func (p *peer) Address() net.Addr {
	return p.addr.Address
}

// AddNewChannel adds a new channel to the peer. The channel should fail to be
// added if the cancel channel is closed.
//
// NOTE: Part of the lnpeer.Peer interface.
func (p *peer) AddNewChannel(channel *channeldb.OpenChannel,
	cancel <-chan struct{}) error {

	errChan := make(chan error, 1)
	newChanMsg := &newChannelMsg{
		channel: channel,
		err:     errChan,
	}

	select {
	case p.newChannels <- newChanMsg:
	case <-cancel:
		return errors.New("canceled adding new channel")
	case <-p.quit:
		return ErrPeerExiting
	}

	// We pause here to wait for the peer to recognize the new channel
	// before we close the channel barrier corresponding to the channel.
	select {
	case err := <-errChan:
		return err
	case <-p.quit:
		return ErrPeerExiting
	}
}

// StartTime returns the time at which the connection was established if the
// peer started successfully, and zero otherwise.
func (p *peer) StartTime() time.Time {
	return p.startTime
}

// TODO(roasbeef): make all start/stop mutexes a CAS
