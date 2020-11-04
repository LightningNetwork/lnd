package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/multimutex"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/ticker"
)

var (
	// ErrGossiperShuttingDown is an error that is returned if the gossiper
	// is in the process of being shut down.
	ErrGossiperShuttingDown = errors.New("gossiper is shutting down")

	// ErrGossipSyncerNotFound signals that we were unable to find an active
	// gossip syncer corresponding to a gossip query message received from
	// the remote peer.
	ErrGossipSyncerNotFound = errors.New("gossip syncer not found")
)

// optionalMsgFields is a set of optional message fields that external callers
// can provide that serve useful when processing a specific network
// announcement.
type optionalMsgFields struct {
	capacity     *btcutil.Amount
	channelPoint *wire.OutPoint
}

// apply applies the optional fields within the functional options.
func (f *optionalMsgFields) apply(optionalMsgFields ...OptionalMsgField) {
	for _, optionalMsgField := range optionalMsgFields {
		optionalMsgField(f)
	}
}

// OptionalMsgField is a functional option parameter that can be used to provide
// external information that is not included within a network message but serves
// useful when processing it.
type OptionalMsgField func(*optionalMsgFields)

// ChannelCapacity is an optional field that lets the gossiper know of the
// capacity of a channel.
func ChannelCapacity(capacity btcutil.Amount) OptionalMsgField {
	return func(f *optionalMsgFields) {
		f.capacity = &capacity
	}
}

// ChannelPoint is an optional field that lets the gossiper know of the outpoint
// of a channel.
func ChannelPoint(op wire.OutPoint) OptionalMsgField {
	return func(f *optionalMsgFields) {
		f.channelPoint = &op
	}
}

// networkMsg couples a routing related wire message with the peer that
// originally sent it.
type networkMsg struct {
	peer              lnpeer.Peer
	source            *btcec.PublicKey
	msg               lnwire.Message
	optionalMsgFields *optionalMsgFields

	isRemote bool

	err chan error
}

// chanPolicyUpdateRequest is a request that is sent to the server when a caller
// wishes to update a particular set of channels. New ChannelUpdate messages
// will be crafted to be sent out during the next broadcast epoch and the fee
// updates committed to the lower layer.
type chanPolicyUpdateRequest struct {
	edgesToUpdate []EdgeWithInfo
	errChan       chan error
}

// Config defines the configuration for the service. ALL elements within the
// configuration MUST be non-nil for the service to carry out its duties.
type Config struct {
	// ChainHash is a hash that indicates which resident chain of the
	// AuthenticatedGossiper. Any announcements that don't match this
	// chain hash will be ignored.
	//
	// TODO(roasbeef): eventually make into map so can de-multiplex
	// incoming announcements
	//   * also need to do same for Notifier
	ChainHash chainhash.Hash

	// Router is the subsystem which is responsible for managing the
	// topology of lightning network. After incoming channel, node, channel
	// updates announcements are validated they are sent to the router in
	// order to be included in the LN graph.
	Router routing.ChannelGraphSource

	// ChanSeries is an interfaces that provides access to a time series
	// view of the current known channel graph. Each GossipSyncer enabled
	// peer will utilize this in order to create and respond to channel
	// graph time series queries.
	ChanSeries ChannelGraphTimeSeries

	// Notifier is used for receiving notifications of incoming blocks.
	// With each new incoming block found we process previously premature
	// announcements.
	//
	// TODO(roasbeef): could possibly just replace this with an epoch
	// channel.
	Notifier chainntnfs.ChainNotifier

	// Broadcast broadcasts a particular set of announcements to all peers
	// that the daemon is connected to. If supplied, the exclude parameter
	// indicates that the target peer should be excluded from the
	// broadcast.
	Broadcast func(skips map[route.Vertex]struct{},
		msg ...lnwire.Message) error

	// NotifyWhenOnline is a function that allows the gossiper to be
	// notified when a certain peer comes online, allowing it to
	// retry sending a peer message.
	//
	// NOTE: The peerChan channel must be buffered.
	NotifyWhenOnline func(peerPubKey [33]byte, peerChan chan<- lnpeer.Peer)

	// NotifyWhenOffline is a function that allows the gossiper to be
	// notified when a certain peer disconnects, allowing it to request a
	// notification for when it reconnects.
	NotifyWhenOffline func(peerPubKey [33]byte) <-chan struct{}

	// SelfNodeAnnouncement is a function that fetches our own current node
	// announcement, for use when determining whether we should update our
	// peers about our presence on the network. If the refresh is true, a
	// new and updated announcement will be returned.
	SelfNodeAnnouncement func(refresh bool) (lnwire.NodeAnnouncement, error)

	// ProofMatureDelta the number of confirmations which is needed before
	// exchange the channel announcement proofs.
	ProofMatureDelta uint32

	// TrickleDelay the period of trickle timer which flushes to the
	// network the pending batch of new announcements we've received since
	// the last trickle tick.
	TrickleDelay time.Duration

	// RetransmitTicker is a ticker that ticks with a period which
	// indicates that we should check if we need re-broadcast any of our
	// personal channels.
	RetransmitTicker ticker.Ticker

	// RebroadcastInterval is the maximum time we wait between sending out
	// channel updates for our active channels and our own node
	// announcement. We do this to ensure our active presence on the
	// network is known, and we are not being considered a zombie node or
	// having zombie channels.
	RebroadcastInterval time.Duration

	// WaitingProofStore is a persistent storage of partial channel proof
	// announcement messages. We use it to buffer half of the material
	// needed to reconstruct a full authenticated channel announcement.
	// Once we receive the other half the channel proof, we'll be able to
	// properly validate it and re-broadcast it out to the network.
	//
	// TODO(wilmer): make interface to prevent channeldb dependency.
	WaitingProofStore *channeldb.WaitingProofStore

	// MessageStore is a persistent storage of gossip messages which we will
	// use to determine which messages need to be resent for a given peer.
	MessageStore GossipMessageStore

	// AnnSigner is an instance of the MessageSigner interface which will
	// be used to manually sign any outgoing channel updates. The signer
	// implementation should be backed by the public key of the backing
	// Lightning node.
	//
	// TODO(roasbeef): extract ann crafting + sign from fundingMgr into
	// here?
	AnnSigner lnwallet.MessageSigner

	// NumActiveSyncers is the number of peers for which we should have
	// active syncers with. After reaching NumActiveSyncers, any future
	// gossip syncers will be passive.
	NumActiveSyncers int

	// RotateTicker is a ticker responsible for notifying the SyncManager
	// when it should rotate its active syncers. A single active syncer with
	// a chansSynced state will be exchanged for a passive syncer in order
	// to ensure we don't keep syncing with the same peers.
	RotateTicker ticker.Ticker

	// HistoricalSyncTicker is a ticker responsible for notifying the
	// syncManager when it should attempt a historical sync with a gossip
	// sync peer.
	HistoricalSyncTicker ticker.Ticker

	// ActiveSyncerTimeoutTicker is a ticker responsible for notifying the
	// syncManager when it should attempt to start the next pending
	// activeSyncer due to the current one not completing its state machine
	// within the timeout.
	ActiveSyncerTimeoutTicker ticker.Ticker

	// MinimumBatchSize is minimum size of a sub batch of announcement
	// messages.
	MinimumBatchSize int

	// SubBatchDelay is the delay between sending sub batches of
	// gossip messages.
	SubBatchDelay time.Duration

	// IgnoreHistoricalFilters will prevent syncers from replying with
	// historical data when the remote peer sets a gossip_timestamp_range.
	// This prevents ranges with old start times from causing us to dump the
	// graph on connect.
	IgnoreHistoricalFilters bool
}

// AuthenticatedGossiper is a subsystem which is responsible for receiving
// announcements, validating them and applying the changes to router, syncing
// lightning network with newly connected nodes, broadcasting announcements
// after validation, negotiating the channel announcement proofs exchange and
// handling the premature announcements. All outgoing announcements are
// expected to be properly signed as dictated in BOLT#7, additionally, all
// incoming message are expected to be well formed and signed. Invalid messages
// will be rejected by this struct.
type AuthenticatedGossiper struct {
	// Parameters which are needed to properly handle the start and stop of
	// the service.
	started sync.Once
	stopped sync.Once

	// bestHeight is the height of the block at the tip of the main chain
	// as we know it. Accesses *MUST* be done with the gossiper's lock
	// held.
	bestHeight uint32

	quit chan struct{}
	wg   sync.WaitGroup

	// cfg is a copy of the configuration struct that the gossiper service
	// was initialized with.
	cfg *Config

	// blockEpochs encapsulates a stream of block epochs that are sent at
	// every new block height.
	blockEpochs *chainntnfs.BlockEpochEvent

	// prematureAnnouncements maps a block height to a set of network
	// messages which are "premature" from our PoV. A message is premature
	// if it claims to be anchored in a block which is beyond the current
	// main chain tip as we know it. Premature network messages will be
	// processed once the chain tip as we know it extends to/past the
	// premature height.
	//
	// TODO(roasbeef): limit premature networkMsgs to N
	prematureAnnouncements map[uint32][]*networkMsg

	// prematureChannelUpdates is a map of ChannelUpdates we have received
	// that wasn't associated with any channel we know about.  We store
	// them temporarily, such that we can reprocess them when a
	// ChannelAnnouncement for the channel is received.
	prematureChannelUpdates map[uint64][]*networkMsg
	pChanUpdMtx             sync.Mutex

	// networkMsgs is a channel that carries new network broadcasted
	// message from outside the gossiper service to be processed by the
	// networkHandler.
	networkMsgs chan *networkMsg

	// chanPolicyUpdates is a channel that requests to update the
	// forwarding policy of a set of channels is sent over.
	chanPolicyUpdates chan *chanPolicyUpdateRequest

	// selfKey is the identity public key of the backing Lightning node.
	selfKey *btcec.PublicKey

	// channelMtx is used to restrict the database access to one
	// goroutine per channel ID. This is done to ensure that when
	// the gossiper is handling an announcement, the db state stays
	// consistent between when the DB is first read until it's written.
	channelMtx *multimutex.Mutex

	rejectMtx     sync.RWMutex
	recentRejects map[uint64]struct{}

	// syncMgr is a subsystem responsible for managing the gossip syncers
	// for peers currently connected. When a new peer is connected, the
	// manager will create its accompanying gossip syncer and determine
	// whether it should have an activeSync or passiveSync sync type based
	// on how many other gossip syncers are currently active. Any activeSync
	// gossip syncers are started in a round-robin manner to ensure we're
	// not syncing with multiple peers at the same time.
	syncMgr *SyncManager

	// reliableSender is a subsystem responsible for handling reliable
	// message send requests to peers. This should only be used for channels
	// that are unadvertised at the time of handling the message since if it
	// is advertised, then peers should be able to get the message from the
	// network.
	reliableSender *reliableSender

	sync.Mutex
}

// New creates a new AuthenticatedGossiper instance, initialized with the
// passed configuration parameters.
func New(cfg Config, selfKey *btcec.PublicKey) *AuthenticatedGossiper {
	gossiper := &AuthenticatedGossiper{
		selfKey:                 selfKey,
		cfg:                     &cfg,
		networkMsgs:             make(chan *networkMsg),
		quit:                    make(chan struct{}),
		chanPolicyUpdates:       make(chan *chanPolicyUpdateRequest),
		prematureAnnouncements:  make(map[uint32][]*networkMsg),
		prematureChannelUpdates: make(map[uint64][]*networkMsg),
		channelMtx:              multimutex.NewMutex(),
		recentRejects:           make(map[uint64]struct{}),
		syncMgr: newSyncManager(&SyncManagerCfg{
			ChainHash:               cfg.ChainHash,
			ChanSeries:              cfg.ChanSeries,
			RotateTicker:            cfg.RotateTicker,
			HistoricalSyncTicker:    cfg.HistoricalSyncTicker,
			NumActiveSyncers:        cfg.NumActiveSyncers,
			IgnoreHistoricalFilters: cfg.IgnoreHistoricalFilters,
		}),
	}

	gossiper.reliableSender = newReliableSender(&reliableSenderCfg{
		NotifyWhenOnline:  cfg.NotifyWhenOnline,
		NotifyWhenOffline: cfg.NotifyWhenOffline,
		MessageStore:      cfg.MessageStore,
		IsMsgStale:        gossiper.isMsgStale,
	})

	return gossiper
}

// EdgeWithInfo contains the information that is required to update an edge.
type EdgeWithInfo struct {
	// Info describes the channel.
	Info *channeldb.ChannelEdgeInfo

	// Edge describes the policy in one direction of the channel.
	Edge *channeldb.ChannelEdgePolicy
}

// PropagateChanPolicyUpdate signals the AuthenticatedGossiper to perform the
// specified edge updates. Updates are done in two stages: first, the
// AuthenticatedGossiper ensures the update has been committed by dependent
// sub-systems, then it signs and broadcasts new updates to the network. A
// mapping between outpoints and updated channel policies is returned, which is
// used to update the forwarding policies of the underlying links.
func (d *AuthenticatedGossiper) PropagateChanPolicyUpdate(
	edgesToUpdate []EdgeWithInfo) error {

	errChan := make(chan error, 1)
	policyUpdate := &chanPolicyUpdateRequest{
		edgesToUpdate: edgesToUpdate,
		errChan:       errChan,
	}

	select {
	case d.chanPolicyUpdates <- policyUpdate:
		err := <-errChan
		return err
	case <-d.quit:
		return fmt.Errorf("AuthenticatedGossiper shutting down")
	}
}

// Start spawns network messages handler goroutine and registers on new block
// notifications in order to properly handle the premature announcements.
func (d *AuthenticatedGossiper) Start() error {
	var err error
	d.started.Do(func() {
		err = d.start()
	})
	return err
}

func (d *AuthenticatedGossiper) start() error {
	log.Info("Authenticated Gossiper is starting")

	// First we register for new notifications of newly discovered blocks.
	// We do this immediately so we'll later be able to consume any/all
	// blocks which were discovered.
	blockEpochs, err := d.cfg.Notifier.RegisterBlockEpochNtfn(nil)
	if err != nil {
		return err
	}
	d.blockEpochs = blockEpochs

	height, err := d.cfg.Router.CurrentBlockHeight()
	if err != nil {
		return err
	}
	d.bestHeight = height

	// Start the reliable sender. In case we had any pending messages ready
	// to be sent when the gossiper was last shut down, we must continue on
	// our quest to deliver them to their respective peers.
	if err := d.reliableSender.Start(); err != nil {
		return err
	}

	d.syncMgr.Start()

	d.wg.Add(1)
	go d.networkHandler()

	return nil
}

// Stop signals any active goroutines for a graceful closure.
func (d *AuthenticatedGossiper) Stop() {
	d.stopped.Do(d.stop)
}

func (d *AuthenticatedGossiper) stop() {
	log.Info("Authenticated Gossiper is stopping")

	d.blockEpochs.Cancel()

	d.syncMgr.Stop()

	close(d.quit)
	d.wg.Wait()

	// We'll stop our reliable sender after all of the gossiper's goroutines
	// have exited to ensure nothing can cause it to continue executing.
	d.reliableSender.Stop()
}

// TODO(roasbeef): need method to get current gossip timestamp?
//  * using mtx, check time rotate forward is needed?

// ProcessRemoteAnnouncement sends a new remote announcement message along with
// the peer that sent the routing message. The announcement will be processed
// then added to a queue for batched trickled announcement to all connected
// peers.  Remote channel announcements should contain the announcement proof
// and be fully validated.
func (d *AuthenticatedGossiper) ProcessRemoteAnnouncement(msg lnwire.Message,
	peer lnpeer.Peer) chan error {

	errChan := make(chan error, 1)

	// For messages in the known set of channel series queries, we'll
	// dispatch the message directly to the GossipSyncer, and skip the main
	// processing loop.
	switch m := msg.(type) {
	case *lnwire.QueryShortChanIDs,
		*lnwire.QueryChannelRange,
		*lnwire.ReplyChannelRange,
		*lnwire.ReplyShortChanIDsEnd:

		syncer, ok := d.syncMgr.GossipSyncer(peer.PubKey())
		if !ok {
			log.Warnf("Gossip syncer for peer=%x not found",
				peer.PubKey())

			errChan <- ErrGossipSyncerNotFound
			return errChan
		}

		// If we've found the message target, then we'll dispatch the
		// message directly to it.
		syncer.ProcessQueryMsg(m, peer.QuitSignal())

		errChan <- nil
		return errChan

	// If a peer is updating its current update horizon, then we'll dispatch
	// that directly to the proper GossipSyncer.
	case *lnwire.GossipTimestampRange:
		syncer, ok := d.syncMgr.GossipSyncer(peer.PubKey())
		if !ok {
			log.Warnf("Gossip syncer for peer=%x not found",
				peer.PubKey())

			errChan <- ErrGossipSyncerNotFound
			return errChan
		}

		// If we've found the message target, then we'll dispatch the
		// message directly to it.
		if err := syncer.ApplyGossipFilter(m); err != nil {
			log.Warnf("Unable to apply gossip filter for peer=%x: "+
				"%v", peer.PubKey(), err)

			errChan <- err
			return errChan
		}

		errChan <- nil
		return errChan
	}

	nMsg := &networkMsg{
		msg:      msg,
		isRemote: true,
		peer:     peer,
		source:   peer.IdentityKey(),
		err:      errChan,
	}

	select {
	case d.networkMsgs <- nMsg:

	// If the peer that sent us this error is quitting, then we don't need
	// to send back an error and can return immediately.
	case <-peer.QuitSignal():
		return nil
	case <-d.quit:
		nMsg.err <- ErrGossiperShuttingDown
	}

	return nMsg.err
}

// ProcessLocalAnnouncement sends a new remote announcement message along with
// the peer that sent the routing message. The announcement will be processed
// then added to a queue for batched trickled announcement to all connected
// peers.  Local channel announcements don't contain the announcement proof and
// will not be fully validated. Once the channel proofs are received, the
// entire channel announcement and update messages will be re-constructed and
// broadcast to the rest of the network.
func (d *AuthenticatedGossiper) ProcessLocalAnnouncement(msg lnwire.Message,
	source *btcec.PublicKey, optionalFields ...OptionalMsgField) chan error {

	optionalMsgFields := &optionalMsgFields{}
	optionalMsgFields.apply(optionalFields...)

	nMsg := &networkMsg{
		msg:               msg,
		optionalMsgFields: optionalMsgFields,
		isRemote:          false,
		source:            source,
		err:               make(chan error, 1),
	}

	select {
	case d.networkMsgs <- nMsg:
	case <-d.quit:
		nMsg.err <- ErrGossiperShuttingDown
	}

	return nMsg.err
}

// channelUpdateID is a unique identifier for ChannelUpdate messages, as
// channel updates can be identified by the (ShortChannelID, ChannelFlags)
// tuple.
type channelUpdateID struct {
	// channelID represents the set of data which is needed to
	// retrieve all necessary data to validate the channel existence.
	channelID lnwire.ShortChannelID

	// Flags least-significant bit must be set to 0 if the creating node
	// corresponds to the first node in the previously sent channel
	// announcement and 1 otherwise.
	flags lnwire.ChanUpdateChanFlags
}

// msgWithSenders is a wrapper struct around a message, and the set of peers
// that originally sent us this message. Using this struct, we can ensure that
// we don't re-send a message to the peer that sent it to us in the first
// place.
type msgWithSenders struct {
	// msg is the wire message itself.
	msg lnwire.Message

	// sender is the set of peers that sent us this message.
	senders map[route.Vertex]struct{}
}

// mergeSyncerMap is used to merge the set of senders of a particular message
// with peers that we have an active GossipSyncer with. We do this to ensure
// that we don't broadcast messages to any peers that we have active gossip
// syncers for.
func (m *msgWithSenders) mergeSyncerMap(syncers map[route.Vertex]*GossipSyncer) {
	for peerPub := range syncers {
		m.senders[peerPub] = struct{}{}
	}
}

// deDupedAnnouncements de-duplicates announcements that have been added to the
// batch. Internally, announcements are stored in three maps
// (one each for channel announcements, channel updates, and node
// announcements). These maps keep track of unique announcements and ensure no
// announcements are duplicated. We keep the three message types separate, such
// that we can send channel announcements first, then channel updates, and
// finally node announcements when it's time to broadcast them.
type deDupedAnnouncements struct {
	// channelAnnouncements are identified by the short channel id field.
	channelAnnouncements map[lnwire.ShortChannelID]msgWithSenders

	// channelUpdates are identified by the channel update id field.
	channelUpdates map[channelUpdateID]msgWithSenders

	// nodeAnnouncements are identified by the Vertex field.
	nodeAnnouncements map[route.Vertex]msgWithSenders

	sync.Mutex
}

// Reset operates on deDupedAnnouncements to reset the storage of
// announcements.
func (d *deDupedAnnouncements) Reset() {
	d.Lock()
	defer d.Unlock()

	d.reset()
}

// reset is the private version of the Reset method. We have this so we can
// call this method within method that are already holding the lock.
func (d *deDupedAnnouncements) reset() {
	// Storage of each type of announcement (channel announcements, channel
	// updates, node announcements) is set to an empty map where the
	// appropriate key points to the corresponding lnwire.Message.
	d.channelAnnouncements = make(map[lnwire.ShortChannelID]msgWithSenders)
	d.channelUpdates = make(map[channelUpdateID]msgWithSenders)
	d.nodeAnnouncements = make(map[route.Vertex]msgWithSenders)
}

// addMsg adds a new message to the current batch. If the message is already
// present in the current batch, then this new instance replaces the latter,
// and the set of senders is updated to reflect which node sent us this
// message.
func (d *deDupedAnnouncements) addMsg(message networkMsg) {
	// Depending on the message type (channel announcement, channel update,
	// or node announcement), the message is added to the corresponding map
	// in deDupedAnnouncements. Because each identifying key can have at
	// most one value, the announcements are de-duplicated, with newer ones
	// replacing older ones.
	switch msg := message.msg.(type) {

	// Channel announcements are identified by the short channel id field.
	case *lnwire.ChannelAnnouncement:
		deDupKey := msg.ShortChannelID
		sender := route.NewVertex(message.source)

		mws, ok := d.channelAnnouncements[deDupKey]
		if !ok {
			mws = msgWithSenders{
				msg:     msg,
				senders: make(map[route.Vertex]struct{}),
			}
			mws.senders[sender] = struct{}{}

			d.channelAnnouncements[deDupKey] = mws

			return
		}

		mws.msg = msg
		mws.senders[sender] = struct{}{}
		d.channelAnnouncements[deDupKey] = mws

	// Channel updates are identified by the (short channel id,
	// channelflags) tuple.
	case *lnwire.ChannelUpdate:
		sender := route.NewVertex(message.source)
		deDupKey := channelUpdateID{
			msg.ShortChannelID,
			msg.ChannelFlags,
		}

		oldTimestamp := uint32(0)
		mws, ok := d.channelUpdates[deDupKey]
		if ok {
			// If we already have seen this message, record its
			// timestamp.
			oldTimestamp = mws.msg.(*lnwire.ChannelUpdate).Timestamp
		}

		// If we already had this message with a strictly newer
		// timestamp, then we'll just discard the message we got.
		if oldTimestamp > msg.Timestamp {
			return
		}

		// If the message we just got is newer than what we previously
		// have seen, or this is the first time we see it, then we'll
		// add it to our map of announcements.
		if oldTimestamp < msg.Timestamp {
			mws = msgWithSenders{
				msg:     msg,
				senders: make(map[route.Vertex]struct{}),
			}

			// We'll mark the sender of the message in the
			// senders map.
			mws.senders[sender] = struct{}{}

			d.channelUpdates[deDupKey] = mws

			return
		}

		// Lastly, if we had seen this exact message from before, with
		// the same timestamp, we'll add the sender to the map of
		// senders, such that we can skip sending this message back in
		// the next batch.
		mws.msg = msg
		mws.senders[sender] = struct{}{}
		d.channelUpdates[deDupKey] = mws

	// Node announcements are identified by the Vertex field.  Use the
	// NodeID to create the corresponding Vertex.
	case *lnwire.NodeAnnouncement:
		sender := route.NewVertex(message.source)
		deDupKey := route.Vertex(msg.NodeID)

		// We do the same for node announcements as we did for channel
		// updates, as they also carry a timestamp.
		oldTimestamp := uint32(0)
		mws, ok := d.nodeAnnouncements[deDupKey]
		if ok {
			oldTimestamp = mws.msg.(*lnwire.NodeAnnouncement).Timestamp
		}

		// Discard the message if it's old.
		if oldTimestamp > msg.Timestamp {
			return
		}

		// Replace if it's newer.
		if oldTimestamp < msg.Timestamp {
			mws = msgWithSenders{
				msg:     msg,
				senders: make(map[route.Vertex]struct{}),
			}

			mws.senders[sender] = struct{}{}

			d.nodeAnnouncements[deDupKey] = mws

			return
		}

		// Add to senders map if it's the same as we had.
		mws.msg = msg
		mws.senders[sender] = struct{}{}
		d.nodeAnnouncements[deDupKey] = mws
	}
}

// AddMsgs is a helper method to add multiple messages to the announcement
// batch.
func (d *deDupedAnnouncements) AddMsgs(msgs ...networkMsg) {
	d.Lock()
	defer d.Unlock()

	for _, msg := range msgs {
		d.addMsg(msg)
	}
}

// Emit returns the set of de-duplicated announcements to be sent out during
// the next announcement epoch, in the order of channel announcements, channel
// updates, and node announcements. Each message emitted, contains the set of
// peers that sent us the message. This way, we can ensure that we don't waste
// bandwidth by re-sending a message to the peer that sent it to us in the
// first place. Additionally, the set of stored messages are reset.
func (d *deDupedAnnouncements) Emit() []msgWithSenders {
	d.Lock()
	defer d.Unlock()

	// Get the total number of announcements.
	numAnnouncements := len(d.channelAnnouncements) + len(d.channelUpdates) +
		len(d.nodeAnnouncements)

	// Create an empty array of lnwire.Messages with a length equal to
	// the total number of announcements.
	msgs := make([]msgWithSenders, 0, numAnnouncements)

	// Add the channel announcements to the array first.
	for _, message := range d.channelAnnouncements {
		msgs = append(msgs, message)
	}

	// Then add the channel updates.
	for _, message := range d.channelUpdates {
		msgs = append(msgs, message)
	}

	// Finally add the node announcements.
	for _, message := range d.nodeAnnouncements {
		msgs = append(msgs, message)
	}

	d.reset()

	// Return the array of lnwire.messages.
	return msgs
}

// calculateSubBatchSize is a helper function that calculates the size to break
// down the batchSize into.
func calculateSubBatchSize(totalDelay, subBatchDelay time.Duration,
	minimumBatchSize, batchSize int) int {
	if subBatchDelay > totalDelay {
		return batchSize
	}

	subBatchSize := (int(batchSize)*int(subBatchDelay) + int(totalDelay) - 1) /
		int(totalDelay)

	if subBatchSize < minimumBatchSize {
		return minimumBatchSize
	}

	return subBatchSize
}

// splitAnnouncementBatches takes an exiting list of announcements and
// decomposes it into sub batches controlled by the `subBatchSize`.
func splitAnnouncementBatches(subBatchSize int,
	announcementBatch []msgWithSenders) [][]msgWithSenders {
	var splitAnnouncementBatch [][]msgWithSenders

	for subBatchSize < len(announcementBatch) {
		// For slicing with minimal allocation
		// https://github.com/golang/go/wiki/SliceTricks
		announcementBatch, splitAnnouncementBatch =
			announcementBatch[subBatchSize:],
			append(splitAnnouncementBatch,
				announcementBatch[0:subBatchSize:subBatchSize])
	}
	splitAnnouncementBatch = append(splitAnnouncementBatch, announcementBatch)

	return splitAnnouncementBatch
}

// sendBatch broadcasts a list of announcements to our peers.
func (d *AuthenticatedGossiper) sendBatch(announcementBatch []msgWithSenders) {
	syncerPeers := d.syncMgr.GossipSyncers()

	// We'll first attempt to filter out this new message
	// for all peers that have active gossip syncers
	// active.
	for _, syncer := range syncerPeers {
		syncer.FilterGossipMsgs(announcementBatch...)
	}

	for _, msgChunk := range announcementBatch {
		// With the syncers taken care of, we'll merge
		// the sender map with the set of syncers, so
		// we don't send out duplicate messages.
		msgChunk.mergeSyncerMap(syncerPeers)

		err := d.cfg.Broadcast(
			msgChunk.senders, msgChunk.msg,
		)
		if err != nil {
			log.Errorf("Unable to send batch "+
				"announcements: %v", err)
			continue
		}
	}
}

// networkHandler is the primary goroutine that drives this service. The roles
// of this goroutine includes answering queries related to the state of the
// network, syncing up newly connected peers, and also periodically
// broadcasting our latest topology state to all connected peers.
//
// NOTE: This MUST be run as a goroutine.
func (d *AuthenticatedGossiper) networkHandler() {
	defer d.wg.Done()

	// Initialize empty deDupedAnnouncements to store announcement batch.
	announcements := deDupedAnnouncements{}
	announcements.Reset()

	d.cfg.RetransmitTicker.Resume()
	defer d.cfg.RetransmitTicker.Stop()

	trickleTimer := time.NewTicker(d.cfg.TrickleDelay)
	defer trickleTimer.Stop()

	// To start, we'll first check to see if there are any stale channel or
	// node announcements that we need to re-transmit.
	if err := d.retransmitStaleAnns(time.Now()); err != nil {
		log.Errorf("Unable to rebroadcast stale announcements: %v", err)
	}

	// We'll use this validation to ensure that we process jobs in their
	// dependency order during parallel validation.
	validationBarrier := routing.NewValidationBarrier(
		runtime.NumCPU()*4, d.quit,
	)

	for {
		select {
		// A new policy update has arrived. We'll commit it to the
		// sub-systems below us, then craft, sign, and broadcast a new
		// ChannelUpdate for the set of affected clients.
		case policyUpdate := <-d.chanPolicyUpdates:
			// First, we'll now create new fully signed updates for
			// the affected channels and also update the underlying
			// graph with the new state.
			newChanUpdates, err := d.processChanPolicyUpdate(
				policyUpdate.edgesToUpdate,
			)
			policyUpdate.errChan <- err
			if err != nil {
				log.Errorf("Unable to craft policy updates: %v",
					err)
				continue
			}

			// Finally, with the updates committed, we'll now add
			// them to the announcement batch to be flushed at the
			// start of the next epoch.
			announcements.AddMsgs(newChanUpdates...)

		case announcement := <-d.networkMsgs:
			// We should only broadcast this message forward if it
			// originated from us or it wasn't received as part of
			// our initial historical sync.
			shouldBroadcast := !announcement.isRemote ||
				d.syncMgr.IsGraphSynced()

			switch announcement.msg.(type) {
			// Channel announcement signatures are amongst the only
			// messages that we'll process serially.
			case *lnwire.AnnounceSignatures:
				emittedAnnouncements := d.processNetworkAnnouncement(
					announcement,
				)
				if emittedAnnouncements != nil {
					announcements.AddMsgs(
						emittedAnnouncements...,
					)
				}
				continue
			}

			// If this message was recently rejected, then we won't
			// attempt to re-process it.
			if d.isRecentlyRejectedMsg(announcement.msg) {
				announcement.err <- fmt.Errorf("recently " +
					"rejected")
				continue
			}

			// We'll set up any dependent, and wait until a free
			// slot for this job opens up, this allow us to not
			// have thousands of goroutines active.
			validationBarrier.InitJobDependencies(announcement.msg)

			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				defer validationBarrier.CompleteJob()

				// If this message has an existing dependency,
				// then we'll wait until that has been fully
				// validated before we proceed.
				err := validationBarrier.WaitForDependants(
					announcement.msg,
				)
				if err != nil {
					if err != routing.ErrVBarrierShuttingDown {
						log.Warnf("unexpected error "+
							"during validation "+
							"barrier shutdown: %v",
							err)
					}
					announcement.err <- err
					return
				}

				// Process the network announcement to
				// determine if this is either a new
				// announcement from our PoV or an edges to a
				// prior vertex/edge we previously proceeded.
				emittedAnnouncements := d.processNetworkAnnouncement(
					announcement,
				)

				// If this message had any dependencies, then
				// we can now signal them to continue.
				validationBarrier.SignalDependants(
					announcement.msg,
				)

				// If the announcement was accepted, then add
				// the emitted announcements to our announce
				// batch to be broadcast once the trickle timer
				// ticks gain.
				if emittedAnnouncements != nil && shouldBroadcast {
					// TODO(roasbeef): exclude peer that
					// sent.
					announcements.AddMsgs(
						emittedAnnouncements...,
					)
				} else if emittedAnnouncements != nil {
					log.Trace("Skipping broadcast of " +
						"announcements received " +
						"during initial graph sync")
				}

			}()

		// A new block has arrived, so we can re-process the previously
		// premature announcements.
		case newBlock, ok := <-d.blockEpochs.Epochs:
			// If the channel has been closed, then this indicates
			// the daemon is shutting down, so we exit ourselves.
			if !ok {
				return
			}

			// Once a new block arrives, we update our running
			// track of the height of the chain tip.
			d.Lock()
			blockHeight := uint32(newBlock.Height)
			d.bestHeight = blockHeight

			log.Debugf("New block: height=%d, hash=%s", blockHeight,
				newBlock.Hash)

			// Next we check if we have any premature announcements
			// for this height, if so, then we process them once
			// more as normal announcements.
			premature := d.prematureAnnouncements[blockHeight]
			if len(premature) == 0 {
				d.Unlock()
				continue
			}
			delete(d.prematureAnnouncements, blockHeight)
			d.Unlock()

			log.Infof("Re-processing %v premature announcements "+
				"for height %v", len(premature), blockHeight)

			for _, ann := range premature {
				emittedAnnouncements := d.processNetworkAnnouncement(ann)
				if emittedAnnouncements != nil {
					announcements.AddMsgs(
						emittedAnnouncements...,
					)
				}
			}

		// The trickle timer has ticked, which indicates we should
		// flush to the network the pending batch of new announcements
		// we've received since the last trickle tick.
		case <-trickleTimer.C:
			// Emit the current batch of announcements from
			// deDupedAnnouncements.
			announcementBatch := announcements.Emit()

			// If the current announcements batch is nil, then we
			// have no further work here.
			if len(announcementBatch) == 0 {
				continue
			}

			// Next, If we have new things to announce then
			// broadcast them to all our immediately connected
			// peers.
			subBatchSize := calculateSubBatchSize(
				d.cfg.TrickleDelay, d.cfg.SubBatchDelay, d.cfg.MinimumBatchSize,
				len(announcementBatch),
			)

			splitAnnouncementBatch := splitAnnouncementBatches(
				subBatchSize, announcementBatch,
			)

			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				log.Infof("Broadcasting %v new announcements in %d sub batches",
					len(announcementBatch), len(splitAnnouncementBatch))

				for _, announcementBatch := range splitAnnouncementBatch {
					d.sendBatch(announcementBatch)
					select {
					case <-time.After(d.cfg.SubBatchDelay):
					case <-d.quit:
						return
					}
				}
			}()

		// The retransmission timer has ticked which indicates that we
		// should check if we need to prune or re-broadcast any of our
		// personal channels or node announcement. This addresses the
		// case of "zombie" channels and channel advertisements that
		// have been dropped, or not properly propagated through the
		// network.
		case tick := <-d.cfg.RetransmitTicker.Ticks():
			if err := d.retransmitStaleAnns(tick); err != nil {
				log.Errorf("unable to rebroadcast stale "+
					"announcements: %v", err)
			}

		// The gossiper has been signalled to exit, to we exit our
		// main loop so the wait group can be decremented.
		case <-d.quit:
			return
		}
	}
}

// TODO(roasbeef): d/c peers that send updates not on our chain

// InitSyncState is called by outside sub-systems when a connection is
// established to a new peer that understands how to perform channel range
// queries. We'll allocate a new gossip syncer for it, and start any goroutines
// needed to handle new queries.
func (d *AuthenticatedGossiper) InitSyncState(syncPeer lnpeer.Peer) {
	d.syncMgr.InitSyncState(syncPeer)
}

// PruneSyncState is called by outside sub-systems once a peer that we were
// previously connected to has been disconnected. In this case we can stop the
// existing GossipSyncer assigned to the peer and free up resources.
func (d *AuthenticatedGossiper) PruneSyncState(peer route.Vertex) {
	d.syncMgr.PruneSyncState(peer)
}

// isRecentlyRejectedMsg returns true if we recently rejected a message, and
// false otherwise, This avoids expensive reprocessing of the message.
func (d *AuthenticatedGossiper) isRecentlyRejectedMsg(msg lnwire.Message) bool {
	d.rejectMtx.RLock()
	defer d.rejectMtx.RUnlock()

	switch m := msg.(type) {
	case *lnwire.ChannelUpdate:
		_, ok := d.recentRejects[m.ShortChannelID.ToUint64()]
		return ok

	case *lnwire.ChannelAnnouncement:
		_, ok := d.recentRejects[m.ShortChannelID.ToUint64()]
		return ok

	default:
		return false
	}
}

// retransmitStaleAnns examines all outgoing channels that the source node is
// known to maintain to check to see if any of them are "stale". A channel is
// stale iff, the last timestamp of its rebroadcast is older than the
// RebroadcastInterval. We also check if a refreshed node announcement should
// be resent.
func (d *AuthenticatedGossiper) retransmitStaleAnns(now time.Time) error {
	// Iterate over all of our channels and check if any of them fall
	// within the prune interval or re-broadcast interval.
	type updateTuple struct {
		info *channeldb.ChannelEdgeInfo
		edge *channeldb.ChannelEdgePolicy
	}

	var (
		havePublicChannels bool
		edgesToUpdate      []updateTuple
	)
	err := d.cfg.Router.ForAllOutgoingChannels(func(
		info *channeldb.ChannelEdgeInfo,
		edge *channeldb.ChannelEdgePolicy) error {

		// If there's no auth proof attached to this edge, it means
		// that it is a private channel not meant to be announced to
		// the greater network, so avoid sending channel updates for
		// this channel to not leak its
		// existence.
		if info.AuthProof == nil {
			log.Debugf("Skipping retransmission of channel "+
				"without AuthProof: %v", info.ChannelID)
			return nil
		}

		// We make a note that we have at least one public channel. We
		// use this to determine whether we should send a node
		// announcement below.
		havePublicChannels = true

		// If this edge has a ChannelUpdate that was created before the
		// introduction of the MaxHTLC field, then we'll update this
		// edge to propagate this information in the network.
		if !edge.MessageFlags.HasMaxHtlc() {
			// We'll make sure we support the new max_htlc field if
			// not already present.
			edge.MessageFlags |= lnwire.ChanUpdateOptionMaxHtlc
			edge.MaxHTLC = lnwire.NewMSatFromSatoshis(info.Capacity)

			edgesToUpdate = append(edgesToUpdate, updateTuple{
				info: info,
				edge: edge,
			})
			return nil
		}

		timeElapsed := now.Sub(edge.LastUpdate)

		// If it's been longer than RebroadcastInterval since we've
		// re-broadcasted the channel, add the channel to the set of
		// edges we need to update.
		if timeElapsed >= d.cfg.RebroadcastInterval {
			edgesToUpdate = append(edgesToUpdate, updateTuple{
				info: info,
				edge: edge,
			})
		}

		return nil
	})
	if err != nil && err != channeldb.ErrGraphNoEdgesFound {
		return fmt.Errorf("unable to retrieve outgoing channels: %v",
			err)
	}

	var signedUpdates []lnwire.Message
	for _, chanToUpdate := range edgesToUpdate {
		// Re-sign and update the channel on disk and retrieve our
		// ChannelUpdate to broadcast.
		chanAnn, chanUpdate, err := d.updateChannel(
			chanToUpdate.info, chanToUpdate.edge,
		)
		if err != nil {
			return fmt.Errorf("unable to update channel: %v", err)
		}

		// If we have a valid announcement to transmit, then we'll send
		// that along with the update.
		if chanAnn != nil {
			signedUpdates = append(signedUpdates, chanAnn)
		}

		signedUpdates = append(signedUpdates, chanUpdate)
	}

	// If we don't have any public channels, we return as we don't want to
	// broadcast anything that would reveal our existence.
	if !havePublicChannels {
		return nil
	}

	// We'll also check that our NodeAnnouncement is not too old.
	currentNodeAnn, err := d.cfg.SelfNodeAnnouncement(false)
	if err != nil {
		return fmt.Errorf("unable to get current node announment: %v",
			err)
	}

	timestamp := time.Unix(int64(currentNodeAnn.Timestamp), 0)
	timeElapsed := now.Sub(timestamp)

	// If it's been a full day since we've re-broadcasted the
	// node announcement, refresh it and resend it.
	nodeAnnStr := ""
	if timeElapsed >= d.cfg.RebroadcastInterval {
		newNodeAnn, err := d.cfg.SelfNodeAnnouncement(true)
		if err != nil {
			return fmt.Errorf("unable to get refreshed node "+
				"announcement: %v", err)
		}

		signedUpdates = append(signedUpdates, &newNodeAnn)
		nodeAnnStr = " and our refreshed node announcement"

		// Before broadcasting the refreshed node announcement, add it
		// to our own graph.
		if err := d.addNode(&newNodeAnn); err != nil {
			log.Errorf("Unable to add refreshed node announcement "+
				"to graph: %v", err)
		}
	}

	// If we don't have any updates to re-broadcast, then we'll exit
	// early.
	if len(signedUpdates) == 0 {
		return nil
	}

	log.Infof("Retransmitting %v outgoing channels%v",
		len(edgesToUpdate), nodeAnnStr)

	// With all the wire announcements properly crafted, we'll broadcast
	// our known outgoing channels to all our immediate peers.
	if err := d.cfg.Broadcast(nil, signedUpdates...); err != nil {
		return fmt.Errorf("unable to re-broadcast channels: %v", err)
	}

	return nil
}

// processChanPolicyUpdate generates a new set of channel updates for the
// provided list of edges and updates the backing ChannelGraphSource.
func (d *AuthenticatedGossiper) processChanPolicyUpdate(
	edgesToUpdate []EdgeWithInfo) ([]networkMsg, error) {

	var chanUpdates []networkMsg
	for _, edgeInfo := range edgesToUpdate {
		// Now that we've collected all the channels we need to update,
		// we'll re-sign and update the backing ChannelGraphSource, and
		// retrieve our ChannelUpdate to broadcast.
		_, chanUpdate, err := d.updateChannel(
			edgeInfo.Info, edgeInfo.Edge,
		)
		if err != nil {
			return nil, err
		}

		// We'll avoid broadcasting any updates for private channels to
		// avoid directly giving away their existence. Instead, we'll
		// send the update directly to the remote party.
		if edgeInfo.Info.AuthProof == nil {
			remotePubKey := remotePubFromChanInfo(
				edgeInfo.Info, chanUpdate.ChannelFlags,
			)
			err := d.reliableSender.sendMessage(
				chanUpdate, remotePubKey,
			)
			if err != nil {
				log.Errorf("Unable to reliably send %v for "+
					"channel=%v to peer=%x: %v",
					chanUpdate.MsgType(),
					chanUpdate.ShortChannelID,
					remotePubKey, err)
			}
			continue
		}

		// We set ourselves as the source of this message to indicate
		// that we shouldn't skip any peers when sending this message.
		chanUpdates = append(chanUpdates, networkMsg{
			source: d.selfKey,
			msg:    chanUpdate,
		})
	}

	return chanUpdates, nil
}

// remotePubFromChanInfo returns the public key of the remote peer given a
// ChannelEdgeInfo that describe a channel we have with them.
func remotePubFromChanInfo(chanInfo *channeldb.ChannelEdgeInfo,
	chanFlags lnwire.ChanUpdateChanFlags) [33]byte {

	var remotePubKey [33]byte
	switch {
	case chanFlags&lnwire.ChanUpdateDirection == 0:
		remotePubKey = chanInfo.NodeKey2Bytes
	case chanFlags&lnwire.ChanUpdateDirection == 1:
		remotePubKey = chanInfo.NodeKey1Bytes
	}

	return remotePubKey
}

// processRejectedEdge examines a rejected edge to see if we can extract any
// new announcements from it.  An edge will get rejected if we already added
// the same edge without AuthProof to the graph. If the received announcement
// contains a proof, we can add this proof to our edge.  We can end up in this
// situation in the case where we create a channel, but for some reason fail
// to receive the remote peer's proof, while the remote peer is able to fully
// assemble the proof and craft the ChannelAnnouncement.
func (d *AuthenticatedGossiper) processRejectedEdge(
	chanAnnMsg *lnwire.ChannelAnnouncement,
	proof *channeldb.ChannelAuthProof) ([]networkMsg, error) {

	// First, we'll fetch the state of the channel as we know if from the
	// database.
	chanInfo, e1, e2, err := d.cfg.Router.GetChannelByID(
		chanAnnMsg.ShortChannelID,
	)
	if err != nil {
		return nil, err
	}

	// The edge is in the graph, and has a proof attached, then we'll just
	// reject it as normal.
	if chanInfo.AuthProof != nil {
		return nil, nil
	}

	// Otherwise, this means that the edge is within the graph, but it
	// doesn't yet have a proper proof attached. If we did not receive
	// the proof such that we now can add it, there's nothing more we
	// can do.
	if proof == nil {
		return nil, nil
	}

	// We'll then create then validate the new fully assembled
	// announcement.
	chanAnn, e1Ann, e2Ann, err := netann.CreateChanAnnouncement(
		proof, chanInfo, e1, e2,
	)
	if err != nil {
		return nil, err
	}
	err = routing.ValidateChannelAnn(chanAnn)
	if err != nil {
		err := fmt.Errorf("assembled channel announcement proof "+
			"for shortChanID=%v isn't valid: %v",
			chanAnnMsg.ShortChannelID, err)
		log.Error(err)
		return nil, err
	}

	// If everything checks out, then we'll add the fully assembled proof
	// to the database.
	err = d.cfg.Router.AddProof(chanAnnMsg.ShortChannelID, proof)
	if err != nil {
		err := fmt.Errorf("unable add proof to shortChanID=%v: %v",
			chanAnnMsg.ShortChannelID, err)
		log.Error(err)
		return nil, err
	}

	// As we now have a complete channel announcement for this channel,
	// we'll construct the announcement so they can be broadcast out to all
	// our peers.
	announcements := make([]networkMsg, 0, 3)
	announcements = append(announcements, networkMsg{
		source: d.selfKey,
		msg:    chanAnn,
	})
	if e1Ann != nil {
		announcements = append(announcements, networkMsg{
			source: d.selfKey,
			msg:    e1Ann,
		})
	}
	if e2Ann != nil {
		announcements = append(announcements, networkMsg{
			source: d.selfKey,
			msg:    e2Ann,
		})

	}

	return announcements, nil
}

// addNode processes the given node announcement, and adds it to our channel
// graph.
func (d *AuthenticatedGossiper) addNode(msg *lnwire.NodeAnnouncement) error {
	if err := routing.ValidateNodeAnn(msg); err != nil {
		return fmt.Errorf("unable to validate node announcement: %v",
			err)
	}

	timestamp := time.Unix(int64(msg.Timestamp), 0)
	features := lnwire.NewFeatureVector(msg.Features, lnwire.Features)
	node := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           timestamp,
		Addresses:            msg.Addresses,
		PubKeyBytes:          msg.NodeID,
		Alias:                msg.Alias.String(),
		AuthSigBytes:         msg.Signature.ToSignatureBytes(),
		Features:             features,
		Color:                msg.RGBColor,
		ExtraOpaqueData:      msg.ExtraOpaqueData,
	}

	return d.cfg.Router.AddNode(node)
}

// processNetworkAnnouncement processes a new network relate authenticated
// channel or node announcement or announcements proofs. If the announcement
// didn't affect the internal state due to either being out of date, invalid,
// or redundant, then nil is returned. Otherwise, the set of announcements will
// be returned which should be broadcasted to the rest of the network.
func (d *AuthenticatedGossiper) processNetworkAnnouncement(
	nMsg *networkMsg) []networkMsg {

	// isPremature *MUST* be called with the gossiper's lock held.
	isPremature := func(chanID lnwire.ShortChannelID, delta uint32) bool {
		// TODO(roasbeef) make height delta 6
		//  * or configurable
		return chanID.BlockHeight+delta > d.bestHeight
	}

	var announcements []networkMsg

	switch msg := nMsg.msg.(type) {

	// A new node announcement has arrived which either presents new
	// information about a node in one of the channels we know about, or a
	// updating previously advertised information.
	case *lnwire.NodeAnnouncement:
		timestamp := time.Unix(int64(msg.Timestamp), 0)

		// We'll quickly ask the router if it already has a
		// newer update for this node so we can skip validating
		// signatures if not required.
		if d.cfg.Router.IsStaleNode(msg.NodeID, timestamp) {
			nMsg.err <- nil
			return nil
		}

		if err := d.addNode(msg); err != nil {
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {

				log.Debug(err)
			} else {
				log.Error(err)
			}

			nMsg.err <- err
			return nil
		}

		// In order to ensure we don't leak unadvertised nodes, we'll
		// make a quick check to ensure this node intends to publicly
		// advertise itself to the network.
		isPublic, err := d.cfg.Router.IsPublicNode(msg.NodeID)
		if err != nil {
			log.Errorf("Unable to determine if node %x is "+
				"advertised: %v", msg.NodeID, err)
			nMsg.err <- err
			return nil
		}

		// If it does, we'll add their announcement to our batch so that
		// it can be broadcast to the rest of our peers.
		if isPublic {
			announcements = append(announcements, networkMsg{
				peer:   nMsg.peer,
				source: nMsg.source,
				msg:    msg,
			})
		} else {
			log.Tracef("Skipping broadcasting node announcement "+
				"for %x due to being unadvertised", msg.NodeID)
		}

		nMsg.err <- nil
		// TODO(roasbeef): get rid of the above
		return announcements

	// A new channel announcement has arrived, this indicates the
	// *creation* of a new channel within the network. This only advertises
	// the existence of a channel and not yet the routing policies in
	// either direction of the channel.
	case *lnwire.ChannelAnnouncement:
		// We'll ignore any channel announcements that target any chain
		// other than the set of chains we know of.
		if !bytes.Equal(msg.ChainHash[:], d.cfg.ChainHash[:]) {
			err := fmt.Errorf("ignoring ChannelAnnouncement from "+
				"chain=%v, gossiper on chain=%v", msg.ChainHash,
				d.cfg.ChainHash)
			log.Errorf(err.Error())

			d.rejectMtx.Lock()
			d.recentRejects[msg.ShortChannelID.ToUint64()] = struct{}{}
			d.rejectMtx.Unlock()

			nMsg.err <- err
			return nil
		}

		// If the advertised inclusionary block is beyond our knowledge
		// of the chain tip, then we'll put the announcement in limbo
		// to be fully verified once we advance forward in the chain.
		d.Lock()
		if nMsg.isRemote && !msg.ShortChannelID.IsFake() && isPremature(msg.ShortChannelID, 0) {
			blockHeight := msg.ShortChannelID.BlockHeight
			log.Infof("Announcement for chan_id=(%v), is "+
				"premature: advertises height %v, only "+
				"height %v is known",
				msg.ShortChannelID.ToUint64(),
				msg.ShortChannelID.BlockHeight,
				d.bestHeight)

			d.prematureAnnouncements[blockHeight] = append(
				d.prematureAnnouncements[blockHeight],
				nMsg,
			)
			d.Unlock()
			return nil
		}
		d.Unlock()

		// At this point, we'll now ask the router if this is a
		// zombie/known edge. If so we can skip all the processing
		// below.
		if d.cfg.Router.IsKnownEdge(msg.ShortChannelID) {
			nMsg.err <- nil
			return nil
		}

		// If this is a remote channel announcement, then we'll validate
		// all the signatures within the proof as it should be well
		// formed.
		var proof *channeldb.ChannelAuthProof
		if nMsg.isRemote {
			if err := routing.ValidateChannelAnn(msg); err != nil {
				err := fmt.Errorf("unable to validate "+
					"announcement: %v", err)
				d.rejectMtx.Lock()
				d.recentRejects[msg.ShortChannelID.ToUint64()] = struct{}{}
				d.rejectMtx.Unlock()

				log.Error(err)
				nMsg.err <- err
				return nil
			}

			// If the proof checks out, then we'll save the proof
			// itself to the database so we can fetch it later when
			// gossiping with other nodes.
			proof = &channeldb.ChannelAuthProof{
				NodeSig1Bytes:    msg.NodeSig1.ToSignatureBytes(),
				NodeSig2Bytes:    msg.NodeSig2.ToSignatureBytes(),
				BitcoinSig1Bytes: msg.BitcoinSig1.ToSignatureBytes(),
				BitcoinSig2Bytes: msg.BitcoinSig2.ToSignatureBytes(),
			}
		}

		// With the proof validate (if necessary), we can now store it
		// within the database for our path finding and syncing needs.
		var featureBuf bytes.Buffer
		if err := msg.Features.Encode(&featureBuf); err != nil {
			log.Errorf("unable to encode features: %v", err)
			nMsg.err <- err
			return nil
		}

		edge := &channeldb.ChannelEdgeInfo{
			ChannelID:        msg.ShortChannelID.ToUint64(),
			ChainHash:        msg.ChainHash,
			NodeKey1Bytes:    msg.NodeID1,
			NodeKey2Bytes:    msg.NodeID2,
			BitcoinKey1Bytes: msg.BitcoinKey1,
			BitcoinKey2Bytes: msg.BitcoinKey2,
			AuthProof:        proof,
			Features:         featureBuf.Bytes(),
			ExtraOpaqueData:  msg.ExtraOpaqueData,
		}

		// If there were any optional message fields provided, we'll
		// include them in its serialized disk representation now.
		if nMsg.optionalMsgFields != nil {
			if nMsg.optionalMsgFields.capacity != nil {
				edge.Capacity = *nMsg.optionalMsgFields.capacity
			}
			if nMsg.optionalMsgFields.channelPoint != nil {
				edge.ChannelPoint = *nMsg.optionalMsgFields.channelPoint
			}
		}

		// We will add the edge to the channel router. If the nodes
		// present in this channel are not present in the database, a
		// partial node will be added to represent each node while we
		// wait for a node announcement.
		//
		// Before we add the edge to the database, we obtain
		// the mutex for this channel ID. We do this to ensure
		// no other goroutine has read the database and is now
		// making decisions based on this DB state, before it
		// writes to the DB.
		d.channelMtx.Lock(msg.ShortChannelID.ToUint64())
		defer d.channelMtx.Unlock(msg.ShortChannelID.ToUint64())
		if err := d.cfg.Router.AddEdge(edge); err != nil {
			// If the edge was rejected due to already being known,
			// then it may be that case that this new message has a
			// fresh channel proof, so we'll check.
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {

				// Attempt to process the rejected message to
				// see if we get any new announcements.
				anns, rErr := d.processRejectedEdge(msg, proof)
				if rErr != nil {
					d.rejectMtx.Lock()
					d.recentRejects[msg.ShortChannelID.ToUint64()] = struct{}{}
					d.rejectMtx.Unlock()
					nMsg.err <- rErr
					return nil
				}

				// If while processing this rejected edge, we
				// realized there's a set of announcements we
				// could extract, then we'll return those
				// directly.
				if len(anns) != 0 {
					nMsg.err <- nil
					return anns
				}

				// Otherwise, this is just a regular rejected
				// edge.
				log.Debugf("Router rejected channel "+
					"edge: %v", err)
			} else {
				log.Tracef("Router rejected channel "+
					"edge: %v", err)
			}

			nMsg.err <- err
			return nil
		}

		// If we earlier received any ChannelUpdates for this channel,
		// we can now process them, as the channel is added to the
		// graph.
		shortChanID := msg.ShortChannelID.ToUint64()
		var channelUpdates []*networkMsg

		d.pChanUpdMtx.Lock()
		channelUpdates = append(channelUpdates, d.prematureChannelUpdates[shortChanID]...)

		// Now delete the premature ChannelUpdates, since we added them
		// all to the queue of network messages.
		delete(d.prematureChannelUpdates, shortChanID)
		d.pChanUpdMtx.Unlock()

		// Launch a new goroutine to handle each ChannelUpdate, this to
		// ensure we don't block here, as we can handle only one
		// announcement at a time.
		for _, cu := range channelUpdates {
			d.wg.Add(1)
			go func(nMsg *networkMsg) {
				defer d.wg.Done()

				switch msg := nMsg.msg.(type) {

				// Reprocess the message, making sure we return
				// an error to the original caller in case the
				// gossiper shuts down.
				case *lnwire.ChannelUpdate:
					log.Debugf("Reprocessing"+
						" ChannelUpdate for "+
						"shortChanID=%v",
						msg.ShortChannelID.ToUint64())

					select {
					case d.networkMsgs <- nMsg:
					case <-d.quit:
						nMsg.err <- ErrGossiperShuttingDown
					}

				// We don't expect any other message type than
				// ChannelUpdate to be in this map.
				default:
					log.Errorf("Unsupported message type "+
						"found among ChannelUpdates: "+
						"%T", msg)
				}
			}(cu)
		}

		// Channel announcement was successfully proceeded and know it
		// might be broadcast to other connected nodes if it was
		// announcement with proof (remote).
		if proof != nil {
			announcements = append(announcements, networkMsg{
				peer:   nMsg.peer,
				source: nMsg.source,
				msg:    msg,
			})
		}

		nMsg.err <- nil
		return announcements

	// A new authenticated channel edge update has arrived. This indicates
	// that the directional information for an already known channel has
	// been updated.
	case *lnwire.ChannelUpdate:
		// We'll ignore any channel announcements that target any chain
		// other than the set of chains we know of.
		if !bytes.Equal(msg.ChainHash[:], d.cfg.ChainHash[:]) {
			err := fmt.Errorf("ignoring ChannelUpdate from "+
				"chain=%v, gossiper on chain=%v", msg.ChainHash,
				d.cfg.ChainHash)
			log.Errorf(err.Error())

			d.rejectMtx.Lock()
			d.recentRejects[msg.ShortChannelID.ToUint64()] = struct{}{}
			d.rejectMtx.Unlock()

			nMsg.err <- err
			return nil
		}

		blockHeight := msg.ShortChannelID.BlockHeight
		shortChanID := msg.ShortChannelID.ToUint64()

		// If the advertised inclusionary block is beyond our knowledge
		// of the chain tip, then we'll put the announcement in limbo
		// to be fully verified once we advance forward in the chain.
		d.Lock()
		if nMsg.isRemote && !msg.ShortChannelID.IsFake() && isPremature(msg.ShortChannelID, 0) {
			log.Infof("Update announcement for "+
				"short_chan_id(%v), is premature: advertises "+
				"height %v, only height %v is known",
				shortChanID, blockHeight,
				d.bestHeight)

			d.prematureAnnouncements[blockHeight] = append(
				d.prematureAnnouncements[blockHeight],
				nMsg,
			)
			d.Unlock()
			return nil
		}
		d.Unlock()

		// Before we perform any of the expensive checks below, we'll
		// check whether this update is stale or is for a zombie
		// channel in order to quickly reject it.
		timestamp := time.Unix(int64(msg.Timestamp), 0)
		if d.cfg.Router.IsStaleEdgePolicy(
			msg.ShortChannelID, timestamp, msg.ChannelFlags,
		) {
			nMsg.err <- nil
			return nil
		}

		// Get the node pub key as far as we don't have it in channel
		// update announcement message. We'll need this to properly
		// verify message signature.
		//
		// We make sure to obtain the mutex for this channel ID
		// before we access the database. This ensures the state
		// we read from the database has not changed between this
		// point and when we call UpdateEdge() later.
		d.channelMtx.Lock(msg.ShortChannelID.ToUint64())
		defer d.channelMtx.Unlock(msg.ShortChannelID.ToUint64())
		chanInfo, _, _, err := d.cfg.Router.GetChannelByID(msg.ShortChannelID)
		switch err {
		// No error, break.
		case nil:
			break

		case channeldb.ErrZombieEdge:
			// Since we've deemed the update as not stale above,
			// before marking it live, we'll make sure it has been
			// signed by the correct party. The least-significant
			// bit in the flag on the channel update tells us which
			// edge is being updated.
			var pubKey *btcec.PublicKey
			switch {
			case msg.ChannelFlags&lnwire.ChanUpdateDirection == 0:
				pubKey, _ = chanInfo.NodeKey1()
			case msg.ChannelFlags&lnwire.ChanUpdateDirection == 1:
				pubKey, _ = chanInfo.NodeKey2()
			}

			err := routing.VerifyChannelUpdateSignature(msg, pubKey)
			if err != nil {
				err := fmt.Errorf("unable to verify channel "+
					"update signature: %v", err)
				log.Error(err)
				nMsg.err <- err
				return nil
			}

			// With the signature valid, we'll proceed to mark the
			// edge as live and wait for the channel announcement to
			// come through again.
			err = d.cfg.Router.MarkEdgeLive(msg.ShortChannelID)
			if err != nil {
				err := fmt.Errorf("unable to remove edge with "+
					"chan_id=%v from zombie index: %v",
					msg.ShortChannelID, err)
				log.Error(err)
				nMsg.err <- err
				return nil
			}

			log.Debugf("Removed edge with chan_id=%v from zombie "+
				"index", msg.ShortChannelID)

			// We'll fallthrough to ensure we stash the update until
			// we receive its corresponding ChannelAnnouncement.
			// This is needed to ensure the edge exists in the graph
			// before applying the update.
			fallthrough
		case channeldb.ErrGraphNotFound:
			fallthrough
		case channeldb.ErrGraphNoEdgesFound:
			fallthrough
		case channeldb.ErrEdgeNotFound:
			// If the edge corresponding to this ChannelUpdate was
			// not found in the graph, this might be a channel in
			// the process of being opened, and we haven't processed
			// our own ChannelAnnouncement yet, hence it is not
			// found in the graph. This usually gets resolved after
			// the channel proofs are exchanged and the channel is
			// broadcasted to the rest of the network, but in case
			// this is a private channel this won't ever happen.
			// This can also happen in the case of a zombie channel
			// with a fresh update for which we don't have a
			// ChannelAnnouncement for since we reject them. Because
			// of this, we temporarily add it to a map, and
			// reprocess it after our own ChannelAnnouncement has
			// been processed.
			d.pChanUpdMtx.Lock()
			d.prematureChannelUpdates[shortChanID] = append(
				d.prematureChannelUpdates[shortChanID], nMsg,
			)
			d.pChanUpdMtx.Unlock()

			log.Debugf("Got ChannelUpdate for edge not found in "+
				"graph(shortChanID=%v), saving for "+
				"reprocessing later", shortChanID)

			// NOTE: We don't return anything on the error channel
			// for this message, as we expect that will be done when
			// this ChannelUpdate is later reprocessed.
			return nil

		default:
			err := fmt.Errorf("unable to validate channel update "+
				"short_chan_id=%v: %v", shortChanID, err)
			log.Error(err)
			nMsg.err <- err

			d.rejectMtx.Lock()
			d.recentRejects[msg.ShortChannelID.ToUint64()] = struct{}{}
			d.rejectMtx.Unlock()
			return nil
		}

		// The least-significant bit in the flag on the channel update
		// announcement tells us "which" side of the channels directed
		// edge is being updated.
		var pubKey *btcec.PublicKey
		switch {
		case msg.ChannelFlags&lnwire.ChanUpdateDirection == 0:
			pubKey, _ = chanInfo.NodeKey1()
		case msg.ChannelFlags&lnwire.ChanUpdateDirection == 1:
			pubKey, _ = chanInfo.NodeKey2()
		}

		// Validate the channel announcement with the expected public key and
		// channel capacity. In the case of an invalid channel update, we'll
		// return an error to the caller and exit early.
		err = routing.ValidateChannelUpdateAnn(pubKey, chanInfo.Capacity, msg)
		if err != nil {
			rErr := fmt.Errorf("unable to validate channel "+
				"update announcement for short_chan_id=%v: %v",
				spew.Sdump(msg.ShortChannelID), err)

			log.Error(rErr)
			nMsg.err <- rErr
			return nil
		}

		update := &channeldb.ChannelEdgePolicy{
			SigBytes:                  msg.Signature.ToSignatureBytes(),
			ChannelID:                 shortChanID,
			LastUpdate:                timestamp,
			MessageFlags:              msg.MessageFlags,
			ChannelFlags:              msg.ChannelFlags,
			TimeLockDelta:             msg.TimeLockDelta,
			MinHTLC:                   msg.HtlcMinimumMsat,
			MaxHTLC:                   msg.HtlcMaximumMsat,
			FeeBaseMSat:               lnwire.MilliSatoshi(msg.BaseFee),
			FeeProportionalMillionths: lnwire.MilliSatoshi(msg.FeeRate),
			ExtraOpaqueData:           msg.ExtraOpaqueData,
		}

		if err := d.cfg.Router.UpdateEdge(update); err != nil {
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {
				log.Debug(err)
			} else {
				d.rejectMtx.Lock()
				d.recentRejects[msg.ShortChannelID.ToUint64()] = struct{}{}
				d.rejectMtx.Unlock()
				log.Error(err)
			}

			nMsg.err <- err
			return nil
		}

		// If this is a local ChannelUpdate without an AuthProof, it
		// means it is an update to a channel that is not (yet)
		// supposed to be announced to the greater network. However,
		// our channel counter party will need to be given the update,
		// so we'll try sending the update directly to the remote peer.
		if !nMsg.isRemote && chanInfo.AuthProof == nil {
			// Get our peer's public key.
			remotePubKey := remotePubFromChanInfo(
				chanInfo, msg.ChannelFlags,
			)

			// Now, we'll attempt to send the channel update message
			// reliably to the remote peer in the background, so
			// that we don't block if the peer happens to be offline
			// at the moment.
			err := d.reliableSender.sendMessage(msg, remotePubKey)
			if err != nil {
				err := fmt.Errorf("unable to reliably send %v "+
					"for channel=%v to peer=%x: %v",
					msg.MsgType(), msg.ShortChannelID,
					remotePubKey, err)
				nMsg.err <- err
				return nil
			}
		}

		// Channel update announcement was successfully processed and
		// now it can be broadcast to the rest of the network. However,
		// we'll only broadcast the channel update announcement if it
		// has an attached authentication proof.
		if chanInfo.AuthProof != nil {
			announcements = append(announcements, networkMsg{
				peer:   nMsg.peer,
				source: nMsg.source,
				msg:    msg,
			})
		}

		nMsg.err <- nil
		return announcements

	// A new signature announcement has been received. This indicates
	// willingness of nodes involved in the funding of a channel to
	// announce this new channel to the rest of the world.
	case *lnwire.AnnounceSignatures:
		needBlockHeight := msg.ShortChannelID.BlockHeight +
			d.cfg.ProofMatureDelta
		shortChanID := msg.ShortChannelID.ToUint64()

		prefix := "local"
		if nMsg.isRemote {
			prefix = "remote"
		}

		log.Infof("Received new %v channel announcement for %v", prefix,
			msg.ShortChannelID)

		// By the specification, channel announcement proofs should be
		// sent after some number of confirmations after channel was
		// registered in bitcoin blockchain. Therefore, we check if the
		// proof is premature.  If so we'll halt processing until the
		// expected announcement height.  This allows us to be tolerant
		// to other clients if this constraint was changed.
		d.Lock()
		if isPremature(msg.ShortChannelID, d.cfg.ProofMatureDelta) {
			d.prematureAnnouncements[needBlockHeight] = append(
				d.prematureAnnouncements[needBlockHeight],
				nMsg,
			)
			log.Infof("Premature proof announcement, "+
				"current block height lower than needed: %v <"+
				" %v, add announcement to reprocessing batch",
				d.bestHeight, needBlockHeight)
			d.Unlock()
			return nil
		}
		d.Unlock()

		// Ensure that we know of a channel with the target channel ID
		// before proceeding further.
		//
		// We must acquire the mutex for this channel ID before getting
		// the channel from the database, to ensure what we read does
		// not change before we call AddProof() later.
		d.channelMtx.Lock(msg.ShortChannelID.ToUint64())
		defer d.channelMtx.Unlock(msg.ShortChannelID.ToUint64())

		chanInfo, e1, e2, err := d.cfg.Router.GetChannelByID(
			msg.ShortChannelID)
		if err != nil {
			// TODO(andrew.shvv) this is dangerous because remote
			// node might rewrite the waiting proof.
			proof := channeldb.NewWaitingProof(nMsg.isRemote, msg)
			err := d.cfg.WaitingProofStore.Add(proof)
			if err != nil {
				err := fmt.Errorf("unable to store "+
					"the proof for short_chan_id=%v: %v",
					shortChanID, err)
				log.Error(err)
				nMsg.err <- err
				return nil
			}

			log.Infof("Orphan %v proof announcement with "+
				"short_chan_id=%v, adding "+
				"to waiting batch", prefix, shortChanID)
			nMsg.err <- nil
			return nil
		}

		nodeID := nMsg.source.SerializeCompressed()
		isFirstNode := bytes.Equal(nodeID, chanInfo.NodeKey1Bytes[:])
		isSecondNode := bytes.Equal(nodeID, chanInfo.NodeKey2Bytes[:])

		// Ensure that channel that was retrieved belongs to the peer
		// which sent the proof announcement.
		if !(isFirstNode || isSecondNode) {
			err := fmt.Errorf("channel that was received not "+
				"belongs to the peer which sent the proof, "+
				"short_chan_id=%v", shortChanID)
			log.Error(err)
			nMsg.err <- err
			return nil
		}

		// If proof was sent by a local sub-system, then we'll
		// send the announcement signature to the remote node
		// so they can also reconstruct the full channel
		// announcement.
		if !nMsg.isRemote {
			var remotePubKey [33]byte
			if isFirstNode {
				remotePubKey = chanInfo.NodeKey2Bytes
			} else {
				remotePubKey = chanInfo.NodeKey1Bytes
			}
			// Since the remote peer might not be online
			// we'll call a method that will attempt to
			// deliver the proof when it comes online.
			err := d.reliableSender.sendMessage(msg, remotePubKey)
			if err != nil {
				err := fmt.Errorf("unable to reliably send %v "+
					"for channel=%v to peer=%x: %v",
					msg.MsgType(), msg.ShortChannelID,
					remotePubKey, err)
				nMsg.err <- err
				return nil
			}
		}

		// Check if we already have the full proof for this channel.
		if chanInfo.AuthProof != nil {
			// If we already have the fully assembled proof, then
			// the peer sending us their proof has probably not
			// received our local proof yet. So be kind and send
			// them the full proof.
			if nMsg.isRemote {
				peerID := nMsg.source.SerializeCompressed()
				log.Debugf("Got AnnounceSignatures for " +
					"channel with full proof.")

				d.wg.Add(1)
				go func() {
					defer d.wg.Done()
					log.Debugf("Received half proof for "+
						"channel %v with existing "+
						"full proof. Sending full "+
						"proof to peer=%x",
						msg.ChannelID,
						peerID)

					chanAnn, _, _, err := netann.CreateChanAnnouncement(
						chanInfo.AuthProof, chanInfo,
						e1, e2,
					)
					if err != nil {
						log.Errorf("unable to gen "+
							"ann: %v", err)
						return
					}
					err = nMsg.peer.SendMessage(
						false, chanAnn,
					)
					if err != nil {
						log.Errorf("Failed sending "+
							"full proof to "+
							"peer=%x: %v",
							peerID, err)
						return
					}
					log.Debugf("Full proof sent to peer=%x"+
						" for chanID=%v", peerID,
						msg.ChannelID)
				}()
			}

			log.Debugf("Already have proof for channel "+
				"with chanID=%v", msg.ChannelID)
			nMsg.err <- nil
			return nil
		}

		// Check that we received the opposite proof. If so, then we're
		// now able to construct the full proof, and create the channel
		// announcement. If we didn't receive the opposite half of the
		// proof than we should store it this one, and wait for
		// opposite to be received.
		proof := channeldb.NewWaitingProof(nMsg.isRemote, msg)
		oppositeProof, err := d.cfg.WaitingProofStore.Get(
			proof.OppositeKey(),
		)
		if err != nil && err != channeldb.ErrWaitingProofNotFound {
			err := fmt.Errorf("unable to get "+
				"the opposite proof for short_chan_id=%v: %v",
				shortChanID, err)
			log.Error(err)
			nMsg.err <- err
			return nil
		}

		if err == channeldb.ErrWaitingProofNotFound {
			err := d.cfg.WaitingProofStore.Add(proof)
			if err != nil {
				err := fmt.Errorf("unable to store "+
					"the proof for short_chan_id=%v: %v",
					shortChanID, err)
				log.Error(err)
				nMsg.err <- err
				return nil
			}

			log.Infof("1/2 of channel ann proof received for "+
				"short_chan_id=%v, waiting for other half",
				shortChanID)

			nMsg.err <- nil
			return nil
		}

		// We now have both halves of the channel announcement proof,
		// then we'll reconstruct the initial announcement so we can
		// validate it shortly below.
		var dbProof channeldb.ChannelAuthProof
		if isFirstNode {
			dbProof.NodeSig1Bytes = msg.NodeSignature.ToSignatureBytes()
			dbProof.NodeSig2Bytes = oppositeProof.NodeSignature.ToSignatureBytes()
			dbProof.BitcoinSig1Bytes = msg.BitcoinSignature.ToSignatureBytes()
			dbProof.BitcoinSig2Bytes = oppositeProof.BitcoinSignature.ToSignatureBytes()
		} else {
			dbProof.NodeSig1Bytes = oppositeProof.NodeSignature.ToSignatureBytes()
			dbProof.NodeSig2Bytes = msg.NodeSignature.ToSignatureBytes()
			dbProof.BitcoinSig1Bytes = oppositeProof.BitcoinSignature.ToSignatureBytes()
			dbProof.BitcoinSig2Bytes = msg.BitcoinSignature.ToSignatureBytes()
		}
		chanAnn, e1Ann, e2Ann, err := netann.CreateChanAnnouncement(
			&dbProof, chanInfo, e1, e2,
		)
		if err != nil {
			log.Error(err)
			nMsg.err <- err
			return nil
		}

		// With all the necessary components assembled validate the
		// full channel announcement proof.
		if err := routing.ValidateChannelAnn(chanAnn); err != nil {
			err := fmt.Errorf("channel  announcement proof "+
				"for short_chan_id=%v isn't valid: %v",
				shortChanID, err)

			log.Error(err)
			nMsg.err <- err
			return nil
		}

		// If the channel was returned by the router it means that
		// existence of funding point and inclusion of nodes bitcoin
		// keys in it already checked by the router. In this stage we
		// should check that node keys are attest to the bitcoin keys
		// by validating the signatures of announcement.  If proof is
		// valid then we'll populate the channel edge with it, so we
		// can announce it on peer connect.
		err = d.cfg.Router.AddProof(msg.ShortChannelID, &dbProof)
		if err != nil {
			err := fmt.Errorf("unable add proof to the "+
				"channel chanID=%v: %v", msg.ChannelID, err)
			log.Error(err)
			nMsg.err <- err
			return nil
		}

		err = d.cfg.WaitingProofStore.Remove(proof.OppositeKey())
		if err != nil {
			err := fmt.Errorf("unable remove opposite proof "+
				"for the channel with chanID=%v: %v",
				msg.ChannelID, err)
			log.Error(err)
			nMsg.err <- err
			return nil
		}

		// Proof was successfully created and now can announce the
		// channel to the remain network.
		log.Infof("Fully valid channel proof for short_chan_id=%v "+
			"constructed, adding to next ann batch",
			shortChanID)

		// Assemble the necessary announcements to add to the next
		// broadcasting batch.
		announcements = append(announcements, networkMsg{
			peer:   nMsg.peer,
			source: nMsg.source,
			msg:    chanAnn,
		})
		if e1Ann != nil {
			announcements = append(announcements, networkMsg{
				peer:   nMsg.peer,
				source: nMsg.source,
				msg:    e1Ann,
			})
		}
		if e2Ann != nil {
			announcements = append(announcements, networkMsg{
				peer:   nMsg.peer,
				source: nMsg.source,
				msg:    e2Ann,
			})
		}

		// We'll also send along the node announcements for each channel
		// participant if we know of them. To ensure our node
		// announcement propagates to our channel counterparty, we'll
		// set the source for each announcement to the node it belongs
		// to, otherwise we won't send it since the source gets skipped.
		// This isn't necessary for channel updates and announcement
		// signatures since we send those directly to our channel
		// counterparty through the gossiper's reliable sender.
		node1Ann, err := d.fetchNodeAnn(chanInfo.NodeKey1Bytes)
		if err != nil {
			log.Debugf("Unable to fetch node announcement for "+
				"%x: %v", chanInfo.NodeKey1Bytes, err)
		} else {
			if nodeKey1, err := chanInfo.NodeKey1(); err == nil {
				announcements = append(announcements, networkMsg{
					peer:   nMsg.peer,
					source: nodeKey1,
					msg:    node1Ann,
				})
			}
		}
		node2Ann, err := d.fetchNodeAnn(chanInfo.NodeKey2Bytes)
		if err != nil {
			log.Debugf("Unable to fetch node announcement for "+
				"%x: %v", chanInfo.NodeKey2Bytes, err)
		} else {
			if nodeKey2, err := chanInfo.NodeKey2(); err == nil {
				announcements = append(announcements, networkMsg{
					peer:   nMsg.peer,
					source: nodeKey2,
					msg:    node2Ann,
				})
			}
		}

		nMsg.err <- nil
		return announcements

	default:
		nMsg.err <- errors.New("wrong type of the announcement")
		return nil
	}
}

// fetchNodeAnn fetches the latest signed node announcement from our point of
// view for the node with the given public key.
func (d *AuthenticatedGossiper) fetchNodeAnn(
	pubKey [33]byte) (*lnwire.NodeAnnouncement, error) {

	node, err := d.cfg.Router.FetchLightningNode(pubKey)
	if err != nil {
		return nil, err
	}

	return node.NodeAnnouncement(true)
}

// isMsgStale determines whether a message retrieved from the backing
// MessageStore is seen as stale by the current graph.
func (d *AuthenticatedGossiper) isMsgStale(msg lnwire.Message) bool {
	switch msg := msg.(type) {
	case *lnwire.AnnounceSignatures:
		chanInfo, _, _, err := d.cfg.Router.GetChannelByID(
			msg.ShortChannelID,
		)

		// If the channel cannot be found, it is most likely a leftover
		// message for a channel that was closed, so we can consider it
		// stale.
		if err == channeldb.ErrEdgeNotFound {
			return true
		}
		if err != nil {
			log.Debugf("Unable to retrieve channel=%v from graph: "+
				"%v", err)
			return false
		}

		// If the proof exists in the graph, then we have successfully
		// received the remote proof and assembled the full proof, so we
		// can safely delete the local proof from the database.
		return chanInfo.AuthProof != nil

	case *lnwire.ChannelUpdate:
		_, p1, p2, err := d.cfg.Router.GetChannelByID(msg.ShortChannelID)

		// If the channel cannot be found, it is most likely a leftover
		// message for a channel that was closed, so we can consider it
		// stale.
		if err == channeldb.ErrEdgeNotFound {
			return true
		}
		if err != nil {
			log.Debugf("Unable to retrieve channel=%v from graph: "+
				"%v", msg.ShortChannelID, err)
			return false
		}

		// Otherwise, we'll retrieve the correct policy that we
		// currently have stored within our graph to check if this
		// message is stale by comparing its timestamp.
		var p *channeldb.ChannelEdgePolicy
		if msg.ChannelFlags&lnwire.ChanUpdateDirection == 0 {
			p = p1
		} else {
			p = p2
		}

		// If the policy is still unknown, then we can consider this
		// policy fresh.
		if p == nil {
			return false
		}

		timestamp := time.Unix(int64(msg.Timestamp), 0)
		return p.LastUpdate.After(timestamp)

	default:
		// We'll make sure to not mark any unsupported messages as stale
		// to ensure they are not removed.
		return false
	}
}

// updateChannel creates a new fully signed update for the channel, and updates
// the underlying graph with the new state.
func (d *AuthenticatedGossiper) updateChannel(info *channeldb.ChannelEdgeInfo,
	edge *channeldb.ChannelEdgePolicy) (*lnwire.ChannelAnnouncement,
	*lnwire.ChannelUpdate, error) {

	// Parse the unsigned edge into a channel update.
	chanUpdate := netann.UnsignedChannelUpdateFromEdge(info, edge)

	// We'll generate a new signature over a digest of the channel
	// announcement itself and update the timestamp to ensure it propagate.
	err := netann.SignChannelUpdate(
		d.cfg.AnnSigner, d.selfKey, chanUpdate,
		netann.ChanUpdSetTimestamp,
	)
	if err != nil {
		return nil, nil, err
	}

	// Next, we'll set the new signature in place, and update the reference
	// in the backing slice.
	edge.LastUpdate = time.Unix(int64(chanUpdate.Timestamp), 0)
	edge.SigBytes = chanUpdate.Signature.ToSignatureBytes()

	// To ensure that our signature is valid, we'll verify it ourself
	// before committing it to the slice returned.
	err = routing.ValidateChannelUpdateAnn(d.selfKey, info.Capacity, chanUpdate)
	if err != nil {
		return nil, nil, fmt.Errorf("generated invalid channel "+
			"update sig: %v", err)
	}

	// Finally, we'll write the new edge policy to disk.
	if err := d.cfg.Router.UpdateEdge(edge); err != nil {
		return nil, nil, err
	}

	// We'll also create the original channel announcement so the two can
	// be broadcast along side each other (if necessary), but only if we
	// have a full channel announcement for this channel.
	var chanAnn *lnwire.ChannelAnnouncement
	if info.AuthProof != nil {
		chanID := lnwire.NewShortChanIDFromInt(info.ChannelID)
		chanAnn = &lnwire.ChannelAnnouncement{
			ShortChannelID:  chanID,
			NodeID1:         info.NodeKey1Bytes,
			NodeID2:         info.NodeKey2Bytes,
			ChainHash:       info.ChainHash,
			BitcoinKey1:     info.BitcoinKey1Bytes,
			Features:        lnwire.NewRawFeatureVector(),
			BitcoinKey2:     info.BitcoinKey2Bytes,
			ExtraOpaqueData: edge.ExtraOpaqueData,
		}
		chanAnn.NodeSig1, err = lnwire.NewSigFromRawSignature(
			info.AuthProof.NodeSig1Bytes,
		)
		if err != nil {
			return nil, nil, err
		}
		chanAnn.NodeSig2, err = lnwire.NewSigFromRawSignature(
			info.AuthProof.NodeSig2Bytes,
		)
		if err != nil {
			return nil, nil, err
		}
		chanAnn.BitcoinSig1, err = lnwire.NewSigFromRawSignature(
			info.AuthProof.BitcoinSig1Bytes,
		)
		if err != nil {
			return nil, nil, err
		}
		chanAnn.BitcoinSig2, err = lnwire.NewSigFromRawSignature(
			info.AuthProof.BitcoinSig2Bytes,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return chanAnn, chanUpdate, err
}

// SyncManager returns the gossiper's SyncManager instance.
func (d *AuthenticatedGossiper) SyncManager() *SyncManager {
	return d.syncMgr
}
