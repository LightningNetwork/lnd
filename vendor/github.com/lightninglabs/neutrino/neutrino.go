// NOTE: THIS API IS UNSTABLE RIGHT NOW.
// TODO: Add functional options to ChainService instantiation.

package neutrino

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/blockntfns"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/neutrino/filterdb"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/lightninglabs/neutrino/pushtx"
	"github.com/lightninglabs/neutrino/query"
)

// These are exported variables so they can be changed by users.
//
// TODO: Export functional options for these as much as possible so they can be
// changed call-to-call.
var (
	// ConnectionRetryInterval is the base amount of time to wait in
	// between retries when connecting to persistent peers.  It is adjusted
	// by the number of retries such that there is a retry backoff.
	ConnectionRetryInterval = time.Second * 5

	// UserAgentName is the user agent name and is used to help identify
	// ourselves to other bitcoin peers.
	UserAgentName = "neutrino"

	// UserAgentVersion is the user agent version and is used to help
	// identify ourselves to other bitcoin peers.
	UserAgentVersion = "0.11.0-beta"

	// Services describes the services that are supported by the server.
	Services = wire.SFNodeWitness | wire.SFNodeCF

	// RequiredServices describes the services that are required to be
	// supported by outbound peers.
	RequiredServices = wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeCF

	// BanThreshold is the maximum ban score before a peer is banned.
	BanThreshold = uint32(100)

	// BanDuration is the duration of a ban.
	BanDuration = time.Hour * 24

	// TargetOutbound is the number of outbound peers to target.
	TargetOutbound = 8

	// MaxPeers is the maximum number of connections the client maintains.
	MaxPeers = 125

	// DisableDNSSeed disables getting initial addresses for Bitcoin nodes
	// from DNS.
	DisableDNSSeed = false

	// DefaultFilterCacheSize is the size (in bytes) of filters neutrino
	// will keep in memory if no size is specified in the neutrino.Config.
	// Since we utilize the cache during batch filter fetching, it is
	// beneficial if it is able to to keep a whole batch. The current batch
	// size is 1000, so we default to 30 MB, which can fit about 1450 to
	// 2300 mainnet filters.
	DefaultFilterCacheSize uint64 = 3120 * 10 * 1000

	// DefaultBlockCacheSize is the size (in bytes) of blocks neutrino will
	// keep in memory if no size is specified in the neutrino.Config.
	DefaultBlockCacheSize uint64 = 4096 * 10 * 1000 // 40 MB
)

// updatePeerHeightsMsg is a message sent from the blockmanager to the server
// after a new block has been accepted. The purpose of the message is to update
// the heights of peers that were known to announce the block before we
// connected it to the main chain or recognized it as an orphan. With these
// updates, peer heights will be kept up to date, allowing for fresh data when
// selecting sync peer candidacy.
type updatePeerHeightsMsg struct {
	newHash    *chainhash.Hash
	newHeight  int32
	originPeer *ServerPeer
}

// peerState maintains state of inbound, persistent, outbound peers as well
// as banned peers and outbound groups.
type peerState struct {
	outboundPeers   map[int32]*ServerPeer
	persistentPeers map[int32]*ServerPeer
	outboundGroups  map[string]int
}

// Count returns the count of all known peers.
func (ps *peerState) Count() int {
	return len(ps.outboundPeers) + len(ps.persistentPeers)
}

// forAllOutboundPeers is a helper function that runs closure on all outbound
// peers known to peerState.
func (ps *peerState) forAllOutboundPeers(closure func(sp *ServerPeer)) {
	for _, e := range ps.outboundPeers {
		closure(e)
	}
	for _, e := range ps.persistentPeers {
		closure(e)
	}
}

// forAllPeers is a helper function that runs closure on all peers known to
// peerState.
func (ps *peerState) forAllPeers(closure func(sp *ServerPeer)) {
	ps.forAllOutboundPeers(closure)
}

// spMsg represents a message over the wire from a specific peer.
type spMsg struct {
	sp  *ServerPeer
	msg wire.Message
}

// spMsgSubscription sends all messages from a peer over a channel, allowing
// pluggable filtering of the messages.
type spMsgSubscription struct {
	msgChan  chan<- spMsg
	quitChan <-chan struct{}
}

// msgSubscription sends all messages from a peer over a channel, allowing
// pluggable filtering of the messages.
type msgSubscription struct {
	msgChan  chan<- wire.Message
	quitChan <-chan struct{}
}

// ServerPeer extends the peer to maintain state shared by the server and the
// blockmanager.
type ServerPeer struct {
	// The following variables must only be used atomically
	feeFilter int64

	*peer.Peer

	connReq        *connmgr.ConnReq
	server         *ChainService
	persistent     bool
	continueHash   *chainhash.Hash
	requestQueue   []*wire.InvVect
	knownAddresses map[string]struct{}
	banScore       connmgr.DynamicBanScore
	quit           chan struct{}

	// The following map of subcribers is used to subscribe to messages
	// from the peer. This allows broadcast to multiple subscribers at
	// once, allowing for multiple queries to be going to multiple peers at
	// any one time. The mutex is for subscribe/unsubscribe functionality.
	// The sends on these channels WILL NOT block; any messages the channel
	// can't accept will be dropped silently.
	// TODO(halseth): remove one of the maps when all queries go through
	// work manager.
	recvSubscribers  map[spMsgSubscription]struct{}
	recvSubscribers2 map[msgSubscription]struct{}
	mtxSubscribers   sync.RWMutex
}

// newServerPeer returns a new ServerPeer instance. The peer needs to be set by
// the caller.
func newServerPeer(s *ChainService, isPersistent bool) *ServerPeer {
	return &ServerPeer{
		server:           s,
		persistent:       isPersistent,
		knownAddresses:   make(map[string]struct{}),
		quit:             make(chan struct{}),
		recvSubscribers:  make(map[spMsgSubscription]struct{}),
		recvSubscribers2: make(map[msgSubscription]struct{}),
	}
}

// newestBlock returns the current best block hash and height using the format
// required by the configuration for the peer package.
func (sp *ServerPeer) newestBlock() (*chainhash.Hash, int32, error) {
	bestHeader, bestHeight, err := sp.server.BlockHeaders.ChainTip()
	if err != nil {
		return nil, 0, err
	}
	bestHash := bestHeader.BlockHash()
	return &bestHash, int32(bestHeight), nil
}

// addKnownAddresses adds the given addresses to the set of known addresses to
// the peer to prevent sending duplicate addresses.
func (sp *ServerPeer) addKnownAddresses(addresses []*wire.NetAddress) {
	for _, na := range addresses {
		sp.knownAddresses[addrmgr.NetAddressKey(na)] = struct{}{}
	}
}

// addressKnown true if the given address is already known to the peer.
func (sp *ServerPeer) addressKnown(na *wire.NetAddress) bool {
	_, exists := sp.knownAddresses[addrmgr.NetAddressKey(na)]
	return exists
}

// addBanScore increases the persistent and decaying ban score fields by the
// values passed as parameters. If the resulting score exceeds half of the ban
// threshold, a warning is logged including the reason provided. Further, if
// the score is above the ban threshold, the peer will be banned and
// disconnected.
func (sp *ServerPeer) addBanScore(persistent, transient uint32, reason string) {
	// No warning is logged and no score is calculated if banning is
	// disabled.
	warnThreshold := BanThreshold >> 1
	if transient == 0 && persistent == 0 {
		// The score is not being increased, but a warning message is
		// still logged if the score is above the warn threshold.
		score := sp.banScore.Int()
		if score > warnThreshold {
			log.Warnf("Misbehaving peer %s: %s -- ban score is "+
				"%d, it was not increased this time", sp,
				reason, score)
		}
		return
	}

	score := sp.banScore.Increase(persistent, transient)
	if score > warnThreshold {
		log.Warnf("Misbehaving peer %s: %s -- ban score increased to %d",
			sp, reason, score)

		if score > BanThreshold {
			peerAddr := sp.Addr()
			err := sp.server.BanPeer(
				peerAddr, banman.ExceededBanThreshold,
			)
			if err != nil {
				log.Errorf("Unable to ban peer %v: %v",
					peerAddr, err)
			}
		}
	}
}

// OnVerAck is invoked when a peer receives a verack bitcoin message and is used
// to kick start communication with them.
func (sp *ServerPeer) OnVerAck(_ *peer.Peer, msg *wire.MsgVerAck) {
	sp.server.AddPeer(sp)
}

// OnVersion is invoked when a peer receives a version bitcoin message
// and is used to negotiate the protocol version details as well as kick start
// the communications.
func (sp *ServerPeer) OnVersion(_ *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
	// Add the remote peer time as a sample for creating an offset against
	// the local clock to keep the network time in sync.
	sp.server.timeSource.AddTimeSample(sp.Addr(), msg.Timestamp)

	// Check to see if the peer supports the latest protocol version and
	// service bits required to service us. If not, then we'll disconnect
	// so we can find compatible peers.
	peerServices := sp.Services()
	if peerServices&wire.SFNodeWitness != wire.SFNodeWitness ||
		peerServices&wire.SFNodeCF != wire.SFNodeCF {

		peerAddr := sp.Addr()
		err := sp.server.BanPeer(peerAddr, banman.NoCompactFilters)
		if err != nil {
			log.Errorf("Unable to ban peer %v: %v", peerAddr, err)
		}

		// Disconnect the peer even though BanPeer attempts to do so
		// because it has yet to be added.
		sp.Disconnect()

		return nil
	}

	// Update the address manager with the advertised services for outbound
	// connections in case they have changed. This is not done for inbound
	// connections to help prevent malicious behavior and is skipped when
	// running on the simulation test network since it is only intended to
	// connect to specified peers and actively avoids advertising and
	// connecting to discovered peers.
	if !sp.Inbound() {
		sp.server.addrManager.SetServices(sp.NA(), msg.Services)
	}

	return nil
}

// OnInv is invoked when a peer receives an inv bitcoin message and is
// used to examine the inventory being advertised by the remote peer and react
// accordingly.  We pass the message down to blockmanager which will call
// QueueMessage with any appropriate responses.
func (sp *ServerPeer) OnInv(p *peer.Peer, msg *wire.MsgInv) {
	log.Tracef("Got inv with %d items from %s", len(msg.InvList), p.Addr())
	newInv := wire.NewMsgInvSizeHint(uint(len(msg.InvList)))
	for _, invVect := range msg.InvList {
		if invVect.Type == wire.InvTypeTx {
			log.Tracef("Ignoring tx %s in inv from %v -- "+
				"SPV mode", invVect.Hash, sp)
			if sp.ProtocolVersion() >= wire.BIP0037Version {
				log.Infof("Peer %v is announcing "+
					"transactions -- disconnecting", sp)
				sp.Disconnect()
				return
			}
			continue
		}
		err := newInv.AddInvVect(invVect)
		if err != nil {
			log.Errorf("Failed to add inventory vector: %s", err)
			break
		}
	}

	if len(newInv.InvList) > 0 {
		sp.server.blockManager.QueueInv(newInv, sp)
	}
}

// OnHeaders is invoked when a peer receives a headers bitcoin
// message.  The message is passed down to the block manager.
func (sp *ServerPeer) OnHeaders(p *peer.Peer, msg *wire.MsgHeaders) {
	log.Tracef("Got headers with %d items from %s", len(msg.Headers),
		p.Addr())
	sp.server.blockManager.QueueHeaders(msg, sp)
}

// OnFeeFilter is invoked when a peer receives a feefilter bitcoin message and
// is used by remote peers to request that no transactions which have a fee rate
// lower than provided value are inventoried to them.  The peer will be
// disconnected if an invalid fee filter value is provided.
func (sp *ServerPeer) OnFeeFilter(_ *peer.Peer, msg *wire.MsgFeeFilter) {
	// Check that the passed minimum fee is a valid amount.
	if msg.MinFee < 0 || msg.MinFee > btcutil.MaxSatoshi {
		log.Debugf("Peer %v sent an invalid feefilter '%v' -- "+
			"disconnecting", sp, btcutil.Amount(msg.MinFee))
		sp.Disconnect()
		return
	}

	atomic.StoreInt64(&sp.feeFilter, msg.MinFee)
}

// OnReject is invoked when a peer receives a reject bitcoin message and is
// used to notify the server about a rejected transaction.
func (sp *ServerPeer) OnReject(_ *peer.Peer, msg *wire.MsgReject) {
	// TODO(roaseef): log?
}

// OnAddr is invoked when a peer receives an addr bitcoin message and is
// used to notify the server about advertised addresses.
func (sp *ServerPeer) OnAddr(_ *peer.Peer, msg *wire.MsgAddr) {
	// Ignore addresses when running on the simulation test network.  This
	// helps prevent the network from becoming another public test network
	// since it will not be able to learn about other peers that have not
	// specifically been provided.
	if sp.server.chainParams.Net == chaincfg.SimNetParams.Net {
		return
	}

	// Ignore old style addresses which don't include a timestamp.
	if sp.ProtocolVersion() < wire.NetAddressTimeVersion {
		return
	}

	// A message that has no addresses is invalid.
	if len(msg.AddrList) == 0 {
		log.Errorf("Command [%s] from %s does not contain any "+
			"addresses", msg.Command(), sp.Addr())
		sp.Disconnect()
		return
	}

	var addrsSupportingServices []*wire.NetAddress
	for _, na := range msg.AddrList {
		// Don't add more address if we're disconnecting.
		if !sp.Connected() {
			return
		}

		// Skip any that don't advertise our required services.
		if na.Services&RequiredServices != RequiredServices {
			continue
		}

		// Set the timestamp to 5 days ago if it's more than 24 hours
		// in the future so this address is one of the first to be
		// removed when space is needed.
		now := time.Now()
		if na.Timestamp.After(now.Add(time.Minute * 10)) {
			na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
		}

		addrsSupportingServices = append(addrsSupportingServices, na)

	}

	// Ignore any addr messages if none of them contained our required
	// services.
	if len(addrsSupportingServices) == 0 {
		return
	}

	// Add address to known addresses for this peer.
	sp.addKnownAddresses(addrsSupportingServices)

	// Add addresses to server address manager.  The address manager handles
	// the details of things such as preventing duplicate addresses, max
	// addresses, and last seen updates.
	// XXX bitcoind gives a 2 hour time penalty here, do we want to do the
	// same?
	sp.server.addrManager.AddAddresses(addrsSupportingServices, sp.NA())
}

// OnRead is invoked when a peer receives a message and it is used to update
// the bytes received by the server.
func (sp *ServerPeer) OnRead(_ *peer.Peer, bytesRead int, msg wire.Message,
	err error) {

	sp.server.AddBytesReceived(uint64(bytesRead))

	// Send a message to each subscriber. Each message gets its own
	// goroutine to prevent blocking on the mutex lock.
	// TODO: Flood control.
	sp.mtxSubscribers.RLock()
	defer sp.mtxSubscribers.RUnlock()
	for subscription := range sp.recvSubscribers {
		go func(subscription spMsgSubscription) {
			select {
			case <-subscription.quitChan:
			case subscription.msgChan <- spMsg{
				msg: msg,
				sp:  sp,
			}:
			}
		}(subscription)
	}
	for subscription := range sp.recvSubscribers2 {
		// Quickly determine if this subscription has been canceled, if
		// so delete it.
		select {
		case <-subscription.quitChan:
			delete(sp.recvSubscribers2, subscription)
			continue
		default:
		}

		go func(subscription msgSubscription) {
			select {
			case <-subscription.quitChan:
			case subscription.msgChan <- msg:
			}
		}(subscription)
	}
}

// subscribeRecvMsg handles adding OnRead subscriptions to the server peer.
func (sp *ServerPeer) subscribeRecvMsg(subscription spMsgSubscription) {
	sp.mtxSubscribers.Lock()
	defer sp.mtxSubscribers.Unlock()
	sp.recvSubscribers[subscription] = struct{}{}
}

// unsubscribeRecvMsgs handles removing OnRead subscriptions from the server
// peer.
func (sp *ServerPeer) unsubscribeRecvMsgs(subscription spMsgSubscription) {
	sp.mtxSubscribers.Lock()
	defer sp.mtxSubscribers.Unlock()
	delete(sp.recvSubscribers, subscription)
}

// A compile-time check to ensure that ServerPeer implements the query.Peer
// interface.
var _ query.Peer = (*ServerPeer)(nil)

// SubscribeRecvMsg adds a OnRead subscription to the peer. All bitcoin
// messages received from this peer will be sent on the returned channel. A
// closure is also returned, that should be called to cancel the subscription.
//
// NOTE: Part of the query.Peer interface.
func (sp *ServerPeer) SubscribeRecvMsg() (<-chan wire.Message, func()) {
	// We won't have to buffer this channel, since we'll always send on it
	// from a new goroutine.
	msgChan := make(chan wire.Message)
	quitChan := make(chan struct{})

	sub := msgSubscription{
		msgChan:  msgChan,
		quitChan: quitChan,
	}

	sp.mtxSubscribers.Lock()
	defer sp.mtxSubscribers.Unlock()
	sp.recvSubscribers2[sub] = struct{}{}

	return msgChan, func() {
		close(quitChan)
	}
}

// OnDisconnect returns a channel that will be closed when this peer is
// disconnected.
//
// NOTE: Part of the query.Peer interface.
func (sp *ServerPeer) OnDisconnect() <-chan struct{} {
	return sp.quit
}

// OnWrite is invoked when a peer sends a message and it is used to update
// the bytes sent by the server.
func (sp *ServerPeer) OnWrite(_ *peer.Peer, bytesWritten int, msg wire.Message, err error) {
	sp.server.AddBytesSent(uint64(bytesWritten))
}

// Config is a struct detailing the configuration of the chain service.
type Config struct {
	// DataDir is the directory that neutrino will store all header
	// information within.
	DataDir string

	// Database is an *open* database instance that we'll use to storm
	// indexes of teh chain.
	Database walletdb.DB

	// ChainParams is the chain that we're running on.
	ChainParams chaincfg.Params

	// ConnectPeers is a slice of hosts that should be connected to on
	// startup, and be established as persistent peers.
	//
	// NOTE: If specified, we'll *only* connect to this set of peers and
	// won't attempt to automatically seek outbound peers.
	ConnectPeers []string

	// AddPeers is a slice of hosts that should be connected to on startup,
	// and be maintained as persistent peers.
	AddPeers []string

	// Dialer is an optional function closure that will be used to
	// establish outbound TCP connections. If specified, then the
	// connection manager will use this in place of net.Dial for all
	// outbound connection attempts.
	Dialer func(addr net.Addr) (net.Conn, error)

	// NameResolver is an optional function closure that will be used to
	// lookup the IP of any host. If specified, then the address manager,
	// along with regular outbound connection attempts will use this
	// instead.
	NameResolver func(host string) ([]net.IP, error)

	// FilterCacheSize indicates the size (in bytes) of filters the cache will
	// hold in memory at most.
	FilterCacheSize uint64

	// BlockCacheSize indicates the size (in bytes) of blocks the block
	// cache will hold in memory at most.
	BlockCacheSize uint64

	// AssertFilterHeader is an optional field that allows the creator of
	// the ChainService to ensure that if any chain data exists, it's
	// compliant with the expected filter header state. If neutrino starts
	// up and this filter header state has diverged, then it'll remove the
	// current on disk filter headers to sync them anew.
	AssertFilterHeader *headerfs.FilterHeader
}

// peerSubscription holds a peer subscription which we'll notify about any
// connected peers.
type peerSubscription struct {
	peers  chan<- query.Peer
	cancel <-chan struct{}
}

// ChainService is instantiated with functional options
type ChainService struct {
	// The following variables must only be used atomically.
	// Putting the uint64s first makes them 64-bit aligned for 32-bit systems.
	bytesReceived uint64 // Total bytes received from all peers since start.
	bytesSent     uint64 // Total bytes sent by all peers since start.
	started       int32
	shutdown      int32

	FilterDB         filterdb.FilterDatabase
	BlockHeaders     headerfs.BlockHeaderStore
	RegFilterHeaders *headerfs.FilterHeaderStore

	FilterCache *lru.Cache
	BlockCache  *lru.Cache

	// queryPeers will be called to send messages to one or more peers,
	// expecting a response.
	queryPeers func(wire.Message, func(*ServerPeer, wire.Message,
		chan<- struct{}), ...QueryOption)

	chainParams          chaincfg.Params
	addrManager          *addrmgr.AddrManager
	connManager          *connmgr.ConnManager
	blockManager         *blockManager
	blockSubscriptionMgr *blockntfns.SubscriptionManager
	newPeers             chan *ServerPeer
	donePeers            chan *ServerPeer
	query                chan interface{}
	firstPeerConnect     chan struct{}
	peerHeightsUpdate    chan updatePeerHeightsMsg
	wg                   sync.WaitGroup
	quit                 chan struct{}
	timeSource           blockchain.MedianTimeSource
	services             wire.ServiceFlag
	utxoScanner          *UtxoScanner
	broadcaster          *pushtx.Broadcaster
	banStore             banman.Store
	workManager          *query.WorkManager

	// peerSubscribers is a slice of active peer subscriptions, that we
	// will notify each time a new peer is connected.
	peerSubscribers []*peerSubscription

	// TODO: Add a map for more granular exclusion?
	mtxCFilter sync.Mutex

	userAgentName    string
	userAgentVersion string

	nameResolver func(string) ([]net.IP, error)
	dialer       func(net.Addr) (net.Conn, error)
}

// NewChainService returns a new chain service configured to connect to the
// bitcoin network type specified by chainParams.  Use start to begin syncing
// with peers.
func NewChainService(cfg Config) (*ChainService, error) {
	// First, we'll sort out the methods that we'll use to established
	// outbound TCP connections, as well as perform any DNS queries.
	//
	// If the dialler was specified, then we'll use that in place of the
	// default net.Dial function.
	var (
		nameResolver func(string) ([]net.IP, error)
		dialer       func(net.Addr) (net.Conn, error)
	)
	if cfg.Dialer != nil {
		dialer = cfg.Dialer
	} else {
		dialer = func(addr net.Addr) (net.Conn, error) {
			return net.Dial(addr.Network(), addr.String())
		}
	}

	// Similarly, if the user specified as function to use for name
	// resolution, then we'll use that everywhere as well.
	if cfg.NameResolver != nil {
		nameResolver = cfg.NameResolver
	} else {
		nameResolver = net.LookupIP
	}

	// When creating the addr manager, we'll check to see if the user has
	// provided their own resolution function. If so, then we'll use that
	// instead as this may be proxying requests over an anonymizing
	// network.
	amgr := addrmgr.New(cfg.DataDir, nameResolver)

	s := ChainService{
		chainParams:       cfg.ChainParams,
		addrManager:       amgr,
		newPeers:          make(chan *ServerPeer, MaxPeers),
		donePeers:         make(chan *ServerPeer, MaxPeers),
		query:             make(chan interface{}),
		quit:              make(chan struct{}),
		firstPeerConnect:  make(chan struct{}),
		peerHeightsUpdate: make(chan updatePeerHeightsMsg),
		timeSource:        blockchain.NewMedianTime(),
		services:          Services,
		userAgentName:     UserAgentName,
		userAgentVersion:  UserAgentVersion,
		nameResolver:      nameResolver,
		dialer:            dialer,
	}
	s.workManager = query.New(&query.Config{
		ConnectedPeers: s.ConnectedPeers,
		NewWorker:      query.NewWorker,
		Ranking:        query.NewPeerRanking(),
	})

	// We set the queryPeers method to point to queryChainServicePeers,
	// passing a reference to the newly created ChainService.
	s.queryPeers = func(msg wire.Message, f func(*ServerPeer,
		wire.Message, chan<- struct{}), qo ...QueryOption) {
		queryChainServicePeers(&s, msg, f, qo...)
	}

	var err error

	s.FilterDB, err = filterdb.New(cfg.Database, cfg.ChainParams)
	if err != nil {
		return nil, err
	}

	filterCacheSize := DefaultFilterCacheSize
	if cfg.FilterCacheSize != 0 {
		filterCacheSize = cfg.FilterCacheSize
	}
	s.FilterCache = lru.NewCache(filterCacheSize)

	blockCacheSize := DefaultBlockCacheSize
	if cfg.BlockCacheSize != 0 {
		blockCacheSize = cfg.BlockCacheSize
	}
	s.BlockCache = lru.NewCache(blockCacheSize)

	s.BlockHeaders, err = headerfs.NewBlockHeaderStore(
		cfg.DataDir, cfg.Database, &cfg.ChainParams,
	)
	if err != nil {
		return nil, err
	}
	s.RegFilterHeaders, err = headerfs.NewFilterHeaderStore(
		cfg.DataDir, cfg.Database, headerfs.RegularFilter,
		&cfg.ChainParams, cfg.AssertFilterHeader,
	)
	if err != nil {
		return nil, err
	}

	bm, err := newBlockManager(&blockManagerCfg{
		ChainParams:      s.chainParams,
		BlockHeaders:     s.BlockHeaders,
		RegFilterHeaders: s.RegFilterHeaders,
		TimeSource:       s.timeSource,
		QueryDispatcher:  s.workManager,
		BanPeer:          s.BanPeer,
		GetBlock:         s.GetBlock,
		firstPeerSignal:  s.firstPeerConnect,
		queryAllPeers:    s.queryAllPeers,
	})
	if err != nil {
		return nil, err
	}
	s.blockManager = bm
	s.blockSubscriptionMgr = blockntfns.NewSubscriptionManager(s.blockManager)

	// Only setup a function to return new addresses to connect to when not
	// running in connect-only mode.  The simulation network is always in
	// connect-only mode since it is only intended to connect to specified
	// peers and actively avoid advertising and connecting to discovered
	// peers in order to prevent it from becoming a public test network.
	var newAddressFunc func() (net.Addr, error)
	if s.chainParams.Net != chaincfg.SimNetParams.Net {
		newAddressFunc = func() (net.Addr, error) {

			// Gather our set of currently connected peers to avoid
			// connecting to them again.
			connectedPeers := make(map[string]struct{})
			for _, peer := range s.Peers() {
				peerAddr := addrmgr.NetAddressKey(peer.NA())
				connectedPeers[peerAddr] = struct{}{}
			}

			for tries := 0; tries < 100; tries++ {
				select {
				case <-s.quit:
					return nil, ErrShuttingDown
				default:
				}

				addr := s.addrManager.GetAddress()
				if addr == nil {
					break
				}

				// Ignore peers that we've already banned.
				addrString := addrmgr.NetAddressKey(addr.NetAddress())
				if s.IsBanned(addrString) {
					log.Debugf("Ignoring banned peer: %v", addrString)
					continue
				}

				// Skip any addresses that correspond to our set
				// of currently connected peers.
				if _, ok := connectedPeers[addrString]; ok {
					continue
				}

				// The peer behind this address should support
				// all of our required services.
				if addr.Services()&RequiredServices != RequiredServices {
					continue
				}

				// Address will not be invalid, local or unroutable
				// because addrmanager rejects those on addition.
				// Just check that we don't already have an address
				// in the same group so that we are not connecting
				// to the same network segment at the expense of
				// others.
				key := addrmgr.GroupKey(addr.NetAddress())
				if s.OutboundGroupCount(key) != 0 {
					continue
				}

				// only allow recent nodes (10mins) after we failed 30
				// times
				if tries < 30 && time.Since(addr.LastAttempt()) < 10*time.Minute {
					continue
				}

				// allow nondefault ports after 50 failed tries.
				if tries < 50 && fmt.Sprintf("%d", addr.NetAddress().Port) !=
					s.chainParams.DefaultPort {
					continue
				}

				// Mark an attempt for the valid address.
				s.addrManager.Attempt(addr.NetAddress())
				return s.addrStringToNetAddr(addrString)
			}

			return nil, errors.New("no valid connect address")
		}
	}

	cmgrCfg := &connmgr.Config{
		RetryDuration:  ConnectionRetryInterval,
		TargetOutbound: uint32(TargetOutbound),
		OnConnection:   s.outboundPeerConnected,
		Dial:           dialer,
	}
	if len(cfg.ConnectPeers) == 0 {
		cmgrCfg.GetNewAddress = newAddressFunc
	}

	// Create a connection manager.
	if MaxPeers < TargetOutbound {
		TargetOutbound = MaxPeers
	}
	cmgr, err := connmgr.New(cmgrCfg)
	if err != nil {
		return nil, err
	}
	s.connManager = cmgr

	// Start up persistent peers.
	permanentPeers := cfg.ConnectPeers
	if len(permanentPeers) == 0 {
		permanentPeers = cfg.AddPeers
	}
	for _, addr := range permanentPeers {
		tcpAddr, err := s.addrStringToNetAddr(addr)
		if err != nil {
			return nil, err
		}

		go s.connManager.Connect(&connmgr.ConnReq{
			Addr:      tcpAddr,
			Permanent: true,
		})
	}

	s.utxoScanner = NewUtxoScanner(&UtxoScannerConfig{
		BestSnapshot: s.BestBlock,
		GetBlockHash: s.GetBlockHash,
		GetBlock:     s.GetBlock,
		BlockFilterMatches: func(ro *rescanOptions,
			blockHash *chainhash.Hash) (bool, error) {

			return blockFilterMatches(
				&RescanChainSource{&s}, ro, blockHash,
			)
		},
	})

	s.broadcaster = pushtx.NewBroadcaster(&pushtx.Config{
		Broadcast: func(tx *wire.MsgTx) error {
			return s.sendTransaction(tx)
		},
		SubscribeBlocks: func() (*blockntfns.Subscription, error) {
			return s.blockSubscriptionMgr.NewSubscription(0)
		},
		RebroadcastInterval: pushtx.DefaultRebroadcastInterval,
	})

	s.banStore, err = banman.NewStore(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ban store: %v", err)
	}

	return &s, nil
}

// BestBlock retrieves the most recent block's height and hash where we
// have both the header and filter header ready.
func (s *ChainService) BestBlock() (*headerfs.BlockStamp, error) {
	bestHeader, bestHeight, err := s.BlockHeaders.ChainTip()
	if err != nil {
		return nil, err
	}

	_, filterHeight, err := s.RegFilterHeaders.ChainTip()
	if err != nil {
		return nil, err
	}

	// Filter headers might lag behind block headers, so we can can fetch a
	// previous block header if the filter headers are not caught up.
	if filterHeight < bestHeight {
		bestHeight = filterHeight
		bestHeader, err = s.BlockHeaders.FetchHeaderByHeight(
			bestHeight,
		)
		if err != nil {
			return nil, err
		}
	}

	return &headerfs.BlockStamp{
		Height: int32(bestHeight),
		Hash:   bestHeader.BlockHash(),
	}, nil
}

// GetBlockHash returns the block hash at the given height.
func (s *ChainService) GetBlockHash(height int64) (*chainhash.Hash, error) {
	header, err := s.BlockHeaders.FetchHeaderByHeight(uint32(height))
	if err != nil {
		return nil, err
	}
	hash := header.BlockHash()
	return &hash, err
}

// GetBlockHeader returns the block header for the given block hash, or an
// error if the hash doesn't exist or is unknown.
func (s *ChainService) GetBlockHeader(
	blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	header, _, err := s.BlockHeaders.FetchHeader(blockHash)
	return header, err
}

// GetBlockHeight gets the height of a block by its hash. An error is returned
// if the given block hash is unknown.
func (s *ChainService) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	_, height, err := s.BlockHeaders.FetchHeader(hash)
	if err != nil {
		return 0, err
	}
	return int32(height), nil
}

// BanPeer disconnects and bans a peer due to a specific reason for a duration
// of BanDuration.
func (s *ChainService) BanPeer(addr string, reason banman.Reason) error {
	log.Warnf("Banning peer %v: duration=%v, reason=%v", addr, BanDuration,
		reason)

	// We'll want to disconnect the peer after we return regardless of
	// whether we ban the peer or not. We do this to prevent a possible race
	// condition where we end up reconnecting with the peer slightly
	// before the ban succeeds.
	defer func() {
		// We do so in a goroutine to prevent blocking if the server is
		// handling a query or a new/stale peer.
		go func() {
			if sp := s.PeerByAddr(addr); sp != nil {
				sp.Disconnect()
			}
		}()
	}()

	ipNet, err := banman.ParseIPNet(addr, nil)
	if err != nil {
		return fmt.Errorf("unable to parse IP network for peer %v: %v",
			addr, err)
	}
	return s.banStore.BanIPNet(ipNet, reason, BanDuration)
}

// IsBanned returns true if the peer is banned, and false otherwise.
func (s *ChainService) IsBanned(addr string) bool {
	ipNet, err := banman.ParseIPNet(addr, nil)
	if err != nil {
		log.Errorf("Unable to parse IP network for peer %v: %v", addr,
			err)
		return false
	}
	banStatus, err := s.banStore.Status(ipNet)
	if err != nil {
		log.Errorf("Unable to determine ban status for peer %v: %v",
			addr, err)
		return false
	}

	// Log how much time left the peer will remain banned for, if any.
	if time.Now().Before(banStatus.Expiration) {
		log.Debugf("Peer %v is banned for another %v", addr,
			banStatus.Expiration.Sub(time.Now()))
	}

	return banStatus.Banned
}

// AddPeer adds a new peer that has already been connected to the server.
func (s *ChainService) AddPeer(sp *ServerPeer) {
	select {
	case s.newPeers <- sp:
	case <-s.quit:
		return
	}
}

// AddBytesSent adds the passed number of bytes to the total bytes sent counter
// for the server.  It is safe for concurrent access.
func (s *ChainService) AddBytesSent(bytesSent uint64) {
	atomic.AddUint64(&s.bytesSent, bytesSent)
}

// AddBytesReceived adds the passed number of bytes to the total bytes received
// counter for the server.  It is safe for concurrent access.
func (s *ChainService) AddBytesReceived(bytesReceived uint64) {
	atomic.AddUint64(&s.bytesReceived, bytesReceived)
}

// NetTotals returns the sum of all bytes received and sent across the network
// for all peers.  It is safe for concurrent access.
func (s *ChainService) NetTotals() (uint64, uint64) {
	return atomic.LoadUint64(&s.bytesReceived),
		atomic.LoadUint64(&s.bytesSent)
}

// peerHandler is used to handle peer operations such as adding and removing
// peers to and from the server, banning peers, and broadcasting messages to
// peers.  It must be run in a goroutine.
func (s *ChainService) peerHandler() {
	state := &peerState{
		persistentPeers: make(map[int32]*ServerPeer),
		outboundPeers:   make(map[int32]*ServerPeer),
		outboundGroups:  make(map[string]int),
	}

	if !DisableDNSSeed {
		// Add peers discovered through DNS to the address manager.
		connmgr.SeedFromDNS(&s.chainParams, RequiredServices,
			s.nameResolver, func(addrs []*wire.NetAddress) {
				var validAddrs []*wire.NetAddress
				for _, addr := range addrs {
					addr.Services = RequiredServices

					validAddrs = append(validAddrs, addr)
				}

				if len(validAddrs) == 0 {
					return
				}

				// Bitcoind uses a lookup of the dns seeder
				// here. This is rather strange since the
				// values looked up by the DNS seed lookups
				// will vary quite a lot.  to replicate this
				// behaviour we put all addresses as having
				// come from the first one.
				s.addrManager.AddAddresses(
					validAddrs, validAddrs[0],
				)
			})
	}

out:
	for {
		select {
		// New peers connected to the server.
		case p := <-s.newPeers:
			s.handleAddPeerMsg(state, p)

		// Disconnected peers.
		case p := <-s.donePeers:
			s.handleDonePeerMsg(state, p)

		// Block accepted in mainchain or orphan, update peer height.
		case umsg := <-s.peerHeightsUpdate:
			s.handleUpdatePeerHeights(state, umsg)

		case qmsg := <-s.query:
			s.handleQuery(state, qmsg)

		case <-s.quit:
			// Disconnect all peers on server shutdown.
			state.forAllPeers(func(sp *ServerPeer) {
				log.Tracef("Shutdown peer %s", sp)
				sp.Disconnect()
			})
			break out
		}
	}

	// Drain channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-s.newPeers:
		case <-s.donePeers:
		case <-s.peerHeightsUpdate:
		case <-s.query:
		default:
			break cleanup
		}
	}
	s.wg.Done()
	log.Tracef("Peer handler done")
}

// addrStringToNetAddr takes an address in the form of 'host:port' or 'host'
// and returns a net.Addr which maps to the original address with any host
// names resolved to IP addresses and a default port added, if not specified,
// from the ChainService's network parameters.
func (s *ChainService) addrStringToNetAddr(addr string) (net.Addr, error) {
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		switch err.(type) {
		case *net.AddrError:
			host = addr
			strPort = s.ChainParams().DefaultPort
		default:
			return nil, err
		}
	}

	// Attempt to look up an IP address associated with the parsed host.
	ips, err := s.nameResolver(host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{
		IP:   ips[0],
		Port: port,
	}, nil
}

// handleUpdatePeerHeight updates the heights of all peers who were known to
// announce a block we recently accepted.
func (s *ChainService) handleUpdatePeerHeights(state *peerState, umsg updatePeerHeightsMsg) {
	state.forAllPeers(func(sp *ServerPeer) {
		// The origin peer should already have the updated height.
		if sp == umsg.originPeer {
			return
		}

		// This is a pointer to the underlying memory which doesn't
		// change.
		latestBlkHash := sp.LastAnnouncedBlock()

		// Skip this peer if it hasn't recently announced any new blocks.
		if latestBlkHash == nil {
			return
		}

		// If the peer has recently announced a block, and this block
		// matches our newly accepted block, then update their block
		// height.
		if *latestBlkHash == *umsg.newHash {
			sp.UpdateLastBlockHeight(umsg.newHeight)
			sp.UpdateLastAnnouncedBlock(nil)
		}
	})
}

// handleAddPeerMsg deals with adding new peers.  It is invoked from the
// peerHandler goroutine.
func (s *ChainService) handleAddPeerMsg(state *peerState, sp *ServerPeer) bool {
	if sp == nil || !sp.Connected() {
		return false
	}

	// Ignore new peers if we're shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		log.Infof("New peer %s ignored - server is shutting down", sp)
		sp.Disconnect()
		return false
	}

	// Disconnect banned peers.
	if s.IsBanned(sp.Addr()) {
		sp.Disconnect()
		return false
	}

	// TODO: Check for max peers from a single IP.

	// Limit max number of total peers.
	if state.Count() >= MaxPeers {
		log.Infof("Max peers reached [%d] - disconnecting peer %s",
			MaxPeers, sp)
		sp.Disconnect()
		// TODO: how to handle permanent peers here?
		// they should be rescheduled.
		return false
	}

	// Add the new peer and start it.
	log.Debugf("New peer %s", sp)
	state.outboundGroups[addrmgr.GroupKey(sp.NA())]++
	if sp.persistent {
		state.persistentPeers[sp.ID()] = sp
	} else {
		state.outboundPeers[sp.ID()] = sp
	}

	// Close firstPeerConnect channel so blockManager will be notified.
	if s.firstPeerConnect != nil {
		close(s.firstPeerConnect)
		s.firstPeerConnect = nil
	}

	// Update the address' last seen time if the peer has acknowledged our
	// version and has sent us its version as well.
	if sp.VerAckReceived() && sp.VersionKnown() && sp.NA() != nil {
		s.addrManager.Connected(sp.NA())
	}

	// Signal the block manager this peer is a new sync candidate.
	s.blockManager.NewPeer(sp)

	// Update the address manager and request known addresses from the
	// remote peer for outbound connections. This is skipped when running on
	// the simulation test network since it is only intended to connect to
	// specified peers and actively avoids advertising and connecting to
	// discovered peers.
	if s.chainParams.Net != chaincfg.SimNetParams.Net {
		// Request known addresses if the server address manager needs
		// more and the peer has a protocol version new enough to
		// include a timestamp with addresses.
		hasTimestamp := sp.ProtocolVersion() >= wire.NetAddressTimeVersion
		if s.addrManager.NeedMoreAddresses() && hasTimestamp {
			sp.QueueMessage(wire.NewMsgGetAddr(), nil)
		}

		// Add the address to the addr manager anew, and also mark it as
		// a good address.
		s.addrManager.AddAddresses([]*wire.NetAddress{sp.NA()}, sp.NA())
		s.addrManager.Good(sp.NA())
	}

	// We'll go through each peer subscriber and notify it about the added
	// peer.
	n := 0
	for i, sub := range s.peerSubscribers {
		select {
		// Quickly check whether this subscription has been canceled.
		case <-sub.cancel:
			// Avoid GC leak.
			s.peerSubscribers[i] = nil
			continue
		default:
		}

		// Keep non-canceled subscribers around.
		s.peerSubscribers[n] = sub
		n++

		// Send a notification in a goroutine to avoid blocking the
		// peerHandler.
		s.wg.Add(1)
		go s.notifyConnectedPeer(sub, sp)
	}

	// Re-align the slice to only active subscribers.
	s.peerSubscribers = s.peerSubscribers[:n]

	return true
}

// notifyConnectedPeer sends the given peer to the peerSubsription.
//
// NOTE: MUST be run as a goroutine.
func (s *ChainService) notifyConnectedPeer(
	sub *peerSubscription, sp *ServerPeer) {

	defer s.wg.Done()

	select {
	case sub.peers <- sp:
	case <-sub.cancel:
	case <-s.quit:
	}
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It is
// invoked from the peerHandler goroutine.
func (s *ChainService) handleDonePeerMsg(state *peerState, sp *ServerPeer) {
	// If the peer is being tracked internally, i.e., we received their
	// VerAck, we'll need to remove them.
	var list map[int32]*ServerPeer
	if sp.persistent {
		list = state.persistentPeers
	} else {
		list = state.outboundPeers
	}
	if _, ok := list[sp.ID()]; ok {
		state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		delete(list, sp.ID())

		log.Debugf("Removed peer %s", sp)
	}

	// Only request a new connection if the peer being disconnected is not
	// persistent and we still need more peer connections. There's no need
	// to do so if the peer is persistent since the connection manager will
	// attempt to reconnect.
	if sp.persistent {
		s.connManager.Disconnect(sp.connReq.ID())
		return
	}

	s.connManager.Remove(sp.connReq.ID())
	if state.Count() < MaxPeers {
		go s.connManager.NewConnReq()
	}
}

// disconnectPeer attempts to drop the connection of a tageted peer in the
// passed peer list. Targets are identified via usage of the passed
// `compareFunc`, which should return `true` if the passed peer is the target
// peer. This function returns true on success and false if the peer is unable
// to be located. If the peer is found, and the passed callback: `whenFound'
// isn't nil, we call it with the peer as the argument before it is removed
// from the peerList, and is disconnected from the server.
func disconnectPeer(peerList map[int32]*ServerPeer,
	compareFunc func(*ServerPeer) bool, whenFound func(*ServerPeer)) bool {

	for addr, peer := range peerList {
		if compareFunc(peer) {
			if whenFound != nil {
				whenFound(peer)
			}

			// This is ok because we are not continuing
			// to iterate so won't corrupt the loop.
			delete(peerList, addr)
			peer.Disconnect()
			return true
		}
	}
	return false
}

// SendTransaction broadcasts the transaction to all currently active peers so
// it can be propagated to other nodes and eventually mined. An error won't be
// returned if the transaction already exists within the mempool. Any
// transaction broadcast through this method will be rebroadcast upon every
// change of the tip of the chain.
func (s *ChainService) SendTransaction(tx *wire.MsgTx) error {
	// TODO(roasbeef): pipe through querying interface
	return s.broadcaster.Broadcast(tx)
}

// newPeerConfig returns the configuration for the given ServerPeer.
func newPeerConfig(sp *ServerPeer) *peer.Config {
	return &peer.Config{
		Listeners: peer.MessageListeners{
			OnVersion:   sp.OnVersion,
			OnVerAck:    sp.OnVerAck,
			OnInv:       sp.OnInv,
			OnHeaders:   sp.OnHeaders,
			OnReject:    sp.OnReject,
			OnFeeFilter: sp.OnFeeFilter,
			OnAddr:      sp.OnAddr,
			OnRead:      sp.OnRead,
			OnWrite:     sp.OnWrite,

			// Note: The reference client currently bans peers that send alerts
			// not signed with its key.  We could verify against their key, but
			// since the reference client is currently unwilling to support
			// other implementations' alert messages, we will not relay theirs.
			OnAlert: nil,
		},
		NewestBlock:      sp.newestBlock,
		HostToNetAddress: sp.server.addrManager.HostToNetAddress,
		UserAgentName:    sp.server.userAgentName,
		UserAgentVersion: sp.server.userAgentVersion,
		ChainParams:      &sp.server.chainParams,
		Services:         sp.server.services,
		ProtocolVersion:  wire.FeeFilterVersion,
		DisableRelayTx:   true,
	}
}

// outboundPeerConnected is invoked by the connection manager when a new
// outbound connection is established.  It initializes a new outbound server
// peer instance, associates it with the relevant state such as the connection
// request instance and the connection itself, and finally notifies the address
// manager of the attempt.
func (s *ChainService) outboundPeerConnected(c *connmgr.ConnReq, conn net.Conn) {
	// In the event that we have to disconnect the peer, we'll choose the
	// appropriate method to do so based on whether the connection request
	// is for a persistent peer or not.
	var disconnect func()
	if c.Permanent {
		disconnect = func() {
			s.connManager.Disconnect(c.ID())
		}
	} else {
		disconnect = func() {
			// Since we're completely removing the request for this
			// peer, we'll need to request a new one.
			s.connManager.Remove(c.ID())
			go s.connManager.NewConnReq()
		}
	}

	// If the peer is banned, then we'll disconnect them.
	peerAddr := c.Addr.String()
	if s.IsBanned(peerAddr) {
		disconnect()
		return
	}

	// If we're already connected to this peer, then we'll close out the new
	// connection and keep the old.
	if s.PeerByAddr(peerAddr) != nil {
		disconnect()
		return
	}

	sp := newServerPeer(s, c.Permanent)
	p, err := peer.NewOutboundPeer(newPeerConfig(sp), peerAddr)
	if err != nil {
		log.Debugf("Cannot create outbound peer %s: %s", c.Addr, err)
		disconnect()
		return
	}
	sp.Peer = p
	sp.connReq = c
	sp.AssociateConnection(conn)
	go s.peerDoneHandler(sp)
}

// peerDoneHandler handles peer disconnects by notifiying the server that it's
// done along with other performing other desirable cleanup.
func (s *ChainService) peerDoneHandler(sp *ServerPeer) {
	sp.WaitForDisconnect()

	select {
	case s.donePeers <- sp:
	case <-s.quit:
		return
	}

	// Only tell block manager we are gone if we ever told it we existed.
	if sp.VersionKnown() {
		s.blockManager.DonePeer(sp)
	}
	close(sp.quit)
}

// UpdatePeerHeights updates the heights of all peers who have have announced
// the latest connected main chain block, or a recognized orphan. These height
// updates allow us to dynamically refresh peer heights, ensuring sync peer
// selection has access to the latest block heights for each peer.
func (s *ChainService) UpdatePeerHeights(latestBlkHash *chainhash.Hash,
	latestHeight int32, updateSource *ServerPeer) {

	select {
	case s.peerHeightsUpdate <- updatePeerHeightsMsg{
		newHash:    latestBlkHash,
		newHeight:  latestHeight,
		originPeer: updateSource,
	}:
	case <-s.quit:
		return
	}
}

// ChainParams returns a copy of the ChainService's chaincfg.Params.
func (s *ChainService) ChainParams() chaincfg.Params {
	return s.chainParams
}

// Start begins connecting to peers and syncing the blockchain.
func (s *ChainService) Start() error {
	// Already started?
	if atomic.AddInt32(&s.started, 1) != 1 {
		return nil
	}

	// Start the address manager and block manager, both of which are
	// needed by peers.
	s.addrManager.Start()
	s.blockManager.Start()
	s.blockSubscriptionMgr.Start()
	s.workManager.Start()

	s.utxoScanner.Start()

	if err := s.broadcaster.Start(); err != nil {
		return fmt.Errorf("unable to start transaction broadcaster: %v",
			err)
	}

	go s.connManager.Start()

	// Start the peer handler which in turn starts the address and block
	// managers.
	s.wg.Add(1)
	go s.peerHandler()

	return nil
}

// Stop gracefully shuts down the server by stopping and disconnecting all
// peers and the main listener.
func (s *ChainService) Stop() error {
	// Make sure this only happens once.
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		return nil
	}

	s.connManager.Stop()
	s.broadcaster.Stop()
	s.utxoScanner.Stop()
	s.workManager.Stop()
	s.blockSubscriptionMgr.Stop()
	s.blockManager.Stop()
	s.addrManager.Stop()

	// Signal the remaining goroutines to quit.
	close(s.quit)
	s.wg.Wait()
	return nil
}

// IsCurrent lets the caller know whether the chain service's block manager
// thinks its view of the network is current.
func (s *ChainService) IsCurrent() bool {
	return s.blockManager.IsFullySynced()
}

// PeerByAddr lets the caller look up a peer address in the service's peer
// table, if connected to that peer address.
func (s *ChainService) PeerByAddr(addr string) *ServerPeer {
	for _, peer := range s.Peers() {
		if peer.Addr() == addr {
			return peer
		}
	}
	return nil
}

// RescanChainSource is a wrapper type around the ChainService struct that will
// be used to satisfy the rescan.ChainSource interface.
type RescanChainSource struct {
	*ChainService
}

// A compile-time check to ensure that RescanChainSource implements the
// rescan.ChainSource interface.
var _ ChainSource = (*RescanChainSource)(nil)

// GetBlockHeaderByHeight returns the header of the block with the given height.
func (s *RescanChainSource) GetBlockHeaderByHeight(
	height uint32) (*wire.BlockHeader, error) {
	return s.BlockHeaders.FetchHeaderByHeight(height)
}

// GetBlockHeader returns the header of the block with the given hash.
func (s *RescanChainSource) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, uint32, error) {
	return s.BlockHeaders.FetchHeader(hash)
}

// GetFilterHeaderByHeight returns the filter header of the block with the given
// height.
func (s *RescanChainSource) GetFilterHeaderByHeight(
	height uint32) (*chainhash.Hash, error) {
	return s.RegFilterHeaders.FetchHeaderByHeight(height)
}

// Subscribe returns a block subscription that delivers block notifications in
// order. The bestHeight parameter can be used to signal that a backlog of
// notifications should be delivered from this height. When providing a height
// of 0, a backlog will not be delivered.
func (s *RescanChainSource) Subscribe(
	bestHeight uint32) (*blockntfns.Subscription, error) {
	return s.blockSubscriptionMgr.NewSubscription(bestHeight)
}
