// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/lru"
)

const (
	// MaxProtocolVersion is the max protocol version the peer supports.
	MaxProtocolVersion = wire.FeeFilterVersion

	// DefaultTrickleInterval is the min time between attempts to send an
	// inv message to a peer.
	DefaultTrickleInterval = 10 * time.Second

	// MinAcceptableProtocolVersion is the lowest protocol version that a
	// connected peer may support.
	MinAcceptableProtocolVersion = wire.MultipleAddressVersion

	// outputBufferSize is the number of elements the output channels use.
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000

	// pingInterval is the interval of time to wait in between sending ping
	// messages.
	pingInterval = 2 * time.Minute

	// negotiateTimeout is the duration of inactivity before we timeout a
	// peer that hasn't completed the initial version negotiation.
	negotiateTimeout = 30 * time.Second

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute

	// stallTickInterval is the interval of time between each check for
	// stalled peers.
	stallTickInterval = 15 * time.Second

	// stallResponseTimeout is the base maximum amount of time messages that
	// expect a response will wait before disconnecting the peer for
	// stalling.  The deadlines are adjusted for callback running times and
	// only checked on each stall tick interval.
	stallResponseTimeout = 30 * time.Second
)

var (
	// nodeCount is the total number of peer connections made since startup
	// and is used to assign an id to a peer.
	nodeCount int32

	// zeroHash is the zero value hash (all zeros).  It is defined as a
	// convenience.
	zeroHash chainhash.Hash

	// sentNonces houses the unique nonces that are generated when pushing
	// version messages that are used to detect self connections.
	sentNonces = lru.NewCache(50)

	// allowSelfConns is only used to allow the tests to bypass the self
	// connection detecting and disconnect logic since they intentionally
	// do so for testing purposes.
	allowSelfConns bool
)

// MessageListeners defines callback function pointers to invoke with message
// listeners for a peer. Any listener which is not set to a concrete callback
// during peer initialization is ignored. Execution of multiple message
// listeners occurs serially, so one callback blocks the execution of the next.
//
// NOTE: Unless otherwise documented, these listeners must NOT directly call any
// blocking calls (such as WaitForShutdown) on the peer instance since the input
// handler goroutine blocks until the callback has completed.  Doing so will
// result in a deadlock.
type MessageListeners struct {
	// OnGetAddr is invoked when a peer receives a getaddr bitcoin message.
	OnGetAddr func(p *Peer, msg *wire.MsgGetAddr)

	// OnAddr is invoked when a peer receives an addr bitcoin message.
	OnAddr func(p *Peer, msg *wire.MsgAddr)

	// OnPing is invoked when a peer receives a ping bitcoin message.
	OnPing func(p *Peer, msg *wire.MsgPing)

	// OnPong is invoked when a peer receives a pong bitcoin message.
	OnPong func(p *Peer, msg *wire.MsgPong)

	// OnAlert is invoked when a peer receives an alert bitcoin message.
	OnAlert func(p *Peer, msg *wire.MsgAlert)

	// OnMemPool is invoked when a peer receives a mempool bitcoin message.
	OnMemPool func(p *Peer, msg *wire.MsgMemPool)

	// OnTx is invoked when a peer receives a tx bitcoin message.
	OnTx func(p *Peer, msg *wire.MsgTx)

	// OnBlock is invoked when a peer receives a block bitcoin message.
	OnBlock func(p *Peer, msg *wire.MsgBlock, buf []byte)

	// OnCFilter is invoked when a peer receives a cfilter bitcoin message.
	OnCFilter func(p *Peer, msg *wire.MsgCFilter)

	// OnCFHeaders is invoked when a peer receives a cfheaders bitcoin
	// message.
	OnCFHeaders func(p *Peer, msg *wire.MsgCFHeaders)

	// OnCFCheckpt is invoked when a peer receives a cfcheckpt bitcoin
	// message.
	OnCFCheckpt func(p *Peer, msg *wire.MsgCFCheckpt)

	// OnInv is invoked when a peer receives an inv bitcoin message.
	OnInv func(p *Peer, msg *wire.MsgInv)

	// OnHeaders is invoked when a peer receives a headers bitcoin message.
	OnHeaders func(p *Peer, msg *wire.MsgHeaders)

	// OnNotFound is invoked when a peer receives a notfound bitcoin
	// message.
	OnNotFound func(p *Peer, msg *wire.MsgNotFound)

	// OnGetData is invoked when a peer receives a getdata bitcoin message.
	OnGetData func(p *Peer, msg *wire.MsgGetData)

	// OnGetBlocks is invoked when a peer receives a getblocks bitcoin
	// message.
	OnGetBlocks func(p *Peer, msg *wire.MsgGetBlocks)

	// OnGetHeaders is invoked when a peer receives a getheaders bitcoin
	// message.
	OnGetHeaders func(p *Peer, msg *wire.MsgGetHeaders)

	// OnGetCFilters is invoked when a peer receives a getcfilters bitcoin
	// message.
	OnGetCFilters func(p *Peer, msg *wire.MsgGetCFilters)

	// OnGetCFHeaders is invoked when a peer receives a getcfheaders
	// bitcoin message.
	OnGetCFHeaders func(p *Peer, msg *wire.MsgGetCFHeaders)

	// OnGetCFCheckpt is invoked when a peer receives a getcfcheckpt
	// bitcoin message.
	OnGetCFCheckpt func(p *Peer, msg *wire.MsgGetCFCheckpt)

	// OnFeeFilter is invoked when a peer receives a feefilter bitcoin message.
	OnFeeFilter func(p *Peer, msg *wire.MsgFeeFilter)

	// OnFilterAdd is invoked when a peer receives a filteradd bitcoin message.
	OnFilterAdd func(p *Peer, msg *wire.MsgFilterAdd)

	// OnFilterClear is invoked when a peer receives a filterclear bitcoin
	// message.
	OnFilterClear func(p *Peer, msg *wire.MsgFilterClear)

	// OnFilterLoad is invoked when a peer receives a filterload bitcoin
	// message.
	OnFilterLoad func(p *Peer, msg *wire.MsgFilterLoad)

	// OnMerkleBlock  is invoked when a peer receives a merkleblock bitcoin
	// message.
	OnMerkleBlock func(p *Peer, msg *wire.MsgMerkleBlock)

	// OnVersion is invoked when a peer receives a version bitcoin message.
	// The caller may return a reject message in which case the message will
	// be sent to the peer and the peer will be disconnected.
	OnVersion func(p *Peer, msg *wire.MsgVersion) *wire.MsgReject

	// OnVerAck is invoked when a peer receives a verack bitcoin message.
	OnVerAck func(p *Peer, msg *wire.MsgVerAck)

	// OnReject is invoked when a peer receives a reject bitcoin message.
	OnReject func(p *Peer, msg *wire.MsgReject)

	// OnSendHeaders is invoked when a peer receives a sendheaders bitcoin
	// message.
	OnSendHeaders func(p *Peer, msg *wire.MsgSendHeaders)

	// OnRead is invoked when a peer receives a bitcoin message.  It
	// consists of the number of bytes read, the message, and whether or not
	// an error in the read occurred.  Typically, callers will opt to use
	// the callbacks for the specific message types, however this can be
	// useful for circumstances such as keeping track of server-wide byte
	// counts or working with custom message types for which the peer does
	// not directly provide a callback.
	OnRead func(p *Peer, bytesRead int, msg wire.Message, err error)

	// OnWrite is invoked when we write a bitcoin message to a peer.  It
	// consists of the number of bytes written, the message, and whether or
	// not an error in the write occurred.  This can be useful for
	// circumstances such as keeping track of server-wide byte counts.
	OnWrite func(p *Peer, bytesWritten int, msg wire.Message, err error)
}

// Config is the struct to hold configuration options useful to Peer.
type Config struct {
	// NewestBlock specifies a callback which provides the newest block
	// details to the peer as needed.  This can be nil in which case the
	// peer will report a block height of 0, however it is good practice for
	// peers to specify this so their currently best known is accurately
	// reported.
	NewestBlock HashFunc

	// HostToNetAddress returns the netaddress for the given host. This can be
	// nil in  which case the host will be parsed as an IP address.
	HostToNetAddress HostToNetAddrFunc

	// Proxy indicates a proxy is being used for connections.  The only
	// effect this has is to prevent leaking the tor proxy address, so it
	// only needs to specified if using a tor proxy.
	Proxy string

	// UserAgentName specifies the user agent name to advertise.  It is
	// highly recommended to specify this value.
	UserAgentName string

	// UserAgentVersion specifies the user agent version to advertise.  It
	// is highly recommended to specify this value and that it follows the
	// form "major.minor.revision" e.g. "2.6.41".
	UserAgentVersion string

	// UserAgentComments specify the user agent comments to advertise.  These
	// values must not contain the illegal characters specified in BIP 14:
	// '/', ':', '(', ')'.
	UserAgentComments []string

	// ChainParams identifies which chain parameters the peer is associated
	// with.  It is highly recommended to specify this field, however it can
	// be omitted in which case the test network will be used.
	ChainParams *chaincfg.Params

	// Services specifies which services to advertise as supported by the
	// local peer.  This field can be omitted in which case it will be 0
	// and therefore advertise no supported services.
	Services wire.ServiceFlag

	// ProtocolVersion specifies the maximum protocol version to use and
	// advertise.  This field can be omitted in which case
	// peer.MaxProtocolVersion will be used.
	ProtocolVersion uint32

	// DisableRelayTx specifies if the remote peer should be informed to
	// not send inv messages for transactions.
	DisableRelayTx bool

	// Listeners houses callback functions to be invoked on receiving peer
	// messages.
	Listeners MessageListeners

	// TrickleInterval is the duration of the ticker which trickles down the
	// inventory to a peer.
	TrickleInterval time.Duration
}

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// newNetAddress attempts to extract the IP address and port from the passed
// net.Addr interface and create a bitcoin NetAddress structure using that
// information.
func newNetAddress(addr net.Addr, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// addr will be a net.TCPAddr when not using a proxy.
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip := tcpAddr.IP
		port := uint16(tcpAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// addr will be a socks.ProxiedAddr when using a proxy.
	if proxiedAddr, ok := addr.(*socks.ProxiedAddr); ok {
		ip := net.ParseIP(proxiedAddr.Host)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		port := uint16(proxiedAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// For the most part, addr should be one of the two above cases, but
	// to be safe, fall back to trying to parse the information from the
	// address string as a last resort.
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), services)
	return na, nil
}

// outMsg is used to house a message to be sent along with a channel to signal
// when the message has been sent (or won't be sent due to things such as
// shutdown)
type outMsg struct {
	msg      wire.Message
	doneChan chan<- struct{}
	encoding wire.MessageEncoding
}

// stallControlCmd represents the command of a stall control message.
type stallControlCmd uint8

// Constants for the command of a stall control message.
const (
	// sccSendMessage indicates a message is being sent to the remote peer.
	sccSendMessage stallControlCmd = iota

	// sccReceiveMessage indicates a message has been received from the
	// remote peer.
	sccReceiveMessage

	// sccHandlerStart indicates a callback handler is about to be invoked.
	sccHandlerStart

	// sccHandlerStart indicates a callback handler has completed.
	sccHandlerDone
)

// stallControlMsg is used to signal the stall handler about specific events
// so it can properly detect and handle stalled remote peers.
type stallControlMsg struct {
	command stallControlCmd
	message wire.Message
}

// StatsSnap is a snapshot of peer stats at a point in time.
type StatsSnap struct {
	ID             int32
	Addr           string
	Services       wire.ServiceFlag
	LastSend       time.Time
	LastRecv       time.Time
	BytesSent      uint64
	BytesRecv      uint64
	ConnTime       time.Time
	TimeOffset     int64
	Version        uint32
	UserAgent      string
	Inbound        bool
	StartingHeight int32
	LastBlock      int32
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64
}

// HashFunc is a function which returns a block hash, height and error
// It is used as a callback to get newest block details.
type HashFunc func() (hash *chainhash.Hash, height int32, err error)

// AddrFunc is a func which takes an address and returns a related address.
type AddrFunc func(remoteAddr *wire.NetAddress) *wire.NetAddress

// HostToNetAddrFunc is a func which takes a host, port, services and returns
// the netaddress.
type HostToNetAddrFunc func(host string, port uint16,
	services wire.ServiceFlag) (*wire.NetAddress, error)

// NOTE: The overall data flow of a peer is split into 3 goroutines.  Inbound
// messages are read via the inHandler goroutine and generally dispatched to
// their own handler.  For inbound data-related messages such as blocks,
// transactions, and inventory, the data is handled by the corresponding
// message handlers.  The data flow for outbound messages is split into 2
// goroutines, queueHandler and outHandler.  The first, queueHandler, is used
// as a way for external entities to queue messages, by way of the QueueMessage
// function, quickly regardless of whether the peer is currently sending or not.
// It acts as the traffic cop between the external world and the actual
// goroutine which writes to the network socket.

// Peer provides a basic concurrent safe bitcoin peer for handling bitcoin
// communications via the peer-to-peer protocol.  It provides full duplex
// reading and writing, automatic handling of the initial handshake process,
// querying of usage statistics and other information about the remote peer such
// as its address, user agent, and protocol version, output message queuing,
// inventory trickling, and the ability to dynamically register and unregister
// callbacks for handling bitcoin protocol messages.
//
// Outbound messages are typically queued via QueueMessage or QueueInventory.
// QueueMessage is intended for all messages, including responses to data such
// as blocks and transactions.  QueueInventory, on the other hand, is only
// intended for relaying inventory as it employs a trickling mechanism to batch
// the inventory together.  However, some helper functions for pushing messages
// of specific types that typically require common special handling are
// provided as a convenience.
type Peer struct {
	// The following variables must only be used atomically.
	bytesReceived uint64
	bytesSent     uint64
	lastRecv      int64
	lastSend      int64
	connected     int32
	disconnect    int32

	conn net.Conn

	// These fields are set at creation time and never modified, so they are
	// safe to read from concurrently without a mutex.
	addr    string
	cfg     Config
	inbound bool

	flagsMtx             sync.Mutex // protects the peer flags below
	na                   *wire.NetAddress
	id                   int32
	userAgent            string
	services             wire.ServiceFlag
	versionKnown         bool
	advertisedProtoVer   uint32 // protocol version advertised by remote
	protocolVersion      uint32 // negotiated protocol version
	sendHeadersPreferred bool   // peer sent a sendheaders message
	verAckReceived       bool
	witnessEnabled       bool

	wireEncoding wire.MessageEncoding

	knownInventory     lru.Cache
	prevGetBlocksMtx   sync.Mutex
	prevGetBlocksBegin *chainhash.Hash
	prevGetBlocksStop  *chainhash.Hash
	prevGetHdrsMtx     sync.Mutex
	prevGetHdrsBegin   *chainhash.Hash
	prevGetHdrsStop    *chainhash.Hash

	// These fields keep track of statistics for the peer and are protected
	// by the statsMtx mutex.
	statsMtx           sync.RWMutex
	timeOffset         int64
	timeConnected      time.Time
	startingHeight     int32
	lastBlock          int32
	lastAnnouncedBlock *chainhash.Hash
	lastPingNonce      uint64    // Set to nonce if we have a pending ping.
	lastPingTime       time.Time // Time we sent last ping.
	lastPingMicros     int64     // Time for last ping to return.

	stallControl  chan stallControlMsg
	outputQueue   chan outMsg
	sendQueue     chan outMsg
	sendDoneQueue chan struct{}
	outputInvChan chan *wire.InvVect
	inQuit        chan struct{}
	queueQuit     chan struct{}
	outQuit       chan struct{}
	quit          chan struct{}
}

// String returns the peer's address and directionality as a human-readable
// string.
//
// This function is safe for concurrent access.
func (p *Peer) String() string {
	return fmt.Sprintf("%s (%s)", p.addr, directionString(p.inbound))
}

// UpdateLastBlockHeight updates the last known block for the peer.
//
// This function is safe for concurrent access.
func (p *Peer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.addr, p.lastBlock, newHeight)
	p.lastBlock = newHeight
	p.statsMtx.Unlock()
}

// UpdateLastAnnouncedBlock updates meta-data about the last block hash this
// peer is known to have announced.
//
// This function is safe for concurrent access.
func (p *Peer) UpdateLastAnnouncedBlock(blkHash *chainhash.Hash) {
	log.Tracef("Updating last blk for peer %v, %v", p.addr, blkHash)

	p.statsMtx.Lock()
	p.lastAnnouncedBlock = blkHash
	p.statsMtx.Unlock()
}

// AddKnownInventory adds the passed inventory to the cache of known inventory
// for the peer.
//
// This function is safe for concurrent access.
func (p *Peer) AddKnownInventory(invVect *wire.InvVect) {
	p.knownInventory.Add(invVect)
}

// StatsSnapshot returns a snapshot of the current peer flags and statistics.
//
// This function is safe for concurrent access.
func (p *Peer) StatsSnapshot() *StatsSnap {
	p.statsMtx.RLock()

	p.flagsMtx.Lock()
	id := p.id
	addr := p.addr
	userAgent := p.userAgent
	services := p.services
	protocolVersion := p.advertisedProtoVer
	p.flagsMtx.Unlock()

	// Get a copy of all relevant flags and stats.
	statsSnap := &StatsSnap{
		ID:             id,
		Addr:           addr,
		UserAgent:      userAgent,
		Services:       services,
		LastSend:       p.LastSend(),
		LastRecv:       p.LastRecv(),
		BytesSent:      p.BytesSent(),
		BytesRecv:      p.BytesReceived(),
		ConnTime:       p.timeConnected,
		TimeOffset:     p.timeOffset,
		Version:        protocolVersion,
		Inbound:        p.inbound,
		StartingHeight: p.startingHeight,
		LastBlock:      p.lastBlock,
		LastPingNonce:  p.lastPingNonce,
		LastPingMicros: p.lastPingMicros,
		LastPingTime:   p.lastPingTime,
	}

	p.statsMtx.RUnlock()
	return statsSnap
}

// ID returns the peer id.
//
// This function is safe for concurrent access.
func (p *Peer) ID() int32 {
	p.flagsMtx.Lock()
	id := p.id
	p.flagsMtx.Unlock()

	return id
}

// NA returns the peer network address.
//
// This function is safe for concurrent access.
func (p *Peer) NA() *wire.NetAddress {
	p.flagsMtx.Lock()
	na := p.na
	p.flagsMtx.Unlock()

	return na
}

// Addr returns the peer address.
//
// This function is safe for concurrent access.
func (p *Peer) Addr() string {
	// The address doesn't change after initialization, therefore it is not
	// protected by a mutex.
	return p.addr
}

// Inbound returns whether the peer is inbound.
//
// This function is safe for concurrent access.
func (p *Peer) Inbound() bool {
	return p.inbound
}

// Services returns the services flag of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) Services() wire.ServiceFlag {
	p.flagsMtx.Lock()
	services := p.services
	p.flagsMtx.Unlock()

	return services
}

// UserAgent returns the user agent of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) UserAgent() string {
	p.flagsMtx.Lock()
	userAgent := p.userAgent
	p.flagsMtx.Unlock()

	return userAgent
}

// LastAnnouncedBlock returns the last announced block of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastAnnouncedBlock() *chainhash.Hash {
	p.statsMtx.RLock()
	lastAnnouncedBlock := p.lastAnnouncedBlock
	p.statsMtx.RUnlock()

	return lastAnnouncedBlock
}

// LastPingNonce returns the last ping nonce of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastPingNonce() uint64 {
	p.statsMtx.RLock()
	lastPingNonce := p.lastPingNonce
	p.statsMtx.RUnlock()

	return lastPingNonce
}

// LastPingTime returns the last ping time of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastPingTime() time.Time {
	p.statsMtx.RLock()
	lastPingTime := p.lastPingTime
	p.statsMtx.RUnlock()

	return lastPingTime
}

// LastPingMicros returns the last ping micros of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastPingMicros() int64 {
	p.statsMtx.RLock()
	lastPingMicros := p.lastPingMicros
	p.statsMtx.RUnlock()

	return lastPingMicros
}

// VersionKnown returns the whether or not the version of a peer is known
// locally.
//
// This function is safe for concurrent access.
func (p *Peer) VersionKnown() bool {
	p.flagsMtx.Lock()
	versionKnown := p.versionKnown
	p.flagsMtx.Unlock()

	return versionKnown
}

// VerAckReceived returns whether or not a verack message was received by the
// peer.
//
// This function is safe for concurrent access.
func (p *Peer) VerAckReceived() bool {
	p.flagsMtx.Lock()
	verAckReceived := p.verAckReceived
	p.flagsMtx.Unlock()

	return verAckReceived
}

// ProtocolVersion returns the negotiated peer protocol version.
//
// This function is safe for concurrent access.
func (p *Peer) ProtocolVersion() uint32 {
	p.flagsMtx.Lock()
	protocolVersion := p.protocolVersion
	p.flagsMtx.Unlock()

	return protocolVersion
}

// LastBlock returns the last block of the peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastBlock() int32 {
	p.statsMtx.RLock()
	lastBlock := p.lastBlock
	p.statsMtx.RUnlock()

	return lastBlock
}

// LastSend returns the last send time of the peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastSend() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastSend), 0)
}

// LastRecv returns the last recv time of the peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastRecv() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastRecv), 0)
}

// LocalAddr returns the local address of the connection.
//
// This function is safe fo concurrent access.
func (p *Peer) LocalAddr() net.Addr {
	var localAddr net.Addr
	if atomic.LoadInt32(&p.connected) != 0 {
		localAddr = p.conn.LocalAddr()
	}
	return localAddr
}

// BytesSent returns the total number of bytes sent by the peer.
//
// This function is safe for concurrent access.
func (p *Peer) BytesSent() uint64 {
	return atomic.LoadUint64(&p.bytesSent)
}

// BytesReceived returns the total number of bytes received by the peer.
//
// This function is safe for concurrent access.
func (p *Peer) BytesReceived() uint64 {
	return atomic.LoadUint64(&p.bytesReceived)
}

// TimeConnected returns the time at which the peer connected.
//
// This function is safe for concurrent access.
func (p *Peer) TimeConnected() time.Time {
	p.statsMtx.RLock()
	timeConnected := p.timeConnected
	p.statsMtx.RUnlock()

	return timeConnected
}

// TimeOffset returns the number of seconds the local time was offset from the
// time the peer reported during the initial negotiation phase.  Negative values
// indicate the remote peer's time is before the local time.
//
// This function is safe for concurrent access.
func (p *Peer) TimeOffset() int64 {
	p.statsMtx.RLock()
	timeOffset := p.timeOffset
	p.statsMtx.RUnlock()

	return timeOffset
}

// StartingHeight returns the last known height the peer reported during the
// initial negotiation phase.
//
// This function is safe for concurrent access.
func (p *Peer) StartingHeight() int32 {
	p.statsMtx.RLock()
	startingHeight := p.startingHeight
	p.statsMtx.RUnlock()

	return startingHeight
}

// WantsHeaders returns if the peer wants header messages instead of
// inventory vectors for blocks.
//
// This function is safe for concurrent access.
func (p *Peer) WantsHeaders() bool {
	p.flagsMtx.Lock()
	sendHeadersPreferred := p.sendHeadersPreferred
	p.flagsMtx.Unlock()

	return sendHeadersPreferred
}

// IsWitnessEnabled returns true if the peer has signalled that it supports
// segregated witness.
//
// This function is safe for concurrent access.
func (p *Peer) IsWitnessEnabled() bool {
	p.flagsMtx.Lock()
	witnessEnabled := p.witnessEnabled
	p.flagsMtx.Unlock()

	return witnessEnabled
}

// PushAddrMsg sends an addr message to the connected peer using the provided
// addresses.  This function is useful over manually sending the message via
// QueueMessage since it automatically limits the addresses to the maximum
// number allowed by the message and randomizes the chosen addresses when there
// are too many.  It returns the addresses that were actually sent and no
// message will be sent if there are no entries in the provided addresses slice.
//
// This function is safe for concurrent access.
func (p *Peer) PushAddrMsg(addresses []*wire.NetAddress) ([]*wire.NetAddress, error) {
	addressCount := len(addresses)

	// Nothing to send.
	if addressCount == 0 {
		return nil, nil
	}

	msg := wire.NewMsgAddr()
	msg.AddrList = make([]*wire.NetAddress, addressCount)
	copy(msg.AddrList, addresses)

	// Randomize the addresses sent if there are more than the maximum allowed.
	if addressCount > wire.MaxAddrPerMsg {
		// Shuffle the address list.
		for i := 0; i < wire.MaxAddrPerMsg; i++ {
			j := i + rand.Intn(addressCount-i)
			msg.AddrList[i], msg.AddrList[j] = msg.AddrList[j], msg.AddrList[i]
		}

		// Truncate it to the maximum size.
		msg.AddrList = msg.AddrList[:wire.MaxAddrPerMsg]
	}

	p.QueueMessage(msg, nil)
	return msg.AddrList, nil
}

// PushGetBlocksMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
//
// This function is safe for concurrent access.
func (p *Peer) PushGetBlocksMsg(locator blockchain.BlockLocator, stopHash *chainhash.Hash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getblocks requests.
	var beginHash *chainhash.Hash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getblocks requests.
	p.prevGetBlocksMtx.Lock()
	isDuplicate := p.prevGetBlocksStop != nil && p.prevGetBlocksBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetBlocksStop) &&
		beginHash.IsEqual(p.prevGetBlocksBegin)
	p.prevGetBlocksMtx.Unlock()

	if isDuplicate {
		log.Tracef("Filtering duplicate [getblocks] with begin "+
			"hash %v, stop hash %v", beginHash, stopHash)
		return nil
	}

	// Construct the getblocks request and queue it to be sent.
	msg := wire.NewMsgGetBlocks(stopHash)
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	p.QueueMessage(msg, nil)

	// Update the previous getblocks request information for filtering
	// duplicates.
	p.prevGetBlocksMtx.Lock()
	p.prevGetBlocksBegin = beginHash
	p.prevGetBlocksStop = stopHash
	p.prevGetBlocksMtx.Unlock()
	return nil
}

// PushGetHeadersMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
//
// This function is safe for concurrent access.
func (p *Peer) PushGetHeadersMsg(locator blockchain.BlockLocator, stopHash *chainhash.Hash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getheaders requests.
	var beginHash *chainhash.Hash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getheaders requests.
	p.prevGetHdrsMtx.Lock()
	isDuplicate := p.prevGetHdrsStop != nil && p.prevGetHdrsBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetHdrsStop) &&
		beginHash.IsEqual(p.prevGetHdrsBegin)
	p.prevGetHdrsMtx.Unlock()

	if isDuplicate {
		log.Tracef("Filtering duplicate [getheaders] with begin hash %v",
			beginHash)
		return nil
	}

	// Construct the getheaders request and queue it to be sent.
	msg := wire.NewMsgGetHeaders()
	msg.HashStop = *stopHash
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	p.QueueMessage(msg, nil)

	// Update the previous getheaders request information for filtering
	// duplicates.
	p.prevGetHdrsMtx.Lock()
	p.prevGetHdrsBegin = beginHash
	p.prevGetHdrsStop = stopHash
	p.prevGetHdrsMtx.Unlock()
	return nil
}

// PushRejectMsg sends a reject message for the provided command, reject code,
// reject reason, and hash.  The hash will only be used when the command is a tx
// or block and should be nil in other cases.  The wait parameter will cause the
// function to block until the reject message has actually been sent.
//
// This function is safe for concurrent access.
func (p *Peer) PushRejectMsg(command string, code wire.RejectCode, reason string, hash *chainhash.Hash, wait bool) {
	// Don't bother sending the reject message if the protocol version
	// is too low.
	if p.VersionKnown() && p.ProtocolVersion() < wire.RejectVersion {
		return
	}

	msg := wire.NewMsgReject(command, code, reason)
	if command == wire.CmdTx || command == wire.CmdBlock {
		if hash == nil {
			log.Warnf("Sending a reject message for command "+
				"type %v which should have specified a hash "+
				"but does not", command)
			hash = &zeroHash
		}
		msg.Hash = *hash
	}

	// Send the message without waiting if the caller has not requested it.
	if !wait {
		p.QueueMessage(msg, nil)
		return
	}

	// Send the message and block until it has been sent before returning.
	doneChan := make(chan struct{}, 1)
	p.QueueMessage(msg, doneChan)
	<-doneChan
}

// handlePingMsg is invoked when a peer receives a ping bitcoin message.  For
// recent clients (protocol version > BIP0031Version), it replies with a pong
// message.  For older clients, it does nothing and anything other than failure
// is considered a successful ping.
func (p *Peer) handlePingMsg(msg *wire.MsgPing) {
	// Only reply with pong if the message is from a new enough client.
	if p.ProtocolVersion() > wire.BIP0031Version {
		// Include nonce from ping so pong can be identified.
		p.QueueMessage(wire.NewMsgPong(msg.Nonce), nil)
	}
}

// handlePongMsg is invoked when a peer receives a pong bitcoin message.  It
// updates the ping statistics as required for recent clients (protocol
// version > BIP0031Version).  There is no effect for older clients or when a
// ping was not previously sent.
func (p *Peer) handlePongMsg(msg *wire.MsgPong) {
	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping rpc call since we ping infrequently
	// enough that if they overlap we would have timed out the peer.
	if p.ProtocolVersion() > wire.BIP0031Version {
		p.statsMtx.Lock()
		if p.lastPingNonce != 0 && msg.Nonce == p.lastPingNonce {
			p.lastPingMicros = time.Since(p.lastPingTime).Nanoseconds()
			p.lastPingMicros /= 1000 // convert to usec.
			p.lastPingNonce = 0
		}
		p.statsMtx.Unlock()
	}
}

// readMessage reads the next bitcoin message from the peer with logging.
func (p *Peer) readMessage(encoding wire.MessageEncoding) (wire.Message, []byte, error) {
	n, msg, buf, err := wire.ReadMessageWithEncodingN(p.conn,
		p.ProtocolVersion(), p.cfg.ChainParams.Net, encoding)
	atomic.AddUint64(&p.bytesReceived, uint64(n))
	if p.cfg.Listeners.OnRead != nil {
		p.cfg.Listeners.OnRead(p, n, msg, err)
	}
	if err != nil {
		return nil, nil, err
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Received %v%s from %s",
			msg.Command(), summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(buf)
	}))

	return msg, buf, nil
}

// writeMessage sends a bitcoin message to the peer with logging.
func (p *Peer) writeMessage(msg wire.Message, enc wire.MessageEncoding) error {
	// Don't do anything if we're disconnecting.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return nil
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Sending %v%s to %s", msg.Command(),
			summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		var buf bytes.Buffer
		_, err := wire.WriteMessageWithEncodingN(&buf, msg, p.ProtocolVersion(),
			p.cfg.ChainParams.Net, enc)
		if err != nil {
			return err.Error()
		}
		return spew.Sdump(buf.Bytes())
	}))

	// Write the message to the peer.
	n, err := wire.WriteMessageWithEncodingN(p.conn, msg,
		p.ProtocolVersion(), p.cfg.ChainParams.Net, enc)
	atomic.AddUint64(&p.bytesSent, uint64(n))
	if p.cfg.Listeners.OnWrite != nil {
		p.cfg.Listeners.OnWrite(p, n, msg, err)
	}
	return err
}

// isAllowedReadError returns whether or not the passed error is allowed without
// disconnecting the peer.  In particular, regression tests need to be allowed
// to send malformed messages without the peer being disconnected.
func (p *Peer) isAllowedReadError(err error) bool {
	// Only allow read errors in regression test mode.
	if p.cfg.ChainParams.Net != wire.TestNet {
		return false
	}

	// Don't allow the error if it's not specifically a malformed message error.
	if _, ok := err.(*wire.MessageError); !ok {
		return false
	}

	// Don't allow the error if it's not coming from localhost or the
	// hostname can't be determined for some reason.
	host, _, err := net.SplitHostPort(p.addr)
	if err != nil {
		return false
	}

	if host != "127.0.0.1" && host != "localhost" {
		return false
	}

	// Allowed if all checks passed.
	return true
}

// shouldHandleReadError returns whether or not the passed error, which is
// expected to have come from reading from the remote peer in the inHandler,
// should be logged and responded to with a reject message.
func (p *Peer) shouldHandleReadError(err error) bool {
	// No logging or reject message when the peer is being forcibly
	// disconnected.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging or reject message when the remote peer has been
	// disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// maybeAddDeadline potentially adds a deadline for the appropriate expected
// response for the passed wire protocol command to the pending responses map.
func (p *Peer) maybeAddDeadline(pendingResponses map[string]time.Time, msgCmd string) {
	// Setup a deadline for each message being sent that expects a response.
	//
	// NOTE: Pings are intentionally ignored here since they are typically
	// sent asynchronously and as a result of a long backlock of messages,
	// such as is typical in the case of initial block download, the
	// response won't be received in time.
	deadline := time.Now().Add(stallResponseTimeout)
	switch msgCmd {
	case wire.CmdVersion:
		// Expects a verack message.
		pendingResponses[wire.CmdVerAck] = deadline

	case wire.CmdMemPool:
		// Expects an inv message.
		pendingResponses[wire.CmdInv] = deadline

	case wire.CmdGetBlocks:
		// Expects an inv message.
		pendingResponses[wire.CmdInv] = deadline

	case wire.CmdGetData:
		// Expects a block, merkleblock, tx, or notfound message.
		pendingResponses[wire.CmdBlock] = deadline
		pendingResponses[wire.CmdMerkleBlock] = deadline
		pendingResponses[wire.CmdTx] = deadline
		pendingResponses[wire.CmdNotFound] = deadline

	case wire.CmdGetHeaders:
		// Expects a headers message.  Use a longer deadline since it
		// can take a while for the remote peer to load all of the
		// headers.
		deadline = time.Now().Add(stallResponseTimeout * 3)
		pendingResponses[wire.CmdHeaders] = deadline
	}
}

// stallHandler handles stall detection for the peer.  This entails keeping
// track of expected responses and assigning them deadlines while accounting for
// the time spent in callbacks.  It must be run as a goroutine.
func (p *Peer) stallHandler() {
	// These variables are used to adjust the deadline times forward by the
	// time it takes callbacks to execute.  This is done because new
	// messages aren't read until the previous one is finished processing
	// (which includes callbacks), so the deadline for receiving a response
	// for a given message must account for the processing time as well.
	var handlerActive bool
	var handlersStartTime time.Time
	var deadlineOffset time.Duration

	// pendingResponses tracks the expected response deadline times.
	pendingResponses := make(map[string]time.Time)

	// stallTicker is used to periodically check pending responses that have
	// exceeded the expected deadline and disconnect the peer due to
	// stalling.
	stallTicker := time.NewTicker(stallTickInterval)
	defer stallTicker.Stop()

	// ioStopped is used to detect when both the input and output handler
	// goroutines are done.
	var ioStopped bool
out:
	for {
		select {
		case msg := <-p.stallControl:
			switch msg.command {
			case sccSendMessage:
				// Add a deadline for the expected response
				// message if needed.
				p.maybeAddDeadline(pendingResponses,
					msg.message.Command())

			case sccReceiveMessage:
				// Remove received messages from the expected
				// response map.  Since certain commands expect
				// one of a group of responses, remove
				// everything in the expected group accordingly.
				switch msgCmd := msg.message.Command(); msgCmd {
				case wire.CmdBlock:
					fallthrough
				case wire.CmdMerkleBlock:
					fallthrough
				case wire.CmdTx:
					fallthrough
				case wire.CmdNotFound:
					delete(pendingResponses, wire.CmdBlock)
					delete(pendingResponses, wire.CmdMerkleBlock)
					delete(pendingResponses, wire.CmdTx)
					delete(pendingResponses, wire.CmdNotFound)

				default:
					delete(pendingResponses, msgCmd)
				}

			case sccHandlerStart:
				// Warn on unbalanced callback signalling.
				if handlerActive {
					log.Warn("Received handler start " +
						"control command while a " +
						"handler is already active")
					continue
				}

				handlerActive = true
				handlersStartTime = time.Now()

			case sccHandlerDone:
				// Warn on unbalanced callback signalling.
				if !handlerActive {
					log.Warn("Received handler done " +
						"control command when a " +
						"handler is not already active")
					continue
				}

				// Extend active deadlines by the time it took
				// to execute the callback.
				duration := time.Since(handlersStartTime)
				deadlineOffset += duration
				handlerActive = false

			default:
				log.Warnf("Unsupported message command %v",
					msg.command)
			}

		case <-stallTicker.C:
			// Calculate the offset to apply to the deadline based
			// on how long the handlers have taken to execute since
			// the last tick.
			now := time.Now()
			offset := deadlineOffset
			if handlerActive {
				offset += now.Sub(handlersStartTime)
			}

			// Disconnect the peer if any of the pending responses
			// don't arrive by their adjusted deadline.
			for command, deadline := range pendingResponses {
				if now.Before(deadline.Add(offset)) {
					continue
				}

				log.Debugf("Peer %s appears to be stalled or "+
					"misbehaving, %s timeout -- "+
					"disconnecting", p, command)
				p.Disconnect()
				break
			}

			// Reset the deadline offset for the next tick.
			deadlineOffset = 0

		case <-p.inQuit:
			// The stall handler can exit once both the input and
			// output handler goroutines are done.
			if ioStopped {
				break out
			}
			ioStopped = true

		case <-p.outQuit:
			// The stall handler can exit once both the input and
			// output handler goroutines are done.
			if ioStopped {
				break out
			}
			ioStopped = true
		}
	}

	// Drain any wait channels before going away so there is nothing left
	// waiting on this goroutine.
cleanup:
	for {
		select {
		case <-p.stallControl:
		default:
			break cleanup
		}
	}
	log.Tracef("Peer stall handler done for %s", p)
}

// inHandler handles all incoming messages for the peer.  It must be run as a
// goroutine.
func (p *Peer) inHandler() {
	// The timer is stopped when a new message is received and reset after it
	// is processed.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		log.Warnf("Peer %s no answer for %s -- disconnecting", p, idleTimeout)
		p.Disconnect()
	})

out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		// Read a message and stop the idle timer as soon as the read
		// is done.  The timer is reset below for the next iteration if
		// needed.
		rmsg, buf, err := p.readMessage(p.wireEncoding)
		idleTimer.Stop()
		if err != nil {
			// In order to allow regression tests with malformed messages, don't
			// disconnect the peer when we're in regression test mode and the
			// error is one of the allowed errors.
			if p.isAllowedReadError(err) {
				log.Errorf("Allowed test error from %s: %v", p, err)
				idleTimer.Reset(idleTimeout)
				continue
			}

			// Only log the error and send reject message if the
			// local peer is not forcibly disconnecting and the
			// remote peer has not disconnected.
			if p.shouldHandleReadError(err) {
				errMsg := fmt.Sprintf("Can't read message from %s: %v", p, err)
				if err != io.ErrUnexpectedEOF {
					log.Errorf(errMsg)
				}

				// Push a reject message for the malformed message and wait for
				// the message to be sent before disconnecting.
				//
				// NOTE: Ideally this would include the command in the header if
				// at least that much of the message was valid, but that is not
				// currently exposed by wire, so just used malformed for the
				// command.
				p.PushRejectMsg("malformed", wire.RejectMalformed, errMsg, nil,
					true)
			}
			break out
		}
		atomic.StoreInt64(&p.lastRecv, time.Now().Unix())
		p.stallControl <- stallControlMsg{sccReceiveMessage, rmsg}

		// Handle each supported message type.
		p.stallControl <- stallControlMsg{sccHandlerStart, rmsg}
		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			// Limit to one version message per peer.
			p.PushRejectMsg(msg.Command(), wire.RejectDuplicate,
				"duplicate version message", nil, true)
			break out

		case *wire.MsgVerAck:
			// Limit to one verack message per peer.
			p.PushRejectMsg(
				msg.Command(), wire.RejectDuplicate,
				"duplicate verack message", nil, true,
			)
			break out

		case *wire.MsgGetAddr:
			if p.cfg.Listeners.OnGetAddr != nil {
				p.cfg.Listeners.OnGetAddr(p, msg)
			}

		case *wire.MsgAddr:
			if p.cfg.Listeners.OnAddr != nil {
				p.cfg.Listeners.OnAddr(p, msg)
			}

		case *wire.MsgPing:
			p.handlePingMsg(msg)
			if p.cfg.Listeners.OnPing != nil {
				p.cfg.Listeners.OnPing(p, msg)
			}

		case *wire.MsgPong:
			p.handlePongMsg(msg)
			if p.cfg.Listeners.OnPong != nil {
				p.cfg.Listeners.OnPong(p, msg)
			}

		case *wire.MsgAlert:
			if p.cfg.Listeners.OnAlert != nil {
				p.cfg.Listeners.OnAlert(p, msg)
			}

		case *wire.MsgMemPool:
			if p.cfg.Listeners.OnMemPool != nil {
				p.cfg.Listeners.OnMemPool(p, msg)
			}

		case *wire.MsgTx:
			if p.cfg.Listeners.OnTx != nil {
				p.cfg.Listeners.OnTx(p, msg)
			}

		case *wire.MsgBlock:
			if p.cfg.Listeners.OnBlock != nil {
				p.cfg.Listeners.OnBlock(p, msg, buf)
			}

		case *wire.MsgInv:
			if p.cfg.Listeners.OnInv != nil {
				p.cfg.Listeners.OnInv(p, msg)
			}

		case *wire.MsgHeaders:
			if p.cfg.Listeners.OnHeaders != nil {
				p.cfg.Listeners.OnHeaders(p, msg)
			}

		case *wire.MsgNotFound:
			if p.cfg.Listeners.OnNotFound != nil {
				p.cfg.Listeners.OnNotFound(p, msg)
			}

		case *wire.MsgGetData:
			if p.cfg.Listeners.OnGetData != nil {
				p.cfg.Listeners.OnGetData(p, msg)
			}

		case *wire.MsgGetBlocks:
			if p.cfg.Listeners.OnGetBlocks != nil {
				p.cfg.Listeners.OnGetBlocks(p, msg)
			}

		case *wire.MsgGetHeaders:
			if p.cfg.Listeners.OnGetHeaders != nil {
				p.cfg.Listeners.OnGetHeaders(p, msg)
			}

		case *wire.MsgGetCFilters:
			if p.cfg.Listeners.OnGetCFilters != nil {
				p.cfg.Listeners.OnGetCFilters(p, msg)
			}

		case *wire.MsgGetCFHeaders:
			if p.cfg.Listeners.OnGetCFHeaders != nil {
				p.cfg.Listeners.OnGetCFHeaders(p, msg)
			}

		case *wire.MsgGetCFCheckpt:
			if p.cfg.Listeners.OnGetCFCheckpt != nil {
				p.cfg.Listeners.OnGetCFCheckpt(p, msg)
			}

		case *wire.MsgCFilter:
			if p.cfg.Listeners.OnCFilter != nil {
				p.cfg.Listeners.OnCFilter(p, msg)
			}

		case *wire.MsgCFHeaders:
			if p.cfg.Listeners.OnCFHeaders != nil {
				p.cfg.Listeners.OnCFHeaders(p, msg)
			}

		case *wire.MsgFeeFilter:
			if p.cfg.Listeners.OnFeeFilter != nil {
				p.cfg.Listeners.OnFeeFilter(p, msg)
			}

		case *wire.MsgFilterAdd:
			if p.cfg.Listeners.OnFilterAdd != nil {
				p.cfg.Listeners.OnFilterAdd(p, msg)
			}

		case *wire.MsgFilterClear:
			if p.cfg.Listeners.OnFilterClear != nil {
				p.cfg.Listeners.OnFilterClear(p, msg)
			}

		case *wire.MsgFilterLoad:
			if p.cfg.Listeners.OnFilterLoad != nil {
				p.cfg.Listeners.OnFilterLoad(p, msg)
			}

		case *wire.MsgMerkleBlock:
			if p.cfg.Listeners.OnMerkleBlock != nil {
				p.cfg.Listeners.OnMerkleBlock(p, msg)
			}

		case *wire.MsgReject:
			if p.cfg.Listeners.OnReject != nil {
				p.cfg.Listeners.OnReject(p, msg)
			}

		case *wire.MsgSendHeaders:
			p.flagsMtx.Lock()
			p.sendHeadersPreferred = true
			p.flagsMtx.Unlock()

			if p.cfg.Listeners.OnSendHeaders != nil {
				p.cfg.Listeners.OnSendHeaders(p, msg)
			}

		default:
			log.Debugf("Received unhandled message of type %v "+
				"from %v", rmsg.Command(), p)
		}
		p.stallControl <- stallControlMsg{sccHandlerDone, rmsg}

		// A message was received so reset the idle timer.
		idleTimer.Reset(idleTimeout)
	}

	// Ensure the idle timer is stopped to avoid leaking the resource.
	idleTimer.Stop()

	// Ensure connection is closed.
	p.Disconnect()

	close(p.inQuit)
	log.Tracef("Peer input handler done for %s", p)
}

// queueHandler handles the queuing of outgoing data for the peer. This runs as
// a muxer for various sources of input so we can ensure that server and peer
// handlers will not block on us sending a message.  That data is then passed on
// to outHandler to be actually written.
func (p *Peer) queueHandler() {
	pendingMsgs := list.New()
	invSendQueue := list.New()
	trickleTicker := time.NewTicker(p.cfg.TrickleInterval)
	defer trickleTicker.Stop()

	// We keep the waiting flag so that we know if we have a message queued
	// to the outHandler or not.  We could use the presence of a head of
	// the list for this but then we have rather racy concerns about whether
	// it has gotten it at cleanup time - and thus who sends on the
	// message's done channel.  To avoid such confusion we keep a different
	// flag and pendingMsgs only contains messages that we have not yet
	// passed to outHandler.
	waiting := false

	// To avoid duplication below.
	queuePacket := func(msg outMsg, list *list.List, waiting bool) bool {
		if !waiting {
			p.sendQueue <- msg
		} else {
			list.PushBack(msg)
		}
		// we are always waiting now.
		return true
	}
out:
	for {
		select {
		case msg := <-p.outputQueue:
			waiting = queuePacket(msg, pendingMsgs, waiting)

		// This channel is notified when a message has been sent across
		// the network socket.
		case <-p.sendDoneQueue:
			// No longer waiting if there are no more messages
			// in the pending messages queue.
			next := pendingMsgs.Front()
			if next == nil {
				waiting = false
				continue
			}

			// Notify the outHandler about the next item to
			// asynchronously send.
			val := pendingMsgs.Remove(next)
			p.sendQueue <- val.(outMsg)

		case iv := <-p.outputInvChan:
			// No handshake?  They'll find out soon enough.
			if p.VersionKnown() {
				// If this is a new block, then we'll blast it
				// out immediately, sipping the inv trickle
				// queue.
				if iv.Type == wire.InvTypeBlock ||
					iv.Type == wire.InvTypeWitnessBlock {

					invMsg := wire.NewMsgInvSizeHint(1)
					invMsg.AddInvVect(iv)
					waiting = queuePacket(outMsg{msg: invMsg},
						pendingMsgs, waiting)
				} else {
					invSendQueue.PushBack(iv)
				}
			}

		case <-trickleTicker.C:
			// Don't send anything if we're disconnecting or there
			// is no queued inventory.
			// version is known if send queue has any entries.
			if atomic.LoadInt32(&p.disconnect) != 0 ||
				invSendQueue.Len() == 0 {
				continue
			}

			// Create and send as many inv messages as needed to
			// drain the inventory send queue.
			invMsg := wire.NewMsgInvSizeHint(uint(invSendQueue.Len()))
			for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
				iv := invSendQueue.Remove(e).(*wire.InvVect)

				// Don't send inventory that became known after
				// the initial check.
				if p.knownInventory.Contains(iv) {
					continue
				}

				invMsg.AddInvVect(iv)
				if len(invMsg.InvList) >= maxInvTrickleSize {
					waiting = queuePacket(
						outMsg{msg: invMsg},
						pendingMsgs, waiting)
					invMsg = wire.NewMsgInvSizeHint(uint(invSendQueue.Len()))
				}

				// Add the inventory that is being relayed to
				// the known inventory for the peer.
				p.AddKnownInventory(iv)
			}
			if len(invMsg.InvList) > 0 {
				waiting = queuePacket(outMsg{msg: invMsg},
					pendingMsgs, waiting)
			}

		case <-p.quit:
			break out
		}
	}

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us.
	for e := pendingMsgs.Front(); e != nil; e = pendingMsgs.Front() {
		val := pendingMsgs.Remove(e)
		msg := val.(outMsg)
		if msg.doneChan != nil {
			msg.doneChan <- struct{}{}
		}
	}
cleanup:
	for {
		select {
		case msg := <-p.outputQueue:
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
		case <-p.outputInvChan:
			// Just drain channel
		// sendDoneQueue is buffered so doesn't need draining.
		default:
			break cleanup
		}
	}
	close(p.queueQuit)
	log.Tracef("Peer queue handler done for %s", p)
}

// shouldLogWriteError returns whether or not the passed error, which is
// expected to have come from writing to the remote peer in the outHandler,
// should be logged.
func (p *Peer) shouldLogWriteError(err error) bool {
	// No logging when the peer is being forcibly disconnected.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging when the remote peer has been disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// outHandler handles all outgoing messages for the peer.  It must be run as a
// goroutine.  It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
func (p *Peer) outHandler() {
out:
	for {
		select {
		case msg := <-p.sendQueue:
			switch m := msg.msg.(type) {
			case *wire.MsgPing:
				// Only expects a pong message in later protocol
				// versions.  Also set up statistics.
				if p.ProtocolVersion() > wire.BIP0031Version {
					p.statsMtx.Lock()
					p.lastPingNonce = m.Nonce
					p.lastPingTime = time.Now()
					p.statsMtx.Unlock()
				}
			}

			p.stallControl <- stallControlMsg{sccSendMessage, msg.msg}

			err := p.writeMessage(msg.msg, msg.encoding)
			if err != nil {
				p.Disconnect()
				if p.shouldLogWriteError(err) {
					log.Errorf("Failed to send message to "+
						"%s: %v", p, err)
				}
				if msg.doneChan != nil {
					msg.doneChan <- struct{}{}
				}
				continue
			}

			// At this point, the message was successfully sent, so
			// update the last send time, signal the sender of the
			// message that it has been sent (if requested), and
			// signal the send queue to the deliver the next queued
			// message.
			atomic.StoreInt64(&p.lastSend, time.Now().Unix())
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			p.sendDoneQueue <- struct{}{}

		case <-p.quit:
			break out
		}
	}

	<-p.queueQuit

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us. We have waited on queueQuit and thus we can be sure
	// that we will not miss anything sent on sendQueue.
cleanup:
	for {
		select {
		case msg := <-p.sendQueue:
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			// no need to send on sendDoneQueue since queueHandler
			// has been waited on and already exited.
		default:
			break cleanup
		}
	}
	close(p.outQuit)
	log.Tracef("Peer output handler done for %s", p)
}

// pingHandler periodically pings the peer.  It must be run as a goroutine.
func (p *Peer) pingHandler() {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

out:
	for {
		select {
		case <-pingTicker.C:
			nonce, err := wire.RandomUint64()
			if err != nil {
				log.Errorf("Not sending ping to %s: %v", p, err)
				continue
			}
			p.QueueMessage(wire.NewMsgPing(nonce), nil)

		case <-p.quit:
			break out
		}
	}
}

// QueueMessage adds the passed bitcoin message to the peer send queue.
//
// This function is safe for concurrent access.
func (p *Peer) QueueMessage(msg wire.Message, doneChan chan<- struct{}) {
	p.QueueMessageWithEncoding(msg, doneChan, wire.BaseEncoding)
}

// QueueMessageWithEncoding adds the passed bitcoin message to the peer send
// queue. This function is identical to QueueMessage, however it allows the
// caller to specify the wire encoding type that should be used when
// encoding/decoding blocks and transactions.
//
// This function is safe for concurrent access.
func (p *Peer) QueueMessageWithEncoding(msg wire.Message, doneChan chan<- struct{},
	encoding wire.MessageEncoding) {

	// Avoid risk of deadlock if goroutine already exited.  The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected and *then* it drains the channels.
	if !p.Connected() {
		if doneChan != nil {
			go func() {
				doneChan <- struct{}{}
			}()
		}
		return
	}
	p.outputQueue <- outMsg{msg: msg, encoding: encoding, doneChan: doneChan}
}

// QueueInventory adds the passed inventory to the inventory send queue which
// might not be sent right away, rather it is trickled to the peer in batches.
// Inventory that the peer is already known to have is ignored.
//
// This function is safe for concurrent access.
func (p *Peer) QueueInventory(invVect *wire.InvVect) {
	// Don't add the inventory to the send queue if the peer is already
	// known to have it.
	if p.knownInventory.Contains(invVect) {
		return
	}

	// Avoid risk of deadlock if goroutine already exited.  The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected and *then* it drains the channels.
	if !p.Connected() {
		return
	}

	p.outputInvChan <- invVect
}

// Connected returns whether or not the peer is currently connected.
//
// This function is safe for concurrent access.
func (p *Peer) Connected() bool {
	return atomic.LoadInt32(&p.connected) != 0 &&
		atomic.LoadInt32(&p.disconnect) == 0
}

// Disconnect disconnects the peer by closing the connection.  Calling this
// function when the peer is already disconnected or in the process of
// disconnecting will have no effect.
func (p *Peer) Disconnect() {
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	log.Tracef("Disconnecting %s", p)
	if atomic.LoadInt32(&p.connected) != 0 {
		p.conn.Close()
	}
	close(p.quit)
}

// readRemoteVersionMsg waits for the next message to arrive from the remote
// peer.  If the next message is not a version message or the version is not
// acceptable then return an error.
func (p *Peer) readRemoteVersionMsg() error {
	// Read their version message.
	remoteMsg, _, err := p.readMessage(wire.LatestEncoding)
	if err != nil {
		return err
	}

	// Notify and disconnect clients if the first message is not a version
	// message.
	msg, ok := remoteMsg.(*wire.MsgVersion)
	if !ok {
		reason := "a version message must precede all others"
		rejectMsg := wire.NewMsgReject(msg.Command(), wire.RejectMalformed,
			reason)
		_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
		return errors.New(reason)
	}

	// Detect self connections.
	if !allowSelfConns && sentNonces.Contains(msg.Nonce) {
		return errors.New("disconnecting peer connected to self")
	}

	// Negotiate the protocol version and set the services to what the remote
	// peer advertised.
	p.flagsMtx.Lock()
	p.advertisedProtoVer = uint32(msg.ProtocolVersion)
	p.protocolVersion = minUint32(p.protocolVersion, p.advertisedProtoVer)
	p.versionKnown = true
	p.services = msg.Services
	p.flagsMtx.Unlock()
	log.Debugf("Negotiated protocol version %d for peer %s",
		p.protocolVersion, p)

	// Updating a bunch of stats including block based stats, and the
	// peer's time offset.
	p.statsMtx.Lock()
	p.lastBlock = msg.LastBlock
	p.startingHeight = msg.LastBlock
	p.timeOffset = msg.Timestamp.Unix() - time.Now().Unix()
	p.statsMtx.Unlock()

	// Set the peer's ID, user agent, and potentially the flag which
	// specifies the witness support is enabled.
	p.flagsMtx.Lock()
	p.id = atomic.AddInt32(&nodeCount, 1)
	p.userAgent = msg.UserAgent

	// Determine if the peer would like to receive witness data with
	// transactions, or not.
	if p.services&wire.SFNodeWitness == wire.SFNodeWitness {
		p.witnessEnabled = true
	}
	p.flagsMtx.Unlock()

	// Once the version message has been exchanged, we're able to determine
	// if this peer knows how to encode witness data over the wire
	// protocol. If so, then we'll switch to a decoding mode which is
	// prepared for the new transaction format introduced as part of
	// BIP0144.
	if p.services&wire.SFNodeWitness == wire.SFNodeWitness {
		p.wireEncoding = wire.WitnessEncoding
	}

	// Invoke the callback if specified.
	if p.cfg.Listeners.OnVersion != nil {
		rejectMsg := p.cfg.Listeners.OnVersion(p, msg)
		if rejectMsg != nil {
			_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
			return errors.New(rejectMsg.Reason)
		}
	}

	// Notify and disconnect clients that have a protocol version that is
	// too old.
	//
	// NOTE: If minAcceptableProtocolVersion is raised to be higher than
	// wire.RejectVersion, this should send a reject packet before
	// disconnecting.
	if uint32(msg.ProtocolVersion) < MinAcceptableProtocolVersion {
		// Send a reject message indicating the protocol version is
		// obsolete and wait for the message to be sent before
		// disconnecting.
		reason := fmt.Sprintf("protocol version must be %d or greater",
			MinAcceptableProtocolVersion)
		rejectMsg := wire.NewMsgReject(msg.Command(), wire.RejectObsolete,
			reason)
		_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
		return errors.New(reason)
	}

	return nil
}

// readRemoteVerAckMsg waits for the next message to arrive from the remote
// peer. If this message is not a verack message, then an error is returned.
// This method is to be used as part of the version negotiation upon a new
// connection.
func (p *Peer) readRemoteVerAckMsg() error {
	// Read the next message from the wire.
	remoteMsg, _, err := p.readMessage(wire.LatestEncoding)
	if err != nil {
		return err
	}

	// It should be a verack message, otherwise send a reject message to the
	// peer explaining why.
	msg, ok := remoteMsg.(*wire.MsgVerAck)
	if !ok {
		reason := "a verack message must follow version"
		rejectMsg := wire.NewMsgReject(
			msg.Command(), wire.RejectMalformed, reason,
		)
		_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
		return errors.New(reason)
	}

	p.flagsMtx.Lock()
	p.verAckReceived = true
	p.flagsMtx.Unlock()

	if p.cfg.Listeners.OnVerAck != nil {
		p.cfg.Listeners.OnVerAck(p, msg)
	}

	return nil
}

// localVersionMsg creates a version message that can be used to send to the
// remote peer.
func (p *Peer) localVersionMsg() (*wire.MsgVersion, error) {
	var blockNum int32
	if p.cfg.NewestBlock != nil {
		var err error
		_, blockNum, err = p.cfg.NewestBlock()
		if err != nil {
			return nil, err
		}
	}

	theirNA := p.na

	// If we are behind a proxy and the connection comes from the proxy then
	// we return an unroutable address as their address. This is to prevent
	// leaking the tor proxy address.
	if p.cfg.Proxy != "" {
		proxyaddress, _, err := net.SplitHostPort(p.cfg.Proxy)
		// invalid proxy means poorly configured, be on the safe side.
		if err != nil || p.na.IP.String() == proxyaddress {
			theirNA = wire.NewNetAddressIPPort(net.IP([]byte{0, 0, 0, 0}), 0,
				theirNA.Services)
		}
	}

	// Create a wire.NetAddress with only the services set to use as the
	// "addrme" in the version message.
	//
	// Older nodes previously added the IP and port information to the
	// address manager which proved to be unreliable as an inbound
	// connection from a peer didn't necessarily mean the peer itself
	// accepted inbound connections.
	//
	// Also, the timestamp is unused in the version message.
	ourNA := &wire.NetAddress{
		Services: p.cfg.Services,
	}

	// Generate a unique nonce for this peer so self connections can be
	// detected.  This is accomplished by adding it to a size-limited map of
	// recently seen nonces.
	nonce := uint64(rand.Int63())
	sentNonces.Add(nonce)

	// Version message.
	msg := wire.NewMsgVersion(ourNA, theirNA, nonce, blockNum)
	msg.AddUserAgent(p.cfg.UserAgentName, p.cfg.UserAgentVersion,
		p.cfg.UserAgentComments...)

	// Advertise local services.
	msg.Services = p.cfg.Services

	// Advertise our max supported protocol version.
	msg.ProtocolVersion = int32(p.cfg.ProtocolVersion)

	// Advertise if inv messages for transactions are desired.
	msg.DisableRelayTx = p.cfg.DisableRelayTx

	return msg, nil
}

// writeLocalVersionMsg writes our version message to the remote peer.
func (p *Peer) writeLocalVersionMsg() error {
	localVerMsg, err := p.localVersionMsg()
	if err != nil {
		return err
	}

	return p.writeMessage(localVerMsg, wire.LatestEncoding)
}

// negotiateInboundProtocol performs the negotiation protocol for an inbound
// peer. The events should occur in the following order, otherwise an error is
// returned:
//
//   1. Remote peer sends their version.
//   2. We send our version.
//   3. We send our verack.
//   4. Remote peer sends their verack.
func (p *Peer) negotiateInboundProtocol() error {
	if err := p.readRemoteVersionMsg(); err != nil {
		return err
	}

	if err := p.writeLocalVersionMsg(); err != nil {
		return err
	}

	err := p.writeMessage(wire.NewMsgVerAck(), wire.LatestEncoding)
	if err != nil {
		return err
	}

	return p.readRemoteVerAckMsg()
}

// negotiateOutboundProtocol performs the negotiation protocol for an outbound
// peer. The events should occur in the following order, otherwise an error is
// returned:
//
//   1. We send our version.
//   2. Remote peer sends their version.
//   3. Remote peer sends their verack.
//   4. We send our verack.
func (p *Peer) negotiateOutboundProtocol() error {
	if err := p.writeLocalVersionMsg(); err != nil {
		return err
	}

	if err := p.readRemoteVersionMsg(); err != nil {
		return err
	}

	if err := p.readRemoteVerAckMsg(); err != nil {
		return err
	}

	return p.writeMessage(wire.NewMsgVerAck(), wire.LatestEncoding)
}

// start begins processing input and output messages.
func (p *Peer) start() error {
	log.Tracef("Starting peer %s", p)

	negotiateErr := make(chan error, 1)
	go func() {
		if p.inbound {
			negotiateErr <- p.negotiateInboundProtocol()
		} else {
			negotiateErr <- p.negotiateOutboundProtocol()
		}
	}()

	// Negotiate the protocol within the specified negotiateTimeout.
	select {
	case err := <-negotiateErr:
		if err != nil {
			p.Disconnect()
			return err
		}
	case <-time.After(negotiateTimeout):
		p.Disconnect()
		return errors.New("protocol negotiation timeout")
	}
	log.Debugf("Connected to %s", p.Addr())

	// The protocol has been negotiated successfully so start processing input
	// and output messages.
	go p.stallHandler()
	go p.inHandler()
	go p.queueHandler()
	go p.outHandler()
	go p.pingHandler()

	return nil
}

// AssociateConnection associates the given conn to the peer.   Calling this
// function when the peer is already connected will have no effect.
func (p *Peer) AssociateConnection(conn net.Conn) {
	// Already connected?
	if !atomic.CompareAndSwapInt32(&p.connected, 0, 1) {
		return
	}

	p.conn = conn
	p.timeConnected = time.Now()

	if p.inbound {
		p.addr = p.conn.RemoteAddr().String()

		// Set up a NetAddress for the peer to be used with AddrManager.  We
		// only do this inbound because outbound set this up at connection time
		// and no point recomputing.
		na, err := newNetAddress(p.conn.RemoteAddr(), p.services)
		if err != nil {
			log.Errorf("Cannot create remote net address: %v", err)
			p.Disconnect()
			return
		}
		p.na = na
	}

	go func() {
		if err := p.start(); err != nil {
			log.Debugf("Cannot start peer %v: %v", p, err)
			p.Disconnect()
		}
	}()
}

// WaitForDisconnect waits until the peer has completely disconnected and all
// resources are cleaned up.  This will happen if either the local or remote
// side has been disconnected or the peer is forcibly disconnected via
// Disconnect.
func (p *Peer) WaitForDisconnect() {
	<-p.quit
}

// newPeerBase returns a new base bitcoin peer based on the inbound flag.  This
// is used by the NewInboundPeer and NewOutboundPeer functions to perform base
// setup needed by both types of peers.
func newPeerBase(origCfg *Config, inbound bool) *Peer {
	// Default to the max supported protocol version if not specified by the
	// caller.
	cfg := *origCfg // Copy to avoid mutating caller.
	if cfg.ProtocolVersion == 0 {
		cfg.ProtocolVersion = MaxProtocolVersion
	}

	// Set the chain parameters to testnet if the caller did not specify any.
	if cfg.ChainParams == nil {
		cfg.ChainParams = &chaincfg.TestNet3Params
	}

	// Set the trickle interval if a non-positive value is specified.
	if cfg.TrickleInterval <= 0 {
		cfg.TrickleInterval = DefaultTrickleInterval
	}

	p := Peer{
		inbound:         inbound,
		wireEncoding:    wire.BaseEncoding,
		knownInventory:  lru.NewCache(maxKnownInventory),
		stallControl:    make(chan stallControlMsg, 1), // nonblocking sync
		outputQueue:     make(chan outMsg, outputBufferSize),
		sendQueue:       make(chan outMsg, 1),   // nonblocking sync
		sendDoneQueue:   make(chan struct{}, 1), // nonblocking sync
		outputInvChan:   make(chan *wire.InvVect, outputBufferSize),
		inQuit:          make(chan struct{}),
		queueQuit:       make(chan struct{}),
		outQuit:         make(chan struct{}),
		quit:            make(chan struct{}),
		cfg:             cfg, // Copy so caller can't mutate.
		services:        cfg.Services,
		protocolVersion: cfg.ProtocolVersion,
	}
	return &p
}

// NewInboundPeer returns a new inbound bitcoin peer. Use Start to begin
// processing incoming and outgoing messages.
func NewInboundPeer(cfg *Config) *Peer {
	return newPeerBase(cfg, true)
}

// NewOutboundPeer returns a new outbound bitcoin peer.
func NewOutboundPeer(cfg *Config, addr string) (*Peer, error) {
	p := newPeerBase(cfg, false)
	p.addr = addr

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	if cfg.HostToNetAddress != nil {
		na, err := cfg.HostToNetAddress(host, uint16(port), 0)
		if err != nil {
			return nil, err
		}
		p.na = na
	} else {
		p.na = wire.NewNetAddressIPPort(net.ParseIP(host), uint16(port), 0)
	}

	return p, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
