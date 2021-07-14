package peer

import (
	"net"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
)

// LinkUpdater is an interface implemented by most messages in BOLT 2 that are
// allowed to update the channel state.
type LinkUpdater interface {
	// TargetChanID returns the channel id of the link for which this message
	// is intended.
	TargetChanID() lnwire.ChannelID
}

// MessageConn is an interface implemented by anything that delivers
// an lnwire.Message using a net.Conn interface.
type MessageConn interface {
	// RemoteAddr returns the remote address on the other end of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address on our end of the connection.
	LocalAddr() net.Addr

	// Read reads bytes from the connection.
	Read([]byte) (int, error)

	// Write writes bytes to the connection.
	Write([]byte) (int, error)

	// SetDeadline sets the deadline for the connection.
	SetDeadline(time.Time) error

	// SetReadDeadline sets the read deadline.
	SetReadDeadline(time.Time) error

	// SetWriteDeadline sets the write deadline.
	SetWriteDeadline(time.Time) error

	// Close closes the connection.
	Close() error

	// Flush attempts a flush.
	Flush() (int, error)

	// WriteMessage writes the message.
	WriteMessage([]byte) error

	// ReadNextHeader reads the next header.
	ReadNextHeader() (uint32, error)

	// ReadNextBody reads the next body.
	ReadNextBody([]byte) ([]byte, error)
}

// MessageLink is an interface that contains some functionality from a
// htlcswitch.ChannelLink.
type MessageLink interface {
	// ChanID returns the ChannelID of the MessageLink.
	ChanID() lnwire.ChannelID

	// HandleChannelUpdate passes lnwire.Message to the MessageLink.
	HandleChannelUpdate(lnwire.Message)
}

// MessageSwitch is an interface that manages setup, retrieval, and shutdown of
// MessageLink implementations.
type MessageSwitch interface {
	// BestHeight returns the best height known to the MessageSwitch.
	BestHeight() uint32

	// CircuitModifier returns a reference to a CircuitModifier.
	CircuitModifier() htlcswitch.CircuitModifier

	// GetLink retrieves a MessageLink given a ChannelID.
	GetLink(lnwire.ChannelID) (MessageLink, error)

	// InitLink creates a link given a ChannelLinkConfig and
	// LightningChannel.
	InitLink(htlcswitch.ChannelLinkConfig,
		*lnwallet.LightningChannel) error

	// RemoveLink removes a MessageLink from the MessageSwitch given a
	// ChannelID.
	RemoveLink(lnwire.ChannelID)
}

// ChannelGraph is an interface that abstracts the network graph.
type ChannelGraph interface {
	// FetchChannelEdgesByOutpoint queries for channel information given an
	// outpoint.
	FetchChannelEdgesByOutpoint(*wire.OutPoint) (
		*channeldb.ChannelEdgeInfo, *channeldb.ChannelEdgePolicy,
		*channeldb.ChannelEdgePolicy, error)
}

// StatusManager is an interface that abstracts the subsystem that deals with
// enabling and disabling of a channel via ChannelUpdate's disabled bit.
type StatusManager interface {
	// RequestEnable attempts to enable a channel.
	RequestEnable(wire.OutPoint, bool) error

	// RequestDisable attempts to disable a channel.
	RequestDisable(wire.OutPoint, bool) error
}

// ChainArbitrator is an interface that abstracts the subsystem that manages
// on-chain handling related to our channels.
type ChainArbitrator interface {
	// SubscribeChannelEvents subscribes to the set of on-chain events for
	// a channel.
	SubscribeChannelEvents(wire.OutPoint) (
		*contractcourt.ChainEventSubscription, error)

	// UpdateContractSignals updates the contract signals that updates to
	// the channel will be sent over.
	UpdateContractSignals(wire.OutPoint,
		*contractcourt.ContractSignals) error

	// ForceCloseContract attempts to force close the channel.
	ForceCloseContract(wire.OutPoint) (*wire.MsgTx, error)
}

// Sphinx is an interface that abstracts the decryption of onion blobs.
type Sphinx interface {
	// DecodeHopIterators batch decodes HTLC onion blobs.
	DecodeHopIterators([]byte, []hop.DecodeHopIteratorRequest) (
		[]hop.DecodeHopIteratorResponse, error)

	// ExtractErrorEncrypter creates an ErrorEncrypter instance using a
	// derived shared secret.
	ExtractErrorEncrypter(*btcec.PublicKey) (hop.ErrorEncrypter,
		lnwire.FailCode)
}

// Gossiper is an interface that abstracts the subsystem that handles the
// gossiping protocol.
type Gossiper interface {
	// InitSyncState initializes a gossip syncer for a given peer that
	// understands channel range queries.
	InitSyncState(lnpeer.Peer)

	// ProcessRemoteAnnouncement processes a remote message intended for
	// the Gossiper.
	ProcessRemoteAnnouncement(lnwire.Message, lnpeer.Peer) chan error
}

// Funding is an interface that abstracts the funding process.
type Funding interface {
	// ProcessFundingMsg processes a funding message represented by the
	// lnwire.Message parameter along with the Peer object representing a
	// connection to the counterparty.
	ProcessFundingMsg(lnwire.Message, lnpeer.Peer)

	// IsPendingChannel returns whether a particular 32-byte identifier
	// represents a pending channel in the Funding implementation.
	IsPendingChannel([32]byte, lnpeer.Peer) bool
}
