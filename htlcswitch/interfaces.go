package htlcswitch

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
)

// InvoiceDatabase is an interface which represents the persistent subsystem
// which may search, lookup and settle invoices.
type InvoiceDatabase interface {
	// LookupInvoice attempts to look up an invoice according to its 32
	// byte payment hash.
	LookupInvoice(lntypes.Hash) (channeldb.Invoice, error)

	// NotifyExitHopHtlc attempts to mark an invoice as settled. If the
	// invoice is a debug invoice, then this method is a noop as debug
	// invoices are never fully settled. The return value describes how the
	// htlc should be resolved. If the htlc cannot be resolved immediately,
	// the resolution is sent on the passed in hodlChan later. The eob
	// field passes the entire onion hop payload into the invoice registry
	// for decoding purposes.
	NotifyExitHopHtlc(payHash lntypes.Hash, paidAmount lnwire.MilliSatoshi,
		expiry uint32, currentHeight int32,
		circuitKey channeldb.CircuitKey, hodlChan chan<- interface{},
		payload invoices.Payload) (invoices.HtlcResolution, error)

	// CancelInvoice attempts to cancel the invoice corresponding to the
	// passed payment hash.
	CancelInvoice(payHash lntypes.Hash) error

	// SettleHodlInvoice settles a hold invoice.
	SettleHodlInvoice(preimage lntypes.Preimage) error

	// HodlUnsubscribeAll unsubscribes from all htlc resolutions.
	HodlUnsubscribeAll(subscriber chan<- interface{})
}

// ChannelLink is an interface which represents the subsystem for managing the
// incoming htlc requests, applying the changes to the channel, and also
// propagating/forwarding it to htlc switch.
//
//  abstraction level
//       ^
//       |
//       | - - - - - - - - - - - - Lightning - - - - - - - - - - - - -
//       |
//       | (Switch)		     (Switch)		       (Switch)
//       |  Alice <-- channel link --> Bob <-- channel link --> Carol
//       |
//       | - - - - - - - - - - - - - TCP - - - - - - - - - - - - - - -
//       |
//       |  (Peer) 		     (Peer)	                (Peer)
//       |  Alice <----- tcp conn --> Bob <---- tcp conn -----> Carol
//       |
//
type ChannelLink interface {
	// TODO(roasbeef): modify interface to embed mail boxes?

	// HandleSwitchPacket handles the switch packets. This packets might be
	// forwarded to us from another channel link in case the htlc update
	// came from another peer or if the update was created by user
	// initially.
	//
	// NOTE: This function MUST be non-blocking (or block as little as
	// possible).
	HandleSwitchPacket(*htlcPacket) error

	// HandleLocalAddPacket handles a locally-initiated UpdateAddHTLC
	// packet. It will be processed synchronously.
	HandleLocalAddPacket(*htlcPacket) error

	// HandleChannelUpdate handles the htlc requests as settle/add/fail
	// which sent to us from remote peer we have a channel with.
	//
	// NOTE: This function MUST be non-blocking (or block as little as
	// possible).
	HandleChannelUpdate(lnwire.Message)

	// ChannelPoint returns the channel outpoint for the channel link.
	ChannelPoint() *wire.OutPoint

	// ChanID returns the channel ID for the channel link. The channel ID
	// is a more compact representation of a channel's full outpoint.
	ChanID() lnwire.ChannelID

	// ShortChanID returns the short channel ID for the channel link. The
	// short channel ID encodes the exact location in the main chain that
	// the original funding output can be found.
	ShortChanID() lnwire.ShortChannelID

	// UpdateShortChanID updates the short channel ID for a link. This may
	// be required in the event that a link is created before the short
	// chan ID for it is known, or a re-org occurs, and the funding
	// transaction changes location within the chain.
	UpdateShortChanID() (lnwire.ShortChannelID, error)

	// UpdateForwardingPolicy updates the forwarding policy for the target
	// ChannelLink. Once updated, the link will use the new forwarding
	// policy to govern if it an incoming HTLC should be forwarded or not.
	UpdateForwardingPolicy(ForwardingPolicy)

	// CheckHtlcForward should return a nil error if the passed HTLC details
	// satisfy the current forwarding policy fo the target link. Otherwise,
	// a LinkError with a valid protocol failure message should be returned
	// in order to signal to the source of the HTLC, the policy consistency
	// issue.
	CheckHtlcForward(payHash [32]byte, incomingAmt lnwire.MilliSatoshi,
		amtToForward lnwire.MilliSatoshi,
		incomingTimeout, outgoingTimeout uint32,
		heightNow uint32) *LinkError

	// CheckHtlcTransit should return a nil error if the passed HTLC details
	// satisfy the current channel policy.  Otherwise, a LinkError with a
	// valid protocol failure message should be returned in order to signal
	// the violation. This call is intended to be used for locally initiated
	// payments for which there is no corresponding incoming htlc.
	CheckHtlcTransit(payHash [32]byte, amt lnwire.MilliSatoshi,
		timeout uint32, heightNow uint32) *LinkError

	// Bandwidth returns the amount of milli-satoshis which current link
	// might pass through channel link. The value returned from this method
	// represents the up to date available flow through the channel. This
	// takes into account any forwarded but un-cleared HTLC's, and any
	// HTLC's which have been set to the over flow queue.
	Bandwidth() lnwire.MilliSatoshi

	// Stats return the statistics of channel link. Number of updates,
	// total sent/received milli-satoshis.
	Stats() (uint64, lnwire.MilliSatoshi, lnwire.MilliSatoshi)

	// Peer returns the representation of remote peer with which we have
	// the channel link opened.
	Peer() lnpeer.Peer

	// EligibleToForward returns a bool indicating if the channel is able
	// to actively accept requests to forward HTLC's. A channel may be
	// active, but not able to forward HTLC's if it hasn't yet finalized
	// the pre-channel operation protocol with the remote peer. The switch
	// will use this function in forwarding decisions accordingly.
	EligibleToForward() bool

	// MayAddOutgoingHtlc returns an error if we may not add an outgoing
	// htlc to the channel. This check does not reserve a space, since
	// forwards or other payments may use the available slot, so it should
	// be considered best effort.
	MayAddOutgoingHtlc(amt lnwire.MilliSatoshi) error

	// AttachMailBox delivers an active MailBox to the link. The MailBox may
	// have buffered messages.
	AttachMailBox(MailBox)

	// Start/Stop are used to initiate the start/stop of the channel link
	// functioning.
	Start() error
	Stop()
}

// ForwardingLog is an interface that represents a time series database which
// keep track of all successfully completed payment circuits. Every few
// seconds, the switch will collate and flush out all the successful payment
// circuits during the last interval.
type ForwardingLog interface {
	// AddForwardingEvents is a method that should write out the set of
	// forwarding events in a batch to persistent storage. Outside
	// sub-systems can then query the contents of the log for analysis,
	// visualizations, etc.
	AddForwardingEvents([]channeldb.ForwardingEvent) error
}

// TowerClient is the primary interface used by the daemon to backup pre-signed
// justice transactions to watchtowers.
type TowerClient interface {
	// RegisterChannel persistently initializes any channel-dependent
	// parameters within the client. This should be called during link
	// startup to ensure that the client is able to support the link during
	// operation.
	RegisterChannel(lnwire.ChannelID) error

	// BackupState initiates a request to back up a particular revoked
	// state. If the method returns nil, the backup is guaranteed to be
	// successful unless the tower is unavailable and client is force quit,
	// or the justice transaction would create dust outputs when trying to
	// abide by the negotiated policy. If the channel we're trying to back
	// up doesn't have a tweak for the remote party's output, then
	// isTweakless should be true.
	BackupState(*lnwire.ChannelID, *lnwallet.BreachRetribution,
		channeldb.ChannelType) error
}

// InterceptableHtlcForwarder is the interface to set the interceptor
// implementation that intercepts htlc forwards.
type InterceptableHtlcForwarder interface {
	// SetInterceptor sets a ForwardInterceptor.
	SetInterceptor(interceptor ForwardInterceptor)
}

// ForwardInterceptor is a function that is invoked from the switch for every
// incoming htlc that is intended to be forwarded. It is passed with the
// InterceptedForward that contains the information about the packet and a way
// to resolve it manually later in case it is held.
// The return value indicates if this handler will take control of this forward
// and resolve it later or let the switch execute its default behavior.
type ForwardInterceptor func(InterceptedForward) bool

// InterceptedPacket contains the relevant information for the interceptor about
// an htlc.
type InterceptedPacket struct {
	// IncomingCircuit contains the incoming channel and htlc id of the
	// packet.
	IncomingCircuit channeldb.CircuitKey

	// OutgoingChanID is the destination channel for this packet.
	OutgoingChanID lnwire.ShortChannelID

	// Hash is the payment hash of the htlc.
	Hash lntypes.Hash

	// OutgoingExpiry is the absolute block height at which the outgoing
	// htlc expires.
	OutgoingExpiry uint32

	// OutgoingAmount is the amount to forward.
	OutgoingAmount lnwire.MilliSatoshi

	// IncomingExpiry is the absolute block height at which the incoming
	// htlc expires.
	IncomingExpiry uint32

	// IncomingAmount is the amount of the accepted htlc.
	IncomingAmount lnwire.MilliSatoshi

	// CustomRecords are user-defined records in the custom type range that
	// were included in the payload.
	CustomRecords record.CustomSet

	// OnionBlob is the onion packet for the next hop
	OnionBlob [lnwire.OnionPacketSize]byte
}

// InterceptedForward is passed to the ForwardInterceptor for every forwarded
// htlc. It contains all the information about the packet which accordingly
// the interceptor decides if to hold or not.
// In addition this interface allows a later resolution by calling either
// Resume, Settle or Fail.
type InterceptedForward interface {
	// Packet returns the intercepted packet.
	Packet() InterceptedPacket

	// Resume notifies the intention to resume an existing hold forward. This
	// basically means the caller wants to resume with the default behavior for
	// this htlc which usually means forward it.
	Resume() error

	// Settle notifies the intention to settle an existing hold
	// forward with a given preimage.
	Settle(lntypes.Preimage) error

	// Fails notifies the intention to fail an existing hold forward
	Fail() error
}

// htlcNotifier is an interface which represents the input side of the
// HtlcNotifier which htlc events are piped through. This interface is intended
// to allow for mocking of the htlcNotifier in tests, so is unexported because
// it is not needed outside of the htlcSwitch package.
type htlcNotifier interface {
	// NotifyForwardingEvent notifies the HtlcNotifier than a htlc has been
	// forwarded.
	NotifyForwardingEvent(key HtlcKey, info HtlcInfo,
		eventType HtlcEventType)

	// NotifyIncomingLinkFailEvent notifies that a htlc has failed on our
	// incoming link. It takes an isReceive bool to differentiate between
	// our node's receives and forwards.
	NotifyLinkFailEvent(key HtlcKey, info HtlcInfo,
		eventType HtlcEventType, linkErr *LinkError, incoming bool)

	// NotifyForwardingFailEvent notifies the HtlcNotifier that a htlc we
	// forwarded has failed down the line.
	NotifyForwardingFailEvent(key HtlcKey, eventType HtlcEventType)

	// NotifySettleEvent notifies the HtlcNotifier that a htlc that we
	// committed to as part of a forward or a receive to our node has been
	// settled.
	NotifySettleEvent(key HtlcKey, preimage lntypes.Preimage,
		eventType HtlcEventType)
}
