package htlcswitch

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	prand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/queue"
	"github.com/lightningnetwork/lnd/ticker"
)

func init() {
	prand.Seed(time.Now().UnixNano())
}

const (
	// DefaultMaxOutgoingCltvExpiry is the maximum outgoing time lock that
	// the node accepts for forwarded payments. The value is relative to the
	// current block height. The reason to have a maximum is to prevent
	// funds getting locked up unreasonably long. Otherwise, an attacker
	// willing to lock its own funds too, could force the funds of this node
	// to be locked up for an indefinite (max int32) number of blocks.
	//
	// The value 2016 corresponds to on average two weeks worth of blocks
	// and is based on the maximum number of hops (20), the default CLTV
	// delta (40), and some extra margin to account for the other lightning
	// implementations and past lnd versions which used to have a default
	// CLTV delta of 144.
	DefaultMaxOutgoingCltvExpiry = 2016

	// DefaultMinLinkFeeUpdateTimeout represents the minimum interval in
	// which a link should propose to update its commitment fee rate.
	DefaultMinLinkFeeUpdateTimeout = 10 * time.Minute

	// DefaultMaxLinkFeeUpdateTimeout represents the maximum interval in
	// which a link should propose to update its commitment fee rate.
	DefaultMaxLinkFeeUpdateTimeout = 60 * time.Minute

	// DefaultMaxLinkFeeAllocation is the highest allocation we'll allow
	// a channel's commitment fee to be of its balance. This only applies to
	// the initiator of the channel.
	DefaultMaxLinkFeeAllocation float64 = 0.5
)

// ForwardingPolicy describes the set of constraints that a given ChannelLink
// is to adhere to when forwarding HTLC's. For each incoming HTLC, this set of
// constraints will be consulted in order to ensure that adequate fees are
// paid, and our time-lock parameters are respected. In the event that an
// incoming HTLC violates any of these constraints, it is to be _rejected_ with
// the error possibly carrying along a ChannelUpdate message that includes the
// latest policy.
type ForwardingPolicy struct {
	// MinHTLC is the smallest HTLC that is to be forwarded.
	MinHTLCOut lnwire.MilliSatoshi

	// MaxHTLC is the largest HTLC that is to be forwarded.
	MaxHTLC lnwire.MilliSatoshi

	// BaseFee is the base fee, expressed in milli-satoshi that must be
	// paid for each incoming HTLC. This field, combined with FeeRate is
	// used to compute the required fee for a given HTLC.
	BaseFee lnwire.MilliSatoshi

	// FeeRate is the fee rate, expressed in milli-satoshi that must be
	// paid for each incoming HTLC. This field combined with BaseFee is
	// used to compute the required fee for a given HTLC.
	FeeRate lnwire.MilliSatoshi

	// TimeLockDelta is the absolute time-lock value, expressed in blocks,
	// that will be subtracted from an incoming HTLC's timelock value to
	// create the time-lock value for the forwarded outgoing HTLC. The
	// following constraint MUST hold for an HTLC to be forwarded:
	//
	//  * incomingHtlc.timeLock - timeLockDelta = fwdInfo.OutgoingCTLV
	//
	//    where fwdInfo is the forwarding information extracted from the
	//    per-hop payload of the incoming HTLC's onion packet.
	TimeLockDelta uint32

	// TODO(roasbeef): add fee module inside of switch
}

// ExpectedFee computes the expected fee for a given htlc amount. The value
// returned from this function is to be used as a sanity check when forwarding
// HTLC's to ensure that an incoming HTLC properly adheres to our propagated
// forwarding policy.
//
// TODO(roasbeef): also add in current available channel bandwidth, inverse
// func
func ExpectedFee(f ForwardingPolicy,
	htlcAmt lnwire.MilliSatoshi) lnwire.MilliSatoshi {

	return f.BaseFee + (htlcAmt*f.FeeRate)/1000000
}

// ChannelLinkConfig defines the configuration for the channel link. ALL
// elements within the configuration MUST be non-nil for channel link to carry
// out its duties.
type ChannelLinkConfig struct {
	// FwrdingPolicy is the initial forwarding policy to be used when
	// deciding whether to forwarding incoming HTLC's or not. This value
	// can be updated with subsequent calls to UpdateForwardingPolicy
	// targeted at a given ChannelLink concrete interface implementation.
	FwrdingPolicy ForwardingPolicy

	// Circuits provides restricted access to the switch's circuit map,
	// allowing the link to open and close circuits.
	Circuits CircuitModifier

	// Switch provides a reference to the HTLC switch, we only use this in
	// testing to access circuit operations not typically exposed by the
	// CircuitModifier.
	//
	// TODO(conner): remove after refactoring htlcswitch testing framework.
	Switch *Switch

	// BestHeight returns the best known height.
	BestHeight func() uint32

	// ForwardPackets attempts to forward the batch of htlcs through the
	// switch. The function returns and error in case it fails to send one or
	// more packets. The link's quit signal should be provided to allow
	// cancellation of forwarding during link shutdown.
	ForwardPackets func(chan struct{}, ...*htlcPacket) error

	// DecodeHopIterators facilitates batched decoding of HTLC Sphinx onion
	// blobs, which are then used to inform how to forward an HTLC.
	//
	// NOTE: This function assumes the same set of readers and preimages
	// are always presented for the same identifier.
	DecodeHopIterators func([]byte, []hop.DecodeHopIteratorRequest) (
		[]hop.DecodeHopIteratorResponse, error)

	// ExtractErrorEncrypter function is responsible for decoding HTLC
	// Sphinx onion blob, and creating onion failure obfuscator.
	ExtractErrorEncrypter hop.ErrorEncrypterExtracter

	// FetchLastChannelUpdate retrieves the latest routing policy for a
	// target channel. This channel will typically be the outgoing channel
	// specified when we receive an incoming HTLC.  This will be used to
	// provide payment senders our latest policy when sending encrypted
	// error messages.
	FetchLastChannelUpdate func(lnwire.ShortChannelID) (*lnwire.ChannelUpdate, error)

	// Peer is a lightning network node with which we have the channel link
	// opened.
	Peer lnpeer.Peer

	// Registry is a sub-system which responsible for managing the invoices
	// in thread-safe manner.
	Registry InvoiceDatabase

	// PreimageCache is a global witness beacon that houses any new
	// preimages discovered by other links. We'll use this to add new
	// witnesses that we discover which will notify any sub-systems
	// subscribed to new events.
	PreimageCache contractcourt.WitnessBeacon

	// OnChannelFailure is a function closure that we'll call if the
	// channel failed for some reason. Depending on the severity of the
	// error, the closure potentially must force close this channel and
	// disconnect the peer.
	//
	// NOTE: The method must return in order for the ChannelLink to be able
	// to shut down properly.
	OnChannelFailure func(lnwire.ChannelID, lnwire.ShortChannelID,
		LinkFailureError)

	// UpdateContractSignals is a function closure that we'll use to update
	// outside sub-systems with the latest signals for our inner Lightning
	// channel. These signals will notify the caller when the channel has
	// been closed, or when the set of active HTLC's is updated.
	UpdateContractSignals func(*contractcourt.ContractSignals) error

	// ChainEvents is an active subscription to the chain watcher for this
	// channel to be notified of any on-chain activity related to this
	// channel.
	ChainEvents *contractcourt.ChainEventSubscription

	// FeeEstimator is an instance of a live fee estimator which will be
	// used to dynamically regulate the current fee of the commitment
	// transaction to ensure timely confirmation.
	FeeEstimator chainfee.Estimator

	// hodl.Mask is a bitvector composed of hodl.Flags, specifying breakpoints
	// for HTLC forwarding internal to the switch.
	//
	// NOTE: This should only be used for testing.
	HodlMask hodl.Mask

	// SyncStates is used to indicate that we need send the channel
	// reestablishment message to the remote peer. It should be done if our
	// clients have been restarted, or remote peer have been reconnected.
	SyncStates bool

	// BatchTicker is the ticker that determines the interval that we'll
	// use to check the batch to see if there're any updates we should
	// flush out. By batching updates into a single commit, we attempt to
	// increase throughput by maximizing the number of updates coalesced
	// into a single commit.
	BatchTicker ticker.Ticker

	// FwdPkgGCTicker is the ticker determining the frequency at which
	// garbage collection of forwarding packages occurs. We use a
	// time-based approach, as opposed to block epochs, as to not hinder
	// syncing.
	FwdPkgGCTicker ticker.Ticker

	// PendingCommitTicker is a ticker that allows the link to determine if
	// a locally initiated commitment dance gets stuck waiting for the
	// remote party to revoke.
	PendingCommitTicker ticker.Ticker

	// BatchSize is the max size of a batch of updates done to the link
	// before we do a state update.
	BatchSize uint32

	// UnsafeReplay will cause a link to replay the adds in its latest
	// commitment txn after the link is restarted. This should only be used
	// in testing, it is here to ensure the sphinx replay detection on the
	// receiving node is persistent.
	UnsafeReplay bool

	// MinFeeUpdateTimeout represents the minimum interval in which a link
	// will propose to update its commitment fee rate. A random timeout will
	// be selected between this and MaxFeeUpdateTimeout.
	MinFeeUpdateTimeout time.Duration

	// MaxFeeUpdateTimeout represents the maximum interval in which a link
	// will propose to update its commitment fee rate. A random timeout will
	// be selected between this and MinFeeUpdateTimeout.
	MaxFeeUpdateTimeout time.Duration

	// OutgoingCltvRejectDelta defines the number of blocks before expiry of
	// an htlc where we don't offer an htlc anymore. This should be at least
	// the outgoing broadcast delta, because in any case we don't want to
	// risk offering an htlc that triggers channel closure.
	OutgoingCltvRejectDelta uint32

	// TowerClient is an optional engine that manages the signing,
	// encrypting, and uploading of justice transactions to the daemon's
	// configured set of watchtowers for legacy channels.
	TowerClient TowerClient

	// MaxOutgoingCltvExpiry is the maximum outgoing timelock that the link
	// should accept for a forwarded HTLC. The value is relative to the
	// current block height.
	MaxOutgoingCltvExpiry uint32

	// MaxFeeAllocation is the highest allocation we'll allow a channel's
	// commitment fee to be of its balance. This only applies to the
	// initiator of the channel.
	MaxFeeAllocation float64

	// MaxAnchorsCommitFeeRate is the max commitment fee rate we'll use as
	// the initiator for channels of the anchor type.
	MaxAnchorsCommitFeeRate chainfee.SatPerKWeight

	// NotifyActiveLink allows the link to tell the ChannelNotifier when a
	// link is first started.
	NotifyActiveLink func(wire.OutPoint)

	// NotifyActiveChannel allows the link to tell the ChannelNotifier when
	// channels becomes active.
	NotifyActiveChannel func(wire.OutPoint)

	// NotifyInactiveChannel allows the switch to tell the ChannelNotifier
	// when channels become inactive.
	NotifyInactiveChannel func(wire.OutPoint)

	// HtlcNotifier is an instance of a htlcNotifier which we will pipe htlc
	// events through.
	HtlcNotifier htlcNotifier
}

// localUpdateAddMsg contains a locally initiated htlc and a channel that will
// receive the outcome of the link processing. This channel must be buffered to
// prevent the link from blocking.
type localUpdateAddMsg struct {
	pkt *htlcPacket
	err chan error
}

// channelLink is the service which drives a channel's commitment update
// state-machine. In the event that an HTLC needs to be propagated to another
// link, the forward handler from config is used which sends HTLC to the
// switch. Additionally, the link encapsulate logic of commitment protocol
// message ordering and updates.
type channelLink struct {
	// The following fields are only meant to be used *atomically*
	started       int32
	reestablished int32
	shutdown      int32

	// failed should be set to true in case a link error happens, making
	// sure we don't process any more updates.
	failed bool

	// keystoneBatch represents a volatile list of keystones that must be
	// written before attempting to sign the next commitment txn. These
	// represent all the HTLC's forwarded to the link from the switch. Once
	// we lock them into our outgoing commitment, then the circuit has a
	// keystone, and is fully opened.
	keystoneBatch []Keystone

	// openedCircuits is the set of all payment circuits that will be open
	// once we make our next commitment. After making the commitment we'll
	// ACK all these from our mailbox to ensure that they don't get
	// re-delivered if we reconnect.
	openedCircuits []CircuitKey

	// closedCircuits is the set of all payment circuits that will be
	// closed once we make our next commitment. After taking the commitment
	// we'll ACK all these to ensure that they don't get re-delivered if we
	// reconnect.
	closedCircuits []CircuitKey

	// channel is a lightning network channel to which we apply htlc
	// updates.
	channel *lnwallet.LightningChannel

	// shortChanID is the most up to date short channel ID for the link.
	shortChanID lnwire.ShortChannelID

	// cfg is a structure which carries all dependable fields/handlers
	// which may affect behaviour of the service.
	cfg ChannelLinkConfig

	// mailBox is the main interface between the outside world and the
	// link. All incoming messages will be sent over this mailBox. Messages
	// include new updates from our connected peer, and new packets to be
	// forwarded sent by the switch.
	mailBox MailBox

	// upstream is a channel that new messages sent from the remote peer to
	// the local peer will be sent across.
	upstream chan lnwire.Message

	// downstream is a channel in which new multi-hop HTLC's to be
	// forwarded will be sent across. Messages from this channel are sent
	// by the HTLC switch.
	downstream chan *htlcPacket

	// localUpdateAdd is a channel to which locally initiated HTLCs are
	// sent across.
	localUpdateAdd chan *localUpdateAddMsg

	// htlcUpdates is a channel that we'll use to update outside
	// sub-systems with the latest set of active HTLC's on our channel.
	htlcUpdates chan *contractcourt.ContractUpdate

	// updateFeeTimer is the timer responsible for updating the link's
	// commitment fee every time it fires.
	updateFeeTimer *time.Timer

	// uncommittedPreimages stores a list of all preimages that have been
	// learned since receiving the last CommitSig from the remote peer. The
	// batch will be flushed just before accepting the subsequent CommitSig
	// or on shutdown to avoid doing a write for each preimage received.
	uncommittedPreimages []lntypes.Preimage

	sync.RWMutex

	// hodlQueue is used to receive exit hop htlc resolutions from invoice
	// registry.
	hodlQueue *queue.ConcurrentQueue

	// hodlMap stores related htlc data for a circuit key. It allows
	// resolving those htlcs when we receive a message on hodlQueue.
	hodlMap map[channeldb.CircuitKey]hodlHtlc

	// log is a link-specific logging instance.
	log btclog.Logger

	wg   sync.WaitGroup
	quit chan struct{}
}

// hodlHtlc contains htlc data that is required for resolution.
type hodlHtlc struct {
	pd         *lnwallet.PaymentDescriptor
	obfuscator hop.ErrorEncrypter
}

// NewChannelLink creates a new instance of a ChannelLink given a configuration
// and active channel that will be used to verify/apply updates to.
func NewChannelLink(cfg ChannelLinkConfig,
	channel *lnwallet.LightningChannel) ChannelLink {

	logPrefix := fmt.Sprintf("ChannelLink(%v):", channel.ShortChanID())

	return &channelLink{
		cfg:         cfg,
		channel:     channel,
		shortChanID: channel.ShortChanID(),
		// TODO(roasbeef): just do reserve here?
		htlcUpdates:    make(chan *contractcourt.ContractUpdate),
		hodlMap:        make(map[channeldb.CircuitKey]hodlHtlc),
		hodlQueue:      queue.NewConcurrentQueue(10),
		log:            build.NewPrefixLog(logPrefix, log),
		quit:           make(chan struct{}),
		localUpdateAdd: make(chan *localUpdateAddMsg),
	}
}

// A compile time check to ensure channelLink implements the ChannelLink
// interface.
var _ ChannelLink = (*channelLink)(nil)

// Start starts all helper goroutines required for the operation of the channel
// link.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) Start() error {
	if !atomic.CompareAndSwapInt32(&l.started, 0, 1) {
		err := errors.Errorf("channel link(%v): already started", l)
		l.log.Warn("already started")
		return err
	}

	l.log.Info("starting")

	// If the config supplied watchtower client, ensure the channel is
	// registered before trying to use it during operation.
	if l.cfg.TowerClient != nil {
		err := l.cfg.TowerClient.RegisterChannel(l.ChanID())
		if err != nil {
			return err
		}
	}

	l.mailBox.ResetMessages()
	l.hodlQueue.Start()

	// Before launching the htlcManager messages, revert any circuits that
	// were marked open in the switch's circuit map, but did not make it
	// into a commitment txn. We use the next local htlc index as the cut
	// off point, since all indexes below that are committed. This action
	// is only performed if the link's final short channel ID has been
	// assigned, otherwise we would try to trim the htlcs belonging to the
	// all-zero, hop.Source ID.
	if l.ShortChanID() != hop.Source {
		localHtlcIndex, err := l.channel.NextLocalHtlcIndex()
		if err != nil {
			return fmt.Errorf("unable to retrieve next local "+
				"htlc index: %v", err)
		}

		// NOTE: This is automatically done by the switch when it
		// starts up, but is necessary to prevent inconsistencies in
		// the case that the link flaps. This is a result of a link's
		// life-cycle being shorter than that of the switch.
		chanID := l.ShortChanID()
		err = l.cfg.Circuits.TrimOpenCircuits(chanID, localHtlcIndex)
		if err != nil {
			return fmt.Errorf("unable to trim circuits above "+
				"local htlc index %d: %v", localHtlcIndex, err)
		}

		// Since the link is live, before we start the link we'll update
		// the ChainArbitrator with the set of new channel signals for
		// this channel.
		//
		// TODO(roasbeef): split goroutines within channel arb to avoid
		go func() {
			signals := &contractcourt.ContractSignals{
				HtlcUpdates: l.htlcUpdates,
				ShortChanID: l.channel.ShortChanID(),
			}

			err := l.cfg.UpdateContractSignals(signals)
			if err != nil {
				l.log.Errorf("unable to update signals")
			}
		}()
	}

	l.updateFeeTimer = time.NewTimer(l.randomFeeUpdateTimeout())

	l.wg.Add(1)
	go l.htlcManager()

	return nil
}

// Stop gracefully stops all active helper goroutines, then waits until they've
// exited.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) Stop() {
	if !atomic.CompareAndSwapInt32(&l.shutdown, 0, 1) {
		l.log.Warn("already stopped")
		return
	}

	l.log.Info("stopping")

	// As the link is stopping, we are no longer interested in htlc
	// resolutions coming from the invoice registry.
	l.cfg.Registry.HodlUnsubscribeAll(l.hodlQueue.ChanIn())

	if l.cfg.ChainEvents.Cancel != nil {
		l.cfg.ChainEvents.Cancel()
	}

	// Ensure the channel for the timer is drained.
	if !l.updateFeeTimer.Stop() {
		select {
		case <-l.updateFeeTimer.C:
		default:
		}
	}

	l.hodlQueue.Stop()

	close(l.quit)
	l.wg.Wait()

	// Now that the htlcManager has completely exited, reset the packet
	// courier. This allows the mailbox to revaluate any lingering Adds that
	// were delivered but didn't make it on a commitment to be failed back
	// if the link is offline for an extended period of time. The error is
	// ignored since it can only fail when the daemon is exiting.
	_ = l.mailBox.ResetPackets()

	// As a final precaution, we will attempt to flush any uncommitted
	// preimages to the preimage cache. The preimages should be re-delivered
	// after channel reestablishment, however this adds an extra layer of
	// protection in case the peer never returns. Without this, we will be
	// unable to settle any contracts depending on the preimages even though
	// we had learned them at some point.
	err := l.cfg.PreimageCache.AddPreimages(l.uncommittedPreimages...)
	if err != nil {
		l.log.Errorf("unable to add preimages=%v to cache: %v",
			l.uncommittedPreimages, err)
	}
}

// WaitForShutdown blocks until the link finishes shutting down, which includes
// termination of all dependent goroutines.
func (l *channelLink) WaitForShutdown() {
	l.wg.Wait()
}

// EligibleToForward returns a bool indicating if the channel is able to
// actively accept requests to forward HTLC's. We're able to forward HTLC's if
// we know the remote party's next revocation point. Otherwise, we can't
// initiate new channel state. We also require that the short channel ID not be
// the all-zero source ID, meaning that the channel has had its ID finalized.
func (l *channelLink) EligibleToForward() bool {
	return l.channel.RemoteNextRevocation() != nil &&
		l.ShortChanID() != hop.Source &&
		l.isReestablished()
}

// isReestablished returns true if the link has successfully completed the
// channel reestablishment dance.
func (l *channelLink) isReestablished() bool {
	return atomic.LoadInt32(&l.reestablished) == 1
}

// markReestablished signals that the remote peer has successfully exchanged
// channel reestablish messages and that the channel is ready to process
// subsequent messages.
func (l *channelLink) markReestablished() {
	atomic.StoreInt32(&l.reestablished, 1)
}

// sampleNetworkFee samples the current fee rate on the network to get into the
// chain in a timely manner. The returned value is expressed in fee-per-kw, as
// this is the native rate used when computing the fee for commitment
// transactions, and the second-level HTLC transactions.
func (l *channelLink) sampleNetworkFee() (chainfee.SatPerKWeight, error) {
	// We'll first query for the sat/kw recommended to be confirmed within 3
	// blocks.
	feePerKw, err := l.cfg.FeeEstimator.EstimateFeePerKW(3)
	if err != nil {
		return 0, err
	}

	l.log.Debugf("sampled fee rate for 3 block conf: %v sat/kw",
		int64(feePerKw))

	return feePerKw, nil
}

// shouldAdjustCommitFee returns true if we should update our commitment fee to
// match that of the network fee. We'll only update our commitment fee if the
// network fee is +/- 10% to our network fee.
func shouldAdjustCommitFee(netFee, chanFee chainfee.SatPerKWeight) bool {
	switch {
	// If the network fee is greater than the commitment fee, then we'll
	// switch to it if it's at least 10% greater than the commit fee.
	case netFee > chanFee && netFee >= (chanFee+(chanFee*10)/100):
		return true

	// If the network fee is less than our commitment fee, then we'll
	// switch to it if it's at least 10% less than the commitment fee.
	case netFee < chanFee && netFee <= (chanFee-(chanFee*10)/100):
		return true

	// Otherwise, we won't modify our fee.
	default:
		return false
	}
}

// createFailureWithUpdate retrieves this link's last channel update message and
// passes it into the callback. It expects a fully populated failure message.
func (l *channelLink) createFailureWithUpdate(
	cb func(update *lnwire.ChannelUpdate) lnwire.FailureMessage) lnwire.FailureMessage {

	update, err := l.cfg.FetchLastChannelUpdate(l.ShortChanID())
	if err != nil {
		return &lnwire.FailTemporaryNodeFailure{}
	}

	return cb(update)
}

// syncChanState attempts to synchronize channel states with the remote party.
// This method is to be called upon reconnection after the initial funding
// flow. We'll compare out commitment chains with the remote party, and re-send
// either a danging commit signature, a revocation, or both.
func (l *channelLink) syncChanStates() error {
	l.log.Info("attempting to re-synchronize")

	// First, we'll generate our ChanSync message to send to the other
	// side. Based on this message, the remote party will decide if they
	// need to retransmit any data or not.
	chanState := l.channel.State()
	localChanSyncMsg, err := chanState.ChanSyncMsg()
	if err != nil {
		return fmt.Errorf("unable to generate chan sync message for "+
			"ChannelPoint(%v)", l.channel.ChannelPoint())
	}

	if err := l.cfg.Peer.SendMessage(true, localChanSyncMsg); err != nil {
		return fmt.Errorf("unable to send chan sync message for "+
			"ChannelPoint(%v): %v", l.channel.ChannelPoint(), err)
	}

	var msgsToReSend []lnwire.Message

	// Next, we'll wait indefinitely to receive the ChanSync message. The
	// first message sent MUST be the ChanSync message.
	select {
	case msg := <-l.upstream:
		remoteChanSyncMsg, ok := msg.(*lnwire.ChannelReestablish)
		if !ok {
			return fmt.Errorf("first message sent to sync "+
				"should be ChannelReestablish, instead "+
				"received: %T", msg)
		}

		// If the remote party indicates that they think we haven't
		// done any state updates yet, then we'll retransmit the
		// funding locked message first. We do this, as at this point
		// we can't be sure if they've really received the
		// FundingLocked message.
		if remoteChanSyncMsg.NextLocalCommitHeight == 1 &&
			localChanSyncMsg.NextLocalCommitHeight == 1 &&
			!l.channel.IsPending() {

			l.log.Infof("resending FundingLocked message to peer")

			nextRevocation, err := l.channel.NextRevocationKey()
			if err != nil {
				return fmt.Errorf("unable to create next "+
					"revocation: %v", err)
			}

			fundingLockedMsg := lnwire.NewFundingLocked(
				l.ChanID(), nextRevocation,
			)
			err = l.cfg.Peer.SendMessage(false, fundingLockedMsg)
			if err != nil {
				return fmt.Errorf("unable to re-send "+
					"FundingLocked: %v", err)
			}
		}

		// In any case, we'll then process their ChanSync message.
		l.log.Info("received re-establishment message from remote side")

		var (
			openedCircuits []CircuitKey
			closedCircuits []CircuitKey
		)

		// We've just received a ChanSync message from the remote
		// party, so we'll process the message  in order to determine
		// if we need to re-transmit any messages to the remote party.
		msgsToReSend, openedCircuits, closedCircuits, err =
			l.channel.ProcessChanSyncMsg(remoteChanSyncMsg)
		if err != nil {
			return err
		}

		// Repopulate any identifiers for circuits that may have been
		// opened or unclosed. This may happen if we needed to
		// retransmit a commitment signature message.
		l.openedCircuits = openedCircuits
		l.closedCircuits = closedCircuits

		// Ensure that all packets have been have been removed from the
		// link's mailbox.
		if err := l.ackDownStreamPackets(); err != nil {
			return err
		}

		if len(msgsToReSend) > 0 {
			l.log.Infof("sending %v updates to synchronize the "+
				"state", len(msgsToReSend))
		}

		// If we have any messages to retransmit, we'll do so
		// immediately so we return to a synchronized state as soon as
		// possible.
		for _, msg := range msgsToReSend {
			l.cfg.Peer.SendMessage(false, msg)
		}

	case <-l.quit:
		return ErrLinkShuttingDown
	}

	return nil
}

// resolveFwdPkgs loads any forwarding packages for this link from disk, and
// reprocesses them in order. The primary goal is to make sure that any HTLCs
// we previously received are reinstated in memory, and forwarded to the switch
// if necessary. After a restart, this will also delete any previously
// completed packages.
func (l *channelLink) resolveFwdPkgs() error {
	fwdPkgs, err := l.channel.LoadFwdPkgs()
	if err != nil {
		return err
	}

	l.log.Debugf("loaded %d fwd pks", len(fwdPkgs))

	for _, fwdPkg := range fwdPkgs {
		if err := l.resolveFwdPkg(fwdPkg); err != nil {
			return err
		}
	}

	// If any of our reprocessing steps require an update to the commitment
	// txn, we initiate a state transition to capture all relevant changes.
	if l.channel.PendingLocalUpdateCount() > 0 {
		return l.updateCommitTx()
	}

	return nil
}

// resolveFwdPkg interprets the FwdState of the provided package, either
// reprocesses any outstanding htlcs in the package, or performs garbage
// collection on the package.
func (l *channelLink) resolveFwdPkg(fwdPkg *channeldb.FwdPkg) error {
	// Remove any completed packages to clear up space.
	if fwdPkg.State == channeldb.FwdStateCompleted {
		l.log.Debugf("removing completed fwd pkg for height=%d",
			fwdPkg.Height)

		err := l.channel.RemoveFwdPkgs(fwdPkg.Height)
		if err != nil {
			l.log.Errorf("unable to remove fwd pkg for height=%d: "+
				"%v", fwdPkg.Height, err)
			return err
		}
	}

	// Otherwise this is either a new package or one has gone through
	// processing, but contains htlcs that need to be restored in memory.
	// We replay this forwarding package to make sure our local mem state
	// is resurrected, we mimic any original responses back to the remote
	// party, and re-forward the relevant HTLCs to the switch.

	// If the package is fully acked but not completed, it must still have
	// settles and fails to propagate.
	if !fwdPkg.SettleFailFilter.IsFull() {
		settleFails, err := lnwallet.PayDescsFromRemoteLogUpdates(
			fwdPkg.Source, fwdPkg.Height, fwdPkg.SettleFails,
		)
		if err != nil {
			l.log.Errorf("unable to process remote log updates: %v",
				err)
			return err
		}
		l.processRemoteSettleFails(fwdPkg, settleFails)
	}

	// Finally, replay *ALL ADDS* in this forwarding package. The
	// downstream logic is able to filter out any duplicates, but we must
	// shove the entire, original set of adds down the pipeline so that the
	// batch of adds presented to the sphinx router does not ever change.
	if !fwdPkg.AckFilter.IsFull() {
		adds, err := lnwallet.PayDescsFromRemoteLogUpdates(
			fwdPkg.Source, fwdPkg.Height, fwdPkg.Adds,
		)
		if err != nil {
			l.log.Errorf("unable to process remote log updates: %v",
				err)
			return err
		}
		l.processRemoteAdds(fwdPkg, adds)

		// If the link failed during processing the adds, we must
		// return to ensure we won't attempted to update the state
		// further.
		if l.failed {
			return fmt.Errorf("link failed while " +
				"processing remote adds")
		}
	}

	return nil
}

// fwdPkgGarbager periodically reads all forwarding packages from disk and
// removes those that can be discarded. It is safe to do this entirely in the
// background, since all state is coordinated on disk. This also ensures the
// link can continue to process messages and interleave database accesses.
//
// NOTE: This MUST be run as a goroutine.
func (l *channelLink) fwdPkgGarbager() {
	defer l.wg.Done()

	l.cfg.FwdPkgGCTicker.Resume()
	defer l.cfg.FwdPkgGCTicker.Stop()

	if err := l.loadAndRemove(); err != nil {
		l.log.Warnf("unable to run initial fwd pkgs gc: %v", err)
	}

	for {
		select {
		case <-l.cfg.FwdPkgGCTicker.Ticks():
			if err := l.loadAndRemove(); err != nil {
				l.log.Warnf("unable to remove fwd pkgs: %v",
					err)
				continue
			}
		case <-l.quit:
			return
		}
	}
}

// loadAndRemove loads all the channels forwarding packages and determines if
// they can be removed. It is called once before the FwdPkgGCTicker ticks so that
// a longer tick interval can be used.
func (l *channelLink) loadAndRemove() error {
	fwdPkgs, err := l.channel.LoadFwdPkgs()
	if err != nil {
		return err
	}

	var removeHeights []uint64
	for _, fwdPkg := range fwdPkgs {
		if fwdPkg.State != channeldb.FwdStateCompleted {
			continue
		}

		removeHeights = append(removeHeights, fwdPkg.Height)
	}

	// If removeHeights is empty, return early so we don't use a db
	// transaction.
	if len(removeHeights) == 0 {
		return nil
	}

	return l.channel.RemoveFwdPkgs(removeHeights...)
}

// htlcManager is the primary goroutine which drives a channel's commitment
// update state-machine in response to messages received via several channels.
// This goroutine reads messages from the upstream (remote) peer, and also from
// downstream channel managed by the channel link. In the event that an htlc
// needs to be forwarded, then send-only forward handler is used which sends
// htlc packets to the switch. Additionally, the this goroutine handles acting
// upon all timeouts for any active HTLCs, manages the channel's revocation
// window, and also the htlc trickle queue+timer for this active channels.
//
// NOTE: This MUST be run as a goroutine.
func (l *channelLink) htlcManager() {
	defer func() {
		l.cfg.BatchTicker.Stop()
		l.wg.Done()
		l.log.Infof("exited")
	}()

	l.log.Infof("HTLC manager started, bandwidth=%v", l.Bandwidth())

	// Notify any clients that the link is now in the switch via an
	// ActiveLinkEvent.
	l.cfg.NotifyActiveLink(*l.ChannelPoint())

	// TODO(roasbeef): need to call wipe chan whenever D/C?

	// If this isn't the first time that this channel link has been
	// created, then we'll need to check to see if we need to
	// re-synchronize state with the remote peer. settledHtlcs is a map of
	// HTLC's that we re-settled as part of the channel state sync.
	if l.cfg.SyncStates {
		err := l.syncChanStates()
		if err != nil {
			l.log.Warnf("error when syncing channel states: %v", err)

			errDataLoss, localDataLoss :=
				err.(*lnwallet.ErrCommitSyncLocalDataLoss)

			switch {
			case err == ErrLinkShuttingDown:
				l.log.Debugf("unable to sync channel states, " +
					"link is shutting down")
				return

			// We failed syncing the commit chains, probably
			// because the remote has lost state. We should force
			// close the channel.
			case err == lnwallet.ErrCommitSyncRemoteDataLoss:
				fallthrough

			// The remote sent us an invalid last commit secret, we
			// should force close the channel.
			// TODO(halseth): and permanently ban the peer?
			case err == lnwallet.ErrInvalidLastCommitSecret:
				fallthrough

			// The remote sent us a commit point different from
			// what they sent us before.
			// TODO(halseth): ban peer?
			case err == lnwallet.ErrInvalidLocalUnrevokedCommitPoint:
				// We'll fail the link and tell the peer to
				// force close the channel. Note that the
				// database state is not updated here, but will
				// be updated when the close transaction is
				// ready to avoid that we go down before
				// storing the transaction in the db.
				l.fail(
					LinkFailureError{
						code:       ErrSyncError,
						ForceClose: true,
					},
					"unable to synchronize channel "+
						"states: %v", err,
				)
				return

			// We have lost state and cannot safely force close the
			// channel. Fail the channel and wait for the remote to
			// hopefully force close it. The remote has sent us its
			// latest unrevoked commitment point, and we'll store
			// it in the database, such that we can attempt to
			// recover the funds if the remote force closes the
			// channel.
			case localDataLoss:
				err := l.channel.MarkDataLoss(
					errDataLoss.CommitPoint,
				)
				if err != nil {
					l.log.Errorf("unable to mark channel "+
						"data loss: %v", err)
				}

			// We determined the commit chains were not possible to
			// sync. We cautiously fail the channel, but don't
			// force close.
			// TODO(halseth): can we safely force close in any
			// cases where this error is returned?
			case err == lnwallet.ErrCannotSyncCommitChains:
				if err := l.channel.MarkBorked(); err != nil {
					l.log.Errorf("unable to mark channel "+
						"borked: %v", err)
				}

			// Other, unspecified error.
			default:
			}

			l.fail(
				LinkFailureError{
					code:       ErrRecoveryError,
					ForceClose: false,
				},
				"unable to synchronize channel "+
					"states: %v", err,
			)
			return
		}
	}

	// We've successfully reestablished the channel, mark it as such to
	// allow the switch to forward HTLCs in the outbound direction.
	l.markReestablished()

	// Now that we've received both funding locked and channel reestablish,
	// we can go ahead and send the active channel notification. We'll also
	// defer the inactive notification for when the link exits to ensure
	// that every active notification is matched by an inactive one.
	l.cfg.NotifyActiveChannel(*l.ChannelPoint())
	defer l.cfg.NotifyInactiveChannel(*l.ChannelPoint())

	// With the channel states synced, we now reset the mailbox to ensure
	// we start processing all unacked packets in order. This is done here
	// to ensure that all acknowledgments that occur during channel
	// resynchronization have taken affect, causing us only to pull unacked
	// packets after starting to read from the downstream mailbox.
	l.mailBox.ResetPackets()

	// After cleaning up any memory pertaining to incoming packets, we now
	// replay our forwarding packages to handle any htlcs that can be
	// processed locally, or need to be forwarded out to the switch. We will
	// only attempt to resolve packages if our short chan id indicates that
	// the channel is not pending, otherwise we should have no htlcs to
	// reforward.
	if l.ShortChanID() != hop.Source {
		if err := l.resolveFwdPkgs(); err != nil {
			l.fail(LinkFailureError{code: ErrInternalError},
				"unable to resolve fwd pkgs: %v", err)
			return
		}

		// With our link's in-memory state fully reconstructed, spawn a
		// goroutine to manage the reclamation of disk space occupied by
		// completed forwarding packages.
		l.wg.Add(1)
		go l.fwdPkgGarbager()
	}

	for {
		// We must always check if we failed at some point processing
		// the last update before processing the next.
		if l.failed {
			l.log.Errorf("link failed, exiting htlcManager")
			return
		}

		// If the previous event resulted in a non-empty batch, resume
		// the batch ticker so that it can be cleared. Otherwise pause
		// the ticker to prevent waking up the htlcManager while the
		// batch is empty.
		if l.channel.PendingLocalUpdateCount() > 0 {
			l.cfg.BatchTicker.Resume()
		} else {
			l.cfg.BatchTicker.Pause()
		}

		select {
		// Our update fee timer has fired, so we'll check the network
		// fee to see if we should adjust our commitment fee.
		case <-l.updateFeeTimer.C:
			l.updateFeeTimer.Reset(l.randomFeeUpdateTimeout())

			// If we're not the initiator of the channel, don't we
			// don't control the fees, so we can ignore this.
			if !l.channel.IsInitiator() {
				continue
			}

			// If we are the initiator, then we'll sample the
			// current fee rate to get into the chain within 3
			// blocks.
			netFee, err := l.sampleNetworkFee()
			if err != nil {
				l.log.Errorf("unable to sample network fee: %v",
					err)
				continue
			}

			// We'll check to see if we should update the fee rate
			// based on our current set fee rate. We'll cap the new
			// fee rate to our max fee allocation.
			commitFee := l.channel.CommitFeeRate()
			maxFee := l.channel.MaxFeeRate(
				l.cfg.MaxFeeAllocation,
				l.cfg.MaxAnchorsCommitFeeRate,
			)
			newCommitFee := chainfee.SatPerKWeight(
				math.Min(float64(netFee), float64(maxFee)),
			)
			if !shouldAdjustCommitFee(newCommitFee, commitFee) {
				continue
			}

			// If we do, then we'll send a new UpdateFee message to
			// the remote party, to be locked in with a new update.
			if err := l.updateChannelFee(newCommitFee); err != nil {
				l.log.Errorf("unable to update fee rate: %v",
					err)
				continue
			}

		// The underlying channel has notified us of a unilateral close
		// carried out by the remote peer. In the case of such an
		// event, we'll wipe the channel state from the peer, and mark
		// the contract as fully settled. Afterwards we can exit.
		//
		// TODO(roasbeef): add force closure? also breach?
		case <-l.cfg.ChainEvents.RemoteUnilateralClosure:
			l.log.Warnf("remote peer has closed on-chain")

			// TODO(roasbeef): remove all together
			go func() {
				chanPoint := l.channel.ChannelPoint()
				l.cfg.Peer.WipeChannel(chanPoint)
			}()

			return

		case <-l.cfg.BatchTicker.Ticks():
			// Attempt to extend the remote commitment chain
			// including all the currently pending entries. If the
			// send was unsuccessful, then abandon the update,
			// waiting for the revocation window to open up.
			if !l.updateCommitTxOrFail() {
				return
			}

		case <-l.cfg.PendingCommitTicker.Ticks():
			l.fail(LinkFailureError{code: ErrRemoteUnresponsive},
				"unable to complete dance")
			return

		// A message from the switch was just received. This indicates
		// that the link is an intermediate hop in a multi-hop HTLC
		// circuit.
		case pkt := <-l.downstream:
			l.handleDownstreamPkt(pkt)

		// A message containing a locally initiated add was received.
		case msg := <-l.localUpdateAdd:
			msg.err <- l.handleDownstreamUpdateAdd(msg.pkt)

		// A message from the connected peer was just received. This
		// indicates that we have a new incoming HTLC, either directly
		// for us, or part of a multi-hop HTLC circuit.
		case msg := <-l.upstream:
			l.handleUpstreamMsg(msg)

		// A htlc resolution is received. This means that we now have a
		// resolution for a previously accepted htlc.
		case hodlItem := <-l.hodlQueue.ChanOut():
			htlcResolution := hodlItem.(invoices.HtlcResolution)
			err := l.processHodlQueue(htlcResolution)
			if err != nil {
				l.fail(LinkFailureError{code: ErrInternalError},
					fmt.Sprintf("process hodl queue: %v",
						err.Error()),
				)
				return
			}

		case <-l.quit:
			return
		}
	}
}

// processHodlQueue processes a received htlc resolution and continues reading
// from the hodl queue until no more resolutions remain. When this function
// returns without an error, the commit tx should be updated.
func (l *channelLink) processHodlQueue(
	firstResolution invoices.HtlcResolution) error {

	// Try to read all waiting resolution messages, so that they can all be
	// processed in a single commitment tx update.
	htlcResolution := firstResolution
loop:
	for {
		// Lookup all hodl htlcs that can be failed or settled with this event.
		// The hodl htlc must be present in the map.
		circuitKey := htlcResolution.CircuitKey()
		hodlHtlc, ok := l.hodlMap[circuitKey]
		if !ok {
			return fmt.Errorf("hodl htlc not found: %v", circuitKey)
		}

		if err := l.processHtlcResolution(htlcResolution, hodlHtlc); err != nil {
			return err
		}

		// Clean up hodl map.
		delete(l.hodlMap, circuitKey)

		select {
		case item := <-l.hodlQueue.ChanOut():
			htlcResolution = item.(invoices.HtlcResolution)
		default:
			break loop
		}
	}

	// Update the commitment tx.
	if err := l.updateCommitTx(); err != nil {
		return fmt.Errorf("unable to update commitment: %v", err)
	}

	return nil
}

// processHtlcResolution applies a received htlc resolution to the provided
// htlc. When this function returns without an error, the commit tx should be
// updated.
func (l *channelLink) processHtlcResolution(resolution invoices.HtlcResolution,
	htlc hodlHtlc) error {

	circuitKey := resolution.CircuitKey()

	// Determine required action for the resolution based on the type of
	// resolution we have received.
	switch res := resolution.(type) {
	// Settle htlcs that returned a settle resolution using the preimage
	// in the resolution.
	case *invoices.HtlcSettleResolution:
		l.log.Debugf("received settle resolution for %v "+
			"with outcome: %v", circuitKey, res.Outcome)

		return l.settleHTLC(res.Preimage, htlc.pd)

	// For htlc failures, we get the relevant failure message based
	// on the failure resolution and then fail the htlc.
	case *invoices.HtlcFailResolution:
		l.log.Debugf("received cancel resolution for "+
			"%v with outcome: %v", circuitKey, res.Outcome)

		// Get the lnwire failure message based on the resolution
		// result.
		failure := getResolutionFailure(res, htlc.pd.Amount)

		l.sendHTLCError(
			htlc.pd, failure, htlc.obfuscator, true,
		)
		return nil

	// Fail if we do not get a settle of fail resolution, since we
	// are only expecting to handle settles and fails.
	default:
		return fmt.Errorf("unknown htlc resolution type: %T",
			resolution)
	}
}

// getResolutionFailure returns the wire message that a htlc resolution should
// be failed with.
func getResolutionFailure(resolution *invoices.HtlcFailResolution,
	amount lnwire.MilliSatoshi) *LinkError {

	// If the resolution has been resolved as part of a MPP timeout,
	// we need to fail the htlc with lnwire.FailMppTimeout.
	if resolution.Outcome == invoices.ResultMppTimeout {
		return NewDetailedLinkError(
			&lnwire.FailMPPTimeout{}, resolution.Outcome,
		)
	}

	// If the htlc is not a MPP timeout, we fail it with
	// FailIncorrectDetails. This error is sent for invoice payment
	// failures such as underpayment/ expiry too soon and hodl invoices
	// (which return FailIncorrectDetails to avoid leaking information).
	incorrectDetails := lnwire.NewFailIncorrectDetails(
		amount, uint32(resolution.AcceptHeight),
	)

	return NewDetailedLinkError(incorrectDetails, resolution.Outcome)
}

// randomFeeUpdateTimeout returns a random timeout between the bounds defined
// within the link's configuration that will be used to determine when the link
// should propose an update to its commitment fee rate.
func (l *channelLink) randomFeeUpdateTimeout() time.Duration {
	lower := int64(l.cfg.MinFeeUpdateTimeout)
	upper := int64(l.cfg.MaxFeeUpdateTimeout)
	return time.Duration(prand.Int63n(upper-lower) + lower)
}

// handleDownstreamUpdateAdd processes an UpdateAddHTLC packet sent from the
// downstream HTLC Switch.
func (l *channelLink) handleDownstreamUpdateAdd(pkt *htlcPacket) error {
	htlc, ok := pkt.htlc.(*lnwire.UpdateAddHTLC)
	if !ok {
		return errors.New("not an UpdateAddHTLC packet")
	}

	// If hodl.AddOutgoing mode is active, we exit early to simulate
	// arbitrary delays between the switch adding an ADD to the
	// mailbox, and the HTLC being added to the commitment state.
	if l.cfg.HodlMask.Active(hodl.AddOutgoing) {
		l.log.Warnf(hodl.AddOutgoing.Warning())
		l.mailBox.AckPacket(pkt.inKey())
		return nil
	}

	// A new payment has been initiated via the downstream channel,
	// so we add the new HTLC to our local log, then update the
	// commitment chains.
	htlc.ChanID = l.ChanID()
	openCircuitRef := pkt.inKey()
	index, err := l.channel.AddHTLC(htlc, &openCircuitRef)
	if err != nil {
		// The HTLC was unable to be added to the state machine,
		// as a result, we'll signal the switch to cancel the
		// pending payment.
		l.log.Warnf("Unable to handle downstream add HTLC: %v",
			err)

		// Remove this packet from the link's mailbox, this
		// prevents it from being reprocessed if the link
		// restarts and resets it mailbox. If this response
		// doesn't make it back to the originating link, it will
		// be rejected upon attempting to reforward the Add to
		// the switch, since the circuit was never fully opened,
		// and the forwarding package shows it as
		// unacknowledged.
		l.mailBox.FailAdd(pkt)

		return NewDetailedLinkError(
			lnwire.NewTemporaryChannelFailure(nil),
			OutgoingFailureDownstreamHtlcAdd,
		)
	}

	l.log.Tracef("received downstream htlc: payment_hash=%x, "+
		"local_log_index=%v, pend_updates=%v",
		htlc.PaymentHash[:], index,
		l.channel.PendingLocalUpdateCount())

	pkt.outgoingChanID = l.ShortChanID()
	pkt.outgoingHTLCID = index
	htlc.ID = index

	l.log.Debugf("queueing keystone of ADD open circuit: %s->%s",
		pkt.inKey(), pkt.outKey())

	l.openedCircuits = append(l.openedCircuits, pkt.inKey())
	l.keystoneBatch = append(l.keystoneBatch, pkt.keystone())

	_ = l.cfg.Peer.SendMessage(false, htlc)

	// Send a forward event notification to htlcNotifier.
	l.cfg.HtlcNotifier.NotifyForwardingEvent(
		newHtlcKey(pkt),
		HtlcInfo{
			IncomingTimeLock: pkt.incomingTimeout,
			IncomingAmt:      pkt.incomingAmount,
			OutgoingTimeLock: htlc.Expiry,
			OutgoingAmt:      htlc.Amount,
		},
		getEventType(pkt),
	)

	l.tryBatchUpdateCommitTx()

	return nil
}

// handleDownstreamPkt processes an HTLC packet sent from the downstream HTLC
// Switch. Possible messages sent by the switch include requests to forward new
// HTLCs, timeout previously cleared HTLCs, and finally to settle currently
// cleared HTLCs with the upstream peer.
//
// TODO(roasbeef): add sync ntfn to ensure switch always has consistent view?
func (l *channelLink) handleDownstreamPkt(pkt *htlcPacket) {
	switch htlc := pkt.htlc.(type) {
	case *lnwire.UpdateAddHTLC:
		// Handle add message. The returned error can be ignored,
		// because it is also sent through the mailbox.
		_ = l.handleDownstreamUpdateAdd(pkt)

	case *lnwire.UpdateFulfillHTLC:
		// If hodl.SettleOutgoing mode is active, we exit early to
		// simulate arbitrary delays between the switch adding the
		// SETTLE to the mailbox, and the HTLC being added to the
		// commitment state.
		if l.cfg.HodlMask.Active(hodl.SettleOutgoing) {
			l.log.Warnf(hodl.SettleOutgoing.Warning())
			l.mailBox.AckPacket(pkt.inKey())
			return
		}

		// An HTLC we forward to the switch has just settled somewhere
		// upstream. Therefore we settle the HTLC within the our local
		// state machine.
		inKey := pkt.inKey()
		err := l.channel.SettleHTLC(
			htlc.PaymentPreimage,
			pkt.incomingHTLCID,
			pkt.sourceRef,
			pkt.destRef,
			&inKey,
		)
		if err != nil {
			l.log.Errorf("unable to settle incoming HTLC for "+
				"circuit-key=%v: %v", inKey, err)

			// If the HTLC index for Settle response was not known
			// to our commitment state, it has already been
			// cleaned up by a prior response. We'll thus try to
			// clean up any lingering state to ensure we don't
			// continue reforwarding.
			if _, ok := err.(lnwallet.ErrUnknownHtlcIndex); ok {
				l.cleanupSpuriousResponse(pkt)
			}

			// Remove the packet from the link's mailbox to ensure
			// it doesn't get replayed after a reconnection.
			l.mailBox.AckPacket(inKey)

			return
		}

		l.log.Debugf("queueing removal of SETTLE closed circuit: "+
			"%s->%s", pkt.inKey(), pkt.outKey())

		l.closedCircuits = append(l.closedCircuits, pkt.inKey())

		// With the HTLC settled, we'll need to populate the wire
		// message to target the specific channel and HTLC to be
		// canceled.
		htlc.ChanID = l.ChanID()
		htlc.ID = pkt.incomingHTLCID

		// Then we send the HTLC settle message to the connected peer
		// so we can continue the propagation of the settle message.
		l.cfg.Peer.SendMessage(false, htlc)

		// Send a settle event notification to htlcNotifier.
		l.cfg.HtlcNotifier.NotifySettleEvent(
			newHtlcKey(pkt),
			htlc.PaymentPreimage,
			getEventType(pkt),
		)

		// Immediately update the commitment tx to minimize latency.
		l.updateCommitTxOrFail()

	case *lnwire.UpdateFailHTLC:
		// If hodl.FailOutgoing mode is active, we exit early to
		// simulate arbitrary delays between the switch adding a FAIL to
		// the mailbox, and the HTLC being added to the commitment
		// state.
		if l.cfg.HodlMask.Active(hodl.FailOutgoing) {
			l.log.Warnf(hodl.FailOutgoing.Warning())
			l.mailBox.AckPacket(pkt.inKey())
			return
		}

		// An HTLC cancellation has been triggered somewhere upstream,
		// we'll remove then HTLC from our local state machine.
		inKey := pkt.inKey()
		err := l.channel.FailHTLC(
			pkt.incomingHTLCID,
			htlc.Reason,
			pkt.sourceRef,
			pkt.destRef,
			&inKey,
		)
		if err != nil {
			l.log.Errorf("unable to cancel incoming HTLC for "+
				"circuit-key=%v: %v", inKey, err)

			// If the HTLC index for Fail response was not known to
			// our commitment state, it has already been cleaned up
			// by a prior response. We'll thus try to clean up any
			// lingering state to ensure we don't continue
			// reforwarding.
			if _, ok := err.(lnwallet.ErrUnknownHtlcIndex); ok {
				l.cleanupSpuriousResponse(pkt)
			}

			// Remove the packet from the link's mailbox to ensure
			// it doesn't get replayed after a reconnection.
			l.mailBox.AckPacket(inKey)

			return
		}

		l.log.Debugf("queueing removal of FAIL closed circuit: %s->%s",
			pkt.inKey(), pkt.outKey())

		l.closedCircuits = append(l.closedCircuits, pkt.inKey())

		// With the HTLC removed, we'll need to populate the wire
		// message to target the specific channel and HTLC to be
		// canceled. The "Reason" field will have already been set
		// within the switch.
		htlc.ChanID = l.ChanID()
		htlc.ID = pkt.incomingHTLCID

		// We send the HTLC message to the peer which initially created
		// the HTLC.
		l.cfg.Peer.SendMessage(false, htlc)

		// If the packet does not have a link failure set, it failed
		// further down the route so we notify a forwarding failure.
		// Otherwise, we notify a link failure because it failed at our
		// node.
		if pkt.linkFailure != nil {
			l.cfg.HtlcNotifier.NotifyLinkFailEvent(
				newHtlcKey(pkt),
				newHtlcInfo(pkt),
				getEventType(pkt),
				pkt.linkFailure,
				false,
			)
		} else {
			l.cfg.HtlcNotifier.NotifyForwardingFailEvent(
				newHtlcKey(pkt), getEventType(pkt),
			)
		}

		// Immediately update the commitment tx to minimize latency.
		l.updateCommitTxOrFail()
	}
}

// tryBatchUpdateCommitTx updates the commitment transaction if the batch is
// full.
func (l *channelLink) tryBatchUpdateCommitTx() {
	if l.channel.PendingLocalUpdateCount() < uint64(l.cfg.BatchSize) {
		return
	}

	l.updateCommitTxOrFail()
}

// cleanupSpuriousResponse attempts to ack any AddRef or SettleFailRef
// associated with this packet. If successful in doing so, it will also purge
// the open circuit from the circuit map and remove the packet from the link's
// mailbox.
func (l *channelLink) cleanupSpuriousResponse(pkt *htlcPacket) {
	inKey := pkt.inKey()

	l.log.Debugf("cleaning up spurious response for incoming "+
		"circuit-key=%v", inKey)

	// If the htlc packet doesn't have a source reference, it is unsafe to
	// proceed, as skipping this ack may cause the htlc to be reforwarded.
	if pkt.sourceRef == nil {
		l.log.Errorf("unable to cleanup response for incoming "+
			"circuit-key=%v, does not contain source reference",
			inKey)
		return
	}

	// If the source reference is present,  we will try to prevent this link
	// from resending the packet to the switch. To do so, we ack the AddRef
	// of the incoming HTLC belonging to this link.
	err := l.channel.AckAddHtlcs(*pkt.sourceRef)
	if err != nil {
		l.log.Errorf("unable to ack AddRef for incoming "+
			"circuit-key=%v: %v", inKey, err)

		// If this operation failed, it is unsafe to attempt removal of
		// the destination reference or circuit, so we exit early. The
		// cleanup may proceed with a different packet in the future
		// that succeeds on this step.
		return
	}

	// Now that we know this link will stop retransmitting Adds to the
	// switch, we can begin to teardown the response reference and circuit
	// map.
	//
	// If the packet includes a destination reference, then a response for
	// this HTLC was locked into the outgoing channel. Attempt to remove
	// this reference, so we stop retransmitting the response internally.
	// Even if this fails, we will proceed in trying to delete the circuit.
	// When retransmitting responses, the destination references will be
	// cleaned up if an open circuit is not found in the circuit map.
	if pkt.destRef != nil {
		err := l.channel.AckSettleFails(*pkt.destRef)
		if err != nil {
			l.log.Errorf("unable to ack SettleFailRef "+
				"for incoming circuit-key=%v: %v",
				inKey, err)
		}
	}

	l.log.Debugf("deleting circuit for incoming circuit-key=%x", inKey)

	// With all known references acked, we can now safely delete the circuit
	// from the switch's circuit map, as the state is no longer needed.
	err = l.cfg.Circuits.DeleteCircuits(inKey)
	if err != nil {
		l.log.Errorf("unable to delete circuit for "+
			"circuit-key=%v: %v", inKey, err)
	}
}

// handleUpstreamMsg processes wire messages related to commitment state
// updates from the upstream peer. The upstream peer is the peer whom we have a
// direct channel with, updating our respective commitment chains.
func (l *channelLink) handleUpstreamMsg(msg lnwire.Message) {
	switch msg := msg.(type) {

	case *lnwire.UpdateAddHTLC:
		// We just received an add request from an upstream peer, so we
		// add it to our state machine, then add the HTLC to our
		// "settle" list in the event that we know the preimage.
		index, err := l.channel.ReceiveHTLC(msg)
		if err != nil {
			l.fail(LinkFailureError{code: ErrInvalidUpdate},
				"unable to handle upstream add HTLC: %v", err)
			return
		}

		l.log.Tracef("receive upstream htlc with payment hash(%x), "+
			"assigning index: %v", msg.PaymentHash[:], index)

	case *lnwire.UpdateFulfillHTLC:
		pre := msg.PaymentPreimage
		idx := msg.ID
		if err := l.channel.ReceiveHTLCSettle(pre, idx); err != nil {
			l.fail(
				LinkFailureError{
					code:       ErrInvalidUpdate,
					ForceClose: true,
				},
				"unable to handle upstream settle HTLC: %v", err,
			)
			return
		}

		settlePacket := &htlcPacket{
			outgoingChanID: l.ShortChanID(),
			outgoingHTLCID: idx,
			htlc: &lnwire.UpdateFulfillHTLC{
				PaymentPreimage: pre,
			},
		}

		// Add the newly discovered preimage to our growing list of
		// uncommitted preimage. These will be written to the witness
		// cache just before accepting the next commitment signature
		// from the remote peer.
		l.uncommittedPreimages = append(l.uncommittedPreimages, pre)

		// Pipeline this settle, send it to the switch.
		go l.forwardBatch(settlePacket)

	case *lnwire.UpdateFailMalformedHTLC:
		// Convert the failure type encoded within the HTLC fail
		// message to the proper generic lnwire error code.
		var failure lnwire.FailureMessage
		switch msg.FailureCode {
		case lnwire.CodeInvalidOnionVersion:
			failure = &lnwire.FailInvalidOnionVersion{
				OnionSHA256: msg.ShaOnionBlob,
			}
		case lnwire.CodeInvalidOnionHmac:
			failure = &lnwire.FailInvalidOnionHmac{
				OnionSHA256: msg.ShaOnionBlob,
			}

		case lnwire.CodeInvalidOnionKey:
			failure = &lnwire.FailInvalidOnionKey{
				OnionSHA256: msg.ShaOnionBlob,
			}
		default:
			l.log.Warnf("unexpected failure code received in "+
				"UpdateFailMailformedHTLC: %v", msg.FailureCode)

			// We don't just pass back the error we received from
			// our successor. Otherwise we might report a failure
			// that penalizes us more than needed. If the onion that
			// we forwarded was correct, the node should have been
			// able to send back its own failure. The node did not
			// send back its own failure, so we assume there was a
			// problem with the onion and report that back. We reuse
			// the invalid onion key failure because there is no
			// specific error for this case.
			failure = &lnwire.FailInvalidOnionKey{
				OnionSHA256: msg.ShaOnionBlob,
			}
		}

		// With the error parsed, we'll convert the into it's opaque
		// form.
		var b bytes.Buffer
		if err := lnwire.EncodeFailure(&b, failure, 0); err != nil {
			l.log.Errorf("unable to encode malformed error: %v", err)
			return
		}

		// If remote side have been unable to parse the onion blob we
		// have sent to it, than we should transform the malformed HTLC
		// message to the usual HTLC fail message.
		err := l.channel.ReceiveFailHTLC(msg.ID, b.Bytes())
		if err != nil {
			l.fail(LinkFailureError{code: ErrInvalidUpdate},
				"unable to handle upstream fail HTLC: %v", err)
			return
		}

	case *lnwire.UpdateFailHTLC:
		idx := msg.ID
		err := l.channel.ReceiveFailHTLC(idx, msg.Reason[:])
		if err != nil {
			l.fail(LinkFailureError{code: ErrInvalidUpdate},
				"unable to handle upstream fail HTLC: %v", err)
			return
		}

	case *lnwire.CommitSig:
		// Since we may have learned new preimages for the first time,
		// we'll add them to our preimage cache. By doing this, we
		// ensure any contested contracts watched by any on-chain
		// arbitrators can now sweep this HTLC on-chain. We delay
		// committing the preimages until just before accepting the new
		// remote commitment, as afterwards the peer won't resend the
		// Settle messages on the next channel reestablishment. Doing so
		// allows us to more effectively batch this operation, instead
		// of doing a single write per preimage.
		err := l.cfg.PreimageCache.AddPreimages(
			l.uncommittedPreimages...,
		)
		if err != nil {
			l.fail(
				LinkFailureError{code: ErrInternalError},
				"unable to add preimages=%v to cache: %v",
				l.uncommittedPreimages, err,
			)
			return
		}

		// Instead of truncating the slice to conserve memory
		// allocations, we simply set the uncommitted preimage slice to
		// nil so that a new one will be initialized if any more
		// witnesses are discovered. We do this maximum size of the
		// slice can occupy 15KB, and want to ensure we release that
		// memory back to the runtime.
		l.uncommittedPreimages = nil

		// We just received a new updates to our local commitment
		// chain, validate this new commitment, closing the link if
		// invalid.
		err = l.channel.ReceiveNewCommitment(msg.CommitSig, msg.HtlcSigs)
		if err != nil {
			// If we were unable to reconstruct their proposed
			// commitment, then we'll examine the type of error. If
			// it's an InvalidCommitSigError, then we'll send a
			// direct error.
			var sendData []byte
			switch err.(type) {
			case *lnwallet.InvalidCommitSigError:
				sendData = []byte(err.Error())
			case *lnwallet.InvalidHtlcSigError:
				sendData = []byte(err.Error())
			}
			l.fail(
				LinkFailureError{
					code:       ErrInvalidCommitment,
					ForceClose: true,
					SendData:   sendData,
				},
				"ChannelPoint(%v): unable to accept new "+
					"commitment: %v",
				l.channel.ChannelPoint(), err,
			)
			return
		}

		// As we've just accepted a new state, we'll now
		// immediately send the remote peer a revocation for our prior
		// state.
		nextRevocation, currentHtlcs, err := l.channel.RevokeCurrentCommitment()
		if err != nil {
			l.log.Errorf("unable to revoke commitment: %v", err)
			return
		}
		l.cfg.Peer.SendMessage(false, nextRevocation)

		// Since we just revoked our commitment, we may have a new set
		// of HTLC's on our commitment, so we'll send them over our
		// HTLC update channel so any callers can be notified.
		select {
		case l.htlcUpdates <- &contractcourt.ContractUpdate{
			HtlcKey: contractcourt.LocalHtlcSet,
			Htlcs:   currentHtlcs,
		}:
		case <-l.quit:
			return
		}

		// If both commitment chains are fully synced from our PoV,
		// then we don't need to reply with a signature as both sides
		// already have a commitment with the latest accepted.
		if !l.channel.OweCommitment(true) {
			return
		}

		// Otherwise, the remote party initiated the state transition,
		// so we'll reply with a signature to provide them with their
		// version of the latest commitment.
		if !l.updateCommitTxOrFail() {
			return
		}

	case *lnwire.RevokeAndAck:
		// We've received a revocation from the remote chain, if valid,
		// this moves the remote chain forward, and expands our
		// revocation window.
		fwdPkg, adds, settleFails, remoteHTLCs, err := l.channel.ReceiveRevocation(
			msg,
		)
		if err != nil {
			// TODO(halseth): force close?
			l.fail(LinkFailureError{code: ErrInvalidRevocation},
				"unable to accept revocation: %v", err)
			return
		}

		// The remote party now has a new primary commitment, so we'll
		// update the contract court to be aware of this new set (the
		// prior old remote pending).
		select {
		case l.htlcUpdates <- &contractcourt.ContractUpdate{
			HtlcKey: contractcourt.RemoteHtlcSet,
			Htlcs:   remoteHTLCs,
		}:
		case <-l.quit:
			return
		}

		// If we have a tower client for this channel type, we'll
		if l.cfg.TowerClient != nil {
			state := l.channel.State()
			breachInfo, err := lnwallet.NewBreachRetribution(
				state, state.RemoteCommitment.CommitHeight-1, 0,
			)
			if err != nil {
				l.fail(LinkFailureError{code: ErrInternalError},
					"failed to load breach info: %v", err)
				return
			}

			chanID := l.ChanID()
			err = l.cfg.TowerClient.BackupState(
				&chanID, breachInfo, state.ChanType,
			)
			if err != nil {
				l.fail(LinkFailureError{code: ErrInternalError},
					"unable to queue breach backup: %v", err)
				return
			}
		}

		l.processRemoteSettleFails(fwdPkg, settleFails)
		l.processRemoteAdds(fwdPkg, adds)

		// If the link failed during processing the adds, we must
		// return to ensure we won't attempted to update the state
		// further.
		if l.failed {
			return
		}

		// The revocation window opened up. If there are pending local
		// updates, try to update the commit tx. Pending updates could
		// already have been present because of a previously failed
		// update to the commit tx or freshly added in by
		// processRemoteAdds. Also in case there are no local updates,
		// but there are still remote updates that are not in the remote
		// commit tx yet, send out an update.
		if l.channel.OweCommitment(true) {
			if !l.updateCommitTxOrFail() {
				return
			}
		}

	case *lnwire.UpdateFee:
		// We received fee update from peer. If we are the initiator we
		// will fail the channel, if not we will apply the update.
		fee := chainfee.SatPerKWeight(msg.FeePerKw)
		if err := l.channel.ReceiveUpdateFee(fee); err != nil {
			l.fail(LinkFailureError{code: ErrInvalidUpdate},
				"error receiving fee update: %v", err)
			return
		}
	case *lnwire.Error:
		// Error received from remote, MUST fail channel, but should
		// only print the contents of the error message if all
		// characters are printable ASCII.
		l.fail(
			LinkFailureError{
				code: ErrRemoteError,

				// TODO(halseth): we currently don't fail the
				// channel permanently, as there are some sync
				// issues with other implementations that will
				// lead to them sending an error message, but
				// we can recover from on next connection. See
				// https://github.com/ElementsProject/lightning/issues/4212
				PermanentFailure: false,
			},
			"ChannelPoint(%v): received error from peer: %v",
			l.channel.ChannelPoint(), msg.Error(),
		)
	default:
		l.log.Warnf("received unknown message of type %T", msg)
	}

}

// ackDownStreamPackets is responsible for removing htlcs from a link's mailbox
// for packets delivered from server, and cleaning up any circuits closed by
// signing a previous commitment txn. This method ensures that the circuits are
// removed from the circuit map before removing them from the link's mailbox,
// otherwise it could be possible for some circuit to be missed if this link
// flaps.
func (l *channelLink) ackDownStreamPackets() error {
	// First, remove the downstream Add packets that were included in the
	// previous commitment signature. This will prevent the Adds from being
	// replayed if this link disconnects.
	for _, inKey := range l.openedCircuits {
		// In order to test the sphinx replay logic of the remote
		// party, unsafe replay does not acknowledge the packets from
		// the mailbox. We can then force a replay of any Add packets
		// held in memory by disconnecting and reconnecting the link.
		if l.cfg.UnsafeReplay {
			continue
		}

		l.log.Debugf("removing Add packet %s from mailbox", inKey)
		l.mailBox.AckPacket(inKey)
	}

	// Now, we will delete all circuits closed by the previous commitment
	// signature, which is the result of downstream Settle/Fail packets. We
	// batch them here to ensure circuits are closed atomically and for
	// performance.
	err := l.cfg.Circuits.DeleteCircuits(l.closedCircuits...)
	switch err {
	case nil:
		// Successful deletion.

	default:
		l.log.Errorf("unable to delete %d circuits: %v",
			len(l.closedCircuits), err)
		return err
	}

	// With the circuits removed from memory and disk, we now ack any
	// Settle/Fails in the mailbox to ensure they do not get redelivered
	// after startup. If forgive is enabled and we've reached this point,
	// the circuits must have been removed at some point, so it is now safe
	// to un-queue the corresponding Settle/Fails.
	for _, inKey := range l.closedCircuits {
		l.log.Debugf("removing Fail/Settle packet %s from mailbox",
			inKey)
		l.mailBox.AckPacket(inKey)
	}

	// Lastly, reset our buffers to be empty while keeping any acquired
	// growth in the backing array.
	l.openedCircuits = l.openedCircuits[:0]
	l.closedCircuits = l.closedCircuits[:0]

	return nil
}

// updateCommitTxOrFail updates the commitment tx and if that fails, it fails
// the link.
func (l *channelLink) updateCommitTxOrFail() bool {
	if err := l.updateCommitTx(); err != nil {
		l.fail(LinkFailureError{code: ErrInternalError},
			"unable to update commitment: %v", err)
		return false
	}

	return true
}

// updateCommitTx signs, then sends an update to the remote peer adding a new
// commitment to their commitment chain which includes all the latest updates
// we've received+processed up to this point.
func (l *channelLink) updateCommitTx() error {
	// Preemptively write all pending keystones to disk, just in case the
	// HTLCs we have in memory are included in the subsequent attempt to
	// sign a commitment state.
	err := l.cfg.Circuits.OpenCircuits(l.keystoneBatch...)
	if err != nil {
		return err
	}

	// Reset the batch, but keep the backing buffer to avoid reallocating.
	l.keystoneBatch = l.keystoneBatch[:0]

	// If hodl.Commit mode is active, we will refrain from attempting to
	// commit any in-memory modifications to the channel state. Exiting here
	// permits testing of either the switch or link's ability to trim
	// circuits that have been opened, but unsuccessfully committed.
	if l.cfg.HodlMask.Active(hodl.Commit) {
		l.log.Warnf(hodl.Commit.Warning())
		return nil
	}

	theirCommitSig, htlcSigs, pendingHTLCs, err := l.channel.SignNextCommitment()
	if err == lnwallet.ErrNoWindow {
		l.cfg.PendingCommitTicker.Resume()

		l.log.Tracef("revocation window exhausted, unable to send: "+
			"%v, pend_updates=%v, dangling_closes%v",
			l.channel.PendingLocalUpdateCount(),
			newLogClosure(func() string {
				return spew.Sdump(l.openedCircuits)
			}),
			newLogClosure(func() string {
				return spew.Sdump(l.closedCircuits)
			}),
		)
		return nil
	} else if err != nil {
		return err
	}

	if err := l.ackDownStreamPackets(); err != nil {
		return err
	}

	l.cfg.PendingCommitTicker.Pause()

	// The remote party now has a new pending commitment, so we'll update
	// the contract court to be aware of this new set (the prior old remote
	// pending).
	select {
	case l.htlcUpdates <- &contractcourt.ContractUpdate{
		HtlcKey: contractcourt.RemotePendingHtlcSet,
		Htlcs:   pendingHTLCs,
	}:
	case <-l.quit:
		return ErrLinkShuttingDown
	}

	commitSig := &lnwire.CommitSig{
		ChanID:    l.ChanID(),
		CommitSig: theirCommitSig,
		HtlcSigs:  htlcSigs,
	}
	l.cfg.Peer.SendMessage(false, commitSig)

	return nil
}

// Peer returns the representation of remote peer with which we have the
// channel link opened.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) Peer() lnpeer.Peer {
	return l.cfg.Peer
}

// ChannelPoint returns the channel outpoint for the channel link.
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) ChannelPoint() *wire.OutPoint {
	return l.channel.ChannelPoint()
}

// ShortChanID returns the short channel ID for the channel link. The short
// channel ID encodes the exact location in the main chain that the original
// funding output can be found.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) ShortChanID() lnwire.ShortChannelID {
	l.RLock()
	defer l.RUnlock()

	return l.shortChanID
}

// UpdateShortChanID updates the short channel ID for a link. This may be
// required in the event that a link is created before the short chan ID for it
// is known, or a re-org occurs, and the funding transaction changes location
// within the chain.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) UpdateShortChanID() (lnwire.ShortChannelID, error) {
	chanID := l.ChanID()

	// Refresh the channel state's short channel ID by loading it from disk.
	// This ensures that the channel state accurately reflects the updated
	// short channel ID.
	err := l.channel.State().RefreshShortChanID()
	if err != nil {
		l.log.Errorf("unable to refresh short_chan_id for chan_id=%v: "+
			"%v", chanID, err)
		return hop.Source, err
	}

	sid := l.channel.ShortChanID()

	l.log.Infof("updating to short_chan_id=%v for chan_id=%v", sid, chanID)

	l.Lock()
	l.shortChanID = sid
	l.Unlock()

	go func() {
		err := l.cfg.UpdateContractSignals(&contractcourt.ContractSignals{
			HtlcUpdates: l.htlcUpdates,
			ShortChanID: sid,
		})
		if err != nil {
			l.log.Errorf("unable to update signals")
		}
	}()

	// Now that the short channel ID has been properly updated, we can begin
	// garbage collecting any forwarding packages we create.
	l.wg.Add(1)
	go l.fwdPkgGarbager()

	return sid, nil
}

// ChanID returns the channel ID for the channel link. The channel ID is a more
// compact representation of a channel's full outpoint.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) ChanID() lnwire.ChannelID {
	return lnwire.NewChanIDFromOutPoint(l.channel.ChannelPoint())
}

// Bandwidth returns the total amount that can flow through the channel link at
// this given instance. The value returned is expressed in millisatoshi and can
// be used by callers when making forwarding decisions to determine if a link
// can accept an HTLC.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) Bandwidth() lnwire.MilliSatoshi {
	// Get the balance available on the channel for new HTLCs. This takes
	// the channel reserve into account so HTLCs up to this value won't
	// violate it.
	return l.channel.AvailableBalance()
}

// MayAddOutgoingHtlc indicates whether we may add any more outgoing htlcs to
// this channel.
func (l *channelLink) MayAddOutgoingHtlc() error {
	return l.channel.MayAddOutgoingHtlc()
}

// AttachMailBox updates the current mailbox used by this link, and hooks up
// the mailbox's message and packet outboxes to the link's upstream and
// downstream chans, respectively.
func (l *channelLink) AttachMailBox(mailbox MailBox) {
	l.Lock()
	l.mailBox = mailbox
	l.upstream = mailbox.MessageOutBox()
	l.downstream = mailbox.PacketOutBox()
	l.Unlock()
}

// UpdateForwardingPolicy updates the forwarding policy for the target
// ChannelLink. Once updated, the link will use the new forwarding policy to
// govern if it an incoming HTLC should be forwarded or not. We assume that
// fields that are zero are intentionally set to zero, so we'll use newPolicy to
// update all of the link's FwrdingPolicy's values.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) UpdateForwardingPolicy(newPolicy ForwardingPolicy) {
	l.Lock()
	defer l.Unlock()

	l.cfg.FwrdingPolicy = newPolicy
}

// CheckHtlcForward should return a nil error if the passed HTLC details
// satisfy the current forwarding policy fo the target link. Otherwise,
// a LinkError with a valid protocol failure message should be returned
// in order to signal to the source of the HTLC, the policy consistency
// issue.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) CheckHtlcForward(payHash [32]byte,
	incomingHtlcAmt, amtToForward lnwire.MilliSatoshi,
	incomingTimeout, outgoingTimeout uint32,
	heightNow uint32) *LinkError {

	l.RLock()
	policy := l.cfg.FwrdingPolicy
	l.RUnlock()

	// First check whether the outgoing htlc satisfies the channel policy.
	err := l.canSendHtlc(
		policy, payHash, amtToForward, outgoingTimeout, heightNow,
	)
	if err != nil {
		return err
	}

	// Next, using the amount of the incoming HTLC, we'll calculate the
	// expected fee this incoming HTLC must carry in order to satisfy the
	// constraints of the outgoing link.
	expectedFee := ExpectedFee(policy, amtToForward)

	// If the actual fee is less than our expected fee, then we'll reject
	// this HTLC as it didn't provide a sufficient amount of fees, or the
	// values have been tampered with, or the send used incorrect/dated
	// information to construct the forwarding information for this hop. In
	// any case, we'll cancel this HTLC.
	actualFee := incomingHtlcAmt - amtToForward
	if incomingHtlcAmt < amtToForward || actualFee < expectedFee {
		l.log.Warnf("outgoing htlc(%x) has insufficient fee: "+
			"expected %v, got %v",
			payHash[:], int64(expectedFee), int64(actualFee))

		// As part of the returned error, we'll send our latest routing
		// policy so the sending node obtains the most up to date data.
		failure := l.createFailureWithUpdate(
			func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
				return lnwire.NewFeeInsufficient(
					amtToForward, *upd,
				)
			},
		)
		return NewLinkError(failure)
	}

	// Finally, we'll ensure that the time-lock on the outgoing HTLC meets
	// the following constraint: the incoming time-lock minus our time-lock
	// delta should equal the outgoing time lock. Otherwise, whether the
	// sender messed up, or an intermediate node tampered with the HTLC.
	timeDelta := policy.TimeLockDelta
	if incomingTimeout < outgoingTimeout+timeDelta {
		l.log.Warnf("incoming htlc(%x) has incorrect time-lock value: "+
			"expected at least %v block delta, got %v block delta",
			payHash[:], timeDelta, incomingTimeout-outgoingTimeout)

		// Grab the latest routing policy so the sending node is up to
		// date with our current policy.
		failure := l.createFailureWithUpdate(
			func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
				return lnwire.NewIncorrectCltvExpiry(
					incomingTimeout, *upd,
				)
			},
		)
		return NewLinkError(failure)
	}

	return nil
}

// CheckHtlcTransit should return a nil error if the passed HTLC details
// satisfy the current channel policy.  Otherwise, a LinkError with a
// valid protocol failure message should be returned in order to signal
// the violation. This call is intended to be used for locally initiated
// payments for which there is no corresponding incoming htlc.
func (l *channelLink) CheckHtlcTransit(payHash [32]byte,
	amt lnwire.MilliSatoshi, timeout uint32,
	heightNow uint32) *LinkError {

	l.RLock()
	policy := l.cfg.FwrdingPolicy
	l.RUnlock()

	return l.canSendHtlc(
		policy, payHash, amt, timeout, heightNow,
	)
}

// canSendHtlc checks whether the given htlc parameters satisfy
// the channel's amount and time lock constraints.
func (l *channelLink) canSendHtlc(policy ForwardingPolicy,
	payHash [32]byte, amt lnwire.MilliSatoshi, timeout uint32,
	heightNow uint32) *LinkError {

	// As our first sanity check, we'll ensure that the passed HTLC isn't
	// too small for the next hop. If so, then we'll cancel the HTLC
	// directly.
	if amt < policy.MinHTLCOut {
		l.log.Warnf("outgoing htlc(%x) is too small: min_htlc=%v, "+
			"htlc_value=%v", payHash[:], policy.MinHTLCOut,
			amt)

		// As part of the returned error, we'll send our latest routing
		// policy so the sending node obtains the most up to date data.
		failure := l.createFailureWithUpdate(
			func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
				return lnwire.NewAmountBelowMinimum(
					amt, *upd,
				)
			},
		)
		return NewLinkError(failure)
	}

	// Next, ensure that the passed HTLC isn't too large. If so, we'll
	// cancel the HTLC directly.
	if policy.MaxHTLC != 0 && amt > policy.MaxHTLC {
		l.log.Warnf("outgoing htlc(%x) is too large: max_htlc=%v, "+
			"htlc_value=%v", payHash[:], policy.MaxHTLC, amt)

		// As part of the returned error, we'll send our latest routing
		// policy so the sending node obtains the most up-to-date data.
		failure := l.createFailureWithUpdate(
			func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
				return lnwire.NewTemporaryChannelFailure(upd)
			},
		)
		return NewDetailedLinkError(failure, OutgoingFailureHTLCExceedsMax)
	}

	// We want to avoid offering an HTLC which will expire in the near
	// future, so we'll reject an HTLC if the outgoing expiration time is
	// too close to the current height.
	if timeout <= heightNow+l.cfg.OutgoingCltvRejectDelta {
		l.log.Warnf("htlc(%x) has an expiry that's too soon: "+
			"outgoing_expiry=%v, best_height=%v", payHash[:],
			timeout, heightNow)
		failure := l.createFailureWithUpdate(
			func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
				return lnwire.NewExpiryTooSoon(*upd)
			},
		)
		return NewLinkError(failure)
	}

	// Check absolute max delta.
	if timeout > l.cfg.MaxOutgoingCltvExpiry+heightNow {
		l.log.Warnf("outgoing htlc(%x) has a time lock too far in "+
			"the future: got %v, but maximum is %v", payHash[:],
			timeout-heightNow, l.cfg.MaxOutgoingCltvExpiry)

		return NewLinkError(&lnwire.FailExpiryTooFar{})
	}

	// Check to see if there is enough balance in this channel.
	if amt > l.Bandwidth() {
		l.log.Warnf("insufficient bandwidth to route htlc: %v is "+
			"larger than %v", amt, l.Bandwidth())
		failure := l.createFailureWithUpdate(
			func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
				return lnwire.NewTemporaryChannelFailure(upd)
			},
		)
		return NewDetailedLinkError(
			failure, OutgoingFailureInsufficientBalance,
		)
	}

	return nil
}

// Stats returns the statistics of channel link.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) Stats() (uint64, lnwire.MilliSatoshi, lnwire.MilliSatoshi) {
	snapshot := l.channel.StateSnapshot()

	return snapshot.ChannelCommitment.CommitHeight,
		snapshot.TotalMSatSent,
		snapshot.TotalMSatReceived
}

// String returns the string representation of channel link.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) String() string {
	return l.channel.ChannelPoint().String()
}

// HandleSwitchPacket handles the switch packets. This packets which might be
// forwarded to us from another channel link in case the htlc update came from
// another peer or if the update was created by user
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) HandleSwitchPacket(pkt *htlcPacket) error {
	l.log.Tracef("received switch packet inkey=%v, outkey=%v",
		pkt.inKey(), pkt.outKey())

	return l.mailBox.AddPacket(pkt)
}

// HandleLocalAddPacket handles a locally-initiated UpdateAddHTLC packet. It
// will be processed synchronously.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) HandleLocalAddPacket(pkt *htlcPacket) error {
	l.log.Tracef("received switch packet outkey=%v", pkt.outKey())

	// Create a buffered result channel to prevent the link from blocking.
	errChan := make(chan error, 1)

	select {
	case l.localUpdateAdd <- &localUpdateAddMsg{
		pkt: pkt,
		err: errChan,
	}:
	case <-l.quit:
		return ErrLinkShuttingDown
	}

	select {
	case err := <-errChan:
		return err
	case <-l.quit:
		return ErrLinkShuttingDown
	}
}

// HandleChannelUpdate handles the htlc requests as settle/add/fail which sent
// to us from remote peer we have a channel with.
//
// NOTE: Part of the ChannelLink interface.
func (l *channelLink) HandleChannelUpdate(message lnwire.Message) {
	l.mailBox.AddMessage(message)
}

// updateChannelFee updates the commitment fee-per-kw on this channel by
// committing to an update_fee message.
func (l *channelLink) updateChannelFee(feePerKw chainfee.SatPerKWeight) error {

	l.log.Infof("updating commit fee to %v sat/kw", feePerKw)

	// We skip sending the UpdateFee message if the channel is not
	// currently eligible to forward messages.
	if !l.EligibleToForward() {
		l.log.Debugf("skipping fee update for inactive channel")
		return nil
	}

	// First, we'll update the local fee on our commitment.
	if err := l.channel.UpdateFee(feePerKw); err != nil {
		return err
	}

	// We'll then attempt to send a new UpdateFee message, and also lock it
	// in immediately by triggering a commitment update.
	msg := lnwire.NewUpdateFee(l.ChanID(), uint32(feePerKw))
	if err := l.cfg.Peer.SendMessage(false, msg); err != nil {
		return err
	}
	return l.updateCommitTx()
}

// processRemoteSettleFails accepts a batch of settle/fail payment descriptors
// after receiving a revocation from the remote party, and reprocesses them in
// the context of the provided forwarding package. Any settles or fails that
// have already been acknowledged in the forwarding package will not be sent to
// the switch.
func (l *channelLink) processRemoteSettleFails(fwdPkg *channeldb.FwdPkg,
	settleFails []*lnwallet.PaymentDescriptor) {

	if len(settleFails) == 0 {
		return
	}

	l.log.Debugf("settle-fail-filter %v", fwdPkg.SettleFailFilter)

	var switchPackets []*htlcPacket
	for i, pd := range settleFails {
		// Skip any settles or fails that have already been
		// acknowledged by the incoming link that originated the
		// forwarded Add.
		if fwdPkg.SettleFailFilter.Contains(uint16(i)) {
			continue
		}

		// TODO(roasbeef): rework log entries to a shared
		// interface.

		switch pd.EntryType {

		// A settle for an HTLC we previously forwarded HTLC has been
		// received. So we'll forward the HTLC to the switch which will
		// handle propagating the settle to the prior hop.
		case lnwallet.Settle:
			// If hodl.SettleIncoming is requested, we will not
			// forward the SETTLE to the switch and will not signal
			// a free slot on the commitment transaction.
			if l.cfg.HodlMask.Active(hodl.SettleIncoming) {
				l.log.Warnf(hodl.SettleIncoming.Warning())
				continue
			}

			settlePacket := &htlcPacket{
				outgoingChanID: l.ShortChanID(),
				outgoingHTLCID: pd.ParentIndex,
				destRef:        pd.DestRef,
				htlc: &lnwire.UpdateFulfillHTLC{
					PaymentPreimage: pd.RPreimage,
				},
			}

			// Add the packet to the batch to be forwarded, and
			// notify the overflow queue that a spare spot has been
			// freed up within the commitment state.
			switchPackets = append(switchPackets, settlePacket)

		// A failureCode message for a previously forwarded HTLC has
		// been received. As a result a new slot will be freed up in
		// our commitment state, so we'll forward this to the switch so
		// the backwards undo can continue.
		case lnwallet.Fail:
			// If hodl.SettleIncoming is requested, we will not
			// forward the FAIL to the switch and will not signal a
			// free slot on the commitment transaction.
			if l.cfg.HodlMask.Active(hodl.FailIncoming) {
				l.log.Warnf(hodl.FailIncoming.Warning())
				continue
			}

			// Fetch the reason the HTLC was canceled so we can
			// continue to propagate it. This failure originated
			// from another node, so the linkFailure field is not
			// set on the packet.
			failPacket := &htlcPacket{
				outgoingChanID: l.ShortChanID(),
				outgoingHTLCID: pd.ParentIndex,
				destRef:        pd.DestRef,
				htlc: &lnwire.UpdateFailHTLC{
					Reason: lnwire.OpaqueReason(
						pd.FailReason,
					),
				},
			}

			l.log.Debugf("Failed to send %s", pd.Amount)

			// If the failure message lacks an HMAC (but includes
			// the 4 bytes for encoding the message and padding
			// lengths, then this means that we received it as an
			// UpdateFailMalformedHTLC. As a result, we'll signal
			// that we need to convert this error within the switch
			// to an actual error, by encrypting it as if we were
			// the originating hop.
			convertedErrorSize := lnwire.FailureMessageLength + 4
			if len(pd.FailReason) == convertedErrorSize {
				failPacket.convertedError = true
			}

			// Add the packet to the batch to be forwarded, and
			// notify the overflow queue that a spare spot has been
			// freed up within the commitment state.
			switchPackets = append(switchPackets, failPacket)
		}
	}

	// Only spawn the task forward packets we have a non-zero number.
	if len(switchPackets) > 0 {
		go l.forwardBatch(switchPackets...)
	}
}

// processRemoteAdds serially processes each of the Add payment descriptors
// which have been "locked-in" by receiving a revocation from the remote party.
// The forwarding package provided instructs how to process this batch,
// indicating whether this is the first time these Adds are being processed, or
// whether we are reprocessing as a result of a failure or restart. Adds that
// have already been acknowledged in the forwarding package will be ignored.
func (l *channelLink) processRemoteAdds(fwdPkg *channeldb.FwdPkg,
	lockedInHtlcs []*lnwallet.PaymentDescriptor) {

	l.log.Tracef("processing %d remote adds for height %d",
		len(lockedInHtlcs), fwdPkg.Height)

	decodeReqs := make(
		[]hop.DecodeHopIteratorRequest, 0, len(lockedInHtlcs),
	)
	for _, pd := range lockedInHtlcs {
		switch pd.EntryType {

		// TODO(conner): remove type switch?
		case lnwallet.Add:
			// Before adding the new htlc to the state machine,
			// parse the onion object in order to obtain the
			// routing information with DecodeHopIterator function
			// which process the Sphinx packet.
			onionReader := bytes.NewReader(pd.OnionBlob)

			req := hop.DecodeHopIteratorRequest{
				OnionReader:  onionReader,
				RHash:        pd.RHash[:],
				IncomingCltv: pd.Timeout,
			}

			decodeReqs = append(decodeReqs, req)
		}
	}

	// Atomically decode the incoming htlcs, simultaneously checking for
	// replay attempts. A particular index in the returned, spare list of
	// channel iterators should only be used if the failure code at the
	// same index is lnwire.FailCodeNone.
	decodeResps, sphinxErr := l.cfg.DecodeHopIterators(
		fwdPkg.ID(), decodeReqs,
	)
	if sphinxErr != nil {
		l.fail(LinkFailureError{code: ErrInternalError},
			"unable to decode hop iterators: %v", sphinxErr)
		return
	}

	var switchPackets []*htlcPacket

	for i, pd := range lockedInHtlcs {
		idx := uint16(i)

		if fwdPkg.State == channeldb.FwdStateProcessed &&
			fwdPkg.AckFilter.Contains(idx) {

			// If this index is already found in the ack filter,
			// the response to this forwarding decision has already
			// been committed by one of our commitment txns. ADDs
			// in this state are waiting for the rest of the fwding
			// package to get acked before being garbage collected.
			continue
		}

		// An incoming HTLC add has been full-locked in. As a result we
		// can now examine the forwarding details of the HTLC, and the
		// HTLC itself to decide if: we should forward it, cancel it,
		// or are able to settle it (and it adheres to our fee related
		// constraints).

		// Fetch the onion blob that was included within this processed
		// payment descriptor.
		var onionBlob [lnwire.OnionPacketSize]byte
		copy(onionBlob[:], pd.OnionBlob)

		// Before adding the new htlc to the state machine, parse the
		// onion object in order to obtain the routing information with
		// DecodeHopIterator function which process the Sphinx packet.
		chanIterator, failureCode := decodeResps[i].Result()
		if failureCode != lnwire.CodeNone {
			// If we're unable to process the onion blob than we
			// should send the malformed htlc error to payment
			// sender.
			l.sendMalformedHTLCError(pd.HtlcIndex, failureCode,
				onionBlob[:], pd.SourceRef)

			l.log.Errorf("unable to decode onion hop "+
				"iterator: %v", failureCode)
			continue
		}

		// Retrieve onion obfuscator from onion blob in order to
		// produce initial obfuscation of the onion failureCode.
		obfuscator, failureCode := chanIterator.ExtractErrorEncrypter(
			l.cfg.ExtractErrorEncrypter,
		)
		if failureCode != lnwire.CodeNone {
			// If we're unable to process the onion blob than we
			// should send the malformed htlc error to payment
			// sender.
			l.sendMalformedHTLCError(
				pd.HtlcIndex, failureCode, onionBlob[:], pd.SourceRef,
			)

			l.log.Errorf("unable to decode onion "+
				"obfuscator: %v", failureCode)
			continue
		}

		heightNow := l.cfg.BestHeight()

		pld, err := chanIterator.HopPayload()
		if err != nil {
			// If we're unable to process the onion payload, or we
			// received invalid onion payload failure, then we
			// should send an error back to the caller so the HTLC
			// can be canceled.
			var failedType uint64
			if e, ok := err.(hop.ErrInvalidPayload); ok {
				failedType = uint64(e.Type)
			}

			// TODO: currently none of the test unit infrastructure
			// is setup to handle TLV payloads, so testing this
			// would require implementing a separate mock iterator
			// for TLV payloads that also supports injecting invalid
			// payloads. Deferring this non-trival effort till a
			// later date
			failure := lnwire.NewInvalidOnionPayload(failedType, 0)
			l.sendHTLCError(
				pd, NewLinkError(failure), obfuscator, false,
			)

			l.log.Errorf("unable to decode forwarding "+
				"instructions: %v", err)
			continue
		}

		fwdInfo := pld.ForwardingInfo()

		switch fwdInfo.NextHop {
		case hop.Exit:
			err := l.processExitHop(
				pd, obfuscator, fwdInfo, heightNow, pld,
			)
			if err != nil {
				l.fail(LinkFailureError{code: ErrInternalError},
					err.Error(),
				)

				return
			}

		// There are additional channels left within this route. So
		// we'll simply do some forwarding package book-keeping.
		default:
			// If hodl.AddIncoming is requested, we will not
			// validate the forwarded ADD, nor will we send the
			// packet to the htlc switch.
			if l.cfg.HodlMask.Active(hodl.AddIncoming) {
				l.log.Warnf(hodl.AddIncoming.Warning())
				continue
			}

			switch fwdPkg.State {
			case channeldb.FwdStateProcessed:
				// This add was not forwarded on the previous
				// processing phase, run it through our
				// validation pipeline to reproduce an error.
				// This may trigger a different error due to
				// expiring timelocks, but we expect that an
				// error will be reproduced.
				if !fwdPkg.FwdFilter.Contains(idx) {
					break
				}

				// Otherwise, it was already processed, we can
				// can collect it and continue.
				addMsg := &lnwire.UpdateAddHTLC{
					Expiry:      fwdInfo.OutgoingCTLV,
					Amount:      fwdInfo.AmountToForward,
					PaymentHash: pd.RHash,
				}

				// Finally, we'll encode the onion packet for
				// the _next_ hop using the hop iterator
				// decoded for the current hop.
				buf := bytes.NewBuffer(addMsg.OnionBlob[0:0])

				// We know this cannot fail, as this ADD
				// was marked forwarded in a previous
				// round of processing.
				chanIterator.EncodeNextHop(buf)

				updatePacket := &htlcPacket{
					incomingChanID:  l.ShortChanID(),
					incomingHTLCID:  pd.HtlcIndex,
					outgoingChanID:  fwdInfo.NextHop,
					sourceRef:       pd.SourceRef,
					incomingAmount:  pd.Amount,
					amount:          addMsg.Amount,
					htlc:            addMsg,
					obfuscator:      obfuscator,
					incomingTimeout: pd.Timeout,
					outgoingTimeout: fwdInfo.OutgoingCTLV,
					customRecords:   pld.CustomRecords(),
				}
				switchPackets = append(
					switchPackets, updatePacket,
				)

				continue
			}

			// TODO(roasbeef): ensure don't accept outrageous
			// timeout for htlc

			// With all our forwarding constraints met, we'll
			// create the outgoing HTLC using the parameters as
			// specified in the forwarding info.
			addMsg := &lnwire.UpdateAddHTLC{
				Expiry:      fwdInfo.OutgoingCTLV,
				Amount:      fwdInfo.AmountToForward,
				PaymentHash: pd.RHash,
			}

			// Finally, we'll encode the onion packet for the
			// _next_ hop using the hop iterator decoded for the
			// current hop.
			buf := bytes.NewBuffer(addMsg.OnionBlob[0:0])
			err := chanIterator.EncodeNextHop(buf)
			if err != nil {
				l.log.Errorf("unable to encode the "+
					"remaining route %v", err)

				failure := l.createFailureWithUpdate(
					func(upd *lnwire.ChannelUpdate) lnwire.FailureMessage {
						return lnwire.NewTemporaryChannelFailure(
							upd,
						)
					},
				)

				l.sendHTLCError(
					pd, NewLinkError(failure), obfuscator, false,
				)
				continue
			}

			// Now that this add has been reprocessed, only append
			// it to our list of packets to forward to the switch
			// this is the first time processing the add. If the
			// fwd pkg has already been processed, then we entered
			// the above section to recreate a previous error.  If
			// the packet had previously been forwarded, it would
			// have been added to switchPackets at the top of this
			// section.
			if fwdPkg.State == channeldb.FwdStateLockedIn {
				updatePacket := &htlcPacket{
					incomingChanID:  l.ShortChanID(),
					incomingHTLCID:  pd.HtlcIndex,
					outgoingChanID:  fwdInfo.NextHop,
					sourceRef:       pd.SourceRef,
					incomingAmount:  pd.Amount,
					amount:          addMsg.Amount,
					htlc:            addMsg,
					obfuscator:      obfuscator,
					incomingTimeout: pd.Timeout,
					outgoingTimeout: fwdInfo.OutgoingCTLV,
					customRecords:   pld.CustomRecords(),
				}

				fwdPkg.FwdFilter.Set(idx)
				switchPackets = append(switchPackets,
					updatePacket)
			}
		}
	}

	// Commit the htlcs we are intending to forward if this package has not
	// been fully processed.
	if fwdPkg.State == channeldb.FwdStateLockedIn {
		err := l.channel.SetFwdFilter(fwdPkg.Height, fwdPkg.FwdFilter)
		if err != nil {
			l.fail(LinkFailureError{code: ErrInternalError},
				"unable to set fwd filter: %v", err)
			return
		}
	}

	if len(switchPackets) == 0 {
		return
	}

	l.log.Debugf("forwarding %d packets to switch", len(switchPackets))

	// NOTE: This call is made synchronous so that we ensure all circuits
	// are committed in the exact order that they are processed in the link.
	// Failing to do this could cause reorderings/gaps in the range of
	// opened circuits, which violates assumptions made by the circuit
	// trimming.
	l.forwardBatch(switchPackets...)
}

// processExitHop handles an htlc for which this link is the exit hop. It
// returns a boolean indicating whether the commitment tx needs an update.
func (l *channelLink) processExitHop(pd *lnwallet.PaymentDescriptor,
	obfuscator hop.ErrorEncrypter, fwdInfo hop.ForwardingInfo,
	heightNow uint32, payload invoices.Payload) error {

	// If hodl.ExitSettle is requested, we will not validate the final hop's
	// ADD, nor will we settle the corresponding invoice or respond with the
	// preimage.
	if l.cfg.HodlMask.Active(hodl.ExitSettle) {
		l.log.Warnf(hodl.ExitSettle.Warning())

		return nil
	}

	// As we're the exit hop, we'll double check the hop-payload included in
	// the HTLC to ensure that it was crafted correctly by the sender and
	// matches the HTLC we were extended.
	if pd.Amount != fwdInfo.AmountToForward {

		l.log.Errorf("onion payload of incoming htlc(%x) has incorrect "+
			"value: expected %v, got %v", pd.RHash,
			pd.Amount, fwdInfo.AmountToForward)

		failure := NewLinkError(
			lnwire.NewFinalIncorrectHtlcAmount(pd.Amount),
		)
		l.sendHTLCError(pd, failure, obfuscator, true)

		return nil
	}

	// We'll also ensure that our time-lock value has been computed
	// correctly.
	if pd.Timeout != fwdInfo.OutgoingCTLV {
		l.log.Errorf("onion payload of incoming htlc(%x) has incorrect "+
			"time-lock: expected %v, got %v",
			pd.RHash[:], pd.Timeout, fwdInfo.OutgoingCTLV)

		failure := NewLinkError(
			lnwire.NewFinalIncorrectCltvExpiry(pd.Timeout),
		)
		l.sendHTLCError(pd, failure, obfuscator, true)

		return nil
	}

	// Notify the invoiceRegistry of the exit hop htlc. If we crash right
	// after this, this code will be re-executed after restart. We will
	// receive back a resolution event.
	invoiceHash := lntypes.Hash(pd.RHash)

	circuitKey := channeldb.CircuitKey{
		ChanID: l.ShortChanID(),
		HtlcID: pd.HtlcIndex,
	}

	event, err := l.cfg.Registry.NotifyExitHopHtlc(
		invoiceHash, pd.Amount, pd.Timeout, int32(heightNow),
		circuitKey, l.hodlQueue.ChanIn(), payload,
	)
	if err != nil {
		return err
	}

	// Create a hodlHtlc struct and decide either resolved now or later.
	htlc := hodlHtlc{
		pd:         pd,
		obfuscator: obfuscator,
	}

	// If the event is nil, the invoice is being held, so we save payment
	// descriptor for future reference.
	if event == nil {
		l.hodlMap[circuitKey] = htlc
		return nil
	}

	// Process the received resolution.
	return l.processHtlcResolution(event, htlc)
}

// settleHTLC settles the HTLC on the channel.
func (l *channelLink) settleHTLC(preimage lntypes.Preimage,
	pd *lnwallet.PaymentDescriptor) error {

	hash := preimage.Hash()

	l.log.Infof("settling htlc %v as exit hop", hash)

	err := l.channel.SettleHTLC(
		preimage, pd.HtlcIndex, pd.SourceRef, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to settle htlc: %v", err)
	}

	// If the link is in hodl.BogusSettle mode, replace the preimage with a
	// fake one before sending it to the peer.
	if l.cfg.HodlMask.Active(hodl.BogusSettle) {
		l.log.Warnf(hodl.BogusSettle.Warning())
		preimage = [32]byte{}
		copy(preimage[:], bytes.Repeat([]byte{2}, 32))
	}

	// HTLC was successfully settled locally send notification about it
	// remote peer.
	l.cfg.Peer.SendMessage(false, &lnwire.UpdateFulfillHTLC{
		ChanID:          l.ChanID(),
		ID:              pd.HtlcIndex,
		PaymentPreimage: preimage,
	})

	// Once we have successfully settled the htlc, notify a settle event.
	l.cfg.HtlcNotifier.NotifySettleEvent(
		HtlcKey{
			IncomingCircuit: channeldb.CircuitKey{
				ChanID: l.ShortChanID(),
				HtlcID: pd.HtlcIndex,
			},
		},
		preimage,
		HtlcEventTypeReceive,
	)

	return nil
}

// forwardBatch forwards the given htlcPackets to the switch, and waits on the
// err chan for the individual responses. This method is intended to be spawned
// as a goroutine so the responses can be handled in the background.
func (l *channelLink) forwardBatch(packets ...*htlcPacket) {
	// Don't forward packets for which we already have a response in our
	// mailbox. This could happen if a packet fails and is buffered in the
	// mailbox, and the incoming link flaps.
	var filteredPkts = make([]*htlcPacket, 0, len(packets))
	for _, pkt := range packets {
		if l.mailBox.HasPacket(pkt.inKey()) {
			continue
		}

		filteredPkts = append(filteredPkts, pkt)
	}

	if err := l.cfg.ForwardPackets(l.quit, filteredPkts...); err != nil {
		log.Errorf("Unhandled error while reforwarding htlc "+
			"settle/fail over htlcswitch: %v", err)
	}
}

// sendHTLCError functions cancels HTLC and send cancel message back to the
// peer from which HTLC was received.
func (l *channelLink) sendHTLCError(pd *lnwallet.PaymentDescriptor,
	failure *LinkError, e hop.ErrorEncrypter, isReceive bool) {

	reason, err := e.EncryptFirstHop(failure.WireMessage())
	if err != nil {
		l.log.Errorf("unable to obfuscate error: %v", err)
		return
	}

	err = l.channel.FailHTLC(pd.HtlcIndex, reason, pd.SourceRef, nil, nil)
	if err != nil {
		l.log.Errorf("unable cancel htlc: %v", err)
		return
	}

	l.cfg.Peer.SendMessage(false, &lnwire.UpdateFailHTLC{
		ChanID: l.ChanID(),
		ID:     pd.HtlcIndex,
		Reason: reason,
	})

	// Notify a link failure on our incoming link. Outgoing htlc information
	// is not available at this point, because we have not decrypted the
	// onion, so it is excluded.
	var eventType HtlcEventType
	if isReceive {
		eventType = HtlcEventTypeReceive
	} else {
		eventType = HtlcEventTypeForward
	}

	l.cfg.HtlcNotifier.NotifyLinkFailEvent(
		HtlcKey{
			IncomingCircuit: channeldb.CircuitKey{
				ChanID: l.ShortChanID(),
				HtlcID: pd.HtlcIndex,
			},
		},
		HtlcInfo{
			IncomingTimeLock: pd.Timeout,
			IncomingAmt:      pd.Amount,
		},
		eventType,
		failure,
		true,
	)
}

// sendMalformedHTLCError helper function which sends the malformed HTLC update
// to the payment sender.
func (l *channelLink) sendMalformedHTLCError(htlcIndex uint64,
	code lnwire.FailCode, onionBlob []byte, sourceRef *channeldb.AddRef) {

	shaOnionBlob := sha256.Sum256(onionBlob)
	err := l.channel.MalformedFailHTLC(htlcIndex, code, shaOnionBlob, sourceRef)
	if err != nil {
		l.log.Errorf("unable cancel htlc: %v", err)
		return
	}

	l.cfg.Peer.SendMessage(false, &lnwire.UpdateFailMalformedHTLC{
		ChanID:       l.ChanID(),
		ID:           htlcIndex,
		ShaOnionBlob: shaOnionBlob,
		FailureCode:  code,
	})
}

// fail is a function which is used to encapsulate the action necessary for
// properly failing the link. It takes a LinkFailureError, which will be passed
// to the OnChannelFailure closure, in order for it to determine if we should
// force close the channel, and if we should send an error message to the
// remote peer.
func (l *channelLink) fail(linkErr LinkFailureError,
	format string, a ...interface{}) {
	reason := errors.Errorf(format, a...)

	// Return if we have already notified about a failure.
	if l.failed {
		l.log.Warnf("ignoring link failure (%v), as link already "+
			"failed", reason)
		return
	}

	l.log.Errorf("failing link: %s with error: %v", reason, linkErr)

	// Set failed, such that we won't process any more updates, and notify
	// the peer about the failure.
	l.failed = true
	l.cfg.OnChannelFailure(l.ChanID(), l.ShortChanID(), linkErr)
}
