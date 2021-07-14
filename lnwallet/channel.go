package lnwallet

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// ErrChanClosing is returned when a caller attempts to close a channel
	// that has already been closed or is in the process of being closed.
	ErrChanClosing = fmt.Errorf("channel is being closed, operation disallowed")

	// ErrNoWindow is returned when revocation window is exhausted.
	ErrNoWindow = fmt.Errorf("unable to sign new commitment, the current" +
		" revocation window is exhausted")

	// ErrMaxWeightCost is returned when the cost/weight (see segwit)
	// exceeds the widely used maximum allowed policy weight limit. In this
	// case the commitment transaction can't be propagated through the
	// network.
	ErrMaxWeightCost = fmt.Errorf("commitment transaction exceed max " +
		"available cost")

	// ErrMaxHTLCNumber is returned when a proposed HTLC would exceed the
	// maximum number of allowed HTLC's if committed in a state transition
	ErrMaxHTLCNumber = fmt.Errorf("commitment transaction exceed max " +
		"htlc number")

	// ErrMaxPendingAmount is returned when a proposed HTLC would exceed
	// the overall maximum pending value of all HTLCs if committed in a
	// state transition.
	ErrMaxPendingAmount = fmt.Errorf("commitment transaction exceed max" +
		"overall pending htlc value")

	// ErrBelowChanReserve is returned when a proposed HTLC would cause
	// one of the peer's funds to dip below the channel reserve limit.
	ErrBelowChanReserve = fmt.Errorf("commitment transaction dips peer " +
		"below chan reserve")

	// ErrBelowMinHTLC is returned when a proposed HTLC has a value that
	// is below the minimum HTLC value constraint for either us or our
	// peer depending on which flags are set.
	ErrBelowMinHTLC = fmt.Errorf("proposed HTLC value is below minimum " +
		"allowed HTLC value")

	// ErrInvalidHTLCAmt signals that a proposed HTLC has a value that is
	// not positive.
	ErrInvalidHTLCAmt = fmt.Errorf("proposed HTLC value must be positive")

	// ErrCannotSyncCommitChains is returned if, upon receiving a ChanSync
	// message, the state machine deems that is unable to properly
	// synchronize states with the remote peer. In this case we should fail
	// the channel, but we won't automatically force close.
	ErrCannotSyncCommitChains = fmt.Errorf("unable to sync commit chains")

	// ErrInvalidLastCommitSecret is returned in the case that the
	// commitment secret sent by the remote party in their
	// ChannelReestablish message doesn't match the last secret we sent.
	ErrInvalidLastCommitSecret = fmt.Errorf("commit secret is incorrect")

	// ErrInvalidLocalUnrevokedCommitPoint is returned in the case that the
	// commitment point sent by the remote party in their
	// ChannelReestablish message doesn't match the last unrevoked commit
	// point they sent us.
	ErrInvalidLocalUnrevokedCommitPoint = fmt.Errorf("unrevoked commit " +
		"point is invalid")

	// ErrCommitSyncRemoteDataLoss is returned in the case that we receive
	// a ChannelReestablish message from the remote that advertises a
	// NextLocalCommitHeight that is lower than what they have already
	// ACKed, or a RemoteCommitTailHeight that is lower than our revoked
	// height. In this case we should force close the channel such that
	// both parties can retrieve their funds.
	ErrCommitSyncRemoteDataLoss = fmt.Errorf("possible remote commitment " +
		"state data loss")
)

// ErrCommitSyncLocalDataLoss is returned in the case that we receive a valid
// commit secret within the ChannelReestablish message from the remote node AND
// they advertise a RemoteCommitTailHeight higher than our current known
// height. This means we have lost some critical data, and must fail the
// channel and MUST NOT force close it. Instead we should wait for the remote
// to force close it, such that we can attempt to sweep our funds. The
// commitment point needed to sweep the remote's force close is encapsuled.
type ErrCommitSyncLocalDataLoss struct {
	// ChannelPoint is the identifier for the channel that experienced data
	// loss.
	ChannelPoint wire.OutPoint

	// CommitPoint is the last unrevoked commit point, sent to us by the
	// remote when we determined we had lost state.
	CommitPoint *btcec.PublicKey
}

// Error returns a string representation of the local data loss error.
func (e *ErrCommitSyncLocalDataLoss) Error() string {
	return fmt.Sprintf("ChannelPoint(%v) with CommitPoint(%x) had "+
		"possible local commitment state data loss", e.ChannelPoint,
		e.CommitPoint.SerializeCompressed())
}

// channelState is an enum like type which represents the current state of a
// particular channel.
// TODO(roasbeef): actually update state
type channelState uint8

const (
	// channelPending indicates this channel is still going through the
	// funding workflow, and isn't yet open.
	channelPending channelState = iota // nolint: unused

	// channelOpen represents an open, active channel capable of
	// sending/receiving HTLCs.
	channelOpen

	// channelClosing represents a channel which is in the process of being
	// closed.
	channelClosing

	// channelClosed represents a channel which has been fully closed. Note
	// that before a channel can be closed, ALL pending HTLCs must be
	// settled/removed.
	channelClosed

	// channelDispute indicates that an un-cooperative closure has been
	// detected within the channel.
	channelDispute

	// channelPendingPayment indicates that there a currently outstanding
	// HTLCs within the channel.
	channelPendingPayment // nolint:unused
)

// PaymentHash represents the sha256 of a random value. This hash is used to
// uniquely track incoming/outgoing payments within this channel, as well as
// payments requested by the wallet/daemon.
type PaymentHash [32]byte

// updateType is the exact type of an entry within the shared HTLC log.
type updateType uint8

const (
	// Add is an update type that adds a new HTLC entry into the log.
	// Either side can add a new pending HTLC by adding a new Add entry
	// into their update log.
	Add updateType = iota

	// Fail is an update type which removes a prior HTLC entry from the
	// log. Adding a Fail entry to ones log will modify the _remote_
	// parties update log once a new commitment view has been evaluated
	// which contains the Fail entry.
	Fail

	// MalformedFail is an update type which removes a prior HTLC entry
	// from the log. Adding a MalformedFail entry to ones log will modify
	// the _remote_ parties update log once a new commitment view has been
	// evaluated which contains the MalformedFail entry. The difference
	// from Fail type lie in the different data we have to store.
	MalformedFail

	// Settle is an update type which settles a prior HTLC crediting the
	// balance of the receiving node. Adding a Settle entry to a log will
	// result in the settle entry being removed on the log as well as the
	// original add entry from the remote party's log after the next state
	// transition.
	Settle

	// FeeUpdate is an update type sent by the channel initiator that
	// updates the fee rate used when signing the commitment transaction.
	FeeUpdate
)

// String returns a human readable string that uniquely identifies the target
// update type.
func (u updateType) String() string {
	switch u {
	case Add:
		return "Add"
	case Fail:
		return "Fail"
	case MalformedFail:
		return "MalformedFail"
	case Settle:
		return "Settle"
	case FeeUpdate:
		return "FeeUpdate"
	default:
		return "<unknown type>"
	}
}

// PaymentDescriptor represents a commitment state update which either adds,
// settles, or removes an HTLC. PaymentDescriptors encapsulate all necessary
// metadata w.r.t to an HTLC, and additional data pairing a settle message to
// the original added HTLC.
//
// TODO(roasbeef): LogEntry interface??
//  * need to separate attrs for cancel/add/settle/feeupdate
type PaymentDescriptor struct {
	// RHash is the payment hash for this HTLC. The HTLC can be settled iff
	// the preimage to this hash is presented.
	RHash PaymentHash

	// RPreimage is the preimage that settles the HTLC pointed to within the
	// log by the ParentIndex.
	RPreimage PaymentHash

	// Timeout is the absolute timeout in blocks, after which this HTLC
	// expires.
	Timeout uint32

	// Amount is the HTLC amount in milli-satoshis.
	Amount lnwire.MilliSatoshi

	// LogIndex is the log entry number that his HTLC update has within the
	// log. Depending on if IsIncoming is true, this is either an entry the
	// remote party added, or one that we added locally.
	LogIndex uint64

	// HtlcIndex is the index within the main update log for this HTLC.
	// Entries within the log of type Add will have this field populated,
	// as other entries will point to the entry via this counter.
	//
	// NOTE: This field will only be populate if EntryType is Add.
	HtlcIndex uint64

	// ParentIndex is the HTLC index of the entry that this update settles or
	// times out.
	//
	// NOTE: This field will only be populate if EntryType is Fail or
	// Settle.
	ParentIndex uint64

	// SourceRef points to an Add update in a forwarding package owned by
	// this channel.
	//
	// NOTE: This field will only be populated if EntryType is Fail or
	// Settle.
	SourceRef *channeldb.AddRef

	// DestRef points to a Fail/Settle update in another link's forwarding
	// package.
	//
	// NOTE: This field will only be populated if EntryType is Fail or
	// Settle, and the forwarded Add successfully included in an outgoing
	// link's commitment txn.
	DestRef *channeldb.SettleFailRef

	// OpenCircuitKey references the incoming Chan/HTLC ID of an Add HTLC
	// packet delivered by the switch.
	//
	// NOTE: This field is only populated for payment descriptors in the
	// *local* update log, and if the Add packet was delivered by the
	// switch.
	OpenCircuitKey *channeldb.CircuitKey

	// ClosedCircuitKey references the incoming Chan/HTLC ID of the Add HTLC
	// that opened the circuit.
	//
	// NOTE: This field is only populated for payment descriptors in the
	// *local* update log, and if settle/fails have a committed circuit in
	// the circuit map.
	ClosedCircuitKey *channeldb.CircuitKey

	// localOutputIndex is the output index of this HTLc output in the
	// commitment transaction of the local node.
	//
	// NOTE: If the output is dust from the PoV of the local commitment
	// chain, then this value will be -1.
	localOutputIndex int32

	// remoteOutputIndex is the output index of this HTLC output in the
	// commitment transaction of the remote node.
	//
	// NOTE: If the output is dust from the PoV of the remote commitment
	// chain, then this value will be -1.
	remoteOutputIndex int32

	// sig is the signature for the second-level HTLC transaction that
	// spends the version of this HTLC on the commitment transaction of the
	// local node. This signature is generated by the remote node and
	// stored by the local node in the case that local node needs to
	// broadcast their commitment transaction.
	sig *btcec.Signature

	// addCommitHeight[Remote|Local] encodes the height of the commitment
	// which included this HTLC on either the remote or local commitment
	// chain. This value is used to determine when an HTLC is fully
	// "locked-in".
	addCommitHeightRemote uint64
	addCommitHeightLocal  uint64

	// removeCommitHeight[Remote|Local] encodes the height of the
	// commitment which removed the parent pointer of this
	// PaymentDescriptor either due to a timeout or a settle. Once both
	// these heights are below the tail of both chains, the log entries can
	// safely be removed.
	removeCommitHeightRemote uint64
	removeCommitHeightLocal  uint64

	// OnionBlob is an opaque blob which is used to complete multi-hop
	// routing.
	//
	// NOTE: Populated only on add payment descriptor entry types.
	OnionBlob []byte

	// ShaOnionBlob is a sha of the onion blob.
	//
	// NOTE: Populated only in payment descriptor with MalformedFail type.
	ShaOnionBlob [sha256.Size]byte

	// FailReason stores the reason why a particular payment was canceled.
	//
	// NOTE: Populate only in fail payment descriptor entry types.
	FailReason []byte

	// FailCode stores the code why a particular payment was canceled.
	//
	// NOTE: Populated only in payment descriptor with MalformedFail type.
	FailCode lnwire.FailCode

	// [our|their|]PkScript are the raw public key scripts that encodes the
	// redemption rules for this particular HTLC. These fields will only be
	// populated iff the EntryType of this PaymentDescriptor is Add.
	// ourPkScript is the ourPkScript from the context of our local
	// commitment chain. theirPkScript is the latest pkScript from the
	// context of the remote commitment chain.
	//
	// NOTE: These values may change within the logs themselves, however,
	// they'll stay consistent within the commitment chain entries
	// themselves.
	ourPkScript        []byte
	ourWitnessScript   []byte
	theirPkScript      []byte
	theirWitnessScript []byte

	// EntryType denotes the exact type of the PaymentDescriptor. In the
	// case of a Timeout, or Settle type, then the Parent field will point
	// into the log to the HTLC being modified.
	EntryType updateType

	// isForwarded denotes if an incoming HTLC has been forwarded to any
	// possible upstream peers in the route.
	isForwarded bool
}

// PayDescsFromRemoteLogUpdates converts a slice of LogUpdates received from the
// remote peer into PaymentDescriptors to inform a link's forwarding decisions.
//
// NOTE: The provided `logUpdates` MUST corresponding exactly to either the Adds
// or SettleFails in this channel's forwarding package at `height`.
func PayDescsFromRemoteLogUpdates(chanID lnwire.ShortChannelID, height uint64,
	logUpdates []channeldb.LogUpdate) ([]*PaymentDescriptor, error) {

	// Allocate enough space to hold all of the payment descriptors we will
	// reconstruct, and also the list of pointers that will be returned to
	// the caller.
	payDescs := make([]PaymentDescriptor, 0, len(logUpdates))
	payDescPtrs := make([]*PaymentDescriptor, 0, len(logUpdates))

	// Iterate over the log updates we loaded from disk, and reconstruct the
	// payment descriptor corresponding to one of the four types of htlcs we
	// can receive from the remote peer. We only repopulate the information
	// necessary to process the packets and, if necessary, forward them to
	// the switch.
	//
	// For each log update, we include either an AddRef or a SettleFailRef
	// so that they can be ACK'd and garbage collected.
	for i, logUpdate := range logUpdates {
		var pd PaymentDescriptor
		switch wireMsg := logUpdate.UpdateMsg.(type) {

		case *lnwire.UpdateAddHTLC:
			pd = PaymentDescriptor{
				RHash:     wireMsg.PaymentHash,
				Timeout:   wireMsg.Expiry,
				Amount:    wireMsg.Amount,
				EntryType: Add,
				HtlcIndex: wireMsg.ID,
				LogIndex:  logUpdate.LogIndex,
				SourceRef: &channeldb.AddRef{
					Height: height,
					Index:  uint16(i),
				},
			}
			pd.OnionBlob = make([]byte, len(wireMsg.OnionBlob))
			copy(pd.OnionBlob[:], wireMsg.OnionBlob[:])

		case *lnwire.UpdateFulfillHTLC:
			pd = PaymentDescriptor{
				RPreimage:   wireMsg.PaymentPreimage,
				ParentIndex: wireMsg.ID,
				EntryType:   Settle,
				DestRef: &channeldb.SettleFailRef{
					Source: chanID,
					Height: height,
					Index:  uint16(i),
				},
			}

		case *lnwire.UpdateFailHTLC:
			pd = PaymentDescriptor{
				ParentIndex: wireMsg.ID,
				EntryType:   Fail,
				FailReason:  wireMsg.Reason[:],
				DestRef: &channeldb.SettleFailRef{
					Source: chanID,
					Height: height,
					Index:  uint16(i),
				},
			}

		case *lnwire.UpdateFailMalformedHTLC:
			pd = PaymentDescriptor{
				ParentIndex:  wireMsg.ID,
				EntryType:    MalformedFail,
				FailCode:     wireMsg.FailureCode,
				ShaOnionBlob: wireMsg.ShaOnionBlob,
				DestRef: &channeldb.SettleFailRef{
					Source: chanID,
					Height: height,
					Index:  uint16(i),
				},
			}

		// NOTE: UpdateFee is not expected since they are not forwarded.
		case *lnwire.UpdateFee:
			return nil, fmt.Errorf("unexpected update fee")

		}

		payDescs = append(payDescs, pd)
		payDescPtrs = append(payDescPtrs, &payDescs[i])
	}

	return payDescPtrs, nil
}

// commitment represents a commitment to a new state within an active channel.
// New commitments can be initiated by either side. Commitments are ordered
// into a commitment chain, with one existing for both parties. Each side can
// independently extend the other side's commitment chain, up to a certain
// "revocation window", which once reached, disallows new commitments until
// the local nodes receives the revocation for the remote node's chain tail.
type commitment struct {
	// height represents the commitment height of this commitment, or the
	// update number of this commitment.
	height uint64

	// isOurs indicates whether this is the local or remote node's version
	// of the commitment.
	isOurs bool

	// [our|their]MessageIndex are indexes into the HTLC log, up to which
	// this commitment transaction includes. These indexes allow both sides
	// to independently, and concurrent send create new commitments. Each
	// new commitment sent to the remote party includes an index in the
	// shared log which details which of their updates we're including in
	// this new commitment.
	ourMessageIndex   uint64
	theirMessageIndex uint64

	// [our|their]HtlcIndex are the current running counters for the HTLC's
	// offered by either party. This value is incremented each time a party
	// offers a new HTLC. The log update methods that consume HTLC's will
	// reference these counters, rather than the running cumulative message
	// counters.
	ourHtlcIndex   uint64
	theirHtlcIndex uint64

	// txn is the commitment transaction generated by including any HTLC
	// updates whose index are below the two indexes listed above. If this
	// commitment is being added to the remote chain, then this txn is
	// their version of the commitment transactions. If the local commit
	// chain is being modified, the opposite is true.
	txn *wire.MsgTx

	// sig is a signature for the above commitment transaction.
	sig []byte

	// [our|their]Balance represents the settled balances at this point
	// within the commitment chain. This balance is computed by properly
	// evaluating all the add/remove/settle log entries before the listed
	// indexes.
	//
	// NOTE: This is the balance *after* subtracting any commitment fee,
	// AND anchor output values.
	ourBalance   lnwire.MilliSatoshi
	theirBalance lnwire.MilliSatoshi

	// fee is the amount that will be paid as fees for this commitment
	// transaction. The fee is recorded here so that it can be added back
	// and recalculated for each new update to the channel state.
	fee btcutil.Amount

	// feePerKw is the fee per kw used to calculate this commitment
	// transaction's fee.
	feePerKw chainfee.SatPerKWeight

	// dustLimit is the limit on the commitment transaction such that no
	// output values should be below this amount.
	dustLimit btcutil.Amount

	// outgoingHTLCs is a slice of all the outgoing HTLC's (from our PoV)
	// on this commitment transaction.
	outgoingHTLCs []PaymentDescriptor

	// incomingHTLCs is a slice of all the incoming HTLC's (from our PoV)
	// on this commitment transaction.
	incomingHTLCs []PaymentDescriptor

	// [outgoing|incoming]HTLCIndex is an index that maps an output index
	// on the commitment transaction to the payment descriptor that
	// represents the HTLC output.
	//
	// NOTE: that these fields are only populated if this commitment state
	// belongs to the local node. These maps are used when validating any
	// HTLC signatures which are part of the local commitment state. We use
	// this map in order to locate the details needed to validate an HTLC
	// signature while iterating of the outputs in the local commitment
	// view.
	outgoingHTLCIndex map[int32]*PaymentDescriptor
	incomingHTLCIndex map[int32]*PaymentDescriptor
}

// locateOutputIndex is a small helper function to locate the output index of a
// particular HTLC within the current commitment transaction. The duplicate map
// massed in is to be retained for each output within the commitment
// transition.  This ensures that we don't assign multiple HTLC's to the same
// index within the commitment transaction.
func locateOutputIndex(p *PaymentDescriptor, tx *wire.MsgTx, ourCommit bool,
	dups map[PaymentHash][]int32, cltvs []uint32) (int32, error) {

	// Checks to see if element (e) exists in slice (s).
	contains := func(s []int32, e int32) bool {
		for _, a := range s {
			if a == e {
				return true
			}
		}
		return false
	}

	// If this their commitment transaction, we'll be trying to locate
	// their pkScripts, otherwise we'll be looking for ours. This is
	// required as the commitment states are asymmetric in order to ascribe
	// blame in the case of a contract breach.
	pkScript := p.theirPkScript
	if ourCommit {
		pkScript = p.ourPkScript
	}

	for i, txOut := range tx.TxOut {
		cltv := cltvs[i]

		if bytes.Equal(txOut.PkScript, pkScript) &&
			txOut.Value == int64(p.Amount.ToSatoshis()) &&
			cltv == p.Timeout {

			// If this payment hash and index has already been
			// found, then we'll continue in order to avoid any
			// duplicate indexes.
			if contains(dups[p.RHash], int32(i)) {
				continue
			}

			idx := int32(i)
			dups[p.RHash] = append(dups[p.RHash], idx)
			return idx, nil
		}
	}

	return 0, fmt.Errorf("unable to find htlc: script=%x, value=%v, "+
		"cltv=%v", pkScript, p.Amount, p.Timeout)
}

// populateHtlcIndexes modifies the set of HTLC's locked-into the target view
// to have full indexing information populated. This information is required as
// we need to keep track of the indexes of each HTLC in order to properly write
// the current state to disk, and also to locate the PaymentDescriptor
// corresponding to HTLC outputs in the commitment transaction.
func (c *commitment) populateHtlcIndexes(chanType channeldb.ChannelType,
	cltvs []uint32) error {

	// First, we'll set up some state to allow us to locate the output
	// index of the all the HTLC's within the commitment transaction. We
	// must keep this index so we can validate the HTLC signatures sent to
	// us.
	dups := make(map[PaymentHash][]int32)
	c.outgoingHTLCIndex = make(map[int32]*PaymentDescriptor)
	c.incomingHTLCIndex = make(map[int32]*PaymentDescriptor)

	// populateIndex is a helper function that populates the necessary
	// indexes within the commitment view for a particular HTLC.
	populateIndex := func(htlc *PaymentDescriptor, incoming bool) error {
		isDust := htlcIsDust(
			chanType, incoming, c.isOurs, c.feePerKw,
			htlc.Amount.ToSatoshis(), c.dustLimit,
		)

		var err error
		switch {

		// If this is our commitment transaction, and this is a dust
		// output then we mark it as such using a -1 index.
		case c.isOurs && isDust:
			htlc.localOutputIndex = -1

		// If this is the commitment transaction of the remote party,
		// and this is a dust output then we mark it as such using a -1
		// index.
		case !c.isOurs && isDust:
			htlc.remoteOutputIndex = -1

		// If this is our commitment transaction, then we'll need to
		// locate the output and the index so we can verify an HTLC
		// signatures.
		case c.isOurs:
			htlc.localOutputIndex, err = locateOutputIndex(
				htlc, c.txn, c.isOurs, dups, cltvs,
			)
			if err != nil {
				return err
			}

			// As this is our commitment transactions, we need to
			// keep track of the locations of each output on the
			// transaction so we can verify any HTLC signatures
			// sent to us after we construct the HTLC view.
			if incoming {
				c.incomingHTLCIndex[htlc.localOutputIndex] = htlc
			} else {
				c.outgoingHTLCIndex[htlc.localOutputIndex] = htlc
			}

		// Otherwise, this is there remote party's commitment
		// transaction and we only need to populate the remote output
		// index within the HTLC index.
		case !c.isOurs:
			htlc.remoteOutputIndex, err = locateOutputIndex(
				htlc, c.txn, c.isOurs, dups, cltvs,
			)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid commitment configuration")
		}

		return nil
	}

	// Finally, we'll need to locate the index within the commitment
	// transaction of all the HTLC outputs. This index will be required
	// later when we write the commitment state to disk, and also when
	// generating signatures for each of the HTLC transactions.
	for i := 0; i < len(c.outgoingHTLCs); i++ {
		htlc := &c.outgoingHTLCs[i]
		if err := populateIndex(htlc, false); err != nil {
			return err
		}
	}
	for i := 0; i < len(c.incomingHTLCs); i++ {
		htlc := &c.incomingHTLCs[i]
		if err := populateIndex(htlc, true); err != nil {
			return err
		}
	}

	return nil
}

// toDiskCommit converts the target commitment into a format suitable to be
// written to disk after an accepted state transition.
func (c *commitment) toDiskCommit(ourCommit bool) *channeldb.ChannelCommitment {
	numHtlcs := len(c.outgoingHTLCs) + len(c.incomingHTLCs)

	commit := &channeldb.ChannelCommitment{
		CommitHeight:    c.height,
		LocalLogIndex:   c.ourMessageIndex,
		LocalHtlcIndex:  c.ourHtlcIndex,
		RemoteLogIndex:  c.theirMessageIndex,
		RemoteHtlcIndex: c.theirHtlcIndex,
		LocalBalance:    c.ourBalance,
		RemoteBalance:   c.theirBalance,
		CommitFee:       c.fee,
		FeePerKw:        btcutil.Amount(c.feePerKw),
		CommitTx:        c.txn,
		CommitSig:       c.sig,
		Htlcs:           make([]channeldb.HTLC, 0, numHtlcs),
	}

	for _, htlc := range c.outgoingHTLCs {
		outputIndex := htlc.localOutputIndex
		if !ourCommit {
			outputIndex = htlc.remoteOutputIndex
		}

		h := channeldb.HTLC{
			RHash:         htlc.RHash,
			Amt:           htlc.Amount,
			RefundTimeout: htlc.Timeout,
			OutputIndex:   outputIndex,
			HtlcIndex:     htlc.HtlcIndex,
			LogIndex:      htlc.LogIndex,
			Incoming:      false,
		}
		h.OnionBlob = make([]byte, len(htlc.OnionBlob))
		copy(h.OnionBlob[:], htlc.OnionBlob)

		if ourCommit && htlc.sig != nil {
			h.Signature = htlc.sig.Serialize()
		}

		commit.Htlcs = append(commit.Htlcs, h)
	}

	for _, htlc := range c.incomingHTLCs {
		outputIndex := htlc.localOutputIndex
		if !ourCommit {
			outputIndex = htlc.remoteOutputIndex
		}

		h := channeldb.HTLC{
			RHash:         htlc.RHash,
			Amt:           htlc.Amount,
			RefundTimeout: htlc.Timeout,
			OutputIndex:   outputIndex,
			HtlcIndex:     htlc.HtlcIndex,
			LogIndex:      htlc.LogIndex,
			Incoming:      true,
		}
		h.OnionBlob = make([]byte, len(htlc.OnionBlob))
		copy(h.OnionBlob[:], htlc.OnionBlob)

		if ourCommit && htlc.sig != nil {
			h.Signature = htlc.sig.Serialize()
		}

		commit.Htlcs = append(commit.Htlcs, h)
	}

	return commit
}

// diskHtlcToPayDesc converts an HTLC previously written to disk within a
// commitment state to the form required to manipulate in memory within the
// commitment struct and updateLog. This function is used when we need to
// restore commitment state written do disk back into memory once we need to
// restart a channel session.
func (lc *LightningChannel) diskHtlcToPayDesc(feeRate chainfee.SatPerKWeight,
	commitHeight uint64, htlc *channeldb.HTLC, localCommitKeys,
	remoteCommitKeys *CommitmentKeyRing, isLocal bool) (PaymentDescriptor,
	error) {

	// The proper pkScripts for this PaymentDescriptor must be
	// generated so we can easily locate them within the commitment
	// transaction in the future.
	var (
		ourP2WSH, theirP2WSH                 []byte
		ourWitnessScript, theirWitnessScript []byte
		pd                                   PaymentDescriptor
		err                                  error
		chanType                             = lc.channelState.ChanType
	)

	// If the either outputs is dust from the local or remote node's
	// perspective, then we don't need to generate the scripts as we only
	// generate them in order to locate the outputs within the commitment
	// transaction. As we'll mark dust with a special output index in the
	// on-disk state snapshot.
	isDustLocal := htlcIsDust(
		chanType, htlc.Incoming, true, feeRate,
		htlc.Amt.ToSatoshis(), lc.channelState.LocalChanCfg.DustLimit,
	)
	if !isDustLocal && localCommitKeys != nil {
		ourP2WSH, ourWitnessScript, err = genHtlcScript(
			chanType, htlc.Incoming, true, htlc.RefundTimeout,
			htlc.RHash, localCommitKeys,
		)
		if err != nil {
			return pd, err
		}
	}
	isDustRemote := htlcIsDust(
		chanType, htlc.Incoming, false, feeRate,
		htlc.Amt.ToSatoshis(), lc.channelState.RemoteChanCfg.DustLimit,
	)
	if !isDustRemote && remoteCommitKeys != nil {
		theirP2WSH, theirWitnessScript, err = genHtlcScript(
			chanType, htlc.Incoming, false, htlc.RefundTimeout,
			htlc.RHash, remoteCommitKeys,
		)
		if err != nil {
			return pd, err
		}
	}

	// Reconstruct the proper local/remote output indexes from the HTLC's
	// persisted output index depending on whose commitment we are
	// generating.
	var (
		localOutputIndex  int32
		remoteOutputIndex int32
	)
	if isLocal {
		localOutputIndex = htlc.OutputIndex
	} else {
		remoteOutputIndex = htlc.OutputIndex
	}

	// With the scripts reconstructed (depending on if this is our commit
	// vs theirs or a pending commit for the remote party), we can now
	// re-create the original payment descriptor.
	pd = PaymentDescriptor{
		RHash:              htlc.RHash,
		Timeout:            htlc.RefundTimeout,
		Amount:             htlc.Amt,
		EntryType:          Add,
		HtlcIndex:          htlc.HtlcIndex,
		LogIndex:           htlc.LogIndex,
		OnionBlob:          htlc.OnionBlob,
		localOutputIndex:   localOutputIndex,
		remoteOutputIndex:  remoteOutputIndex,
		ourPkScript:        ourP2WSH,
		ourWitnessScript:   ourWitnessScript,
		theirPkScript:      theirP2WSH,
		theirWitnessScript: theirWitnessScript,
	}

	return pd, nil
}

// extractPayDescs will convert all HTLC's present within a disk commit state
// to a set of incoming and outgoing payment descriptors. Once reconstructed,
// these payment descriptors can be re-inserted into the in-memory updateLog
// for each side.
func (lc *LightningChannel) extractPayDescs(commitHeight uint64,
	feeRate chainfee.SatPerKWeight, htlcs []channeldb.HTLC, localCommitKeys,
	remoteCommitKeys *CommitmentKeyRing, isLocal bool) ([]PaymentDescriptor,
	[]PaymentDescriptor, error) {

	var (
		incomingHtlcs []PaymentDescriptor
		outgoingHtlcs []PaymentDescriptor
	)

	// For each included HTLC within this commitment state, we'll convert
	// the disk format into our in memory PaymentDescriptor format,
	// partitioning based on if we offered or received the HTLC.
	for _, htlc := range htlcs {
		// TODO(roasbeef): set isForwarded to false for all? need to
		// persist state w.r.t to if forwarded or not, or can
		// inadvertently trigger replays

		payDesc, err := lc.diskHtlcToPayDesc(
			feeRate, commitHeight, &htlc,
			localCommitKeys, remoteCommitKeys,
			isLocal,
		)
		if err != nil {
			return incomingHtlcs, outgoingHtlcs, err
		}

		if htlc.Incoming {
			incomingHtlcs = append(incomingHtlcs, payDesc)
		} else {
			outgoingHtlcs = append(outgoingHtlcs, payDesc)
		}
	}

	return incomingHtlcs, outgoingHtlcs, nil
}

// diskCommitToMemCommit converts the on-disk commitment format to our
// in-memory commitment format which is needed in order to properly resume
// channel operations after a restart.
func (lc *LightningChannel) diskCommitToMemCommit(isLocal bool,
	diskCommit *channeldb.ChannelCommitment, localCommitPoint,
	remoteCommitPoint *btcec.PublicKey) (*commitment, error) {

	// First, we'll need to re-derive the commitment key ring for each
	// party used within this particular state. If this is a pending commit
	// (we extended but weren't able to complete the commitment dance
	// before shutdown), then the localCommitPoint won't be set as we
	// haven't yet received a responding commitment from the remote party.
	var localCommitKeys, remoteCommitKeys *CommitmentKeyRing
	if localCommitPoint != nil {
		localCommitKeys = DeriveCommitmentKeys(
			localCommitPoint, true, lc.channelState.ChanType,
			&lc.channelState.LocalChanCfg,
			&lc.channelState.RemoteChanCfg,
		)
	}
	if remoteCommitPoint != nil {
		remoteCommitKeys = DeriveCommitmentKeys(
			remoteCommitPoint, false, lc.channelState.ChanType,
			&lc.channelState.LocalChanCfg,
			&lc.channelState.RemoteChanCfg,
		)
	}

	// With the key rings re-created, we'll now convert all the on-disk
	// HTLC"s into PaymentDescriptor's so we can re-insert them into our
	// update log.
	incomingHtlcs, outgoingHtlcs, err := lc.extractPayDescs(
		diskCommit.CommitHeight,
		chainfee.SatPerKWeight(diskCommit.FeePerKw),
		diskCommit.Htlcs, localCommitKeys, remoteCommitKeys,
		isLocal,
	)
	if err != nil {
		return nil, err
	}

	// With the necessary items generated, we'll now re-construct the
	// commitment state as it was originally present in memory.
	commit := &commitment{
		height:            diskCommit.CommitHeight,
		isOurs:            isLocal,
		ourBalance:        diskCommit.LocalBalance,
		theirBalance:      diskCommit.RemoteBalance,
		ourMessageIndex:   diskCommit.LocalLogIndex,
		ourHtlcIndex:      diskCommit.LocalHtlcIndex,
		theirMessageIndex: diskCommit.RemoteLogIndex,
		theirHtlcIndex:    diskCommit.RemoteHtlcIndex,
		txn:               diskCommit.CommitTx,
		sig:               diskCommit.CommitSig,
		fee:               diskCommit.CommitFee,
		feePerKw:          chainfee.SatPerKWeight(diskCommit.FeePerKw),
		incomingHTLCs:     incomingHtlcs,
		outgoingHTLCs:     outgoingHtlcs,
	}
	if isLocal {
		commit.dustLimit = lc.channelState.LocalChanCfg.DustLimit
	} else {
		commit.dustLimit = lc.channelState.RemoteChanCfg.DustLimit
	}

	return commit, nil
}

// commitmentChain represents a chain of unrevoked commitments. The tail of the
// chain is the latest fully signed, yet unrevoked commitment. Two chains are
// tracked, one for the local node, and another for the remote node. New
// commitments we create locally extend the remote node's chain, and vice
// versa. Commitment chains are allowed to grow to a bounded length, after
// which the tail needs to be "dropped" before new commitments can be received.
// The tail is "dropped" when the owner of the chain sends a revocation for the
// previous tail.
type commitmentChain struct {
	// commitments is a linked list of commitments to new states. New
	// commitments are added to the end of the chain with increase height.
	// Once a commitment transaction is revoked, the tail is incremented,
	// freeing up the revocation window for new commitments.
	commitments *list.List
}

// newCommitmentChain creates a new commitment chain.
func newCommitmentChain() *commitmentChain {
	return &commitmentChain{
		commitments: list.New(),
	}
}

// addCommitment extends the commitment chain by a single commitment. This
// added commitment represents a state update proposed by either party. Once
// the commitment prior to this commitment is revoked, the commitment becomes
// the new defacto state within the channel.
func (s *commitmentChain) addCommitment(c *commitment) {
	s.commitments.PushBack(c)
}

// advanceTail reduces the length of the commitment chain by one. The tail of
// the chain should be advanced once a revocation for the lowest unrevoked
// commitment in the chain is received.
func (s *commitmentChain) advanceTail() {
	s.commitments.Remove(s.commitments.Front())
}

// tip returns the latest commitment added to the chain.
func (s *commitmentChain) tip() *commitment {
	return s.commitments.Back().Value.(*commitment)
}

// tail returns the lowest unrevoked commitment transaction in the chain.
func (s *commitmentChain) tail() *commitment {
	return s.commitments.Front().Value.(*commitment)
}

// hasUnackedCommitment returns true if the commitment chain has more than one
// entry. The tail of the commitment chain has been ACKed by revoking all prior
// commitments, but any subsequent commitments have not yet been ACKed.
func (s *commitmentChain) hasUnackedCommitment() bool {
	return s.commitments.Front() != s.commitments.Back()
}

// updateLog is an append-only log that stores updates to a node's commitment
// chain. This structure can be seen as the "mempool" within Lightning where
// changes are stored before they're committed to the chain. Once an entry has
// been committed in both the local and remote commitment chain, then it can be
// removed from this log.
//
// TODO(roasbeef): create lightning package, move commitment and update to
// package?
//  * also move state machine, separate from lnwallet package
//  * possible embed updateLog within commitmentChain.
type updateLog struct {
	// logIndex is a monotonically increasing integer that tracks the total
	// number of update entries ever applied to the log. When sending new
	// commitment states, we include all updates up to this index.
	logIndex uint64

	// htlcCounter is a monotonically increasing integer that tracks the
	// total number of offered HTLC's by the owner of this update log. We
	// use a distinct index for this purpose, as update's that remove
	// entries from the log will be indexed using this counter.
	htlcCounter uint64

	// List is the updatelog itself, we embed this value so updateLog has
	// access to all the method of a list.List.
	*list.List

	// updateIndex is an index that maps a particular entries index to the
	// list element within the list.List above.
	updateIndex map[uint64]*list.Element

	// offerIndex is an index that maps the counter for offered HTLC's to
	// their list element within the main list.List.
	htlcIndex map[uint64]*list.Element

	// modifiedHtlcs is a set that keeps track of all the current modified
	// htlcs. A modified HTLC is one that's present in the log, and has as
	// a pending fail or settle that's attempting to consume it.
	modifiedHtlcs map[uint64]struct{}
}

// newUpdateLog creates a new updateLog instance.
func newUpdateLog(logIndex, htlcCounter uint64) *updateLog {
	return &updateLog{
		List:          list.New(),
		updateIndex:   make(map[uint64]*list.Element),
		htlcIndex:     make(map[uint64]*list.Element),
		logIndex:      logIndex,
		htlcCounter:   htlcCounter,
		modifiedHtlcs: make(map[uint64]struct{}),
	}
}

// restoreHtlc will "restore" a prior HTLC to the updateLog. We say restore as
// this method is intended to be used when re-covering a prior commitment
// state. This function differs from appendHtlc in that it won't increment
// either of log's counters. If the HTLC is already present, then it is
// ignored.
func (u *updateLog) restoreHtlc(pd *PaymentDescriptor) {
	if _, ok := u.htlcIndex[pd.HtlcIndex]; ok {
		return
	}

	u.htlcIndex[pd.HtlcIndex] = u.PushBack(pd)
}

// appendUpdate appends a new update to the tip of the updateLog. The entry is
// also added to index accordingly.
func (u *updateLog) appendUpdate(pd *PaymentDescriptor) {
	u.updateIndex[u.logIndex] = u.PushBack(pd)
	u.logIndex++
}

// restoreUpdate appends a new update to the tip of the updateLog. The entry is
// also added to index accordingly. This function differs from appendUpdate in
// that it won't increment the log index counter.
func (u *updateLog) restoreUpdate(pd *PaymentDescriptor) {
	u.updateIndex[pd.LogIndex] = u.PushBack(pd)
}

// appendHtlc appends a new HTLC offer to the tip of the update log. The entry
// is also added to the offer index accordingly.
func (u *updateLog) appendHtlc(pd *PaymentDescriptor) {
	u.htlcIndex[u.htlcCounter] = u.PushBack(pd)
	u.htlcCounter++

	u.logIndex++
}

// lookupHtlc attempts to look up an offered HTLC according to its offer
// index. If the entry isn't found, then a nil pointer is returned.
func (u *updateLog) lookupHtlc(i uint64) *PaymentDescriptor {
	htlc, ok := u.htlcIndex[i]
	if !ok {
		return nil
	}

	return htlc.Value.(*PaymentDescriptor)
}

// remove attempts to remove an entry from the update log. If the entry is
// found, then the entry will be removed from the update log and index.
func (u *updateLog) removeUpdate(i uint64) {
	entry := u.updateIndex[i]
	u.Remove(entry)
	delete(u.updateIndex, i)
}

// removeHtlc attempts to remove an HTLC offer form the update log. If the
// entry is found, then the entry will be removed from both the main log and
// the offer index.
func (u *updateLog) removeHtlc(i uint64) {
	entry := u.htlcIndex[i]
	u.Remove(entry)
	delete(u.htlcIndex, i)

	delete(u.modifiedHtlcs, i)
}

// htlcHasModification returns true if the HTLC identified by the passed index
// has a pending modification within the log.
func (u *updateLog) htlcHasModification(i uint64) bool {
	_, o := u.modifiedHtlcs[i]
	return o
}

// markHtlcModified marks an HTLC as modified based on its HTLC index. After a
// call to this method, htlcHasModification will return true until the HTLC is
// removed.
func (u *updateLog) markHtlcModified(i uint64) {
	u.modifiedHtlcs[i] = struct{}{}
}

// compactLogs performs garbage collection within the log removing HTLCs which
// have been removed from the point-of-view of the tail of both chains. The
// entries which timeout/settle HTLCs are also removed.
func compactLogs(ourLog, theirLog *updateLog,
	localChainTail, remoteChainTail uint64) {

	compactLog := func(logA, logB *updateLog) {
		var nextA *list.Element
		for e := logA.Front(); e != nil; e = nextA {
			// Assign next iteration element at top of loop because
			// we may remove the current element from the list,
			// which can change the iterated sequence.
			nextA = e.Next()

			htlc := e.Value.(*PaymentDescriptor)

			// We skip Adds, as they will be removed along with the
			// fail/settles below.
			if htlc.EntryType == Add {
				continue
			}

			// If the HTLC hasn't yet been removed from either
			// chain, the skip it.
			if htlc.removeCommitHeightRemote == 0 ||
				htlc.removeCommitHeightLocal == 0 {
				continue
			}

			// Otherwise if the height of the tail of both chains
			// is at least the height in which the HTLC was
			// removed, then evict the settle/timeout entry along
			// with the original add entry.
			if remoteChainTail >= htlc.removeCommitHeightRemote &&
				localChainTail >= htlc.removeCommitHeightLocal {

				// Fee updates have no parent htlcs, so we only
				// remove the update itself.
				if htlc.EntryType == FeeUpdate {
					logA.removeUpdate(htlc.LogIndex)
					continue
				}

				// The other types (fail/settle) do have a
				// parent HTLC, so we'll remove that HTLC from
				// the other log.
				logA.removeUpdate(htlc.LogIndex)
				logB.removeHtlc(htlc.ParentIndex)
			}

		}
	}

	compactLog(ourLog, theirLog)
	compactLog(theirLog, ourLog)
}

// LightningChannel implements the state machine which corresponds to the
// current commitment protocol wire spec. The state machine implemented allows
// for asynchronous fully desynchronized, batched+pipelined updates to
// commitment transactions allowing for a high degree of non-blocking
// bi-directional payment throughput.
//
// In order to allow updates to be fully non-blocking, either side is able to
// create multiple new commitment states up to a pre-determined window size.
// This window size is encoded within InitialRevocationWindow. Before the start
// of a session, both side should send out revocation messages with nil
// preimages in order to populate their revocation window for the remote party.
//
// The state machine has for main methods:
//  * .SignNextCommitment()
//    * Called one one wishes to sign the next commitment, either initiating a
//      new state update, or responding to a received commitment.
//  * .ReceiveNewCommitment()
//    * Called upon receipt of a new commitment from the remote party. If the
//      new commitment is valid, then a revocation should immediately be
//      generated and sent.
//  * .RevokeCurrentCommitment()
//    * Revokes the current commitment. Should be called directly after
//      receiving a new commitment.
//  * .ReceiveRevocation()
//   * Processes a revocation from the remote party. If successful creates a
//     new defacto broadcastable state.
//
// See the individual comments within the above methods for further details.
type LightningChannel struct {
	// Signer is the main signer instances that will be responsible for
	// signing any HTLC and commitment transaction generated by the state
	// machine.
	Signer input.Signer

	// signDesc is the primary sign descriptor that is capable of signing
	// the commitment transaction that spends the multi-sig output.
	signDesc *input.SignDescriptor

	status channelState

	// ChanPoint is the funding outpoint of this channel.
	ChanPoint *wire.OutPoint

	// sigPool is a pool of workers that are capable of signing and
	// validating signatures in parallel. This is utilized as an
	// optimization to void serially signing or validating the HTLC
	// signatures, of which there may be hundreds.
	sigPool *SigPool

	// Capacity is the total capacity of this channel.
	Capacity btcutil.Amount

	// currentHeight is the current height of our local commitment chain.
	// This is also the same as the number of updates to the channel we've
	// accepted.
	currentHeight uint64

	// remoteCommitChain is the remote node's commitment chain. Any new
	// commitments we initiate are added to the tip of this chain.
	remoteCommitChain *commitmentChain

	// localCommitChain is our local commitment chain. Any new commitments
	// received are added to the tip of this chain. The tail (or lowest
	// height) in this chain is our current accepted state, which we are
	// able to broadcast safely.
	localCommitChain *commitmentChain

	channelState *channeldb.OpenChannel

	commitBuilder *CommitmentBuilder

	// [local|remote]Log is a (mostly) append-only log storing all the HTLC
	// updates to this channel. The log is walked backwards as HTLC updates
	// are applied in order to re-construct a commitment transaction from a
	// commitment. The log is compacted once a revocation is received.
	localUpdateLog  *updateLog
	remoteUpdateLog *updateLog

	// LocalFundingKey is the public key under control by the wallet that
	// was used for the 2-of-2 funding output which created this channel.
	LocalFundingKey *btcec.PublicKey

	// RemoteFundingKey is the public key for the remote channel counter
	// party  which used for the 2-of-2 funding output which created this
	// channel.
	RemoteFundingKey *btcec.PublicKey

	// log is a channel-specific logging instance.
	log btclog.Logger

	sync.RWMutex
}

// NewLightningChannel creates a new, active payment channel given an
// implementation of the chain notifier, channel database, and the current
// settled channel state. Throughout state transitions, then channel will
// automatically persist pertinent state to the database in an efficient
// manner.
func NewLightningChannel(signer input.Signer,
	state *channeldb.OpenChannel,
	sigPool *SigPool) (*LightningChannel, error) {

	localCommit := state.LocalCommitment
	remoteCommit := state.RemoteCommitment

	// First, initialize the update logs with their current counter values
	// from the local and remote commitments.
	localUpdateLog := newUpdateLog(
		remoteCommit.LocalLogIndex, remoteCommit.LocalHtlcIndex,
	)
	remoteUpdateLog := newUpdateLog(
		localCommit.RemoteLogIndex, localCommit.RemoteHtlcIndex,
	)

	logPrefix := fmt.Sprintf("ChannelPoint(%v):", state.FundingOutpoint)

	lc := &LightningChannel{
		Signer:            signer,
		sigPool:           sigPool,
		currentHeight:     localCommit.CommitHeight,
		remoteCommitChain: newCommitmentChain(),
		localCommitChain:  newCommitmentChain(),
		channelState:      state,
		commitBuilder:     NewCommitmentBuilder(state),
		localUpdateLog:    localUpdateLog,
		remoteUpdateLog:   remoteUpdateLog,
		ChanPoint:         &state.FundingOutpoint,
		Capacity:          state.Capacity,
		LocalFundingKey:   state.LocalChanCfg.MultiSigKey.PubKey,
		RemoteFundingKey:  state.RemoteChanCfg.MultiSigKey.PubKey,
		log:               build.NewPrefixLog(logPrefix, walletLog),
	}

	// With the main channel struct reconstructed, we'll now restore the
	// commitment state in memory and also the update logs themselves.
	err := lc.restoreCommitState(&localCommit, &remoteCommit)
	if err != nil {
		return nil, err
	}

	// Create the sign descriptor which we'll be using very frequently to
	// request a signature for the 2-of-2 multi-sig from the signer in
	// order to complete channel state transitions.
	if err := lc.createSignDesc(); err != nil {
		return nil, err
	}

	return lc, nil
}

// createSignDesc derives the SignDescriptor for commitment transactions from
// other fields on the LightningChannel.
func (lc *LightningChannel) createSignDesc() error {
	localKey := lc.channelState.LocalChanCfg.MultiSigKey.PubKey.
		SerializeCompressed()
	remoteKey := lc.channelState.RemoteChanCfg.MultiSigKey.PubKey.
		SerializeCompressed()

	multiSigScript, err := input.GenMultiSigScript(localKey, remoteKey)
	if err != nil {
		return err
	}

	fundingPkScript, err := input.WitnessScriptHash(multiSigScript)
	if err != nil {
		return err
	}
	lc.signDesc = &input.SignDescriptor{
		KeyDesc:       lc.channelState.LocalChanCfg.MultiSigKey,
		WitnessScript: multiSigScript,
		Output: &wire.TxOut{
			PkScript: fundingPkScript,
			Value:    int64(lc.channelState.Capacity),
		},
		HashType:   txscript.SigHashAll,
		InputIndex: 0,
	}

	return nil
}

// ResetState resets the state of the channel back to the default state. This
// ensures that any active goroutines which need to act based on on-chain
// events do so properly.
func (lc *LightningChannel) ResetState() {
	lc.Lock()
	lc.status = channelOpen
	lc.Unlock()
}

// logUpdateToPayDesc converts a LogUpdate into a matching PaymentDescriptor
// entry that can be re-inserted into the update log. This method is used when
// we extended a state to the remote party, but the connection was obstructed
// before we could finish the commitment dance. In this case, we need to
// re-insert the original entries back into the update log so we can resume as
// if nothing happened.
func (lc *LightningChannel) logUpdateToPayDesc(logUpdate *channeldb.LogUpdate,
	remoteUpdateLog *updateLog, commitHeight uint64,
	feeRate chainfee.SatPerKWeight, remoteCommitKeys *CommitmentKeyRing,
	remoteDustLimit btcutil.Amount) (*PaymentDescriptor, error) {

	// Depending on the type of update message we'll map that to a distinct
	// PaymentDescriptor instance.
	var pd *PaymentDescriptor

	switch wireMsg := logUpdate.UpdateMsg.(type) {

	// For offered HTLC's, we'll map that to a PaymentDescriptor with the
	// type Add, ensuring we restore the necessary fields. From the PoV of
	// the commitment chain, this HTLC was included in the remote chain,
	// but not the local chain.
	case *lnwire.UpdateAddHTLC:
		// First, we'll map all the relevant fields in the
		// UpdateAddHTLC message to their corresponding fields in the
		// PaymentDescriptor struct. We also set addCommitHeightRemote
		// as we've included this HTLC in our local commitment chain
		// for the remote party.
		pd = &PaymentDescriptor{
			RHash:                 wireMsg.PaymentHash,
			Timeout:               wireMsg.Expiry,
			Amount:                wireMsg.Amount,
			EntryType:             Add,
			HtlcIndex:             wireMsg.ID,
			LogIndex:              logUpdate.LogIndex,
			addCommitHeightRemote: commitHeight,
		}
		pd.OnionBlob = make([]byte, len(wireMsg.OnionBlob))
		copy(pd.OnionBlob[:], wireMsg.OnionBlob[:])

		isDustRemote := htlcIsDust(
			lc.channelState.ChanType, false, false, feeRate,
			wireMsg.Amount.ToSatoshis(), remoteDustLimit,
		)
		if !isDustRemote {
			theirP2WSH, theirWitnessScript, err := genHtlcScript(
				lc.channelState.ChanType, false, false,
				wireMsg.Expiry, wireMsg.PaymentHash,
				remoteCommitKeys,
			)
			if err != nil {
				return nil, err
			}

			pd.theirPkScript = theirP2WSH
			pd.theirWitnessScript = theirWitnessScript
		}

	// For HTLC's we're offered we'll fetch the original offered HTLC
	// from the remote party's update log so we can retrieve the same
	// PaymentDescriptor that SettleHTLC would produce.
	case *lnwire.UpdateFulfillHTLC:
		ogHTLC := remoteUpdateLog.lookupHtlc(wireMsg.ID)

		pd = &PaymentDescriptor{
			Amount:                   ogHTLC.Amount,
			RHash:                    ogHTLC.RHash,
			RPreimage:                wireMsg.PaymentPreimage,
			LogIndex:                 logUpdate.LogIndex,
			ParentIndex:              ogHTLC.HtlcIndex,
			EntryType:                Settle,
			removeCommitHeightRemote: commitHeight,
		}

	// If we sent a failure for a prior incoming HTLC, then we'll consult
	// the update log of the remote party so we can retrieve the
	// information of the original HTLC we're failing. We also set the
	// removal height for the remote commitment.
	case *lnwire.UpdateFailHTLC:
		ogHTLC := remoteUpdateLog.lookupHtlc(wireMsg.ID)

		pd = &PaymentDescriptor{
			Amount:                   ogHTLC.Amount,
			RHash:                    ogHTLC.RHash,
			ParentIndex:              ogHTLC.HtlcIndex,
			LogIndex:                 logUpdate.LogIndex,
			EntryType:                Fail,
			FailReason:               wireMsg.Reason[:],
			removeCommitHeightRemote: commitHeight,
		}

	// HTLC fails due to malformed onion blobs are treated the exact same
	// way as regular HTLC fails.
	case *lnwire.UpdateFailMalformedHTLC:
		ogHTLC := remoteUpdateLog.lookupHtlc(wireMsg.ID)
		// TODO(roasbeef): err if nil?

		pd = &PaymentDescriptor{
			Amount:                   ogHTLC.Amount,
			RHash:                    ogHTLC.RHash,
			ParentIndex:              ogHTLC.HtlcIndex,
			LogIndex:                 logUpdate.LogIndex,
			EntryType:                MalformedFail,
			FailCode:                 wireMsg.FailureCode,
			ShaOnionBlob:             wireMsg.ShaOnionBlob,
			removeCommitHeightRemote: commitHeight,
		}

	// For fee updates we'll create a FeeUpdate type to add to the log. We
	// reuse the amount field to hold the fee rate. Since the amount field
	// is denominated in msat we won't lose precision when storing the
	// sat/kw denominated feerate. Note that we set both the add and remove
	// height to the same value, as we consider the fee update locked in by
	// adding and removing it at the same height.
	case *lnwire.UpdateFee:
		pd = &PaymentDescriptor{
			LogIndex: logUpdate.LogIndex,
			Amount: lnwire.NewMSatFromSatoshis(
				btcutil.Amount(wireMsg.FeePerKw),
			),
			EntryType:                FeeUpdate,
			addCommitHeightRemote:    commitHeight,
			removeCommitHeightRemote: commitHeight,
		}
	}

	return pd, nil
}

// localLogUpdateToPayDesc converts a LogUpdate into a matching PaymentDescriptor
// entry that can be re-inserted into the local update log. This method is used
// when we sent an update+sig, receive a revocation, but drop right before the
// counterparty can sign for the update we just sent. In this case, we need to
// re-insert the original entries back into the update log so we'll be expecting
// the peer to sign them. The height of the remote commitment is expected to be
// provided and we restore all log update entries with this height, even though
// the real height may be lower. In the way these fields are used elsewhere, this
// doesn't change anything.
func (lc *LightningChannel) localLogUpdateToPayDesc(logUpdate *channeldb.LogUpdate,
	remoteUpdateLog *updateLog, commitHeight uint64) (*PaymentDescriptor,
	error) {

	// Since Add updates aren't saved to disk under this key, the update will
	// never be an Add.
	switch wireMsg := logUpdate.UpdateMsg.(type) {

	// For HTLCs that we settled, we'll fetch the original offered HTLC from
	// the remote update log so we can retrieve the same PaymentDescriptor that
	// ReceiveHTLCSettle would produce.
	case *lnwire.UpdateFulfillHTLC:
		ogHTLC := remoteUpdateLog.lookupHtlc(wireMsg.ID)

		return &PaymentDescriptor{
			Amount:                   ogHTLC.Amount,
			RHash:                    ogHTLC.RHash,
			RPreimage:                wireMsg.PaymentPreimage,
			LogIndex:                 logUpdate.LogIndex,
			ParentIndex:              ogHTLC.HtlcIndex,
			EntryType:                Settle,
			removeCommitHeightRemote: commitHeight,
		}, nil

	// If we sent a failure for a prior incoming HTLC, then we'll consult the
	// remote update log so we can retrieve the information of the original
	// HTLC we're failing.
	case *lnwire.UpdateFailHTLC:
		ogHTLC := remoteUpdateLog.lookupHtlc(wireMsg.ID)

		return &PaymentDescriptor{
			Amount:                   ogHTLC.Amount,
			RHash:                    ogHTLC.RHash,
			ParentIndex:              ogHTLC.HtlcIndex,
			LogIndex:                 logUpdate.LogIndex,
			EntryType:                Fail,
			FailReason:               wireMsg.Reason[:],
			removeCommitHeightRemote: commitHeight,
		}, nil

	// HTLC fails due to malformed onion blocks are treated the exact same
	// way as regular HTLC fails.
	case *lnwire.UpdateFailMalformedHTLC:
		ogHTLC := remoteUpdateLog.lookupHtlc(wireMsg.ID)

		return &PaymentDescriptor{
			Amount:                   ogHTLC.Amount,
			RHash:                    ogHTLC.RHash,
			ParentIndex:              ogHTLC.HtlcIndex,
			LogIndex:                 logUpdate.LogIndex,
			EntryType:                MalformedFail,
			FailCode:                 wireMsg.FailureCode,
			ShaOnionBlob:             wireMsg.ShaOnionBlob,
			removeCommitHeightRemote: commitHeight,
		}, nil

	case *lnwire.UpdateFee:
		return &PaymentDescriptor{
			LogIndex: logUpdate.LogIndex,
			Amount: lnwire.NewMSatFromSatoshis(
				btcutil.Amount(wireMsg.FeePerKw),
			),
			EntryType:                FeeUpdate,
			addCommitHeightRemote:    commitHeight,
			removeCommitHeightRemote: commitHeight,
		}, nil

	default:
		return nil, fmt.Errorf("unknown message type: %T", wireMsg)
	}
}

// remoteLogUpdateToPayDesc converts a LogUpdate into a matching
// PaymentDescriptor entry that can be re-inserted into the update log. This
// method is used when we revoked a local commitment, but the connection was
// obstructed before we could sign a remote commitment that contains these
// updates. In this case, we need to re-insert the original entries back into
// the update log so we can resume as if nothing happened. The height of the
// latest local commitment is also expected to be provided. We are restoring all
// log update entries with this height, even though the real commitment height
// may be lower. In the way these fields are used elsewhere, this doesn't change
// anything.
func (lc *LightningChannel) remoteLogUpdateToPayDesc(logUpdate *channeldb.LogUpdate,
	localUpdateLog *updateLog, commitHeight uint64) (*PaymentDescriptor,
	error) {

	switch wireMsg := logUpdate.UpdateMsg.(type) {

	case *lnwire.UpdateAddHTLC:
		pd := &PaymentDescriptor{
			RHash:                wireMsg.PaymentHash,
			Timeout:              wireMsg.Expiry,
			Amount:               wireMsg.Amount,
			EntryType:            Add,
			HtlcIndex:            wireMsg.ID,
			LogIndex:             logUpdate.LogIndex,
			addCommitHeightLocal: commitHeight,
		}
		pd.OnionBlob = make([]byte, len(wireMsg.OnionBlob))
		copy(pd.OnionBlob, wireMsg.OnionBlob[:])

		// We don't need to generate an htlc script yet. This will be
		// done once we sign our remote commitment.

		return pd, nil

	// For HTLCs that the remote party settled, we'll fetch the original
	// offered HTLC from the local update log so we can retrieve the same
	// PaymentDescriptor that ReceiveHTLCSettle would produce.
	case *lnwire.UpdateFulfillHTLC:
		ogHTLC := localUpdateLog.lookupHtlc(wireMsg.ID)

		return &PaymentDescriptor{
			Amount:                  ogHTLC.Amount,
			RHash:                   ogHTLC.RHash,
			RPreimage:               wireMsg.PaymentPreimage,
			LogIndex:                logUpdate.LogIndex,
			ParentIndex:             ogHTLC.HtlcIndex,
			EntryType:               Settle,
			removeCommitHeightLocal: commitHeight,
		}, nil

	// If we received a failure for a prior outgoing HTLC, then we'll
	// consult the local update log so we can retrieve the information of
	// the original HTLC we're failing.
	case *lnwire.UpdateFailHTLC:
		ogHTLC := localUpdateLog.lookupHtlc(wireMsg.ID)

		return &PaymentDescriptor{
			Amount:                  ogHTLC.Amount,
			RHash:                   ogHTLC.RHash,
			ParentIndex:             ogHTLC.HtlcIndex,
			LogIndex:                logUpdate.LogIndex,
			EntryType:               Fail,
			FailReason:              wireMsg.Reason[:],
			removeCommitHeightLocal: commitHeight,
		}, nil

	// HTLC fails due to malformed onion blobs are treated the exact same
	// way as regular HTLC fails.
	case *lnwire.UpdateFailMalformedHTLC:
		ogHTLC := localUpdateLog.lookupHtlc(wireMsg.ID)

		return &PaymentDescriptor{
			Amount:                  ogHTLC.Amount,
			RHash:                   ogHTLC.RHash,
			ParentIndex:             ogHTLC.HtlcIndex,
			LogIndex:                logUpdate.LogIndex,
			EntryType:               MalformedFail,
			FailCode:                wireMsg.FailureCode,
			ShaOnionBlob:            wireMsg.ShaOnionBlob,
			removeCommitHeightLocal: commitHeight,
		}, nil

	// For fee updates we'll create a FeeUpdate type to add to the log. We
	// reuse the amount field to hold the fee rate. Since the amount field
	// is denominated in msat we won't lose precision when storing the
	// sat/kw denominated feerate. Note that we set both the add and remove
	// height to the same value, as we consider the fee update locked in by
	// adding and removing it at the same height.
	case *lnwire.UpdateFee:
		return &PaymentDescriptor{
			LogIndex: logUpdate.LogIndex,
			Amount: lnwire.NewMSatFromSatoshis(
				btcutil.Amount(wireMsg.FeePerKw),
			),
			EntryType:               FeeUpdate,
			addCommitHeightLocal:    commitHeight,
			removeCommitHeightLocal: commitHeight,
		}, nil

	default:
		return nil, errors.New("unknown message type")
	}
}

// restoreCommitState will restore the local commitment chain and updateLog
// state to a consistent in-memory representation of the passed disk commitment.
// This method is to be used upon reconnection to our channel counter party.
// Once the connection has been established, we'll prepare our in memory state
// to re-sync states with the remote party, and also verify/extend new proposed
// commitment states.
func (lc *LightningChannel) restoreCommitState(
	localCommitState, remoteCommitState *channeldb.ChannelCommitment) error {

	// In order to reconstruct the pkScripts on each of the pending HTLC
	// outputs (if any) we'll need to regenerate the current revocation for
	// this current un-revoked state as well as retrieve the current
	// revocation for the remote party.
	ourRevPreImage, err := lc.channelState.RevocationProducer.AtIndex(
		lc.currentHeight,
	)
	if err != nil {
		return err
	}
	localCommitPoint := input.ComputeCommitmentPoint(ourRevPreImage[:])
	remoteCommitPoint := lc.channelState.RemoteCurrentRevocation

	// With the revocation state reconstructed, we can now convert the disk
	// commitment into our in-memory commitment format, inserting it into
	// the local commitment chain.
	localCommit, err := lc.diskCommitToMemCommit(
		true, localCommitState, localCommitPoint,
		remoteCommitPoint,
	)
	if err != nil {
		return err
	}
	lc.localCommitChain.addCommitment(localCommit)

	lc.log.Debugf("starting local commitment: %v",
		newLogClosure(func() string {
			return spew.Sdump(lc.localCommitChain.tail())
		}),
	)

	// We'll also do the same for the remote commitment chain.
	remoteCommit, err := lc.diskCommitToMemCommit(
		false, remoteCommitState, localCommitPoint,
		remoteCommitPoint,
	)
	if err != nil {
		return err
	}
	lc.remoteCommitChain.addCommitment(remoteCommit)

	lc.log.Debugf("starting remote commitment: %v",
		newLogClosure(func() string {
			return spew.Sdump(lc.remoteCommitChain.tail())
		}),
	)

	var (
		pendingRemoteCommit     *commitment
		pendingRemoteCommitDiff *channeldb.CommitDiff
		pendingRemoteKeyChain   *CommitmentKeyRing
	)

	// Next, we'll check to see if we have an un-acked commitment state we
	// extended to the remote party but which was never ACK'd.
	pendingRemoteCommitDiff, err = lc.channelState.RemoteCommitChainTip()
	if err != nil && err != channeldb.ErrNoPendingCommit {
		return err
	}

	if pendingRemoteCommitDiff != nil {
		// If we have a pending remote commitment, then we'll also
		// reconstruct the original commitment for that state,
		// inserting it into the remote party's commitment chain. We
		// don't pass our commit point as we don't have the
		// corresponding state for the local commitment chain.
		pendingCommitPoint := lc.channelState.RemoteNextRevocation
		pendingRemoteCommit, err = lc.diskCommitToMemCommit(
			false, &pendingRemoteCommitDiff.Commitment,
			nil, pendingCommitPoint,
		)
		if err != nil {
			return err
		}
		lc.remoteCommitChain.addCommitment(pendingRemoteCommit)

		lc.log.Debugf("pending remote commitment: %v",
			newLogClosure(func() string {
				return spew.Sdump(lc.remoteCommitChain.tip())
			}),
		)

		// We'll also re-create the set of commitment keys needed to
		// fully re-derive the state.
		pendingRemoteKeyChain = DeriveCommitmentKeys(
			pendingCommitPoint, false, lc.channelState.ChanType,
			&lc.channelState.LocalChanCfg, &lc.channelState.RemoteChanCfg,
		)
	}

	// Fetch remote updates that we have acked but not yet signed for.
	unsignedAckedUpdates, err := lc.channelState.UnsignedAckedUpdates()
	if err != nil {
		return err
	}

	// Fetch the local updates the peer still needs to sign for.
	remoteUnsignedLocalUpdates, err := lc.channelState.RemoteUnsignedLocalUpdates()
	if err != nil {
		return err
	}

	// Finally, with the commitment states restored, we'll now restore the
	// state logs based on the current local+remote commit, and any pending
	// remote commit that exists.
	err = lc.restoreStateLogs(
		localCommit, remoteCommit, pendingRemoteCommit,
		pendingRemoteCommitDiff, pendingRemoteKeyChain,
		unsignedAckedUpdates, remoteUnsignedLocalUpdates,
	)
	if err != nil {
		return err
	}

	return nil
}

// restoreStateLogs runs through the current locked-in HTLCs from the point of
// view of the channel and insert corresponding log entries (both local and
// remote) for each HTLC read from disk. This method is required to sync the
// in-memory state of the state machine with that read from persistent storage.
func (lc *LightningChannel) restoreStateLogs(
	localCommitment, remoteCommitment, pendingRemoteCommit *commitment,
	pendingRemoteCommitDiff *channeldb.CommitDiff,
	pendingRemoteKeys *CommitmentKeyRing,
	unsignedAckedUpdates,
	remoteUnsignedLocalUpdates []channeldb.LogUpdate) error {

	// We make a map of incoming HTLCs to the height of the remote
	// commitment they were first added, and outgoing HTLCs to the height
	// of the local commit they were first added. This will be used when we
	// restore the update logs below.
	incomingRemoteAddHeights := make(map[uint64]uint64)
	outgoingLocalAddHeights := make(map[uint64]uint64)

	// We start by setting the height of the incoming HTLCs on the pending
	// remote commitment. We set these heights first since if there are
	// duplicates, these will be overwritten by the lower height of the
	// remoteCommitment below.
	if pendingRemoteCommit != nil {
		for _, r := range pendingRemoteCommit.incomingHTLCs {
			incomingRemoteAddHeights[r.HtlcIndex] =
				pendingRemoteCommit.height
		}
	}

	// Now set the remote commit height of all incoming HTLCs found on the
	// remote commitment.
	for _, r := range remoteCommitment.incomingHTLCs {
		incomingRemoteAddHeights[r.HtlcIndex] = remoteCommitment.height
	}

	// And finally we can do the same for the outgoing HTLCs.
	for _, l := range localCommitment.outgoingHTLCs {
		outgoingLocalAddHeights[l.HtlcIndex] = localCommitment.height
	}

	// If we have any unsigned acked updates to sign for, then the add is no
	// longer on our local commitment, but is still on the remote's commitment.
	// <---fail---
	// <---sig----
	// ----rev--->
	// To ensure proper channel operation, we restore the add's addCommitHeightLocal
	// field to the height of our local commitment.
	for _, logUpdate := range unsignedAckedUpdates {

		var htlcIdx uint64
		switch wireMsg := logUpdate.UpdateMsg.(type) {
		case *lnwire.UpdateFulfillHTLC:
			htlcIdx = wireMsg.ID
		case *lnwire.UpdateFailHTLC:
			htlcIdx = wireMsg.ID
		case *lnwire.UpdateFailMalformedHTLC:
			htlcIdx = wireMsg.ID
		default:
			continue
		}

		// The htlcIdx is stored in the map with the local commitment
		// height so the related add's addCommitHeightLocal field can be
		// restored.
		outgoingLocalAddHeights[htlcIdx] = localCommitment.height
	}

	// If there are local updates that the peer needs to sign for, then the
	// corresponding add is no longer on the remote commitment, but is still on
	// our local commitment.
	// ----fail--->
	// ----sig---->
	// <---rev-----
	// To ensure proper channel operation, we restore the add's addCommitHeightRemote
	// field to the height of the remote commitment.
	for _, logUpdate := range remoteUnsignedLocalUpdates {

		var htlcIdx uint64
		switch wireMsg := logUpdate.UpdateMsg.(type) {
		case *lnwire.UpdateFulfillHTLC:
			htlcIdx = wireMsg.ID
		case *lnwire.UpdateFailHTLC:
			htlcIdx = wireMsg.ID
		case *lnwire.UpdateFailMalformedHTLC:
			htlcIdx = wireMsg.ID
		default:
			continue
		}

		// The htlcIdx is stored in the map with the remote commitment
		// height so the related add's addCommitHeightRemote field can be
		// restored.
		incomingRemoteAddHeights[htlcIdx] = remoteCommitment.height
	}

	// For each incoming HTLC within the local commitment, we add it to the
	// remote update log. Since HTLCs are added first to the receiver's
	// commitment, we don't have to restore outgoing HTLCs, as they will be
	// restored from the remote commitment below.
	for i := range localCommitment.incomingHTLCs {
		htlc := localCommitment.incomingHTLCs[i]

		// We'll need to set the add height of the HTLC. Since it is on
		// this local commit, we can use its height as local add
		// height. As remote add height we consult the incoming HTLC
		// map we created earlier. Note that if this HTLC is not in
		// incomingRemoteAddHeights, the remote add height will be set
		// to zero, which indicates that it is not added yet.
		htlc.addCommitHeightLocal = localCommitment.height
		htlc.addCommitHeightRemote = incomingRemoteAddHeights[htlc.HtlcIndex]

		// Restore the htlc back to the remote log.
		lc.remoteUpdateLog.restoreHtlc(&htlc)
	}

	// Similarly, we'll do the same for the outgoing HTLCs within the
	// remote commitment, adding them to the local update log.
	for i := range remoteCommitment.outgoingHTLCs {
		htlc := remoteCommitment.outgoingHTLCs[i]

		// As for the incoming HTLCs, we'll use the current remote
		// commit height as remote add height, and consult the map
		// created above for the local add height.
		htlc.addCommitHeightRemote = remoteCommitment.height
		htlc.addCommitHeightLocal = outgoingLocalAddHeights[htlc.HtlcIndex]

		// Restore the htlc back to the local log.
		lc.localUpdateLog.restoreHtlc(&htlc)
	}

	// If we have a dangling (un-acked) commit for the remote party, then we
	// restore the updates leading up to this commit.
	if pendingRemoteCommit != nil {
		err := lc.restorePendingLocalUpdates(
			pendingRemoteCommitDiff, pendingRemoteKeys,
		)
		if err != nil {
			return err
		}
	}

	// Restore unsigned acked remote log updates so that we can include them
	// in our next signature.
	err := lc.restorePendingRemoteUpdates(
		unsignedAckedUpdates, localCommitment.height,
		pendingRemoteCommit,
	)
	if err != nil {
		return err
	}

	// Restore unsigned acked local log updates so we expect the peer to
	// sign for them.
	return lc.restorePeerLocalUpdates(
		remoteUnsignedLocalUpdates, remoteCommitment.height,
	)
}

// restorePendingRemoteUpdates restores the acked remote log updates that we
// haven't yet signed for.
func (lc *LightningChannel) restorePendingRemoteUpdates(
	unsignedAckedUpdates []channeldb.LogUpdate,
	localCommitmentHeight uint64,
	pendingRemoteCommit *commitment) error {

	lc.log.Debugf("Restoring %v dangling remote updates",
		len(unsignedAckedUpdates))

	for _, logUpdate := range unsignedAckedUpdates {
		logUpdate := logUpdate

		payDesc, err := lc.remoteLogUpdateToPayDesc(
			&logUpdate, lc.localUpdateLog, localCommitmentHeight,
		)
		if err != nil {
			return err
		}

		logIdx := payDesc.LogIndex

		// Sanity check that we are not restoring a remote log update
		// that we haven't received a sig for.
		if logIdx >= lc.remoteUpdateLog.logIndex {
			return fmt.Errorf("attempted to restore an "+
				"unsigned remote update: log_index=%v",
				logIdx)
		}

		// We previously restored Adds along with all the other upates,
		// but this Add restoration was a no-op as every single one of
		// these Adds was already restored since they're all incoming
		// htlcs on the local commitment.
		if payDesc.EntryType == Add {
			continue
		}

		var (
			height    uint64
			heightSet bool
		)

		// If we have a pending commitment for them, and this update
		// is included in that commit, then we'll use this commitment
		// height as this commitment will include these updates for
		// their new remote commitment.
		if pendingRemoteCommit != nil {
			if logIdx < pendingRemoteCommit.theirMessageIndex {
				height = pendingRemoteCommit.height
				heightSet = true
			}
		}

		// Insert the update into the log. The log update index doesn't
		// need to be incremented (hence the restore calls), because its
		// final value was properly persisted with the last local
		// commitment update.
		switch payDesc.EntryType {
		case FeeUpdate:
			if heightSet {
				payDesc.addCommitHeightRemote = height
				payDesc.removeCommitHeightRemote = height
			}

			lc.remoteUpdateLog.restoreUpdate(payDesc)

		default:
			if heightSet {
				payDesc.removeCommitHeightRemote = height
			}

			lc.remoteUpdateLog.restoreUpdate(payDesc)
			lc.localUpdateLog.markHtlcModified(payDesc.ParentIndex)
		}
	}

	return nil
}

// restorePeerLocalUpdates restores the acked local log updates the peer still
// needs to sign for.
func (lc *LightningChannel) restorePeerLocalUpdates(updates []channeldb.LogUpdate,
	remoteCommitmentHeight uint64) error {

	lc.log.Debugf("Restoring %v local updates that the peer should sign",
		len(updates))

	for _, logUpdate := range updates {
		logUpdate := logUpdate

		payDesc, err := lc.localLogUpdateToPayDesc(
			&logUpdate, lc.remoteUpdateLog, remoteCommitmentHeight,
		)
		if err != nil {
			return err
		}

		lc.localUpdateLog.restoreUpdate(payDesc)

		// Since Add updates are not stored and FeeUpdates don't have a
		// corresponding entry in the remote update log, we only need to
		// mark the htlc as modified if the update was Settle, Fail, or
		// MalformedFail.
		if payDesc.EntryType != FeeUpdate {
			lc.remoteUpdateLog.markHtlcModified(payDesc.ParentIndex)
		}
	}

	return nil
}

// restorePendingLocalUpdates restores the local log updates leading up to the
// given pending remote commitment.
func (lc *LightningChannel) restorePendingLocalUpdates(
	pendingRemoteCommitDiff *channeldb.CommitDiff,
	pendingRemoteKeys *CommitmentKeyRing) error {

	pendingCommit := pendingRemoteCommitDiff.Commitment
	pendingHeight := pendingCommit.CommitHeight

	// If we did have a dangling commit, then we'll examine which updates
	// we included in that state and re-insert them into our update log.
	for _, logUpdate := range pendingRemoteCommitDiff.LogUpdates {
		logUpdate := logUpdate

		payDesc, err := lc.logUpdateToPayDesc(
			&logUpdate, lc.remoteUpdateLog, pendingHeight,
			chainfee.SatPerKWeight(pendingCommit.FeePerKw),
			pendingRemoteKeys,
			lc.channelState.RemoteChanCfg.DustLimit,
		)
		if err != nil {
			return err
		}

		// Earlier versions did not write the log index to disk for fee
		// updates, so they will be unset. To account for this we set
		// them to to current update log index.
		if payDesc.EntryType == FeeUpdate && payDesc.LogIndex == 0 &&
			lc.localUpdateLog.logIndex > 0 {

			payDesc.LogIndex = lc.localUpdateLog.logIndex
			lc.log.Debugf("Found FeeUpdate on "+
				"pendingRemoteCommitDiff without logIndex, "+
				"using %v", payDesc.LogIndex)
		}

		// At this point the restored update's logIndex must be equal
		// to the update log, otherwise somthing is horribly wrong.
		if payDesc.LogIndex != lc.localUpdateLog.logIndex {
			panic(fmt.Sprintf("log index mismatch: "+
				"%v vs %v", payDesc.LogIndex,
				lc.localUpdateLog.logIndex))
		}

		switch payDesc.EntryType {
		case Add:
			// The HtlcIndex of the added HTLC _must_ be equal to
			// the log's htlcCounter at this point. If it is not we
			// panic to catch this.
			// TODO(halseth): remove when cause of htlc entry bug
			// is found.
			if payDesc.HtlcIndex != lc.localUpdateLog.htlcCounter {
				panic(fmt.Sprintf("htlc index mismatch: "+
					"%v vs %v", payDesc.HtlcIndex,
					lc.localUpdateLog.htlcCounter))
			}

			lc.localUpdateLog.appendHtlc(payDesc)

		case FeeUpdate:
			lc.localUpdateLog.appendUpdate(payDesc)

		default:
			lc.localUpdateLog.appendUpdate(payDesc)

			lc.remoteUpdateLog.markHtlcModified(payDesc.ParentIndex)
		}
	}

	return nil
}

// HtlcRetribution contains all the items necessary to seep a revoked HTLC
// transaction from a revoked commitment transaction broadcast by the remote
// party.
type HtlcRetribution struct {
	// SignDesc is a design descriptor capable of generating the necessary
	// signatures to satisfy the revocation clause of the HTLC's public key
	// script.
	SignDesc input.SignDescriptor

	// OutPoint is the target outpoint of this HTLC pointing to the
	// breached commitment transaction.
	OutPoint wire.OutPoint

	// SecondLevelWitnessScript is the witness script that will be created
	// if the second level HTLC transaction for this output is
	// broadcast/confirmed. We provide this as if the remote party attempts
	// to go to the second level to claim the HTLC then we'll need to
	// update the SignDesc above accordingly to sweep properly.
	SecondLevelWitnessScript []byte

	// IsIncoming is a boolean flag that indicates whether or not this
	// HTLC was accepted from the counterparty. A false value indicates that
	// this HTLC was offered by us. This flag is used determine the exact
	// witness type should be used to sweep the output.
	IsIncoming bool
}

// BreachRetribution contains all the data necessary to bring a channel
// counterparty to justice claiming ALL lingering funds within the channel in
// the scenario that they broadcast a revoked commitment transaction. A
// BreachRetribution is created by the closeObserver if it detects an
// uncooperative close of the channel which uses a revoked commitment
// transaction. The BreachRetribution is then sent over the ContractBreach
// channel in order to allow the subscriber of the channel to dispatch justice.
type BreachRetribution struct {
	// BreachTransaction is the transaction which breached the channel
	// contract by spending from the funding multi-sig with a revoked
	// commitment transaction.
	BreachTransaction *wire.MsgTx

	// BreachHeight records the block height confirming the breach
	// transaction, used as a height hint when registering for
	// confirmations.
	BreachHeight uint32

	// ChainHash is the chain that the contract beach was identified
	// within. This is also the resident chain of the contract (the chain
	// the contract was created on).
	ChainHash chainhash.Hash

	// RevokedStateNum is the revoked state number which was broadcast.
	RevokedStateNum uint64

	// PendingHTLCs is a slice of the HTLCs which were pending at this
	// point within the channel's history transcript.
	PendingHTLCs []channeldb.HTLC

	// LocalOutputSignDesc is a SignDescriptor which is capable of
	// generating the signature necessary to sweep the output within the
	// BreachTransaction that pays directly us.
	//
	// NOTE: A nil value indicates that the local output is considered dust
	// according to the remote party's dust limit.
	LocalOutputSignDesc *input.SignDescriptor

	// LocalOutpoint is the outpoint of the output paying to us (the local
	// party) within the breach transaction.
	LocalOutpoint wire.OutPoint

	// LocalDelay is the CSV delay for the to_remote script on the breached
	// commitment.
	LocalDelay uint32

	// RemoteOutputSignDesc is a SignDescriptor which is capable of
	// generating the signature required to claim the funds as described
	// within the revocation clause of the remote party's commitment
	// output.
	//
	// NOTE: A nil value indicates that the local output is considered dust
	// according to the remote party's dust limit.
	RemoteOutputSignDesc *input.SignDescriptor

	// RemoteOutpoint is the outpoint of the output paying to the remote
	// party within the breach transaction.
	RemoteOutpoint wire.OutPoint

	// RemoteDelay specifies the CSV delay applied to to-local scripts on
	// the breaching commitment transaction.
	RemoteDelay uint32

	// HtlcRetributions is a slice of HTLC retributions for each output
	// active HTLC output within the breached commitment transaction.
	HtlcRetributions []HtlcRetribution

	// KeyRing contains the derived public keys used to construct the
	// breaching commitment transaction. This allows downstream clients to
	// have access to the public keys used in the scripts.
	KeyRing *CommitmentKeyRing
}

// NewBreachRetribution creates a new fully populated BreachRetribution for the
// passed channel, at a particular revoked state number, and one which targets
// the passed commitment transaction.
func NewBreachRetribution(chanState *channeldb.OpenChannel, stateNum uint64,
	breachHeight uint32) (*BreachRetribution, error) {

	// Query the on-disk revocation log for the snapshot which was recorded
	// at this particular state num.
	revokedSnapshot, err := chanState.FindPreviousState(stateNum)
	if err != nil {
		return nil, err
	}

	commitHash := revokedSnapshot.CommitTx.TxHash()

	// With the state number broadcast known, we can now derive/restore the
	// proper revocation preimage necessary to sweep the remote party's
	// output.
	revocationPreimage, err := chanState.RevocationStore.LookUp(stateNum)
	if err != nil {
		return nil, err
	}
	commitmentSecret, commitmentPoint := btcec.PrivKeyFromBytes(
		btcec.S256(), revocationPreimage[:],
	)

	// With the commitment point generated, we can now generate the four
	// keys we'll need to reconstruct the commitment state,
	keyRing := DeriveCommitmentKeys(
		commitmentPoint, false, chanState.ChanType,
		&chanState.LocalChanCfg, &chanState.RemoteChanCfg,
	)

	// Next, reconstruct the scripts as they were present at this state
	// number so we can have the proper witness script to sign and include
	// within the final witness.
	theirDelay := uint32(chanState.RemoteChanCfg.CsvDelay)
	theirPkScript, err := input.CommitScriptToSelf(
		theirDelay, keyRing.ToLocalKey, keyRing.RevocationKey,
	)
	if err != nil {
		return nil, err
	}
	theirWitnessHash, err := input.WitnessScriptHash(theirPkScript)
	if err != nil {
		return nil, err
	}

	// Since it is the remote breach we are reconstructing, the output going
	// to us will be a to-remote script with our local params.
	ourScript, ourDelay, err := CommitScriptToRemote(
		chanState.ChanType, keyRing.ToRemoteKey,
	)
	if err != nil {
		return nil, err
	}

	// In order to fully populate the breach retribution struct, we'll need
	// to find the exact index of the commitment outputs.
	ourOutpoint := wire.OutPoint{
		Hash: commitHash,
	}
	theirOutpoint := wire.OutPoint{
		Hash: commitHash,
	}
	for i, txOut := range revokedSnapshot.CommitTx.TxOut {
		switch {
		case bytes.Equal(txOut.PkScript, ourScript.PkScript):
			ourOutpoint.Index = uint32(i)
		case bytes.Equal(txOut.PkScript, theirWitnessHash):
			theirOutpoint.Index = uint32(i)
		}
	}

	// Conditionally instantiate a sign descriptor for each of the
	// commitment outputs. If either is considered dust using the remote
	// party's dust limit, the respective sign descriptor will be nil.
	var (
		ourSignDesc   *input.SignDescriptor
		theirSignDesc *input.SignDescriptor
	)

	// Compute the balances in satoshis.
	ourAmt := revokedSnapshot.LocalBalance.ToSatoshis()
	theirAmt := revokedSnapshot.RemoteBalance.ToSatoshis()

	// If our balance exceeds the remote party's dust limit, instantiate
	// the sign descriptor for our output.
	if ourAmt >= chanState.RemoteChanCfg.DustLimit {
		ourSignDesc = &input.SignDescriptor{
			SingleTweak:   keyRing.LocalCommitKeyTweak,
			KeyDesc:       chanState.LocalChanCfg.PaymentBasePoint,
			WitnessScript: ourScript.WitnessScript,
			Output: &wire.TxOut{
				PkScript: ourScript.PkScript,
				Value:    int64(ourAmt),
			},
			HashType: txscript.SigHashAll,
		}
	}

	// Similarly, if their balance exceeds the remote party's dust limit,
	// assemble the sign descriptor for their output, which we can sweep.
	if theirAmt >= chanState.RemoteChanCfg.DustLimit {
		theirSignDesc = &input.SignDescriptor{
			KeyDesc:       chanState.LocalChanCfg.RevocationBasePoint,
			DoubleTweak:   commitmentSecret,
			WitnessScript: theirPkScript,
			Output: &wire.TxOut{
				PkScript: theirWitnessHash,
				Value:    int64(theirAmt),
			},
			HashType: txscript.SigHashAll,
		}
	}

	// With the commitment outputs located, we'll now generate all the
	// retribution structs for each of the HTLC transactions active on the
	// remote commitment transaction.
	htlcRetributions := make([]HtlcRetribution, 0, len(revokedSnapshot.Htlcs))
	for _, htlc := range revokedSnapshot.Htlcs {
		// If the HTLC is dust, then we'll skip it as it doesn't have
		// an output on the commitment transaction.
		if htlcIsDust(
			chanState.ChanType, htlc.Incoming, false,
			chainfee.SatPerKWeight(revokedSnapshot.FeePerKw),
			htlc.Amt.ToSatoshis(), chanState.RemoteChanCfg.DustLimit,
		) {
			continue
		}

		// We'll generate the original second level witness script now,
		// as we'll need it if we're revoking an HTLC output on the
		// remote commitment transaction, and *they* go to the second
		// level.
		secondLevelWitnessScript, err := input.SecondLevelHtlcScript(
			keyRing.RevocationKey, keyRing.ToLocalKey, theirDelay,
		)
		if err != nil {
			return nil, err
		}

		// If this is an incoming HTLC, then this means that they were
		// the sender of the HTLC (relative to us). So we'll
		// re-generate the sender HTLC script. Otherwise, is this was
		// an outgoing HTLC that we sent, then from the PoV of the
		// remote commitment state, they're the receiver of this HTLC.
		htlcPkScript, htlcWitnessScript, err := genHtlcScript(
			chanState.ChanType, htlc.Incoming, false,
			htlc.RefundTimeout, htlc.RHash, keyRing,
		)
		if err != nil {
			return nil, err
		}

		htlcRetributions = append(htlcRetributions, HtlcRetribution{
			SignDesc: input.SignDescriptor{
				KeyDesc:       chanState.LocalChanCfg.RevocationBasePoint,
				DoubleTweak:   commitmentSecret,
				WitnessScript: htlcWitnessScript,
				Output: &wire.TxOut{
					PkScript: htlcPkScript,
					Value:    int64(htlc.Amt.ToSatoshis()),
				},
				HashType: txscript.SigHashAll,
			},
			OutPoint: wire.OutPoint{
				Hash:  commitHash,
				Index: uint32(htlc.OutputIndex),
			},
			SecondLevelWitnessScript: secondLevelWitnessScript,
			IsIncoming:               htlc.Incoming,
		})
	}

	// Finally, with all the necessary data constructed, we can create the
	// BreachRetribution struct which houses all the data necessary to
	// swiftly bring justice to the cheating remote party.
	return &BreachRetribution{
		ChainHash:            chanState.ChainHash,
		BreachTransaction:    revokedSnapshot.CommitTx,
		BreachHeight:         breachHeight,
		RevokedStateNum:      stateNum,
		PendingHTLCs:         revokedSnapshot.Htlcs,
		LocalOutpoint:        ourOutpoint,
		LocalOutputSignDesc:  ourSignDesc,
		LocalDelay:           ourDelay,
		RemoteOutpoint:       theirOutpoint,
		RemoteOutputSignDesc: theirSignDesc,
		RemoteDelay:          theirDelay,
		HtlcRetributions:     htlcRetributions,
		KeyRing:              keyRing,
	}, nil
}

// htlcIsDust determines if an HTLC output is dust or not depending on two
// bits: if the HTLC is incoming and if the HTLC will be placed on our
// commitment transaction, or theirs. These two pieces of information are
// require as we currently used second-level HTLC transactions as off-chain
// covenants. Depending on the two bits, we'll either be using a timeout or
// success transaction which have different weights.
func htlcIsDust(chanType channeldb.ChannelType,
	incoming, ourCommit bool, feePerKw chainfee.SatPerKWeight,
	htlcAmt, dustLimit btcutil.Amount) bool {

	// First we'll determine the fee required for this HTLC based on if this is
	// an incoming HTLC or not, and also on whose commitment transaction it
	// will be placed on.
	var htlcFee btcutil.Amount
	switch {

	// If this is an incoming HTLC on our commitment transaction, then the
	// second-level transaction will be a success transaction.
	case incoming && ourCommit:
		htlcFee = HtlcSuccessFee(chanType, feePerKw)

	// If this is an incoming HTLC on their commitment transaction, then
	// we'll be using a second-level timeout transaction as they've added
	// this HTLC.
	case incoming && !ourCommit:
		htlcFee = HtlcTimeoutFee(chanType, feePerKw)

	// If this is an outgoing HTLC on our commitment transaction, then
	// we'll be using a timeout transaction as we're the sender of the
	// HTLC.
	case !incoming && ourCommit:
		htlcFee = HtlcTimeoutFee(chanType, feePerKw)

	// If this is an outgoing HTLC on their commitment transaction, then
	// we'll be using an HTLC success transaction as they're the receiver
	// of this HTLC.
	case !incoming && !ourCommit:
		htlcFee = HtlcSuccessFee(chanType, feePerKw)
	}

	return (htlcAmt - htlcFee) < dustLimit
}

// htlcView represents the "active" HTLCs at a particular point within the
// history of the HTLC update log.
type htlcView struct {
	ourUpdates   []*PaymentDescriptor
	theirUpdates []*PaymentDescriptor
	feePerKw     chainfee.SatPerKWeight
}

// fetchHTLCView returns all the candidate HTLC updates which should be
// considered for inclusion within a commitment based on the passed HTLC log
// indexes.
func (lc *LightningChannel) fetchHTLCView(theirLogIndex, ourLogIndex uint64) *htlcView {
	var ourHTLCs []*PaymentDescriptor
	for e := lc.localUpdateLog.Front(); e != nil; e = e.Next() {
		htlc := e.Value.(*PaymentDescriptor)

		// This HTLC is active from this point-of-view iff the log
		// index of the state update is below the specified index in
		// our update log.
		if htlc.LogIndex < ourLogIndex {
			ourHTLCs = append(ourHTLCs, htlc)
		}
	}

	var theirHTLCs []*PaymentDescriptor
	for e := lc.remoteUpdateLog.Front(); e != nil; e = e.Next() {
		htlc := e.Value.(*PaymentDescriptor)

		// If this is an incoming HTLC, then it is only active from
		// this point-of-view if the index of the HTLC addition in
		// their log is below the specified view index.
		if htlc.LogIndex < theirLogIndex {
			theirHTLCs = append(theirHTLCs, htlc)
		}
	}

	return &htlcView{
		ourUpdates:   ourHTLCs,
		theirUpdates: theirHTLCs,
	}
}

// fetchCommitmentView returns a populated commitment which expresses the state
// of the channel from the point of view of a local or remote chain, evaluating
// the HTLC log up to the passed indexes. This function is used to construct
// both local and remote commitment transactions in order to sign or verify new
// commitment updates. A fully populated commitment is returned which reflects
// the proper balances for both sides at this point in the commitment chain.
func (lc *LightningChannel) fetchCommitmentView(remoteChain bool,
	ourLogIndex, ourHtlcIndex, theirLogIndex, theirHtlcIndex uint64,
	keyRing *CommitmentKeyRing) (*commitment, error) {

	commitChain := lc.localCommitChain
	dustLimit := lc.channelState.LocalChanCfg.DustLimit
	if remoteChain {
		commitChain = lc.remoteCommitChain
		dustLimit = lc.channelState.RemoteChanCfg.DustLimit
	}

	nextHeight := commitChain.tip().height + 1

	// Run through all the HTLCs that will be covered by this transaction
	// in order to update their commitment addition height, and to adjust
	// the balances on the commitment transaction accordingly. Note that
	// these balances will be *before* taking a commitment fee from the
	// initiator.
	htlcView := lc.fetchHTLCView(theirLogIndex, ourLogIndex)
	ourBalance, theirBalance, _, filteredHTLCView, err := lc.computeView(
		htlcView, remoteChain, true,
	)
	if err != nil {
		return nil, err
	}
	feePerKw := filteredHTLCView.feePerKw

	// Actually generate unsigned commitment transaction for this view.
	commitTx, err := lc.commitBuilder.createUnsignedCommitmentTx(
		ourBalance, theirBalance, !remoteChain, feePerKw, nextHeight,
		filteredHTLCView, keyRing,
	)
	if err != nil {
		return nil, err
	}

	// We'll assert that there hasn't been a mistake during fee calculation
	// leading to a fee too low.
	var totalOut btcutil.Amount
	for _, txOut := range commitTx.txn.TxOut {
		totalOut += btcutil.Amount(txOut.Value)
	}
	fee := lc.channelState.Capacity - totalOut

	// Since the transaction is not signed yet, we use the witness weight
	// used for weight calculation.
	uTx := btcutil.NewTx(commitTx.txn)
	weight := blockchain.GetTransactionWeight(uTx) +
		input.WitnessCommitmentTxWeight

	effFeeRate := chainfee.SatPerKWeight(fee) * 1000 /
		chainfee.SatPerKWeight(weight)
	if effFeeRate < chainfee.AbsoluteFeePerKwFloor {
		return nil, fmt.Errorf("height=%v, for ChannelPoint(%v) "+
			"attempts to create commitment with feerate %v: %v",
			nextHeight, lc.channelState.FundingOutpoint,
			effFeeRate, spew.Sdump(commitTx))
	}

	// With the commitment view created, store the resulting balances and
	// transaction with the other parameters for this height.
	c := &commitment{
		ourBalance:        commitTx.ourBalance,
		theirBalance:      commitTx.theirBalance,
		txn:               commitTx.txn,
		fee:               commitTx.fee,
		ourMessageIndex:   ourLogIndex,
		ourHtlcIndex:      ourHtlcIndex,
		theirMessageIndex: theirLogIndex,
		theirHtlcIndex:    theirHtlcIndex,
		height:            nextHeight,
		feePerKw:          feePerKw,
		dustLimit:         dustLimit,
		isOurs:            !remoteChain,
	}

	// In order to ensure _none_ of the HTLC's associated with this new
	// commitment are mutated, we'll manually copy over each HTLC to its
	// respective slice.
	c.outgoingHTLCs = make([]PaymentDescriptor, len(filteredHTLCView.ourUpdates))
	for i, htlc := range filteredHTLCView.ourUpdates {
		c.outgoingHTLCs[i] = *htlc
	}
	c.incomingHTLCs = make([]PaymentDescriptor, len(filteredHTLCView.theirUpdates))
	for i, htlc := range filteredHTLCView.theirUpdates {
		c.incomingHTLCs[i] = *htlc
	}

	// Finally, we'll populate all the HTLC indexes so we can track the
	// locations of each HTLC in the commitment state. We pass in the sorted
	// slice of CLTV deltas in order to properly locate HTLCs that otherwise
	// have the same payment hash and amount.
	err = c.populateHtlcIndexes(lc.channelState.ChanType, commitTx.cltvs)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func fundingTxIn(chanState *channeldb.OpenChannel) wire.TxIn {
	return *wire.NewTxIn(&chanState.FundingOutpoint, nil, nil)
}

// evaluateHTLCView processes all update entries in both HTLC update logs,
// producing a final view which is the result of properly applying all adds,
// settles, timeouts and fee updates found in both logs. The resulting view
// returned reflects the current state of HTLCs within the remote or local
// commitment chain, and the current commitment fee rate.
//
// If mutateState is set to true, then the add height of all added HTLCs
// will be set to nextHeight, and the remove height of all removed HTLCs
// will be set to nextHeight. This should therefore only be set to true
// once for each height, and only in concert with signing a new commitment.
// TODO(halseth): return htlcs to mutate instead of mutating inside
// method.
func (lc *LightningChannel) evaluateHTLCView(view *htlcView, ourBalance,
	theirBalance *lnwire.MilliSatoshi, nextHeight uint64,
	remoteChain, mutateState bool) (*htlcView, error) {

	// We initialize the view's fee rate to the fee rate of the unfiltered
	// view. If any fee updates are found when evaluating the view, it will
	// be updated.
	newView := &htlcView{
		feePerKw: view.feePerKw,
	}

	// We use two maps, one for the local log and one for the remote log to
	// keep track of which entries we need to skip when creating the final
	// htlc view. We skip an entry whenever we find a settle or a timeout
	// modifying an entry.
	skipUs := make(map[uint64]struct{})
	skipThem := make(map[uint64]struct{})

	// First we run through non-add entries in both logs, populating the
	// skip sets and mutating the current chain state (crediting balances,
	// etc) to reflect the settle/timeout entry encountered.
	for _, entry := range view.ourUpdates {
		switch entry.EntryType {
		// Skip adds for now. They will be processed below.
		case Add:
			continue

		// Process fee updates, updating the current feePerKw.
		case FeeUpdate:
			processFeeUpdate(
				entry, nextHeight, remoteChain, mutateState,
				newView,
			)
			continue
		}

		// If we're settling an inbound HTLC, and it hasn't been
		// processed yet, then increment our state tracking the total
		// number of satoshis we've received within the channel.
		if mutateState && entry.EntryType == Settle && !remoteChain &&
			entry.removeCommitHeightLocal == 0 {
			lc.channelState.TotalMSatReceived += entry.Amount
		}

		addEntry, err := lc.fetchParent(entry, remoteChain, true)
		if err != nil {
			return nil, err
		}

		skipThem[addEntry.HtlcIndex] = struct{}{}
		processRemoveEntry(entry, ourBalance, theirBalance,
			nextHeight, remoteChain, true, mutateState)
	}
	for _, entry := range view.theirUpdates {
		switch entry.EntryType {
		// Skip adds for now. They will be processed below.
		case Add:
			continue

		// Process fee updates, updating the current feePerKw.
		case FeeUpdate:
			processFeeUpdate(
				entry, nextHeight, remoteChain, mutateState,
				newView,
			)
			continue
		}

		// If the remote party is settling one of our outbound HTLC's,
		// and it hasn't been processed, yet, the increment our state
		// tracking the total number of satoshis we've sent within the
		// channel.
		if mutateState && entry.EntryType == Settle && !remoteChain &&
			entry.removeCommitHeightLocal == 0 {
			lc.channelState.TotalMSatSent += entry.Amount
		}

		addEntry, err := lc.fetchParent(entry, remoteChain, false)
		if err != nil {
			return nil, err
		}

		skipUs[addEntry.HtlcIndex] = struct{}{}
		processRemoveEntry(entry, ourBalance, theirBalance,
			nextHeight, remoteChain, false, mutateState)
	}

	// Next we take a second pass through all the log entries, skipping any
	// settled HTLCs, and debiting the chain state balance due to any newly
	// added HTLCs.
	for _, entry := range view.ourUpdates {
		isAdd := entry.EntryType == Add
		if _, ok := skipUs[entry.HtlcIndex]; !isAdd || ok {
			continue
		}

		processAddEntry(entry, ourBalance, theirBalance, nextHeight,
			remoteChain, false, mutateState)
		newView.ourUpdates = append(newView.ourUpdates, entry)
	}
	for _, entry := range view.theirUpdates {
		isAdd := entry.EntryType == Add
		if _, ok := skipThem[entry.HtlcIndex]; !isAdd || ok {
			continue
		}

		processAddEntry(entry, ourBalance, theirBalance, nextHeight,
			remoteChain, true, mutateState)
		newView.theirUpdates = append(newView.theirUpdates, entry)
	}

	return newView, nil
}

// fetchParent is a helper that looks up update log parent entries in the
// appropriate log.
func (lc *LightningChannel) fetchParent(entry *PaymentDescriptor,
	remoteChain, remoteLog bool) (*PaymentDescriptor, error) {

	var (
		updateLog *updateLog
		logName   string
	)

	if remoteLog {
		updateLog = lc.remoteUpdateLog
		logName = "remote"
	} else {
		updateLog = lc.localUpdateLog
		logName = "local"
	}

	addEntry := updateLog.lookupHtlc(entry.ParentIndex)

	switch {
	// We check if the parent entry is not found at this point.
	// This could happen for old versions of lnd, and we return an
	// error to gracefully shut down the state machine if such an
	// entry is still in the logs.
	case addEntry == nil:
		return nil, fmt.Errorf("unable to find parent entry "+
			"%d in %v update log: %v\nUpdatelog: %v",
			entry.ParentIndex, logName,
			newLogClosure(func() string {
				return spew.Sdump(entry)
			}), newLogClosure(func() string {
				return spew.Sdump(updateLog)
			}),
		)

	// The parent add height should never be zero at this point. If
	// that's the case we probably forgot to send a new commitment.
	case remoteChain && addEntry.addCommitHeightRemote == 0:
		return nil, fmt.Errorf("parent entry %d for update %d "+
			"had zero remote add height", entry.ParentIndex,
			entry.LogIndex)
	case !remoteChain && addEntry.addCommitHeightLocal == 0:
		return nil, fmt.Errorf("parent entry %d for update %d "+
			"had zero local add height", entry.ParentIndex,
			entry.LogIndex)
	}

	return addEntry, nil
}

// processAddEntry evaluates the effect of an add entry within the HTLC log.
// If the HTLC hasn't yet been committed in either chain, then the height it
// was committed is updated. Keeping track of this inclusion height allows us to
// later compact the log once the change is fully committed in both chains.
func processAddEntry(htlc *PaymentDescriptor, ourBalance, theirBalance *lnwire.MilliSatoshi,
	nextHeight uint64, remoteChain bool, isIncoming, mutateState bool) {

	// If we're evaluating this entry for the remote chain (to create/view
	// a new commitment), then we'll may be updating the height this entry
	// was added to the chain. Otherwise, we may be updating the entry's
	// height w.r.t the local chain.
	var addHeight *uint64
	if remoteChain {
		addHeight = &htlc.addCommitHeightRemote
	} else {
		addHeight = &htlc.addCommitHeightLocal
	}

	if *addHeight != 0 {
		return
	}

	if isIncoming {
		// If this is a new incoming (un-committed) HTLC, then we need
		// to update their balance accordingly by subtracting the
		// amount of the HTLC that are funds pending.
		*theirBalance -= htlc.Amount
	} else {
		// Similarly, we need to debit our balance if this is an out
		// going HTLC to reflect the pending balance.
		*ourBalance -= htlc.Amount
	}

	if mutateState {
		*addHeight = nextHeight
	}
}

// processRemoveEntry processes a log entry which settles or times out a
// previously added HTLC. If the removal entry has already been processed, it
// is skipped.
func processRemoveEntry(htlc *PaymentDescriptor, ourBalance,
	theirBalance *lnwire.MilliSatoshi, nextHeight uint64,
	remoteChain bool, isIncoming, mutateState bool) {

	var removeHeight *uint64
	if remoteChain {
		removeHeight = &htlc.removeCommitHeightRemote
	} else {
		removeHeight = &htlc.removeCommitHeightLocal
	}

	// Ignore any removal entries which have already been processed.
	if *removeHeight != 0 {
		return
	}

	switch {
	// If an incoming HTLC is being settled, then this means that we've
	// received the preimage either from another subsystem, or the
	// upstream peer in the route. Therefore, we increase our balance by
	// the HTLC amount.
	case isIncoming && htlc.EntryType == Settle:
		*ourBalance += htlc.Amount

	// Otherwise, this HTLC is being failed out, therefore the value of the
	// HTLC should return to the remote party.
	case isIncoming && (htlc.EntryType == Fail || htlc.EntryType == MalformedFail):
		*theirBalance += htlc.Amount

	// If an outgoing HTLC is being settled, then this means that the
	// downstream party resented the preimage or learned of it via a
	// downstream peer. In either case, we credit their settled value with
	// the value of the HTLC.
	case !isIncoming && htlc.EntryType == Settle:
		*theirBalance += htlc.Amount

	// Otherwise, one of our outgoing HTLC's has timed out, so the value of
	// the HTLC should be returned to our settled balance.
	case !isIncoming && (htlc.EntryType == Fail || htlc.EntryType == MalformedFail):
		*ourBalance += htlc.Amount
	}

	if mutateState {
		*removeHeight = nextHeight
	}
}

// processFeeUpdate processes a log update that updates the current commitment
// fee.
func processFeeUpdate(feeUpdate *PaymentDescriptor, nextHeight uint64,
	remoteChain bool, mutateState bool, view *htlcView) {

	// Fee updates are applied for all commitments after they are
	// sent/received, so we consider them being added and removed at the
	// same height.
	var addHeight *uint64
	var removeHeight *uint64
	if remoteChain {
		addHeight = &feeUpdate.addCommitHeightRemote
		removeHeight = &feeUpdate.removeCommitHeightRemote
	} else {
		addHeight = &feeUpdate.addCommitHeightLocal
		removeHeight = &feeUpdate.removeCommitHeightLocal
	}

	if *addHeight != 0 {
		return
	}

	// If the update wasn't already locked in, update the current fee rate
	// to reflect this update.
	view.feePerKw = chainfee.SatPerKWeight(feeUpdate.Amount.ToSatoshis())

	if mutateState {
		*addHeight = nextHeight
		*removeHeight = nextHeight
	}
}

// generateRemoteHtlcSigJobs generates a series of HTLC signature jobs for the
// sig pool, along with a channel that if closed, will cancel any jobs after
// they have been submitted to the sigPool. This method is to be used when
// generating a new commitment for the remote party. The jobs generated by the
// signature can be submitted to the sigPool to generate all the signatures
// asynchronously and in parallel.
func genRemoteHtlcSigJobs(keyRing *CommitmentKeyRing,
	chanType channeldb.ChannelType,
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig,
	remoteCommitView *commitment) ([]SignJob, chan struct{}, error) {

	txHash := remoteCommitView.txn.TxHash()
	dustLimit := remoteChanCfg.DustLimit
	feePerKw := remoteCommitView.feePerKw
	sigHashType := HtlcSigHashType(chanType)

	// With the keys generated, we'll make a slice with enough capacity to
	// hold potentially all the HTLCs. The actual slice may be a bit
	// smaller (than its total capacity) and some HTLCs may be dust.
	numSigs := (len(remoteCommitView.incomingHTLCs) +
		len(remoteCommitView.outgoingHTLCs))
	sigBatch := make([]SignJob, 0, numSigs)

	var err error
	cancelChan := make(chan struct{})

	// For each outgoing and incoming HTLC, if the HTLC isn't considered a
	// dust output after taking into account second-level HTLC fees, then a
	// sigJob will be generated and appended to the current batch.
	for _, htlc := range remoteCommitView.incomingHTLCs {
		if htlcIsDust(
			chanType, true, false, feePerKw,
			htlc.Amount.ToSatoshis(), dustLimit,
		) {
			continue
		}

		// If the HTLC isn't dust, then we'll create an empty sign job
		// to add to the batch momentarily.
		sigJob := SignJob{}
		sigJob.Cancel = cancelChan
		sigJob.Resp = make(chan SignJobResp, 1)

		// As this is an incoming HTLC and we're sinning the commitment
		// transaction of the remote node, we'll need to generate an
		// HTLC timeout transaction for them. The output of the timeout
		// transaction needs to account for fees, so we'll compute the
		// required fee and output now.
		htlcFee := HtlcTimeoutFee(chanType, feePerKw)
		outputAmt := htlc.Amount.ToSatoshis() - htlcFee

		// With the fee calculate, we can properly create the HTLC
		// timeout transaction using the HTLC amount minus the fee.
		op := wire.OutPoint{
			Hash:  txHash,
			Index: uint32(htlc.remoteOutputIndex),
		}
		sigJob.Tx, err = CreateHtlcTimeoutTx(
			chanType, op, outputAmt, htlc.Timeout,
			uint32(remoteChanCfg.CsvDelay),
			keyRing.RevocationKey, keyRing.ToLocalKey,
		)
		if err != nil {
			return nil, nil, err
		}

		// Finally, we'll generate a sign descriptor to generate a
		// signature to give to the remote party for this commitment
		// transaction. Note we use the raw HTLC amount.
		txOut := remoteCommitView.txn.TxOut[htlc.remoteOutputIndex]
		sigJob.SignDesc = input.SignDescriptor{
			KeyDesc:       localChanCfg.HtlcBasePoint,
			SingleTweak:   keyRing.LocalHtlcKeyTweak,
			WitnessScript: htlc.theirWitnessScript,
			Output:        txOut,
			HashType:      sigHashType,
			SigHashes:     txscript.NewTxSigHashes(sigJob.Tx),
			InputIndex:    0,
		}
		sigJob.OutputIndex = htlc.remoteOutputIndex

		sigBatch = append(sigBatch, sigJob)
	}
	for _, htlc := range remoteCommitView.outgoingHTLCs {
		if htlcIsDust(
			chanType, false, false, feePerKw,
			htlc.Amount.ToSatoshis(), dustLimit,
		) {
			continue
		}

		sigJob := SignJob{}
		sigJob.Cancel = cancelChan
		sigJob.Resp = make(chan SignJobResp, 1)

		// As this is an outgoing HTLC and we're signing the commitment
		// transaction of the remote node, we'll need to generate an
		// HTLC success transaction for them. The output of the timeout
		// transaction needs to account for fees, so we'll compute the
		// required fee and output now.
		htlcFee := HtlcSuccessFee(chanType, feePerKw)
		outputAmt := htlc.Amount.ToSatoshis() - htlcFee

		// With the proper output amount calculated, we can now
		// generate the success transaction using the remote party's
		// CSV delay.
		op := wire.OutPoint{
			Hash:  txHash,
			Index: uint32(htlc.remoteOutputIndex),
		}
		sigJob.Tx, err = CreateHtlcSuccessTx(
			chanType, op, outputAmt, uint32(remoteChanCfg.CsvDelay),
			keyRing.RevocationKey, keyRing.ToLocalKey,
		)
		if err != nil {
			return nil, nil, err
		}

		// Finally, we'll generate a sign descriptor to generate a
		// signature to give to the remote party for this commitment
		// transaction. Note we use the raw HTLC amount.
		txOut := remoteCommitView.txn.TxOut[htlc.remoteOutputIndex]
		sigJob.SignDesc = input.SignDescriptor{
			KeyDesc:       localChanCfg.HtlcBasePoint,
			SingleTweak:   keyRing.LocalHtlcKeyTweak,
			WitnessScript: htlc.theirWitnessScript,
			Output:        txOut,
			HashType:      sigHashType,
			SigHashes:     txscript.NewTxSigHashes(sigJob.Tx),
			InputIndex:    0,
		}
		sigJob.OutputIndex = htlc.remoteOutputIndex

		sigBatch = append(sigBatch, sigJob)
	}

	return sigBatch, cancelChan, nil
}

// createCommitDiff will create a commit diff given a new pending commitment
// for the remote party and the necessary signatures for the remote party to
// validate this new state. This function is called right before sending the
// new commitment to the remote party. The commit diff returned contains all
// information necessary for retransmission.
func (lc *LightningChannel) createCommitDiff(
	newCommit *commitment, commitSig lnwire.Sig,
	htlcSigs []lnwire.Sig) (*channeldb.CommitDiff, error) {

	// First, we need to convert the funding outpoint into the ID that's
	// used on the wire to identify this channel. We'll use this shortly
	// when recording the exact CommitSig message that we'll be sending
	// out.
	chanID := lnwire.NewChanIDFromOutPoint(&lc.channelState.FundingOutpoint)

	var (
		logUpdates        []channeldb.LogUpdate
		ackAddRefs        []channeldb.AddRef
		settleFailRefs    []channeldb.SettleFailRef
		openCircuitKeys   []channeldb.CircuitKey
		closedCircuitKeys []channeldb.CircuitKey
	)

	// We'll now run through our local update log to locate the items which
	// were only just committed within this pending state. This will be the
	// set of items we need to retransmit if we reconnect and find that
	// they didn't process this new state fully.
	for e := lc.localUpdateLog.Front(); e != nil; e = e.Next() {
		pd := e.Value.(*PaymentDescriptor)

		// If this entry wasn't committed at the exact height of this
		// remote commitment, then we'll skip it as it was already
		// lingering in the log.
		if pd.addCommitHeightRemote != newCommit.height &&
			pd.removeCommitHeightRemote != newCommit.height {

			continue
		}

		// Knowing that this update is a part of this new commitment,
		// we'll create a log update and not its index in the log so
		// we can later restore it properly if a restart occurs.
		logUpdate := channeldb.LogUpdate{
			LogIndex: pd.LogIndex,
		}

		// We'll map the type of the PaymentDescriptor to one of the
		// four messages that it corresponds to. With this set of
		// messages obtained, we can simply read from disk and re-send
		// them in the case of a needed channel sync.
		switch pd.EntryType {
		case Add:
			htlc := &lnwire.UpdateAddHTLC{
				ChanID:      chanID,
				ID:          pd.HtlcIndex,
				Amount:      pd.Amount,
				Expiry:      pd.Timeout,
				PaymentHash: pd.RHash,
			}
			copy(htlc.OnionBlob[:], pd.OnionBlob)
			logUpdate.UpdateMsg = htlc

			// Gather any references for circuits opened by this Add
			// HTLC.
			if pd.OpenCircuitKey != nil {
				openCircuitKeys = append(openCircuitKeys,
					*pd.OpenCircuitKey)
			}

			logUpdates = append(logUpdates, logUpdate)

			// Short circuit here since an add should not have any
			// of the references gathered in the case of settles,
			// fails or malformed fails.
			continue

		case Settle:
			logUpdate.UpdateMsg = &lnwire.UpdateFulfillHTLC{
				ChanID:          chanID,
				ID:              pd.ParentIndex,
				PaymentPreimage: pd.RPreimage,
			}

		case Fail:
			logUpdate.UpdateMsg = &lnwire.UpdateFailHTLC{
				ChanID: chanID,
				ID:     pd.ParentIndex,
				Reason: pd.FailReason,
			}

		case MalformedFail:
			logUpdate.UpdateMsg = &lnwire.UpdateFailMalformedHTLC{
				ChanID:       chanID,
				ID:           pd.ParentIndex,
				ShaOnionBlob: pd.ShaOnionBlob,
				FailureCode:  pd.FailCode,
			}

		case FeeUpdate:
			// The Amount field holds the feerate denominated in
			// msat. Since feerates are only denominated in sat/kw,
			// we can convert it without loss of precision.
			logUpdate.UpdateMsg = &lnwire.UpdateFee{
				ChanID:   chanID,
				FeePerKw: uint32(pd.Amount.ToSatoshis()),
			}
		}

		// Gather the fwd pkg references from any settle or fail
		// packets, if they exist.
		if pd.SourceRef != nil {
			ackAddRefs = append(ackAddRefs, *pd.SourceRef)
		}
		if pd.DestRef != nil {
			settleFailRefs = append(settleFailRefs, *pd.DestRef)
		}
		if pd.ClosedCircuitKey != nil {
			closedCircuitKeys = append(closedCircuitKeys,
				*pd.ClosedCircuitKey)
		}

		logUpdates = append(logUpdates, logUpdate)
	}

	// With the set of log updates mapped into wire messages, we'll now
	// convert the in-memory commit into a format suitable for writing to
	// disk.
	diskCommit := newCommit.toDiskCommit(false)

	return &channeldb.CommitDiff{
		Commitment: *diskCommit,
		CommitSig: &lnwire.CommitSig{
			ChanID: lnwire.NewChanIDFromOutPoint(
				&lc.channelState.FundingOutpoint,
			),
			CommitSig: commitSig,
			HtlcSigs:  htlcSigs,
		},
		LogUpdates:        logUpdates,
		OpenedCircuitKeys: openCircuitKeys,
		ClosedCircuitKeys: closedCircuitKeys,
		AddAcks:           ackAddRefs,
		SettleFailAcks:    settleFailRefs,
	}, nil
}

// getUnsignedAckedUpdates returns all remote log updates that we haven't
// signed for yet ourselves.
func (lc *LightningChannel) getUnsignedAckedUpdates() []channeldb.LogUpdate {
	// First, we need to convert the funding outpoint into the ID that's
	// used on the wire to identify this channel.
	chanID := lnwire.NewChanIDFromOutPoint(&lc.channelState.FundingOutpoint)

	// Fetch the last remote update that we have signed for.
	lastRemoteCommitted := lc.remoteCommitChain.tail().theirMessageIndex

	// Fetch the last remote update that we have acked.
	lastLocalCommitted := lc.localCommitChain.tail().theirMessageIndex

	// We'll now run through the remote update log to locate the items that
	// we haven't signed for yet. This will be the set of items we need to
	// restore if we reconnect in order to produce the signature that the
	// remote party expects.
	var logUpdates []channeldb.LogUpdate
	for e := lc.remoteUpdateLog.Front(); e != nil; e = e.Next() {
		pd := e.Value.(*PaymentDescriptor)

		// Skip all remote updates that we have already included in our
		// commit chain.
		if pd.LogIndex < lastRemoteCommitted {
			continue
		}

		// Skip all remote updates that we haven't acked yet. At the
		// moment this function is called, there shouldn't be any, but
		// we check it anyway to make this function more generally
		// usable.
		if pd.LogIndex >= lastLocalCommitted {
			continue
		}

		logUpdate := channeldb.LogUpdate{
			LogIndex: pd.LogIndex,
		}

		// We'll map the type of the PaymentDescriptor to one of the
		// four messages that it corresponds to.
		switch pd.EntryType {
		case Add:
			htlc := &lnwire.UpdateAddHTLC{
				ChanID:      chanID,
				ID:          pd.HtlcIndex,
				Amount:      pd.Amount,
				Expiry:      pd.Timeout,
				PaymentHash: pd.RHash,
			}
			copy(htlc.OnionBlob[:], pd.OnionBlob)
			logUpdate.UpdateMsg = htlc

		case Settle:
			logUpdate.UpdateMsg = &lnwire.UpdateFulfillHTLC{
				ChanID:          chanID,
				ID:              pd.ParentIndex,
				PaymentPreimage: pd.RPreimage,
			}

		case Fail:
			logUpdate.UpdateMsg = &lnwire.UpdateFailHTLC{
				ChanID: chanID,
				ID:     pd.ParentIndex,
				Reason: pd.FailReason,
			}

		case MalformedFail:
			logUpdate.UpdateMsg = &lnwire.UpdateFailMalformedHTLC{
				ChanID:       chanID,
				ID:           pd.ParentIndex,
				ShaOnionBlob: pd.ShaOnionBlob,
				FailureCode:  pd.FailCode,
			}

		case FeeUpdate:
			// The Amount field holds the feerate denominated in
			// msat. Since feerates are only denominated in sat/kw,
			// we can convert it without loss of precision.
			logUpdate.UpdateMsg = &lnwire.UpdateFee{
				ChanID:   chanID,
				FeePerKw: uint32(pd.Amount.ToSatoshis()),
			}
		}

		logUpdates = append(logUpdates, logUpdate)
	}
	return logUpdates
}

// validateCommitmentSanity is used to validate the current state of the
// commitment transaction in terms of the ChannelConstraints that we and our
// remote peer agreed upon during the funding workflow. The
// predict[Our|Their]Add should parameters should be set to a valid
// PaymentDescriptor if we are validating in the state when adding a new HTLC,
// or nil otherwise.
func (lc *LightningChannel) validateCommitmentSanity(theirLogCounter,
	ourLogCounter uint64, remoteChain bool,
	predictOurAdd, predictTheirAdd *PaymentDescriptor) error {

	// Fetch all updates not committed.
	view := lc.fetchHTLCView(theirLogCounter, ourLogCounter)

	// If we are checking if we can add a new HTLC, we add this to the
	// appropriate update log, in order to validate the sanity of the
	// commitment resulting from _actually adding_ this HTLC to the state.
	if predictOurAdd != nil {
		view.ourUpdates = append(view.ourUpdates, predictOurAdd)
	}
	if predictTheirAdd != nil {
		view.theirUpdates = append(view.theirUpdates, predictTheirAdd)
	}

	commitChain := lc.localCommitChain
	if remoteChain {
		commitChain = lc.remoteCommitChain
	}
	ourInitialBalance := commitChain.tip().ourBalance
	theirInitialBalance := commitChain.tip().theirBalance

	ourBalance, theirBalance, commitWeight, filteredView, err := lc.computeView(
		view, remoteChain, false,
	)
	if err != nil {
		return err
	}
	feePerKw := filteredView.feePerKw

	// Calculate the commitment fee, and subtract it from the initiator's
	// balance.
	commitFee := feePerKw.FeeForWeight(commitWeight)
	commitFeeMsat := lnwire.NewMSatFromSatoshis(commitFee)
	if lc.channelState.IsInitiator {
		ourBalance -= commitFeeMsat
	} else {
		theirBalance -= commitFeeMsat
	}

	// As a quick sanity check, we'll ensure that if we interpret the
	// balances as signed integers, they haven't dipped down below zero. If
	// they have, then this indicates that a party doesn't have sufficient
	// balance to satisfy the final evaluated HTLC's.
	switch {
	case int64(ourBalance) < 0:
		return ErrBelowChanReserve
	case int64(theirBalance) < 0:
		return ErrBelowChanReserve
	}

	// Ensure that the fee being applied is enough to be relayed across the
	// network in a reasonable time frame.
	if feePerKw < chainfee.FeePerKwFloor {
		return fmt.Errorf("commitment fee per kw %v below fee floor %v",
			feePerKw, chainfee.FeePerKwFloor)
	}

	// If the added HTLCs will decrease the balance, make sure they won't
	// dip the local and remote balances below the channel reserves.
	switch {
	case ourBalance < ourInitialBalance &&
		ourBalance < lnwire.NewMSatFromSatoshis(
			lc.channelState.LocalChanCfg.ChanReserve):

		return ErrBelowChanReserve
	case theirBalance < theirInitialBalance &&
		theirBalance < lnwire.NewMSatFromSatoshis(
			lc.channelState.RemoteChanCfg.ChanReserve):

		return ErrBelowChanReserve
	}

	// validateUpdates take a set of updates, and validates them against
	// the passed channel constraints.
	validateUpdates := func(updates []*PaymentDescriptor,
		constraints *channeldb.ChannelConfig) error {

		// We keep track of the number of HTLCs in flight for the
		// commitment, and the amount in flight.
		var numInFlight uint16
		var amtInFlight lnwire.MilliSatoshi

		// Go through all updates, checking that they don't violate the
		// channel constraints.
		for _, entry := range updates {
			if entry.EntryType == Add {
				// An HTLC is being added, this will add to the
				// number and amount in flight.
				amtInFlight += entry.Amount
				numInFlight++

				// Check that the HTLC amount is positive.
				if entry.Amount == 0 {
					return ErrInvalidHTLCAmt
				}

				// Check that the value of the HTLC they added
				// is above our minimum.
				if entry.Amount < constraints.MinHTLC {
					return ErrBelowMinHTLC
				}
			}
		}

		// Now that we know the total value of added HTLCs, we check
		// that this satisfy the MaxPendingAmont contraint.
		if amtInFlight > constraints.MaxPendingAmount {
			return ErrMaxPendingAmount
		}

		// In this step, we verify that the total number of active
		// HTLCs does not exceed the constraint of the maximum number
		// of HTLCs in flight.
		if numInFlight > constraints.MaxAcceptedHtlcs {
			return ErrMaxHTLCNumber
		}

		return nil
	}

	// First check that the remote updates won't violate it's channel
	// constraints.
	err = validateUpdates(
		filteredView.theirUpdates, &lc.channelState.RemoteChanCfg,
	)
	if err != nil {
		return err
	}

	// Secondly check that our updates won't violate our channel
	// constraints.
	err = validateUpdates(
		filteredView.ourUpdates, &lc.channelState.LocalChanCfg,
	)
	if err != nil {
		return err
	}

	return nil
}

// SignNextCommitment signs a new commitment which includes any previous
// unsettled HTLCs, any new HTLCs, and any modifications to prior HTLCs
// committed in previous commitment updates. Signing a new commitment
// decrements the available revocation window by 1. After a successful method
// call, the remote party's commitment chain is extended by a new commitment
// which includes all updates to the HTLC log prior to this method invocation.
// The first return parameter is the signature for the commitment transaction
// itself, while the second parameter is a slice of all HTLC signatures (if
// any). The HTLC signatures are sorted according to the BIP 69 order of the
// HTLC's on the commitment transaction. Finally, the new set of pending HTLCs
// for the remote party's commitment are also returned.
func (lc *LightningChannel) SignNextCommitment() (lnwire.Sig, []lnwire.Sig, []channeldb.HTLC, error) {

	lc.Lock()
	defer lc.Unlock()

	// Check for empty commit sig. This should never happen, but we don't
	// dare to fail hard here. We assume peers can deal with the empty sig
	// and continue channel operation. We log an error so that the bug
	// causing this can be tracked down.
	if !lc.oweCommitment(true) {
		lc.log.Errorf("sending empty commit sig")
	}

	var (
		sig      lnwire.Sig
		htlcSigs []lnwire.Sig
	)

	// If we're awaiting for an ACK to a commitment signature, or if we
	// don't yet have the initial next revocation point of the remote
	// party, then we're unable to create new states. Each time we create a
	// new state, we consume a prior revocation point.
	commitPoint := lc.channelState.RemoteNextRevocation
	if lc.remoteCommitChain.hasUnackedCommitment() || commitPoint == nil {

		return sig, htlcSigs, nil, ErrNoWindow
	}

	// Determine the last update on the remote log that has been locked in.
	remoteACKedIndex := lc.localCommitChain.tail().theirMessageIndex
	remoteHtlcIndex := lc.localCommitChain.tail().theirHtlcIndex

	// Before we extend this new commitment to the remote commitment chain,
	// ensure that we aren't violating any of the constraints the remote
	// party set up when we initially set up the channel. If we are, then
	// we'll abort this state transition.
	err := lc.validateCommitmentSanity(
		remoteACKedIndex, lc.localUpdateLog.logIndex, true, nil, nil,
	)
	if err != nil {
		return sig, htlcSigs, nil, err
	}

	// Grab the next commitment point for the remote party. This will be
	// used within fetchCommitmentView to derive all the keys necessary to
	// construct the commitment state.
	keyRing := DeriveCommitmentKeys(
		commitPoint, false, lc.channelState.ChanType,
		&lc.channelState.LocalChanCfg, &lc.channelState.RemoteChanCfg,
	)

	// Create a new commitment view which will calculate the evaluated
	// state of the remote node's new commitment including our latest added
	// HTLCs. The view includes the latest balances for both sides on the
	// remote node's chain, and also update the addition height of any new
	// HTLC log entries. When we creating a new remote view, we include
	// _all_ of our changes (pending or committed) but only the remote
	// node's changes up to the last change we've ACK'd.
	newCommitView, err := lc.fetchCommitmentView(
		true, lc.localUpdateLog.logIndex, lc.localUpdateLog.htlcCounter,
		remoteACKedIndex, remoteHtlcIndex, keyRing,
	)
	if err != nil {
		return sig, htlcSigs, nil, err
	}

	lc.log.Tracef("extending remote chain to height %v, "+
		"local_log=%v, remote_log=%v",
		newCommitView.height,
		lc.localUpdateLog.logIndex, remoteACKedIndex)

	lc.log.Tracef("remote chain: our_balance=%v, "+
		"their_balance=%v, commit_tx: %v",
		newCommitView.ourBalance,
		newCommitView.theirBalance,
		newLogClosure(func() string {
			return spew.Sdump(newCommitView.txn)
		}),
	)

	// With the commitment view constructed, if there are any HTLC's, we'll
	// need to generate signatures of each of them for the remote party's
	// commitment state. We do so in two phases: first we generate and
	// submit the set of signature jobs to the worker pool.
	sigBatch, cancelChan, err := genRemoteHtlcSigJobs(
		keyRing, lc.channelState.ChanType,
		&lc.channelState.LocalChanCfg, &lc.channelState.RemoteChanCfg,
		newCommitView,
	)
	if err != nil {
		return sig, htlcSigs, nil, err
	}
	lc.sigPool.SubmitSignBatch(sigBatch)

	// While the jobs are being carried out, we'll Sign their version of
	// the new commitment transaction while we're waiting for the rest of
	// the HTLC signatures to be processed.
	lc.signDesc.SigHashes = txscript.NewTxSigHashes(newCommitView.txn)
	rawSig, err := lc.Signer.SignOutputRaw(newCommitView.txn, lc.signDesc)
	if err != nil {
		close(cancelChan)
		return sig, htlcSigs, nil, err
	}
	sig, err = lnwire.NewSigFromSignature(rawSig)
	if err != nil {
		close(cancelChan)
		return sig, htlcSigs, nil, err
	}

	// We'll need to send over the signatures to the remote party in the
	// order as they appear on the commitment transaction after BIP 69
	// sorting.
	sort.Slice(sigBatch, func(i, j int) bool {
		return sigBatch[i].OutputIndex < sigBatch[j].OutputIndex
	})

	// With the jobs sorted, we'll now iterate through all the responses to
	// gather each of the signatures in order.
	htlcSigs = make([]lnwire.Sig, 0, len(sigBatch))
	for _, htlcSigJob := range sigBatch {
		jobResp := <-htlcSigJob.Resp

		// If an error occurred, then we'll cancel any other active
		// jobs.
		if jobResp.Err != nil {
			close(cancelChan)
			return sig, htlcSigs, nil, jobResp.Err
		}

		htlcSigs = append(htlcSigs, jobResp.Sig)
	}

	// As we're about to proposer a new commitment state for the remote
	// party, we'll write this pending state to disk before we exit, so we
	// can retransmit it if necessary.
	commitDiff, err := lc.createCommitDiff(newCommitView, sig, htlcSigs)
	if err != nil {
		return sig, htlcSigs, nil, err
	}
	err = lc.channelState.AppendRemoteCommitChain(commitDiff)
	if err != nil {
		return sig, htlcSigs, nil, err
	}

	// TODO(roasbeef): check that one eclair bug
	//  * need to retransmit on first state still?
	//  * after initial reconnect

	// Extend the remote commitment chain by one with the addition of our
	// latest commitment update.
	lc.remoteCommitChain.addCommitment(newCommitView)

	return sig, htlcSigs, commitDiff.Commitment.Htlcs, nil
}

// ProcessChanSyncMsg processes a ChannelReestablish message sent by the remote
// connection upon re establishment of our connection with them. This method
// will return a single message if we are currently out of sync, otherwise a
// nil lnwire.Message will be returned. If it is decided that our level of
// de-synchronization is irreconcilable, then an error indicating the issue
// will be returned. In this case that an error is returned, the channel should
// be force closed, as we cannot continue updates.
//
// One of two message sets will be returned:
//
//  * CommitSig+Updates: if we have a pending remote commit which they claim to
//    have not received
//  * RevokeAndAck: if we sent a revocation message that they claim to have
//    not received
//
// If we detect a scenario where we need to send a CommitSig+Updates, this
// method also returns two sets channeldb.CircuitKeys identifying the circuits
// that were opened and closed, respectively, as a result of signing the
// previous commitment txn. This allows the link to clear its mailbox of those
// circuits in case they are still in memory, and ensure the switch's circuit
// map has been updated by deleting the closed circuits.
func (lc *LightningChannel) ProcessChanSyncMsg(
	msg *lnwire.ChannelReestablish) ([]lnwire.Message, []channeldb.CircuitKey,
	[]channeldb.CircuitKey, error) {

	// Now we'll examine the state we have, vs what was contained in the
	// chain sync message. If we're de-synchronized, then we'll send a
	// batch of messages which when applied will kick start the chain
	// resync.
	var (
		updates        []lnwire.Message
		openedCircuits []channeldb.CircuitKey
		closedCircuits []channeldb.CircuitKey
	)

	// If the remote party included the optional fields, then we'll verify
	// their correctness first, as it will influence our decisions below.
	hasRecoveryOptions := msg.LocalUnrevokedCommitPoint != nil
	if hasRecoveryOptions && msg.RemoteCommitTailHeight != 0 {
		// We'll check that they've really sent a valid commit
		// secret from our shachain for our prior height, but only if
		// this isn't the first state.
		heightSecret, err := lc.channelState.RevocationProducer.AtIndex(
			msg.RemoteCommitTailHeight - 1,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		commitSecretCorrect := bytes.Equal(
			heightSecret[:], msg.LastRemoteCommitSecret[:],
		)

		// If the commit secret they sent is incorrect then we'll fail
		// the channel as the remote node has an inconsistent state.
		if !commitSecretCorrect {
			// In this case, we'll return an error to indicate the
			// remote node sent us the wrong values. This will let
			// the caller act accordingly.
			lc.log.Errorf("sync failed: remote provided invalid " +
				"commit secret!")
			return nil, nil, nil, ErrInvalidLastCommitSecret
		}
	}

	// If we detect that this is is a restored channel, then we can skip a
	// portion of the verification, as we already know that we're unable to
	// proceed with any updates.
	isRestoredChan := lc.channelState.HasChanStatus(
		channeldb.ChanStatusRestored,
	)

	// Take note of our current commit chain heights before we begin adding
	// more to them.
	var (
		localTailHeight  = lc.localCommitChain.tail().height
		remoteTailHeight = lc.remoteCommitChain.tail().height
		remoteTipHeight  = lc.remoteCommitChain.tip().height
	)

	// We'll now check that their view of our local chain is up-to-date.
	// This means checking that what their view of our local chain tail
	// height is what they believe. Note that the tail and tip height will
	// always be the same for the local chain at this stage, as we won't
	// store any received commitment to disk before it is ACKed.
	switch {

	// If their reported height for our local chain tail is ahead of our
	// view, then we're behind!
	case msg.RemoteCommitTailHeight > localTailHeight || isRestoredChan:
		lc.log.Errorf("sync failed with local data loss: remote "+
			"believes our tail height is %v, while we have %v!",
			msg.RemoteCommitTailHeight, localTailHeight)

		if isRestoredChan {
			lc.log.Warnf("detected restored triggering DLP")
		}

		// We must check that we had recovery options to ensure the
		// commitment secret matched up, and the remote is just not
		// lying about its height.
		if !hasRecoveryOptions {
			// At this point we the remote is either lying about
			// its height, or we are actually behind but the remote
			// doesn't support data loss protection. In either case
			// it is not safe for us to keep using the channel, so
			// we mark it borked and fail the channel.
			lc.log.Errorf("sync failed: local data loss, but no " +
				"recovery option.")

			return nil, nil, nil, ErrCannotSyncCommitChains
		}

		// In this case, we've likely lost data and shouldn't proceed
		// with channel updates.
		return nil, nil, nil, &ErrCommitSyncLocalDataLoss{
			ChannelPoint: lc.channelState.FundingOutpoint,
			CommitPoint:  msg.LocalUnrevokedCommitPoint,
		}

	// If the height of our commitment chain reported by the remote party
	// is behind our view of the chain, then they probably lost some state,
	// and we'll force close the channel.
	case msg.RemoteCommitTailHeight+1 < localTailHeight:
		lc.log.Errorf("sync failed: remote believes our tail height is "+
			"%v, while we have %v!",
			msg.RemoteCommitTailHeight, localTailHeight)
		return nil, nil, nil, ErrCommitSyncRemoteDataLoss

	// Their view of our commit chain is consistent with our view.
	case msg.RemoteCommitTailHeight == localTailHeight:
		// In sync, don't have to do anything.

	// We owe them a revocation if the tail of our current commitment chain
	// is one greater than what they _think_ our commitment tail is. In
	// this case we'll re-send the last revocation message that we sent.
	// This will be the revocation message for our prior chain tail.
	case msg.RemoteCommitTailHeight+1 == localTailHeight:
		lc.log.Debugf("sync: remote believes our tail height is %v, "+
			"while we have %v, we owe them a revocation",
			msg.RemoteCommitTailHeight, localTailHeight)

		revocationMsg, err := lc.generateRevocation(
			localTailHeight - 1,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		updates = append(updates, revocationMsg)

		// Next, as a precaution, we'll check a special edge case. If
		// they initiated a state transition, we sent the revocation,
		// but died before the signature was sent. We re-transmit our
		// revocation, but also initiate a state transition to re-sync
		// them.
		if lc.OweCommitment(true) {
			commitSig, htlcSigs, _, err := lc.SignNextCommitment()
			switch {

			// If we signed this state, then we'll accumulate
			// another update to send over.
			case err == nil:
				updates = append(updates, &lnwire.CommitSig{
					ChanID: lnwire.NewChanIDFromOutPoint(
						&lc.channelState.FundingOutpoint,
					),
					CommitSig: commitSig,
					HtlcSigs:  htlcSigs,
				})

			// If we get a failure due to not knowing their next
			// point, then this is fine as they'll either send
			// FundingLocked, or revoke their next state to allow
			// us to continue forwards.
			case err == ErrNoWindow:

			// Otherwise, this is an error and we'll treat it as
			// such.
			default:
				return nil, nil, nil, err
			}
		}

	// There should be no other possible states.
	default:
		lc.log.Errorf("sync failed: remote believes our tail height is "+
			"%v, while we have %v!",
			msg.RemoteCommitTailHeight, localTailHeight)
		return nil, nil, nil, ErrCannotSyncCommitChains
	}

	// Now check if our view of the remote chain is consistent with what
	// they tell us.
	switch {

	// The remote's view of what their next commit height is 2+ states
	// ahead of us, we most likely lost data, or the remote is trying to
	// trick us. Since we have no way of verifying whether they are lying
	// or not, we will fail the channel, but should not force close it
	// automatically.
	case msg.NextLocalCommitHeight > remoteTipHeight+1:
		lc.log.Errorf("sync failed: remote's next commit height is %v, "+
			"while we believe it is %v!",
			msg.NextLocalCommitHeight, remoteTipHeight)

		return nil, nil, nil, ErrCannotSyncCommitChains

	// They are waiting for a state they have already ACKed.
	case msg.NextLocalCommitHeight <= remoteTailHeight:
		lc.log.Errorf("sync failed: remote's next commit height is %v, "+
			"while we believe it is %v!",
			msg.NextLocalCommitHeight, remoteTipHeight)

		// They previously ACKed our current tail, and now they are
		// waiting for it. They probably lost state.
		return nil, nil, nil, ErrCommitSyncRemoteDataLoss

	// They have received our latest commitment, life is good.
	case msg.NextLocalCommitHeight == remoteTipHeight+1:

	// We owe them a commitment if the tip of their chain (from our Pov) is
	// equal to what they think their next commit height should be. We'll
	// re-send all the updates necessary to recreate this state, along
	// with the commit sig.
	case msg.NextLocalCommitHeight == remoteTipHeight:
		lc.log.Debugf("sync: remote's next commit height is %v, while "+
			"we believe it is %v, we owe them a commitment",
			msg.NextLocalCommitHeight, remoteTipHeight)

		// Grab the current remote chain tip from the database.  This
		// commit diff contains all the information required to re-sync
		// our states.
		commitDiff, err := lc.channelState.RemoteCommitChainTip()
		if err != nil {
			return nil, nil, nil, err
		}

		var commitUpdates []lnwire.Message

		// Next, we'll need to send over any updates we sent as part of
		// this new proposed commitment state.
		for _, logUpdate := range commitDiff.LogUpdates {
			commitUpdates = append(commitUpdates, logUpdate.UpdateMsg)
		}

		// With the batch of updates accumulated, we'll now re-send the
		// original CommitSig message required to re-sync their remote
		// commitment chain with our local version of their chain.
		commitUpdates = append(commitUpdates, commitDiff.CommitSig)

		// NOTE: If a revocation is not owed, then updates is empty.
		if lc.channelState.LastWasRevoke {
			// If lastWasRevoke is set to true, a revocation was last and we
			// need to reorder the updates so that the revocation stored in
			// updates comes after the LogUpdates+CommitSig.
			//
			// ---logupdates--->
			// ---commitsig---->
			// ---revocation--->
			updates = append(commitUpdates, updates...)
		} else {
			// Otherwise, the revocation should come before LogUpdates
			// + CommitSig.
			//
			// ---revocation--->
			// ---logupdates--->
			// ---commitsig---->
			updates = append(updates, commitUpdates...)
		}

		openedCircuits = commitDiff.OpenedCircuitKeys
		closedCircuits = commitDiff.ClosedCircuitKeys

	// There should be no other possible states as long as the commit chain
	// can have at most two elements. If that's the case, something is
	// wrong.
	default:
		lc.log.Errorf("sync failed: remote's next commit height is %v, "+
			"while we believe it is %v!",
			msg.NextLocalCommitHeight, remoteTipHeight)
		return nil, nil, nil, ErrCannotSyncCommitChains
	}

	// If we didn't have recovery options, then the final check cannot be
	// performed, and we'll return early.
	if !hasRecoveryOptions {
		return updates, openedCircuits, closedCircuits, nil
	}

	// At this point we have determined that either the commit heights are
	// in sync, or that we are in a state we can recover from. As a final
	// check, we ensure that the commitment point sent to us by the remote
	// is valid.
	var commitPoint *btcec.PublicKey
	switch {
	// If their height is one beyond what we know their current height to
	// be, then we need to compare their current unrevoked commitment point
	// as that's what they should send.
	case msg.NextLocalCommitHeight == remoteTailHeight+1:
		commitPoint = lc.channelState.RemoteCurrentRevocation

	// Alternatively, if their height is two beyond what we know their best
	// height to be, then they're holding onto two commitments, and the
	// highest unrevoked point is their next revocation.
	//
	// TODO(roasbeef): verify this in the spec...
	case msg.NextLocalCommitHeight == remoteTailHeight+2:
		commitPoint = lc.channelState.RemoteNextRevocation
	}

	// Only if this is a tweakless channel will we attempt to verify the
	// commitment point, as otherwise it has no validity requirements.
	tweakless := lc.channelState.ChanType.IsTweakless()
	if !tweakless && commitPoint != nil &&
		!commitPoint.IsEqual(msg.LocalUnrevokedCommitPoint) {

		lc.log.Errorf("sync failed: remote sent invalid commit point "+
			"for height %v!",
			msg.NextLocalCommitHeight)
		return nil, nil, nil, ErrInvalidLocalUnrevokedCommitPoint
	}

	return updates, openedCircuits, closedCircuits, nil
}

// computeView takes the given htlcView, and calculates the balances, filtered
// view (settling unsettled HTLCs), commitment weight and feePerKw, after
// applying the HTLCs to the latest commitment. The returned balances are the
// balances *before* subtracting the commitment fee from the initiator's
// balance.
//
// If the updateState boolean is set true, the add and remove heights of the
// HTLCs will be set to the next commitment height.
func (lc *LightningChannel) computeView(view *htlcView, remoteChain bool,
	updateState bool) (lnwire.MilliSatoshi, lnwire.MilliSatoshi, int64,
	*htlcView, error) {

	commitChain := lc.localCommitChain
	dustLimit := lc.channelState.LocalChanCfg.DustLimit
	if remoteChain {
		commitChain = lc.remoteCommitChain
		dustLimit = lc.channelState.RemoteChanCfg.DustLimit
	}

	// Since the fetched htlc view will include all updates added after the
	// last committed state, we start with the balances reflecting that
	// state.
	ourBalance := commitChain.tip().ourBalance
	theirBalance := commitChain.tip().theirBalance

	// Add the fee from the previous commitment state back to the
	// initiator's balance, so that the fee can be recalculated and
	// re-applied in case fee estimation parameters have changed or the
	// number of outstanding HTLCs has changed.
	if lc.channelState.IsInitiator {
		ourBalance += lnwire.NewMSatFromSatoshis(
			commitChain.tip().fee)
	} else if !lc.channelState.IsInitiator {
		theirBalance += lnwire.NewMSatFromSatoshis(
			commitChain.tip().fee)
	}
	nextHeight := commitChain.tip().height + 1

	// Initiate feePerKw to the last committed fee for this chain as we'll
	// need this to determine which HTLCs are dust, and also the final fee
	// rate.
	view.feePerKw = commitChain.tip().feePerKw

	// We evaluate the view at this stage, meaning settled and failed HTLCs
	// will remove their corresponding added HTLCs.  The resulting filtered
	// view will only have Add entries left, making it easy to compare the
	// channel constraints to the final commitment state. If any fee
	// updates are found in the logs, the commitment fee rate should be
	// changed, so we'll also set the feePerKw to this new value.
	filteredHTLCView, err := lc.evaluateHTLCView(view, &ourBalance,
		&theirBalance, nextHeight, remoteChain, updateState)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	feePerKw := filteredHTLCView.feePerKw

	// Now go through all HTLCs at this stage, to calculate the total
	// weight, needed to calculate the transaction fee.
	var totalHtlcWeight int64
	for _, htlc := range filteredHTLCView.ourUpdates {
		if htlcIsDust(
			lc.channelState.ChanType, false, !remoteChain,
			feePerKw, htlc.Amount.ToSatoshis(), dustLimit,
		) {
			continue
		}

		totalHtlcWeight += input.HTLCWeight
	}
	for _, htlc := range filteredHTLCView.theirUpdates {
		if htlcIsDust(
			lc.channelState.ChanType, true, !remoteChain,
			feePerKw, htlc.Amount.ToSatoshis(), dustLimit,
		) {
			continue
		}

		totalHtlcWeight += input.HTLCWeight
	}

	totalCommitWeight := CommitWeight(lc.channelState.ChanType) +
		totalHtlcWeight
	return ourBalance, theirBalance, totalCommitWeight, filteredHTLCView, nil
}

// genHtlcSigValidationJobs generates a series of signatures verification jobs
// meant to verify all the signatures for HTLC's attached to a newly created
// commitment state. The jobs generated are fully populated, and can be sent
// directly into the pool of workers.
func genHtlcSigValidationJobs(localCommitmentView *commitment,
	keyRing *CommitmentKeyRing, htlcSigs []lnwire.Sig,
	chanType channeldb.ChannelType,
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig) ([]VerifyJob, error) {

	txHash := localCommitmentView.txn.TxHash()
	feePerKw := localCommitmentView.feePerKw
	sigHashType := HtlcSigHashType(chanType)

	// With the required state generated, we'll create a slice with large
	// enough capacity to hold verification jobs for all HTLC's in this
	// view. In the case that we have some dust outputs, then the actual
	// length will be smaller than the total capacity.
	numHtlcs := (len(localCommitmentView.incomingHTLCs) +
		len(localCommitmentView.outgoingHTLCs))
	verifyJobs := make([]VerifyJob, 0, numHtlcs)

	// We'll iterate through each output in the commitment transaction,
	// populating the sigHash closure function if it's detected to be an
	// HLTC output. Given the sighash, and the signing key, we'll be able
	// to validate each signature within the worker pool.
	i := 0
	for index := range localCommitmentView.txn.TxOut {
		var (
			htlcIndex uint64
			sigHash   func() ([]byte, error)
			sig       *btcec.Signature
			err       error
		)

		outputIndex := int32(index)
		switch {

		// If this output index is found within the incoming HTLC
		// index, then this means that we need to generate an HTLC
		// success transaction in order to validate the signature.
		case localCommitmentView.incomingHTLCIndex[outputIndex] != nil:
			htlc := localCommitmentView.incomingHTLCIndex[outputIndex]

			htlcIndex = htlc.HtlcIndex

			sigHash = func() ([]byte, error) {
				op := wire.OutPoint{
					Hash:  txHash,
					Index: uint32(htlc.localOutputIndex),
				}

				htlcFee := HtlcSuccessFee(chanType, feePerKw)
				outputAmt := htlc.Amount.ToSatoshis() - htlcFee

				successTx, err := CreateHtlcSuccessTx(
					chanType, op, outputAmt,
					uint32(localChanCfg.CsvDelay),
					keyRing.RevocationKey, keyRing.ToLocalKey,
				)
				if err != nil {
					return nil, err
				}

				hashCache := txscript.NewTxSigHashes(successTx)
				sigHash, err := txscript.CalcWitnessSigHash(
					htlc.ourWitnessScript, hashCache,
					sigHashType, successTx, 0,
					int64(htlc.Amount.ToSatoshis()),
				)
				if err != nil {
					return nil, err
				}

				return sigHash, nil
			}

			// Make sure there are more signatures left.
			if i >= len(htlcSigs) {
				return nil, fmt.Errorf("not enough HTLC " +
					"signatures")
			}

			// With the sighash generated, we'll also store the
			// signature so it can be written to disk if this state
			// is valid.
			sig, err = htlcSigs[i].ToSignature()
			if err != nil {
				return nil, err
			}
			htlc.sig = sig

		// Otherwise, if this is an outgoing HTLC, then we'll need to
		// generate a timeout transaction so we can verify the
		// signature presented.
		case localCommitmentView.outgoingHTLCIndex[outputIndex] != nil:
			htlc := localCommitmentView.outgoingHTLCIndex[outputIndex]

			htlcIndex = htlc.HtlcIndex

			sigHash = func() ([]byte, error) {
				op := wire.OutPoint{
					Hash:  txHash,
					Index: uint32(htlc.localOutputIndex),
				}

				htlcFee := HtlcTimeoutFee(chanType, feePerKw)
				outputAmt := htlc.Amount.ToSatoshis() - htlcFee

				timeoutTx, err := CreateHtlcTimeoutTx(
					chanType, op, outputAmt, htlc.Timeout,
					uint32(localChanCfg.CsvDelay),
					keyRing.RevocationKey, keyRing.ToLocalKey,
				)
				if err != nil {
					return nil, err
				}

				hashCache := txscript.NewTxSigHashes(timeoutTx)
				sigHash, err := txscript.CalcWitnessSigHash(
					htlc.ourWitnessScript, hashCache,
					sigHashType, timeoutTx, 0,
					int64(htlc.Amount.ToSatoshis()),
				)
				if err != nil {
					return nil, err
				}

				return sigHash, nil
			}

			// Make sure there are more signatures left.
			if i >= len(htlcSigs) {
				return nil, fmt.Errorf("not enough HTLC " +
					"signatures")
			}

			// With the sighash generated, we'll also store the
			// signature so it can be written to disk if this state
			// is valid.
			sig, err = htlcSigs[i].ToSignature()
			if err != nil {
				return nil, err
			}
			htlc.sig = sig

		default:
			continue
		}

		verifyJobs = append(verifyJobs, VerifyJob{
			HtlcIndex: htlcIndex,
			PubKey:    keyRing.RemoteHtlcKey,
			Sig:       sig,
			SigHash:   sigHash,
		})

		i++
	}

	// If we received a number of HTLC signatures that doesn't match our
	// commitment, we'll return an error now.
	if len(htlcSigs) != i {
		return nil, fmt.Errorf("number of htlc sig mismatch. "+
			"Expected %v sigs, got %v", i, len(htlcSigs))
	}

	return verifyJobs, nil
}

// InvalidCommitSigError is a struct that implements the error interface to
// report a failure to validate a commitment signature for a remote peer.
// We'll use the items in this struct to generate a rich error message for the
// remote peer when we receive an invalid signature from it. Doing so can
// greatly aide in debugging cross implementation issues.
type InvalidCommitSigError struct {
	commitHeight uint64

	commitSig []byte

	sigHash []byte

	commitTx []byte
}

// Error returns a detailed error string including the exact transaction that
// caused an invalid commitment signature.
func (i *InvalidCommitSigError) Error() string {
	return fmt.Sprintf("rejected commitment: commit_height=%v, "+
		"invalid_commit_sig=%x, commit_tx=%x, sig_hash=%x", i.commitHeight,
		i.commitSig[:], i.commitTx, i.sigHash[:])
}

// A compile time flag to ensure that InvalidCommitSigError implements the
// error interface.
var _ error = (*InvalidCommitSigError)(nil)

// InvalidHtlcSigError is a struct that implements the error interface to
// report a failure to validate an htlc signature from a remote peer. We'll use
// the items in this struct to generate a rich error message for the remote
// peer when we receive an invalid signature from it. Doing so can greatly aide
// in debugging across implementation issues.
type InvalidHtlcSigError struct {
	commitHeight uint64

	htlcSig []byte

	htlcIndex uint64

	sigHash []byte

	commitTx []byte
}

// Error returns a detailed error string including the exact transaction that
// caused an invalid htlc signature.
func (i *InvalidHtlcSigError) Error() string {
	return fmt.Sprintf("rejected commitment: commit_height=%v, "+
		"invalid_htlc_sig=%x, commit_tx=%x, sig_hash=%x", i.commitHeight,
		i.htlcSig, i.commitTx, i.sigHash[:])
}

// A compile time flag to ensure that InvalidCommitSigError implements the
// error interface.
var _ error = (*InvalidCommitSigError)(nil)

// ReceiveNewCommitment process a signature for a new commitment state sent by
// the remote party. This method should be called in response to the
// remote party initiating a new change, or when the remote party sends a
// signature fully accepting a new state we've initiated. If we are able to
// successfully validate the signature, then the generated commitment is added
// to our local commitment chain. Once we send a revocation for our prior
// state, then this newly added commitment becomes our current accepted channel
// state.
func (lc *LightningChannel) ReceiveNewCommitment(commitSig lnwire.Sig,
	htlcSigs []lnwire.Sig) error {

	lc.Lock()
	defer lc.Unlock()

	// Check for empty commit sig. Because of a previously existing bug, it
	// is possible that we receive an empty commit sig from nodes running an
	// older version. This is a relaxation of the spec, but it is still
	// possible to handle it. To not break any channels with those older
	// nodes, we just log the event. This check is also not totally
	// reliable, because it could be that we've sent out a new sig, but the
	// remote hasn't received it yet. We could then falsely assume that they
	// should add our updates to their remote commitment tx.
	if !lc.oweCommitment(false) {
		lc.log.Warnf("empty commit sig message received")
	}

	// Determine the last update on the local log that has been locked in.
	localACKedIndex := lc.remoteCommitChain.tail().ourMessageIndex
	localHtlcIndex := lc.remoteCommitChain.tail().ourHtlcIndex

	// Ensure that this new local update from the remote node respects all
	// the constraints we specified during initial channel setup. If not,
	// then we'll abort the channel as they've violated our constraints.
	err := lc.validateCommitmentSanity(
		lc.remoteUpdateLog.logIndex, localACKedIndex, false, nil, nil,
	)
	if err != nil {
		return err
	}

	// We're receiving a new commitment which attempts to extend our local
	// commitment chain height by one, so fetch the proper commitment point
	// as this will be needed to derive the keys required to construct the
	// commitment.
	nextHeight := lc.currentHeight + 1
	commitSecret, err := lc.channelState.RevocationProducer.AtIndex(nextHeight)
	if err != nil {
		return err
	}
	commitPoint := input.ComputeCommitmentPoint(commitSecret[:])
	keyRing := DeriveCommitmentKeys(
		commitPoint, true, lc.channelState.ChanType,
		&lc.channelState.LocalChanCfg, &lc.channelState.RemoteChanCfg,
	)

	// With the current commitment point re-calculated, construct the new
	// commitment view which includes all the entries (pending or committed)
	// we know of in the remote node's HTLC log, but only our local changes
	// up to the last change the remote node has ACK'd.
	localCommitmentView, err := lc.fetchCommitmentView(
		false, localACKedIndex, localHtlcIndex,
		lc.remoteUpdateLog.logIndex, lc.remoteUpdateLog.htlcCounter,
		keyRing,
	)
	if err != nil {
		return err
	}

	lc.log.Tracef("extending local chain to height %v, "+
		"local_log=%v, remote_log=%v",
		localCommitmentView.height,
		localACKedIndex, lc.remoteUpdateLog.logIndex)

	lc.log.Tracef("local chain: our_balance=%v, "+
		"their_balance=%v, commit_tx: %v",
		localCommitmentView.ourBalance, localCommitmentView.theirBalance,
		newLogClosure(func() string {
			return spew.Sdump(localCommitmentView.txn)
		}),
	)

	// Construct the sighash of the commitment transaction corresponding to
	// this newly proposed state update.
	localCommitTx := localCommitmentView.txn
	multiSigScript := lc.signDesc.WitnessScript
	hashCache := txscript.NewTxSigHashes(localCommitTx)
	sigHash, err := txscript.CalcWitnessSigHash(
		multiSigScript, hashCache, txscript.SigHashAll,
		localCommitTx, 0, int64(lc.channelState.Capacity),
	)
	if err != nil {
		// TODO(roasbeef): fetchview has already mutated the HTLCs...
		//  * need to either roll-back, or make pure
		return err
	}

	// As an optimization, we'll generate a series of jobs for the worker
	// pool to verify each of the HTLc signatures presented. Once
	// generated, we'll submit these jobs to the worker pool.
	verifyJobs, err := genHtlcSigValidationJobs(
		localCommitmentView, keyRing, htlcSigs,
		lc.channelState.ChanType, &lc.channelState.LocalChanCfg,
		&lc.channelState.RemoteChanCfg,
	)
	if err != nil {
		return err
	}

	cancelChan := make(chan struct{})
	verifyResps := lc.sigPool.SubmitVerifyBatch(verifyJobs, cancelChan)

	// While the HTLC verification jobs are proceeding asynchronously,
	// we'll ensure that the newly constructed commitment state has a valid
	// signature.
	verifyKey := btcec.PublicKey{
		X:     lc.channelState.RemoteChanCfg.MultiSigKey.PubKey.X,
		Y:     lc.channelState.RemoteChanCfg.MultiSigKey.PubKey.Y,
		Curve: btcec.S256(),
	}
	cSig, err := commitSig.ToSignature()
	if err != nil {
		return err
	}
	if !cSig.Verify(sigHash, &verifyKey) {
		close(cancelChan)

		// If we fail to validate their commitment signature, we'll
		// generate a special error to send over the protocol. We'll
		// include the exact signature and commitment we failed to
		// verify against in order to aide debugging.
		var txBytes bytes.Buffer
		localCommitTx.Serialize(&txBytes)
		return &InvalidCommitSigError{
			commitHeight: nextHeight,
			commitSig:    commitSig.ToSignatureBytes(),
			sigHash:      sigHash,
			commitTx:     txBytes.Bytes(),
		}
	}

	// With the primary commitment transaction validated, we'll check each
	// of the HTLC validation jobs.
	for i := 0; i < len(verifyJobs); i++ {
		// In the case that a single signature is invalid, we'll exit
		// early and cancel all the outstanding verification jobs.
		htlcErr := <-verifyResps
		if htlcErr != nil {
			close(cancelChan)

			sig, err := lnwire.NewSigFromSignature(
				htlcErr.Sig,
			)
			if err != nil {
				return err
			}
			sigHash, err := htlcErr.SigHash()
			if err != nil {
				return err
			}

			var txBytes bytes.Buffer
			localCommitTx.Serialize(&txBytes)
			return &InvalidHtlcSigError{
				commitHeight: nextHeight,
				htlcSig:      sig.ToSignatureBytes(),
				htlcIndex:    htlcErr.HtlcIndex,
				sigHash:      sigHash,
				commitTx:     txBytes.Bytes(),
			}
		}
	}

	// The signature checks out, so we can now add the new commitment to
	// our local commitment chain.
	localCommitmentView.sig = commitSig.ToSignatureBytes()
	lc.localCommitChain.addCommitment(localCommitmentView)

	return nil
}

// OweCommitment returns a boolean value reflecting whether we need to send
// out a commitment signature because there are outstanding local updates and/or
// updates in the local commit tx that aren't reflected in the remote commit tx
// yet.
func (lc *LightningChannel) OweCommitment(local bool) bool {
	lc.RLock()
	defer lc.RUnlock()

	return lc.oweCommitment(local)
}

// oweCommitment is the internal version of OweCommitment. This function expects
// to be executed with a lock held.
func (lc *LightningChannel) oweCommitment(local bool) bool {
	var (
		remoteUpdatesPending, localUpdatesPending bool

		lastLocalCommit  = lc.localCommitChain.tip()
		lastRemoteCommit = lc.remoteCommitChain.tip()

		perspective string
	)

	if local {
		perspective = "local"

		// There are local updates pending if our local update log is
		// not in sync with our remote commitment tx.
		localUpdatesPending = lc.localUpdateLog.logIndex !=
			lastRemoteCommit.ourMessageIndex

		// There are remote updates pending if their remote commitment
		// tx (our local commitment tx) contains updates that we don't
		// have added to our remote commitment tx yet.
		remoteUpdatesPending = lastLocalCommit.theirMessageIndex !=
			lastRemoteCommit.theirMessageIndex

	} else {
		perspective = "remote"

		// There are local updates pending (local updates from the
		// perspective of the remote party) if the remote party has
		// updates to their remote tx pending for which they haven't
		// signed yet.
		localUpdatesPending = lc.remoteUpdateLog.logIndex !=
			lastLocalCommit.theirMessageIndex

		// There are remote updates pending (remote updates from the
		// perspective of the remote party) if we have updates on our
		// remote commitment tx that they haven't added to theirs yet.
		remoteUpdatesPending = lastRemoteCommit.ourMessageIndex !=
			lastLocalCommit.ourMessageIndex
	}

	// If any of the conditions above is true, we owe a commitment
	// signature.
	oweCommitment := localUpdatesPending || remoteUpdatesPending

	lc.log.Tracef("%v owes commit: %v (local updates: %v, "+
		"remote updates %v)", perspective, oweCommitment,
		localUpdatesPending, remoteUpdatesPending)

	return oweCommitment
}

// PendingLocalUpdateCount returns the number of local updates that still need
// to be applied to the remote commitment tx.
func (lc *LightningChannel) PendingLocalUpdateCount() uint64 {
	lc.RLock()
	defer lc.RUnlock()

	lastRemoteCommit := lc.remoteCommitChain.tip()

	return lc.localUpdateLog.logIndex - lastRemoteCommit.ourMessageIndex
}

// RevokeCurrentCommitment revokes the next lowest unrevoked commitment
// transaction in the local commitment chain. As a result the edge of our
// revocation window is extended by one, and the tail of our local commitment
// chain is advanced by a single commitment. This now lowest unrevoked
// commitment becomes our currently accepted state within the channel. This
// method also returns the set of HTLC's currently active within the commitment
// transaction. This return value allows callers to act once an HTLC has been
// locked into our commitment transaction.
func (lc *LightningChannel) RevokeCurrentCommitment() (*lnwire.RevokeAndAck, []channeldb.HTLC, error) {
	lc.Lock()
	defer lc.Unlock()

	revocationMsg, err := lc.generateRevocation(lc.currentHeight)
	if err != nil {
		return nil, nil, err
	}

	lc.log.Tracef("revoking height=%v, now at height=%v",
		lc.localCommitChain.tail().height,
		lc.currentHeight+1)

	// Advance our tail, as we've revoked our previous state.
	lc.localCommitChain.advanceTail()
	lc.currentHeight++

	// Additionally, generate a channel delta for this state transition for
	// persistent storage.
	chainTail := lc.localCommitChain.tail()
	newCommitment := chainTail.toDiskCommit(true)

	// Get the unsigned acked remotes updates that are currently in memory.
	// We need them after a restart to sync our remote commitment with what
	// is committed locally.
	unsignedAckedUpdates := lc.getUnsignedAckedUpdates()

	err = lc.channelState.UpdateCommitment(
		newCommitment, unsignedAckedUpdates,
	)
	if err != nil {
		return nil, nil, err
	}

	lc.log.Tracef("state transition accepted: "+
		"our_balance=%v, their_balance=%v, unsigned_acked_updates=%v",
		chainTail.ourBalance,
		chainTail.theirBalance,
		len(unsignedAckedUpdates))

	revocationMsg.ChanID = lnwire.NewChanIDFromOutPoint(
		&lc.channelState.FundingOutpoint,
	)

	return revocationMsg, newCommitment.Htlcs, nil
}

// ReceiveRevocation processes a revocation sent by the remote party for the
// lowest unrevoked commitment within their commitment chain. We receive a
// revocation either during the initial session negotiation wherein revocation
// windows are extended, or in response to a state update that we initiate. If
// successful, then the remote commitment chain is advanced by a single
// commitment, and a log compaction is attempted.
//
// The returned values correspond to:
//   1. The forwarding package corresponding to the remote commitment height
//      that was revoked.
//   2. The PaymentDescriptor of any Add HTLCs that were locked in by this
//      revocation.
//   3. The PaymentDescriptor of any Settle/Fail HTLCs that were locked in by
//      this revocation.
//   4. The set of HTLCs present on the current valid commitment transaction
//      for the remote party.
func (lc *LightningChannel) ReceiveRevocation(revMsg *lnwire.RevokeAndAck) (
	*channeldb.FwdPkg, []*PaymentDescriptor, []*PaymentDescriptor,
	[]channeldb.HTLC, error) {

	lc.Lock()
	defer lc.Unlock()

	// Ensure that the new pre-image can be placed in preimage store.
	store := lc.channelState.RevocationStore
	revocation, err := chainhash.NewHash(revMsg.Revocation[:])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := store.AddNextEntry(revocation); err != nil {
		return nil, nil, nil, nil, err
	}

	// Verify that if we use the commitment point computed based off of the
	// revealed secret to derive a revocation key with our revocation base
	// point, then it matches the current revocation of the remote party.
	currentCommitPoint := lc.channelState.RemoteCurrentRevocation
	derivedCommitPoint := input.ComputeCommitmentPoint(revMsg.Revocation[:])
	if !derivedCommitPoint.IsEqual(currentCommitPoint) {
		return nil, nil, nil, nil, fmt.Errorf("revocation key mismatch")
	}

	// Now that we've verified that the prior commitment has been properly
	// revoked, we'll advance the revocation state we track for the remote
	// party: the new current revocation is what was previously the next
	// revocation, and the new next revocation is set to the key included
	// in the message.
	lc.channelState.RemoteCurrentRevocation = lc.channelState.RemoteNextRevocation
	lc.channelState.RemoteNextRevocation = revMsg.NextRevocationKey

	lc.log.Tracef("remote party accepted state transition, revoked height "+
		"%v, now at %v",
		lc.remoteCommitChain.tail().height,
		lc.remoteCommitChain.tail().height+1)

	// Add one to the remote tail since this will be height *after* we write
	// the revocation to disk, the local height will remain unchanged.
	remoteChainTail := lc.remoteCommitChain.tail().height + 1
	localChainTail := lc.localCommitChain.tail().height

	source := lc.ShortChanID()
	chanID := lnwire.NewChanIDFromOutPoint(&lc.channelState.FundingOutpoint)

	// Determine the set of htlcs that can be forwarded as a result of
	// having received the revocation. We will simultaneously construct the
	// log updates and payment descriptors, allowing us to persist the log
	// updates to disk and optimistically buffer the forwarding package in
	// memory.
	var (
		addsToForward        []*PaymentDescriptor
		addUpdates           []channeldb.LogUpdate
		settleFailsToForward []*PaymentDescriptor
		settleFailUpdates    []channeldb.LogUpdate
	)

	var addIndex, settleFailIndex uint16
	for e := lc.remoteUpdateLog.Front(); e != nil; e = e.Next() {
		pd := e.Value.(*PaymentDescriptor)

		// Fee updates are local to this particular channel, and should
		// never be forwarded.
		if pd.EntryType == FeeUpdate {
			continue
		}

		if pd.isForwarded {
			continue
		}

		// For each type of HTLC, we will only consider forwarding it if
		// both of the remote and local heights are non-zero. If either
		// of these values is zero, it has yet to be committed in both
		// the local and remote chains.
		committedAdd := pd.addCommitHeightRemote > 0 &&
			pd.addCommitHeightLocal > 0
		committedRmv := pd.removeCommitHeightRemote > 0 &&
			pd.removeCommitHeightLocal > 0

		// Using the height of the remote and local commitments,
		// preemptively compute whether or not to forward this HTLC for
		// the case in which this in an Add HTLC, or if this is a
		// Settle, Fail, or MalformedFail.
		shouldFwdAdd := remoteChainTail == pd.addCommitHeightRemote &&
			localChainTail >= pd.addCommitHeightLocal
		shouldFwdRmv := remoteChainTail == pd.removeCommitHeightRemote &&
			localChainTail >= pd.removeCommitHeightLocal

		// We'll only forward any new HTLC additions iff, it's "freshly
		// locked in". Meaning that the HTLC was only *just* considered
		// locked-in at this new state. By doing this we ensure that we
		// don't re-forward any already processed HTLC's after a
		// restart.
		switch {
		case pd.EntryType == Add && committedAdd && shouldFwdAdd:
			// Construct a reference specifying the location that
			// this forwarded Add will be written in the forwarding
			// package constructed at this remote height.
			pd.SourceRef = &channeldb.AddRef{
				Height: remoteChainTail,
				Index:  addIndex,
			}
			addIndex++

			pd.isForwarded = true
			addsToForward = append(addsToForward, pd)

		case pd.EntryType != Add && committedRmv && shouldFwdRmv:
			// Construct a reference specifying the location that
			// this forwarded Settle/Fail will be written in the
			// forwarding package constructed at this remote height.
			pd.DestRef = &channeldb.SettleFailRef{
				Source: source,
				Height: remoteChainTail,
				Index:  settleFailIndex,
			}
			settleFailIndex++

			pd.isForwarded = true
			settleFailsToForward = append(settleFailsToForward, pd)

		default:
			continue
		}

		// If we've reached this point, this HTLC will be added to the
		// forwarding package at the height of the remote commitment.
		// All types of HTLCs will record their assigned log index.
		logUpdate := channeldb.LogUpdate{
			LogIndex: pd.LogIndex,
		}

		// Next, we'll map the type of the PaymentDescriptor to one of
		// the four messages that it corresponds to and separate the
		// updates into Adds and Settle/Fail/MalformedFail such that
		// they can be written in the forwarding package. Adds are
		// aggregated separately from the other types of HTLCs.
		switch pd.EntryType {
		case Add:
			htlc := &lnwire.UpdateAddHTLC{
				ChanID:      chanID,
				ID:          pd.HtlcIndex,
				Amount:      pd.Amount,
				Expiry:      pd.Timeout,
				PaymentHash: pd.RHash,
			}
			copy(htlc.OnionBlob[:], pd.OnionBlob)
			logUpdate.UpdateMsg = htlc
			addUpdates = append(addUpdates, logUpdate)

		case Settle:
			logUpdate.UpdateMsg = &lnwire.UpdateFulfillHTLC{
				ChanID:          chanID,
				ID:              pd.ParentIndex,
				PaymentPreimage: pd.RPreimage,
			}
			settleFailUpdates = append(settleFailUpdates, logUpdate)

		case Fail:
			logUpdate.UpdateMsg = &lnwire.UpdateFailHTLC{
				ChanID: chanID,
				ID:     pd.ParentIndex,
				Reason: pd.FailReason,
			}
			settleFailUpdates = append(settleFailUpdates, logUpdate)

		case MalformedFail:
			logUpdate.UpdateMsg = &lnwire.UpdateFailMalformedHTLC{
				ChanID:       chanID,
				ID:           pd.ParentIndex,
				ShaOnionBlob: pd.ShaOnionBlob,
				FailureCode:  pd.FailCode,
			}
			settleFailUpdates = append(settleFailUpdates, logUpdate)
		}
	}

	// We use the remote commitment chain's tip as it will soon become the tail
	// once advanceTail is called.
	remoteMessageIndex := lc.remoteCommitChain.tip().ourMessageIndex
	localMessageIndex := lc.localCommitChain.tail().ourMessageIndex

	localPeerUpdates := lc.unsignedLocalUpdates(
		remoteMessageIndex, localMessageIndex, chanID,
	)

	// Now that we have gathered the set of HTLCs to forward, separated by
	// type, construct a forwarding package using the height that the remote
	// commitment chain will be extended after persisting the revocation.
	fwdPkg := channeldb.NewFwdPkg(
		source, remoteChainTail, addUpdates, settleFailUpdates,
	)

	// At this point, the revocation has been accepted, and we've rotated
	// the current revocation key+hash for the remote party. Therefore we
	// sync now to ensure the revocation producer state is consistent with
	// the current commitment height and also to advance the on-disk
	// commitment chain.
	err = lc.channelState.AdvanceCommitChainTail(fwdPkg, localPeerUpdates)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Since they revoked the current lowest height in their commitment
	// chain, we can advance their chain by a single commitment.
	lc.remoteCommitChain.advanceTail()

	// As we've just completed a new state transition, attempt to see if we
	// can remove any entries from the update log which have been removed
	// from the PoV of both commitment chains.
	compactLogs(
		lc.localUpdateLog, lc.remoteUpdateLog, localChainTail,
		remoteChainTail,
	)

	remoteHTLCs := lc.channelState.RemoteCommitment.Htlcs

	return fwdPkg, addsToForward, settleFailsToForward, remoteHTLCs, nil
}

// LoadFwdPkgs loads any pending log updates from disk and returns the payment
// descriptors to be processed by the link.
func (lc *LightningChannel) LoadFwdPkgs() ([]*channeldb.FwdPkg, error) {
	return lc.channelState.LoadFwdPkgs()
}

// AckAddHtlcs sets a bit in the FwdFilter of a forwarding package belonging to
// this channel, that corresponds to the given AddRef. This method also succeeds
// if no forwarding package is found.
func (lc *LightningChannel) AckAddHtlcs(addRef channeldb.AddRef) error {
	return lc.channelState.AckAddHtlcs(addRef)
}

// AckSettleFails sets a bit in the SettleFailFilter of a forwarding package
// belonging to this channel, that corresponds to the given SettleFailRef. This
// method also succeeds if no forwarding package is found.
func (lc *LightningChannel) AckSettleFails(
	settleFailRefs ...channeldb.SettleFailRef) error {

	return lc.channelState.AckSettleFails(settleFailRefs...)
}

// SetFwdFilter writes the forwarding decision for a given remote commitment
// height.
func (lc *LightningChannel) SetFwdFilter(height uint64,
	fwdFilter *channeldb.PkgFilter) error {

	return lc.channelState.SetFwdFilter(height, fwdFilter)
}

// RemoveFwdPkgs permanently deletes the forwarding package at the given heights.
func (lc *LightningChannel) RemoveFwdPkgs(heights ...uint64) error {
	return lc.channelState.RemoveFwdPkgs(heights...)
}

// NextRevocationKey returns the commitment point for the _next_ commitment
// height. The pubkey returned by this function is required by the remote party
// along with their revocation base to extend our commitment chain with a
// new commitment.
func (lc *LightningChannel) NextRevocationKey() (*btcec.PublicKey, error) {
	lc.RLock()
	defer lc.RUnlock()

	nextHeight := lc.currentHeight + 1
	revocation, err := lc.channelState.RevocationProducer.AtIndex(nextHeight)
	if err != nil {
		return nil, err
	}

	return input.ComputeCommitmentPoint(revocation[:]), nil
}

// InitNextRevocation inserts the passed commitment point as the _next_
// revocation to be used when creating a new commitment state for the remote
// party. This function MUST be called before the channel can accept or propose
// any new states.
func (lc *LightningChannel) InitNextRevocation(revKey *btcec.PublicKey) error {
	lc.Lock()
	defer lc.Unlock()

	return lc.channelState.InsertNextRevocation(revKey)
}

// AddHTLC adds an HTLC to the state machine's local update log. This method
// should be called when preparing to send an outgoing HTLC.
//
// The additional openKey argument corresponds to the incoming CircuitKey of the
// committed circuit for this HTLC. This value should never be nil.
//
// Note that AddHTLC doesn't reserve the HTLC fee for future payment (like
// AvailableBalance does), so one could get into the "stuck channel" state by
// sending dust HTLCs.
// TODO(halseth): fix this either by using additional reserve, or better commit
// format. See https://github.com/lightningnetwork/lightning-rfc/issues/728
//
// NOTE: It is okay for sourceRef to be nil when unit testing the wallet.
func (lc *LightningChannel) AddHTLC(htlc *lnwire.UpdateAddHTLC,
	openKey *channeldb.CircuitKey) (uint64, error) {

	lc.Lock()
	defer lc.Unlock()

	pd := lc.htlcAddDescriptor(htlc, openKey)
	if err := lc.validateAddHtlc(pd); err != nil {
		return 0, err
	}

	lc.localUpdateLog.appendHtlc(pd)

	return pd.HtlcIndex, nil
}

// MayAddOutgoingHtlc validates whether we can add an outgoing htlc to this
// channel. We don't have a value or circuit for this htlc, because we just
// want to test that we have slots for a potential htlc so we use a "mock"
// htlc to validate a potential commitment state with one more outgoing htlc.
func (lc *LightningChannel) MayAddOutgoingHtlc(amt lnwire.MilliSatoshi) error {
	lc.Lock()
	defer lc.Unlock()

	// Create a "mock" outgoing htlc with the amount provided, we do not
	// add a zero check here because we expect sane callers to add non-zero
	// htlc amounts.
	pd := lc.htlcAddDescriptor(
		&lnwire.UpdateAddHTLC{
			Amount: amt,
		},
		&channeldb.CircuitKey{},
	)

	if err := lc.validateAddHtlc(pd); err != nil {
		lc.log.Debugf("May add outgoing htlc rejected: %v", err)
		return err
	}

	return nil
}

// htlcAddDescriptor returns a payment descriptor for the htlc and open key
// provided to add to our local update log.
func (lc *LightningChannel) htlcAddDescriptor(htlc *lnwire.UpdateAddHTLC,
	openKey *channeldb.CircuitKey) *PaymentDescriptor {

	return &PaymentDescriptor{
		EntryType:      Add,
		RHash:          PaymentHash(htlc.PaymentHash),
		Timeout:        htlc.Expiry,
		Amount:         htlc.Amount,
		LogIndex:       lc.localUpdateLog.logIndex,
		HtlcIndex:      lc.localUpdateLog.htlcCounter,
		OnionBlob:      htlc.OnionBlob[:],
		OpenCircuitKey: openKey,
	}
}

// validateAddHtlc validates the addition of an outgoing htlc to our local and
// remote commitments.
func (lc *LightningChannel) validateAddHtlc(pd *PaymentDescriptor) error {
	// Make sure adding this HTLC won't violate any of the constraints we
	// must keep on the commitment transactions.
	remoteACKedIndex := lc.localCommitChain.tail().theirMessageIndex

	// First we'll check whether this HTLC can be added to the remote
	// commitment transaction without violation any of the constraints.
	err := lc.validateCommitmentSanity(
		remoteACKedIndex, lc.localUpdateLog.logIndex, true, pd, nil,
	)
	if err != nil {
		return err
	}

	// We must also check whether it can be added to our own commitment
	// transaction, or the remote node will refuse to sign. This is not
	// totally bullet proof, as the remote might be adding updates
	// concurrently, but if we fail this check there is for sure not
	// possible for us to add the HTLC.
	err = lc.validateCommitmentSanity(
		lc.remoteUpdateLog.logIndex, lc.localUpdateLog.logIndex,
		false, pd, nil,
	)
	if err != nil {
		return err
	}

	return nil
}

// ReceiveHTLC adds an HTLC to the state machine's remote update log. This
// method should be called in response to receiving a new HTLC from the remote
// party.
func (lc *LightningChannel) ReceiveHTLC(htlc *lnwire.UpdateAddHTLC) (uint64, error) {
	lc.Lock()
	defer lc.Unlock()

	if htlc.ID != lc.remoteUpdateLog.htlcCounter {
		return 0, fmt.Errorf("ID %d on HTLC add does not match expected next "+
			"ID %d", htlc.ID, lc.remoteUpdateLog.htlcCounter)
	}

	pd := &PaymentDescriptor{
		EntryType: Add,
		RHash:     PaymentHash(htlc.PaymentHash),
		Timeout:   htlc.Expiry,
		Amount:    htlc.Amount,
		LogIndex:  lc.remoteUpdateLog.logIndex,
		HtlcIndex: lc.remoteUpdateLog.htlcCounter,
		OnionBlob: htlc.OnionBlob[:],
	}

	localACKedIndex := lc.remoteCommitChain.tail().ourMessageIndex

	// Clamp down on the number of HTLC's we can receive by checking the
	// commitment sanity.
	err := lc.validateCommitmentSanity(
		lc.remoteUpdateLog.logIndex, localACKedIndex, false, nil, pd,
	)
	if err != nil {
		return 0, err
	}

	lc.remoteUpdateLog.appendHtlc(pd)

	return pd.HtlcIndex, nil
}

// SettleHTLC attempts to settle an existing outstanding received HTLC. The
// remote log index of the HTLC settled is returned in order to facilitate
// creating the corresponding wire message. In the case the supplied preimage
// is invalid, an error is returned.
//
// The additional arguments correspond to:
//  * sourceRef: specifies the location of the Add HTLC within a forwarding
//      package that this HTLC is settling. Every Settle fails exactly one Add,
//      so this should never be empty in practice.
//
//  * destRef: specifies the location of the Settle HTLC within another
//      channel's forwarding package. This value can be nil if the corresponding
//      Add HTLC was never locked into an outgoing commitment txn, or this
//      HTLC does not originate as a response from the peer on the outgoing
//      link, e.g. on-chain resolutions.
//
//  * closeKey: identifies the circuit that should be deleted after this Settle
//      HTLC is included in a commitment txn. This value should only be nil if
//      the HTLC was settled locally before committing a circuit to the circuit
//      map.
//
// NOTE: It is okay for sourceRef, destRef, and closeKey to be nil when unit
// testing the wallet.
func (lc *LightningChannel) SettleHTLC(preimage [32]byte,
	htlcIndex uint64, sourceRef *channeldb.AddRef,
	destRef *channeldb.SettleFailRef, closeKey *channeldb.CircuitKey) error {

	lc.Lock()
	defer lc.Unlock()

	htlc := lc.remoteUpdateLog.lookupHtlc(htlcIndex)
	if htlc == nil {
		return ErrUnknownHtlcIndex{lc.ShortChanID(), htlcIndex}
	}

	// Now that we know the HTLC exists, before checking to see if the
	// preimage matches, we'll ensure that we haven't already attempted to
	// modify the HTLC.
	if lc.remoteUpdateLog.htlcHasModification(htlcIndex) {
		return ErrHtlcIndexAlreadySettled(htlcIndex)
	}

	if htlc.RHash != sha256.Sum256(preimage[:]) {
		return ErrInvalidSettlePreimage{preimage[:], htlc.RHash[:]}
	}

	pd := &PaymentDescriptor{
		Amount:           htlc.Amount,
		RPreimage:        preimage,
		LogIndex:         lc.localUpdateLog.logIndex,
		ParentIndex:      htlcIndex,
		EntryType:        Settle,
		SourceRef:        sourceRef,
		DestRef:          destRef,
		ClosedCircuitKey: closeKey,
	}

	lc.localUpdateLog.appendUpdate(pd)

	// With the settle added to our local log, we'll now mark the HTLC as
	// modified to prevent ourselves from accidentally attempting a
	// duplicate settle.
	lc.remoteUpdateLog.markHtlcModified(htlcIndex)

	return nil
}

// ReceiveHTLCSettle attempts to settle an existing outgoing HTLC indexed by an
// index into the local log. If the specified index doesn't exist within the
// log, and error is returned. Similarly if the preimage is invalid w.r.t to
// the referenced of then a distinct error is returned.
func (lc *LightningChannel) ReceiveHTLCSettle(preimage [32]byte, htlcIndex uint64) error {
	lc.Lock()
	defer lc.Unlock()

	htlc := lc.localUpdateLog.lookupHtlc(htlcIndex)
	if htlc == nil {
		return ErrUnknownHtlcIndex{lc.ShortChanID(), htlcIndex}
	}

	// Now that we know the HTLC exists, before checking to see if the
	// preimage matches, we'll ensure that they haven't already attempted
	// to modify the HTLC.
	if lc.localUpdateLog.htlcHasModification(htlcIndex) {
		return ErrHtlcIndexAlreadySettled(htlcIndex)
	}

	if htlc.RHash != sha256.Sum256(preimage[:]) {
		return ErrInvalidSettlePreimage{preimage[:], htlc.RHash[:]}
	}

	pd := &PaymentDescriptor{
		Amount:      htlc.Amount,
		RPreimage:   preimage,
		ParentIndex: htlc.HtlcIndex,
		RHash:       htlc.RHash,
		LogIndex:    lc.remoteUpdateLog.logIndex,
		EntryType:   Settle,
	}

	lc.remoteUpdateLog.appendUpdate(pd)

	// With the settle added to the remote log, we'll now mark the HTLC as
	// modified to prevent the remote party from accidentally attempting a
	// duplicate settle.
	lc.localUpdateLog.markHtlcModified(htlcIndex)

	return nil
}

// FailHTLC attempts to fail a targeted HTLC by its payment hash, inserting an
// entry which will remove the target log entry within the next commitment
// update. This method is intended to be called in order to cancel in
// _incoming_ HTLC.
//
// The additional arguments correspond to:
//  * sourceRef: specifies the location of the Add HTLC within a forwarding
//      package that this HTLC is failing. Every Fail fails exactly one Add, so
//      this should never be empty in practice.
//
//  * destRef: specifies the location of the Fail HTLC within another channel's
//      forwarding package. This value can be nil if the corresponding Add HTLC
//      was never locked into an outgoing commitment txn, or this HTLC does not
//      originate as a response from the peer on the outgoing link, e.g.
//      on-chain resolutions.
//
//  * closeKey: identifies the circuit that should be deleted after this Fail
//      HTLC is included in a commitment txn. This value should only be nil if
//      the HTLC was failed locally before committing a circuit to the circuit
//      map.
//
// NOTE: It is okay for sourceRef, destRef, and closeKey to be nil when unit
// testing the wallet.
func (lc *LightningChannel) FailHTLC(htlcIndex uint64, reason []byte,
	sourceRef *channeldb.AddRef, destRef *channeldb.SettleFailRef,
	closeKey *channeldb.CircuitKey) error {

	lc.Lock()
	defer lc.Unlock()

	htlc := lc.remoteUpdateLog.lookupHtlc(htlcIndex)
	if htlc == nil {
		return ErrUnknownHtlcIndex{lc.ShortChanID(), htlcIndex}
	}

	// Now that we know the HTLC exists, we'll ensure that we haven't
	// already attempted to fail the HTLC.
	if lc.remoteUpdateLog.htlcHasModification(htlcIndex) {
		return ErrHtlcIndexAlreadyFailed(htlcIndex)
	}

	pd := &PaymentDescriptor{
		Amount:           htlc.Amount,
		RHash:            htlc.RHash,
		ParentIndex:      htlcIndex,
		LogIndex:         lc.localUpdateLog.logIndex,
		EntryType:        Fail,
		FailReason:       reason,
		SourceRef:        sourceRef,
		DestRef:          destRef,
		ClosedCircuitKey: closeKey,
	}

	lc.localUpdateLog.appendUpdate(pd)

	// With the fail added to the remote log, we'll now mark the HTLC as
	// modified to prevent ourselves from accidentally attempting a
	// duplicate fail.
	lc.remoteUpdateLog.markHtlcModified(htlcIndex)

	return nil
}

// MalformedFailHTLC attempts to fail a targeted HTLC by its payment hash,
// inserting an entry which will remove the target log entry within the next
// commitment update. This method is intended to be called in order to cancel
// in _incoming_ HTLC.
//
// The additional sourceRef specifies the location of the Add HTLC within a
// forwarding package that this HTLC is failing. This value should never be
// empty.
//
// NOTE: It is okay for sourceRef to be nil when unit testing the wallet.
func (lc *LightningChannel) MalformedFailHTLC(htlcIndex uint64,
	failCode lnwire.FailCode, shaOnionBlob [sha256.Size]byte,
	sourceRef *channeldb.AddRef) error {

	lc.Lock()
	defer lc.Unlock()

	htlc := lc.remoteUpdateLog.lookupHtlc(htlcIndex)
	if htlc == nil {
		return ErrUnknownHtlcIndex{lc.ShortChanID(), htlcIndex}
	}

	// Now that we know the HTLC exists, we'll ensure that we haven't
	// already attempted to fail the HTLC.
	if lc.remoteUpdateLog.htlcHasModification(htlcIndex) {
		return ErrHtlcIndexAlreadyFailed(htlcIndex)
	}

	pd := &PaymentDescriptor{
		Amount:       htlc.Amount,
		RHash:        htlc.RHash,
		ParentIndex:  htlcIndex,
		LogIndex:     lc.localUpdateLog.logIndex,
		EntryType:    MalformedFail,
		FailCode:     failCode,
		ShaOnionBlob: shaOnionBlob,
		SourceRef:    sourceRef,
	}

	lc.localUpdateLog.appendUpdate(pd)

	// With the fail added to the remote log, we'll now mark the HTLC as
	// modified to prevent ourselves from accidentally attempting a
	// duplicate fail.
	lc.remoteUpdateLog.markHtlcModified(htlcIndex)

	return nil
}

// ReceiveFailHTLC attempts to cancel a targeted HTLC by its log index,
// inserting an entry which will remove the target log entry within the next
// commitment update. This method should be called in response to the upstream
// party cancelling an outgoing HTLC. The value of the failed HTLC is returned
// along with an error indicating success.
func (lc *LightningChannel) ReceiveFailHTLC(htlcIndex uint64, reason []byte,
) error {

	lc.Lock()
	defer lc.Unlock()

	htlc := lc.localUpdateLog.lookupHtlc(htlcIndex)
	if htlc == nil {
		return ErrUnknownHtlcIndex{lc.ShortChanID(), htlcIndex}
	}

	// Now that we know the HTLC exists, we'll ensure that they haven't
	// already attempted to fail the HTLC.
	if lc.localUpdateLog.htlcHasModification(htlcIndex) {
		return ErrHtlcIndexAlreadyFailed(htlcIndex)
	}

	pd := &PaymentDescriptor{
		Amount:      htlc.Amount,
		RHash:       htlc.RHash,
		ParentIndex: htlc.HtlcIndex,
		LogIndex:    lc.remoteUpdateLog.logIndex,
		EntryType:   Fail,
		FailReason:  reason,
	}

	lc.remoteUpdateLog.appendUpdate(pd)

	// With the fail added to the remote log, we'll now mark the HTLC as
	// modified to prevent ourselves from accidentally attempting a
	// duplicate fail.
	lc.localUpdateLog.markHtlcModified(htlcIndex)

	return nil
}

// ChannelPoint returns the outpoint of the original funding transaction which
// created this active channel. This outpoint is used throughout various
// subsystems to uniquely identify an open channel.
func (lc *LightningChannel) ChannelPoint() *wire.OutPoint {
	return &lc.channelState.FundingOutpoint
}

// ShortChanID returns the short channel ID for the channel. The short channel
// ID encodes the exact location in the main chain that the original
// funding output can be found.
func (lc *LightningChannel) ShortChanID() lnwire.ShortChannelID {
	return lc.channelState.ShortChanID()
}

// LocalUpfrontShutdownScript returns the local upfront shutdown script for the
// channel. If it was not set, an empty byte array is returned.
func (lc *LightningChannel) LocalUpfrontShutdownScript() lnwire.DeliveryAddress {
	return lc.channelState.LocalShutdownScript
}

// RemoteUpfrontShutdownScript returns the remote upfront shutdown script for the
// channel. If it was not set, an empty byte array is returned.
func (lc *LightningChannel) RemoteUpfrontShutdownScript() lnwire.DeliveryAddress {
	return lc.channelState.RemoteShutdownScript
}

// getSignedCommitTx function take the latest commitment transaction and
// populate it with witness data.
func (lc *LightningChannel) getSignedCommitTx() (*wire.MsgTx, error) {
	// Fetch the current commitment transaction, along with their signature
	// for the transaction.
	localCommit := lc.channelState.LocalCommitment
	commitTx := localCommit.CommitTx.Copy()

	theirSig, err := btcec.ParseDERSignature(
		localCommit.CommitSig, btcec.S256(),
	)
	if err != nil {
		return nil, err
	}

	// With this, we then generate the full witness so the caller can
	// broadcast a fully signed transaction.
	lc.signDesc.SigHashes = txscript.NewTxSigHashes(commitTx)
	ourSig, err := lc.Signer.SignOutputRaw(commitTx, lc.signDesc)
	if err != nil {
		return nil, err
	}

	// With the final signature generated, create the witness stack
	// required to spend from the multi-sig output.
	ourKey := lc.channelState.LocalChanCfg.MultiSigKey.PubKey.
		SerializeCompressed()
	theirKey := lc.channelState.RemoteChanCfg.MultiSigKey.PubKey.
		SerializeCompressed()

	commitTx.TxIn[0].Witness = input.SpendMultiSig(
		lc.signDesc.WitnessScript, ourKey,
		ourSig, theirKey, theirSig,
	)

	return commitTx, nil
}

// CommitOutputResolution carries the necessary information required to allow
// us to sweep our commitment output in the case that either party goes to
// chain.
type CommitOutputResolution struct {
	// SelfOutPoint is the full outpoint that points to out pay-to-self
	// output within the closing commitment transaction.
	SelfOutPoint wire.OutPoint

	// SelfOutputSignDesc is a fully populated sign descriptor capable of
	// generating a valid signature to sweep the output paying to us.
	SelfOutputSignDesc input.SignDescriptor

	// MaturityDelay is the relative time-lock, in blocks for all outputs
	// that pay to the local party within the broadcast commitment
	// transaction.
	MaturityDelay uint32
}

// UnilateralCloseSummary describes the details of a detected unilateral
// channel closure. This includes the information about with which
// transactions, and block the channel was unilaterally closed, as well as
// summarization details concerning the _state_ of the channel at the point of
// channel closure. Additionally, if we had a commitment output above dust on
// the remote party's commitment transaction, the necessary a SignDescriptor
// with the material necessary to seep the output are returned. Finally, if we
// had any outgoing HTLC's within the commitment transaction, then an
// OutgoingHtlcResolution for each output will included.
type UnilateralCloseSummary struct {
	// SpendDetail is a struct that describes how and when the funding
	// output was spent.
	*chainntnfs.SpendDetail

	// ChannelCloseSummary is a struct describing the final state of the
	// channel and in which state is was closed.
	channeldb.ChannelCloseSummary

	// CommitResolution contains all the data required to sweep the output
	// to ourselves. If this is our commitment transaction, then we'll need
	// to wait a time delay before we can sweep the output.
	//
	// NOTE: If our commitment delivery output is below the dust limit,
	// then this will be nil.
	CommitResolution *CommitOutputResolution

	// HtlcResolutions contains a fully populated HtlcResolutions struct
	// which contains all the data required to sweep any outgoing HTLC's,
	// and also any incoming HTLC's that we know the pre-image to.
	HtlcResolutions *HtlcResolutions

	// RemoteCommit is the exact commitment state that the remote party
	// broadcast.
	RemoteCommit channeldb.ChannelCommitment

	// AnchorResolution contains the data required to sweep our anchor
	// output. If the channel type doesn't include anchors, the value of
	// this field will be nil.
	AnchorResolution *AnchorResolution
}

// NewUnilateralCloseSummary creates a new summary that provides the caller
// with all the information required to claim all funds on chain in the event
// that the remote party broadcasts their commitment. The commitPoint argument
// should be set to the per_commitment_point corresponding to the spending
// commitment.
//
// NOTE: The remoteCommit argument should be set to the stored commitment for
// this particular state. If we don't have the commitment stored (should only
// happen in case we have lost state) it should be set to an empty struct, in
// which case we will attempt to sweep the non-HTLC output using the passed
// commitPoint.
func NewUnilateralCloseSummary(chanState *channeldb.OpenChannel, signer input.Signer,
	commitSpend *chainntnfs.SpendDetail,
	remoteCommit channeldb.ChannelCommitment,
	commitPoint *btcec.PublicKey) (*UnilateralCloseSummary, error) {

	// First, we'll generate the commitment point and the revocation point
	// so we can re-construct the HTLC state and also our payment key.
	keyRing := DeriveCommitmentKeys(
		commitPoint, false, chanState.ChanType,
		&chanState.LocalChanCfg, &chanState.RemoteChanCfg,
	)

	// Next, we'll obtain HTLC resolutions for all the outgoing HTLC's we
	// had on their commitment transaction.
	htlcResolutions, err := extractHtlcResolutions(
		chainfee.SatPerKWeight(remoteCommit.FeePerKw), false, signer,
		remoteCommit.Htlcs, keyRing, &chanState.LocalChanCfg,
		&chanState.RemoteChanCfg, commitSpend.SpendingTx,
		chanState.ChanType,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create htlc "+
			"resolutions: %v", err)
	}

	commitTxBroadcast := commitSpend.SpendingTx

	// Before we can generate the proper sign descriptor, we'll need to
	// locate the output index of our non-delayed output on the commitment
	// transaction.
	selfScript, maturityDelay, err := CommitScriptToRemote(
		chanState.ChanType, keyRing.ToRemoteKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create self commit "+
			"script: %v", err)
	}

	var (
		selfPoint    *wire.OutPoint
		localBalance int64
	)

	for outputIndex, txOut := range commitTxBroadcast.TxOut {
		if bytes.Equal(txOut.PkScript, selfScript.PkScript) {
			selfPoint = &wire.OutPoint{
				Hash:  *commitSpend.SpenderTxHash,
				Index: uint32(outputIndex),
			}
			localBalance = txOut.Value
			break
		}
	}

	// With the HTLC's taken care of, we'll generate the sign descriptor
	// necessary to sweep our commitment output, but only if we had a
	// non-trimmed balance.
	var commitResolution *CommitOutputResolution
	if selfPoint != nil {
		localPayBase := chanState.LocalChanCfg.PaymentBasePoint
		commitResolution = &CommitOutputResolution{
			SelfOutPoint: *selfPoint,
			SelfOutputSignDesc: input.SignDescriptor{
				KeyDesc:       localPayBase,
				SingleTweak:   keyRing.LocalCommitKeyTweak,
				WitnessScript: selfScript.WitnessScript,
				Output: &wire.TxOut{
					Value:    localBalance,
					PkScript: selfScript.PkScript,
				},
				HashType: txscript.SigHashAll,
			},
			MaturityDelay: maturityDelay,
		}
	}

	closeSummary := channeldb.ChannelCloseSummary{
		ChanPoint:               chanState.FundingOutpoint,
		ChainHash:               chanState.ChainHash,
		ClosingTXID:             *commitSpend.SpenderTxHash,
		CloseHeight:             uint32(commitSpend.SpendingHeight),
		RemotePub:               chanState.IdentityPub,
		Capacity:                chanState.Capacity,
		SettledBalance:          btcutil.Amount(localBalance),
		CloseType:               channeldb.RemoteForceClose,
		IsPending:               true,
		RemoteCurrentRevocation: chanState.RemoteCurrentRevocation,
		RemoteNextRevocation:    chanState.RemoteNextRevocation,
		ShortChanID:             chanState.ShortChanID(),
		LocalChanConfig:         chanState.LocalChanCfg,
	}

	// Attempt to add a channel sync message to the close summary.
	chanSync, err := chanState.ChanSyncMsg()
	if err != nil {
		walletLog.Errorf("ChannelPoint(%v): unable to create channel sync "+
			"message: %v", chanState.FundingOutpoint, err)
	} else {
		closeSummary.LastChanSyncMsg = chanSync
	}

	anchorResolution, err := NewAnchorResolution(
		chanState, commitTxBroadcast,
	)
	if err != nil {
		return nil, err
	}

	return &UnilateralCloseSummary{
		SpendDetail:         commitSpend,
		ChannelCloseSummary: closeSummary,
		CommitResolution:    commitResolution,
		HtlcResolutions:     htlcResolutions,
		RemoteCommit:        remoteCommit,
		AnchorResolution:    anchorResolution,
	}, nil
}

// IncomingHtlcResolution houses the information required to sweep any incoming
// HTLC's that we know the preimage to. We'll need to sweep an HTLC manually
// using this struct if we need to go on-chain for any reason, or if we detect
// that the remote party broadcasts their commitment transaction.
type IncomingHtlcResolution struct {
	// Preimage is the preimage that will be used to satisfy the contract of
	// the HTLC.
	//
	// NOTE: This field will only be populated in the incoming contest
	// resolver.
	Preimage [32]byte

	// SignedSuccessTx is the fully signed HTLC success transaction. This
	// transaction (if non-nil) can be broadcast immediately. After a csv
	// delay (included below), then the output created by this transactions
	// can be swept on-chain.
	//
	// NOTE: If this field is nil, then this indicates that we don't need
	// to go to the second level to claim this HTLC. Instead, it can be
	// claimed directly from the outpoint listed below.
	SignedSuccessTx *wire.MsgTx

	// SignDetails is non-nil if SignedSuccessTx is non-nil, and the
	// channel is of the anchor type. As the above HTLC transaction will be
	// signed by the channel peer using SINGLE|ANYONECANPAY for such
	// channels, we can use the sign details to add the input-output pair
	// of the HTLC transaction to another transaction, thereby aggregating
	// multiple HTLC transactions together, and adding fees as needed.
	SignDetails *input.SignDetails

	// CsvDelay is the relative time lock (expressed in blocks) that must
	// pass after the SignedSuccessTx is confirmed in the chain before the
	// output can be swept.
	//
	// NOTE: If SignedTimeoutTx is nil, then this field denotes the CSV
	// delay needed to spend from the commitment transaction.
	CsvDelay uint32

	// ClaimOutpoint is the final outpoint that needs to be spent in order
	// to fully sweep the HTLC. The SignDescriptor below should be used to
	// spend this outpoint. In the case of a second-level HTLC (non-nil
	// SignedTimeoutTx), then we'll be spending a new transaction.
	// Otherwise, it'll be an output in the commitment transaction.
	ClaimOutpoint wire.OutPoint

	// SweepSignDesc is a sign descriptor that has been populated with the
	// necessary items required to spend the sole output of the above
	// transaction.
	SweepSignDesc input.SignDescriptor
}

// OutgoingHtlcResolution houses the information necessary to sweep any
// outgoing HTLC's after their contract has expired. This struct will be needed
// in one of two cases: the local party force closes the commitment transaction
// or the remote party unilaterally closes with their version of the commitment
// transaction.
type OutgoingHtlcResolution struct {
	// Expiry the absolute timeout of the HTLC. This value is expressed in
	// block height, meaning after this height the HLTC can be swept.
	Expiry uint32

	// SignedTimeoutTx is the fully signed HTLC timeout transaction. This
	// must be broadcast immediately after timeout has passed. Once this
	// has been confirmed, the HTLC output will transition into the
	// delay+claim state.
	//
	// NOTE: If this field is nil, then this indicates that we don't need
	// to go to the second level to claim this HTLC. Instead, it can be
	// claimed directly from the outpoint listed below.
	SignedTimeoutTx *wire.MsgTx

	// SignDetails is non-nil if SignedTimeoutTx is non-nil, and the
	// channel is of the anchor type. As the above HTLC transaction will be
	// signed by the channel peer using SINGLE|ANYONECANPAY for such
	// channels, we can use the sign details to add the input-output pair
	// of the HTLC transaction to another transaction, thereby aggregating
	// multiple HTLC transactions together, and adding fees as needed.
	SignDetails *input.SignDetails

	// CsvDelay is the relative time lock (expressed in blocks) that must
	// pass after the SignedTimeoutTx is confirmed in the chain before the
	// output can be swept.
	//
	// NOTE: If SignedTimeoutTx is nil, then this field denotes the CSV
	// delay needed to spend from the commitment transaction.
	CsvDelay uint32

	// ClaimOutpoint is the final outpoint that needs to be spent in order
	// to fully sweep the HTLC. The SignDescriptor below should be used to
	// spend this outpoint. In the case of a second-level HTLC (non-nil
	// SignedTimeoutTx), then we'll be spending a new transaction.
	// Otherwise, it'll be an output in the commitment transaction.
	ClaimOutpoint wire.OutPoint

	// SweepSignDesc is a sign descriptor that has been populated with the
	// necessary items required to spend the sole output of the above
	// transaction.
	SweepSignDesc input.SignDescriptor
}

// HtlcResolutions contains the items necessary to sweep HTLC's on chain
// directly from a commitment transaction. We'll use this in case either party
// goes broadcasts a commitment transaction with live HTLC's.
type HtlcResolutions struct {
	// IncomingHTLCs contains a set of structs that can be used to sweep
	// all the incoming HTL'C that we know the preimage to.
	IncomingHTLCs []IncomingHtlcResolution

	// OutgoingHTLCs contains a set of structs that contains all the info
	// needed to sweep an outgoing HTLC we've sent to the remote party
	// after an absolute delay has expired.
	OutgoingHTLCs []OutgoingHtlcResolution
}

// newOutgoingHtlcResolution generates a new HTLC resolution capable of
// allowing the caller to sweep an outgoing HTLC present on either their, or
// the remote party's commitment transaction.
func newOutgoingHtlcResolution(signer input.Signer,
	localChanCfg *channeldb.ChannelConfig, commitTx *wire.MsgTx,
	htlc *channeldb.HTLC, keyRing *CommitmentKeyRing,
	feePerKw chainfee.SatPerKWeight, csvDelay uint32,
	localCommit bool, chanType channeldb.ChannelType) (*OutgoingHtlcResolution, error) {

	op := wire.OutPoint{
		Hash:  commitTx.TxHash(),
		Index: uint32(htlc.OutputIndex),
	}

	// First, we'll re-generate the script used to send the HTLC to
	// the remote party within their commitment transaction.
	htlcScriptHash, htlcScript, err := genHtlcScript(
		chanType, false, localCommit, htlc.RefundTimeout, htlc.RHash,
		keyRing,
	)
	if err != nil {
		return nil, err
	}

	// If we're spending this HTLC output from the remote node's
	// commitment, then we won't need to go to the second level as our
	// outputs don't have a CSV delay.
	if !localCommit {
		// With the script generated, we can completely populated the
		// SignDescriptor needed to sweep the output.
		return &OutgoingHtlcResolution{
			Expiry:        htlc.RefundTimeout,
			ClaimOutpoint: op,
			SweepSignDesc: input.SignDescriptor{
				KeyDesc:       localChanCfg.HtlcBasePoint,
				SingleTweak:   keyRing.LocalHtlcKeyTweak,
				WitnessScript: htlcScript,
				Output: &wire.TxOut{
					PkScript: htlcScriptHash,
					Value:    int64(htlc.Amt.ToSatoshis()),
				},
				HashType: txscript.SigHashAll,
			},
			CsvDelay: HtlcSecondLevelInputSequence(chanType),
		}, nil
	}

	// Otherwise, we'll need to craft a second level HTLC transaction, as
	// well as a sign desc to sweep after the CSV delay.

	// In order to properly reconstruct the HTLC transaction, we'll need to
	// re-calculate the fee required at this state, so we can add the
	// correct output value amount to the transaction.
	htlcFee := HtlcTimeoutFee(chanType, feePerKw)
	secondLevelOutputAmt := htlc.Amt.ToSatoshis() - htlcFee

	// With the fee calculated, re-construct the second level timeout
	// transaction.
	timeoutTx, err := CreateHtlcTimeoutTx(
		chanType, op, secondLevelOutputAmt, htlc.RefundTimeout,
		csvDelay, keyRing.RevocationKey, keyRing.ToLocalKey,
	)
	if err != nil {
		return nil, err
	}

	// With the transaction created, we can generate a sign descriptor
	// that's capable of generating the signature required to spend the
	// HTLC output using the timeout transaction.
	txOut := commitTx.TxOut[htlc.OutputIndex]
	timeoutSignDesc := input.SignDescriptor{
		KeyDesc:       localChanCfg.HtlcBasePoint,
		SingleTweak:   keyRing.LocalHtlcKeyTweak,
		WitnessScript: htlcScript,
		Output:        txOut,
		HashType:      txscript.SigHashAll,
		SigHashes:     txscript.NewTxSigHashes(timeoutTx),
		InputIndex:    0,
	}

	htlcSig, err := btcec.ParseDERSignature(htlc.Signature, btcec.S256())
	if err != nil {
		return nil, err
	}

	// With the sign desc created, we can now construct the full witness
	// for the timeout transaction, and populate it as well.
	sigHashType := HtlcSigHashType(chanType)
	timeoutWitness, err := input.SenderHtlcSpendTimeout(
		htlcSig, sigHashType, signer, &timeoutSignDesc, timeoutTx,
	)
	if err != nil {
		return nil, err
	}
	timeoutTx.TxIn[0].Witness = timeoutWitness

	// If this is an anchor type channel, the sign details will let us
	// re-sign an aggregated tx later.
	txSignDetails := HtlcSignDetails(
		chanType, timeoutSignDesc, sigHashType, htlcSig,
	)

	// Finally, we'll generate the script output that the timeout
	// transaction creates so we can generate the signDesc required to
	// complete the claim process after a delay period.
	htlcSweepScript, err := input.SecondLevelHtlcScript(
		keyRing.RevocationKey, keyRing.ToLocalKey, csvDelay,
	)
	if err != nil {
		return nil, err
	}
	htlcSweepScriptHash, err := input.WitnessScriptHash(htlcSweepScript)
	if err != nil {
		return nil, err
	}

	localDelayTweak := input.SingleTweakBytes(
		keyRing.CommitPoint, localChanCfg.DelayBasePoint.PubKey,
	)
	return &OutgoingHtlcResolution{
		Expiry:          htlc.RefundTimeout,
		SignedTimeoutTx: timeoutTx,
		SignDetails:     txSignDetails,
		CsvDelay:        csvDelay,
		ClaimOutpoint: wire.OutPoint{
			Hash:  timeoutTx.TxHash(),
			Index: 0,
		},
		SweepSignDesc: input.SignDescriptor{
			KeyDesc:       localChanCfg.DelayBasePoint,
			SingleTweak:   localDelayTweak,
			WitnessScript: htlcSweepScript,
			Output: &wire.TxOut{
				PkScript: htlcSweepScriptHash,
				Value:    int64(secondLevelOutputAmt),
			},
			HashType: txscript.SigHashAll,
		},
	}, nil
}

// newIncomingHtlcResolution creates a new HTLC resolution capable of allowing
// the caller to sweep an incoming HTLC. If the HTLC is on the caller's
// commitment transaction, then they'll need to broadcast a second-level
// transaction before sweeping the output (and incur a CSV delay). Otherwise,
// they can just sweep the output immediately with knowledge of the pre-image.
//
// TODO(roasbeef) consolidate code with above func
func newIncomingHtlcResolution(signer input.Signer,
	localChanCfg *channeldb.ChannelConfig, commitTx *wire.MsgTx,
	htlc *channeldb.HTLC, keyRing *CommitmentKeyRing,
	feePerKw chainfee.SatPerKWeight, csvDelay uint32, localCommit bool,
	chanType channeldb.ChannelType) (*IncomingHtlcResolution, error) {

	op := wire.OutPoint{
		Hash:  commitTx.TxHash(),
		Index: uint32(htlc.OutputIndex),
	}

	// First, we'll re-generate the script the remote party used to
	// send the HTLC to us in their commitment transaction.
	htlcScriptHash, htlcScript, err := genHtlcScript(
		chanType, true, localCommit, htlc.RefundTimeout, htlc.RHash,
		keyRing,
	)
	if err != nil {
		return nil, err
	}

	// If we're spending this output from the remote node's commitment,
	// then we can skip the second layer and spend the output directly.
	if !localCommit {
		// With the script generated, we can completely populated the
		// SignDescriptor needed to sweep the output.
		return &IncomingHtlcResolution{
			ClaimOutpoint: op,
			SweepSignDesc: input.SignDescriptor{
				KeyDesc:       localChanCfg.HtlcBasePoint,
				SingleTweak:   keyRing.LocalHtlcKeyTweak,
				WitnessScript: htlcScript,
				Output: &wire.TxOut{
					PkScript: htlcScriptHash,
					Value:    int64(htlc.Amt.ToSatoshis()),
				},
				HashType: txscript.SigHashAll,
			},
			CsvDelay: HtlcSecondLevelInputSequence(chanType),
		}, nil
	}

	// Otherwise, we'll need to go to the second level to sweep this HTLC.

	// First, we'll reconstruct the original HTLC success transaction,
	// taking into account the fee rate used.
	htlcFee := HtlcSuccessFee(chanType, feePerKw)
	secondLevelOutputAmt := htlc.Amt.ToSatoshis() - htlcFee
	successTx, err := CreateHtlcSuccessTx(
		chanType, op, secondLevelOutputAmt, csvDelay,
		keyRing.RevocationKey, keyRing.ToLocalKey,
	)
	if err != nil {
		return nil, err
	}

	// Once we've created the second-level transaction, we'll generate the
	// SignDesc needed spend the HTLC output using the success transaction.
	txOut := commitTx.TxOut[htlc.OutputIndex]
	successSignDesc := input.SignDescriptor{
		KeyDesc:       localChanCfg.HtlcBasePoint,
		SingleTweak:   keyRing.LocalHtlcKeyTweak,
		WitnessScript: htlcScript,
		Output:        txOut,
		HashType:      txscript.SigHashAll,
		SigHashes:     txscript.NewTxSigHashes(successTx),
		InputIndex:    0,
	}

	htlcSig, err := btcec.ParseDERSignature(htlc.Signature, btcec.S256())
	if err != nil {
		return nil, err
	}

	// Next, we'll construct the full witness needed to satisfy the input of
	// the success transaction. Don't specify the preimage yet. The preimage
	// will be supplied by the contract resolver, either directly or when it
	// becomes known.
	sigHashType := HtlcSigHashType(chanType)
	successWitness, err := input.ReceiverHtlcSpendRedeem(
		htlcSig, sigHashType, nil, signer, &successSignDesc, successTx,
	)
	if err != nil {
		return nil, err
	}
	successTx.TxIn[0].Witness = successWitness

	// If this is an anchor type channel, the sign details will let us
	// re-sign an aggregated tx later.
	txSignDetails := HtlcSignDetails(
		chanType, successSignDesc, sigHashType, htlcSig,
	)

	// Finally, we'll generate the script that the second-level transaction
	// creates so we can generate the proper signDesc to sweep it after the
	// CSV delay has passed.
	htlcSweepScript, err := input.SecondLevelHtlcScript(
		keyRing.RevocationKey, keyRing.ToLocalKey, csvDelay,
	)
	if err != nil {
		return nil, err
	}
	htlcSweepScriptHash, err := input.WitnessScriptHash(htlcSweepScript)
	if err != nil {
		return nil, err
	}

	localDelayTweak := input.SingleTweakBytes(
		keyRing.CommitPoint, localChanCfg.DelayBasePoint.PubKey,
	)
	return &IncomingHtlcResolution{
		SignedSuccessTx: successTx,
		SignDetails:     txSignDetails,
		CsvDelay:        csvDelay,
		ClaimOutpoint: wire.OutPoint{
			Hash:  successTx.TxHash(),
			Index: 0,
		},
		SweepSignDesc: input.SignDescriptor{
			KeyDesc:       localChanCfg.DelayBasePoint,
			SingleTweak:   localDelayTweak,
			WitnessScript: htlcSweepScript,
			Output: &wire.TxOut{
				PkScript: htlcSweepScriptHash,
				Value:    int64(secondLevelOutputAmt),
			},
			HashType: txscript.SigHashAll,
		},
	}, nil
}

// HtlcPoint returns the htlc's outpoint on the commitment tx.
func (r *IncomingHtlcResolution) HtlcPoint() wire.OutPoint {
	// If we have a success transaction, then the htlc's outpoint
	// is the transaction's only input. Otherwise, it's the claim
	// point.
	if r.SignedSuccessTx != nil {
		return r.SignedSuccessTx.TxIn[0].PreviousOutPoint
	}

	return r.ClaimOutpoint
}

// HtlcPoint returns the htlc's outpoint on the commitment tx.
func (r *OutgoingHtlcResolution) HtlcPoint() wire.OutPoint {
	// If we have a timeout transaction, then the htlc's outpoint
	// is the transaction's only input. Otherwise, it's the claim
	// point.
	if r.SignedTimeoutTx != nil {
		return r.SignedTimeoutTx.TxIn[0].PreviousOutPoint
	}

	return r.ClaimOutpoint
}

// extractHtlcResolutions creates a series of outgoing HTLC resolutions, and
// the local key used when generating the HTLC scrips. This function is to be
// used in two cases: force close, or a unilateral close.
func extractHtlcResolutions(feePerKw chainfee.SatPerKWeight, ourCommit bool,
	signer input.Signer, htlcs []channeldb.HTLC, keyRing *CommitmentKeyRing,
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig,
	commitTx *wire.MsgTx, chanType channeldb.ChannelType) (
	*HtlcResolutions, error) {

	// TODO(roasbeef): don't need to swap csv delay?
	dustLimit := remoteChanCfg.DustLimit
	csvDelay := remoteChanCfg.CsvDelay
	if ourCommit {
		dustLimit = localChanCfg.DustLimit
		csvDelay = localChanCfg.CsvDelay
	}

	incomingResolutions := make([]IncomingHtlcResolution, 0, len(htlcs))
	outgoingResolutions := make([]OutgoingHtlcResolution, 0, len(htlcs))
	for _, htlc := range htlcs {
		htlc := htlc

		// We'll skip any HTLC's which were dust on the commitment
		// transaction, as these don't have a corresponding output
		// within the commitment transaction.
		if htlcIsDust(
			chanType, htlc.Incoming, ourCommit, feePerKw,
			htlc.Amt.ToSatoshis(), dustLimit,
		) {
			continue
		}

		// If the HTLC is incoming, then we'll attempt to see if we
		// know the pre-image to the HTLC.
		if htlc.Incoming {
			// Otherwise, we'll create an incoming HTLC resolution
			// as we can satisfy the contract.
			ihr, err := newIncomingHtlcResolution(
				signer, localChanCfg, commitTx, &htlc,
				keyRing, feePerKw, uint32(csvDelay), ourCommit,
				chanType,
			)
			if err != nil {
				return nil, err
			}

			incomingResolutions = append(incomingResolutions, *ihr)
			continue
		}

		ohr, err := newOutgoingHtlcResolution(
			signer, localChanCfg, commitTx, &htlc, keyRing,
			feePerKw, uint32(csvDelay), ourCommit, chanType,
		)
		if err != nil {
			return nil, err
		}

		outgoingResolutions = append(outgoingResolutions, *ohr)
	}

	return &HtlcResolutions{
		IncomingHTLCs: incomingResolutions,
		OutgoingHTLCs: outgoingResolutions,
	}, nil
}

// AnchorResolution holds the information necessary to spend our commitment tx
// anchor.
type AnchorResolution struct {
	// AnchorSignDescriptor is the sign descriptor for our anchor.
	AnchorSignDescriptor input.SignDescriptor

	// CommitAnchor is the anchor outpoint on the commit tx.
	CommitAnchor wire.OutPoint

	// CommitFee is the fee of the commit tx.
	CommitFee btcutil.Amount

	// CommitWeight is the weight of the commit tx.
	CommitWeight int64
}

// LocalForceCloseSummary describes the final commitment state before the
// channel is locked-down to initiate a force closure by broadcasting the
// latest state on-chain. If we intend to broadcast this this state, the
// channel should not be used after generating this close summary.  The summary
// includes all the information required to claim all rightfully owned outputs
// when the commitment gets confirmed.
type LocalForceCloseSummary struct {
	// ChanPoint is the outpoint that created the channel which has been
	// force closed.
	ChanPoint wire.OutPoint

	// CloseTx is the transaction which can be used to close the channel
	// on-chain. When we initiate a force close, this will be our latest
	// commitment state.
	CloseTx *wire.MsgTx

	// CommitResolution contains all the data required to sweep the output
	// to ourselves. Since this is our commitment transaction, we'll need
	// to wait a time delay before we can sweep the output.
	//
	// NOTE: If our commitment delivery output is below the dust limit,
	// then this will be nil.
	CommitResolution *CommitOutputResolution

	// HtlcResolutions contains all the data required to sweep any outgoing
	// HTLC's and incoming HTLc's we know the preimage to. For each of these
	// HTLC's, we'll need to go to the second level to sweep them fully.
	HtlcResolutions *HtlcResolutions

	// ChanSnapshot is a snapshot of the final state of the channel at the
	// time the summary was created.
	ChanSnapshot channeldb.ChannelSnapshot

	// AnchorResolution contains the data required to sweep the anchor
	// output. If the channel type doesn't include anchors, the value of
	// this field will be nil.
	AnchorResolution *AnchorResolution
}

// ForceClose executes a unilateral closure of the transaction at the current
// lowest commitment height of the channel. Following a force closure, all
// state transitions, or modifications to the state update logs will be
// rejected. Additionally, this function also returns a LocalForceCloseSummary
// which includes the necessary details required to sweep all the time-locked
// outputs within the commitment transaction.
//
// TODO(roasbeef): all methods need to abort if in dispute state
// TODO(roasbeef): method to generate CloseSummaries for when the remote peer
// does a unilateral close
func (lc *LightningChannel) ForceClose() (*LocalForceCloseSummary, error) {
	lc.Lock()
	defer lc.Unlock()

	// If we've detected local data loss for this channel, then we won't
	// allow a force close, as it may be the case that we have a dated
	// version of the commitment, or this is actually a channel shell.
	if lc.channelState.HasChanStatus(channeldb.ChanStatusLocalDataLoss) {
		return nil, fmt.Errorf("cannot force close channel with "+
			"state: %v", lc.channelState.ChanStatus())
	}

	commitTx, err := lc.getSignedCommitTx()
	if err != nil {
		return nil, err
	}

	localCommitment := lc.channelState.LocalCommitment
	summary, err := NewLocalForceCloseSummary(
		lc.channelState, lc.Signer, commitTx,
		localCommitment.CommitHeight,
	)
	if err != nil {
		return nil, err
	}

	// Set the channel state to indicate that the channel is now in a
	// contested state.
	lc.status = channelDispute

	return summary, nil
}

// NewLocalForceCloseSummary generates a LocalForceCloseSummary from the given
// channel state.  The passed commitTx must be a fully signed commitment
// transaction corresponding to localCommit.
func NewLocalForceCloseSummary(chanState *channeldb.OpenChannel,
	signer input.Signer, commitTx *wire.MsgTx, stateNum uint64) (
	*LocalForceCloseSummary, error) {

	// Re-derive the original pkScript for to-self output within the
	// commitment transaction. We'll need this to find the corresponding
	// output in the commitment transaction and potentially for creating
	// the sign descriptor.
	csvTimeout := uint32(chanState.LocalChanCfg.CsvDelay)

	// We use the passed state num to derive our scripts, since in case
	// this is after recovery, our latest channels state might not be up to
	// date.
	revocation, err := chanState.RevocationProducer.AtIndex(stateNum)
	if err != nil {
		return nil, err
	}
	commitPoint := input.ComputeCommitmentPoint(revocation[:])
	keyRing := DeriveCommitmentKeys(
		commitPoint, true, chanState.ChanType,
		&chanState.LocalChanCfg, &chanState.RemoteChanCfg,
	)

	selfScript, err := input.CommitScriptToSelf(
		csvTimeout, keyRing.ToLocalKey, keyRing.RevocationKey,
	)
	if err != nil {
		return nil, err
	}
	payToUsScriptHash, err := input.WitnessScriptHash(selfScript)
	if err != nil {
		return nil, err
	}

	// Locate the output index of the delayed commitment output back to us.
	// We'll return the details of this output to the caller so they can
	// sweep it once it's mature.
	var (
		delayIndex uint32
		delayOut   *wire.TxOut
	)
	for i, txOut := range commitTx.TxOut {
		if !bytes.Equal(payToUsScriptHash, txOut.PkScript) {
			continue
		}

		delayIndex = uint32(i)
		delayOut = txOut
		break
	}

	// With the necessary information gathered above, create a new sign
	// descriptor which is capable of generating the signature the caller
	// needs to sweep this output. The hash cache, and input index are not
	// set as the caller will decide these values once sweeping the output.
	// If the output is non-existent (dust), have the sign descriptor be
	// nil.
	var commitResolution *CommitOutputResolution
	if delayOut != nil {
		localBalance := delayOut.Value
		commitResolution = &CommitOutputResolution{
			SelfOutPoint: wire.OutPoint{
				Hash:  commitTx.TxHash(),
				Index: delayIndex,
			},
			SelfOutputSignDesc: input.SignDescriptor{
				KeyDesc:       chanState.LocalChanCfg.DelayBasePoint,
				SingleTweak:   keyRing.LocalCommitKeyTweak,
				WitnessScript: selfScript,
				Output: &wire.TxOut{
					PkScript: delayOut.PkScript,
					Value:    localBalance,
				},
				HashType: txscript.SigHashAll,
			},
			MaturityDelay: csvTimeout,
		}
	}

	// Once the delay output has been found (if it exists), then we'll also
	// need to create a series of sign descriptors for any lingering
	// outgoing HTLC's that we'll need to claim as well. If this is after
	// recovery there is not much we can do with HTLCs, so we'll always
	// use what we have in our latest state when extracting resolutions.
	localCommit := chanState.LocalCommitment
	htlcResolutions, err := extractHtlcResolutions(
		chainfee.SatPerKWeight(localCommit.FeePerKw), true, signer,
		localCommit.Htlcs, keyRing, &chanState.LocalChanCfg,
		&chanState.RemoteChanCfg, commitTx, chanState.ChanType,
	)
	if err != nil {
		return nil, err
	}

	anchorResolution, err := NewAnchorResolution(
		chanState, commitTx,
	)
	if err != nil {
		return nil, err
	}

	return &LocalForceCloseSummary{
		ChanPoint:        chanState.FundingOutpoint,
		CloseTx:          commitTx,
		CommitResolution: commitResolution,
		HtlcResolutions:  htlcResolutions,
		ChanSnapshot:     *chanState.Snapshot(),
		AnchorResolution: anchorResolution,
	}, nil
}

// CreateCloseProposal is used by both parties in a cooperative channel close
// workflow to generate proposed close transactions and signatures. This method
// should only be executed once all pending HTLCs (if any) on the channel have
// been cleared/removed. Upon completion, the source channel will shift into
// the "closing" state, which indicates that all incoming/outgoing HTLC
// requests should be rejected. A signature for the closing transaction is
// returned.
//
// TODO(roasbeef): caller should initiate signal to reject all incoming HTLCs,
// settle any in flight.
func (lc *LightningChannel) CreateCloseProposal(proposedFee btcutil.Amount,
	localDeliveryScript []byte,
	remoteDeliveryScript []byte) (input.Signature, *chainhash.Hash,
	btcutil.Amount, error) {

	lc.Lock()
	defer lc.Unlock()

	// If we've already closed the channel, then ignore this request.
	if lc.status == channelClosed {
		// TODO(roasbeef): check to ensure no pending payments
		return nil, nil, 0, ErrChanClosing
	}

	// Get the final balances after subtracting the proposed fee, taking
	// care not to persist the adjusted balance, as the feeRate may change
	// during the channel closing process.
	ourBalance, theirBalance, err := CoopCloseBalance(
		lc.channelState.ChanType, lc.channelState.IsInitiator,
		proposedFee, lc.channelState.LocalCommitment,
	)
	if err != nil {
		return nil, nil, 0, err
	}

	closeTx := CreateCooperativeCloseTx(
		fundingTxIn(lc.channelState), lc.channelState.LocalChanCfg.DustLimit,
		lc.channelState.RemoteChanCfg.DustLimit, ourBalance, theirBalance,
		localDeliveryScript, remoteDeliveryScript,
	)

	// Ensure that the transaction doesn't explicitly violate any
	// consensus rules such as being too big, or having any value with a
	// negative output.
	tx := btcutil.NewTx(closeTx)
	if err := blockchain.CheckTransactionSanity(tx); err != nil {
		return nil, nil, 0, err
	}

	// Finally, sign the completed cooperative closure transaction. As the
	// initiator we'll simply send our signature over to the remote party,
	// using the generated txid to be notified once the closure transaction
	// has been confirmed.
	lc.signDesc.SigHashes = txscript.NewTxSigHashes(closeTx)
	sig, err := lc.Signer.SignOutputRaw(closeTx, lc.signDesc)
	if err != nil {
		return nil, nil, 0, err
	}

	// As everything checks out, indicate in the channel status that a
	// channel closure has been initiated.
	lc.status = channelClosing

	closeTXID := closeTx.TxHash()
	return sig, &closeTXID, ourBalance, nil
}

// CompleteCooperativeClose completes the cooperative closure of the target
// active lightning channel. A fully signed closure transaction as well as the
// signature itself are returned. Additionally, we also return our final
// settled balance, which reflects any fees we may have paid.
//
// NOTE: The passed local and remote sigs are expected to be fully complete
// signatures including the proper sighash byte.
func (lc *LightningChannel) CompleteCooperativeClose(
	localSig, remoteSig input.Signature,
	localDeliveryScript, remoteDeliveryScript []byte,
	proposedFee btcutil.Amount) (*wire.MsgTx, btcutil.Amount, error) {

	lc.Lock()
	defer lc.Unlock()

	// If the channel is already closed, then ignore this request.
	if lc.status == channelClosed {
		// TODO(roasbeef): check to ensure no pending payments
		return nil, 0, ErrChanClosing
	}

	// Get the final balances after subtracting the proposed fee.
	ourBalance, theirBalance, err := CoopCloseBalance(
		lc.channelState.ChanType, lc.channelState.IsInitiator,
		proposedFee, lc.channelState.LocalCommitment,
	)
	if err != nil {
		return nil, 0, err
	}

	// Create the transaction used to return the current settled balance
	// on this active channel back to both parties. In this current model,
	// the initiator pays full fees for the cooperative close transaction.
	closeTx := CreateCooperativeCloseTx(
		fundingTxIn(lc.channelState), lc.channelState.LocalChanCfg.DustLimit,
		lc.channelState.RemoteChanCfg.DustLimit, ourBalance, theirBalance,
		localDeliveryScript, remoteDeliveryScript,
	)

	// Ensure that the transaction doesn't explicitly validate any
	// consensus rules such as being too big, or having any value with a
	// negative output.
	tx := btcutil.NewTx(closeTx)
	if err := blockchain.CheckTransactionSanity(tx); err != nil {
		return nil, 0, err
	}
	hashCache := txscript.NewTxSigHashes(closeTx)

	// Finally, construct the witness stack minding the order of the
	// pubkeys+sigs on the stack.
	ourKey := lc.channelState.LocalChanCfg.MultiSigKey.PubKey.
		SerializeCompressed()
	theirKey := lc.channelState.RemoteChanCfg.MultiSigKey.PubKey.
		SerializeCompressed()
	witness := input.SpendMultiSig(
		lc.signDesc.WitnessScript, ourKey, localSig, theirKey,
		remoteSig,
	)
	closeTx.TxIn[0].Witness = witness

	// Validate the finalized transaction to ensure the output script is
	// properly met, and that the remote peer supplied a valid signature.
	prevOut := lc.signDesc.Output
	vm, err := txscript.NewEngine(prevOut.PkScript, closeTx, 0,
		txscript.StandardVerifyFlags, nil, hashCache, prevOut.Value)
	if err != nil {
		return nil, 0, err
	}
	if err := vm.Execute(); err != nil {
		return nil, 0, err
	}

	// As the transaction is sane, and the scripts are valid we'll mark the
	// channel now as closed as the closure transaction should get into the
	// chain in a timely manner and possibly be re-broadcast by the wallet.
	lc.status = channelClosed

	return closeTx, ourBalance, nil
}

// AnchorResolutions is a set of anchor resolutions that's being used when
// sweeping anchors during local channel force close.
type AnchorResolutions struct {
	// Local is the anchor resolution for the local commitment tx.
	Local *AnchorResolution

	// Remote is the anchor resolution for the remote commitment tx.
	Remote *AnchorResolution

	// RemotePending is the anchor resolution for the remote pending
	// commitment tx. The value will be non-nil iff we've created a new
	// commitment tx for the remote party which they haven't ACKed yet.
	RemotePending *AnchorResolution
}

// NewAnchorResolutions returns a set of anchor resolutions wrapped in the
// struct AnchorResolutions. Because we have no view on the mempool, we can
// only blindly anchor all of these txes down. Caller needs to check the
// returned values against nil to decide whether there exists an anchor
// resolution for local/remote/pending remote commitment txes.
func (lc *LightningChannel) NewAnchorResolutions() (*AnchorResolutions,
	error) {

	lc.Lock()
	defer lc.Unlock()

	resolutions := &AnchorResolutions{}

	// Add anchor for local commitment tx, if any.
	localRes, err := NewAnchorResolution(
		lc.channelState, lc.channelState.LocalCommitment.CommitTx,
	)
	if err != nil {
		return nil, err
	}
	resolutions.Local = localRes

	// Add anchor for remote commitment tx, if any.
	remoteRes, err := NewAnchorResolution(
		lc.channelState, lc.channelState.RemoteCommitment.CommitTx,
	)
	if err != nil {
		return nil, err
	}
	resolutions.Remote = remoteRes

	// Add anchor for remote pending commitment tx, if any.
	remotePendingCommit, err := lc.channelState.RemoteCommitChainTip()
	if err != nil && err != channeldb.ErrNoPendingCommit {
		return nil, err
	}

	if remotePendingCommit != nil {
		remotePendingRes, err := NewAnchorResolution(
			lc.channelState,
			remotePendingCommit.Commitment.CommitTx,
		)
		if err != nil {
			return nil, err
		}
		resolutions.RemotePending = remotePendingRes
	}

	return resolutions, nil
}

// NewAnchorResolution returns the information that is required to sweep the
// local anchor.
func NewAnchorResolution(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx) (*AnchorResolution, error) {

	// Return nil resolution if the channel has no anchors.
	if !chanState.ChanType.HasAnchors() {
		return nil, nil
	}

	// Derive our local anchor script.
	localAnchor, _, err := CommitScriptAnchors(
		&chanState.LocalChanCfg, &chanState.RemoteChanCfg,
	)
	if err != nil {
		return nil, err
	}

	// Look up the script on the commitment transaction. It may not be
	// present if there is no output paying to us.
	found, index := input.FindScriptOutputIndex(commitTx, localAnchor.PkScript)
	if !found {
		return nil, nil
	}

	outPoint := &wire.OutPoint{
		Hash:  commitTx.TxHash(),
		Index: index,
	}

	// Instantiate the sign descriptor that allows sweeping of the anchor.
	signDesc := &input.SignDescriptor{
		KeyDesc:       chanState.LocalChanCfg.MultiSigKey,
		WitnessScript: localAnchor.WitnessScript,
		Output: &wire.TxOut{
			PkScript: localAnchor.PkScript,
			Value:    int64(anchorSize),
		},
		HashType: txscript.SigHashAll,
	}

	// Calculate commit tx weight. This commit tx doesn't yet include the
	// witness spending the funding output, so we add the (worst case)
	// weight for that too.
	utx := btcutil.NewTx(commitTx)
	weight := blockchain.GetTransactionWeight(utx) +
		input.WitnessCommitmentTxWeight

	// Calculate commit tx fee.
	fee := chanState.Capacity
	for _, out := range commitTx.TxOut {
		fee -= btcutil.Amount(out.Value)
	}

	return &AnchorResolution{
		CommitAnchor:         *outPoint,
		AnchorSignDescriptor: *signDesc,
		CommitWeight:         weight,
		CommitFee:            fee,
	}, nil
}

// AvailableBalance returns the current balance available for sending within
// the channel. By available balance, we mean that if at this very instance a
// new commitment were to be created which evals all the log entries, what
// would our available balance for adding an additional HTLC be. It takes into
// account the fee that must be paid for adding this HTLC (if we're the
// initiator), and that we cannot spend from the channel reserve. This method
// is useful when deciding if a given channel can accept an HTLC in the
// multi-hop forwarding scenario.
func (lc *LightningChannel) AvailableBalance() lnwire.MilliSatoshi {
	lc.RLock()
	defer lc.RUnlock()

	bal, _ := lc.availableBalance()
	return bal
}

// availableBalance is the private, non mutexed version of AvailableBalance.
// This method is provided so methods that already hold the lock can access
// this method. Additionally, the total weight of the next to be created
// commitment is returned for accounting purposes.
func (lc *LightningChannel) availableBalance() (lnwire.MilliSatoshi, int64) {
	// We'll grab the current set of log updates that the remote has
	// ACKed.
	remoteACKedIndex := lc.localCommitChain.tip().theirMessageIndex
	htlcView := lc.fetchHTLCView(remoteACKedIndex,
		lc.localUpdateLog.logIndex)

	// Calculate our available balance from our local commitment.
	// TODO(halseth): could reuse parts validateCommitmentSanity to do this
	// balance calculation, as most of the logic is the same.
	//
	// NOTE: This is not always accurate, since the remote node can always
	// add updates concurrently, causing our balance to go down if we're
	// the initiator, but this is a problem on the protocol level.
	ourLocalCommitBalance, commitWeight := lc.availableCommitmentBalance(
		htlcView, false,
	)

	// Do the same calculation from the remote commitment point of view.
	ourRemoteCommitBalance, _ := lc.availableCommitmentBalance(
		htlcView, true,
	)

	// Return which ever balance is lowest.
	if ourRemoteCommitBalance < ourLocalCommitBalance {
		return ourRemoteCommitBalance, commitWeight
	}

	return ourLocalCommitBalance, commitWeight
}

// availableCommitmentBalance attempts to calculate the balance we have
// available for HTLCs on the local/remote commitment given the htlcView. To
// account for sending HTLCs of different sizes, it will report the balance
// available for sending non-dust HTLCs, which will be manifested on the
// commitment, increasing the commitment fee we must pay as an initiator,
// eating into our balance. It will make sure we won't violate the channel
// reserve constraints for this amount.
func (lc *LightningChannel) availableCommitmentBalance(view *htlcView,
	remoteChain bool) (lnwire.MilliSatoshi, int64) {

	// Compute the current balances for this commitment. This will take
	// into account HTLCs to determine the commit weight, which the
	// initiator must pay the fee for.
	ourBalance, theirBalance, commitWeight, filteredView, err := lc.computeView(
		view, remoteChain, false,
	)
	if err != nil {
		lc.log.Errorf("Unable to fetch available balance: %v", err)
		return 0, 0
	}

	// We can never spend from the channel reserve, so we'll subtract it
	// from our available balance.
	ourReserve := lnwire.NewMSatFromSatoshis(
		lc.channelState.LocalChanCfg.ChanReserve,
	)
	if ourReserve <= ourBalance {
		ourBalance -= ourReserve
	} else {
		ourBalance = 0
	}

	// Calculate the commitment fee in the case where we would add another
	// HTLC to the commitment, as only the balance remaining after this fee
	// has been paid is actually available for sending.
	feePerKw := filteredView.feePerKw
	htlcCommitFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(commitWeight + input.HTLCWeight),
	)

	// If we are the channel initiator, we must to subtract this commitment
	// fee from our available balance in order to ensure we can afford both
	// the value of the HTLC and the additional commitment fee from adding
	// the HTLC.
	if lc.channelState.IsInitiator {
		// There is an edge case where our non-zero balance is lower
		// than the htlcCommitFee, where we could still be sending dust
		// HTLCs, but we return 0 in this case. This is to avoid
		// lowering our balance even further, as this takes us into a
		// bad state wehere neither we nor our channel counterparty can
		// add HTLCs.
		if ourBalance < htlcCommitFee {
			return 0, commitWeight
		}

		return ourBalance - htlcCommitFee, commitWeight
	}

	// If we're not the initiator, we must check whether the remote has
	// enough balance to pay for the fee of our HTLC. We'll start by also
	// subtracting our counterparty's reserve from their balance.
	theirReserve := lnwire.NewMSatFromSatoshis(
		lc.channelState.RemoteChanCfg.ChanReserve,
	)
	if theirReserve <= theirBalance {
		theirBalance -= theirReserve
	} else {
		theirBalance = 0
	}

	// We'll use the dustlimit and htlcFee to find the largest HTLC value
	// that will be considered dust on the commitment.
	dustlimit := lnwire.NewMSatFromSatoshis(
		lc.channelState.LocalChanCfg.DustLimit,
	)

	// For an extra HTLC fee to be paid on our commitment, the HTLC must be
	// large enough to make a non-dust HTLC timeout transaction.
	htlcFee := lnwire.NewMSatFromSatoshis(
		HtlcTimeoutFee(lc.channelState.ChanType, feePerKw),
	)

	// If we are looking at the remote commitment, we must use the remote
	// dust limit and the fee for adding an HTLC success transaction.
	if remoteChain {
		dustlimit = lnwire.NewMSatFromSatoshis(
			lc.channelState.RemoteChanCfg.DustLimit,
		)
		htlcFee = lnwire.NewMSatFromSatoshis(
			HtlcSuccessFee(lc.channelState.ChanType, feePerKw),
		)
	}

	// The HTLC output will be manifested on the commitment if it
	// is non-dust after paying the HTLC fee.
	nonDustHtlcAmt := dustlimit + htlcFee

	// If they cannot pay the fee if we add another non-dust HTLC, we'll
	// report our available balance just below the non-dust amount, to
	// avoid attempting HTLCs larger than this size.
	if theirBalance < htlcCommitFee && ourBalance >= nonDustHtlcAmt {
		ourBalance = nonDustHtlcAmt - 1
	}

	return ourBalance, commitWeight
}

// StateSnapshot returns a snapshot of the current fully committed state within
// the channel.
func (lc *LightningChannel) StateSnapshot() *channeldb.ChannelSnapshot {
	lc.RLock()
	defer lc.RUnlock()

	return lc.channelState.Snapshot()
}

// validateFeeRate ensures that if the passed fee is applied to the channel,
// and a new commitment is created (which evaluates this fee), then the
// initiator of the channel does not dip below their reserve.
func (lc *LightningChannel) validateFeeRate(feePerKw chainfee.SatPerKWeight) error {
	// We'll ensure that we can accommodate this new fee change, yet still
	// be above our reserve balance. Otherwise, we'll reject the fee
	// update.
	availableBalance, txWeight := lc.availableBalance()
	oldFee := lnwire.NewMSatFromSatoshis(lc.localCommitChain.tip().fee)

	// Our base balance is the total amount of satoshis we can commit
	// towards fees before factoring in the channel reserve.
	baseBalance := availableBalance + oldFee

	// Using the weight of the commitment transaction if we were to create
	// a commitment now, we'll compute our remaining balance if we apply
	// this new fee update.
	newFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(txWeight),
	)

	// If the total fee exceeds our available balance (taking into account
	// the fee from the last state), then we'll reject this update as it
	// would mean we need to trim our entire output.
	if newFee > baseBalance {
		return fmt.Errorf("cannot apply fee_update=%v sat/kw, new fee "+
			"of %v is greater than balance of %v", int64(feePerKw),
			newFee, baseBalance)
	}

	// If this new balance is below our reserve, then we can't accommodate
	// the fee change, so we'll reject it.
	balanceAfterFee := baseBalance - newFee
	if balanceAfterFee.ToSatoshis() < lc.channelState.LocalChanCfg.ChanReserve {
		return fmt.Errorf("cannot apply fee_update=%v sat/kw, "+
			"new balance=%v would dip below channel reserve=%v",
			int64(feePerKw),
			balanceAfterFee.ToSatoshis(),
			lc.channelState.LocalChanCfg.ChanReserve)
	}

	// TODO(halseth): should fail if fee update is unreasonable,
	// as specified in BOLT#2.
	//  * COMMENT(roasbeef): can cross-check with our ideal fee rate

	return nil
}

// UpdateFee initiates a fee update for this channel. Must only be called by
// the channel initiator, and must be called before sending update_fee to
// the remote.
func (lc *LightningChannel) UpdateFee(feePerKw chainfee.SatPerKWeight) error {
	lc.Lock()
	defer lc.Unlock()

	// Only initiator can send fee update, so trying to send one as
	// non-initiator will fail.
	if !lc.channelState.IsInitiator {
		return fmt.Errorf("local fee update as non-initiator")
	}

	// Ensure that the passed fee rate meets our current requirements.
	if err := lc.validateFeeRate(feePerKw); err != nil {
		return err
	}

	pd := &PaymentDescriptor{
		LogIndex:  lc.localUpdateLog.logIndex,
		Amount:    lnwire.NewMSatFromSatoshis(btcutil.Amount(feePerKw)),
		EntryType: FeeUpdate,
	}

	lc.localUpdateLog.appendUpdate(pd)

	return nil
}

// ReceiveUpdateFee handles an updated fee sent from remote. This method will
// return an error if called as channel initiator.
func (lc *LightningChannel) ReceiveUpdateFee(feePerKw chainfee.SatPerKWeight) error {
	lc.Lock()
	defer lc.Unlock()

	// Only initiator can send fee update, and we must fail if we receive
	// fee update as initiator
	if lc.channelState.IsInitiator {
		return fmt.Errorf("received fee update as initiator")
	}

	// TODO(roasbeef): or just modify to use the other balance?
	pd := &PaymentDescriptor{
		LogIndex:  lc.remoteUpdateLog.logIndex,
		Amount:    lnwire.NewMSatFromSatoshis(btcutil.Amount(feePerKw)),
		EntryType: FeeUpdate,
	}

	lc.remoteUpdateLog.appendUpdate(pd)

	return nil
}

// generateRevocation generates the revocation message for a given height.
func (lc *LightningChannel) generateRevocation(height uint64) (*lnwire.RevokeAndAck,
	error) {

	// Now that we've accept a new state transition, we send the remote
	// party the revocation for our current commitment state.
	revocationMsg := &lnwire.RevokeAndAck{}
	commitSecret, err := lc.channelState.RevocationProducer.AtIndex(height)
	if err != nil {
		return nil, err
	}
	copy(revocationMsg.Revocation[:], commitSecret[:])

	// Along with this revocation, we'll also send the _next_ commitment
	// point that the remote party should use to create our next commitment
	// transaction. We use a +2 here as we already gave them a look ahead
	// of size one after the FundingLocked message was sent:
	//
	// 0: current revocation, 1: their "next" revocation, 2: this revocation
	//
	// We're revoking the current revocation. Once they receive this
	// message they'll set the "current" revocation for us to their stored
	// "next" revocation, and this revocation will become their new "next"
	// revocation.
	//
	// Put simply in the window slides to the left by one.
	nextCommitSecret, err := lc.channelState.RevocationProducer.AtIndex(
		height + 2,
	)
	if err != nil {
		return nil, err
	}

	revocationMsg.NextRevocationKey = input.ComputeCommitmentPoint(nextCommitSecret[:])
	revocationMsg.ChanID = lnwire.NewChanIDFromOutPoint(
		&lc.channelState.FundingOutpoint)

	return revocationMsg, nil
}

// CreateCooperativeCloseTx creates a transaction which if signed by both
// parties, then broadcast cooperatively closes an active channel. The creation
// of the closure transaction is modified by a boolean indicating if the party
// constructing the channel is the initiator of the closure. Currently it is
// expected that the initiator pays the transaction fees for the closing
// transaction in full.
func CreateCooperativeCloseTx(fundingTxIn wire.TxIn,
	localDust, remoteDust, ourBalance, theirBalance btcutil.Amount,
	ourDeliveryScript, theirDeliveryScript []byte) *wire.MsgTx {

	// Construct the transaction to perform a cooperative closure of the
	// channel. In the event that one side doesn't have any settled funds
	// within the channel then a refund output for that particular side can
	// be omitted.
	closeTx := wire.NewMsgTx(2)
	closeTx.AddTxIn(&fundingTxIn)

	// Create both cooperative closure outputs, properly respecting the
	// dust limits of both parties.
	if ourBalance >= localDust {
		closeTx.AddTxOut(&wire.TxOut{
			PkScript: ourDeliveryScript,
			Value:    int64(ourBalance),
		})
	}
	if theirBalance >= remoteDust {
		closeTx.AddTxOut(&wire.TxOut{
			PkScript: theirDeliveryScript,
			Value:    int64(theirBalance),
		})
	}

	txsort.InPlaceSort(closeTx)

	return closeTx
}

// CalcFee returns the commitment fee to use for the given
// fee rate (fee-per-kw).
func (lc *LightningChannel) CalcFee(feeRate chainfee.SatPerKWeight) btcutil.Amount {
	return feeRate.FeeForWeight(CommitWeight(lc.channelState.ChanType))
}

// MaxFeeRate returns the maximum fee rate given an allocation of the channel
// initiator's spendable balance. This can be useful to determine when we should
// stop proposing fee updates that exceed our maximum allocation. We also take
// a fee rate cap that should be used for anchor type channels.
//
// NOTE: This should only be used for channels in which the local commitment is
// the initiator.
func (lc *LightningChannel) MaxFeeRate(maxAllocation float64,
	maxAnchorFeeRate chainfee.SatPerKWeight) chainfee.SatPerKWeight {

	lc.RLock()
	defer lc.RUnlock()

	// The maximum fee depends of the available balance that can be
	// committed towards fees.
	commit := lc.channelState.LocalCommitment
	feeBalance := float64(
		commit.LocalBalance.ToSatoshis() + commit.CommitFee,
	)
	maxFee := feeBalance * maxAllocation

	// Ensure the fee rate doesn't dip below the fee floor.
	_, weight := lc.availableBalance()
	maxFeeRate := maxFee / (float64(weight) / 1000)
	feeRate := chainfee.SatPerKWeight(
		math.Max(maxFeeRate, float64(chainfee.FeePerKwFloor)),
	)

	// Cap anchor fee rates.
	if lc.channelState.ChanType.HasAnchors() && feeRate > maxAnchorFeeRate {
		return maxAnchorFeeRate
	}

	return feeRate
}

// RemoteNextRevocation returns the channelState's RemoteNextRevocation.
func (lc *LightningChannel) RemoteNextRevocation() *btcec.PublicKey {
	lc.RLock()
	defer lc.RUnlock()

	return lc.channelState.RemoteNextRevocation
}

// IsInitiator returns true if we were the ones that initiated the funding
// workflow which led to the creation of this channel. Otherwise, it returns
// false.
func (lc *LightningChannel) IsInitiator() bool {
	lc.RLock()
	defer lc.RUnlock()

	return lc.channelState.IsInitiator
}

// CommitFeeRate returns the current fee rate of the commitment transaction in
// units of sat-per-kw.
func (lc *LightningChannel) CommitFeeRate() chainfee.SatPerKWeight {
	lc.RLock()
	defer lc.RUnlock()

	return chainfee.SatPerKWeight(lc.channelState.LocalCommitment.FeePerKw)
}

// IsPending returns true if the channel's funding transaction has been fully
// confirmed, and false otherwise.
func (lc *LightningChannel) IsPending() bool {
	lc.RLock()
	defer lc.RUnlock()

	return lc.channelState.IsPending
}

// State provides access to the channel's internal state.
func (lc *LightningChannel) State() *channeldb.OpenChannel {
	return lc.channelState
}

// MarkBorked marks the event when the channel as reached an irreconcilable
// state, such as a channel breach or state desynchronization. Borked channels
// should never be added to the switch.
func (lc *LightningChannel) MarkBorked() error {
	lc.Lock()
	defer lc.Unlock()

	return lc.channelState.MarkBorked()
}

// MarkCommitmentBroadcasted marks the channel as a commitment transaction has
// been broadcast, either our own or the remote, and we should watch the chain
// for it to confirm before taking any further action. It takes a boolean which
// indicates whether we initiated the close.
func (lc *LightningChannel) MarkCommitmentBroadcasted(tx *wire.MsgTx,
	locallyInitiated bool) error {

	lc.Lock()
	defer lc.Unlock()

	return lc.channelState.MarkCommitmentBroadcasted(tx, locallyInitiated)
}

// MarkCoopBroadcasted marks the channel as a cooperative close transaction has
// been broadcast, and that we should watch the chain for it to confirm before
// taking any further action. It takes a locally initiated bool which is true
// if we initiated the cooperative close.
func (lc *LightningChannel) MarkCoopBroadcasted(tx *wire.MsgTx,
	localInitiated bool) error {

	lc.Lock()
	defer lc.Unlock()

	return lc.channelState.MarkCoopBroadcasted(tx, localInitiated)
}

// MarkDataLoss marks sets the channel status to LocalDataLoss and stores the
// passed commitPoint for use to retrieve funds in case the remote force closes
// the channel.
func (lc *LightningChannel) MarkDataLoss(commitPoint *btcec.PublicKey) error {
	lc.Lock()
	defer lc.Unlock()

	return lc.channelState.MarkDataLoss(commitPoint)
}

// ActiveHtlcs returns a slice of HTLC's which are currently active on *both*
// commitment transactions.
func (lc *LightningChannel) ActiveHtlcs() []channeldb.HTLC {
	lc.RLock()
	defer lc.RUnlock()

	return lc.channelState.ActiveHtlcs()
}

// LocalChanReserve returns our local ChanReserve requirement for the remote party.
func (lc *LightningChannel) LocalChanReserve() btcutil.Amount {
	return lc.channelState.LocalChanCfg.ChanReserve
}

// NextLocalHtlcIndex returns the next unallocated local htlc index. To ensure
// this always returns the next index that has been not been allocated, this
// will first try to examine any pending commitments, before falling back to the
// last locked-in local commitment.
func (lc *LightningChannel) NextLocalHtlcIndex() (uint64, error) {
	lc.RLock()
	defer lc.RUnlock()

	return lc.channelState.NextLocalHtlcIndex()
}

// FwdMinHtlc returns the minimum HTLC value required by the remote node, i.e.
// the minimum value HTLC we can forward on this channel.
func (lc *LightningChannel) FwdMinHtlc() lnwire.MilliSatoshi {
	return lc.channelState.LocalChanCfg.MinHTLC
}

// unsignedLocalUpdates retrieves the unsigned local updates that we should
// store upon receiving a revocation. This function is called from
// ReceiveRevocation. remoteMessageIndex is the height into the local update
// log that the remote commitment chain tip includes. localMessageIndex
// is the height into the local update log that the local commitment tail
// includes. Our local updates that are unsigned by the remote should
// have height greater than or equal to localMessageIndex (not on our commit),
// and height less than remoteMessageIndex (on the remote commit).
//
// NOTE: remoteMessageIndex is the height on the tip because this is called
// before the tail is advanced to the tip during ReceiveRevocation.
func (lc *LightningChannel) unsignedLocalUpdates(remoteMessageIndex,
	localMessageIndex uint64, chanID lnwire.ChannelID) []channeldb.LogUpdate {

	var localPeerUpdates []channeldb.LogUpdate
	for e := lc.localUpdateLog.Front(); e != nil; e = e.Next() {
		pd := e.Value.(*PaymentDescriptor)

		// We don't save add updates as they are restored from the
		// remote commitment in restoreStateLogs.
		if pd.EntryType == Add {
			continue
		}

		// This is a settle/fail that is on the remote commitment, but
		// not on the local commitment. We expect this update to be
		// covered in the next commitment signature that the remote
		// sends.
		if pd.LogIndex < remoteMessageIndex && pd.LogIndex >= localMessageIndex {
			logUpdate := channeldb.LogUpdate{
				LogIndex: pd.LogIndex,
			}

			switch pd.EntryType {
			case FeeUpdate:
				logUpdate.UpdateMsg = &lnwire.UpdateFee{
					ChanID:   chanID,
					FeePerKw: uint32(pd.Amount.ToSatoshis()),
				}
			case Settle:
				logUpdate.UpdateMsg = &lnwire.UpdateFulfillHTLC{
					ChanID:          chanID,
					ID:              pd.ParentIndex,
					PaymentPreimage: pd.RPreimage,
				}
			case Fail:
				logUpdate.UpdateMsg = &lnwire.UpdateFailHTLC{
					ChanID: chanID,
					ID:     pd.ParentIndex,
					Reason: pd.FailReason,
				}
			case MalformedFail:
				logUpdate.UpdateMsg = &lnwire.UpdateFailMalformedHTLC{
					ChanID:       chanID,
					ID:           pd.ParentIndex,
					ShaOnionBlob: pd.ShaOnionBlob,
					FailureCode:  pd.FailCode,
				}
			}

			localPeerUpdates = append(localPeerUpdates, logUpdate)
		}
	}

	return localPeerUpdates
}
