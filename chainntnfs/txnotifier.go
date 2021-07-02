package chainntnfs

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/channeldb"
)

const (
	// ReorgSafetyLimit is the chain depth beyond which it is assumed a
	// block will not be reorganized out of the chain. This is used to
	// determine when to prune old confirmation requests so that reorgs are
	// handled correctly. The average number of blocks in a day is a
	// reasonable value to use.
	ReorgSafetyLimit = 144

	// MaxNumConfs is the maximum number of confirmations that can be
	// requested on a transaction.
	MaxNumConfs = ReorgSafetyLimit
)

var (
	// ZeroHash is the value that should be used as the txid when
	// registering for the confirmation of a script on-chain. This allows
	// the notifier to match _and_ dispatch upon the inclusion of the script
	// on-chain, rather than the txid.
	ZeroHash chainhash.Hash

	// ZeroOutPoint is the value that should be used as the outpoint when
	// registering for the spend of a script on-chain. This allows the
	// notifier to match _and_ dispatch upon detecting the spend of the
	// script on-chain, rather than the outpoint.
	ZeroOutPoint wire.OutPoint
)

var (
	// ErrTxNotifierExiting is an error returned when attempting to interact
	// with the TxNotifier but it been shut down.
	ErrTxNotifierExiting = errors.New("TxNotifier is exiting")

	// ErrNoScript is an error returned when a confirmation/spend
	// registration is attempted without providing an accompanying output
	// script.
	ErrNoScript = errors.New("an output script must be provided")

	// ErrNoHeightHint is an error returned when a confirmation/spend
	// registration is attempted without providing an accompanying height
	// hint.
	ErrNoHeightHint = errors.New("a height hint greater than 0 must be " +
		"provided")

	// ErrNumConfsOutOfRange is an error returned when a confirmation/spend
	// registration is attempted and the number of confirmations provided is
	// out of range.
	ErrNumConfsOutOfRange = fmt.Errorf("number of confirmations must be "+
		"between %d and %d", 1, MaxNumConfs)
)

// rescanState indicates the progression of a registration before the notifier
// can begin dispatching confirmations at tip.
type rescanState byte

const (
	// rescanNotStarted is the initial state, denoting that a historical
	// dispatch may be required.
	rescanNotStarted rescanState = iota

	// rescanPending indicates that a dispatch has already been made, and we
	// are waiting for its completion. No other rescans should be dispatched
	// while in this state.
	rescanPending

	// rescanComplete signals either that a rescan was dispatched and has
	// completed, or that we began watching at tip immediately. In either
	// case, the notifier can only dispatch notifications from tip when in
	// this state.
	rescanComplete
)

// confNtfnSet holds all known, registered confirmation notifications for a
// txid/output script. If duplicates notifications are requested, only one
// historical dispatch will be spawned to ensure redundant scans are not
// permitted. A single conf detail will be constructed and dispatched to all
// interested
// clients.
type confNtfnSet struct {
	// ntfns keeps tracks of all the active client notification requests for
	// a transaction/output script
	ntfns map[uint64]*ConfNtfn

	// rescanStatus represents the current rescan state for the
	// transaction/output script.
	rescanStatus rescanState

	// details serves as a cache of the confirmation details of a
	// transaction that we'll use to determine if a transaction/output
	// script has already confirmed at the time of registration.
	// details is also used to make sure that in case of an address reuse
	// (funds sent to a previously confirmed script) no additional
	// notification is registered which would lead to an inconsistent state.
	details *TxConfirmation
}

// newConfNtfnSet constructs a fresh confNtfnSet for a group of clients
// interested in a notification for a particular txid.
func newConfNtfnSet() *confNtfnSet {
	return &confNtfnSet{
		ntfns:        make(map[uint64]*ConfNtfn),
		rescanStatus: rescanNotStarted,
	}
}

// spendNtfnSet holds all known, registered spend notifications for a spend
// request (outpoint/output script). If duplicate notifications are requested,
// only one historical dispatch will be spawned to ensure redundant scans are
// not permitted.
type spendNtfnSet struct {
	// ntfns keeps tracks of all the active client notification requests for
	// an outpoint/output script.
	ntfns map[uint64]*SpendNtfn

	// rescanStatus represents the current rescan state for the spend
	// request (outpoint/output script).
	rescanStatus rescanState

	// details serves as a cache of the spend details for an outpoint/output
	// script that we'll use to determine if it has already been spent at
	// the time of registration.
	details *SpendDetail
}

// newSpendNtfnSet constructs a new spend notification set.
func newSpendNtfnSet() *spendNtfnSet {
	return &spendNtfnSet{
		ntfns:        make(map[uint64]*SpendNtfn),
		rescanStatus: rescanNotStarted,
	}
}

// ConfRequest encapsulates a request for a confirmation notification of either
// a txid or output script.
type ConfRequest struct {
	// TxID is the hash of the transaction for which confirmation
	// notifications are requested. If set to a zero hash, then a
	// confirmation notification will be dispatched upon inclusion of the
	// _script_, rather than the txid.
	TxID chainhash.Hash

	// PkScript is the public key script of an outpoint created in this
	// transaction.
	PkScript txscript.PkScript
}

// NewConfRequest creates a request for a confirmation notification of either a
// txid or output script. A nil txid or an allocated ZeroHash can be used to
// dispatch the confirmation notification on the script.
func NewConfRequest(txid *chainhash.Hash, pkScript []byte) (ConfRequest, error) {
	var r ConfRequest
	outputScript, err := txscript.ParsePkScript(pkScript)
	if err != nil {
		return r, err
	}

	// We'll only set a txid for which we'll dispatch a confirmation
	// notification on this request if one was provided. Otherwise, we'll
	// default to dispatching on the confirmation of the script instead.
	if txid != nil {
		r.TxID = *txid
	}
	r.PkScript = outputScript

	return r, nil
}

// String returns the string representation of the ConfRequest.
func (r ConfRequest) String() string {
	if r.TxID != ZeroHash {
		return fmt.Sprintf("txid=%v", r.TxID)
	}
	return fmt.Sprintf("script=%v", r.PkScript)
}

// ConfHintKey returns the key that will be used to index the confirmation
// request's hint within the height hint cache.
func (r ConfRequest) ConfHintKey() ([]byte, error) {
	if r.TxID == ZeroHash {
		return r.PkScript.Script(), nil
	}

	var txid bytes.Buffer
	if err := channeldb.WriteElement(&txid, r.TxID); err != nil {
		return nil, err
	}

	return txid.Bytes(), nil
}

// MatchesTx determines whether the given transaction satisfies the confirmation
// request. If the confirmation request is for a script, then we'll check all of
// the outputs of the transaction to determine if it matches. Otherwise, we'll
// match on the txid.
func (r ConfRequest) MatchesTx(tx *wire.MsgTx) bool {
	scriptMatches := func() bool {
		pkScript := r.PkScript.Script()
		for _, txOut := range tx.TxOut {
			if bytes.Equal(txOut.PkScript, pkScript) {
				return true
			}
		}

		return false
	}

	if r.TxID != ZeroHash {
		return r.TxID == tx.TxHash() && scriptMatches()
	}

	return scriptMatches()
}

// ConfNtfn represents a notifier client's request to receive a notification
// once the target transaction/output script gets sufficient confirmations. The
// client is asynchronously notified via the ConfirmationEvent channels.
type ConfNtfn struct {
	// ConfID uniquely identifies the confirmation notification request for
	// the specified transaction/output script.
	ConfID uint64

	// ConfRequest represents either the txid or script we should detect
	// inclusion of within the chain.
	ConfRequest

	// NumConfirmations is the number of confirmations after which the
	// notification is to be sent.
	NumConfirmations uint32

	// Event contains references to the channels that the notifications are to
	// be sent over.
	Event *ConfirmationEvent

	// HeightHint is the minimum height in the chain that we expect to find
	// this txid.
	HeightHint uint32

	// dispatched is false if the confirmed notification has not been sent yet.
	dispatched bool
}

// HistoricalConfDispatch parameterizes a manual rescan for a particular
// transaction/output script. The parameters include the start and end block
// heights specifying the range of blocks to scan.
type HistoricalConfDispatch struct {
	// ConfRequest represents either the txid or script we should detect
	// inclusion of within the chain.
	ConfRequest

	// StartHeight specifies the block height at which to begin the
	// historical rescan.
	StartHeight uint32

	// EndHeight specifies the last block height (inclusive) that the
	// historical scan should consider.
	EndHeight uint32
}

// ConfRegistration encompasses all of the information required for callers to
// retrieve details about a confirmation event.
type ConfRegistration struct {
	// Event contains references to the channels that the notifications are
	// to be sent over.
	Event *ConfirmationEvent

	// HistoricalDispatch, if non-nil, signals to the client who registered
	// the notification that they are responsible for attempting to manually
	// rescan blocks for the txid/output script between the start and end
	// heights.
	HistoricalDispatch *HistoricalConfDispatch

	// Height is the height of the TxNotifier at the time the confirmation
	// notification was registered. This can be used so that backends can
	// request to be notified of confirmations from this point forwards.
	Height uint32
}

// SpendRequest encapsulates a request for a spend notification of either an
// outpoint or output script.
type SpendRequest struct {
	// OutPoint is the outpoint for which a client has requested a spend
	// notification for. If set to a zero outpoint, then a spend
	// notification will be dispatched upon detecting the spend of the
	// _script_, rather than the outpoint.
	OutPoint wire.OutPoint

	// PkScript is the script of the outpoint. If a zero outpoint is set,
	// then this can be an arbitrary script.
	PkScript txscript.PkScript
}

// NewSpendRequest creates a request for a spend notification of either an
// outpoint or output script. A nil outpoint or an allocated ZeroOutPoint can be
// used to dispatch the confirmation notification on the script.
func NewSpendRequest(op *wire.OutPoint, pkScript []byte) (SpendRequest, error) {
	var r SpendRequest
	outputScript, err := txscript.ParsePkScript(pkScript)
	if err != nil {
		return r, err
	}

	// We'll only set an outpoint for which we'll dispatch a spend
	// notification on this request if one was provided. Otherwise, we'll
	// default to dispatching on the spend of the script instead.
	if op != nil {
		r.OutPoint = *op
	}
	r.PkScript = outputScript

	return r, nil
}

// String returns the string representation of the SpendRequest.
func (r SpendRequest) String() string {
	if r.OutPoint != ZeroOutPoint {
		return fmt.Sprintf("outpoint=%v, script=%v", r.OutPoint,
			r.PkScript)
	}
	return fmt.Sprintf("outpoint=<zero>, script=%v", r.PkScript)
}

// SpendHintKey returns the key that will be used to index the spend request's
// hint within the height hint cache.
func (r SpendRequest) SpendHintKey() ([]byte, error) {
	if r.OutPoint == ZeroOutPoint {
		return r.PkScript.Script(), nil
	}

	var outpoint bytes.Buffer
	err := channeldb.WriteElement(&outpoint, r.OutPoint)
	if err != nil {
		return nil, err
	}

	return outpoint.Bytes(), nil
}

// MatchesTx determines whether the given transaction satisfies the spend
// request. If the spend request is for an outpoint, then we'll check all of
// the outputs being spent by the inputs of the transaction to determine if it
// matches. Otherwise, we'll need to match on the output script being spent, so
// we'll recompute it for each input of the transaction to determine if it
// matches.
func (r SpendRequest) MatchesTx(tx *wire.MsgTx) (bool, uint32, error) {
	if r.OutPoint != ZeroOutPoint {
		for i, txIn := range tx.TxIn {
			if txIn.PreviousOutPoint == r.OutPoint {
				return true, uint32(i), nil
			}
		}

		return false, 0, nil
	}

	for i, txIn := range tx.TxIn {
		pkScript, err := txscript.ComputePkScript(
			txIn.SignatureScript, txIn.Witness,
		)
		if err == txscript.ErrUnsupportedScriptType {
			continue
		}
		if err != nil {
			return false, 0, err
		}

		if bytes.Equal(pkScript.Script(), r.PkScript.Script()) {
			return true, uint32(i), nil
		}
	}

	return false, 0, nil
}

// SpendNtfn represents a client's request to receive a notification once an
// outpoint/output script has been spent on-chain. The client is asynchronously
// notified via the SpendEvent channels.
type SpendNtfn struct {
	// SpendID uniquely identies the spend notification request for the
	// specified outpoint/output script.
	SpendID uint64

	// SpendRequest represents either the outpoint or script we should
	// detect the spend of.
	SpendRequest

	// Event contains references to the channels that the notifications are
	// to be sent over.
	Event *SpendEvent

	// HeightHint is the earliest height in the chain that we expect to find
	// the spending transaction of the specified outpoint/output script.
	// This value will be overridden by the spend hint cache if it contains
	// an entry for it.
	HeightHint uint32

	// dispatched signals whether a spend notification has been disptached
	// to the client.
	dispatched bool
}

// HistoricalSpendDispatch parameterizes a manual rescan to determine the
// spending details (if any) of an outpoint/output script. The parameters
// include the start and end block heights specifying the range of blocks to
// scan.
type HistoricalSpendDispatch struct {
	// SpendRequest represents either the outpoint or script we should
	// detect the spend of.
	SpendRequest

	// StartHeight specified the block height at which to begin the
	// historical rescan.
	StartHeight uint32

	// EndHeight specifies the last block height (inclusive) that the
	// historical rescan should consider.
	EndHeight uint32
}

// SpendRegistration encompasses all of the information required for callers to
// retrieve details about a spend event.
type SpendRegistration struct {
	// Event contains references to the channels that the notifications are
	// to be sent over.
	Event *SpendEvent

	// HistoricalDispatch, if non-nil, signals to the client who registered
	// the notification that they are responsible for attempting to manually
	// rescan blocks for the txid/output script between the start and end
	// heights.
	HistoricalDispatch *HistoricalSpendDispatch

	// Height is the height of the TxNotifier at the time the spend
	// notification was registered. This can be used so that backends can
	// request to be notified of spends from this point forwards.
	Height uint32
}

// TxNotifier is a struct responsible for delivering transaction notifications
// to subscribers. These notifications can be of two different types:
// transaction/output script confirmations and/or outpoint/output script spends.
// The TxNotifier will watch the blockchain as new blocks come in, in order to
// satisfy its client requests.
type TxNotifier struct {
	confClientCounter  uint64 // To be used atomically.
	spendClientCounter uint64 // To be used atomically.

	// currentHeight is the height of the tracked blockchain. It is used to
	// determine the number of confirmations a tx has and ensure blocks are
	// connected and disconnected in order.
	currentHeight uint32

	// reorgSafetyLimit is the chain depth beyond which it is assumed a
	// block will not be reorganized out of the chain. This is used to
	// determine when to prune old notification requests so that reorgs are
	// handled correctly. The coinbase maturity period is a reasonable value
	// to use.
	reorgSafetyLimit uint32

	// reorgDepth is the depth of a chain organization that this system is
	// being informed of. This is incremented as long as a sequence of
	// blocks are disconnected without being interrupted by a new block.
	reorgDepth uint32

	// confNotifications is an index of confirmation notification requests
	// by transaction hash/output script.
	confNotifications map[ConfRequest]*confNtfnSet

	// confsByInitialHeight is an index of watched transactions/output
	// scripts by the height that they are included at in the chain. This
	// is tracked so that incorrect notifications are not sent if a
	// transaction/output script is reorged out of the chain and so that
	// negative confirmations can be recognized.
	confsByInitialHeight map[uint32]map[ConfRequest]struct{}

	// ntfnsByConfirmHeight is an index of notification requests by the
	// height at which the transaction/output script will have sufficient
	// confirmations.
	ntfnsByConfirmHeight map[uint32]map[*ConfNtfn]struct{}

	// spendNotifications is an index of all active notification requests
	// per outpoint/output script.
	spendNotifications map[SpendRequest]*spendNtfnSet

	// spendsByHeight is an index that keeps tracks of the spending height
	// of outpoints/output scripts we are currently tracking notifications
	// for. This is used in order to recover from spending transactions
	// being reorged out of the chain.
	spendsByHeight map[uint32]map[SpendRequest]struct{}

	// confirmHintCache is a cache used to maintain the latest height hints
	// for transactions/output scripts. Each height hint represents the
	// earliest height at which they scripts could have been confirmed
	// within the chain.
	confirmHintCache ConfirmHintCache

	// spendHintCache is a cache used to maintain the latest height hints
	// for outpoints/output scripts. Each height hint represents the
	// earliest height at which they could have been spent within the chain.
	spendHintCache SpendHintCache

	// quit is closed in order to signal that the notifier is gracefully
	// exiting.
	quit chan struct{}

	sync.Mutex
}

// NewTxNotifier creates a TxNotifier. The current height of the blockchain is
// accepted as a parameter. The different hint caches (confirm and spend) are
// used as an optimization in order to retrieve a better starting point when
// dispatching a recan for a historical event in the chain.
func NewTxNotifier(startHeight uint32, reorgSafetyLimit uint32,
	confirmHintCache ConfirmHintCache,
	spendHintCache SpendHintCache) *TxNotifier {

	return &TxNotifier{
		currentHeight:        startHeight,
		reorgSafetyLimit:     reorgSafetyLimit,
		confNotifications:    make(map[ConfRequest]*confNtfnSet),
		confsByInitialHeight: make(map[uint32]map[ConfRequest]struct{}),
		ntfnsByConfirmHeight: make(map[uint32]map[*ConfNtfn]struct{}),
		spendNotifications:   make(map[SpendRequest]*spendNtfnSet),
		spendsByHeight:       make(map[uint32]map[SpendRequest]struct{}),
		confirmHintCache:     confirmHintCache,
		spendHintCache:       spendHintCache,
		quit:                 make(chan struct{}),
	}
}

// newConfNtfn validates all of the parameters required to successfully create
// and register a confirmation notification.
func (n *TxNotifier) newConfNtfn(txid *chainhash.Hash,
	pkScript []byte, numConfs, heightHint uint32) (*ConfNtfn, error) {

	// An accompanying output script must always be provided.
	if len(pkScript) == 0 {
		return nil, ErrNoScript
	}

	// Enforce that we will not dispatch confirmations beyond the reorg
	// safety limit.
	if numConfs == 0 || numConfs > n.reorgSafetyLimit {
		return nil, ErrNumConfsOutOfRange
	}

	// A height hint must be provided to prevent scanning from the genesis
	// block.
	if heightHint == 0 {
		return nil, ErrNoHeightHint
	}

	// Ensure the output script is of a supported type.
	confRequest, err := NewConfRequest(txid, pkScript)
	if err != nil {
		return nil, err
	}

	confID := atomic.AddUint64(&n.confClientCounter, 1)
	return &ConfNtfn{
		ConfID:           confID,
		ConfRequest:      confRequest,
		NumConfirmations: numConfs,
		Event: NewConfirmationEvent(numConfs, func() {
			n.CancelConf(confRequest, confID)
		}),
		HeightHint: heightHint,
	}, nil
}

// RegisterConf handles a new confirmation notification request. The client will
// be notified when the transaction/output script gets a sufficient number of
// confirmations in the blockchain.
//
// NOTE: If the transaction/output script has already been included in a block
// on the chain, the confirmation details must be provided with the
// UpdateConfDetails method, otherwise we will wait for the transaction/output
// script to confirm even though it already has.
func (n *TxNotifier) RegisterConf(txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32) (*ConfRegistration, error) {

	select {
	case <-n.quit:
		return nil, ErrTxNotifierExiting
	default:
	}

	// We'll start by performing a series of validation checks.
	ntfn, err := n.newConfNtfn(txid, pkScript, numConfs, heightHint)
	if err != nil {
		return nil, err
	}

	// Before proceeding to register the notification, we'll query our
	// height hint cache to determine whether a better one exists.
	//
	// TODO(conner): verify that all submitted height hints are identical.
	startHeight := ntfn.HeightHint
	hint, err := n.confirmHintCache.QueryConfirmHint(ntfn.ConfRequest)
	if err == nil {
		if hint > startHeight {
			Log.Debugf("Using height hint %d retrieved from cache "+
				"for %v instead of %d", hint, ntfn.ConfRequest,
				startHeight)
			startHeight = hint
		}
	} else if err != ErrConfirmHintNotFound {
		Log.Errorf("Unable to query confirm hint for %v: %v",
			ntfn.ConfRequest, err)
	}

	Log.Infof("New confirmation subscription: conf_id=%d, %v, "+
		"num_confs=%v height_hint=%d", ntfn.ConfID, ntfn.ConfRequest,
		numConfs, startHeight)

	n.Lock()
	defer n.Unlock()

	confSet, ok := n.confNotifications[ntfn.ConfRequest]
	if !ok {
		// If this is the first registration for this request, construct
		// a confSet to coalesce all notifications for the same request.
		confSet = newConfNtfnSet()
		n.confNotifications[ntfn.ConfRequest] = confSet
	}
	confSet.ntfns[ntfn.ConfID] = ntfn

	switch confSet.rescanStatus {

	// A prior rescan has already completed and we are actively watching at
	// tip for this request.
	case rescanComplete:
		// If the confirmation details for this set of notifications has
		// already been found, we'll attempt to deliver them immediately
		// to this client.
		Log.Debugf("Attempting to dispatch confirmation for %v on "+
			"registration since rescan has finished",
			ntfn.ConfRequest)

		err := n.dispatchConfDetails(ntfn, confSet.details)
		if err != nil {
			return nil, err
		}

		return &ConfRegistration{
			Event:              ntfn.Event,
			HistoricalDispatch: nil,
			Height:             n.currentHeight,
		}, nil

	// A rescan is already in progress, return here to prevent dispatching
	// another. When the rescan returns, this notification's details will be
	// updated as well.
	case rescanPending:
		Log.Debugf("Waiting for pending rescan to finish before "+
			"notifying %v at tip", ntfn.ConfRequest)

		return &ConfRegistration{
			Event:              ntfn.Event,
			HistoricalDispatch: nil,
			Height:             n.currentHeight,
		}, nil

	// If no rescan has been dispatched, attempt to do so now.
	case rescanNotStarted:
	}

	// If the provided or cached height hint indicates that the
	// transaction with the given txid/output script is to be confirmed at a
	// height greater than the notifier's current height, we'll refrain from
	// spawning a historical dispatch.
	if startHeight > n.currentHeight {
		Log.Debugf("Height hint is above current height, not "+
			"dispatching historical confirmation rescan for %v",
			ntfn.ConfRequest)

		// Set the rescan status to complete, which will allow the
		// notifier to start delivering messages for this set
		// immediately.
		confSet.rescanStatus = rescanComplete
		return &ConfRegistration{
			Event:              ntfn.Event,
			HistoricalDispatch: nil,
			Height:             n.currentHeight,
		}, nil
	}

	Log.Debugf("Dispatching historical confirmation rescan for %v",
		ntfn.ConfRequest)

	// Construct the parameters for historical dispatch, scanning the range
	// of blocks between our best known height hint and the notifier's
	// current height. The notifier will begin also watching for
	// confirmations at tip starting with the next block.
	dispatch := &HistoricalConfDispatch{
		ConfRequest: ntfn.ConfRequest,
		StartHeight: startHeight,
		EndHeight:   n.currentHeight,
	}

	// Set this confSet's status to pending, ensuring subsequent
	// registrations don't also attempt a dispatch.
	confSet.rescanStatus = rescanPending

	return &ConfRegistration{
		Event:              ntfn.Event,
		HistoricalDispatch: dispatch,
		Height:             n.currentHeight,
	}, nil
}

// CancelConf cancels an existing request for a spend notification of an
// outpoint/output script. The request is identified by its spend ID.
func (n *TxNotifier) CancelConf(confRequest ConfRequest, confID uint64) {
	select {
	case <-n.quit:
		return
	default:
	}

	n.Lock()
	defer n.Unlock()

	confSet, ok := n.confNotifications[confRequest]
	if !ok {
		return
	}
	ntfn, ok := confSet.ntfns[confID]
	if !ok {
		return
	}

	Log.Infof("Canceling confirmation notification: conf_id=%d, %v", confID,
		confRequest)

	// We'll close all the notification channels to let the client know
	// their cancel request has been fulfilled.
	close(ntfn.Event.Confirmed)
	close(ntfn.Event.Updates)
	close(ntfn.Event.NegativeConf)

	// Finally, we'll clean up any lingering references to this
	// notification.
	delete(confSet.ntfns, confID)

	// Remove the queued confirmation notification if the transaction has
	// already confirmed, but hasn't met its required number of
	// confirmations.
	if confSet.details != nil {
		confHeight := confSet.details.BlockHeight +
			ntfn.NumConfirmations - 1
		delete(n.ntfnsByConfirmHeight[confHeight], ntfn)
	}
}

// UpdateConfDetails attempts to update the confirmation details for an active
// notification within the notifier. This should only be used in the case of a
// transaction/output script that has confirmed before the notifier's current
// height.
//
// NOTE: The notification should be registered first to ensure notifications are
// dispatched correctly.
func (n *TxNotifier) UpdateConfDetails(confRequest ConfRequest,
	details *TxConfirmation) error {

	select {
	case <-n.quit:
		return ErrTxNotifierExiting
	default:
	}

	// Ensure we hold the lock throughout handling the notification to
	// prevent the notifier from advancing its height underneath us.
	n.Lock()
	defer n.Unlock()

	// First, we'll determine whether we have an active confirmation
	// notification for the given txid/script.
	confSet, ok := n.confNotifications[confRequest]
	if !ok {
		return fmt.Errorf("confirmation notification for %v not found",
			confRequest)
	}

	// If the confirmation details were already found at tip, all existing
	// notifications will have been dispatched or queued for dispatch. We
	// can exit early to avoid sending too many notifications on the
	// buffered channels.
	if confSet.details != nil {
		return nil
	}

	// The historical dispatch has been completed for this confSet. We'll
	// update the rescan status and cache any details that were found. If
	// the details are nil, that implies we did not find them and will
	// continue to watch for them at tip.
	confSet.rescanStatus = rescanComplete

	// The notifier has yet to reach the height at which the
	// transaction/output script was included in a block, so we should defer
	// until handling it then within ConnectTip.
	if details == nil {
		Log.Debugf("Confirmation details for %v not found during "+
			"historical dispatch, waiting to dispatch at tip",
			confRequest)

		// We'll commit the current height as the confirm hint to
		// prevent another potentially long rescan if we restart before
		// a new block comes in.
		err := n.confirmHintCache.CommitConfirmHint(
			n.currentHeight, confRequest,
		)
		if err != nil {
			// The error is not fatal as this is an optimistic
			// optimization, so we'll avoid returning an error.
			Log.Debugf("Unable to update confirm hint to %d for "+
				"%v: %v", n.currentHeight, confRequest, err)
		}

		return nil
	}

	if details.BlockHeight > n.currentHeight {
		Log.Debugf("Confirmation details for %v found above current "+
			"height, waiting to dispatch at tip", confRequest)

		return nil
	}

	Log.Debugf("Updating confirmation details for %v", confRequest)

	err := n.confirmHintCache.CommitConfirmHint(
		details.BlockHeight, confRequest,
	)
	if err != nil {
		// The error is not fatal, so we should not return an error to
		// the caller.
		Log.Errorf("Unable to update confirm hint to %d for %v: %v",
			details.BlockHeight, confRequest, err)
	}

	// Cache the details found in the rescan and attempt to dispatch any
	// notifications that have not yet been delivered.
	confSet.details = details
	for _, ntfn := range confSet.ntfns {
		err = n.dispatchConfDetails(ntfn, details)
		if err != nil {
			return err
		}
	}

	return nil
}

// dispatchConfDetails attempts to cache and dispatch details to a particular
// client if the transaction/output script has sufficiently confirmed. If the
// provided details are nil, this method will be a no-op.
func (n *TxNotifier) dispatchConfDetails(
	ntfn *ConfNtfn, details *TxConfirmation) error {

	// If no details are provided, return early as we can't dispatch.
	if details == nil {
		Log.Debugf("Unable to dispatch %v, no details provided",
			ntfn.ConfRequest)

		return nil
	}

	// Now, we'll examine whether the transaction/output script of this
	// request has reached its required number of confirmations. If it has,
	// we'll dispatch a confirmation notification to the caller.
	confHeight := details.BlockHeight + ntfn.NumConfirmations - 1
	if confHeight <= n.currentHeight {
		Log.Infof("Dispatching %v confirmation notification for %v",
			ntfn.NumConfirmations, ntfn.ConfRequest)

		// We'll send a 0 value to the Updates channel,
		// indicating that the transaction/output script has already
		// been confirmed.
		select {
		case ntfn.Event.Updates <- 0:
		case <-n.quit:
			return ErrTxNotifierExiting
		}

		select {
		case ntfn.Event.Confirmed <- details:
			ntfn.dispatched = true
		case <-n.quit:
			return ErrTxNotifierExiting
		}
	} else {
		Log.Debugf("Queueing %v confirmation notification for %v at tip ",
			ntfn.NumConfirmations, ntfn.ConfRequest)

		// Otherwise, we'll keep track of the notification
		// request by the height at which we should dispatch the
		// confirmation notification.
		ntfnSet, exists := n.ntfnsByConfirmHeight[confHeight]
		if !exists {
			ntfnSet = make(map[*ConfNtfn]struct{})
			n.ntfnsByConfirmHeight[confHeight] = ntfnSet
		}
		ntfnSet[ntfn] = struct{}{}

		// We'll also send an update to the client of how many
		// confirmations are left for the transaction/output script to
		// be confirmed.
		numConfsLeft := confHeight - n.currentHeight
		select {
		case ntfn.Event.Updates <- numConfsLeft:
		case <-n.quit:
			return ErrTxNotifierExiting
		}
	}

	// As a final check, we'll also watch the transaction/output script if
	// it's still possible for it to get reorged out of the chain.
	reorgSafeHeight := details.BlockHeight + n.reorgSafetyLimit
	if reorgSafeHeight > n.currentHeight {
		txSet, exists := n.confsByInitialHeight[details.BlockHeight]
		if !exists {
			txSet = make(map[ConfRequest]struct{})
			n.confsByInitialHeight[details.BlockHeight] = txSet
		}
		txSet[ntfn.ConfRequest] = struct{}{}
	}

	return nil
}

// newSpendNtfn validates all of the parameters required to successfully create
// and register a spend notification.
func (n *TxNotifier) newSpendNtfn(outpoint *wire.OutPoint,
	pkScript []byte, heightHint uint32) (*SpendNtfn, error) {

	// An accompanying output script must always be provided.
	if len(pkScript) == 0 {
		return nil, ErrNoScript
	}

	// A height hint must be provided to prevent scanning from the genesis
	// block.
	if heightHint == 0 {
		return nil, ErrNoHeightHint
	}

	// Ensure the output script is of a supported type.
	spendRequest, err := NewSpendRequest(outpoint, pkScript)
	if err != nil {
		return nil, err
	}

	spendID := atomic.AddUint64(&n.spendClientCounter, 1)
	return &SpendNtfn{
		SpendID:      spendID,
		SpendRequest: spendRequest,
		Event: NewSpendEvent(func() {
			n.CancelSpend(spendRequest, spendID)
		}),
		HeightHint: heightHint,
	}, nil
}

// RegisterSpend handles a new spend notification request. The client will be
// notified once the outpoint/output script is detected as spent within the
// chain.
//
// NOTE: If the outpoint/output script has already been spent within the chain
// before the notifier's current tip, the spend details must be provided with
// the UpdateSpendDetails method, otherwise we will wait for the outpoint/output
// script to be spent at tip, even though it already has.
func (n *TxNotifier) RegisterSpend(outpoint *wire.OutPoint, pkScript []byte,
	heightHint uint32) (*SpendRegistration, error) {

	select {
	case <-n.quit:
		return nil, ErrTxNotifierExiting
	default:
	}

	// We'll start by performing a series of validation checks.
	ntfn, err := n.newSpendNtfn(outpoint, pkScript, heightHint)
	if err != nil {
		return nil, err
	}

	// Before proceeding to register the notification, we'll query our spend
	// hint cache to determine whether a better one exists.
	startHeight := ntfn.HeightHint
	hint, err := n.spendHintCache.QuerySpendHint(ntfn.SpendRequest)
	if err == nil {
		if hint > startHeight {
			Log.Debugf("Using height hint %d retrieved from cache "+
				"for %v instead of %d", hint, ntfn.SpendRequest,
				startHeight)
			startHeight = hint
		}
	} else if err != ErrSpendHintNotFound {
		Log.Errorf("Unable to query spend hint for %v: %v",
			ntfn.SpendRequest, err)
	}

	n.Lock()
	defer n.Unlock()

	Log.Infof("New spend subscription: spend_id=%d, %v, height_hint=%d",
		ntfn.SpendID, ntfn.SpendRequest, startHeight)

	// Keep track of the notification request so that we can properly
	// dispatch a spend notification later on.
	spendSet, ok := n.spendNotifications[ntfn.SpendRequest]
	if !ok {
		// If this is the first registration for the request, we'll
		// construct a spendNtfnSet to coalesce all notifications.
		spendSet = newSpendNtfnSet()
		n.spendNotifications[ntfn.SpendRequest] = spendSet
	}
	spendSet.ntfns[ntfn.SpendID] = ntfn

	// We'll now let the caller know whether a historical rescan is needed
	// depending on the current rescan status.
	switch spendSet.rescanStatus {

	// If the spending details for this request have already been determined
	// and cached, then we can use them to immediately dispatch the spend
	// notification to the client.
	case rescanComplete:
		Log.Debugf("Attempting to dispatch spend for %v on "+
			"registration since rescan has finished",
			ntfn.SpendRequest)

		err := n.dispatchSpendDetails(ntfn, spendSet.details)
		if err != nil {
			return nil, err
		}

		return &SpendRegistration{
			Event:              ntfn.Event,
			HistoricalDispatch: nil,
			Height:             n.currentHeight,
		}, nil

	// If there is an active rescan to determine whether the request has
	// been spent, then we won't trigger another one.
	case rescanPending:
		Log.Debugf("Waiting for pending rescan to finish before "+
			"notifying %v at tip", ntfn.SpendRequest)

		return &SpendRegistration{
			Event:              ntfn.Event,
			HistoricalDispatch: nil,
			Height:             n.currentHeight,
		}, nil

	// Otherwise, we'll fall through and let the caller know that a rescan
	// should be dispatched to determine whether the request has already
	// been spent.
	case rescanNotStarted:
	}

	// However, if the spend hint, either provided by the caller or
	// retrieved from the cache, is found to be at a later height than the
	// TxNotifier is aware of, then we'll refrain from dispatching a
	// historical rescan and wait for the spend to come in at tip.
	if startHeight > n.currentHeight {
		Log.Debugf("Spend hint of %d for %v is above current height %d",
			startHeight, ntfn.SpendRequest, n.currentHeight)

		// We'll also set the rescan status as complete to ensure that
		// spend hints for this request get updated upon
		// connected/disconnected blocks.
		spendSet.rescanStatus = rescanComplete
		return &SpendRegistration{
			Event:              ntfn.Event,
			HistoricalDispatch: nil,
			Height:             n.currentHeight,
		}, nil
	}

	// We'll set the rescan status to pending to ensure subsequent
	// notifications don't also attempt a historical dispatch.
	spendSet.rescanStatus = rescanPending

	Log.Infof("Dispatching historical spend rescan for %v, start=%d, "+
		"end=%d", ntfn.SpendRequest, startHeight, n.currentHeight)

	return &SpendRegistration{
		Event: ntfn.Event,
		HistoricalDispatch: &HistoricalSpendDispatch{
			SpendRequest: ntfn.SpendRequest,
			StartHeight:  startHeight,
			EndHeight:    n.currentHeight,
		},
		Height: n.currentHeight,
	}, nil
}

// CancelSpend cancels an existing request for a spend notification of an
// outpoint/output script. The request is identified by its spend ID.
func (n *TxNotifier) CancelSpend(spendRequest SpendRequest, spendID uint64) {
	select {
	case <-n.quit:
		return
	default:
	}

	n.Lock()
	defer n.Unlock()

	spendSet, ok := n.spendNotifications[spendRequest]
	if !ok {
		return
	}
	ntfn, ok := spendSet.ntfns[spendID]
	if !ok {
		return
	}

	Log.Infof("Canceling spend notification: spend_id=%d, %v", spendID,
		spendRequest)

	// We'll close all the notification channels to let the client know
	// their cancel request has been fulfilled.
	close(ntfn.Event.Spend)
	close(ntfn.Event.Reorg)
	close(ntfn.Event.Done)
	delete(spendSet.ntfns, spendID)
}

// ProcessRelevantSpendTx processes a transaction provided externally. This will
// check whether the transaction is relevant to the notifier if it spends any
// outpoints/output scripts for which we currently have registered notifications
// for. If it is relevant, spend notifications will be dispatched to the caller.
func (n *TxNotifier) ProcessRelevantSpendTx(tx *btcutil.Tx,
	blockHeight uint32) error {

	select {
	case <-n.quit:
		return ErrTxNotifierExiting
	default:
	}

	// Ensure we hold the lock throughout handling the notification to
	// prevent the notifier from advancing its height underneath us.
	n.Lock()
	defer n.Unlock()

	// We'll use a channel to coalesce all the spend requests that this
	// transaction fulfills.
	type spend struct {
		request *SpendRequest
		details *SpendDetail
	}

	// We'll set up the onSpend filter callback to gather all the fulfilled
	// spends requests within this transaction.
	var spends []spend
	onSpend := func(request SpendRequest, details *SpendDetail) {
		spends = append(spends, spend{&request, details})
	}
	n.filterTx(tx, nil, blockHeight, nil, onSpend)

	// After the transaction has been filtered, we can finally dispatch
	// notifications for each request.
	for _, spend := range spends {
		err := n.updateSpendDetails(*spend.request, spend.details)
		if err != nil {
			return err
		}
	}

	return nil
}

// UpdateSpendDetails attempts to update the spend details for all active spend
// notification requests for an outpoint/output script. This method should be
// used once a historical scan of the chain has finished. If the historical scan
// did not find a spending transaction for it, the spend details may be nil.
//
// NOTE: A notification request for the outpoint/output script must be
// registered first to ensure notifications are delivered.
func (n *TxNotifier) UpdateSpendDetails(spendRequest SpendRequest,
	details *SpendDetail) error {

	select {
	case <-n.quit:
		return ErrTxNotifierExiting
	default:
	}

	// Ensure we hold the lock throughout handling the notification to
	// prevent the notifier from advancing its height underneath us.
	n.Lock()
	defer n.Unlock()

	return n.updateSpendDetails(spendRequest, details)
}

// updateSpendDetails attempts to update the spend details for all active spend
// notification requests for an outpoint/output script. This method should be
// used once a historical scan of the chain has finished. If the historical scan
// did not find a spending transaction for it, the spend details may be nil.
//
// NOTE: This method must be called with the TxNotifier's lock held.
func (n *TxNotifier) updateSpendDetails(spendRequest SpendRequest,
	details *SpendDetail) error {

	// Mark the ongoing historical rescan for this request as finished. This
	// will allow us to update the spend hints for it at tip.
	spendSet, ok := n.spendNotifications[spendRequest]
	if !ok {
		return fmt.Errorf("spend notification for %v not found",
			spendRequest)
	}

	// If the spend details have already been found either at tip, then the
	// notifications should have already been dispatched, so we can exit
	// early to prevent sending duplicate notifications.
	if spendSet.details != nil {
		return nil
	}

	// Since the historical rescan has completed for this request, we'll
	// mark its rescan status as complete in order to ensure that the
	// TxNotifier can properly update its spend hints upon
	// connected/disconnected blocks.
	spendSet.rescanStatus = rescanComplete

	// If the historical rescan was not able to find a spending transaction
	// for this request, then we can track the spend at tip.
	if details == nil {
		// We'll commit the current height as the spend hint to prevent
		// another potentially long rescan if we restart before a new
		// block comes in.
		err := n.spendHintCache.CommitSpendHint(
			n.currentHeight, spendRequest,
		)
		if err != nil {
			// The error is not fatal as this is an optimistic
			// optimization, so we'll avoid returning an error.
			Log.Debugf("Unable to update spend hint to %d for %v: %v",
				n.currentHeight, spendRequest, err)
		}

		Log.Debugf("Updated spend hint to height=%v for unconfirmed "+
			"spend request %v", n.currentHeight, spendRequest)
		return nil
	}

	// If the historical rescan found the spending transaction for this
	// request, but it's at a later height than the notifier (this can
	// happen due to latency with the backend during a reorg), then we'll
	// defer handling the notification until the notifier has caught up to
	// such height.
	if uint32(details.SpendingHeight) > n.currentHeight {
		return nil
	}

	// Now that we've determined the request has been spent, we'll commit
	// its spending height as its hint in the cache and dispatch
	// notifications to all of its respective clients.
	err := n.spendHintCache.CommitSpendHint(
		uint32(details.SpendingHeight), spendRequest,
	)
	if err != nil {
		// The error is not fatal as this is an optimistic optimization,
		// so we'll avoid returning an error.
		Log.Debugf("Unable to update spend hint to %d for %v: %v",
			details.SpendingHeight, spendRequest, err)
	}

	Log.Debugf("Updated spend hint to height=%v for confirmed spend "+
		"request %v", details.SpendingHeight, spendRequest)

	spendSet.details = details
	for _, ntfn := range spendSet.ntfns {
		err := n.dispatchSpendDetails(ntfn, spendSet.details)
		if err != nil {
			return err
		}
	}

	return nil
}

// dispatchSpendDetails dispatches a spend notification to the client.
//
// NOTE: This must be called with the TxNotifier's lock held.
func (n *TxNotifier) dispatchSpendDetails(ntfn *SpendNtfn, details *SpendDetail) error {
	// If there are no spend details to dispatch or if the notification has
	// already been dispatched, then we can skip dispatching to this client.
	if details == nil || ntfn.dispatched {
		Log.Debugf("Skipping dispatch of spend details(%v) for "+
			"request %v, dispatched=%v", details, ntfn.SpendRequest,
			ntfn.dispatched)
		return nil
	}

	Log.Infof("Dispatching confirmed spend notification for %v at "+
		"current height=%d: %v", ntfn.SpendRequest, n.currentHeight,
		details)

	select {
	case ntfn.Event.Spend <- details:
		ntfn.dispatched = true
	case <-n.quit:
		return ErrTxNotifierExiting
	}

	spendHeight := uint32(details.SpendingHeight)

	// We also add to spendsByHeight to notify on chain reorgs.
	reorgSafeHeight := spendHeight + n.reorgSafetyLimit
	if reorgSafeHeight > n.currentHeight {
		txSet, exists := n.spendsByHeight[spendHeight]
		if !exists {
			txSet = make(map[SpendRequest]struct{})
			n.spendsByHeight[spendHeight] = txSet
		}
		txSet[ntfn.SpendRequest] = struct{}{}
	}

	return nil
}

// ConnectTip handles a new block extending the current chain. It will go
// through every transaction and determine if it is relevant to any of its
// clients. A transaction can be relevant in either of the following two ways:
//
//   1. One of the inputs in the transaction spends an outpoint/output script
//   for which we currently have an active spend registration for.
//
//   2. The transaction has a txid or output script for which we currently have
//   an active confirmation registration for.
//
// In the event that the transaction is relevant, a confirmation/spend
// notification will be queued for dispatch to the relevant clients.
// Confirmation notifications will only be dispatched for transactions/output
// scripts that have met the required number of confirmations required by the
// client.
//
// NOTE: In order to actually dispatch the relevant transaction notifications to
// clients, NotifyHeight must be called with the same block height in order to
// maintain correctness.
func (n *TxNotifier) ConnectTip(blockHash *chainhash.Hash, blockHeight uint32,
	txns []*btcutil.Tx) error {

	select {
	case <-n.quit:
		return ErrTxNotifierExiting
	default:
	}

	n.Lock()
	defer n.Unlock()

	if blockHeight != n.currentHeight+1 {
		return fmt.Errorf("received blocks out of order: "+
			"current height=%d, new height=%d",
			n.currentHeight, blockHeight)
	}
	n.currentHeight++
	n.reorgDepth = 0

	// First, we'll iterate over all the transactions found in this block to
	// determine if it includes any relevant transactions to the TxNotifier.
	Log.Debugf("Filtering %d txns for %d spend requests at height %d",
		len(txns), len(n.spendNotifications), blockHeight)
	for _, tx := range txns {
		n.filterTx(
			tx, blockHash, blockHeight, n.handleConfDetailsAtTip,
			n.handleSpendDetailsAtTip,
		)
	}

	// Now that we've determined which requests were confirmed and spent
	// within the new block, we can update their entries in their respective
	// caches, along with all of our unconfirmed and unspent requests.
	n.updateHints(blockHeight)

	// Finally, we'll clear the entries from our set of notifications for
	// requests that are no longer under the risk of being reorged out of
	// the chain.
	if blockHeight >= n.reorgSafetyLimit {
		matureBlockHeight := blockHeight - n.reorgSafetyLimit
		for confRequest := range n.confsByInitialHeight[matureBlockHeight] {
			confSet := n.confNotifications[confRequest]
			for _, ntfn := range confSet.ntfns {
				select {
				case ntfn.Event.Done <- struct{}{}:
				case <-n.quit:
					return ErrTxNotifierExiting
				}
			}

			delete(n.confNotifications, confRequest)
		}
		delete(n.confsByInitialHeight, matureBlockHeight)

		for spendRequest := range n.spendsByHeight[matureBlockHeight] {
			spendSet := n.spendNotifications[spendRequest]
			for _, ntfn := range spendSet.ntfns {
				select {
				case ntfn.Event.Done <- struct{}{}:
				case <-n.quit:
					return ErrTxNotifierExiting
				}
			}

			Log.Debugf("Deleting mature spend request %v at "+
				"height=%d", spendRequest, blockHeight)
			delete(n.spendNotifications, spendRequest)
		}
		delete(n.spendsByHeight, matureBlockHeight)
	}

	return nil
}

// filterTx determines whether the transaction spends or confirms any
// outstanding pending requests. The onConf and onSpend callbacks can be used to
// retrieve all the requests fulfilled by this transaction as they occur.
func (n *TxNotifier) filterTx(tx *btcutil.Tx, blockHash *chainhash.Hash,
	blockHeight uint32, onConf func(ConfRequest, *TxConfirmation),
	onSpend func(SpendRequest, *SpendDetail)) {

	// In order to determine if this transaction is relevant to the
	// notifier, we'll check its inputs for any outstanding spend
	// requests.
	txHash := tx.Hash()
	if onSpend != nil {
		// notifyDetails is a helper closure that will construct the
		// spend details of a request and hand them off to the onSpend
		// callback.
		notifyDetails := func(spendRequest SpendRequest,
			prevOut wire.OutPoint, inputIdx uint32) {

			Log.Debugf("Found spend of %v: spend_tx=%v, "+
				"block_height=%d", spendRequest, txHash,
				blockHeight)

			onSpend(spendRequest, &SpendDetail{
				SpentOutPoint:     &prevOut,
				SpenderTxHash:     txHash,
				SpendingTx:        tx.MsgTx(),
				SpenderInputIndex: inputIdx,
				SpendingHeight:    int32(blockHeight),
			})
		}

		for i, txIn := range tx.MsgTx().TxIn {
			// We'll re-derive the script of the output being spent
			// to determine if the inputs spends any registered
			// requests.
			prevOut := txIn.PreviousOutPoint
			pkScript, err := txscript.ComputePkScript(
				txIn.SignatureScript, txIn.Witness,
			)
			if err != nil {
				continue
			}
			spendRequest := SpendRequest{
				OutPoint: prevOut,
				PkScript: pkScript,
			}

			// If we have any, we'll record their spend height so
			// that notifications get dispatched to the respective
			// clients.
			if _, ok := n.spendNotifications[spendRequest]; ok {
				notifyDetails(spendRequest, prevOut, uint32(i))
			}
			spendRequest.OutPoint = ZeroOutPoint
			if _, ok := n.spendNotifications[spendRequest]; ok {
				notifyDetails(spendRequest, prevOut, uint32(i))
			}
		}
	}

	// We'll also check its outputs to determine if there are any
	// outstanding confirmation requests.
	if onConf != nil {
		// notifyDetails is a helper closure that will construct the
		// confirmation details of a request and hand them off to the
		// onConf callback.
		notifyDetails := func(confRequest ConfRequest) {
			Log.Debugf("Found initial confirmation of %v: "+
				"height=%d, hash=%v", confRequest,
				blockHeight, blockHash)

			details := &TxConfirmation{
				Tx:          tx.MsgTx(),
				BlockHash:   blockHash,
				BlockHeight: blockHeight,
				TxIndex:     uint32(tx.Index()),
			}

			onConf(confRequest, details)
		}

		for _, txOut := range tx.MsgTx().TxOut {
			// We'll parse the script of the output to determine if
			// we have any registered requests for it or the
			// transaction itself.
			pkScript, err := txscript.ParsePkScript(txOut.PkScript)
			if err != nil {
				continue
			}
			confRequest := ConfRequest{
				TxID:     *txHash,
				PkScript: pkScript,
			}

			// If we have any, we'll record their confirmed height
			// so that notifications get dispatched when they
			// reaches the clients' desired number of confirmations.
			if _, ok := n.confNotifications[confRequest]; ok {
				notifyDetails(confRequest)
			}
			confRequest.TxID = ZeroHash
			if _, ok := n.confNotifications[confRequest]; ok {
				notifyDetails(confRequest)
			}
		}
	}
}

// handleConfDetailsAtTip tracks the confirmation height of the txid/output
// script in order to properly dispatch a confirmation notification after
// meeting each request's desired number of confirmations for all current and
// future registered clients.
func (n *TxNotifier) handleConfDetailsAtTip(confRequest ConfRequest,
	details *TxConfirmation) {

	// TODO(wilmer): cancel pending historical rescans if any?
	confSet := n.confNotifications[confRequest]

	// If we already have details for this request, we don't want to add it
	// again since we have already dispatched notifications for it.
	if confSet.details != nil {
		Log.Warnf("Ignoring address reuse for %s at height %d.",
			confRequest, details.BlockHeight)
		return
	}

	confSet.rescanStatus = rescanComplete
	confSet.details = details

	for _, ntfn := range confSet.ntfns {
		// In the event that this notification was aware that the
		// transaction/output script was reorged out of the chain, we'll
		// consume the reorg notification if it hasn't been done yet
		// already.
		select {
		case <-ntfn.Event.NegativeConf:
		default:
		}

		// We'll note this client's required number of confirmations so
		// that we can notify them when expected.
		confHeight := details.BlockHeight + ntfn.NumConfirmations - 1
		ntfnSet, exists := n.ntfnsByConfirmHeight[confHeight]
		if !exists {
			ntfnSet = make(map[*ConfNtfn]struct{})
			n.ntfnsByConfirmHeight[confHeight] = ntfnSet
		}
		ntfnSet[ntfn] = struct{}{}
	}

	// We'll also note the initial confirmation height in order to correctly
	// handle dispatching notifications when the transaction/output script
	// gets reorged out of the chain.
	txSet, exists := n.confsByInitialHeight[details.BlockHeight]
	if !exists {
		txSet = make(map[ConfRequest]struct{})
		n.confsByInitialHeight[details.BlockHeight] = txSet
	}
	txSet[confRequest] = struct{}{}
}

// handleSpendDetailsAtTip tracks the spend height of the outpoint/output script
// in order to properly dispatch a spend notification for all current and future
// registered clients.
func (n *TxNotifier) handleSpendDetailsAtTip(spendRequest SpendRequest,
	details *SpendDetail) {

	// TODO(wilmer): cancel pending historical rescans if any?
	spendSet := n.spendNotifications[spendRequest]
	spendSet.rescanStatus = rescanComplete
	spendSet.details = details

	for _, ntfn := range spendSet.ntfns {
		// In the event that this notification was aware that the
		// spending transaction of its outpoint/output script was
		// reorged out of the chain, we'll consume the reorg
		// notification if it hasn't been done yet already.
		select {
		case <-ntfn.Event.Reorg:
		default:
		}
	}

	// We'll note the spending height of the request in order to correctly
	// handle dispatching notifications when the spending transactions gets
	// reorged out of the chain.
	spendHeight := uint32(details.SpendingHeight)
	opSet, exists := n.spendsByHeight[spendHeight]
	if !exists {
		opSet = make(map[SpendRequest]struct{})
		n.spendsByHeight[spendHeight] = opSet
	}
	opSet[spendRequest] = struct{}{}

	Log.Debugf("Spend request %v spent at tip=%d", spendRequest,
		spendHeight)
}

// NotifyHeight dispatches confirmation and spend notifications to the clients
// who registered for a notification which has been fulfilled at the passed
// height.
func (n *TxNotifier) NotifyHeight(height uint32) error {
	n.Lock()
	defer n.Unlock()

	// First, we'll dispatch an update to all of the notification clients
	// for our watched requests with the number of confirmations left at
	// this new height.
	for _, confRequests := range n.confsByInitialHeight {
		for confRequest := range confRequests {
			confSet := n.confNotifications[confRequest]
			for _, ntfn := range confSet.ntfns {
				txConfHeight := confSet.details.BlockHeight +
					ntfn.NumConfirmations - 1
				numConfsLeft := txConfHeight - height

				// Since we don't clear notifications until
				// transactions/output scripts are no longer
				// under the risk of being reorganized out of
				// the chain, we'll skip sending updates for
				// those that have already been confirmed.
				if int32(numConfsLeft) < 0 {
					continue
				}

				select {
				case ntfn.Event.Updates <- numConfsLeft:
				case <-n.quit:
					return ErrTxNotifierExiting
				}
			}
		}
	}

	// Then, we'll dispatch notifications for all the requests that have
	// become confirmed at this new block height.
	for ntfn := range n.ntfnsByConfirmHeight[height] {
		confSet := n.confNotifications[ntfn.ConfRequest]

		Log.Infof("Dispatching %v confirmation notification for %v",
			ntfn.NumConfirmations, ntfn.ConfRequest)

		select {
		case ntfn.Event.Confirmed <- confSet.details:
			ntfn.dispatched = true
		case <-n.quit:
			return ErrTxNotifierExiting
		}
	}
	delete(n.ntfnsByConfirmHeight, height)

	// Finally, we'll dispatch spend notifications for all the requests that
	// were spent at this new block height.
	for spendRequest := range n.spendsByHeight[height] {
		spendSet := n.spendNotifications[spendRequest]
		for _, ntfn := range spendSet.ntfns {
			err := n.dispatchSpendDetails(ntfn, spendSet.details)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// DisconnectTip handles the tip of the current chain being disconnected during
// a chain reorganization. If any watched requests were included in this block,
// internal structures are updated to ensure confirmation/spend notifications
// are consumed (if not already), and reorg notifications are dispatched
// instead. Confirmation/spend notifications will be dispatched again upon block
// inclusion.
func (n *TxNotifier) DisconnectTip(blockHeight uint32) error {
	select {
	case <-n.quit:
		return ErrTxNotifierExiting
	default:
	}

	n.Lock()
	defer n.Unlock()

	if blockHeight != n.currentHeight {
		return fmt.Errorf("received blocks out of order: "+
			"current height=%d, disconnected height=%d",
			n.currentHeight, blockHeight)
	}
	n.currentHeight--
	n.reorgDepth++

	// With the block disconnected, we'll update the confirm and spend hints
	// for our notification requests to reflect the new height, except for
	// those that have confirmed/spent at previous heights.
	n.updateHints(blockHeight)

	// We'll go through all of our watched confirmation requests and attempt
	// to drain their notification channels to ensure sending notifications
	// to the clients is always non-blocking.
	for initialHeight, txHashes := range n.confsByInitialHeight {
		for txHash := range txHashes {
			// If the transaction/output script has been reorged out
			// of the chain, we'll make sure to remove the cached
			// confirmation details to prevent notifying clients
			// with old information.
			confSet := n.confNotifications[txHash]
			if initialHeight == blockHeight {
				confSet.details = nil
			}

			for _, ntfn := range confSet.ntfns {
				// First, we'll attempt to drain an update
				// from each notification to ensure sends to the
				// Updates channel are always non-blocking.
				select {
				case <-ntfn.Event.Updates:
				case <-n.quit:
					return ErrTxNotifierExiting
				default:
				}

				// Then, we'll check if the current
				// transaction/output script was included in the
				// block currently being disconnected. If it
				// was, we'll need to dispatch a reorg
				// notification to the client.
				if initialHeight == blockHeight {
					err := n.dispatchConfReorg(
						ntfn, blockHeight,
					)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// We'll also go through our watched spend requests and attempt to drain
	// their dispatched notifications to ensure dispatching notifications to
	// clients later on is always non-blocking. We're only interested in
	// requests whose spending transaction was included at the height being
	// disconnected.
	for op := range n.spendsByHeight[blockHeight] {
		// Since the spending transaction is being reorged out of the
		// chain, we'll need to clear out the spending details of the
		// request.
		spendSet := n.spendNotifications[op]
		spendSet.details = nil

		// For all requests which have had a spend notification
		// dispatched, we'll attempt to drain it and send a reorg
		// notification instead.
		for _, ntfn := range spendSet.ntfns {
			if err := n.dispatchSpendReorg(ntfn); err != nil {
				return err
			}
		}
	}

	// Finally, we can remove the requests that were confirmed and/or spent
	// at the height being disconnected. We'll still continue to track them
	// until they have been confirmed/spent and are no longer under the risk
	// of being reorged out of the chain again.
	delete(n.confsByInitialHeight, blockHeight)
	delete(n.spendsByHeight, blockHeight)

	return nil
}

// updateHints attempts to update the confirm and spend hints for all relevant
// requests respectively. The height parameter is used to determine which
// requests we should update based on whether a new block is being
// connected/disconnected.
//
// NOTE: This must be called with the TxNotifier's lock held and after its
// height has already been reflected by a block being connected/disconnected.
func (n *TxNotifier) updateHints(height uint32) {
	// TODO(wilmer): update under one database transaction.
	//
	// To update the height hint for all the required confirmation requests
	// under one database transaction, we'll gather the set of unconfirmed
	// requests along with the ones that confirmed at the height being
	// connected/disconnected.
	confRequests := n.unconfirmedRequests()
	for confRequest := range n.confsByInitialHeight[height] {
		confRequests = append(confRequests, confRequest)
	}
	err := n.confirmHintCache.CommitConfirmHint(
		n.currentHeight, confRequests...,
	)
	if err != nil {
		// The error is not fatal as this is an optimistic optimization,
		// so we'll avoid returning an error.
		Log.Debugf("Unable to update confirm hints to %d for "+
			"%v: %v", n.currentHeight, confRequests, err)
	}

	// Similarly, to update the height hint for all the required spend
	// requests under one database transaction, we'll gather the set of
	// unspent requests along with the ones that were spent at the height
	// being connected/disconnected.
	spendRequests := n.unspentRequests()
	for spendRequest := range n.spendsByHeight[height] {
		spendRequests = append(spendRequests, spendRequest)
	}
	err = n.spendHintCache.CommitSpendHint(n.currentHeight, spendRequests...)
	if err != nil {
		// The error is not fatal as this is an optimistic optimization,
		// so we'll avoid returning an error.
		Log.Debugf("Unable to update spend hints to %d for "+
			"%v: %v", n.currentHeight, spendRequests, err)
	}
}

// unconfirmedRequests returns the set of confirmation requests that are
// still seen as unconfirmed by the TxNotifier.
//
// NOTE: This method must be called with the TxNotifier's lock held.
func (n *TxNotifier) unconfirmedRequests() []ConfRequest {
	var unconfirmed []ConfRequest
	for confRequest, confNtfnSet := range n.confNotifications {
		// If the notification is already aware of its confirmation
		// details, or it's in the process of learning them, we'll skip
		// it as we can't yet determine if it's confirmed or not.
		if confNtfnSet.rescanStatus != rescanComplete ||
			confNtfnSet.details != nil {
			continue
		}

		unconfirmed = append(unconfirmed, confRequest)
	}

	return unconfirmed
}

// unspentRequests returns the set of spend requests that are still seen as
// unspent by the TxNotifier.
//
// NOTE: This method must be called with the TxNotifier's lock held.
func (n *TxNotifier) unspentRequests() []SpendRequest {
	var unspent []SpendRequest
	for spendRequest, spendNtfnSet := range n.spendNotifications {
		// If the notification is already aware of its spend details, or
		// it's in the process of learning them, we'll skip it as we
		// can't yet determine if it's unspent or not.
		if spendNtfnSet.rescanStatus != rescanComplete ||
			spendNtfnSet.details != nil {
			continue
		}

		unspent = append(unspent, spendRequest)
	}

	return unspent
}

// dispatchConfReorg dispatches a reorg notification to the client if the
// confirmation notification was already delivered.
//
// NOTE: This must be called with the TxNotifier's lock held.
func (n *TxNotifier) dispatchConfReorg(ntfn *ConfNtfn,
	heightDisconnected uint32) error {

	// If the request's confirmation notification has yet to be dispatched,
	// we'll need to clear its entry within the ntfnsByConfirmHeight index
	// to prevent from notifying the client once the notifier reaches the
	// confirmation height.
	if !ntfn.dispatched {
		confHeight := heightDisconnected + ntfn.NumConfirmations - 1
		ntfnSet, exists := n.ntfnsByConfirmHeight[confHeight]
		if exists {
			delete(ntfnSet, ntfn)
		}
		return nil
	}

	// Otherwise, the entry within the ntfnsByConfirmHeight has already been
	// deleted, so we'll attempt to drain the confirmation notification to
	// ensure sends to the Confirmed channel are always non-blocking.
	select {
	case <-ntfn.Event.Confirmed:
	case <-n.quit:
		return ErrTxNotifierExiting
	default:
	}

	ntfn.dispatched = false

	// Send a negative confirmation notification to the client indicating
	// how many blocks have been disconnected successively.
	select {
	case ntfn.Event.NegativeConf <- int32(n.reorgDepth):
	case <-n.quit:
		return ErrTxNotifierExiting
	}

	return nil
}

// dispatchSpendReorg dispatches a reorg notification to the client if a spend
// notiification was already delivered.
//
// NOTE: This must be called with the TxNotifier's lock held.
func (n *TxNotifier) dispatchSpendReorg(ntfn *SpendNtfn) error {
	if !ntfn.dispatched {
		return nil
	}

	// Attempt to drain the spend notification to ensure sends to the Spend
	// channel are always non-blocking.
	select {
	case <-ntfn.Event.Spend:
	default:
	}

	// Send a reorg notification to the client in order for them to
	// correctly handle reorgs.
	select {
	case ntfn.Event.Reorg <- struct{}{}:
	case <-n.quit:
		return ErrTxNotifierExiting
	}

	ntfn.dispatched = false

	return nil
}

// TearDown is to be called when the owner of the TxNotifier is exiting. This
// closes the event channels of all registered notifications that have not been
// dispatched yet.
func (n *TxNotifier) TearDown() {
	close(n.quit)

	n.Lock()
	defer n.Unlock()

	for _, confSet := range n.confNotifications {
		for confID, ntfn := range confSet.ntfns {
			close(ntfn.Event.Confirmed)
			close(ntfn.Event.Updates)
			close(ntfn.Event.NegativeConf)
			close(ntfn.Event.Done)
			delete(confSet.ntfns, confID)
		}
	}

	for _, spendSet := range n.spendNotifications {
		for spendID, ntfn := range spendSet.ntfns {
			close(ntfn.Event.Spend)
			close(ntfn.Event.Reorg)
			close(ntfn.Event.Done)
			delete(spendSet.ntfns, spendID)
		}
	}
}
