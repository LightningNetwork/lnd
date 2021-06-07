package lnwallet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
	"github.com/lightningnetwork/lnd/lnwallet/chanvalidate"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
)

const (
	// The size of the buffered queue of requests to the wallet from the
	// outside word.
	msgBufferSize = 100

	// anchorChanReservedValue is the amount we'll keep around in the
	// wallet in case we have to fee bump anchor channels on force close.
	// TODO(halseth): update constant to target a specific commit size at
	// set fee rate.
	anchorChanReservedValue = btcutil.Amount(10_000)

	// maxAnchorChanReservedValue is the maximum value we'll reserve for
	// anchor channel fee bumping. We cap it at 10 times the per-channel
	// amount such that nodes with a high number of channels don't have to
	// keep around a very large amount for the unlikely scenario that they
	// all close at the same time.
	maxAnchorChanReservedValue = 10 * anchorChanReservedValue
)

var (
	// ErrPsbtFundingRequired is the error that is returned during the
	// contribution handling process if the process should be paused for
	// the construction of a PSBT outside of lnd's wallet.
	ErrPsbtFundingRequired = errors.New("PSBT funding required")

	// ErrReservedValueInvalidated is returned if we try to publish a
	// transaction that would take the walletbalance below what we require
	// to keep around to fee bump our open anchor channels.
	ErrReservedValueInvalidated = errors.New("reserved wallet balance " +
		"invalidated")
)

// PsbtFundingRequired is a type that implements the error interface and
// contains the information needed to construct a PSBT.
type PsbtFundingRequired struct {
	// Intent is the pending PSBT funding intent that needs to be funded
	// if the wrapping error is returned.
	Intent *chanfunding.PsbtIntent
}

// Error returns the underlying error.
//
// NOTE: This method is part of the error interface.
func (p *PsbtFundingRequired) Error() string {
	return ErrPsbtFundingRequired.Error()
}

// InitFundingReserveMsg is the first message sent to initiate the workflow
// required to open a payment channel with a remote peer. The initial required
// parameters are configurable across channels. These parameters are to be
// chosen depending on the fee climate within the network, and time value of
// funds to be locked up within the channel. Upon success a ChannelReservation
// will be created in order to track the lifetime of this pending channel.
// Outputs selected will be 'locked', making them unavailable, for any other
// pending reservations. Therefore, all channels in reservation limbo will be
// periodically timed out after an idle period in order to avoid "exhaustion"
// attacks.
type InitFundingReserveMsg struct {
	// ChainHash denotes that chain to be used to ultimately open the
	// target channel.
	ChainHash *chainhash.Hash

	// PendingChanID is the pending channel ID for this funding flow as
	// used in the wire protocol.
	PendingChanID [32]byte

	// NodeID is the ID of the remote node we would like to open a channel
	// with.
	NodeID *btcec.PublicKey

	// NodeAddr is the address port that we used to either establish or
	// accept the connection which led to the negotiation of this funding
	// workflow.
	NodeAddr net.Addr

	// SubtractFees should be set if we intend to spend exactly
	// LocalFundingAmt when opening the channel, subtracting the fees from
	// the funding output. This can be used for instance to use all our
	// remaining funds to open the channel, since it will take fees into
	// account.
	SubtractFees bool

	// LocalFundingAmt is the amount of funds requested from us for this
	// channel.
	LocalFundingAmt btcutil.Amount

	// RemoteFundingAmnt is the amount of funds the remote will contribute
	// to this channel.
	RemoteFundingAmt btcutil.Amount

	// CommitFeePerKw is the starting accepted satoshis/Kw fee for the set
	// of initial commitment transactions. In order to ensure timely
	// confirmation, it is recommended that this fee should be generous,
	// paying some multiple of the accepted base fee rate of the network.
	CommitFeePerKw chainfee.SatPerKWeight

	// FundingFeePerKw is the fee rate in sat/kw to use for the initial
	// funding transaction.
	FundingFeePerKw chainfee.SatPerKWeight

	// PushMSat is the number of milli-satoshis that should be pushed over
	// the responder as part of the initial channel creation.
	PushMSat lnwire.MilliSatoshi

	// Flags are the channel flags specified by the initiator in the
	// open_channel message.
	Flags lnwire.FundingFlag

	// MinConfs indicates the minimum number of confirmations that each
	// output selected to fund the channel should satisfy.
	MinConfs int32

	// CommitType indicates what type of commitment type the channel should
	// be using, like tweakless or anchors.
	CommitType CommitmentType

	// ChanFunder is an optional channel funder that allows the caller to
	// control exactly how the channel funding is carried out. If not
	// specified, then the default chanfunding.WalletAssembler will be
	// used.
	ChanFunder chanfunding.Assembler

	// err is a channel in which all errors will be sent across. Will be
	// nil if this initial set is successful.
	//
	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error

	// resp is channel in which a ChannelReservation with our contributions
	// filled in will be sent across this channel in the case of a
	// successfully reservation initiation. In the case of an error, this
	// will read a nil pointer.
	//
	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	resp chan *ChannelReservation
}

// fundingReserveCancelMsg is a message reserved for cancelling an existing
// channel reservation identified by its reservation ID. Cancelling a reservation
// frees its locked outputs up, for inclusion within further reservations.
type fundingReserveCancelMsg struct {
	pendingFundingID uint64

	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error // Buffered
}

// addContributionMsg represents a message executing the second phase of the
// channel reservation workflow. This message carries the counterparty's
// "contribution" to the payment channel. In the case that this message is
// processed without generating any errors, then channel reservation will then
// be able to construct the funding tx, both commitment transactions, and
// finally generate signatures for all our inputs to the funding transaction,
// and for the remote node's version of the commitment transaction.
type addContributionMsg struct {
	pendingFundingID uint64

	// TODO(roasbeef): Should also carry SPV proofs in we're in SPV mode
	contribution *ChannelContribution

	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error
}

// continueContributionMsg represents a message that signals that the
// interrupted funding process involving a PSBT can now be continued because the
// finalized transaction is now available.
type continueContributionMsg struct {
	pendingFundingID uint64

	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error
}

// addSingleContributionMsg represents a message executing the second phase of
// a single funder channel reservation workflow. This messages carries the
// counterparty's "contribution" to the payment channel. As this message is
// sent when on the responding side to a single funder workflow, no further
// action apart from storing the provided contribution is carried out.
type addSingleContributionMsg struct {
	pendingFundingID uint64

	contribution *ChannelContribution

	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error
}

// addCounterPartySigsMsg represents the final message required to complete,
// and 'open' a payment channel. This message carries the counterparty's
// signatures for each of their inputs to the funding transaction, and also a
// signature allowing us to spend our version of the commitment transaction.
// If we're able to verify all the signatures are valid, the funding transaction
// will be broadcast to the network. After the funding transaction gains a
// configurable number of confirmations, the channel is officially considered
// 'open'.
type addCounterPartySigsMsg struct {
	pendingFundingID uint64

	// Should be order of sorted inputs that are theirs. Sorting is done
	// in accordance to BIP-69:
	// https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki.
	theirFundingInputScripts []*input.Script

	// This should be 1/2 of the signatures needed to successfully spend our
	// version of the commitment transaction.
	theirCommitmentSig input.Signature

	// This channel is used to return the completed channel after the wallet
	// has completed all of its stages in the funding process.
	completeChan chan *channeldb.OpenChannel

	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error
}

// addSingleFunderSigsMsg represents the next-to-last message required to
// complete a single-funder channel workflow. Once the initiator is able to
// construct the funding transaction, they send both the outpoint and a
// signature for our version of the commitment transaction. Once this message
// is processed we (the responder) are able to construct both commitment
// transactions, signing the remote party's version.
type addSingleFunderSigsMsg struct {
	pendingFundingID uint64

	// fundingOutpoint is the outpoint of the completed funding
	// transaction as assembled by the workflow initiator.
	fundingOutpoint *wire.OutPoint

	// theirCommitmentSig are the 1/2 of the signatures needed to
	// successfully spend our version of the commitment transaction.
	theirCommitmentSig input.Signature

	// This channel is used to return the completed channel after the wallet
	// has completed all of its stages in the funding process.
	completeChan chan *channeldb.OpenChannel

	// NOTE: In order to avoid deadlocks, this channel MUST be buffered.
	err chan error
}

// LightningWallet is a domain specific, yet general Bitcoin wallet capable of
// executing workflow required to interact with the Lightning Network. It is
// domain specific in the sense that it understands all the fancy scripts used
// within the Lightning Network, channel lifetimes, etc. However, it embeds a
// general purpose Bitcoin wallet within it. Therefore, it is also able to
// serve as a regular Bitcoin wallet which uses HD keys. The wallet is highly
// concurrent internally. All communication, and requests towards the wallet
// are dispatched as messages over channels, ensuring thread safety across all
// operations. Interaction has been designed independent of any peer-to-peer
// communication protocol, allowing the wallet to be self-contained and
// embeddable within future projects interacting with the Lightning Network.
//
// NOTE: At the moment the wallet requires a btcd full node, as it's dependent
// on btcd's websockets notifications as event triggers during the lifetime of a
// channel. However, once the chainntnfs package is complete, the wallet will
// be compatible with multiple RPC/notification services such as Electrum,
// Bitcoin Core + ZeroMQ, etc. Eventually, the wallet won't require a full-node
// at all, as SPV support is integrated into btcwallet.
type LightningWallet struct {
	started  int32 // To be used atomically.
	shutdown int32 // To be used atomically.

	nextFundingID uint64 // To be used atomically.

	// Cfg is the configuration struct that will be used by the wallet to
	// access the necessary interfaces and default it needs to carry on its
	// duties.
	Cfg Config

	// WalletController is the core wallet, all non Lightning Network
	// specific interaction is proxied to the internal wallet.
	WalletController

	// SecretKeyRing is the interface we'll use to derive any keys related
	// to our purpose within the network including: multi-sig keys, node
	// keys, revocation keys, etc.
	keychain.SecretKeyRing

	// This mutex MUST be held when performing coin selection in order to
	// avoid inadvertently creating multiple funding transaction which
	// double spend inputs across each other.
	coinSelectMtx sync.RWMutex

	// All messages to the wallet are to be sent across this channel.
	msgChan chan interface{}

	// Incomplete payment channels are stored in the map below. An intent
	// to create a payment channel is tracked as a "reservation" within
	// limbo. Once the final signatures have been exchanged, a reservation
	// is removed from limbo. Each reservation is tracked by a unique
	// monotonically integer. All requests concerning the channel MUST
	// carry a valid, active funding ID.
	fundingLimbo map[uint64]*ChannelReservation

	// reservationIDs maps a pending channel ID to the reservation ID used
	// as key in the fundingLimbo map. Used to easily look up a channel
	// reservation given a pending channel ID.
	reservationIDs map[[32]byte]uint64
	limboMtx       sync.RWMutex

	// lockedOutPoints is a set of the currently locked outpoint. This
	// information is kept in order to provide an easy way to unlock all
	// the currently locked outpoints.
	lockedOutPoints map[wire.OutPoint]struct{}

	// fundingIntents houses all the "interception" registered by a caller
	// using the RegisterFundingIntent method.
	intentMtx      sync.RWMutex
	fundingIntents map[[32]byte]chanfunding.Intent

	quit chan struct{}

	wg sync.WaitGroup

	// TODO(roasbeef): handle wallet lock/unlock
}

// NewLightningWallet creates/opens and initializes a LightningWallet instance.
// If the wallet has never been created (according to the passed dataDir), first-time
// setup is executed.
func NewLightningWallet(Cfg Config) (*LightningWallet, error) {

	return &LightningWallet{
		Cfg:              Cfg,
		SecretKeyRing:    Cfg.SecretKeyRing,
		WalletController: Cfg.WalletController,
		msgChan:          make(chan interface{}, msgBufferSize),
		nextFundingID:    0,
		fundingLimbo:     make(map[uint64]*ChannelReservation),
		reservationIDs:   make(map[[32]byte]uint64),
		lockedOutPoints:  make(map[wire.OutPoint]struct{}),
		fundingIntents:   make(map[[32]byte]chanfunding.Intent),
		quit:             make(chan struct{}),
	}, nil
}

// Startup establishes a connection to the RPC source, and spins up all
// goroutines required to handle incoming messages.
func (l *LightningWallet) Startup() error {
	// Already started?
	if atomic.AddInt32(&l.started, 1) != 1 {
		return nil
	}

	// Start the underlying wallet controller.
	if err := l.Start(); err != nil {
		return err
	}

	l.wg.Add(1)
	// TODO(roasbeef): multiple request handlers?
	go l.requestHandler()

	return nil
}

// Shutdown gracefully stops the wallet, and all active goroutines.
func (l *LightningWallet) Shutdown() error {
	if atomic.AddInt32(&l.shutdown, 1) != 1 {
		return nil
	}

	// Signal the underlying wallet controller to shutdown, waiting until
	// all active goroutines have been shutdown.
	if err := l.Stop(); err != nil {
		return err
	}

	close(l.quit)
	l.wg.Wait()
	return nil
}

// ConfirmedBalance returns the current confirmed balance of a wallet account.
// This methods wraps the internal WalletController method so we're able to
// properly hold the coin select mutex while we compute the balance.
func (l *LightningWallet) ConfirmedBalance(confs int32,
	account string) (btcutil.Amount, error) {

	l.coinSelectMtx.Lock()
	defer l.coinSelectMtx.Unlock()

	return l.WalletController.ConfirmedBalance(confs, account)
}

// ListUnspentWitnessFromDefaultAccount returns all unspent outputs from the
// default wallet account which are version 0 witness programs. The 'minConfs'
// and 'maxConfs' parameters indicate the minimum and maximum number of
// confirmations an output needs in order to be returned by this method. Passing
// -1 as 'minConfs' indicates that even unconfirmed outputs should be returned.
// Using MaxInt32 as 'maxConfs' implies returning all outputs with at least
// 'minConfs'.
//
// NOTE: This method requires the global coin selection lock to be held.
func (l *LightningWallet) ListUnspentWitnessFromDefaultAccount(
	minConfs, maxConfs int32) ([]*Utxo, error) {

	return l.WalletController.ListUnspentWitness(
		minConfs, maxConfs, DefaultAccountName,
	)
}

// LockedOutpoints returns a list of all currently locked outpoint.
func (l *LightningWallet) LockedOutpoints() []*wire.OutPoint {
	outPoints := make([]*wire.OutPoint, 0, len(l.lockedOutPoints))
	for outPoint := range l.lockedOutPoints {
		outPoint := outPoint

		outPoints = append(outPoints, &outPoint)
	}

	return outPoints
}

// ResetReservations reset the volatile wallet state which tracks all currently
// active reservations.
func (l *LightningWallet) ResetReservations() {
	l.nextFundingID = 0
	l.fundingLimbo = make(map[uint64]*ChannelReservation)
	l.reservationIDs = make(map[[32]byte]uint64)

	for outpoint := range l.lockedOutPoints {
		l.UnlockOutpoint(outpoint)
	}
	l.lockedOutPoints = make(map[wire.OutPoint]struct{})
}

// ActiveReservations returns a slice of all the currently active
// (non-canceled) reservations.
func (l *LightningWallet) ActiveReservations() []*ChannelReservation {
	reservations := make([]*ChannelReservation, 0, len(l.fundingLimbo))
	for _, reservation := range l.fundingLimbo {
		reservations = append(reservations, reservation)
	}

	return reservations
}

// requestHandler is the primary goroutine(s) responsible for handling, and
// dispatching replies to all messages.
func (l *LightningWallet) requestHandler() {
	defer l.wg.Done()

out:
	for {
		select {
		case m := <-l.msgChan:
			switch msg := m.(type) {
			case *InitFundingReserveMsg:
				l.handleFundingReserveRequest(msg)
			case *fundingReserveCancelMsg:
				l.handleFundingCancelRequest(msg)
			case *addSingleContributionMsg:
				l.handleSingleContribution(msg)
			case *addContributionMsg:
				l.handleContributionMsg(msg)
			case *continueContributionMsg:
				l.handleChanPointReady(msg)
			case *addSingleFunderSigsMsg:
				l.handleSingleFunderSigs(msg)
			case *addCounterPartySigsMsg:
				l.handleFundingCounterPartySigs(msg)
			}
		case <-l.quit:
			// TODO: do some clean up
			break out
		}
	}
}

// InitChannelReservation kicks off the 3-step workflow required to successfully
// open a payment channel with a remote node. As part of the funding
// reservation, the inputs selected for the funding transaction are 'locked'.
// This ensures that multiple channel reservations aren't double spending the
// same inputs in the funding transaction. If reservation initialization is
// successful, a ChannelReservation containing our completed contribution is
// returned. Our contribution contains all the items necessary to allow the
// counterparty to build the funding transaction, and both versions of the
// commitment transaction. Otherwise, an error occurred and a nil pointer along
// with an error are returned.
//
// Once a ChannelReservation has been obtained, two additional steps must be
// processed before a payment channel can be considered 'open'. The second step
// validates, and processes the counterparty's channel contribution. The third,
// and final step verifies all signatures for the inputs of the funding
// transaction, and that the signature we record for our version of the
// commitment transaction is valid.
func (l *LightningWallet) InitChannelReservation(
	req *InitFundingReserveMsg) (*ChannelReservation, error) {

	req.resp = make(chan *ChannelReservation, 1)
	req.err = make(chan error, 1)

	select {
	case l.msgChan <- req:
	case <-l.quit:
		return nil, errors.New("wallet shutting down")
	}

	return <-req.resp, <-req.err
}

// RegisterFundingIntent allows a caller to signal to the wallet that if a
// pending channel ID of expectedID is found, then it can skip constructing a
// new chanfunding.Assembler, and instead use the specified chanfunding.Intent.
// As an example, this lets some of the parameters for funding transaction to
// be negotiated outside the regular funding protocol.
func (l *LightningWallet) RegisterFundingIntent(expectedID [32]byte,
	shimIntent chanfunding.Intent) error {

	l.intentMtx.Lock()
	defer l.intentMtx.Unlock()

	if _, ok := l.fundingIntents[expectedID]; ok {
		return fmt.Errorf("pendingChanID(%x) already has intent "+
			"registered", expectedID[:])
	}

	l.fundingIntents[expectedID] = shimIntent

	return nil
}

// PsbtFundingVerify looks up a previously registered funding intent by its
// pending channel ID and tries to advance the state machine by verifying the
// passed PSBT.
func (l *LightningWallet) PsbtFundingVerify(pendingChanID [32]byte,
	packet *psbt.Packet) error {

	l.intentMtx.Lock()
	defer l.intentMtx.Unlock()

	intent, ok := l.fundingIntents[pendingChanID]
	if !ok {
		return fmt.Errorf("no funding intent found for "+
			"pendingChannelID(%x)", pendingChanID[:])
	}
	psbtIntent, ok := intent.(*chanfunding.PsbtIntent)
	if !ok {
		return fmt.Errorf("incompatible funding intent")
	}
	err := psbtIntent.Verify(packet)
	if err != nil {
		return fmt.Errorf("error verifying PSBT: %v", err)
	}

	// Get the channel reservation for that corresponds to this pending
	// channel ID.
	l.limboMtx.Lock()
	pid, ok := l.reservationIDs[pendingChanID]
	if !ok {
		l.limboMtx.Unlock()
		return fmt.Errorf("no channel reservation found for "+
			"pendingChannelID(%x)", pendingChanID[:])
	}

	pendingReservation, ok := l.fundingLimbo[pid]
	l.limboMtx.Unlock()

	if !ok {
		return fmt.Errorf("no channel reservation found for "+
			"reservation ID %v", pid)
	}

	// Now the the PSBT has been verified, we can again check whether the
	// value reserved for anchor fee bumping is respected.
	numAnchors, err := l.currentNumAnchorChans()
	if err != nil {
		return err
	}

	// If this commit type is an anchor channel we add that to our counter,
	// but only if we are contributing funds to the channel. This is done
	// to still allow incoming channels even though we have no UTXOs
	// available, as in bootstrapping phases. We only count public
	// channels.
	isPublic := pendingReservation.partialState.ChannelFlags&lnwire.FFAnnounceChannel != 0
	if pendingReservation.partialState.ChanType.HasAnchors() &&
		intent.LocalFundingAmt() > 0 && isPublic {
		numAnchors++
	}

	// We check the reserve value again, this should already have been
	// checked for regular FullIntents, but now the PSBT intent is also
	// populated.
	return l.WithCoinSelectLock(func() error {
		_, err := l.CheckReservedValue(
			intent.Inputs(), intent.Outputs(), numAnchors,
		)
		return err
	})
}

// PsbtFundingFinalize looks up a previously registered funding intent by its
// pending channel ID and tries to advance the state machine by finalizing the
// passed PSBT.
func (l *LightningWallet) PsbtFundingFinalize(pid [32]byte, packet *psbt.Packet,
	rawTx *wire.MsgTx) error {

	l.intentMtx.Lock()
	defer l.intentMtx.Unlock()

	intent, ok := l.fundingIntents[pid]
	if !ok {
		return fmt.Errorf("no funding intent found for "+
			"pendingChannelID(%x)", pid[:])
	}
	psbtIntent, ok := intent.(*chanfunding.PsbtIntent)
	if !ok {
		return fmt.Errorf("incompatible funding intent")
	}

	// Either the PSBT or the raw TX must be set.
	switch {
	case packet != nil && rawTx == nil:
		err := psbtIntent.Finalize(packet)
		if err != nil {
			return fmt.Errorf("error finalizing PSBT: %v", err)
		}

	case rawTx != nil && packet == nil:
		err := psbtIntent.FinalizeRawTX(rawTx)
		if err != nil {
			return fmt.Errorf("error finalizing raw TX: %v", err)
		}

	default:
		return fmt.Errorf("either a PSBT or raw TX must be specified")
	}

	return nil
}

// CancelFundingIntent allows a caller to cancel a previously registered
// funding intent. If no intent was found, then an error will be returned.
func (l *LightningWallet) CancelFundingIntent(pid [32]byte) error {
	l.intentMtx.Lock()
	defer l.intentMtx.Unlock()

	intent, ok := l.fundingIntents[pid]
	if !ok {
		return fmt.Errorf("no funding intent found for "+
			"pendingChannelID(%x)", pid[:])
	}

	// Give the intent a chance to clean up after itself, removing coin
	// locks or similar reserved resources.
	intent.Cancel()

	delete(l.fundingIntents, pid)

	return nil
}

// handleFundingReserveRequest processes a message intending to create, and
// validate a funding reservation request.
func (l *LightningWallet) handleFundingReserveRequest(req *InitFundingReserveMsg) {
	// It isn't possible to create a channel with zero funds committed.
	if req.LocalFundingAmt+req.RemoteFundingAmt == 0 {
		err := ErrZeroCapacity()
		req.err <- err
		req.resp <- nil
		return
	}

	// If the funding request is for a different chain than the one the
	// wallet is aware of, then we'll reject the request.
	if !bytes.Equal(l.Cfg.NetParams.GenesisHash[:], req.ChainHash[:]) {
		err := ErrChainMismatch(
			l.Cfg.NetParams.GenesisHash, req.ChainHash,
		)
		req.err <- err
		req.resp <- nil
		return
	}

	// If no chanFunder was provided, then we'll assume the default
	// assembler, which is backed by the wallet's internal coin selection.
	if req.ChanFunder == nil {
		cfg := chanfunding.WalletConfig{
			CoinSource:       &CoinSource{l},
			CoinSelectLocker: l,
			CoinLocker:       l,
			Signer:           l.Cfg.Signer,
			DustLimit:        DefaultDustLimit(),
		}
		req.ChanFunder = chanfunding.NewWalletAssembler(cfg)
	}

	localFundingAmt := req.LocalFundingAmt
	remoteFundingAmt := req.RemoteFundingAmt

	var (
		fundingIntent chanfunding.Intent
		err           error
	)

	// If we've just received an inbound funding request that we have a
	// registered shim intent to, then we'll obtain the backing intent now.
	// In this case, we're doing a special funding workflow that allows
	// more advanced constructions such as channel factories to be
	// instantiated.
	l.intentMtx.Lock()
	fundingIntent, ok := l.fundingIntents[req.PendingChanID]
	l.intentMtx.Unlock()

	// Otherwise, this is a normal funding flow, so we'll use the chan
	// funder in the attached request to provision the inputs/outputs
	// that'll ultimately be used to construct the funding transaction.
	if !ok {
		// Coin selection is done on the basis of sat/kw, so we'll use
		// the fee rate passed in to perform coin selection.
		var err error
		fundingReq := &chanfunding.Request{
			RemoteAmt:    req.RemoteFundingAmt,
			LocalAmt:     req.LocalFundingAmt,
			MinConfs:     req.MinConfs,
			SubtractFees: req.SubtractFees,
			FeeRate:      req.FundingFeePerKw,
			ChangeAddr: func() (btcutil.Address, error) {
				return l.NewAddress(
					WitnessPubKey, true, DefaultAccountName,
				)
			},
		}
		fundingIntent, err = req.ChanFunder.ProvisionChannel(
			fundingReq,
		)
		if err != nil {
			req.err <- err
			req.resp <- nil
			return
		}

		// Register the funding intent now in case we need to access it
		// again later, as it's the case for the PSBT state machine for
		// example.
		err = l.RegisterFundingIntent(req.PendingChanID, fundingIntent)
		if err != nil {
			req.err <- err
			req.resp <- nil
			return
		}

		localFundingAmt = fundingIntent.LocalFundingAmt()
		remoteFundingAmt = fundingIntent.RemoteFundingAmt()
	}

	// At this point there _has_ to be a funding intent, otherwise something
	// went really wrong.
	if fundingIntent == nil {
		req.err <- fmt.Errorf("no funding intent present")
		req.resp <- nil
		return
	}

	// If this is a shim intent, then it may be attempting to use an
	// existing set of keys for the funding workflow. In this case, we'll
	// make a simple wrapper keychain.KeyRing that will proxy certain
	// derivation calls to future callers.
	var (
		keyRing    keychain.KeyRing = l.SecretKeyRing
		thawHeight uint32
	)
	if shimIntent, ok := fundingIntent.(*chanfunding.ShimIntent); ok {
		keyRing = &shimKeyRing{
			KeyRing:    keyRing,
			ShimIntent: shimIntent,
		}

		// As this was a registered shim intent, we'll obtain the thaw
		// height of the intent, if present at all. If this is
		// non-zero, then we'll mark this as the proper channel type.
		thawHeight = shimIntent.ThawHeight()
	}

	// Now that we have a funding intent, we'll check whether funding a
	// channel using it would violate our reserved value for anchor channel
	// fee bumping. We first get our current number of anchor channels.
	numAnchors, err := l.currentNumAnchorChans()
	if err != nil {
		fundingIntent.Cancel()

		req.err <- err
		req.resp <- nil
		return
	}

	// If this commit type is an anchor channel we add that to our counter,
	// but only if we are contributing funds to the channel. This is done
	// to still allow incoming channels even though we have no UTXOs
	// available, as in bootstrapping phases. We only count public
	// channels.
	isPublic := req.Flags&lnwire.FFAnnounceChannel != 0
	if req.CommitType == CommitmentTypeAnchorsZeroFeeHtlcTx &&
		fundingIntent.LocalFundingAmt() > 0 && isPublic {
		numAnchors++
	}

	// Check the reserved value using the inputs and outputs given by the
	// intent. Not that for the PSBT intent type we don't yet have the
	// funding tx ready, so this will always pass. We'll do another check
	// when the PSBT has been verified.
	err = l.WithCoinSelectLock(func() error {
		_, err := l.CheckReservedValue(
			fundingIntent.Inputs(), fundingIntent.Outputs(),
			numAnchors,
		)
		return err
	})
	if err != nil {
		fundingIntent.Cancel()

		req.err <- err
		req.resp <- nil
		return
	}

	// The total channel capacity will be the size of the funding output we
	// created plus the remote contribution.
	capacity := localFundingAmt + remoteFundingAmt

	id := atomic.AddUint64(&l.nextFundingID, 1)
	reservation, err := NewChannelReservation(
		capacity, localFundingAmt, req.CommitFeePerKw, l, id,
		req.PushMSat, l.Cfg.NetParams.GenesisHash, req.Flags,
		req.CommitType, req.ChanFunder, req.PendingChanID,
		thawHeight,
	)
	if err != nil {
		fundingIntent.Cancel()

		req.err <- err
		req.resp <- nil
		return
	}

	err = l.initOurContribution(
		reservation, fundingIntent, req.NodeAddr, req.NodeID, keyRing,
	)
	if err != nil {
		fundingIntent.Cancel()

		req.err <- err
		req.resp <- nil
		return
	}

	// Create a limbo and record entry for this newly pending funding
	// request.
	l.limboMtx.Lock()
	l.fundingLimbo[id] = reservation
	l.reservationIDs[req.PendingChanID] = id
	l.limboMtx.Unlock()

	// Funding reservation request successfully handled. The funding inputs
	// will be marked as unavailable until the reservation is either
	// completed, or canceled.
	req.resp <- reservation
	req.err <- nil
}

// currentNumAnchorChans returns the current number of non-private anchor
// channels the wallet should be ready to fee bump if needed.
func (l *LightningWallet) currentNumAnchorChans() (int, error) {
	// Count all anchor channels that are open or pending
	// open, or waiting close.
	chans, err := l.Cfg.Database.FetchAllChannels()
	if err != nil {
		return 0, err
	}

	var numAnchors int
	cntChannel := func(c *channeldb.OpenChannel) {
		// We skip private channels, as we assume they won't be used
		// for routing.
		if c.ChannelFlags&lnwire.FFAnnounceChannel == 0 {
			return
		}

		// Count anchor channels.
		if c.ChanType.HasAnchors() {
			numAnchors++
		}

	}

	for _, c := range chans {
		cntChannel(c)
	}

	// We also count pending close channels.
	pendingClosed, err := l.Cfg.Database.FetchClosedChannels(
		true,
	)
	if err != nil {
		return 0, err
	}

	for _, c := range pendingClosed {
		c, err := l.Cfg.Database.FetchHistoricalChannel(
			&c.ChanPoint,
		)
		if err != nil {
			// We don't have a guarantee that all channels re found
			// in the historical channels bucket, so we continue.
			walletLog.Warnf("Unable to fetch historical "+
				"channel: %v", err)
			continue
		}

		cntChannel(c)
	}

	return numAnchors, nil
}

// CheckReservedValue checks whether publishing a transaction with the given
// inputs and outputs would violate the value we reserve in the wallet for
// bumping the fee of anchor channels. The numAnchorChans argument should be
// set the the number of open anchor channels controlled by the wallet after
// the transaction has been published.
//
// If the reserved value is violated, the returned error will be
// ErrReservedValueInvalidated. The method will also return the current
// reserved value, both in case of success and in case of
// ErrReservedValueInvalidated.
//
// NOTE: This method should only be run with the CoinSelectLock held.
func (l *LightningWallet) CheckReservedValue(in []wire.OutPoint,
	out []*wire.TxOut, numAnchorChans int) (btcutil.Amount, error) {

	// Get all unspent coins in the wallet. We only care about those part of
	// the wallet's default account as we know we can readily sign for those
	// at any time.
	witnessOutputs, err := l.ListUnspentWitnessFromDefaultAccount(
		0, math.MaxInt32,
	)
	if err != nil {
		return 0, err
	}

	ourInput := make(map[wire.OutPoint]struct{})
	for _, op := range in {
		ourInput[op] = struct{}{}
	}

	// When crafting a transaction with inputs from the wallet, these coins
	// will usually be locked in the process, and not be returned when
	// listing unspents. In this case they have already been deducted from
	// the wallet balance. In case they haven't been properly locked, we
	// check whether they are still listed among our unspents and deduct
	// them.
	var walletBalance btcutil.Amount
	for _, in := range witnessOutputs {
		// Spending an unlocked wallet UTXO, don't add it to the
		// balance.
		if _, ok := ourInput[in.OutPoint]; ok {
			continue
		}

		walletBalance += in.Value
	}

	// Now we go through the outputs of the transaction, if any of the
	// outputs are paying into the wallet (likely a change output), we add
	// it to our final balance.
	for _, txOut := range out {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, &l.Cfg.NetParams,
		)
		if err != nil {
			// Non-standard outputs can safely be skipped because
			// they're not supported by the wallet.
			continue
		}

		for _, addr := range addrs {
			if !l.IsOurAddress(addr) {
				continue
			}

			walletBalance += btcutil.Amount(txOut.Value)

			// We break since we don't want to double count the output.
			break
		}
	}

	// We reserve a given amount for each anchor channel.
	reserved := btcutil.Amount(numAnchorChans) * anchorChanReservedValue
	if reserved > maxAnchorChanReservedValue {
		reserved = maxAnchorChanReservedValue
	}

	if walletBalance < reserved {
		walletLog.Debugf("Reserved value=%v above final "+
			"walletbalance=%v with %d anchor channels open",
			reserved, walletBalance, numAnchorChans)
		return reserved, ErrReservedValueInvalidated
	}

	return reserved, nil
}

// CheckReservedValueTx calls CheckReservedValue with the inputs and outputs
// from the given tx, with the number of anchor channels currently open in the
// database.
//
// NOTE: This method should only be run with the CoinSelectLock held.
func (l *LightningWallet) CheckReservedValueTx(tx *wire.MsgTx) (btcutil.Amount,
	error) {

	numAnchors, err := l.currentNumAnchorChans()
	if err != nil {
		return 0, err
	}

	var inputs []wire.OutPoint
	for _, txIn := range tx.TxIn {
		inputs = append(inputs, txIn.PreviousOutPoint)
	}

	return l.CheckReservedValue(inputs, tx.TxOut, numAnchors)
}

// initOurContribution initializes the given ChannelReservation with our coins
// and change reserved for the channel, and derives the keys to use for this
// channel.
func (l *LightningWallet) initOurContribution(reservation *ChannelReservation,
	fundingIntent chanfunding.Intent, nodeAddr net.Addr,
	nodeID *btcec.PublicKey, keyRing keychain.KeyRing) error {

	// Grab the mutex on the ChannelReservation to ensure thread-safety
	reservation.Lock()
	defer reservation.Unlock()

	// At this point, if we have a funding intent, we'll use it to populate
	// the existing reservation state entries for our coin selection.
	if fundingIntent != nil {
		if intent, ok := fundingIntent.(*chanfunding.FullIntent); ok {
			for _, coin := range intent.InputCoins {
				reservation.ourContribution.Inputs = append(
					reservation.ourContribution.Inputs,
					&wire.TxIn{
						PreviousOutPoint: coin.OutPoint,
					},
				)
			}
			reservation.ourContribution.ChangeOutputs = intent.ChangeOutputs
		}

		reservation.fundingIntent = fundingIntent
	}

	reservation.nodeAddr = nodeAddr
	reservation.partialState.IdentityPub = nodeID

	var err error
	reservation.ourContribution.MultiSigKey, err = keyRing.DeriveNextKey(
		keychain.KeyFamilyMultiSig,
	)
	if err != nil {
		return err
	}
	reservation.ourContribution.RevocationBasePoint, err = keyRing.DeriveNextKey(
		keychain.KeyFamilyRevocationBase,
	)
	if err != nil {
		return err
	}
	reservation.ourContribution.HtlcBasePoint, err = keyRing.DeriveNextKey(
		keychain.KeyFamilyHtlcBase,
	)
	if err != nil {
		return err
	}
	reservation.ourContribution.PaymentBasePoint, err = keyRing.DeriveNextKey(
		keychain.KeyFamilyPaymentBase,
	)
	if err != nil {
		return err
	}
	reservation.ourContribution.DelayBasePoint, err = keyRing.DeriveNextKey(
		keychain.KeyFamilyDelayBase,
	)
	if err != nil {
		return err
	}

	// With the above keys created, we'll also need to initialize our
	// revocation tree state, and from that generate the per-commitment point.
	producer, err := l.nextRevocationProducer(reservation, keyRing)
	if err != nil {
		return err
	}

	firstPreimage, err := producer.AtIndex(0)
	if err != nil {
		return err
	}
	reservation.ourContribution.FirstCommitmentPoint = input.ComputeCommitmentPoint(
		firstPreimage[:],
	)

	reservation.partialState.RevocationProducer = producer
	reservation.ourContribution.ChannelConstraints = l.Cfg.DefaultConstraints

	return nil
}

// handleFundingReserveCancel cancels an existing channel reservation. As part
// of the cancellation, outputs previously selected as inputs for the funding
// transaction via coin selection are freed allowing future reservations to
// include them.
func (l *LightningWallet) handleFundingCancelRequest(req *fundingReserveCancelMsg) {
	// TODO(roasbeef): holding lock too long
	l.limboMtx.Lock()
	defer l.limboMtx.Unlock()

	pendingReservation, ok := l.fundingLimbo[req.pendingFundingID]
	if !ok {
		// TODO(roasbeef): make new error, "unknown funding state" or something
		req.err <- fmt.Errorf("attempted to cancel non-existent funding state")
		return
	}

	// Grab the mutex on the ChannelReservation to ensure thread-safety
	pendingReservation.Lock()
	defer pendingReservation.Unlock()

	// Mark all previously locked outpoints as useable for future funding
	// requests.
	for _, unusedInput := range pendingReservation.ourContribution.Inputs {
		delete(l.lockedOutPoints, unusedInput.PreviousOutPoint)
		l.UnlockOutpoint(unusedInput.PreviousOutPoint)
	}

	// TODO(roasbeef): is it even worth it to keep track of unused keys?

	// TODO(roasbeef): Is it possible to mark the unused change also as
	// available?

	delete(l.fundingLimbo, req.pendingFundingID)

	pid := pendingReservation.pendingChanID
	delete(l.reservationIDs, pid)

	l.intentMtx.Lock()
	if intent, ok := l.fundingIntents[pid]; ok {
		intent.Cancel()

		delete(l.fundingIntents, pendingReservation.pendingChanID)
	}
	l.intentMtx.Unlock()

	req.err <- nil
}

// CreateCommitmentTxns is a helper function that creates the initial
// commitment transaction for both parties. This function is used during the
// initial funding workflow as both sides must generate a signature for the
// remote party's commitment transaction, and verify the signature for their
// version of the commitment transaction.
func CreateCommitmentTxns(localBalance, remoteBalance btcutil.Amount,
	ourChanCfg, theirChanCfg *channeldb.ChannelConfig,
	localCommitPoint, remoteCommitPoint *btcec.PublicKey,
	fundingTxIn wire.TxIn, chanType channeldb.ChannelType) (
	*wire.MsgTx, *wire.MsgTx, error) {

	localCommitmentKeys := DeriveCommitmentKeys(
		localCommitPoint, true, chanType, ourChanCfg, theirChanCfg,
	)
	remoteCommitmentKeys := DeriveCommitmentKeys(
		remoteCommitPoint, false, chanType, ourChanCfg, theirChanCfg,
	)

	ourCommitTx, err := CreateCommitTx(
		chanType, fundingTxIn, localCommitmentKeys, ourChanCfg,
		theirChanCfg, localBalance, remoteBalance, 0,
	)
	if err != nil {
		return nil, nil, err
	}

	otxn := btcutil.NewTx(ourCommitTx)
	if err := blockchain.CheckTransactionSanity(otxn); err != nil {
		return nil, nil, err
	}

	theirCommitTx, err := CreateCommitTx(
		chanType, fundingTxIn, remoteCommitmentKeys, theirChanCfg,
		ourChanCfg, remoteBalance, localBalance, 0,
	)
	if err != nil {
		return nil, nil, err
	}

	ttxn := btcutil.NewTx(theirCommitTx)
	if err := blockchain.CheckTransactionSanity(ttxn); err != nil {
		return nil, nil, err
	}

	return ourCommitTx, theirCommitTx, nil
}

// handleContributionMsg processes the second workflow step for the lifetime of
// a channel reservation. Upon completion, the reservation will carry a
// completed funding transaction (minus the counterparty's input signatures),
// both versions of the commitment transaction, and our signature for their
// version of the commitment transaction.
func (l *LightningWallet) handleContributionMsg(req *addContributionMsg) {

	l.limboMtx.Lock()
	pendingReservation, ok := l.fundingLimbo[req.pendingFundingID]
	l.limboMtx.Unlock()
	if !ok {
		req.err <- fmt.Errorf("attempted to update non-existent funding state")
		return
	}

	// Grab the mutex on the ChannelReservation to ensure thread-safety
	pendingReservation.Lock()
	defer pendingReservation.Unlock()

	// Some temporary variables to cut down on the resolution verbosity.
	pendingReservation.theirContribution = req.contribution
	theirContribution := req.contribution
	ourContribution := pendingReservation.ourContribution

	var (
		chanPoint *wire.OutPoint
		err       error
	)

	// At this point, we can now construct our channel point. Depending on
	// which type of intent we obtained from our chanfunding.Assembler,
	// we'll carry out a distinct set of steps.
	switch fundingIntent := pendingReservation.fundingIntent.(type) {
	// The transaction was created outside of the wallet and might already
	// be published. Nothing left to do other than using the correct
	// outpoint.
	case *chanfunding.ShimIntent:
		chanPoint, err = fundingIntent.ChanPoint()
		if err != nil {
			req.err <- fmt.Errorf("unable to obtain chan point: %v", err)
			return
		}

		pendingReservation.partialState.FundingOutpoint = *chanPoint

	// The user has signaled that they want to use a PSBT to construct the
	// funding transaction. Because we now have the multisig keys from both
	// parties, we can create the multisig script that needs to be funded
	// and then pause the process until the user supplies the PSBT
	// containing the eventual funding transaction.
	case *chanfunding.PsbtIntent:
		if fundingIntent.PendingPsbt != nil {
			req.err <- fmt.Errorf("PSBT funding already in" +
				"progress")
			return
		}

		// Now that we know our contribution, we can bind both the local
		// and remote key which will be needed to calculate the multisig
		// funding output in a next step.
		pendingChanID := pendingReservation.pendingChanID
		walletLog.Debugf("Advancing PSBT funding flow for "+
			"pending_id(%x), binding keys local_key=%v, "+
			"remote_key=%x", pendingChanID,
			&ourContribution.MultiSigKey,
			theirContribution.MultiSigKey.PubKey.SerializeCompressed())
		fundingIntent.BindKeys(
			&ourContribution.MultiSigKey,
			theirContribution.MultiSigKey.PubKey,
		)

		// Exit early because we can't continue the funding flow yet.
		req.err <- &PsbtFundingRequired{
			Intent: fundingIntent,
		}
		return

	case *chanfunding.FullIntent:
		// Now that we know their public key, we can bind theirs as
		// well as ours to the funding intent.
		fundingIntent.BindKeys(
			&pendingReservation.ourContribution.MultiSigKey,
			theirContribution.MultiSigKey.PubKey,
		)

		// With our keys bound, we can now construct+sign the final
		// funding transaction and also obtain the chanPoint that
		// creates the channel.
		fundingTx, err := fundingIntent.CompileFundingTx(
			theirContribution.Inputs,
			theirContribution.ChangeOutputs,
		)
		if err != nil {
			req.err <- fmt.Errorf("unable to construct funding "+
				"tx: %v", err)
			return
		}
		chanPoint, err = fundingIntent.ChanPoint()
		if err != nil {
			req.err <- fmt.Errorf("unable to obtain chan "+
				"point: %v", err)
			return
		}

		// Finally, we'll populate the relevant information in our
		// pendingReservation so the rest of the funding flow can
		// continue as normal.
		pendingReservation.fundingTx = fundingTx
		pendingReservation.partialState.FundingOutpoint = *chanPoint
		pendingReservation.ourFundingInputScripts = make(
			[]*input.Script, 0, len(ourContribution.Inputs),
		)
		for _, txIn := range fundingTx.TxIn {
			_, err := l.FetchInputInfo(&txIn.PreviousOutPoint)
			if err != nil {
				continue
			}

			pendingReservation.ourFundingInputScripts = append(
				pendingReservation.ourFundingInputScripts,
				&input.Script{
					Witness:   txIn.Witness,
					SigScript: txIn.SignatureScript,
				},
			)
		}

		walletLog.Debugf("Funding tx for ChannelPoint(%v) "+
			"generated: %v", chanPoint, spew.Sdump(fundingTx))
	}

	// If we landed here and didn't exit early, it means we already have
	// the channel point ready. We can jump directly to the next step.
	l.handleChanPointReady(&continueContributionMsg{
		pendingFundingID: req.pendingFundingID,
		err:              req.err,
	})
}

// handleChanPointReady continues the funding process once the channel point
// is known and the funding transaction can be completed.
func (l *LightningWallet) handleChanPointReady(req *continueContributionMsg) {
	l.limboMtx.Lock()
	pendingReservation, ok := l.fundingLimbo[req.pendingFundingID]
	l.limboMtx.Unlock()
	if !ok {
		req.err <- fmt.Errorf("attempted to update non-existent " +
			"funding state")
		return
	}
	ourContribution := pendingReservation.ourContribution
	theirContribution := pendingReservation.theirContribution
	chanPoint := pendingReservation.partialState.FundingOutpoint

	// If we're in the PSBT funding flow, we now should have everything that
	// is needed to construct and publish the full funding transaction.
	intent := pendingReservation.fundingIntent
	if psbtIntent, ok := intent.(*chanfunding.PsbtIntent); ok {
		// With our keys bound, we can now construct and possibly sign
		// the final funding transaction and also obtain the chanPoint
		// that creates the channel. We _have_to call CompileFundingTx
		// even if we don't publish ourselves as that sets the actual
		// funding outpoint in stone for this channel.
		fundingTx, err := psbtIntent.CompileFundingTx()
		if err != nil {
			req.err <- fmt.Errorf("unable to construct funding "+
				"tx: %v", err)
			return
		}
		chanPointPtr, err := psbtIntent.ChanPoint()
		if err != nil {
			req.err <- fmt.Errorf("unable to obtain chan "+
				"point: %v", err)
			return
		}

		pendingReservation.partialState.FundingOutpoint = *chanPointPtr
		chanPoint = *chanPointPtr

		// Finally, we'll populate the relevant information in our
		// pendingReservation so the rest of the funding flow can
		// continue as normal in case we are going to publish ourselves.
		if psbtIntent.ShouldPublishFundingTX() {
			pendingReservation.fundingTx = fundingTx
			pendingReservation.ourFundingInputScripts = make(
				[]*input.Script, 0, len(ourContribution.Inputs),
			)
			for _, txIn := range fundingTx.TxIn {
				pendingReservation.ourFundingInputScripts = append(
					pendingReservation.ourFundingInputScripts,
					&input.Script{
						Witness:   txIn.Witness,
						SigScript: txIn.SignatureScript,
					},
				)
			}
		}
	}

	// Initialize an empty sha-chain for them, tracking the current pending
	// revocation hash (we don't yet know the preimage so we can't add it
	// to the chain).
	s := shachain.NewRevocationStore()
	pendingReservation.partialState.RevocationStore = s

	// Store their current commitment point. We'll need this after the
	// first state transition in order to verify the authenticity of the
	// revocation.
	chanState := pendingReservation.partialState
	chanState.RemoteCurrentRevocation = theirContribution.FirstCommitmentPoint

	// Create the txin to our commitment transaction; required to construct
	// the commitment transactions.
	fundingTxIn := wire.TxIn{
		PreviousOutPoint: chanPoint,
	}

	// With the funding tx complete, create both commitment transactions.
	localBalance := pendingReservation.partialState.LocalCommitment.LocalBalance.ToSatoshis()
	remoteBalance := pendingReservation.partialState.LocalCommitment.RemoteBalance.ToSatoshis()
	ourCommitTx, theirCommitTx, err := CreateCommitmentTxns(
		localBalance, remoteBalance, ourContribution.ChannelConfig,
		theirContribution.ChannelConfig,
		ourContribution.FirstCommitmentPoint,
		theirContribution.FirstCommitmentPoint, fundingTxIn,
		pendingReservation.partialState.ChanType,
	)
	if err != nil {
		req.err <- err
		return
	}

	// With both commitment transactions constructed, generate the state
	// obfuscator then use it to encode the current state number within
	// both commitment transactions.
	var stateObfuscator [StateHintSize]byte
	if chanState.ChanType.IsSingleFunder() {
		stateObfuscator = DeriveStateHintObfuscator(
			ourContribution.PaymentBasePoint.PubKey,
			theirContribution.PaymentBasePoint.PubKey,
		)
	} else {
		ourSer := ourContribution.PaymentBasePoint.PubKey.SerializeCompressed()
		theirSer := theirContribution.PaymentBasePoint.PubKey.SerializeCompressed()
		switch bytes.Compare(ourSer, theirSer) {
		case -1:
			stateObfuscator = DeriveStateHintObfuscator(
				ourContribution.PaymentBasePoint.PubKey,
				theirContribution.PaymentBasePoint.PubKey,
			)
		default:
			stateObfuscator = DeriveStateHintObfuscator(
				theirContribution.PaymentBasePoint.PubKey,
				ourContribution.PaymentBasePoint.PubKey,
			)
		}
	}
	err = initStateHints(ourCommitTx, theirCommitTx, stateObfuscator)
	if err != nil {
		req.err <- err
		return
	}

	// Sort both transactions according to the agreed upon canonical
	// ordering. This lets us skip sending the entire transaction over,
	// instead we'll just send signatures.
	txsort.InPlaceSort(ourCommitTx)
	txsort.InPlaceSort(theirCommitTx)

	walletLog.Debugf("Local commit tx for ChannelPoint(%v): %v",
		chanPoint, spew.Sdump(ourCommitTx))
	walletLog.Debugf("Remote commit tx for ChannelPoint(%v): %v",
		chanPoint, spew.Sdump(theirCommitTx))

	// Record newly available information within the open channel state.
	chanState.FundingOutpoint = chanPoint
	chanState.LocalCommitment.CommitTx = ourCommitTx
	chanState.RemoteCommitment.CommitTx = theirCommitTx

	// Next, we'll obtain the funding witness script, and the funding
	// output itself so we can generate a valid signature for the remote
	// party.
	fundingIntent := pendingReservation.fundingIntent
	fundingWitnessScript, fundingOutput, err := fundingIntent.FundingOutput()
	if err != nil {
		req.err <- fmt.Errorf("unable to obtain funding output")
		return
	}

	// Generate a signature for their version of the initial commitment
	// transaction.
	ourKey := ourContribution.MultiSigKey
	signDesc := input.SignDescriptor{
		WitnessScript: fundingWitnessScript,
		KeyDesc:       ourKey,
		Output:        fundingOutput,
		HashType:      txscript.SigHashAll,
		SigHashes:     txscript.NewTxSigHashes(theirCommitTx),
		InputIndex:    0,
	}
	sigTheirCommit, err := l.Cfg.Signer.SignOutputRaw(theirCommitTx, &signDesc)
	if err != nil {
		req.err <- err
		return
	}
	pendingReservation.ourCommitmentSig = sigTheirCommit

	req.err <- nil
}

// handleSingleContribution is called as the second step to a single funder
// workflow to which we are the responder. It simply saves the remote peer's
// contribution to the channel, as solely the remote peer will contribute any
// funds to the channel.
func (l *LightningWallet) handleSingleContribution(req *addSingleContributionMsg) {
	l.limboMtx.Lock()
	pendingReservation, ok := l.fundingLimbo[req.pendingFundingID]
	l.limboMtx.Unlock()
	if !ok {
		req.err <- fmt.Errorf("attempted to update non-existent funding state")
		return
	}

	// Grab the mutex on the channelReservation to ensure thread-safety.
	pendingReservation.Lock()
	defer pendingReservation.Unlock()

	// TODO(roasbeef): verify sanity of remote party's parameters, fail if
	// disagree

	// Simply record the counterparty's contribution into the pending
	// reservation data as they'll be solely funding the channel entirely.
	pendingReservation.theirContribution = req.contribution
	theirContribution := pendingReservation.theirContribution
	chanState := pendingReservation.partialState

	// Initialize an empty sha-chain for them, tracking the current pending
	// revocation hash (we don't yet know the preimage so we can't add it
	// to the chain).
	remotePreimageStore := shachain.NewRevocationStore()
	chanState.RevocationStore = remotePreimageStore

	// Now that we've received their first commitment point, we'll store it
	// within the channel state so we can sync it to disk once the funding
	// process is complete.
	chanState.RemoteCurrentRevocation = theirContribution.FirstCommitmentPoint

	req.err <- nil
}

// verifyFundingInputs attempts to verify all remote inputs to the funding
// transaction.
func (l *LightningWallet) verifyFundingInputs(fundingTx *wire.MsgTx,
	remoteInputScripts []*input.Script) error {

	sigIndex := 0
	fundingHashCache := txscript.NewTxSigHashes(fundingTx)
	inputScripts := remoteInputScripts
	for i, txin := range fundingTx.TxIn {
		if len(inputScripts) != 0 && len(txin.Witness) == 0 {
			// Attach the input scripts so we can verify it below.
			txin.Witness = inputScripts[sigIndex].Witness
			txin.SignatureScript = inputScripts[sigIndex].SigScript

			// Fetch the alleged previous output along with the
			// pkscript referenced by this input.
			//
			// TODO(roasbeef): when dual funder pass actual
			// height-hint
			//
			// TODO(roasbeef): this fails for neutrino always as it
			// treats the height hint as an exact birthday of the
			// utxo rather than a lower bound
			pkScript, err := txscript.ComputePkScript(
				txin.SignatureScript, txin.Witness,
			)
			if err != nil {
				return fmt.Errorf("cannot create script: %v", err)
			}
			output, err := l.Cfg.ChainIO.GetUtxo(
				&txin.PreviousOutPoint,
				pkScript.Script(), 0, l.quit,
			)
			if output == nil {
				return fmt.Errorf("input to funding tx does "+
					"not exist: %v", err)
			}

			// Ensure that the witness+sigScript combo is valid.
			vm, err := txscript.NewEngine(
				output.PkScript, fundingTx, i,
				txscript.StandardVerifyFlags, nil,
				fundingHashCache, output.Value,
			)
			if err != nil {
				return fmt.Errorf("cannot create script "+
					"engine: %s", err)
			}
			if err = vm.Execute(); err != nil {
				return fmt.Errorf("cannot validate "+
					"transaction: %s", err)
			}

			sigIndex++
		}
	}

	return nil
}

// handleFundingCounterPartySigs is the final step in the channel reservation
// workflow. During this step, we validate *all* the received signatures for
// inputs to the funding transaction. If any of these are invalid, we bail,
// and forcibly cancel this funding request. Additionally, we ensure that the
// signature we received from the counterparty for our version of the commitment
// transaction allows us to spend from the funding output with the addition of
// our signature.
func (l *LightningWallet) handleFundingCounterPartySigs(msg *addCounterPartySigsMsg) {
	l.limboMtx.RLock()
	res, ok := l.fundingLimbo[msg.pendingFundingID]
	l.limboMtx.RUnlock()
	if !ok {
		msg.err <- fmt.Errorf("attempted to update non-existent funding state")
		return
	}

	// Grab the mutex on the ChannelReservation to ensure thread-safety
	res.Lock()
	defer res.Unlock()

	// Now we can complete the funding transaction by adding their
	// signatures to their inputs.
	res.theirFundingInputScripts = msg.theirFundingInputScripts
	inputScripts := msg.theirFundingInputScripts

	// Only if we have the final funding transaction do we need to verify
	// the final set of inputs. Otherwise, it may be the case that the
	// channel was funded via an external wallet.
	fundingTx := res.fundingTx
	if res.partialState.ChanType.HasFundingTx() {
		err := l.verifyFundingInputs(fundingTx, inputScripts)
		if err != nil {
			msg.err <- err
			msg.completeChan <- nil
			return
		}
	}

	// At this point, we can also record and verify their signature for our
	// commitment transaction.
	res.theirCommitmentSig = msg.theirCommitmentSig
	commitTx := res.partialState.LocalCommitment.CommitTx
	ourKey := res.ourContribution.MultiSigKey
	theirKey := res.theirContribution.MultiSigKey

	// Re-generate both the witnessScript and p2sh output. We sign the
	// witnessScript script, but include the p2sh output as the subscript
	// for verification.
	witnessScript, _, err := input.GenFundingPkScript(
		ourKey.PubKey.SerializeCompressed(),
		theirKey.PubKey.SerializeCompressed(),
		int64(res.partialState.Capacity),
	)
	if err != nil {
		msg.err <- err
		msg.completeChan <- nil
		return
	}

	// Next, create the spending scriptSig, and then verify that the script
	// is complete, allowing us to spend from the funding transaction.
	channelValue := int64(res.partialState.Capacity)
	hashCache := txscript.NewTxSigHashes(commitTx)
	sigHash, err := txscript.CalcWitnessSigHash(
		witnessScript, hashCache, txscript.SigHashAll, commitTx,
		0, channelValue,
	)
	if err != nil {
		msg.err <- err
		msg.completeChan <- nil
		return
	}

	// Verify that we've received a valid signature from the remote party
	// for our version of the commitment transaction.
	if !msg.theirCommitmentSig.Verify(sigHash, theirKey.PubKey) {
		msg.err <- fmt.Errorf("counterparty's commitment signature is invalid")
		msg.completeChan <- nil
		return
	}
	theirCommitSigBytes := msg.theirCommitmentSig.Serialize()
	res.partialState.LocalCommitment.CommitSig = theirCommitSigBytes

	// Funding complete, this entry can be removed from limbo.
	l.limboMtx.Lock()
	delete(l.fundingLimbo, res.reservationID)
	delete(l.reservationIDs, res.pendingChanID)
	l.limboMtx.Unlock()

	l.intentMtx.Lock()
	delete(l.fundingIntents, res.pendingChanID)
	l.intentMtx.Unlock()

	// As we're about to broadcast the funding transaction, we'll take note
	// of the current height for record keeping purposes.
	//
	// TODO(roasbeef): this info can also be piped into light client's
	// basic fee estimation?
	_, bestHeight, err := l.Cfg.ChainIO.GetBestBlock()
	if err != nil {
		msg.err <- err
		msg.completeChan <- nil
		return
	}

	// As we've completed the funding process, we'll no convert the
	// contribution structs into their underlying channel config objects to
	// he stored within the database.
	res.partialState.LocalChanCfg = res.ourContribution.toChanConfig()
	res.partialState.RemoteChanCfg = res.theirContribution.toChanConfig()

	// We'll also record the finalized funding txn, which will allow us to
	// rebroadcast on startup in case we fail.
	res.partialState.FundingTxn = fundingTx

	// Set optional upfront shutdown scripts on the channel state so that they
	// are persisted. These values may be nil.
	res.partialState.LocalShutdownScript =
		res.ourContribution.UpfrontShutdown
	res.partialState.RemoteShutdownScript =
		res.theirContribution.UpfrontShutdown

	res.partialState.RevocationKeyLocator = res.nextRevocationKeyLoc

	// Add the complete funding transaction to the DB, in its open bucket
	// which will be used for the lifetime of this channel.
	nodeAddr := res.nodeAddr
	err = res.partialState.SyncPending(nodeAddr, uint32(bestHeight))
	if err != nil {
		msg.err <- err
		msg.completeChan <- nil
		return
	}

	msg.completeChan <- res.partialState
	msg.err <- nil
}

// handleSingleFunderSigs is called once the remote peer who initiated the
// single funder workflow has assembled the funding transaction, and generated
// a signature for our version of the commitment transaction. This method
// progresses the workflow by generating a signature for the remote peer's
// version of the commitment transaction.
func (l *LightningWallet) handleSingleFunderSigs(req *addSingleFunderSigsMsg) {
	l.limboMtx.RLock()
	pendingReservation, ok := l.fundingLimbo[req.pendingFundingID]
	l.limboMtx.RUnlock()
	if !ok {
		req.err <- fmt.Errorf("attempted to update non-existent funding state")
		req.completeChan <- nil
		return
	}

	// Grab the mutex on the ChannelReservation to ensure thread-safety
	pendingReservation.Lock()
	defer pendingReservation.Unlock()

	chanState := pendingReservation.partialState
	chanState.FundingOutpoint = *req.fundingOutpoint
	fundingTxIn := wire.NewTxIn(req.fundingOutpoint, nil, nil)

	// Now that we have the funding outpoint, we can generate both versions
	// of the commitment transaction, and generate a signature for the
	// remote node's commitment transactions.
	localBalance := pendingReservation.partialState.LocalCommitment.LocalBalance.ToSatoshis()
	remoteBalance := pendingReservation.partialState.LocalCommitment.RemoteBalance.ToSatoshis()
	ourCommitTx, theirCommitTx, err := CreateCommitmentTxns(
		localBalance, remoteBalance,
		pendingReservation.ourContribution.ChannelConfig,
		pendingReservation.theirContribution.ChannelConfig,
		pendingReservation.ourContribution.FirstCommitmentPoint,
		pendingReservation.theirContribution.FirstCommitmentPoint,
		*fundingTxIn, pendingReservation.partialState.ChanType,
	)
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}

	// With both commitment transactions constructed, we can now use the
	// generator state obfuscator to encode the current state number within
	// both commitment transactions.
	stateObfuscator := DeriveStateHintObfuscator(
		pendingReservation.theirContribution.PaymentBasePoint.PubKey,
		pendingReservation.ourContribution.PaymentBasePoint.PubKey,
	)
	err = initStateHints(ourCommitTx, theirCommitTx, stateObfuscator)
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}

	// Sort both transactions according to the agreed upon canonical
	// ordering. This ensures that both parties sign the same sighash
	// without further synchronization.
	txsort.InPlaceSort(ourCommitTx)
	txsort.InPlaceSort(theirCommitTx)
	chanState.LocalCommitment.CommitTx = ourCommitTx
	chanState.RemoteCommitment.CommitTx = theirCommitTx

	walletLog.Debugf("Local commit tx for ChannelPoint(%v): %v",
		req.fundingOutpoint, spew.Sdump(ourCommitTx))
	walletLog.Debugf("Remote commit tx for ChannelPoint(%v): %v",
		req.fundingOutpoint, spew.Sdump(theirCommitTx))

	channelValue := int64(pendingReservation.partialState.Capacity)
	hashCache := txscript.NewTxSigHashes(ourCommitTx)
	theirKey := pendingReservation.theirContribution.MultiSigKey
	ourKey := pendingReservation.ourContribution.MultiSigKey
	witnessScript, _, err := input.GenFundingPkScript(
		ourKey.PubKey.SerializeCompressed(),
		theirKey.PubKey.SerializeCompressed(), channelValue,
	)
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}

	sigHash, err := txscript.CalcWitnessSigHash(
		witnessScript, hashCache, txscript.SigHashAll, ourCommitTx, 0,
		channelValue,
	)
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}

	// Verify that we've received a valid signature from the remote party
	// for our version of the commitment transaction.
	if !req.theirCommitmentSig.Verify(sigHash, theirKey.PubKey) {
		req.err <- fmt.Errorf("counterparty's commitment signature " +
			"is invalid")
		req.completeChan <- nil
		return
	}
	theirCommitSigBytes := req.theirCommitmentSig.Serialize()
	chanState.LocalCommitment.CommitSig = theirCommitSigBytes

	// With their signature for our version of the commitment transactions
	// verified, we can now generate a signature for their version,
	// allowing the funding transaction to be safely broadcast.
	p2wsh, err := input.WitnessScriptHash(witnessScript)
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}
	signDesc := input.SignDescriptor{
		WitnessScript: witnessScript,
		KeyDesc:       ourKey,
		Output: &wire.TxOut{
			PkScript: p2wsh,
			Value:    channelValue,
		},
		HashType:   txscript.SigHashAll,
		SigHashes:  txscript.NewTxSigHashes(theirCommitTx),
		InputIndex: 0,
	}
	sigTheirCommit, err := l.Cfg.Signer.SignOutputRaw(theirCommitTx, &signDesc)
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}
	pendingReservation.ourCommitmentSig = sigTheirCommit

	_, bestHeight, err := l.Cfg.ChainIO.GetBestBlock()
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}

	// Set optional upfront shutdown scripts on the channel state so that they
	// are persisted. These values may be nil.
	chanState.LocalShutdownScript =
		pendingReservation.ourContribution.UpfrontShutdown
	chanState.RemoteShutdownScript =
		pendingReservation.theirContribution.UpfrontShutdown

	// Add the complete funding transaction to the DB, in it's open bucket
	// which will be used for the lifetime of this channel.
	chanState.LocalChanCfg = pendingReservation.ourContribution.toChanConfig()
	chanState.RemoteChanCfg = pendingReservation.theirContribution.toChanConfig()

	chanState.RevocationKeyLocator = pendingReservation.nextRevocationKeyLoc

	err = chanState.SyncPending(pendingReservation.nodeAddr, uint32(bestHeight))
	if err != nil {
		req.err <- err
		req.completeChan <- nil
		return
	}

	req.completeChan <- chanState
	req.err <- nil

	l.limboMtx.Lock()
	delete(l.fundingLimbo, req.pendingFundingID)
	l.limboMtx.Unlock()

	l.intentMtx.Lock()
	delete(l.fundingIntents, pendingReservation.pendingChanID)
	l.intentMtx.Unlock()
}

// WithCoinSelectLock will execute the passed function closure in a
// synchronized manner preventing any coin selection operations from proceeding
// while the closure is executing. This can be seen as the ability to execute a
// function closure under an exclusive coin selection lock.
func (l *LightningWallet) WithCoinSelectLock(f func() error) error {
	l.coinSelectMtx.Lock()
	defer l.coinSelectMtx.Unlock()

	return f()
}

// DeriveStateHintObfuscator derives the bytes to be used for obfuscating the
// state hints from the root to be used for a new channel. The obfuscator is
// generated via the following computation:
//
//   * sha256(initiatorKey || responderKey)[26:]
//     * where both keys are the multi-sig keys of the respective parties
//
// The first 6 bytes of the resulting hash are used as the state hint.
func DeriveStateHintObfuscator(key1, key2 *btcec.PublicKey) [StateHintSize]byte {
	h := sha256.New()
	h.Write(key1.SerializeCompressed())
	h.Write(key2.SerializeCompressed())

	sha := h.Sum(nil)

	var obfuscator [StateHintSize]byte
	copy(obfuscator[:], sha[26:])

	return obfuscator
}

// initStateHints properly sets the obfuscated state hints on both commitment
// transactions using the passed obfuscator.
func initStateHints(commit1, commit2 *wire.MsgTx,
	obfuscator [StateHintSize]byte) error {

	if err := SetStateNumHint(commit1, 0, obfuscator); err != nil {
		return err
	}
	if err := SetStateNumHint(commit2, 0, obfuscator); err != nil {
		return err
	}

	return nil
}

// ValidateChannel will attempt to fully validate a newly mined channel, given
// its funding transaction and existing channel state. If this method returns
// an error, then the mined channel is invalid, and shouldn't be used.
func (l *LightningWallet) ValidateChannel(channelState *channeldb.OpenChannel,
	fundingTx *wire.MsgTx) error {

	// First, we'll obtain a fully signed commitment transaction so we can
	// pass into it on the chanvalidate package for verification.
	channel, err := NewLightningChannel(l.Cfg.Signer, channelState, nil)
	if err != nil {
		return err
	}
	signedCommitTx, err := channel.getSignedCommitTx()
	if err != nil {
		return err
	}

	// We'll also need the multi-sig witness script itself so the
	// chanvalidate package can check it for correctness against the
	// funding transaction, and also commitment validity.
	localKey := channelState.LocalChanCfg.MultiSigKey.PubKey
	remoteKey := channelState.RemoteChanCfg.MultiSigKey.PubKey
	witnessScript, err := input.GenMultiSigScript(
		localKey.SerializeCompressed(),
		remoteKey.SerializeCompressed(),
	)
	if err != nil {
		return err
	}
	pkScript, err := input.WitnessScriptHash(witnessScript)
	if err != nil {
		return err
	}

	// Finally, we'll pass in all the necessary context needed to fully
	// validate that this channel is indeed what we expect, and can be
	// used.
	_, err = chanvalidate.Validate(&chanvalidate.Context{
		Locator: &chanvalidate.OutPointChanLocator{
			ChanPoint: channelState.FundingOutpoint,
		},
		MultiSigPkScript: pkScript,
		FundingTx:        fundingTx,
		CommitCtx: &chanvalidate.CommitmentContext{
			Value:               channel.Capacity,
			FullySignedCommitTx: signedCommitTx,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

// CoinSource is a wrapper around the wallet that implements the
// chanfunding.CoinSource interface.
type CoinSource struct {
	wallet *LightningWallet
}

// NewCoinSource creates a new instance of the CoinSource wrapper struct.
func NewCoinSource(w *LightningWallet) *CoinSource {
	return &CoinSource{wallet: w}
}

// ListCoins returns all UTXOs from the source that have between
// minConfs and maxConfs number of confirmations.
func (c *CoinSource) ListCoins(minConfs int32,
	maxConfs int32) ([]chanfunding.Coin, error) {

	utxos, err := c.wallet.ListUnspentWitnessFromDefaultAccount(
		minConfs, maxConfs,
	)
	if err != nil {
		return nil, err
	}

	var coins []chanfunding.Coin
	for _, utxo := range utxos {
		coins = append(coins, chanfunding.Coin{
			TxOut: wire.TxOut{
				Value:    int64(utxo.Value),
				PkScript: utxo.PkScript,
			},
			OutPoint: utxo.OutPoint,
		})
	}

	return coins, nil
}

// CoinFromOutPoint attempts to locate details pertaining to a coin based on
// its outpoint. If the coin isn't under the control of the backing CoinSource,
// then an error should be returned.
func (c *CoinSource) CoinFromOutPoint(op wire.OutPoint) (*chanfunding.Coin, error) {
	inputInfo, err := c.wallet.FetchInputInfo(&op)
	if err != nil {
		return nil, err
	}

	return &chanfunding.Coin{
		TxOut: wire.TxOut{
			Value:    int64(inputInfo.Value),
			PkScript: inputInfo.PkScript,
		},
		OutPoint: inputInfo.OutPoint,
	}, nil
}

// shimKeyRing is a wrapper struct that's used to provide the proper multi-sig
// key for an initiated external funding flow.
type shimKeyRing struct {
	keychain.KeyRing

	*chanfunding.ShimIntent
}

// DeriveNextKey intercepts the normal DeriveNextKey call to a keychain.KeyRing
// instance, and supplies the multi-sig key specified by the ShimIntent. This
// allows us to transparently insert new keys into the existing funding flow,
// as these keys may not come from the wallet itself.
func (s *shimKeyRing) DeriveNextKey(keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {
	if keyFam != keychain.KeyFamilyMultiSig {
		return s.KeyRing.DeriveNextKey(keyFam)
	}

	fundingKeys, err := s.ShimIntent.MultiSigKeys()
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}

	return *fundingKeys.LocalKey, nil
}
