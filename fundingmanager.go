package lnd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/coreos/bbolt"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"golang.org/x/crypto/salsa20"
	"google.golang.org/grpc"
)

const (
	// TODO(roasbeef): tune
	msgBufferSize = 50

	// minBtcRemoteDelay and maxBtcRemoteDelay is the extremes of the
	// Bitcoin CSV delay we will require the remote to use for its
	// commitment transaction. The actual delay we will require will be
	// somewhere between these values, depending on channel size.
	minBtcRemoteDelay uint16 = 144
	maxBtcRemoteDelay uint16 = 2016

	// minLtcRemoteDelay and maxLtcRemoteDelay is the extremes of the
	// Litecoin CSV delay we will require the remote to use for its
	// commitment transaction. The actual delay we will require will be
	// somewhere between these values, depending on channel size.
	minLtcRemoteDelay uint16 = 576
	maxLtcRemoteDelay uint16 = 8064

	// maxWaitNumBlocksFundingConf is the maximum number of blocks to wait
	// for the funding transaction to be confirmed before forgetting
	// channels that aren't initiated by us. 2016 blocks is ~2 weeks.
	maxWaitNumBlocksFundingConf = 2016

	// minChanFundingSize is the smallest channel that we'll allow to be
	// created over the RPC interface.
	minChanFundingSize = btcutil.Amount(20000)

	// MaxBtcFundingAmount is a soft-limit of the maximum channel size
	// currently accepted on the Bitcoin chain within the Lightning
	// Protocol. This limit is defined in BOLT-0002, and serves as an
	// initial precautionary limit while implementations are battle tested
	// in the real world.
	MaxBtcFundingAmount = btcutil.Amount(1<<24) - 1

	// maxLtcFundingAmount is a soft-limit of the maximum channel size
	// currently accepted on the Litecoin chain within the Lightning
	// Protocol.
	maxLtcFundingAmount = MaxBtcFundingAmount * btcToLtcConversionRate
)

var (
	// MaxFundingAmount is a soft-limit of the maximum channel size
	// currently accepted within the Lightning Protocol. This limit is
	// defined in BOLT-0002, and serves as an initial precautionary limit
	// while implementations are battle tested in the real world.
	//
	// At the moment, this value depends on which chain is active. It is set
	// to the value under the Bitcoin chain as default.
	//
	// TODO(roasbeef): add command line param to modify
	MaxFundingAmount = MaxBtcFundingAmount

	// ErrFundingManagerShuttingDown is an error returned when attempting to
	// process a funding request/message but the funding manager has already
	// been signaled to shut down.
	ErrFundingManagerShuttingDown = errors.New("funding manager shutting " +
		"down")
)

// reservationWithCtx encapsulates a pending channel reservation. This wrapper
// struct is used internally within the funding manager to track and progress
// the funding workflow initiated by incoming/outgoing methods from the target
// peer. Additionally, this struct houses a response and error channel which is
// used to respond to the caller in the case a channel workflow is initiated
// via a local signal such as RPC.
//
// TODO(roasbeef): actually use the context package
//  * deadlines, etc.
type reservationWithCtx struct {
	reservation *lnwallet.ChannelReservation
	peer        lnpeer.Peer

	chanAmt btcutil.Amount

	// Constraints we require for the remote.
	remoteCsvDelay uint16
	remoteMinHtlc  lnwire.MilliSatoshi

	updateMtx   sync.RWMutex
	lastUpdated time.Time

	updates chan *lnrpc.OpenStatusUpdate
	err     chan error
}

// isLocked checks the reservation's timestamp to determine whether it is locked.
func (r *reservationWithCtx) isLocked() bool {
	r.updateMtx.RLock()
	defer r.updateMtx.RUnlock()

	// The time zero value represents a locked reservation.
	return r.lastUpdated.IsZero()
}

// lock locks the reservation from zombie pruning by setting its timestamp to the
// zero value.
func (r *reservationWithCtx) lock() {
	r.updateMtx.Lock()
	defer r.updateMtx.Unlock()

	r.lastUpdated = time.Time{}
}

// updateTimestamp updates the reservation's timestamp with the current time.
func (r *reservationWithCtx) updateTimestamp() {
	r.updateMtx.Lock()
	defer r.updateMtx.Unlock()

	r.lastUpdated = time.Now()
}

// initFundingMsg is sent by an outside subsystem to the funding manager in
// order to kick off a funding workflow with a specified target peer. The
// original request which defines the parameters of the funding workflow are
// embedded within this message giving the funding manager full context w.r.t
// the workflow.
type initFundingMsg struct {
	peer lnpeer.Peer
	*openChanReq
}

// fundingOpenMsg couples an lnwire.OpenChannel message with the peer who sent
// the message. This allows the funding manager to queue a response directly to
// the peer, progressing the funding workflow.
type fundingOpenMsg struct {
	msg  *lnwire.OpenChannel
	peer lnpeer.Peer
}

// fundingAcceptMsg couples an lnwire.AcceptChannel message with the peer who
// sent the message. This allows the funding manager to queue a response
// directly to the peer, progressing the funding workflow.
type fundingAcceptMsg struct {
	msg  *lnwire.AcceptChannel
	peer lnpeer.Peer
}

// fundingCreatedMsg couples an lnwire.FundingCreated message with the peer who
// sent the message. This allows the funding manager to queue a response
// directly to the peer, progressing the funding workflow.
type fundingCreatedMsg struct {
	msg  *lnwire.FundingCreated
	peer lnpeer.Peer
}

// fundingSignedMsg couples an lnwire.FundingSigned message with the peer who
// sent the message. This allows the funding manager to queue a response
// directly to the peer, progressing the funding workflow.
type fundingSignedMsg struct {
	msg  *lnwire.FundingSigned
	peer lnpeer.Peer
}

// fundingLockedMsg couples an lnwire.FundingLocked message with the peer who
// sent the message. This allows the funding manager to finalize the funding
// process and announce the existence of the new channel.
type fundingLockedMsg struct {
	msg  *lnwire.FundingLocked
	peer lnpeer.Peer
}

// fundingErrorMsg couples an lnwire.Error message with the peer who sent the
// message. This allows the funding manager to properly process the error.
type fundingErrorMsg struct {
	err     *lnwire.Error
	peerKey *btcec.PublicKey
}

// pendingChannels is a map instantiated per-peer which tracks all active
// pending single funded channels indexed by their pending channel identifier,
// which is a set of 32-bytes generated via a CSPRNG.
type pendingChannels map[[32]byte]*reservationWithCtx

// serializedPubKey is used within the FundingManager's activeReservations list
// to identify the nodes with which the FundingManager is actively working to
// initiate new channels.
type serializedPubKey [33]byte

// newSerializedKey creates a new serialized public key from an instance of a
// live pubkey object.
func newSerializedKey(pubKey *btcec.PublicKey) serializedPubKey {
	var s serializedPubKey
	copy(s[:], pubKey.SerializeCompressed())
	return s
}

// fundingConfig defines the configuration for the FundingManager. All elements
// within the configuration MUST be non-nil for the FundingManager to carry out
// its duties.
type fundingConfig struct {
	// IDKey is the PublicKey that is used to identify this node within the
	// Lightning Network.
	IDKey *btcec.PublicKey

	// Wallet handles the parts of the funding process that involves moving
	// funds from on-chain transaction outputs into Lightning channels.
	Wallet *lnwallet.LightningWallet

	// PublishTransaction facilitates the process of broadcasting a
	// transaction to the network.
	PublishTransaction func(*wire.MsgTx) error

	// FeeEstimator calculates appropriate fee rates based on historical
	// transaction information.
	FeeEstimator lnwallet.FeeEstimator

	// Notifier is used by the FundingManager to determine when the
	// channel's funding transaction has been confirmed on the blockchain
	// so that the channel creation process can be completed.
	Notifier chainntnfs.ChainNotifier

	// SignMessage signs an arbitrary message with a given public key. The
	// actual digest signed is the double sha-256 of the message. In the
	// case that the private key corresponding to the passed public key
	// cannot be located, then an error is returned.
	//
	// TODO(roasbeef): should instead pass on this responsibility to a
	// distinct sub-system?
	SignMessage func(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error)

	// CurrentNodeAnnouncement should return the latest, fully signed node
	// announcement from the backing Lightning Network node.
	CurrentNodeAnnouncement func() (lnwire.NodeAnnouncement, error)

	// SendAnnouncement is used by the FundingManager to send announcement
	// messages to the Gossiper to possibly broadcast to the greater
	// network. A set of optional message fields can be provided to populate
	// any information within the graph that is not included in the gossip
	// message.
	SendAnnouncement func(msg lnwire.Message,
		optionalFields ...discovery.OptionalMsgField) chan error

	// NotifyWhenOnline allows the FundingManager to register with a
	// subsystem that will notify it when the peer comes online. This is
	// used when sending the fundingLocked message, since it MUST be
	// delivered after the funding transaction is confirmed.
	//
	// NOTE: The peerChan channel must be buffered.
	NotifyWhenOnline func(peer [33]byte, peerChan chan<- lnpeer.Peer)

	// FindChannel queries the database for the channel with the given
	// channel ID.
	FindChannel func(chanID lnwire.ChannelID) (*channeldb.OpenChannel, error)

	// TempChanIDSeed is a cryptographically random string of bytes that's
	// used as a seed to generate pending channel ID's.
	TempChanIDSeed [32]byte

	// DefaultRoutingPolicy is the default routing policy used when
	// initially announcing channels.
	DefaultRoutingPolicy htlcswitch.ForwardingPolicy

	// NumRequiredConfs is a function closure that helps the funding
	// manager decide how many confirmations it should require for a
	// channel extended to it. The function is able to take into account
	// the amount of the channel, and any funds we'll be pushed in the
	// process to determine how many confirmations we'll require.
	NumRequiredConfs func(btcutil.Amount, lnwire.MilliSatoshi) uint16

	// RequiredRemoteDelay is a function that maps the total amount in a
	// proposed channel to the CSV delay that we'll require for the remote
	// party. Naturally a larger channel should require a higher CSV delay
	// in order to give us more time to claim funds in the case of a
	// contract breach.
	RequiredRemoteDelay func(btcutil.Amount) uint16

	// RequiredRemoteChanReserve is a function closure that, given the
	// channel capacity and dust limit, will return an appropriate amount
	// for the remote peer's required channel reserve that is to be adhered
	// to at all times.
	RequiredRemoteChanReserve func(capacity, dustLimit btcutil.Amount) btcutil.Amount

	// RequiredRemoteMaxValue is a function closure that, given the channel
	// capacity, returns the amount of MilliSatoshis that our remote peer
	// can have in total outstanding HTLCs with us.
	RequiredRemoteMaxValue func(btcutil.Amount) lnwire.MilliSatoshi

	// RequiredRemoteMaxHTLCs is a function closure that, given the channel
	// capacity, returns the number of maximum HTLCs the remote peer can
	// offer us.
	RequiredRemoteMaxHTLCs func(btcutil.Amount) uint16

	// WatchNewChannel is to be called once a new channel enters the final
	// funding stage: waiting for on-chain confirmation. This method sends
	// the channel to the ChainArbitrator so it can watch for any on-chain
	// events related to the channel. We also provide the public key of the
	// node we're establishing a channel with for reconnection purposes.
	WatchNewChannel func(*channeldb.OpenChannel, *btcec.PublicKey) error

	// ReportShortChanID allows the funding manager to report the newly
	// discovered short channel ID of a formerly pending channel to outside
	// sub-systems.
	ReportShortChanID func(wire.OutPoint) error

	// ZombieSweeperInterval is the periodic time interval in which the
	// zombie sweeper is run.
	ZombieSweeperInterval time.Duration

	// ReservationTimeout is the length of idle time that must pass before
	// a reservation is considered a zombie.
	ReservationTimeout time.Duration

	// MinChanSize is the smallest channel size that we'll accept as an
	// inbound channel. We have such a parameter, as otherwise, nodes could
	// flood us with very small channels that would never really be usable
	// due to fees.
	MinChanSize btcutil.Amount

	// NotifyOpenChannelEvent informs the ChannelNotifier when channels
	// transition from pending open to open.
	NotifyOpenChannelEvent func(wire.OutPoint)

	// NotifyReadyChannelEvent notifies an outside subs-system that a
	// channel is "ready" for use. A channel only becomes ready once the
	// FundingLocked message is received and processed.
	NotifyReadyChannelEvent func(wire.OutPoint)
}

// fundingManager acts as an orchestrator/bridge between the wallet's
// 'ChannelReservation' workflow, and the wire protocol's funding initiation
// messages. Any requests to initiate the funding workflow for a channel,
// either kicked-off locally or remotely are handled by the funding manager.
// Once a channel's funding workflow has been completed, any local callers, the
// local peer, and possibly the remote peer are notified of the completion of
// the channel workflow. Additionally, any temporary or permanent access
// controls between the wallet and remote peers are enforced via the funding
// manager.
type fundingManager struct {
	started sync.Once
	stopped sync.Once

	// cfg is a copy of the configuration struct that the FundingManager
	// was initialized with.
	cfg *fundingConfig

	// chanIDKey is a cryptographically random key that's used to generate
	// temporary channel ID's.
	chanIDKey [32]byte

	// chanIDNonce is a nonce that's incremented for each new funding
	// reservation created.
	nonceMtx    sync.RWMutex
	chanIDNonce uint64

	// activeReservations is a map which houses the state of all pending
	// funding workflows.
	activeReservations map[serializedPubKey]pendingChannels

	// signedReservations is a utility map that maps the permanent channel
	// ID of a funding reservation to its temporary channel ID. This is
	// required as mid funding flow, we switch to referencing the channel
	// by its full channel ID once the commitment transactions have been
	// signed by both parties.
	signedReservations map[lnwire.ChannelID][32]byte

	// resMtx guards both of the maps above to ensure that all access is
	// goroutine safe.
	resMtx sync.RWMutex

	// fundingMsgs is a channel which receives wrapped wire messages
	// related to funding workflow from outside peers.
	fundingMsgs chan interface{}

	// queries is a channel which receives requests to query the internal
	// state of the funding manager.
	queries chan interface{}

	// fundingRequests is a channel used to receive channel initiation
	// requests from a local subsystem within the daemon.
	fundingRequests chan *initFundingMsg

	// newChanBarriers is a map from a channel ID to a 'barrier' which will
	// be signalled once the channel is fully open. This barrier acts as a
	// synchronization point for any incoming/outgoing HTLCs before the
	// channel has been fully opened.
	barrierMtx      sync.RWMutex
	newChanBarriers map[lnwire.ChannelID]chan struct{}

	localDiscoveryMtx     sync.Mutex
	localDiscoverySignals map[lnwire.ChannelID]chan struct{}

	handleFundingLockedMtx      sync.RWMutex
	handleFundingLockedBarriers map[lnwire.ChannelID]struct{}

	quit chan struct{}
	wg   sync.WaitGroup
}

// channelOpeningState represents the different states a channel can be in
// between the funding transaction has been confirmed and the channel is
// announced to the network and ready to be used.
type channelOpeningState uint8

const (
	// markedOpen is the opening state of a channel if the funding
	// transaction is confirmed on-chain, but fundingLocked is not yet
	// successfully sent to the other peer.
	markedOpen channelOpeningState = iota

	// fundingLockedSent is the opening state of a channel if the
	// fundingLocked message has successfully been sent to the other peer,
	// but we still haven't announced the channel to the network.
	fundingLockedSent

	// addedToRouterGraph is the opening state of a channel if the
	// channel has been successfully added to the router graph
	// immediately after the fundingLocked message has been sent, but
	// we still haven't announced the channel to the network.
	addedToRouterGraph
)

var (
	// channelOpeningStateBucket is the database bucket used to store the
	// channelOpeningState for each channel that is currently in the process
	// of being opened.
	channelOpeningStateBucket = []byte("channelOpeningState")

	// ErrChannelNotFound is an error returned when a channel is not known
	// to us. In this case of the fundingManager, this error is returned
	// when the channel in question is not considered being in an opening
	// state.
	ErrChannelNotFound = fmt.Errorf("channel not found")
)

// newFundingManager creates and initializes a new instance of the
// fundingManager.
func newFundingManager(cfg fundingConfig) (*fundingManager, error) {
	return &fundingManager{
		cfg:                         &cfg,
		chanIDKey:                   cfg.TempChanIDSeed,
		activeReservations:          make(map[serializedPubKey]pendingChannels),
		signedReservations:          make(map[lnwire.ChannelID][32]byte),
		newChanBarriers:             make(map[lnwire.ChannelID]chan struct{}),
		fundingMsgs:                 make(chan interface{}, msgBufferSize),
		fundingRequests:             make(chan *initFundingMsg, msgBufferSize),
		localDiscoverySignals:       make(map[lnwire.ChannelID]chan struct{}),
		handleFundingLockedBarriers: make(map[lnwire.ChannelID]struct{}),
		queries:                     make(chan interface{}, 1),
		quit:                        make(chan struct{}),
	}, nil
}

// Start launches all helper goroutines required for handling requests sent
// to the funding manager.
func (f *fundingManager) Start() error {
	var err error
	f.started.Do(func() {
		err = f.start()
	})
	return err
}

func (f *fundingManager) start() error {
	fndgLog.Tracef("Funding manager running")

	// Upon restart, the Funding Manager will check the database to load any
	// channels that were  waiting for their funding transactions to be
	// confirmed on the blockchain at the time when the daemon last went
	// down.
	// TODO(roasbeef): store height that funding finished?
	//  * would then replace call below
	pendingChannels, err := f.cfg.Wallet.Cfg.Database.FetchPendingChannels()
	if err != nil {
		return err
	}

	// For any channels that were in a pending state when the daemon was
	// last connected, the Funding Manager will re-initialize the channel
	// barriers and will also launch waitForFundingConfirmation to wait for
	// the channel's funding transaction to be confirmed on the blockchain.
	for _, channel := range pendingChannels {
		f.barrierMtx.Lock()
		fndgLog.Tracef("Loading pending ChannelPoint(%v), creating chan "+
			"barrier", channel.FundingOutpoint)
		chanID := lnwire.NewChanIDFromOutPoint(&channel.FundingOutpoint)
		f.newChanBarriers[chanID] = make(chan struct{})
		f.barrierMtx.Unlock()

		f.localDiscoverySignals[chanID] = make(chan struct{})

		// Rebroadcast the funding transaction for any pending channel
		// that we initiated. If this operation fails due to a reported
		// double spend, we treat this as an indicator that we have
		// already broadcast this transaction. Otherwise, we simply log
		// the error as there isn't anything we can currently do to
		// recover.
		if channel.ChanType == channeldb.SingleFunder &&
			channel.IsInitiator {

			err := f.cfg.PublishTransaction(channel.FundingTxn)
			if err != nil {
				fndgLog.Errorf("Unable to rebroadcast funding "+
					"tx for ChannelPoint(%v): %v",
					channel.FundingOutpoint, err)
			}
		}

		confChan := make(chan *lnwire.ShortChannelID)
		timeoutChan := make(chan struct{})

		go func(ch *channeldb.OpenChannel) {
			go f.waitForFundingWithTimeout(ch, confChan, timeoutChan)

			select {
			case <-timeoutChan:
				// Timeout channel will be triggered if the number of blocks
				// mined since the channel was initiated reaches
				// maxWaitNumBlocksFundingConf and we are not the channel
				// initiator.
				localBalance := ch.LocalCommitment.LocalBalance.ToSatoshis()
				closeInfo := &channeldb.ChannelCloseSummary{
					ChainHash:               ch.ChainHash,
					ChanPoint:               ch.FundingOutpoint,
					RemotePub:               ch.IdentityPub,
					Capacity:                ch.Capacity,
					SettledBalance:          localBalance,
					CloseType:               channeldb.FundingCanceled,
					RemoteCurrentRevocation: ch.RemoteCurrentRevocation,
					RemoteNextRevocation:    ch.RemoteNextRevocation,
					LocalChanConfig:         ch.LocalChanCfg,
				}

				if err := ch.CloseChannel(closeInfo); err != nil {
					fndgLog.Errorf("Failed closing channel "+
						"%v: %v", ch.FundingOutpoint, err)
				}

			case <-f.quit:
				// The fundingManager is shutting down, and will
				// resume wait on startup.
			case shortChanID, ok := <-confChan:
				if !ok {
					fndgLog.Errorf("Waiting for funding" +
						"confirmation failed")
					return
				}

				// The funding transaction has confirmed, so
				// we'll attempt to retrieve the remote peer
				// to complete the rest of the funding flow.
				peerChan := make(chan lnpeer.Peer, 1)

				var peerKey [33]byte
				copy(peerKey[:], ch.IdentityPub.SerializeCompressed())

				f.cfg.NotifyWhenOnline(peerKey, peerChan)

				var peer lnpeer.Peer
				select {
				case peer = <-peerChan:
				case <-f.quit:
					return
				}
				err := f.handleFundingConfirmation(
					peer, ch, shortChanID,
				)
				if err != nil {
					fndgLog.Errorf("Failed to handle "+
						"funding confirmation: %v", err)
					return
				}
			}
		}(channel)
	}

	// Fetch all our open channels, and make sure they all finalized the
	// opening process.
	// TODO(halseth): this check is only done on restart atm, but should
	// also be done if a peer that disappeared during the opening process
	// reconnects.
	openChannels, err := f.cfg.Wallet.Cfg.Database.FetchAllChannels()
	if err != nil {
		return err
	}

	for _, channel := range openChannels {
		channelState, shortChanID, err := f.getChannelOpeningState(
			&channel.FundingOutpoint)
		if err == ErrChannelNotFound {
			// Channel not in fundingManager's opening database,
			// meaning it was successfully announced to the
			// network.
			continue
		} else if err != nil {
			return err
		}

		chanID := lnwire.NewChanIDFromOutPoint(&channel.FundingOutpoint)
		fndgLog.Debugf("channel (%v) with opening state %v found",
			chanID, channelState)

		if channel.IsPending {
			// Set up the channel barriers again, to make sure
			// waitUntilChannelOpen correctly waits until the
			// opening process is completely over.
			f.barrierMtx.Lock()
			fndgLog.Tracef("Loading pending ChannelPoint(%v), "+
				"creating chan barrier", channel.FundingOutpoint)
			f.newChanBarriers[chanID] = make(chan struct{})
			f.barrierMtx.Unlock()
		}

		// If we did find the channel in the opening state database, we
		// have seen the funding transaction being confirmed, but we
		// did not finish the rest of the setup procedure before we shut
		// down. We handle the remaining steps of this setup by
		// continuing the procedure where we left off.
		switch channelState {
		case markedOpen:
			// The funding transaction was confirmed, but we did not
			// successfully send the fundingLocked message to the
			// peer, so let's do that now.
			f.wg.Add(1)
			go func(dbChan *channeldb.OpenChannel) {
				defer f.wg.Done()

				peerChan := make(chan lnpeer.Peer, 1)

				var peerKey [33]byte
				copy(peerKey[:], dbChan.IdentityPub.SerializeCompressed())

				f.cfg.NotifyWhenOnline(peerKey, peerChan)

				var peer lnpeer.Peer
				select {
				case peer = <-peerChan:
				case <-f.quit:
					return
				}
				err := f.handleFundingConfirmation(
					peer, dbChan, shortChanID,
				)
				if err != nil {
					fndgLog.Errorf("Failed to handle "+
						"funding confirmation: %v", err)
					return
				}
			}(channel)

		case fundingLockedSent:
			// fundingLocked was sent to peer, but the channel
			// was not added to the router graph and the channel
			// announcement was not sent.
			f.wg.Add(1)
			go func(dbChan *channeldb.OpenChannel) {
				defer f.wg.Done()

				err = f.addToRouterGraph(dbChan, shortChanID)
				if err != nil {
					fndgLog.Errorf("failed adding to "+
						"router graph: %v", err)
					return
				}

				// TODO(halseth): should create a state machine
				// that can more easily be resumed from
				// different states, to avoid this code
				// duplication.
				err = f.annAfterSixConfs(dbChan, shortChanID)
				if err != nil {
					fndgLog.Errorf("error sending channel "+
						"announcements: %v", err)
					return
				}
			}(channel)

		case addedToRouterGraph:
			// The channel was added to the Router's topology, but
			// the channel announcement was not sent.
			f.wg.Add(1)
			go func(dbChan *channeldb.OpenChannel) {
				defer f.wg.Done()

				err = f.annAfterSixConfs(dbChan, shortChanID)
				if err != nil {
					fndgLog.Errorf("error sending channel "+
						"announcement: %v", err)
					return
				}
			}(channel)

		default:
			fndgLog.Errorf("undefined channelState: %v",
				channelState)
		}
	}

	f.wg.Add(1) // TODO(roasbeef): tune
	go f.reservationCoordinator()

	return nil
}

// Stop signals all helper goroutines to execute a graceful shutdown. This
// method will block until all goroutines have exited.
func (f *fundingManager) Stop() error {
	var err error
	f.stopped.Do(func() {
		err = f.stop()
	})
	return err
}

func (f *fundingManager) stop() error {
	fndgLog.Infof("Funding manager shutting down")

	close(f.quit)
	f.wg.Wait()

	return nil
}

// nextPendingChanID returns the next free pending channel ID to be used to
// identify a particular future channel funding workflow.
func (f *fundingManager) nextPendingChanID() [32]byte {
	// Obtain a fresh nonce. We do this by encoding the current nonce
	// counter, then incrementing it by one.
	f.nonceMtx.Lock()
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], f.chanIDNonce)
	f.chanIDNonce++
	f.nonceMtx.Unlock()

	// We'll generate the next pending channelID by "encrypting" 32-bytes
	// of zeroes which'll extract 32 random bytes from our stream cipher.
	var (
		nextChanID [32]byte
		zeroes     [32]byte
	)
	salsa20.XORKeyStream(nextChanID[:], zeroes[:], nonce[:], &f.chanIDKey)

	return nextChanID
}

type pendingChannel struct {
	identityPub   *btcec.PublicKey
	channelPoint  *wire.OutPoint
	capacity      btcutil.Amount
	localBalance  btcutil.Amount
	remoteBalance btcutil.Amount
}

type pendingChansReq struct {
	resp chan []*pendingChannel
	err  chan error
}

// PendingChannels returns a slice describing all the channels which are
// currently pending at the last state of the funding workflow.
func (f *fundingManager) PendingChannels() ([]*pendingChannel, error) {
	respChan := make(chan []*pendingChannel, 1)
	errChan := make(chan error, 1)

	req := &pendingChansReq{
		resp: respChan,
		err:  errChan,
	}

	select {
	case f.queries <- req:
	case <-f.quit:
		return nil, ErrFundingManagerShuttingDown
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case err := <-errChan:
		return nil, err
	case <-f.quit:
		return nil, ErrFundingManagerShuttingDown
	}
}

// CancelPeerReservations cancels all active reservations associated with the
// passed node. This will ensure any outputs which have been pre committed,
// (and thus locked from coin selection), are properly freed.
func (f *fundingManager) CancelPeerReservations(nodePub [33]byte) {

	fndgLog.Debugf("Cancelling all reservations for peer %x", nodePub[:])

	f.resMtx.Lock()
	defer f.resMtx.Unlock()

	// We'll attempt to look up this node in the set of active
	// reservations.  If they don't have any, then there's no further work
	// to be done.
	nodeReservations, ok := f.activeReservations[nodePub]
	if !ok {
		fndgLog.Debugf("No active reservations for node: %x", nodePub[:])
		return
	}

	// If they do have any active reservations, then we'll cancel all of
	// them (which releases any locked UTXO's), and also delete it from the
	// reservation map.
	for pendingID, resCtx := range nodeReservations {
		if err := resCtx.reservation.Cancel(); err != nil {
			fndgLog.Errorf("unable to cancel reservation for "+
				"node=%x: %v", nodePub[:], err)
		}

		resCtx.err <- fmt.Errorf("peer disconnected")
		delete(nodeReservations, pendingID)
	}

	// Finally, we'll delete the node itself from the set of reservations.
	delete(f.activeReservations, nodePub)
}

// failFundingFlow will fail the active funding flow with the target peer,
// identified by its unique temporary channel ID. This method will send an
// error to the remote peer, and also remove the reservation from our set of
// pending reservations.
//
// TODO(roasbeef): if peer disconnects, and haven't yet broadcast funding
// transaction, then all reservations should be cleared.
func (f *fundingManager) failFundingFlow(peer lnpeer.Peer, tempChanID [32]byte,
	fundingErr error) {

	fndgLog.Debugf("Failing funding flow for pendingID=%x: %v",
		tempChanID, fundingErr)

	ctx, err := f.cancelReservationCtx(peer.IdentityKey(), tempChanID)
	if err != nil {
		fndgLog.Errorf("unable to cancel reservation: %v", err)
	}

	// In case the case where the reservation existed, send the funding
	// error on the error channel.
	if ctx != nil {
		ctx.err <- fundingErr
	}

	// We only send the exact error if it is part of out whitelisted set of
	// errors (lnwire.ErrorCode or lnwallet.ReservationError).
	var msg lnwire.ErrorData
	switch e := fundingErr.(type) {

	// Let the actual error message be sent to the remote.
	case lnwallet.ReservationError:
		msg = lnwire.ErrorData(e.Error())

	// Send the status code.
	case lnwire.ErrorCode:
		msg = lnwire.ErrorData{byte(e)}

	// We just send a generic error.
	default:
		msg = lnwire.ErrorData("funding failed due to internal error")
	}

	errMsg := &lnwire.Error{
		ChanID: tempChanID,
		Data:   msg,
	}

	fndgLog.Debugf("Sending funding error to peer (%x): %v",
		peer.IdentityKey().SerializeCompressed(), spew.Sdump(errMsg))
	if err := peer.SendMessage(false, errMsg); err != nil {
		fndgLog.Errorf("unable to send error message to peer %v", err)
	}
}

// reservationCoordinator is the primary goroutine tasked with progressing the
// funding workflow between the wallet, and any outside peers or local callers.
//
// NOTE: This MUST be run as a goroutine.
func (f *fundingManager) reservationCoordinator() {
	defer f.wg.Done()

	zombieSweepTicker := time.NewTicker(f.cfg.ZombieSweeperInterval)
	defer zombieSweepTicker.Stop()

	for {
		select {

		case msg := <-f.fundingMsgs:
			switch fmsg := msg.(type) {
			case *fundingOpenMsg:
				f.handleFundingOpen(fmsg)
			case *fundingAcceptMsg:
				f.handleFundingAccept(fmsg)
			case *fundingCreatedMsg:
				f.handleFundingCreated(fmsg)
			case *fundingSignedMsg:
				f.handleFundingSigned(fmsg)
			case *fundingLockedMsg:
				f.wg.Add(1)
				go f.handleFundingLocked(fmsg)
			case *fundingErrorMsg:
				f.handleErrorMsg(fmsg)
			}
		case req := <-f.fundingRequests:
			f.handleInitFundingMsg(req)

		case <-zombieSweepTicker.C:
			f.pruneZombieReservations()

		case req := <-f.queries:
			switch msg := req.(type) {
			case *pendingChansReq:
				f.handlePendingChannels(msg)
			}
		case <-f.quit:
			return
		}
	}
}

// handlePendingChannels responds to a request for details concerning all
// currently pending channels waiting for the final phase of the funding
// workflow (funding txn confirmation).
func (f *fundingManager) handlePendingChannels(msg *pendingChansReq) {
	var pendingChannels []*pendingChannel

	dbPendingChannels, err := f.cfg.Wallet.Cfg.Database.FetchPendingChannels()
	if err != nil {
		msg.err <- err
		return
	}

	for _, dbPendingChan := range dbPendingChannels {
		pendingChan := &pendingChannel{
			identityPub:   dbPendingChan.IdentityPub,
			channelPoint:  &dbPendingChan.FundingOutpoint,
			capacity:      dbPendingChan.Capacity,
			localBalance:  dbPendingChan.LocalCommitment.LocalBalance.ToSatoshis(),
			remoteBalance: dbPendingChan.LocalCommitment.RemoteBalance.ToSatoshis(),
		}

		pendingChannels = append(pendingChannels, pendingChan)
	}

	msg.resp <- pendingChannels
}

// processFundingOpen sends a message to the fundingManager allowing it to
// initiate the new funding workflow with the source peer.
func (f *fundingManager) processFundingOpen(msg *lnwire.OpenChannel,
	peer lnpeer.Peer) {

	select {
	case f.fundingMsgs <- &fundingOpenMsg{msg, peer}:
	case <-f.quit:
		return
	}
}

// handleFundingOpen creates an initial 'ChannelReservation' within the wallet,
// then responds to the source peer with an accept channel message progressing
// the funding workflow.
//
// TODO(roasbeef): add error chan to all, let channelManager handle
// error+propagate
func (f *fundingManager) handleFundingOpen(fmsg *fundingOpenMsg) {
	// Check number of pending channels to be smaller than maximum allowed
	// number and send ErrorGeneric to remote peer if condition is
	// violated.
	peerPubKey := fmsg.peer.IdentityKey()
	peerIDKey := newSerializedKey(peerPubKey)

	msg := fmsg.msg
	amt := msg.FundingAmount

	// We count the number of pending channels for this peer. This is the
	// sum of the active reservations and the channels pending open in the
	// database.
	f.resMtx.RLock()
	numPending := len(f.activeReservations[peerIDKey])
	f.resMtx.RUnlock()

	channels, err := f.cfg.Wallet.Cfg.Database.FetchOpenChannels(peerPubKey)
	if err != nil {
		f.failFundingFlow(
			fmsg.peer, fmsg.msg.PendingChannelID, err,
		)
		return
	}

	for _, c := range channels {
		if c.IsPending {
			numPending++
		}
	}

	// TODO(roasbeef): modify to only accept a _single_ pending channel per
	// block unless white listed
	if numPending >= cfg.MaxPendingChannels {
		f.failFundingFlow(
			fmsg.peer, fmsg.msg.PendingChannelID,
			lnwire.ErrMaxPendingChannels,
		)
		return
	}

	// We'll also reject any requests to create channels until we're fully
	// synced to the network as we won't be able to properly validate the
	// confirmation of the funding transaction.
	isSynced, _, err := f.cfg.Wallet.IsSynced()
	if err != nil || !isSynced {
		if err != nil {
			fndgLog.Errorf("unable to query wallet: %v", err)
		}
		f.failFundingFlow(
			fmsg.peer, fmsg.msg.PendingChannelID,
			lnwire.ErrSynchronizingChain,
		)
		return
	}

	// We'll reject any request to create a channel that's above the
	// current soft-limit for channel size.
	if msg.FundingAmount > MaxFundingAmount {
		f.failFundingFlow(
			fmsg.peer, fmsg.msg.PendingChannelID,
			lnwire.ErrChanTooLarge,
		)
		return
	}

	// We'll, also ensure that the remote party isn't attempting to propose
	// a channel that's below our current min channel size.
	if amt < f.cfg.MinChanSize {
		f.failFundingFlow(
			fmsg.peer, fmsg.msg.PendingChannelID,
			lnwallet.ErrChanTooSmall(amt, btcutil.Amount(f.cfg.MinChanSize)),
		)
		return
	}

	// If request specifies non-zero push amount and 'rejectpush' is set,
	// signal an error.
	if cfg.RejectPush && msg.PushAmount > 0 {
		f.failFundingFlow(
			fmsg.peer, fmsg.msg.PendingChannelID,
			lnwallet.ErrNonZeroPushAmount())
		return
	}

	fndgLog.Infof("Recv'd fundingRequest(amt=%v, push=%v, delay=%v, "+
		"pendingId=%x) from peer(%x)", amt, msg.PushAmount,
		msg.CsvDelay, msg.PendingChannelID,
		fmsg.peer.IdentityKey().SerializeCompressed())

	// Attempt to initialize a reservation within the wallet. If the wallet
	// has insufficient resources to create the channel, then the
	// reservation attempt may be rejected. Note that since we're on the
	// responding side of a single funder workflow, we don't commit any
	// funds to the channel ourselves.
	chainHash := chainhash.Hash(msg.ChainHash)
	req := &lnwallet.InitFundingReserveMsg{
		ChainHash:       &chainHash,
		NodeID:          fmsg.peer.IdentityKey(),
		NodeAddr:        fmsg.peer.Address(),
		FundingAmount:   0,
		Capacity:        amt,
		CommitFeePerKw:  lnwallet.SatPerKWeight(msg.FeePerKiloWeight),
		FundingFeePerKw: 0,
		PushMSat:        msg.PushAmount,
		Flags:           msg.ChannelFlags,
		MinConfs:        1,
	}

	reservation, err := f.cfg.Wallet.InitChannelReservation(req)
	if err != nil {
		fndgLog.Errorf("Unable to initialize reservation: %v", err)
		f.failFundingFlow(fmsg.peer, msg.PendingChannelID, err)
		return
	}

	// As we're the responder, we get to specify the number of confirmations
	// that we require before both of us consider the channel open. We'll
	// use our mapping to derive the proper number of confirmations based on
	// the amount of the channel, and also if any funds are being pushed to
	// us.
	numConfsReq := f.cfg.NumRequiredConfs(msg.FundingAmount, msg.PushAmount)
	reservation.SetNumConfsRequired(numConfsReq)

	// We'll also validate and apply all the constraints the initiating
	// party is attempting to dictate for our commitment transaction.
	channelConstraints := &channeldb.ChannelConstraints{
		DustLimit:        msg.DustLimit,
		ChanReserve:      msg.ChannelReserve,
		MaxPendingAmount: msg.MaxValueInFlight,
		MinHTLC:          msg.HtlcMinimum,
		MaxAcceptedHtlcs: msg.MaxAcceptedHTLCs,
		CsvDelay:         msg.CsvDelay,
	}
	err = reservation.CommitConstraints(channelConstraints)
	if err != nil {
		fndgLog.Errorf("Unacceptable channel constraints: %v", err)
		f.failFundingFlow(fmsg.peer, fmsg.msg.PendingChannelID, err)
		return
	}

	fndgLog.Infof("Requiring %v confirmations for pendingChan(%x): "+
		"amt=%v, push_amt=%v", numConfsReq, fmsg.msg.PendingChannelID,
		amt, msg.PushAmount)

	// Generate our required constraints for the remote party.
	remoteCsvDelay := f.cfg.RequiredRemoteDelay(amt)
	chanReserve := f.cfg.RequiredRemoteChanReserve(amt, msg.DustLimit)
	maxValue := f.cfg.RequiredRemoteMaxValue(amt)
	maxHtlcs := f.cfg.RequiredRemoteMaxHTLCs(amt)
	minHtlc := f.cfg.DefaultRoutingPolicy.MinHTLC

	// Once the reservation has been created successfully, we add it to
	// this peer's map of pending reservations to track this particular
	// reservation until either abort or completion.
	f.resMtx.Lock()
	if _, ok := f.activeReservations[peerIDKey]; !ok {
		f.activeReservations[peerIDKey] = make(pendingChannels)
	}
	resCtx := &reservationWithCtx{
		reservation:    reservation,
		chanAmt:        amt,
		remoteCsvDelay: remoteCsvDelay,
		remoteMinHtlc:  minHtlc,
		err:            make(chan error, 1),
		peer:           fmsg.peer,
	}
	f.activeReservations[peerIDKey][msg.PendingChannelID] = resCtx
	f.resMtx.Unlock()

	// Update the timestamp once the fundingOpenMsg has been handled.
	defer resCtx.updateTimestamp()

	// With our parameters set, we'll now process their contribution so we
	// can move the funding workflow ahead.
	remoteContribution := &lnwallet.ChannelContribution{
		FundingAmount:        amt,
		FirstCommitmentPoint: msg.FirstCommitmentPoint,
		ChannelConfig: &channeldb.ChannelConfig{
			ChannelConstraints: channeldb.ChannelConstraints{
				DustLimit:        msg.DustLimit,
				MaxPendingAmount: maxValue,
				ChanReserve:      chanReserve,
				MinHTLC:          minHtlc,
				MaxAcceptedHtlcs: maxHtlcs,
				CsvDelay:         remoteCsvDelay,
			},
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.FundingKey),
			},
			RevocationBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.RevocationPoint),
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.PaymentPoint),
			},
			DelayBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.DelayedPaymentPoint),
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.HtlcPoint),
			},
		},
	}
	err = reservation.ProcessSingleContribution(remoteContribution)
	if err != nil {
		fndgLog.Errorf("unable to add contribution reservation: %v", err)
		f.failFundingFlow(fmsg.peer, msg.PendingChannelID, err)
		return
	}

	fndgLog.Infof("Sending fundingResp for pendingID(%x)",
		msg.PendingChannelID)
	fndgLog.Debugf("Remote party accepted commitment constraints: %v",
		spew.Sdump(remoteContribution.ChannelConfig.ChannelConstraints))

	// With the initiator's contribution recorded, respond with our
	// contribution in the next message of the workflow.
	ourContribution := reservation.OurContribution()
	fundingAccept := lnwire.AcceptChannel{
		PendingChannelID:     msg.PendingChannelID,
		DustLimit:            ourContribution.DustLimit,
		MaxValueInFlight:     maxValue,
		ChannelReserve:       chanReserve,
		MinAcceptDepth:       uint32(numConfsReq),
		HtlcMinimum:          minHtlc,
		CsvDelay:             remoteCsvDelay,
		MaxAcceptedHTLCs:     maxHtlcs,
		FundingKey:           ourContribution.MultiSigKey.PubKey,
		RevocationPoint:      ourContribution.RevocationBasePoint.PubKey,
		PaymentPoint:         ourContribution.PaymentBasePoint.PubKey,
		DelayedPaymentPoint:  ourContribution.DelayBasePoint.PubKey,
		HtlcPoint:            ourContribution.HtlcBasePoint.PubKey,
		FirstCommitmentPoint: ourContribution.FirstCommitmentPoint,
	}
	if err := fmsg.peer.SendMessage(false, &fundingAccept); err != nil {
		fndgLog.Errorf("unable to send funding response to peer: %v", err)
		f.failFundingFlow(fmsg.peer, msg.PendingChannelID, err)
		return
	}
}

// processFundingAccept sends a message to the fundingManager allowing it to
// continue the second phase of a funding workflow with the target peer.
func (f *fundingManager) processFundingAccept(msg *lnwire.AcceptChannel,
	peer lnpeer.Peer) {

	select {
	case f.fundingMsgs <- &fundingAcceptMsg{msg, peer}:
	case <-f.quit:
		return
	}
}

// handleFundingAccept processes a response to the workflow initiation sent by
// the remote peer. This message then queues a message with the funding
// outpoint, and a commitment signature to the remote peer.
func (f *fundingManager) handleFundingAccept(fmsg *fundingAcceptMsg) {
	msg := fmsg.msg
	pendingChanID := fmsg.msg.PendingChannelID
	peerKey := fmsg.peer.IdentityKey()

	resCtx, err := f.getReservationCtx(peerKey, pendingChanID)
	if err != nil {
		fndgLog.Warnf("Can't find reservation (peerKey:%v, chanID:%v)",
			peerKey, pendingChanID)
		return
	}

	// Update the timestamp once the fundingAcceptMsg has been handled.
	defer resCtx.updateTimestamp()

	fndgLog.Infof("Recv'd fundingResponse for pendingID(%x)", pendingChanID[:])

	// The required number of confirmations should not be greater than the
	// maximum number of confirmations required by the ChainNotifier to
	// properly dispatch confirmations.
	if msg.MinAcceptDepth > chainntnfs.MaxNumConfs {
		err := lnwallet.ErrNumConfsTooLarge(
			msg.MinAcceptDepth, chainntnfs.MaxNumConfs,
		)
		fndgLog.Warnf("Unacceptable channel constraints: %v", err)
		f.failFundingFlow(fmsg.peer, fmsg.msg.PendingChannelID, err)
		return
	}

	// We'll also specify the responder's preference for the number of
	// required confirmations, and also the set of channel constraints
	// they've specified for commitment states we can create.
	resCtx.reservation.SetNumConfsRequired(uint16(msg.MinAcceptDepth))
	channelConstraints := &channeldb.ChannelConstraints{
		DustLimit:        msg.DustLimit,
		ChanReserve:      msg.ChannelReserve,
		MaxPendingAmount: msg.MaxValueInFlight,
		MinHTLC:          msg.HtlcMinimum,
		MaxAcceptedHtlcs: msg.MaxAcceptedHTLCs,
		CsvDelay:         msg.CsvDelay,
	}
	err = resCtx.reservation.CommitConstraints(channelConstraints)
	if err != nil {
		fndgLog.Warnf("Unacceptable channel constraints: %v", err)
		f.failFundingFlow(fmsg.peer, fmsg.msg.PendingChannelID, err)
		return
	}

	// As they've accepted our channel constraints, we'll regenerate them
	// here so we can properly commit their accepted constraints to the
	// reservation.
	chanReserve := f.cfg.RequiredRemoteChanReserve(resCtx.chanAmt, msg.DustLimit)
	maxValue := f.cfg.RequiredRemoteMaxValue(resCtx.chanAmt)
	maxHtlcs := f.cfg.RequiredRemoteMaxHTLCs(resCtx.chanAmt)

	// The remote node has responded with their portion of the channel
	// contribution. At this point, we can process their contribution which
	// allows us to construct and sign both the commitment transaction, and
	// the funding transaction.
	remoteContribution := &lnwallet.ChannelContribution{
		FirstCommitmentPoint: msg.FirstCommitmentPoint,
		ChannelConfig: &channeldb.ChannelConfig{
			ChannelConstraints: channeldb.ChannelConstraints{
				DustLimit:        msg.DustLimit,
				MaxPendingAmount: maxValue,
				ChanReserve:      chanReserve,
				MinHTLC:          resCtx.remoteMinHtlc,
				MaxAcceptedHtlcs: maxHtlcs,
				CsvDelay:         resCtx.remoteCsvDelay,
			},
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.FundingKey),
			},
			RevocationBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.RevocationPoint),
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.PaymentPoint),
			},
			DelayBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.DelayedPaymentPoint),
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: copyPubKey(msg.HtlcPoint),
			},
		},
	}
	err = resCtx.reservation.ProcessContribution(remoteContribution)
	if err != nil {
		fndgLog.Errorf("Unable to process contribution from %v: %v",
			peerKey, err)
		f.failFundingFlow(fmsg.peer, msg.PendingChannelID, err)
		return
	}

	fndgLog.Infof("pendingChan(%x): remote party proposes num_confs=%v, "+
		"csv_delay=%v", pendingChanID[:], msg.MinAcceptDepth, msg.CsvDelay)
	fndgLog.Debugf("Remote party accepted commitment constraints: %v",
		spew.Sdump(remoteContribution.ChannelConfig.ChannelConstraints))

	// Now that we have their contribution, we can extract, then send over
	// both the funding out point and our signature for their version of
	// the commitment transaction to the remote peer.
	outPoint := resCtx.reservation.FundingOutpoint()
	_, sig := resCtx.reservation.OurSignatures()

	// A new channel has almost finished the funding process. In order to
	// properly synchronize with the writeHandler goroutine, we add a new
	// channel to the barriers map which will be closed once the channel is
	// fully open.
	f.barrierMtx.Lock()
	channelID := lnwire.NewChanIDFromOutPoint(outPoint)
	fndgLog.Debugf("Creating chan barrier for ChanID(%v)", channelID)
	f.newChanBarriers[channelID] = make(chan struct{})
	f.barrierMtx.Unlock()

	// The next message that advances the funding flow will reference the
	// channel via its permanent channel ID, so we'll set up this mapping
	// so we can retrieve the reservation context once we get the
	// FundingSigned message.
	f.resMtx.Lock()
	f.signedReservations[channelID] = pendingChanID
	f.resMtx.Unlock()

	fndgLog.Infof("Generated ChannelPoint(%v) for pendingID(%x)", outPoint,
		pendingChanID[:])

	fundingCreated := &lnwire.FundingCreated{
		PendingChannelID: pendingChanID,
		FundingPoint:     *outPoint,
	}
	fundingCreated.CommitSig, err = lnwire.NewSigFromRawSignature(sig)
	if err != nil {
		fndgLog.Errorf("Unable to parse signature: %v", err)
		f.failFundingFlow(fmsg.peer, msg.PendingChannelID, err)
		return
	}
	if err := fmsg.peer.SendMessage(false, fundingCreated); err != nil {
		fndgLog.Errorf("Unable to send funding complete message: %v", err)
		f.failFundingFlow(fmsg.peer, msg.PendingChannelID, err)
		return
	}
}

// processFundingCreated queues a funding complete message coupled with the
// source peer to the fundingManager.
func (f *fundingManager) processFundingCreated(msg *lnwire.FundingCreated,
	peer lnpeer.Peer) {

	select {
	case f.fundingMsgs <- &fundingCreatedMsg{msg, peer}:
	case <-f.quit:
		return
	}
}

// handleFundingCreated progresses the funding workflow when the daemon is on
// the responding side of a single funder workflow. Once this message has been
// processed, a signature is sent to the remote peer allowing it to broadcast
// the funding transaction, progressing the workflow into the final stage.
func (f *fundingManager) handleFundingCreated(fmsg *fundingCreatedMsg) {
	peerKey := fmsg.peer.IdentityKey()
	pendingChanID := fmsg.msg.PendingChannelID

	resCtx, err := f.getReservationCtx(peerKey, pendingChanID)
	if err != nil {
		fndgLog.Warnf("can't find reservation (peerID:%v, chanID:%x)",
			peerKey, pendingChanID[:])
		return
	}

	// The channel initiator has responded with the funding outpoint of the
	// final funding transaction, as well as a signature for our version of
	// the commitment transaction. So at this point, we can validate the
	// initiator's commitment transaction, then send our own if it's valid.
	// TODO(roasbeef): make case (p vs P) consistent throughout
	fundingOut := fmsg.msg.FundingPoint
	fndgLog.Infof("completing pendingID(%x) with ChannelPoint(%v)",
		pendingChanID[:], fundingOut)

	// With all the necessary data available, attempt to advance the
	// funding workflow to the next stage. If this succeeds then the
	// funding transaction will broadcast after our next message.
	// CompleteReservationSingle will also mark the channel as 'IsPending'
	// in the database.
	commitSig := fmsg.msg.CommitSig.ToSignatureBytes()
	completeChan, err := resCtx.reservation.CompleteReservationSingle(
		&fundingOut, commitSig)
	if err != nil {
		// TODO(roasbeef): better error logging: peerID, channelID, etc.
		fndgLog.Errorf("unable to complete single reservation: %v", err)
		f.failFundingFlow(fmsg.peer, pendingChanID, err)
		return
	}

	// The channel is marked IsPending in the database, and can be removed
	// from the set of active reservations.
	f.deleteReservationCtx(peerKey, fmsg.msg.PendingChannelID)

	// If something goes wrong before the funding transaction is confirmed,
	// we use this convenience method to delete the pending OpenChannel
	// from the database.
	deleteFromDatabase := func() {
		localBalance := completeChan.LocalCommitment.LocalBalance.ToSatoshis()
		closeInfo := &channeldb.ChannelCloseSummary{
			ChanPoint:               completeChan.FundingOutpoint,
			ChainHash:               completeChan.ChainHash,
			RemotePub:               completeChan.IdentityPub,
			CloseType:               channeldb.FundingCanceled,
			Capacity:                completeChan.Capacity,
			SettledBalance:          localBalance,
			RemoteCurrentRevocation: completeChan.RemoteCurrentRevocation,
			RemoteNextRevocation:    completeChan.RemoteNextRevocation,
			LocalChanConfig:         completeChan.LocalChanCfg,
		}

		if err := completeChan.CloseChannel(closeInfo); err != nil {
			fndgLog.Errorf("Failed closing channel %v: %v",
				completeChan.FundingOutpoint, err)
		}
	}

	// A new channel has almost finished the funding process. In order to
	// properly synchronize with the writeHandler goroutine, we add a new
	// channel to the barriers map which will be closed once the channel is
	// fully open.
	f.barrierMtx.Lock()
	channelID := lnwire.NewChanIDFromOutPoint(&fundingOut)
	fndgLog.Debugf("Creating chan barrier for ChanID(%v)", channelID)
	f.newChanBarriers[channelID] = make(chan struct{})
	f.barrierMtx.Unlock()

	fndgLog.Infof("sending FundingSigned for pendingID(%x) over "+
		"ChannelPoint(%v)", pendingChanID[:], fundingOut)

	// With their signature for our version of the commitment transaction
	// verified, we can now send over our signature to the remote peer.
	_, sig := resCtx.reservation.OurSignatures()
	ourCommitSig, err := lnwire.NewSigFromRawSignature(sig)
	if err != nil {
		fndgLog.Errorf("unable to parse signature: %v", err)
		f.failFundingFlow(fmsg.peer, pendingChanID, err)
		deleteFromDatabase()
		return
	}

	fundingSigned := &lnwire.FundingSigned{
		ChanID:    channelID,
		CommitSig: ourCommitSig,
	}
	if err := fmsg.peer.SendMessage(false, fundingSigned); err != nil {
		fndgLog.Errorf("unable to send FundingSigned message: %v", err)
		f.failFundingFlow(fmsg.peer, pendingChanID, err)
		deleteFromDatabase()
		return
	}

	// Now that we've sent over our final signature for this channel, we'll
	// send it to the ChainArbitrator so it can watch for any on-chain
	// actions during this final confirmation stage.
	if err := f.cfg.WatchNewChannel(completeChan, peerKey); err != nil {
		fndgLog.Errorf("Unable to send new ChannelPoint(%v) for "+
			"arbitration: %v", fundingOut, err)
	}

	// Create an entry in the local discovery map so we can ensure that we
	// process the channel confirmation fully before we receive a funding
	// locked message.
	f.localDiscoveryMtx.Lock()
	f.localDiscoverySignals[channelID] = make(chan struct{})
	f.localDiscoveryMtx.Unlock()

	// At this point we have sent our last funding message to the
	// initiating peer before the funding transaction will be broadcast.
	// With this last message, our job as the responder is now complete.
	// We'll wait for the funding transaction to reach the specified number
	// of confirmations, then start normal operations.
	//
	// When we get to this point we have sent the signComplete message to
	// the channel funder, and BOLT#2 specifies that we MUST remember the
	// channel for reconnection. The channel is already marked
	// as pending in the database, so in case of a disconnect or restart,
	// we will continue waiting for the confirmation the next time we start
	// the funding manager. In case the funding transaction never appears
	// on the blockchain, we must forget this channel. We therefore
	// completely forget about this channel if we haven't seen the funding
	// transaction in 288 blocks (~ 48 hrs), by canceling the reservation
	// and canceling the wait for the funding confirmation.
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		confChan := make(chan *lnwire.ShortChannelID)
		timeoutChan := make(chan struct{})
		go f.waitForFundingWithTimeout(completeChan, confChan,
			timeoutChan)

		var shortChanID *lnwire.ShortChannelID
		var ok bool
		select {
		case <-timeoutChan:
			// We did not see the funding confirmation before
			// timeout, so we forget the channel.
			err := fmt.Errorf("timeout waiting for funding tx "+
				"(%v) to confirm", completeChan.FundingOutpoint)
			fndgLog.Warnf(err.Error())
			f.failFundingFlow(fmsg.peer, pendingChanID, err)
			deleteFromDatabase()
			return
		case <-f.quit:
			// The fundingManager is shutting down, will resume
			// wait for funding transaction on startup.
			return
		case shortChanID, ok = <-confChan:
			if !ok {
				fndgLog.Errorf("waiting for funding confirmation" +
					" failed")
				return
			}
			// Fallthrough.
		}

		// Success, funding transaction was confirmed.
		err := f.handleFundingConfirmation(
			fmsg.peer, completeChan, shortChanID,
		)
		if err != nil {
			fndgLog.Errorf("failed to handle funding"+
				"confirmation: %v", err)
			return
		}
	}()
}

// processFundingSigned sends a single funding sign complete message along with
// the source peer to the funding manager.
func (f *fundingManager) processFundingSigned(msg *lnwire.FundingSigned,
	peer lnpeer.Peer) {

	select {
	case f.fundingMsgs <- &fundingSignedMsg{msg, peer}:
	case <-f.quit:
		return
	}
}

// handleFundingSigned processes the final message received in a single funder
// workflow. Once this message is processed, the funding transaction is
// broadcast. Once the funding transaction reaches a sufficient number of
// confirmations, a message is sent to the responding peer along with a compact
// encoding of the location of the channel within the blockchain.
func (f *fundingManager) handleFundingSigned(fmsg *fundingSignedMsg) {
	// As the funding signed message will reference the reservation by its
	// permanent channel ID, we'll need to perform an intermediate look up
	// before we can obtain the reservation.
	f.resMtx.Lock()
	pendingChanID, ok := f.signedReservations[fmsg.msg.ChanID]
	delete(f.signedReservations, fmsg.msg.ChanID)
	f.resMtx.Unlock()
	if !ok {
		err := fmt.Errorf("Unable to find signed reservation for "+
			"chan_id=%x", fmsg.msg.ChanID)
		fndgLog.Warnf(err.Error())
		f.failFundingFlow(fmsg.peer, fmsg.msg.ChanID, err)
		return
	}

	peerKey := fmsg.peer.IdentityKey()
	resCtx, err := f.getReservationCtx(peerKey, pendingChanID)
	if err != nil {
		fndgLog.Warnf("Unable to find reservation (peerID:%v, chanID:%x)",
			peerKey, pendingChanID[:])
		// TODO: add ErrChanNotFound?
		f.failFundingFlow(fmsg.peer, pendingChanID, err)
		return
	}

	// Create an entry in the local discovery map so we can ensure that we
	// process the channel confirmation fully before we receive a funding
	// locked message.
	fundingPoint := resCtx.reservation.FundingOutpoint()
	permChanID := lnwire.NewChanIDFromOutPoint(fundingPoint)
	f.localDiscoveryMtx.Lock()
	f.localDiscoverySignals[permChanID] = make(chan struct{})
	f.localDiscoveryMtx.Unlock()

	// The remote peer has responded with a signature for our commitment
	// transaction. We'll verify the signature for validity, then commit
	// the state to disk as we can now open the channel.
	commitSig := fmsg.msg.CommitSig.ToSignatureBytes()
	completeChan, err := resCtx.reservation.CompleteReservation(
		nil, commitSig,
	)
	if err != nil {
		fndgLog.Errorf("Unable to complete reservation sign "+
			"complete: %v", err)
		f.failFundingFlow(fmsg.peer, pendingChanID, err)
		return
	}

	// The channel is now marked IsPending in the database, and we can
	// delete it from our set of active reservations.
	f.deleteReservationCtx(peerKey, pendingChanID)

	// Broadcast the finalized funding transaction to the network.
	fundingTx := completeChan.FundingTxn
	fndgLog.Infof("Broadcasting funding tx for ChannelPoint(%v): %v",
		completeChan.FundingOutpoint, spew.Sdump(fundingTx))

	err = f.cfg.PublishTransaction(fundingTx)
	if err != nil {
		fndgLog.Errorf("Unable to broadcast funding tx for "+
			"ChannelPoint(%v): %v", completeChan.FundingOutpoint,
			err)
		// We failed to broadcast the funding transaction, but watch
		// the channel regardless, in case the transaction made it to
		// the network. We will retry broadcast at startup.
		// TODO(halseth): retry more often? Handle with CPFP? Just
		// delete from the DB?
	}

	// Now that we have a finalized reservation for this funding flow,
	// we'll send the to be active channel to the ChainArbitrator so it can
	// watch for any on-chain actions before the channel has fully
	// confirmed.
	if err := f.cfg.WatchNewChannel(completeChan, peerKey); err != nil {
		fndgLog.Errorf("Unable to send new ChannelPoint(%v) for "+
			"arbitration: %v", fundingPoint, err)
	}

	fndgLog.Infof("Finalizing pendingID(%x) over ChannelPoint(%v), "+
		"waiting for channel open on-chain", pendingChanID[:],
		fundingPoint)

	// Send an update to the upstream client that the negotiation process
	// is over.
	// TODO(roasbeef): add abstraction over updates to accommodate
	// long-polling, or SSE, etc.
	upd := &lnrpc.OpenStatusUpdate{
		Update: &lnrpc.OpenStatusUpdate_ChanPending{
			ChanPending: &lnrpc.PendingUpdate{
				Txid:        fundingPoint.Hash[:],
				OutputIndex: fundingPoint.Index,
			},
		},
	}

	select {
	case resCtx.updates <- upd:
	case <-f.quit:
		return
	}

	// At this point we have broadcast the funding transaction and done all
	// necessary processing.
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		confChan := make(chan *lnwire.ShortChannelID)
		cancelChan := make(chan struct{})

		// In case the fundingManager is stopped at some point during
		// the remaining part of the opening process, we must wait for
		// this process to finish (either successfully or with some
		// error), before the fundingManager can be shut down.
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.waitForFundingConfirmation(completeChan, cancelChan,
				confChan)
		}()

		var shortChanID *lnwire.ShortChannelID
		var ok bool
		select {
		case <-f.quit:
			return
		case shortChanID, ok = <-confChan:
			if !ok {
				fndgLog.Errorf("waiting for funding confirmation" +
					" failed")
				return
			}
		}

		fndgLog.Debugf("Channel with ShortChanID %v now confirmed",
			shortChanID.ToUint64())

		// Go on adding the channel to the channel graph, and crafting
		// channel announcements.
		lnChannel, err := lnwallet.NewLightningChannel(
			nil, completeChan, nil,
		)
		if err != nil {
			fndgLog.Errorf("failed creating lnChannel: %v", err)
			return
		}

		err = f.sendFundingLocked(
			fmsg.peer, completeChan, lnChannel, shortChanID,
		)
		if err != nil {
			fndgLog.Errorf("failed sending fundingLocked: %v", err)
			return
		}
		fndgLog.Debugf("FundingLocked for channel with ShortChanID "+
			"%v sent", shortChanID.ToUint64())

		err = f.addToRouterGraph(completeChan, shortChanID)
		if err != nil {
			fndgLog.Errorf("failed adding to router graph: %v", err)
			return
		}
		fndgLog.Debugf("Channel with ShortChanID %v added to "+
			"router graph", shortChanID.ToUint64())

		// Give the caller a final update notifying them that
		// the channel is now open.
		// TODO(roasbeef): only notify after recv of funding locked?
		upd := &lnrpc.OpenStatusUpdate{
			Update: &lnrpc.OpenStatusUpdate_ChanOpen{
				ChanOpen: &lnrpc.ChannelOpenUpdate{
					ChannelPoint: &lnrpc.ChannelPoint{
						FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
							FundingTxidBytes: fundingPoint.Hash[:],
						},
						OutputIndex: fundingPoint.Index,
					},
				},
			},
		}

		select {
		case resCtx.updates <- upd:
		case <-f.quit:
			return
		}

		err = f.annAfterSixConfs(completeChan, shortChanID)
		if err != nil {
			fndgLog.Errorf("failed sending channel announcement: %v",
				err)
			return
		}
	}()
}

// waitForFundingWithTimeout is a wrapper around waitForFundingConfirmation that
// will cancel the wait for confirmation if we are not the channel initiator and
// the maxWaitNumBlocksFundingConf has passed from bestHeight.
// In the case of timeout, the timeoutChan will be closed. In case of error,
// confChan will be closed. In case of success, a *lnwire.ShortChannelID will be
// passed to confChan.
func (f *fundingManager) waitForFundingWithTimeout(completeChan *channeldb.OpenChannel,
	confChan chan<- *lnwire.ShortChannelID, timeoutChan chan<- struct{}) {

	epochClient, err := f.cfg.Notifier.RegisterBlockEpochNtfn(nil)
	if err != nil {
		fndgLog.Errorf("unable to register for epoch notification: %v",
			err)
		close(confChan)
		return
	}

	defer epochClient.Cancel()

	waitingConfChan := make(chan *lnwire.ShortChannelID)
	cancelChan := make(chan struct{})

	// Add this goroutine to wait group so we can be sure that it is
	// properly stopped before the funding manager can be shut down.
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.waitForFundingConfirmation(completeChan, cancelChan,
			waitingConfChan)
	}()

	// On block maxHeight we will cancel the funding confirmation wait.
	maxHeight := completeChan.FundingBroadcastHeight + maxWaitNumBlocksFundingConf
	for {
		select {
		case epoch, ok := <-epochClient.Epochs:
			if !ok {
				fndgLog.Warnf("Epoch client shutting down")
				return
			}

			// If we are not the channel initiator it's safe
			// to timeout the channel
			if uint32(epoch.Height) >= maxHeight && !completeChan.IsInitiator {
				fndgLog.Warnf("waited for %v blocks without "+
					"seeing funding transaction confirmed,"+
					" cancelling.", maxWaitNumBlocksFundingConf)

				// Cancel the waitForFundingConfirmation
				// goroutine.
				close(cancelChan)

				// Notify the caller of the timeout.
				close(timeoutChan)
				return
			}

			// TODO: If we are the channel initiator implement
			// a method for recovering the funds from the funding
			// transaction

		case <-f.quit:
			// The fundingManager is shutting down, will resume
			// waiting for the funding transaction on startup.
			return
		case shortChanID, ok := <-waitingConfChan:
			if !ok {
				// Failed waiting for confirmation, close
				// confChan to indicate failure.
				close(confChan)
				return
			}

			select {
			case confChan <- shortChanID:
			case <-f.quit:
				return
			}
		}
	}
}

// makeFundingScript re-creates the funding script for the funding transaction
// of the target channel.
func makeFundingScript(channel *channeldb.OpenChannel) ([]byte, error) {
	localKey := channel.LocalChanCfg.MultiSigKey.PubKey.SerializeCompressed()
	remoteKey := channel.RemoteChanCfg.MultiSigKey.PubKey.SerializeCompressed()

	multiSigScript, err := input.GenMultiSigScript(localKey, remoteKey)
	if err != nil {
		return nil, err
	}

	return input.WitnessScriptHash(multiSigScript)
}

// waitForFundingConfirmation handles the final stages of the channel funding
// process once the funding transaction has been broadcast. The primary
// function of waitForFundingConfirmation is to wait for blockchain
// confirmation, and then to notify the other systems that must be notified
// when a channel has become active for lightning transactions.
// The wait can be canceled by closing the cancelChan. In case of success,
// a *lnwire.ShortChannelID will be passed to confChan.
func (f *fundingManager) waitForFundingConfirmation(completeChan *channeldb.OpenChannel,
	cancelChan <-chan struct{}, confChan chan<- *lnwire.ShortChannelID) {

	defer close(confChan)

	// Register with the ChainNotifier for a notification once the funding
	// transaction reaches `numConfs` confirmations.
	txid := completeChan.FundingOutpoint.Hash
	fundingScript, err := makeFundingScript(completeChan)
	if err != nil {
		fndgLog.Errorf("unable to create funding script for "+
			"ChannelPoint(%v): %v", completeChan.FundingOutpoint, err)
		return
	}
	numConfs := uint32(completeChan.NumConfsRequired)
	confNtfn, err := f.cfg.Notifier.RegisterConfirmationsNtfn(
		&txid, fundingScript, numConfs, completeChan.FundingBroadcastHeight,
	)
	if err != nil {
		fndgLog.Errorf("Unable to register for confirmation of "+
			"ChannelPoint(%v): %v", completeChan.FundingOutpoint, err)
		return
	}

	fndgLog.Infof("Waiting for funding tx (%v) to reach %v confirmations",
		txid, numConfs)

	var confDetails *chainntnfs.TxConfirmation
	var ok bool

	// Wait until the specified number of confirmations has been reached,
	// we get a cancel signal, or the wallet signals a shutdown.
	select {
	case confDetails, ok = <-confNtfn.Confirmed:
		// fallthrough
	case <-cancelChan:
		fndgLog.Warnf("canceled waiting for funding confirmation, "+
			"stopping funding flow for ChannelPoint(%v)",
			completeChan.FundingOutpoint)
		return
	case <-f.quit:
		fndgLog.Warnf("fundingManager shutting down, stopping funding "+
			"flow for ChannelPoint(%v)", completeChan.FundingOutpoint)
		return
	}

	if !ok {
		fndgLog.Warnf("ChainNotifier shutting down, cannot complete "+
			"funding flow for ChannelPoint(%v)",
			completeChan.FundingOutpoint)
		return
	}

	fundingPoint := completeChan.FundingOutpoint
	chanID := lnwire.NewChanIDFromOutPoint(&fundingPoint)

	fndgLog.Infof("ChannelPoint(%v) is now active: ChannelID(%x)",
		fundingPoint, chanID[:])

	// With the block height and the transaction index known, we can
	// construct the compact chanID which is used on the network to unique
	// identify channels.
	shortChanID := lnwire.ShortChannelID{
		BlockHeight: confDetails.BlockHeight,
		TxIndex:     confDetails.TxIndex,
		TxPosition:  uint16(fundingPoint.Index),
	}

	// Now that the channel has been fully confirmed, we'll mark it as open
	// within the database.
	if err := completeChan.MarkAsOpen(shortChanID); err != nil {
		fndgLog.Errorf("error setting channel pending flag to false: "+
			"%v", err)
		return
	}

	// Inform the ChannelNotifier that the channel has transitioned from
	// pending open to open.
	f.cfg.NotifyOpenChannelEvent(completeChan.FundingOutpoint)

	// TODO(roasbeef): ideally persistent state update for chan above
	// should be abstracted

	// The funding transaction now being confirmed, we add this channel to
	// the fundingManager's internal persistent state machine that we use
	// to track the remaining process of the channel opening. This is
	// useful to resume the opening process in case of restarts.
	//
	// TODO(halseth): make the two db transactions (MarkChannelAsOpen and
	// saveChannelOpeningState) atomic by doing them in the same transaction.
	// Needed to be properly fault-tolerant.
	err = f.saveChannelOpeningState(
		&completeChan.FundingOutpoint, markedOpen, &shortChanID,
	)
	if err != nil {
		fndgLog.Errorf("error setting channel state to markedOpen: %v",
			err)
		return
	}

	// As there might already be an active link in the switch with an
	// outdated short chan ID, we'll instruct the switch to load the updated
	// short chan id from disk.
	err = f.cfg.ReportShortChanID(fundingPoint)
	if err != nil {
		fndgLog.Errorf("unable to report short chan id: %v", err)
	}

	select {
	case confChan <- &shortChanID:
	case <-f.quit:
		return
	}

	// Close the discoverySignal channel, indicating to a separate
	// goroutine that the channel now is marked as open in the database
	// and that it is acceptable to process funding locked messages
	// from the peer.
	f.localDiscoveryMtx.Lock()
	if discoverySignal, ok := f.localDiscoverySignals[chanID]; ok {
		close(discoverySignal)
	}
	f.localDiscoveryMtx.Unlock()
}

// handleFundingConfirmation is a wrapper method for creating a new
// lnwallet.LightningChannel object, calling sendFundingLocked,
// addToRouterGraph, and annAfterSixConfs. This is called after the funding
// transaction is confirmed.
func (f *fundingManager) handleFundingConfirmation(peer lnpeer.Peer,
	completeChan *channeldb.OpenChannel,
	shortChanID *lnwire.ShortChannelID) error {

	// We create the state-machine object which wraps the database state.
	lnChannel, err := lnwallet.NewLightningChannel(
		nil, completeChan, nil,
	)
	if err != nil {
		return err
	}

	chanID := lnwire.NewChanIDFromOutPoint(&completeChan.FundingOutpoint)

	fndgLog.Debugf("ChannelID(%v) is now fully confirmed!", chanID)

	err = f.sendFundingLocked(peer, completeChan, lnChannel, shortChanID)
	if err != nil {
		return fmt.Errorf("failed sending fundingLocked: %v", err)
	}
	err = f.addToRouterGraph(completeChan, shortChanID)
	if err != nil {
		return fmt.Errorf("failed adding to router graph: %v", err)
	}
	err = f.annAfterSixConfs(completeChan, shortChanID)
	if err != nil {
		return fmt.Errorf("failed sending channel announcement: %v",
			err)
	}

	return nil
}

// sendFundingLocked creates and sends the fundingLocked message.
// This should be called after the funding transaction has been confirmed,
// and the channelState is 'markedOpen'.
func (f *fundingManager) sendFundingLocked(peer lnpeer.Peer,
	completeChan *channeldb.OpenChannel, channel *lnwallet.LightningChannel,
	shortChanID *lnwire.ShortChannelID) error {

	chanID := lnwire.NewChanIDFromOutPoint(&completeChan.FundingOutpoint)

	var peerKey [33]byte
	copy(peerKey[:], completeChan.IdentityPub.SerializeCompressed())

	// Next, we'll send over the funding locked message which marks that we
	// consider the channel open by presenting the remote party with our
	// next revocation key. Without the revocation key, the remote party
	// will be unable to propose state transitions.
	nextRevocation, err := channel.NextRevocationKey()
	if err != nil {
		return fmt.Errorf("unable to create next revocation: %v", err)
	}
	fundingLockedMsg := lnwire.NewFundingLocked(chanID, nextRevocation)

	// If the peer has disconnected before we reach this point, we will need
	// to wait for him to come back online before sending the fundingLocked
	// message. This is special for fundingLocked, since failing to send any
	// of the previous messages in the funding flow just cancels the flow.
	// But now the funding transaction is confirmed, the channel is open
	// and we have to make sure the peer gets the fundingLocked message when
	// it comes back online. This is also crucial during restart of lnd,
	// where we might try to resend the fundingLocked message before the
	// server has had the time to connect to the peer. We keep trying to
	// send fundingLocked until we succeed, or the fundingManager is shut
	// down.
	for {
		fndgLog.Debugf("Sending FundingLocked for ChannelID(%v) to "+
			"peer %x", chanID, peerKey)

		if err := peer.SendMessage(false, fundingLockedMsg); err == nil {
			// Sending succeeded, we can break out and continue the
			// funding flow.
			break
		}

		fndgLog.Warnf("Unable to send fundingLocked to peer %x: %v. "+
			"Will retry when online", peerKey, err)

		connected := make(chan lnpeer.Peer, 1)
		f.cfg.NotifyWhenOnline(peerKey, connected)

		select {
		case <-connected:
			fndgLog.Infof("Peer(%x) came back online, will retry "+
				"sending FundingLocked for ChannelID(%v)",
				peerKey, chanID)

			// Retry sending.
		case <-f.quit:
			return ErrFundingManagerShuttingDown
		}
	}

	// As the fundingLocked message is now sent to the peer, the channel is
	// moved to the next state of the state machine. It will be moved to the
	// last state (actually deleted from the database) after the channel is
	// finally announced.
	err = f.saveChannelOpeningState(&completeChan.FundingOutpoint,
		fundingLockedSent, shortChanID)
	if err != nil {
		return fmt.Errorf("error setting channel state to"+
			" fundingLockedSent: %v", err)
	}

	return nil
}

// addToRouterGraph sends a ChannelAnnouncement and a ChannelUpdate to the
// gossiper so that the channel is added to the Router's internal graph.
// These announcement messages are NOT broadcasted to the greater network,
// only to the channel counter party. The proofs required to announce the
// channel to the greater network will be created and sent in annAfterSixConfs.
func (f *fundingManager) addToRouterGraph(completeChan *channeldb.OpenChannel,
	shortChanID *lnwire.ShortChannelID) error {

	chanID := lnwire.NewChanIDFromOutPoint(&completeChan.FundingOutpoint)

	// We'll obtain the min HTLC value we can forward in our direction, as
	// we'll use this value within our ChannelUpdate. This constraint is
	// originally set by the remote node, as it will be the one that will
	// need to determine the smallest HTLC it deems economically relevant.
	fwdMinHTLC := completeChan.LocalChanCfg.MinHTLC

	// We'll obtain the max HTLC value we can forward in our direction, as
	// we'll use this value within our ChannelUpdate. This value must be <=
	// channel capacity and <= the maximum in-flight msats set by the peer.
	fwdMaxHTLC := completeChan.LocalChanCfg.MaxPendingAmount
	capacityMSat := lnwire.NewMSatFromSatoshis(completeChan.Capacity)
	if fwdMaxHTLC > capacityMSat {
		fwdMaxHTLC = capacityMSat
	}

	ann, err := f.newChanAnnouncement(
		f.cfg.IDKey, completeChan.IdentityPub,
		completeChan.LocalChanCfg.MultiSigKey.PubKey,
		completeChan.RemoteChanCfg.MultiSigKey.PubKey, *shortChanID,
		chanID, fwdMinHTLC, fwdMaxHTLC,
	)
	if err != nil {
		return fmt.Errorf("error generating channel "+
			"announcement: %v", err)
	}

	// Send ChannelAnnouncement and ChannelUpdate to the gossiper to add
	// to the Router's topology.
	errChan := f.cfg.SendAnnouncement(
		ann.chanAnn, discovery.ChannelCapacity(completeChan.Capacity),
		discovery.ChannelPoint(completeChan.FundingOutpoint),
	)
	select {
	case err := <-errChan:
		if err != nil {
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {
				fndgLog.Debugf("Router rejected "+
					"ChannelAnnouncement: %v", err)
			} else {
				return fmt.Errorf("error sending channel "+
					"announcement: %v", err)
			}
		}
	case <-f.quit:
		return ErrFundingManagerShuttingDown
	}

	errChan = f.cfg.SendAnnouncement(ann.chanUpdateAnn)
	select {
	case err := <-errChan:
		if err != nil {
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {
				fndgLog.Debugf("Router rejected "+
					"ChannelUpdate: %v", err)
			} else {
				return fmt.Errorf("error sending channel "+
					"update: %v", err)
			}
		}
	case <-f.quit:
		return ErrFundingManagerShuttingDown
	}

	// As the channel is now added to the ChannelRouter's topology, the
	// channel is moved to the next state of the state machine. It will be
	// moved to the last state (actually deleted from the database) after
	// the channel is finally announced.
	err = f.saveChannelOpeningState(&completeChan.FundingOutpoint,
		addedToRouterGraph, shortChanID)
	if err != nil {
		return fmt.Errorf("error setting channel state to"+
			" addedToRouterGraph: %v", err)
	}

	return nil
}

// annAfterSixConfs broadcasts the necessary channel announcement messages to
// the network after 6 confs. Should be called after the fundingLocked message
// is sent and the channel is added to the router graph (channelState is
// 'addedToRouterGraph') and the channel is ready to be used. This is the last
// step in the channel opening process, and the opening state will be deleted
// from the database if successful.
func (f *fundingManager) annAfterSixConfs(completeChan *channeldb.OpenChannel,
	shortChanID *lnwire.ShortChannelID) error {

	// If this channel is not meant to be announced to the greater network,
	// we'll only send our NodeAnnouncement to our counterparty to ensure we
	// don't leak any of our information.
	announceChan := completeChan.ChannelFlags&lnwire.FFAnnounceChannel != 0
	if !announceChan {
		fndgLog.Debugf("Will not announce private channel %v.",
			shortChanID.ToUint64())

		peerChan := make(chan lnpeer.Peer, 1)

		var peerKey [33]byte
		copy(peerKey[:], completeChan.IdentityPub.SerializeCompressed())

		f.cfg.NotifyWhenOnline(peerKey, peerChan)

		var peer lnpeer.Peer
		select {
		case peer = <-peerChan:
		case <-f.quit:
			return ErrFundingManagerShuttingDown
		}

		nodeAnn, err := f.cfg.CurrentNodeAnnouncement()
		if err != nil {
			return fmt.Errorf("unable to retrieve current node "+
				"announcement: %v", err)
		}

		chanID := lnwire.NewChanIDFromOutPoint(
			&completeChan.FundingOutpoint,
		)
		pubKey := peer.PubKey()
		fndgLog.Debugf("Sending our NodeAnnouncement for "+
			"ChannelID(%v) to %x", chanID, pubKey)

		if err := peer.SendMessage(true, &nodeAnn); err != nil {
			return fmt.Errorf("unable to send node announcement "+
				"to peer %x: %v", pubKey, err)
		}
	} else {
		// Otherwise, we'll wait until the funding transaction has
		// reached 6 confirmations before announcing it.
		numConfs := uint32(completeChan.NumConfsRequired)
		if numConfs < 6 {
			numConfs = 6
		}
		txid := completeChan.FundingOutpoint.Hash
		fndgLog.Debugf("Will announce channel %v after ChannelPoint"+
			"(%v) has gotten %d confirmations",
			shortChanID.ToUint64(), completeChan.FundingOutpoint,
			numConfs)

		fundingScript, err := makeFundingScript(completeChan)
		if err != nil {
			return fmt.Errorf("unable to create funding script for "+
				"ChannelPoint(%v): %v",
				completeChan.FundingOutpoint, err)
		}

		// Register with the ChainNotifier for a notification once the
		// funding transaction reaches at least 6 confirmations.
		confNtfn, err := f.cfg.Notifier.RegisterConfirmationsNtfn(
			&txid, fundingScript, numConfs,
			completeChan.FundingBroadcastHeight,
		)
		if err != nil {
			return fmt.Errorf("Unable to register for "+
				"confirmation of ChannelPoint(%v): %v",
				completeChan.FundingOutpoint, err)
		}

		// Wait until 6 confirmations has been reached or the wallet
		// signals a shutdown.
		select {
		case _, ok := <-confNtfn.Confirmed:
			if !ok {
				return fmt.Errorf("ChainNotifier shutting "+
					"down, cannot complete funding flow "+
					"for ChannelPoint(%v)",
					completeChan.FundingOutpoint)
			}
			// Fallthrough.

		case <-f.quit:
			return fmt.Errorf("%v, stopping funding flow for "+
				"ChannelPoint(%v)",
				ErrFundingManagerShuttingDown,
				completeChan.FundingOutpoint)
		}

		fundingPoint := completeChan.FundingOutpoint
		chanID := lnwire.NewChanIDFromOutPoint(&fundingPoint)

		fndgLog.Infof("Announcing ChannelPoint(%v), short_chan_id=%v",
			&fundingPoint, shortChanID)

		// We'll obtain the min HTLC value we can forward in our
		// direction, as we'll use this value within our ChannelUpdate.
		// This constraint is originally set by the remote node, as it
		// will be the one that will need to determine the smallest
		// HTLC it deems economically relevant.
		fwdMinHTLC := completeChan.LocalChanCfg.MinHTLC

		// We'll obtain the max HTLC value we can forward in our
		// direction, as we'll use this value within our ChannelUpdate.
		// This value must be <= channel capacity and <= the maximum
		// in-flight msats set by the peer.
		fwdMaxHTLC := completeChan.LocalChanCfg.MaxPendingAmount
		capacityMSat := lnwire.NewMSatFromSatoshis(completeChan.Capacity)
		if fwdMaxHTLC > capacityMSat {
			fwdMaxHTLC = capacityMSat
		}

		// Create and broadcast the proofs required to make this channel
		// public and usable for other nodes for routing.
		err = f.announceChannel(
			f.cfg.IDKey, completeChan.IdentityPub,
			completeChan.LocalChanCfg.MultiSigKey.PubKey,
			completeChan.RemoteChanCfg.MultiSigKey.PubKey,
			*shortChanID, chanID, fwdMinHTLC, fwdMaxHTLC,
		)
		if err != nil {
			return fmt.Errorf("channel announcement failed: %v", err)
		}

		fndgLog.Debugf("Channel with ChannelPoint(%v), short_chan_id=%v "+
			"announced", &fundingPoint, shortChanID)
	}

	// We delete the channel opening state from our internal database
	// as the opening process has succeeded. We can do this because we
	// assume the AuthenticatedGossiper queues the announcement messages,
	// and persists them in case of a daemon shutdown.
	err := f.deleteChannelOpeningState(&completeChan.FundingOutpoint)
	if err != nil {
		return fmt.Errorf("error deleting channel state: %v", err)
	}

	return nil
}

// processFundingLocked sends a message to the fundingManager allowing it to
// finish the funding workflow.
func (f *fundingManager) processFundingLocked(msg *lnwire.FundingLocked,
	peer lnpeer.Peer) {

	select {
	case f.fundingMsgs <- &fundingLockedMsg{msg, peer}:
	case <-f.quit:
		return
	}
}

// handleFundingLocked finalizes the channel funding process and enables the
// channel to enter normal operating mode.
func (f *fundingManager) handleFundingLocked(fmsg *fundingLockedMsg) {
	defer f.wg.Done()
	fndgLog.Debugf("Received FundingLocked for ChannelID(%v) from "+
		"peer %x", fmsg.msg.ChanID,
		fmsg.peer.IdentityKey().SerializeCompressed())

	// If we are currently in the process of handling a funding locked
	// message for this channel, ignore.
	f.handleFundingLockedMtx.Lock()
	_, ok := f.handleFundingLockedBarriers[fmsg.msg.ChanID]
	if ok {
		fndgLog.Infof("Already handling fundingLocked for "+
			"ChannelID(%v), ignoring.", fmsg.msg.ChanID)
		f.handleFundingLockedMtx.Unlock()
		return
	}

	// If not already handling fundingLocked for this channel, set up
	// barrier, and move on.
	f.handleFundingLockedBarriers[fmsg.msg.ChanID] = struct{}{}
	f.handleFundingLockedMtx.Unlock()

	defer func() {
		f.handleFundingLockedMtx.Lock()
		delete(f.handleFundingLockedBarriers, fmsg.msg.ChanID)
		f.handleFundingLockedMtx.Unlock()
	}()

	f.localDiscoveryMtx.Lock()
	localDiscoverySignal, ok := f.localDiscoverySignals[fmsg.msg.ChanID]
	f.localDiscoveryMtx.Unlock()

	if ok {
		// Before we proceed with processing the funding locked
		// message, we'll wait for the local waitForFundingConfirmation
		// goroutine to signal that it has the necessary state in
		// place. Otherwise, we may be missing critical information
		// required to handle forwarded HTLC's.
		select {
		case <-localDiscoverySignal:
			// Fallthrough
		case <-f.quit:
			return
		}

		// With the signal received, we can now safely delete the entry
		// from the map.
		f.localDiscoveryMtx.Lock()
		delete(f.localDiscoverySignals, fmsg.msg.ChanID)
		f.localDiscoveryMtx.Unlock()
	}

	// First, we'll attempt to locate the channel whose funding workflow is
	// being finalized by this message. We go to the database rather than
	// our reservation map as we may have restarted, mid funding flow.
	chanID := fmsg.msg.ChanID
	channel, err := f.cfg.FindChannel(chanID)
	if err != nil {
		fndgLog.Errorf("Unable to locate ChannelID(%v), cannot complete "+
			"funding", chanID)
		return
	}

	// If the RemoteNextRevocation is non-nil, it means that we have
	// already processed fundingLocked for this channel, so ignore.
	if channel.RemoteNextRevocation != nil {
		fndgLog.Infof("Received duplicate fundingLocked for "+
			"ChannelID(%v), ignoring.", chanID)
		return
	}

	// The funding locked message contains the next commitment point we'll
	// need to create the next commitment state for the remote party. So
	// we'll insert that into the channel now before passing it along to
	// other sub-systems.
	err = channel.InsertNextRevocation(fmsg.msg.NextPerCommitmentPoint)
	if err != nil {
		fndgLog.Errorf("unable to insert next commitment point: %v", err)
		return
	}

	// As this is the earliest possible time that the channel can be used
	// to create/receive commitment updates, we'll mark the channel has
	// active now.
	f.cfg.NotifyReadyChannelEvent(channel.FundingOutpoint)

	// Launch a defer so we _ensure_ that the channel barrier is properly
	// closed even if the target peer is no longer online at this point.
	defer func() {
		// Close the active channel barrier signalling the readHandler
		// that commitment related modifications to this channel can
		// now proceed.
		f.barrierMtx.Lock()
		chanBarrier, ok := f.newChanBarriers[chanID]
		if ok {
			fndgLog.Tracef("Closing chan barrier for ChanID(%v)",
				chanID)
			close(chanBarrier)
			delete(f.newChanBarriers, chanID)
		}
		f.barrierMtx.Unlock()
	}()

	if err := fmsg.peer.AddNewChannel(channel, f.quit); err != nil {
		fndgLog.Errorf("Unable to add new channel %v with peer %x: %v",
			fmsg.peer.IdentityKey().SerializeCompressed(),
			channel.FundingOutpoint, err)
	}
}

// channelProof is one half of the proof necessary to create an authenticated
// announcement on the network. The two signatures individually sign a
// statement of the existence of a channel.
type channelProof struct {
	nodeSig    *btcec.Signature
	bitcoinSig *btcec.Signature
}

// chanAnnouncement encapsulates the two authenticated announcements that we
// send out to the network after a new channel has been created locally.
type chanAnnouncement struct {
	chanAnn       *lnwire.ChannelAnnouncement
	chanUpdateAnn *lnwire.ChannelUpdate
	chanProof     *lnwire.AnnounceSignatures
}

// newChanAnnouncement creates the authenticated channel announcement messages
// required to broadcast a newly created channel to the network. The
// announcement is two part: the first part authenticates the existence of the
// channel and contains four signatures binding the funding pub keys and
// identity pub keys of both parties to the channel, and the second segment is
// authenticated only by us and contains our directional routing policy for the
// channel.
func (f *fundingManager) newChanAnnouncement(localPubKey, remotePubKey,
	localFundingKey, remoteFundingKey *btcec.PublicKey,
	shortChanID lnwire.ShortChannelID, chanID lnwire.ChannelID,
	fwdMinHTLC, fwdMaxHTLC lnwire.MilliSatoshi) (*chanAnnouncement, error) {

	chainHash := *f.cfg.Wallet.Cfg.NetParams.GenesisHash

	// The unconditional section of the announcement is the ShortChannelID
	// itself which compactly encodes the location of the funding output
	// within the blockchain.
	chanAnn := &lnwire.ChannelAnnouncement{
		ShortChannelID: shortChanID,
		Features:       lnwire.NewRawFeatureVector(),
		ChainHash:      chainHash,
	}

	// The chanFlags field indicates which directed edge of the channel is
	// being updated within the ChannelUpdateAnnouncement announcement
	// below. A value of zero means it's the edge of the "first" node and 1
	// being the other node.
	var chanFlags lnwire.ChanUpdateChanFlags

	// The lexicographical ordering of the two identity public keys of the
	// nodes indicates which of the nodes is "first". If our serialized
	// identity key is lower than theirs then we're the "first" node and
	// second otherwise.
	selfBytes := localPubKey.SerializeCompressed()
	remoteBytes := remotePubKey.SerializeCompressed()
	if bytes.Compare(selfBytes, remoteBytes) == -1 {
		copy(chanAnn.NodeID1[:], localPubKey.SerializeCompressed())
		copy(chanAnn.NodeID2[:], remotePubKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey1[:], localFundingKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey2[:], remoteFundingKey.SerializeCompressed())

		// If we're the first node then update the chanFlags to
		// indicate the "direction" of the update.
		chanFlags = 0
	} else {
		copy(chanAnn.NodeID1[:], remotePubKey.SerializeCompressed())
		copy(chanAnn.NodeID2[:], localPubKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey1[:], remoteFundingKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey2[:], localFundingKey.SerializeCompressed())

		// If we're the second node then update the chanFlags to
		// indicate the "direction" of the update.
		chanFlags = 1
	}

	// Our channel update message flags will signal that we support the
	// max_htlc field.
	msgFlags := lnwire.ChanUpdateOptionMaxHtlc

	// We announce the channel with the default values. Some of
	// these values can later be changed by crafting a new ChannelUpdate.
	chanUpdateAnn := &lnwire.ChannelUpdate{
		ShortChannelID: shortChanID,
		ChainHash:      chainHash,
		Timestamp:      uint32(time.Now().Unix()),
		MessageFlags:   msgFlags,
		ChannelFlags:   chanFlags,
		TimeLockDelta:  uint16(f.cfg.DefaultRoutingPolicy.TimeLockDelta),

		// We use the HtlcMinimumMsat that the remote party required us
		// to use, as our ChannelUpdate will be used to carry HTLCs
		// towards them.
		HtlcMinimumMsat: fwdMinHTLC,
		HtlcMaximumMsat: fwdMaxHTLC,

		BaseFee: uint32(f.cfg.DefaultRoutingPolicy.BaseFee),
		FeeRate: uint32(f.cfg.DefaultRoutingPolicy.FeeRate),
	}

	// With the channel update announcement constructed, we'll generate a
	// signature that signs a double-sha digest of the announcement.
	// This'll serve to authenticate this announcement and any other future
	// updates we may send.
	chanUpdateMsg, err := chanUpdateAnn.DataToSign()
	if err != nil {
		return nil, err
	}
	sig, err := f.cfg.SignMessage(f.cfg.IDKey, chanUpdateMsg)
	if err != nil {
		return nil, errors.Errorf("unable to generate channel "+
			"update announcement signature: %v", err)
	}
	chanUpdateAnn.Signature, err = lnwire.NewSigFromSignature(sig)
	if err != nil {
		return nil, errors.Errorf("unable to generate channel "+
			"update announcement signature: %v", err)
	}

	// The channel existence proofs itself is currently announced in
	// distinct message. In order to properly authenticate this message, we
	// need two signatures: one under the identity public key used which
	// signs the message itself and another signature of the identity
	// public key under the funding key itself.
	//
	// TODO(roasbeef): use SignAnnouncement here instead?
	chanAnnMsg, err := chanAnn.DataToSign()
	if err != nil {
		return nil, err
	}
	nodeSig, err := f.cfg.SignMessage(f.cfg.IDKey, chanAnnMsg)
	if err != nil {
		return nil, errors.Errorf("unable to generate node "+
			"signature for channel announcement: %v", err)
	}
	bitcoinSig, err := f.cfg.SignMessage(localFundingKey, chanAnnMsg)
	if err != nil {
		return nil, errors.Errorf("unable to generate bitcoin "+
			"signature for node public key: %v", err)
	}

	// Finally, we'll generate the announcement proof which we'll use to
	// provide the other side with the necessary signatures required to
	// allow them to reconstruct the full channel announcement.
	proof := &lnwire.AnnounceSignatures{
		ChannelID:      chanID,
		ShortChannelID: shortChanID,
	}
	proof.NodeSignature, err = lnwire.NewSigFromSignature(nodeSig)
	if err != nil {
		return nil, err
	}
	proof.BitcoinSignature, err = lnwire.NewSigFromSignature(bitcoinSig)
	if err != nil {
		return nil, err
	}

	return &chanAnnouncement{
		chanAnn:       chanAnn,
		chanUpdateAnn: chanUpdateAnn,
		chanProof:     proof,
	}, nil
}

// announceChannel announces a newly created channel to the rest of the network
// by crafting the two authenticated announcements required for the peers on
// the network to recognize the legitimacy of the channel. The crafted
// announcements are then sent to the channel router to handle broadcasting to
// the network during its next trickle.
// This method is synchronous and will return when all the network requests
// finish, either successfully or with an error.
func (f *fundingManager) announceChannel(localIDKey, remoteIDKey, localFundingKey,
	remoteFundingKey *btcec.PublicKey, shortChanID lnwire.ShortChannelID,
	chanID lnwire.ChannelID, fwdMinHTLC, fwdMaxHTLC lnwire.MilliSatoshi) error {

	// First, we'll create the batch of announcements to be sent upon
	// initial channel creation. This includes the channel announcement
	// itself, the channel update announcement, and our half of the channel
	// proof needed to fully authenticate the channel.
	ann, err := f.newChanAnnouncement(localIDKey, remoteIDKey,
		localFundingKey, remoteFundingKey, shortChanID, chanID,
		fwdMinHTLC, fwdMaxHTLC,
	)
	if err != nil {
		fndgLog.Errorf("can't generate channel announcement: %v", err)
		return err
	}

	// We only send the channel proof announcement and the node announcement
	// because addToRouterGraph previously sent the ChannelAnnouncement and
	// the ChannelUpdate announcement messages. The channel proof and node
	// announcements are broadcast to the greater network.
	errChan := f.cfg.SendAnnouncement(ann.chanProof)
	select {
	case err := <-errChan:
		if err != nil {
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {
				fndgLog.Debugf("Router rejected "+
					"AnnounceSignatures: %v", err)
			} else {
				fndgLog.Errorf("Unable to send channel "+
					"proof: %v", err)
				return err
			}
		}

	case <-f.quit:
		return ErrFundingManagerShuttingDown
	}

	// Now that the channel is announced to the network, we will also
	// obtain and send a node announcement. This is done since a node
	// announcement is only accepted after a channel is known for that
	// particular node, and this might be our first channel.
	nodeAnn, err := f.cfg.CurrentNodeAnnouncement()
	if err != nil {
		fndgLog.Errorf("can't generate node announcement: %v", err)
		return err
	}

	errChan = f.cfg.SendAnnouncement(&nodeAnn)
	select {
	case err := <-errChan:
		if err != nil {
			if routing.IsError(err, routing.ErrOutdated,
				routing.ErrIgnored) {
				fndgLog.Debugf("Router rejected "+
					"NodeAnnouncement: %v", err)
			} else {
				fndgLog.Errorf("Unable to send node "+
					"announcement: %v", err)
				return err
			}
		}

	case <-f.quit:
		return ErrFundingManagerShuttingDown
	}

	return nil
}

// initFundingWorkflow sends a message to the funding manager instructing it
// to initiate a single funder workflow with the source peer.
// TODO(roasbeef): re-visit blocking nature..
func (f *fundingManager) initFundingWorkflow(peer lnpeer.Peer, req *openChanReq) {
	f.fundingRequests <- &initFundingMsg{
		peer:        peer,
		openChanReq: req,
	}
}

// handleInitFundingMsg creates a channel reservation within the daemon's
// wallet, then sends a funding request to the remote peer kicking off the
// funding workflow.
func (f *fundingManager) handleInitFundingMsg(msg *initFundingMsg) {
	var (
		peerKey        = msg.peer.IdentityKey()
		localAmt       = msg.localFundingAmt
		remoteAmt      = msg.remoteFundingAmt
		capacity       = localAmt + remoteAmt
		minHtlc        = msg.minHtlc
		remoteCsvDelay = msg.remoteCsvDelay
	)

	// We'll determine our dust limit depending on which chain is active.
	var ourDustLimit btcutil.Amount
	switch registeredChains.PrimaryChain() {
	case bitcoinChain:
		ourDustLimit = lnwallet.DefaultDustLimit()
	case litecoinChain:
		ourDustLimit = defaultLitecoinDustLimit
	}

	fndgLog.Infof("Initiating fundingRequest(localAmt=%v, remoteAmt=%v, "+
		"capacity=%v, chainhash=%v, peer=%x, dustLimit=%v, min_confs=%v)",
		localAmt, msg.pushAmt, capacity, msg.chainHash,
		peerKey.SerializeCompressed(), ourDustLimit, msg.minConfs)

	// First, we'll query the fee estimator for a fee that should get the
	// commitment transaction confirmed by the next few blocks (conf target
	// of 3). We target the near blocks here to ensure that we'll be able
	// to execute a timely unilateral channel closure if needed.
	commitFeePerKw, err := f.cfg.FeeEstimator.EstimateFeePerKW(3)
	if err != nil {
		msg.err <- err
		return
	}

	// We set the channel flags to indicate whether we want this channel to
	// be announced to the network.
	var channelFlags lnwire.FundingFlag
	if !msg.openChanReq.private {
		// This channel will be announced.
		channelFlags = lnwire.FFAnnounceChannel
	}

	// Initialize a funding reservation with the local wallet. If the
	// wallet doesn't have enough funds to commit to this channel, then the
	// request will fail, and be aborted.
	req := &lnwallet.InitFundingReserveMsg{
		ChainHash:       &msg.chainHash,
		NodeID:          peerKey,
		NodeAddr:        msg.peer.Address(),
		FundingAmount:   localAmt,
		Capacity:        capacity,
		CommitFeePerKw:  commitFeePerKw,
		FundingFeePerKw: msg.fundingFeePerKw,
		PushMSat:        msg.pushAmt,
		Flags:           channelFlags,
		MinConfs:        msg.minConfs,
	}

	reservation, err := f.cfg.Wallet.InitChannelReservation(req)
	if err != nil {
		msg.err <- err
		return
	}

	// Obtain a new pending channel ID which is used to track this
	// reservation throughout its lifetime.
	chanID := f.nextPendingChanID()

	fndgLog.Infof("Target commit tx sat/kw for pendingID(%x): %v", chanID,
		int64(commitFeePerKw))

	// If the remote CSV delay was not set in the open channel request,
	// we'll use the RequiredRemoteDelay closure to compute the delay we
	// require given the total amount of funds within the channel.
	if remoteCsvDelay == 0 {
		remoteCsvDelay = f.cfg.RequiredRemoteDelay(capacity)
	}

	// If no minimum HTLC value was specified, use the default one.
	if minHtlc == 0 {
		minHtlc = f.cfg.DefaultRoutingPolicy.MinHTLC
	}

	// If a pending channel map for this peer isn't already created, then
	// we create one, ultimately allowing us to track this pending
	// reservation within the target peer.
	peerIDKey := newSerializedKey(peerKey)
	f.resMtx.Lock()
	if _, ok := f.activeReservations[peerIDKey]; !ok {
		f.activeReservations[peerIDKey] = make(pendingChannels)
	}

	resCtx := &reservationWithCtx{
		chanAmt:        capacity,
		remoteCsvDelay: remoteCsvDelay,
		remoteMinHtlc:  minHtlc,
		reservation:    reservation,
		peer:           msg.peer,
		updates:        msg.updates,
		err:            msg.err,
	}
	f.activeReservations[peerIDKey][chanID] = resCtx
	f.resMtx.Unlock()

	// Update the timestamp once the initFundingMsg has been handled.
	defer resCtx.updateTimestamp()

	// Once the reservation has been created, and indexed, queue a funding
	// request to the remote peer, kicking off the funding workflow.
	ourContribution := reservation.OurContribution()

	// Finally, we'll use the current value of the channels and our default
	// policy to determine of required commitment constraints for the
	// remote party.
	chanReserve := f.cfg.RequiredRemoteChanReserve(capacity, ourDustLimit)
	maxValue := f.cfg.RequiredRemoteMaxValue(capacity)
	maxHtlcs := f.cfg.RequiredRemoteMaxHTLCs(capacity)

	fndgLog.Infof("Starting funding workflow with %v for pendingID(%x)",
		msg.peer.Address(), chanID)

	fundingOpen := lnwire.OpenChannel{
		ChainHash:            *f.cfg.Wallet.Cfg.NetParams.GenesisHash,
		PendingChannelID:     chanID,
		FundingAmount:        capacity,
		PushAmount:           msg.pushAmt,
		DustLimit:            ourContribution.DustLimit,
		MaxValueInFlight:     maxValue,
		ChannelReserve:       chanReserve,
		HtlcMinimum:          minHtlc,
		FeePerKiloWeight:     uint32(commitFeePerKw),
		CsvDelay:             remoteCsvDelay,
		MaxAcceptedHTLCs:     maxHtlcs,
		FundingKey:           ourContribution.MultiSigKey.PubKey,
		RevocationPoint:      ourContribution.RevocationBasePoint.PubKey,
		PaymentPoint:         ourContribution.PaymentBasePoint.PubKey,
		HtlcPoint:            ourContribution.HtlcBasePoint.PubKey,
		DelayedPaymentPoint:  ourContribution.DelayBasePoint.PubKey,
		FirstCommitmentPoint: ourContribution.FirstCommitmentPoint,
		ChannelFlags:         channelFlags,
	}
	if err := msg.peer.SendMessage(false, &fundingOpen); err != nil {
		e := fmt.Errorf("Unable to send funding request message: %v",
			err)
		fndgLog.Errorf(e.Error())

		// Since we were unable to send the initial message to the peer
		// and start the funding flow, we'll cancel this reservation.
		if _, err := f.cancelReservationCtx(peerKey, chanID); err != nil {
			fndgLog.Errorf("unable to cancel reservation: %v", err)
		}

		msg.err <- e
		return
	}
}

// waitUntilChannelOpen is designed to prevent other lnd subsystems from
// sending new update messages to a channel before the channel is fully
// opened.
func (f *fundingManager) waitUntilChannelOpen(targetChan lnwire.ChannelID,
	quit <-chan struct{}) error {

	f.barrierMtx.RLock()
	barrier, ok := f.newChanBarriers[targetChan]
	f.barrierMtx.RUnlock()
	if ok {
		fndgLog.Tracef("waiting for chan barrier signal for ChanID(%v)",
			targetChan)

		select {
		case <-barrier:
		case <-quit:
			return ErrFundingManagerShuttingDown
		case <-f.quit:
			return ErrFundingManagerShuttingDown
		}

		fndgLog.Tracef("barrier for ChanID(%v) closed", targetChan)
		return nil
	}

	return nil
}

// processFundingError sends a message to the fundingManager allowing it to
// process the occurred generic error.
func (f *fundingManager) processFundingError(err *lnwire.Error,
	peerKey *btcec.PublicKey) {

	select {
	case f.fundingMsgs <- &fundingErrorMsg{err, peerKey}:
	case <-f.quit:
		return
	}
}

// handleErrorMsg processes the error which was received from remote peer,
// depending on the type of error we should do different clean up steps and
// inform the user about it.
func (f *fundingManager) handleErrorMsg(fmsg *fundingErrorMsg) {
	protocolErr := fmsg.err

	chanID := fmsg.err.ChanID

	// First, we'll attempt to retrieve and cancel the funding workflow
	// that this error was tied to. If we're unable to do so, then we'll
	// exit early as this was an unwarranted error.
	resCtx, err := f.cancelReservationCtx(fmsg.peerKey, chanID)
	if err != nil {
		fndgLog.Warnf("Received error for non-existent funding "+
			"flow: %v (%v)", err, spew.Sdump(protocolErr))
		return
	}

	// If we did indeed find the funding workflow, then we'll return the
	// error back to the caller (if any), and cancel the workflow itself.
	lnErr := lnwire.ErrorCode(protocolErr.Data[0])
	fndgLog.Errorf("Received funding error from %x: %v",
		fmsg.peerKey.SerializeCompressed(), string(protocolErr.Data),
	)

	// If this isn't a simple error code, then we'll display the entire
	// thing.
	if len(protocolErr.Data) > 1 {
		err = grpc.Errorf(
			lnErr.ToGrpcCode(), string(protocolErr.Data),
		)
	} else {
		// Otherwise, we'll attempt to display just the error code
		// itself.
		err = grpc.Errorf(
			lnErr.ToGrpcCode(), lnErr.String(),
		)
	}
	resCtx.err <- err
}

// pruneZombieReservations loops through all pending reservations and fails the
// funding flow for any reservations that have not been updated since the
// ReservationTimeout and are not locked waiting for the funding transaction.
func (f *fundingManager) pruneZombieReservations() {
	zombieReservations := make(pendingChannels)

	f.resMtx.RLock()
	for _, pendingReservations := range f.activeReservations {
		for pendingChanID, resCtx := range pendingReservations {
			if resCtx.isLocked() {
				continue
			}

			if time.Since(resCtx.lastUpdated) > f.cfg.ReservationTimeout {
				zombieReservations[pendingChanID] = resCtx
			}
		}
	}
	f.resMtx.RUnlock()

	for pendingChanID, resCtx := range zombieReservations {
		err := fmt.Errorf("reservation timed out waiting for peer "+
			"(peerID:%v, chanID:%x)", resCtx.peer.IdentityKey(),
			pendingChanID[:])
		fndgLog.Warnf(err.Error())
		f.failFundingFlow(resCtx.peer, pendingChanID, err)
	}
}

// cancelReservationCtx does all needed work in order to securely cancel the
// reservation.
func (f *fundingManager) cancelReservationCtx(peerKey *btcec.PublicKey,
	pendingChanID [32]byte) (*reservationWithCtx, error) {

	fndgLog.Infof("Cancelling funding reservation for node_key=%x, "+
		"chan_id=%x", peerKey.SerializeCompressed(), pendingChanID[:])

	peerIDKey := newSerializedKey(peerKey)
	f.resMtx.Lock()
	defer f.resMtx.Unlock()

	nodeReservations, ok := f.activeReservations[peerIDKey]
	if !ok {
		// No reservations for this node.
		return nil, errors.Errorf("no active reservations for peer(%x)",
			peerIDKey[:])
	}

	ctx, ok := nodeReservations[pendingChanID]
	if !ok {
		return nil, errors.Errorf("unknown channel (id: %x) for "+
			"peer(%x)", pendingChanID[:], peerIDKey[:])
	}

	if err := ctx.reservation.Cancel(); err != nil {
		return nil, errors.Errorf("unable to cancel reservation: %v",
			err)
	}

	delete(nodeReservations, pendingChanID)

	// If this was the last active reservation for this peer, delete the
	// peer's entry altogether.
	if len(nodeReservations) == 0 {
		delete(f.activeReservations, peerIDKey)
	}
	return ctx, nil
}

// deleteReservationCtx deletes the reservation uniquely identified by the
// target public key of the peer, and the specified pending channel ID.
func (f *fundingManager) deleteReservationCtx(peerKey *btcec.PublicKey,
	pendingChanID [32]byte) {

	// TODO(roasbeef): possibly cancel funding barrier in peer's
	// channelManager?
	peerIDKey := newSerializedKey(peerKey)
	f.resMtx.Lock()
	defer f.resMtx.Unlock()

	nodeReservations, ok := f.activeReservations[peerIDKey]
	if !ok {
		// No reservations for this node.
		return
	}
	delete(nodeReservations, pendingChanID)

	// If this was the last active reservation for this peer, delete the
	// peer's entry altogether.
	if len(nodeReservations) == 0 {
		delete(f.activeReservations, peerIDKey)
	}
}

// getReservationCtx returns the reservation context for a particular pending
// channel ID for a target peer.
func (f *fundingManager) getReservationCtx(peerKey *btcec.PublicKey,
	pendingChanID [32]byte) (*reservationWithCtx, error) {

	peerIDKey := newSerializedKey(peerKey)
	f.resMtx.RLock()
	resCtx, ok := f.activeReservations[peerIDKey][pendingChanID]
	f.resMtx.RUnlock()

	if !ok {
		return nil, errors.Errorf("unknown channel (id: %x) for "+
			"peer(%x)", pendingChanID[:], peerIDKey[:])
	}

	return resCtx, nil
}

// IsPendingChannel returns a boolean indicating whether the channel identified
// by the pendingChanID and given peer is pending, meaning it is in the process
// of being funded. After the funding transaction has been confirmed, the
// channel will receive a new, permanent channel ID, and will no longer be
// considered pending.
func (f *fundingManager) IsPendingChannel(pendingChanID [32]byte,
	peerKey *btcec.PublicKey) bool {

	peerIDKey := newSerializedKey(peerKey)
	f.resMtx.RLock()
	_, ok := f.activeReservations[peerIDKey][pendingChanID]
	f.resMtx.RUnlock()

	return ok
}

func copyPubKey(pub *btcec.PublicKey) *btcec.PublicKey {
	return &btcec.PublicKey{
		Curve: btcec.S256(),
		X:     pub.X,
		Y:     pub.Y,
	}
}

// saveChannelOpeningState saves the channelOpeningState for the provided
// chanPoint to the channelOpeningStateBucket.
func (f *fundingManager) saveChannelOpeningState(chanPoint *wire.OutPoint,
	state channelOpeningState, shortChanID *lnwire.ShortChannelID) error {
	return f.cfg.Wallet.Cfg.Database.Update(func(tx *bbolt.Tx) error {

		bucket, err := tx.CreateBucketIfNotExists(channelOpeningStateBucket)
		if err != nil {
			return err
		}

		var outpointBytes bytes.Buffer
		if err = writeOutpoint(&outpointBytes, chanPoint); err != nil {
			return err
		}

		// Save state and the uint64 representation of the shortChanID
		// for later use.
		scratch := make([]byte, 10)
		byteOrder.PutUint16(scratch[:2], uint16(state))
		byteOrder.PutUint64(scratch[2:], shortChanID.ToUint64())

		return bucket.Put(outpointBytes.Bytes(), scratch)
	})
}

// getChannelOpeningState fetches the channelOpeningState for the provided
// chanPoint from the database, or returns ErrChannelNotFound if the channel
// is not found.
func (f *fundingManager) getChannelOpeningState(chanPoint *wire.OutPoint) (
	channelOpeningState, *lnwire.ShortChannelID, error) {

	var state channelOpeningState
	var shortChanID lnwire.ShortChannelID
	err := f.cfg.Wallet.Cfg.Database.View(func(tx *bbolt.Tx) error {

		bucket := tx.Bucket(channelOpeningStateBucket)
		if bucket == nil {
			// If the bucket does not exist, it means we never added
			//  a channel to the db, so return ErrChannelNotFound.
			return ErrChannelNotFound
		}

		var outpointBytes bytes.Buffer
		if err := writeOutpoint(&outpointBytes, chanPoint); err != nil {
			return err
		}

		value := bucket.Get(outpointBytes.Bytes())
		if value == nil {
			return ErrChannelNotFound
		}

		state = channelOpeningState(byteOrder.Uint16(value[:2]))
		shortChanID = lnwire.NewShortChanIDFromInt(byteOrder.Uint64(value[2:]))
		return nil
	})
	if err != nil {
		return 0, nil, err
	}

	return state, &shortChanID, nil
}

// deleteChannelOpeningState removes any state for chanPoint from the database.
func (f *fundingManager) deleteChannelOpeningState(chanPoint *wire.OutPoint) error {
	return f.cfg.Wallet.Cfg.Database.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(channelOpeningStateBucket)
		if bucket == nil {
			return fmt.Errorf("Bucket not found")
		}

		var outpointBytes bytes.Buffer
		if err := writeOutpoint(&outpointBytes, chanPoint); err != nil {
			return err
		}

		return bucket.Delete(outpointBytes.Bytes())
	})
}
