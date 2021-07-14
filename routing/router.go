package routing

import (
	"bytes"
	goErrors "errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"

	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/amp"
	"github.com/lightningnetwork/lnd/batch"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chanvalidate"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/multimutex"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/routing/chainview"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/routing/shards"
	"github.com/lightningnetwork/lnd/ticker"
	"github.com/lightningnetwork/lnd/zpay32"
)

const (
	// DefaultPayAttemptTimeout is the default payment attempt timeout. The
	// payment attempt timeout defines the duration after which we stop
	// trying more routes for a payment.
	DefaultPayAttemptTimeout = time.Duration(time.Second * 60)

	// DefaultChannelPruneExpiry is the default duration used to determine
	// if a channel should be pruned or not.
	DefaultChannelPruneExpiry = time.Duration(time.Hour * 24 * 14)

	// DefaultFirstTimePruneDelay is the time we'll wait after startup
	// before attempting to prune the graph for zombie channels. We don't
	// do it immediately after startup to allow lnd to start up without
	// getting blocked by this job.
	DefaultFirstTimePruneDelay = 30 * time.Second

	// defaultStatInterval governs how often the router will log non-empty
	// stats related to processing new channels, updates, or node
	// announcements.
	defaultStatInterval = time.Minute

	// MinCLTVDelta is the minimum CLTV value accepted by LND for all
	// timelock deltas. This includes both forwarding CLTV deltas set on
	// channel updates, as well as final CLTV deltas used to create BOLT 11
	// payment requests.
	//
	// NOTE: For payment requests, BOLT 11 stipulates that a final CLTV
	// delta of 9 should be used when no value is decoded. This however
	// leads to inflexiblity in upgrading this default parameter, since it
	// can create inconsistencies around the assumed value between sender
	// and receiver. Specifically, if the receiver assumes a higher value
	// than the sender, the receiver will always see the received HTLCs as
	// invalid due to their timelock not meeting the required delta.
	//
	// We skirt this by always setting an explicit CLTV delta when creating
	// invoices. This allows LND nodes to freely update the minimum without
	// creating incompatibilities during the upgrade process. For some time
	// LND has used an explicit default final CLTV delta of 40 blocks for
	// bitcoin (160 for litecoin), though we now clamp the lower end of this
	// range for user-chosen deltas to 18 blocks to be conservative.
	MinCLTVDelta = 18
)

var (
	// ErrRouterShuttingDown is returned if the router is in the process of
	// shutting down.
	ErrRouterShuttingDown = fmt.Errorf("router shutting down")
)

// ChannelGraphSource represents the source of information about the topology
// of the lightning network. It's responsible for the addition of nodes, edges,
// applying edge updates, and returning the current block height with which the
// topology is synchronized.
type ChannelGraphSource interface {
	// AddNode is used to add information about a node to the router
	// database. If the node with this pubkey is not present in an existing
	// channel, it will be ignored.
	AddNode(node *channeldb.LightningNode, op ...batch.SchedulerOption) error

	// AddEdge is used to add edge/channel to the topology of the router,
	// after all information about channel will be gathered this
	// edge/channel might be used in construction of payment path.
	AddEdge(edge *channeldb.ChannelEdgeInfo, op ...batch.SchedulerOption) error

	// AddProof updates the channel edge info with proof which is needed to
	// properly announce the edge to the rest of the network.
	AddProof(chanID lnwire.ShortChannelID, proof *channeldb.ChannelAuthProof) error

	// UpdateEdge is used to update edge information, without this message
	// edge considered as not fully constructed.
	UpdateEdge(policy *channeldb.ChannelEdgePolicy, op ...batch.SchedulerOption) error

	// IsStaleNode returns true if the graph source has a node announcement
	// for the target node with a more recent timestamp. This method will
	// also return true if we don't have an active channel announcement for
	// the target node.
	IsStaleNode(node route.Vertex, timestamp time.Time) bool

	// IsPublicNode determines whether the given vertex is seen as a public
	// node in the graph from the graph's source node's point of view.
	IsPublicNode(node route.Vertex) (bool, error)

	// IsKnownEdge returns true if the graph source already knows of the
	// passed channel ID either as a live or zombie edge.
	IsKnownEdge(chanID lnwire.ShortChannelID) bool

	// IsStaleEdgePolicy returns true if the graph source has a channel
	// edge for the passed channel ID (and flags) that have a more recent
	// timestamp.
	IsStaleEdgePolicy(chanID lnwire.ShortChannelID, timestamp time.Time,
		flags lnwire.ChanUpdateChanFlags) bool

	// MarkEdgeLive clears an edge from our zombie index, deeming it as
	// live.
	MarkEdgeLive(chanID lnwire.ShortChannelID) error

	// ForAllOutgoingChannels is used to iterate over all channels
	// emanating from the "source" node which is the center of the
	// star-graph.
	ForAllOutgoingChannels(cb func(c *channeldb.ChannelEdgeInfo,
		e *channeldb.ChannelEdgePolicy) error) error

	// CurrentBlockHeight returns the block height from POV of the router
	// subsystem.
	CurrentBlockHeight() (uint32, error)

	// GetChannelByID return the channel by the channel id.
	GetChannelByID(chanID lnwire.ShortChannelID) (*channeldb.ChannelEdgeInfo,
		*channeldb.ChannelEdgePolicy, *channeldb.ChannelEdgePolicy, error)

	// FetchLightningNode attempts to look up a target node by its identity
	// public key. channeldb.ErrGraphNodeNotFound is returned if the node
	// doesn't exist within the graph.
	FetchLightningNode(route.Vertex) (*channeldb.LightningNode, error)

	// ForEachNode is used to iterate over every node in the known graph.
	ForEachNode(func(node *channeldb.LightningNode) error) error

	// ForEachChannel is used to iterate over every channel in the known
	// graph.
	ForEachChannel(func(chanInfo *channeldb.ChannelEdgeInfo,
		e1, e2 *channeldb.ChannelEdgePolicy) error) error
}

// PaymentAttemptDispatcher is used by the router to send payment attempts onto
// the network, and receive their results.
type PaymentAttemptDispatcher interface {
	// SendHTLC is a function that directs a link-layer switch to
	// forward a fully encoded payment to the first hop in the route
	// denoted by its public key. A non-nil error is to be returned if the
	// payment was unsuccessful.
	SendHTLC(firstHop lnwire.ShortChannelID,
		attemptID uint64,
		htlcAdd *lnwire.UpdateAddHTLC) error

	// GetPaymentResult returns the the result of the payment attempt with
	// the given attemptID. The paymentHash should be set to the payment's
	// overall hash, or in case of AMP payments the payment's unique
	// identifier.
	//
	// The method returns a channel where the payment result will be sent
	// when available, or an error is encountered during forwarding. When a
	// result is received on the channel, the HTLC is guaranteed to no
	// longer be in flight.  The switch shutting down is signaled by
	// closing the channel. If the attemptID is unknown,
	// ErrPaymentIDNotFound will be returned.
	GetPaymentResult(attemptID uint64, paymentHash lntypes.Hash,
		deobfuscator htlcswitch.ErrorDecrypter) (
		<-chan *htlcswitch.PaymentResult, error)

	// CleanStore calls the underlying result store, telling it is safe to
	// delete all entries except the ones in the keepPids map. This should
	// be called preiodically to let the switch clean up payment results
	// that we have handled.
	// NOTE: New payment attempts MUST NOT be made after the keepPids map
	// has been created and this method has returned.
	CleanStore(keepPids map[uint64]struct{}) error
}

// PaymentSessionSource is an interface that defines a source for the router to
// retrive new payment sessions.
type PaymentSessionSource interface {
	// NewPaymentSession creates a new payment session that will produce
	// routes to the given target. An optional set of routing hints can be
	// provided in order to populate additional edges to explore when
	// finding a path to the payment's destination.
	NewPaymentSession(p *LightningPayment) (PaymentSession, error)

	// NewPaymentSessionEmpty creates a new paymentSession instance that is
	// empty, and will be exhausted immediately. Used for failure reporting
	// to missioncontrol for resumed payment we don't want to make more
	// attempts for.
	NewPaymentSessionEmpty() PaymentSession
}

// MissionController is an interface that exposes failure reporting and
// probability estimation.
type MissionController interface {
	// ReportPaymentFail reports a failed payment to mission control as
	// input for future probability estimates. It returns a bool indicating
	// whether this error is a final error and no further payment attempts
	// need to be made.
	ReportPaymentFail(attemptID uint64, rt *route.Route,
		failureSourceIdx *int, failure lnwire.FailureMessage) (
		*channeldb.FailureReason, error)

	// ReportPaymentSuccess reports a successful payment to mission control as input
	// for future probability estimates.
	ReportPaymentSuccess(attemptID uint64, rt *route.Route) error

	// GetProbability is expected to return the success probability of a
	// payment from fromNode along edge.
	GetProbability(fromNode, toNode route.Vertex,
		amt lnwire.MilliSatoshi) float64
}

// FeeSchema is the set fee configuration for a Lightning Node on the network.
// Using the coefficients described within the schema, the required fee to
// forward outgoing payments can be derived.
type FeeSchema struct {
	// BaseFee is the base amount of milli-satoshis that will be chained
	// for ANY payment forwarded.
	BaseFee lnwire.MilliSatoshi

	// FeeRate is the rate that will be charged for forwarding payments.
	// This value should be interpreted as the numerator for a fraction
	// (fixed point arithmetic) whose denominator is 1 million. As a result
	// the effective fee rate charged per mSAT will be: (amount *
	// FeeRate/1,000,000).
	FeeRate uint32
}

// ChannelPolicy holds the parameters that determine the policy we enforce
// when forwarding payments on a channel. These parameters are communicated
// to the rest of the network in ChannelUpdate messages.
type ChannelPolicy struct {
	// FeeSchema holds the fee configuration for a channel.
	FeeSchema

	// TimeLockDelta is the required HTLC timelock delta to be used
	// when forwarding payments.
	TimeLockDelta uint32

	// MaxHTLC is the maximum HTLC size including fees we are allowed to
	// forward over this channel.
	MaxHTLC lnwire.MilliSatoshi

	// MinHTLC is the minimum HTLC size including fees we are allowed to
	// forward over this channel.
	MinHTLC *lnwire.MilliSatoshi
}

// Config defines the configuration for the ChannelRouter. ALL elements within
// the configuration MUST be non-nil for the ChannelRouter to carry out its
// duties.
type Config struct {
	// Graph is the channel graph that the ChannelRouter will use to gather
	// metrics from and also to carry out path finding queries.
	// TODO(roasbeef): make into an interface
	Graph *channeldb.ChannelGraph

	// Chain is the router's source to the most up-to-date blockchain data.
	// All incoming advertised channels will be checked against the chain
	// to ensure that the channels advertised are still open.
	Chain lnwallet.BlockChainIO

	// ChainView is an instance of a FilteredChainView which is used to
	// watch the sub-set of the UTXO set (the set of active channels) that
	// we need in order to properly maintain the channel graph.
	ChainView chainview.FilteredChainView

	// Payer is an instance of a PaymentAttemptDispatcher and is used by
	// the router to send payment attempts onto the network, and receive
	// their results.
	Payer PaymentAttemptDispatcher

	// Control keeps track of the status of ongoing payments, ensuring we
	// can properly resume them across restarts.
	Control ControlTower

	// MissionControl is a shared memory of sorts that executions of
	// payment path finding use in order to remember which vertexes/edges
	// were pruned from prior attempts. During SendPayment execution,
	// errors sent by nodes are mapped into a vertex or edge to be pruned.
	// Each run will then take into account this set of pruned
	// vertexes/edges to reduce route failure and pass on graph information
	// gained to the next execution.
	MissionControl MissionController

	// SessionSource defines a source for the router to retrieve new payment
	// sessions.
	SessionSource PaymentSessionSource

	// ChannelPruneExpiry is the duration used to determine if a channel
	// should be pruned or not. If the delta between now and when the
	// channel was last updated is greater than ChannelPruneExpiry, then
	// the channel is marked as a zombie channel eligible for pruning.
	ChannelPruneExpiry time.Duration

	// GraphPruneInterval is used as an interval to determine how often we
	// should examine the channel graph to garbage collect zombie channels.
	GraphPruneInterval time.Duration

	// FirstTimePruneDelay is the time we'll wait after startup before
	// attempting to prune the graph for zombie channels. We don't do it
	// immediately after startup to allow lnd to start up without getting
	// blocked by this job.
	FirstTimePruneDelay time.Duration

	// QueryBandwidth is a method that allows the router to query the lower
	// link layer to determine the up to date available bandwidth at a
	// prospective link to be traversed. If the  link isn't available, then
	// a value of zero should be returned. Otherwise, the current up to
	// date knowledge of the available bandwidth of the link should be
	// returned.
	QueryBandwidth linkBandwidthQuery

	// NextPaymentID is a method that guarantees to return a new, unique ID
	// each time it is called. This is used by the router to generate a
	// unique payment ID for each payment it attempts to send, such that
	// the switch can properly handle the HTLC.
	NextPaymentID func() (uint64, error)

	// AssumeChannelValid toggles whether or not the router will check for
	// spentness of channel outpoints. For neutrino, this saves long rescans
	// from blocking initial usage of the daemon.
	AssumeChannelValid bool

	// PathFindingConfig defines global path finding parameters.
	PathFindingConfig PathFindingConfig

	// Clock is mockable time provider.
	Clock clock.Clock

	// StrictZombiePruning determines if we attempt to prune zombie
	// channels according to a stricter criteria. If true, then we'll prune
	// a channel if only *one* of the edges is considered a zombie.
	// Otherwise, we'll only prune the channel when both edges have a very
	// dated last update.
	StrictZombiePruning bool
}

// EdgeLocator is a struct used to identify a specific edge.
type EdgeLocator struct {
	// ChannelID is the channel of this edge.
	ChannelID uint64

	// Direction takes the value of 0 or 1 and is identical in definition to
	// the channel direction flag. A value of 0 means the direction from the
	// lower node pubkey to the higher.
	Direction uint8
}

// String returns a human readable version of the edgeLocator values.
func (e *EdgeLocator) String() string {
	return fmt.Sprintf("%v:%v", e.ChannelID, e.Direction)
}

// ChannelRouter is the layer 3 router within the Lightning stack. Below the
// ChannelRouter is the HtlcSwitch, and below that is the Bitcoin blockchain
// itself. The primary role of the ChannelRouter is to respond to queries for
// potential routes that can support a payment amount, and also general graph
// reachability questions. The router will prune the channel graph
// automatically as new blocks are discovered which spend certain known funding
// outpoints, thereby closing their respective channels.
type ChannelRouter struct {
	ntfnClientCounter uint64 // To be used atomically.

	started uint32 // To be used atomically.
	stopped uint32 // To be used atomically.

	bestHeight uint32 // To be used atomically.

	// cfg is a copy of the configuration struct that the ChannelRouter was
	// initialized with.
	cfg *Config

	// selfNode is the center of the star-graph centered around the
	// ChannelRouter. The ChannelRouter uses this node as a starting point
	// when doing any path finding.
	selfNode *channeldb.LightningNode

	// newBlocks is a channel in which new blocks connected to the end of
	// the main chain are sent over, and blocks updated after a call to
	// UpdateFilter.
	newBlocks <-chan *chainview.FilteredBlock

	// staleBlocks is a channel in which blocks disconnected fromt the end
	// of our currently known best chain are sent over.
	staleBlocks <-chan *chainview.FilteredBlock

	// networkUpdates is a channel that carries new topology updates
	// messages from outside the ChannelRouter to be processed by the
	// networkHandler.
	networkUpdates chan *routingMsg

	// topologyClients maps a client's unique notification ID to a
	// topologyClient client that contains its notification dispatch
	// channel.
	topologyClients map[uint64]*topologyClient

	// ntfnClientUpdates is a channel that's used to send new updates to
	// topology notification clients to the ChannelRouter. Updates either
	// add a new notification client, or cancel notifications for an
	// existing client.
	ntfnClientUpdates chan *topologyClientUpdate

	// channelEdgeMtx is a mutex we use to make sure we process only one
	// ChannelEdgePolicy at a time for a given channelID, to ensure
	// consistency between the various database accesses.
	channelEdgeMtx *multimutex.Mutex

	// statTicker is a resumable ticker that logs the router's progress as
	// it discovers channels or receives updates.
	statTicker ticker.Ticker

	// stats tracks newly processed channels, updates, and node
	// announcements over a window of defaultStatInterval.
	stats *routerStats

	sync.RWMutex

	quit chan struct{}
	wg   sync.WaitGroup
}

// A compile time check to ensure ChannelRouter implements the
// ChannelGraphSource interface.
var _ ChannelGraphSource = (*ChannelRouter)(nil)

// New creates a new instance of the ChannelRouter with the specified
// configuration parameters. As part of initialization, if the router detects
// that the channel graph isn't fully in sync with the latest UTXO (since the
// channel graph is a subset of the UTXO set) set, then the router will proceed
// to fully sync to the latest state of the UTXO set.
func New(cfg Config) (*ChannelRouter, error) {

	selfNode, err := cfg.Graph.SourceNode()
	if err != nil {
		return nil, err
	}

	r := &ChannelRouter{
		cfg:               &cfg,
		networkUpdates:    make(chan *routingMsg),
		topologyClients:   make(map[uint64]*topologyClient),
		ntfnClientUpdates: make(chan *topologyClientUpdate),
		channelEdgeMtx:    multimutex.NewMutex(),
		selfNode:          selfNode,
		statTicker:        ticker.New(defaultStatInterval),
		stats:             new(routerStats),
		quit:              make(chan struct{}),
	}

	return r, nil
}

// Start launches all the goroutines the ChannelRouter requires to carry out
// its duties. If the router has already been started, then this method is a
// noop.
func (r *ChannelRouter) Start() error {
	if !atomic.CompareAndSwapUint32(&r.started, 0, 1) {
		return nil
	}

	log.Tracef("Channel Router starting")

	bestHash, bestHeight, err := r.cfg.Chain.GetBestBlock()
	if err != nil {
		return err
	}

	// If the graph has never been pruned, or hasn't fully been created yet,
	// then we don't treat this as an explicit error.
	if _, _, err := r.cfg.Graph.PruneTip(); err != nil {
		switch {
		case err == channeldb.ErrGraphNeverPruned:
			fallthrough
		case err == channeldb.ErrGraphNotFound:
			// If the graph has never been pruned, then we'll set
			// the prune height to the current best height of the
			// chain backend.
			_, err = r.cfg.Graph.PruneGraph(
				nil, bestHash, uint32(bestHeight),
			)
			if err != nil {
				return err
			}
		default:
			return err
		}
	}

	// If AssumeChannelValid is present, then we won't rely on pruning
	// channels from the graph based on their spentness, but whether they
	// are considered zombies or not. We will start zombie pruning after a
	// small delay, to avoid slowing down startup of lnd.
	if r.cfg.AssumeChannelValid {
		time.AfterFunc(r.cfg.FirstTimePruneDelay, func() {
			select {
			case <-r.quit:
				return
			default:
			}

			log.Info("Initial zombie prune starting")
			if err := r.pruneZombieChans(); err != nil {
				log.Errorf("Unable to prune zombies: %v", err)
			}
		})
	} else {
		// Otherwise, we'll use our filtered chain view to prune
		// channels as soon as they are detected as spent on-chain.
		if err := r.cfg.ChainView.Start(); err != nil {
			return err
		}

		// Once the instance is active, we'll fetch the channel we'll
		// receive notifications over.
		r.newBlocks = r.cfg.ChainView.FilteredBlocks()
		r.staleBlocks = r.cfg.ChainView.DisconnectedBlocks()

		// Before we perform our manual block pruning, we'll construct
		// and apply a fresh chain filter to the active
		// FilteredChainView instance.  We do this before, as otherwise
		// we may miss on-chain events as the filter hasn't properly
		// been applied.
		channelView, err := r.cfg.Graph.ChannelView()
		if err != nil && err != channeldb.ErrGraphNoEdgesFound {
			return err
		}

		log.Infof("Filtering chain using %v channels active",
			len(channelView))

		if len(channelView) != 0 {
			err = r.cfg.ChainView.UpdateFilter(
				channelView, uint32(bestHeight),
			)
			if err != nil {
				return err
			}
		}

		// The graph pruning might have taken a while and there could be
		// new blocks available.
		_, bestHeight, err = r.cfg.Chain.GetBestBlock()
		if err != nil {
			return err
		}
		r.bestHeight = uint32(bestHeight)

		// Before we begin normal operation of the router, we first need
		// to synchronize the channel graph to the latest state of the
		// UTXO set.
		if err := r.syncGraphWithChain(); err != nil {
			return err
		}

		// Finally, before we proceed, we'll prune any unconnected nodes
		// from the graph in order to ensure we maintain a tight graph
		// of "useful" nodes.
		err = r.cfg.Graph.PruneGraphNodes()
		if err != nil && err != channeldb.ErrGraphNodesNotFound {
			return err
		}
	}

	// If any payments are still in flight, we resume, to make sure their
	// results are properly handled.
	payments, err := r.cfg.Control.FetchInFlightPayments()
	if err != nil {
		return err
	}

	// Before we restart existing payments and start accepting more
	// payments to be made, we clean the network result store of the
	// Switch. We do this here at startup to ensure no more payments can be
	// made concurrently, so we know the toKeep map will be up-to-date
	// until the cleaning has finished.
	toKeep := make(map[uint64]struct{})
	for _, p := range payments {
		for _, a := range p.HTLCs {
			toKeep[a.AttemptID] = struct{}{}
		}
	}

	log.Debugf("Cleaning network result store.")
	if err := r.cfg.Payer.CleanStore(toKeep); err != nil {
		return err
	}

	for _, payment := range payments {
		log.Infof("Resuming payment %v", payment.Info.PaymentIdentifier)
		r.wg.Add(1)
		go func(payment *channeldb.MPPayment) {
			defer r.wg.Done()

			// Get the hashes used for the outstanding HTLCs.
			htlcs := make(map[uint64]lntypes.Hash)
			for _, a := range payment.HTLCs {
				a := a

				// We check whether the individual attempts
				// have their HTLC hash set, if not we'll fall
				// back to the overall payment hash.
				hash := payment.Info.PaymentIdentifier
				if a.Hash != nil {
					hash = *a.Hash
				}

				htlcs[a.AttemptID] = hash
			}

			// Since we are not supporting creating more shards
			// after a restart (only receiving the result of the
			// shards already outstanding), we create a simple
			// shard tracker that will map the attempt IDs to
			// hashes used for the HTLCs. This will be enough also
			// for AMP payments, since we only need the hashes for
			// the individual HTLCs to regenerate the circuits, and
			// we don't currently persist the root share necessary
			// to re-derive them.
			shardTracker := shards.NewSimpleShardTracker(
				payment.Info.PaymentIdentifier, htlcs,
			)

			// We create a dummy, empty payment session such that
			// we won't make another payment attempt when the
			// result for the in-flight attempt is received.
			paySession := r.cfg.SessionSource.NewPaymentSessionEmpty()

			// We pass in a zero timeout value, to indicate we
			// don't need it to timeout. It will stop immediately
			// after the existing attempt has finished anyway. We
			// also set a zero fee limit, as no more routes should
			// be tried.
			_, _, err := r.sendPayment(
				payment.Info.Value, 0,
				payment.Info.PaymentIdentifier, 0, paySession,
				shardTracker,
			)
			if err != nil {
				log.Errorf("Resuming payment %v failed: %v.",
					payment.Info.PaymentIdentifier, err)
				return
			}

			log.Infof("Resumed payment %v completed.",
				payment.Info.PaymentIdentifier)
		}(payment)
	}

	r.wg.Add(1)
	go r.networkHandler()

	return nil
}

// Stop signals the ChannelRouter to gracefully halt all routines. This method
// will *block* until all goroutines have excited. If the channel router has
// already stopped then this method will return immediately.
func (r *ChannelRouter) Stop() error {
	if !atomic.CompareAndSwapUint32(&r.stopped, 0, 1) {
		return nil
	}

	log.Tracef("Channel Router shutting down")

	// Our filtered chain view could've only been started if
	// AssumeChannelValid isn't present.
	if !r.cfg.AssumeChannelValid {
		if err := r.cfg.ChainView.Stop(); err != nil {
			return err
		}
	}

	close(r.quit)
	r.wg.Wait()

	return nil
}

// syncGraphWithChain attempts to synchronize the current channel graph with
// the latest UTXO set state. This process involves pruning from the channel
// graph any channels which have been closed by spending their funding output
// since we've been down.
func (r *ChannelRouter) syncGraphWithChain() error {
	// First, we'll need to check to see if we're already in sync with the
	// latest state of the UTXO set.
	bestHash, bestHeight, err := r.cfg.Chain.GetBestBlock()
	if err != nil {
		return err
	}
	r.bestHeight = uint32(bestHeight)

	pruneHash, pruneHeight, err := r.cfg.Graph.PruneTip()
	if err != nil {
		switch {
		// If the graph has never been pruned, or hasn't fully been
		// created yet, then we don't treat this as an explicit error.
		case err == channeldb.ErrGraphNeverPruned:
		case err == channeldb.ErrGraphNotFound:
		default:
			return err
		}
	}

	log.Infof("Prune tip for Channel Graph: height=%v, hash=%v", pruneHeight,
		pruneHash)

	switch {

	// If the graph has never been pruned, then we can exit early as this
	// entails it's being created for the first time and hasn't seen any
	// block or created channels.
	case pruneHeight == 0 || pruneHash == nil:
		return nil

	// If the block hashes and heights match exactly, then we don't need to
	// prune the channel graph as we're already fully in sync.
	case bestHash.IsEqual(pruneHash) && uint32(bestHeight) == pruneHeight:
		return nil
	}

	// If the main chain blockhash at prune height is different from the
	// prune hash, this might indicate the database is on a stale branch.
	mainBlockHash, err := r.cfg.Chain.GetBlockHash(int64(pruneHeight))
	if err != nil {
		return err
	}

	// While we are on a stale branch of the chain, walk backwards to find
	// first common block.
	for !pruneHash.IsEqual(mainBlockHash) {
		log.Infof("channel graph is stale. Disconnecting block %v "+
			"(hash=%v)", pruneHeight, pruneHash)
		// Prune the graph for every channel that was opened at height
		// >= pruneHeight.
		_, err := r.cfg.Graph.DisconnectBlockAtHeight(pruneHeight)
		if err != nil {
			return err
		}

		pruneHash, pruneHeight, err = r.cfg.Graph.PruneTip()
		if err != nil {
			switch {
			// If at this point the graph has never been pruned, we
			// can exit as this entails we are back to the point
			// where it hasn't seen any block or created channels,
			// alas there's nothing left to prune.
			case err == channeldb.ErrGraphNeverPruned:
				return nil
			case err == channeldb.ErrGraphNotFound:
				return nil
			default:
				return err
			}
		}
		mainBlockHash, err = r.cfg.Chain.GetBlockHash(int64(pruneHeight))
		if err != nil {
			return err
		}
	}

	log.Infof("Syncing channel graph from height=%v (hash=%v) to height=%v "+
		"(hash=%v)", pruneHeight, pruneHash, bestHeight, bestHash)

	// If we're not yet caught up, then we'll walk forward in the chain
	// pruning the channel graph with each new block that hasn't yet been
	// consumed by the channel graph.
	var spentOutputs []*wire.OutPoint
	for nextHeight := pruneHeight + 1; nextHeight <= uint32(bestHeight); nextHeight++ {
		// Break out of the rescan early if a shutdown has been
		// requested, otherwise long rescans will block the daemon from
		// shutting down promptly.
		select {
		case <-r.quit:
			return ErrRouterShuttingDown
		default:
		}

		// Using the next height, request a manual block pruning from
		// the chainview for the particular block hash.
		nextHash, err := r.cfg.Chain.GetBlockHash(int64(nextHeight))
		if err != nil {
			return err
		}
		filterBlock, err := r.cfg.ChainView.FilterBlock(nextHash)
		if err != nil {
			return err
		}

		// We're only interested in all prior outputs that have been
		// spent in the block, so collate all the referenced previous
		// outpoints within each tx and input.
		for _, tx := range filterBlock.Transactions {
			for _, txIn := range tx.TxIn {
				spentOutputs = append(spentOutputs,
					&txIn.PreviousOutPoint)
			}
		}
	}

	// With the spent outputs gathered, attempt to prune the channel graph,
	// also passing in the best hash+height so the prune tip can be updated.
	closedChans, err := r.cfg.Graph.PruneGraph(
		spentOutputs, bestHash, uint32(bestHeight),
	)
	if err != nil {
		return err
	}

	log.Infof("Graph pruning complete: %v channels were closed since "+
		"height %v", len(closedChans), pruneHeight)
	return nil
}

// pruneZombieChans is a method that will be called periodically to prune out
// any "zombie" channels. We consider channels zombies if *both* edges haven't
// been updated since our zombie horizon. If AssumeChannelValid is present,
// we'll also consider channels zombies if *both* edges are disabled. This
// usually signals that a channel has been closed on-chain. We do this
// periodically to keep a healthy, lively routing table.
func (r *ChannelRouter) pruneZombieChans() error {
	chansToPrune := make(map[uint64]struct{})
	chanExpiry := r.cfg.ChannelPruneExpiry

	log.Infof("Examining channel graph for zombie channels")

	// A helper method to detect if the channel belongs to this node
	isSelfChannelEdge := func(info *channeldb.ChannelEdgeInfo) bool {
		return info.NodeKey1Bytes == r.selfNode.PubKeyBytes ||
			info.NodeKey2Bytes == r.selfNode.PubKeyBytes
	}

	// First, we'll collect all the channels which are eligible for garbage
	// collection due to being zombies.
	filterPruneChans := func(info *channeldb.ChannelEdgeInfo,
		e1, e2 *channeldb.ChannelEdgePolicy) error {

		// Exit early in case this channel is already marked to be pruned
		if _, markedToPrune := chansToPrune[info.ChannelID]; markedToPrune {
			return nil
		}

		// We'll ensure that we don't attempt to prune our *own*
		// channels from the graph, as in any case this should be
		// re-advertised by the sub-system above us.
		if isSelfChannelEdge(info) {
			return nil
		}

		// If either edge hasn't been updated for a period of
		// chanExpiry, then we'll mark the channel itself as eligible
		// for graph pruning.
		e1Zombie := e1 == nil || time.Since(e1.LastUpdate) >= chanExpiry
		e2Zombie := e2 == nil || time.Since(e2.LastUpdate) >= chanExpiry

		if e1Zombie {
			log.Tracef("Node1 pubkey=%x of chan_id=%v is zombie",
				info.NodeKey1Bytes, info.ChannelID)
		}
		if e2Zombie {
			log.Tracef("Node2 pubkey=%x of chan_id=%v is zombie",
				info.NodeKey2Bytes, info.ChannelID)
		}

		// If we're using strict zombie pruning, then a channel is only
		// considered live if both edges have a recent update we know
		// of.
		var channelIsLive bool
		switch {
		case r.cfg.StrictZombiePruning:
			channelIsLive = !e1Zombie && !e2Zombie

		// Otherwise, if we're using the less strict variant, then a
		// channel is considered live if either of the edges have a
		// recent update.
		default:
			channelIsLive = !e1Zombie || !e2Zombie
		}

		// Return early if the channel is still considered to be live
		// with the current set of configuration parameters.
		if channelIsLive {
			return nil
		}

		log.Debugf("ChannelID(%v) is a zombie, collecting to prune",
			info.ChannelID)

		// TODO(roasbeef): add ability to delete single directional edge
		chansToPrune[info.ChannelID] = struct{}{}

		return nil
	}

	// If AssumeChannelValid is present we'll look at the disabled bit for both
	// edges. If they're both disabled, then we can interpret this as the
	// channel being closed and can prune it from our graph.
	if r.cfg.AssumeChannelValid {
		disabledChanIDs, err := r.cfg.Graph.DisabledChannelIDs()
		if err != nil {
			return fmt.Errorf("unable to get disabled channels ids "+
				"chans: %v", err)
		}

		disabledEdges, err := r.cfg.Graph.FetchChanInfos(disabledChanIDs)
		if err != nil {
			return fmt.Errorf("unable to fetch disabled channels edges "+
				"chans: %v", err)
		}

		// Ensuring we won't prune our own channel from the graph.
		for _, disabledEdge := range disabledEdges {
			if !isSelfChannelEdge(disabledEdge.Info) {
				chansToPrune[disabledEdge.Info.ChannelID] = struct{}{}
			}
		}
	}

	startTime := time.Unix(0, 0)
	endTime := time.Now().Add(-1 * chanExpiry)
	oldEdges, err := r.cfg.Graph.ChanUpdatesInHorizon(startTime, endTime)
	if err != nil {
		return fmt.Errorf("unable to fetch expired channel updates "+
			"chans: %v", err)
	}

	for _, u := range oldEdges {
		filterPruneChans(u.Info, u.Policy1, u.Policy2)
	}

	log.Infof("Pruning %v zombie channels", len(chansToPrune))
	if len(chansToPrune) == 0 {
		return nil
	}

	// With the set of zombie-like channels obtained, we'll do another pass
	// to delete them from the channel graph.
	toPrune := make([]uint64, 0, len(chansToPrune))
	for chanID := range chansToPrune {
		toPrune = append(toPrune, chanID)
		log.Tracef("Pruning zombie channel with ChannelID(%v)", chanID)
	}
	err = r.cfg.Graph.DeleteChannelEdges(r.cfg.StrictZombiePruning, toPrune...)
	if err != nil {
		return fmt.Errorf("unable to delete zombie channels: %v", err)
	}

	// With the channels pruned, we'll also attempt to prune any nodes that
	// were a part of them.
	err = r.cfg.Graph.PruneGraphNodes()
	if err != nil && err != channeldb.ErrGraphNodesNotFound {
		return fmt.Errorf("unable to prune graph nodes: %v", err)
	}

	return nil
}

// networkHandler is the primary goroutine for the ChannelRouter. The roles of
// this goroutine include answering queries related to the state of the
// network, pruning the graph on new block notification, applying network
// updates, and registering new topology clients.
//
// NOTE: This MUST be run as a goroutine.
func (r *ChannelRouter) networkHandler() {
	defer r.wg.Done()

	graphPruneTicker := time.NewTicker(r.cfg.GraphPruneInterval)
	defer graphPruneTicker.Stop()

	defer r.statTicker.Stop()

	r.stats.Reset()

	// We'll use this validation barrier to ensure that we process all jobs
	// in the proper order during parallel validation.
	//
	// NOTE: For AssumeChannelValid, we bump up the maximum number of
	// concurrent validation requests since there are no blocks being
	// fetched. This significantly increases the performance of IGD for
	// neutrino nodes.
	//
	// However, we dial back to use multiple of the number of cores when
	// fully validating, to avoid fetching up to 1000 blocks from the
	// backend. On bitcoind, this will empirically cause massive latency
	// spikes when executing this many concurrent RPC calls. Critical
	// subsystems or basic rpc calls that rely on calls such as GetBestBlock
	// will hang due to excessive load.
	//
	// See https://github.com/lightningnetwork/lnd/issues/4892.
	var validationBarrier *ValidationBarrier
	if r.cfg.AssumeChannelValid {
		validationBarrier = NewValidationBarrier(1000, r.quit)
	} else {
		validationBarrier = NewValidationBarrier(
			4*runtime.NumCPU(), r.quit,
		)
	}

	for {

		// If there are stats, resume the statTicker.
		if !r.stats.Empty() {
			r.statTicker.Resume()
		}

		select {
		// A new fully validated network update has just arrived. As a
		// result we'll modify the channel graph accordingly depending
		// on the exact type of the message.
		case update := <-r.networkUpdates:
			// We'll set up any dependants, and wait until a free
			// slot for this job opens up, this allow us to not
			// have thousands of goroutines active.
			validationBarrier.InitJobDependencies(update.msg)

			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer validationBarrier.CompleteJob()

				// If this message has an existing dependency,
				// then we'll wait until that has been fully
				// validated before we proceed.
				err := validationBarrier.WaitForDependants(
					update.msg,
				)
				if err != nil {
					switch err {
					case ErrVBarrierShuttingDown:
						update.err <- err
					case ErrParentValidationFailed:
						update.err <- newErrf(
							ErrIgnored, err.Error(),
						)
					default:
						log.Warnf("unexpected error "+
							"during validation "+
							"barrier shutdown: %v",
							err)
						update.err <- err
					}
					return
				}

				// Process the routing update to determine if
				// this is either a new update from our PoV or
				// an update to a prior vertex/edge we
				// previously accepted.
				err = r.processUpdate(update.msg, update.op...)
				update.err <- err

				// If this message had any dependencies, then
				// we can now signal them to continue.
				allowDependents := err == nil ||
					IsError(err, ErrIgnored, ErrOutdated)
				validationBarrier.SignalDependants(
					update.msg, allowDependents,
				)
				if err != nil {
					return
				}

				// Send off a new notification for the newly
				// accepted update.
				topChange := &TopologyChange{}
				err = addToTopologyChange(
					r.cfg.Graph, topChange, update.msg,
				)
				if err != nil {
					log.Errorf("unable to update topology "+
						"change notification: %v", err)
					return
				}

				if !topChange.isEmpty() {
					r.notifyTopologyChange(topChange)
				}
			}()

			// TODO(roasbeef): remove all unconnected vertexes
			// after N blocks pass with no corresponding
			// announcements.

		case chainUpdate, ok := <-r.staleBlocks:
			// If the channel has been closed, then this indicates
			// the daemon is shutting down, so we exit ourselves.
			if !ok {
				return
			}

			// Since this block is stale, we update our best height
			// to the previous block.
			blockHeight := uint32(chainUpdate.Height)
			atomic.StoreUint32(&r.bestHeight, blockHeight-1)

			// Update the channel graph to reflect that this block
			// was disconnected.
			_, err := r.cfg.Graph.DisconnectBlockAtHeight(blockHeight)
			if err != nil {
				log.Errorf("unable to prune graph with stale "+
					"block: %v", err)
				continue
			}

			// TODO(halseth): notify client about the reorg?

		// A new block has arrived, so we can prune the channel graph
		// of any channels which were closed in the block.
		case chainUpdate, ok := <-r.newBlocks:
			// If the channel has been closed, then this indicates
			// the daemon is shutting down, so we exit ourselves.
			if !ok {
				return
			}

			// We'll ensure that any new blocks received attach
			// directly to the end of our main chain. If not, then
			// we've somehow missed some blocks. We don't process
			// this block as otherwise, we may miss on-chain
			// events.
			currentHeight := atomic.LoadUint32(&r.bestHeight)
			if chainUpdate.Height != currentHeight+1 {
				log.Errorf("out of order block: expecting "+
					"height=%v, got height=%v", currentHeight+1,
					chainUpdate.Height)
				continue
			}

			// Once a new block arrives, we update our running
			// track of the height of the chain tip.
			blockHeight := uint32(chainUpdate.Height)
			atomic.StoreUint32(&r.bestHeight, blockHeight)
			log.Infof("Pruning channel graph using block %v (height=%v)",
				chainUpdate.Hash, blockHeight)

			// We're only interested in all prior outputs that have
			// been spent in the block, so collate all the
			// referenced previous outpoints within each tx and
			// input.
			var spentOutputs []*wire.OutPoint
			for _, tx := range chainUpdate.Transactions {
				for _, txIn := range tx.TxIn {
					spentOutputs = append(spentOutputs,
						&txIn.PreviousOutPoint)
				}
			}

			// With the spent outputs gathered, attempt to prune
			// the channel graph, also passing in the hash+height
			// of the block being pruned so the prune tip can be
			// updated.
			chansClosed, err := r.cfg.Graph.PruneGraph(spentOutputs,
				&chainUpdate.Hash, chainUpdate.Height)
			if err != nil {
				log.Errorf("unable to prune routing table: %v", err)
				continue
			}

			log.Infof("Block %v (height=%v) closed %v channels",
				chainUpdate.Hash, blockHeight, len(chansClosed))

			if len(chansClosed) == 0 {
				continue
			}

			// Notify all currently registered clients of the newly
			// closed channels.
			closeSummaries := createCloseSummaries(blockHeight, chansClosed...)
			r.notifyTopologyChange(&TopologyChange{
				ClosedChannels: closeSummaries,
			})

		// A new notification client update has arrived. We're either
		// gaining a new client, or cancelling notifications for an
		// existing client.
		case ntfnUpdate := <-r.ntfnClientUpdates:
			clientID := ntfnUpdate.clientID

			if ntfnUpdate.cancel {
				r.RLock()
				client, ok := r.topologyClients[ntfnUpdate.clientID]
				r.RUnlock()
				if ok {
					r.Lock()
					delete(r.topologyClients, clientID)
					r.Unlock()

					close(client.exit)
					client.wg.Wait()

					close(client.ntfnChan)
				}

				continue
			}

			r.Lock()
			r.topologyClients[ntfnUpdate.clientID] = &topologyClient{
				ntfnChan: ntfnUpdate.ntfnChan,
				exit:     make(chan struct{}),
			}
			r.Unlock()

		// The graph prune ticker has ticked, so we'll examine the
		// state of the known graph to filter out any zombie channels
		// for pruning.
		case <-graphPruneTicker.C:
			if err := r.pruneZombieChans(); err != nil {
				log.Errorf("Unable to prune zombies: %v", err)
			}

		// Log any stats if we've processed a non-empty number of
		// channels, updates, or nodes. We'll only pause the ticker if
		// the last window contained no updates to avoid resuming and
		// pausing while consecutive windows contain new info.
		case <-r.statTicker.Ticks():
			if !r.stats.Empty() {
				log.Infof(r.stats.String())
			} else {
				r.statTicker.Pause()
			}
			r.stats.Reset()

		// The router has been signalled to exit, to we exit our main
		// loop so the wait group can be decremented.
		case <-r.quit:
			return
		}
	}
}

// assertNodeAnnFreshness returns a non-nil error if we have an announcement in
// the database for the passed node with a timestamp newer than the passed
// timestamp. ErrIgnored will be returned if we already have the node, and
// ErrOutdated will be returned if we have a timestamp that's after the new
// timestamp.
func (r *ChannelRouter) assertNodeAnnFreshness(node route.Vertex,
	msgTimestamp time.Time) error {

	// If we are not already aware of this node, it means that we don't
	// know about any channel using this node. To avoid a DoS attack by
	// node announcements, we will ignore such nodes. If we do know about
	// this node, check that this update brings info newer than what we
	// already have.
	lastUpdate, exists, err := r.cfg.Graph.HasLightningNode(node)
	if err != nil {
		return errors.Errorf("unable to query for the "+
			"existence of node: %v", err)
	}
	if !exists {
		return newErrf(ErrIgnored, "Ignoring node announcement"+
			" for node not found in channel graph (%x)",
			node[:])
	}

	// If we've reached this point then we're aware of the vertex being
	// advertised. So we now check if the new message has a new time stamp,
	// if not then we won't accept the new data as it would override newer
	// data.
	if !lastUpdate.Before(msgTimestamp) {
		return newErrf(ErrOutdated, "Ignoring outdated "+
			"announcement for %x", node[:])
	}

	return nil
}

// addZombieEdge adds a channel that failed complete validation into the zombie
// index so we can avoid having to re-validate it in the future.
func (r *ChannelRouter) addZombieEdge(chanID uint64) error {
	// If the edge fails validation we'll mark the edge itself as a zombie
	// so we don't continue to request it. We use the "zero key" for both
	// node pubkeys so this edge can't be resurrected.
	var zeroKey [33]byte
	err := r.cfg.Graph.MarkEdgeZombie(chanID, zeroKey, zeroKey)
	if err != nil {
		return fmt.Errorf("unable to mark spent chan(id=%v) as a "+
			"zombie: %w", chanID, err)
	}

	return nil
}

// processUpdate processes a new relate authenticated channel/edge, node or
// channel/edge update network update. If the update didn't affect the internal
// state of the draft due to either being out of date, invalid, or redundant,
// then error is returned.
func (r *ChannelRouter) processUpdate(msg interface{},
	op ...batch.SchedulerOption) error {

	switch msg := msg.(type) {
	case *channeldb.LightningNode:
		// Before we add the node to the database, we'll check to see
		// if the announcement is "fresh" or not. If it isn't, then
		// we'll return an error.
		err := r.assertNodeAnnFreshness(msg.PubKeyBytes, msg.LastUpdate)
		if err != nil {
			return err
		}

		if err := r.cfg.Graph.AddLightningNode(msg, op...); err != nil {
			return errors.Errorf("unable to add node %v to the "+
				"graph: %v", msg.PubKeyBytes, err)
		}

		log.Tracef("Updated vertex data for node=%x", msg.PubKeyBytes)
		r.stats.incNumNodeUpdates()

	case *channeldb.ChannelEdgeInfo:
		// Prior to processing the announcement we first check if we
		// already know of this channel, if so, then we can exit early.
		_, _, exists, isZombie, err := r.cfg.Graph.HasChannelEdge(
			msg.ChannelID,
		)
		if err != nil && err != channeldb.ErrGraphNoEdgesFound {
			return errors.Errorf("unable to check for edge "+
				"existence: %v", err)
		}
		if isZombie {
			return newErrf(ErrIgnored, "ignoring msg for zombie "+
				"chan_id=%v", msg.ChannelID)
		}
		if exists {
			return newErrf(ErrIgnored, "ignoring msg for known "+
				"chan_id=%v", msg.ChannelID)
		}

		// If AssumeChannelValid is present, then we are unable to
		// perform any of the expensive checks below, so we'll
		// short-circuit our path straight to adding the edge to our
		// graph.
		if r.cfg.AssumeChannelValid {
			if err := r.cfg.Graph.AddChannelEdge(msg, op...); err != nil {
				return fmt.Errorf("unable to add edge: %v", err)
			}
			log.Tracef("New channel discovered! Link "+
				"connects %x and %x with ChannelID(%v)",
				msg.NodeKey1Bytes, msg.NodeKey2Bytes,
				msg.ChannelID)
			r.stats.incNumEdgesDiscovered()

			break
		}

		// Before we can add the channel to the channel graph, we need
		// to obtain the full funding outpoint that's encoded within
		// the channel ID.
		channelID := lnwire.NewShortChanIDFromInt(msg.ChannelID)
		fundingTx, err := r.fetchFundingTx(&channelID)
		if err != nil {
			// In order to ensure we don't erroneously mark a
			// channel as a zombie due to an RPC failure, we'll
			// attempt to string match for the relevant errors.
			//
			// * btcd:
			//    * https://github.com/btcsuite/btcd/blob/master/rpcserver.go#L1316
			//    * https://github.com/btcsuite/btcd/blob/master/rpcserver.go#L1086
			// * bitcoind:
			//    * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/rpc/blockchain.cpp#L770
			//     * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/rpc/blockchain.cpp#L954
			switch {
			case strings.Contains(err.Error(), "not found"):
				fallthrough

			case strings.Contains(err.Error(), "out of range"):
				// If the funding transaction isn't found at
				// all, then we'll mark the edge itself as a
				// zombie so we don't continue to request it.
				// We use the "zero key" for both node pubkeys
				// so this edge can't be resurrected.
				zErr := r.addZombieEdge(msg.ChannelID)
				if zErr != nil {
					return zErr
				}

			default:
			}

			return newErrf(ErrNoFundingTransaction, "unable to "+
				"locate funding tx: %v", err)
		}

		// Recreate witness output to be sure that declared in channel
		// edge bitcoin keys and channel value corresponds to the
		// reality.
		witnessScript, err := input.GenMultiSigScript(
			msg.BitcoinKey1Bytes[:], msg.BitcoinKey2Bytes[:],
		)
		if err != nil {
			return err
		}
		pkScript, err := input.WitnessScriptHash(witnessScript)
		if err != nil {
			return err
		}

		// Next we'll validate that this channel is actually well
		// formed. If this check fails, then this channel either
		// doesn't exist, or isn't the one that was meant to be created
		// according to the passed channel proofs.
		fundingPoint, err := chanvalidate.Validate(&chanvalidate.Context{
			Locator: &chanvalidate.ShortChanIDChanLocator{
				ID: channelID,
			},
			MultiSigPkScript: pkScript,
			FundingTx:        fundingTx,
		})
		if err != nil {
			// Mark the edge as a zombie so we won't try to
			// re-validate it on start up.
			if err := r.addZombieEdge(msg.ChannelID); err != nil {
				return err
			}

			return newErrf(ErrInvalidFundingOutput, "output "+
				"failed validation: %w", err)
		}

		// Now that we have the funding outpoint of the channel, ensure
		// that it hasn't yet been spent. If so, then this channel has
		// been closed so we'll ignore it.
		fundingPkScript, err := input.WitnessScriptHash(witnessScript)
		if err != nil {
			return err
		}
		chanUtxo, err := r.cfg.Chain.GetUtxo(
			fundingPoint, fundingPkScript, channelID.BlockHeight,
			r.quit,
		)
		if err != nil {
			if errors.Is(err, btcwallet.ErrOutputSpent) {
				zErr := r.addZombieEdge(msg.ChannelID)
				if zErr != nil {
					return zErr
				}
			}

			return newErrf(ErrChannelSpent, "unable to fetch utxo "+
				"for chan_id=%v, chan_point=%v: %v",
				msg.ChannelID, fundingPoint, err)
		}

		// TODO(roasbeef): this is a hack, needs to be removed
		// after commitment fees are dynamic.
		msg.Capacity = btcutil.Amount(chanUtxo.Value)
		msg.ChannelPoint = *fundingPoint
		if err := r.cfg.Graph.AddChannelEdge(msg, op...); err != nil {
			return errors.Errorf("unable to add edge: %v", err)
		}

		log.Tracef("New channel discovered! Link "+
			"connects %x and %x with ChannelPoint(%v): "+
			"chan_id=%v, capacity=%v",
			msg.NodeKey1Bytes, msg.NodeKey2Bytes,
			fundingPoint, msg.ChannelID, msg.Capacity)
		r.stats.incNumEdgesDiscovered()

		// As a new edge has been added to the channel graph, we'll
		// update the current UTXO filter within our active
		// FilteredChainView so we are notified if/when this channel is
		// closed.
		filterUpdate := []channeldb.EdgePoint{
			{
				FundingPkScript: fundingPkScript,
				OutPoint:        *fundingPoint,
			},
		}
		err = r.cfg.ChainView.UpdateFilter(
			filterUpdate, atomic.LoadUint32(&r.bestHeight),
		)
		if err != nil {
			return errors.Errorf("unable to update chain "+
				"view: %v", err)
		}

	case *channeldb.ChannelEdgePolicy:
		// We make sure to hold the mutex for this channel ID,
		// such that no other goroutine is concurrently doing
		// database accesses for the same channel ID.
		r.channelEdgeMtx.Lock(msg.ChannelID)
		defer r.channelEdgeMtx.Unlock(msg.ChannelID)

		edge1Timestamp, edge2Timestamp, exists, isZombie, err :=
			r.cfg.Graph.HasChannelEdge(msg.ChannelID)
		if err != nil && err != channeldb.ErrGraphNoEdgesFound {
			return errors.Errorf("unable to check for edge "+
				"existence: %v", err)

		}

		// If the channel is marked as a zombie in our database, and
		// we consider this a stale update, then we should not apply the
		// policy.
		isStaleUpdate := time.Since(msg.LastUpdate) > r.cfg.ChannelPruneExpiry
		if isZombie && isStaleUpdate {
			return newErrf(ErrIgnored, "ignoring stale update "+
				"(flags=%v|%v) for zombie chan_id=%v",
				msg.MessageFlags, msg.ChannelFlags,
				msg.ChannelID)
		}

		// If the channel doesn't exist in our database, we cannot
		// apply the updated policy.
		if !exists {
			return newErrf(ErrIgnored, "ignoring update "+
				"(flags=%v|%v) for unknown chan_id=%v",
				msg.MessageFlags, msg.ChannelFlags,
				msg.ChannelID)
		}

		// As edges are directional edge node has a unique policy for
		// the direction of the edge they control. Therefore we first
		// check if we already have the most up to date information for
		// that edge. If this message has a timestamp not strictly
		// newer than what we already know of we can exit early.
		switch {

		// A flag set of 0 indicates this is an announcement for the
		// "first" node in the channel.
		case msg.ChannelFlags&lnwire.ChanUpdateDirection == 0:

			// Ignore outdated message.
			if !edge1Timestamp.Before(msg.LastUpdate) {
				return newErrf(ErrOutdated, "Ignoring "+
					"outdated update (flags=%v|%v) for "+
					"known chan_id=%v", msg.MessageFlags,
					msg.ChannelFlags, msg.ChannelID)
			}

		// Similarly, a flag set of 1 indicates this is an announcement
		// for the "second" node in the channel.
		case msg.ChannelFlags&lnwire.ChanUpdateDirection == 1:

			// Ignore outdated message.
			if !edge2Timestamp.Before(msg.LastUpdate) {
				return newErrf(ErrOutdated, "Ignoring "+
					"outdated update (flags=%v|%v) for "+
					"known chan_id=%v", msg.MessageFlags,
					msg.ChannelFlags, msg.ChannelID)
			}
		}

		// Now that we know this isn't a stale update, we'll apply the
		// new edge policy to the proper directional edge within the
		// channel graph.
		if err = r.cfg.Graph.UpdateEdgePolicy(msg, op...); err != nil {
			err := errors.Errorf("unable to add channel: %v", err)
			log.Error(err)
			return err
		}

		log.Tracef("New channel update applied: %v",
			newLogClosure(func() string { return spew.Sdump(msg) }))
		r.stats.incNumChannelUpdates()

	default:
		return errors.Errorf("wrong routing update message type")
	}

	return nil
}

// fetchFundingTx returns the funding transaction identified by the passed
// short channel ID.
//
// TODO(roasbeef): replace with call to GetBlockTransaction? (would allow to
// later use getblocktxn)
func (r *ChannelRouter) fetchFundingTx(
	chanID *lnwire.ShortChannelID) (*wire.MsgTx, error) {

	// First fetch the block hash by the block number encoded, then use
	// that hash to fetch the block itself.
	blockNum := int64(chanID.BlockHeight)
	blockHash, err := r.cfg.Chain.GetBlockHash(blockNum)
	if err != nil {
		return nil, err
	}
	fundingBlock, err := r.cfg.Chain.GetBlock(blockHash)
	if err != nil {
		return nil, err
	}

	// As a sanity check, ensure that the advertised transaction index is
	// within the bounds of the total number of transactions within a
	// block.
	numTxns := uint32(len(fundingBlock.Transactions))
	if chanID.TxIndex > numTxns-1 {
		return nil, fmt.Errorf("tx_index=#%v "+
			"is out of range (max_index=%v), network_chan_id=%v",
			chanID.TxIndex, numTxns-1, chanID)
	}

	return fundingBlock.Transactions[chanID.TxIndex], nil
}

// routingMsg couples a routing related routing topology update to the
// error channel.
type routingMsg struct {
	msg interface{}
	op  []batch.SchedulerOption
	err chan error
}

// FindRoute attempts to query the ChannelRouter for the optimum path to a
// particular target destination to which it is able to send `amt` after
// factoring in channel capacities and cumulative fees along the route.
func (r *ChannelRouter) FindRoute(source, target route.Vertex,
	amt lnwire.MilliSatoshi, restrictions *RestrictParams,
	destCustomRecords record.CustomSet,
	routeHints map[route.Vertex][]*channeldb.ChannelEdgePolicy,
	finalExpiry uint16) (*route.Route, error) {

	log.Debugf("Searching for path to %v, sending %v", target, amt)

	// We'll attempt to obtain a set of bandwidth hints that can help us
	// eliminate certain routes early on in the path finding process.
	bandwidthHints, err := newBandwidthManager(
		r.selfNode, r.cfg.QueryBandwidth,
	)
	if err != nil {
		return nil, err
	}

	// We'll fetch the current block height so we can properly calculate the
	// required HTLC time locks within the route.
	_, currentHeight, err := r.cfg.Chain.GetBestBlock()
	if err != nil {
		return nil, err
	}

	// Now that we know the destination is reachable within the graph, we'll
	// execute our path finding algorithm.
	finalHtlcExpiry := currentHeight + int32(finalExpiry)

	routingTx, err := newDbRoutingTx(r.cfg.Graph)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := routingTx.close()
		if err != nil {
			log.Errorf("Error closing db tx: %v", err)
		}
	}()

	path, err := findPath(
		&graphParams{
			additionalEdges: routeHints,
			bandwidthHints:  bandwidthHints,
			graph:           routingTx,
		},
		restrictions,
		&r.cfg.PathFindingConfig,
		source, target, amt, finalHtlcExpiry,
	)
	if err != nil {
		return nil, err
	}

	// Create the route with absolute time lock values.
	route, err := newRoute(
		source, path, uint32(currentHeight),
		finalHopParams{
			amt:       amt,
			totalAmt:  amt,
			cltvDelta: finalExpiry,
			records:   destCustomRecords,
		},
	)
	if err != nil {
		return nil, err
	}

	go log.Tracef("Obtained path to send %v to %x: %v",
		amt, target, newLogClosure(func() string {
			return spew.Sdump(route)
		}),
	)

	return route, nil
}

// generateNewSessionKey generates a new ephemeral private key to be used for a
// payment attempt.
func generateNewSessionKey() (*btcec.PrivateKey, error) {
	// Generate a new random session key to ensure that we don't trigger
	// any replay.
	//
	// TODO(roasbeef): add more sources of randomness?
	return btcec.NewPrivateKey(btcec.S256())
}

// generateSphinxPacket generates then encodes a sphinx packet which encodes
// the onion route specified by the passed layer 3 route. The blob returned
// from this function can immediately be included within an HTLC add packet to
// be sent to the first hop within the route.
func generateSphinxPacket(rt *route.Route, paymentHash []byte,
	sessionKey *btcec.PrivateKey) ([]byte, *sphinx.Circuit, error) {

	// Now that we know we have an actual route, we'll map the route into a
	// sphinx payument path which includes per-hop paylods for each hop
	// that give each node within the route the necessary information
	// (fees, CLTV value, etc) to properly forward the payment.
	sphinxPath, err := rt.ToSphinxPath()
	if err != nil {
		return nil, nil, err
	}

	log.Tracef("Constructed per-hop payloads for payment_hash=%x: %v",
		paymentHash[:], newLogClosure(func() string {
			path := make([]sphinx.OnionHop, sphinxPath.TrueRouteLength())
			for i := range path {
				hopCopy := sphinxPath[i]
				hopCopy.NodePub.Curve = nil
				path[i] = hopCopy
			}
			return spew.Sdump(path)
		}),
	)

	// Next generate the onion routing packet which allows us to perform
	// privacy preserving source routing across the network.
	sphinxPacket, err := sphinx.NewOnionPacket(
		sphinxPath, sessionKey, paymentHash,
		sphinx.DeterministicPacketFiller,
	)
	if err != nil {
		return nil, nil, err
	}

	// Finally, encode Sphinx packet using its wire representation to be
	// included within the HTLC add packet.
	var onionBlob bytes.Buffer
	if err := sphinxPacket.Encode(&onionBlob); err != nil {
		return nil, nil, err
	}

	log.Tracef("Generated sphinx packet: %v",
		newLogClosure(func() string {
			// We make a copy of the ephemeral key and unset the
			// internal curve here in order to keep the logs from
			// getting noisy.
			key := *sphinxPacket.EphemeralKey
			key.Curve = nil
			packetCopy := *sphinxPacket
			packetCopy.EphemeralKey = &key
			return spew.Sdump(packetCopy)
		}),
	)

	return onionBlob.Bytes(), &sphinx.Circuit{
		SessionKey:  sessionKey,
		PaymentPath: sphinxPath.NodeKeys(),
	}, nil
}

// LightningPayment describes a payment to be sent through the network to the
// final destination.
type LightningPayment struct {
	// Target is the node in which the payment should be routed towards.
	Target route.Vertex

	// Amount is the value of the payment to send through the network in
	// milli-satoshis.
	Amount lnwire.MilliSatoshi

	// FeeLimit is the maximum fee in millisatoshis that the payment should
	// accept when sending it through the network. The payment will fail
	// if there isn't a route with lower fees than this limit.
	FeeLimit lnwire.MilliSatoshi

	// CltvLimit is the maximum time lock that is allowed for attempts to
	// complete this payment.
	CltvLimit uint32

	// paymentHash is the r-hash value to use within the HTLC extended to
	// the first hop. This won't be set for AMP payments.
	paymentHash *lntypes.Hash

	// amp is an optional field that is set if and only if this is am AMP
	// payment.
	amp *AMPOptions

	// FinalCLTVDelta is the CTLV expiry delta to use for the _final_ hop
	// in the route. This means that the final hop will have a CLTV delta
	// of at least: currentHeight + FinalCLTVDelta.
	FinalCLTVDelta uint16

	// PayAttemptTimeout is a timeout value that we'll use to determine
	// when we should should abandon the payment attempt after consecutive
	// payment failure. This prevents us from attempting to send a payment
	// indefinitely. A zero value means the payment will never time out.
	//
	// TODO(halseth): make wallclock time to allow resume after startup.
	PayAttemptTimeout time.Duration

	// RouteHints represents the different routing hints that can be used to
	// assist a payment in reaching its destination successfully. These
	// hints will act as intermediate hops along the route.
	//
	// NOTE: This is optional unless required by the payment. When providing
	// multiple routes, ensure the hop hints within each route are chained
	// together and sorted in forward order in order to reach the
	// destination successfully.
	RouteHints [][]zpay32.HopHint

	// OutgoingChannelIDs is the list of channels that are allowed for the
	// first hop. If nil, any channel may be used.
	OutgoingChannelIDs []uint64

	// LastHop is the pubkey of the last node before the final destination
	// is reached. If nil, any node may be used.
	LastHop *route.Vertex

	// DestFeatures specifies the set of features we assume the final node
	// has for pathfinding. Typically these will be taken directly from an
	// invoice, but they can also be manually supplied or assumed by the
	// sender. If a nil feature vector is provided, the router will try to
	// fallback to the graph in order to load a feature vector for a node in
	// the public graph.
	DestFeatures *lnwire.FeatureVector

	// PaymentAddr is the payment address specified by the receiver. This
	// field should be a random 32-byte nonce presented in the receiver's
	// invoice to prevent probing of the destination.
	PaymentAddr *[32]byte

	// PaymentRequest is an optional payment request that this payment is
	// attempting to complete.
	PaymentRequest []byte

	// DestCustomRecords are TLV records that are to be sent to the final
	// hop in the new onion payload format. If the destination does not
	// understand this new onion payload format, then the payment will
	// fail.
	DestCustomRecords record.CustomSet

	// MaxParts is the maximum number of partial payments that may be used
	// to complete the full amount.
	MaxParts uint32

	// MaxShardAmt is the largest shard that we'll attempt to split using.
	// If this field is set, and we need to split, rather than attempting
	// half of the original payment amount, we'll use this value if half
	// the payment amount is greater than it.
	//
	// NOTE: This field is _optional_.
	MaxShardAmt *lnwire.MilliSatoshi
}

// AMPOptions houses information that must be known in order to send an AMP
// payment.
type AMPOptions struct {
	SetID     [32]byte
	RootShare [32]byte
}

// SetPaymentHash sets the given hash as the payment's overall hash. This
// should only be used for non-AMP payments.
func (l *LightningPayment) SetPaymentHash(hash lntypes.Hash) error {
	if l.amp != nil {
		return fmt.Errorf("cannot set payment hash for AMP payment")
	}

	l.paymentHash = &hash
	return nil
}

// SetAMP sets the given AMP options for the payment.
func (l *LightningPayment) SetAMP(amp *AMPOptions) error {
	if l.paymentHash != nil {
		return fmt.Errorf("cannot set amp options for payment " +
			"with payment hash")
	}

	l.amp = amp
	return nil
}

// Identifier returns a 32-byte slice that uniquely identifies this single
// payment. For non-AMP payments this will be the payment hash, for AMP
// payments this will be the used SetID.
func (l *LightningPayment) Identifier() [32]byte {
	if l.amp != nil {
		return l.amp.SetID
	}

	return *l.paymentHash
}

// SendPayment attempts to send a payment as described within the passed
// LightningPayment. This function is blocking and will return either: when the
// payment is successful, or all candidates routes have been attempted and
// resulted in a failed payment. If the payment succeeds, then a non-nil Route
// will be returned which describes the path the successful payment traversed
// within the network to reach the destination. Additionally, the payment
// preimage will also be returned.
func (r *ChannelRouter) SendPayment(payment *LightningPayment) ([32]byte,
	*route.Route, error) {

	paySession, shardTracker, err := r.preparePayment(payment)
	if err != nil {
		return [32]byte{}, nil, err
	}

	log.Tracef("Dispatching SendPayment for lightning payment: %v",
		spewPayment(payment))

	// Since this is the first time this payment is being made, we pass nil
	// for the existing attempt.
	return r.sendPayment(
		payment.Amount, payment.FeeLimit, payment.Identifier(),
		payment.PayAttemptTimeout, paySession, shardTracker,
	)
}

// SendPaymentAsync is the non-blocking version of SendPayment. The payment
// result needs to be retrieved via the control tower.
func (r *ChannelRouter) SendPaymentAsync(payment *LightningPayment) error {
	paySession, shardTracker, err := r.preparePayment(payment)
	if err != nil {
		return err
	}

	// Since this is the first time this payment is being made, we pass nil
	// for the existing attempt.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		log.Tracef("Dispatching SendPayment for lightning payment: %v",
			spewPayment(payment))

		_, _, err := r.sendPayment(
			payment.Amount, payment.FeeLimit, payment.Identifier(),
			payment.PayAttemptTimeout, paySession, shardTracker,
		)
		if err != nil {
			log.Errorf("Payment %x failed: %v",
				payment.Identifier(), err)
		}
	}()

	return nil
}

// spewPayment returns a log closures that provides a spewed string
// representation of the passed payment.
func spewPayment(payment *LightningPayment) logClosure {
	return newLogClosure(func() string {
		// Make a copy of the payment with a nilled Curve
		// before spewing.
		var routeHints [][]zpay32.HopHint
		for _, routeHint := range payment.RouteHints {
			var hopHints []zpay32.HopHint
			for _, hopHint := range routeHint {
				h := hopHint.Copy()
				h.NodeID.Curve = nil
				hopHints = append(hopHints, h)
			}
			routeHints = append(routeHints, hopHints)
		}
		p := *payment
		p.RouteHints = routeHints
		return spew.Sdump(p)
	})
}

// preparePayment creates the payment session and registers the payment with the
// control tower.
func (r *ChannelRouter) preparePayment(payment *LightningPayment) (
	PaymentSession, shards.ShardTracker, error) {

	// Before starting the HTLC routing attempt, we'll create a fresh
	// payment session which will report our errors back to mission
	// control.
	paySession, err := r.cfg.SessionSource.NewPaymentSession(payment)
	if err != nil {
		return nil, nil, err
	}

	// Record this payment hash with the ControlTower, ensuring it is not
	// already in-flight.
	//
	// TODO(roasbeef): store records as part of creation info?
	info := &channeldb.PaymentCreationInfo{
		PaymentIdentifier: payment.Identifier(),
		Value:             payment.Amount,
		CreationTime:      r.cfg.Clock.Now(),
		PaymentRequest:    payment.PaymentRequest,
	}

	// Create a new ShardTracker that we'll use during the life cycle of
	// this payment.
	var shardTracker shards.ShardTracker
	switch {

	// If this is an AMP payment, we'll use the AMP shard tracker.
	case payment.amp != nil:
		shardTracker = amp.NewShardTracker(
			payment.amp.RootShare, payment.amp.SetID,
			*payment.PaymentAddr, payment.Amount,
		)

	// Otherwise we'll use the simple tracker that will map each attempt to
	// the same payment hash.
	default:
		shardTracker = shards.NewSimpleShardTracker(
			payment.Identifier(), nil,
		)
	}

	err = r.cfg.Control.InitPayment(payment.Identifier(), info)
	if err != nil {
		return nil, nil, err
	}

	return paySession, shardTracker, nil
}

// SendToRoute attempts to send a payment with the given hash through the
// provided route. This function is blocking and will return the attempt
// information as it is stored in the database. For a successful htlc, this
// information will contain the preimage. If an error occurs after the attempt
// was initiated, both return values will be non-nil.
func (r *ChannelRouter) SendToRoute(htlcHash lntypes.Hash, rt *route.Route) (
	*channeldb.HTLCAttempt, error) {

	// Calculate amount paid to receiver.
	amt := rt.ReceiverAmt()

	// If this is meant as a MP payment shard, we set the amount
	// for the creating info to the total amount of the payment.
	finalHop := rt.Hops[len(rt.Hops)-1]
	mpp := finalHop.MPP
	if mpp != nil {
		amt = mpp.TotalMsat()
	}

	// For non-AMP payments the overall payment identifier will be the same
	// hash as used for this HTLC.
	paymentIdentifier := htlcHash

	// For AMP-payments, we'll use the setID as the unique ID for the
	// overall payment.
	amp := finalHop.AMP
	if amp != nil {
		paymentIdentifier = amp.SetID()
	}

	// Record this payment hash with the ControlTower, ensuring it is not
	// already in-flight.
	info := &channeldb.PaymentCreationInfo{
		PaymentIdentifier: paymentIdentifier,
		Value:             amt,
		CreationTime:      r.cfg.Clock.Now(),
		PaymentRequest:    nil,
	}

	err := r.cfg.Control.InitPayment(paymentIdentifier, info)
	switch {
	// If this is an MPP attempt and the hash is already registered with
	// the database, we can go on to launch the shard.
	case err == channeldb.ErrPaymentInFlight && mpp != nil:

	// Any other error is not tolerated.
	case err != nil:
		return nil, err
	}

	log.Tracef("Dispatching SendToRoute for HTLC hash %v: %v",
		htlcHash, newLogClosure(func() string {
			return spew.Sdump(rt)
		}),
	)

	// Since the HTLC hashes and preimages are specified manually over the
	// RPC for SendToRoute requests, we don't have to worry about creating
	// a ShardTracker that can generate hashes for AMP payments. Instead we
	// create a simple tracker that can just return the hash for the single
	// shard we'll now launch.
	shardTracker := shards.NewSimpleShardTracker(htlcHash, nil)

	// Launch a shard along the given route.
	sh := &shardHandler{
		router:       r,
		identifier:   paymentIdentifier,
		shardTracker: shardTracker,
	}

	var shardError error
	attempt, outcome, err := sh.launchShard(rt, false)

	// With SendToRoute, it can happen that the route exceeds protocol
	// constraints. Mark the payment as failed with an internal error.
	if err == route.ErrMaxRouteHopsExceeded ||
		err == sphinx.ErrMaxRoutingInfoSizeExceeded {

		log.Debugf("Invalid route provided for payment %x: %v",
			paymentIdentifier, err)

		controlErr := r.cfg.Control.Fail(
			paymentIdentifier, channeldb.FailureReasonError,
		)
		if controlErr != nil {
			return nil, controlErr
		}
	}

	// In any case, don't continue if there is an error.
	if err != nil {
		return nil, err
	}

	var htlcAttempt *channeldb.HTLCAttempt
	switch {
	// Failed to launch shard.
	case outcome.err != nil:
		shardError = outcome.err
		htlcAttempt = outcome.attempt

	// Shard successfully launched, wait for the result to be available.
	default:
		result, err := sh.collectResult(attempt)
		if err != nil {
			return nil, err
		}

		// We got a successful result.
		if result.err == nil {
			return result.attempt, nil
		}

		// The shard failed, break switch to handle it.
		shardError = result.err
		htlcAttempt = result.attempt
	}

	// Since for SendToRoute we won't retry in case the shard fails, we'll
	// mark the payment failed with the control tower immediately. Process
	// the error to check if it maps into a terminal error code, if not use
	// a generic NO_ROUTE error.
	var failureReason *channeldb.FailureReason
	err = sh.handleSendError(attempt, shardError)

	switch {
	// If we weren't able to extract a proper failure reason (which can
	// happen if the second chance logic is triggered), then we'll use the
	// normal no route error.
	case err == nil:
		err = r.cfg.Control.Fail(
			paymentIdentifier, channeldb.FailureReasonNoRoute,
		)

	// If this is a failure reason, then we'll apply the failure directly
	// to the control tower, and return the normal response to the caller.
	case goErrors.As(err, &failureReason):
		err = r.cfg.Control.Fail(paymentIdentifier, *failureReason)
	}
	if err != nil {
		return nil, err
	}

	return htlcAttempt, shardError
}

// sendPayment attempts to send a payment to the passed payment hash. This
// function is blocking and will return either: when the payment is successful,
// or all candidates routes have been attempted and resulted in a failed
// payment. If the payment succeeds, then a non-nil Route will be returned
// which describes the path the successful payment traversed within the network
// to reach the destination. Additionally, the payment preimage will also be
// returned.
//
// The existing attempt argument should be set to nil if this is a payment that
// haven't had any payment attempt sent to the switch yet. If it has had an
// attempt already, it should be passed such that the result can be retrieved.
//
// This method relies on the ControlTower's internal payment state machine to
// carry out its execution. After restarts it is safe, and assumed, that the
// router will call this method for every payment still in-flight according to
// the ControlTower.
func (r *ChannelRouter) sendPayment(
	totalAmt, feeLimit lnwire.MilliSatoshi, identifier lntypes.Hash,
	timeout time.Duration, paySession PaymentSession,
	shardTracker shards.ShardTracker) ([32]byte, *route.Route, error) {

	// We'll also fetch the current block height so we can properly
	// calculate the required HTLC time locks within the route.
	_, currentHeight, err := r.cfg.Chain.GetBestBlock()
	if err != nil {
		return [32]byte{}, nil, err
	}

	// Now set up a paymentLifecycle struct with these params, such that we
	// can resume the payment from the current state.
	p := &paymentLifecycle{
		router:        r,
		totalAmount:   totalAmt,
		feeLimit:      feeLimit,
		identifier:    identifier,
		paySession:    paySession,
		shardTracker:  shardTracker,
		currentHeight: currentHeight,
	}

	// If a timeout is specified, create a timeout channel. If no timeout is
	// specified, the channel is left nil and will never abort the payment
	// loop.
	if timeout != 0 {
		p.timeoutChan = time.After(timeout)
	}

	return p.resumePayment()

}

// extractChannelUpdate examines the error and extracts the channel update.
func (r *ChannelRouter) extractChannelUpdate(
	failure lnwire.FailureMessage) *lnwire.ChannelUpdate {

	var update *lnwire.ChannelUpdate
	switch onionErr := failure.(type) {
	case *lnwire.FailExpiryTooSoon:
		update = &onionErr.Update
	case *lnwire.FailAmountBelowMinimum:
		update = &onionErr.Update
	case *lnwire.FailFeeInsufficient:
		update = &onionErr.Update
	case *lnwire.FailIncorrectCltvExpiry:
		update = &onionErr.Update
	case *lnwire.FailChannelDisabled:
		update = &onionErr.Update
	case *lnwire.FailTemporaryChannelFailure:
		update = onionErr.Update
	}

	return update
}

// applyChannelUpdate validates a channel update and if valid, applies it to the
// database. It returns a bool indicating whether the updates was successful.
func (r *ChannelRouter) applyChannelUpdate(msg *lnwire.ChannelUpdate,
	pubKey *btcec.PublicKey) bool {

	ch, _, _, err := r.GetChannelByID(msg.ShortChannelID)
	if err != nil {
		log.Errorf("Unable to retrieve channel by id: %v", err)
		return false
	}

	if err := ValidateChannelUpdateAnn(pubKey, ch.Capacity, msg); err != nil {
		log.Errorf("Unable to validate channel update: %v", err)
		return false
	}

	err = r.UpdateEdge(&channeldb.ChannelEdgePolicy{
		SigBytes:                  msg.Signature.ToSignatureBytes(),
		ChannelID:                 msg.ShortChannelID.ToUint64(),
		LastUpdate:                time.Unix(int64(msg.Timestamp), 0),
		MessageFlags:              msg.MessageFlags,
		ChannelFlags:              msg.ChannelFlags,
		TimeLockDelta:             msg.TimeLockDelta,
		MinHTLC:                   msg.HtlcMinimumMsat,
		MaxHTLC:                   msg.HtlcMaximumMsat,
		FeeBaseMSat:               lnwire.MilliSatoshi(msg.BaseFee),
		FeeProportionalMillionths: lnwire.MilliSatoshi(msg.FeeRate),
	})
	if err != nil && !IsError(err, ErrIgnored, ErrOutdated) {
		log.Errorf("Unable to apply channel update: %v", err)
		return false
	}

	return true
}

// AddNode is used to add information about a node to the router database. If
// the node with this pubkey is not present in an existing channel, it will
// be ignored.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) AddNode(node *channeldb.LightningNode,
	op ...batch.SchedulerOption) error {

	rMsg := &routingMsg{
		msg: node,
		op:  op,
		err: make(chan error, 1),
	}

	select {
	case r.networkUpdates <- rMsg:
		select {
		case err := <-rMsg.err:
			return err
		case <-r.quit:
			return ErrRouterShuttingDown
		}
	case <-r.quit:
		return ErrRouterShuttingDown
	}
}

// AddEdge is used to add edge/channel to the topology of the router, after all
// information about channel will be gathered this edge/channel might be used
// in construction of payment path.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) AddEdge(edge *channeldb.ChannelEdgeInfo,
	op ...batch.SchedulerOption) error {

	rMsg := &routingMsg{
		msg: edge,
		op:  op,
		err: make(chan error, 1),
	}

	select {
	case r.networkUpdates <- rMsg:
		select {
		case err := <-rMsg.err:
			return err
		case <-r.quit:
			return ErrRouterShuttingDown
		}
	case <-r.quit:
		return ErrRouterShuttingDown
	}
}

// UpdateEdge is used to update edge information, without this message edge
// considered as not fully constructed.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) UpdateEdge(update *channeldb.ChannelEdgePolicy,
	op ...batch.SchedulerOption) error {

	rMsg := &routingMsg{
		msg: update,
		op:  op,
		err: make(chan error, 1),
	}

	select {
	case r.networkUpdates <- rMsg:
		select {
		case err := <-rMsg.err:
			return err
		case <-r.quit:
			return ErrRouterShuttingDown
		}
	case <-r.quit:
		return ErrRouterShuttingDown
	}
}

// CurrentBlockHeight returns the block height from POV of the router subsystem.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) CurrentBlockHeight() (uint32, error) {
	_, height, err := r.cfg.Chain.GetBestBlock()
	return uint32(height), err
}

// SyncedHeight returns the block height to which the router subsystem currently
// is synced to. This can differ from the above chain height if the goroutine
// responsible for processing the blocks isn't yet up to speed.
func (r *ChannelRouter) SyncedHeight() uint32 {
	return atomic.LoadUint32(&r.bestHeight)
}

// GetChannelByID return the channel by the channel id.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) GetChannelByID(chanID lnwire.ShortChannelID) (
	*channeldb.ChannelEdgeInfo,
	*channeldb.ChannelEdgePolicy,
	*channeldb.ChannelEdgePolicy, error) {

	return r.cfg.Graph.FetchChannelEdgesByID(chanID.ToUint64())
}

// FetchLightningNode attempts to look up a target node by its identity public
// key. channeldb.ErrGraphNodeNotFound is returned if the node doesn't exist
// within the graph.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) FetchLightningNode(node route.Vertex) (*channeldb.LightningNode, error) {
	return r.cfg.Graph.FetchLightningNode(nil, node)
}

// ForEachNode is used to iterate over every node in router topology.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) ForEachNode(cb func(*channeldb.LightningNode) error) error {
	return r.cfg.Graph.ForEachNode(func(_ kvdb.RTx, n *channeldb.LightningNode) error {
		return cb(n)
	})
}

// ForAllOutgoingChannels is used to iterate over all outgoing channels owned by
// the router.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) ForAllOutgoingChannels(cb func(*channeldb.ChannelEdgeInfo,
	*channeldb.ChannelEdgePolicy) error) error {

	return r.selfNode.ForEachChannel(nil, func(_ kvdb.RTx, c *channeldb.ChannelEdgeInfo,
		e, _ *channeldb.ChannelEdgePolicy) error {

		if e == nil {
			return fmt.Errorf("channel from self node has no policy")
		}

		return cb(c, e)
	})
}

// ForEachChannel is used to iterate over every known edge (channel) within our
// view of the channel graph.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) ForEachChannel(cb func(chanInfo *channeldb.ChannelEdgeInfo,
	e1, e2 *channeldb.ChannelEdgePolicy) error) error {

	return r.cfg.Graph.ForEachChannel(cb)
}

// AddProof updates the channel edge info with proof which is needed to
// properly announce the edge to the rest of the network.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) AddProof(chanID lnwire.ShortChannelID,
	proof *channeldb.ChannelAuthProof) error {

	info, _, _, err := r.cfg.Graph.FetchChannelEdgesByID(chanID.ToUint64())
	if err != nil {
		return err
	}

	info.AuthProof = proof
	return r.cfg.Graph.UpdateChannelEdge(info)
}

// IsStaleNode returns true if the graph source has a node announcement for the
// target node with a more recent timestamp.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) IsStaleNode(node route.Vertex, timestamp time.Time) bool {
	// If our attempt to assert that the node announcement is fresh fails,
	// then we know that this is actually a stale announcement.
	return r.assertNodeAnnFreshness(node, timestamp) != nil
}

// IsPublicNode determines whether the given vertex is seen as a public node in
// the graph from the graph's source node's point of view.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) IsPublicNode(node route.Vertex) (bool, error) {
	return r.cfg.Graph.IsPublicNode(node)
}

// IsKnownEdge returns true if the graph source already knows of the passed
// channel ID either as a live or zombie edge.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) IsKnownEdge(chanID lnwire.ShortChannelID) bool {
	_, _, exists, isZombie, _ := r.cfg.Graph.HasChannelEdge(chanID.ToUint64())
	return exists || isZombie
}

// IsStaleEdgePolicy returns true if the graph soruce has a channel edge for
// the passed channel ID (and flags) that have a more recent timestamp.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) IsStaleEdgePolicy(chanID lnwire.ShortChannelID,
	timestamp time.Time, flags lnwire.ChanUpdateChanFlags) bool {

	edge1Timestamp, edge2Timestamp, exists, isZombie, err :=
		r.cfg.Graph.HasChannelEdge(chanID.ToUint64())
	if err != nil {
		return false

	}

	// If we know of the edge as a zombie, then we'll make some additional
	// checks to determine if the new policy is fresh.
	if isZombie {
		// When running with AssumeChannelValid, we also prune channels
		// if both of their edges are disabled. We'll mark the new
		// policy as stale if it remains disabled.
		if r.cfg.AssumeChannelValid {
			isDisabled := flags&lnwire.ChanUpdateDisabled ==
				lnwire.ChanUpdateDisabled
			if isDisabled {
				return true
			}
		}

		// Otherwise, we'll fall back to our usual ChannelPruneExpiry.
		return time.Since(timestamp) > r.cfg.ChannelPruneExpiry
	}

	// If we don't know of the edge, then it means it's fresh (thus not
	// stale).
	if !exists {
		return false
	}

	// As edges are directional edge node has a unique policy for the
	// direction of the edge they control. Therefore we first check if we
	// already have the most up to date information for that edge. If so,
	// then we can exit early.
	switch {
	// A flag set of 0 indicates this is an announcement for the "first"
	// node in the channel.
	case flags&lnwire.ChanUpdateDirection == 0:
		return !edge1Timestamp.Before(timestamp)

	// Similarly, a flag set of 1 indicates this is an announcement for the
	// "second" node in the channel.
	case flags&lnwire.ChanUpdateDirection == 1:
		return !edge2Timestamp.Before(timestamp)
	}

	return false
}

// MarkEdgeLive clears an edge from our zombie index, deeming it as live.
//
// NOTE: This method is part of the ChannelGraphSource interface.
func (r *ChannelRouter) MarkEdgeLive(chanID lnwire.ShortChannelID) error {
	return r.cfg.Graph.MarkEdgeLive(chanID.ToUint64())
}

// ErrNoChannel is returned when a route cannot be built because there are no
// channels that satisfy all requirements.
type ErrNoChannel struct {
	position int
	fromNode route.Vertex
}

// Error returns a human readable string describing the error.
func (e ErrNoChannel) Error() string {
	return fmt.Sprintf("no matching outgoing channel available for "+
		"node %v (%v)", e.position, e.fromNode)
}

// BuildRoute returns a fully specified route based on a list of pubkeys. If
// amount is nil, the minimum routable amount is used. To force a specific
// outgoing channel, use the outgoingChan parameter.
func (r *ChannelRouter) BuildRoute(amt *lnwire.MilliSatoshi,
	hops []route.Vertex, outgoingChan *uint64,
	finalCltvDelta int32, payAddr *[32]byte) (*route.Route, error) {

	log.Tracef("BuildRoute called: hopsCount=%v, amt=%v",
		len(hops), amt)

	var outgoingChans map[uint64]struct{}
	if outgoingChan != nil {
		outgoingChans = map[uint64]struct{}{
			*outgoingChan: {},
		}
	}

	// If no amount is specified, we need to build a route for the minimum
	// amount that this route can carry.
	useMinAmt := amt == nil

	// We'll attempt to obtain a set of bandwidth hints that helps us select
	// the best outgoing channel to use in case no outgoing channel is set.
	bandwidthHints, err := newBandwidthManager(
		r.selfNode, r.cfg.QueryBandwidth,
	)
	if err != nil {
		return nil, err
	}

	// Fetch the current block height outside the routing transaction, to
	// prevent the rpc call blocking the database.
	_, height, err := r.cfg.Chain.GetBestBlock()
	if err != nil {
		return nil, err
	}

	// Allocate a list that will contain the unified policies for this
	// route.
	edges := make([]*unifiedPolicy, len(hops))

	var runningAmt lnwire.MilliSatoshi
	if useMinAmt {
		// For minimum amount routes, aim to deliver at least 1 msat to
		// the destination. There are nodes in the wild that have a
		// min_htlc channel policy of zero, which could lead to a zero
		// amount payment being made.
		runningAmt = 1
	} else {
		// If an amount is specified, we need to build a route that
		// delivers exactly this amount to the final destination.
		runningAmt = *amt
	}

	// Open a transaction to execute the graph queries in.
	routingTx, err := newDbRoutingTx(r.cfg.Graph)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := routingTx.close()
		if err != nil {
			log.Errorf("Error closing db tx: %v", err)
		}
	}()

	// Traverse hops backwards to accumulate fees in the running amounts.
	source := r.selfNode.PubKeyBytes
	for i := len(hops) - 1; i >= 0; i-- {
		toNode := hops[i]

		var fromNode route.Vertex
		if i == 0 {
			fromNode = source
		} else {
			fromNode = hops[i-1]
		}

		localChan := i == 0

		// Build unified policies for this hop based on the channels
		// known in the graph.
		u := newUnifiedPolicies(source, toNode, outgoingChans)

		err := u.addGraphPolicies(routingTx)
		if err != nil {
			return nil, err
		}

		// Exit if there are no channels.
		unifiedPolicy, ok := u.policies[fromNode]
		if !ok {
			return nil, ErrNoChannel{
				fromNode: fromNode,
				position: i,
			}
		}

		// If using min amt, increase amt if needed.
		if useMinAmt {
			min := unifiedPolicy.minAmt()
			if min > runningAmt {
				runningAmt = min
			}
		}

		// Get a forwarding policy for the specific amount that we want
		// to forward.
		policy := unifiedPolicy.getPolicy(runningAmt, bandwidthHints)
		if policy == nil {
			return nil, ErrNoChannel{
				fromNode: fromNode,
				position: i,
			}
		}

		// Add fee for this hop.
		if !localChan {
			runningAmt += policy.ComputeFee(runningAmt)
		}

		log.Tracef("Select channel %v at position %v", policy.ChannelID, i)

		edges[i] = unifiedPolicy
	}

	// Now that we arrived at the start of the route and found out the route
	// total amount, we make a forward pass. Because the amount may have
	// been increased in the backward pass, fees need to be recalculated and
	// amount ranges re-checked.
	var pathEdges []*channeldb.ChannelEdgePolicy
	receiverAmt := runningAmt
	for i, edge := range edges {
		policy := edge.getPolicy(receiverAmt, bandwidthHints)
		if policy == nil {
			return nil, ErrNoChannel{
				fromNode: hops[i-1],
				position: i,
			}
		}

		if i > 0 {
			// Decrease the amount to send while going forward.
			receiverAmt -= policy.ComputeFeeFromIncoming(
				receiverAmt,
			)
		}

		pathEdges = append(pathEdges, policy)
	}

	// Build and return the final route.
	return newRoute(
		source, pathEdges, uint32(height),
		finalHopParams{
			amt:         receiverAmt,
			totalAmt:    receiverAmt,
			cltvDelta:   uint16(finalCltvDelta),
			records:     nil,
			paymentAddr: payAddr,
		},
	)
}
