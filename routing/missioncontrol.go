package routing

import (
	"math"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/zpay32"
)

const (
	// defaultPenaltyHalfLife is the default half-life duration. The
	// half-life duration defines after how much time a penalized node or
	// channel is back at 50% probability.
	defaultPenaltyHalfLife = time.Hour

	// hardPruneDuration defines the time window during which pruned nodes
	// and edges will receive zero probability.
	defaultHardPruneDuration = time.Minute
)

// MissionControl contains state which summarizes the past attempts of HTLC
// routing by external callers when sending payments throughout the network. It
// acts as a shared memory during routing attempts with the goal to optimize the
// payment attempt success rate.
//
// Failed payment attempts are reported to mission control. These reports are
// used to track the time of the last node or channel level failure. The time
// since the last failure is used to estimate a success probability that is fed
// into the path finding process for subsequent payment attempts.
type MissionControl struct {
	history map[route.Vertex]*nodeHistory

	graph *channeldb.ChannelGraph

	selfNode *channeldb.LightningNode

	queryBandwidth func(*channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi

	// now is expected to return the current time. It is supplied as an
	// external function to enable deterministic unit tests.
	now func() time.Time

	// penaltyHalfLife defines after how much time a penalized node or
	// channel is back at 50% probability.
	penaltyHalfLife time.Duration

	// hardPruneDuration defines the time window during which pruned nodes
	// and edges will receive zero probability. This is required to prevent
	// the payment process from getting into an endless loop too easily.
	hardPruneDuration time.Duration

	sync.Mutex

	// TODO(roasbeef): further counters, if vertex continually unavailable,
	// add to another generation

	// TODO(roasbeef): also add favorable metrics for nodes
}

// nodeHistory contains a summary of payment attempt outcomes involving a
// particular node.
type nodeHistory struct {
	lastFail        *time.Time
	channelLastFail map[uint64]time.Time
}

// NewMissionControl returns a new instance of missionControl.
//
// TODO(roasbeef): persist memory
func NewMissionControl(g *channeldb.ChannelGraph, selfNode *channeldb.LightningNode,
	qb func(*channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi) *MissionControl {

	return &MissionControl{
		history:           make(map[route.Vertex]*nodeHistory),
		selfNode:          selfNode,
		queryBandwidth:    qb,
		graph:             g,
		now:               time.Now,
		penaltyHalfLife:   defaultPenaltyHalfLife,
		hardPruneDuration: defaultHardPruneDuration,
	}
}

// NewPaymentSession creates a new payment session backed by the latest prune
// view from Mission Control. An optional set of routing hints can be provided
// in order to populate additional edges to explore when finding a path to the
// payment's destination.
func (m *MissionControl) newPaymentSession(routeHints [][]zpay32.HopHint,
	target route.Vertex) (*paymentSession, error) {

	edges := make(map[route.Vertex][]*channeldb.ChannelEdgePolicy)

	// Traverse through all of the available hop hints and include them in
	// our edges map, indexed by the public key of the channel's starting
	// node.
	for _, routeHint := range routeHints {
		// If multiple hop hints are provided within a single route
		// hint, we'll assume they must be chained together and sorted
		// in forward order in order to reach the target successfully.
		for i, hopHint := range routeHint {
			// In order to determine the end node of this hint,
			// we'll need to look at the next hint's start node. If
			// we've reached the end of the hints list, we can
			// assume we've reached the destination.
			endNode := &channeldb.LightningNode{}
			if i != len(routeHint)-1 {
				endNode.AddPubKey(routeHint[i+1].NodeID)
			} else {
				targetPubKey, err := btcec.ParsePubKey(
					target[:], btcec.S256(),
				)
				if err != nil {
					return nil, err
				}
				endNode.AddPubKey(targetPubKey)
			}

			// Finally, create the channel edge from the hop hint
			// and add it to list of edges corresponding to the node
			// at the start of the channel.
			edge := &channeldb.ChannelEdgePolicy{
				Node:      endNode,
				ChannelID: hopHint.ChannelID,
				FeeBaseMSat: lnwire.MilliSatoshi(
					hopHint.FeeBaseMSat,
				),
				FeeProportionalMillionths: lnwire.MilliSatoshi(
					hopHint.FeeProportionalMillionths,
				),
				TimeLockDelta: hopHint.CLTVExpiryDelta,
			}

			v := route.NewVertex(hopHint.NodeID)
			edges[v] = append(edges[v], edge)
		}
	}

	// We'll also obtain a set of bandwidthHints from the lower layer for
	// each of our outbound channels. This will allow the path finding to
	// skip any links that aren't active or just don't have enough
	// bandwidth to carry the payment.
	sourceNode, err := m.graph.SourceNode()
	if err != nil {
		return nil, err
	}
	bandwidthHints, err := generateBandwidthHints(
		sourceNode, m.queryBandwidth,
	)
	if err != nil {
		return nil, err
	}

	return &paymentSession{
		additionalEdges:      edges,
		bandwidthHints:       bandwidthHints,
		errFailedPolicyChans: make(map[nodeChannel]struct{}),
		mc:                   m,
		pathFinder:           findPath,
	}, nil
}

// newPaymentSessionFromRoutes creates a new paymentSession instance that will
// skip all path finding, and will instead utilize a set of pre-built routes.
// This constructor allows callers to specify their own routes which can be
// used for things like channel rebalancing, and swaps.
func (m *MissionControl) newPaymentSessionFromRoutes(
	routes []*route.Route) *paymentSession {

	return &paymentSession{
		haveRoutes:           true,
		preBuiltRoutes:       routes,
		errFailedPolicyChans: make(map[nodeChannel]struct{}),
		mc:                   m,
		pathFinder:           findPath,
	}
}

// generateBandwidthHints is a helper function that's utilized the main
// findPath function in order to obtain hints from the lower layer w.r.t to the
// available bandwidth of edges on the network. Currently, we'll only obtain
// bandwidth hints for the edges we directly have open ourselves. Obtaining
// these hints allows us to reduce the number of extraneous attempts as we can
// skip channels that are inactive, or just don't have enough bandwidth to
// carry the payment.
func generateBandwidthHints(sourceNode *channeldb.LightningNode,
	queryBandwidth func(*channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi) (map[uint64]lnwire.MilliSatoshi, error) {

	// First, we'll collect the set of outbound edges from the target
	// source node.
	var localChans []*channeldb.ChannelEdgeInfo
	err := sourceNode.ForEachChannel(nil, func(tx *bbolt.Tx,
		edgeInfo *channeldb.ChannelEdgeInfo,
		_, _ *channeldb.ChannelEdgePolicy) error {

		localChans = append(localChans, edgeInfo)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Now that we have all of our outbound edges, we'll populate the set
	// of bandwidth hints, querying the lower switch layer for the most up
	// to date values.
	bandwidthHints := make(map[uint64]lnwire.MilliSatoshi)
	for _, localChan := range localChans {
		bandwidthHints[localChan.ChannelID] = queryBandwidth(localChan)
	}

	return bandwidthHints, nil
}

// ResetHistory resets the history of missionControl returning it to a state as
// if no payment attempts have been made.
func (m *MissionControl) ResetHistory() {
	m.Lock()
	m.history = make(map[route.Vertex]*nodeHistory)
	m.Unlock()
}

// getEdgeProbability is expected to return the success probability of a payment
// from fromNode along edge.
func (m *MissionControl) getEdgeProbability(fromNode route.Vertex,
	edge EdgeLocator) float64 {

	m.Lock()
	defer m.Unlock()

	nodeHistory, ok := m.history[fromNode]
	if !ok {
		return 1
	}

	return m.getEdgeProbabilityForNode(nodeHistory, edge.ChannelID)
}

// getEdgeProbabilityForNode estimates the probability of successfully
// traversing a channel based on the node history.
func (m *MissionControl) getEdgeProbabilityForNode(nodeHistory *nodeHistory,
	channelID uint64) float64 {

	now := m.now()

	// Calculate the last failure of the given edge. A node failure is
	// considered a failure that would have affected every edge.
	var lastFailure time.Time
	if nodeHistory.lastFail != nil {
		lastFailure = *nodeHistory.lastFail
	}

	lastEdgeFailure, ok := nodeHistory.channelLastFail[channelID]
	if ok {
		if lastEdgeFailure.After(lastFailure) {
			lastFailure = lastEdgeFailure
		}
	}

	// If we are still in the hard prune window, return probability 0.
	// Otherwise every channel would always have a non-zero probability,
	// meaning that there are always routes available to try. Even if those
	// routes have just been tried before.
	timeSinceLastFailure := now.Sub(lastFailure)
	if timeSinceLastFailure < m.hardPruneDuration {
		return 0
	}

	// Calculate time since end of the hard prune window.
	recoveryDuration := timeSinceLastFailure - m.hardPruneDuration

	// Calculate coefficient to set the half life time.
	coeff := math.Log10(2) / m.penaltyHalfLife.Hours()

	// Calculate success probability.
	probability := 1 - (1 / (math.Pow(10, coeff*recoveryDuration.Hours())))

	return probability
}

// createHistoryIfNotExists returns the history for the given node. If the node
// is yet unknown, it will create an empty history structure.
func (m *MissionControl) createHistoryIfNotExists(vertex route.Vertex) *nodeHistory {
	if node, ok := m.history[vertex]; ok {
		return node
	}

	node := &nodeHistory{
		channelLastFail: make(map[uint64]time.Time),
	}
	m.history[vertex] = node

	return node
}

// reportVertexFailure reports a node level failure.
func (m *MissionControl) reportVertexFailure(v route.Vertex) {
	log.Debugf("Reporting vertex %v failure to Mission Control", v)

	now := m.now()

	m.Lock()
	defer m.Unlock()

	history := m.createHistoryIfNotExists(v)
	history.lastFail = &now
}

// reportEdgeFailure reports a channel level failure.
//
// TODO(roasbeef): also add value attempted to send and capacity of channel
func (m *MissionControl) reportEdgeFailure(failedEdge edge) {
	log.Debugf("Reporting channel %v failure to Mission Control",
		failedEdge.channel)

	now := m.now()

	m.Lock()
	defer m.Unlock()

	history := m.createHistoryIfNotExists(failedEdge.from)
	history.channelLastFail[failedEdge.channel] = now
}
