package routing

import (
	"encoding/binary"
	"fmt"
	"math"

	"container/heap"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	// HopLimit is the maximum number hops that is permissible as a route.
	// Any potential paths found that lie above this limit will be rejected
	// with an error. This value is computed using the current fixed-size
	// packet length of the Sphinx construction.
	HopLimit = 20

	// infinity is used as a starting distance in our shortest path search.
	infinity = math.MaxInt64

	// RiskFactorBillionths controls the influence of time lock delta
	// of a channel on route selection. It is expressed as billionths
	// of msat per msat sent through the channel per time lock delta
	// block. See edgeWeight function below for more details.
	// The chosen value is based on the previous incorrect weight function
	// 1 + timelock + fee * fee. In this function, the fee penalty
	// diminishes the time lock penalty for all but the smallest amounts.
	// To not change the behaviour of path finding too drastically, a
	// relatively small value is chosen which is still big enough to give
	// some effect with smaller time lock values. The value may need
	// tweaking and/or be made configurable in the future.
	RiskFactorBillionths = 15
)

// HopHint is a routing hint that contains the minimum information of a channel
// required for an intermediate hop in a route to forward the payment to the
// next. This should be ideally used for private channels, since they are not
// publicly advertised to the network for routing.
type HopHint struct {
	// NodeID is the public key of the node at the start of the channel.
	NodeID *btcec.PublicKey

	// ChannelID is the unique identifier of the channel.
	ChannelID uint64

	// FeeBaseMSat is the base fee of the channel in millisatoshis.
	FeeBaseMSat uint32

	// FeeProportionalMillionths is the fee rate, in millionths of a
	// satoshi, for every satoshi sent through the channel.
	FeeProportionalMillionths uint32

	// CLTVExpiryDelta is the time-lock delta of the channel.
	CLTVExpiryDelta uint16
}

// ChannelHop describes the channel through which an intermediate or final
// hop can be reached. This struct contains the relevant routing policy of
// the particular edge (which is a property of the source node of the channel
// edge), as well as the total capacity. It also includes the origin chain of
// the channel itself.
type ChannelHop struct {
	// Capacity is the total capacity of the channel being traversed. This
	// value is expressed for stability in satoshis.
	Capacity btcutil.Amount

	// Chain is a 32-byte has that denotes the base blockchain network of
	// the channel. The 32-byte hash is the "genesis" block of the
	// blockchain, or the very first block in the chain.
	//
	// TODO(roasbeef): store chain within edge info/policy in database.
	Chain chainhash.Hash

	*channeldb.ChannelEdgePolicy
}

// Hop represents an intermediate or final node of the route. This naming
// is in line with the definition given in BOLT #4: Onion Routing Protocol.
// The struct houses the channel along which this hop can be reached and
// the values necessary to create the HTLC that needs to be sent to the
// next hop. It is also used to encode the per-hop payload included within
// the Sphinx packet.
type Hop struct {
	// Channel is the active payment channel edge along which the packet
	// travels to reach this hop. This is the _incoming_ channel to this hop.
	Channel *ChannelHop

	// OutgoingTimeLock is the timelock value that should be used when
	// crafting the _outgoing_ HTLC from this hop.
	OutgoingTimeLock uint32

	// AmtToForward is the amount that this hop will forward to the next
	// hop. This value is less than the value that the incoming HTLC
	// carries as a fee will be subtracted by the hop.
	AmtToForward lnwire.MilliSatoshi

	// Fee is the total fee that this hop will subtract from the incoming
	// payment, this difference nets the hop fees for forwarding the
	// payment.
	Fee lnwire.MilliSatoshi
}

// computeFee computes the fee to forward an HTLC of `amt` milli-satoshis over
// the passed active payment channel. This value is currently computed as
// specified in BOLT07, but will likely change in the near future.
func computeFee(amt lnwire.MilliSatoshi,
	edge *channeldb.ChannelEdgePolicy) lnwire.MilliSatoshi {

	return edge.FeeBaseMSat + (amt*edge.FeeProportionalMillionths)/1000000
}

// isSamePath returns true if path1 and path2 travel through the exact same
// edges, and false otherwise.
func isSamePath(path1, path2 []*ChannelHop) bool {
	if len(path1) != len(path2) {
		return false
	}

	for i := 0; i < len(path1); i++ {
		if path1[i].ChannelID != path2[i].ChannelID {
			return false
		}
	}

	return true
}

// Route represents a path through the channel graph which runs over one or
// more channels in succession. This struct carries all the information
// required to craft the Sphinx onion packet, and send the payment along the
// first hop in the path. A route is only selected as valid if all the channels
// have sufficient capacity to carry the initial payment amount after fees are
// accounted for.
type Route struct {
	// TotalTimeLock is the cumulative (final) time lock across the entire
	// route. This is the CLTV value that should be extended to the first
	// hop in the route. All other hops will decrement the time-lock as
	// advertised, leaving enough time for all hops to wait for or present
	// the payment preimage to complete the payment.
	TotalTimeLock uint32

	// TotalFees is the sum of the fees paid at each hop within the final
	// route. In the case of a one-hop payment, this value will be zero as
	// we don't need to pay a fee to ourself.
	TotalFees lnwire.MilliSatoshi

	// TotalAmount is the total amount of funds required to complete a
	// payment over this route. This value includes the cumulative fees at
	// each hop. As a result, the HTLC extended to the first-hop in the
	// route will need to have at least this many satoshis, otherwise the
	// route will fail at an intermediate node due to an insufficient
	// amount of fees.
	TotalAmount lnwire.MilliSatoshi

	// Hops contains details concerning the specific forwarding details at
	// each hop.
	Hops []*Hop

	// nodeIndex is a map that allows callers to quickly look up if a node
	// is present in this computed route or not.
	nodeIndex map[Vertex]struct{}

	// chanIndex is an index that allows callers to determine if a channel
	// is present in this route or not. Channels are identified by the
	// uint64 version of the short channel ID.
	chanIndex map[uint64]struct{}

	// nextHop maps a node, to the next channel that it will pass the HTLC
	// off to. With this map, we can easily look up the next outgoing
	// channel or node for pruning purposes.
	nextHopMap map[Vertex]*ChannelHop

	// prevHop maps a node, to the channel that was directly before it
	// within the route. With this map, we can easily look up the previous
	// channel or node for pruning purposes.
	prevHopMap map[Vertex]*ChannelHop
}

// nextHopVertex returns the next hop (by Vertex) after the target node. If the
// target node is not found in the route, then false is returned.
func (r *Route) nextHopVertex(n *btcec.PublicKey) (Vertex, bool) {
	hop, ok := r.nextHopMap[NewVertex(n)]
	return Vertex(hop.Node.PubKeyBytes), ok
}

// nextHopChannel returns the uint64 channel ID of the next hop after the
// target node. If the target node is not found in the route, then false is
// returned.
func (r *Route) nextHopChannel(n *btcec.PublicKey) (*ChannelHop, bool) {
	hop, ok := r.nextHopMap[NewVertex(n)]
	return hop, ok
}

// prevHopChannel returns the uint64 channel ID of the before hop after the
// target node. If the target node is not found in the route, then false is
// returned.
func (r *Route) prevHopChannel(n *btcec.PublicKey) (*ChannelHop, bool) {
	hop, ok := r.prevHopMap[NewVertex(n)]
	return hop, ok
}

// containsNode returns true if a node is present in the target route, and
// false otherwise.
func (r *Route) containsNode(v Vertex) bool {
	_, ok := r.nodeIndex[v]
	return ok
}

// containsChannel returns true if a channel is present in the target route,
// and false otherwise. The passed chanID should be the converted uint64 form
// of lnwire.ShortChannelID.
func (r *Route) containsChannel(chanID uint64) bool {
	_, ok := r.chanIndex[chanID]
	return ok
}

// ToHopPayloads converts a complete route into the series of per-hop payloads
// that is to be encoded within each HTLC using an opaque Sphinx packet.
func (r *Route) ToHopPayloads() []sphinx.HopData {
	hopPayloads := make([]sphinx.HopData, len(r.Hops))

	// For each hop encoded within the route, we'll convert the hop struct
	// to the matching per-hop payload struct as used by the sphinx
	// package.
	for i, hop := range r.Hops {
		hopPayloads[i] = sphinx.HopData{
			// TODO(roasbeef): properly set realm, make sphinx type
			// an enum actually?
			Realm:         0,
			ForwardAmount: uint64(hop.AmtToForward),
			OutgoingCltv:  hop.OutgoingTimeLock,
		}

		// As a base case, the next hop is set to all zeroes in order
		// to indicate that the "last hop" as no further hops after it.
		nextHop := uint64(0)

		// If we aren't on the last hop, then we set the "next address"
		// field to be the channel that directly follows it.
		if i != len(r.Hops)-1 {
			nextHop = r.Hops[i+1].Channel.ChannelID
		}

		binary.BigEndian.PutUint64(hopPayloads[i].NextAddress[:],
			nextHop)
	}

	return hopPayloads
}

// newRoute returns a fully valid route between the source and target that's
// capable of supporting a payment of `amtToSend` after fees are fully
// computed. If the route is too long, or the selected path cannot support the
// fully payment including fees, then a non-nil error is returned.
//
// NOTE: The passed slice of ChannelHops MUST be sorted in forward order: from
// the source to the target node of the path finding attempt.
func newRoute(amtToSend, feeLimit lnwire.MilliSatoshi, sourceVertex Vertex,
	pathEdges []*ChannelHop, currentHeight uint32,
	finalCLTVDelta uint16) (*Route, error) {

	// First, we'll create a new empty route with enough hops to match the
	// amount of path edges. We set the TotalTimeLock to the current block
	// height, as this is the basis that all of the time locks will be
	// calculated from.
	route := &Route{
		Hops:          make([]*Hop, len(pathEdges)),
		TotalTimeLock: currentHeight,
		nodeIndex:     make(map[Vertex]struct{}),
		chanIndex:     make(map[uint64]struct{}),
		nextHopMap:    make(map[Vertex]*ChannelHop),
		prevHopMap:    make(map[Vertex]*ChannelHop),
	}

	// We'll populate the next hop map for the _source_ node with the
	// information for the first hop so the mapping is sound.
	route.nextHopMap[sourceVertex] = pathEdges[0]

	pathLength := len(pathEdges)
	for i := pathLength - 1; i >= 0; i-- {
		edge := pathEdges[i]

		// First, we'll update both the node and channel index, to
		// indicate that this Vertex, and outgoing channel link are
		// present within this route.
		v := Vertex(edge.Node.PubKeyBytes)
		route.nodeIndex[v] = struct{}{}
		route.chanIndex[edge.ChannelID] = struct{}{}

		// If this isn't a direct payment, and this isn't the edge to
		// the last hop in the route, then we'll also populate the
		// nextHop map to allow easy route traversal by callers.
		if len(pathEdges) > 1 && i != len(pathEdges)-1 {
			route.nextHopMap[v] = route.Hops[i+1].Channel
		}

		// Now we'll start to calculate the items within the per-hop
		// payload for the hop this edge is leading to. This hop will
		// be called the 'current hop'.

		// If it is the last hop, then the hop payload will contain
		// the exact amount. In BOLT #4: Onion Routing
		// Protocol / "Payload for the Last Node", this is detailed.
		amtToForward := amtToSend

		// Fee is not part of the hop payload, but only used for
		// reporting through RPC. Set to zero for the final hop.
		fee := lnwire.MilliSatoshi(0)

		// If the current hop isn't the last hop, then add enough funds
		// to pay for transit over the next link.
		if i != len(pathEdges)-1 {
			// We'll grab the per-hop payload of the next hop (the
			// hop _after_ the hop this edge leads to) in the
			// route so we can calculate fees properly.
			nextHop := route.Hops[i+1]

			// The amount that the current hop needs to forward is
			// based on how much the next hop forwards plus the fee
			// that needs to be paid to the next hop.
			amtToForward = nextHop.AmtToForward + nextHop.Fee

			// The fee that needs to be paid to the current hop is
			// based on the amount that this hop needs to forward
			// and its policy for the outgoing channel. This policy
			// is stored as part of the incoming channel of
			// the next hop.
			fee = computeFee(amtToForward, nextHop.Channel.ChannelEdgePolicy)
		}

		// Now we create the hop struct for the current hop.
		currentHop := &Hop{
			Channel:      edge,
			AmtToForward: amtToForward,
			Fee:          fee,
		}

		// Accumulate all fees.
		route.TotalFees += currentHop.Fee

		// Invalidate this route if its total fees exceed our fee limit.
		if route.TotalFees > feeLimit {
			err := fmt.Sprintf("total route fees exceeded fee "+
				"limit of %v", feeLimit)
			return nil, newErrf(ErrFeeLimitExceeded, err)
		}

		// As a sanity check, we ensure that the incoming channel has
		// enough capacity to carry the required amount which
		// includes the fee dictated at each hop. Make the comparison
		// in msat to prevent rounding errors.
		if currentHop.AmtToForward+fee > lnwire.NewMSatFromSatoshis(
			currentHop.Channel.Capacity) {

			err := fmt.Sprintf("channel graph has insufficient "+
				"capacity for the payment: need %v, have %v",
				currentHop.AmtToForward.ToSatoshis(),
				currentHop.Channel.Capacity)

			return nil, newErrf(ErrInsufficientCapacity, err)
		}

		// If this is the last hop, then for verification purposes, the
		// value of the outgoing time-lock should be _exactly_ the
		// absolute time out they'd expect in the HTLC.
		if i == len(pathEdges)-1 {
			// As this is the last hop, we'll use the specified
			// final CLTV delta value instead of the value from the
			// last link in the route.
			route.TotalTimeLock += uint32(finalCLTVDelta)

			currentHop.OutgoingTimeLock = currentHeight + uint32(finalCLTVDelta)
		} else {
			// Next, increment the total timelock of the entire
			// route such that each hops time lock increases as we
			// walk backwards in the route, using the delta of the
			// previous hop.
			delta := uint32(pathEdges[i+1].TimeLockDelta)
			route.TotalTimeLock += delta

			// Otherwise, the value of the outgoing time-lock will
			// be the value of the time-lock for the _outgoing_
			// HTLC, so we factor in their specified grace period
			// (time lock delta).
			currentHop.OutgoingTimeLock = route.TotalTimeLock - delta
		}

		route.Hops[i] = currentHop
	}

	// We'll then make a second run through our route in order to set up
	// our prev hop mapping.
	for _, hop := range route.Hops {
		vertex := Vertex(hop.Channel.Node.PubKeyBytes)
		route.prevHopMap[vertex] = hop.Channel
	}

	// The total amount required for this route will be the value
	// that the first hop needs to forward plus the fee that
	// the first hop charges for this. Note that the sender of the
	// payment is not a hop in the route.
	route.TotalAmount = route.Hops[0].AmtToForward + route.Hops[0].Fee

	return route, nil
}

// Vertex is a simple alias for the serialization of a compressed Bitcoin
// public key.
type Vertex [33]byte

// NewVertex returns a new Vertex given a public key.
func NewVertex(pub *btcec.PublicKey) Vertex {
	var v Vertex
	copy(v[:], pub.SerializeCompressed())
	return v
}

// String returns a human readable version of the Vertex which is the
// hex-encoding of the serialized compressed public key.
func (v Vertex) String() string {
	return fmt.Sprintf("%x", v[:])
}

// edgeWithPrev is a helper struct used in path finding that couples an
// directional edge with the node's ID in the opposite direction.
type edgeWithPrev struct {
	edge     *ChannelHop
	prevNode [33]byte
}

// edgeWeight computes the weight of an edge. This value is used when searching
// for the shortest path within the channel graph between two nodes. Weight is
// is the fee itself plus a time lock penalty added to it. This benefits
// channels with shorter time lock deltas and shorter (hops) routes in general.
// RiskFactor controls the influence of time lock on route selection. This is
// currently a fixed value, but might be configurable in the future.
func edgeWeight(amt lnwire.MilliSatoshi, e *channeldb.ChannelEdgePolicy) int64 {
	// First, we'll compute the "pure" fee through this hop. We say pure,
	// as this may not be what's ultimately paid as fees are properly
	// calculated backwards, while we're going in the reverse direction.
	pureFee := int64(computeFee(amt, e))

	// timeLockPenalty is the penalty for the time lock delta of this channel.
	// It is controlled by RiskFactorBillionths and scales proportional
	// to the amount that will pass through channel. Rationale is that it if
	// a twice as large amount gets locked up, it is twice as bad.
	timeLockPenalty := int64(amt) * int64(e.TimeLockDelta) * RiskFactorBillionths / 1000000000

	return pureFee + timeLockPenalty
}

// findPath attempts to find a path from the source node within the
// ChannelGraph to the target node that's capable of supporting a payment of
// `amt` value. The current approach implemented is modified version of
// Dijkstra's algorithm to find a single shortest path between the source node
// and the destination. The distance metric used for edges is related to the
// time-lock+fee costs along a particular edge. If a path is found, this
// function returns a slice of ChannelHop structs which encoded the chosen path
// from the target to the source.
func findPath(tx *bolt.Tx, graph *channeldb.ChannelGraph,
	additionalEdges map[Vertex][]*channeldb.ChannelEdgePolicy,
	sourceNode *channeldb.LightningNode, target *btcec.PublicKey,
	ignoredNodes map[Vertex]struct{}, ignoredEdges map[uint64]struct{},
	amt lnwire.MilliSatoshi,
	bandwidthHints map[uint64]lnwire.MilliSatoshi) ([]*ChannelHop, error) {

	var err error
	if tx == nil {
		tx, err = graph.Database().Begin(false)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
	}

	// First we'll initialize an empty heap which'll help us to quickly
	// locate the next edge we should visit next during our graph
	// traversal.
	var nodeHeap distanceHeap

	// For each node in the graph, we create an entry in the distance
	// map for the node set with a distance of "infinity".
	distance := make(map[Vertex]nodeWithDist)
	if err := graph.ForEachNode(tx, func(_ *bolt.Tx, node *channeldb.LightningNode) error {
		// TODO(roasbeef): with larger graph can just use disk seeks
		// with a visited map
		distance[Vertex(node.PubKeyBytes)] = nodeWithDist{
			dist: infinity,
			node: node,
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// We'll also include all the nodes found within the additional edges
	// that are not known to us yet in the distance map.
	for vertex := range additionalEdges {
		node := &channeldb.LightningNode{PubKeyBytes: vertex}
		distance[vertex] = nodeWithDist{
			dist: infinity,
			node: node,
		}
	}

	// We can't always assume that the end destination is publicly
	// advertised to the network and included in the graph.ForEachNode call
	// above, so we'll manually include the target node.
	targetVertex := NewVertex(target)
	targetNode := &channeldb.LightningNode{PubKeyBytes: targetVertex}
	distance[targetVertex] = nodeWithDist{
		dist: infinity,
		node: targetNode,
	}

	// We'll use this map as a series of "previous" hop pointers. So to get
	// to `Vertex` we'll take the edge that it's mapped to within `prev`.
	prev := make(map[Vertex]edgeWithPrev)

	// processEdge is a helper closure that will be used to make sure edges
	// satisfy our specific requirements.
	processEdge := func(edge *channeldb.ChannelEdgePolicy,
		bandwidth lnwire.MilliSatoshi, pivot Vertex) {

		v := Vertex(edge.Node.PubKeyBytes)

		// If the edge is currently disabled, then we'll stop here, as
		// we shouldn't attempt to route through it.
		edgeFlags := lnwire.ChanUpdateFlag(edge.Flags)
		if edgeFlags&lnwire.ChanUpdateDisabled != 0 {
			return
		}

		// If this vertex or edge has been black listed, then we'll skip
		// exploring this edge.
		if _, ok := ignoredNodes[v]; ok {
			return
		}
		if _, ok := ignoredEdges[edge.ChannelID]; ok {
			return
		}

		// Compute the tentative distance to this new channel/edge which
		// is the distance to our pivot node plus the weight of this
		// edge. Takes into account for self routing.
		var tempDist int64
		if distance[pivot].dist == infinity {
			tempDist = 1
		} else {
			tempDist = distance[pivot].dist + edgeWeight(amt, edge)
		}

		// If this new tentative distance is better than the current
		// best known distance to this node, then we record the new
		// better distance, and also populate our "next hop" map with
		// this edge. We'll also shave off irrelevant edges by adding
		// the sufficient capacity of an edge and clearing their
		// min-htlc amount to our relaxation condition.
		if tempDist < distance[v].dist && bandwidth >= amt &&
			amt >= edge.MinHTLC && edge.TimeLockDelta != 0 {

			distance[v] = nodeWithDist{
				dist: tempDist,
				node: edge.Node,
			}

			prev[v] = edgeWithPrev{
				edge: &ChannelHop{
					ChannelEdgePolicy: edge,
					Capacity:          bandwidth.ToSatoshis(),
				},
				prevNode: pivot,
			}

			// Add this new node to our heap as we'd like to further
			// explore down this edge.
			heap.Push(&nodeHeap, distance[v])

			// In the event of self routing and next node.dist is less than
			// current node dist, then we know there is a potential path back to source.
		} else if targetNode.PubKeyBytes == sourceNode.PubKeyBytes && tempDist >= distance[v].dist {

			// First we adds nodes and edges in the current to pass to the 'from middle to source'
			// pathFind iteration as "ignored" to prevent loops.
			tempIgnoredEdges := make(map[uint64]struct{})
			tempIgnoredNodes := make(map[Vertex]struct{})
			for x := range ignoredNodes {
				tempIgnoredNodes[x] = ignoredNodes[x]
			}
			for x := range ignoredEdges {
				tempIgnoredEdges[x] = ignoredEdges[x]
			}

			prevNode := pivot
			for prevNode != Vertex(sourceNode.PubKeyBytes) {
				// Add the current hop to the list of path edges then walk
				// backwards from this hop via the prev pointer for this hop
				// within the prevHop map.
				tempIgnoredEdges[prev[prevNode].edge.ChannelID] = struct{}{}
				tempIgnoredNodes[prevNode] = struct{}{}

				prevNode = Vertex(prev[prevNode].prevNode)
			}

			// Next we invert the bandwidth hints, as we need to know balances from the point of
			// view of the non-source node.
			inverseBandwidthHints := make(map[uint64]lnwire.MilliSatoshi)
			err = sourceNode.ForEachChannel(tx, func(tx *bolt.Tx,
				edgeInfo *channeldb.ChannelEdgeInfo,
				outEdge, inEdge *channeldb.ChannelEdgePolicy) error {

				inverseBandwidthHints[edgeInfo.ChannelID] = lnwire.NewMSatFromSatoshis(edgeInfo.Capacity) -
					bandwidthHints[edgeInfo.ChannelID]

				return nil
			})
			if err != nil {
				return
			}

			currentNode := &channeldb.LightningNode{PubKeyBytes: pivot}
			pathFromMiddle, err := findPath(
				tx, graph, nil, currentNode, target, tempIgnoredNodes, tempIgnoredEdges,
				amt, inverseBandwidthHints,
			)
			if err != nil {
				return
			}
			// Adds all edges found in PathFromMiddle to prev map
			prev[Vertex(pathFromMiddle[0].Node.PubKeyBytes)] = edgeWithPrev{
				edge: &ChannelHop{
					ChannelEdgePolicy: pathFromMiddle[0].ChannelEdgePolicy,
					Capacity:          pathFromMiddle[0].Capacity,
				},
				prevNode: pivot,
			}
			numEdges := len(pathFromMiddle)
			for i := 0; i < numEdges-1; i++ {
				prev[Vertex(pathFromMiddle[i+1].Node.PubKeyBytes)] = edgeWithPrev{
					edge: &ChannelHop{
						ChannelEdgePolicy: pathFromMiddle[i+1].ChannelEdgePolicy,
						Capacity:          pathFromMiddle[i+1].Capacity,
					},
					prevNode: pathFromMiddle[i].Node.PubKeyBytes,
				}
			}
		}
	}

	// TODO(roasbeef): also add path caching
	//  * similar to route caching, but doesn't factor in the amount

	// To start, we add the source of our path finding attempt to the
	// distance map with a distance of 0. This indicates our starting
	// point in the graph traversal.
	sourceVertex := Vertex(sourceNode.PubKeyBytes)
	distance[sourceVertex] = nodeWithDist{
		dist: 0,
		node: sourceNode,
	}

	// To start, our source node will the sole item within our distance
	// heap.
	heap.Push(&nodeHeap, distance[sourceVertex])

	for nodeHeap.Len() != 0 {
		// Fetch the node within the smallest distance from our source
		// from the heap.
		partialPath := heap.Pop(&nodeHeap).(nodeWithDist)
		bestNode := partialPath.node

		// If we found a full path back to self in an inner loop, we exit early.
		if _, ok := prev[sourceVertex]; ok {
			break
		}
		// If we've reached our target (or we don't have any outgoing
		// edges), then we're done here and can exit the graph
		// traversal early.
		if bestNode.PubKeyBytes == targetNode.PubKeyBytes {
			// In the event that we're sending payments to ourselves,
			// we don't want to give up when starting at the source,
			// thinking the shortest path is zero.
			if distance[targetVertex].dist == 0 &&
				sourceNode.PubKeyBytes == targetNode.PubKeyBytes {
				distance[sourceVertex] = nodeWithDist{
					dist: infinity,
					node: sourceNode,
				}
			} else {
				break
			}
		}

		// Now that we've found the next potential step to take we'll
		// examine all the outgoing edge (channels) from this node to
		// further our graph traversal.
		pivot := Vertex(bestNode.PubKeyBytes)
		err := bestNode.ForEachChannel(tx, func(tx *bolt.Tx,
			edgeInfo *channeldb.ChannelEdgeInfo,
			outEdge, _ *channeldb.ChannelEdgePolicy) error {

			// Doesn't process edges where Prev node and next node are the same
			// Necessary when source = destination and always beneficial.
			if pivot != Vertex(sourceNode.PubKeyBytes) && prev[pivot].prevNode == Vertex(outEdge.Node.PubKeyBytes) {
				return nil
			}

			// We'll query the lower layer to see if we can obtain
			// any more up to date information concerning the
			// bandwidth of this edge.
			edgeBandwidth, ok := bandwidthHints[edgeInfo.ChannelID]
			if !ok {
				// If we don't have a hint for this edge, then
				// we'll just use the known Capacity as the
				// available bandwidth.
				edgeBandwidth = lnwire.NewMSatFromSatoshis(
					edgeInfo.Capacity,
				)
			}

			processEdge(outEdge, edgeBandwidth, pivot)

			// TODO(roasbeef): return min HTLC as error in end?

			return nil
		})
		if err != nil {
			return nil, err
		}

		// Then, we'll examine all the additional edges from the node
		// we're currently visiting. Since we don't know the capacity
		// of the private channel, we'll assume it was selected as a
		// routing hint due to having enough capacity for the payment
		// and use the payment amount as its capacity.
		for _, edge := range additionalEdges[bestNode.PubKeyBytes] {
			processEdge(edge, amt, pivot)
		}
	}

	// If the target node isn't found in the prev hop map, then a path
	// doesn't exist, so we terminate in an error.
	if _, ok := prev[NewVertex(target)]; !ok {
		return nil, newErrf(ErrNoPathFound, "unable to find a path to "+
			"destination")
	}

	// If the potential route if below the max hop limit, then we'll use
	// the prevHop map to unravel the path. We end up with a list of edges
	// in the reverse direction which we'll use to properly calculate the
	// timelock and fee values.
	pathEdges := make([]*ChannelHop, 0, len(prev))
	prevNode := NewVertex(target)

	// In the event of self routing and path is found, processes first step
	// through prevHop map, and deletes previous hop of source to prevent
	// infinite loops. Required for routing to self. This allows the necessary
	// loop self back to self, while preventing an infinite loop.
	if sourceNode.PubKeyBytes == targetNode.PubKeyBytes {
		pathEdges = append(pathEdges, prev[prevNode].edge)

		prevNode = Vertex(prev[prevNode].prevNode)
		delete(prev, sourceVertex)
	}

	for prevNode != sourceVertex { // TODO(roasbeef): assumes no cycles
		// Add the current hop to the limit of path edges then walk
		// backwards from this hop via the prev pointer for this hop
		// within the prevHop map.
		pathEdges = append(pathEdges, prev[prevNode].edge)

		prevNode = Vertex(prev[prevNode].prevNode)
	}

	// The route is invalid if it spans more than 20 hops. The current
	// Sphinx (onion routing) implementation can only encode up to 20 hops
	// as the entire packet is fixed size. If this route is more than 20
	// hops, then it's invalid.
	numEdges := len(pathEdges)
	if numEdges > HopLimit {
		return nil, newErr(ErrMaxHopsExceeded, "potential path has "+
			"too many hops")
	}

	// As our traversal of the prev map above walked backwards from the
	// target to the source in the route, we need to reverse it before
	// returning the final route.
	for i := 0; i < numEdges/2; i++ {
		pathEdges[i], pathEdges[numEdges-i-1] = pathEdges[numEdges-i-1], pathEdges[i]
	}

	return pathEdges, nil
}

// findPaths implements a k-shortest paths algorithm to find all the reachable
// paths between the passed source and target. The algorithm will continue to
// traverse the graph until all possible candidate paths have been depleted.
// This function implements a modified version of Yen's. To find each path
// itself, we utilize our modified version of Dijkstra's found above. When
// examining possible spur and root paths, rather than removing edges or
// Vertexes from the graph, we instead utilize a Vertex+edge black-list that
// will be ignored by our modified Dijkstra's algorithm. With this approach, we
// make our inner path finding algorithm aware of our k-shortest paths
// algorithm, rather than attempting to use an unmodified path finding
// algorithm in a block box manner.
func findPaths(tx *bolt.Tx, graph *channeldb.ChannelGraph,
	source *channeldb.LightningNode, target *btcec.PublicKey,
	amt lnwire.MilliSatoshi, numPaths uint32,
	bandwidthHints map[uint64]lnwire.MilliSatoshi) ([][]*ChannelHop, error) {

	ignoredEdges := make(map[uint64]struct{})
	ignoredVertexes := make(map[Vertex]struct{})

	// TODO(roasbeef): modifying ordering within heap to eliminate final
	// sorting step?
	var (
		shortestPaths  [][]*ChannelHop
		candidatePaths pathHeap
	)

	// First we'll find a single shortest path from the source (our
	// selfNode) to the target destination that's capable of carrying amt
	// satoshis along the path before fees are calculated.
	startingPath, err := findPath(
		tx, graph, nil, source, target, ignoredVertexes, ignoredEdges,
		amt, bandwidthHints,
	)
	if err != nil {
		log.Errorf("Unable to find path: %v", err)
		return nil, err
	}

	// Manually insert a "self" edge emanating from ourselves. This
	// self-edge is required in order for the path finding algorithm to
	// function properly.
	firstPath := make([]*ChannelHop, 0, len(startingPath)+1)
	firstPath = append(firstPath, &ChannelHop{
		ChannelEdgePolicy: &channeldb.ChannelEdgePolicy{
			Node: source,
		},
	})
	firstPath = append(firstPath, startingPath...)

	shortestPaths = append(shortestPaths, firstPath)

	// While we still have candidate paths to explore we'll keep exploring
	// the sub-graphs created to find the next k-th shortest path.
	for k := uint32(1); k < numPaths; k++ {
		prevShortest := shortestPaths[k-1]

		// We'll examine each edge in the previous iteration's shortest
		// path in order to find path deviations from each node in the
		// path.
		for i := 0; i < len(prevShortest)-1; i++ {
			// These two maps will mark the edges and Vertexes
			// we'll exclude from the next path finding attempt.
			// These are required to ensure the paths are unique
			// and loopless.
			ignoredEdges = make(map[uint64]struct{})
			ignoredVertexes = make(map[Vertex]struct{})

			// Our spur node is the i-th node in the prior shortest
			// path, and our root path will be all nodes in the
			// path leading up to our spurNode.
			spurNode := prevShortest[i].Node
			rootPath := prevShortest[:i+1]

			// Before we kickoff our next path finding iteration,
			// we'll find all the edges we need to ignore in this
			// next round. This ensures that we create a new unique
			// path.
			for _, path := range shortestPaths {
				// If our current rootPath is a prefix of this
				// shortest path, then we'll remove the edge
				// directly _after_ our spur node from the
				// graph so we don't repeat paths.
				if len(path) > i+1 && isSamePath(rootPath, path[:i+1]) {
					ignoredEdges[path[i+1].ChannelID] = struct{}{}
				}
			}

			// Next we'll remove all entries in the root path that
			// aren't the current spur node from the graph. This
			// ensures we don't create a path with loops.
			for _, hop := range rootPath {
				node := hop.Node.PubKeyBytes
				if node == spurNode.PubKeyBytes {
					continue
				}

				ignoredVertexes[Vertex(node)] = struct{}{}
			}

			// With the edges that are part of our root path, and
			// the Vertexes (other than the spur path) within the
			// root path removed, we'll attempt to find another
			// shortest path from the spur node to the destination.
			spurPath, err := findPath(
				tx, graph, nil, spurNode, target,
				ignoredVertexes, ignoredEdges, amt,
				bandwidthHints,
			)

			// If we weren't able to find a path, we'll continue to
			// the next round.
			if IsError(err, ErrNoPathFound) {
				continue
			} else if err != nil {
				return nil, err
			}

			// Create the new combined path by concatenating the
			// rootPath to the spurPath.
			newPathLen := len(rootPath) + len(spurPath)
			newPath := path{
				hops: make([]*ChannelHop, 0, newPathLen),
				dist: newPathLen,
			}
			newPath.hops = append(newPath.hops, rootPath...)
			newPath.hops = append(newPath.hops, spurPath...)

			// TODO(roasbeef): add and consult path finger print

			// We'll now add this newPath to the heap of candidate
			// shortest paths.
			heap.Push(&candidatePaths, newPath)
		}

		// If our min-heap of candidate paths is empty, then we can
		// exit early.
		if candidatePaths.Len() == 0 {
			break
		}

		// To conclude this latest iteration, we'll take the shortest
		// path in our set of candidate paths and add it to our
		// shortestPaths list as the *next* shortest path.
		nextShortestPath := heap.Pop(&candidatePaths).(path).hops
		shortestPaths = append(shortestPaths, nextShortestPath)
	}

	return shortestPaths, nil
}
