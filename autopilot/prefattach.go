package autopilot

import (
	"fmt"
	prand "math/rand"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
)

// ConstrainedPrefAttachment is an implementation of the AttachmentHeuristic
// interface that implement a constrained non-linear preferential attachment
// heuristic. This means that given a threshold to allocate to automatic
// channel establishment, the heuristic will attempt to favor connecting to
// nodes which already have a set amount of links, selected by sampling from a
// power law distribution. The attachment ins non-linear in that it favors
// nodes with a higher in-degree but less so that regular linear preferential
// attachment. As a result, this creates smaller and less clusters than regular
// linear preferential attachment.
//
// TODO(roasbeef): BA, with k=-3
type ConstrainedPrefAttachment struct {
	minChanSize btcutil.Amount
	maxChanSize btcutil.Amount

	chanLimit uint16

	threshold float64
}

// NewConstrainedPrefAttachment creates a new instance of a
// ConstrainedPrefAttachment heuristics given bounds on allowed channel sizes,
// and an allocation amount which is interpreted as a percentage of funds that
// is to be committed to channels at all times.
func NewConstrainedPrefAttachment(minChanSize, maxChanSize btcutil.Amount,
	chanLimit uint16, allocation float64) *ConstrainedPrefAttachment {

	prand.Seed(time.Now().Unix())

	return &ConstrainedPrefAttachment{
		minChanSize: minChanSize,
		chanLimit:   chanLimit,
		maxChanSize: maxChanSize,
		threshold:   allocation,
	}
}

// A compile time assertion to ensure ConstrainedPrefAttachment meets the
// AttachmentHeuristic interface.
var _ AttachmentHeuristic = (*ConstrainedPrefAttachment)(nil)

// NeedMoreChans is a predicate that should return true if, given the passed
// parameters, and its internal state, more channels should be opened within
// the channel graph. If the heuristic decides that we do indeed need more
// channels, then the second argument returned will represent the amount of
// additional funds to be used towards creating channels.
//
// NOTE: This is a part of the AttachmentHeuristic interface.
func (p *ConstrainedPrefAttachment) NeedMoreChans(channels []Channel,
	funds btcutil.Amount) (btcutil.Amount, uint32, bool) {

	// If we're already over our maximum allowed number of channels, then
	// we'll instruct the controller not to create any more channels.
	if len(channels) >= int(p.chanLimit) {
		return 0, 0, false
	}

	// The number of additional channels that should be opened is the
	// difference between the channel limit, and the number of channels we
	// already have open.
	numAdditionalChans := uint32(p.chanLimit) - uint32(len(channels))

	// First, we'll tally up the total amount of funds that are currently
	// present within the set of active channels.
	var totalChanAllocation btcutil.Amount
	for _, channel := range channels {
		totalChanAllocation += channel.Capacity
	}

	// With this value known, we'll now compute the total amount of fund
	// allocated across regular utxo's and channel utxo's.
	totalFunds := funds + totalChanAllocation

	// Once the total amount has been computed, we then calculate the
	// fraction of funds currently allocated to channels.
	fundsFraction := float64(totalChanAllocation) / float64(totalFunds)

	// If this fraction is below our threshold, then we'll return true, to
	// indicate the controller should call Select to obtain a candidate set
	// of channels to attempt to open.
	needMore := fundsFraction < p.threshold
	if !needMore {
		return 0, 0, false
	}

	// Now that we know we need more funds, we'll compute the amount of
	// additional funds we should allocate towards channels.
	targetAllocation := btcutil.Amount(float64(totalFunds) * p.threshold)
	fundsAvailable := targetAllocation - totalChanAllocation
	return fundsAvailable, numAdditionalChans, true
}

// NodeID is a simple type that holds an EC public key serialized in compressed
// format.
type NodeID [33]byte

// NewNodeID creates a new nodeID from a passed public key.
func NewNodeID(pub *btcec.PublicKey) NodeID {
	var n NodeID
	copy(n[:], pub.SerializeCompressed())
	return n
}

// shuffleCandidates shuffles the set of candidate nodes for preferential
// attachment in order to break any ordering already enforced by the sorted
// order of the public key for each node. To shuffle the set of candidates, we
// use a version of the Fisher–Yates shuffle algorithm.
func shuffleCandidates(candidates []Node) []Node {
	shuffledNodes := make([]Node, len(candidates))
	perm := prand.Perm(len(candidates))

	for i, v := range perm {
		shuffledNodes[v] = candidates[i]
	}

	return shuffledNodes
}

// Select returns a candidate set of attachment directives that should be
// executed based on the current internal state, the state of the channel
// graph, the set of nodes we should exclude, and the amount of funds
// available. The heuristic employed by this method is one that attempts to
// promote a scale-free network globally, via local attachment preferences for
// new nodes joining the network with an amount of available funds to be
// allocated to channels. Specifically, we consider the degree of each node
// (and the flow in/out of the node available via its open channels) and
// utilize the Barabási–Albert model to drive our recommended attachment
// heuristics. If implemented globally for each new participant, this results
// in a channel graph that is scale-free and follows a power law distribution
// with k=-3.
//
// NOTE: This is a part of the AttachmentHeuristic interface.
func (p *ConstrainedPrefAttachment) Select(self *btcec.PublicKey, g ChannelGraph,
	fundsAvailable btcutil.Amount, numNewChans uint32,
	skipNodes map[NodeID]struct{}) ([]AttachmentDirective, error) {

	// TODO(roasbeef): rename?

	var directives []AttachmentDirective

	if fundsAvailable < p.minChanSize {
		return directives, nil
	}

	// We'll continue our attachment loop until we've exhausted the current
	// amount of available funds.
	visited := make(map[NodeID]struct{})
	for i := uint32(0); i < numNewChans; i++ {
		// selectionSlice will be used to randomly select a node
		// according to a power law distribution. For each connected
		// edge, we'll add an instance of the node to this slice. Thus,
		// for a given node, the probability that we'll attach to it
		// is: k_i / sum(k_j), where k_i is the degree of the target
		// node, and k_j is the degree of all other nodes i != j. This
		// implements the classic Barabási–Albert model for
		// preferential attachment.
		var selectionSlice []Node

		// For each node, and each channel that the node has, we'll add
		// an instance of that node to the selection slice above.
		// This'll slice where the frequency of each node is equivalent
		// to the number of channels that connect to it.
		//
		// TODO(roasbeef): add noise to make adversarially resistant?
		if err := g.ForEachNode(func(node Node) error {
			nID := NewNodeID(node.PubKey())

			// Once a node has already been attached to, we'll
			// ensure that it isn't factored into any further
			// decisions within this round.
			if _, ok := visited[nID]; ok {
				return nil
			}

			// If we come across ourselves, them we'll continue in
			// order to avoid attempting to make a channel with
			// ourselves.
			if node.PubKey().IsEqual(self) {
				return nil
			}

			// Additionally, if this node is in the backlist, then
			// we'll skip it.
			if _, ok := skipNodes[nID]; ok {
				return nil
			}

			// For each active channel the node has, we'll add an
			// additional channel to the selection slice to
			// increase their weight.
			var numEnabledChans int
			var totalChans int
			if err := node.ForEachChannel(func(channel ChannelEdge) error {
				if !channel.Disabled {
					numEnabledChans++
				}
				totalChans++
				return nil
			}); err != nil {
				return err
			}

			// Compute the fraction of channels that are reported as
			// enabled for this node. As an arbitrary threshold, if
			// more than half the channels are disabled we'll assume
			// the node is unreliable.
			enabledPercent := float64(numEnabledChans) /
				float64(totalChans)
			if enabledPercent < 0.5 {
				return nil
			}

			// Otherwise, we will determine the node's weight as the
			// fraction of enabled chan times the number of enabled
			// channels. This penalizes a node with N enabled
			// channels more heavily if it also has a large number
			// of disabled channels. A different node with N enabled
			// channels but none disabled will receive a higher
			// score.
			selectionWeight := int(
				enabledPercent * float64(numEnabledChans),
			)

			// Add the node to our selection slice according to the
			// computed selection weight.
			for i := 0; i < selectionWeight; i++ {
				selectionSlice = append(selectionSlice, node)
			}

			return nil
		}); err != nil {
			return nil, err
		}

		// If no nodes at all were accumulated, then we'll exit early
		// as there are no eligible candidates.
		if len(selectionSlice) == 0 {
			break
		}

		// Given our selection slice, we'll now generate a random index
		// into this slice. The node we select will be recommended by
		// us to create a channel to.
		candidates := shuffleCandidates(selectionSlice)
		selectedIndex := prand.Int31n(int32(len(candidates)))
		selectedNode := candidates[selectedIndex]

		// TODO(roasbeef): cap on num channels to same participant?

		// With the node selected, we'll add this (node, amount) tuple
		// to out set of recommended directives.
		pub := selectedNode.PubKey()
		directives = append(directives, AttachmentDirective{
			// TODO(roasbeef): need curve?
			PeerKey: &btcec.PublicKey{
				X: pub.X,
				Y: pub.Y,
			},
			Addrs: selectedNode.Addrs(),
		})

		// With the node selected, we'll add it to the set of visited
		// nodes to avoid attaching to it again.
		visited[NewNodeID(selectedNode.PubKey())] = struct{}{}
	}

	numSelectedNodes := int64(len(directives))
	switch {
	// If we have enough available funds to distribute the maximum channel
	// size for each of the selected peers to attach to, then we'll
	// allocate the maximum amount to each peer.
	case int64(fundsAvailable) >= numSelectedNodes*int64(p.maxChanSize):
		for i := 0; i < int(numSelectedNodes); i++ {
			directives[i].ChanAmt = p.maxChanSize
		}

		return directives, nil

	// Otherwise, we'll greedily allocate our funds to the channels
	// successively until we run out of available funds, or can't create a
	// channel above the min channel size.
	case int64(fundsAvailable) < numSelectedNodes*int64(p.maxChanSize):
		i := 0
		for fundsAvailable > p.minChanSize {
			// We'll attempt to allocate the max channel size
			// initially. If we don't have enough funds to do this,
			// then we'll allocate the remainder of the funds
			// available to the channel.
			delta := p.maxChanSize
			if fundsAvailable-delta < 0 {
				delta = fundsAvailable
			}

			directives[i].ChanAmt = delta

			fundsAvailable -= delta
			i++
		}

		// We'll slice the initial set of directives to properly
		// reflect the amount of funds we were able to allocate.
		return directives[:i:i], nil

	default:
		return nil, fmt.Errorf("err")
	}
}
