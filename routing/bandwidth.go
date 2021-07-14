package routing

import (
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
)

// bandwidthHints is provides hints about the currently available balance in
// our channels.
type bandwidthHints interface {
	// availableChanBandwidth returns the total available bandwidth for a
	// channel and a bool indicating whether the channel hint was found.
	// If the channel is unavailable, a zero amount is returned.
	availableChanBandwidth(channelID uint64) (lnwire.MilliSatoshi, bool)
}

// linkBandwidthQuery is the function signature used to query the link for the
// currently available bandwidth for an edge.
type linkBandwidthQuery func(*channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi

// bandwidthManager is an implementation of the bandwidthHints interface which
// uses the linkBandwidthQuery provided to query the link for our latest local
// channel balances.
type bandwidthManager struct {
	getBandwidth linkBandwidthQuery
	localChans   map[uint64]*channeldb.ChannelEdgeInfo
}

// newBandwidthManager creates a bandwidth manager for the source node provided
// which is used to obtain hints from the lower layer w.r.t the available
// bandwidth of edges on the network. Currently, we'll only obtain bandwidth
// hints for the edges we directly have open ourselves. Obtaining these hints
// allows us to reduce the number of extraneous attempts as we can skip channels
// that are inactive, or just don't have enough bandwidth to carry the payment.
func newBandwidthManager(sourceNode *channeldb.LightningNode,
	linkQuery linkBandwidthQuery) (*bandwidthManager, error) {

	manager := &bandwidthManager{
		getBandwidth: linkQuery,
		localChans:   make(map[uint64]*channeldb.ChannelEdgeInfo),
	}

	// First, we'll collect the set of outbound edges from the target
	// source node and add them to our bandwidth manager's map of channels.
	err := sourceNode.ForEachChannel(nil, func(tx kvdb.RTx,
		edgeInfo *channeldb.ChannelEdgeInfo,
		_, _ *channeldb.ChannelEdgePolicy) error {

		manager.localChans[edgeInfo.ChannelID] = edgeInfo

		return nil
	})
	if err != nil {
		return nil, err
	}

	return manager, nil
}

// availableChanBandwidth returns the total available bandwidth for a channel
// and a bool indicating whether the channel hint was found. If the channel is
// unavailable, a zero amount is returned.
func (b *bandwidthManager) availableChanBandwidth(channelID uint64) (
	lnwire.MilliSatoshi, bool) {

	channel, ok := b.localChans[channelID]
	if !ok {
		return 0, false
	}

	return b.getBandwidth(channel), true
}
