package channelnotifier

import (
	"sync/atomic"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/subscribe"
)

// ChannelNotifier is a subsystem which all active, inactive, and closed channel
// events pipe through. It takes subscriptions for its events, and whenever
// it receives a new event it notifies its subscribers over the proper channel.
type ChannelNotifier struct {
	started uint32
	stopped uint32

	ntfnServer *subscribe.Server

	chanDB *channeldb.DB
}

// OpenChannelEvent represents a new event where a channel goes from pending
// open to open.
type OpenChannelEvent struct {
	// Channel is the channel that has become open.
	Channel *channeldb.OpenChannel
}

// ActiveChannelEvent represents a new event where a channel becomes active.
type ActiveChannelEvent struct {
	// ChannelPoint is the channelpoint for the newly active channel.
	ChannelPoint *wire.OutPoint
}

// InactiveChannelEvent represents a new event where a channel becomes inactive.
type InactiveChannelEvent struct {
	// ChannelPoint is the channelpoint for the newly inactive channel.
	ChannelPoint *wire.OutPoint
}

// ClosedChannelEvent represents a new event where a channel becomes closed.
type ClosedChannelEvent struct {
	// CloseSummary is the summary of the channel close that has occurred.
	CloseSummary *channeldb.ChannelCloseSummary
}

// New creates a new channel notifier. The ChannelNotifier gets channel events
// from peers and from the chain arbitrator, and dispatches them to its
// clients.
func New(chanDB *channeldb.DB) *ChannelNotifier {
	return &ChannelNotifier{
		ntfnServer: subscribe.NewServer(),
		chanDB:     chanDB,
	}
}

// Start starts the ChannelNotifier and all goroutines it needs to carry out
// its task.
func (c *ChannelNotifier) Start() error {
	if !atomic.CompareAndSwapUint32(&c.started, 0, 1) {
		return nil
	}

	log.Tracef("ChannelNotifier starting")

	if err := c.ntfnServer.Start(); err != nil {
		return err
	}

	return nil
}

// Stop signals the notifier for a graceful shutdown.
func (c *ChannelNotifier) Stop() {
	if !atomic.CompareAndSwapUint32(&c.stopped, 0, 1) {
		return
	}

	c.ntfnServer.Stop()
}

// SubscribeChannelEvents returns a subscribe.Client that will receive updates
// any time the Server is made aware of a new event.
func (c *ChannelNotifier) SubscribeChannelEvents() (*subscribe.Client, error) {
	return c.ntfnServer.Subscribe()
}

// NotifyOpenChannelEvent notifies the channelEventNotifier goroutine that a
// channel has gone from pending open to open.
func (c *ChannelNotifier) NotifyOpenChannelEvent(chanPoint wire.OutPoint) {

	// Fetch the relevant channel from the database.
	channel, err := c.chanDB.FetchChannel(chanPoint)
	if err != nil {
		log.Warnf("Unable to fetch open channel from the db: %v", err)
	}

	// Send the open event to all channel event subscribers.
	event := OpenChannelEvent{Channel: channel}
	if err := c.ntfnServer.SendUpdate(event); err != nil {
		log.Warnf("Unable to send open channel update: %v", err)
	}
}

// NotifyClosedChannelEvent notifies the channelEventNotifier goroutine that a
// channel has closed.
func (c *ChannelNotifier) NotifyClosedChannelEvent(chanPoint wire.OutPoint) {
	// Fetch the relevant closed channel from the database.
	closeSummary, err := c.chanDB.FetchClosedChannel(&chanPoint)
	if err != nil {
		log.Warnf("Unable to fetch closed channel summary from "+
			"the db: %v", err)
	}

	// Send the closed event to all channel event subscribers.
	event := ClosedChannelEvent{CloseSummary: closeSummary}
	if err := c.ntfnServer.SendUpdate(event); err != nil {
		log.Warnf("Unable to send closed channel update: %v", err)
	}
}

// NotifyActiveChannelEvent notifies the channelEventNotifier goroutine that a
// channel is active.
func (c *ChannelNotifier) NotifyActiveChannelEvent(chanPoint wire.OutPoint) {
	event := ActiveChannelEvent{ChannelPoint: &chanPoint}
	if err := c.ntfnServer.SendUpdate(event); err != nil {
		log.Warnf("Unable to send active channel update: %v", err)
	}
}

// NotifyInactiveChannelEvent notifies the channelEventNotifier goroutine that
// a channel is inactive.
func (c *ChannelNotifier) NotifyInactiveChannelEvent(chanPoint wire.OutPoint) {
	event := InactiveChannelEvent{ChannelPoint: &chanPoint}
	if err := c.ntfnServer.SendUpdate(event); err != nil {
		log.Warnf("Unable to send inactive channel update: %v", err)
	}
}
