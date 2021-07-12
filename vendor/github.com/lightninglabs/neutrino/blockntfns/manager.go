package blockntfns

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/lightningnetwork/lnd/queue"
)

var (
	// ErrSubscriptionManagerStopped is an error returned when we attempt to
	// register a new block subscription but the manager has been stopped.
	ErrSubscriptionManagerStopped = errors.New("subscription manager was " +
		"stopped")
)

// newSubscription is an internal message used within the SubscriptionManager to
// denote a new client's intent to receive block notifications.
type newSubscription struct {
	canceled sync.Once

	id uint64

	ntfnChan  chan BlockNtfn
	ntfnQueue *queue.ConcurrentQueue

	bestHeight uint32
	errChan    chan error

	quit chan struct{}
	wg   sync.WaitGroup
}

func (s *newSubscription) cancel() {
	s.canceled.Do(func() {
		s.ntfnQueue.Stop()
		close(s.quit)
		s.wg.Wait()
		close(s.ntfnChan)
	})
}

// cancelSubscription is an internal message used within the SubscriptionManager
// to denote an existing client's intent to stop receiving block notifications.
type cancelSubscription struct {
	id uint64
}

// NotificationSource is an interface responsible for delivering block
// notifications of a chain.
type NotificationSource interface {
	// Notifications returns a channel through which the latest
	// notifications of the tip of the chain can be retrieved from.
	Notifications() <-chan BlockNtfn

	// NotificationsSinceHeight returns a backlog of block notifications
	// starting from the given height to the tip of the chain.
	//
	// TODO(wilmer): extend with best hash to track reorgs.
	NotificationsSinceHeight(uint32) ([]BlockNtfn, uint32, error)
}

// Subscription represents an intent to receive notifications about the latest
// block events in the chain. The notifications will be streamed through the
// Notifications channel. A Cancel closure is also included to indicate that the
// client no longer wishes to receive any notifications.
type Subscription struct {
	// Notifications is the channel through which block notifications will
	// be sent through.
	//
	// TODO(wilmer): make read-only chan once we remove
	// resetBlockReFetchTimer hack from rescan.
	Notifications chan BlockNtfn

	// Cancel is closure that can be invoked to cancel the client's desire
	// to receive notifications.
	Cancel func()
}

// SubscriptionManager is a system responsible for managing the delivery of
// block notifications for a chain at tip to multiple clients in an asynchronous
// manner.
type SubscriptionManager struct {
	subscriberCounter uint64 // to be used atomically

	started int32 // to be used atomically
	stopped int32 // to be used atomically

	subscribers map[uint64]*newSubscription

	newSubscriptions    chan *newSubscription
	cancelSubscriptions chan *cancelSubscription

	ntfnSource NotificationSource

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewSubscriptionManager creates a subscription manager backed by a
// NotificationSource.
func NewSubscriptionManager(ntfnSource NotificationSource) *SubscriptionManager {
	return &SubscriptionManager{
		subscribers:         make(map[uint64]*newSubscription),
		newSubscriptions:    make(chan *newSubscription),
		cancelSubscriptions: make(chan *cancelSubscription),
		ntfnSource:          ntfnSource,
		quit:                make(chan struct{}),
	}
}

// Start starts all the goroutines required for the SubscriptionManager to carry
// out its duties.
func (m *SubscriptionManager) Start() {
	if atomic.AddInt32(&m.started, 1) != 1 {
		return
	}

	log.Debug("Starting block notifications subscription manager")

	m.wg.Add(1)
	go m.subscriptionHandler()
}

// Stop stops all active goroutines required for the SubscriptionManager to
// carry out its duties.
func (m *SubscriptionManager) Stop() {
	if atomic.AddInt32(&m.stopped, 1) != 1 {
		return
	}

	log.Debug("Stopping block notifications subscription manager")

	close(m.quit)
	m.wg.Wait()

	var wg sync.WaitGroup
	wg.Add(len(m.subscribers))
	for _, subscriber := range m.subscribers {
		go func() {
			defer wg.Done()
			subscriber.cancel()
		}()
	}

	wg.Wait()
}

// subscriptionHandler is the main event handler of the SubscriptionManager.
// It's responsible for atomically handling notifications for new blocks and
// creating/removing client block subscriptions.
//
// NOTE: This must be run as a goroutine.
func (m *SubscriptionManager) subscriptionHandler() {
	defer m.wg.Done()

	for {
		select {
		// A new subscription request has been received from a client.
		case msg := <-m.newSubscriptions:
			msg.errChan <- m.handleNewSubscription(msg)

		// A request to cancel an existing subscription has been
		// received from a client.
		case msg := <-m.cancelSubscriptions:
			m.handleCancelSubscription(msg)

		// A new block notification for the tip of the chain has been
		// received from the backing NotificationSource.
		case ntfn, ok := <-m.ntfnSource.Notifications():
			if !ok {
				log.Warn("Block source is unable to deliver " +
					"new updates")
				return
			}

			m.notifySubscribers(ntfn)

		case <-m.quit:
			return
		}
	}
}

// NewSubscription creates a new block notification subscription for a client.
// The bestHeight parameter can be used by the client to indicate its best known
// state. A backlog of notifications from said point until the tip of the chain
// will be delivered upon the client's successful registration. When providing a
// bestHeight of 0, no backlog will be delivered.
//
// These notifications, along with the latest notifications of the chain, will
// be delivered through the Notifications channel within the Subscription
// returned. A Cancel closure is also provided, in the event that the client
// wishes to no longer receive any notifications.
func (m *SubscriptionManager) NewSubscription(bestHeight uint32) (*Subscription,
	error) {

	// We'll start by constructing the internal messages that the
	// subscription handler will use to register the new client.
	sub := &newSubscription{
		id:         atomic.AddUint64(&m.subscriberCounter, 1),
		ntfnChan:   make(chan BlockNtfn, 20),
		ntfnQueue:  queue.NewConcurrentQueue(20),
		bestHeight: bestHeight,
		errChan:    make(chan error, 1),
		quit:       make(chan struct{}),
	}

	// We'll start the notification queue now so that it is ready in the
	// event that a backlog of notifications is to be delivered.
	sub.ntfnQueue.Start()

	// We'll also start a goroutine that will attempt to consume
	// notifications from this queue by delivering them to the client
	// itself.
	sub.wg.Add(1)
	go func() {
		defer sub.wg.Done()

		for {
			select {
			case ntfn, ok := <-sub.ntfnQueue.ChanOut():
				if !ok {
					return
				}

				select {
				case sub.ntfnChan <- ntfn.(BlockNtfn):
				case <-sub.quit:
					return
				case <-m.quit:
					return
				}
			case <-sub.quit:
				return
			case <-m.quit:
				return
			}
		}
	}()

	// Now, we can deliver the notification to the subscription handler.
	select {
	case m.newSubscriptions <- sub:
	case <-m.quit:
		sub.ntfnQueue.Stop()
		return nil, ErrSubscriptionManagerStopped
	}

	// It's possible that the registration failed if we were unable to
	// deliver the backlog of notifications, so we'll make sure to handle
	// the error.
	select {
	case err := <-sub.errChan:
		if err != nil {
			sub.ntfnQueue.Stop()
			return nil, err
		}
	case <-m.quit:
		sub.ntfnQueue.Stop()
		return nil, ErrSubscriptionManagerStopped
	}

	// Finally, we can return to the client with its new subscription
	// successfully registered.
	return &Subscription{
		Notifications: sub.ntfnChan,
		Cancel: func() {
			m.cancelSubscription(sub)
		},
	}, nil
}

// handleNewSubscription handles a request to create a new block subscription.
func (m *SubscriptionManager) handleNewSubscription(sub *newSubscription) error {
	log.Infof("Registering block subscription: id=%d", sub.id)

	// We'll start by retrieving a backlog of notifications from the
	// client's best height.
	blocks, currentHeight, err := m.ntfnSource.NotificationsSinceHeight(
		sub.bestHeight,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve blocks since height=%d: "+
			"%v", sub.bestHeight, err)
	}

	// We'll then attempt to deliver these notifications.
	log.Debugf("Delivering backlog of block notifications: id=%d, "+
		"start_height=%d, end_height=%d", sub.id, sub.bestHeight,
		currentHeight)

	for _, block := range blocks {
		m.notifySubscriber(sub, block)
	}

	// With the notifications delivered, we can keep track of the new client
	// internally in order to deliver new block notifications about the
	// chain.
	m.subscribers[sub.id] = sub

	return nil
}

// cancelSubscription sends a request to the subscription handler to cancel an
// existing subscription.
func (m *SubscriptionManager) cancelSubscription(sub *newSubscription) {
	select {
	case m.cancelSubscriptions <- &cancelSubscription{sub.id}:
	case <-m.quit:
	}
}

// handleCancelSubscription handles a request to cancel an existing
// subscription.
func (m *SubscriptionManager) handleCancelSubscription(msg *cancelSubscription) {
	// First, we'll attempt to look up an existing susbcriber with the given
	// ID.
	sub, ok := m.subscribers[msg.id]
	if !ok {
		return
	}

	log.Infof("Canceling block subscription: id=%d", msg.id)

	// If there is one, we'll stop their internal queue to no longer deliver
	// notifications to them.
	delete(m.subscribers, msg.id)
	sub.cancel()
}

// notifySubscribers notifies all currently active subscribers about the block.
func (m *SubscriptionManager) notifySubscribers(ntfn BlockNtfn) {
	log.Tracef("Notifying %v", ntfn)

	for _, subscriber := range m.subscribers {
		m.notifySubscriber(subscriber, ntfn)
	}
}

// notifySubscriber notifies a single subscriber about the block.
func (m *SubscriptionManager) notifySubscriber(sub *newSubscription,
	block BlockNtfn) {

	select {
	case sub.ntfnQueue.ChanIn() <- block:
	case <-sub.quit:
	case <-m.quit:
		return
	}
}
