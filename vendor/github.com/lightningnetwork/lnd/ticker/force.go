package ticker

import (
	"sync"
	"sync/atomic"
	"time"
)

// Force implements the Ticker interface, and provides a method of force-feeding
// ticks, even while paused.
type Force struct {
	isActive uint32 // used atomically

	// Force is used to force-feed a ticks into the ticker. Useful for
	// debugging when trying to wake an event.
	Force chan time.Time

	ticker <-chan time.Time
	skip   chan struct{}

	wg   sync.WaitGroup
	quit chan struct{}
}

// A compile-time constraint to ensure Force satisfies the Ticker interface.
var _ Ticker = (*Force)(nil)

// NewForce returns a Force ticker, used for testing and debugging. It supports
// the ability to force-feed events that get output by the
func NewForce(interval time.Duration) *Force {
	m := &Force{
		ticker: time.NewTicker(interval).C,
		Force:  make(chan time.Time),
		skip:   make(chan struct{}),
		quit:   make(chan struct{}),
	}

	// Proxy the real ticks to our Force channel if we are active.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case t := <-m.ticker:
				if atomic.LoadUint32(&m.isActive) == 0 {
					continue
				}

				select {
				case m.Force <- t:
				case <-m.skip:
				case <-m.quit:
					return
				}

			case <-m.quit:
				return
			}
		}
	}()

	return m
}

// Ticks returns a receive-only channel that delivers times at the ticker's
// prescribed interval when active. Force-fed ticks can be delivered at any
// time.
//
// NOTE: Part of the Ticker interface.
func (m *Force) Ticks() <-chan time.Time {
	return m.Force
}

// Resume starts underlying time.Ticker and causes the ticker to begin
// delivering scheduled events.
//
// NOTE: Part of the Ticker interface.
func (m *Force) Resume() {
	atomic.StoreUint32(&m.isActive, 1)
}

// Pause suspends the underlying ticker, such that Ticks() stops signaling at
// regular intervals.
//
// NOTE: Part of the Ticker interface.
func (m *Force) Pause() {
	atomic.StoreUint32(&m.isActive, 0)

	// If the ticker fired and read isActive as true, it may still send the
	// tick. We'll try to send on the skip channel to drop it.
	select {
	case m.skip <- struct{}{}:
	default:
	}
}

// Stop suspends the underlying ticker, such that Ticks() stops signaling at
// regular intervals, and permanently frees up any resources.
//
// NOTE: Part of the Ticker interface.
func (m *Force) Stop() {
	m.Pause()
	close(m.quit)
	m.wg.Wait()
}
