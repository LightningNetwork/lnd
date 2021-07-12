package queue

import (
	"container/list"
	"time"

	"github.com/lightningnetwork/lnd/ticker"
)

// GCQueue is garbage collecting queue, which dynamically grows and contracts
// based on load. If the queue has items which have been returned, the queue
// will check every gcInterval amount of time to see if any elements are
// eligible to be released back to the runtime. Elements that have been in the
// queue for a duration of least expiryInterval will be released upon the next
// iteration of the garbage collection, thus the maximum amount of time an
// element remain in the queue is expiryInterval+gcInterval. The gc ticker will
// be disabled after all items in the queue have been taken or released to
// ensure that the GCQueue becomes quiescent, and imposes minimal overhead in
// the steady state.
type GCQueue struct {
	// takeBuffer coordinates the delivery of items taken from the queue
	// such that they are delivered to requesters.
	takeBuffer chan interface{}

	// returnBuffer coordinates the return of items back into the queue,
	// where they will be kept until retaken or released.
	returnBuffer chan interface{}

	// newItem is a constructor, used to generate new elements if none are
	// otherwise available for reuse.
	newItem func() interface{}

	// expiryInterval is the minimum amount of time an element will remain
	// in the queue before being released.
	expiryInterval time.Duration

	// recycleTicker is a resumable ticker used to trigger a sweep to
	// release elements that have been in the queue longer than
	// expiryInterval.
	recycleTicker ticker.Ticker

	// freeList maintains a list of gcQueueEntries, sorted in order of
	// increasing time of arrival.
	freeList *list.List

	quit chan struct{}
}

// NewGCQueue creates a new garbage collecting queue, which dynamically grows
// and contracts based on load. If the queue has items which have been returned,
// the queue will check every gcInterval amount of time to see if any elements
// are eligible to be released back to the runtime. Elements that have been in
// the queue for a duration of least expiryInterval will be released upon the
// next iteration of the garbage collection, thus the maximum amount of time an
// element remain in the queue is expiryInterval+gcInterval. The gc ticker will
// be disabled after all items in the queue have been taken or released to
// ensure that the GCQueue becomes quiescent, and imposes minimal overhead in
// the steady state. The returnQueueSize parameter is used to size the maximal
// number of items that can be returned without being dropped during large
// bursts in attempts to return items to the GCQUeue.
func NewGCQueue(newItem func() interface{}, returnQueueSize int,
	gcInterval, expiryInterval time.Duration) *GCQueue {

	q := &GCQueue{
		takeBuffer:     make(chan interface{}),
		returnBuffer:   make(chan interface{}, returnQueueSize),
		expiryInterval: expiryInterval,
		freeList:       list.New(),
		recycleTicker:  ticker.New(gcInterval),
		newItem:        newItem,
		quit:           make(chan struct{}),
	}

	go q.queueManager()

	return q
}

// Take returns either a recycled element from the queue, or creates a new item
// if none are available.
func (q *GCQueue) Take() interface{} {
	select {
	case item := <-q.takeBuffer:
		return item
	case <-time.After(time.Millisecond):
		return q.newItem()
	}
}

// Return adds the returned item to freelist if the queue's returnBuffer has
// available capacity. Under load, items may be dropped to ensure this method
// does not block.
func (q *GCQueue) Return(item interface{}) {
	select {
	case q.returnBuffer <- item:
	default:
	}
}

// gcQueueEntry is a tuple containing an interface{} and the time at which the
// item was added to the queue. The recorded time is used to determine when the
// entry becomes stale, and can be released if it has not already been taken.
type gcQueueEntry struct {
	item interface{}
	time time.Time
}

// queueManager maintains the free list of elements by popping the head of the
// queue when items are needed, and appending them to the end of the queue when
// items are returned. The queueManager will periodically attempt to release any
// items that have been in the queue longer than the expiry interval.
//
// NOTE: This method SHOULD be run as a goroutine.
func (q *GCQueue) queueManager() {
	for {
		// If the pool is empty, initialize a buffer pool to serve a
		// client that takes a buffer immediately. If this happens, this
		// is either:
		//   1) the first iteration of the loop,
		//   2) after all entries were garbage collected, or
		//   3) the freelist was emptied after the last entry was taken.
		//
		// In all of these cases, it is safe to pause the recycle ticker
		// since it will be resumed as soon an entry is returned to the
		// freelist.
		if q.freeList.Len() == 0 {
			q.freeList.PushBack(gcQueueEntry{
				item: q.newItem(),
				time: time.Now(),
			})

			q.recycleTicker.Pause()
		}

		next := q.freeList.Front()

		select {

		// If a client requests a new write buffer, deliver the buffer
		// at the head of the freelist to them.
		case q.takeBuffer <- next.Value.(gcQueueEntry).item:
			q.freeList.Remove(next)

		// If a client is returning a write buffer, add it to the free
		// list and resume the recycle ticker so that it can be cleared
		// if the entries are not quickly reused.
		case item := <-q.returnBuffer:
			// Add the returned buffer to the freelist, recording
			// the current time so we can determine when the entry
			// expires.
			q.freeList.PushBack(gcQueueEntry{
				item: item,
				time: time.Now(),
			})

			// Adding the buffer implies that we now have a non-zero
			// number of elements in the free list. Resume the
			// recycle ticker to cleanup any entries that go unused.
			q.recycleTicker.Resume()

		// If the recycle ticker fires, we will aggresively release any
		// write buffers in the freelist for which the expiryInterval
		// has elapsed since their insertion. If after doing so, no
		// elements remain, we will pause the recylce ticker.
		case <-q.recycleTicker.Ticks():
			// Since the insert time of all entries will be
			// monotonically increasing, iterate over elements and
			// remove all entries that have expired.
			var next *list.Element
			for e := q.freeList.Front(); e != nil; e = next {
				// Cache the next element, since it will become
				// unreachable from the current element if it is
				// removed.
				next = e.Next()
				entry := e.Value.(gcQueueEntry)

				// Use now - insertTime <= expiryInterval to
				// determine if this entry has not expired.
				if time.Since(entry.time) <= q.expiryInterval {
					// If this entry hasn't expired, then
					// all entries that follow will still be
					// valid.
					break
				}

				// Otherwise, remove the expired entry from the
				// linked-list.
				q.freeList.Remove(e)
				entry.item = nil
				e.Value = nil
			}
		}
	}
}
