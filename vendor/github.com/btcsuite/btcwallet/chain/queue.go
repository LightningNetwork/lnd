package chain

import (
	"container/list"
)

// ConcurrentQueue is a concurrent-safe FIFO queue with unbounded capacity.
// Clients interact with the queue by pushing items into the in channel and
// popping items from the out channel. There is a goroutine that manages moving
// items from the in channel to the out channel in the correct order that must
// be started by calling Start().
type ConcurrentQueue struct {
	chanIn   chan interface{}
	chanOut  chan interface{}
	quit     chan struct{}
	overflow *list.List
}

// NewConcurrentQueue constructs a ConcurrentQueue. The bufferSize parameter is
// the capacity of the output channel. When the size of the queue is below this
// threshold, pushes do not incur the overhead of the less efficient overflow
// structure.
func NewConcurrentQueue(bufferSize int) *ConcurrentQueue {
	return &ConcurrentQueue{
		chanIn:   make(chan interface{}),
		chanOut:  make(chan interface{}, bufferSize),
		quit:     make(chan struct{}),
		overflow: list.New(),
	}
}

// ChanIn returns a channel that can be used to push new items into the queue.
func (cq *ConcurrentQueue) ChanIn() chan<- interface{} {
	return cq.chanIn
}

// ChanOut returns a channel that can be used to pop items from the queue.
func (cq *ConcurrentQueue) ChanOut() <-chan interface{} {
	return cq.chanOut
}

// Start begins a goroutine that manages moving items from the in channel to
// the out channel. The queue tries to move items directly to the out channel
// minimize overhead, but if the out channel is full it pushes items to an
// overflow queue. This must be called before using the queue.
func (cq *ConcurrentQueue) Start() {
	go func() {
		for {
			nextElement := cq.overflow.Front()
			if nextElement == nil {
				// The overflow queue is empty, so incoming
				// items can be pushed directly to the output
				// channel. However, if output channel is full,
				// we'll push to the overflow list instead.
				select {
				case item := <-cq.chanIn:
					select {
					case cq.chanOut <- item:
					case <-cq.quit:
						return
					default:
						cq.overflow.PushBack(item)
					}
				case <-cq.quit:
					return
				}
			} else {
				// The overflow queue is not empty, so any new
				// items get pushed to the back to preserve
				// order.
				select {
				case item := <-cq.chanIn:
					cq.overflow.PushBack(item)
				case cq.chanOut <- nextElement.Value:
					cq.overflow.Remove(nextElement)
				case <-cq.quit:
					return
				}
			}
		}
	}()
}

// Stop ends the goroutine that moves items from the in channel to the out
// channel.
func (cq *ConcurrentQueue) Stop() {
	close(cq.quit)
}
