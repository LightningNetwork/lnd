package queue

import (
	"container/list"
	"sync"
)

// ConcurrentQueue is a concurrent-safe FIFO queue with unbounded capacity.
// Clients interact with the queue by pushing items into the in channel and
// popping items from the out channel. There is a goroutine that manages moving
// items from the in channel to the out channel in the correct order that must
// be started by calling Start().
type ConcurrentQueue struct {
	started sync.Once
	stopped sync.Once

	chanIn   chan interface{}
	chanOut  chan interface{}
	overflow *list.List

	wg   sync.WaitGroup
	quit chan struct{}
}

// NewConcurrentQueue constructs a ConcurrentQueue. The bufferSize parameter is
// the capacity of the output channel. When the size of the queue is below this
// threshold, pushes do not incur the overhead of the less efficient overflow
// structure.
func NewConcurrentQueue(bufferSize int) *ConcurrentQueue {
	return &ConcurrentQueue{
		chanIn:   make(chan interface{}),
		chanOut:  make(chan interface{}, bufferSize),
		overflow: list.New(),
		quit:     make(chan struct{}),
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

// Start begins a goroutine that manages moving items from the in channel to the
// out channel. The queue tries to move items directly to the out channel
// minimize overhead, but if the out channel is full it pushes items to an
// overflow queue. This must be called before using the queue.
func (cq *ConcurrentQueue) Start() {
	cq.started.Do(cq.start)
}

func (cq *ConcurrentQueue) start() {
	cq.wg.Add(1)
	go func() {
		defer cq.wg.Done()

	readLoop:
		for {
			nextElement := cq.overflow.Front()
			if nextElement == nil {
				// Overflow queue is empty so incoming items can be pushed
				// directly to the output channel. If output channel is full
				// though, push to overflow.
				select {
				case item, ok := <-cq.chanIn:
					if !ok {
						break readLoop
					}
					select {
					case cq.chanOut <- item:
						// Optimistically push directly to chanOut
					default:
						cq.overflow.PushBack(item)
					}
				case <-cq.quit:
					return
				}
			} else {
				// Overflow queue is not empty, so any new items get pushed to
				// the back to preserve order.
				select {
				case item, ok := <-cq.chanIn:
					if !ok {
						break readLoop
					}
					cq.overflow.PushBack(item)
				case cq.chanOut <- nextElement.Value:
					cq.overflow.Remove(nextElement)
				case <-cq.quit:
					return
				}
			}
		}

		// Incoming channel has been closed. Empty overflow queue into
		// the outgoing channel.
		nextElement := cq.overflow.Front()
		for nextElement != nil {
			select {
			case cq.chanOut <- nextElement.Value:
				cq.overflow.Remove(nextElement)
			case <-cq.quit:
				return
			}
			nextElement = cq.overflow.Front()
		}

		// Close outgoing channel.
		close(cq.chanOut)
	}()
}

// Stop ends the goroutine that moves items from the in channel to the out
// channel. This does not clear the queue state, so the queue can be restarted
// without dropping items.
func (cq *ConcurrentQueue) Stop() {
	cq.stopped.Do(func() {
		close(cq.quit)
		cq.wg.Wait()
	})
}
