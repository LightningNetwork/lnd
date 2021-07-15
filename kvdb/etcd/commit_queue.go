// +build kvdb_etcd

package etcd

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// commitQueue is a simple execution queue to manage conflicts for transactions
// and thereby reduce the number of times conflicting transactions need to be
// retried. When a new transaction is added to the queue, we first upgrade the
// read/write counts in the queue's own accounting to decide whether the new
// transaction has any conflicting dependencies. If the transaction does not
// conflict with any other, then it is comitted immediately, otherwise it'll be
// queued up for later exection.
// The algorithm is described in: http://www.cs.umd.edu/~abadi/papers/vll-vldb13.pdf
type commitQueue struct {
	ctx       context.Context
	mx        sync.Mutex
	readerMap map[string]int
	writerMap map[string]int

	queue     *list.List
	queueMx   sync.Mutex
	queueCond *sync.Cond

	shutdown chan struct{}
}

type commitQueueTxn struct {
	commitLoop func()
	blocked    bool
	rset       []string
	wset       []string
}

// NewCommitQueue creates a new commit queue, with the passed abort context.
func NewCommitQueue(ctx context.Context) *commitQueue {
	q := &commitQueue{
		ctx:       ctx,
		readerMap: make(map[string]int),
		writerMap: make(map[string]int),
		queue:     list.New(),
		shutdown:  make(chan struct{}),
	}
	q.queueCond = sync.NewCond(&q.queueMx)

	// Start the queue consumer loop.
	go q.mainLoop()

	return q
}

// Wait waits for the queue to stop (after the queue context has been canceled).
func (c *commitQueue) Wait() {
	c.signalUntilShutdown()
}

// Add increases lock counts and queues up tx commit closure for execution.
// Transactions that don't have any conflicts are executed immediately by
// "downgrading" the count mutex to allow concurrency.
func (c *commitQueue) Add(commitLoop func(), rset []string, wset []string) {
	c.mx.Lock()
	blocked := false

	// Mark as blocked if there's any writer changing any of the keys in
	// the read set. Do not increment the reader counts yet as we'll need to
	// use the original reader counts when scanning through the write set.
	for _, key := range rset {
		if c.writerMap[key] > 0 {
			blocked = true
			break
		}
	}

	// Mark as blocked if there's any writer or reader for any of the keys
	// in the write set.
	for _, key := range wset {
		blocked = blocked || c.readerMap[key] > 0 || c.writerMap[key] > 0

		// Increment the writer count.
		c.writerMap[key] += 1
	}

	// Finally we can increment the reader counts for keys in the read set.
	for _, key := range rset {
		c.readerMap[key] += 1
	}

	c.queueCond.L.Lock()
	c.queue.PushBack(&commitQueueTxn{
		commitLoop: commitLoop,
		blocked:    blocked,
		rset:       rset,
		wset:       wset,
	})
	c.queueCond.L.Unlock()

	c.mx.Unlock()

	c.queueCond.Signal()
}

// done decreases lock counts of the keys in the read/write sets.
func (c *commitQueue) done(rset []string, wset []string) {
	c.mx.Lock()
	defer c.mx.Unlock()

	for _, key := range rset {
		c.readerMap[key] -= 1
		if c.readerMap[key] == 0 {
			delete(c.readerMap, key)
		}
	}

	for _, key := range wset {
		c.writerMap[key] -= 1
		if c.writerMap[key] == 0 {
			delete(c.writerMap, key)
		}
	}
}

// mainLoop executes queued transaction commits for transactions that have
// dependencies. The queue ensures that the top element doesn't conflict with
// any other transactions and therefore can be executed freely.
func (c *commitQueue) mainLoop() {
	defer close(c.shutdown)

	for {
		// Wait until there are no unblocked transactions being
		// executed, and for there to be at least one blocked
		// transaction in our queue.
		c.queueCond.L.Lock()
		for c.queue.Front() == nil {
			c.queueCond.Wait()

			// Check the exit condition before looping again.
			select {
			case <-c.ctx.Done():
				c.queueCond.L.Unlock()
				return
			default:
			}
		}

		// Now collect all txns until we find the next blocking one.
		// These shouldn't conflict (if the precollected read/write
		// keys sets don't grow), meaning we can safely commit them
		// in parallel.
		work := make([]*commitQueueTxn, 1)
		e := c.queue.Front()
		work[0] = c.queue.Remove(e).(*commitQueueTxn)

		for {
			e := c.queue.Front()
			if e == nil {
				break
			}

			next := e.Value.(*commitQueueTxn)
			if !next.blocked {
				work = append(work, next)
				c.queue.Remove(e)
			} else {
				// We found the next blocking txn which means
				// the block of work needs to be cut here.
				break
			}
		}

		c.queueCond.L.Unlock()

		// Check if we need to exit before continuing.
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		var wg sync.WaitGroup
		wg.Add(len(work))

		// Fire up N goroutines where each will run its commit loop
		// and then clean up the reader/writer maps.
		for _, w := range work {
			w := w
			go func() {
				defer wg.Done()
				w.commitLoop()

				// We can safely cleanup here as done only
				// holds the main mutex.
				c.done(w.rset, w.wset)
			}()
		}

		wg.Wait()

		// Check if we need to exit before continuing.
		select {
		case <-c.ctx.Done():
			return
		default:
		}
	}
}

// signalUntilShutdown strobes the queue's condition variable to ensure the
// mainLoop reliably unblocks to check for the exit condition.
func (c *commitQueue) signalUntilShutdown() {
	for {
		select {
		case <-time.After(time.Millisecond):
			c.queueCond.Signal()
		case <-c.shutdown:
			return
		}
	}
}
