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

	queueMu   sync.RWMutex
	queueCond *sync.Cond
	queue     *list.List
	freeCount uint32

	shutdown chan struct{}
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
	q.queueCond = sync.NewCond(&q.queueMu)

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
func (c *commitQueue) Add(commitLoop func(), rset readSet, wset writeSet) {
	c.mx.Lock()
	blocked := false

	// Mark as blocked if there's any writer changing any of the keys in
	// the read set. Do not increment the reader counts yet as we'll need to
	// use the original reader counts when scanning through the write set.
	for key := range rset {
		if c.writerMap[key] > 0 {
			blocked = true
			break
		}
	}

	// Mark as blocked if there's any writer or reader for any of the keys
	// in the write set.
	for key := range wset {
		blocked = blocked || c.readerMap[key] > 0 || c.writerMap[key] > 0

		// Increment the writer count.
		c.writerMap[key] += 1
	}

	// Finally we can increment the reader counts for keys in the read set.
	for key := range rset {
		c.readerMap[key] += 1
	}

	if blocked {
		// Add the transaction to the queue if it conflicts with an
		// already queued one. It is safe to do so outside the lock,
		// since this we know it will be executed serially.
		c.mx.Unlock()

		c.queueCond.L.Lock()
		c.queue.PushBack(commitLoop)
		c.queueCond.L.Unlock()
	} else {
		// To make sure we don't add a new tx to the queue that depends
		// on this "unblocked" tx. Increment our free counter before
		// unlocking so that the mainLoop stops pulling off blocked
		// transactions from the queue.

		c.queueCond.L.Lock()
		c.freeCount++
		c.queueCond.L.Unlock()

		c.mx.Unlock()

		// At this point it is safe to execute the "unblocked" tx, as no
		// blocked tx will be read from the queue until the freeCount is
		// decremented back to 0.
		go func() {
			commitLoop()

			c.queueCond.L.Lock()
			c.freeCount--
			c.queueCond.L.Unlock()
			c.queueCond.Signal()
		}()

	}
}

// Done decreases lock counts of the keys in the read/write sets.
func (c *commitQueue) Done(rset readSet, wset writeSet) {
	c.mx.Lock()
	defer c.mx.Unlock()

	for key := range rset {
		c.readerMap[key] -= 1
		if c.readerMap[key] == 0 {
			delete(c.readerMap, key)
		}
	}

	for key := range wset {
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
		for c.freeCount > 0 || c.queue.Front() == nil {
			c.queueCond.Wait()

			// Check the exit condition before looping again.
			select {
			case <-c.ctx.Done():
				c.queueCond.L.Unlock()
				return
			default:
			}
		}

		// Remove the top element from the queue, now that we know there
		// are no possible conflicts.
		e := c.queue.Front()
		top := c.queue.Remove(e).(func())
		c.queueCond.L.Unlock()

		// Check if we need to exit before continuing.
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Execute the next blocked transaction.
		top()

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
