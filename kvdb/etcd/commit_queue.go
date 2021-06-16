// +build kvdb_etcd

package etcd

import (
	"context"
	"sync"
)

// commitQueueSize is the maximum number of commits we let to queue up. All
// remaining commits will block on commitQueue.Add().
const commitQueueSize = 100

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

	commitMutex sync.RWMutex
	queue       chan (func())
	wg          sync.WaitGroup
}

// NewCommitQueue creates a new commit queue, with the passed abort context.
func NewCommitQueue(ctx context.Context) *commitQueue {
	q := &commitQueue{
		ctx:       ctx,
		readerMap: make(map[string]int),
		writerMap: make(map[string]int),
		queue:     make(chan func(), commitQueueSize),
	}

	// Start the queue consumer loop.
	q.wg.Add(1)
	go q.mainLoop()

	return q
}

// Wait waits for the queue to stop (after the queue context has been canceled).
func (c *commitQueue) Wait() {
	c.wg.Wait()
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

	if blocked {
		// Add the transaction to the queue if conflicts with an already
		// queued one.
		c.mx.Unlock()

		select {
		case c.queue <- commitLoop:
		case <-c.ctx.Done():
		}
	} else {
		// To make sure we don't add a new tx to the queue that depends
		// on this "unblocked" tx, grab the commitMutex before lifting
		// the mutex guarding the lock maps.
		c.commitMutex.RLock()
		c.mx.Unlock()

		// At this point we're safe to execute the "unblocked" tx, as
		// we cannot execute blocked tx that may have been read from the
		// queue until the commitMutex is held.
		commitLoop()

		c.commitMutex.RUnlock()
	}
}

// Done decreases lock counts of the keys in the read/write sets.
func (c *commitQueue) Done(rset []string, wset []string) {
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
	defer c.wg.Done()

	for {
		select {
		case top := <-c.queue:
			// Execute the next blocked transaction. As it is
			// the top element in the queue it means that it doesn't
			// depend on any other transactions anymore.
			c.commitMutex.Lock()
			top()
			c.commitMutex.Unlock()

		case <-c.ctx.Done():
			return
		}
	}
}
