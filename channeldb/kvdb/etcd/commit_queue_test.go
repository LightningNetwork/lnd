// +build kvdb_etcd

package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCommitQueue tests that non-conflicting transactions commit concurrently,
// while conflicting transactions are queued up.
func TestCommitQueue(t *testing.T) {
	const numCommits = 4
	var wg sync.WaitGroup
	commits := make([]string, numCommits)
	idx := int32(-1)

	commit := func(tag string, commit chan struct{},
		ready <-chan struct{}) func() {

		return func() {
			if commit != nil {
				close(commit)
			}
			defer wg.Done()

			// Update our log of commit order. Avoid blocking
			// by preallocating the commit log and increasing
			// the log index atomically.
			i := atomic.AddInt32(&idx, 1)
			commits[i] = tag

			if ready != nil {
				<-ready
			}
		}
	}

	// Helper function to create a read set from the passed keys.
	makeReadSet := func(keys []string) readSet {
		rs := make(map[string]stmGet)

		for _, key := range keys {
			rs[key] = stmGet{}
		}

		return rs
	}

	// Helper function to create a write set from the passed keys.
	makeWriteSet := func(keys []string) writeSet {
		ws := make(map[string]stmPut)

		for _, key := range keys {
			ws[key] = stmPut{}
		}

		return ws
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	q := NewCommitQueue(ctx)
	defer q.Wait()
	defer cancel()

	wg.Add(numCommits)

	ready := make(chan struct{})

	// Tx1: reads: key1, key2, writes: key3, conflict: none
	// Since we simulate that the txn takes a long time, we'll add in a
	// new goroutine and wait for the txn commit to start execution.
	q.Add(
		commit("free", nil, ready),
		makeReadSet([]string{"key1", "key2"}),
		makeWriteSet([]string{"key3"}),
	)

	// Tx2: reads: key1, key5, writes: key3, conflict: Tx1 (key3)
	// We don't expect queue add to block as this txn will queue up after
	// tx1.
	q.Add(
		commit("blocked1", nil, nil),
		makeReadSet([]string{"key1", "key2"}),
		makeWriteSet([]string{"key3"}),
	)

	// Tx3: reads: key1, key2, writes: key4, conflict: none
	// We expect this transaction to be reordered before blocked1, even
	// though it was added after since it it doesn't have any conflicts.
	q.Add(
		commit("free", nil, ready),
		makeReadSet([]string{"key1", "key2"}),
		makeWriteSet([]string{"key4"}),
	)

	// Tx4: reads: key2, writes: key4 conflicts: Tx3 (key4)
	// We don't expect queue add to block as this txn will queue up after
	// tx2.
	q.Add(
		commit("blocked2", nil, nil),
		makeReadSet([]string{"key2"}),
		makeWriteSet([]string{"key4"}),
	)

	// Allow Tx1 to continue with the commit.
	close(ready)

	// Wait for all commits.
	wg.Wait()

	// Expect that the non-conflicting "free" transactions are executed
	// before the conflicting ones, and the conflicting ones are executed in
	// the order of addition.
	require.Equal(t,
		[]string{"free", "free", "blocked1", "blocked2"},
		commits,
	)
}
