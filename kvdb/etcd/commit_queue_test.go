// +build kvdb_etcd

package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCommitQueue tests that non-conflicting transactions commit concurrently,
// while conflicting transactions are queued up.
func TestCommitQueue(t *testing.T) {
	// The duration of each commit.
	const commitDuration = time.Millisecond * 500
	const numCommits = 4

	var wg sync.WaitGroup
	commits := make([]string, numCommits)
	idx := int32(-1)

	commit := func(tag string, sleep bool) func() {
		return func() {
			defer wg.Done()

			// Update our log of commit order. Avoid blocking
			// by preallocating the commit log and increasing
			// the log index atomically.
			i := atomic.AddInt32(&idx, 1)
			commits[i] = tag

			if sleep {
				time.Sleep(commitDuration)
			}
		}
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	q := NewCommitQueue(ctx)
	defer q.Wait()
	defer cancel()

	wg.Add(numCommits)
	t1 := time.Now()

	// Tx1: reads: key1, key2, writes: key3, conflict: none
	q.Add(
		commit("free", true),
		[]string{"key1", "key2"},
		[]string{"key3"},
	)
	// Tx2: reads: key1, key2, writes: key3, conflict: Tx1
	q.Add(
		commit("blocked1", false),
		[]string{"key1", "key2"},
		[]string{"key3"},
	)
	// Tx3: reads: key1, writes: key4, conflict: none
	q.Add(
		commit("free", true),
		[]string{"key1", "key2"},
		[]string{"key4"},
	)
	// Tx4: reads: key2, writes: key4 conflict: Tx3
	q.Add(
		commit("blocked2", false),
		[]string{"key2"},
		[]string{"key4"},
	)

	// Wait for all commits.
	wg.Wait()
	t2 := time.Now()

	// Expected total execution time: delta.
	// 2 * commitDuration <= delta < 3 * commitDuration
	delta := t2.Sub(t1)
	require.LessOrEqual(t, int64(commitDuration*2), int64(delta))
	require.Greater(t, int64(commitDuration*3), int64(delta))

	// Expect that the non-conflicting "free" transactions are executed
	// before the blocking ones, and the blocking ones are executed in
	// the order of addition.
	require.Equal(t,
		[]string{"free", "free", "blocked1", "blocked2"},
		commits,
	)
}
