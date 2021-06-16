// +build kvdb_etcd

package etcd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func reverseKVs(a []KV) []KV {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}

	return a
}

func TestPutToEmpty(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	txQueue := NewCommitQueue(ctx)
	defer func() {
		cancel()
		f.Cleanup()
		txQueue.Wait()
	}()

	db, err := newEtcdBackend(ctx, f.BackendConfig())
	require.NoError(t, err)

	apply := func(stm STM) error {
		stm.Put("123", "abc")
		return nil
	}

	callCount, err := RunSTM(db.cli, apply, txQueue)
	require.NoError(t, err)
	require.Equal(t, 1, callCount)

	require.Equal(t, "abc", f.Get("123"))
}

func TestGetPutDel(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	txQueue := NewCommitQueue(ctx)
	defer func() {
		cancel()
		f.Cleanup()
		txQueue.Wait()
	}()

	testKeyValues := []KV{
		{"a", "1"},
		{"b", "2"},
		{"c", "3"},
		{"d", "4"},
		{"e", "5"},
	}

	// Extra 2 => Get(x), Commit()
	expectedCallCount := len(testKeyValues) + 2

	for _, kv := range testKeyValues {
		f.Put(kv.key, kv.val)
	}

	db, err := newEtcdBackend(ctx, f.BackendConfig())
	require.NoError(t, err)

	apply := func(stm STM) error {
		// Get some non existing keys.
		v, err := stm.Get("")
		require.NoError(t, err)
		require.Nil(t, v)

		// Fetches: 1.
		v, err = stm.Get("x")
		require.NoError(t, err)
		require.Nil(t, v)

		// Get all existing keys. Fetches: len(testKeyValues)
		for _, kv := range testKeyValues {
			v, err = stm.Get(kv.key)
			require.NoError(t, err)
			require.Equal(t, []byte(kv.val), v)
		}

		// Overwrite, then delete an existing key.
		stm.Put("c", "6")

		v, err = stm.Get("c")
		require.NoError(t, err)
		require.Equal(t, []byte("6"), v)

		stm.Del("c")

		v, err = stm.Get("c")
		require.NoError(t, err)
		require.Nil(t, v)

		// Re-add the deleted key.
		stm.Put("c", "7")

		v, err = stm.Get("c")
		require.NoError(t, err)
		require.Equal(t, []byte("7"), v)

		// Add a new key.
		stm.Put("x", "x")

		v, err = stm.Get("x")
		require.NoError(t, err)
		require.Equal(t, []byte("x"), v)

		return nil
	}

	callCount, err := RunSTM(db.cli, apply, txQueue)
	require.NoError(t, err)
	require.Equal(t, expectedCallCount, callCount)

	require.Equal(t, "1", f.Get("a"))
	require.Equal(t, "2", f.Get("b"))
	require.Equal(t, "7", f.Get("c"))
	require.Equal(t, "4", f.Get("d"))
	require.Equal(t, "5", f.Get("e"))
	require.Equal(t, "x", f.Get("x"))
}

func TestFirstLastNextPrev(t *testing.T) {
	t.Parallel()

	testFirstLastNextPrev(t, nil, nil, 38)
	testFirstLastNextPrev(t, nil, []string{"k"}, 4)
	testFirstLastNextPrev(t, nil, []string{"k", "w"}, 2)
	testFirstLastNextPrev(t, []string{"kb"}, nil, 39)
	testFirstLastNextPrev(t, []string{"kb", "ke"}, nil, 39)
	testFirstLastNextPrev(t, []string{"kb", "ke", "w"}, []string{"k", "w"}, 2)
}

func testFirstLastNextPrev(t *testing.T, prefetchKeys []string,
	prefetchRange []string, expectedCallCount int) {

	f := NewEtcdTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	txQueue := NewCommitQueue(ctx)
	defer func() {
		cancel()
		f.Cleanup()
		txQueue.Wait()
	}()

	testKeyValues := []KV{
		{"kb", "1"},
		{"kc", "2"},
		{"kda", "3"},
		{"ke", "4"},
		{"w", "w"},
	}
	for _, kv := range testKeyValues {
		f.Put(kv.key, kv.val)
	}

	db, err := newEtcdBackend(ctx, f.BackendConfig())
	require.NoError(t, err)

	apply := func(stm STM) error {
		stm.Prefetch(prefetchKeys, prefetchRange)

		// First/Last on valid multi item interval.
		kv, err := stm.First("k")
		require.NoError(t, err)
		require.Equal(t, &KV{"kb", "1"}, kv)

		kv, err = stm.Last("k")
		require.NoError(t, err)
		require.Equal(t, &KV{"ke", "4"}, kv)

		// First/Last on single item interval.
		kv, err = stm.First("w")
		require.NoError(t, err)
		require.Equal(t, &KV{"w", "w"}, kv)

		kv, err = stm.Last("w")
		require.NoError(t, err)
		require.Equal(t, &KV{"w", "w"}, kv)

		// Next/Prev on start/end.
		kv, err = stm.Next("k", "ke")
		require.NoError(t, err)
		require.Nil(t, kv)

		kv, err = stm.Prev("k", "kb")
		require.NoError(t, err)
		require.Nil(t, kv)

		// Next/Prev in the middle.
		kv, err = stm.Next("k", "kc")
		require.NoError(t, err)
		require.Equal(t, &KV{"kda", "3"}, kv)

		kv, err = stm.Prev("k", "ke")
		require.NoError(t, err)
		require.Equal(t, &KV{"kda", "3"}, kv)

		// Delete first item, then add an item before the
		// deleted one. Check that First/Next will "jump"
		// over the deleted item and return the new first.
		stm.Del("kb")
		stm.Put("ka", "0")

		kv, err = stm.First("k")
		require.NoError(t, err)
		require.Equal(t, &KV{"ka", "0"}, kv)

		kv, err = stm.Prev("k", "kc")
		require.NoError(t, err)
		require.Equal(t, &KV{"ka", "0"}, kv)

		// Similarly test that a new end is returned if
		// the old end is deleted first.
		stm.Del("ke")
		stm.Put("kf", "5")

		kv, err = stm.Last("k")
		require.NoError(t, err)
		require.Equal(t, &KV{"kf", "5"}, kv)

		kv, err = stm.Next("k", "kda")
		require.NoError(t, err)
		require.Equal(t, &KV{"kf", "5"}, kv)

		// Overwrite one in the middle.
		stm.Put("kda", "6")

		kv, err = stm.Next("k", "kc")
		require.NoError(t, err)
		require.Equal(t, &KV{"kda", "6"}, kv)

		// Add three in the middle, then delete one.
		stm.Put("kdb", "7")
		stm.Put("kdc", "8")
		stm.Put("kdd", "9")
		stm.Del("kdc")

		// Check that stepping from first to last returns
		// the expected sequence.
		var kvs []KV

		curr, err := stm.First("k")
		require.NoError(t, err)

		for curr != nil {
			kvs = append(kvs, *curr)
			curr, err = stm.Next("k", curr.key)
			require.NoError(t, err)
		}

		expected := []KV{
			{"ka", "0"},
			{"kc", "2"},
			{"kda", "6"},
			{"kdb", "7"},
			{"kdd", "9"},
			{"kf", "5"},
		}
		require.Equal(t, expected, kvs)

		// Similarly check that stepping from last to first
		// returns the expected sequence.
		kvs = []KV{}

		curr, err = stm.Last("k")
		require.NoError(t, err)

		for curr != nil {
			kvs = append(kvs, *curr)
			curr, err = stm.Prev("k", curr.key)
			require.NoError(t, err)
		}

		expected = reverseKVs(expected)
		require.Equal(t, expected, kvs)

		return nil
	}

	callCount, err := RunSTM(db.cli, apply, txQueue)
	require.NoError(t, err)
	require.Equal(t, expectedCallCount, callCount)

	require.Equal(t, "0", f.Get("ka"))
	require.Equal(t, "2", f.Get("kc"))
	require.Equal(t, "6", f.Get("kda"))
	require.Equal(t, "7", f.Get("kdb"))
	require.Equal(t, "9", f.Get("kdd"))
	require.Equal(t, "5", f.Get("kf"))
	require.Equal(t, "w", f.Get("w"))
}

func TestCommitError(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	txQueue := NewCommitQueue(ctx)
	defer func() {
		cancel()
		f.Cleanup()
		txQueue.Wait()
	}()

	db, err := newEtcdBackend(ctx, f.BackendConfig())
	require.NoError(t, err)

	// Preset DB state.
	f.Put("123", "xyz")

	// Count the number of applies.
	cnt := 0

	apply := func(stm STM) error {
		// STM must have the key/value.
		val, err := stm.Get("123")
		require.NoError(t, err)

		if cnt == 0 {
			require.Equal(t, []byte("xyz"), val)

			// Put a conflicting key/value during the first apply.
			f.Put("123", "def")
		}

		// We'd expect to
		stm.Put("123", "abc")

		cnt++
		return nil
	}

	callCount, err := RunSTM(db.cli, apply, txQueue)
	require.NoError(t, err)
	require.Equal(t, 2, cnt)
	// Get() + 2 * Commit().
	require.Equal(t, 3, callCount)

	require.Equal(t, "abc", f.Get("123"))
}

func TestManualTxError(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	txQueue := NewCommitQueue(ctx)
	defer func() {
		cancel()
		f.Cleanup()
		txQueue.Wait()
	}()

	db, err := newEtcdBackend(ctx, f.BackendConfig())
	require.NoError(t, err)

	// Preset DB state.
	f.Put("123", "xyz")

	stm := NewSTM(db.cli, txQueue)

	val, err := stm.Get("123")
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), val)

	// Put a conflicting key/value.
	f.Put("123", "def")

	// Should still get the original version.
	val, err = stm.Get("123")
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), val)

	// Commit will fail with CommitError.
	err = stm.Commit()
	var e CommitError
	require.True(t, errors.As(err, &e))

	// We expect that the transacton indeed did not commit.
	require.Equal(t, "def", f.Get("123"))
}
