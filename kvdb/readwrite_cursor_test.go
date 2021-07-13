package kvdb

import (
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

func testReadCursorEmptyInterval(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		b, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, b)

		return nil
	}, func() {})
	require.NoError(t, err)

	err = View(db, func(tx walletdb.ReadTx) error {
		b := tx.ReadBucket([]byte("apple"))
		require.NotNil(t, b)

		cursor := b.ReadCursor()
		k, v := cursor.First()
		require.Nil(t, k)
		require.Nil(t, v)

		k, v = cursor.Next()
		require.Nil(t, k)
		require.Nil(t, v)

		k, v = cursor.Last()
		require.Nil(t, k)
		require.Nil(t, v)

		k, v = cursor.Prev()
		require.Nil(t, k)
		require.Nil(t, v)

		return nil
	}, func() {})
	require.NoError(t, err)
}

func testReadCursorNonEmptyInterval(t *testing.T, db walletdb.DB) {
	testKeyValues := []KV{
		{"b", "1"},
		{"c", "2"},
		{"da", "3"},
		{"e", "4"},
	}

	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		b, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, b)

		for _, kv := range testKeyValues {
			require.NoError(t, b.Put([]byte(kv.key), []byte(kv.val)))
		}
		return nil
	}, func() {})

	require.NoError(t, err)

	err = View(db, func(tx walletdb.ReadTx) error {
		b := tx.ReadBucket([]byte("apple"))
		require.NotNil(t, b)

		// Iterate from the front.
		var kvs []KV
		cursor := b.ReadCursor()
		k, v := cursor.First()

		for k != nil && v != nil {
			kvs = append(kvs, KV{string(k), string(v)})
			k, v = cursor.Next()
		}
		require.Equal(t, testKeyValues, kvs)

		// Iterate from the back.
		kvs = []KV{}
		k, v = cursor.Last()

		for k != nil && v != nil {
			kvs = append(kvs, KV{string(k), string(v)})
			k, v = cursor.Prev()
		}
		require.Equal(t, reverseKVs(testKeyValues), kvs)

		// Random access
		perm := []int{3, 0, 2, 1}
		for _, i := range perm {
			k, v := cursor.Seek([]byte(testKeyValues[i].key))
			require.Equal(t, []byte(testKeyValues[i].key), k)
			require.Equal(t, []byte(testKeyValues[i].val), v)
		}

		// Seek to nonexisting key.
		k, v = cursor.Seek(nil)
		require.Equal(t, "b", string(k))
		require.Equal(t, "1", string(v))

		k, v = cursor.Seek([]byte("x"))
		require.Nil(t, k)
		require.Nil(t, v)

		return nil
	}, func() {})

	require.NoError(t, err)
}

func testReadWriteCursor(t *testing.T, db walletdb.DB) {
	testKeyValues := []KV{
		{"b", "1"},
		{"c", "2"},
		{"da", "3"},
		{"e", "4"},
	}

	count := len(testKeyValues)

	// Pre-store the first half of the interval.
	require.NoError(t, Update(db, func(tx walletdb.ReadWriteTx) error {
		b, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, b)

		for i := 0; i < count/2; i++ {
			err = b.Put(
				[]byte(testKeyValues[i].key),
				[]byte(testKeyValues[i].val),
			)
			require.NoError(t, err)
		}
		return nil
	}, func() {}))

	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		b := tx.ReadWriteBucket([]byte("apple"))
		require.NotNil(t, b)

		// Store the second half of the interval.
		for i := count / 2; i < count; i++ {
			err := b.Put(
				[]byte(testKeyValues[i].key),
				[]byte(testKeyValues[i].val),
			)
			require.NoError(t, err)
		}

		cursor := b.ReadWriteCursor()

		// First on valid interval.
		fk, fv := cursor.First()
		require.Equal(t, []byte("b"), fk)
		require.Equal(t, []byte("1"), fv)

		// Prev(First()) = nil
		k, v := cursor.Prev()
		require.Nil(t, k)
		require.Nil(t, v)

		// Last on valid interval.
		lk, lv := cursor.Last()
		require.Equal(t, []byte("e"), lk)
		require.Equal(t, []byte("4"), lv)

		// Next(Last()) = nil
		k, v = cursor.Next()
		require.Nil(t, k)
		require.Nil(t, v)

		// Delete first item, then add an item before the
		// deleted one. Check that First/Next will "jump"
		// over the deleted item and return the new first.
		_, _ = cursor.First()
		require.NoError(t, cursor.Delete())
		require.NoError(t, b.Put([]byte("a"), []byte("0")))
		fk, fv = cursor.First()

		require.Equal(t, []byte("a"), fk)
		require.Equal(t, []byte("0"), fv)

		k, v = cursor.Next()
		require.Equal(t, []byte("c"), k)
		require.Equal(t, []byte("2"), v)

		// Similarly test that a new end is returned if
		// the old end is deleted first.
		_, _ = cursor.Last()
		require.NoError(t, cursor.Delete())
		require.NoError(t, b.Put([]byte("f"), []byte("5")))

		lk, lv = cursor.Last()
		require.Equal(t, []byte("f"), lk)
		require.Equal(t, []byte("5"), lv)

		k, v = cursor.Prev()
		require.Equal(t, []byte("da"), k)
		require.Equal(t, []byte("3"), v)

		// Overwrite k/v in the middle of the interval.
		require.NoError(t, b.Put([]byte("c"), []byte("3")))
		k, v = cursor.Prev()
		require.Equal(t, []byte("c"), k)
		require.Equal(t, []byte("3"), v)

		// Insert new key/values.
		require.NoError(t, b.Put([]byte("cx"), []byte("x")))
		require.NoError(t, b.Put([]byte("cy"), []byte("y")))

		k, v = cursor.Next()
		require.Equal(t, []byte("cx"), k)
		require.Equal(t, []byte("x"), v)

		k, v = cursor.Next()
		require.Equal(t, []byte("cy"), k)
		require.Equal(t, []byte("y"), v)

		expected := []KV{
			{"a", "0"},
			{"c", "3"},
			{"cx", "x"},
			{"cy", "y"},
			{"da", "3"},
			{"f", "5"},
		}

		// Iterate from the front.
		var kvs []KV
		k, v = cursor.First()

		for k != nil && v != nil {
			kvs = append(kvs, KV{string(k), string(v)})
			k, v = cursor.Next()
		}
		require.Equal(t, expected, kvs)

		// Iterate from the back.
		kvs = []KV{}
		k, v = cursor.Last()

		for k != nil && v != nil {
			kvs = append(kvs, KV{string(k), string(v)})
			k, v = cursor.Prev()
		}
		require.Equal(t, reverseKVs(expected), kvs)

		return nil
	}, func() {})

	require.NoError(t, err)
}

// testReadWriteCursorWithBucketAndValue tests that cursors are able to iterate
// over both bucket and value keys if both are present in the iterated bucket.
func testReadWriteCursorWithBucketAndValue(t *testing.T, db walletdb.DB) {

	// Pre-store the first half of the interval.
	require.NoError(t, Update(db, func(tx walletdb.ReadWriteTx) error {
		b, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, b)

		require.NoError(t, b.Put([]byte("key"), []byte("val")))

		b1, err := b.CreateBucket([]byte("banana"))
		require.NoError(t, err)
		require.NotNil(t, b1)

		b2, err := b.CreateBucket([]byte("pear"))
		require.NoError(t, err)
		require.NotNil(t, b2)

		return nil
	}, func() {}))

	err := View(db, func(tx walletdb.ReadTx) error {
		b := tx.ReadBucket([]byte("apple"))
		require.NotNil(t, b)

		cursor := b.ReadCursor()

		// First on valid interval.
		k, v := cursor.First()
		require.Equal(t, []byte("banana"), k)
		require.Nil(t, v)

		k, v = cursor.Next()
		require.Equal(t, []byte("key"), k)
		require.Equal(t, []byte("val"), v)

		k, v = cursor.Last()
		require.Equal(t, []byte("pear"), k)
		require.Nil(t, v)

		k, v = cursor.Seek([]byte("k"))
		require.Equal(t, []byte("key"), k)
		require.Equal(t, []byte("val"), v)

		k, v = cursor.Seek([]byte("banana"))
		require.Equal(t, []byte("banana"), k)
		require.Nil(t, v)

		k, v = cursor.Next()
		require.Equal(t, []byte("key"), k)
		require.Equal(t, []byte("val"), v)

		return nil
	}, func() {})

	require.NoError(t, err)
}
