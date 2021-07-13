package kvdb

import (
	"fmt"
	"math"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

func testBucketCreation(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		// empty bucket name
		b, err := tx.CreateTopLevelBucket(nil)
		require.Error(t, walletdb.ErrBucketNameRequired, err)
		require.Nil(t, b)

		// empty bucket name
		b, err = tx.CreateTopLevelBucket([]byte(""))
		require.Error(t, walletdb.ErrBucketNameRequired, err)
		require.Nil(t, b)

		// "apple"
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, apple)

		// Check bucket tx.
		require.Equal(t, tx, apple.Tx())

		// "apple" already created
		b, err = tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, b)

		// "apple/banana"
		banana, err := apple.CreateBucket([]byte("banana"))
		require.NoError(t, err)
		require.NotNil(t, banana)

		banana, err = apple.CreateBucketIfNotExists([]byte("banana"))
		require.NoError(t, err)
		require.NotNil(t, banana)

		// Try creating "apple/banana" again
		b, err = apple.CreateBucket([]byte("banana"))
		require.Error(t, walletdb.ErrBucketExists, err)
		require.Nil(t, b)

		// "apple/mango"
		mango, err := apple.CreateBucket([]byte("mango"))
		require.Nil(t, err)
		require.NotNil(t, mango)

		// "apple/banana/pear"
		pear, err := banana.CreateBucket([]byte("pear"))
		require.Nil(t, err)
		require.NotNil(t, pear)

		// empty bucket
		require.Nil(t, apple.NestedReadWriteBucket(nil))
		require.Nil(t, apple.NestedReadWriteBucket([]byte("")))

		// "apple/pear" doesn't exist
		require.Nil(t, apple.NestedReadWriteBucket([]byte("pear")))

		// "apple/banana" exits
		require.NotNil(t, apple.NestedReadWriteBucket([]byte("banana")))
		require.NotNil(t, apple.NestedReadBucket([]byte("banana")))
		return nil
	}, func() {})

	require.Nil(t, err)
}

func testBucketDeletion(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		// "apple"
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.Nil(t, err)
		require.NotNil(t, apple)

		// "apple/banana"
		banana, err := apple.CreateBucket([]byte("banana"))
		require.Nil(t, err)
		require.NotNil(t, banana)

		kvs := []KV{{"key1", "val1"}, {"key2", "val2"}, {"key3", "val3"}}

		for _, kv := range kvs {
			require.NoError(t, banana.Put([]byte(kv.key), []byte(kv.val)))
			require.Equal(t, []byte(kv.val), banana.Get([]byte(kv.key)))
		}

		// Delete a k/v from "apple/banana"
		require.NoError(t, banana.Delete([]byte("key2")))
		// Try getting/putting/deleting invalid k/v's.
		require.Nil(t, banana.Get(nil))
		require.Error(t, walletdb.ErrKeyRequired, banana.Put(nil, []byte("val")))
		require.Error(t, walletdb.ErrKeyRequired, banana.Delete(nil))

		// Try deleting a k/v that doesn't exist.
		require.NoError(t, banana.Delete([]byte("nokey")))

		// "apple/pear"
		pear, err := apple.CreateBucket([]byte("pear"))
		require.Nil(t, err)
		require.NotNil(t, pear)

		// Put some values into "apple/pear"
		for _, kv := range kvs {
			require.Nil(t, pear.Put([]byte(kv.key), []byte(kv.val)))
			require.Equal(t, []byte(kv.val), pear.Get([]byte(kv.key)))
		}

		// Create nested bucket "apple/pear/cherry"
		cherry, err := pear.CreateBucket([]byte("cherry"))
		require.Nil(t, err)
		require.NotNil(t, cherry)

		// Put some values into "apple/pear/cherry"
		for _, kv := range kvs {
			require.NoError(t, cherry.Put([]byte(kv.key), []byte(kv.val)))
		}

		// Read back values in "apple/pear/cherry" trough a read bucket.
		cherryReadBucket := pear.NestedReadBucket([]byte("cherry"))
		for _, kv := range kvs {
			require.Equal(
				t, []byte(kv.val),
				cherryReadBucket.Get([]byte(kv.key)),
			)
		}

		// Try deleting some invalid buckets.
		require.Error(t,
			walletdb.ErrBucketNameRequired, apple.DeleteNestedBucket(nil),
		)

		// Try deleting a non existing bucket.
		require.Error(
			t,
			walletdb.ErrBucketNotFound,
			apple.DeleteNestedBucket([]byte("missing")),
		)

		// Delete "apple/pear"
		require.Nil(t, apple.DeleteNestedBucket([]byte("pear")))

		// "apple/pear" deleted
		require.Nil(t, apple.NestedReadWriteBucket([]byte("pear")))

		// "aple/banana" exists
		require.NotNil(t, apple.NestedReadWriteBucket([]byte("banana")))
		return nil
	}, func() {})

	require.Nil(t, err)
}

func testBucketForEach(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		// "apple"
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.Nil(t, err)
		require.NotNil(t, apple)

		// "apple/banana"
		banana, err := apple.CreateBucket([]byte("banana"))
		require.Nil(t, err)
		require.NotNil(t, banana)

		kvs := []KV{{"key1", "val1"}, {"key2", "val2"}, {"key3", "val3"}}

		// put some values into "apple" and "apple/banana" too
		for _, kv := range kvs {
			require.Nil(t, apple.Put([]byte(kv.key), []byte(kv.val)))
			require.Equal(t, []byte(kv.val), apple.Get([]byte(kv.key)))

			require.Nil(t, banana.Put([]byte(kv.key), []byte(kv.val)))
			require.Equal(t, []byte(kv.val), banana.Get([]byte(kv.key)))
		}

		got := make(map[string]string)
		err = apple.ForEach(func(key, val []byte) error {
			got[string(key)] = string(val)
			return nil
		})

		expected := map[string]string{
			"key1":   "val1",
			"key2":   "val2",
			"key3":   "val3",
			"banana": "",
		}

		require.NoError(t, err)
		require.Equal(t, expected, got)

		got = make(map[string]string)
		err = banana.ForEach(func(key, val []byte) error {
			got[string(key)] = string(val)
			return nil
		})

		require.NoError(t, err)
		// remove the sub-bucket key
		delete(expected, "banana")
		require.Equal(t, expected, got)

		return nil
	}, func() {})

	require.Nil(t, err)
}

func testBucketForEachWithError(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		// "apple"
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.Nil(t, err)
		require.NotNil(t, apple)

		// "apple/banana"
		banana, err := apple.CreateBucket([]byte("banana"))
		require.Nil(t, err)
		require.NotNil(t, banana)

		// "apple/pear"
		pear, err := apple.CreateBucket([]byte("pear"))
		require.Nil(t, err)
		require.NotNil(t, pear)

		kvs := []KV{{"key1", "val1"}, {"key2", "val2"}}

		// Put some values into "apple" and "apple/banana" too.
		for _, kv := range kvs {
			require.Nil(t, apple.Put([]byte(kv.key), []byte(kv.val)))
			require.Equal(t, []byte(kv.val), apple.Get([]byte(kv.key)))
		}

		got := make(map[string]string)
		i := 0
		// Error while iterating value keys.
		err = apple.ForEach(func(key, val []byte) error {
			if i == 2 {
				return fmt.Errorf("error")
			}

			got[string(key)] = string(val)
			i++
			return nil
		})

		expected := map[string]string{
			"banana": "",
			"key1":   "val1",
		}

		require.Equal(t, expected, got)
		require.Error(t, err)

		got = make(map[string]string)
		i = 0
		// Erro while iterating buckets.
		err = apple.ForEach(func(key, val []byte) error {
			if i == 3 {
				return fmt.Errorf("error")
			}

			got[string(key)] = string(val)
			i++
			return nil
		})

		expected = map[string]string{
			"banana": "",
			"key1":   "val1",
			"key2":   "val2",
		}

		require.Equal(t, expected, got)
		require.Error(t, err)
		return nil
	}, func() {})

	require.Nil(t, err)
}

func testBucketSequence(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.Nil(t, err)
		require.NotNil(t, apple)

		banana, err := apple.CreateBucket([]byte("banana"))
		require.Nil(t, err)
		require.NotNil(t, banana)

		require.Equal(t, uint64(0), apple.Sequence())
		require.Equal(t, uint64(0), banana.Sequence())

		require.Nil(t, apple.SetSequence(math.MaxUint64))
		require.Equal(t, uint64(math.MaxUint64), apple.Sequence())

		for i := uint64(0); i < uint64(5); i++ {
			s, err := apple.NextSequence()
			require.Nil(t, err)
			require.Equal(t, i, s)
		}

		return nil
	}, func() {})

	require.Nil(t, err)
}

// TestKeyClash tests that one cannot create a bucket if a value with the same
// key exists and the same is true in reverse: that a value cannot be put if
// a bucket with the same key exists.
func testKeyClash(t *testing.T, db walletdb.DB) {
	// First:
	// put: /apple/key -> val
	// create bucket: /apple/banana
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.Nil(t, err)
		require.NotNil(t, apple)

		require.NoError(t, apple.Put([]byte("key"), []byte("val")))

		banana, err := apple.CreateBucket([]byte("banana"))
		require.Nil(t, err)
		require.NotNil(t, banana)

		return nil
	}, func() {})

	require.Nil(t, err)

	// Next try to:
	// put: /apple/banana -> val => will fail (as /apple/banana is a bucket)
	// create bucket: /apple/key => will fail (as /apple/key is a value)
	err = Update(db, func(tx walletdb.ReadWriteTx) error {
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.Nil(t, err)
		require.NotNil(t, apple)

		require.Error(t,
			walletdb.ErrIncompatibleValue,
			apple.Put([]byte("banana"), []byte("val")),
		)

		b, err := apple.CreateBucket([]byte("key"))
		require.Nil(t, b)
		require.Error(t, walletdb.ErrIncompatibleValue, b)

		b, err = apple.CreateBucketIfNotExists([]byte("key"))
		require.Nil(t, b)
		require.Error(t, walletdb.ErrIncompatibleValue, b)

		return nil
	}, func() {})

	require.Nil(t, err)
}

// TestBucketCreateDelete tests that creating then deleting then creating a
// bucket suceeds.
func testBucketCreateDelete(t *testing.T, db walletdb.DB) {
	err := Update(db, func(tx walletdb.ReadWriteTx) error {
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, apple)

		banana, err := apple.CreateBucket([]byte("banana"))
		require.NoError(t, err)
		require.NotNil(t, banana)

		return nil
	}, func() {})
	require.NoError(t, err)

	err = Update(db, func(tx walletdb.ReadWriteTx) error {
		apple := tx.ReadWriteBucket([]byte("apple"))
		require.NotNil(t, apple)
		require.NoError(t, apple.DeleteNestedBucket([]byte("banana")))

		return nil
	}, func() {})
	require.NoError(t, err)

	err = Update(db, func(tx walletdb.ReadWriteTx) error {
		apple := tx.ReadWriteBucket([]byte("apple"))
		require.NotNil(t, apple)
		require.NoError(t, apple.Put([]byte("banana"), []byte("value")))

		return nil
	}, func() {})
	require.NoError(t, err)
}

func testTopLevelBucketCreation(t *testing.T, db walletdb.DB) {
	require.NoError(t, Update(db, func(tx walletdb.ReadWriteTx) error {
		// Try to delete all data (there is none).
		err := tx.DeleteTopLevelBucket([]byte("top"))
		require.ErrorIs(t, walletdb.ErrBucketNotFound, err)

		// Create top level bucket.
		top, err := tx.CreateTopLevelBucket([]byte("top"))
		require.NoError(t, err)
		require.NotNil(t, top)

		// Create second top level bucket with special characters.
		top2, err := tx.CreateTopLevelBucket([]byte{1, 2, 3})
		require.NoError(t, err)
		require.NotNil(t, top2)

		top2 = tx.ReadWriteBucket([]byte{1, 2, 3})
		require.NotNil(t, top2)

		// List top level buckets.
		var tlKeys [][]byte
		require.NoError(t, tx.ForEachBucket(func(k []byte) error {
			tlKeys = append(tlKeys, k)
			return nil
		}))
		require.Equal(t, [][]byte{[]byte{1, 2, 3}, []byte("top")}, tlKeys)

		// Create third top level bucket with special uppercase.
		top3, err := tx.CreateTopLevelBucket([]byte("UpperBucket"))
		require.NoError(t, err)
		require.NotNil(t, top3)

		top3 = tx.ReadWriteBucket([]byte("UpperBucket"))
		require.NotNil(t, top3)

		return nil
	}, func() {}))
}

func testBucketOperations(t *testing.T, db walletdb.DB) {
	require.NoError(t, Update(db, func(tx walletdb.ReadWriteTx) error {
		// Create top level bucket.
		top, err := tx.CreateTopLevelBucket([]byte("top"))
		require.NoError(t, err)
		require.NotNil(t, top)

		// Assert that key doesn't exist.
		require.Nil(t, top.Get([]byte("key")))

		require.NoError(t, top.ForEach(func(k, v []byte) error {
			require.Fail(t, "unexpected data")
			return nil
		}))

		// Put key.
		require.NoError(t, top.Put([]byte("key"), []byte("val")))
		require.Equal(t, []byte("val"), top.Get([]byte("key")))

		// Overwrite key.
		require.NoError(t, top.Put([]byte("key"), []byte("val2")))
		require.Equal(t, []byte("val2"), top.Get([]byte("key")))

		// Put nil value.
		require.NoError(t, top.Put([]byte("nilkey"), nil))
		require.Equal(t, []byte(""), top.Get([]byte("nilkey")))

		// Put empty value.
		require.NoError(t, top.Put([]byte("nilkey"), []byte{}))
		require.Equal(t, []byte(""), top.Get([]byte("nilkey")))

		// Try to create bucket with same name as previous key.
		_, err = top.CreateBucket([]byte("key"))
		require.ErrorIs(t, err, walletdb.ErrIncompatibleValue)

		_, err = top.CreateBucketIfNotExists([]byte("key"))
		require.ErrorIs(t, err, walletdb.ErrIncompatibleValue)

		// Create sub-bucket.
		sub2, err := top.CreateBucket([]byte("sub2"))
		require.NoError(t, err)
		require.NotNil(t, sub2)

		// Assert that re-creating the bucket fails.
		_, err = top.CreateBucket([]byte("sub2"))
		require.ErrorIs(t, err, walletdb.ErrBucketExists)

		// Assert that create-if-not-exists succeeds.
		_, err = top.CreateBucketIfNotExists([]byte("sub2"))
		require.NoError(t, err)

		// Assert that fetching the bucket succeeds.
		sub2 = top.NestedReadWriteBucket([]byte("sub2"))
		require.NotNil(t, sub2)

		// Try to put key with same name as bucket.
		require.ErrorIs(t, top.Put([]byte("sub2"), []byte("val")), walletdb.ErrIncompatibleValue)

		// Put key into sub bucket.
		require.NoError(t, sub2.Put([]byte("subkey"), []byte("subval")))
		require.Equal(t, []byte("subval"), sub2.Get([]byte("subkey")))

		// Overwrite key in sub bucket.
		require.NoError(t, sub2.Put([]byte("subkey"), []byte("subval2")))
		require.Equal(t, []byte("subval2"), sub2.Get([]byte("subkey")))

		// Check for each result.
		kvs := make(map[string][]byte)
		require.NoError(t, top.ForEach(func(k, v []byte) error {
			kvs[string(k)] = v
			return nil
		}))
		require.Equal(t, map[string][]byte{
			"key":    []byte("val2"),
			"nilkey": []byte(""),
			"sub2":   nil,
		}, kvs)

		// Delete key.
		require.NoError(t, top.Delete([]byte("key")))

		// Delete non-existent key.
		require.NoError(t, top.Delete([]byte("keynonexistent")))

		// Test cursor.
		cursor := top.ReadWriteCursor()
		k, v := cursor.First()
		require.Equal(t, []byte("nilkey"), k)
		require.Equal(t, []byte(""), v)

		k, v = cursor.Last()
		require.Equal(t, []byte("sub2"), k)
		require.Nil(t, v)

		k, v = cursor.Prev()
		require.Equal(t, []byte("nilkey"), k)
		require.Equal(t, []byte(""), v)

		k, v = cursor.Prev()
		require.Nil(t, k)
		require.Nil(t, v)

		k, v = cursor.Next()
		require.Equal(t, []byte("sub2"), k)
		require.Nil(t, v)

		k, v = cursor.Next()
		require.Nil(t, k)
		require.Nil(t, v)

		k, v = cursor.Seek([]byte("nilkey"))
		require.Equal(t, []byte("nilkey"), k)
		require.Equal(t, []byte(""), v)

		require.NoError(t, sub2.Put([]byte("k1"), []byte("v1")))
		require.NoError(t, sub2.Put([]byte("k2"), []byte("v2")))
		require.NoError(t, sub2.Put([]byte("k3"), []byte("v3")))

		cursor = sub2.ReadWriteCursor()
		cursor.First()
		for i := 0; i < 4; i++ {
			require.NoError(t, cursor.Delete())
		}
		require.NoError(t, sub2.ForEach(func(k, v []byte) error {
			require.Fail(t, "unexpected data")
			return nil
		}))

		_, err = sub2.CreateBucket([]byte("sub3"))
		require.NoError(t, err)
		require.ErrorIs(t, cursor.Delete(), walletdb.ErrIncompatibleValue)

		//Try to delete all data.
		require.NoError(t, tx.DeleteTopLevelBucket([]byte("top")))
		require.Nil(t, tx.ReadBucket([]byte("top")))

		return nil
	}, func() {}))
}

func testSubBucketSequence(t *testing.T, db walletdb.DB) {
	require.NoError(t, Update(db, func(tx walletdb.ReadWriteTx) error {
		// Create top level bucket.
		top, err := tx.CreateTopLevelBucket([]byte("top"))
		require.NoError(t, err)
		require.NotNil(t, top)

		// Create sub-bucket.
		sub2, err := top.CreateBucket([]byte("sub2"))
		require.NoError(t, err)
		require.NotNil(t, sub2)

		// Test sequence.
		require.Equal(t, uint64(0), top.Sequence())

		require.NoError(t, top.SetSequence(100))
		require.Equal(t, uint64(100), top.Sequence())

		require.NoError(t, top.SetSequence(101))
		require.Equal(t, uint64(101), top.Sequence())

		next, err := top.NextSequence()
		require.NoError(t, err)
		require.Equal(t, uint64(102), next)

		next, err = sub2.NextSequence()
		require.NoError(t, err)
		require.Equal(t, uint64(1), next)

		return nil
	}, func() {}))
}
