// +build kvdb_etcd

package etcd

import (
	"context"
	"fmt"
	"math"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

func TestBucketCreation(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
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

	expected := map[string]string{
		bkey("apple"):                   bval("apple"),
		bkey("apple", "banana"):         bval("apple", "banana"),
		bkey("apple", "mango"):          bval("apple", "mango"),
		bkey("apple", "banana", "pear"): bval("apple", "banana", "pear"),
	}
	require.Equal(t, expected, f.Dump())
}

func TestBucketDeletion(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
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

		// "apple/pear/cherry" deleted
		require.Nil(t, pear.NestedReadWriteBucket([]byte("cherry")))

		// Values deleted too.
		for _, kv := range kvs {
			require.Nil(t, pear.Get([]byte(kv.key)))
			require.Nil(t, cherry.Get([]byte(kv.key)))
		}

		// "aple/banana" exists
		require.NotNil(t, apple.NestedReadWriteBucket([]byte("banana")))
		return nil
	}, func() {})

	require.Nil(t, err)

	expected := map[string]string{
		bkey("apple"):                   bval("apple"),
		bkey("apple", "banana"):         bval("apple", "banana"),
		vkey("key1", "apple", "banana"): "val1",
		vkey("key3", "apple", "banana"): "val3",
	}
	require.Equal(t, expected, f.Dump())
}

func TestBucketForEach(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
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

	expected := map[string]string{
		bkey("apple"):                   bval("apple"),
		bkey("apple", "banana"):         bval("apple", "banana"),
		vkey("key1", "apple"):           "val1",
		vkey("key2", "apple"):           "val2",
		vkey("key3", "apple"):           "val3",
		vkey("key1", "apple", "banana"): "val1",
		vkey("key2", "apple", "banana"): "val2",
		vkey("key3", "apple", "banana"): "val3",
	}
	require.Equal(t, expected, f.Dump())
}

func TestBucketForEachWithError(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
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

	expected := map[string]string{
		bkey("apple"):           bval("apple"),
		bkey("apple", "banana"): bval("apple", "banana"),
		bkey("apple", "pear"):   bval("apple", "pear"),
		vkey("key1", "apple"):   "val1",
		vkey("key2", "apple"):   "val2",
	}
	require.Equal(t, expected, f.Dump())
}

func TestBucketSequence(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
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

// TestBucketCreateDelete tests that creating then deleting then creating a
// bucket suceeds.
func TestBucketCreateDelete(t *testing.T) {
	t.Parallel()
	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, apple)

		banana, err := apple.CreateBucket([]byte("banana"))
		require.NoError(t, err)
		require.NotNil(t, banana)

		return nil
	}, func() {})
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
		apple := tx.ReadWriteBucket([]byte("apple"))
		require.NotNil(t, apple)
		require.NoError(t, apple.DeleteNestedBucket([]byte("banana")))

		return nil
	}, func() {})
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
		apple := tx.ReadWriteBucket([]byte("apple"))
		require.NotNil(t, apple)
		require.NoError(t, apple.Put([]byte("banana"), []byte("value")))

		return nil
	}, func() {})
	require.NoError(t, err)

	expected := map[string]string{
		vkey("banana", "apple"): "value",
		bkey("apple"):           bval("apple"),
	}
	require.Equal(t, expected, f.Dump())
}
