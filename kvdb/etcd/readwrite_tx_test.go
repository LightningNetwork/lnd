// +build kvdb_etcd

package etcd

import (
	"context"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

func TestChangeDuringManualTx(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	tx, err := db.BeginReadWriteTx()
	require.Nil(t, err)
	require.NotNil(t, tx)

	apple, err := tx.CreateTopLevelBucket([]byte("apple"))
	require.Nil(t, err)
	require.NotNil(t, apple)

	require.NoError(t, apple.Put([]byte("testKey"), []byte("testVal")))

	// Try overwriting the bucket key.
	f.Put(BucketKey("apple"), "banana")

	// TODO: translate error
	require.NotNil(t, tx.Commit())
	require.Equal(t, map[string]string{
		BucketKey("apple"): "banana",
	}, f.Dump())
}

func TestChangeDuringUpdate(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	count := 0

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, apple)

		require.NoError(t, apple.Put([]byte("key"), []byte("value")))

		if count == 0 {
			f.Put(ValueKey("key", "apple"), "new_value")
			f.Put(ValueKey("key2", "apple"), "value2")
		}

		cursor := apple.ReadCursor()
		k, v := cursor.First()
		require.Equal(t, []byte("key"), k)
		require.Equal(t, []byte("value"), v)
		require.Equal(t, v, apple.Get([]byte("key")))

		k, v = cursor.Next()
		if count == 0 {
			require.Nil(t, k)
			require.Nil(t, v)
		} else {
			require.Equal(t, []byte("key2"), k)
			require.Equal(t, []byte("value2"), v)
		}

		count++
		return nil
	}, func() {})

	require.Nil(t, err)
	require.Equal(t, count, 2)

	expected := map[string]string{
		BucketKey("apple"):         BucketVal("apple"),
		ValueKey("key", "apple"):  "value",
		ValueKey("key2", "apple"): "value2",
	}
	require.Equal(t, expected, f.Dump())
}
