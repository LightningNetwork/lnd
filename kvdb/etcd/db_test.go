// +build kvdb_etcd

package etcd

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(t, err)

	err = db.Update(func(tx walletdb.ReadWriteTx) error {
		// "apple"
		apple, err := tx.CreateTopLevelBucket([]byte("apple"))
		require.NoError(t, err)
		require.NotNil(t, apple)

		require.NoError(t, apple.Put([]byte("key"), []byte("val")))
		return nil
	}, func() {})

	// Expect non-zero copy.
	var buf bytes.Buffer

	require.NoError(t, db.Copy(&buf))
	require.Greater(t, buf.Len(), 0)
	require.Nil(t, err)

	expected := map[string]string{
		BucketKey("apple"):        BucketVal("apple"),
		ValueKey("key", "apple"): "val",
	}
	require.Equal(t, expected, f.Dump())
}

func TestAbortContext(t *testing.T) {
	t.Parallel()

	f := NewEtcdTestFixture(t)
	defer f.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	config := f.BackendConfig()

	// Pass abort context and abort right away.
	db, err := newEtcdBackend(ctx, config)
	require.NoError(t, err)
	cancel()

	// Expect that the update will fail.
	err = db.Update(func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket([]byte("bucket"))
		require.Error(t, err, "context canceled")

		return nil
	}, func() {})

	require.Error(t, err, "context canceled")

	// No changes in the DB.
	require.Equal(t, map[string]string{}, f.Dump())
}
