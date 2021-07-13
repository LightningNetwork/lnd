package kvdb

import (
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

func testTxManualCommit(t *testing.T, db walletdb.DB) {
	tx, err := db.BeginReadWriteTx()
	require.NoError(t, err)
	require.NotNil(t, tx)

	committed := false

	tx.OnCommit(func() {
		committed = true
	})

	apple, err := tx.CreateTopLevelBucket([]byte("apple"))
	require.NoError(t, err)
	require.NotNil(t, apple)
	require.NoError(t, apple.Put([]byte("testKey"), []byte("testVal")))

	banana, err := tx.CreateTopLevelBucket([]byte("banana"))
	require.NoError(t, err)
	require.NotNil(t, banana)
	require.NoError(t, banana.Put([]byte("testKey"), []byte("testVal")))
	require.NoError(t, tx.DeleteTopLevelBucket([]byte("banana")))

	require.NoError(t, tx.Commit())
	require.True(t, committed)
}

func testTxRollback(t *testing.T, db walletdb.DB) {
	tx, err := db.BeginReadWriteTx()
	require.Nil(t, err)
	require.NotNil(t, tx)

	apple, err := tx.CreateTopLevelBucket([]byte("apple"))
	require.Nil(t, err)
	require.NotNil(t, apple)

	require.NoError(t, apple.Put([]byte("testKey"), []byte("testVal")))

	require.NoError(t, tx.Rollback())
	require.Error(t, walletdb.ErrTxClosed, tx.Commit())
}
