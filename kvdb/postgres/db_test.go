package postgres

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/walletdbtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

// TestInterface performs all interfaces tests for this database driver.
func TestInterface(t *testing.T) {
	f := NewFixture(t)
	defer f.Cleanup()

	// dbType is the database type name for this driver.
	const dbType = "postgres"

	ctx := context.Background()
	cfg := &Config{
		Dsn: dsn,
	}

	walletdbtest.TestInterface(t, dbType, ctx, cfg, prefix)
}

// TestPanic tests recovery from panic conditions.
func TestPanic(t *testing.T) {
	f := NewFixture(t)
	defer f.Cleanup()

	d := f.NewBackend()

	err := d.(*db).Update(func(tx walletdb.ReadWriteTx) error {
		bucket, err := tx.CreateTopLevelBucket([]byte("test"))
		require.NoError(t, err)

		// Stop database server.
		f.Cleanup()

		// Keep trying to get data until Get panics because the
		// connection is lost.
		for i := 0; i < 50; i++ {
			bucket.Get([]byte("key"))
			time.Sleep(100 * time.Millisecond)
		}

		return nil
	}, func() {})

	require.Contains(t, err.Error(), "terminating connection")
}
