// +build kvdb_etcd

package kvdb

import (
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/kvdb/etcd"
	"github.com/stretchr/testify/require"
)

var (
	bkey = etcd.BucketKey
	bval = etcd.BucketVal
	vkey = etcd.ValueKey
)

func TestEtcd(t *testing.T) {
	tests := []struct {
		name       string
		test       func(*testing.T, walletdb.DB)
		expectedDb map[string]string
	}{
		{
			name: "read cursor empty interval",
			test: testReadCursorEmptyInterval,
		},
		{
			name: "read cursor non empty interval",
			test: testReadCursorNonEmptyInterval,
		},
		{
			name: "read write cursor",
			test: testReadWriteCursor,
			expectedDb: map[string]string{
				bkey("apple"):       bval("apple"),
				vkey("a", "apple"):  "0",
				vkey("c", "apple"):  "3",
				vkey("cx", "apple"): "x",
				vkey("cy", "apple"): "y",
				vkey("da", "apple"): "3",
				vkey("f", "apple"):  "5",
			},
		},
		{
			name: "read write cursor with bucket and value",
			test: testReadWriteCursorWithBucketAndValue,
			expectedDb: map[string]string{
				bkey("apple"):           bval("apple"),
				bkey("apple", "banana"): bval("apple", "banana"),
				bkey("apple", "pear"):   bval("apple", "pear"),
				vkey("key", "apple"):    "val",
			},
		},
		{
			name: "bucket creation",
			test: testBucketCreation,
			expectedDb: map[string]string{
				bkey("apple"):                   bval("apple"),
				bkey("apple", "banana"):         bval("apple", "banana"),
				bkey("apple", "mango"):          bval("apple", "mango"),
				bkey("apple", "banana", "pear"): bval("apple", "banana", "pear"),
			},
		},
		{
			name: "bucket deletion",
			test: testBucketDeletion,
			expectedDb: map[string]string{
				bkey("apple"):                   bval("apple"),
				bkey("apple", "banana"):         bval("apple", "banana"),
				vkey("key1", "apple", "banana"): "val1",
				vkey("key3", "apple", "banana"): "val3",
			},
		},
		{
			name: "bucket for each",
			test: testBucketForEach,
			expectedDb: map[string]string{
				bkey("apple"):                   bval("apple"),
				bkey("apple", "banana"):         bval("apple", "banana"),
				vkey("key1", "apple"):           "val1",
				vkey("key2", "apple"):           "val2",
				vkey("key3", "apple"):           "val3",
				vkey("key1", "apple", "banana"): "val1",
				vkey("key2", "apple", "banana"): "val2",
				vkey("key3", "apple", "banana"): "val3",
			},
		},
		{
			name: "bucket for each with error",
			test: testBucketForEachWithError,
			expectedDb: map[string]string{
				bkey("apple"):           bval("apple"),
				bkey("apple", "banana"): bval("apple", "banana"),
				bkey("apple", "pear"):   bval("apple", "pear"),
				vkey("key1", "apple"):   "val1",
				vkey("key2", "apple"):   "val2",
			},
		},
		{
			name: "bucket sequence",
			test: testBucketSequence,
		},
		{
			name: "key clash",
			test: testKeyClash,
			expectedDb: map[string]string{
				bkey("apple"):           bval("apple"),
				bkey("apple", "banana"): bval("apple", "banana"),
				vkey("key", "apple"):    "val",
			},
		},
		{
			name: "bucket create delete",
			test: testBucketCreateDelete,
			expectedDb: map[string]string{
				vkey("banana", "apple"): "value",
				bkey("apple"):           bval("apple"),
			},
		},
		{
			name: "tx manual commit",
			test: testTxManualCommit,
			expectedDb: map[string]string{
				bkey("apple"):            bval("apple"),
				vkey("testKey", "apple"): "testVal",
			},
		},
		{
			name:       "tx rollback",
			test:       testTxRollback,
			expectedDb: map[string]string{},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			f := etcd.NewEtcdTestFixture(t)
			defer f.Cleanup()

			test.test(t, f.NewBackend())

			if test.expectedDb != nil {
				dump := f.Dump()
				require.Equal(t, test.expectedDb, dump)
			}
		})
	}
}
