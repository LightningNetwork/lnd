package kvdb

import (
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/kvdb/postgres"
	"github.com/stretchr/testify/require"
)

type m = map[string]interface{}

func TestPostgres(t *testing.T) {
	f := postgres.NewFixture(t)
	defer f.Cleanup()

	tests := []struct {
		name       string
		test       func(*testing.T, walletdb.DB)
		expectedDb map[string]interface{}
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
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(3), "key": "da", "parent_id": nil, "sequence": nil, "value": "3"},
					m{"id": int64(5), "key": "a", "parent_id": nil, "sequence": nil, "value": "0"},
					m{"id": int64(6), "key": "f", "parent_id": nil, "sequence": nil, "value": "5"},
					m{"id": int64(2), "key": "c", "parent_id": nil, "sequence": nil, "value": "3"},
					m{"id": int64(8), "key": "cx", "parent_id": nil, "sequence": nil, "value": "x"},
					m{"id": int64(9), "key": "cy", "parent_id": nil, "sequence": nil, "value": "y"},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil),
			},
		},
		{
			name: "read write cursor with bucket and value",
			test: testReadWriteCursorWithBucketAndValue,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "key", "parent_id": nil, "sequence": nil, "value": "val"},
					m{"id": int64(2), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(3), "key": "pear", "parent_id": nil, "sequence": nil, "value": nil},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil),
			},
		},
		{
			name: "bucket creation",
			test: testBucketCreation,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(2), "key": "mango", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(3), "key": "pear", "parent_id": int64(1), "sequence": nil, "value": nil}},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil)},
		},
		{
			name: "bucket deletion",
			test: testBucketDeletion,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(2), "key": "key1", "parent_id": int64(1), "sequence": nil, "value": "val1"},
					m{"id": int64(4), "key": "key3", "parent_id": int64(1), "sequence": nil, "value": "val3"},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil),
			},
		},
		{
			name: "bucket for each",
			test: testBucketForEach,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(2), "key": "key1", "parent_id": nil, "sequence": nil, "value": "val1"},
					m{"id": int64(3), "key": "key1", "parent_id": int64(1), "sequence": nil, "value": "val1"},
					m{"id": int64(4), "key": "key2", "parent_id": nil, "sequence": nil, "value": "val2"},
					m{"id": int64(5), "key": "key2", "parent_id": int64(1), "sequence": nil, "value": "val2"},
					m{"id": int64(6), "key": "key3", "parent_id": nil, "sequence": nil, "value": "val3"},
					m{"id": int64(7), "key": "key3", "parent_id": int64(1), "sequence": nil, "value": "val3"},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil)},
		},
		{
			name: "bucket for each with error",
			test: testBucketForEachWithError,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(2), "key": "pear", "parent_id": nil, "sequence": nil, "value": nil},
					m{"id": int64(3), "key": "key1", "parent_id": nil, "sequence": nil, "value": "val1"},
					m{"id": int64(4), "key": "key2", "parent_id": nil, "sequence": nil, "value": "val2"},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil)},
		},
		{
			name: "bucket sequence",
			test: testBucketSequence,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m{m{"sequence": int64(4), "table_name": "test_apple"}},
			},
		},
		{
			name: "key clash",
			test: testKeyClash,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "key", "parent_id": nil, "sequence": nil, "value": "val"},
					m{"id": int64(2), "key": "banana", "parent_id": nil, "sequence": nil, "value": nil},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil)},
		},
		{
			name: "bucket create delete",
			test: testBucketCreateDelete,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(2), "key": "banana", "parent_id": nil, "sequence": nil, "value": "value"},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil),
			},
		},
		{
			name: "tx manual commit",
			test: testTxManualCommit,
			expectedDb: m{
				"test_apple": []m{
					m{"id": int64(1), "key": "testKey", "parent_id": nil, "sequence": nil, "value": "testVal"},
				},
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil),
			},
		},
		{
			name: "tx rollback",
			test: testTxRollback,
			expectedDb: m{
				"testsys_hex":      []m(nil),
				"testsys_sequence": []m(nil),
			},
		},
		{
			name: "top level bucket creation",
			test: testTopLevelBucketCreation,
		},
		{
			name: "bucket operation",
			test: testBucketOperations,
		},
		{
			name: "sub bucket sequence",
			test: testSubBucketSequence,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.test(t, f.NewBackend())

			if test.expectedDb != nil {
				dump := f.Dump()
				require.Equal(t, test.expectedDb, dump)
			}
		})
	}
}
