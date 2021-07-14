package kvdb

import (
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Import to register backend.
)

// Update opens a database read/write transaction and executes the function f
// with the transaction passed as a parameter. After f exits, if f did not
// error, the transaction is committed. Otherwise, if f did error, the
// transaction is rolled back. If the rollback fails, the original error
// returned by f is still returned. If the commit fails, the commit error is
// returned. As callers may expect retries of the f closure (depending on the
// database backend used), the reset function will be called before each retry
// respectively.
func Update(db Backend, f func(tx RwTx) error, reset func()) error {
	if extendedDB, ok := db.(ExtendedBackend); ok {
		return extendedDB.Update(f, reset)
	}

	reset()
	return walletdb.Update(db, f)
}

// View opens a database read transaction and executes the function f with the
// transaction passed as a parameter. After f exits, the transaction is rolled
// back. If f errors, its error is returned, not a rollback error (if any
// occur). The passed reset function is called before the start of the
// transaction and can be used to reset intermediate state. As callers may
// expect retries of the f closure (depending on the database backend used), the
// reset function will be called before each retry respectively.
func View(db Backend, f func(tx RTx) error, reset func()) error {
	if extendedDB, ok := db.(ExtendedBackend); ok {
		return extendedDB.View(f, reset)
	}

	// Since we know that walletdb simply calls into bbolt which never
	// retries transactions, we'll call the reset function here before View.
	reset()

	return walletdb.View(db, f)
}

// Batch is identical to the Update call, but it attempts to combine several
// individual Update transactions into a single write database transaction on
// an optimistic basis. This only has benefits if multiple goroutines call
// Batch. For etcd Batch simply does an Update since combination is more complex
// in that case due to STM retries.
func Batch(db Backend, f func(tx RwTx) error) error {
	if extendedDB, ok := db.(ExtendedBackend); ok {
		// Since Batch calls handle external state reset, we can safely
		// pass in an empty reset closure.
		return extendedDB.Update(f, func() {})
	}

	return walletdb.Batch(db, f)
}

// Create initializes and opens a database for the specified type. The
// arguments are specific to the database type driver. See the documentation
// for the database driver for further details.
//
// ErrDbUnknownType will be returned if the database type is not registered.
var Create = walletdb.Create

// Backend represents an ACID database. All database access is performed
// through read or read+write transactions.
type Backend = walletdb.DB

// ExtendedBackend is and interface that supports View and Update and also able
// to collect database access patterns.
type ExtendedBackend interface {
	Backend

	// PrintStats returns all collected stats pretty printed into a string.
	PrintStats() string

	// View opens a database read transaction and executes the function f
	// with the transaction passed as a parameter. After f exits, the
	// transaction is rolled back. If f errors, its error is returned, not a
	// rollback error (if any occur). The passed reset function is called
	// before the start of the transaction and can be used to reset
	// intermediate state. As callers may expect retries of the f closure
	// (depending on the database backend used), the reset function will be
	//called before each retry respectively.
	View(f func(tx walletdb.ReadTx) error, reset func()) error

	// Update opens a database read/write transaction and executes the
	// function f with the transaction passed as a parameter. After f exits,
	// if f did not error, the transaction is committed. Otherwise, if f did
	// error, the transaction is rolled back. If the rollback fails, the
	// original error returned by f is still returned. If the commit fails,
	// the commit error is returned. As callers may expect retries of the f
	// closure (depending on the database backend used), the reset function
	// will be called before each retry respectively.
	Update(f func(tx walletdb.ReadWriteTx) error, reset func()) error
}

// Open opens an existing database for the specified type. The arguments are
// specific to the database type driver. See the documentation for the database
// driver for further details.
//
// ErrDbUnknownType will be returned if the database type is not registered.
var Open = walletdb.Open

// Driver defines a structure for backend drivers to use when they registered
// themselves as a backend which implements the Backend interface.
type Driver = walletdb.Driver

// RBucket represents a bucket (a hierarchical structure within the
// database) that is only allowed to perform read operations.
type RBucket = walletdb.ReadBucket

// RCursor represents a bucket cursor that can be positioned at the start or
// end of the bucket's key/value pairs and iterate over pairs in the bucket.
// This type is only allowed to perform database read operations.
type RCursor = walletdb.ReadCursor

// RTx represents a database transaction that can only be used for reads. If
// a database update must occur, use a RwTx.
type RTx = walletdb.ReadTx

// RwBucket represents a bucket (a hierarchical structure within the database)
// that is allowed to perform both read and write operations.
type RwBucket = walletdb.ReadWriteBucket

// RwCursor represents a bucket cursor that can be positioned at the start or
// end of the bucket's key/value pairs and iterate over pairs in the bucket.
// This abstraction is allowed to perform both database read and write
// operations.
type RwCursor = walletdb.ReadWriteCursor

// ReadWriteTx represents a database transaction that can be used for both
// reads and writes. When only reads are necessary, consider using a RTx
// instead.
type RwTx = walletdb.ReadWriteTx

// ExtendedRTx is an extension to walletdb.ReadTx to allow prefetching of keys.
type ExtendedRTx interface {
	RTx

	// RootBucket returns the "root bucket" which is pseudo bucket used
	// when prefetching (keys from) top level buckets.
	RootBucket() RBucket
}

// ExtendedRBucket is an extension to walletdb.ReadBucket to allow prefetching
// of different kind of keys.
type ExtendedRBucket interface {
	RBucket

	// Prefetch will prefetch keys (exact match) and ranges (prefix match).
	// So that subsequent fetches for those keys and keys in ranges don't
	// go the the DB.
	Prefetch(keys []string, ranges []string)

	// BucketKey creates a bucket key from the passed buckets as represented
	// by the underlying implementation.
	BucketKey(buckets ...string) string

	// RangeKey creates a prefix key (all keys inside the bucket) from the
	// passed buckets as represented by the implementation.
	RangeKey(buckets ...string) string

	// ValueKey creates a key for a single value from the passed key and
	// buckets as represented by the implementation.
	ValueKey(key string, buckets ...string) string
}

// BucketKey is a wrapper to ExtendedRBucket.BucketKey which does nothing if
// the implementation doesn't have ExtendedRBucket.
func BucketKey(b RBucket, buckets ...string) string {
	if bucket, ok := b.(ExtendedRBucket); ok {
		return bucket.BucketKey(buckets...)
	}

	return ""
}

// ValueKey is a wrapper to ExtendedRBucket.ValueKey which does nothing if
// the implementation doesn't have ExtendedRBucket.
func ValueKey(b RBucket, key string, buckets ...string) string {
	if bucket, ok := b.(ExtendedRBucket); ok {
		return bucket.ValueKey(key, buckets...)
	}

	return ""
}

// RangeKey is a wrapper to ExtendedRBucket.RangeKey which does nothing if
// the implementation doesn't have ExtendedRBucket.
func RangeKey(b RBucket, buckets ...string) string {
	if bucket, ok := b.(ExtendedRBucket); ok {
		return bucket.RangeKey(buckets...)
	}

	return ""
}

// Prefetch is a wrapper to ExtendedRBucket.Prefetch which does nothing if
// the implementation doesn't have ExtendedRBucket.
func Prefetch(b RBucket, keys []string, ranges []string) {
	if bucket, ok := b.(ExtendedRBucket); ok {
		bucket.Prefetch(keys, ranges)
	}
}

// RootBucket is a wrapper to ExtendedRTx.RootBucket which does nothing if
// the implementation doesn't have ExtendedRTx.
func RootBucket(t RTx) RBucket {
	if tx, ok := t.(ExtendedRTx); ok {
		return tx.RootBucket()
	}

	return nil
}

var (
	// ErrBucketNotFound is returned when trying to access a bucket that
	// has not been created yet.
	ErrBucketNotFound = walletdb.ErrBucketNotFound

	// ErrBucketExists is returned when creating a bucket that already
	// exists.
	ErrBucketExists = walletdb.ErrBucketExists

	// ErrDatabaseNotOpen is returned when a database instance is accessed
	// before it is opened or after it is closed.
	ErrDatabaseNotOpen = walletdb.ErrDbNotOpen
)
