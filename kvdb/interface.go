package kvdb

import (
	"github.com/btcsuite/btcwallet/walletdb"
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
