// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This interface was inspired heavily by the excellent boltdb project at
// https://github.com/boltdb/bolt by Ben B. Johnson.

package walletdb

import (
	"fmt"
	"io"
)

// ReadTx represents a database transaction that can only be used for reads.  If
// a database update must occur, use a ReadWriteTx.
type ReadTx interface {
	// ReadBucket opens the root bucket for read only access.  If the bucket
	// described by the key does not exist, nil is returned.
	ReadBucket(key []byte) ReadBucket

	// Rollback closes the transaction, discarding changes (if any) if the
	// database was modified by a write transaction.
	Rollback() error
}

// ReadWriteTx represents a database transaction that can be used for both reads
// and writes.  When only reads are necessary, consider using a ReadTx instead.
type ReadWriteTx interface {
	ReadTx

	// ReadWriteBucket opens the root bucket for read/write access.  If the
	// bucket described by the key does not exist, nil is returned.
	ReadWriteBucket(key []byte) ReadWriteBucket

	// CreateTopLevelBucket creates the top level bucket for a key if it
	// does not exist.  The newly-created bucket it returned.
	CreateTopLevelBucket(key []byte) (ReadWriteBucket, error)

	// DeleteTopLevelBucket deletes the top level bucket for a key.  This
	// errors if the bucket can not be found or the key keys a single value
	// instead of a bucket.
	DeleteTopLevelBucket(key []byte) error

	// Commit commits all changes that have been on the transaction's root
	// buckets and all of their sub-buckets to persistent storage.
	Commit() error

	// OnCommit takes a function closure that will be executed when the
	// transaction successfully gets committed.
	OnCommit(func())
}

// ReadBucket represents a bucket (a hierarchical structure within the database)
// that is only allowed to perform read operations.
type ReadBucket interface {
	// NestedReadBucket retrieves a nested bucket with the given key.
	// Returns nil if the bucket does not exist.
	NestedReadBucket(key []byte) ReadBucket

	// ForEach invokes the passed function with every key/value pair in
	// the bucket.  This includes nested buckets, in which case the value
	// is nil, but it does not include the key/value pairs within those
	// nested buckets.
	//
	// NOTE: The values returned by this function are only valid during a
	// transaction.  Attempting to access them after a transaction has ended
	// results in undefined behavior.  This constraint prevents additional
	// data copies and allows support for memory-mapped database
	// implementations.
	ForEach(func(k, v []byte) error) error

	// Get returns the value for the given key.  Returns nil if the key does
	// not exist in this bucket (or nested buckets).
	//
	// NOTE: The value returned by this function is only valid during a
	// transaction.  Attempting to access it after a transaction has ended
	// results in undefined behavior.  This constraint prevents additional
	// data copies and allows support for memory-mapped database
	// implementations.
	Get(key []byte) []byte

	ReadCursor() ReadCursor
}

// ReadWriteBucket represents a bucket (a hierarchical structure within the
// database) that is allowed to perform both read and write operations.
type ReadWriteBucket interface {
	ReadBucket

	// NestedReadWriteBucket retrieves a nested bucket with the given key.
	// Returns nil if the bucket does not exist.
	NestedReadWriteBucket(key []byte) ReadWriteBucket

	// CreateBucket creates and returns a new nested bucket with the given
	// key.  Returns ErrBucketExists if the bucket already exists,
	// ErrBucketNameRequired if the key is empty, or ErrIncompatibleValue
	// if the key value is otherwise invalid for the particular database
	// implementation.  Other errors are possible depending on the
	// implementation.
	CreateBucket(key []byte) (ReadWriteBucket, error)

	// CreateBucketIfNotExists creates and returns a new nested bucket with
	// the given key if it does not already exist.  Returns
	// ErrBucketNameRequired if the key is empty or ErrIncompatibleValue
	// if the key value is otherwise invalid for the particular database
	// backend.  Other errors are possible depending on the implementation.
	CreateBucketIfNotExists(key []byte) (ReadWriteBucket, error)

	// DeleteNestedBucket removes a nested bucket with the given key.
	// Returns ErrTxNotWritable if attempted against a read-only transaction
	// and ErrBucketNotFound if the specified bucket does not exist.
	DeleteNestedBucket(key []byte) error

	// Put saves the specified key/value pair to the bucket.  Keys that do
	// not already exist are added and keys that already exist are
	// overwritten.  Returns ErrTxNotWritable if attempted against a
	// read-only transaction.
	Put(key, value []byte) error

	// Delete removes the specified key from the bucket.  Deleting a key
	// that does not exist does not return an error.  Returns
	// ErrTxNotWritable if attempted against a read-only transaction.
	Delete(key []byte) error

	// Cursor returns a new cursor, allowing for iteration over the bucket's
	// key/value pairs and nested buckets in forward or backward order.
	ReadWriteCursor() ReadWriteCursor

	// Tx returns the bucket's transaction.
	Tx() ReadWriteTx

	// NextSequence returns an autoincrementing integer for the bucket.
	NextSequence() (uint64, error)

	// SetSequence updates the sequence number for the bucket.
	SetSequence(v uint64) error

	// Sequence returns the current integer for the bucket without
	// incrementing it.
	Sequence() uint64
}

// ReadCursor represents a bucket cursor that can be positioned at the start or
// end of the bucket's key/value pairs and iterate over pairs in the bucket.
// This type is only allowed to perform database read operations.
type ReadCursor interface {
	// First positions the cursor at the first key/value pair and returns
	// the pair.
	First() (key, value []byte)

	// Last positions the cursor at the last key/value pair and returns the
	// pair.
	Last() (key, value []byte)

	// Next moves the cursor one key/value pair forward and returns the new
	// pair.
	Next() (key, value []byte)

	// Prev moves the cursor one key/value pair backward and returns the new
	// pair.
	Prev() (key, value []byte)

	// Seek positions the cursor at the passed seek key.  If the key does
	// not exist, the cursor is moved to the next key after seek.  Returns
	// the new pair.
	Seek(seek []byte) (key, value []byte)
}

// ReadWriteCursor represents a bucket cursor that can be positioned at the
// start or end of the bucket's key/value pairs and iterate over pairs in the
// bucket.  This abstraction is allowed to perform both database read and write
// operations.
type ReadWriteCursor interface {
	ReadCursor

	// Delete removes the current key/value pair the cursor is at without
	// invalidating the cursor.  Returns ErrIncompatibleValue if attempted
	// when the cursor points to a nested bucket.
	Delete() error
}

// BucketIsEmpty returns whether the bucket is empty, that is, whether there are
// no key/value pairs or nested buckets.
func BucketIsEmpty(bucket ReadBucket) bool {
	k, v := bucket.ReadCursor().First()
	return k == nil && v == nil
}

// DB represents an ACID database.  All database access is performed through
// read or read+write transactions.
type DB interface {
	// BeginReadTx opens a database read transaction.
	BeginReadTx() (ReadTx, error)

	// BeginReadWriteTx opens a database read+write transaction.
	BeginReadWriteTx() (ReadWriteTx, error)

	// Copy writes a copy of the database to the provided writer.  This
	// call will start a read-only transaction to perform all operations.
	Copy(w io.Writer) error

	// Close cleanly shuts down the database and syncs all data.
	Close() error
}

// BatchDB is a special version of the main DB interface that allos the caller
// to specify write transactions that should be combine dtoegether if multiple
// goroutines are calling the Batch method.
type BatchDB interface {
	DB

	// Batch is similar to the package-level Update method, but it will
	// attempt to optismitcally combine the invocation of several
	// transaction functions into a single db write transaction.
	Batch(func(tx ReadWriteTx) error) error
}

// View opens a database read transaction and executes the function f with the
// transaction passed as a parameter.  After f exits, the transaction is rolled
// back.  If f errors, its error is returned, not a rollback error (if any
// occur).
func View(db DB, f func(tx ReadTx) error) error {
	tx, err := db.BeginReadTx()
	if err != nil {
		return err
	}

	// Make sure the transaction rolls back in the event of a panic.
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	err = f(tx)
	rollbackErr := tx.Rollback()
	if err != nil {
		return err
	}

	if rollbackErr != nil {
		return rollbackErr
	}
	return nil
}

// Update opens a database read/write transaction and executes the function f
// with the transaction passed as a parameter.  After f exits, if f did not
// error, the transaction is committed.  Otherwise, if f did error, the
// transaction is rolled back.  If the rollback fails, the original error
// returned by f is still returned.  If the commit fails, the commit error is
// returned.
func Update(db DB, f func(tx ReadWriteTx) error) error {
	tx, err := db.BeginReadWriteTx()
	if err != nil {
		return err
	}

	// Make sure the transaction rolls back in the event of a panic.
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	err = f(tx)
	if err != nil {
		// Want to return the original error, not a rollback error if
		// any occur.
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

// Batch opens a database read/write transaction and executes the function f
// with the transaction passed as a parameter.  After f exits, if f did not
// error, the transaction is committed.  Otherwise, if f did error, the
// transaction is rolled back.  If the rollback fails, the original error
// returned by f is still returned.  If the commit fails, the commit error is
// returned.
//
// Batch is only useful when there are multiple goroutines calling it.
func Batch(db DB, f func(tx ReadWriteTx) error) error {
	batchDB, ok := db.(BatchDB)
	if !ok {
		return fmt.Errorf("need batch")
	}

	return batchDB.Batch(f)
}

// Driver defines a structure for backend drivers to use when they registered
// themselves as a backend which implements the Db interface.
type Driver struct {
	// DbType is the identifier used to uniquely identify a specific
	// database driver.  There can be only one driver with the same name.
	DbType string

	// Create is the function that will be invoked with all user-specified
	// arguments to create the database.  This function must return
	// ErrDbExists if the database already exists.
	Create func(args ...interface{}) (DB, error)

	// Open is the function that will be invoked with all user-specified
	// arguments to open the database.  This function must return
	// ErrDbDoesNotExist if the database has not already been created.
	Open func(args ...interface{}) (DB, error)
}

// driverList holds all of the registered database backends.
var drivers = make(map[string]*Driver)

// RegisterDriver adds a backend database driver to available interfaces.
// ErrDbTypeRegistered will be retruned if the database type for the driver has
// already been registered.
func RegisterDriver(driver Driver) error {
	if _, exists := drivers[driver.DbType]; exists {
		return ErrDbTypeRegistered
	}

	drivers[driver.DbType] = &driver
	return nil
}

// SupportedDrivers returns a slice of strings that represent the database
// drivers that have been registered and are therefore supported.
func SupportedDrivers() []string {
	supportedDBs := make([]string, 0, len(drivers))
	for _, drv := range drivers {
		supportedDBs = append(supportedDBs, drv.DbType)
	}
	return supportedDBs
}

// Create intializes and opens a database for the specified type.  The arguments
// are specific to the database type driver.  See the documentation for the
// database driver for further details.
//
// ErrDbUnknownType will be returned if the the database type is not registered.
func Create(dbType string, args ...interface{}) (DB, error) {
	drv, exists := drivers[dbType]
	if !exists {
		return nil, ErrDbUnknownType
	}

	return drv.Create(args...)
}

// Open opens an existing database for the specified type.  The arguments are
// specific to the database type driver.  See the documentation for the database
// driver for further details.
//
// ErrDbUnknownType will be returned if the the database type is not registered.
func Open(dbType string, args ...interface{}) (DB, error) {
	drv, exists := drivers[dbType]
	if !exists {
		return nil, ErrDbUnknownType
	}

	return drv.Open(args...)
}
