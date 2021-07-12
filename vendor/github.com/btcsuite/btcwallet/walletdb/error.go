// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletdb

import (
	"errors"
)

// Errors that can occur during driver registration.
var (
	// ErrDbTypeRegistered is returned when two different database drivers
	// attempt to register with the name database type.
	ErrDbTypeRegistered = errors.New("database type already registered")
)

// Errors that the various database functions may return.
var (
	// ErrDbUnknownType is returned when there is no driver registered for
	// the specified database type.
	ErrDbUnknownType = errors.New("unknown database type")

	// ErrDbDoesNotExist is returned when open is called for a database that
	// does not exist.
	ErrDbDoesNotExist = errors.New("database does not exist")

	// ErrDbExists is returned when create is called for a database that
	// already exists.
	ErrDbExists = errors.New("database already exists")

	// ErrDbNotOpen is returned when a database instance is accessed before
	// it is opened or after it is closed.
	ErrDbNotOpen = errors.New("database not open")

	// ErrDbAlreadyOpen is returned when open is called on a database that
	// is already open.
	ErrDbAlreadyOpen = errors.New("database already open")

	// ErrInvalid is returned if the specified database is not valid.
	ErrInvalid = errors.New("invalid database")
)

// Errors that can occur when beginning or committing a transaction.
var (
	// ErrTxClosed is returned when attempting to commit or rollback a
	// transaction that has already had one of those operations performed.
	ErrTxClosed = errors.New("tx closed")

	// ErrTxNotWritable is returned when an operation that requires write
	// access to the database is attempted against a read-only transaction.
	ErrTxNotWritable = errors.New("tx not writable")
)

// Errors that can occur when putting or deleting a value or bucket.
var (
	// ErrBucketNotFound is returned when trying to access a bucket that has
	// not been created yet.
	ErrBucketNotFound = errors.New("bucket not found")

	// ErrBucketExists is returned when creating a bucket that already exists.
	ErrBucketExists = errors.New("bucket already exists")

	// ErrBucketNameRequired is returned when creating a bucket with a blank name.
	ErrBucketNameRequired = errors.New("bucket name required")

	// ErrKeyRequired is returned when inserting a zero-length key.
	ErrKeyRequired = errors.New("key required")

	// ErrKeyTooLarge is returned when inserting a key that is larger than MaxKeySize.
	ErrKeyTooLarge = errors.New("key too large")

	// ErrValueTooLarge is returned when inserting a value that is larger than MaxValueSize.
	ErrValueTooLarge = errors.New("value too large")

	// ErrIncompatibleValue is returned when trying create or delete a
	// bucket on an existing non-bucket key or when trying to create or
	// delete a non-bucket key on an existing bucket key.
	ErrIncompatibleValue = errors.New("incompatible value")
)
