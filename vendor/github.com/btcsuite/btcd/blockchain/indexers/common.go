// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package indexers implements optional block chain indexes.
*/
package indexers

import (
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcutil"
)

var (
	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian

	// errInterruptRequested indicates that an operation was cancelled due
	// to a user-requested interrupt.
	errInterruptRequested = errors.New("interrupt requested")
)

// NeedsInputser provides a generic interface for an indexer to specify the it
// requires the ability to look up inputs for a transaction.
type NeedsInputser interface {
	NeedsInputs() bool
}

// Indexer provides a generic interface for an indexer that is managed by an
// index manager such as the Manager type provided by this package.
type Indexer interface {
	// Key returns the key of the index as a byte slice.
	Key() []byte

	// Name returns the human-readable name of the index.
	Name() string

	// Create is invoked when the indexer manager determines the index needs
	// to be created for the first time.
	Create(dbTx database.Tx) error

	// Init is invoked when the index manager is first initializing the
	// index.  This differs from the Create method in that it is called on
	// every load, including the case the index was just created.
	Init() error

	// ConnectBlock is invoked when a new block has been connected to the
	// main chain. The set of output spent within a block is also passed in
	// so indexers can access the pevious output scripts input spent if
	// required.
	ConnectBlock(database.Tx, *btcutil.Block, []blockchain.SpentTxOut) error

	// DisconnectBlock is invoked when a block has been disconnected from
	// the main chain. The set of outputs scripts that were spent within
	// this block is also returned so indexers can clean up the prior index
	// state for this block
	DisconnectBlock(database.Tx, *btcutil.Block, []blockchain.SpentTxOut) error
}

// AssertError identifies an error that indicates an internal code consistency
// issue and should be treated as a critical and unrecoverable error.
type AssertError string

// Error returns the assertion error as a huma-readable string and satisfies
// the error interface.
func (e AssertError) Error() string {
	return "assertion failed: " + string(e)
}

// errDeserialize signifies that a problem was encountered when deserializing
// data.
type errDeserialize string

// Error implements the error interface.
func (e errDeserialize) Error() string {
	return string(e)
}

// isDeserializeErr returns whether or not the passed error is an errDeserialize
// error.
func isDeserializeErr(err error) bool {
	_, ok := err.(errDeserialize)
	return ok
}

// internalBucket is an abstraction over a database bucket.  It is used to make
// the code easier to test since it allows mock objects in the tests to only
// implement these functions instead of everything a database.Bucket supports.
type internalBucket interface {
	Get(key []byte) []byte
	Put(key []byte, value []byte) error
	Delete(key []byte) error
}

// interruptRequested returns true when the provided channel has been closed.
// This simplifies early shutdown slightly since the caller can just use an if
// statement instead of a select.
func interruptRequested(interrupted <-chan struct{}) bool {
	select {
	case <-interrupted:
		return true
	default:
	}

	return false
}
