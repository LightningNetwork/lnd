// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package walletdb provides a namespaced database interface for btcwallet.

Overview

A wallet essentially consists of a multitude of stored data such as private
and public keys, key derivation bits, pay-to-script-hash scripts, and various
metadata.  One of the issues with many wallets is they are tightly integrated.
Designing a wallet with loosely coupled components that provide specific
functionality is ideal, however it presents a challenge in regards to data
storage since each component needs to store its own data without knowing the
internals of other components or breaking atomicity.

This package solves this issue by providing a pluggable driver, namespaced
database interface that is intended to be used by the main wallet daemon.  This
allows the potential for any backend database type with a suitable driver.  Each
component, which will typically be a package, can then implement various
functionality such as address management, voting pools, and colored coin
metadata in their own namespace without having to worry about conflicts with
other packages even though they are sharing the same database that is managed by
the wallet.

A quick overview of the features walletdb provides are as follows:

 - Key/value store
 - Namespace support
 - Allows multiple packages to have their own area in the database without
   worrying about conflicts
 - Read-only and read-write transactions with both manual and managed modes
 - Nested buckets
 - Supports registration of backend databases
 - Comprehensive test coverage

Database

The main entry point is the DB interface.  It exposes functionality for
creating, retrieving, and removing namespaces.  It is obtained via the Create
and Open functions which take a database type string that identifies the
specific database driver (backend) to use as well as arguments specific to the
specified driver.

Namespaces

The Namespace interface is an abstraction that provides facilities for obtaining
transactions (the Tx interface) that are the basis of all database reads and
writes.  Unlike some database interfaces that support reading and writing
without transactions, this interface requires transactions even when only
reading or writing a single key.

The Begin function provides an unmanaged transaction while the View and Update
functions provide a managed transaction.  These are described in more detail
below.

Transactions

The Tx interface provides facilities for rolling back or commiting changes that
took place while the transaction was active.  It also provides the root bucket
under which all keys, values, and nested buckets are stored.  A transaction
can either be read-only or read-write and managed or unmanaged.

Managed versus Unmanaged Transactions

A managed transaction is one where the caller provides a function to execute
within the context of the transaction and the commit or rollback is handled
automatically depending on whether or not the provided function returns an
error.  Attempting to manually call Rollback or Commit on the managed
transaction will result in a panic.

An unmanaged transaction, on the other hand, requires the caller to manually
call Commit or Rollback when they are finished with it.  Leaving transactions
open for long periods of time can have several adverse effects, so it is
recommended that managed transactions are used instead.

Buckets

The Bucket interface provides the ability to manipulate key/value pairs and
nested buckets as well as iterate through them.

The Get, Put, and Delete functions work with key/value pairs, while the Bucket,
CreateBucket, CreateBucketIfNotExists, and DeleteBucket functions work with
buckets.  The ForEach function allows the caller to provide a function to be
called with each key/value pair and nested bucket in the current bucket.

Root Bucket

As discussed above, all of the functions which are used to manipulate key/value
pairs and nested buckets exist on the Bucket interface.  The root bucket is the
upper-most bucket in a namespace under which data is stored and is created at
the same time as the namespace.  Use the RootBucket function on the Tx interface
to retrieve it.

Nested Buckets

The CreateBucket and CreateBucketIfNotExists functions on the Bucket interface
provide the ability to create an arbitrary number of nested buckets.  It is
a good idea to avoid a lot of buckets with little data in them as it could lead
to poor page utilization depending on the specific driver in use.
*/
package walletdb
