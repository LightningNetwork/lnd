// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package database provides a block and metadata storage database.

Overview

As of Feb 2016, there are over 400,000 blocks in the Bitcoin block chain and
and over 112 million transactions (which turns out to be over 60GB of data).
This package provides a database layer to store and retrieve this data in a
simple and efficient manner.

The default backend, ffldb, has a strong focus on speed, efficiency, and
robustness.  It makes use leveldb for the metadata, flat files for block
storage, and strict checksums in key areas to ensure data integrity.

A quick overview of the features database provides are as follows:

 - Key/value metadata store
 - Bitcoin block storage
 - Efficient retrieval of block headers and regions (transactions, scripts, etc)
 - Read-only and read-write transactions with both manual and managed modes
 - Nested buckets
 - Supports registration of backend databases
 - Comprehensive test coverage

Database

The main entry point is the DB interface.  It exposes functionality for
transactional-based access and storage of metadata and block data.  It is
obtained via the Create and Open functions which take a database type string
that identifies the specific database driver (backend) to use as well as
arguments specific to the specified driver.

The interface provides facilities for obtaining transactions (the Tx interface)
that are the basis of all database reads and writes.  Unlike some database
interfaces that support reading and writing without transactions, this interface
requires transactions even when only reading or writing a single key.

The Begin function provides an unmanaged transaction while the View and Update
functions provide a managed transaction.  These are described in more detail
below.

Transactions

The Tx interface provides facilities for rolling back or committing changes that
took place while the transaction was active.  It also provides the root metadata
bucket under which all keys, values, and nested buckets are stored.  A
transaction can either be read-only or read-write and managed or unmanaged.

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

Metadata Bucket

As discussed above, all of the functions which are used to manipulate key/value
pairs and nested buckets exist on the Bucket interface.  The root metadata
bucket is the upper-most bucket in which data is stored and is created at the
same time as the database.  Use the Metadata function on the Tx interface
to retrieve it.

Nested Buckets

The CreateBucket and CreateBucketIfNotExists functions on the Bucket interface
provide the ability to create an arbitrary number of nested buckets.  It is
a good idea to avoid a lot of buckets with little data in them as it could lead
to poor page utilization depending on the specific driver in use.
*/
package database
