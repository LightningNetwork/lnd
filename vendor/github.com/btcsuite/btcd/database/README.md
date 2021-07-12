database
========

[![Build Status](http://img.shields.io/travis/btcsuite/btcd.svg)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/database)

Package database provides a block and metadata storage database.

Please note that this package is intended to enable btcd to support different
database backends and is not something that a client can directly access as only
one entity can have the database open at a time (for most database backends),
and that entity will be btcd.

When a client wants programmatic access to the data provided by btcd, they'll
likely want to use the [rpcclient](https://github.com/btcsuite/btcd/tree/master/rpcclient)
package which makes use of the [JSON-RPC API](https://github.com/btcsuite/btcd/tree/master/docs/json_rpc_api.md).

However, this package could be extremely useful for any applications requiring
Bitcoin block storage capabilities.

The default backend, ffldb, has a strong focus on speed, efficiency, and
robustness.  It makes use of leveldb for the metadata, flat files for block
storage, and strict checksums in key areas to ensure data integrity.

## Feature Overview

- Key/value metadata store
- Bitcoin block storage
- Efficient retrieval of block headers and regions (transactions, scripts, etc)
- Read-only and read-write transactions with both manual and managed modes
- Nested buckets
- Iteration support including cursors with seek capability
- Supports registration of backend databases
- Comprehensive test coverage

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/database
```

## Examples

* [Basic Usage Example](http://godoc.org/github.com/btcsuite/btcd/database#example-package--BasicUsage)  
  Demonstrates creating a new database and using a managed read-write
  transaction to store and retrieve metadata.

* [Block Storage and Retrieval Example](http://godoc.org/github.com/btcsuite/btcd/database#example-package--BlockStorageAndRetrieval)  
  Demonstrates creating a new database, using a managed read-write transaction
  to store a block, and then using a managed read-only transaction to fetch the
  block.

## License

Package database is licensed under the [copyfree](http://copyfree.org) ISC
License.
