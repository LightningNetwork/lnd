walletdb
========

[![Build Status](https://travis-ci.org/btcsuite/btcwallet.png?branch=master)]
(https://travis-ci.org/btcsuite/btcwallet)

Package walletdb provides a namespaced database interface for btcwallet.

A wallet essentially consists of a multitude of stored data such as private
and public keys, key derivation bits, pay-to-script-hash scripts, and various
metadata.  One of the issues with many wallets is they are tightly integrated.
Designing a wallet with loosely coupled components that provide specific
functionality is ideal, however it presents a challenge in regards to data
storage since each component needs to store its own data without knowing the
internals of other components or breaking atomicity.

This package solves this issue by providing a namespaced database interface that
is intended to be used by the main wallet daemon.  This allows the potential for
any backend database type with a suitable driver.  Each component, which will
typically be a package, can then implement various functionality such as address
management, voting pools, and colored coin metadata in their own namespace
without having to worry about conflicts with other packages even though they are
sharing the same database that is managed by the wallet.

A suite of tests is provided to ensure proper functionality.  See
`test_coverage.txt` for the gocov coverage report.  Alternatively, if you are
running a POSIX OS, you can run the `cov_report.sh` script for a real-time
report.  Package walletdb is licensed under the copyfree ISC license.

This interfaces provided by this package were heavily inspired by the excellent
boltdb project at https://github.com/boltdb/bolt by Ben B. Johnson.

## Feature Overview

- Key/value store
- Namespace support
  - Allows multiple packages to have their own area in the database without
    worrying about conflicts
- Read-only and read-write transactions with both manual and managed modes
- Nested buckets
- Supports registration of backend databases
- Comprehensive test coverage

## Documentation

[![GoDoc](https://godoc.org/github.com/btcsuite/btcwallet/walletdb?status.png)]
(http://godoc.org/github.com/btcsuite/btcwallet/walletdb)

Full `go doc` style documentation for the project can be viewed online without
installing this package by using the GoDoc site here:
http://godoc.org/github.com/btcsuite/btcwallet/walletdb

You can also view the documentation locally once the package is installed with
the `godoc` tool by running `godoc -http=":6060"` and pointing your browser to
http://localhost:6060/pkg/github.com/btcsuite/btcwallet/walletdb

## Installation

```bash
$ go get github.com/btcsuite/btcwallet/walletdb
```

## Examples

* [Basic Usage Example]
  (http://godoc.org/github.com/btcsuite/btcwallet/walletdb#example-package--BasicUsage)  
  Demonstrates creating a new database, getting a namespace from it, and using a
  managed read-write transaction against the namespace to store and retrieve
  data.


## License

Package walletdb is licensed under the [copyfree](http://copyfree.org) ISC
License.
