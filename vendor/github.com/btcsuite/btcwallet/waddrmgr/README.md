waddrmgr
========

[![Build Status](https://travis-ci.org/btcsuite/btcwallet.png?branch=master)]
(https://travis-ci.org/btcsuite/btcwallet)

Package waddrmgr provides a secure hierarchical deterministic wallet address
manager.

A suite of tests is provided to ensure proper functionality.  See
`test_coverage.txt` for the gocov coverage report.  Alternatively, if you are
running a POSIX OS, you can run the `cov_report.sh` script for a real-time
report.  Package waddrmgr is licensed under the liberal ISC license.

## Feature Overview

- BIP0032 hierarchical deterministic keys
- BIP0043/BIP0044 multi-account hierarchy
- Strong focus on security:
  - Fully encrypted database including public information such as addresses as
    well as private information such as private keys and scripts needed to
    redeem pay-to-script-hash transactions
  - Hardened against memory scraping through the use of actively clearing
    private material from memory when locked
  - Different crypto keys used for public, private, and script data
  - Ability for different passphrases for public and private data
  - Scrypt-based key derivation
  - NaCl-based secretbox cryptography (XSalsa20 and Poly1305)
- Scalable design:
  - Multi-tier key design to allow instant password changes regardless of the
    number of addresses stored
  - Import WIF keys
  - Import pay-to-script-hash scripts for things such as multi-signature
    transactions
  - Ability to start in watching-only mode which does not contain any private
    key material
  - Ability to convert to watching-only mode
  - Programmatically detectable errors, including encapsulation of errors from
    packages it relies on
  - Address synchronization capabilities
- Comprehensive test coverage

## Documentation

[![GoDoc](https://godoc.org/github.com/btcsuite/btcwallet/waddrmgr?status.png)]
(http://godoc.org/github.com/btcsuite/btcwallet/waddrmgr)

Full `go doc` style documentation for the project can be viewed online without
installing this package by using the GoDoc site here:
http://godoc.org/github.com/btcsuite/btcwallet/waddrmgr

You can also view the documentation locally once the package is installed with
the `godoc` tool by running `godoc -http=":6060"` and pointing your browser to
http://localhost:6060/pkg/github.com/btcsuite/btcwallet/waddrmgr

## Installation

```bash
$ go get github.com/btcsuite/btcwallet/waddrmgr
```

Package waddrmgr is licensed under the [copyfree](http://copyfree.org) ISC
License.
