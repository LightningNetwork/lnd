mempool
=======

[![Build Status](http://img.shields.io/travis/btcsuite/btcd.svg)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/mempool)

Package mempool provides a policy-enforced pool of unmined bitcoin transactions.

A key responsbility of the bitcoin network is mining user-generated transactions
into blocks.  In order to facilitate this, the mining process relies on having a
readily-available source of transactions to include in a block that is being
solved.

At a high level, this package satisfies that requirement by providing an
in-memory pool of fully validated transactions that can also optionally be
further filtered based upon a configurable policy.

One of the policy configuration options controls whether or not "standard"
transactions are accepted.  In essence, a "standard" transaction is one that
satisfies a fairly strict set of requirements that are largely intended to help
provide fair use of the system to all users.  It is important to note that what
is considered a "standard" transaction changes over time.  For some insight, at
the time of this writing, an example of _some_ of the criteria that are required
for a transaction to be considered standard are that it is of the most-recently
supported version, finalized, does not exceed a specific size, and only consists
of specific script forms.

Since this package does not deal with other bitcoin specifics such as network
communication and transaction relay, it returns a list of transactions that were
accepted which gives the caller a high level of flexibility in how they want to
proceed.  Typically, this will involve things such as relaying the transactions
to other peers on the network and notifying the mining process that new
transactions are available.

This package has intentionally been designed so it can be used as a standalone
package for any projects needing the ability create an in-memory pool of bitcoin
transactions that are not only valid by consensus rules, but also adhere to a
configurable policy.

## Feature Overview

The following is a quick overview of the major features.  It is not intended to
be an exhaustive list.

- Maintain a pool of fully validated transactions
  - Reject non-fully-spent duplicate transactions
  - Reject coinbase transactions
  - Reject double spends (both from the chain and other transactions in pool)
  - Reject invalid transactions according to the network consensus rules
  - Full script execution and validation with signature cache support
  - Individual transaction query support
- Orphan transaction support (transactions that spend from unknown outputs)
  - Configurable limits (see transaction acceptance policy)
  - Automatic addition of orphan transactions that are no longer orphans as new
    transactions are added to the pool
  - Individual orphan transaction query support
- Configurable transaction acceptance policy
  - Option to accept or reject standard transactions
  - Option to accept or reject transactions based on priority calculations
  - Rate limiting of low-fee and free transactions
  - Non-zero fee threshold
  - Max signature operations per transaction
  - Max orphan transaction size
  - Max number of orphan transactions allowed
- Additional metadata tracking for each transaction
  - Timestamp when the transaction was added to the pool
  - Most recent block height when the transaction was added to the pool
  - The fee the transaction pays
  - The starting priority for the transaction
- Manual control of transaction removal
  - Recursive removal of all dependent transactions

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/mempool
```

## License

Package mempool is licensed under the [copyfree](http://copyfree.org) ISC
License.
