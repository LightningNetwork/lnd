blockchain
==========

[![Build Status](http://img.shields.io/travis/btcsuite/btcd.svg)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/blockchain)

Package blockchain implements bitcoin block handling and chain selection rules.
The test coverage is currently only around 60%, but will be increasing over
time. See `test_coverage.txt` for the gocov coverage report.  Alternatively, if
you are running a POSIX OS, you can run the `cov_report.sh` script for a
real-time report.  Package blockchain is licensed under the liberal ISC license.

There is an associated blog post about the release of this package
[here](https://blog.conformal.com/btcchain-the-bitcoin-chain-package-from-bctd/).

This package has intentionally been designed so it can be used as a standalone
package for any projects needing to handle processing of blocks into the bitcoin
block chain.

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/blockchain
```

## Bitcoin Chain Processing Overview

Before a block is allowed into the block chain, it must go through an intensive
series of validation rules.  The following list serves as a general outline of
those rules to provide some intuition into what is going on under the hood, but
is by no means exhaustive:

 - Reject duplicate blocks
 - Perform a series of sanity checks on the block and its transactions such as
   verifying proof of work, timestamps, number and character of transactions,
   transaction amounts, script complexity, and merkle root calculations
 - Compare the block against predetermined checkpoints for expected timestamps
   and difficulty based on elapsed time since the checkpoint
 - Save the most recent orphan blocks for a limited time in case their parent
   blocks become available
 - Stop processing if the block is an orphan as the rest of the processing
   depends on the block's position within the block chain
 - Perform a series of more thorough checks that depend on the block's position
   within the block chain such as verifying block difficulties adhere to
   difficulty retarget rules, timestamps are after the median of the last
   several blocks, all transactions are finalized, checkpoint blocks match, and
   block versions are in line with the previous blocks
 - Determine how the block fits into the chain and perform different actions
   accordingly in order to ensure any side chains which have higher difficulty
   than the main chain become the new main chain
 - When a block is being connected to the main chain (either through
   reorganization of a side chain to the main chain or just extending the
   main chain), perform further checks on the block's transactions such as
   verifying transaction duplicates, script complexity for the combination of
   connected scripts, coinbase maturity, double spends, and connected
   transaction values
 - Run the transaction scripts to verify the spender is allowed to spend the
   coins
 - Insert the block into the block database

## Examples

* [ProcessBlock Example](http://godoc.org/github.com/btcsuite/btcd/blockchain#example-BlockChain-ProcessBlock)  
  Demonstrates how to create a new chain instance and use ProcessBlock to
  attempt to add a block to the chain.  This example intentionally
  attempts to insert a duplicate genesis block to illustrate how an invalid
  block is handled.

* [CompactToBig Example](http://godoc.org/github.com/btcsuite/btcd/blockchain#example-CompactToBig)  
  Demonstrates how to convert the compact "bits" in a block header which
  represent the target difficulty to a big integer and display it using the
  typical hex notation.

* [BigToCompact Example](http://godoc.org/github.com/btcsuite/btcd/blockchain#example-BigToCompact)  
  Demonstrates how to convert a target difficulty into the
  compact "bits" in a block header which represent that target difficulty.

## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from the btcsuite developers.  To
verify the signature perform the following:

- Download the public key from the Conformal website at
  https://opensource.conformal.com/GIT-GPG-KEY-conformal.txt

- Import the public key into your GPG keyring:
  ```bash
  gpg --import GIT-GPG-KEY-conformal.txt
  ```

- Verify the release tag with the following command where `TAG_NAME` is a
  placeholder for the specific tag:
  ```bash
  git tag -v TAG_NAME
  ```

## License


Package blockchain is licensed under the [copyfree](http://copyfree.org) ISC
License.
