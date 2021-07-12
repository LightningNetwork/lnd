// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package blockchain implements bitcoin block handling and chain selection rules.

The bitcoin block handling and chain selection rules are an integral, and quite
likely the most important, part of bitcoin.  Unfortunately, at the time of
this writing, these rules are also largely undocumented and had to be
ascertained from the bitcoind source code.  At its core, bitcoin is a
distributed consensus of which blocks are valid and which ones will comprise the
main block chain (public ledger) that ultimately determines accepted
transactions, so it is extremely important that fully validating nodes agree on
all rules.

At a high level, this package provides support for inserting new blocks into
the block chain according to the aforementioned rules.  It includes
functionality such as rejecting duplicate blocks, ensuring blocks and
transactions follow all rules, orphan handling, and best chain selection along
with reorganization.

Since this package does not deal with other bitcoin specifics such as network
communication or wallets, it provides a notification system which gives the
caller a high level of flexibility in how they want to react to certain events
such as orphan blocks which need their parents requested and newly connected
main chain blocks which might result in wallet updates.

Bitcoin Chain Processing Overview

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

Errors

Errors returned by this package are either the raw errors provided by underlying
calls or of type blockchain.RuleError.  This allows the caller to differentiate
between unexpected errors, such as database errors, versus errors due to rule
violations through type assertions.  In addition, callers can programmatically
determine the specific rule violation by examining the ErrorCode field of the
type asserted blockchain.RuleError.

Bitcoin Improvement Proposals

This package includes spec changes outlined by the following BIPs:

		BIP0016 (https://en.bitcoin.it/wiki/BIP_0016)
		BIP0030 (https://en.bitcoin.it/wiki/BIP_0030)
		BIP0034 (https://en.bitcoin.it/wiki/BIP_0034)
*/
package blockchain
