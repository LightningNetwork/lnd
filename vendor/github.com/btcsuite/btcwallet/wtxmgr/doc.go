// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wtxmgr provides an implementation of a transaction database handling
// spend tracking for a bitcoin wallet.  Its primary purpose is to save
// transactions with outputs spendable with wallet keys and transactions that
// are signed by wallet keys in memory, handle spend tracking for unspent
// outputs and newly-inserted transactions, and report the spendable balance
// from each unspent transaction output. It uses walletdb as the backend for
// storing the serialized transaction objects in buckets.
//
// Transaction outputs which are spendable by wallet keys are called credits
// (because they credit to a wallet's total spendable balance).  Transaction
// inputs which spend previously-inserted credits are called debits (because
// they debit from the wallet's spendable balance).
//
// Spend tracking is mostly automatic.  When a new transaction is inserted, if
// it spends from any unspent credits, they are automatically marked spent by
// the new transaction, and each input which spent a credit is marked as a
// debit.  However, transaction outputs of inserted transactions must manually
// marked as credits, as this package has no knowledge of wallet keys or
// addresses, and therefore cannot determine which outputs may be spent.
//
// Details regarding individual transactions and their credits and debits may be
// queried either by just a transaction hash, or by hash and block.  When
// querying for just a transaction hash, the most recent transaction with a
// matching hash will be queried.  However, because transaction hashes may
// collide with other transaction hashes, methods to query for specific
// transactions in the chain (or unmined) are provided as well.
package wtxmgr
