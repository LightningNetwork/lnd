// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mining

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// UnminedHeight is the height used for the "block" height field of the
	// contextual transaction information provided in a transaction store
	// when it has not yet been mined into a block.
	UnminedHeight = 0x7fffffff
)

// Policy houses the policy (configuration parameters) which is used to control
// the generation of block templates.  See the documentation for
// NewBlockTemplate for more details on each of these parameters are used.
type Policy struct {
	// BlockMinWeight is the minimum block weight to be used when
	// generating a block template.
	BlockMinWeight uint32

	// BlockMaxWeight is the maximum block weight to be used when
	// generating a block template.
	BlockMaxWeight uint32

	// BlockMinWeight is the minimum block size to be used when generating
	// a block template.
	BlockMinSize uint32

	// BlockMaxSize is the maximum block size to be used when generating a
	// block template.
	BlockMaxSize uint32

	// BlockPrioritySize is the size in bytes for high-priority / low-fee
	// transactions to be used when generating a block template.
	BlockPrioritySize uint32

	// TxMinFreeFee is the minimum fee in Satoshi/1000 bytes that is
	// required for a transaction to be treated as free for mining purposes
	// (block template generation).
	TxMinFreeFee btcutil.Amount
}

// minInt is a helper function to return the minimum of two ints.  This avoids
// a math import and the need to cast to floats.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// calcInputValueAge is a helper function used to calculate the input age of
// a transaction.  The input age for a txin is the number of confirmations
// since the referenced txout multiplied by its output value.  The total input
// age is the sum of this value for each txin.  Any inputs to the transaction
// which are currently in the mempool and hence not mined into a block yet,
// contribute no additional input age to the transaction.
func calcInputValueAge(tx *wire.MsgTx, utxoView *blockchain.UtxoViewpoint, nextBlockHeight int32) float64 {
	var totalInputAge float64
	for _, txIn := range tx.TxIn {
		// Don't attempt to accumulate the total input age if the
		// referenced transaction output doesn't exist.
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if entry != nil && !entry.IsSpent() {
			// Inputs with dependencies currently in the mempool
			// have their block height set to a special constant.
			// Their input age should computed as zero since their
			// parent hasn't made it into a block yet.
			var inputAge int32
			originHeight := entry.BlockHeight()
			if originHeight == UnminedHeight {
				inputAge = 0
			} else {
				inputAge = nextBlockHeight - originHeight
			}

			// Sum the input value times age.
			inputValue := entry.Amount()
			totalInputAge += float64(inputValue * int64(inputAge))
		}
	}

	return totalInputAge
}

// CalcPriority returns a transaction priority given a transaction and the sum
// of each of its input values multiplied by their age (# of confirmations).
// Thus, the final formula for the priority is:
// sum(inputValue * inputAge) / adjustedTxSize
func CalcPriority(tx *wire.MsgTx, utxoView *blockchain.UtxoViewpoint, nextBlockHeight int32) float64 {
	// In order to encourage spending multiple old unspent transaction
	// outputs thereby reducing the total set, don't count the constant
	// overhead for each input as well as enough bytes of the signature
	// script to cover a pay-to-script-hash redemption with a compressed
	// pubkey.  This makes additional inputs free by boosting the priority
	// of the transaction accordingly.  No more incentive is given to avoid
	// encouraging gaming future transactions through the use of junk
	// outputs.  This is the same logic used in the reference
	// implementation.
	//
	// The constant overhead for a txin is 41 bytes since the previous
	// outpoint is 36 bytes + 4 bytes for the sequence + 1 byte the
	// signature script length.
	//
	// A compressed pubkey pay-to-script-hash redemption with a maximum len
	// signature is of the form:
	// [OP_DATA_73 <73-byte sig> + OP_DATA_35 + {OP_DATA_33
	// <33 byte compresed pubkey> + OP_CHECKSIG}]
	//
	// Thus 1 + 73 + 1 + 1 + 33 + 1 = 110
	overhead := 0
	for _, txIn := range tx.TxIn {
		// Max inputs + size can't possibly overflow here.
		overhead += 41 + minInt(110, len(txIn.SignatureScript))
	}

	serializedTxSize := tx.SerializeSize()
	if overhead >= serializedTxSize {
		return 0.0
	}

	inputValueAge := calcInputValueAge(tx, utxoView, nextBlockHeight)
	return inputValueAge / float64(serializedTxSize-overhead)
}
