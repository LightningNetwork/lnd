// Copyright (c) 2015-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/walletdb"
)

// CreditRecord contains metadata regarding a transaction credit for a known
// transaction.  Further details may be looked up by indexing a wire.MsgTx.TxOut
// with the Index field.
type CreditRecord struct {
	Amount btcutil.Amount
	Index  uint32
	Spent  bool
	Change bool
}

// DebitRecord contains metadata regarding a transaction debit for a known
// transaction.  Further details may be looked up by indexing a wire.MsgTx.TxIn
// with the Index field.
type DebitRecord struct {
	Amount btcutil.Amount
	Index  uint32
}

// TxDetails is intended to provide callers with access to rich details
// regarding a relevant transaction and which inputs and outputs are credit or
// debits.
type TxDetails struct {
	TxRecord
	Block   BlockMeta
	Credits []CreditRecord
	Debits  []DebitRecord
	Label   string
}

// minedTxDetails fetches the TxDetails for the mined transaction with hash
// txHash and the passed tx record key and value.
func (s *Store) minedTxDetails(ns walletdb.ReadBucket, txHash *chainhash.Hash, recKey, recVal []byte) (*TxDetails, error) {
	var details TxDetails

	// Parse transaction record k/v, lookup the full block record for the
	// block time, and read all matching credits, debits.
	err := readRawTxRecord(txHash, recVal, &details.TxRecord)
	if err != nil {
		return nil, err
	}
	err = readRawTxRecordBlock(recKey, &details.Block.Block)
	if err != nil {
		return nil, err
	}
	details.Block.Time, err = fetchBlockTime(ns, details.Block.Height)
	if err != nil {
		return nil, err
	}

	credIter := makeReadCreditIterator(ns, recKey)
	for credIter.next() {
		if int(credIter.elem.Index) >= len(details.MsgTx.TxOut) {
			str := "saved credit index exceeds number of outputs"
			return nil, storeError(ErrData, str, nil)
		}

		// The credit iterator does not record whether this credit was
		// spent by an unmined transaction, so check that here.
		if !credIter.elem.Spent {
			k := canonicalOutPoint(txHash, credIter.elem.Index)
			spent := existsRawUnminedInput(ns, k) != nil
			credIter.elem.Spent = spent
		}
		details.Credits = append(details.Credits, credIter.elem)
	}
	if credIter.err != nil {
		return nil, credIter.err
	}

	debIter := makeReadDebitIterator(ns, recKey)
	for debIter.next() {
		if int(debIter.elem.Index) >= len(details.MsgTx.TxIn) {
			str := "saved debit index exceeds number of inputs"
			return nil, storeError(ErrData, str, nil)
		}

		details.Debits = append(details.Debits, debIter.elem)
	}
	if debIter.err != nil {
		return nil, debIter.err
	}

	// Finally, we add the transaction label to details.
	details.Label, err = s.TxLabel(ns, *txHash)
	if err != nil {
		return nil, err
	}

	return &details, nil
}

// unminedTxDetails fetches the TxDetails for the unmined transaction with the
// hash txHash and the passed unmined record value.
func (s *Store) unminedTxDetails(ns walletdb.ReadBucket, txHash *chainhash.Hash, v []byte) (*TxDetails, error) {
	details := TxDetails{
		Block: BlockMeta{Block: Block{Height: -1}},
	}
	err := readRawTxRecord(txHash, v, &details.TxRecord)
	if err != nil {
		return nil, err
	}

	it := makeReadUnminedCreditIterator(ns, txHash)
	for it.next() {
		if int(it.elem.Index) >= len(details.MsgTx.TxOut) {
			str := "saved credit index exceeds number of outputs"
			return nil, storeError(ErrData, str, nil)
		}

		// Set the Spent field since this is not done by the iterator.
		it.elem.Spent = existsRawUnminedInput(ns, it.ck) != nil
		details.Credits = append(details.Credits, it.elem)
	}
	if it.err != nil {
		return nil, it.err
	}

	// Debit records are not saved for unmined transactions.  Instead, they
	// must be looked up for each transaction input manually.  There are two
	// kinds of previous credits that may be debited by an unmined
	// transaction: mined unspent outputs (which remain marked unspent even
	// when spent by an unmined transaction), and credits from other unmined
	// transactions.  Both situations must be considered.
	for i, output := range details.MsgTx.TxIn {
		opKey := canonicalOutPoint(&output.PreviousOutPoint.Hash,
			output.PreviousOutPoint.Index)
		credKey := existsRawUnspent(ns, opKey)
		if credKey != nil {
			v := existsRawCredit(ns, credKey)
			amount, err := fetchRawCreditAmount(v)
			if err != nil {
				return nil, err
			}

			details.Debits = append(details.Debits, DebitRecord{
				Amount: amount,
				Index:  uint32(i),
			})
			continue
		}

		v := existsRawUnminedCredit(ns, opKey)
		if v == nil {
			continue
		}

		amount, err := fetchRawCreditAmount(v)
		if err != nil {
			return nil, err
		}
		details.Debits = append(details.Debits, DebitRecord{
			Amount: amount,
			Index:  uint32(i),
		})
	}

	// Finally, we add the transaction label to details.
	details.Label, err = s.TxLabel(ns, *txHash)
	if err != nil {
		return nil, err
	}

	return &details, nil
}

// TxLabel looks up a transaction label for the txHash provided. If the store
// has no labels in it, or the specific txHash does not have a label, an empty
// string and no error are returned.
func (s *Store) TxLabel(ns walletdb.ReadBucket, txHash chainhash.Hash) (string,
	error) {

	label, err := FetchTxLabel(ns, txHash)
	switch err {
	// If there are no saved labels yet (the bucket has not been created) or
	// there is not a label for this particular tx, we ignore the error.
	case ErrNoLabelBucket:
		fallthrough
	case ErrTxLabelNotFound:
		return "", nil

	// If we found the label, we return it.
	case nil:
		return label, nil
	}

	// Otherwise, another error occurred while looking uo the label, so we
	// return it.
	return "", err
}

// TxDetails looks up all recorded details regarding a transaction with some
// hash.  In case of a hash collision, the most recent transaction with a
// matching hash is returned.
//
// Not finding a transaction with this hash is not an error.  In this case,
// a nil TxDetails is returned.
func (s *Store) TxDetails(ns walletdb.ReadBucket, txHash *chainhash.Hash) (*TxDetails, error) {
	// First, check whether there exists an unmined transaction with this
	// hash.  Use it if found.
	v := existsRawUnmined(ns, txHash[:])
	if v != nil {
		return s.unminedTxDetails(ns, txHash, v)
	}

	// Otherwise, if there exists a mined transaction with this matching
	// hash, skip over to the newest and begin fetching all details.
	k, v := latestTxRecord(ns, txHash)
	if v == nil {
		// not found
		return nil, nil
	}
	return s.minedTxDetails(ns, txHash, k, v)
}

// UniqueTxDetails looks up all recorded details for a transaction recorded
// mined in some particular block, or an unmined transaction if block is nil.
//
// Not finding a transaction with this hash from this block is not an error.  In
// this case, a nil TxDetails is returned.
func (s *Store) UniqueTxDetails(ns walletdb.ReadBucket, txHash *chainhash.Hash,
	block *Block) (*TxDetails, error) {

	if block == nil {
		v := existsRawUnmined(ns, txHash[:])
		if v == nil {
			return nil, nil
		}
		return s.unminedTxDetails(ns, txHash, v)
	}

	k, v := existsTxRecord(ns, txHash, block)
	if v == nil {
		return nil, nil
	}
	return s.minedTxDetails(ns, txHash, k, v)
}

// rangeUnminedTransactions executes the function f with TxDetails for every
// unmined transaction.  f is not executed if no unmined transactions exist.
// Error returns from f (if any) are propigated to the caller.  Returns true
// (signaling breaking out of a RangeTransactions) iff f executes and returns
// true.
func (s *Store) rangeUnminedTransactions(ns walletdb.ReadBucket, f func([]TxDetails) (bool, error)) (bool, error) {
	var details []TxDetails
	err := ns.NestedReadBucket(bucketUnmined).ForEach(func(k, v []byte) error {
		if len(k) < 32 {
			str := fmt.Sprintf("%s: short key (expected %d "+
				"bytes, read %d)", bucketUnmined, 32, len(k))
			return storeError(ErrData, str, nil)
		}

		var txHash chainhash.Hash
		copy(txHash[:], k)
		detail, err := s.unminedTxDetails(ns, &txHash, v)
		if err != nil {
			return err
		}

		// Because the key was created while foreach-ing over the
		// bucket, it should be impossible for unminedTxDetails to ever
		// successfully return a nil details struct.
		details = append(details, *detail)
		return nil
	})
	if err == nil && len(details) > 0 {
		return f(details)
	}
	return false, err
}

// rangeBlockTransactions executes the function f with TxDetails for every block
// between heights begin and end (reverse order when end > begin) until f
// returns true, or the transactions from block is processed.  Returns true iff
// f executes and returns true.
func (s *Store) rangeBlockTransactions(ns walletdb.ReadBucket, begin, end int32,
	f func([]TxDetails) (bool, error)) (bool, error) {

	// Mempool height is considered a high bound.
	if begin < 0 {
		begin = int32(^uint32(0) >> 1)
	}
	if end < 0 {
		end = int32(^uint32(0) >> 1)
	}

	var blockIter blockIterator
	var advance func(*blockIterator) bool
	if begin < end {
		// Iterate in forwards order
		blockIter = makeReadBlockIterator(ns, begin)
		advance = func(it *blockIterator) bool {
			if !it.next() {
				return false
			}
			return it.elem.Height <= end
		}
	} else {
		// Iterate in backwards order, from begin -> end.
		blockIter = makeReadBlockIterator(ns, begin)
		advance = func(it *blockIterator) bool {
			if !it.prev() {
				return false
			}
			return end <= it.elem.Height
		}
	}

	var details []TxDetails
	for advance(&blockIter) {
		block := &blockIter.elem

		if cap(details) < len(block.transactions) {
			details = make([]TxDetails, 0, len(block.transactions))
		} else {
			details = details[:0]
		}

		for _, txHash := range block.transactions {
			k := keyTxRecord(&txHash, &block.Block)
			v := existsRawTxRecord(ns, k)
			if v == nil {
				str := fmt.Sprintf("missing transaction %v for "+
					"block %v", txHash, block.Height)
				return false, storeError(ErrData, str, nil)
			}

			detail, err := s.minedTxDetails(ns, &txHash, k, v)
			if err != nil {
				return false, err
			}

			details = append(details, *detail)
		}

		// Every block record must have at least one transaction, so it
		// is safe to call f.
		brk, err := f(details)
		if err != nil || brk {
			return brk, err
		}
	}
	return false, blockIter.err
}

// RangeTransactions runs the function f on all transaction details between
// blocks on the best chain over the height range [begin,end].  The special
// height -1 may be used to also include unmined transactions.  If the end
// height comes before the begin height, blocks are iterated in reverse order
// and unmined transactions (if any) are processed first.
//
// The function f may return an error which, if non-nil, is propagated to the
// caller.  Additionally, a boolean return value allows exiting the function
// early without reading any additional transactions early when true.
//
// All calls to f are guaranteed to be passed a slice with more than zero
// elements.  The slice may be reused for multiple blocks, so it is not safe to
// use it after the loop iteration it was acquired.
func (s *Store) RangeTransactions(ns walletdb.ReadBucket, begin, end int32,
	f func([]TxDetails) (bool, error)) error {

	var addedUnmined bool
	if begin < 0 {
		brk, err := s.rangeUnminedTransactions(ns, f)
		if err != nil || brk {
			return err
		}
		addedUnmined = true
	}

	brk, err := s.rangeBlockTransactions(ns, begin, end, f)
	if err == nil && !brk && !addedUnmined && end < 0 {
		_, err = s.rangeUnminedTransactions(ns, f)
	}
	return err
}

// PreviousPkScripts returns a slice of previous output scripts for each credit
// output this transaction record debits from.
func (s *Store) PreviousPkScripts(ns walletdb.ReadBucket, rec *TxRecord, block *Block) ([][]byte, error) {
	var pkScripts [][]byte

	if block == nil {
		for _, input := range rec.MsgTx.TxIn {
			prevOut := &input.PreviousOutPoint

			// Input may spend a previous unmined output, a
			// mined output (which would still be marked
			// unspent), or neither.

			v := existsRawUnmined(ns, prevOut.Hash[:])
			if v != nil {
				// Ensure a credit exists for this
				// unmined transaction before including
				// the output script.
				k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
				if existsRawUnminedCredit(ns, k) == nil {
					continue
				}

				pkScript, err := fetchRawTxRecordPkScript(
					prevOut.Hash[:], v, prevOut.Index)
				if err != nil {
					return nil, err
				}
				pkScripts = append(pkScripts, pkScript)
				continue
			}

			_, credKey := existsUnspent(ns, prevOut)
			if credKey != nil {
				k := extractRawCreditTxRecordKey(credKey)
				v = existsRawTxRecord(ns, k)
				pkScript, err := fetchRawTxRecordPkScript(k, v,
					prevOut.Index)
				if err != nil {
					return nil, err
				}
				pkScripts = append(pkScripts, pkScript)
				continue
			}
		}
		return pkScripts, nil
	}

	recKey := keyTxRecord(&rec.Hash, block)
	it := makeReadDebitIterator(ns, recKey)
	for it.next() {
		credKey := extractRawDebitCreditKey(it.cv)
		index := extractRawCreditIndex(credKey)
		k := extractRawCreditTxRecordKey(credKey)
		v := existsRawTxRecord(ns, k)
		pkScript, err := fetchRawTxRecordPkScript(k, v, index)
		if err != nil {
			return nil, err
		}
		pkScripts = append(pkScripts, pkScript)
	}
	if it.err != nil {
		return nil, it.err
	}

	return pkScripts, nil
}
