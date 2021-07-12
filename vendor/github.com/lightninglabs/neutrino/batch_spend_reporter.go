package neutrino

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// batchSpendReporter orchestrates the delivery of spend reports to
// GetUtxoRequests processed by the UtxoScanner. The reporter expects a sequence
// of blocks consisting of those containing a UTXO to watch, or any whose
// filter generates a match using current filterEntries. This instance supports
// multiple requests for the same outpoint.
type batchSpendReporter struct {
	// requests maps an outpoint to list of GetUtxoRequests waiting for that
	// UTXO's spend report.
	requests map[wire.OutPoint][]*GetUtxoRequest

	// initialTxns contains a map from an outpoint to the "unspent" version
	// of it's spend report. This value is populated by fetching the output
	// from the block in the request's start height. This spend report will
	// be returned in the case that the output remained unspent for the
	// duration of the scan.
	initialTxns map[wire.OutPoint]*SpendReport

	// outpoints caches the filter entry for each outpoint, conserving
	// allocations when reconstructing the current filterEntries.
	outpoints map[wire.OutPoint][]byte

	// filterEntries holds the current set of watched outpoint, and is
	// applied to cfilters to guage whether we should download the block.
	//
	// NOTE: This watchlist is updated during each call to ProcessBlock.
	filterEntries [][]byte
}

// newBatchSpendReporter instantiates a fresh batchSpendReporter.
func newBatchSpendReporter() *batchSpendReporter {
	return &batchSpendReporter{
		requests:    make(map[wire.OutPoint][]*GetUtxoRequest),
		initialTxns: make(map[wire.OutPoint]*SpendReport),
		outpoints:   make(map[wire.OutPoint][]byte),
	}
}

// NotifyUnspentAndUnfound iterates through any requests for which no spends
// were detected. If we were able to find the initial output, this will be
// delivered signaling that no spend was detected. If the original output could
// not be found, a nil spend report is returned.
func (b *batchSpendReporter) NotifyUnspentAndUnfound() {
	log.Debugf("Finished batch, %d unspent outpoints", len(b.requests))

	for outpoint, requests := range b.requests {
		// A nil SpendReport indicates the output was not found.
		tx, ok := b.initialTxns[outpoint]
		if !ok {
			log.Warnf("Unknown initial txn for getuxo request %v",
				outpoint)
		}

		b.notifyRequests(&outpoint, requests, tx, nil)
	}
}

// FailRemaining will return an error to all remaining requests in the event we
// experience a critical rescan error. The error is threaded through to allow
// the syntax:
//     return reporter.FailRemaining(err)
func (b *batchSpendReporter) FailRemaining(err error) error {
	for outpoint, requests := range b.requests {
		b.notifyRequests(&outpoint, requests, nil, err)
	}
	return err
}

// notifyRequests delivers the same final response to the given requests, and
// cleans up any remaining state for the outpoint.
//
// NOTE: AT MOST ONE of `report` or `err` may be non-nil.
func (b *batchSpendReporter) notifyRequests(
	outpoint *wire.OutPoint,
	requests []*GetUtxoRequest,
	report *SpendReport,
	err error) {

	delete(b.requests, *outpoint)
	delete(b.initialTxns, *outpoint)
	delete(b.outpoints, *outpoint)

	for _, request := range requests {
		request.deliver(report, err)
	}
}

// ProcessBlock accepts a block, block height, and any new requests whose start
// height matches the provided height. If a non-zero number of new requests are
// presented, the block will first be checked for the initial outputs from which
// spends may occur. Afterwards, any spends detected in the block are
// immediately dispatched, and the watchlist updated in preparation of filtering
// the next block.
func (b *batchSpendReporter) ProcessBlock(blk *wire.MsgBlock,
	newReqs []*GetUtxoRequest, height uint32) {

	// If any requests want the UTXOs at this height, scan the block to find
	// the original outputs that might be spent from.
	if len(newReqs) > 0 {
		b.addNewRequests(newReqs)
		b.findInitialTransactions(blk, newReqs, height)
	}

	// Next, filter the block for any spends using the current set of
	// watched outpoints. This will include any new requests added above.
	spends := b.notifySpends(blk, height)

	// Finally, rebuild filter entries from cached entries remaining in
	// outpoints map. This will provide an updated watchlist used to scan
	// the subsequent filters.
	rebuildWatchlist := len(newReqs) > 0 || len(spends) > 0
	if rebuildWatchlist {
		b.filterEntries = b.filterEntries[:0]
		for _, entry := range b.outpoints {
			b.filterEntries = append(b.filterEntries, entry)
		}
	}
}

// addNewRequests adds a set of new GetUtxoRequests to the spend reporter's
// state. This method immediately adds the request's outpoints to the reporter's
// watchlist.
func (b *batchSpendReporter) addNewRequests(reqs []*GetUtxoRequest) {
	for _, req := range reqs {
		outpoint := req.Input.OutPoint

		log.Debugf("Adding outpoint=%s height=%d to watchlist",
			outpoint, req.BirthHeight)

		b.requests[outpoint] = append(b.requests[outpoint], req)

		// Build the filter entry only if it is the first time seeing
		// the outpoint.
		if _, ok := b.outpoints[outpoint]; !ok {
			entry := req.Input.PkScript
			b.outpoints[outpoint] = entry
			b.filterEntries = append(b.filterEntries, entry)
		}
	}
}

// findInitialTransactions searches the given block for the creation of the
// UTXOs that are supposed to be birthed in this block. If any are found, a
// spend report containing the initial outpoint will be saved in case the
// outpoint is not spent later on. Requests corresponding to outpoints that are
// not found in the block will return a nil spend report to indicate that the
// UTXO was not found.
func (b *batchSpendReporter) findInitialTransactions(block *wire.MsgBlock,
	newReqs []*GetUtxoRequest, height uint32) map[wire.OutPoint]*SpendReport {

	// First, construct  a reverse index from txid to all a list of requests
	// whose outputs share the same txid.
	txidReverseIndex := make(map[chainhash.Hash][]*GetUtxoRequest)
	for _, req := range newReqs {
		txidReverseIndex[req.Input.OutPoint.Hash] = append(
			txidReverseIndex[req.Input.OutPoint.Hash], req,
		)
	}

	// Iterate over the transactions in this block, hashing each and
	// querying our reverse index to see if any requests depend on the txn.
	initialTxns := make(map[wire.OutPoint]*SpendReport)
	for _, tx := range block.Transactions {
		// If our reverse index has been cleared, we are done.
		if len(txidReverseIndex) == 0 {
			break
		}

		hash := tx.TxHash()
		txidReqs, ok := txidReverseIndex[hash]
		if !ok {
			continue
		}
		delete(txidReverseIndex, hash)

		// For all requests that are watching this txid, use the output
		// index of each to grab the initial output.
		txOuts := tx.TxOut
		for _, req := range txidReqs {
			op := req.Input.OutPoint

			// Ensure that the outpoint's index references an actual
			// output on the transaction. If not, we will be unable
			// to find the initial output.
			if op.Index >= uint32(len(txOuts)) {
				log.Errorf("Failed to find outpoint %s -- "+
					"invalid output index", op)
				initialTxns[op] = nil
				continue
			}

			initialTxns[op] = &SpendReport{
				Output: txOuts[op.Index],
			}
		}
	}

	// Finally, we must reconcile any requests for which the txid did not
	// exist in this block. A nil spend report is saved for every initial
	// txn that could not be found, otherwise the result is copied from scan
	// above. The copied values can include valid initial txns, as well as
	// nil spend report if the output index was invalid.
	for _, req := range newReqs {
		tx, ok := initialTxns[req.Input.OutPoint]
		switch {
		case !ok:
			log.Debugf("Outpoint %v not found in block %d ",
				req.Input.OutPoint, height)
			initialTxns[req.Input.OutPoint] = nil
		case tx != nil:
			log.Tracef("Block %d creates output %s",
				height, req.Input.OutPoint)
		default:
		}

		b.initialTxns[req.Input.OutPoint] = tx
	}

	return initialTxns
}

// notifySpends finds any transactions in the block that spend from our watched
// outpoints. If a spend is detected, it is immediately delivered and cleaned up
// from the reporter's internal state.
func (b *batchSpendReporter) notifySpends(block *wire.MsgBlock,
	height uint32) map[wire.OutPoint]*SpendReport {

	spends := make(map[wire.OutPoint]*SpendReport)
	for _, tx := range block.Transactions {
		// Check each input to see if this transaction spends one of our
		// watched outpoints.
		for i, ti := range tx.TxIn {
			outpoint := ti.PreviousOutPoint

			// Find the requests this spend relates to.
			requests, ok := b.requests[outpoint]
			if !ok {
				continue
			}

			log.Debugf("UTXO %v spent by txn %v", outpoint,
				tx.TxHash())

			spend := &SpendReport{
				SpendingTx:         tx,
				SpendingInputIndex: uint32(i),
				SpendingTxHeight:   height,
			}

			spends[outpoint] = spend

			// With the requests located, we remove this outpoint
			// from both the requests, outpoints, and initial txns
			// map. This will ensures we don't continue watching
			// this outpoint.
			b.notifyRequests(&outpoint, requests, spend, nil)
		}
	}

	return spends
}
