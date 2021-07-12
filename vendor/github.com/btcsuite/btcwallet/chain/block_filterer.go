package chain

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// BlockFilterer is used to iteratively scan blocks for a set of addresses of
// interest. This is done by constructing reverse indexes mapping the
// addresses to a ScopedIndex, which permits the reconstruction of the exact
// child deriviation paths that reported matches.
//
// Once initialized, a BlockFilterer can be used to scan any number of blocks
// until a invocation of `FilterBlock` returns true. This allows the reverse
// indexes to be resused in the event that the set of addresses does not need to
// be altered. After a match is reported, a new BlockFilterer should be
// initialized with the updated set of addresses that include any new keys that
// are now within our look-ahead.
//
// We track internal and external addresses separately in order to conserve the
// amount of space occupied in memory. Specifically, the account and branch
// combined contribute only 1-bit of information when using the default scopes
// used by the wallet. Thus we can avoid storing an additional 64-bits per
// address of interest by not storing the full derivation paths, and instead
// opting to allow the caller to contextually infer the account (DefaultAccount)
// and branch (Internal or External).
type BlockFilterer struct {
	// Params specifies the chain params of the current network.
	Params *chaincfg.Params

	// ExReverseFilter holds a reverse index mapping an external address to
	// the scoped index from which it was derived.
	ExReverseFilter map[string]waddrmgr.ScopedIndex

	// InReverseFilter holds a reverse index mapping an internal address to
	// the scoped index from which it was derived.
	InReverseFilter map[string]waddrmgr.ScopedIndex

	// WathcedOutPoints is a global set of outpoints being tracked by the
	// wallet. This allows the block filterer to check for spends from an
	// outpoint we own.
	WatchedOutPoints map[wire.OutPoint]btcutil.Address

	// FoundExternal is a two-layer map recording the scope and index of
	// external addresses found in a single block.
	FoundExternal map[waddrmgr.KeyScope]map[uint32]struct{}

	// FoundInternal is a two-layer map recording the scope and index of
	// internal addresses found in a single block.
	FoundInternal map[waddrmgr.KeyScope]map[uint32]struct{}

	// FoundOutPoints is a set of outpoints found in a single block whose
	// address belongs to the wallet.
	FoundOutPoints map[wire.OutPoint]btcutil.Address

	// RelevantTxns records the transactions found in a particular block
	// that contained matches from an address in either ExReverseFilter or
	// InReverseFilter.
	RelevantTxns []*wire.MsgTx
}

// NewBlockFilterer constructs the reverse indexes for the current set of
// external and internal addresses that we are searching for, and is used to
// scan successive blocks for addresses of interest. A particular block filter
// can be reused until the first call from `FitlerBlock` returns true.
func NewBlockFilterer(params *chaincfg.Params,
	req *FilterBlocksRequest) *BlockFilterer {

	// Construct a reverse index by address string for the requested
	// external addresses.
	nExAddrs := len(req.ExternalAddrs)
	exReverseFilter := make(map[string]waddrmgr.ScopedIndex, nExAddrs)
	for scopedIndex, addr := range req.ExternalAddrs {
		exReverseFilter[addr.EncodeAddress()] = scopedIndex
	}

	// Construct a reverse index by address string for the requested
	// internal addresses.
	nInAddrs := len(req.InternalAddrs)
	inReverseFilter := make(map[string]waddrmgr.ScopedIndex, nInAddrs)
	for scopedIndex, addr := range req.InternalAddrs {
		inReverseFilter[addr.EncodeAddress()] = scopedIndex
	}

	foundExternal := make(map[waddrmgr.KeyScope]map[uint32]struct{})
	foundInternal := make(map[waddrmgr.KeyScope]map[uint32]struct{})
	foundOutPoints := make(map[wire.OutPoint]btcutil.Address)

	return &BlockFilterer{
		Params:           params,
		ExReverseFilter:  exReverseFilter,
		InReverseFilter:  inReverseFilter,
		WatchedOutPoints: req.WatchedOutPoints,
		FoundExternal:    foundExternal,
		FoundInternal:    foundInternal,
		FoundOutPoints:   foundOutPoints,
	}
}

// FilterBlock parses all txns in the provided block, searching for any that
// contain addresses of interest in either the external or internal reverse
// filters. This method return true iff the block contains a non-zero number of
// addresses of interest, or a transaction in the block spends from outpoints
// controlled by the wallet.
func (bf *BlockFilterer) FilterBlock(block *wire.MsgBlock) bool {
	var hasRelevantTxns bool
	for _, tx := range block.Transactions {
		if bf.FilterTx(tx) {
			bf.RelevantTxns = append(bf.RelevantTxns, tx)
			hasRelevantTxns = true
		}
	}

	return hasRelevantTxns
}

// FilterTx scans all txouts in the provided txn, testing to see if any found
// addresses match those contained within the external or internal reverse
// indexes. This method returns true iff the txn contains a non-zero number of
// addresses of interest, or the transaction spends from an outpoint that
// belongs to the wallet.
func (bf *BlockFilterer) FilterTx(tx *wire.MsgTx) bool {
	var isRelevant bool

	// First, check the inputs to this transaction to see if they spend any
	// inputs belonging to the wallet. In addition to checking
	// WatchedOutPoints, we also check FoundOutPoints, in case a txn spends
	// from an outpoint created in the same block.
	for _, in := range tx.TxIn {
		if _, ok := bf.WatchedOutPoints[in.PreviousOutPoint]; ok {
			isRelevant = true
		}
		if _, ok := bf.FoundOutPoints[in.PreviousOutPoint]; ok {
			isRelevant = true
		}
	}

	// Now, parse all of the outputs created by this transactions, and see
	// if they contain any addresses known the wallet using our reverse
	// indexes for both external and internal addresses. If a new output is
	// found, we will add the outpoint to our set of FoundOutPoints.
	for i, out := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			out.PkScript, bf.Params,
		)
		if err != nil {
			log.Warnf("Could not parse output script in %s:%d: %v",
				tx.TxHash(), i, err)
			continue
		}

		if !bf.FilterOutputAddrs(addrs) {
			continue
		}

		// If we've reached this point, then the output contains an
		// address of interest.
		isRelevant = true

		// Record the outpoint that containing the address in our set of
		// found outpoints, so that the caller can update its global
		// set of watched outpoints.
		outPoint := wire.OutPoint{
			Hash:  *btcutil.NewTx(tx).Hash(),
			Index: uint32(i),
		}

		bf.FoundOutPoints[outPoint] = addrs[0]
	}

	return isRelevant
}

// FilterOutputAddrs tests the set of addresses against the block filterer's
// external and internal reverse address indexes. If any are found, they are
// added to set of external and internal found addresses, respectively. This
// method returns true iff a non-zero number of the provided addresses are of
// interest.
func (bf *BlockFilterer) FilterOutputAddrs(addrs []btcutil.Address) bool {
	var isRelevant bool
	for _, addr := range addrs {
		addrStr := addr.EncodeAddress()
		if scopedIndex, ok := bf.ExReverseFilter[addrStr]; ok {
			bf.foundExternal(scopedIndex)
			isRelevant = true
		}
		if scopedIndex, ok := bf.InReverseFilter[addrStr]; ok {
			bf.foundInternal(scopedIndex)
			isRelevant = true
		}
	}

	return isRelevant
}

// foundExternal marks the scoped index as found within the block filterer's
// FoundExternal map. If this the first index found for a particular scope, the
// scope's second layer map will be initialized before marking the index.
func (bf *BlockFilterer) foundExternal(scopedIndex waddrmgr.ScopedIndex) {
	if _, ok := bf.FoundExternal[scopedIndex.Scope]; !ok {
		bf.FoundExternal[scopedIndex.Scope] = make(map[uint32]struct{})
	}
	bf.FoundExternal[scopedIndex.Scope][scopedIndex.Index] = struct{}{}
}

// foundInternal marks the scoped index as found within the block filterer's
// FoundInternal map. If this the first index found for a particular scope, the
// scope's second layer map will be initialized before marking the index.
func (bf *BlockFilterer) foundInternal(scopedIndex waddrmgr.ScopedIndex) {
	if _, ok := bf.FoundInternal[scopedIndex.Scope]; !ok {
		bf.FoundInternal[scopedIndex.Scope] = make(map[uint32]struct{})
	}
	bf.FoundInternal[scopedIndex.Scope][scopedIndex.Index] = struct{}{}
}
