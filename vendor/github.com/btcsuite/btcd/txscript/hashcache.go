// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// TxSigHashes houses the partial set of sighashes introduced within BIP0143.
// This partial set of sighashes may be re-used within each input across a
// transaction when validating all inputs. As a result, validation complexity
// for SigHashAll can be reduced by a polynomial factor.
type TxSigHashes struct {
	HashPrevOuts chainhash.Hash
	HashSequence chainhash.Hash
	HashOutputs  chainhash.Hash
}

// NewTxSigHashes computes, and returns the cached sighashes of the given
// transaction.
func NewTxSigHashes(tx *wire.MsgTx) *TxSigHashes {
	return &TxSigHashes{
		HashPrevOuts: calcHashPrevOuts(tx),
		HashSequence: calcHashSequence(tx),
		HashOutputs:  calcHashOutputs(tx),
	}
}

// HashCache houses a set of partial sighashes keyed by txid. The set of partial
// sighashes are those introduced within BIP0143 by the new more efficient
// sighash digest calculation algorithm. Using this threadsafe shared cache,
// multiple goroutines can safely re-use the pre-computed partial sighashes
// speeding up validation time amongst all inputs found within a block.
type HashCache struct {
	sigHashes map[chainhash.Hash]*TxSigHashes

	sync.RWMutex
}

// NewHashCache returns a new instance of the HashCache given a maximum number
// of entries which may exist within it at anytime.
func NewHashCache(maxSize uint) *HashCache {
	return &HashCache{
		sigHashes: make(map[chainhash.Hash]*TxSigHashes, maxSize),
	}
}

// AddSigHashes computes, then adds the partial sighashes for the passed
// transaction.
func (h *HashCache) AddSigHashes(tx *wire.MsgTx) {
	h.Lock()
	h.sigHashes[tx.TxHash()] = NewTxSigHashes(tx)
	h.Unlock()
}

// ContainsHashes returns true if the partial sighashes for the passed
// transaction currently exist within the HashCache, and false otherwise.
func (h *HashCache) ContainsHashes(txid *chainhash.Hash) bool {
	h.RLock()
	_, found := h.sigHashes[*txid]
	h.RUnlock()

	return found
}

// GetSigHashes possibly returns the previously cached partial sighashes for
// the passed transaction. This function also returns an additional boolean
// value indicating if the sighashes for the passed transaction were found to
// be present within the HashCache.
func (h *HashCache) GetSigHashes(txid *chainhash.Hash) (*TxSigHashes, bool) {
	h.RLock()
	item, found := h.sigHashes[*txid]
	h.RUnlock()

	return item, found
}

// PurgeSigHashes removes all partial sighashes from the HashCache belonging to
// the passed transaction.
func (h *HashCache) PurgeSigHashes(txid *chainhash.Hash) {
	h.Lock()
	delete(h.sigHashes, *txid)
	h.Unlock()
}
