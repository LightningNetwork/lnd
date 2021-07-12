// Copyright (c) 2016 The Decred developers
// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type unstableAPI struct {
	w *Wallet
}

// UnstableAPI exposes additional unstable public APIs for a Wallet.  These APIs
// may be changed or removed at any time.  Currently this type exists to ease
// the transation (particularly for the legacy JSON-RPC server) from using
// exported manager packages to a unified wallet package that exposes all
// functionality by itself.  New code should not be written using this API.
func UnstableAPI(w *Wallet) unstableAPI { return unstableAPI{w} }

// TxDetails calls wtxmgr.Store.TxDetails under a single database view transaction.
func (u unstableAPI) TxDetails(txHash *chainhash.Hash) (*wtxmgr.TxDetails, error) {
	var details *wtxmgr.TxDetails
	err := walletdb.View(u.w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		details, err = u.w.TxStore.TxDetails(txmgrNs, txHash)
		return err
	})
	return details, err
}

// RangeTransactions calls wtxmgr.Store.RangeTransactions under a single
// database view tranasction.
func (u unstableAPI) RangeTransactions(begin, end int32, f func([]wtxmgr.TxDetails) (bool, error)) error {
	return walletdb.View(u.w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
		return u.w.TxStore.RangeTransactions(txmgrNs, begin, end, f)
	})
}
