// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// MakeMultiSigScript creates a multi-signature script that can be redeemed with
// nRequired signatures of the passed keys and addresses.  If the address is a
// P2PKH address, the associated pubkey is looked up by the wallet if possible,
// otherwise an error is returned for a missing pubkey.
//
// This function only works with pubkeys and P2PKH addresses derived from them.
func (w *Wallet) MakeMultiSigScript(addrs []btcutil.Address, nRequired int) ([]byte, error) {
	pubKeys := make([]*btcutil.AddressPubKey, len(addrs))

	var dbtx walletdb.ReadTx
	var addrmgrNs walletdb.ReadBucket
	defer func() {
		if dbtx != nil {
			dbtx.Rollback()
		}
	}()

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, addr := range addrs {
		switch addr := addr.(type) {
		default:
			return nil, errors.New("cannot make multisig script for " +
				"a non-secp256k1 public key or P2PKH address")

		case *btcutil.AddressPubKey:
			pubKeys[i] = addr

		case *btcutil.AddressPubKeyHash:
			if dbtx == nil {
				var err error
				dbtx, err = w.db.BeginReadTx()
				if err != nil {
					return nil, err
				}
				addrmgrNs = dbtx.ReadBucket(waddrmgrNamespaceKey)
			}
			addrInfo, err := w.Manager.Address(addrmgrNs, addr)
			if err != nil {
				return nil, err
			}
			serializedPubKey := addrInfo.(waddrmgr.ManagedPubKeyAddress).
				PubKey().SerializeCompressed()

			pubKeyAddr, err := btcutil.NewAddressPubKey(
				serializedPubKey, w.chainParams)
			if err != nil {
				return nil, err
			}
			pubKeys[i] = pubKeyAddr
		}
	}

	return txscript.MultiSigScript(pubKeys, nRequired)
}

// ImportP2SHRedeemScript adds a P2SH redeem script to the wallet.
func (w *Wallet) ImportP2SHRedeemScript(script []byte) (*btcutil.AddressScriptHash, error) {
	var p2shAddr *btcutil.AddressScriptHash
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// TODO(oga) blockstamp current block?
		bs := &waddrmgr.BlockStamp{
			Hash:   *w.ChainParams().GenesisHash,
			Height: 0,
		}

		// As this is a regular P2SH script, we'll import this into the
		// BIP0044 scope.
		bip44Mgr, err := w.Manager.FetchScopedKeyManager(
			waddrmgr.KeyScopeBIP0084,
		)
		if err != nil {
			return err
		}

		addrInfo, err := bip44Mgr.ImportScript(addrmgrNs, script, bs)
		if err != nil {
			// Don't care if it's already there, but still have to
			// set the p2shAddr since the address manager didn't
			// return anything useful.
			if waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress) {
				// This function will never error as it always
				// hashes the script to the correct length.
				p2shAddr, _ = btcutil.NewAddressScriptHash(script,
					w.chainParams)
				return nil
			}
			return err
		}

		p2shAddr = addrInfo.Address().(*btcutil.AddressScriptHash)
		return nil
	})
	return p2shAddr, err
}
