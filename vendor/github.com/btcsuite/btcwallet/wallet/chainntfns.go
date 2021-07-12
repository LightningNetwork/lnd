// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// birthdayBlockDelta is the maximum time delta allowed between our
	// birthday timestamp and our birthday block's timestamp when searching
	// for a better birthday block candidate (if possible).
	birthdayBlockDelta = 2 * time.Hour
)

func (w *Wallet) handleChainNotifications() {
	defer w.wg.Done()

	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		return
	}

	catchUpHashes := func(w *Wallet, client chain.Interface,
		height int32) error {
		// TODO(aakselrod): There's a race conditon here, which
		// happens when a reorg occurs between the
		// rescanProgress notification and the last GetBlockHash
		// call. The solution when using btcd is to make btcd
		// send blockconnected notifications with each block
		// the way Neutrino does, and get rid of the loop. The
		// other alternative is to check the final hash and,
		// if it doesn't match the original hash returned by
		// the notification, to roll back and restart the
		// rescan.
		log.Infof("Catching up block hashes to height %d, this"+
			" might take a while", height)
		err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			startBlock := w.Manager.SyncedTo()

			for i := startBlock.Height + 1; i <= height; i++ {
				hash, err := client.GetBlockHash(int64(i))
				if err != nil {
					return err
				}
				header, err := chainClient.GetBlockHeader(hash)
				if err != nil {
					return err
				}

				bs := waddrmgr.BlockStamp{
					Height:    i,
					Hash:      *hash,
					Timestamp: header.Timestamp,
				}
				err = w.Manager.SetSyncedTo(ns, &bs)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Errorf("Failed to update address manager "+
				"sync state for height %d: %v", height, err)
		}

		log.Info("Done catching up block hashes")
		return err
	}

	for {
		select {
		case n, ok := <-chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				// Before attempting to sync with our backend,
				// we'll make sure that our birthday block has
				// been set correctly to potentially prevent
				// missing relevant events.
				birthdayStore := &walletBirthdayStore{
					db:      w.db,
					manager: w.Manager,
				}
				birthdayBlock, err := birthdaySanityCheck(
					chainClient, birthdayStore,
				)
				if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet) {
					panic(fmt.Errorf("Unable to sanity "+
						"check wallet birthday block: %v",
						err))
				}

				err = w.syncWithChain(birthdayBlock)
				if err != nil && !w.ShuttingDown() {
					panic(fmt.Errorf("Unable to synchronize "+
						"wallet to chain: %v", err))
				}
			case chain.BlockConnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.connectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "block connected"
			case chain.BlockDisconnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.disconnectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "block disconnected"
			case chain.RelevantTx:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.addRelevantTx(tx, n.TxRecord, n.Block)
				})
				notificationName = "relevant transaction"
			case chain.FilteredBlockConnected:
				// Atomically update for the whole block.
				if len(n.RelevantTxs) > 0 {
					err = walletdb.Update(w.db, func(
						tx walletdb.ReadWriteTx) error {
						var err error
						for _, rec := range n.RelevantTxs {
							err = w.addRelevantTx(tx, rec,
								n.Block)
							if err != nil {
								return err
							}
						}
						return nil
					})
				}
				notificationName = "filtered block connected"

			// The following require some database maintenance, but also
			// need to be reported to the wallet's rescan goroutine.
			case *chain.RescanProgress:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescan progress"
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			case *chain.RescanFinished:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescan finished"
				w.SetChainSynced(true)
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			}
			if err != nil {
				// If we received a block connected notification
				// while rescanning, then we can ignore logging
				// the error as we'll properly catch up once we
				// process the RescanFinished notification.
				if notificationName == "block connected" &&
					waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) &&
					!w.ChainSynced() {

					log.Debugf("Received block connected "+
						"notification for height %v "+
						"while rescanning",
						n.(chain.BlockConnected).Height)
					continue
				}

				log.Errorf("Unable to process chain backend "+
					"%v notification: %v", notificationName,
					err)
			}
		case <-w.quit:
			return
		}
	}
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.
func (w *Wallet) connectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	bs := waddrmgr.BlockStamp{
		Height:    b.Height,
		Hash:      b.Hash,
		Timestamp: b.Time,
	}
	err := w.Manager.SetSyncedTo(addrmgrNs, &bs)
	if err != nil {
		return err
	}

	// Notify interested clients of the connected block.
	//
	// TODO: move all notifications outside of the database transaction.
	w.NtfnServer.notifyAttachedBlock(dbtx, &b)
	return nil
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (w *Wallet) disconnectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	if !w.ChainSynced() {
		return nil
	}

	// Disconnect the removed block and all blocks after it if we know about
	// the disconnected block. Otherwise, the block is in the future.
	if b.Height <= w.Manager.SyncedTo().Height {
		hash, err := w.Manager.BlockHash(addrmgrNs, b.Height)
		if err != nil {
			return err
		}
		if bytes.Equal(hash[:], b.Hash[:]) {
			bs := waddrmgr.BlockStamp{
				Height: b.Height - 1,
			}
			hash, err = w.Manager.BlockHash(addrmgrNs, bs.Height)
			if err != nil {
				return err
			}
			b.Hash = *hash

			client := w.ChainClient()
			header, err := client.GetBlockHeader(hash)
			if err != nil {
				return err
			}

			bs.Timestamp = header.Timestamp
			err = w.Manager.SetSyncedTo(addrmgrNs, &bs)
			if err != nil {
				return err
			}

			err = w.TxStore.Rollback(txmgrNs, b.Height)
			if err != nil {
				return err
			}
		}
	}

	// Notify interested clients of the disconnected block.
	w.NtfnServer.notifyDetachedBlock(&b.Hash)

	return nil
}

func (w *Wallet) addRelevantTx(dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	err := w.TxStore.InsertTx(txmgrNs, rec, block)
	if err != nil {
		return err
	}

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range rec.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,
			w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		for _, addr := range addrs {
			ma, err := w.Manager.Address(addrmgrNs, addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.TxStore.AddCredit(txmgrNs, rec, block, uint32(i),
					ma.Internal())
				if err != nil {
					return err
				}
				err = w.Manager.MarkUsed(addrmgrNs, addr)
				if err != nil {
					return err
				}
				log.Debugf("Marked address %v used", addr)
				continue
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if !waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				return err
			}
		}
	}

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: Avoid the extra db hits.
	if block == nil {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, nil)
		if err != nil {
			log.Errorf("Cannot query transaction details for notification: %v", err)
		}

		// It's possible that the transaction was not found within the
		// wallet's set of unconfirmed transactions due to it already
		// being confirmed, so we'll avoid notifying it.
		//
		// TODO(wilmer): ideally we should find the culprit to why we're
		// receiving an additional unconfirmed chain.RelevantTx
		// notification from the chain backend.
		if details != nil {
			w.NtfnServer.notifyUnminedTransaction(dbtx, details)
		}
	} else {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, &block.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for notification: %v", err)
		}

		// We'll only notify the transaction if it was found within the
		// wallet's set of confirmed transactions.
		if details != nil {
			w.NtfnServer.notifyMinedTransaction(dbtx, details, block)
		}
	}

	return nil
}

// chainConn is an interface that abstracts the chain connection logic required
// to perform a wallet's birthday block sanity check.
type chainConn interface {
	// GetBestBlock returns the hash and height of the best block known to
	// the backend.
	GetBestBlock() (*chainhash.Hash, int32, error)

	// GetBlockHash returns the hash of the block with the given height.
	GetBlockHash(int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header for the block with the given hash.
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
}

// birthdayStore is an interface that abstracts the wallet's sync-related
// information required to perform a birthday block sanity check.
type birthdayStore interface {
	// Birthday returns the birthday timestamp of the wallet.
	Birthday() time.Time

	// BirthdayBlock returns the birthday block of the wallet. The boolean
	// returned should signal whether the wallet has already verified the
	// correctness of its birthday block.
	BirthdayBlock() (waddrmgr.BlockStamp, bool, error)

	// SetBirthdayBlock updates the birthday block of the wallet to the
	// given block. The boolean can be used to signal whether this block
	// should be sanity checked the next time the wallet starts.
	//
	// NOTE: This should also set the wallet's synced tip to reflect the new
	// birthday block. This will allow the wallet to rescan from this point
	// to detect any potentially missed events.
	SetBirthdayBlock(waddrmgr.BlockStamp) error
}

// walletBirthdayStore is a wrapper around the wallet's database and address
// manager that satisfies the birthdayStore interface.
type walletBirthdayStore struct {
	db      walletdb.DB
	manager *waddrmgr.Manager
}

var _ birthdayStore = (*walletBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *walletBirthdayStore) Birthday() time.Time {
	return s.manager.Birthday()
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *walletBirthdayStore) BirthdayBlock() (waddrmgr.BlockStamp, bool, error) {
	var (
		birthdayBlock         waddrmgr.BlockStamp
		birthdayBlockVerified bool
	)

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		var err error
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		birthdayBlock, birthdayBlockVerified, err = s.manager.BirthdayBlock(ns)
		return err
	})

	return birthdayBlock, birthdayBlockVerified, err
}

// SetBirthdayBlock updates the birthday block of the wallet to the
// given block. The boolean can be used to signal whether this block
// should be sanity checked the next time the wallet starts.
//
// NOTE: This should also set the wallet's synced tip to reflect the new
// birthday block. This will allow the wallet to rescan from this point
// to detect any potentially missed events.
func (s *walletBirthdayStore) SetBirthdayBlock(block waddrmgr.BlockStamp) error {
	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		err := s.manager.SetBirthdayBlock(ns, block, true)
		if err != nil {
			return err
		}
		return s.manager.SetSyncedTo(ns, &block)
	})
}

// birthdaySanityCheck is a helper function that ensures a birthday block
// correctly reflects the birthday timestamp within a reasonable timestamp
// delta. It's intended to be run after the wallet establishes its connection
// with the backend, but before it begins syncing. This is done as the second
// part to the wallet's address manager migration where we populate the birthday
// block to ensure we do not miss any relevant events throughout rescans.
// waddrmgr.ErrBirthdayBlockNotSet is returned if the birthday block has not
// been set yet.
func birthdaySanityCheck(chainConn chainConn,
	birthdayStore birthdayStore) (*waddrmgr.BlockStamp, error) {

	// We'll start by fetching our wallet's birthday timestamp and block.
	birthdayTimestamp := birthdayStore.Birthday()
	birthdayBlock, birthdayBlockVerified, err := birthdayStore.BirthdayBlock()
	if err != nil {
		return nil, err
	}

	// If the birthday block has already been verified to be correct, we can
	// exit our sanity check to prevent potentially fetching a better
	// candidate.
	if birthdayBlockVerified {
		log.Debugf("Birthday block has already been verified: "+
			"height=%d, hash=%v", birthdayBlock.Height,
			birthdayBlock.Hash)

		return &birthdayBlock, nil
	}

	// Otherwise, we'll attempt to locate a better one now that we have
	// access to the chain.
	newBirthdayBlock, err := locateBirthdayBlock(chainConn, birthdayTimestamp)
	if err != nil {
		return nil, err
	}

	if err := birthdayStore.SetBirthdayBlock(*newBirthdayBlock); err != nil {
		return nil, err
	}

	return newBirthdayBlock, nil
}
