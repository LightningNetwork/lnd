// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

// BlockStamp defines a block (by height and a unique hash) and is used to mark
// a point in the blockchain that an address manager element is
// synced to.
type BlockStamp struct {
	Height    int32
	Hash      chainhash.Hash
	Timestamp time.Time
}

// syncState houses the sync state of the manager.  It consists of the recently
// seen blocks as height, as well as the start and current sync block stamps.
type syncState struct {
	// startBlock is the first block that can be safely used to start a
	// rescan.  It is either the block the manager was created with, or the
	// earliest block provided with imported addresses or scripts.
	startBlock BlockStamp

	// syncedTo is the current block the addresses in the manager are known
	// to be synced against.
	syncedTo BlockStamp
}

// newSyncState returns a new sync state with the provided parameters.
func newSyncState(startBlock, syncedTo *BlockStamp) *syncState {

	return &syncState{
		startBlock: *startBlock,
		syncedTo:   *syncedTo,
	}
}

// SetSyncedTo marks the address manager to be in sync with the recently-seen
// block described by the blockstamp.  When the provided blockstamp is nil, the
// oldest blockstamp of the block the manager was created at and of all
// imported addresses will be used.  This effectively allows the manager to be
// marked as unsynced back to the oldest known point any of the addresses have
// appeared in the block chain.
func (m *Manager) SetSyncedTo(ns walletdb.ReadWriteBucket, bs *BlockStamp) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Use the stored start blockstamp and reset recent hashes and height
	// when the provided blockstamp is nil.
	if bs == nil {
		bs = &m.syncState.startBlock
	}

	// Update the database.
	err := PutSyncedTo(ns, bs)
	if err != nil {
		return err
	}

	// Update memory now that the database is updated.
	m.syncState.syncedTo = *bs
	return nil
}

// SyncedTo returns details about the block height and hash that the address
// manager is synced through at the very least.  The intention is that callers
// can use this information for intelligently initiating rescans to sync back to
// the best chain from the last known good block.
func (m *Manager) SyncedTo() BlockStamp {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.syncState.syncedTo
}

// BlockHash returns the block hash at a particular block height. This
// information is useful for comparing against the chain back-end to see if a
// reorg is taking place and how far back it goes.
func (m *Manager) BlockHash(ns walletdb.ReadBucket, height int32) (
	*chainhash.Hash, error) {

	return fetchBlockHash(ns, height)
}

// Birthday returns the birthday, or earliest time a key could have been used,
// for the manager.
func (m *Manager) Birthday() time.Time {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.birthday
}

// SetBirthday sets the birthday, or earliest time a key could have been used,
// for the manager.
func (m *Manager) SetBirthday(ns walletdb.ReadWriteBucket,
	birthday time.Time) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.birthday = birthday
	return putBirthday(ns, birthday)
}

// BirthdayBlock returns the birthday block, or earliest block a key could have
// been used, for the manager. A boolean is also returned to indicate whether
// the birthday block has been verified as correct.
func (m *Manager) BirthdayBlock(ns walletdb.ReadBucket) (BlockStamp, bool, error) {
	birthdayBlock, err := FetchBirthdayBlock(ns)
	if err != nil {
		return BlockStamp{}, false, err
	}

	return birthdayBlock, fetchBirthdayBlockVerification(ns), nil
}

// SetBirthdayBlock sets the birthday block, or earliest time a key could have
// been used, for the manager. The verified boolean can be used to specify
// whether this birthday block should be sanity checked to determine if there
// exists a better candidate to prevent less block fetching.
func (m *Manager) SetBirthdayBlock(ns walletdb.ReadWriteBucket,
	block BlockStamp, verified bool) error {

	if err := PutBirthdayBlock(ns, block); err != nil {
		return err
	}
	return putBirthdayBlockVerification(ns, verified)
}
