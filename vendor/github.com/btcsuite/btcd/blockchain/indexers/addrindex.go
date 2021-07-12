// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// addrIndexName is the human-readable name for the index.
	addrIndexName = "address index"

	// level0MaxEntries is the maximum number of transactions that are
	// stored in level 0 of an address index entry.  Subsequent levels store
	// 2^n * level0MaxEntries entries, or in words, double the maximum of
	// the previous level.
	level0MaxEntries = 8

	// addrKeySize is the number of bytes an address key consumes in the
	// index.  It consists of 1 byte address type + 20 bytes hash160.
	addrKeySize = 1 + 20

	// levelKeySize is the number of bytes a level key in the address index
	// consumes.  It consists of the address key + 1 byte for the level.
	levelKeySize = addrKeySize + 1

	// levelOffset is the offset in the level key which identifes the level.
	levelOffset = levelKeySize - 1

	// addrKeyTypePubKeyHash is the address type in an address key which
	// represents both a pay-to-pubkey-hash and a pay-to-pubkey address.
	// This is done because both are identical for the purposes of the
	// address index.
	addrKeyTypePubKeyHash = 0

	// addrKeyTypeScriptHash is the address type in an address key which
	// represents a pay-to-script-hash address.  This is necessary because
	// the hash of a pubkey address might be the same as that of a script
	// hash.
	addrKeyTypeScriptHash = 1

	// addrKeyTypePubKeyHash is the address type in an address key which
	// represents a pay-to-witness-pubkey-hash address. This is required
	// as the 20-byte data push of a p2wkh witness program may be the same
	// data push used a p2pkh address.
	addrKeyTypeWitnessPubKeyHash = 2

	// addrKeyTypeScriptHash is the address type in an address key which
	// represents a pay-to-witness-script-hash address. This is required,
	// as p2wsh are distinct from p2sh addresses since they use a new
	// script template, as well as a 32-byte data push.
	addrKeyTypeWitnessScriptHash = 3

	// Size of a transaction entry.  It consists of 4 bytes block id + 4
	// bytes offset + 4 bytes length.
	txEntrySize = 4 + 4 + 4
)

var (
	// addrIndexKey is the key of the address index and the db bucket used
	// to house it.
	addrIndexKey = []byte("txbyaddridx")

	// errUnsupportedAddressType is an error that is used to signal an
	// unsupported address type has been used.
	errUnsupportedAddressType = errors.New("address type is not supported " +
		"by the address index")
)

// -----------------------------------------------------------------------------
// The address index maps addresses referenced in the blockchain to a list of
// all the transactions involving that address.  Transactions are stored
// according to their order of appearance in the blockchain.  That is to say
// first by block height and then by offset inside the block.  It is also
// important to note that this implementation requires the transaction index
// since it is needed in order to catch up old blocks due to the fact the spent
// outputs will already be pruned from the utxo set.
//
// The approach used to store the index is similar to a log-structured merge
// tree (LSM tree) and is thus similar to how leveldb works internally.
//
// Every address consists of one or more entries identified by a level starting
// from 0 where each level holds a maximum number of entries such that each
// subsequent level holds double the maximum of the previous one.  In equation
// form, the number of entries each level holds is 2^n * firstLevelMaxSize.
//
// New transactions are appended to level 0 until it becomes full at which point
// the entire level 0 entry is appended to the level 1 entry and level 0 is
// cleared.  This process continues until level 1 becomes full at which point it
// will be appended to level 2 and cleared and so on.
//
// The result of this is the lower levels contain newer transactions and the
// transactions within each level are ordered from oldest to newest.
//
// The intent of this approach is to provide a balance between space efficiency
// and indexing cost.  Storing one entry per transaction would have the lowest
// indexing cost, but would waste a lot of space because the same address hash
// would be duplicated for every transaction key.  On the other hand, storing a
// single entry with all transactions would be the most space efficient, but
// would cause indexing cost to grow quadratically with the number of
// transactions involving the same address.  The approach used here provides
// logarithmic insertion and retrieval.
//
// The serialized key format is:
//
//   <addr type><addr hash><level>
//
//   Field           Type      Size
//   addr type       uint8     1 byte
//   addr hash       hash160   20 bytes
//   level           uint8     1 byte
//   -----
//   Total: 22 bytes
//
// The serialized value format is:
//
//   [<block id><start offset><tx length>,...]
//
//   Field           Type      Size
//   block id        uint32    4 bytes
//   start offset    uint32    4 bytes
//   tx length       uint32    4 bytes
//   -----
//   Total: 12 bytes per indexed tx
// -----------------------------------------------------------------------------

// fetchBlockHashFunc defines a callback function to use in order to convert a
// serialized block ID to an associated block hash.
type fetchBlockHashFunc func(serializedID []byte) (*chainhash.Hash, error)

// serializeAddrIndexEntry serializes the provided block id and transaction
// location according to the format described in detail above.
func serializeAddrIndexEntry(blockID uint32, txLoc wire.TxLoc) []byte {
	// Serialize the entry.
	serialized := make([]byte, 12)
	byteOrder.PutUint32(serialized, blockID)
	byteOrder.PutUint32(serialized[4:], uint32(txLoc.TxStart))
	byteOrder.PutUint32(serialized[8:], uint32(txLoc.TxLen))
	return serialized
}

// deserializeAddrIndexEntry decodes the passed serialized byte slice into the
// provided region struct according to the format described in detail above and
// uses the passed block hash fetching function in order to conver the block ID
// to the associated block hash.
func deserializeAddrIndexEntry(serialized []byte, region *database.BlockRegion,
	fetchBlockHash fetchBlockHashFunc) error {

	// Ensure there are enough bytes to decode.
	if len(serialized) < txEntrySize {
		return errDeserialize("unexpected end of data")
	}

	hash, err := fetchBlockHash(serialized[0:4])
	if err != nil {
		return err
	}
	region.Hash = hash
	region.Offset = byteOrder.Uint32(serialized[4:8])
	region.Len = byteOrder.Uint32(serialized[8:12])
	return nil
}

// keyForLevel returns the key for a specific address and level in the address
// index entry.
func keyForLevel(addrKey [addrKeySize]byte, level uint8) [levelKeySize]byte {
	var key [levelKeySize]byte
	copy(key[:], addrKey[:])
	key[levelOffset] = level
	return key
}

// dbPutAddrIndexEntry updates the address index to include the provided entry
// according to the level-based scheme described in detail above.
func dbPutAddrIndexEntry(bucket internalBucket, addrKey [addrKeySize]byte,
	blockID uint32, txLoc wire.TxLoc) error {

	// Start with level 0 and its initial max number of entries.
	curLevel := uint8(0)
	maxLevelBytes := level0MaxEntries * txEntrySize

	// Simply append the new entry to level 0 and return now when it will
	// fit.  This is the most common path.
	newData := serializeAddrIndexEntry(blockID, txLoc)
	level0Key := keyForLevel(addrKey, 0)
	level0Data := bucket.Get(level0Key[:])
	if len(level0Data)+len(newData) <= maxLevelBytes {
		mergedData := newData
		if len(level0Data) > 0 {
			mergedData = make([]byte, len(level0Data)+len(newData))
			copy(mergedData, level0Data)
			copy(mergedData[len(level0Data):], newData)
		}
		return bucket.Put(level0Key[:], mergedData)
	}

	// At this point, level 0 is full, so merge each level into higher
	// levels as many times as needed to free up level 0.
	prevLevelData := level0Data
	for {
		// Each new level holds twice as much as the previous one.
		curLevel++
		maxLevelBytes *= 2

		// Move to the next level as long as the current level is full.
		curLevelKey := keyForLevel(addrKey, curLevel)
		curLevelData := bucket.Get(curLevelKey[:])
		if len(curLevelData) == maxLevelBytes {
			prevLevelData = curLevelData
			continue
		}

		// The current level has room for the data in the previous one,
		// so merge the data from previous level into it.
		mergedData := prevLevelData
		if len(curLevelData) > 0 {
			mergedData = make([]byte, len(curLevelData)+
				len(prevLevelData))
			copy(mergedData, curLevelData)
			copy(mergedData[len(curLevelData):], prevLevelData)
		}
		err := bucket.Put(curLevelKey[:], mergedData)
		if err != nil {
			return err
		}

		// Move all of the levels before the previous one up a level.
		for mergeLevel := curLevel - 1; mergeLevel > 0; mergeLevel-- {
			mergeLevelKey := keyForLevel(addrKey, mergeLevel)
			prevLevelKey := keyForLevel(addrKey, mergeLevel-1)
			prevData := bucket.Get(prevLevelKey[:])
			err := bucket.Put(mergeLevelKey[:], prevData)
			if err != nil {
				return err
			}
		}
		break
	}

	// Finally, insert the new entry into level 0 now that it is empty.
	return bucket.Put(level0Key[:], newData)
}

// dbFetchAddrIndexEntries returns block regions for transactions referenced by
// the given address key and the number of entries skipped since it could have
// been less in the case where there are less total entries than the requested
// number of entries to skip.
func dbFetchAddrIndexEntries(bucket internalBucket, addrKey [addrKeySize]byte,
	numToSkip, numRequested uint32, reverse bool,
	fetchBlockHash fetchBlockHashFunc) ([]database.BlockRegion, uint32, error) {

	// When the reverse flag is not set, all levels need to be fetched
	// because numToSkip and numRequested are counted from the oldest
	// transactions (highest level) and thus the total count is needed.
	// However, when the reverse flag is set, only enough records to satisfy
	// the requested amount are needed.
	var level uint8
	var serialized []byte
	for !reverse || len(serialized) < int(numToSkip+numRequested)*txEntrySize {
		curLevelKey := keyForLevel(addrKey, level)
		levelData := bucket.Get(curLevelKey[:])
		if levelData == nil {
			// Stop when there are no more levels.
			break
		}

		// Higher levels contain older transactions, so prepend them.
		prepended := make([]byte, len(serialized)+len(levelData))
		copy(prepended, levelData)
		copy(prepended[len(levelData):], serialized)
		serialized = prepended
		level++
	}

	// When the requested number of entries to skip is larger than the
	// number available, skip them all and return now with the actual number
	// skipped.
	numEntries := uint32(len(serialized) / txEntrySize)
	if numToSkip >= numEntries {
		return nil, numEntries, nil
	}

	// Nothing more to do when there are no requested entries.
	if numRequested == 0 {
		return nil, numToSkip, nil
	}

	// Limit the number to load based on the number of available entries,
	// the number to skip, and the number requested.
	numToLoad := numEntries - numToSkip
	if numToLoad > numRequested {
		numToLoad = numRequested
	}

	// Start the offset after all skipped entries and load the calculated
	// number.
	results := make([]database.BlockRegion, numToLoad)
	for i := uint32(0); i < numToLoad; i++ {
		// Calculate the read offset according to the reverse flag.
		var offset uint32
		if reverse {
			offset = (numEntries - numToSkip - i - 1) * txEntrySize
		} else {
			offset = (numToSkip + i) * txEntrySize
		}

		// Deserialize and populate the result.
		err := deserializeAddrIndexEntry(serialized[offset:],
			&results[i], fetchBlockHash)
		if err != nil {
			// Ensure any deserialization errors are returned as
			// database corruption errors.
			if isDeserializeErr(err) {
				err = database.Error{
					ErrorCode: database.ErrCorruption,
					Description: fmt.Sprintf("failed to "+
						"deserialized address index "+
						"for key %x: %v", addrKey, err),
				}
			}

			return nil, 0, err
		}
	}

	return results, numToSkip, nil
}

// minEntriesToReachLevel returns the minimum number of entries that are
// required to reach the given address index level.
func minEntriesToReachLevel(level uint8) int {
	maxEntriesForLevel := level0MaxEntries
	minRequired := 1
	for l := uint8(1); l <= level; l++ {
		minRequired += maxEntriesForLevel
		maxEntriesForLevel *= 2
	}
	return minRequired
}

// maxEntriesForLevel returns the maximum number of entries allowed for the
// given address index level.
func maxEntriesForLevel(level uint8) int {
	numEntries := level0MaxEntries
	for l := level; l > 0; l-- {
		numEntries *= 2
	}
	return numEntries
}

// dbRemoveAddrIndexEntries removes the specified number of entries from from
// the address index for the provided key.  An assertion error will be returned
// if the count exceeds the total number of entries in the index.
func dbRemoveAddrIndexEntries(bucket internalBucket, addrKey [addrKeySize]byte,
	count int) error {

	// Nothing to do if no entries are being deleted.
	if count <= 0 {
		return nil
	}

	// Make use of a local map to track pending updates and define a closure
	// to apply it to the database.  This is done in order to reduce the
	// number of database reads and because there is more than one exit
	// path that needs to apply the updates.
	pendingUpdates := make(map[uint8][]byte)
	applyPending := func() error {
		for level, data := range pendingUpdates {
			curLevelKey := keyForLevel(addrKey, level)
			if len(data) == 0 {
				err := bucket.Delete(curLevelKey[:])
				if err != nil {
					return err
				}
				continue
			}
			err := bucket.Put(curLevelKey[:], data)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// Loop forwards through the levels while removing entries until the
	// specified number has been removed.  This will potentially result in
	// entirely empty lower levels which will be backfilled below.
	var highestLoadedLevel uint8
	numRemaining := count
	for level := uint8(0); numRemaining > 0; level++ {
		// Load the data for the level from the database.
		curLevelKey := keyForLevel(addrKey, level)
		curLevelData := bucket.Get(curLevelKey[:])
		if len(curLevelData) == 0 && numRemaining > 0 {
			return AssertError(fmt.Sprintf("dbRemoveAddrIndexEntries "+
				"not enough entries for address key %x to "+
				"delete %d entries", addrKey, count))
		}
		pendingUpdates[level] = curLevelData
		highestLoadedLevel = level

		// Delete the entire level as needed.
		numEntries := len(curLevelData) / txEntrySize
		if numRemaining >= numEntries {
			pendingUpdates[level] = nil
			numRemaining -= numEntries
			continue
		}

		// Remove remaining entries to delete from the level.
		offsetEnd := len(curLevelData) - (numRemaining * txEntrySize)
		pendingUpdates[level] = curLevelData[:offsetEnd]
		break
	}

	// When all elements in level 0 were not removed there is nothing left
	// to do other than updating the database.
	if len(pendingUpdates[0]) != 0 {
		return applyPending()
	}

	// At this point there are one or more empty levels before the current
	// level which need to be backfilled and the current level might have
	// had some entries deleted from it as well.  Since all levels after
	// level 0 are required to either be empty, half full, or completely
	// full, the current level must be adjusted accordingly by backfilling
	// each previous levels in a way which satisfies the requirements.  Any
	// entries that are left are assigned to level 0 after the loop as they
	// are guaranteed to fit by the logic in the loop.  In other words, this
	// effectively squashes all remaining entries in the current level into
	// the lowest possible levels while following the level rules.
	//
	// Note that the level after the current level might also have entries
	// and gaps are not allowed, so this also keeps track of the lowest
	// empty level so the code below knows how far to backfill in case it is
	// required.
	lowestEmptyLevel := uint8(255)
	curLevelData := pendingUpdates[highestLoadedLevel]
	curLevelMaxEntries := maxEntriesForLevel(highestLoadedLevel)
	for level := highestLoadedLevel; level > 0; level-- {
		// When there are not enough entries left in the current level
		// for the number that would be required to reach it, clear the
		// the current level which effectively moves them all up to the
		// previous level on the next iteration.  Otherwise, there are
		// are sufficient entries, so update the current level to
		// contain as many entries as possible while still leaving
		// enough remaining entries required to reach the level.
		numEntries := len(curLevelData) / txEntrySize
		prevLevelMaxEntries := curLevelMaxEntries / 2
		minPrevRequired := minEntriesToReachLevel(level - 1)
		if numEntries < prevLevelMaxEntries+minPrevRequired {
			lowestEmptyLevel = level
			pendingUpdates[level] = nil
		} else {
			// This level can only be completely full or half full,
			// so choose the appropriate offset to ensure enough
			// entries remain to reach the level.
			var offset int
			if numEntries-curLevelMaxEntries >= minPrevRequired {
				offset = curLevelMaxEntries * txEntrySize
			} else {
				offset = prevLevelMaxEntries * txEntrySize
			}
			pendingUpdates[level] = curLevelData[:offset]
			curLevelData = curLevelData[offset:]
		}

		curLevelMaxEntries = prevLevelMaxEntries
	}
	pendingUpdates[0] = curLevelData
	if len(curLevelData) == 0 {
		lowestEmptyLevel = 0
	}

	// When the highest loaded level is empty, it's possible the level after
	// it still has data and thus that data needs to be backfilled as well.
	for len(pendingUpdates[highestLoadedLevel]) == 0 {
		// When the next level is empty too, the is no data left to
		// continue backfilling, so there is nothing left to do.
		// Otherwise, populate the pending updates map with the newly
		// loaded data and update the highest loaded level accordingly.
		level := highestLoadedLevel + 1
		curLevelKey := keyForLevel(addrKey, level)
		levelData := bucket.Get(curLevelKey[:])
		if len(levelData) == 0 {
			break
		}
		pendingUpdates[level] = levelData
		highestLoadedLevel = level

		// At this point the highest level is not empty, but it might
		// be half full.  When that is the case, move it up a level to
		// simplify the code below which backfills all lower levels that
		// are still empty.  This also means the current level will be
		// empty, so the loop will perform another another iteration to
		// potentially backfill this level with data from the next one.
		curLevelMaxEntries := maxEntriesForLevel(level)
		if len(levelData)/txEntrySize != curLevelMaxEntries {
			pendingUpdates[level] = nil
			pendingUpdates[level-1] = levelData
			level--
			curLevelMaxEntries /= 2
		}

		// Backfill all lower levels that are still empty by iteratively
		// halfing the data until the lowest empty level is filled.
		for level > lowestEmptyLevel {
			offset := (curLevelMaxEntries / 2) * txEntrySize
			pendingUpdates[level] = levelData[:offset]
			levelData = levelData[offset:]
			pendingUpdates[level-1] = levelData
			level--
			curLevelMaxEntries /= 2
		}

		// The lowest possible empty level is now the highest loaded
		// level.
		lowestEmptyLevel = highestLoadedLevel
	}

	// Apply the pending updates.
	return applyPending()
}

// addrToKey converts known address types to an addrindex key.  An error is
// returned for unsupported types.
func addrToKey(addr btcutil.Address) ([addrKeySize]byte, error) {
	switch addr := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *btcutil.AddressScriptHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeScriptHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *btcutil.AddressPubKey:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHash
		copy(result[1:], addr.AddressPubKeyHash().Hash160()[:])
		return result, nil

	case *btcutil.AddressWitnessScriptHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeWitnessScriptHash

		// P2WSH outputs utilize a 32-byte data push created by hashing
		// the script with sha256 instead of hash160. In order to keep
		// all address entries within the database uniform and compact,
		// we use a hash160 here to reduce the size of the salient data
		// push to 20-bytes.
		copy(result[1:], btcutil.Hash160(addr.ScriptAddress()))
		return result, nil

	case *btcutil.AddressWitnessPubKeyHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeWitnessPubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil
	}

	return [addrKeySize]byte{}, errUnsupportedAddressType
}

// AddrIndex implements a transaction by address index.  That is to say, it
// supports querying all transactions that reference a given address because
// they are either crediting or debiting the address.  The returned transactions
// are ordered according to their order of appearance in the blockchain.  In
// other words, first by block height and then by offset inside the block.
//
// In addition, support is provided for a memory-only index of unconfirmed
// transactions such as those which are kept in the memory pool before inclusion
// in a block.
type AddrIndex struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	db          database.DB
	chainParams *chaincfg.Params

	// The following fields are used to quickly link transactions and
	// addresses that have not been included into a block yet when an
	// address index is being maintained.  The are protected by the
	// unconfirmedLock field.
	//
	// The txnsByAddr field is used to keep an index of all transactions
	// which either create an output to a given address or spend from a
	// previous output to it keyed by the address.
	//
	// The addrsByTx field is essentially the reverse and is used to
	// keep an index of all addresses which a given transaction involves.
	// This allows fairly efficient updates when transactions are removed
	// once they are included into a block.
	unconfirmedLock sync.RWMutex
	txnsByAddr      map[[addrKeySize]byte]map[chainhash.Hash]*btcutil.Tx
	addrsByTx       map[chainhash.Hash]map[[addrKeySize]byte]struct{}
}

// Ensure the AddrIndex type implements the Indexer interface.
var _ Indexer = (*AddrIndex)(nil)

// Ensure the AddrIndex type implements the NeedsInputser interface.
var _ NeedsInputser = (*AddrIndex)(nil)

// NeedsInputs signals that the index requires the referenced inputs in order
// to properly create the index.
//
// This implements the NeedsInputser interface.
func (idx *AddrIndex) NeedsInputs() bool {
	return true
}

// Init is only provided to satisfy the Indexer interface as there is nothing to
// initialize for this index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Init() error {
	// Nothing to do.
	return nil
}

// Key returns the database key to use for the index as a byte slice.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Key() []byte {
	return addrIndexKey
}

// Name returns the human-readable name of the index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Name() string {
	return addrIndexName
}

// Create is invoked when the indexer manager determines the index needs
// to be created for the first time.  It creates the bucket for the address
// index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(addrIndexKey)
	return err
}

// writeIndexData represents the address index data to be written for one block.
// It consists of the address mapped to an ordered list of the transactions
// that involve the address in block.  It is ordered so the transactions can be
// stored in the order they appear in the block.
type writeIndexData map[[addrKeySize]byte][]int

// indexPkScript extracts all standard addresses from the passed public key
// script and maps each of them to the associated transaction using the passed
// map.
func (idx *AddrIndex) indexPkScript(data writeIndexData, pkScript []byte, txIdx int) {
	// Nothing to index if the script is non-standard or otherwise doesn't
	// contain any addresses.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		idx.chainParams)
	if err != nil || len(addrs) == 0 {
		return
	}

	for _, addr := range addrs {
		addrKey, err := addrToKey(addr)
		if err != nil {
			// Ignore unsupported address types.
			continue
		}

		// Avoid inserting the transaction more than once.  Since the
		// transactions are indexed serially any duplicates will be
		// indexed in a row, so checking the most recent entry for the
		// address is enough to detect duplicates.
		indexedTxns := data[addrKey]
		numTxns := len(indexedTxns)
		if numTxns > 0 && indexedTxns[numTxns-1] == txIdx {
			continue
		}
		indexedTxns = append(indexedTxns, txIdx)
		data[addrKey] = indexedTxns
	}
}

// indexBlock extract all of the standard addresses from all of the transactions
// in the passed block and maps each of them to the associated transaction using
// the passed map.
func (idx *AddrIndex) indexBlock(data writeIndexData, block *btcutil.Block,
	stxos []blockchain.SpentTxOut) {

	stxoIndex := 0
	for txIdx, tx := range block.Transactions() {
		// Coinbases do not reference any inputs.  Since the block is
		// required to have already gone through full validation, it has
		// already been proven on the first transaction in the block is
		// a coinbase.
		if txIdx != 0 {
			for range tx.MsgTx().TxIn {
				// We'll access the slice of all the
				// transactions spent in this block properly
				// ordered to fetch the previous input script.
				pkScript := stxos[stxoIndex].PkScript
				idx.indexPkScript(data, pkScript, txIdx)

				// With an input indexed, we'll advance the
				// stxo coutner.
				stxoIndex++
			}
		}

		for _, txOut := range tx.MsgTx().TxOut {
			idx.indexPkScript(data, txOut.PkScript, txIdx)
		}
	}
}

// ConnectBlock is invoked by the index manager when a new block has been
// connected to the main chain.  This indexer adds a mapping for each address
// the transactions in the block involve.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block,
	stxos []blockchain.SpentTxOut) error {

	// The offset and length of the transactions within the serialized
	// block.
	txLocs, err := block.TxLoc()
	if err != nil {
		return err
	}

	// Get the internal block ID associated with the block.
	blockID, err := dbFetchBlockIDByHash(dbTx, block.Hash())
	if err != nil {
		return err
	}

	// Build all of the address to transaction mappings in a local map.
	addrsToTxns := make(writeIndexData)
	idx.indexBlock(addrsToTxns, block, stxos)

	// Add all of the index entries for each address.
	addrIdxBucket := dbTx.Metadata().Bucket(addrIndexKey)
	for addrKey, txIdxs := range addrsToTxns {
		for _, txIdx := range txIdxs {
			err := dbPutAddrIndexEntry(addrIdxBucket, addrKey,
				blockID, txLocs[txIdx])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// DisconnectBlock is invoked by the index manager when a block has been
// disconnected from the main chain.  This indexer removes the address mappings
// each transaction in the block involve.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block,
	stxos []blockchain.SpentTxOut) error {

	// Build all of the address to transaction mappings in a local map.
	addrsToTxns := make(writeIndexData)
	idx.indexBlock(addrsToTxns, block, stxos)

	// Remove all of the index entries for each address.
	bucket := dbTx.Metadata().Bucket(addrIndexKey)
	for addrKey, txIdxs := range addrsToTxns {
		err := dbRemoveAddrIndexEntries(bucket, addrKey, len(txIdxs))
		if err != nil {
			return err
		}
	}

	return nil
}

// TxRegionsForAddress returns a slice of block regions which identify each
// transaction that involves the passed address according to the specified
// number to skip, number requested, and whether or not the results should be
// reversed.  It also returns the number actually skipped since it could be less
// in the case where there are not enough entries.
//
// NOTE: These results only include transactions confirmed in blocks.  See the
// UnconfirmedTxnsForAddress method for obtaining unconfirmed transactions
// that involve a given address.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) TxRegionsForAddress(dbTx database.Tx, addr btcutil.Address,
	numToSkip, numRequested uint32, reverse bool) ([]database.BlockRegion, uint32, error) {

	addrKey, err := addrToKey(addr)
	if err != nil {
		return nil, 0, err
	}

	var regions []database.BlockRegion
	var skipped uint32
	err = idx.db.View(func(dbTx database.Tx) error {
		// Create closure to lookup the block hash given the ID using
		// the database transaction.
		fetchBlockHash := func(id []byte) (*chainhash.Hash, error) {
			// Deserialize and populate the result.
			return dbFetchBlockHashBySerializedID(dbTx, id)
		}

		var err error
		addrIdxBucket := dbTx.Metadata().Bucket(addrIndexKey)
		regions, skipped, err = dbFetchAddrIndexEntries(addrIdxBucket,
			addrKey, numToSkip, numRequested, reverse,
			fetchBlockHash)
		return err
	})

	return regions, skipped, err
}

// indexUnconfirmedAddresses modifies the unconfirmed (memory-only) address
// index to include mappings for the addresses encoded by the passed public key
// script to the transaction.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) indexUnconfirmedAddresses(pkScript []byte, tx *btcutil.Tx) {
	// The error is ignored here since the only reason it can fail is if the
	// script fails to parse and it was already validated before being
	// admitted to the mempool.
	_, addresses, _, _ := txscript.ExtractPkScriptAddrs(pkScript,
		idx.chainParams)
	for _, addr := range addresses {
		// Ignore unsupported address types.
		addrKey, err := addrToKey(addr)
		if err != nil {
			continue
		}

		// Add a mapping from the address to the transaction.
		idx.unconfirmedLock.Lock()
		addrIndexEntry := idx.txnsByAddr[addrKey]
		if addrIndexEntry == nil {
			addrIndexEntry = make(map[chainhash.Hash]*btcutil.Tx)
			idx.txnsByAddr[addrKey] = addrIndexEntry
		}
		addrIndexEntry[*tx.Hash()] = tx

		// Add a mapping from the transaction to the address.
		addrsByTxEntry := idx.addrsByTx[*tx.Hash()]
		if addrsByTxEntry == nil {
			addrsByTxEntry = make(map[[addrKeySize]byte]struct{})
			idx.addrsByTx[*tx.Hash()] = addrsByTxEntry
		}
		addrsByTxEntry[addrKey] = struct{}{}
		idx.unconfirmedLock.Unlock()
	}
}

// AddUnconfirmedTx adds all addresses related to the transaction to the
// unconfirmed (memory-only) address index.
//
// NOTE: This transaction MUST have already been validated by the memory pool
// before calling this function with it and have all of the inputs available in
// the provided utxo view.  Failure to do so could result in some or all
// addresses not being indexed.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) AddUnconfirmedTx(tx *btcutil.Tx, utxoView *blockchain.UtxoViewpoint) {
	// Index addresses of all referenced previous transaction outputs.
	//
	// The existence checks are elided since this is only called after the
	// transaction has already been validated and thus all inputs are
	// already known to exist.
	for _, txIn := range tx.MsgTx().TxIn {
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if entry == nil {
			// Ignore missing entries.  This should never happen
			// in practice since the function comments specifically
			// call out all inputs must be available.
			continue
		}
		idx.indexUnconfirmedAddresses(entry.PkScript(), tx)
	}

	// Index addresses of all created outputs.
	for _, txOut := range tx.MsgTx().TxOut {
		idx.indexUnconfirmedAddresses(txOut.PkScript, tx)
	}
}

// RemoveUnconfirmedTx removes the passed transaction from the unconfirmed
// (memory-only) address index.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) RemoveUnconfirmedTx(hash *chainhash.Hash) {
	idx.unconfirmedLock.Lock()
	defer idx.unconfirmedLock.Unlock()

	// Remove all address references to the transaction from the address
	// index and remove the entry for the address altogether if it no longer
	// references any transactions.
	for addrKey := range idx.addrsByTx[*hash] {
		delete(idx.txnsByAddr[addrKey], *hash)
		if len(idx.txnsByAddr[addrKey]) == 0 {
			delete(idx.txnsByAddr, addrKey)
		}
	}

	// Remove the entry from the transaction to address lookup map as well.
	delete(idx.addrsByTx, *hash)
}

// UnconfirmedTxnsForAddress returns all transactions currently in the
// unconfirmed (memory-only) address index that involve the passed address.
// Unsupported address types are ignored and will result in no results.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) UnconfirmedTxnsForAddress(addr btcutil.Address) []*btcutil.Tx {
	// Ignore unsupported address types.
	addrKey, err := addrToKey(addr)
	if err != nil {
		return nil
	}

	// Protect concurrent access.
	idx.unconfirmedLock.RLock()
	defer idx.unconfirmedLock.RUnlock()

	// Return a new slice with the results if there are any.  This ensures
	// safe concurrency.
	if txns, exists := idx.txnsByAddr[addrKey]; exists {
		addressTxns := make([]*btcutil.Tx, 0, len(txns))
		for _, tx := range txns {
			addressTxns = append(addressTxns, tx)
		}
		return addressTxns
	}

	return nil
}

// NewAddrIndex returns a new instance of an indexer that is used to create a
// mapping of all addresses in the blockchain to the respective transactions
// that involve them.
//
// It implements the Indexer interface which plugs into the IndexManager that in
// turn is used by the blockchain package.  This allows the index to be
// seamlessly maintained along with the chain.
func NewAddrIndex(db database.DB, chainParams *chaincfg.Params) *AddrIndex {
	return &AddrIndex{
		db:          db,
		chainParams: chainParams,
		txnsByAddr:  make(map[[addrKeySize]byte]map[chainhash.Hash]*btcutil.Tx),
		addrsByTx:   make(map[chainhash.Hash]map[[addrKeySize]byte]struct{}),
	}
}

// DropAddrIndex drops the address index from the provided database if it
// exists.
func DropAddrIndex(db database.DB, interrupt <-chan struct{}) error {
	return dropIndex(db, addrIndexKey, addrIndexName, interrupt)
}
