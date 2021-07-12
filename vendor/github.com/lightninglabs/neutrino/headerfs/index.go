package headerfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// indexBucket is the main top-level bucket for the header index.
	// Nothing is stored in this bucket other than the sub-buckets which
	// contains the indexes for the various header types.
	indexBucket = []byte("header-index")

	// bitcoinTip is the key which tracks the "tip" of the block header
	// chain. The value of this key will be the current block hash of the
	// best known chain that we're synced to.
	bitcoinTip = []byte("bitcoin")

	// regFilterTip is the key which tracks the "tip" of the regular
	// compact filter header chain. The value of this key will be the
	// current block hash of the best known chain that the headers for
	// regular filter are synced to.
	regFilterTip = []byte("regular")

	// extFilterTip is the key which tracks the "tip" of the extended
	// compact filter header chain. The value of this key will be the
	// current block hash of the best known chain that the headers for
	// extended filter are synced to.
	extFilterTip = []byte("ext")
)

var (
	// ErrHeightNotFound is returned when a specified height isn't found in
	// a target index.
	ErrHeightNotFound = fmt.Errorf("target height not found in index")

	// ErrHashNotFound is returned when a specified block hash isn't found
	// in a target index.
	ErrHashNotFound = fmt.Errorf("target hash not found in index")
)

// HeaderType is an enum-like type which defines the various header types that
// are stored within the index.
type HeaderType uint8

const (
	// Block is the header type that represents regular Bitcoin block
	// headers.
	Block HeaderType = iota

	// RegularFilter is a header type that represents the basic filter
	// header type for the filter header chain.
	RegularFilter
)

const (
	// BlockHeaderSize is the size in bytes of the Block header type.
	BlockHeaderSize = 80

	// RegularFilterHeaderSize is the size in bytes of the RegularFilter
	// header type.
	RegularFilterHeaderSize = 32
)

// headerIndex is an index stored within the database that allows for random
// access into the on-disk header file. This, in conjunction with a flat file
// of headers consists of header database. The keys have been specifically
// crafted in order to ensure maximum write performance during IBD, and also to
// provide the necessary indexing properties required.
type headerIndex struct {
	db walletdb.DB

	indexType HeaderType
}

// newHeaderIndex creates a new headerIndex given an already open database, and
// a particular header type.
func newHeaderIndex(db walletdb.DB, indexType HeaderType) (*headerIndex, error) {
	// As an initially step, we'll attempt to create all the buckets
	// necessary for functioning of the index. If these buckets has already
	// been created, then we can exit early.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(indexBucket)
		return err

	})
	if err != nil && err != walletdb.ErrBucketExists {
		return nil, err
	}

	return &headerIndex{
		db:        db,
		indexType: indexType,
	}, nil
}

// headerEntry is an internal type that's used to quickly map a (height, hash)
// pair into the proper key that'll be stored within the database.
type headerEntry struct {
	hash   chainhash.Hash
	height uint32
}

// headerBatch is a batch of header entries to be written to disk.
//
// NOTE: The entries within a batch SHOULD be properly sorted by hash in
// order to ensure the batch is written in a sequential write.
type headerBatch []headerEntry

// Len returns the number of routes in the collection.
//
// NOTE: This is part of the sort.Interface implementation.
func (h headerBatch) Len() int {
	return len(h)
}

// Less reports where the entry with index i should sort before the entry with
// index j. As we want to ensure the items are written in sequential order,
// items with the "first" hash.
//
// NOTE: This is part of the sort.Interface implementation.
func (h headerBatch) Less(i, j int) bool {
	return bytes.Compare(h[i].hash[:], h[j].hash[:]) < 0
}

// Swap swaps the elements with indexes i and j.
//
// NOTE: This is part of the sort.Interface implementation.
func (h headerBatch) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

// addHeaders writes a batch of header entries in a single atomic batch
func (h *headerIndex) addHeaders(batch headerBatch) error {
	// If we're writing a 0-length batch, make no changes and return.
	if len(batch) == 0 {
		return nil
	}

	// In order to ensure optimal write performance, we'll ensure that the
	// items are sorted by their hash before insertion into the database.
	sort.Sort(batch)

	return walletdb.Update(h.db, func(tx walletdb.ReadWriteTx) error {
		rootBucket := tx.ReadWriteBucket(indexBucket)

		var tipKey []byte

		// Based on the specified index type of this instance of the
		// index, we'll grab the key that tracks the tip of the chain
		// so we can update the index once all the header entries have
		// been updated.
		// TODO(roasbeef): only need block tip?
		switch h.indexType {
		case Block:
			tipKey = bitcoinTip
		case RegularFilter:
			tipKey = regFilterTip
		default:
			return fmt.Errorf("unknown index type: %v", h.indexType)
		}

		var (
			chainTipHash   chainhash.Hash
			chainTipHeight uint32
		)

		for _, header := range batch {
			var heightBytes [4]byte
			binary.BigEndian.PutUint32(heightBytes[:], header.height)
			err := rootBucket.Put(header.hash[:], heightBytes[:])
			if err != nil {
				return err
			}

			// TODO(roasbeef): need to remedy if side-chain
			// tracking added
			if header.height >= chainTipHeight {
				chainTipHash = header.hash
				chainTipHeight = header.height
			}
		}

		return rootBucket.Put(tipKey, chainTipHash[:])
	})
}

// heightFromHash returns the height of the entry that matches the specified
// height. With this height, the caller is then able to seek to the appropriate
// spot in the flat files in order to extract the true header.
func (h *headerIndex) heightFromHash(hash *chainhash.Hash) (uint32, error) {
	var height uint32
	err := walletdb.View(h.db, func(tx walletdb.ReadTx) error {
		rootBucket := tx.ReadBucket(indexBucket)

		heightBytes := rootBucket.Get(hash[:])
		if heightBytes == nil {
			// If the hash wasn't found, then we don't know of this
			// hash within the index.
			return ErrHashNotFound
		}

		height = binary.BigEndian.Uint32(heightBytes)
		return nil
	})
	if err != nil {
		return 0, err
	}

	return height, nil
}

// chainTip returns the best hash and height that the index knows of.
func (h *headerIndex) chainTip() (*chainhash.Hash, uint32, error) {
	var (
		tipHeight uint32
		tipHash   *chainhash.Hash
	)

	err := walletdb.View(h.db, func(tx walletdb.ReadTx) error {
		rootBucket := tx.ReadBucket(indexBucket)

		var tipKey []byte

		// Based on the specified index type of this instance of the
		// index, we'll grab the particular key that tracks the chain
		// tip.
		switch h.indexType {
		case Block:
			tipKey = bitcoinTip
		case RegularFilter:
			tipKey = regFilterTip
		default:
			return fmt.Errorf("unknown chain tip index type: %v", h.indexType)
		}

		// Now that we have the particular tip key for this header
		// type, we'll fetch the hash for this tip, then using that
		// we'll fetch the height that corresponds to that hash.
		tipHashBytes := rootBucket.Get(tipKey)
		tipHeightBytes := rootBucket.Get(tipHashBytes)
		if len(tipHeightBytes) != 4 {
			return ErrHeightNotFound
		}

		// With the height fetched, we can now populate our return
		// parameters.
		h, err := chainhash.NewHash(tipHashBytes)
		if err != nil {
			return err
		}
		tipHash = h
		tipHeight = binary.BigEndian.Uint32(tipHeightBytes)

		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	return tipHash, tipHeight, nil
}

// truncateIndex truncates the index for a particluar header type by a single
// header entry. The passed newTip pointer should point to the hash of the new
// chain tip. Optionally, if the entry is to be deleted as well, then the
// delete flag should be set to true.
func (h *headerIndex) truncateIndex(newTip *chainhash.Hash, delete bool) error {
	return walletdb.Update(h.db, func(tx walletdb.ReadWriteTx) error {
		rootBucket := tx.ReadWriteBucket(indexBucket)

		var tipKey []byte

		// Based on the specified index type of this instance of the
		// index, we'll grab the key that tracks the tip of the chain
		// we need to update.
		switch h.indexType {
		case Block:
			tipKey = bitcoinTip
		case RegularFilter:
			tipKey = regFilterTip
		default:
			return fmt.Errorf("unknown index type: %v", h.indexType)
		}

		// If the delete flag is set, then we'll also delete this entry
		// from the database as the primary index (block headers) is
		// being rolled back.
		if delete {
			prevTipHash := rootBucket.Get(tipKey)
			if err := rootBucket.Delete(prevTipHash); err != nil {
				return err
			}
		}

		// With the now stale entry deleted, we'll update the chain tip
		// to point to the new hash.
		return rootBucket.Put(tipKey, newTip[:])
	})
}
