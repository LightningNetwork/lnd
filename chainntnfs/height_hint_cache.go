package chainntnfs

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	bolt "github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/channeldb"
)

const (
	// dbName is the default name of the database storing the height hints.
	dbName = "heighthint.db"

	// dbFilePermission is the default permission of the database file
	// storing the height hints.
	dbFilePermission = 0600

	// DefaultHintPruneInterval specifies how often the hint cache will try
	// to purge spend and confirm hints that are no longer needed.
	DefaultHintPruneInterval = time.Hour

	// DefaultHintPruneTimeout is the required duration of inactivity that
	// will cause spend or confirm hints to be cleaned up.
	DefaultHintPruneTimeout = 50 * time.Minute
)

var (
	// spendHintBucket is the name of the bucket which houses the height
	// hint for outpoints. Each height hint represents the earliest height
	// at which its corresponding outpoint could have been spent within.
	spendHintBucket = []byte("spend-hints")

	// confirmHintBucket is the name of the bucket which houses the height
	// hints for transactions. Each height hint represents the earliest
	// height at which its corresponding transaction could have been
	// confirmed within.
	confirmHintBucket = []byte("confirm-hints")

	// ErrCorruptedHeightHintCache indicates that the on-disk bucketing
	// structure has altered since the height hint cache instance was
	// initialized.
	ErrCorruptedHeightHintCache = errors.New("height hint cache has been " +
		"corrupted")

	// ErrSpendHintNotFound is an error returned when a spend hint for an
	// outpoint was not found.
	ErrSpendHintNotFound = errors.New("spend hint not found")

	// ErrConfirmHintNotFound is an error returned when a confirm hint for a
	// transaction was not found.
	ErrConfirmHintNotFound = errors.New("confirm hint not found")
)

// SpendHintCache is an interface whose duty is to cache spend hints for
// outpoints. A spend hint is defined as the earliest height in the chain at
// which an outpoint could have been spent within.
type SpendHintCache interface {
	// CommitSpendHint commits a spend hint for the outpoints to the cache.
	CommitSpendHint(height uint32, ops ...wire.OutPoint) error

	// QuerySpendHint returns the latest spend hint for an outpoint.
	// ErrSpendHintNotFound is returned if a spend hint does not exist
	// within the cache for the outpoint.
	QuerySpendHint(op wire.OutPoint) (uint32, error)

	// PurgeSpendHint removes the spend hint for the outpoints from the
	// cache.
	PurgeSpendHint(ops ...wire.OutPoint) error
}

// ConfirmHintCache is an interface whose duty is to cache confirm hints for
// transactions. A confirm hint is defined as the earliest height in the chain
// at which a transaction could have been included in a block.
type ConfirmHintCache interface {
	// CommitConfirmHint commits a confirm hint for the transactions to the
	// cache.
	CommitConfirmHint(height uint32, txids ...chainhash.Hash) error

	// QueryConfirmHint returns the latest confirm hint for a transaction
	// hash. ErrConfirmHintNotFound is returned if a confirm hint does not
	// exist within the cache for the transaction hash.
	QueryConfirmHint(txid chainhash.Hash) (uint32, error)

	// PurgeConfirmHint removes the confirm hint for the transactions from
	// the cache.
	PurgeConfirmHint(txids ...chainhash.Hash) error
}

// HintCache composes the individual ConfirmHintCache and SpendHintCache, and
// includes additional methods to start and stop the cache's automated garbage
// collection.
type HintCache interface {
	SpendHintCache
	ConfirmHintCache

	// Start begins the hint cache, and starts the hint garbage collection.
	Start() error

	// Stop shutdowns the hint cache and suspends the hint garbage collection.
	Stop() error
}

// HeightHintCache is an implementation of the SpendHintCache and
// ConfirmHintCache interfaces backed by a channeldb DB instance where the hints
// will be stored.
type HeightHintCache struct {
	started uint32 // used atomically
	stopped uint32 // used atomically

	db       *channeldb.DB
	disabled bool

	pruneInterval time.Duration
	pruneTimeout  time.Duration

	mu                 sync.RWMutex
	lastTouchedSpend   map[wire.OutPoint]time.Time
	lastTouchedConfirm map[chainhash.Hash]time.Time

	wg   sync.WaitGroup
	quit chan struct{}
}

// Compile-time checks to ensure HeightHintCache satisfies the HintCache
// interface.
var _ HintCache = (*HeightHintCache)(nil)

// NewHeightHintCache returns a new height hint cache backed by a database. The
// cache can be feature-flipped using the `disable` boolean. Pruning of the
// height hints and spends hints is governed by the additional `pruneInterval`
// and `pruneTimeout` parameters. The former instructs how often the cache will
// attempt to prune, while latter determines when a specific entry becomes
// eligible for pruning. A hint that has not been updated or queried for after
// `pruneTimeout`, will be eligible for eviction during the next sweep for
// zombie hints.
func NewHeightHintCache(db *channeldb.DB, disable bool,
	pruneInterval, pruneTimeout time.Duration) (*HeightHintCache, error) {
	cache := &HeightHintCache{
		db:                 db,
		disabled:           disable,
		lastTouchedSpend:   make(map[wire.OutPoint]time.Time),
		lastTouchedConfirm: make(map[chainhash.Hash]time.Time),
		pruneInterval:      pruneInterval,
		pruneTimeout:       pruneTimeout,
		quit:               make(chan struct{}),
	}

	if err := cache.initBuckets(); err != nil {
		return nil, err
	}

	if err := cache.indexCurrentHints(); err != nil {
		return nil, err
	}

	return cache, nil
}

// initBuckets ensures that the primary buckets used by the circuit are
// initialized so that we can assume their existence after startup.
func (c *HeightHintCache) initBuckets() error {
	return c.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(spendHintBucket)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(confirmHintBucket)
		return err
	})
}

// indexCurrentHints reads the current state of all spend and confirm hints
// stored on disk, and populates our indexes that tracks the last time each is
// modified. After detecting that certain spend or confirm hints are no longer
// in use, they will be pruned to recover disk space.
func (c *HeightHintCache) indexCurrentHints() error {
	return c.db.View(func(tx *bolt.Tx) error {
		// Set the last touched time to now for all spend hints.
		spendHints := tx.Bucket(spendHintBucket)
		if spendHints == nil {
			return ErrCorruptedHeightHintCache
		}

		err := spendHints.ForEach(func(k, _ []byte) error {
			var outpoint wire.OutPoint
			outpointReader := bytes.NewReader(k)
			err := channeldb.ReadElement(outpointReader, &outpoint)
			if err != nil {
				return err
			}

			c.lastTouchedSpend[outpoint] = time.Now()

			return nil
		})
		if err != nil {
			return err
		}

		// Set last touched time to now for all confirm hints.
		confirmHints := tx.Bucket(confirmHintBucket)
		if confirmHints == nil {
			return ErrCorruptedHeightHintCache
		}

		return confirmHints.ForEach(func(k, _ []byte) error {
			var txid chainhash.Hash
			txidReader := bytes.NewReader(k)
			err := channeldb.ReadElement(txidReader, &txid)
			if err != nil {
				return err
			}

			c.lastTouchedConfirm[txid] = time.Now()

			return nil
		})
	})
}

// Start begins the hint cache, and starts the hint garbage collection.
func (c *HeightHintCache) Start() error {
	if !atomic.CompareAndSwapUint32(&c.started, 0, 1) {
		return nil
	}

	c.wg.Add(1)
	go c.hintPruner()

	return nil
}

// Stop shutdowns the hint cache and suspends the hint garbage collection.
func (c *HeightHintCache) Stop() error {
	if !atomic.CompareAndSwapUint32(&c.stopped, 0, 1) {
		return nil
	}

	close(c.quit)
	c.wg.Wait()

	return nil
}

// hintPruner periodically scans all tracked confirm and spend hints, garbage
// collecting those that whose last time of modification or query exceeds the
// prune timeout.
//
// NOTE: This method MUST be run as a goroutine.
func (c *HeightHintCache) hintPruner() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case now := <-ticker.C:
			Log.Debugf("Attempting to prune spend and confirm hints")

			var (
				zombieSpends   []wire.OutPoint
				zombieConfirms []chainhash.Hash
			)

			// Gather all spend and confirm hints that have not been
			// updated within the prune timeout.
			c.mu.RLock()
			for outpoint, lastTime := range c.lastTouchedSpend {
				if now.Sub(lastTime) >= c.pruneTimeout {
					zombieSpends = append(
						zombieSpends, outpoint,
					)
				}
			}
			for txid, lastTime := range c.lastTouchedConfirm {
				if now.Sub(lastTime) >= c.pruneTimeout {
					zombieConfirms = append(
						zombieConfirms, txid,
					)
				}
			}
			c.mu.RUnlock()

			// Delete any zombie spend hints, if any.
			if len(zombieSpends) > 0 {
				err := c.PurgeSpendHint(zombieSpends...)
				if err != nil {
					Log.Errorf("Unable to prune %d zombie "+
						"spend hints: %v",
						len(zombieSpends), err)
				} else {
					Log.Debugf("Pruned %d zombie spend "+
						"hints", len(zombieSpends))
				}
			}

			// Delete any zombie confirm hints, if any.
			if len(zombieConfirms) > 0 {
				err := c.PurgeConfirmHint(zombieConfirms...)
				if err != nil {
					Log.Errorf("Unable to prune %d zombie "+
						"confirm hints: %v",
						len(zombieConfirms), err)
				} else {
					Log.Debugf("Pruned %d zombie confirm "+
						"hints", len(zombieConfirms))
				}
			}

		case <-c.quit:
			return
		}
	}
}

// CommitSpendHint commits a spend hint for the outpoints to the cache.
func (c *HeightHintCache) CommitSpendHint(height uint32, ops ...wire.OutPoint) error {
	if c.disabled {
		return nil
	}

	Log.Tracef("Updating spend hint to height %d for %v", height, ops)

	err := c.db.Batch(func(tx *bolt.Tx) error {
		spendHints := tx.Bucket(spendHintBucket)
		if spendHints == nil {
			return ErrCorruptedHeightHintCache
		}

		var hint bytes.Buffer
		if err := channeldb.WriteElement(&hint, height); err != nil {
			return err
		}

		for _, op := range ops {
			var outpoint bytes.Buffer
			err := channeldb.WriteElement(&outpoint, op)
			if err != nil {
				return err
			}

			err = spendHints.Put(outpoint.Bytes(), hint.Bytes())
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	for _, op := range ops {
		c.lastTouchedSpend[op] = time.Now()
	}
	c.mu.Unlock()

	return nil
}

// QuerySpendHint returns the latest spend hint for an outpoint.
// ErrSpendHintNotFound is returned if a spend hint does not exist within the
// cache for the outpoint.
func (c *HeightHintCache) QuerySpendHint(op wire.OutPoint) (uint32, error) {
	if c.disabled {
		return 0, ErrSpendHintNotFound
	}

	var hint uint32
	err := c.db.View(func(tx *bolt.Tx) error {
		spendHints := tx.Bucket(spendHintBucket)
		if spendHints == nil {
			return ErrCorruptedHeightHintCache
		}

		var outpoint bytes.Buffer
		if err := channeldb.WriteElement(&outpoint, op); err != nil {
			return err
		}

		spendHint := spendHints.Get(outpoint.Bytes())
		if spendHint == nil {
			return ErrSpendHintNotFound
		}

		return channeldb.ReadElement(bytes.NewReader(spendHint), &hint)
	})
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.lastTouchedSpend[op] = time.Now()
	c.mu.Unlock()

	return hint, nil
}

// PurgeSpendHint removes the spend hint for the outpoints from the cache.
func (c *HeightHintCache) PurgeSpendHint(ops ...wire.OutPoint) error {
	if c.disabled {
		return nil
	}

	Log.Tracef("Removing spend hints for %v", ops)

	err := c.db.Batch(func(tx *bolt.Tx) error {
		spendHints := tx.Bucket(spendHintBucket)
		if spendHints == nil {
			return ErrCorruptedHeightHintCache
		}

		for _, op := range ops {
			var outpoint bytes.Buffer
			err := channeldb.WriteElement(&outpoint, op)
			if err != nil {
				return err
			}

			err = spendHints.Delete(outpoint.Bytes())
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	for _, op := range ops {
		delete(c.lastTouchedSpend, op)
	}
	c.mu.Unlock()

	return nil
}

// CommitConfirmHint commits a confirm hint for the transactions to the cache.
func (c *HeightHintCache) CommitConfirmHint(height uint32, txids ...chainhash.Hash) error {
	if c.disabled {
		return nil
	}

	Log.Tracef("Updating confirm hints to height %d for %v", height, txids)

	err := c.db.Batch(func(tx *bolt.Tx) error {
		confirmHints := tx.Bucket(confirmHintBucket)
		if confirmHints == nil {
			return ErrCorruptedHeightHintCache
		}

		var hint bytes.Buffer
		if err := channeldb.WriteElement(&hint, height); err != nil {
			return err
		}

		for _, txid := range txids {
			var txHash bytes.Buffer
			err := channeldb.WriteElement(&txHash, txid)
			if err != nil {
				return err
			}

			err = confirmHints.Put(txHash.Bytes(), hint.Bytes())
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	for _, txid := range txids {
		c.lastTouchedConfirm[txid] = time.Now()
	}
	c.mu.Unlock()

	return nil
}

// QueryConfirmHint returns the latest confirm hint for a transaction hash.
// ErrConfirmHintNotFound is returned if a confirm hint does not exist within
// the cache for the transaction hash.
func (c *HeightHintCache) QueryConfirmHint(txid chainhash.Hash) (uint32, error) {
	if c.disabled {
		return 0, ErrConfirmHintNotFound
	}

	var hint uint32
	err := c.db.View(func(tx *bolt.Tx) error {
		confirmHints := tx.Bucket(confirmHintBucket)
		if confirmHints == nil {
			return ErrCorruptedHeightHintCache
		}

		var txHash bytes.Buffer
		if err := channeldb.WriteElement(&txHash, txid); err != nil {
			return err
		}

		confirmHint := confirmHints.Get(txHash.Bytes())
		if confirmHint == nil {
			return ErrConfirmHintNotFound
		}

		return channeldb.ReadElement(bytes.NewReader(confirmHint), &hint)
	})
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.lastTouchedConfirm[txid] = time.Now()
	c.mu.Unlock()

	return hint, nil
}

// PurgeConfirmHint removes the confirm hint for the transactions from the
// cache.
func (c *HeightHintCache) PurgeConfirmHint(txids ...chainhash.Hash) error {
	if c.disabled {
		return nil
	}

	Log.Tracef("Removing confirm hints for %v", txids)

	err := c.db.Batch(func(tx *bolt.Tx) error {
		confirmHints := tx.Bucket(confirmHintBucket)
		if confirmHints == nil {
			return ErrCorruptedHeightHintCache
		}

		for _, txid := range txids {
			var txHash bytes.Buffer
			err := channeldb.WriteElement(&txHash, txid)
			if err != nil {
				return err
			}

			err = confirmHints.Delete(txHash.Bytes())
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	for _, txid := range txids {
		delete(c.lastTouchedConfirm, txid)
	}
	c.mu.Unlock()

	return nil
}
