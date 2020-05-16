package migration_01_to_11

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"go.etcd.io/bbolt"
)

const (
	dbName           = "channel.db"
	dbFilePermission = 0600
)

// migration is a function which takes a prior outdated version of the database
// instances and mutates the key/bucket structure to arrive at a more
// up-to-date version of the database.
type migration func(tx kvdb.RwTx) error

var (
	// Big endian is the preferred byte order, due to cursor scans over
	// integer keys iterating in order.
	byteOrder = binary.BigEndian
)

// DB is the primary datastore for the lnd daemon. The database stores
// information related to nodes, routing data, open/closed channels, fee
// schedules, and reputation data.
type DB struct {
	kvdb.Backend
	dbPath string
	graph  *ChannelGraph
	now    func() time.Time
}

// Open opens an existing channeldb. Any necessary schemas migrations due to
// updates will take place as necessary.
func Open(dbPath string, modifiers ...OptionModifier) (*DB, error) {
	path := filepath.Join(dbPath, dbName)

	if !fileExists(path) {
		if err := createChannelDB(dbPath); err != nil {
			return nil, err
		}
	}

	opts := DefaultOptions()
	for _, modifier := range modifiers {
		modifier(&opts)
	}

	// Specify bbolt freelist options to reduce heap pressure in case the
	// freelist grows to be very large.
	bboltOpts := &bbolt.Options{
		NoFreelistSync: opts.NoFreelistSync,
	}
	bdb, err := kvdb.Open(kvdb.BoltBackendName, path, bboltOpts)
	if err != nil {
		return nil, err
	}

	chanDB := &DB{
		Backend: bdb,
		dbPath:  dbPath,
		now:     time.Now,
	}
	chanDB.graph = newChannelGraph(
		chanDB, opts.RejectCacheSize, opts.ChannelCacheSize,
	)

	return chanDB, nil
}

// createChannelDB creates and initializes a fresh version of channeldb. In
// the case that the target path has not yet been created or doesn't yet exist,
// then the path is created. Additionally, all required top-level buckets used
// within the database are created.
func createChannelDB(dbPath string) error {
	if !fileExists(dbPath) {
		if err := os.MkdirAll(dbPath, 0700); err != nil {
			return err
		}
	}

	path := filepath.Join(dbPath, dbName)
	bboltOpts := &bbolt.Options{
		NoFreelistSync: false,
	}
	bdb, err := kvdb.Create(kvdb.BoltBackendName, path, bboltOpts)
	if err != nil {
		return err
	}

	err = kvdb.Update(bdb, func(tx kvdb.RwTx) error {
		if _, err := tx.CreateTopLevelBucket(openChannelBucket); err != nil {
			return err
		}
		if _, err := tx.CreateTopLevelBucket(closedChannelBucket); err != nil {
			return err
		}

		if _, err := tx.CreateTopLevelBucket(invoiceBucket); err != nil {
			return err
		}

		if _, err := tx.CreateTopLevelBucket(paymentBucket); err != nil {
			return err
		}

		nodes, err := tx.CreateTopLevelBucket(nodeBucket)
		if err != nil {
			return err
		}
		_, err = nodes.CreateBucket(aliasIndexBucket)
		if err != nil {
			return err
		}
		_, err = nodes.CreateBucket(nodeUpdateIndexBucket)
		if err != nil {
			return err
		}

		edges, err := tx.CreateTopLevelBucket(edgeBucket)
		if err != nil {
			return err
		}
		if _, err := edges.CreateBucket(edgeIndexBucket); err != nil {
			return err
		}
		if _, err := edges.CreateBucket(edgeUpdateIndexBucket); err != nil {
			return err
		}
		if _, err := edges.CreateBucket(channelPointBucket); err != nil {
			return err
		}
		if _, err := edges.CreateBucket(zombieBucket); err != nil {
			return err
		}

		graphMeta, err := tx.CreateTopLevelBucket(graphMetaBucket)
		if err != nil {
			return err
		}
		_, err = graphMeta.CreateBucket(pruneLogBucket)
		if err != nil {
			return err
		}

		if _, err := tx.CreateTopLevelBucket(metaBucket); err != nil {
			return err
		}

		meta := &Meta{
			DbVersionNumber: 0,
		}
		return putMeta(meta, tx)
	})
	if err != nil {
		return fmt.Errorf("unable to create new channeldb")
	}

	return bdb.Close()
}

// fileExists returns true if the file exists, and false otherwise.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// FetchClosedChannels attempts to fetch all closed channels from the database.
// The pendingOnly bool toggles if channels that aren't yet fully closed should
// be returned in the response or not. When a channel was cooperatively closed,
// it becomes fully closed after a single confirmation.  When a channel was
// forcibly closed, it will become fully closed after _all_ the pending funds
// (if any) have been swept.
func (d *DB) FetchClosedChannels(pendingOnly bool) ([]*ChannelCloseSummary, error) {
	var chanSummaries []*ChannelCloseSummary

	if err := kvdb.View(d, func(tx kvdb.ReadTx) error {
		closeBucket := tx.ReadBucket(closedChannelBucket)
		if closeBucket == nil {
			return ErrNoClosedChannels
		}

		return closeBucket.ForEach(func(chanID []byte, summaryBytes []byte) error {
			summaryReader := bytes.NewReader(summaryBytes)
			chanSummary, err := deserializeCloseChannelSummary(summaryReader)
			if err != nil {
				return err
			}

			// If the query specified to only include pending
			// channels, then we'll skip any channels which aren't
			// currently pending.
			if !chanSummary.IsPending && pendingOnly {
				return nil
			}

			chanSummaries = append(chanSummaries, chanSummary)
			return nil
		})
	}); err != nil {
		return nil, err
	}

	return chanSummaries, nil
}

// ChannelGraph returns a new instance of the directed channel graph.
func (d *DB) ChannelGraph() *ChannelGraph {
	return d.graph
}
