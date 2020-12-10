package channeldb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	mig "github.com/lightningnetwork/lnd/channeldb/migration"
	"github.com/lightningnetwork/lnd/channeldb/migration12"
	"github.com/lightningnetwork/lnd/channeldb/migration13"
	"github.com/lightningnetwork/lnd/channeldb/migration16"
	"github.com/lightningnetwork/lnd/channeldb/migration19"
	"github.com/lightningnetwork/lnd/channeldb/migration_01_to_11"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	dbName           = "channel.db"
	dbFilePermission = 0600
)

var (
	// ErrDryRunMigrationOK signals that a migration executed successful,
	// but we intentionally did not commit the result.
	ErrDryRunMigrationOK = errors.New("dry run migration successful")
)

// migration is a function which takes a prior outdated version of the database
// instances and mutates the key/bucket structure to arrive at a more
// up-to-date version of the database.
type migration func(tx kvdb.RwTx) error

type version struct {
	number    uint32
	migration migration
}

var (
	// dbVersions is storing all versions of database. If current version
	// of database don't match with latest version this list will be used
	// for retrieving all migration function that are need to apply to the
	// current db.
	dbVersions = []version{
		{
			// The base DB version requires no migration.
			number:    0,
			migration: nil,
		},
		{
			// The version of the database where two new indexes
			// for the update time of node and channel updates were
			// added.
			number:    1,
			migration: migration_01_to_11.MigrateNodeAndEdgeUpdateIndex,
		},
		{
			// The DB version that added the invoice event time
			// series.
			number:    2,
			migration: migration_01_to_11.MigrateInvoiceTimeSeries,
		},
		{
			// The DB version that updated the embedded invoice in
			// outgoing payments to match the new format.
			number:    3,
			migration: migration_01_to_11.MigrateInvoiceTimeSeriesOutgoingPayments,
		},
		{
			// The version of the database where every channel
			// always has two entries in the edges bucket. If
			// a policy is unknown, this will be represented
			// by a special byte sequence.
			number:    4,
			migration: migration_01_to_11.MigrateEdgePolicies,
		},
		{
			// The DB version where we persist each attempt to send
			// an HTLC to a payment hash, and track whether the
			// payment is in-flight, succeeded, or failed.
			number:    5,
			migration: migration_01_to_11.PaymentStatusesMigration,
		},
		{
			// The DB version that properly prunes stale entries
			// from the edge update index.
			number:    6,
			migration: migration_01_to_11.MigratePruneEdgeUpdateIndex,
		},
		{
			// The DB version that migrates the ChannelCloseSummary
			// to a format where optional fields are indicated with
			// boolean flags.
			number:    7,
			migration: migration_01_to_11.MigrateOptionalChannelCloseSummaryFields,
		},
		{
			// The DB version that changes the gossiper's message
			// store keys to account for the message's type and
			// ShortChannelID.
			number:    8,
			migration: migration_01_to_11.MigrateGossipMessageStoreKeys,
		},
		{
			// The DB version where the payments and payment
			// statuses are moved to being stored in a combined
			// bucket.
			number:    9,
			migration: migration_01_to_11.MigrateOutgoingPayments,
		},
		{
			// The DB version where we started to store legacy
			// payload information for all routes, as well as the
			// optional TLV records.
			number:    10,
			migration: migration_01_to_11.MigrateRouteSerialization,
		},
		{
			// Add invoice htlc and cltv delta fields.
			number:    11,
			migration: migration_01_to_11.MigrateInvoices,
		},
		{
			// Migrate to TLV invoice bodies, add payment address
			// and features, remove receipt.
			number:    12,
			migration: migration12.MigrateInvoiceTLV,
		},
		{
			// Migrate to multi-path payments.
			number:    13,
			migration: migration13.MigrateMPP,
		},
		{
			// Initialize payment address index and begin using it
			// as the default index, falling back to payment hash
			// index.
			number:    14,
			migration: mig.CreateTLB(payAddrIndexBucket),
		},
		{
			// Initialize payment index bucket which will be used
			// to index payments by sequence number. This index will
			// be used to allow more efficient ListPayments queries.
			number:    15,
			migration: mig.CreateTLB(paymentsIndexBucket),
		},
		{
			// Add our existing payments to the index bucket created
			// in migration 15.
			number:    16,
			migration: migration16.MigrateSequenceIndex,
		},
		{
			// Create a top level bucket which will store extra
			// information about channel closes.
			number:    17,
			migration: mig.CreateTLB(closeSummaryBucket),
		},
		{
			// Create a top level bucket which holds information
			// about our peers.
			number:    18,
			migration: mig.CreateTLB(peersBucket),
		},
		{
			// Create a PaymentHash field in ForwardingEvent.
			number:    19,
			migration: migration19.MigrateForwardingEvents,
		},
	}

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
	clock  clock.Clock
	dryRun bool
}

// Update is a wrapper around walletdb.Update which calls into the extended
// backend when available. This call is needed to be able to cast DB to
// ExtendedBackend. The passed reset function is called before the start of the
// transaction and can be used to reset intermediate state. As callers may
// expect retries of the f closure (depending on the database backend used), the
// reset function will be called before each retry respectively.
func (db *DB) Update(f func(tx walletdb.ReadWriteTx) error, reset func()) error {
	if v, ok := db.Backend.(kvdb.ExtendedBackend); ok {
		return v.Update(f, reset)
	}

	reset()
	return walletdb.Update(db, f)
}

// View is a wrapper around walletdb.View which calls into the extended
// backend when available. This call is needed to be able to cast DB to
// ExtendedBackend. The passed reset function is called before the start of the
// transaction and can be used to reset intermediate state. As callers may
// expect retries of the f closure (depending on the database backend used), the
// reset function will be called before each retry respectively.
func (db *DB) View(f func(tx walletdb.ReadTx) error, reset func()) error {
	if v, ok := db.Backend.(kvdb.ExtendedBackend); ok {
		return v.View(f, reset)
	}

	reset()
	return walletdb.View(db, f)
}

// PrintStats calls into the extended backend if available. This call is needed
// to be able to cast DB to ExtendedBackend.
func (db *DB) PrintStats() string {
	if v, ok := db.Backend.(kvdb.ExtendedBackend); ok {
		return v.PrintStats()
	}

	return "unimplemented"
}

// Open opens or creates channeldb. Any necessary schemas migrations due
// to updates will take place as necessary.
// TODO(bhandras): deprecate this function.
func Open(dbPath string, modifiers ...OptionModifier) (*DB, error) {
	opts := DefaultOptions()
	for _, modifier := range modifiers {
		modifier(&opts)
	}

	backend, err := kvdb.GetBoltBackend(&kvdb.BoltBackendConfig{
		DBPath:            dbPath,
		DBFileName:        dbName,
		NoFreelistSync:    opts.NoFreelistSync,
		AutoCompact:       opts.AutoCompact,
		AutoCompactMinAge: opts.AutoCompactMinAge,
		DBTimeout:         opts.DBTimeout,
	})
	if err != nil {
		return nil, err
	}

	db, err := CreateWithBackend(backend, modifiers...)
	if err == nil {
		db.dbPath = dbPath
	}
	return db, err
}

// CreateWithBackend creates channeldb instance using the passed kvdb.Backend.
// Any necessary schemas migrations due to updates will take place as necessary.
func CreateWithBackend(backend kvdb.Backend, modifiers ...OptionModifier) (*DB, error) {
	if err := initChannelDB(backend); err != nil {
		return nil, err
	}

	opts := DefaultOptions()
	for _, modifier := range modifiers {
		modifier(&opts)
	}

	chanDB := &DB{
		Backend: backend,
		clock:   opts.clock,
		dryRun:  opts.dryRun,
	}
	chanDB.graph = newChannelGraph(
		chanDB, opts.RejectCacheSize, opts.ChannelCacheSize,
		opts.BatchCommitInterval,
	)

	// Synchronize the version of database and apply migrations if needed.
	if err := chanDB.syncVersions(dbVersions); err != nil {
		backend.Close()
		return nil, err
	}

	return chanDB, nil
}

// Path returns the file path to the channel database.
func (d *DB) Path() string {
	return d.dbPath
}

var topLevelBuckets = [][]byte{
	openChannelBucket,
	closedChannelBucket,
	forwardingLogBucket,
	fwdPackagesKey,
	invoiceBucket,
	payAddrIndexBucket,
	paymentsIndexBucket,
	peersBucket,
	nodeInfoBucket,
	nodeBucket,
	edgeBucket,
	edgeIndexBucket,
	graphMetaBucket,
	metaBucket,
	closeSummaryBucket,
}

// Wipe completely deletes all saved state within all used buckets within the
// database. The deletion is done in a single transaction, therefore this
// operation is fully atomic.
func (d *DB) Wipe() error {
	return kvdb.Update(d, func(tx kvdb.RwTx) error {
		for _, tlb := range topLevelBuckets {
			err := tx.DeleteTopLevelBucket(tlb)
			if err != nil && err != kvdb.ErrBucketNotFound {
				return err
			}
		}
		return nil
	}, func() {})
}

// createChannelDB creates and initializes a fresh version of channeldb. In
// the case that the target path has not yet been created or doesn't yet exist,
// then the path is created. Additionally, all required top-level buckets used
// within the database are created.
func initChannelDB(db kvdb.Backend) error {
	err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		meta := &Meta{}
		// Check if DB is already initialized.
		err := fetchMeta(meta, tx)
		if err == nil {
			return nil
		}

		for _, tlb := range topLevelBuckets {
			if _, err := tx.CreateTopLevelBucket(tlb); err != nil {
				return err
			}
		}

		nodes := tx.ReadWriteBucket(nodeBucket)
		_, err = nodes.CreateBucket(aliasIndexBucket)
		if err != nil {
			return err
		}
		_, err = nodes.CreateBucket(nodeUpdateIndexBucket)
		if err != nil {
			return err
		}

		edges := tx.ReadWriteBucket(edgeBucket)
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

		graphMeta := tx.ReadWriteBucket(graphMetaBucket)
		_, err = graphMeta.CreateBucket(pruneLogBucket)
		if err != nil {
			return err
		}

		meta.DbVersionNumber = getLatestDBVersion(dbVersions)
		return putMeta(meta, tx)
	}, func() {})
	if err != nil {
		return fmt.Errorf("unable to create new channeldb: %v", err)
	}

	return nil
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

// FetchOpenChannels starts a new database transaction and returns all stored
// currently active/open channels associated with the target nodeID. In the case
// that no active channels are known to have been created with this node, then a
// zero-length slice is returned.
func (d *DB) FetchOpenChannels(nodeID *btcec.PublicKey) ([]*OpenChannel, error) {
	var channels []*OpenChannel
	err := kvdb.View(d, func(tx kvdb.RTx) error {
		var err error
		channels, err = d.fetchOpenChannels(tx, nodeID)
		return err
	}, func() {
		channels = nil
	})

	return channels, err
}

// fetchOpenChannels uses and existing database transaction and returns all
// stored currently active/open channels associated with the target nodeID. In
// the case that no active channels are known to have been created with this
// node, then a zero-length slice is returned.
func (db *DB) fetchOpenChannels(tx kvdb.RTx,
	nodeID *btcec.PublicKey) ([]*OpenChannel, error) {

	// Get the bucket dedicated to storing the metadata for open channels.
	openChanBucket := tx.ReadBucket(openChannelBucket)
	if openChanBucket == nil {
		return nil, nil
	}

	// Within this top level bucket, fetch the bucket dedicated to storing
	// open channel data specific to the remote node.
	pub := nodeID.SerializeCompressed()
	nodeChanBucket := openChanBucket.NestedReadBucket(pub)
	if nodeChanBucket == nil {
		return nil, nil
	}

	// Next, we'll need to go down an additional layer in order to retrieve
	// the channels for each chain the node knows of.
	var channels []*OpenChannel
	err := nodeChanBucket.ForEach(func(chainHash, v []byte) error {
		// If there's a value, it's not a bucket so ignore it.
		if v != nil {
			return nil
		}

		// If we've found a valid chainhash bucket, then we'll retrieve
		// that so we can extract all the channels.
		chainBucket := nodeChanBucket.NestedReadBucket(chainHash)
		if chainBucket == nil {
			return fmt.Errorf("unable to read bucket for chain=%x",
				chainHash[:])
		}

		// Finally, we both of the necessary buckets retrieved, fetch
		// all the active channels related to this node.
		nodeChannels, err := db.fetchNodeChannels(chainBucket)
		if err != nil {
			return fmt.Errorf("unable to read channel for "+
				"chain_hash=%x, node_key=%x: %v",
				chainHash[:], pub, err)
		}

		channels = append(channels, nodeChannels...)
		return nil
	})

	return channels, err
}

// fetchNodeChannels retrieves all active channels from the target chainBucket
// which is under a node's dedicated channel bucket. This function is typically
// used to fetch all the active channels related to a particular node.
func (db *DB) fetchNodeChannels(chainBucket kvdb.RBucket) ([]*OpenChannel, error) {

	var channels []*OpenChannel

	// A node may have channels on several chains, so for each known chain,
	// we'll extract all the channels.
	err := chainBucket.ForEach(func(chanPoint, v []byte) error {
		// If there's a value, it's not a bucket so ignore it.
		if v != nil {
			return nil
		}

		// Once we've found a valid channel bucket, we'll extract it
		// from the node's chain bucket.
		chanBucket := chainBucket.NestedReadBucket(chanPoint)

		var outPoint wire.OutPoint
		err := readOutpoint(bytes.NewReader(chanPoint), &outPoint)
		if err != nil {
			return err
		}
		oChannel, err := fetchOpenChannel(chanBucket, &outPoint)
		if err != nil {
			return fmt.Errorf("unable to read channel data for "+
				"chan_point=%v: %v", outPoint, err)
		}
		oChannel.Db = db

		channels = append(channels, oChannel)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return channels, nil
}

// FetchChannel attempts to locate a channel specified by the passed channel
// point. If the channel cannot be found, then an error will be returned.
func (d *DB) FetchChannel(chanPoint wire.OutPoint) (*OpenChannel, error) {
	var (
		targetChan      *OpenChannel
		targetChanPoint bytes.Buffer
	)

	if err := writeOutpoint(&targetChanPoint, &chanPoint); err != nil {
		return nil, err
	}

	// chanScan will traverse the following bucket structure:
	//  * nodePub => chainHash => chanPoint
	//
	// At each level we go one further, ensuring that we're traversing the
	// proper key (that's actually a bucket). By only reading the bucket
	// structure and skipping fully decoding each channel, we save a good
	// bit of CPU as we don't need to do things like decompress public
	// keys.
	chanScan := func(tx kvdb.RTx) error {
		// Get the bucket dedicated to storing the metadata for open
		// channels.
		openChanBucket := tx.ReadBucket(openChannelBucket)
		if openChanBucket == nil {
			return ErrNoActiveChannels
		}

		// Within the node channel bucket, are the set of node pubkeys
		// we have channels with, we don't know the entire set, so
		// we'll check them all.
		return openChanBucket.ForEach(func(nodePub, v []byte) error {
			// Ensure that this is a key the same size as a pubkey,
			// and also that it leads directly to a bucket.
			if len(nodePub) != 33 || v != nil {
				return nil
			}

			nodeChanBucket := openChanBucket.NestedReadBucket(nodePub)
			if nodeChanBucket == nil {
				return nil
			}

			// The next layer down is all the chains that this node
			// has channels on with us.
			return nodeChanBucket.ForEach(func(chainHash, v []byte) error {
				// If there's a value, it's not a bucket so
				// ignore it.
				if v != nil {
					return nil
				}

				chainBucket := nodeChanBucket.NestedReadBucket(
					chainHash,
				)
				if chainBucket == nil {
					return fmt.Errorf("unable to read "+
						"bucket for chain=%x", chainHash[:])
				}

				// Finally we reach the leaf bucket that stores
				// all the chanPoints for this node.
				chanBucket := chainBucket.NestedReadBucket(
					targetChanPoint.Bytes(),
				)
				if chanBucket == nil {
					return nil
				}

				channel, err := fetchOpenChannel(
					chanBucket, &chanPoint,
				)
				if err != nil {
					return err
				}

				targetChan = channel
				targetChan.Db = d

				return nil
			})
		})
	}

	err := kvdb.View(d, chanScan, func() {})
	if err != nil {
		return nil, err
	}

	if targetChan != nil {
		return targetChan, nil
	}

	// If we can't find the channel, then we return with an error, as we
	// have nothing to  backup.
	return nil, ErrChannelNotFound
}

// FetchAllChannels attempts to retrieve all open channels currently stored
// within the database, including pending open, fully open and channels waiting
// for a closing transaction to confirm.
func (d *DB) FetchAllChannels() ([]*OpenChannel, error) {
	return fetchChannels(d)
}

// FetchAllOpenChannels will return all channels that have the funding
// transaction confirmed, and is not waiting for a closing transaction to be
// confirmed.
func (d *DB) FetchAllOpenChannels() ([]*OpenChannel, error) {
	return fetchChannels(
		d,
		pendingChannelFilter(false),
		waitingCloseFilter(false),
	)
}

// FetchPendingChannels will return channels that have completed the process of
// generating and broadcasting funding transactions, but whose funding
// transactions have yet to be confirmed on the blockchain.
func (d *DB) FetchPendingChannels() ([]*OpenChannel, error) {
	return fetchChannels(d,
		pendingChannelFilter(true),
		waitingCloseFilter(false),
	)
}

// FetchWaitingCloseChannels will return all channels that have been opened,
// but are now waiting for a closing transaction to be confirmed.
//
// NOTE: This includes channels that are also pending to be opened.
func (d *DB) FetchWaitingCloseChannels() ([]*OpenChannel, error) {
	return fetchChannels(
		d, waitingCloseFilter(true),
	)
}

// fetchChannelsFilter applies a filter to channels retrieved in fetchchannels.
// A set of filters can be combined to filter across multiple dimensions.
type fetchChannelsFilter func(channel *OpenChannel) bool

// pendingChannelFilter returns a filter based on whether channels are pending
// (ie, their funding transaction still needs to confirm). If pending is false,
// channels with confirmed funding transactions are returned.
func pendingChannelFilter(pending bool) fetchChannelsFilter {
	return func(channel *OpenChannel) bool {
		return channel.IsPending == pending
	}
}

// waitingCloseFilter returns a filter which filters channels based on whether
// they are awaiting the confirmation of their closing transaction. If waiting
// close is true, channels that have had their closing tx broadcast are
// included. If it is false, channels that are not awaiting confirmation of
// their close transaction are returned.
func waitingCloseFilter(waitingClose bool) fetchChannelsFilter {
	return func(channel *OpenChannel) bool {
		// If the channel is in any other state than Default,
		// then it means it is waiting to be closed.
		channelWaitingClose :=
			channel.ChanStatus() != ChanStatusDefault

		// Include the channel if it matches the value for
		// waiting close that we are filtering on.
		return channelWaitingClose == waitingClose
	}
}

// fetchChannels attempts to retrieve channels currently stored in the
// database. It takes a set of filters which are applied to each channel to
// obtain a set of channels with the desired set of properties. Only channels
// which have a true value returned for *all* of the filters will be returned.
// If no filters are provided, every channel in the open channels bucket will
// be returned.
func fetchChannels(d *DB, filters ...fetchChannelsFilter) ([]*OpenChannel, error) {
	var channels []*OpenChannel

	err := kvdb.View(d, func(tx kvdb.RTx) error {
		// Get the bucket dedicated to storing the metadata for open
		// channels.
		openChanBucket := tx.ReadBucket(openChannelBucket)
		if openChanBucket == nil {
			return ErrNoActiveChannels
		}

		// Next, fetch the bucket dedicated to storing metadata related
		// to all nodes. All keys within this bucket are the serialized
		// public keys of all our direct counterparties.
		nodeMetaBucket := tx.ReadBucket(nodeInfoBucket)
		if nodeMetaBucket == nil {
			return fmt.Errorf("node bucket not created")
		}

		// Finally for each node public key in the bucket, fetch all
		// the channels related to this particular node.
		return nodeMetaBucket.ForEach(func(k, v []byte) error {
			nodeChanBucket := openChanBucket.NestedReadBucket(k)
			if nodeChanBucket == nil {
				return nil
			}

			return nodeChanBucket.ForEach(func(chainHash, v []byte) error {
				// If there's a value, it's not a bucket so
				// ignore it.
				if v != nil {
					return nil
				}

				// If we've found a valid chainhash bucket,
				// then we'll retrieve that so we can extract
				// all the channels.
				chainBucket := nodeChanBucket.NestedReadBucket(
					chainHash,
				)
				if chainBucket == nil {
					return fmt.Errorf("unable to read "+
						"bucket for chain=%x", chainHash[:])
				}

				nodeChans, err := d.fetchNodeChannels(chainBucket)
				if err != nil {
					return fmt.Errorf("unable to read "+
						"channel for chain_hash=%x, "+
						"node_key=%x: %v", chainHash[:], k, err)
				}
				for _, channel := range nodeChans {
					// includeChannel indicates whether the channel
					// meets the criteria specified by our filters.
					includeChannel := true

					// Run through each filter and check whether the
					// channel should be included.
					for _, f := range filters {
						// If the channel fails the filter, set
						// includeChannel to false and don't bother
						// checking the remaining filters.
						if !f(channel) {
							includeChannel = false
							break
						}
					}

					// If the channel passed every filter, include it in
					// our set of channels.
					if includeChannel {
						channels = append(channels, channel)
					}
				}
				return nil
			})

		})
	}, func() {
		channels = nil
	})
	if err != nil {
		return nil, err
	}

	return channels, nil
}

// FetchClosedChannels attempts to fetch all closed channels from the database.
// The pendingOnly bool toggles if channels that aren't yet fully closed should
// be returned in the response or not. When a channel was cooperatively closed,
// it becomes fully closed after a single confirmation.  When a channel was
// forcibly closed, it will become fully closed after _all_ the pending funds
// (if any) have been swept.
func (d *DB) FetchClosedChannels(pendingOnly bool) ([]*ChannelCloseSummary, error) {
	var chanSummaries []*ChannelCloseSummary

	if err := kvdb.View(d, func(tx kvdb.RTx) error {
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
	}, func() {
		chanSummaries = nil
	}); err != nil {
		return nil, err
	}

	return chanSummaries, nil
}

// ErrClosedChannelNotFound signals that a closed channel could not be found in
// the channeldb.
var ErrClosedChannelNotFound = errors.New("unable to find closed channel summary")

// FetchClosedChannel queries for a channel close summary using the channel
// point of the channel in question.
func (d *DB) FetchClosedChannel(chanID *wire.OutPoint) (*ChannelCloseSummary, error) {
	var chanSummary *ChannelCloseSummary
	if err := kvdb.View(d, func(tx kvdb.RTx) error {
		closeBucket := tx.ReadBucket(closedChannelBucket)
		if closeBucket == nil {
			return ErrClosedChannelNotFound
		}

		var b bytes.Buffer
		var err error
		if err = writeOutpoint(&b, chanID); err != nil {
			return err
		}

		summaryBytes := closeBucket.Get(b.Bytes())
		if summaryBytes == nil {
			return ErrClosedChannelNotFound
		}

		summaryReader := bytes.NewReader(summaryBytes)
		chanSummary, err = deserializeCloseChannelSummary(summaryReader)

		return err
	}, func() {
		chanSummary = nil
	}); err != nil {
		return nil, err
	}

	return chanSummary, nil
}

// FetchClosedChannelForID queries for a channel close summary using the
// channel ID of the channel in question.
func (d *DB) FetchClosedChannelForID(cid lnwire.ChannelID) (
	*ChannelCloseSummary, error) {

	var chanSummary *ChannelCloseSummary
	if err := kvdb.View(d, func(tx kvdb.RTx) error {
		closeBucket := tx.ReadBucket(closedChannelBucket)
		if closeBucket == nil {
			return ErrClosedChannelNotFound
		}

		// The first 30 bytes of the channel ID and outpoint will be
		// equal.
		cursor := closeBucket.ReadCursor()
		op, c := cursor.Seek(cid[:30])

		// We scan over all possible candidates for this channel ID.
		for ; op != nil && bytes.Compare(cid[:30], op[:30]) <= 0; op, c = cursor.Next() {
			var outPoint wire.OutPoint
			err := readOutpoint(bytes.NewReader(op), &outPoint)
			if err != nil {
				return err
			}

			// If the found outpoint does not correspond to this
			// channel ID, we continue.
			if !cid.IsChanPoint(&outPoint) {
				continue
			}

			// Deserialize the close summary and return.
			r := bytes.NewReader(c)
			chanSummary, err = deserializeCloseChannelSummary(r)
			if err != nil {
				return err
			}

			return nil
		}
		return ErrClosedChannelNotFound
	}, func() {
		chanSummary = nil
	}); err != nil {
		return nil, err
	}

	return chanSummary, nil
}

// MarkChanFullyClosed marks a channel as fully closed within the database. A
// channel should be marked as fully closed if the channel was initially
// cooperatively closed and it's reached a single confirmation, or after all
// the pending funds in a channel that has been forcibly closed have been
// swept.
func (d *DB) MarkChanFullyClosed(chanPoint *wire.OutPoint) error {
	return kvdb.Update(d, func(tx kvdb.RwTx) error {
		var b bytes.Buffer
		if err := writeOutpoint(&b, chanPoint); err != nil {
			return err
		}

		chanID := b.Bytes()

		closedChanBucket, err := tx.CreateTopLevelBucket(
			closedChannelBucket,
		)
		if err != nil {
			return err
		}

		chanSummaryBytes := closedChanBucket.Get(chanID)
		if chanSummaryBytes == nil {
			return fmt.Errorf("no closed channel for "+
				"chan_point=%v found", chanPoint)
		}

		chanSummaryReader := bytes.NewReader(chanSummaryBytes)
		chanSummary, err := deserializeCloseChannelSummary(
			chanSummaryReader,
		)
		if err != nil {
			return err
		}

		chanSummary.IsPending = false

		var newSummary bytes.Buffer
		err = serializeChannelCloseSummary(&newSummary, chanSummary)
		if err != nil {
			return err
		}

		err = closedChanBucket.Put(chanID, newSummary.Bytes())
		if err != nil {
			return err
		}

		// Now that the channel is closed, we'll check if we have any
		// other open channels with this peer. If we don't we'll
		// garbage collect it to ensure we don't establish persistent
		// connections to peers without open channels.
		return d.pruneLinkNode(tx, chanSummary.RemotePub)
	}, func() {})
}

// pruneLinkNode determines whether we should garbage collect a link node from
// the database due to no longer having any open channels with it. If there are
// any left, then this acts as a no-op.
func (db *DB) pruneLinkNode(tx kvdb.RwTx, remotePub *btcec.PublicKey) error {
	openChannels, err := db.fetchOpenChannels(tx, remotePub)
	if err != nil {
		return fmt.Errorf("unable to fetch open channels for peer %x: "+
			"%v", remotePub.SerializeCompressed(), err)
	}

	if len(openChannels) > 0 {
		return nil
	}

	log.Infof("Pruning link node %x with zero open channels from database",
		remotePub.SerializeCompressed())

	return db.deleteLinkNode(tx, remotePub)
}

// PruneLinkNodes attempts to prune all link nodes found within the databse with
// whom we no longer have any open channels with.
func (d *DB) PruneLinkNodes() error {
	return kvdb.Update(d, func(tx kvdb.RwTx) error {
		linkNodes, err := d.fetchAllLinkNodes(tx)
		if err != nil {
			return err
		}

		for _, linkNode := range linkNodes {
			err := d.pruneLinkNode(tx, linkNode.IdentityPub)
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
}

// ChannelShell is a shell of a channel that is meant to be used for channel
// recovery purposes. It contains a minimal OpenChannel instance along with
// addresses for that target node.
type ChannelShell struct {
	// NodeAddrs the set of addresses that this node has known to be
	// reachable at in the past.
	NodeAddrs []net.Addr

	// Chan is a shell of an OpenChannel, it contains only the items
	// required to restore the channel on disk.
	Chan *OpenChannel
}

// RestoreChannelShells is a method that allows the caller to reconstruct the
// state of an OpenChannel from the ChannelShell. We'll attempt to write the
// new channel to disk, create a LinkNode instance with the passed node
// addresses, and finally create an edge within the graph for the channel as
// well. This method is idempotent, so repeated calls with the same set of
// channel shells won't modify the database after the initial call.
func (d *DB) RestoreChannelShells(channelShells ...*ChannelShell) error {
	err := kvdb.Update(d, func(tx kvdb.RwTx) error {
		for _, channelShell := range channelShells {
			channel := channelShell.Chan

			// When we make a channel, we mark that the channel has
			// been restored, this will signal to other sub-systems
			// to not attempt to use the channel as if it was a
			// regular one.
			channel.chanStatus |= ChanStatusRestored

			// First, we'll attempt to create a new open channel
			// and link node for this channel. If the channel
			// already exists, then in order to ensure this method
			// is idempotent, we'll continue to the next step.
			channel.Db = d
			err := syncNewChannel(
				tx, channel, channelShell.NodeAddrs,
			)
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
	if err != nil {
		return err
	}

	return nil
}

// AddrsForNode consults the graph and channel database for all addresses known
// to the passed node public key.
func (d *DB) AddrsForNode(nodePub *btcec.PublicKey) ([]net.Addr, error) {
	var (
		linkNode  *LinkNode
		graphNode LightningNode
	)

	dbErr := kvdb.View(d, func(tx kvdb.RTx) error {
		var err error

		linkNode, err = fetchLinkNode(tx, nodePub)
		if err != nil {
			return err
		}

		// We'll also query the graph for this peer to see if they have
		// any addresses that we don't currently have stored within the
		// link node database.
		nodes := tx.ReadBucket(nodeBucket)
		if nodes == nil {
			return ErrGraphNotFound
		}
		compressedPubKey := nodePub.SerializeCompressed()
		graphNode, err = fetchLightningNode(nodes, compressedPubKey)
		if err != nil && err != ErrGraphNodeNotFound {
			// If the node isn't found, then that's OK, as we still
			// have the link node data.
			return err
		}

		return nil
	}, func() {
		linkNode = nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// Now that we have both sources of addrs for this node, we'll use a
	// map to de-duplicate any addresses between the two sources, and
	// produce a final list of the combined addrs.
	addrs := make(map[string]net.Addr)
	for _, addr := range linkNode.Addresses {
		addrs[addr.String()] = addr
	}
	for _, addr := range graphNode.Addresses {
		addrs[addr.String()] = addr
	}
	dedupedAddrs := make([]net.Addr, 0, len(addrs))
	for _, addr := range addrs {
		dedupedAddrs = append(dedupedAddrs, addr)
	}

	return dedupedAddrs, nil
}

// AbandonChannel attempts to remove the target channel from the open channel
// database. If the channel was already removed (has a closed channel entry),
// then we'll return a nil error. Otherwise, we'll insert a new close summary
// into the database.
func (db *DB) AbandonChannel(chanPoint *wire.OutPoint, bestHeight uint32) error {
	// With the chanPoint constructed, we'll attempt to find the target
	// channel in the database. If we can't find the channel, then we'll
	// return the error back to the caller.
	dbChan, err := db.FetchChannel(*chanPoint)
	switch {
	// If the channel wasn't found, then it's possible that it was already
	// abandoned from the database.
	case err == ErrChannelNotFound:
		_, closedErr := db.FetchClosedChannel(chanPoint)
		if closedErr != nil {
			return closedErr
		}

		// If the channel was already closed, then we don't return an
		// error as we'd like fro this step to be repeatable.
		return nil
	case err != nil:
		return err
	}

	// Now that we've found the channel, we'll populate a close summary for
	// the channel, so we can store as much information for this abounded
	// channel as possible. We also ensure that we set Pending to false, to
	// indicate that this channel has been "fully" closed.
	summary := &ChannelCloseSummary{
		CloseType:               Abandoned,
		ChanPoint:               *chanPoint,
		ChainHash:               dbChan.ChainHash,
		CloseHeight:             bestHeight,
		RemotePub:               dbChan.IdentityPub,
		Capacity:                dbChan.Capacity,
		SettledBalance:          dbChan.LocalCommitment.LocalBalance.ToSatoshis(),
		ShortChanID:             dbChan.ShortChanID(),
		RemoteCurrentRevocation: dbChan.RemoteCurrentRevocation,
		RemoteNextRevocation:    dbChan.RemoteNextRevocation,
		LocalChanConfig:         dbChan.LocalChanCfg,
	}

	// Finally, we'll close the channel in the DB, and return back to the
	// caller. We set ourselves as the close initiator because we abandoned
	// the channel.
	return dbChan.CloseChannel(summary, ChanStatusLocalCloseInitiator)
}

// syncVersions function is used for safe db version synchronization. It
// applies migration functions to the current database and recovers the
// previous state of db if at least one error/panic appeared during migration.
func (d *DB) syncVersions(versions []version) error {
	meta, err := d.FetchMeta(nil)
	if err != nil {
		if err == ErrMetaNotFound {
			meta = &Meta{}
		} else {
			return err
		}
	}

	latestVersion := getLatestDBVersion(versions)
	log.Infof("Checking for schema update: latest_version=%v, "+
		"db_version=%v", latestVersion, meta.DbVersionNumber)

	switch {

	// If the database reports a higher version that we are aware of, the
	// user is probably trying to revert to a prior version of lnd. We fail
	// here to prevent reversions and unintended corruption.
	case meta.DbVersionNumber > latestVersion:
		log.Errorf("Refusing to revert from db_version=%d to "+
			"lower version=%d", meta.DbVersionNumber,
			latestVersion)
		return ErrDBReversion

	// If the current database version matches the latest version number,
	// then we don't need to perform any migrations.
	case meta.DbVersionNumber == latestVersion:
		return nil
	}

	log.Infof("Performing database schema migration")

	// Otherwise, we fetch the migrations which need to applied, and
	// execute them serially within a single database transaction to ensure
	// the migration is atomic.
	migrations, migrationVersions := getMigrationsToApply(
		versions, meta.DbVersionNumber,
	)
	return kvdb.Update(d, func(tx kvdb.RwTx) error {
		for i, migration := range migrations {
			if migration == nil {
				continue
			}

			log.Infof("Applying migration #%v", migrationVersions[i])

			if err := migration(tx); err != nil {
				log.Infof("Unable to apply migration #%v",
					migrationVersions[i])
				return err
			}
		}

		meta.DbVersionNumber = latestVersion
		err := putMeta(meta, tx)
		if err != nil {
			return err
		}

		// In dry-run mode, return an error to prevent the transaction
		// from committing.
		if d.dryRun {
			return ErrDryRunMigrationOK
		}

		return nil
	}, func() {})
}

// ChannelGraph returns a new instance of the directed channel graph.
func (d *DB) ChannelGraph() *ChannelGraph {
	return d.graph
}

func getLatestDBVersion(versions []version) uint32 {
	return versions[len(versions)-1].number
}

// getMigrationsToApply retrieves the migration function that should be
// applied to the database.
func getMigrationsToApply(versions []version, version uint32) ([]migration, []uint32) {
	migrations := make([]migration, 0, len(versions))
	migrationVersions := make([]uint32, 0, len(versions))

	for _, v := range versions {
		if v.number > version {
			migrations = append(migrations, v.migration)
			migrationVersions = append(migrationVersions, v.number)
		}
	}

	return migrations, migrationVersions
}

// fetchHistoricalChanBucket returns a the channel bucket for a given outpoint
// from the historical channel bucket. If the bucket does not exist,
// ErrNoHistoricalBucket is returned.
func fetchHistoricalChanBucket(tx kvdb.RTx,
	outPoint *wire.OutPoint) (kvdb.RBucket, error) {

	// First fetch the top level bucket which stores all data related to
	// historically stored channels.
	historicalChanBucket := tx.ReadBucket(historicalChannelBucket)
	if historicalChanBucket == nil {
		return nil, ErrNoHistoricalBucket
	}

	// With the bucket for the node and chain fetched, we can now go down
	// another level, for the channel itself.
	var chanPointBuf bytes.Buffer
	if err := writeOutpoint(&chanPointBuf, outPoint); err != nil {
		return nil, err
	}
	chanBucket := historicalChanBucket.NestedReadBucket(chanPointBuf.Bytes())
	if chanBucket == nil {
		return nil, ErrChannelNotFound
	}

	return chanBucket, nil
}

// FetchHistoricalChannel fetches open channel data from the historical channel
// bucket.
func (db *DB) FetchHistoricalChannel(outPoint *wire.OutPoint) (*OpenChannel, error) {
	var channel *OpenChannel
	err := kvdb.View(db, func(tx kvdb.RTx) error {
		chanBucket, err := fetchHistoricalChanBucket(tx, outPoint)
		if err != nil {
			return err
		}

		channel, err = fetchOpenChannel(chanBucket, outPoint)
		return err
	}, func() {
		channel = nil
	})
	if err != nil {
		return nil, err
	}

	return channel, nil
}

// MakeTestDB creates a new instance of the ChannelDB for testing purposes.
// A callback which cleans up the created temporary directories is also
// returned and intended to be executed after the test completes.
func MakeTestDB(modifiers ...OptionModifier) (*DB, func(), error) {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName, err := ioutil.TempDir("", "channeldb")
	if err != nil {
		return nil, nil, err
	}

	// Next, create channeldb for the first time.
	backend, backendCleanup, err := kvdb.GetTestBackend(tempDirName, "cdb")
	if err != nil {
		backendCleanup()
		return nil, nil, err
	}

	cdb, err := CreateWithBackend(backend, modifiers...)
	if err != nil {
		backendCleanup()
		os.RemoveAll(tempDirName)
		return nil, nil, err
	}

	cleanUp := func() {
		cdb.Close()
		backendCleanup()
		os.RemoveAll(tempDirName)
	}

	return cdb, cleanUp, nil
}
