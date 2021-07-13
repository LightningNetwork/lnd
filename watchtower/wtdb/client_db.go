package wtdb

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/blob"
)

var (
	// cSessionKeyIndexBkt is a top-level bucket storing:
	//   tower-id -> reserved-session-key-index (uint32).
	cSessionKeyIndexBkt = []byte("client-session-key-index-bucket")

	// cChanSummaryBkt is a top-level bucket storing:
	//   channel-id -> encoded ClientChanSummary.
	cChanSummaryBkt = []byte("client-channel-summary-bucket")

	// cSessionBkt is a top-level bucket storing:
	//   session-id => cSessionBody -> encoded ClientSessionBody
	//              => cSessionCommits => seqnum -> encoded CommittedUpdate
	//              => cSessionAcks => seqnum -> encoded BackupID
	cSessionBkt = []byte("client-session-bucket")

	// cSessionBody is a sub-bucket of cSessionBkt storing only the body of
	// the ClientSession.
	cSessionBody = []byte("client-session-body")

	// cSessionBody is a sub-bucket of cSessionBkt storing:
	//    seqnum -> encoded CommittedUpdate.
	cSessionCommits = []byte("client-session-commits")

	// cSessionAcks is a sub-bucket of cSessionBkt storing:
	//    seqnum -> encoded BackupID.
	cSessionAcks = []byte("client-session-acks")

	// cTowerBkt is a top-level bucket storing:
	//    tower-id -> encoded Tower.
	cTowerBkt = []byte("client-tower-bucket")

	// cTowerIndexBkt is a top-level bucket storing:
	//    tower-pubkey -> tower-id.
	cTowerIndexBkt = []byte("client-tower-index-bucket")

	// ErrTowerNotFound signals that the target tower was not found in the
	// database.
	ErrTowerNotFound = errors.New("tower not found")

	// ErrTowerUnackedUpdates is an error returned when we attempt to mark a
	// tower's sessions as inactive, but one of its sessions has unacked
	// updates.
	ErrTowerUnackedUpdates = errors.New("tower has unacked updates")

	// ErrCorruptClientSession signals that the client session's on-disk
	// structure deviates from what is expected.
	ErrCorruptClientSession = errors.New("client session corrupted")

	// ErrClientSessionAlreadyExists signals an attempt to reinsert a client
	// session that has already been created.
	ErrClientSessionAlreadyExists = errors.New(
		"client session already exists",
	)

	// ErrChannelAlreadyRegistered signals a duplicate attempt to register a
	// channel with the client database.
	ErrChannelAlreadyRegistered = errors.New("channel already registered")

	// ErrChannelNotRegistered signals a channel has not yet been registered
	// in the client database.
	ErrChannelNotRegistered = errors.New("channel not registered")

	// ErrClientSessionNotFound signals that the requested client session
	// was not found in the database.
	ErrClientSessionNotFound = errors.New("client session not found")

	// ErrUpdateAlreadyCommitted signals that the chosen sequence number has
	// already been committed to an update with a different breach hint.
	ErrUpdateAlreadyCommitted = errors.New("update already committed")

	// ErrCommitUnorderedUpdate signals the client tried to commit a
	// sequence number other than the next unallocated sequence number.
	ErrCommitUnorderedUpdate = errors.New("update seqnum not monotonic")

	// ErrCommittedUpdateNotFound signals that the tower tried to ACK a
	// sequence number that has not yet been allocated by the client.
	ErrCommittedUpdateNotFound = errors.New("committed update not found")

	// ErrUnallocatedLastApplied signals that the tower tried to provide a
	// LastApplied value greater than any allocated sequence number.
	ErrUnallocatedLastApplied = errors.New("tower echoed last appiled " +
		"greater than allocated seqnum")

	// ErrNoReservedKeyIndex signals that a client session could not be
	// created because no session key index was reserved.
	ErrNoReservedKeyIndex = errors.New("key index not reserved")

	// ErrIncorrectKeyIndex signals that the client session could not be
	// created because session key index differs from the reserved key
	// index.
	ErrIncorrectKeyIndex = errors.New("incorrect key index")

	// ErrLastTowerAddr is an error returned when the last address of a
	// watchtower is attempted to be removed.
	ErrLastTowerAddr = errors.New("cannot remove last tower address")
)

// NewBoltBackendCreator returns a function that creates a new bbolt backend for
// the watchtower database.
func NewBoltBackendCreator(active bool, dbPath,
	dbFileName string) func(boltCfg *kvdb.BoltConfig) (kvdb.Backend, error) {

	// If the watchtower client isn't active, we return a function that
	// always returns a nil DB to make sure we don't create empty database
	// files.
	if !active {
		return func(_ *kvdb.BoltConfig) (kvdb.Backend, error) {
			return nil, nil
		}
	}

	return func(boltCfg *kvdb.BoltConfig) (kvdb.Backend, error) {
		cfg := &kvdb.BoltBackendConfig{
			DBPath:            dbPath,
			DBFileName:        dbFileName,
			NoFreelistSync:    !boltCfg.SyncFreelist,
			AutoCompact:       boltCfg.AutoCompact,
			AutoCompactMinAge: boltCfg.AutoCompactMinAge,
			DBTimeout:         boltCfg.DBTimeout,
		}

		db, err := kvdb.GetBoltBackend(cfg)
		if err != nil {
			return nil, fmt.Errorf("could not open boltdb: %v", err)
		}

		return db, nil
	}
}

// ClientDB is single database providing a persistent storage engine for the
// wtclient.
type ClientDB struct {
	db kvdb.Backend
}

// OpenClientDB opens the client database given the path to the database's
// directory. If no such database exists, this method will initialize a fresh
// one using the latest version number and bucket structure. If a database
// exists but has a lower version number than the current version, any necessary
// migrations will be applied before returning. Any attempt to open a database
// with a version number higher that the latest version will fail to prevent
// accidental reversion.
func OpenClientDB(db kvdb.Backend) (*ClientDB, error) {
	firstInit, err := isFirstInit(db)
	if err != nil {
		return nil, err
	}

	clientDB := &ClientDB{
		db: db,
	}

	err = initOrSyncVersions(clientDB, firstInit, clientDBVersions)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Now that the database version fully consistent with our latest known
	// version, ensure that all top-level buckets known to this version are
	// initialized. This allows us to assume their presence throughout all
	// operations. If an known top-level bucket is expected to exist but is
	// missing, this will trigger a ErrUninitializedDB error.
	err = kvdb.Update(clientDB.db, initClientDBBuckets, func() {})
	if err != nil {
		db.Close()
		return nil, err
	}

	return clientDB, nil
}

// initClientDBBuckets creates all top-level buckets required to handle database
// operations required by the latest version.
func initClientDBBuckets(tx kvdb.RwTx) error {
	buckets := [][]byte{
		cSessionKeyIndexBkt,
		cChanSummaryBkt,
		cSessionBkt,
		cTowerBkt,
		cTowerIndexBkt,
	}

	for _, bucket := range buckets {
		_, err := tx.CreateTopLevelBucket(bucket)
		if err != nil {
			return err
		}
	}

	return nil
}

// bdb returns the backing bbolt.DB instance.
//
// NOTE: Part of the versionedDB interface.
func (c *ClientDB) bdb() kvdb.Backend {
	return c.db
}

// Version returns the database's current version number.
//
// NOTE: Part of the versionedDB interface.
func (c *ClientDB) Version() (uint32, error) {
	var version uint32
	err := kvdb.View(c.db, func(tx kvdb.RTx) error {
		var err error
		version, err = getDBVersion(tx)
		return err
	}, func() {
		version = 0
	})
	if err != nil {
		return 0, err
	}

	return version, nil
}

// Close closes the underlying database.
func (c *ClientDB) Close() error {
	return c.db.Close()
}

// CreateTower initialize an address record used to communicate with a
// watchtower. Each Tower is assigned a unique ID, that is used to amortize
// storage costs of the public key when used by multiple sessions. If the tower
// already exists, the address is appended to the list of all addresses used to
// that tower previously and its corresponding sessions are marked as active.
func (c *ClientDB) CreateTower(lnAddr *lnwire.NetAddress) (*Tower, error) {
	var towerPubKey [33]byte
	copy(towerPubKey[:], lnAddr.IdentityKey.SerializeCompressed())

	var tower *Tower
	err := kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		towerIndex := tx.ReadWriteBucket(cTowerIndexBkt)
		if towerIndex == nil {
			return ErrUninitializedDB
		}

		towers := tx.ReadWriteBucket(cTowerBkt)
		if towers == nil {
			return ErrUninitializedDB
		}

		// Check if the tower index already knows of this pubkey.
		towerIDBytes := towerIndex.Get(towerPubKey[:])
		if len(towerIDBytes) == 8 {
			// The tower already exists, deserialize the existing
			// record.
			var err error
			tower, err = getTower(towers, towerIDBytes)
			if err != nil {
				return err
			}

			// Add the new address to the existing tower. If the
			// address is a duplicate, this will result in no
			// change.
			tower.AddAddress(lnAddr.Address)

			// If there are any client sessions that correspond to
			// this tower, we'll mark them as active to ensure we
			// load them upon restarts.
			//
			// TODO(wilmer): with an index of tower -> sessions we
			// can avoid the linear lookup.
			sessions := tx.ReadWriteBucket(cSessionBkt)
			if sessions == nil {
				return ErrUninitializedDB
			}
			towerID := TowerIDFromBytes(towerIDBytes)
			towerSessions, err := listClientSessions(
				sessions, &towerID,
			)
			if err != nil {
				return err
			}
			for _, session := range towerSessions {
				err := markSessionStatus(
					sessions, session, CSessionActive,
				)
				if err != nil {
					return err
				}
			}
		} else {
			// No such tower exists, create a new tower id for our
			// new tower. The error is unhandled since NextSequence
			// never fails in an Update.
			towerID, _ := towerIndex.NextSequence()

			tower = &Tower{
				ID:          TowerID(towerID),
				IdentityKey: lnAddr.IdentityKey,
				Addresses:   []net.Addr{lnAddr.Address},
			}

			towerIDBytes = tower.ID.Bytes()

			// Since this tower is new, record the mapping from
			// tower pubkey to tower id in the tower index.
			err := towerIndex.Put(towerPubKey[:], towerIDBytes)
			if err != nil {
				return err
			}
		}

		// Store the new or updated tower under its tower id.
		return putTower(towers, tower)
	}, func() {
		tower = nil
	})
	if err != nil {
		return nil, err
	}

	return tower, nil
}

// RemoveTower modifies a tower's record within the database. If an address is
// provided, then _only_ the address record should be removed from the tower's
// persisted state. Otherwise, we'll attempt to mark the tower as inactive by
// marking all of its sessions inactive. If any of its sessions has unacked
// updates, then ErrTowerUnackedUpdates is returned. If the tower doesn't have
// any sessions at all, it'll be completely removed from the database.
//
// NOTE: An error is not returned if the tower doesn't exist.
func (c *ClientDB) RemoveTower(pubKey *btcec.PublicKey, addr net.Addr) error {
	return kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		towers := tx.ReadWriteBucket(cTowerBkt)
		if towers == nil {
			return ErrUninitializedDB
		}
		towerIndex := tx.ReadWriteBucket(cTowerIndexBkt)
		if towerIndex == nil {
			return ErrUninitializedDB
		}

		// Don't return an error if the watchtower doesn't exist to act
		// as a NOP.
		pubKeyBytes := pubKey.SerializeCompressed()
		towerIDBytes := towerIndex.Get(pubKeyBytes)
		if towerIDBytes == nil {
			return nil
		}

		// If an address is provided, then we should _only_ remove the
		// address record from the database.
		if addr != nil {
			tower, err := getTower(towers, towerIDBytes)
			if err != nil {
				return err
			}

			// Towers should always have at least one address saved.
			tower.RemoveAddress(addr)
			if len(tower.Addresses) == 0 {
				return ErrLastTowerAddr
			}

			return putTower(towers, tower)
		}

		// Otherwise, we should attempt to mark the tower's sessions as
		// inactive.
		//
		// TODO(wilmer): with an index of tower -> sessions we can avoid
		// the linear lookup.
		sessions := tx.ReadWriteBucket(cSessionBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}
		towerID := TowerIDFromBytes(towerIDBytes)
		towerSessions, err := listClientSessions(sessions, &towerID)
		if err != nil {
			return err
		}

		// If it doesn't have any, we can completely remove it from the
		// database.
		if len(towerSessions) == 0 {
			if err := towerIndex.Delete(pubKeyBytes); err != nil {
				return err
			}
			return towers.Delete(towerIDBytes)
		}

		// We'll mark its sessions as inactive as long as they don't
		// have any pending updates to ensure we don't load them upon
		// restarts.
		for _, session := range towerSessions {
			if len(session.CommittedUpdates) > 0 {
				return ErrTowerUnackedUpdates
			}
			err := markSessionStatus(
				sessions, session, CSessionInactive,
			)
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
}

// LoadTowerByID retrieves a tower by its tower ID.
func (c *ClientDB) LoadTowerByID(towerID TowerID) (*Tower, error) {
	var tower *Tower
	err := kvdb.View(c.db, func(tx kvdb.RTx) error {
		towers := tx.ReadBucket(cTowerBkt)
		if towers == nil {
			return ErrUninitializedDB
		}

		var err error
		tower, err = getTower(towers, towerID.Bytes())
		return err
	}, func() {
		tower = nil
	})
	if err != nil {
		return nil, err
	}

	return tower, nil
}

// LoadTower retrieves a tower by its public key.
func (c *ClientDB) LoadTower(pubKey *btcec.PublicKey) (*Tower, error) {
	var tower *Tower
	err := kvdb.View(c.db, func(tx kvdb.RTx) error {
		towers := tx.ReadBucket(cTowerBkt)
		if towers == nil {
			return ErrUninitializedDB
		}
		towerIndex := tx.ReadBucket(cTowerIndexBkt)
		if towerIndex == nil {
			return ErrUninitializedDB
		}

		towerIDBytes := towerIndex.Get(pubKey.SerializeCompressed())
		if towerIDBytes == nil {
			return ErrTowerNotFound
		}

		var err error
		tower, err = getTower(towers, towerIDBytes)
		return err
	}, func() {
		tower = nil
	})
	if err != nil {
		return nil, err
	}

	return tower, nil
}

// ListTowers retrieves the list of towers available within the database.
func (c *ClientDB) ListTowers() ([]*Tower, error) {
	var towers []*Tower
	err := kvdb.View(c.db, func(tx kvdb.RTx) error {
		towerBucket := tx.ReadBucket(cTowerBkt)
		if towerBucket == nil {
			return ErrUninitializedDB
		}

		return towerBucket.ForEach(func(towerIDBytes, _ []byte) error {
			tower, err := getTower(towerBucket, towerIDBytes)
			if err != nil {
				return err
			}
			towers = append(towers, tower)
			return nil
		})
	}, func() {
		towers = nil
	})
	if err != nil {
		return nil, err
	}

	return towers, nil
}

// NextSessionKeyIndex reserves a new session key derivation index for a
// particular tower id. The index is reserved for that tower until
// CreateClientSession is invoked for that tower and index, at which point a new
// index for that tower can be reserved. Multiple calls to this method before
// CreateClientSession is invoked should return the same index.
func (c *ClientDB) NextSessionKeyIndex(towerID TowerID,
	blobType blob.Type) (uint32, error) {

	var index uint32
	err := kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		keyIndex := tx.ReadWriteBucket(cSessionKeyIndexBkt)
		if keyIndex == nil {
			return ErrUninitializedDB
		}

		// Check the session key index to see if a key has already been
		// reserved for this tower. If so, we'll deserialize and return
		// the index directly.
		var err error
		index, err = getSessionKeyIndex(keyIndex, towerID, blobType)
		if err == nil {
			return nil
		}

		// Otherwise, generate a new session key index since the node
		// doesn't already have reserved index. The error is ignored
		// since NextSequence can't fail inside Update.
		index64, _ := keyIndex.NextSequence()

		// As a sanity check, assert that the index is still in the
		// valid range of unhardened pubkeys. In the future, we should
		// move to only using hardened keys, and this will prevent any
		// overlap from occurring until then. This also prevents us from
		// overflowing uint32s.
		if index64 > math.MaxInt32 {
			return fmt.Errorf("exhausted session key indexes")
		}

		// Create the key that will used to be store the reserved index.
		keyBytes := createSessionKeyIndexKey(towerID, blobType)

		index = uint32(index64)

		var indexBuf [4]byte
		byteOrder.PutUint32(indexBuf[:], index)

		// Record the reserved session key index under this tower's id.
		return keyIndex.Put(keyBytes, indexBuf[:])
	}, func() {
		index = 0
	})
	if err != nil {
		return 0, err
	}

	return index, nil
}

// CreateClientSession records a newly negotiated client session in the set of
// active sessions. The session can be identified by its SessionID.
func (c *ClientDB) CreateClientSession(session *ClientSession) error {
	return kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		keyIndexes := tx.ReadWriteBucket(cSessionKeyIndexBkt)
		if keyIndexes == nil {
			return ErrUninitializedDB
		}

		sessions := tx.ReadWriteBucket(cSessionBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		// Check that  client session with this session id doesn't
		// already exist.
		existingSessionBytes := sessions.NestedReadWriteBucket(session.ID[:])
		if existingSessionBytes != nil {
			return ErrClientSessionAlreadyExists
		}

		towerID := session.TowerID
		blobType := session.Policy.BlobType

		// Check that this tower has a reserved key index.
		index, err := getSessionKeyIndex(keyIndexes, towerID, blobType)
		if err != nil {
			return err
		}

		// Assert that the key index of the inserted session matches the
		// reserved session key index.
		if index != session.KeyIndex {
			return ErrIncorrectKeyIndex
		}

		// Remove the key index reservation. For altruist commit
		// sessions, we'll also purge under the old legacy key format.
		key := createSessionKeyIndexKey(towerID, blobType)
		err = keyIndexes.Delete(key)
		if err != nil {
			return err
		}
		if blobType == blob.TypeAltruistCommit {
			err = keyIndexes.Delete(towerID.Bytes())
			if err != nil {
				return err
			}
		}

		// Finally, write the client session's body in the sessions
		// bucket.
		return putClientSessionBody(sessions, session)
	}, func() {})
}

// createSessionKeyIndexKey returns the indentifier used in the
// session-key-index index, created as tower-id||blob-type.
//
// NOTE: The original serialization only used tower-id, which prevents
// concurrent client types from reserving sessions with the same tower.
func createSessionKeyIndexKey(towerID TowerID, blobType blob.Type) []byte {
	towerIDBytes := towerID.Bytes()

	// Session key indexes are stored under as tower-id||blob-type.
	var keyBytes [6]byte
	copy(keyBytes[:4], towerIDBytes)
	byteOrder.PutUint16(keyBytes[4:], uint16(blobType))

	return keyBytes[:]
}

// getSessionKeyIndex is a helper method
func getSessionKeyIndex(keyIndexes kvdb.RwBucket, towerID TowerID,
	blobType blob.Type) (uint32, error) {

	// Session key indexes are store under as tower-id||blob-type. The
	// original serialization only used tower-id, which prevents concurrent
	// client types from reserving sessions with the same tower.
	keyBytes := createSessionKeyIndexKey(towerID, blobType)

	// Retrieve the index using the key bytes. If the key wasn't found, we
	// will fall back to the legacy format that only uses the tower id, but
	// _only_ if the blob type is for altruist commit sessions since that
	// was the only operational session type prior to changing the key
	// format.
	keyIndexBytes := keyIndexes.Get(keyBytes)
	if keyIndexBytes == nil && blobType == blob.TypeAltruistCommit {
		keyIndexBytes = keyIndexes.Get(towerID.Bytes())
	}

	// All session key indexes should be serialized uint32's. If no key
	// index was found, the length of keyIndexBytes will be 0.
	if len(keyIndexBytes) != 4 {
		return 0, ErrNoReservedKeyIndex
	}

	return byteOrder.Uint32(keyIndexBytes), nil
}

// ListClientSessions returns the set of all client sessions known to the db. An
// optional tower ID can be used to filter out any client sessions in the
// response that do not correspond to this tower.
func (c *ClientDB) ListClientSessions(id *TowerID) (map[SessionID]*ClientSession, error) {
	var clientSessions map[SessionID]*ClientSession
	err := kvdb.View(c.db, func(tx kvdb.RTx) error {
		sessions := tx.ReadBucket(cSessionBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}
		var err error
		clientSessions, err = listClientSessions(sessions, id)
		return err
	}, func() {
		clientSessions = nil
	})
	if err != nil {
		return nil, err
	}

	return clientSessions, nil
}

// listClientSessions returns the set of all client sessions known to the db. An
// optional tower ID can be used to filter out any client sessions in the
// response that do not correspond to this tower.
func listClientSessions(sessions kvdb.RBucket,
	id *TowerID) (map[SessionID]*ClientSession, error) {

	clientSessions := make(map[SessionID]*ClientSession)
	err := sessions.ForEach(func(k, _ []byte) error {
		// We'll load the full client session since the client will need
		// the CommittedUpdates and AckedUpdates on startup to resume
		// committed updates and compute the highest known commit height
		// for each channel.
		session, err := getClientSession(sessions, k)
		if err != nil {
			return err
		}

		// Filter out any sessions that don't correspond to the given
		// tower if one was set.
		if id != nil && session.TowerID != *id {
			return nil
		}

		clientSessions[session.ID] = session

		return nil
	})
	if err != nil {
		return nil, err
	}

	return clientSessions, nil
}

// FetchChanSummaries loads a mapping from all registered channels to their
// channel summaries.
func (c *ClientDB) FetchChanSummaries() (ChannelSummaries, error) {
	var summaries map[lnwire.ChannelID]ClientChanSummary
	err := kvdb.View(c.db, func(tx kvdb.RTx) error {
		chanSummaries := tx.ReadBucket(cChanSummaryBkt)
		if chanSummaries == nil {
			return ErrUninitializedDB
		}

		return chanSummaries.ForEach(func(k, v []byte) error {
			var chanID lnwire.ChannelID
			copy(chanID[:], k)

			var summary ClientChanSummary
			err := summary.Decode(bytes.NewReader(v))
			if err != nil {
				return err
			}

			summaries[chanID] = summary

			return nil
		})
	}, func() {
		summaries = make(map[lnwire.ChannelID]ClientChanSummary)
	})
	if err != nil {
		return nil, err
	}

	return summaries, nil
}

// RegisterChannel registers a channel for use within the client database. For
// now, all that is stored in the channel summary is the sweep pkscript that
// we'd like any tower sweeps to pay into. In the future, this will be extended
// to contain more info to allow the client efficiently request historical
// states to be backed up under the client's active policy.
func (c *ClientDB) RegisterChannel(chanID lnwire.ChannelID,
	sweepPkScript []byte) error {

	return kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		chanSummaries := tx.ReadWriteBucket(cChanSummaryBkt)
		if chanSummaries == nil {
			return ErrUninitializedDB
		}

		_, err := getChanSummary(chanSummaries, chanID)
		switch {

		// Summary already exists.
		case err == nil:
			return ErrChannelAlreadyRegistered

		// Channel is not registered, proceed with registration.
		case err == ErrChannelNotRegistered:

		// Unexpected error.
		default:
			return err
		}

		summary := ClientChanSummary{
			SweepPkScript: sweepPkScript,
		}

		return putChanSummary(chanSummaries, chanID, &summary)
	}, func() {})
}

// MarkBackupIneligible records that the state identified by the (channel id,
// commit height) tuple was ineligible for being backed up under the current
// policy. This state can be retried later under a different policy.
func (c *ClientDB) MarkBackupIneligible(chanID lnwire.ChannelID,
	commitHeight uint64) error {

	return nil
}

// CommitUpdate persists the CommittedUpdate provided in the slot for (session,
// seqNum). This allows the client to retransmit this update on startup.
func (c *ClientDB) CommitUpdate(id *SessionID,
	update *CommittedUpdate) (uint16, error) {

	var lastApplied uint16
	err := kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		sessions := tx.ReadWriteBucket(cSessionBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		// We'll only load the ClientSession body for performance, since
		// we primarily need to inspect its SeqNum and TowerLastApplied
		// fields. The CommittedUpdates will be modified on disk
		// directly.
		session, err := getClientSessionBody(sessions, id[:])
		if err != nil {
			return err
		}

		// Can't fail if the above didn't fail.
		sessionBkt := sessions.NestedReadWriteBucket(id[:])

		// Ensure the session commits sub-bucket is initialized.
		sessionCommits, err := sessionBkt.CreateBucketIfNotExists(
			cSessionCommits,
		)
		if err != nil {
			return err
		}

		var seqNumBuf [2]byte
		byteOrder.PutUint16(seqNumBuf[:], update.SeqNum)

		// Check to see if a committed update already exists for this
		// sequence number.
		committedUpdateBytes := sessionCommits.Get(seqNumBuf[:])
		if committedUpdateBytes != nil {
			var dbUpdate CommittedUpdate
			err := dbUpdate.Decode(
				bytes.NewReader(committedUpdateBytes),
			)
			if err != nil {
				return err
			}

			// If an existing committed update has a different hint,
			// we'll reject this newer update.
			if dbUpdate.Hint != update.Hint {
				return ErrUpdateAlreadyCommitted
			}

			// Otherwise, capture the last applied value and
			// succeed.
			lastApplied = session.TowerLastApplied
			return nil
		}

		// There's no committed update for this sequence number, ensure
		// that we are committing the next unallocated one.
		if update.SeqNum != session.SeqNum+1 {
			return ErrCommitUnorderedUpdate
		}

		// Increment the session's sequence number and store the updated
		// client session.
		//
		// TODO(conner): split out seqnum and last applied own bucket to
		// eliminate serialization of full struct during CommitUpdate?
		// Can also read/write directly to byes [:2] without migration.
		session.SeqNum++
		err = putClientSessionBody(sessions, session)
		if err != nil {
			return err
		}

		// Encode and store the committed update in the sessionCommits
		// sub-bucket under the requested sequence number.
		var b bytes.Buffer
		err = update.Encode(&b)
		if err != nil {
			return err
		}

		err = sessionCommits.Put(seqNumBuf[:], b.Bytes())
		if err != nil {
			return err
		}

		// Finally, capture the session's last applied value so it can
		// be sent in the next state update to the tower.
		lastApplied = session.TowerLastApplied

		return nil

	}, func() {
		lastApplied = 0
	})
	if err != nil {
		return 0, err
	}

	return lastApplied, nil
}

// AckUpdate persists an acknowledgment for a given (session, seqnum) pair. This
// removes the update from the set of committed updates, and validates the
// lastApplied value returned from the tower.
func (c *ClientDB) AckUpdate(id *SessionID, seqNum uint16,
	lastApplied uint16) error {

	return kvdb.Update(c.db, func(tx kvdb.RwTx) error {
		sessions := tx.ReadWriteBucket(cSessionBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		// We'll only load the ClientSession body for performance, since
		// we primarily need to inspect its SeqNum and TowerLastApplied
		// fields. The CommittedUpdates and AckedUpdates will be
		// modified on disk directly.
		session, err := getClientSessionBody(sessions, id[:])
		if err != nil {
			return err
		}

		// If the tower has acked a sequence number beyond our highest
		// sequence number, fail.
		if lastApplied > session.SeqNum {
			return ErrUnallocatedLastApplied
		}

		// If the tower acked with a lower sequence number than it gave
		// us prior, fail.
		if lastApplied < session.TowerLastApplied {
			return ErrLastAppliedReversion
		}

		// TODO(conner): split out seqnum and last applied own bucket to
		// eliminate serialization of full struct during AckUpdate?  Can
		// also read/write directly to byes [2:4] without migration.
		session.TowerLastApplied = lastApplied

		// Write the client session with the updated last applied value.
		err = putClientSessionBody(sessions, session)
		if err != nil {
			return err
		}

		// Can't fail because of getClientSession succeeded.
		sessionBkt := sessions.NestedReadWriteBucket(id[:])

		// If the commits sub-bucket doesn't exist, there can't possibly
		// be a corresponding committed update to remove.
		sessionCommits := sessionBkt.NestedReadWriteBucket(cSessionCommits)
		if sessionCommits == nil {
			return ErrCommittedUpdateNotFound
		}

		var seqNumBuf [2]byte
		byteOrder.PutUint16(seqNumBuf[:], seqNum)

		// Assert that a committed update exists for this sequence
		// number.
		committedUpdateBytes := sessionCommits.Get(seqNumBuf[:])
		if committedUpdateBytes == nil {
			return ErrCommittedUpdateNotFound
		}

		var committedUpdate CommittedUpdate
		err = committedUpdate.Decode(
			bytes.NewReader(committedUpdateBytes),
		)
		if err != nil {
			return err
		}

		// Remove the corresponding committed update.
		err = sessionCommits.Delete(seqNumBuf[:])
		if err != nil {
			return err
		}

		// Ensure that the session acks sub-bucket is initialized so we
		// can insert an entry.
		sessionAcks, err := sessionBkt.CreateBucketIfNotExists(
			cSessionAcks,
		)
		if err != nil {
			return err
		}

		// The session acks only need to track the backup id of the
		// update, so we can discard the blob and hint.
		var b bytes.Buffer
		err = committedUpdate.BackupID.Encode(&b)
		if err != nil {
			return err
		}

		// Finally, insert the ack into the sessionAcks sub-bucket.
		return sessionAcks.Put(seqNumBuf[:], b.Bytes())
	}, func() {})
}

// getClientSessionBody loads the body of a ClientSession from the sessions
// bucket corresponding to the serialized session id. This does not deserialize
// the CommittedUpdates or AckUpdates associated with the session. If the caller
// requires this info, use getClientSession.
func getClientSessionBody(sessions kvdb.RBucket,
	idBytes []byte) (*ClientSession, error) {

	sessionBkt := sessions.NestedReadBucket(idBytes)
	if sessionBkt == nil {
		return nil, ErrClientSessionNotFound
	}

	// Should never have a sessionBkt without also having its body.
	sessionBody := sessionBkt.Get(cSessionBody)
	if sessionBody == nil {
		return nil, ErrCorruptClientSession
	}

	var session ClientSession
	copy(session.ID[:], idBytes)

	err := session.Decode(bytes.NewReader(sessionBody))
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// getClientSession loads the full ClientSession associated with the serialized
// session id. This method populates the CommittedUpdates and AckUpdates in
// addition to the ClientSession's body.
func getClientSession(sessions kvdb.RBucket,
	idBytes []byte) (*ClientSession, error) {

	session, err := getClientSessionBody(sessions, idBytes)
	if err != nil {
		return nil, err
	}

	// Fetch the committed updates for this session.
	commitedUpdates, err := getClientSessionCommits(sessions, idBytes)
	if err != nil {
		return nil, err
	}

	// Fetch the acked updates for this session.
	ackedUpdates, err := getClientSessionAcks(sessions, idBytes)
	if err != nil {
		return nil, err
	}

	session.CommittedUpdates = commitedUpdates
	session.AckedUpdates = ackedUpdates

	return session, nil
}

// getClientSessionCommits retrieves all committed updates for the session
// identified by the serialized session id.
func getClientSessionCommits(sessions kvdb.RBucket,
	idBytes []byte) ([]CommittedUpdate, error) {

	// Can't fail because client session body has already been read.
	sessionBkt := sessions.NestedReadBucket(idBytes)

	// Initialize commitedUpdates so that we can return an initialized map
	// if no committed updates exist.
	committedUpdates := make([]CommittedUpdate, 0)

	sessionCommits := sessionBkt.NestedReadBucket(cSessionCommits)
	if sessionCommits == nil {
		return committedUpdates, nil
	}

	err := sessionCommits.ForEach(func(k, v []byte) error {
		var committedUpdate CommittedUpdate
		err := committedUpdate.Decode(bytes.NewReader(v))
		if err != nil {
			return err
		}
		committedUpdate.SeqNum = byteOrder.Uint16(k)

		committedUpdates = append(committedUpdates, committedUpdate)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return committedUpdates, nil
}

// getClientSessionAcks retrieves all acked updates for the session identified
// by the serialized session id.
func getClientSessionAcks(sessions kvdb.RBucket,
	idBytes []byte) (map[uint16]BackupID, error) {

	// Can't fail because client session body has already been read.
	sessionBkt := sessions.NestedReadBucket(idBytes)

	// Initialize ackedUpdates so that we can return an initialized map if
	// no acked updates exist.
	ackedUpdates := make(map[uint16]BackupID)

	sessionAcks := sessionBkt.NestedReadBucket(cSessionAcks)
	if sessionAcks == nil {
		return ackedUpdates, nil
	}

	err := sessionAcks.ForEach(func(k, v []byte) error {
		seqNum := byteOrder.Uint16(k)

		var backupID BackupID
		err := backupID.Decode(bytes.NewReader(v))
		if err != nil {
			return err
		}

		ackedUpdates[seqNum] = backupID

		return nil
	})
	if err != nil {
		return nil, err
	}

	return ackedUpdates, nil
}

// putClientSessionBody stores the body of the ClientSession (everything but the
// CommittedUpdates and AckedUpdates).
func putClientSessionBody(sessions kvdb.RwBucket,
	session *ClientSession) error {

	sessionBkt, err := sessions.CreateBucketIfNotExists(session.ID[:])
	if err != nil {
		return err
	}

	var b bytes.Buffer
	err = session.Encode(&b)
	if err != nil {
		return err
	}

	return sessionBkt.Put(cSessionBody, b.Bytes())
}

// markSessionStatus updates the persisted state of the session to the new
// status.
func markSessionStatus(sessions kvdb.RwBucket, session *ClientSession,
	status CSessionStatus) error {

	session.Status = status
	return putClientSessionBody(sessions, session)
}

// getChanSummary loads a ClientChanSummary for the passed chanID.
func getChanSummary(chanSummaries kvdb.RBucket,
	chanID lnwire.ChannelID) (*ClientChanSummary, error) {

	chanSummaryBytes := chanSummaries.Get(chanID[:])
	if chanSummaryBytes == nil {
		return nil, ErrChannelNotRegistered
	}

	var summary ClientChanSummary
	err := summary.Decode(bytes.NewReader(chanSummaryBytes))
	if err != nil {
		return nil, err
	}

	return &summary, nil
}

// putChanSummary stores a ClientChanSummary for the passed chanID.
func putChanSummary(chanSummaries kvdb.RwBucket, chanID lnwire.ChannelID,
	summary *ClientChanSummary) error {

	var b bytes.Buffer
	err := summary.Encode(&b)
	if err != nil {
		return err
	}

	return chanSummaries.Put(chanID[:], b.Bytes())
}

// getTower loads a Tower identified by its serialized tower id.
func getTower(towers kvdb.RBucket, id []byte) (*Tower, error) {
	towerBytes := towers.Get(id)
	if towerBytes == nil {
		return nil, ErrTowerNotFound
	}

	var tower Tower
	err := tower.Decode(bytes.NewReader(towerBytes))
	if err != nil {
		return nil, err
	}

	tower.ID = TowerIDFromBytes(id)

	return &tower, nil
}

// putTower stores a Tower identified by its serialized tower id.
func putTower(towers kvdb.RwBucket, tower *Tower) error {
	var b bytes.Buffer
	err := tower.Encode(&b)
	if err != nil {
		return err
	}

	return towers.Put(tower.ID.Bytes(), b.Bytes())
}
