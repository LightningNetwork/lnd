package wtdb

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/watchtower/blob"
)

var (
	// sessionsBkt is a bucket containing all negotiated client sessions.
	//  session id -> session
	sessionsBkt = []byte("sessions-bucket")

	// updatesBkt is a bucket containing all state updates sent by clients.
	// The updates are further bucketed by session id to prevent clients
	// from overwrite each other.
	//   hint => session id -> update
	updatesBkt = []byte("updates-bucket")

	// updateIndexBkt is a bucket that indexes all state updates by their
	// overarching session id. This allows for efficient lookup of updates
	// by their session id, which is currently used to aide deletion
	// performance.
	//  session id => hint1 -> []byte{}
	//             => hint2 -> []byte{}
	updateIndexBkt = []byte("update-index-bucket")

	// lookoutTipBkt is a bucket containing the last block epoch processed
	// by the lookout subsystem. It has one key, lookoutTipKey.
	//   lookoutTipKey -> block epoch
	lookoutTipBkt = []byte("lookout-tip-bucket")

	// lookoutTipKey is a static key used to retrieve lookout tip's block
	// epoch from the lookoutTipBkt.
	lookoutTipKey = []byte("lookout-tip")

	// ErrNoSessionHintIndex signals that an active session does not have an
	// initialized index for tracking its own state updates.
	ErrNoSessionHintIndex = errors.New("session hint index missing")

	// ErrInvalidBlobSize indicates that the encrypted blob provided by the
	// client is not valid according to the blob type of the session.
	ErrInvalidBlobSize = errors.New("invalid blob size")
)

// TowerDB is single database providing a persistent storage engine for the
// wtserver and lookout subsystems.
type TowerDB struct {
	db kvdb.Backend
}

// OpenTowerDB opens the tower database given the path to the database's
// directory. If no such database exists, this method will initialize a fresh
// one using the latest version number and bucket structure. If a database
// exists but has a lower version number than the current version, any necessary
// migrations will be applied before returning. Any attempt to open a database
// with a version number higher that the latest version will fail to prevent
// accidental reversion.
func OpenTowerDB(db kvdb.Backend) (*TowerDB, error) {
	firstInit, err := isFirstInit(db)
	if err != nil {
		return nil, err
	}

	towerDB := &TowerDB{
		db: db,
	}

	err = initOrSyncVersions(towerDB, firstInit, towerDBVersions)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Now that the database version fully consistent with our latest known
	// version, ensure that all top-level buckets known to this version are
	// initialized. This allows us to assume their presence throughout all
	// operations. If an known top-level bucket is expected to exist but is
	// missing, this will trigger a ErrUninitializedDB error.
	err = kvdb.Update(towerDB.db, initTowerDBBuckets, func() {})
	if err != nil {
		db.Close()
		return nil, err
	}

	return towerDB, nil
}

// initTowerDBBuckets creates all top-level buckets required to handle database
// operations required by the latest version.
func initTowerDBBuckets(tx kvdb.RwTx) error {
	buckets := [][]byte{
		sessionsBkt,
		updateIndexBkt,
		updatesBkt,
		lookoutTipBkt,
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
func (t *TowerDB) bdb() kvdb.Backend {
	return t.db
}

// Version returns the database's current version number.
//
// NOTE: Part of the versionedDB interface.
func (t *TowerDB) Version() (uint32, error) {
	var version uint32
	err := kvdb.View(t.db, func(tx kvdb.RTx) error {
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
func (t *TowerDB) Close() error {
	return t.db.Close()
}

// GetSessionInfo retrieves the session for the passed session id. An error is
// returned if the session could not be found.
func (t *TowerDB) GetSessionInfo(id *SessionID) (*SessionInfo, error) {
	var session *SessionInfo
	err := kvdb.View(t.db, func(tx kvdb.RTx) error {
		sessions := tx.ReadBucket(sessionsBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		var err error
		session, err = getSession(sessions, id[:])
		return err
	}, func() {
		session = nil
	})
	if err != nil {
		return nil, err
	}

	return session, nil
}

// InsertSessionInfo records a negotiated session in the tower database. An
// error is returned if the session already exists.
func (t *TowerDB) InsertSessionInfo(session *SessionInfo) error {
	return kvdb.Update(t.db, func(tx kvdb.RwTx) error {
		sessions := tx.ReadWriteBucket(sessionsBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		updateIndex := tx.ReadWriteBucket(updateIndexBkt)
		if updateIndex == nil {
			return ErrUninitializedDB
		}

		dbSession, err := getSession(sessions, session.ID[:])
		switch {
		case err == ErrSessionNotFound:
			// proceed.

		case err != nil:
			return err

		case dbSession.LastApplied > 0:
			return ErrSessionAlreadyExists
		}

		// Perform a quick sanity check on the session policy before
		// accepting.
		if err := session.Policy.Validate(); err != nil {
			return err
		}

		err = putSession(sessions, session)
		if err != nil {
			return err
		}

		// Initialize the session-hint index which will be used to track
		// all updates added for this session. Upon deletion, we will
		// consult the index to determine exactly which updates should
		// be deleted without needing to iterate over the entire
		// database.
		return touchSessionHintBkt(updateIndex, &session.ID)
	}, func() {})
}

// InsertStateUpdate stores an update sent by the client after validating that
// the update is well-formed in the context of other updates sent for the same
// session. This include verifying that the sequence number is incremented
// properly and the last applied values echoed by the client are sane.
func (t *TowerDB) InsertStateUpdate(update *SessionStateUpdate) (uint16, error) {
	var lastApplied uint16
	err := kvdb.Update(t.db, func(tx kvdb.RwTx) error {
		sessions := tx.ReadWriteBucket(sessionsBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		updates := tx.ReadWriteBucket(updatesBkt)
		if updates == nil {
			return ErrUninitializedDB
		}

		updateIndex := tx.ReadWriteBucket(updateIndexBkt)
		if updateIndex == nil {
			return ErrUninitializedDB
		}

		// Fetch the session corresponding to the update's session id.
		// This will be used to validate that the update's sequence
		// number and last applied values are sane.
		session, err := getSession(sessions, update.ID[:])
		if err != nil {
			return err
		}

		// Assert that the blob is the correct size for the session's
		// blob type.
		expBlobSize := blob.Size(session.Policy.BlobType)
		if len(update.EncryptedBlob) != expBlobSize {
			return ErrInvalidBlobSize
		}

		// Validate the update against the current state of the session.
		err = session.AcceptUpdateSequence(
			update.SeqNum, update.LastApplied,
		)
		if err != nil {
			return err
		}

		// Validation succeeded, therefore the update is committed and
		// the session's last applied value is equal to the update's
		// sequence number.
		lastApplied = session.LastApplied

		// Store the updated session to persist the updated last applied
		// values.
		err = putSession(sessions, session)
		if err != nil {
			return err
		}

		// Create or load the hint bucket for this state update's hint
		// and write the given update.
		hints, err := updates.CreateBucketIfNotExists(update.Hint[:])
		if err != nil {
			return err
		}

		var b bytes.Buffer
		err = update.Encode(&b)
		if err != nil {
			return err
		}

		err = hints.Put(update.ID[:], b.Bytes())
		if err != nil {
			return err
		}

		// Finally, create an entry in the update index to track this
		// hint under its session id. This will allow us to delete the
		// entries efficiently if the session is ever removed.
		return putHintForSession(updateIndex, &update.ID, update.Hint)
	}, func() {
		lastApplied = 0
	})
	if err != nil {
		return 0, err
	}

	return lastApplied, nil
}

// DeleteSession removes all data associated with a particular session id from
// the tower's database.
func (t *TowerDB) DeleteSession(target SessionID) error {
	return kvdb.Update(t.db, func(tx kvdb.RwTx) error {
		sessions := tx.ReadWriteBucket(sessionsBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		updates := tx.ReadWriteBucket(updatesBkt)
		if updates == nil {
			return ErrUninitializedDB
		}

		updateIndex := tx.ReadWriteBucket(updateIndexBkt)
		if updateIndex == nil {
			return ErrUninitializedDB
		}

		// Fail if the session doesn't exit.
		_, err := getSession(sessions, target[:])
		if err != nil {
			return err
		}

		// Remove the target session.
		err = sessions.Delete(target[:])
		if err != nil {
			return err
		}

		// Next, check the update index for any hints that were added
		// under this session.
		hints, err := getHintsForSession(updateIndex, &target)
		if err != nil {
			return err
		}

		for _, hint := range hints {
			// Remove the state updates for any blobs stored under
			// the target session identifier.
			updatesForHint := updates.NestedReadWriteBucket(hint[:])
			if updatesForHint == nil {
				continue
			}

			update := updatesForHint.Get(target[:])
			if update == nil {
				continue
			}

			err := updatesForHint.Delete(target[:])
			if err != nil {
				return err
			}

			// If this was the last state update, we can also remove
			// the hint that would map to an empty set.
			err = isBucketEmpty(updatesForHint)
			switch {

			// Other updates exist for this hint, keep the bucket.
			case err == errBucketNotEmpty:
				continue

			// Unexpected error.
			case err != nil:
				return err

			// No more updates for this hint, prune hint bucket.
			default:
				err = updates.DeleteNestedBucket(hint[:])
				if err != nil {
					return err
				}
			}
		}

		// Finally, remove this session from the update index, which
		// also removes any of the indexed hints beneath it.
		return removeSessionHintBkt(updateIndex, &target)
	}, func() {})
}

// QueryMatches searches against all known state updates for any that match the
// passed breachHints. More than one Match will be returned for a given hint if
// they exist in the database.
func (t *TowerDB) QueryMatches(breachHints []blob.BreachHint) ([]Match, error) {
	var matches []Match
	err := kvdb.View(t.db, func(tx kvdb.RTx) error {
		sessions := tx.ReadBucket(sessionsBkt)
		if sessions == nil {
			return ErrUninitializedDB
		}

		updates := tx.ReadBucket(updatesBkt)
		if updates == nil {
			return ErrUninitializedDB
		}

		// Iterate through the target breach hints, appending any
		// matching updates to the set of matches.
		for _, hint := range breachHints {
			// If a bucket does not exist for this hint, no matches
			// are known.
			updatesForHint := updates.NestedReadBucket(hint[:])
			if updatesForHint == nil {
				continue
			}

			// Otherwise, iterate through all (session id, update)
			// pairs, creating a Match for each.
			err := updatesForHint.ForEach(func(k, v []byte) error {
				// Load the session via the session id for this
				// update. The session info contains further
				// instructions for how to process the state
				// update.
				session, err := getSession(sessions, k)
				switch {
				case err == ErrSessionNotFound:
					log.Warnf("Missing session=%x for "+
						"matched state update hint=%x",
						k, hint)
					return nil

				case err != nil:
					return err
				}

				// Decode the state update containing the
				// encrypted blob.
				update := &SessionStateUpdate{}
				err = update.Decode(bytes.NewReader(v))
				if err != nil {
					return err
				}

				var id SessionID
				copy(id[:], k)

				// Construct the final match using the found
				// update and its session info.
				match := Match{
					ID:            id,
					SeqNum:        update.SeqNum,
					Hint:          hint,
					EncryptedBlob: update.EncryptedBlob,
					SessionInfo:   session,
				}

				matches = append(matches, match)

				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {
		matches = nil
	})
	if err != nil {
		return nil, err
	}

	return matches, nil
}

// SetLookoutTip stores the provided epoch as the latest lookout tip epoch in
// the tower database.
func (t *TowerDB) SetLookoutTip(epoch *chainntnfs.BlockEpoch) error {
	return kvdb.Update(t.db, func(tx kvdb.RwTx) error {
		lookoutTip := tx.ReadWriteBucket(lookoutTipBkt)
		if lookoutTip == nil {
			return ErrUninitializedDB
		}

		return putLookoutEpoch(lookoutTip, epoch)
	}, func() {})
}

// GetLookoutTip retrieves the current lookout tip block epoch from the tower
// database.
func (t *TowerDB) GetLookoutTip() (*chainntnfs.BlockEpoch, error) {
	var epoch *chainntnfs.BlockEpoch
	err := kvdb.View(t.db, func(tx kvdb.RTx) error {
		lookoutTip := tx.ReadBucket(lookoutTipBkt)
		if lookoutTip == nil {
			return ErrUninitializedDB
		}

		epoch = getLookoutEpoch(lookoutTip)

		return nil
	}, func() {
		epoch = nil
	})
	if err != nil {
		return nil, err
	}

	return epoch, nil
}

// getSession retrieves the session info from the sessions bucket identified by
// its session id. An error is returned if the session is not found or a
// deserialization error occurs.
func getSession(sessions kvdb.RBucket, id []byte) (*SessionInfo, error) {
	sessionBytes := sessions.Get(id)
	if sessionBytes == nil {
		return nil, ErrSessionNotFound
	}

	var session SessionInfo
	err := session.Decode(bytes.NewReader(sessionBytes))
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// putSession stores the session info in the sessions bucket identified by its
// session id. An error is returned if a serialization error occurs.
func putSession(sessions kvdb.RwBucket, session *SessionInfo) error {
	var b bytes.Buffer
	err := session.Encode(&b)
	if err != nil {
		return err
	}

	return sessions.Put(session.ID[:], b.Bytes())
}

// touchSessionHintBkt initializes the session-hint bucket for a particular
// session id. This ensures that future calls to getHintsForSession or
// putHintForSession can rely on the bucket already being created, and fail if
// index has not been initialized as this points to improper usage.
func touchSessionHintBkt(updateIndex kvdb.RwBucket, id *SessionID) error {
	_, err := updateIndex.CreateBucketIfNotExists(id[:])
	return err
}

// removeSessionHintBkt prunes the session-hint bucket for the given session id
// and all of the hints contained inside. This should be used to clean up the
// index upon session deletion.
func removeSessionHintBkt(updateIndex kvdb.RwBucket, id *SessionID) error {
	return updateIndex.DeleteNestedBucket(id[:])
}

// getHintsForSession returns all known hints belonging to the given session id.
// If the index for the session has not been initialized, this method returns
// ErrNoSessionHintIndex.
func getHintsForSession(updateIndex kvdb.RBucket,
	id *SessionID) ([]blob.BreachHint, error) {

	sessionHints := updateIndex.NestedReadBucket(id[:])
	if sessionHints == nil {
		return nil, ErrNoSessionHintIndex
	}

	var hints []blob.BreachHint
	err := sessionHints.ForEach(func(k, _ []byte) error {
		if len(k) != blob.BreachHintSize {
			return nil
		}

		var hint blob.BreachHint
		copy(hint[:], k)
		hints = append(hints, hint)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return hints, nil
}

// putHintForSession inserts a record into the update index for a given
// (session, hint) pair. The hints are coalesced under a bucket for the target
// session id, and used to perform efficient removal of updates. If the index
// for the session has not been initialized, this method returns
// ErrNoSessionHintIndex.
func putHintForSession(updateIndex kvdb.RwBucket, id *SessionID,
	hint blob.BreachHint) error {

	sessionHints := updateIndex.NestedReadWriteBucket(id[:])
	if sessionHints == nil {
		return ErrNoSessionHintIndex
	}

	return sessionHints.Put(hint[:], []byte{})
}

// putLookoutEpoch stores the given lookout tip block epoch in provided bucket.
func putLookoutEpoch(bkt kvdb.RwBucket, epoch *chainntnfs.BlockEpoch) error {
	epochBytes := make([]byte, 36)
	copy(epochBytes, epoch.Hash[:])
	byteOrder.PutUint32(epochBytes[32:], uint32(epoch.Height))

	return bkt.Put(lookoutTipKey, epochBytes)
}

// getLookoutEpoch retrieves the lookout tip block epoch from the given bucket.
// A nil epoch is returned if no update exists.
func getLookoutEpoch(bkt kvdb.RBucket) *chainntnfs.BlockEpoch {
	epochBytes := bkt.Get(lookoutTipKey)
	if len(epochBytes) != 36 {
		return nil
	}

	var hash chainhash.Hash
	copy(hash[:], epochBytes[:32])
	height := byteOrder.Uint32(epochBytes[32:])

	return &chainntnfs.BlockEpoch{
		Hash:   &hash,
		Height: int32(height),
	}
}

// errBucketNotEmpty is a helper error returned when testing whether a bucket is
// empty or not.
var errBucketNotEmpty = errors.New("bucket not empty")

// isBucketEmpty returns errBucketNotEmpty if the bucket is not empty.
func isBucketEmpty(bkt kvdb.RBucket) error {
	return bkt.ForEach(func(_, _ []byte) error {
		return errBucketNotEmpty
	})
}
