package wtdb_test

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/watchtower"
	"github.com/lightningnetwork/lnd/watchtower/blob"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtmock"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
)

var (
	testBlob = make([]byte, blob.Size(blob.TypeAltruistCommit))
)

// dbInit is a closure used to initialize a watchtower.DB instance and its
// cleanup function.
type dbInit func(*testing.T) (watchtower.DB, func())

// towerDBHarness holds the resources required to execute the tower db tests.
type towerDBHarness struct {
	t  *testing.T
	db watchtower.DB
}

// newTowerDBHarness initializes a fresh test harness for testing watchtower.DB
// implementations.
func newTowerDBHarness(t *testing.T, init dbInit) (*towerDBHarness, func()) {
	db, cleanup := init(t)

	h := &towerDBHarness{
		t:  t,
		db: db,
	}

	return h, cleanup
}

// insertSession attempts to isnert the passed session and asserts that the
// error returned matches expErr.
func (h *towerDBHarness) insertSession(s *wtdb.SessionInfo, expErr error) {
	h.t.Helper()

	err := h.db.InsertSessionInfo(s)
	if err != expErr {
		h.t.Fatalf("expected insert session error: %v, got : %v",
			expErr, err)
	}
}

// getSession retrieves the session identified by id, asserting that the call
// returns expErr. If successful, the found session is returned.
func (h *towerDBHarness) getSession(id *wtdb.SessionID,
	expErr error) *wtdb.SessionInfo {

	h.t.Helper()

	session, err := h.db.GetSessionInfo(id)
	if err != expErr {
		h.t.Fatalf("expected get session error: %v, got: %v",
			expErr, err)
	}

	return session
}

// insertUpdate attempts to insert the passed state update and asserts that the
// error returned matches expErr. If successful, the session's last applied
// value is returned.
func (h *towerDBHarness) insertUpdate(s *wtdb.SessionStateUpdate,
	expErr error) uint16 {

	h.t.Helper()

	lastApplied, err := h.db.InsertStateUpdate(s)
	if err != expErr {
		h.t.Fatalf("expected insert update error: %v, got: %v",
			expErr, err)
	}

	return lastApplied
}

// deleteSession attempts to delete the session identified by id and asserts
// that the error returned from DeleteSession matches the expected error.
func (h *towerDBHarness) deleteSession(id wtdb.SessionID, expErr error) {
	h.t.Helper()

	err := h.db.DeleteSession(id)
	if err != expErr {
		h.t.Fatalf("expected deletion error: %v, got: %v",
			expErr, err)
	}
}

// queryMatches queries that database for the passed breach hint, returning all
// matches found.
func (h *towerDBHarness) queryMatches(hint blob.BreachHint) []wtdb.Match {
	h.t.Helper()

	matches, err := h.db.QueryMatches([]blob.BreachHint{hint})
	if err != nil {
		h.t.Fatalf("unable to query matches: %v", err)
	}

	return matches
}

// hasUpdate queries the database for the passed breach hint, asserting that
// only one match is present and that the hints indeed match. If successful, the
// match is returned.
func (h *towerDBHarness) hasUpdate(hint blob.BreachHint) wtdb.Match {
	h.t.Helper()

	matches := h.queryMatches(hint)
	if len(matches) != 1 {
		h.t.Fatalf("expected 1 match, found: %d", len(matches))
	}

	match := matches[0]
	if match.Hint != hint {
		h.t.Fatalf("expected hint: %x, got: %x", hint, match.Hint)
	}

	return match
}

// testInsertSession asserts that a session can only be inserted if a session
// with the same session id does not already exist.
func testInsertSession(h *towerDBHarness) {
	var id wtdb.SessionID
	h.getSession(&id, wtdb.ErrSessionNotFound)

	session := &wtdb.SessionInfo{
		ID: id,
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType: blob.TypeAltruistCommit,
			},
			MaxUpdates: 100,
		},
		RewardAddress: []byte{0x01, 0x02, 0x03},
	}

	// Try to insert the session, which should fail since the policy doesn't
	// meet the current sanity checks.
	h.insertSession(session, wtpolicy.ErrSweepFeeRateTooLow)

	// Now assign a sane sweep fee rate to the policy, inserting should
	// succeed.
	session.Policy.SweepFeeRate = wtpolicy.DefaultSweepFeeRate
	h.insertSession(session, nil)

	session2 := h.getSession(&id, nil)

	if !reflect.DeepEqual(session, session2) {
		h.t.Fatalf("expected session: %v, got %v",
			session, session2)
	}

	h.insertSession(session, nil)

	// Insert a state update to fully commit the session parameters.
	update := &wtdb.SessionStateUpdate{
		ID:            id,
		SeqNum:        1,
		EncryptedBlob: testBlob,
	}
	h.insertUpdate(update, nil)

	// Trying to insert a new session under the same ID should fail.
	h.insertSession(session, wtdb.ErrSessionAlreadyExists)
}

// testMultipleMatches asserts that if multiple sessions insert state updates
// with the same breach hint that all will be returned from QueryMatches.
func testMultipleMatches(h *towerDBHarness) {
	const numUpdates = 3

	// Create a new session and send updates with all the same hint.
	var hint blob.BreachHint
	for i := 0; i < numUpdates; i++ {
		id := *id(i)
		session := &wtdb.SessionInfo{
			ID: id,
			Policy: wtpolicy.Policy{
				TxPolicy: wtpolicy.TxPolicy{
					BlobType:     blob.TypeAltruistCommit,
					SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
				},
				MaxUpdates: 3,
			},
			RewardAddress: []byte{},
		}
		h.insertSession(session, nil)

		update := &wtdb.SessionStateUpdate{
			ID:            id,
			SeqNum:        1,
			Hint:          hint, // Use same hint to cause multiple matches
			EncryptedBlob: testBlob,
		}
		h.insertUpdate(update, nil)
	}

	// Query the db for matches on the chosen hint.
	matches := h.queryMatches(hint)
	if len(matches) != numUpdates {
		h.t.Fatalf("num updates mismatch, want: %d, got: %d",
			numUpdates, len(matches))
	}

	// Assert that the hints are what we asked for, and compute the set of
	// sessions returned.
	sessions := make(map[wtdb.SessionID]struct{})
	for _, match := range matches {
		if match.Hint != hint {
			h.t.Fatalf("hint mismatch, want: %v, got: %v",
				hint, match.Hint)
		}
		sessions[match.ID] = struct{}{}
	}

	// Assert that the sessions returned match the session ids of the
	// sessions we initially created.
	for i := 0; i < numUpdates; i++ {
		if _, ok := sessions[*id(i)]; !ok {
			h.t.Fatalf("match for session %v not found", *id(i))
		}
	}
}

// testLookoutTip asserts that the database properly stores and returns the
// lookout tip block epochs. It also asserts that the epoch returned is nil when
// no tip has ever been set.
func testLookoutTip(h *towerDBHarness) {
	// Retrieve lookout tip on fresh db.
	epoch, err := h.db.GetLookoutTip()
	if err != nil {
		h.t.Fatalf("unable to fetch lookout tip: %v", err)
	}

	// Assert that the epoch is nil.
	if epoch != nil {
		h.t.Fatalf("lookout tip should not be set, found: %v", epoch)
	}

	// Create a closure that inserts an epoch, retrieves it, and asserts
	// that the returned epoch matches what was inserted.
	setAndCheck := func(i int) {
		expEpoch := epochFromInt(1)
		err = h.db.SetLookoutTip(expEpoch)
		if err != nil {
			h.t.Fatalf("unable to set lookout tip: %v", err)
		}

		epoch, err = h.db.GetLookoutTip()
		if err != nil {
			h.t.Fatalf("unable to fetch lookout tip: %v", err)
		}

		if !reflect.DeepEqual(epoch, expEpoch) {
			h.t.Fatalf("lookout tip mismatch, want: %v, got: %v",
				expEpoch, epoch)
		}
	}

	// Set and assert the lookout tip.
	for i := 0; i < 5; i++ {
		setAndCheck(i)
	}
}

// testDeleteSession asserts the behavior of a tower database when deleting
// session data. The test asserts that the only proper the target session is
// remmoved, and that only updates for a particular session are pruned.
func testDeleteSession(h *towerDBHarness) {
	// First, create a session so that the database is not empty.
	id0 := id(0)
	session0 := &wtdb.SessionInfo{
		ID: *id0,
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	}
	h.insertSession(session0, nil)

	// Now, attempt to delete a session which does not exist, that is also
	// different from the first one created.
	id1 := id(1)
	h.deleteSession(*id1, wtdb.ErrSessionNotFound)

	// The first session should still be present.
	h.getSession(id0, nil)

	// Now insert a second session under a different id.
	session1 := &wtdb.SessionInfo{
		ID: *id1,
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	}
	h.insertSession(session1, nil)

	// Create and insert updates for both sessions that have the same hint.
	var hint blob.BreachHint
	update0 := &wtdb.SessionStateUpdate{
		ID:            *id0,
		Hint:          hint,
		SeqNum:        1,
		EncryptedBlob: testBlob,
	}
	update1 := &wtdb.SessionStateUpdate{
		ID:            *id1,
		Hint:          hint,
		SeqNum:        1,
		EncryptedBlob: testBlob,
	}

	// Insert both updates should succeed.
	h.insertUpdate(update0, nil)
	h.insertUpdate(update1, nil)

	// Remove the new session, which should succeed.
	h.deleteSession(*id1, nil)

	// The first session should still be present.
	h.getSession(id0, nil)

	// The second session should be removed.
	h.getSession(id1, wtdb.ErrSessionNotFound)

	// Assert that only one update is still present.
	matches := h.queryMatches(hint)
	if len(matches) != 1 {
		h.t.Fatalf("expected one update, found: %d", len(matches))
	}

	// Assert that the update belongs to the first session.
	if matches[0].ID != *id0 {
		h.t.Fatalf("expected match for %v, instead is for: %v",
			*id0, matches[0].ID)
	}

	// Finally, remove the first session added.
	h.deleteSession(*id0, nil)

	// The session should no longer be present.
	h.getSession(id0, wtdb.ErrSessionNotFound)

	// No matches should exist for this hint.
	matches = h.queryMatches(hint)
	if len(matches) != 0 {
		h.t.Fatalf("expected zero updates, found: %d", len(matches))
	}
}

type stateUpdateTest struct {
	session    *wtdb.SessionInfo
	sessionErr error
	updates    []*wtdb.SessionStateUpdate
	updateErrs []error
}

func runStateUpdateTest(test stateUpdateTest) func(*towerDBHarness) {
	return func(h *towerDBHarness) {
		// We may need to modify the initial session as we process
		// updates to discern the expected state of the session. We'll
		// create a copy of the test session if necessary to prevent
		// mutations from impacting other tests.
		var expSession *wtdb.SessionInfo

		// Create the session if the tests requests one.
		if test.session != nil {
			// Copy the initial session and insert it into the
			// database.
			ogSession := *test.session
			expErr := test.sessionErr
			h.insertSession(&ogSession, expErr)

			if expErr != nil {
				return
			}

			// Copy the initial state of the accepted session.
			expSession = &wtdb.SessionInfo{}
			*expSession = *test.session
		}

		if len(test.updates) != len(test.updateErrs) {
			h.t.Fatalf("malformed test case, num updates " +
				"should match num errors")
		}

		// Send any updates provided in the test.
		for i, update := range test.updates {
			expErr := test.updateErrs[i]
			h.insertUpdate(update, expErr)

			if expErr != nil {
				continue
			}

			// Don't perform the following checks and modfications
			// if we don't have an expected session to compare
			// against.
			if expSession == nil {
				continue
			}

			// Update the session's last applied and client last
			// applied.
			expSession.LastApplied = update.SeqNum
			expSession.ClientLastApplied = update.LastApplied

			match := h.hasUpdate(update.Hint)
			if !reflect.DeepEqual(match.SessionInfo, expSession) {
				h.t.Fatalf("expected session: %v, got: %v",
					expSession, match.SessionInfo)
			}
		}
	}
}

var stateUpdateNoSession = stateUpdateTest{
	session: nil,
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 1, 0),
	},
	updateErrs: []error{
		wtdb.ErrSessionNotFound,
	},
}

var stateUpdateExhaustSession = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 1, 0),
		updateFromInt(id(0), 2, 0),
		updateFromInt(id(0), 3, 0),
		updateFromInt(id(0), 4, 0),
	},
	updateErrs: []error{
		nil, nil, nil, wtdb.ErrSessionConsumed,
	},
}

var stateUpdateSeqNumEqualLastApplied = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 1, 0),
		updateFromInt(id(0), 2, 1),
		updateFromInt(id(0), 3, 2),
		updateFromInt(id(0), 3, 3),
	},
	updateErrs: []error{
		nil, nil, nil, wtdb.ErrSeqNumAlreadyApplied,
	},
}

var stateUpdateSeqNumLTLastApplied = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 1, 0),
		updateFromInt(id(0), 2, 1),
		updateFromInt(id(0), 1, 2),
	},
	updateErrs: []error{
		nil, nil, wtdb.ErrSeqNumAlreadyApplied,
	},
}

var stateUpdateSeqNumZeroInvalid = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 0, 0),
	},
	updateErrs: []error{
		wtdb.ErrSeqNumAlreadyApplied,
	},
}

var stateUpdateSkipSeqNum = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 2, 0),
	},
	updateErrs: []error{
		wtdb.ErrUpdateOutOfOrder,
	},
}

var stateUpdateRevertSeqNum = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 1, 0),
		updateFromInt(id(0), 2, 0),
		updateFromInt(id(0), 1, 0),
	},
	updateErrs: []error{
		nil, nil, wtdb.ErrUpdateOutOfOrder,
	},
}

var stateUpdateRevertLastApplied = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		updateFromInt(id(0), 1, 0),
		updateFromInt(id(0), 2, 1),
		updateFromInt(id(0), 3, 2),
		updateFromInt(id(0), 4, 1),
	},
	updateErrs: []error{
		nil, nil, nil, wtdb.ErrLastAppliedReversion,
	},
}

var stateUpdateInvalidBlobSize = stateUpdateTest{
	session: &wtdb.SessionInfo{
		ID: *id(0),
		Policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 3,
		},
		RewardAddress: []byte{},
	},
	updates: []*wtdb.SessionStateUpdate{
		{
			ID:            *id(0),
			SeqNum:        1,
			LastApplied:   0,
			EncryptedBlob: []byte{0x01, 0x02, 0x03}, // too $hort
		},
	},
	updateErrs: []error{
		wtdb.ErrInvalidBlobSize,
	},
}

func TestTowerDB(t *testing.T) {
	dbCfg := &kvdb.BoltConfig{DBTimeout: kvdb.DefaultDBTimeout}
	dbs := []struct {
		name string
		init dbInit
	}{
		{
			name: "fresh boltdb",
			init: func(t *testing.T) (watchtower.DB, func()) {
				path, err := ioutil.TempDir("", "towerdb")
				if err != nil {
					t.Fatalf("unable to make temp dir: %v",
						err)
				}

				bdb, err := wtdb.NewBoltBackendCreator(
					true, path, "watchtower.db",
				)(dbCfg)
				if err != nil {
					os.RemoveAll(path)
					t.Fatalf("unable to open db: %v", err)
				}

				db, err := wtdb.OpenTowerDB(bdb)
				if err != nil {
					os.RemoveAll(path)
					t.Fatalf("unable to open db: %v", err)
				}

				cleanup := func() {
					db.Close()
					os.RemoveAll(path)
				}

				return db, cleanup
			},
		},
		{
			name: "reopened boltdb",
			init: func(t *testing.T) (watchtower.DB, func()) {
				path, err := ioutil.TempDir("", "towerdb")
				if err != nil {
					t.Fatalf("unable to make temp dir: %v",
						err)
				}

				bdb, err := wtdb.NewBoltBackendCreator(
					true, path, "watchtower.db",
				)(dbCfg)
				if err != nil {
					os.RemoveAll(path)
					t.Fatalf("unable to open db: %v", err)
				}

				db, err := wtdb.OpenTowerDB(bdb)
				if err != nil {
					os.RemoveAll(path)
					t.Fatalf("unable to open db: %v", err)
				}
				db.Close()

				// Open the db again, ensuring we test a
				// different path during open and that all
				// buckets remain initialized.
				bdb, err = wtdb.NewBoltBackendCreator(
					true, path, "watchtower.db",
				)(dbCfg)
				if err != nil {
					os.RemoveAll(path)
					t.Fatalf("unable to open db: %v", err)
				}

				db, err = wtdb.OpenTowerDB(bdb)
				if err != nil {
					os.RemoveAll(path)
					t.Fatalf("unable to open db: %v", err)
				}

				cleanup := func() {
					db.Close()
					os.RemoveAll(path)
				}

				return db, cleanup
			},
		},
		{
			name: "mock",
			init: func(t *testing.T) (watchtower.DB, func()) {
				return wtmock.NewTowerDB(), func() {}
			},
		},
	}

	tests := []struct {
		name string
		run  func(*towerDBHarness)
	}{
		{
			name: "create session",
			run:  testInsertSession,
		},
		{
			name: "delete session",
			run:  testDeleteSession,
		},
		{
			name: "state update no session",
			run:  runStateUpdateTest(stateUpdateNoSession),
		},
		{
			name: "state update exhaust session",
			run:  runStateUpdateTest(stateUpdateExhaustSession),
		},
		{
			name: "state update seqnum equal last applied",
			run: runStateUpdateTest(
				stateUpdateSeqNumEqualLastApplied,
			),
		},
		{
			name: "state update seqnum less than last applied",
			run: runStateUpdateTest(
				stateUpdateSeqNumLTLastApplied,
			),
		},
		{
			name: "state update seqnum zero invalid",
			run:  runStateUpdateTest(stateUpdateSeqNumZeroInvalid),
		},
		{
			name: "state update skip seqnum",
			run:  runStateUpdateTest(stateUpdateSkipSeqNum),
		},
		{
			name: "state update revert seqnum",
			run:  runStateUpdateTest(stateUpdateRevertSeqNum),
		},
		{
			name: "state update revert last applied",
			run:  runStateUpdateTest(stateUpdateRevertLastApplied),
		},
		{
			name: "invalid blob size",
			run:  runStateUpdateTest(stateUpdateInvalidBlobSize),
		},
		{
			name: "multiple breach matches",
			run:  testMultipleMatches,
		},
		{
			name: "lookout tip",
			run:  testLookoutTip,
		},
	}

	for _, database := range dbs {
		db := database
		t.Run(db.name, func(t *testing.T) {
			t.Parallel()

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					h, cleanup := newTowerDBHarness(
						t, db.init,
					)
					defer cleanup()

					test.run(h)
				})
			}
		})
	}
}

// id creates a session id from an integer.
func id(i int) *wtdb.SessionID {
	var id wtdb.SessionID
	binary.BigEndian.PutUint32(id[:4], uint32(i))
	return &id
}

// updateFromInt creates a unique update for a given (session, seqnum) pair. The
// lastApplied argument can be used to construct updates simulating different
// levels of synchronicity between client and db.
func updateFromInt(id *wtdb.SessionID, i int,
	lastApplied uint16) *wtdb.SessionStateUpdate {

	// Ensure the hint is unique.
	var hint blob.BreachHint
	copy(hint[:4], id[:4])
	binary.BigEndian.PutUint16(hint[4:6], uint16(i))

	blobSize := blob.Size(blob.TypeAltruistCommit)

	return &wtdb.SessionStateUpdate{
		ID:            *id,
		Hint:          hint,
		SeqNum:        uint16(i),
		LastApplied:   lastApplied,
		EncryptedBlob: bytes.Repeat([]byte{byte(i)}, blobSize),
	}
}

// epochFromInt creates a block epoch from an integer.
func epochFromInt(i int) *chainntnfs.BlockEpoch {
	var hash chainhash.Hash
	binary.BigEndian.PutUint32(hash[:4], uint32(i))

	return &chainntnfs.BlockEpoch{
		Hash:   &hash,
		Height: int32(i),
	}
}
