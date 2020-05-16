package contractcourt

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	prand "math/rand"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"go.etcd.io/bbolt"
)

var (
	testChainHash = [chainhash.HashSize]byte{
		0x51, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x48, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0x2d, 0xe7, 0x93, 0xe4,
	}

	testChanPoint1 = wire.OutPoint{
		Hash: chainhash.Hash{
			0x51, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
			0x48, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
			0x2d, 0xe7, 0x93, 0xe4,
		},
		Index: 1,
	}

	testChanPoint2 = wire.OutPoint{
		Hash: chainhash.Hash{
			0x48, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
			0x51, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
			0x2d, 0xe7, 0x93, 0xe4,
		},
		Index: 2,
	}

	testChanPoint3 = wire.OutPoint{
		Hash: chainhash.Hash{
			0x48, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
			0x51, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
			0x2d, 0xe7, 0x93, 0xe4,
		},
		Index: 3,
	}

	testPreimage = [32]byte{
		0x52, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x48, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0x2d, 0xe7, 0x93, 0xe4,
	}

	key1 = []byte{
		0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
		0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
		0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
		0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
		0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
		0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
		0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
		0xb4, 0x12, 0xa3,
	}

	testSignDesc = input.SignDescriptor{
		SingleTweak: []byte{
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02,
		},
		WitnessScript: []byte{
			0x00, 0x14, 0xee, 0x91, 0x41, 0x7e, 0x85, 0x6c, 0xde,
			0x10, 0xa2, 0x91, 0x1e, 0xdc, 0xbd, 0xbd, 0x69, 0xe2,
			0xef, 0xb5, 0x71, 0x48,
		},
		Output: &wire.TxOut{
			Value: 5000000000,
			PkScript: []byte{
				0x41, // OP_DATA_65
				0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
				0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
				0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
				0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
				0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
				0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
				0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
				0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
				0xa6, // 65-byte signature
				0xac, // OP_CHECKSIG
			},
		},
		HashType: txscript.SigHashAll,
	}
)

func makeTestDB() (kvdb.Backend, func(), error) {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName, err := ioutil.TempDir("", "arblog")
	if err != nil {
		return nil, nil, err
	}

	bboltOpts := &bbolt.Options{
		NoFreelistSync: true,
	}
	db, err := kvdb.Create(
		kvdb.BoltBackendName, tempDirName+"/test.db", bboltOpts,
	)
	if err != nil {
		return nil, nil, err
	}

	cleanUp := func() {
		db.Close()
		os.RemoveAll(tempDirName)
	}

	return db, cleanUp, nil
}

func newTestBoltArbLog(chainhash chainhash.Hash,
	op wire.OutPoint) (ArbitratorLog, func(), error) {

	testDB, cleanUp, err := makeTestDB()
	if err != nil {
		return nil, nil, err
	}

	testArbCfg := ChannelArbitratorConfig{}
	testLog, err := newBoltArbitratorLog(testDB, testArbCfg, chainhash, op)
	if err != nil {
		return nil, nil, err
	}

	return testLog, cleanUp, err
}

func randOutPoint() wire.OutPoint {
	var op wire.OutPoint
	rand.Read(op.Hash[:])
	op.Index = prand.Uint32()

	return op
}

func assertResolversEqual(t *testing.T, originalResolver ContractResolver,
	diskResolver ContractResolver) {

	assertTimeoutResEqual := func(ogRes, diskRes *htlcTimeoutResolver) {
		if !reflect.DeepEqual(ogRes.htlcResolution, diskRes.htlcResolution) {
			t.Fatalf("resolution mismatch: expected %#v, got %v#",
				ogRes.htlcResolution, diskRes.htlcResolution)
		}
		if ogRes.outputIncubating != diskRes.outputIncubating {
			t.Fatalf("expected %v, got %v",
				ogRes.outputIncubating, diskRes.outputIncubating)
		}
		if ogRes.resolved != diskRes.resolved {
			t.Fatalf("expected %v, got %v", ogRes.resolved,
				diskRes.resolved)
		}
		if ogRes.broadcastHeight != diskRes.broadcastHeight {
			t.Fatalf("expected %v, got %v",
				ogRes.broadcastHeight, diskRes.broadcastHeight)
		}
		if ogRes.htlc.HtlcIndex != diskRes.htlc.HtlcIndex {
			t.Fatalf("expected %v, got %v", ogRes.htlc.HtlcIndex,
				diskRes.htlc.HtlcIndex)
		}
	}

	assertSuccessResEqual := func(ogRes, diskRes *htlcSuccessResolver) {
		if !reflect.DeepEqual(ogRes.htlcResolution, diskRes.htlcResolution) {
			t.Fatalf("resolution mismatch: expected %#v, got %v#",
				ogRes.htlcResolution, diskRes.htlcResolution)
		}
		if ogRes.outputIncubating != diskRes.outputIncubating {
			t.Fatalf("expected %v, got %v",
				ogRes.outputIncubating, diskRes.outputIncubating)
		}
		if ogRes.resolved != diskRes.resolved {
			t.Fatalf("expected %v, got %v", ogRes.resolved,
				diskRes.resolved)
		}
		if ogRes.broadcastHeight != diskRes.broadcastHeight {
			t.Fatalf("expected %v, got %v",
				ogRes.broadcastHeight, diskRes.broadcastHeight)
		}
		if ogRes.htlc.RHash != diskRes.htlc.RHash {
			t.Fatalf("expected %v, got %v", ogRes.htlc.RHash,
				diskRes.htlc.RHash)
		}
	}

	switch ogRes := originalResolver.(type) {
	case *htlcTimeoutResolver:
		diskRes := diskResolver.(*htlcTimeoutResolver)
		assertTimeoutResEqual(ogRes, diskRes)

	case *htlcSuccessResolver:
		diskRes := diskResolver.(*htlcSuccessResolver)
		assertSuccessResEqual(ogRes, diskRes)

	case *htlcOutgoingContestResolver:
		diskRes := diskResolver.(*htlcOutgoingContestResolver)
		assertTimeoutResEqual(
			&ogRes.htlcTimeoutResolver, &diskRes.htlcTimeoutResolver,
		)

	case *htlcIncomingContestResolver:
		diskRes := diskResolver.(*htlcIncomingContestResolver)
		assertSuccessResEqual(
			&ogRes.htlcSuccessResolver, &diskRes.htlcSuccessResolver,
		)

		if ogRes.htlcExpiry != diskRes.htlcExpiry {
			t.Fatalf("expected %v, got %v", ogRes.htlcExpiry,
				diskRes.htlcExpiry)
		}

	case *commitSweepResolver:
		diskRes := diskResolver.(*commitSweepResolver)
		if !reflect.DeepEqual(ogRes.commitResolution, diskRes.commitResolution) {
			t.Fatalf("resolution mismatch: expected %v, got %v",
				ogRes.commitResolution, diskRes.commitResolution)
		}
		if ogRes.resolved != diskRes.resolved {
			t.Fatalf("expected %v, got %v", ogRes.resolved,
				diskRes.resolved)
		}
		if ogRes.broadcastHeight != diskRes.broadcastHeight {
			t.Fatalf("expected %v, got %v",
				ogRes.broadcastHeight, diskRes.broadcastHeight)
		}
		if ogRes.chanPoint != diskRes.chanPoint {
			t.Fatalf("expected %v, got %v", ogRes.chanPoint,
				diskRes.chanPoint)
		}
	}
}

// TestContractInsertionRetrieval tests that were able to insert a set of
// unresolved contracts into the log, and retrieve the same set properly.
func TestContractInsertionRetrieval(t *testing.T) {
	t.Parallel()

	// First, we'll create a test instance of the ArbitratorLog
	// implementation backed by boltdb.
	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp()

	// The log created, we'll create a series of resolvers, each properly
	// implementing the ContractResolver interface.
	timeoutResolver := htlcTimeoutResolver{
		htlcResolution: lnwallet.OutgoingHtlcResolution{
			Expiry:          99,
			SignedTimeoutTx: nil,
			CsvDelay:        99,
			ClaimOutpoint:   randOutPoint(),
			SweepSignDesc:   testSignDesc,
		},
		outputIncubating: true,
		resolved:         true,
		broadcastHeight:  102,
		htlc: channeldb.HTLC{
			HtlcIndex: 12,
		},
	}
	successResolver := htlcSuccessResolver{
		htlcResolution: lnwallet.IncomingHtlcResolution{
			Preimage:        testPreimage,
			SignedSuccessTx: nil,
			CsvDelay:        900,
			ClaimOutpoint:   randOutPoint(),
			SweepSignDesc:   testSignDesc,
		},
		outputIncubating: true,
		resolved:         true,
		broadcastHeight:  109,
		htlc: channeldb.HTLC{
			RHash: testPreimage,
		},
		sweepTx: nil,
	}
	resolvers := []ContractResolver{
		&timeoutResolver,
		&successResolver,
		&commitSweepResolver{
			commitResolution: lnwallet.CommitOutputResolution{
				SelfOutPoint:       testChanPoint2,
				SelfOutputSignDesc: testSignDesc,
				MaturityDelay:      99,
			},
			resolved:        false,
			broadcastHeight: 109,
			chanPoint:       testChanPoint1,
		},
	}

	// All resolvers require a unique ResolverKey() output. To achieve this
	// for the composite resolvers, we'll mutate the underlying resolver
	// with a new outpoint.
	contestTimeout := timeoutResolver
	contestTimeout.htlcResolution.ClaimOutpoint = randOutPoint()
	resolvers = append(resolvers, &htlcOutgoingContestResolver{
		htlcTimeoutResolver: contestTimeout,
	})
	contestSuccess := successResolver
	contestSuccess.htlcResolution.ClaimOutpoint = randOutPoint()
	resolvers = append(resolvers, &htlcIncomingContestResolver{
		htlcExpiry:          100,
		htlcSuccessResolver: contestSuccess,
	})

	// For quick lookup during the test, we'll create this map which allow
	// us to lookup a resolver according to its unique resolver key.
	resolverMap := make(map[string]ContractResolver)
	resolverMap[string(timeoutResolver.ResolverKey())] = resolvers[0]
	resolverMap[string(successResolver.ResolverKey())] = resolvers[1]
	resolverMap[string(resolvers[2].ResolverKey())] = resolvers[2]
	resolverMap[string(resolvers[3].ResolverKey())] = resolvers[3]
	resolverMap[string(resolvers[4].ResolverKey())] = resolvers[4]

	// Now, we'll insert the resolver into the log.
	if err := testLog.InsertUnresolvedContracts(resolvers...); err != nil {
		t.Fatalf("unable to insert resolvers: %v", err)
	}

	// With the resolvers inserted, we'll now attempt to retrieve them from
	// the database, so we can compare them to the versions we created
	// above.
	diskResolvers, err := testLog.FetchUnresolvedContracts()
	if err != nil {
		t.Fatalf("unable to retrieve resolvers: %v", err)
	}

	if len(diskResolvers) != len(resolvers) {
		t.Fatalf("expected %v got resolvers, instead got %v: %#v",
			len(resolvers), len(diskResolvers),
			diskResolvers)
	}

	// Now we'll run through each of the resolvers, and ensure that it maps
	// to a resolver perfectly that we inserted previously.
	for _, diskResolver := range diskResolvers {
		resKey := string(diskResolver.ResolverKey())
		originalResolver, ok := resolverMap[resKey]
		if !ok {
			t.Fatalf("unable to find resolver match for %T: %v",
				diskResolver, resKey)
		}

		assertResolversEqual(t, originalResolver, diskResolver)
	}

	// We'll now delete the state, then attempt to retrieve the set of
	// resolvers, no resolvers should be found.
	if err := testLog.WipeHistory(); err != nil {
		t.Fatalf("unable to wipe log: %v", err)
	}
	diskResolvers, err = testLog.FetchUnresolvedContracts()
	if err != nil {
		t.Fatalf("unable to fetch unresolved contracts: %v", err)
	}
	if len(diskResolvers) != 0 {
		t.Fatalf("no resolvers should be found, instead %v were",
			len(diskResolvers))
	}
}

// TestContractResolution tests that once we mark a contract as resolved, it's
// properly removed from the database.
func TestContractResolution(t *testing.T) {
	t.Parallel()

	// First, we'll create a test instance of the ArbitratorLog
	// implementation backed by boltdb.
	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp()

	// We'll now create a timeout resolver that we'll be using for the
	// duration of this test.
	timeoutResolver := &htlcTimeoutResolver{
		htlcResolution: lnwallet.OutgoingHtlcResolution{
			Expiry:          991,
			SignedTimeoutTx: nil,
			CsvDelay:        992,
			ClaimOutpoint:   randOutPoint(),
			SweepSignDesc:   testSignDesc,
		},
		outputIncubating: true,
		resolved:         true,
		broadcastHeight:  192,
		htlc: channeldb.HTLC{
			HtlcIndex: 9912,
		},
	}

	// First, we'll insert the resolver into the database and ensure that
	// we get the same resolver out the other side.
	err = testLog.InsertUnresolvedContracts(timeoutResolver)
	if err != nil {
		t.Fatalf("unable to insert contract into db: %v", err)
	}
	dbContracts, err := testLog.FetchUnresolvedContracts()
	if err != nil {
		t.Fatalf("unable to fetch contracts from db: %v", err)
	}
	assertResolversEqual(t, timeoutResolver, dbContracts[0])

	// Now, we'll mark the contract as resolved within the database.
	if err := testLog.ResolveContract(timeoutResolver); err != nil {
		t.Fatalf("unable to resolve contract: %v", err)
	}

	// At this point, no contracts should exist within the log.
	dbContracts, err = testLog.FetchUnresolvedContracts()
	if err != nil {
		t.Fatalf("unable to fetch contracts from db: %v", err)
	}
	if len(dbContracts) != 0 {
		t.Fatalf("no contract should be from in the db, instead %v "+
			"were", len(dbContracts))
	}
}

// TestContractSwapping ensures that callers are able to atomically swap to
// distinct contracts for one another.
func TestContractSwapping(t *testing.T) {
	t.Parallel()

	// First, we'll create a test instance of the ArbitratorLog
	// implementation backed by boltdb.
	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp()

	// We'll create two resolvers, a regular timeout resolver, and the
	// contest resolver that eventually turns into the timeout resolver.
	timeoutResolver := htlcTimeoutResolver{
		htlcResolution: lnwallet.OutgoingHtlcResolution{
			Expiry:          99,
			SignedTimeoutTx: nil,
			CsvDelay:        99,
			ClaimOutpoint:   randOutPoint(),
			SweepSignDesc:   testSignDesc,
		},
		outputIncubating: true,
		resolved:         true,
		broadcastHeight:  102,
		htlc: channeldb.HTLC{
			HtlcIndex: 12,
		},
	}
	contestResolver := &htlcOutgoingContestResolver{
		htlcTimeoutResolver: timeoutResolver,
	}

	// We'll first insert the contest resolver into the log.
	err = testLog.InsertUnresolvedContracts(contestResolver)
	if err != nil {
		t.Fatalf("unable to insert contract into db: %v", err)
	}

	// With the resolver inserted, we'll now attempt to atomically swap it
	// for its underlying timeout resolver.
	err = testLog.SwapContract(contestResolver, &timeoutResolver)
	if err != nil {
		t.Fatalf("unable to swap contracts: %v", err)
	}

	// At this point, there should now only be a single contract in the
	// database.
	dbContracts, err := testLog.FetchUnresolvedContracts()
	if err != nil {
		t.Fatalf("unable to fetch contracts from db: %v", err)
	}
	if len(dbContracts) != 1 {
		t.Fatalf("one contract should be from in the db, instead %v "+
			"were", len(dbContracts))
	}

	// That single contract should be the underlying timeout resolver.
	assertResolversEqual(t, &timeoutResolver, dbContracts[0])
}

// TestContractResolutionsStorage tests that we're able to properly store and
// retrieve contract resolutions written to disk.
func TestContractResolutionsStorage(t *testing.T) {
	t.Parallel()

	// First, we'll create a test instance of the ArbitratorLog
	// implementation backed by boltdb.
	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp()

	// With the test log created, we'll now craft a contact resolution that
	// will be using for the duration of this test.
	res := ContractResolutions{
		CommitHash: testChainHash,
		CommitResolution: &lnwallet.CommitOutputResolution{
			SelfOutPoint:       testChanPoint2,
			SelfOutputSignDesc: testSignDesc,
			MaturityDelay:      101,
		},
		HtlcResolutions: lnwallet.HtlcResolutions{
			IncomingHTLCs: []lnwallet.IncomingHtlcResolution{
				{
					Preimage:        testPreimage,
					SignedSuccessTx: nil,
					CsvDelay:        900,
					ClaimOutpoint:   randOutPoint(),
					SweepSignDesc:   testSignDesc,
				},
			},
			OutgoingHTLCs: []lnwallet.OutgoingHtlcResolution{
				{
					Expiry:          103,
					SignedTimeoutTx: nil,
					CsvDelay:        923923,
					ClaimOutpoint:   randOutPoint(),
					SweepSignDesc:   testSignDesc,
				},
			},
		},
		AnchorResolution: &lnwallet.AnchorResolution{
			CommitAnchor:         testChanPoint3,
			AnchorSignDescriptor: testSignDesc,
		},
	}

	// First make sure that fetching unlogged contract resolutions will
	// fail.
	_, err = testLog.FetchContractResolutions()
	if err == nil {
		t.Fatalf("expected reading unlogged resolution from db to fail")
	}

	// Insert the resolution into the database, then immediately retrieve
	// them so we can compare equality against the original version.
	if err := testLog.LogContractResolutions(&res); err != nil {
		t.Fatalf("unable to insert resolutions into db: %v", err)
	}
	diskRes, err := testLog.FetchContractResolutions()
	if err != nil {
		t.Fatalf("unable to read resolution from db: %v", err)
	}

	if !reflect.DeepEqual(&res, diskRes) {
		t.Fatalf("resolution mismatch: expected %#v\n, got %#v",
			&res, diskRes)
	}

	// We'll now delete the state, then attempt to retrieve the set of
	// resolvers, no resolutions should be found.
	if err := testLog.WipeHistory(); err != nil {
		t.Fatalf("unable to wipe log: %v", err)
	}
	_, err = testLog.FetchContractResolutions()
	if err != errScopeBucketNoExist {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStateMutation tests that we're able to properly mutate the state of the
// log, then retrieve that same mutated state from disk.
func TestStateMutation(t *testing.T) {
	t.Parallel()

	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp()

	// The default state of an arbitrator should be StateDefault.
	arbState, err := testLog.CurrentState()
	if err != nil {
		t.Fatalf("unable to read arb state: %v", err)
	}
	if arbState != StateDefault {
		t.Fatalf("state mismatch: expected %v, got %v", StateDefault,
			arbState)
	}

	// We should now be able to mutate the state to an arbitrary one of our
	// choosing, then read that same state back from disk.
	if err := testLog.CommitState(StateFullyResolved); err != nil {
		t.Fatalf("unable to write state: %v", err)
	}
	arbState, err = testLog.CurrentState()
	if err != nil {
		t.Fatalf("unable to read arb state: %v", err)
	}
	if arbState != StateFullyResolved {
		t.Fatalf("state mismatch: expected %v, got %v", StateFullyResolved,
			arbState)
	}

	// Next, we'll wipe our state and ensure that if we try to query for
	// the current state, we get the proper error.
	err = testLog.WipeHistory()
	if err != nil {
		t.Fatalf("unable to wipe history: %v", err)
	}

	// If we try to query for the state again, we should get the default
	// state again.
	arbState, err = testLog.CurrentState()
	if err != nil {
		t.Fatalf("unable to query current state: %v", err)
	}
	if arbState != StateDefault {
		t.Fatalf("state mismatch: expected %v, got %v", StateDefault,
			arbState)
	}
}

// TestScopeIsolation tests the two distinct ArbitratorLog instances with two
// distinct scopes, don't over write the state of one another.
func TestScopeIsolation(t *testing.T) {
	t.Parallel()

	// We'll create two distinct test logs. Each log will have a unique
	// scope key, and therefore should be isolated from the other on disk.
	testLog1, cleanUp1, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp1()

	testLog2, cleanUp2, err := newTestBoltArbLog(
		testChainHash, testChanPoint2,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp2()

	// We'll now update the current state of both the logs to a unique
	// state.
	if err := testLog1.CommitState(StateWaitingFullResolution); err != nil {
		t.Fatalf("unable to write state: %v", err)
	}
	if err := testLog2.CommitState(StateContractClosed); err != nil {
		t.Fatalf("unable to write state: %v", err)
	}

	// Querying each log, the states should be the prior one we set, and be
	// disjoint.
	log1State, err := testLog1.CurrentState()
	if err != nil {
		t.Fatalf("unable to read arb state: %v", err)
	}
	log2State, err := testLog2.CurrentState()
	if err != nil {
		t.Fatalf("unable to read arb state: %v", err)
	}

	if log1State == log2State {
		t.Fatalf("log states are the same: %v", log1State)
	}

	if log1State != StateWaitingFullResolution {
		t.Fatalf("state mismatch: expected %v, got %v",
			StateWaitingFullResolution, log1State)
	}
	if log2State != StateContractClosed {
		t.Fatalf("state mismatch: expected %v, got %v",
			StateContractClosed, log2State)
	}
}

// TestCommitSetStorage tests that we're able to properly read/write active
// commitment sets.
func TestCommitSetStorage(t *testing.T) {
	t.Parallel()

	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		t.Fatalf("unable to create test log: %v", err)
	}
	defer cleanUp()

	activeHTLCs := []channeldb.HTLC{
		{
			Amt:       1000,
			OnionBlob: make([]byte, 0),
			Signature: make([]byte, 0),
		},
	}

	confTypes := []HtlcSetKey{
		LocalHtlcSet, RemoteHtlcSet, RemotePendingHtlcSet,
	}
	for _, pendingRemote := range []bool{true, false} {
		for _, confType := range confTypes {
			commitSet := &CommitSet{
				ConfCommitKey: &confType,
				HtlcSets:      make(map[HtlcSetKey][]channeldb.HTLC),
			}
			commitSet.HtlcSets[LocalHtlcSet] = activeHTLCs
			commitSet.HtlcSets[RemoteHtlcSet] = activeHTLCs

			if pendingRemote {
				commitSet.HtlcSets[RemotePendingHtlcSet] = activeHTLCs
			}

			err := testLog.InsertConfirmedCommitSet(commitSet)
			if err != nil {
				t.Fatalf("unable to write commit set: %v", err)
			}

			diskCommitSet, err := testLog.FetchConfirmedCommitSet()
			if err != nil {
				t.Fatalf("unable to read commit set: %v", err)
			}

			if !reflect.DeepEqual(commitSet, diskCommitSet) {
				t.Fatalf("commit set mismatch: expected %v, got %v",
					spew.Sdump(commitSet), spew.Sdump(diskCommitSet))
			}
		}
	}

}

func init() {
	testSignDesc.KeyDesc.PubKey, _ = btcec.ParsePubKey(key1, btcec.S256())

	prand.Seed(time.Now().Unix())
}
