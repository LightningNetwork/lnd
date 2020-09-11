package htlcswitch_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	bitcoinCfg "github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

var (
	hash1 = [32]byte{0x01}
	hash2 = [32]byte{0x02}
	hash3 = [32]byte{0x03}

	// closedChannelBucket stores summarization information concerning
	// previously open, but now closed channels.
	closedChannelBucket = []byte("closed-chan-bucket")

	// sphinxPrivKey is the private key given to freshly created sphinx
	// routers.
	sphinxPrivKey *btcec.PrivateKey

	// testEphemeralKey is the ephemeral key that will be extracted to
	// create onion obfuscators.
	testEphemeralKey *btcec.PublicKey

	// testExtracter is a precomputed extraction of testEphemeralKey, using
	// the sphinxPrivKey.
	testExtracter *hop.SphinxErrorEncrypter
)

func init() {
	// Generate a fresh key for our sphinx router.
	var err error
	sphinxPrivKey, err = btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}

	// And another, whose public key will serve as the test ephemeral key.
	testEphemeralPriv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}
	testEphemeralKey = testEphemeralPriv.PubKey()

	// Finally, properly initialize the test extracter
	initTestExtracter()
}

// initTestExtracter spins up a new onion processor specifically for the purpose
// of generating our testExtracter, which should be derived from the
// testEphemeralKey, and which randomly-generated key is used to init the sphinx
// router.
//
// NOTE: This should be called in init(), after testEphemeralKey has been
// properly initialized.
func initTestExtracter() {
	onionProcessor := newOnionProcessor(nil)
	defer onionProcessor.Stop()

	obfuscator, _ := onionProcessor.ExtractErrorEncrypter(
		testEphemeralKey,
	)

	sphinxExtracter, ok := obfuscator.(*hop.SphinxErrorEncrypter)
	if !ok {
		panic("did not extract sphinx error encrypter")
	}

	testExtracter = sphinxExtracter

	// We also set this error extracter on startup, otherwise it will be nil
	// at compile-time.
	halfCircuitTests[2].encrypter = testExtracter
}

// newOnionProcessor creates starts a new htlcswitch.OnionProcessor using a temp
// db and no garbage collection.
func newOnionProcessor(t *testing.T) *hop.OnionProcessor {
	sphinxRouter := sphinx.NewRouter(
		&keychain.PrivKeyECDH{PrivKey: sphinxPrivKey},
		&bitcoinCfg.SimNetParams, sphinx.NewMemoryReplayLog(),
	)

	if err := sphinxRouter.Start(); err != nil {
		t.Fatalf("unable to start sphinx router: %v", err)
	}

	return hop.NewOnionProcessor(sphinxRouter)
}

// newCircuitMap creates a new htlcswitch.CircuitMap using a temp db and a
// fresh sphinx router.
func newCircuitMap(t *testing.T) (*htlcswitch.CircuitMapConfig,
	htlcswitch.CircuitMap) {

	onionProcessor := newOnionProcessor(t)

	circuitMapCfg := &htlcswitch.CircuitMapConfig{
		DB:                    makeCircuitDB(t, ""),
		ExtractErrorEncrypter: onionProcessor.ExtractErrorEncrypter,
	}

	circuitMap, err := htlcswitch.NewCircuitMap(circuitMapCfg)
	if err != nil {
		t.Fatalf("unable to create persistent circuit map: %v", err)
	}

	return circuitMapCfg, circuitMap
}

// TestCircuitMapInit is a quick check to ensure that we can start and restore
// the circuit map, as this will be used extensively in this suite.
func TestCircuitMapInit(t *testing.T) {
	t.Parallel()

	cfg, _ := newCircuitMap(t)
	restartCircuitMap(t, cfg)
}

var halfCircuitTests = []struct {
	hash      [32]byte
	inValue   btcutil.Amount
	outValue  btcutil.Amount
	chanID    lnwire.ShortChannelID
	htlcID    uint64
	encrypter hop.ErrorEncrypter
}{
	{
		hash:      hash1,
		inValue:   0,
		outValue:  1000,
		chanID:    lnwire.NewShortChanIDFromInt(1),
		htlcID:    1,
		encrypter: nil,
	},
	{
		hash:      hash2,
		inValue:   2100,
		outValue:  2000,
		chanID:    lnwire.NewShortChanIDFromInt(2),
		htlcID:    2,
		encrypter: htlcswitch.NewMockObfuscator(),
	},
	{
		hash:     hash3,
		inValue:  10000,
		outValue: 9000,
		chanID:   lnwire.NewShortChanIDFromInt(3),
		htlcID:   3,
		// NOTE: The value of testExtracter is nil at compile-time, it
		// is fully-initialized in initTestExtracter, which should
		// repopulate this encrypter.
		encrypter: testExtracter,
	},
}

// TestHalfCircuitSerialization checks that the half circuits can be properly
// encoded and decoded properly. A critical responsibility of this test is to
// verify that the various ErrorEncrypter implementations can be properly
// reconstructed from a serialized half circuit.
func TestHalfCircuitSerialization(t *testing.T) {
	t.Parallel()

	onionProcessor := newOnionProcessor(t)

	for i, test := range halfCircuitTests {
		circuit := &htlcswitch.PaymentCircuit{
			PaymentHash:    test.hash,
			IncomingAmount: lnwire.NewMSatFromSatoshis(test.inValue),
			OutgoingAmount: lnwire.NewMSatFromSatoshis(test.outValue),
			Incoming: htlcswitch.CircuitKey{
				ChanID: test.chanID,
				HtlcID: test.htlcID,
			},
			ErrorEncrypter: test.encrypter,
		}

		// Write the half circuit to our buffer.
		var b bytes.Buffer
		if err := circuit.Encode(&b); err != nil {
			t.Fatalf("unable to encode half payment circuit test=%d: %v", i, err)
		}

		// Then try to decode the serialized bytes.
		var circuit2 htlcswitch.PaymentCircuit
		circuitReader := bytes.NewReader(b.Bytes())
		if err := circuit2.Decode(circuitReader); err != nil {
			t.Fatalf("unable to decode half payment circuit test=%d: %v", i, err)
		}

		// If the error encrypter is initialized, we will need to
		// reextract it from it's decoded state, as this requires an
		// ECDH with the onion processor's private key. For mock error
		// encrypters, this will be a NOP.
		if circuit2.ErrorEncrypter != nil {
			err := circuit2.ErrorEncrypter.Reextract(
				onionProcessor.ExtractErrorEncrypter,
			)
			if err != nil {
				t.Fatalf("unable to reextract sphinx error "+
					"encrypter: %v", err)
			}
		}

		// Reconstructed half circuit should match the original.
		if !equalIgnoreLFD(circuit, &circuit2) {
			t.Fatalf("unexpected half circuit test=%d, want %v, got %v",
				i, circuit, circuit2)
		}
	}
}

func TestCircuitMapPersistence(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		chan2      = lnwire.NewShortChanIDFromInt(2)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := circuitMap.LookupCircuit(htlcswitch.CircuitKey{
		ChanID: chan1,
		HtlcID: 0,
	})
	if circuit != nil {
		t.Fatalf("LookupByHTLC returned a circuit before any were added: %v",
			circuit)
	}

	circuit1 := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 1,
		},
		PaymentHash:    hash1,
		ErrorEncrypter: htlcswitch.NewMockObfuscator(),
	}
	if _, err := circuitMap.CommitCircuits(circuit1); err != nil {
		t.Fatalf("unable to add half circuit: %v", err)
	}

	// Circuit map should have one circuit that has not been fully opened.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 0)
	assertHasCircuit(t, circuitMap, circuit1)

	cfg, circuitMap = restartCircuitMap(t, cfg)

	assertNumCircuitsWithHash(t, circuitMap, hash1, 0)
	assertHasCircuit(t, circuitMap, circuit1)

	// Add multiple circuits with same destination channel but different HTLC
	// IDs and payment hashes.
	keystone1 := htlcswitch.Keystone{
		InKey: circuit1.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 0,
		},
	}
	circuit1.Outgoing = &keystone1.OutKey
	if err := circuitMap.OpenCircuits(keystone1); err != nil {
		t.Fatalf("unable to add full circuit: %v", err)
	}

	// Circuit map should reflect addition of circuit1, and the change
	// should survive a restart.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuit(t, circuitMap, circuit1)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)

	cfg, circuitMap = restartCircuitMap(t, cfg)

	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuit(t, circuitMap, circuit1)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)

	circuit2 := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 2,
		},
		PaymentHash:    hash2,
		ErrorEncrypter: htlcswitch.NewMockObfuscator(),
	}
	if _, err := circuitMap.CommitCircuits(circuit2); err != nil {
		t.Fatalf("unable to add half circuit: %v", err)
	}

	assertHasCircuit(t, circuitMap, circuit2)

	keystone2 := htlcswitch.Keystone{
		InKey: circuit2.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 1,
		},
	}
	circuit2.Outgoing = &keystone2.OutKey
	if err := circuitMap.OpenCircuits(keystone2); err != nil {
		t.Fatalf("unable to add full circuit: %v", err)
	}

	// Should have two full circuits, one under hash1 and another under
	// hash2. Both half payment circuits should have been removed when the
	// full circuits were added.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuit(t, circuitMap, circuit1)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)

	assertNumCircuitsWithHash(t, circuitMap, hash2, 1)
	assertHasCircuit(t, circuitMap, circuit2)
	assertHasKeystone(t, circuitMap, keystone2.OutKey, circuit2)

	assertNumCircuitsWithHash(t, circuitMap, hash3, 0)

	cfg, circuitMap = restartCircuitMap(t, cfg)

	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuit(t, circuitMap, circuit1)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)

	assertNumCircuitsWithHash(t, circuitMap, hash2, 1)
	assertHasCircuit(t, circuitMap, circuit2)
	assertHasKeystone(t, circuitMap, keystone2.OutKey, circuit2)

	assertNumCircuitsWithHash(t, circuitMap, hash3, 0)

	circuit3 := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 2,
		},
		PaymentHash:    hash3,
		ErrorEncrypter: htlcswitch.NewMockObfuscator(),
	}
	if _, err := circuitMap.CommitCircuits(circuit3); err != nil {
		t.Fatalf("unable to add half circuit: %v", err)
	}

	assertHasCircuit(t, circuitMap, circuit3)
	cfg, circuitMap = restartCircuitMap(t, cfg)
	assertHasCircuit(t, circuitMap, circuit3)

	// Add another circuit with an already-used HTLC ID but different
	// destination channel.
	keystone3 := htlcswitch.Keystone{
		InKey: circuit3.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 0,
		},
	}
	circuit3.Outgoing = &keystone3.OutKey
	if err := circuitMap.OpenCircuits(keystone3); err != nil {
		t.Fatalf("unable to add full circuit: %v", err)
	}

	// Check that all have been marked as full circuits, and that no half
	// circuits are currently being tracked.
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)
	assertHasKeystone(t, circuitMap, keystone2.OutKey, circuit2)
	assertHasKeystone(t, circuitMap, keystone3.OutKey, circuit3)
	cfg, circuitMap = restartCircuitMap(t, cfg)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)
	assertHasKeystone(t, circuitMap, keystone2.OutKey, circuit2)
	assertHasKeystone(t, circuitMap, keystone3.OutKey, circuit3)

	// Even though a circuit was added with chan1, HTLC ID 2 as the source,
	// the lookup should go by destination channel, HTLC ID.
	invalidKeystone := htlcswitch.CircuitKey{
		ChanID: chan1,
		HtlcID: 2,
	}
	circuit = circuitMap.LookupOpenCircuit(invalidKeystone)
	if circuit != nil {
		t.Fatalf("LookupByHTLC returned a circuit without being added: %v",
			circuit)
	}

	circuit4 := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 3,
		},
		PaymentHash:    hash1,
		ErrorEncrypter: htlcswitch.NewMockObfuscator(),
	}
	if _, err := circuitMap.CommitCircuits(circuit4); err != nil {
		t.Fatalf("unable to add half circuit: %v", err)
	}

	// Circuit map should still only show one circuit with hash1, since we
	// have not set the keystone for circuit4.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuit(t, circuitMap, circuit4)

	cfg, circuitMap = restartCircuitMap(t, cfg)

	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuit(t, circuitMap, circuit4)

	// Add a circuit with a destination channel and payment hash that are
	// already added but a different HTLC ID.
	keystone4 := htlcswitch.Keystone{
		InKey: circuit4.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
	}
	circuit4.Outgoing = &keystone4.OutKey
	if err := circuitMap.OpenCircuits(keystone4); err != nil {
		t.Fatalf("unable to add full circuit: %v", err)
	}

	// Verify that all circuits have been fully added.
	assertHasCircuit(t, circuitMap, circuit1)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)
	assertHasCircuit(t, circuitMap, circuit2)
	assertHasKeystone(t, circuitMap, keystone2.OutKey, circuit2)
	assertHasCircuit(t, circuitMap, circuit3)
	assertHasKeystone(t, circuitMap, keystone3.OutKey, circuit3)
	assertHasCircuit(t, circuitMap, circuit4)
	assertHasKeystone(t, circuitMap, keystone4.OutKey, circuit4)

	// Verify that each circuit is exposed via the proper hash bucketing.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 2)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit1)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit4)

	assertNumCircuitsWithHash(t, circuitMap, hash2, 1)
	assertHasCircuitForHash(t, circuitMap, hash2, circuit2)

	assertNumCircuitsWithHash(t, circuitMap, hash3, 1)
	assertHasCircuitForHash(t, circuitMap, hash3, circuit3)

	// Restart, then run checks again.
	cfg, circuitMap = restartCircuitMap(t, cfg)

	// Verify that all circuits have been fully added.
	assertHasCircuit(t, circuitMap, circuit1)
	assertHasKeystone(t, circuitMap, keystone1.OutKey, circuit1)
	assertHasCircuit(t, circuitMap, circuit2)
	assertHasKeystone(t, circuitMap, keystone2.OutKey, circuit2)
	assertHasCircuit(t, circuitMap, circuit3)
	assertHasKeystone(t, circuitMap, keystone3.OutKey, circuit3)
	assertHasCircuit(t, circuitMap, circuit4)
	assertHasKeystone(t, circuitMap, keystone4.OutKey, circuit4)

	// Verify that each circuit is exposed via the proper hash bucketing.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 2)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit1)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit4)

	assertNumCircuitsWithHash(t, circuitMap, hash2, 1)
	assertHasCircuitForHash(t, circuitMap, hash2, circuit2)

	assertNumCircuitsWithHash(t, circuitMap, hash3, 1)
	assertHasCircuitForHash(t, circuitMap, hash3, circuit3)

	// Test removing circuits and the subsequent lookups.
	err = circuitMap.DeleteCircuits(circuit1.Incoming)
	if err != nil {
		t.Fatalf("Remove returned unexpected error: %v", err)
	}

	// There should be exactly one remaining circuit with hash1, and it
	// should be circuit4.
	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit4)
	cfg, circuitMap = restartCircuitMap(t, cfg)
	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit4)

	// Removing already-removed circuit should return an error.
	err = circuitMap.DeleteCircuits(circuit1.Incoming)
	if err != nil {
		t.Fatal("Unexpected failure when deleting already "+
			"deleted circuit: %v", err)
	}

	// Verify that nothing related to hash1 has changed
	assertNumCircuitsWithHash(t, circuitMap, hash1, 1)
	assertHasCircuitForHash(t, circuitMap, hash1, circuit4)

	// Remove last remaining circuit with payment hash hash1.
	err = circuitMap.DeleteCircuits(circuit4.Incoming)
	if err != nil {
		t.Fatalf("Remove returned unexpected error: %v", err)
	}

	assertNumCircuitsWithHash(t, circuitMap, hash1, 0)
	assertNumCircuitsWithHash(t, circuitMap, hash2, 1)
	assertNumCircuitsWithHash(t, circuitMap, hash3, 1)
	cfg, circuitMap = restartCircuitMap(t, cfg)
	assertNumCircuitsWithHash(t, circuitMap, hash1, 0)
	assertNumCircuitsWithHash(t, circuitMap, hash2, 1)
	assertNumCircuitsWithHash(t, circuitMap, hash3, 1)

	// Remove last remaining circuit with payment hash hash2.
	err = circuitMap.DeleteCircuits(circuit2.Incoming)
	if err != nil {
		t.Fatalf("Remove returned unexpected error: %v", err)
	}

	// There should now only be one remaining circuit, with hash3.
	assertNumCircuitsWithHash(t, circuitMap, hash2, 0)
	assertNumCircuitsWithHash(t, circuitMap, hash3, 1)
	cfg, circuitMap = restartCircuitMap(t, cfg)
	assertNumCircuitsWithHash(t, circuitMap, hash2, 0)
	assertNumCircuitsWithHash(t, circuitMap, hash3, 1)

	// In removing the final circuit, we will try and remove all other known
	// circuits as well. Any circuits that are unknown to the circuit map
	// will be ignored, and only circuit 3 should be cause any change in the
	// state.
	err = circuitMap.DeleteCircuits(
		circuit1.Incoming, circuit2.Incoming,
		circuit3.Incoming, circuit4.Incoming,
	)
	if err != nil {
		t.Fatalf("Unexpected failure when removing circuit while also "+
			"deleting already deleted circuits: %v", err)
	}

	// Check that the circuit map is empty, even after restarting.
	assertNumCircuitsWithHash(t, circuitMap, hash3, 0)
	_, circuitMap = restartCircuitMap(t, cfg)
	assertNumCircuitsWithHash(t, circuitMap, hash3, 0)
}

// assertHasKeystone tests that the circuit map contains the provided payment
// circuit.
func assertHasKeystone(t *testing.T, cm htlcswitch.CircuitMap,
	outKey htlcswitch.CircuitKey, c *htlcswitch.PaymentCircuit) {

	circuit := cm.LookupOpenCircuit(outKey)
	if !equalIgnoreLFD(circuit, c) {
		t.Fatalf("unexpected circuit, want: %v, got %v", c, circuit)
	}
}

// assertHasCircuitForHash tests that the provided circuit appears in the list
// of circuits for the given hash.
func assertHasCircuitForHash(t *testing.T, cm htlcswitch.CircuitMap, hash [32]byte,
	circuit *htlcswitch.PaymentCircuit) {

	circuits := cm.LookupByPaymentHash(hash)
	for _, c := range circuits {
		if equalIgnoreLFD(c, circuit) {
			return
		}
	}

	t.Fatalf("unable to find circuit: %v by hash: %v", circuit, hash)
}

// assertNumCircuitsWithHash tests that the circuit has the right number of full
// circuits, indexed by the given hash.
func assertNumCircuitsWithHash(t *testing.T, cm htlcswitch.CircuitMap,
	hash [32]byte, expectedNum int) {

	circuits := cm.LookupByPaymentHash(hash)
	if len(circuits) != expectedNum {
		t.Fatalf("LookupByPaymentHash returned wrong number of circuits for "+
			"hash=%v: expecected %d, got %d", hash, expectedNum,
			len(circuits))
	}
}

// assertHasCircuit queries the circuit map using the half-circuit's half
// key, and fails if the returned half-circuit differs from the provided one.
func assertHasCircuit(t *testing.T, cm htlcswitch.CircuitMap,
	c *htlcswitch.PaymentCircuit) {

	c2 := cm.LookupCircuit(c.Incoming)
	if !equalIgnoreLFD(c, c2) {
		t.Fatalf("expected circuit: %v, got %v", c, c2)
	}
}

// equalIgnoreLFD compares two payment circuits, but ignores the current value
// of LoadedFromDisk. The value is temporarily set to false for the comparison
// and then restored.
func equalIgnoreLFD(c, c2 *htlcswitch.PaymentCircuit) bool {
	ogLFD := c.LoadedFromDisk
	ogLFD2 := c2.LoadedFromDisk

	c.LoadedFromDisk = false
	c2.LoadedFromDisk = false

	isEqual := reflect.DeepEqual(c, c2)

	c.LoadedFromDisk = ogLFD
	c2.LoadedFromDisk = ogLFD2

	return isEqual
}

// makeCircuitDB initializes a new test channeldb for testing the persistence of
// the circuit map. If an empty string is provided as a path, a temp directory
// will be created.
func makeCircuitDB(t *testing.T, path string) *channeldb.DB {
	if path == "" {
		var err error
		path, err = ioutil.TempDir("", "circuitdb")
		if err != nil {
			t.Fatalf("unable to create temp path: %v", err)
		}
	}

	db, err := channeldb.Open(path)
	if err != nil {
		t.Fatalf("unable to open channel db: %v", err)
	}

	return db
}

// Creates a new circuit map, backed by a freshly opened channeldb. The existing
// channeldb is closed in order to simulate a complete restart.
func restartCircuitMap(t *testing.T, cfg *htlcswitch.CircuitMapConfig) (
	*htlcswitch.CircuitMapConfig, htlcswitch.CircuitMap) {

	// Record the current temp path and close current db.
	dbPath := cfg.DB.Path()
	cfg.DB.Close()

	// Reinitialize circuit map with same db path.
	cfg2 := &htlcswitch.CircuitMapConfig{
		DB:                    makeCircuitDB(t, dbPath),
		ExtractErrorEncrypter: cfg.ExtractErrorEncrypter,
	}
	cm2, err := htlcswitch.NewCircuitMap(cfg2)
	if err != nil {
		t.Fatalf("unable to recreate persistent circuit map: %v", err)
	}

	return cfg2, cm2
}

// TestCircuitMapCommitCircuits tests the following behavior of CommitCircuits:
// 1. New circuits are successfully added.
// 2. Duplicate circuits are dropped anytime before circuit map shutsdown.
// 3. Duplicate circuits are failed anytime after circuit map restarts.
func TestCircuitMapCommitCircuits(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
		ErrorEncrypter: testExtracter,
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	actions, err := circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}
	if len(actions.Drops) > 0 {
		t.Fatalf("new circuit should not have been dropped")
	}
	if len(actions.Fails) > 0 {
		t.Fatalf("new circuit should not have failed")
	}
	if len(actions.Adds) != 1 {
		t.Fatalf("only one circuit should have been added, found %d",
			len(actions.Adds))
	}

	circuit2 := circuitMap.LookupCircuit(circuit.Incoming)
	if !reflect.DeepEqual(circuit, circuit2) {
		t.Fatalf("unexpected committed circuit: got %v, want %v",
			circuit2, circuit)
	}

	// Then we will try to readd the same circuit again, this should result
	// in the circuit being dropped. This can happen if the incoming link
	// flaps.
	actions, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}
	if len(actions.Adds) > 0 {
		t.Fatalf("duplicate circuit should not have been added to circuit map")
	}
	if len(actions.Fails) > 0 {
		t.Fatalf("duplicate circuit should not have failed")
	}
	if len(actions.Drops) != 1 {
		t.Fatalf("only one circuit should have been dropped, found %d",
			len(actions.Drops))
	}

	// Finally, restart the circuit map, which will cause the added circuit
	// to be loaded from disk. Since the keystone was never set, subsequent
	// attempts to commit the circuit should cause the circuit map to
	// indicate that the HTLC should be failed back.
	_, circuitMap = restartCircuitMap(t, cfg)

	actions, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}
	if len(actions.Adds) > 0 {
		t.Fatalf("duplicate circuit with incomplete forwarding " +
			"decision should not have been added to circuit map")
	}
	if len(actions.Drops) > 0 {
		t.Fatalf("duplicate circuit with incomplete forwarding " +
			"decision should not have been dropped by circuit map")
	}
	if len(actions.Fails) != 1 {
		t.Fatalf("only one duplicate circuit with incomplete "+
			"forwarding decision should have been failed, found: "+
			"%d", len(actions.Fails))
	}

	// Lookup the committed circuit again, it should be identical apart from
	// the loaded from disk flag.
	circuit2 = circuitMap.LookupCircuit(circuit.Incoming)
	if !equalIgnoreLFD(circuit, circuit2) {
		t.Fatalf("unexpected committed circuit: got %v, want %v",
			circuit2, circuit)
	}
}

// TestCircuitMapOpenCircuits checks that circuits are properly opened, and that
// duplicate attempts to open a circuit will result in an error.
func TestCircuitMapOpenCircuits(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		chan2      = lnwire.NewShortChanIDFromInt(2)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
		ErrorEncrypter: testExtracter,
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}

	keystone := htlcswitch.Keystone{
		InKey: circuit.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 2,
		},
	}

	// Open the circuit for the first time.
	err = circuitMap.OpenCircuits(keystone)
	if err != nil {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Check that we can retrieve the open circuit if the circuit map before
	// the circuit map is restarted.
	circuit2 := circuitMap.LookupOpenCircuit(keystone.OutKey)
	if !reflect.DeepEqual(circuit, circuit2) {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, circuit)
	}

	if !circuit2.HasKeystone() {
		t.Fatalf("open circuit should have keystone")
	}
	if !reflect.DeepEqual(&keystone.OutKey, circuit2.Outgoing) {
		t.Fatalf("expected open circuit to have outgoing key: %v, found %v",
			&keystone.OutKey, circuit2.Outgoing)
	}

	// Open the circuit for a second time, which should fail due to a
	// duplicate keystone
	err = circuitMap.OpenCircuits(keystone)
	if err != htlcswitch.ErrDuplicateKeystone {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Then we will try to readd the same circuit again, this should result
	// in the circuit being dropped. This can happen if the incoming link
	// flaps OR the switch is entirely restarted and the outgoing link has
	// not received a response.
	actions, err := circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}
	if len(actions.Adds) > 0 {
		t.Fatalf("duplicate circuit should not have been added to circuit map")
	}
	if len(actions.Fails) > 0 {
		t.Fatalf("duplicate circuit should not have failed")
	}
	if len(actions.Drops) != 1 {
		t.Fatalf("only one circuit should have been dropped, found %d",
			len(actions.Drops))
	}

	// Now, restart the circuit map, which will cause the opened circuit to
	// be loaded from disk. Since we set the keystone on this circuit, it
	// should be restored as such in memory.
	//
	// NOTE: The channel db doesn't have any channel data, so no keystones
	// will be trimmed.
	_, circuitMap = restartCircuitMap(t, cfg)

	// Check that we can still query for the open circuit.
	circuit2 = circuitMap.LookupOpenCircuit(keystone.OutKey)
	if !equalIgnoreLFD(circuit, circuit2) {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, circuit)
	}

	// Try to open the circuit again, we expect this to fail since the open
	// circuit was restored.
	err = circuitMap.OpenCircuits(keystone)
	if err != htlcswitch.ErrDuplicateKeystone {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Lastly, with the circuit map restarted, try one more time to recommit
	// the open circuit. This should be dropped, and is expected to happen
	// if the incoming link flaps OR the switch is entirely restarted and
	// the outgoing link has not received a response.
	actions, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}
	if len(actions.Adds) > 0 {
		t.Fatalf("duplicate circuit should not have been added to circuit map")
	}
	if len(actions.Fails) > 0 {
		t.Fatalf("duplicate circuit should not have failed")
	}
	if len(actions.Drops) != 1 {
		t.Fatalf("only one circuit should have been dropped, found %d",
			len(actions.Drops))
	}
}

func assertCircuitsOpenedPreRestart(t *testing.T,
	circuitMap htlcswitch.CircuitMap,
	circuits []*htlcswitch.PaymentCircuit,
	keystones []htlcswitch.Keystone) {

	for i, circuit := range circuits {
		keystone := keystones[i]

		openCircuit := circuitMap.LookupOpenCircuit(keystone.OutKey)
		if !reflect.DeepEqual(circuit, openCircuit) {
			t.Fatalf("unexpected open circuit %d: got %v, want %v",
				i, openCircuit, circuit)
		}

		if !openCircuit.HasKeystone() {
			t.Fatalf("open circuit %d should have keystone", i)
		}
		if !reflect.DeepEqual(&keystone.OutKey, openCircuit.Outgoing) {
			t.Fatalf("expected open circuit %d to have outgoing "+
				"key: %v, found %v", i,
				&keystone.OutKey, openCircuit.Outgoing)
		}
	}
}

func assertCircuitsOpenedPostRestart(t *testing.T,
	circuitMap htlcswitch.CircuitMap,
	circuits []*htlcswitch.PaymentCircuit,
	keystones []htlcswitch.Keystone) {

	for i, circuit := range circuits {
		keystone := keystones[i]

		openCircuit := circuitMap.LookupOpenCircuit(keystone.OutKey)
		if !equalIgnoreLFD(circuit, openCircuit) {
			t.Fatalf("unexpected open circuit %d: got %v, want %v",
				i, openCircuit, circuit)
		}

		if !openCircuit.HasKeystone() {
			t.Fatalf("open circuit %d should have keystone", i)
		}
		if !reflect.DeepEqual(&keystone.OutKey, openCircuit.Outgoing) {
			t.Fatalf("expected open circuit %d to have outgoing "+
				"key: %v, found %v", i,
				&keystone.OutKey, openCircuit.Outgoing)
		}
	}
}

func assertCircuitsNotOpenedPreRestart(t *testing.T,
	circuitMap htlcswitch.CircuitMap,
	circuits []*htlcswitch.PaymentCircuit,
	keystones []htlcswitch.Keystone,
	offset int) {

	for i := range circuits {
		keystone := keystones[i]

		openCircuit := circuitMap.LookupOpenCircuit(keystone.OutKey)
		if openCircuit != nil {
			t.Fatalf("expected circuit %d not to be open",
				offset+i)
		}

		circuit := circuitMap.LookupCircuit(keystone.InKey)
		if circuit == nil {
			t.Fatalf("expected to find unopened circuit %d",
				offset+i)
		}
		if circuit.HasKeystone() {
			t.Fatalf("circuit %d should not have keystone",
				offset+i)
		}
	}
}

// TestCircuitMapTrimOpenCircuits verifies that the circuit map properly removes
// circuits from disk and the in-memory state when TrimOpenCircuits is used.
// This test checks that a successful trim survives a restart, and that circuits
// added before the restart can also be trimmed.
func TestCircuitMapTrimOpenCircuits(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		chan2      = lnwire.NewShortChanIDFromInt(2)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	const nCircuits = 10
	const firstTrimIndex = 7
	const secondTrimIndex = 3

	// Create a list of all circuits that will be committed in the circuit
	// map. The incoming HtlcIDs are chosen so that there is overlap with
	// the outgoing HtlcIDs, but ensures that the test is not dependent on
	// them being equal.
	circuits := make([]*htlcswitch.PaymentCircuit, nCircuits)
	for i := range circuits {
		circuits[i] = &htlcswitch.PaymentCircuit{
			Incoming: htlcswitch.CircuitKey{
				ChanID: chan1,
				HtlcID: uint64(i + 3),
			},
			ErrorEncrypter: htlcswitch.NewMockObfuscator(),
		}
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err = circuitMap.CommitCircuits(circuits...)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}

	// Now create a list of the keystones that we will use to preemptively
	// open the circuits. We set the index as the outgoing HtlcID to i
	// simplify the indexing logic of the test.
	keystones := make([]htlcswitch.Keystone, nCircuits)
	for i := range keystones {
		keystones[i] = htlcswitch.Keystone{
			InKey: circuits[i].Incoming,
			OutKey: htlcswitch.CircuitKey{
				ChanID: chan2,
				HtlcID: uint64(i),
			},
		}
	}

	// Open the circuits for the first time.
	err = circuitMap.OpenCircuits(keystones...)
	if err != nil {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Check that all circuits are marked open.
	assertCircuitsOpenedPreRestart(t, circuitMap, circuits, keystones)

	// Now trim up above outgoing htlcid `firstTrimIndex` (7). This should
	// leave the first 7 circuits open, and the rest should be reverted to
	// an unopened state.
	err = circuitMap.TrimOpenCircuits(chan2, firstTrimIndex)
	if err != nil {
		t.Fatalf("unable to trim circuits")
	}

	assertCircuitsOpenedPreRestart(t,
		circuitMap,
		circuits[:firstTrimIndex],
		keystones[:firstTrimIndex],
	)

	assertCircuitsNotOpenedPreRestart(
		t,
		circuitMap,
		circuits[firstTrimIndex:],
		keystones[firstTrimIndex:],
		firstTrimIndex,
	)

	// Restart the circuit map, verify that the trim is reflected on
	// startup.
	cfg, circuitMap = restartCircuitMap(t, cfg)

	assertCircuitsOpenedPostRestart(
		t,
		circuitMap,
		circuits[:firstTrimIndex],
		keystones[:firstTrimIndex],
	)

	assertCircuitsNotOpenedPreRestart(
		t,
		circuitMap,
		circuits[firstTrimIndex:],
		keystones[firstTrimIndex:],
		firstTrimIndex,
	)

	// Now, trim above outgoing htlcid `secondTrimIndex` (3). Only the first
	// three circuits should be open, with any others being reverted back to
	// unopened.
	err = circuitMap.TrimOpenCircuits(chan2, secondTrimIndex)
	if err != nil {
		t.Fatalf("unable to trim circuits")
	}

	assertCircuitsOpenedPostRestart(
		t,
		circuitMap,
		circuits[:secondTrimIndex],
		keystones[:secondTrimIndex],
	)

	assertCircuitsNotOpenedPreRestart(
		t,
		circuitMap,
		circuits[secondTrimIndex:],
		keystones[secondTrimIndex:],
		secondTrimIndex,
	)

	// Restart the circuit map one last time to make sure the changes are
	// persisted.
	_, circuitMap = restartCircuitMap(t, cfg)

	assertCircuitsOpenedPostRestart(
		t,
		circuitMap,
		circuits[:secondTrimIndex],
		keystones[:secondTrimIndex],
	)

	assertCircuitsNotOpenedPreRestart(
		t,
		circuitMap,
		circuits[secondTrimIndex:],
		keystones[secondTrimIndex:],
		secondTrimIndex,
	)
}

// TestCircuitMapCloseOpenCircuits asserts that the circuit map can properly
// close open circuits, and that it allows at most one response to do so
// successfully. It also checks that a circuit is reopened if the close was not
// persisted via DeleteCircuits, and can again be closed.
func TestCircuitMapCloseOpenCircuits(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		chan2      = lnwire.NewShortChanIDFromInt(2)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
		ErrorEncrypter: &hop.SphinxErrorEncrypter{
			EphemeralKey: testEphemeralKey,
		},
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}

	keystone := htlcswitch.Keystone{
		InKey: circuit.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 2,
		},
	}

	// Open the circuit for the first time.
	err = circuitMap.OpenCircuits(keystone)
	if err != nil {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Check that we can retrieve the open circuit if the circuit map before
	// the circuit map is restarted.
	circuit2 := circuitMap.LookupOpenCircuit(keystone.OutKey)
	if !reflect.DeepEqual(circuit, circuit2) {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, circuit)
	}

	// Open the circuit for a second time, which should fail due to a
	// duplicate keystone
	err = circuitMap.OpenCircuits(keystone)
	if err != htlcswitch.ErrDuplicateKeystone {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Close the open circuit for the first time, which should succeed.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Closing the circuit a second time should result in a failure.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != htlcswitch.ErrCircuitClosing {
		t.Fatalf("unable to close unopened circuit")
	}

	// Now, restart the circuit map, which will cause the opened circuit to
	// be loaded from disk. Since we set the keystone on this circuit, it
	// should be restored as such in memory.
	//
	// NOTE: The channel db doesn't have any channel data, so no keystones
	// will be trimmed.
	_, circuitMap = restartCircuitMap(t, cfg)

	// Close the open circuit for the first time, which should succeed.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Closing the circuit a second time should result in a failure.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != htlcswitch.ErrCircuitClosing {
		t.Fatalf("unable to close unopened circuit")
	}
}

// TestCircuitMapCloseUnopenedCircuit tests that closing an unopened circuit
// allows at most semantics, and that the close is not persisted across
// restarts.
func TestCircuitMapCloseUnopenedCircuit(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
		ErrorEncrypter: testExtracter,
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}

	// Close the open circuit for the first time, which should succeed.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Closing the circuit a second time should result in a failure.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != htlcswitch.ErrCircuitClosing {
		t.Fatalf("unable to close unopened circuit")
	}

	// Now, restart the circuit map, which will result in the circuit being
	// reopened, since no attempt to delete the circuit was made.
	_, circuitMap = restartCircuitMap(t, cfg)

	// Close the open circuit for the first time, which should succeed.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Closing the circuit a second time should result in a failure.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != htlcswitch.ErrCircuitClosing {
		t.Fatalf("unable to close unopened circuit")
	}
}

// TestCircuitMapDeleteUnopenedCircuit checks that an unopened circuit can be
// removed persistently from the circuit map.
func TestCircuitMapDeleteUnopenedCircuit(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
		ErrorEncrypter: testExtracter,
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}

	// Close the open circuit for the first time, which should succeed.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	err = circuitMap.DeleteCircuits(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Check that we can retrieve the open circuit if the circuit map before
	// the circuit map is restarted.
	circuit2 := circuitMap.LookupCircuit(circuit.Incoming)
	if circuit2 != nil {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, nil)
	}

	// Now, restart the circuit map, and check that the deletion survived
	// the restart.
	_, circuitMap = restartCircuitMap(t, cfg)

	circuit2 = circuitMap.LookupCircuit(circuit.Incoming)
	if circuit2 != nil {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, nil)
	}
}

// TestCircuitMapDeleteOpenCircuit checks that an open circuit can be removed
// persistently from the circuit map.
func TestCircuitMapDeleteOpenCircuit(t *testing.T) {
	t.Parallel()

	var (
		chan1      = lnwire.NewShortChanIDFromInt(1)
		chan2      = lnwire.NewShortChanIDFromInt(2)
		circuitMap htlcswitch.CircuitMap
		err        error
	)

	cfg, circuitMap := newCircuitMap(t)

	circuit := &htlcswitch.PaymentCircuit{
		Incoming: htlcswitch.CircuitKey{
			ChanID: chan1,
			HtlcID: 3,
		},
		ErrorEncrypter: testExtracter,
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err = circuitMap.CommitCircuits(circuit)
	if err != nil {
		t.Fatalf("failed to commit circuits: %v", err)
	}

	keystone := htlcswitch.Keystone{
		InKey: circuit.Incoming,
		OutKey: htlcswitch.CircuitKey{
			ChanID: chan2,
			HtlcID: 2,
		},
	}

	// Open the circuit for the first time.
	err = circuitMap.OpenCircuits(keystone)
	if err != nil {
		t.Fatalf("failed to open circuits: %v", err)
	}

	// Close the open circuit for the first time, which should succeed.
	_, err = circuitMap.FailCircuit(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Persistently remove the circuit identified by incoming chan id.
	err = circuitMap.DeleteCircuits(circuit.Incoming)
	if err != nil {
		t.Fatalf("unable to close unopened circuit")
	}

	// Check that we can no longer retrieve the open circuit.
	circuit2 := circuitMap.LookupOpenCircuit(keystone.OutKey)
	if circuit2 != nil {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, nil)
	}

	// Now, restart the circuit map, and check that the deletion survived
	// the restart.
	_, circuitMap = restartCircuitMap(t, cfg)

	circuit2 = circuitMap.LookupOpenCircuit(keystone.OutKey)
	if circuit2 != nil {
		t.Fatalf("unexpected open circuit: got %v, want %v",
			circuit2, nil)
	}
}

// TestCircuitMapCleanClosedChannels checks that the circuits and keystones are
// deleted for closed channels upon restart.
func TestCircuitMapCleanClosedChannels(t *testing.T) {
	t.Parallel()

	var (
		inKey0 = htlcswitch.CircuitKey{
			ChanID: lnwire.NewShortChanIDFromInt(uint64(0)),
			HtlcID: 0,
		}
		inKey1 = htlcswitch.CircuitKey{
			ChanID: lnwire.NewShortChanIDFromInt(uint64(1)),
			HtlcID: 0,
		}
		outKey1 = htlcswitch.CircuitKey{
			ChanID: lnwire.NewShortChanIDFromInt(uint64(3)),
			HtlcID: 0,
		}
	)

	type closeChannelParams struct {
		chanID    lnwire.ShortChannelID
		isPending bool
	}

	testParams := []struct {
		name string

		// keystones is used to create and open circuits. A keystone is
		// a pair of circuit keys, inKey and outKey, with the outKey
		// optionally being empty. If a keystone with an outKey is used,
		// a circuit will be created and opened, thus creating a circuit
		// and a Keystone in the DB. Otherwise, only the circuit is
		// created.
		keystones []htlcswitch.Keystone

		chanParams []closeChannelParams
		deleted    []htlcswitch.Keystone
		untouched  []htlcswitch.Keystone
	}{
		{
			name: "no deletion if there are no closed channels",
			keystones: []htlcswitch.Keystone{
				// creates a circuit and a keystone
				{InKey: inKey1, OutKey: outKey1},
			},
			untouched: []htlcswitch.Keystone{
				{InKey: inKey1, OutKey: outKey1},
			},
		},
		{
			name: "delete half circuits for closed channels",
			chanParams: []closeChannelParams{
				{chanID: inKey1.ChanID, isPending: false},
			},
			keystones: []htlcswitch.Keystone{
				// creates a circuit, no keystone created
				{InKey: inKey1},
			},
			deleted: []htlcswitch.Keystone{
				{InKey: inKey1},
			},
		},
		{
			name: "delete open circuits for closed channels",
			chanParams: []closeChannelParams{
				{chanID: inKey1.ChanID, isPending: false},
			},
			keystones: []htlcswitch.Keystone{
				// creates a circuit and a keystone
				{InKey: inKey1, OutKey: outKey1},
			},
			deleted: []htlcswitch.Keystone{
				{InKey: inKey1, OutKey: outKey1},
			},
		},
		{
			name: "no deletion for locally initialized payment",
			chanParams: []closeChannelParams{
				{chanID: inKey0.ChanID, isPending: false},
			},
			keystones: []htlcswitch.Keystone{
				// creates a circuit, no keystone created
				{InKey: inKey0},
			},
			untouched: []htlcswitch.Keystone{
				{InKey: inKey0},
			},
		},
		{
			name: "no deletion for pending close channel",
			chanParams: []closeChannelParams{
				{chanID: inKey1.ChanID, isPending: true},
			},
			keystones: []htlcswitch.Keystone{
				// creates a circuit, no keystone created
				{InKey: inKey1},
			},
			untouched: []htlcswitch.Keystone{
				{InKey: inKey1},
			},
		},
	}

	for _, tt := range testParams {
		test := tt

		t.Run(test.name, func(t *testing.T) {
			cfg, circuitMap := newCircuitMap(t)

			// create test circuits
			for _, ks := range test.keystones {
				err := createTestCircuit(ks, circuitMap)
				require.NoError(
					t, err,
					"failed to create test circuit",
				)
			}

			// create close channels
			err := kvdb.Update(cfg.DB, func(tx kvdb.RwTx) error {
				for _, channel := range test.chanParams {
					if err := createTestCloseChannelSummery(
						tx, channel.isPending,
						channel.chanID,
					); err != nil {
						return err
					}
				}
				return nil
			})
			require.NoError(
				t, err,
				"failed to create close channel summery",
			)

			// Now, restart the circuit map, and check that the
			// circuits and keystones of closed channels are
			// deleted in DB.
			_, circuitMap = restartCircuitMap(t, cfg)

			// Check that items are deleted. LookupCircuit and
			// LookupOpenCircuit will check the cached circuits,
			// which are loaded on restart from the DB.
			for _, ks := range test.deleted {
				assertKeystoneDeleted(t, circuitMap, ks)
			}

			// We also check we are not deleting wanted circuits.
			for _, ks := range test.untouched {
				assertKeystoneNotDeleted(t, circuitMap, ks)
			}

		})
	}

}

// createTestCircuit creates a circuit for testing with its incoming key being
// the keystone's InKey. If the keystone has an OutKey, the circuit will be
// opened, which causes a Keystone to be created in DB.
func createTestCircuit(ks htlcswitch.Keystone, cm htlcswitch.CircuitMap) error {
	circuit := &htlcswitch.PaymentCircuit{
		Incoming:       ks.InKey,
		ErrorEncrypter: testExtracter,
	}

	// First we will try to add an new circuit to the circuit map, this
	// should succeed.
	_, err := cm.CommitCircuits(circuit)
	if err != nil {
		return fmt.Errorf("failed to commit circuits: %v", err)
	}

	// If the keystone has no outgoing key, we won't open it.
	if ks.OutKey.ChanID.ToUint64() == 0 {
		return nil
	}

	// Open the circuit, implicitly creates a keystone on disk.
	err = cm.OpenCircuits(ks)
	if err != nil {
		return fmt.Errorf("failed to open circuits: %v", err)
	}

	return nil
}

// assertKeystoneDeleted checks that a given keystone is deleted from the
// circuit map.
func assertKeystoneDeleted(t *testing.T,
	cm htlcswitch.CircuitMap, ks htlcswitch.Keystone) {

	c := cm.LookupCircuit(ks.InKey)
	require.Nil(t, c, "no circuit should be found using InKey")

	if ks.OutKey.ChanID.ToUint64() != 0 {
		c = cm.LookupOpenCircuit(ks.OutKey)
		require.Nil(t, c, "no circuit should be found using OutKey")
	}
}

// assertKeystoneDeleted checks that a given keystone is not deleted from the
// circuit map.
func assertKeystoneNotDeleted(t *testing.T,
	cm htlcswitch.CircuitMap, ks htlcswitch.Keystone) {

	c := cm.LookupCircuit(ks.InKey)
	require.NotNil(t, c, "expecting circuit found using InKey")

	if ks.OutKey.ChanID.ToUint64() != 0 {
		c = cm.LookupOpenCircuit(ks.OutKey)
		require.NotNil(t, c, "expecting circuit found using OutKey")
	}
}

// createTestCloseChannelSummery creates a CloseChannelSummery for testing.
func createTestCloseChannelSummery(tx kvdb.RwTx, isPending bool,
	chanID lnwire.ShortChannelID) error {

	closedChanBucket, err := tx.CreateTopLevelBucket(closedChannelBucket)
	if err != nil {
		return err
	}
	outputPoint := wire.OutPoint{Hash: hash1, Index: rand.Uint32()}

	ccs := &channeldb.ChannelCloseSummary{
		ChanPoint:      outputPoint,
		ShortChanID:    chanID,
		ChainHash:      hash1,
		ClosingTXID:    hash2,
		CloseHeight:    100,
		RemotePub:      testEphemeralKey,
		Capacity:       btcutil.Amount(10000),
		SettledBalance: btcutil.Amount(50000),
		CloseType:      channeldb.RemoteForceClose,
		IsPending:      isPending,
	}
	var b bytes.Buffer
	if err := serializeChannelCloseSummary(&b, ccs); err != nil {
		return err
	}

	var chanPointBuf bytes.Buffer
	if err := writeOutpoint(&chanPointBuf, &outputPoint); err != nil {
		return err
	}

	return closedChanBucket.Put(chanPointBuf.Bytes(), b.Bytes())
}

func serializeChannelCloseSummary(
	w io.Writer,
	cs *channeldb.ChannelCloseSummary) error {

	err := channeldb.WriteElements(
		w,
		cs.ChanPoint, cs.ShortChanID, cs.ChainHash, cs.ClosingTXID,
		cs.CloseHeight, cs.RemotePub, cs.Capacity, cs.SettledBalance,
		cs.TimeLockedBalance, cs.CloseType, cs.IsPending,
	)
	if err != nil {
		return err
	}

	// If this is a close channel summary created before the addition of
	// the new fields, then we can exit here.
	if cs.RemoteCurrentRevocation == nil {
		return channeldb.WriteElements(w, false)
	}

	return nil
}

// writeOutpoint writes an outpoint to the passed writer using the minimal
// amount of bytes possible.
func writeOutpoint(w io.Writer, o *wire.OutPoint) error {
	if _, err := w.Write(o.Hash[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, o.Index); err != nil {
		return err
	}

	return nil
}
