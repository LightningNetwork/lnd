package htlcswitch

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// ErrCorruptedCircuitMap indicates that the on-disk bucketing structure
	// has altered since the circuit map instance was initialized.
	ErrCorruptedCircuitMap = errors.New("circuit map has been corrupted")

	// ErrCircuitNotInHashIndex indicates that a particular circuit did not
	// appear in the in-memory hash index.
	ErrCircuitNotInHashIndex = errors.New("payment circuit not found in " +
		"hash index")

	// ErrUnknownCircuit signals that circuit could not be removed from the
	// map because it was not found.
	ErrUnknownCircuit = errors.New("unknown payment circuit")

	// ErrCircuitClosing signals that an htlc has already closed this
	// circuit in-memory.
	ErrCircuitClosing = errors.New("circuit has already been closed")

	// ErrDuplicateCircuit signals that this circuit was previously
	// added.
	ErrDuplicateCircuit = errors.New("duplicate circuit add")

	// ErrUnknownKeystone signals that no circuit was found using the
	// outgoing circuit key.
	ErrUnknownKeystone = errors.New("unknown circuit keystone")

	// ErrDuplicateKeystone signals that this circuit was previously
	// assigned a keystone.
	ErrDuplicateKeystone = errors.New("cannot add duplicate keystone")
)

// CircuitModifier is a common interface used by channel links to modify the
// contents of the circuit map maintained by the switch.
type CircuitModifier interface {
	// OpenCircuits preemptively records a batch keystones that will mark
	// currently pending circuits as open. These changes can be rolled back
	// on restart if the outgoing Adds do not make it into a commitment
	// txn.
	OpenCircuits(...Keystone) error

	// TrimOpenCircuits removes a channel's open channels with htlc indexes
	// above `start`.
	TrimOpenCircuits(chanID lnwire.ShortChannelID, start uint64) error

	// DeleteCircuits removes the incoming circuit key to remove all
	// persistent references to a circuit. Returns a ErrUnknownCircuit if
	// any of the incoming keys are not known.
	DeleteCircuits(inKeys ...CircuitKey) error
}

// CircuitLookup is a common interface used to lookup information that is stored
// in the circuit map.
type CircuitLookup interface {
	// LookupCircuit queries the circuit map for the circuit identified by
	// inKey.
	LookupCircuit(inKey CircuitKey) *PaymentCircuit

	// LookupOpenCircuit queries the circuit map for a circuit identified
	// by its outgoing circuit key.
	LookupOpenCircuit(outKey CircuitKey) *PaymentCircuit
}

// CircuitFwdActions represents the forwarding decision made by the circuit
// map, and is returned from CommitCircuits. The sequence of circuits provided
// to CommitCircuits is split into three sub-sequences, allowing the caller to
// do an in-order scan, comparing the head of each subsequence, to determine
// the decision made by the circuit map.
type CircuitFwdActions struct {
	// Adds is the subsequence of circuits that were successfully committed
	// in the circuit map.
	Adds []*PaymentCircuit

	// Drops is the subsequence of circuits for which no action should be
	// done.
	Drops []*PaymentCircuit

	// Fails is the subsequence of circuits that should be failed back by
	// the calling link.
	Fails []*PaymentCircuit
}

// CircuitMap is an interface for managing the construction and teardown of
// payment circuits used by the switch.
type CircuitMap interface {
	CircuitModifier

	CircuitLookup

	// CommitCircuits attempts to add the given circuits to the circuit
	// map. The list of circuits is split into three distinct
	// sub-sequences, corresponding to adds, drops, and fails. Adds should
	// be forwarded to the switch, while fails should be failed back
	// locally within the calling link.
	CommitCircuits(circuit ...*PaymentCircuit) (*CircuitFwdActions, error)

	// CloseCircuit marks the circuit identified by `outKey` as closing
	// in-memory, which prevents duplicate settles/fails from completing an
	// open circuit twice.
	CloseCircuit(outKey CircuitKey) (*PaymentCircuit, error)

	// FailCircuit is used by locally failed HTLCs to mark the circuit
	// identified by `inKey` as closing in-memory, which prevents duplicate
	// settles/fails from being accepted for the same circuit.
	FailCircuit(inKey CircuitKey) (*PaymentCircuit, error)

	// LookupByPaymentHash queries the circuit map and returns all open
	// circuits that use the given payment hash.
	LookupByPaymentHash(hash [32]byte) []*PaymentCircuit

	// NumPending returns the total number of active circuits added by
	// CommitCircuits.
	NumPending() int

	// NumOpen returns the number of circuits with HTLCs that have been
	// forwarded via an outgoing link.
	NumOpen() int
}

var (
	// circuitAddKey is the key used to retrieve the bucket containing
	// payment circuits. A circuit records information about how to return
	// a packet to the source link, potentially including an error
	// encrypter for applying this hop's encryption to the payload in the
	// reverse direction.
	circuitAddKey = []byte("circuit-adds")

	// circuitKeystoneKey is used to retrieve the bucket containing circuit
	// keystones, which are set in place once a forwarded packet is
	// assigned an index on an outgoing commitment txn.
	circuitKeystoneKey = []byte("circuit-keystones")
)

// circuitMap is a data structure that implements thread safe, persistent
// storage of circuit routing information. The switch consults a circuit map to
// determine where to forward returning HTLC update messages. Circuits are
// always identifiable by their incoming CircuitKey, in addition to their
// outgoing CircuitKey if the circuit is fully-opened.
type circuitMap struct {
	cfg *CircuitMapConfig

	mtx sync.RWMutex

	// pending is an in-memory mapping of all half payment circuits, and is
	// kept in sync with the on-disk contents of the circuit map.
	pending map[CircuitKey]*PaymentCircuit

	// opened is an in-memory mapping of all full payment circuits, which
	// is also synchronized with the persistent state of the circuit map.
	opened map[CircuitKey]*PaymentCircuit

	// closed is an in-memory set of circuits for which the switch has
	// received a settle or fail. This precedes the actual deletion of a
	// circuit from disk.
	closed map[CircuitKey]struct{}

	// hashIndex is a volatile index that facilitates fast queries by
	// payment hash against the contents of circuits. This index can be
	// reconstructed entirely from the set of persisted full circuits on
	// startup.
	hashIndex map[[32]byte]map[CircuitKey]struct{}
}

// CircuitMapConfig houses the critical interfaces and references necessary to
// parameterize an instance of circuitMap.
type CircuitMapConfig struct {
	// DB provides the persistent storage engine for the circuit map.
	// TODO(conner): create abstraction to allow for the substitution of
	// other persistence engines.
	DB *channeldb.DB

	// ExtractErrorEncrypter derives the shared secret used to encrypt
	// errors from the obfuscator's ephemeral public key.
	ExtractErrorEncrypter hop.ErrorEncrypterExtracter
}

// NewCircuitMap creates a new instance of the circuitMap.
func NewCircuitMap(cfg *CircuitMapConfig) (CircuitMap, error) {
	cm := &circuitMap{
		cfg: cfg,
	}

	// Initialize the on-disk buckets used by the circuit map.
	if err := cm.initBuckets(); err != nil {
		return nil, err
	}

	// Load any previously persisted circuit into back into memory.
	if err := cm.restoreMemState(); err != nil {
		return nil, err
	}

	// Trim any keystones that were not committed in an outgoing commit txn.
	//
	// NOTE: This operation will be applied to the persistent state of all
	// active channels. Therefore, it must be called before any links are
	// created to avoid interfering with normal operation.
	if err := cm.trimAllOpenCircuits(); err != nil {
		return nil, err
	}

	return cm, nil
}

// initBuckets ensures that the primary buckets used by the circuit are
// initialized so that we can assume their existence after startup.
func (cm *circuitMap) initBuckets() error {
	return kvdb.Update(cm.cfg.DB, func(tx kvdb.RwTx) error {
		_, err := tx.CreateTopLevelBucket(circuitKeystoneKey)
		if err != nil {
			return err
		}

		_, err = tx.CreateTopLevelBucket(circuitAddKey)
		return err
	}, func() {})
}

// restoreMemState loads the contents of the half circuit and full circuit
// buckets from disk and reconstructs the in-memory representation of the
// circuit map. Afterwards, the state of the hash index is reconstructed using
// the recovered set of full circuits. This method will also remove any stray
// keystones, which are those that appear fully-opened, but have no pending
// circuit related to the intended incoming link.
func (cm *circuitMap) restoreMemState() error {
	log.Infof("Restoring in-memory circuit state from disk")

	var (
		opened  map[CircuitKey]*PaymentCircuit
		pending map[CircuitKey]*PaymentCircuit
	)

	if err := kvdb.Update(cm.cfg.DB, func(tx kvdb.RwTx) error {
		// Restore any of the circuits persisted in the circuit bucket
		// back into memory.
		circuitBkt := tx.ReadWriteBucket(circuitAddKey)
		if circuitBkt == nil {
			return ErrCorruptedCircuitMap
		}

		if err := circuitBkt.ForEach(func(_, v []byte) error {
			circuit, err := cm.decodeCircuit(v)
			if err != nil {
				return err
			}

			circuit.LoadedFromDisk = true
			pending[circuit.Incoming] = circuit

			return nil
		}); err != nil {
			return err
		}

		// Furthermore, load the keystone bucket and resurrect the
		// keystones used in any open circuits.
		keystoneBkt := tx.ReadWriteBucket(circuitKeystoneKey)
		if keystoneBkt == nil {
			return ErrCorruptedCircuitMap
		}

		var strayKeystones []Keystone
		if err := keystoneBkt.ForEach(func(k, v []byte) error {
			var (
				inKey  CircuitKey
				outKey = &CircuitKey{}
			)

			// Decode the incoming and outgoing circuit keys.
			if err := inKey.SetBytes(v); err != nil {
				return err
			}
			if err := outKey.SetBytes(k); err != nil {
				return err
			}

			// Retrieve the pending circuit, set its keystone, then
			// add it to the opened map.
			circuit, ok := pending[inKey]
			if ok {
				circuit.Outgoing = outKey
				opened[*outKey] = circuit
			} else {
				strayKeystones = append(strayKeystones, Keystone{
					InKey:  inKey,
					OutKey: *outKey,
				})
			}

			return nil
		}); err != nil {
			return err
		}

		// If any stray keystones were found, we'll proceed to prune
		// them from the circuit map's persistent storage. This may
		// manifest on older nodes that had updated channels before
		// their short channel id was set properly. We believe this
		// issue has been fixed, though this will allow older nodes to
		// recover without additional intervention.
		for _, strayKeystone := range strayKeystones {
			// As a precaution, we will only cleanup keystones
			// related to locally-initiated payments. If a
			// documented case of stray keystones emerges for
			// forwarded payments, this check should be removed, but
			// with extreme caution.
			if strayKeystone.OutKey.ChanID != hop.Source {
				continue
			}

			log.Infof("Removing stray keystone: %v", strayKeystone)
			err := keystoneBkt.Delete(strayKeystone.OutKey.Bytes())
			if err != nil {
				return err
			}
		}

		return nil

	}, func() {
		opened = make(map[CircuitKey]*PaymentCircuit)
		pending = make(map[CircuitKey]*PaymentCircuit)
	}); err != nil {
		return err
	}

	cm.pending = pending
	cm.opened = opened
	cm.closed = make(map[CircuitKey]struct{})

	log.Infof("Payment circuits loaded: num_pending=%v, num_open=%v",
		len(pending), len(opened))

	// Finally, reconstruct the hash index by running through our set of
	// open circuits.
	cm.hashIndex = make(map[[32]byte]map[CircuitKey]struct{})
	for _, circuit := range opened {
		cm.addCircuitToHashIndex(circuit)
	}

	return nil
}

// decodeCircuit reconstructs an in-memory payment circuit from a byte slice.
// The byte slice is assumed to have been generated by the circuit's Encode
// method. If the decoding is successful, the onion obfuscator will be
// reextracted, since it is not stored in plaintext on disk.
func (cm *circuitMap) decodeCircuit(v []byte) (*PaymentCircuit, error) {
	var circuit = &PaymentCircuit{}

	circuitReader := bytes.NewReader(v)
	if err := circuit.Decode(circuitReader); err != nil {
		return nil, err
	}

	// If the error encrypter is nil, this is locally-source payment so
	// there is no encrypter.
	if circuit.ErrorEncrypter == nil {
		return circuit, nil
	}

	// Otherwise, we need to reextract the encrypter, so that the shared
	// secret is rederived from what was decoded.
	err := circuit.ErrorEncrypter.Reextract(
		cm.cfg.ExtractErrorEncrypter,
	)
	if err != nil {
		return nil, err
	}

	return circuit, nil
}

// trimAllOpenCircuits reads the set of active channels from disk and trims
// keystones for any non-pending channels using the next unallocated htlc index.
// This method is intended to be called on startup. Each link will also trim
// it's own circuits upon startup.
//
// NOTE: This operation will be applied to the persistent state of all active
// channels. Therefore, it must be called before any links are created to avoid
// interfering with normal operation.
func (cm *circuitMap) trimAllOpenCircuits() error {
	activeChannels, err := cm.cfg.DB.FetchAllOpenChannels()
	if err != nil {
		return err
	}

	for _, activeChannel := range activeChannels {
		if activeChannel.IsPending {
			continue
		}

		// First, skip any channels that have not been assigned their
		// final channel identifier, otherwise we would try to trim
		// htlcs belonging to the all-zero, hop.Source ID.
		chanID := activeChannel.ShortChanID()
		if chanID == hop.Source {
			continue
		}

		// Next, retrieve the next unallocated htlc index, which bounds
		// the cutoff of confirmed htlc indexes.
		start, err := activeChannel.NextLocalHtlcIndex()
		if err != nil {
			return err
		}

		// Finally, remove all pending circuits above at or above the
		// next unallocated local htlc indexes. This has the effect of
		// reverting any circuits that have either not been locked in,
		// or had not been included in a pending commitment.
		err = cm.TrimOpenCircuits(chanID, start)
		if err != nil {
			return err
		}
	}

	return nil
}

// TrimOpenCircuits removes a channel's keystones above the short chan id's
// highest committed htlc index. This has the effect of returning those
// circuits to a half-open state. Since opening of circuits is done in advance
// of actually committing the Add htlcs into a commitment txn, this allows
// circuits to be opened preemptively, since we can roll them back after any
// failures.
func (cm *circuitMap) TrimOpenCircuits(chanID lnwire.ShortChannelID,
	start uint64) error {

	log.Infof("Trimming open circuits for chan_id=%v, start_htlc_id=%v",
		chanID, start)

	var trimmedOutKeys []CircuitKey

	// Scan forward from the last unacked htlc id, stopping as soon as we
	// don't find any more. Outgoing htlc id's must be assigned in order,
	// so there should never be disjoint segments of keystones to trim.
	cm.mtx.Lock()
	for i := start; ; i++ {
		outKey := CircuitKey{
			ChanID: chanID,
			HtlcID: i,
		}

		circuit, ok := cm.opened[outKey]
		if !ok {
			break
		}

		circuit.Outgoing = nil
		delete(cm.opened, outKey)
		trimmedOutKeys = append(trimmedOutKeys, outKey)
		cm.removeCircuitFromHashIndex(circuit)
	}
	cm.mtx.Unlock()

	if len(trimmedOutKeys) == 0 {
		return nil
	}

	return kvdb.Update(cm.cfg.DB, func(tx kvdb.RwTx) error {
		keystoneBkt := tx.ReadWriteBucket(circuitKeystoneKey)
		if keystoneBkt == nil {
			return ErrCorruptedCircuitMap
		}

		for _, outKey := range trimmedOutKeys {
			err := keystoneBkt.Delete(outKey.Bytes())
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
}

// LookupCircuit queries the circuit map for the circuit identified by its
// incoming circuit key. Returns nil if there is no such circuit.
func (cm *circuitMap) LookupCircuit(inKey CircuitKey) *PaymentCircuit {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	return cm.pending[inKey]
}

// LookupOpenCircuit searches for the circuit identified by its outgoing circuit
// key.
func (cm *circuitMap) LookupOpenCircuit(outKey CircuitKey) *PaymentCircuit {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	return cm.opened[outKey]
}

// LookupByPaymentHash looks up and returns any payment circuits with a given
// payment hash.
func (cm *circuitMap) LookupByPaymentHash(hash [32]byte) []*PaymentCircuit {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	var circuits []*PaymentCircuit
	if circuitSet, ok := cm.hashIndex[hash]; ok {
		// Iterate over the outgoing circuit keys found with this hash,
		// and retrieve the circuit from the opened map.
		circuits = make([]*PaymentCircuit, 0, len(circuitSet))
		for key := range circuitSet {
			if circuit, ok := cm.opened[key]; ok {
				circuits = append(circuits, circuit)
			}
		}
	}

	return circuits
}

// CommitCircuits accepts any number of circuits and persistently adds them to
// the switch's circuit map. The method returns a list of circuits that had not
// been seen prior by the switch. A link should only forward HTLCs corresponding
// to the returned circuits to the switch.
//
// NOTE: This method uses batched writes to improve performance, gains will only
// be realized if it is called concurrently from separate goroutines.
func (cm *circuitMap) CommitCircuits(circuits ...*PaymentCircuit) (
	*CircuitFwdActions, error) {

	inKeys := make([]CircuitKey, 0, len(circuits))
	for _, circuit := range circuits {
		inKeys = append(inKeys, circuit.Incoming)
	}

	log.Tracef("Committing fresh circuits: %v", newLogClosure(func() string {
		return spew.Sdump(inKeys)
	}))

	actions := &CircuitFwdActions{}

	// If an empty list was passed, return early to avoid grabbing the lock.
	if len(circuits) == 0 {
		return actions, nil
	}

	// First, we reconcile the provided circuits with our set of pending
	// circuits to construct a set of new circuits that need to be written
	// to disk. The circuit's pointer is stored so that we only permit this
	// exact circuit to be forwarded through the switch. If a circuit is
	// already pending, the htlc will be reforwarded by the switch.
	//
	// NOTE: We track an additional addFails subsequence, which permits us
	// to fail back all packets that weren't dropped if we encounter an
	// error when committing the circuits.
	cm.mtx.Lock()
	var adds, drops, fails, addFails []*PaymentCircuit
	for _, circuit := range circuits {
		inKey := circuit.InKey()
		if foundCircuit, ok := cm.pending[inKey]; ok {
			switch {

			// This circuit has a keystone, it's waiting for a
			// response from the remote peer on the outgoing link.
			// Drop it like it's hot, ensure duplicates get caught.
			case foundCircuit.HasKeystone():
				drops = append(drops, circuit)

			// If no keystone is set and the switch has not been
			// restarted, the corresponding packet should still be
			// in the outgoing link's mailbox. It will be delivered
			// if it comes online before the switch goes down.
			//
			// NOTE: Dropping here prevents a flapping, incoming
			// link from failing a duplicate add while it is still
			// in the server's memory mailboxes.
			case !foundCircuit.LoadedFromDisk:
				drops = append(drops, circuit)

			// Otherwise, the in-mem packet has been lost due to a
			// restart. It is now safe to send back a failure along
			// the incoming link. The incoming link should be able
			// detect and ignore duplicate packets of this type.
			default:
				fails = append(fails, circuit)
				addFails = append(addFails, circuit)
			}

			continue
		}

		cm.pending[inKey] = circuit
		adds = append(adds, circuit)
		addFails = append(addFails, circuit)
	}
	cm.mtx.Unlock()

	// If all circuits are dropped or failed, we are done.
	if len(adds) == 0 {
		actions.Drops = drops
		actions.Fails = fails
		return actions, nil
	}

	// Now, optimistically serialize the circuits to add.
	var bs = make([]bytes.Buffer, len(adds))
	for i, circuit := range adds {
		if err := circuit.Encode(&bs[i]); err != nil {
			actions.Drops = drops
			actions.Fails = addFails
			return actions, err
		}
	}

	// Write the entire batch of circuits to the persistent circuit bucket
	// using bolt's Batch write. This method must be called from multiple,
	// distinct goroutines to have any impact on performance.
	err := kvdb.Batch(cm.cfg.DB.Backend, func(tx kvdb.RwTx) error {
		circuitBkt := tx.ReadWriteBucket(circuitAddKey)
		if circuitBkt == nil {
			return ErrCorruptedCircuitMap
		}

		for i, circuit := range adds {
			inKeyBytes := circuit.InKey().Bytes()
			circuitBytes := bs[i].Bytes()

			err := circuitBkt.Put(inKeyBytes, circuitBytes)
			if err != nil {
				return err
			}
		}

		return nil
	})

	// Return if the write succeeded.
	if err == nil {
		actions.Adds = adds
		actions.Drops = drops
		actions.Fails = fails
		return actions, nil
	}

	// Otherwise, rollback the circuits added to the pending set if the
	// write failed.
	cm.mtx.Lock()
	for _, circuit := range adds {
		delete(cm.pending, circuit.InKey())
	}
	cm.mtx.Unlock()

	// Since our write failed, we will return the dropped packets and mark
	// all other circuits as failed.
	actions.Drops = drops
	actions.Fails = addFails

	return actions, err
}

// Keystone is a tuple binding an incoming and outgoing CircuitKey. Keystones
// are preemptively written by an outgoing link before signing a new commitment
// state, and cements which HTLCs we are awaiting a response from a remote
// peer.
type Keystone struct {
	InKey  CircuitKey
	OutKey CircuitKey
}

// String returns a human readable description of the Keystone.
func (k *Keystone) String() string {
	return fmt.Sprintf("%s --> %s", k.InKey, k.OutKey)
}

// OpenCircuits sets the outgoing circuit key for the circuit identified by
// inKey, persistently marking the circuit as opened. After the changes have
// been persisted, the circuit map's in-memory indexes are updated so that this
// circuit can be queried using LookupByKeystone or LookupByPaymentHash.
func (cm *circuitMap) OpenCircuits(keystones ...Keystone) error {
	if len(keystones) == 0 {
		return nil
	}

	log.Tracef("Opening finalized circuits: %v", newLogClosure(func() string {
		return spew.Sdump(keystones)
	}))

	// Check that all keystones correspond to committed-but-unopened
	// circuits.
	cm.mtx.RLock()
	openedCircuits := make([]*PaymentCircuit, 0, len(keystones))
	for _, ks := range keystones {
		if _, ok := cm.opened[ks.OutKey]; ok {
			cm.mtx.RUnlock()
			return ErrDuplicateKeystone
		}

		circuit, ok := cm.pending[ks.InKey]
		if !ok {
			cm.mtx.RUnlock()
			return ErrUnknownCircuit
		}

		openedCircuits = append(openedCircuits, circuit)
	}
	cm.mtx.RUnlock()

	err := kvdb.Update(cm.cfg.DB, func(tx kvdb.RwTx) error {
		// Now, load the circuit bucket to which we will write the
		// already serialized circuit.
		keystoneBkt := tx.ReadWriteBucket(circuitKeystoneKey)
		if keystoneBkt == nil {
			return ErrCorruptedCircuitMap
		}

		for _, ks := range keystones {
			outBytes := ks.OutKey.Bytes()
			inBytes := ks.InKey.Bytes()
			err := keystoneBkt.Put(outBytes, inBytes)
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})

	if err != nil {
		return err
	}

	cm.mtx.Lock()
	for i, circuit := range openedCircuits {
		ks := keystones[i]

		// Since our persistent operation was successful, we can now
		// modify the in memory representations. Set the outgoing
		// circuit key on our pending circuit, add the same circuit to
		// set of opened circuits, and add this circuit to the hash
		// index.
		circuit.Outgoing = &CircuitKey{}
		*circuit.Outgoing = ks.OutKey

		cm.opened[ks.OutKey] = circuit
		cm.addCircuitToHashIndex(circuit)
	}
	cm.mtx.Unlock()

	return nil
}

// addCirciutToHashIndex inserts a circuit into the circuit map's hash index, so
// that it can be queried using LookupByPaymentHash.
func (cm *circuitMap) addCircuitToHashIndex(c *PaymentCircuit) {
	if _, ok := cm.hashIndex[c.PaymentHash]; !ok {
		cm.hashIndex[c.PaymentHash] = make(map[CircuitKey]struct{})
	}
	cm.hashIndex[c.PaymentHash][c.OutKey()] = struct{}{}
}

// FailCircuit marks the circuit identified by `inKey` as closing in-memory,
// which prevents duplicate settles/fails from completing an open circuit twice.
func (cm *circuitMap) FailCircuit(inKey CircuitKey) (*PaymentCircuit, error) {

	cm.mtx.Lock()
	defer cm.mtx.Unlock()

	circuit, ok := cm.pending[inKey]
	if !ok {
		return nil, ErrUnknownCircuit
	}

	_, ok = cm.closed[inKey]
	if ok {
		return nil, ErrCircuitClosing
	}

	cm.closed[inKey] = struct{}{}

	return circuit, nil
}

// CloseCircuit marks the circuit identified by `outKey` as closing in-memory,
// which prevents duplicate settles/fails from completing an open
// circuit twice.
func (cm *circuitMap) CloseCircuit(outKey CircuitKey) (*PaymentCircuit, error) {

	cm.mtx.Lock()
	defer cm.mtx.Unlock()

	circuit, ok := cm.opened[outKey]
	if !ok {
		return nil, ErrUnknownCircuit
	}

	_, ok = cm.closed[circuit.Incoming]
	if ok {
		return nil, ErrCircuitClosing
	}

	cm.closed[circuit.Incoming] = struct{}{}

	return circuit, nil
}

// DeleteCircuits destroys the target circuits by removing them from the circuit
// map, additionally removing the circuits' keystones if any HTLCs were
// forwarded through an outgoing link. The circuits should be identified by its
// incoming circuit key. If a given circuit is not found in the circuit map, it
// will be ignored from the query. This would typically indicate that the
// circuit was already cleaned up at a different point in time.
func (cm *circuitMap) DeleteCircuits(inKeys ...CircuitKey) error {

	log.Tracef("Deleting resolved circuits: %v", newLogClosure(func() string {
		return spew.Sdump(inKeys)
	}))

	var (
		closingCircuits = make(map[CircuitKey]struct{})
		removedCircuits = make(map[CircuitKey]*PaymentCircuit)
	)

	cm.mtx.Lock()
	// Remove any references to the circuits from memory, keeping track of
	// which circuits were removed, and which ones had been marked closed.
	// This can be used to restore these entries later if the persistent
	// removal fails.
	for _, inKey := range inKeys {
		circuit, ok := cm.pending[inKey]
		if !ok {
			continue
		}
		delete(cm.pending, inKey)

		if _, ok := cm.closed[inKey]; ok {
			closingCircuits[inKey] = struct{}{}
			delete(cm.closed, inKey)
		}

		if circuit.HasKeystone() {
			delete(cm.opened, circuit.OutKey())
			cm.removeCircuitFromHashIndex(circuit)
		}

		removedCircuits[inKey] = circuit
	}
	cm.mtx.Unlock()

	err := kvdb.Batch(cm.cfg.DB.Backend, func(tx kvdb.RwTx) error {
		for _, circuit := range removedCircuits {
			// If this htlc made it to an outgoing link, load the
			// keystone bucket from which we will remove the
			// outgoing circuit key.
			if circuit.HasKeystone() {
				keystoneBkt := tx.ReadWriteBucket(circuitKeystoneKey)
				if keystoneBkt == nil {
					return ErrCorruptedCircuitMap
				}

				outKey := circuit.OutKey()

				err := keystoneBkt.Delete(outKey.Bytes())
				if err != nil {
					return err
				}
			}

			// Remove the circuit itself based on the incoming
			// circuit key.
			circuitBkt := tx.ReadWriteBucket(circuitAddKey)
			if circuitBkt == nil {
				return ErrCorruptedCircuitMap
			}

			inKey := circuit.InKey()
			if err := circuitBkt.Delete(inKey.Bytes()); err != nil {
				return err
			}
		}

		return nil
	})

	// Return if the write succeeded.
	if err == nil {
		return nil
	}

	// If the persistent changes failed, restore the circuit map to it's
	// previous state.
	cm.mtx.Lock()
	for inKey, circuit := range removedCircuits {
		cm.pending[inKey] = circuit

		if _, ok := closingCircuits[inKey]; ok {
			cm.closed[inKey] = struct{}{}
		}

		if circuit.HasKeystone() {
			cm.opened[circuit.OutKey()] = circuit
			cm.addCircuitToHashIndex(circuit)
		}
	}
	cm.mtx.Unlock()

	return err
}

// removeCircuitFromHashIndex removes the given circuit from the hash index,
// pruning any unnecessary memory optimistically.
func (cm *circuitMap) removeCircuitFromHashIndex(c *PaymentCircuit) {
	// Locate bucket containing this circuit's payment hashes.
	circuitsWithHash, ok := cm.hashIndex[c.PaymentHash]
	if !ok {
		return
	}

	outKey := c.OutKey()

	// Remove this circuit from the set of circuitsWithHash.
	delete(circuitsWithHash, outKey)

	// Prune the payment hash bucket if no other entries remain.
	if len(circuitsWithHash) == 0 {
		delete(cm.hashIndex, c.PaymentHash)
	}
}

// NumPending returns the number of active circuits added to the circuit map.
func (cm *circuitMap) NumPending() int {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	return len(cm.pending)
}

// NumOpen returns the number of circuits that have been opened by way of
// setting their keystones. This is the number of HTLCs that are waiting for a
// settle/fail response from a remote peer.
func (cm *circuitMap) NumOpen() int {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	return len(cm.opened)
}
