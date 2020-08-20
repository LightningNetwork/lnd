package channeldb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
)

// ErrCorruptedFwdPkg signals that the on-disk structure of the forwarding
// package has potentially been mangled.
var ErrCorruptedFwdPkg = errors.New("fwding package db has been corrupted")

// FwdState is an enum used to describe the lifecycle of a FwdPkg.
type FwdState byte

const (
	// FwdStateLockedIn is the starting state for all forwarding packages.
	// Packages in this state have not yet committed to the exact set of
	// Adds to forward to the switch.
	FwdStateLockedIn FwdState = iota

	// FwdStateProcessed marks the state in which all Adds have been
	// locally processed and the forwarding decision to the switch has been
	// persisted.
	FwdStateProcessed

	// FwdStateCompleted signals that all Adds have been acked, and that all
	// settles and fails have been delivered to their sources. Packages in
	// this state can be removed permanently.
	FwdStateCompleted
)

var (
	// fwdPackagesKey is the root-level bucket that all forwarding packages
	// are written. This bucket is further subdivided based on the channel
	// ID of each channel.
	fwdPackagesKey = []byte("fwd-packages")

	// addBucketKey is the bucket to which all Add log updates are written.
	addBucketKey = []byte("add-updates")

	// failSettleBucketKey is the bucket to which all Settle/Fail log
	// updates are written.
	failSettleBucketKey = []byte("fail-settle-updates")

	// fwdFilterKey is a key used to write the set of Adds that passed
	// validation and are to be forwarded to the switch.
	// NOTE: The presence of this key within a forwarding package indicates
	// that the package has reached FwdStateProcessed.
	fwdFilterKey = []byte("fwd-filter-key")

	// ackFilterKey is a key used to access the PkgFilter indicating which
	// Adds have received a Settle/Fail. This response may come from a
	// number of sources, including: exitHop settle/fails, switch failures,
	// chain arbiter interjections, as well as settle/fails from the
	// next hop in the route.
	ackFilterKey = []byte("ack-filter-key")

	// settleFailFilterKey is a key used to access the PkgFilter indicating
	// which Settles/Fails in have been received and processed by the link
	// that originally received the Add.
	settleFailFilterKey = []byte("settle-fail-filter-key")
)

// PkgFilter is used to compactly represent a particular subset of the Adds in a
// forwarding package. Each filter is represented as a simple, statically-sized
// bitvector, where the elements are intended to be the indices of the Adds as
// they are written in the FwdPkg.
type PkgFilter struct {
	count  uint16
	filter []byte
}

// NewPkgFilter initializes an empty PkgFilter supporting `count` elements.
func NewPkgFilter(count uint16) *PkgFilter {
	// We add 7 to ensure that the integer division yields properly rounded
	// values.
	filterLen := (count + 7) / 8

	return &PkgFilter{
		count:  count,
		filter: make([]byte, filterLen),
	}
}

// Count returns the number of elements represented by this PkgFilter.
func (f *PkgFilter) Count() uint16 {
	return f.count
}

// Set marks the `i`-th element as included by this filter.
// NOTE: It is assumed that i is always less than count.
func (f *PkgFilter) Set(i uint16) {
	byt := i / 8
	bit := i % 8

	// Set the i-th bit in the filter.
	// TODO(conner): ignore if > count to prevent panic?
	f.filter[byt] |= byte(1 << (7 - bit))
}

// Contains queries the filter for membership of index `i`.
// NOTE: It is assumed that i is always less than count.
func (f *PkgFilter) Contains(i uint16) bool {
	byt := i / 8
	bit := i % 8

	// Read the i-th bit in the filter.
	// TODO(conner): ignore if > count to prevent panic?
	return f.filter[byt]&(1<<(7-bit)) != 0
}

// Equal checks two PkgFilters for equality.
func (f *PkgFilter) Equal(f2 *PkgFilter) bool {
	if f == f2 {
		return true
	}
	if f.count != f2.count {
		return false
	}

	return bytes.Equal(f.filter, f2.filter)
}

// IsFull returns true if every element in the filter has been Set, and false
// otherwise.
func (f *PkgFilter) IsFull() bool {
	// Batch validate bytes that are fully used.
	for i := uint16(0); i < f.count/8; i++ {
		if f.filter[i] != 0xFF {
			return false
		}
	}

	// If the count is not a multiple of 8, check that the filter contains
	// all remaining bits.
	rem := f.count % 8
	for idx := f.count - rem; idx < f.count; idx++ {
		if !f.Contains(idx) {
			return false
		}
	}

	return true
}

// Size returns number of bytes produced when the PkgFilter is serialized.
func (f *PkgFilter) Size() uint16 {
	// 2 bytes for uint16 `count`, then round up number of bytes required to
	// represent `count` bits.
	return 2 + (f.count+7)/8
}

// Encode writes the filter to the provided io.Writer.
func (f *PkgFilter) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, f.count); err != nil {
		return err
	}

	_, err := w.Write(f.filter)

	return err
}

// Decode reads the filter from the provided io.Reader.
func (f *PkgFilter) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &f.count); err != nil {
		return err
	}

	f.filter = make([]byte, f.Size()-2)
	_, err := io.ReadFull(r, f.filter)

	return err
}

// FwdPkg records all adds, settles, and fails that were locked in as a result
// of the remote peer sending us a revocation. Each package is identified by
// the channel id and remote commitment height corresponding to the revocation
// that locked in the HTLCs. For everything except a locally initiated payment,
// settles and fails in a forwarding package must have a corresponding Add in
// another package, and can be removed individually once the source link has
// received the fail/settle.
//
// Adds cannot be removed, as we need to present the same batch of Adds to
// properly handle replay protection. Instead, we use a PkgFilter to mark that
// we have finished processing a particular Add. A FwdPkg should only be deleted
// after the AckFilter is full and all settles and fails have been persistently
// removed.
type FwdPkg struct {
	// Source identifies the channel that wrote this forwarding package.
	Source lnwire.ChannelID

	// Height is the height of the remote commitment chain that locked in
	// this forwarding package.
	Height uint64

	// State signals the persistent condition of the package and directs how
	// to reprocess the package in the event of failures.
	State FwdState

	// Adds contains all add messages which need to be processed and
	// forwarded to the switch. Adds does not change over the life of a
	// forwarding package.
	Adds []LogUpdate

	// FwdFilter is a filter containing the indices of all Adds that were
	// forwarded to the switch.
	FwdFilter *PkgFilter

	// AckFilter is a filter containing the indices of all Adds for which
	// the source has received a settle or fail and is reflected in the next
	// commitment txn. A package should not be removed until IsFull()
	// returns true.
	AckFilter *PkgFilter

	// SettleFails contains all settle and fail messages that should be
	// forwarded to the switch.
	SettleFails []LogUpdate

	// SettleFailFilter is a filter containing the indices of all Settle or
	// Fails originating in this package that have been received and locked
	// into the incoming link's commitment state.
	SettleFailFilter *PkgFilter
}

// NewFwdPkg initializes a new forwarding package in FwdStateLockedIn. This
// should be used to create a package at the time we receive a revocation.
func NewFwdPkg(source lnwire.ChannelID, height uint64,
	addUpdates, settleFailUpdates []LogUpdate) *FwdPkg {

	nAddUpdates := uint16(len(addUpdates))
	nSettleFailUpdates := uint16(len(settleFailUpdates))

	return &FwdPkg{
		Source:           source,
		Height:           height,
		State:            FwdStateLockedIn,
		Adds:             addUpdates,
		FwdFilter:        NewPkgFilter(nAddUpdates),
		AckFilter:        NewPkgFilter(nAddUpdates),
		SettleFails:      settleFailUpdates,
		SettleFailFilter: NewPkgFilter(nSettleFailUpdates),
	}
}

// ID returns an unique identifier for this package, used to ensure that sphinx
// replay processing of this batch is idempotent.
func (f *FwdPkg) ID() []byte {
	var id = make([]byte, 38)
	copy(id[:32], f.Source[:])
	byteOrder.PutUint64(id[8:], f.Height)
	return id
}

// String returns a human-readable description of the forwarding package.
func (f *FwdPkg) String() string {
	return fmt.Sprintf("%T(src=%v, height=%v, nadds=%v, nfailsettles=%v)",
		f, f.Source, f.Height, len(f.Adds), len(f.SettleFails))
}

// AddRef is used to identify a particular Add in a FwdPkg. The channel ID
// is assumed to be that of the packager.
type AddRef struct {
	// Height is the remote commitment height that locked in the Add.
	Height uint64

	// Index is the index of the Add within the fwd pkg's Adds.
	//
	// NOTE: This index is static over the lifetime of a forwarding package.
	Index uint16
}

// Encode serializes the AddRef to the given io.Writer.
func (a *AddRef) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, a.Height); err != nil {
		return err
	}

	return binary.Write(w, binary.BigEndian, a.Index)
}

// Decode deserializes the AddRef from the given io.Reader.
func (a *AddRef) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &a.Height); err != nil {
		return err
	}

	return binary.Read(r, binary.BigEndian, &a.Index)
}

// SettleFailRef is used to locate a Settle/Fail in another channel's FwdPkg. A
// channel does not remove its own Settle/Fail htlcs, so the source is provided
// to locate a db bucket belonging to another channel.
type SettleFailRef struct {
	// Source identifies the outgoing link that locked in the settle or
	// fail. This is then used by the *incoming* link to find the settle
	// fail in another link's forwarding packages.
	Source lnwire.ChannelID

	// Height is the remote commitment height that locked in this
	// Settle/Fail.
	Height uint64

	// Index is the index of the Add with the fwd pkg's SettleFails.
	//
	// NOTE: This index is static over the lifetime of a forwarding package.
	Index uint16
}

// SettleFailAcker is a generic interface providing the ability to acknowledge
// settle/fail HTLCs stored in forwarding packages.
type SettleFailAcker interface {
	// AckSettleFails atomically updates the settle-fail filters in *other*
	// channels' forwarding packages.
	AckSettleFails(tx kvdb.RwTx, settleFailRefs ...SettleFailRef) error
}

// GlobalFwdPkgReader is an interface used to retrieve the forwarding packages
// of any active channel.
type GlobalFwdPkgReader interface {
	// LoadChannelFwdPkgs loads all known forwarding packages for the given
	// channel.
	LoadChannelFwdPkgs(tx kvdb.RwTx,
		source lnwire.ChannelID) ([]*FwdPkg, error)
}

// FwdOperator defines the interfaces for managing forwarding packages that are
// external to a particular channel. This interface is used by the switch to
// read forwarding packages from arbitrary channels, and acknowledge settles and
// fails for locally-sourced payments.
type FwdOperator interface {
	// GlobalFwdPkgReader provides read access to all known forwarding
	// packages
	GlobalFwdPkgReader

	// SettleFailAcker grants the ability to acknowledge settles or fails
	// residing in arbitrary forwarding packages.
	SettleFailAcker
}

// SwitchPackager is a concrete implementation of the FwdOperator interface.
// A SwitchPackager offers the ability to read any forwarding package, and ack
// arbitrary settle and fail HTLCs.
type SwitchPackager struct{}

// NewSwitchPackager instantiates a new SwitchPackager.
func NewSwitchPackager() *SwitchPackager {
	return &SwitchPackager{}
}

// AckSettleFails atomically updates the settle-fail filters in *other*
// channels' forwarding packages, to mark that the switch has received a settle
// or fail residing in the forwarding package of a link.
func (*SwitchPackager) AckSettleFails(tx kvdb.RwTx,
	settleFailRefs ...SettleFailRef) error {

	return ackSettleFails(tx, settleFailRefs)
}

// LoadChannelFwdPkgs loads all forwarding packages for a particular channel.
func (*SwitchPackager) LoadChannelFwdPkgs(tx kvdb.RwTx,
	source lnwire.ChannelID) ([]*FwdPkg, error) {

	return loadChannelFwdPkgs(tx, source)
}

// FwdPackager supports all operations required to modify fwd packages, such as
// creation, updates, reading, and removal. The interfaces are broken down in
// this way to support future delegation of the subinterfaces.
type FwdPackager interface {
	// AddFwdPkg serializes and writes a FwdPkg for this channel at the
	// remote commitment height included in the forwarding package.
	AddFwdPkg(tx kvdb.RwTx, fwdPkg *FwdPkg) error

	// SetFwdFilter looks up the forwarding package at the remote `height`
	// and sets the `fwdFilter`, marking the Adds for which:
	// 1) We are not the exit node
	// 2) Passed all validation
	// 3) Should be forwarded to the switch immediately after a failure
	SetFwdFilter(tx kvdb.RwTx, height uint64, fwdFilter *PkgFilter) error

	// AckAddHtlcs atomically updates the add filters in this channel's
	// forwarding packages to mark the resolution of an Add that was
	// received from the remote party.
	AckAddHtlcs(tx kvdb.RwTx, addRefs ...AddRef) error

	// SettleFailAcker allows a link to acknowledge settle/fail HTLCs
	// belonging to other channels.
	SettleFailAcker

	// LoadFwdPkgs loads all known forwarding packages owned by this
	// channel.
	LoadFwdPkgs(tx kvdb.RTx) ([]*FwdPkg, error)

	// RemovePkg deletes a forwarding package owned by this channel at
	// the provided remote `height`.
	RemovePkg(tx kvdb.RwTx, height uint64) error
}

// ChannelPackager is used by a channel to manage the lifecycle of its forwarding
// packages. The packager is tied to a particular source channel ID, allowing it
// to create and edit its own packages. Each packager also has the ability to
// remove fail/settle htlcs that correspond to an add contained in one of
// source's packages.
type ChannelPackager struct {
	source lnwire.ChannelID
}

// NewChannelPackager creates a new packager for a single channel.
func NewChannelPackager(source lnwire.ChannelID) *ChannelPackager {
	return &ChannelPackager{
		source: source,
	}
}

// AddFwdPkg writes a newly locked in forwarding package to disk.
func (*ChannelPackager) AddFwdPkg(tx kvdb.RwTx, fwdPkg *FwdPkg) error {
	fwdPkgBkt, err := tx.CreateTopLevelBucket(fwdPackagesKey)
	if err != nil {
		return err
	}

	sourceBkt, err := fwdPkgBkt.CreateBucketIfNotExists(fwdPkg.Source[:])
	if err != nil {
		return err
	}

	heightKey := makeLogKey(fwdPkg.Height)
	heightBkt, err := sourceBkt.CreateBucketIfNotExists(heightKey[:])
	if err != nil {
		return err
	}

	// Write ADD updates we received at this commit height.
	addBkt, err := heightBkt.CreateBucketIfNotExists(addBucketKey)
	if err != nil {
		return err
	}

	// Write SETTLE/FAIL updates we received at this commit height.
	failSettleBkt, err := heightBkt.CreateBucketIfNotExists(failSettleBucketKey)
	if err != nil {
		return err
	}

	for i := range fwdPkg.Adds {
		err = putLogUpdate(addBkt, uint16(i), &fwdPkg.Adds[i])
		if err != nil {
			return err
		}
	}

	// Persist the initialized pkg filter, which will be used to determine
	// when we can remove this forwarding package from disk.
	var ackFilterBuf bytes.Buffer
	if err := fwdPkg.AckFilter.Encode(&ackFilterBuf); err != nil {
		return err
	}

	if err := heightBkt.Put(ackFilterKey, ackFilterBuf.Bytes()); err != nil {
		return err
	}

	for i := range fwdPkg.SettleFails {
		err = putLogUpdate(failSettleBkt, uint16(i), &fwdPkg.SettleFails[i])
		if err != nil {
			return err
		}
	}

	var settleFailFilterBuf bytes.Buffer
	err = fwdPkg.SettleFailFilter.Encode(&settleFailFilterBuf)
	if err != nil {
		return err
	}

	return heightBkt.Put(settleFailFilterKey, settleFailFilterBuf.Bytes())
}

// putLogUpdate writes an htlc to the provided `bkt`, using `index` as the key.
func putLogUpdate(bkt kvdb.RwBucket, idx uint16, htlc *LogUpdate) error {
	var b bytes.Buffer
	if err := htlc.Encode(&b); err != nil {
		return err
	}

	return bkt.Put(uint16Key(idx), b.Bytes())
}

// LoadFwdPkgs scans the forwarding log for any packages that haven't been
// processed, and returns their deserialized log updates in a map indexed by the
// remote commitment height at which the updates were locked in.
func (p *ChannelPackager) LoadFwdPkgs(tx kvdb.RTx) ([]*FwdPkg, error) {
	return loadChannelFwdPkgs(tx, p.source)
}

// loadChannelFwdPkgs loads all forwarding packages owned by `source`.
func loadChannelFwdPkgs(tx kvdb.RTx, source lnwire.ChannelID) ([]*FwdPkg, error) {
	fwdPkgBkt := tx.ReadBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil, nil
	}

	sourceBkt := fwdPkgBkt.NestedReadBucket(source[:])
	if sourceBkt == nil {
		return nil, nil
	}

	var heights []uint64
	if err := sourceBkt.ForEach(func(k, _ []byte) error {
		if len(k) != 8 {
			return ErrCorruptedFwdPkg
		}

		heights = append(heights, byteOrder.Uint64(k))

		return nil
	}); err != nil {
		return nil, err
	}

	// Load the forwarding package for each retrieved height.
	fwdPkgs := make([]*FwdPkg, 0, len(heights))
	for _, height := range heights {
		fwdPkg, err := loadFwdPkg(fwdPkgBkt, source, height)
		if err != nil {
			return nil, err
		}

		fwdPkgs = append(fwdPkgs, fwdPkg)
	}

	return fwdPkgs, nil
}

// loadFwPkg reads the packager's fwd pkg at a given height, and determines the
// appropriate FwdState.
func loadFwdPkg(fwdPkgBkt kvdb.RBucket, source lnwire.ChannelID,
	height uint64) (*FwdPkg, error) {

	sourceBkt := fwdPkgBkt.NestedReadBucket(source[:])
	if sourceBkt == nil {
		return nil, ErrCorruptedFwdPkg
	}

	heightKey := makeLogKey(height)
	heightBkt := sourceBkt.NestedReadBucket(heightKey[:])
	if heightBkt == nil {
		return nil, ErrCorruptedFwdPkg
	}

	// Load ADDs from disk.
	addBkt := heightBkt.NestedReadBucket(addBucketKey)
	if addBkt == nil {
		return nil, ErrCorruptedFwdPkg
	}

	adds, err := loadHtlcs(addBkt)
	if err != nil {
		return nil, err
	}

	// Load ack filter from disk.
	ackFilterBytes := heightBkt.Get(ackFilterKey)
	if ackFilterBytes == nil {
		return nil, ErrCorruptedFwdPkg
	}
	ackFilterReader := bytes.NewReader(ackFilterBytes)

	ackFilter := &PkgFilter{}
	if err := ackFilter.Decode(ackFilterReader); err != nil {
		return nil, err
	}

	// Load SETTLE/FAILs from disk.
	failSettleBkt := heightBkt.NestedReadBucket(failSettleBucketKey)
	if failSettleBkt == nil {
		return nil, ErrCorruptedFwdPkg
	}

	failSettles, err := loadHtlcs(failSettleBkt)
	if err != nil {
		return nil, err
	}

	// Load settle fail filter from disk.
	settleFailFilterBytes := heightBkt.Get(settleFailFilterKey)
	if settleFailFilterBytes == nil {
		return nil, ErrCorruptedFwdPkg
	}
	settleFailFilterReader := bytes.NewReader(settleFailFilterBytes)

	settleFailFilter := &PkgFilter{}
	if err := settleFailFilter.Decode(settleFailFilterReader); err != nil {
		return nil, err
	}

	// Initialize the fwding package, which always starts in the
	// FwdStateLockedIn. We can determine what state the package was left in
	// by examining constraints on the information loaded from disk.
	fwdPkg := &FwdPkg{
		Source:           source,
		State:            FwdStateLockedIn,
		Height:           height,
		Adds:             adds,
		AckFilter:        ackFilter,
		SettleFails:      failSettles,
		SettleFailFilter: settleFailFilter,
	}

	// Check to see if we have written the set exported filter adds to
	// disk. If we haven't, processing of this package was never started, or
	// failed during the last attempt.
	fwdFilterBytes := heightBkt.Get(fwdFilterKey)
	if fwdFilterBytes == nil {
		nAdds := uint16(len(adds))
		fwdPkg.FwdFilter = NewPkgFilter(nAdds)
		return fwdPkg, nil
	}

	fwdFilterReader := bytes.NewReader(fwdFilterBytes)
	fwdPkg.FwdFilter = &PkgFilter{}
	if err := fwdPkg.FwdFilter.Decode(fwdFilterReader); err != nil {
		return nil, err
	}

	// Otherwise, a complete round of processing was completed, and we
	// advance the package to FwdStateProcessed.
	fwdPkg.State = FwdStateProcessed

	// If every add, settle, and fail has been fully acknowledged, we can
	// safely set the package's state to FwdStateCompleted, signalling that
	// it can be garbage collected.
	if fwdPkg.AckFilter.IsFull() && fwdPkg.SettleFailFilter.IsFull() {
		fwdPkg.State = FwdStateCompleted
	}

	return fwdPkg, nil
}

// loadHtlcs retrieves all serialized htlcs in a bucket, returning
// them in order of the indexes they were written under.
func loadHtlcs(bkt kvdb.RBucket) ([]LogUpdate, error) {
	var htlcs []LogUpdate
	if err := bkt.ForEach(func(_, v []byte) error {
		var htlc LogUpdate
		if err := htlc.Decode(bytes.NewReader(v)); err != nil {
			return err
		}

		htlcs = append(htlcs, htlc)

		return nil
	}); err != nil {
		return nil, err
	}

	return htlcs, nil
}

// SetFwdFilter writes the set of indexes corresponding to Adds at the
// `height` that are to be forwarded to the switch. Calling this method causes
// the forwarding package at `height` to be in FwdStateProcessed. We write this
// forwarding decision so that we always arrive at the same behavior for HTLCs
// leaving this channel. After a restart, we skip validation of these Adds,
// since they are assumed to have already been validated, and make the switch or
// outgoing link responsible for handling replays.
func (p *ChannelPackager) SetFwdFilter(tx kvdb.RwTx, height uint64,
	fwdFilter *PkgFilter) error {

	fwdPkgBkt := tx.ReadWriteBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return ErrCorruptedFwdPkg
	}

	sourceBkt := fwdPkgBkt.NestedReadWriteBucket(p.source[:])
	if sourceBkt == nil {
		return ErrCorruptedFwdPkg
	}

	heightKey := makeLogKey(height)
	heightBkt := sourceBkt.NestedReadWriteBucket(heightKey[:])
	if heightBkt == nil {
		return ErrCorruptedFwdPkg
	}

	// If the fwd filter has already been written, we return early to avoid
	// modifying the persistent state.
	forwardedAddsBytes := heightBkt.Get(fwdFilterKey)
	if forwardedAddsBytes != nil {
		return nil
	}

	// Otherwise we serialize and write the provided fwd filter.
	var b bytes.Buffer
	if err := fwdFilter.Encode(&b); err != nil {
		return err
	}

	return heightBkt.Put(fwdFilterKey, b.Bytes())
}

// AckAddHtlcs accepts a list of references to add htlcs, and updates the
// AckAddFilter of those forwarding packages to indicate that a settle or fail
// has been received in response to the add.
func (p *ChannelPackager) AckAddHtlcs(tx kvdb.RwTx, addRefs ...AddRef) error {
	if len(addRefs) == 0 {
		return nil
	}

	fwdPkgBkt := tx.ReadWriteBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return ErrCorruptedFwdPkg
	}

	sourceBkt := fwdPkgBkt.NestedReadWriteBucket(p.source[:])
	if sourceBkt == nil {
		return ErrCorruptedFwdPkg
	}

	// Organize the forward references such that we just get a single slice
	// of indexes for each unique height.
	heightDiffs := make(map[uint64][]uint16)
	for _, addRef := range addRefs {
		heightDiffs[addRef.Height] = append(
			heightDiffs[addRef.Height],
			addRef.Index,
		)
	}

	// Load each height bucket once and remove all acked htlcs at that
	// height.
	for height, indexes := range heightDiffs {
		err := ackAddHtlcsAtHeight(sourceBkt, height, indexes)
		if err != nil {
			return err
		}
	}

	return nil
}

// ackAddHtlcsAtHeight updates the AddAckFilter of a single forwarding package
// with a list of indexes, writing the resulting filter back in its place.
func ackAddHtlcsAtHeight(sourceBkt kvdb.RwBucket, height uint64,
	indexes []uint16) error {

	heightKey := makeLogKey(height)
	heightBkt := sourceBkt.NestedReadWriteBucket(heightKey[:])
	if heightBkt == nil {
		// If the height bucket isn't found, this could be because the
		// forwarding package was already removed. We'll return nil to
		// signal that the operation is successful, as there is nothing
		// to ack.
		return nil
	}

	// Load ack filter from disk.
	ackFilterBytes := heightBkt.Get(ackFilterKey)
	if ackFilterBytes == nil {
		return ErrCorruptedFwdPkg
	}

	ackFilter := &PkgFilter{}
	ackFilterReader := bytes.NewReader(ackFilterBytes)
	if err := ackFilter.Decode(ackFilterReader); err != nil {
		return err
	}

	// Update the ack filter for this height.
	for _, index := range indexes {
		ackFilter.Set(index)
	}

	// Write the resulting filter to disk.
	var ackFilterBuf bytes.Buffer
	if err := ackFilter.Encode(&ackFilterBuf); err != nil {
		return err
	}

	return heightBkt.Put(ackFilterKey, ackFilterBuf.Bytes())
}

// AckSettleFails persistently acknowledges settles or fails from a remote forwarding
// package. This should only be called after the source of the Add has locked in
// the settle/fail, or it becomes otherwise safe to forgo retransmitting the
// settle/fail after a restart.
func (p *ChannelPackager) AckSettleFails(tx kvdb.RwTx, settleFailRefs ...SettleFailRef) error {
	return ackSettleFails(tx, settleFailRefs)
}

// ackSettleFails persistently acknowledges a batch of settle fail references.
func ackSettleFails(tx kvdb.RwTx, settleFailRefs []SettleFailRef) error {
	if len(settleFailRefs) == 0 {
		return nil
	}

	fwdPkgBkt := tx.ReadWriteBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return ErrCorruptedFwdPkg
	}

	// Organize the forward references such that we just get a single slice
	// of indexes for each unique destination-height pair.
	destHeightDiffs := make(map[lnwire.ChannelID]map[uint64][]uint16)
	for _, settleFailRef := range settleFailRefs {
		destHeights, ok := destHeightDiffs[settleFailRef.Source]
		if !ok {
			destHeights = make(map[uint64][]uint16)
			destHeightDiffs[settleFailRef.Source] = destHeights
		}

		destHeights[settleFailRef.Height] = append(
			destHeights[settleFailRef.Height],
			settleFailRef.Index,
		)
	}

	// With the references organized by destination and height, we now load
	// each remote bucket, and update the settle fail filter for any
	// settle/fail htlcs.
	for dest, destHeights := range destHeightDiffs {
		destBkt := fwdPkgBkt.NestedReadWriteBucket(dest[:])
		if destBkt == nil {
			// If the destination bucket is not found, this is
			// likely the result of the destination channel being
			// closed and having it's forwarding packages wiped. We
			// won't treat this as an error, because the response
			// will no longer be retransmitted internally.
			continue
		}

		for height, indexes := range destHeights {
			err := ackSettleFailsAtHeight(destBkt, height, indexes)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ackSettleFailsAtHeight given a destination bucket, acks the provided indexes
// at particular a height by updating the settle fail filter.
func ackSettleFailsAtHeight(destBkt kvdb.RwBucket, height uint64,
	indexes []uint16) error {

	heightKey := makeLogKey(height)
	heightBkt := destBkt.NestedReadWriteBucket(heightKey[:])
	if heightBkt == nil {
		// If the height bucket isn't found, this could be because the
		// forwarding package was already removed. We'll return nil to
		// signal that the operation is as there is nothing to ack.
		return nil
	}

	// Load ack filter from disk.
	settleFailFilterBytes := heightBkt.Get(settleFailFilterKey)
	if settleFailFilterBytes == nil {
		return ErrCorruptedFwdPkg
	}

	settleFailFilter := &PkgFilter{}
	settleFailFilterReader := bytes.NewReader(settleFailFilterBytes)
	if err := settleFailFilter.Decode(settleFailFilterReader); err != nil {
		return err
	}

	// Update the ack filter for this height.
	for _, index := range indexes {
		settleFailFilter.Set(index)
	}

	// Write the resulting filter to disk.
	var settleFailFilterBuf bytes.Buffer
	if err := settleFailFilter.Encode(&settleFailFilterBuf); err != nil {
		return err
	}

	return heightBkt.Put(settleFailFilterKey, settleFailFilterBuf.Bytes())
}

// RemovePkg deletes the forwarding package at the given height from the
// packager's source bucket.
func (p *ChannelPackager) RemovePkg(tx kvdb.RwTx, height uint64) error {
	fwdPkgBkt := tx.ReadWriteBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil
	}

	sourceBkt := fwdPkgBkt.NestedReadWriteBucket(p.source[:])
	if sourceBkt == nil {
		return ErrCorruptedFwdPkg
	}

	heightKey := makeLogKey(height)

	return sourceBkt.DeleteNestedBucket(heightKey[:])
}

// uint16Key writes the provided 16-bit unsigned integer to a 2-byte slice.
func uint16Key(i uint16) []byte {
	key := make([]byte, 2)
	byteOrder.PutUint16(key, i)
	return key
}

// Compile-time constraint to ensure that ChannelPackager implements the public
// FwdPackager interface.
var _ FwdPackager = (*ChannelPackager)(nil)

// Compile-time constraint to ensure that SwitchPackager implements the public
// FwdOperator interface.
var _ FwdOperator = (*SwitchPackager)(nil)
