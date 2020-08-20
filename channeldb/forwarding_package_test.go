package channeldb_test

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
)

// TestPkgFilterBruteForce tests the behavior of a pkg filter up to size 1000,
// which is greater than the number of HTLCs we permit on a commitment txn.
// This should encapsulate every potential filter used in practice.
func TestPkgFilterBruteForce(t *testing.T) {
	t.Parallel()

	checkPkgFilterRange(t, 1000)
}

// checkPkgFilterRange verifies the behavior of a pkg filter when doing a linear
// insertion of `high` elements. This is primarily to test that IsFull functions
// properly for all relevant sizes of `high`.
func checkPkgFilterRange(t *testing.T, high int) {
	for i := uint16(0); i < uint16(high); i++ {
		f := channeldb.NewPkgFilter(i)

		if f.Count() != i {
			t.Fatalf("pkg filter count=%d is actually %d",
				i, f.Count())
		}
		checkPkgFilterEncodeDecode(t, i, f)

		for j := uint16(0); j < i; j++ {
			if f.Contains(j) {
				t.Fatalf("pkg filter count=%d contains %d "+
					"before being added", i, j)
			}

			f.Set(j)
			checkPkgFilterEncodeDecode(t, i, f)

			if !f.Contains(j) {
				t.Fatalf("pkg filter count=%d missing %d "+
					"after being added", i, j)
			}

			if j < i-1 && f.IsFull() {
				t.Fatalf("pkg filter count=%d already full", i)
			}
		}

		if !f.IsFull() {
			t.Fatalf("pkg filter count=%d not full", i)
		}
		checkPkgFilterEncodeDecode(t, i, f)
	}
}

// TestPkgFilterRand uses a random permutation to verify the proper behavior of
// the pkg filter if the entries are not inserted in-order.
func TestPkgFilterRand(t *testing.T) {
	t.Parallel()

	checkPkgFilterRand(t, 3, 17)
}

// checkPkgFilterRand checks the behavior of a pkg filter by randomly inserting
// indices and asserting the invariants. The order in which indices are inserted
// is parameterized by a base `b` coprime to `p`, and using modular
// exponentiation to generate all elements in [1,p).
func checkPkgFilterRand(t *testing.T, b, p uint16) {
	f := channeldb.NewPkgFilter(p)
	var j = b
	for i := uint16(1); i < p; i++ {
		if f.Contains(j) {
			t.Fatalf("pkg filter contains %d-%d "+
				"before being added", i, j)
		}

		f.Set(j)
		checkPkgFilterEncodeDecode(t, i, f)

		if !f.Contains(j) {
			t.Fatalf("pkg filter missing %d-%d "+
				"after being added", i, j)
		}

		if i < p-1 && f.IsFull() {
			t.Fatalf("pkg filter %d already full", i)
		}
		checkPkgFilterEncodeDecode(t, i, f)

		j = (b * j) % p
	}

	// Set 0 independently, since it will never be emitted by the generator.
	f.Set(0)
	checkPkgFilterEncodeDecode(t, p, f)

	if !f.IsFull() {
		t.Fatalf("pkg filter count=%d not full", p)
	}
	checkPkgFilterEncodeDecode(t, p, f)
}

// checkPkgFilterEncodeDecode tests the serialization of a pkg filter by:
//   1) writing it to a buffer
//   2) verifying the number of bytes written matches the filter's Size()
//   3) reconstructing the filter decoding the bytes
//   4) checking that the two filters are the same according to Equal
func checkPkgFilterEncodeDecode(t *testing.T, i uint16, f *channeldb.PkgFilter) {
	var b bytes.Buffer
	if err := f.Encode(&b); err != nil {
		t.Fatalf("unable to serialize pkg filter: %v", err)
	}

	// +2 for uint16 length
	size := uint16(len(b.Bytes()))
	if size != f.Size() {
		t.Fatalf("pkg filter count=%d serialized size differs, "+
			"Size(): %d, len(bytes): %v", i, f.Size(), size)
	}

	reader := bytes.NewReader(b.Bytes())

	f2 := &channeldb.PkgFilter{}
	if err := f2.Decode(reader); err != nil {
		t.Fatalf("unable to deserialize pkg filter: %v", err)
	}

	if !f.Equal(f2) {
		t.Fatalf("pkg filter count=%v does is not equal "+
			"after deserialization, want: %v, got %v",
			i, f, f2)
	}
}

var (
	chanID = lnwire.NewChanIDFromOutPoint(&wire.OutPoint{})

	adds = []channeldb.LogUpdate{
		{
			LogIndex: 0,
			UpdateMsg: &lnwire.UpdateAddHTLC{
				ChanID:      chanID,
				ID:          1,
				Amount:      100,
				Expiry:      1000,
				PaymentHash: [32]byte{0},
			},
		},
		{
			LogIndex: 1,
			UpdateMsg: &lnwire.UpdateAddHTLC{
				ChanID:      chanID,
				ID:          1,
				Amount:      101,
				Expiry:      1001,
				PaymentHash: [32]byte{1},
			},
		},
	}

	settleFails = []channeldb.LogUpdate{
		{
			LogIndex: 2,
			UpdateMsg: &lnwire.UpdateFulfillHTLC{
				ChanID:          chanID,
				ID:              0,
				PaymentPreimage: [32]byte{0},
			},
		},
		{
			LogIndex: 3,
			UpdateMsg: &lnwire.UpdateFailHTLC{
				ChanID: chanID,
				ID:     1,
				Reason: []byte{},
			},
		},
	}
)

// TestPackagerEmptyFwdPkg checks that the state transitions exhibited by a
// forwarding package that contains no adds, fails or settles. We expect that
// the fwdpkg reaches FwdStateCompleted immediately after writing the forwarding
// decision via SetFwdFilter.
func TestPackagerEmptyFwdPkg(t *testing.T) {
	t.Parallel()

	db := makeFwdPkgDB(t, "")

	var chanID [32]byte
	packager := channeldb.NewChannelPackager(chanID)

	// To begin, there should be no forwarding packages on disk.
	fwdPkgs := loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}

	// Next, create and write a new forwarding package with no htlcs.
	fwdPkg := channeldb.NewFwdPkg(chanID, 0, nil, nil)

	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.AddFwdPkg(tx, fwdPkg)
	}); err != nil {
		t.Fatalf("unable to add fwd pkg: %v", err)
	}

	// There should now be one fwdpkg on disk. Since no forwarding decision
	// has been written, we expect it to be FwdStateLockedIn. With no HTLCs,
	// the ack filter will have no elements, and should always return true.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateLockedIn)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], 0, 0)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Now, write the forwarding decision. In this case, its just an empty
	// fwd filter.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.SetFwdFilter(tx, fwdPkg.Height, fwdPkg.FwdFilter)
	}); err != nil {
		t.Fatalf("unable to set fwdfiter: %v", err)
	}

	// We should still have one package on disk. Since the forwarding
	// decision has been written, it will minimally be in FwdStateProcessed.
	// However with no htlcs, it should leap frog to FwdStateCompleted.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateCompleted)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], 0, 0)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Lastly, remove the completed forwarding package from disk.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.RemovePkg(tx, fwdPkg.Height)
	}); err != nil {
		t.Fatalf("unable to remove fwdpkg: %v", err)
	}

	// Check that the fwd package was actually removed.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}
}

// TestPackagerOnlyAdds checks that the fwdpkg does not reach FwdStateCompleted
// as soon as all the adds in the package have been acked using AckAddHtlcs.
func TestPackagerOnlyAdds(t *testing.T) {
	t.Parallel()

	db := makeFwdPkgDB(t, "")

	var chanID [32]byte
	packager := channeldb.NewChannelPackager(chanID)

	// To begin, there should be no forwarding packages on disk.
	fwdPkgs := loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}

	// Next, create and write a new forwarding package that only has add
	// htlcs.
	fwdPkg := channeldb.NewFwdPkg(chanID, 0, adds, nil)

	nAdds := len(adds)

	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.AddFwdPkg(tx, fwdPkg)
	}); err != nil {
		t.Fatalf("unable to add fwd pkg: %v", err)
	}

	// There should now be one fwdpkg on disk. Since no forwarding decision
	// has been written, we expect it to be FwdStateLockedIn. The package
	// has unacked add HTLCs, so the ack filter should not be full.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateLockedIn)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, 0)
	assertAckFilterIsFull(t, fwdPkgs[0], false)

	// Now, write the forwarding decision. Since we have not explicitly
	// added any adds to the fwdfilter, this would indicate that all of the
	// adds were 1) settled locally by this link (exit hop), or 2) the htlc
	// was failed locally.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.SetFwdFilter(tx, fwdPkg.Height, fwdPkg.FwdFilter)
	}); err != nil {
		t.Fatalf("unable to set fwdfiter: %v", err)
	}

	for i := range adds {
		// We should still have one package on disk. Since the forwarding
		// decision has been written, it will minimally be in FwdStateProcessed.
		// However not allf of the HTLCs have been acked, so should not
		// have advanced further.
		fwdPkgs = loadFwdPkgs(t, db, packager)
		if len(fwdPkgs) != 1 {
			t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
		}
		assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateProcessed)
		assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, 0)
		assertAckFilterIsFull(t, fwdPkgs[0], false)

		addRef := channeldb.AddRef{
			Height: fwdPkg.Height,
			Index:  uint16(i),
		}

		if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
			return packager.AckAddHtlcs(tx, addRef)
		}); err != nil {
			t.Fatalf("unable to ack add htlc: %v", err)
		}
	}

	// We should still have one package on disk. Now that all adds have been
	// acked, the ack filter should return true and the package should be
	// FwdStateCompleted since there are no other settle/fail packets.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateCompleted)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, 0)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Lastly, remove the completed forwarding package from disk.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.RemovePkg(tx, fwdPkg.Height)
	}); err != nil {
		t.Fatalf("unable to remove fwdpkg: %v", err)
	}

	// Check that the fwd package was actually removed.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}
}

// TestPackagerOnlySettleFails asserts that the fwdpkg remains in
// FwdStateProcessed after writing the forwarding decision when there are no
// adds in the fwdpkg. We expect this because an empty FwdFilter will always
// return true, but we are still waiting for the remaining fails and settles to
// be deleted.
func TestPackagerOnlySettleFails(t *testing.T) {
	t.Parallel()

	db := makeFwdPkgDB(t, "")

	var chanID [32]byte
	packager := channeldb.NewChannelPackager(chanID)

	// To begin, there should be no forwarding packages on disk.
	fwdPkgs := loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}

	// Next, create and write a new forwarding package that only has add
	// htlcs.
	fwdPkg := channeldb.NewFwdPkg(chanID, 0, nil, settleFails)

	nSettleFails := len(settleFails)

	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.AddFwdPkg(tx, fwdPkg)
	}); err != nil {
		t.Fatalf("unable to add fwd pkg: %v", err)
	}

	// There should now be one fwdpkg on disk. Since no forwarding decision
	// has been written, we expect it to be FwdStateLockedIn. The package
	// has unacked add HTLCs, so the ack filter should not be full.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateLockedIn)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], 0, nSettleFails)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Now, write the forwarding decision. Since we have not explicitly
	// added any adds to the fwdfilter, this would indicate that all of the
	// adds were 1) settled locally by this link (exit hop), or 2) the htlc
	// was failed locally.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.SetFwdFilter(tx, fwdPkg.Height, fwdPkg.FwdFilter)
	}); err != nil {
		t.Fatalf("unable to set fwdfiter: %v", err)
	}

	for i := range settleFails {
		// We should still have one package on disk. Since the
		// forwarding decision has been written, it will minimally be in
		// FwdStateProcessed. However, not all of the HTLCs have been
		// acked, so should not have advanced further.
		fwdPkgs = loadFwdPkgs(t, db, packager)
		if len(fwdPkgs) != 1 {
			t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
		}
		assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateProcessed)
		assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], 0, nSettleFails)
		assertSettleFailFilterIsFull(t, fwdPkgs[0], false)
		assertAckFilterIsFull(t, fwdPkgs[0], true)

		failSettleRef := channeldb.SettleFailRef{
			Source: chanID,
			Height: fwdPkg.Height,
			Index:  uint16(i),
		}

		if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
			return packager.AckSettleFails(tx, failSettleRef)
		}); err != nil {
			t.Fatalf("unable to ack add htlc: %v", err)
		}
	}

	// We should still have one package on disk. Now that all settles and
	// fails have been removed, package should be FwdStateCompleted since
	// there are no other add packets.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateCompleted)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], 0, nSettleFails)
	assertSettleFailFilterIsFull(t, fwdPkgs[0], true)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Lastly, remove the completed forwarding package from disk.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.RemovePkg(tx, fwdPkg.Height)
	}); err != nil {
		t.Fatalf("unable to remove fwdpkg: %v", err)
	}

	// Check that the fwd package was actually removed.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}
}

// TestPackagerAddsThenSettleFails writes a fwdpkg containing both adds and
// settle/fails, then checks the behavior when the adds are acked before any of
// the settle fails. Here we expect pkg to remain in FwdStateProcessed while the
// remainder of the fail/settles are being deleted.
func TestPackagerAddsThenSettleFails(t *testing.T) {
	t.Parallel()

	db := makeFwdPkgDB(t, "")

	var chanID [32]byte
	packager := channeldb.NewChannelPackager(chanID)

	// To begin, there should be no forwarding packages on disk.
	fwdPkgs := loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}

	// Next, create and write a new forwarding package that only has add
	// htlcs.
	fwdPkg := channeldb.NewFwdPkg(chanID, 0, adds, settleFails)

	nAdds := len(adds)
	nSettleFails := len(settleFails)

	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.AddFwdPkg(tx, fwdPkg)
	}); err != nil {
		t.Fatalf("unable to add fwd pkg: %v", err)
	}

	// There should now be one fwdpkg on disk. Since no forwarding decision
	// has been written, we expect it to be FwdStateLockedIn. The package
	// has unacked add HTLCs, so the ack filter should not be full.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateLockedIn)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
	assertAckFilterIsFull(t, fwdPkgs[0], false)

	// Now, write the forwarding decision. Since we have not explicitly
	// added any adds to the fwdfilter, this would indicate that all of the
	// adds were 1) settled locally by this link (exit hop), or 2) the htlc
	// was failed locally.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.SetFwdFilter(tx, fwdPkg.Height, fwdPkg.FwdFilter)
	}); err != nil {
		t.Fatalf("unable to set fwdfiter: %v", err)
	}

	for i := range adds {
		// We should still have one package on disk. Since the forwarding
		// decision has been written, it will minimally be in FwdStateProcessed.
		// However not allf of the HTLCs have been acked, so should not
		// have advanced further.
		fwdPkgs = loadFwdPkgs(t, db, packager)
		if len(fwdPkgs) != 1 {
			t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
		}
		assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateProcessed)
		assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
		assertSettleFailFilterIsFull(t, fwdPkgs[0], false)
		assertAckFilterIsFull(t, fwdPkgs[0], false)

		addRef := channeldb.AddRef{
			Height: fwdPkg.Height,
			Index:  uint16(i),
		}

		if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
			return packager.AckAddHtlcs(tx, addRef)
		}); err != nil {
			t.Fatalf("unable to ack add htlc: %v", err)
		}
	}

	for i := range settleFails {
		// We should still have one package on disk. Since the
		// forwarding decision has been written, it will minimally be in
		// FwdStateProcessed.  However not allf of the HTLCs have been
		// acked, so should not have advanced further.
		fwdPkgs = loadFwdPkgs(t, db, packager)
		if len(fwdPkgs) != 1 {
			t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
		}
		assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateProcessed)
		assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
		assertSettleFailFilterIsFull(t, fwdPkgs[0], false)
		assertAckFilterIsFull(t, fwdPkgs[0], true)

		failSettleRef := channeldb.SettleFailRef{
			Source: chanID,
			Height: fwdPkg.Height,
			Index:  uint16(i),
		}

		if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
			return packager.AckSettleFails(tx, failSettleRef)
		}); err != nil {
			t.Fatalf("unable to remove settle/fail htlc: %v", err)
		}
	}

	// We should still have one package on disk. Now that all settles and
	// fails have been removed, package should be FwdStateCompleted since
	// there are no other add packets.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateCompleted)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
	assertSettleFailFilterIsFull(t, fwdPkgs[0], true)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Lastly, remove the completed forwarding package from disk.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.RemovePkg(tx, fwdPkg.Height)
	}); err != nil {
		t.Fatalf("unable to remove fwdpkg: %v", err)
	}

	// Check that the fwd package was actually removed.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}
}

// TestPackagerSettleFailsThenAdds writes a fwdpkg with both adds and
// settle/fails, then checks the behavior when the settle/fails are removed
// before any of the adds have been acked. This should cause the fwdpkg to
// remain in FwdStateProcessed until the final ack is recorded, at which point
// it should be promoted directly to FwdStateCompleted.since all adds have been
// removed.
func TestPackagerSettleFailsThenAdds(t *testing.T) {
	t.Parallel()

	db := makeFwdPkgDB(t, "")

	var chanID [32]byte
	packager := channeldb.NewChannelPackager(chanID)

	// To begin, there should be no forwarding packages on disk.
	fwdPkgs := loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}

	// Next, create and write a new forwarding package that has both add
	// and settle/fail htlcs.
	fwdPkg := channeldb.NewFwdPkg(chanID, 0, adds, settleFails)

	nAdds := len(adds)
	nSettleFails := len(settleFails)

	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.AddFwdPkg(tx, fwdPkg)
	}); err != nil {
		t.Fatalf("unable to add fwd pkg: %v", err)
	}

	// There should now be one fwdpkg on disk. Since no forwarding decision
	// has been written, we expect it to be FwdStateLockedIn. The package
	// has unacked add HTLCs, so the ack filter should not be full.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateLockedIn)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
	assertAckFilterIsFull(t, fwdPkgs[0], false)

	// Now, write the forwarding decision. Since we have not explicitly
	// added any adds to the fwdfilter, this would indicate that all of the
	// adds were 1) settled locally by this link (exit hop), or 2) the htlc
	// was failed locally.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.SetFwdFilter(tx, fwdPkg.Height, fwdPkg.FwdFilter)
	}); err != nil {
		t.Fatalf("unable to set fwdfiter: %v", err)
	}

	// Simulate another channel deleting the settle/fails it received from
	// the original fwd pkg.
	// TODO(conner): use different packager/s?
	for i := range settleFails {
		// We should still have one package on disk. Since the
		// forwarding decision has been written, it will minimally be in
		// FwdStateProcessed.  However none all of the add HTLCs have
		// been acked, so should not have advanced further.
		fwdPkgs = loadFwdPkgs(t, db, packager)
		if len(fwdPkgs) != 1 {
			t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
		}
		assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateProcessed)
		assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
		assertSettleFailFilterIsFull(t, fwdPkgs[0], false)
		assertAckFilterIsFull(t, fwdPkgs[0], false)

		failSettleRef := channeldb.SettleFailRef{
			Source: chanID,
			Height: fwdPkg.Height,
			Index:  uint16(i),
		}

		if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
			return packager.AckSettleFails(tx, failSettleRef)
		}); err != nil {
			t.Fatalf("unable to remove settle/fail htlc: %v", err)
		}
	}

	// Now simulate this channel receiving a fail/settle for the adds in the
	// fwdpkg.
	for i := range adds {
		// Again, we should still have one package on disk and be in
		// FwdStateProcessed. This should not change until all of the
		// add htlcs have been acked.
		fwdPkgs = loadFwdPkgs(t, db, packager)
		if len(fwdPkgs) != 1 {
			t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
		}
		assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateProcessed)
		assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
		assertSettleFailFilterIsFull(t, fwdPkgs[0], true)
		assertAckFilterIsFull(t, fwdPkgs[0], false)

		addRef := channeldb.AddRef{
			Height: fwdPkg.Height,
			Index:  uint16(i),
		}

		if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
			return packager.AckAddHtlcs(tx, addRef)
		}); err != nil {
			t.Fatalf("unable to ack add htlc: %v", err)
		}
	}

	// We should still have one package on disk. Now that all settles and
	// fails have been removed, package should be FwdStateCompleted since
	// there are no other add packets.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 1 {
		t.Fatalf("expected 1 fwdpkg, instead found %d", len(fwdPkgs))
	}
	assertFwdPkgState(t, fwdPkgs[0], channeldb.FwdStateCompleted)
	assertFwdPkgNumAddsSettleFails(t, fwdPkgs[0], nAdds, nSettleFails)
	assertSettleFailFilterIsFull(t, fwdPkgs[0], true)
	assertAckFilterIsFull(t, fwdPkgs[0], true)

	// Lastly, remove the completed forwarding package from disk.
	if err := kvdb.Update(db, func(tx kvdb.RwTx) error {
		return packager.RemovePkg(tx, fwdPkg.Height)
	}); err != nil {
		t.Fatalf("unable to remove fwdpkg: %v", err)
	}

	// Check that the fwd package was actually removed.
	fwdPkgs = loadFwdPkgs(t, db, packager)
	if len(fwdPkgs) != 0 {
		t.Fatalf("no forwarding packages should exist, found %d", len(fwdPkgs))
	}
}

// assertFwdPkgState checks the current state of a fwdpkg meets our
// expectations.
func assertFwdPkgState(t *testing.T, fwdPkg *channeldb.FwdPkg,
	state channeldb.FwdState) {
	_, _, line, _ := runtime.Caller(1)
	if fwdPkg.State != state {
		t.Fatalf("line %d: expected fwdpkg in state %v, found %v",
			line, state, fwdPkg.State)
	}
}

// assertFwdPkgNumAddsSettleFails checks that the number of adds and
// settle/fail log updates are correct.
func assertFwdPkgNumAddsSettleFails(t *testing.T, fwdPkg *channeldb.FwdPkg,
	expectedNumAdds, expectedNumSettleFails int) {
	_, _, line, _ := runtime.Caller(1)
	if len(fwdPkg.Adds) != expectedNumAdds {
		t.Fatalf("line %d: expected fwdpkg to have %d adds, found %d",
			line, expectedNumAdds, len(fwdPkg.Adds))
	}

	if len(fwdPkg.SettleFails) != expectedNumSettleFails {
		t.Fatalf("line %d: expected fwdpkg to have %d settle/fails, found %d",
			line, expectedNumSettleFails, len(fwdPkg.SettleFails))
	}
}

// assertAckFilterIsFull checks whether or not a fwdpkg's ack filter matches our
// expected full-ness.
func assertAckFilterIsFull(t *testing.T, fwdPkg *channeldb.FwdPkg, expected bool) {
	_, _, line, _ := runtime.Caller(1)
	if fwdPkg.AckFilter.IsFull() != expected {
		t.Fatalf("line %d: expected fwdpkg ack filter IsFull to be %v, "+
			"found %v", line, expected, fwdPkg.AckFilter.IsFull())
	}
}

// assertSettleFailFilterIsFull checks whether or not a fwdpkg's settle fail
// filter matches our expected full-ness.
func assertSettleFailFilterIsFull(t *testing.T, fwdPkg *channeldb.FwdPkg, expected bool) {
	_, _, line, _ := runtime.Caller(1)
	if fwdPkg.SettleFailFilter.IsFull() != expected {
		t.Fatalf("line %d: expected fwdpkg settle/fail filter IsFull to be %v, "+
			"found %v", line, expected, fwdPkg.SettleFailFilter.IsFull())
	}
}

// loadFwdPkgs is a helper method that reads all forwarding packages for a
// particular packager.
func loadFwdPkgs(t *testing.T, db kvdb.Backend,
	packager channeldb.FwdPackager) []*channeldb.FwdPkg {

	var fwdPkgs []*channeldb.FwdPkg
	if err := kvdb.View(db, func(tx kvdb.RTx) error {
		var err error
		fwdPkgs, err = packager.LoadFwdPkgs(tx)
		return err
	}); err != nil {
		t.Fatalf("unable to load fwd pkgs: %v", err)
	}

	return fwdPkgs
}

// makeFwdPkgDB initializes a test database for forwarding packages. If the
// provided path is an empty, it will create a temp dir/file to use.
func makeFwdPkgDB(t *testing.T, path string) kvdb.Backend { // nolint:unparam
	if path == "" {
		var err error
		path, err = ioutil.TempDir("", "fwdpkgdb")
		if err != nil {
			t.Fatalf("unable to create temp path: %v", err)
		}

		path = filepath.Join(path, "fwdpkg.db")
	}

	bdb, err := kvdb.Create(kvdb.BoltBackendName, path, true)
	if err != nil {
		t.Fatalf("unable to open boltdb: %v", err)
	}

	return bdb
}
