package migration18

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	mig "github.com/lightningnetwork/lnd/channeldb/migration_01_to_11"
	"github.com/lightningnetwork/lnd/channeldb/migtest"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	key = [chainhash.HashSize]byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x68, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x93, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xf9, 0x9e, 0xc5, 0x8c, 0xe9,
	}
	testTx = &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte{0x04, 0x31, 0xdc, 0x00,
					0x1b, 0x01, 0x62},
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
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
		},
		LockTime: 5,
	}
	_, pubKey = btcec.PrivKeyFromBytes(btcec.S256(), key[:])
)

// TestMigrateFwdPkgCleanup asserts that the migration will delete all the
// forwarding packages for close channels, and leave the rest untouched.
func TestMigrateFwdPkgCleanup(t *testing.T) {
	migrationTests := []struct {
		name                string
		beforeMigrationFunc func(kvdb.RwTx) error
		afterMigrationFunc  func(kvdb.RwTx) error
	}{
		{
			// no closed channels summeries in the db.
			// This leaves the fwdpkg untouched.
			name: "no closed channel summeries",
			beforeMigrationFunc: genBeforeMigration(
				false, []int{}, []int{1},
			),
			afterMigrationFunc: genAfterMigration(
				[]int{}, []int{1},
			),
		},
		{
			// one closed summery found, and the forwarding package
			// shares the same channel ID.
			// This makes the fwdpkg removed.
			name: "remove one fwdpkg",
			beforeMigrationFunc: genBeforeMigration(
				false, []int{1}, []int{1},
			),
			afterMigrationFunc: genAfterMigration(
				[]int{1}, []int{},
			),
		},
		{
			// one closed summery with pending status found, and the
			// forwarding package shares the same channel ID.
			// This leaves the fwdpkg untouched.
			name: "no action if closed status is pending",
			beforeMigrationFunc: genBeforeMigration(
				true, []int{1}, []int{1},
			),
			afterMigrationFunc: genAfterMigration(
				[]int{}, []int{1},
			),
		},
		{
			// one closed summery found, while the forwarding
			// package has a different channel ID.
			// This leaves the fwdpkg untouched.
			name: "no fwdpkg removed",
			beforeMigrationFunc: genBeforeMigration(
				false, []int{1}, []int{2},
			),
			afterMigrationFunc: genAfterMigration(
				[]int{}, []int{2},
			),
		},
		{
			// multiple closed summeries and fwdpkg nested buckets
			// found. Only the matched fwdPkg nested buckets are
			// removed.
			name: "only matching fwdpkg removed",
			beforeMigrationFunc: genBeforeMigration(false,
				[]int{1, 2, 3},
				[]int{1, 2, 4},
			),
			afterMigrationFunc: genAfterMigration(
				[]int{1, 2},
				[]int{4},
			),
		},
	}

	for _, tt := range migrationTests {
		test := tt
		t.Run(test.name, func(t *testing.T) {
			migtest.ApplyMigration(
				t,
				test.beforeMigrationFunc,
				test.afterMigrationFunc,
				MigrateFwdPkgCleanup,
				false,
			)
		})
	}
}

func genBeforeMigration(isPending bool,
	closeSummeryChanIDs, fwdPkgChanIDs []int) func(kvdb.RwTx) error {

	return func(tx kvdb.RwTx) error {
		// create closed channel summeries
		for _, id := range closeSummeryChanIDs {
			chanID := lnwire.NewShortChanIDFromInt(uint64(id))
			if err := createTestCloseChannelSummery(
				tx, isPending, chanID,
			); err != nil {
				return err
			}
		}

		// create fwdPkg nested buckets
		for _, id := range fwdPkgChanIDs {
			chanID := lnwire.NewShortChanIDFromInt(uint64(id))
			if err := createTestFwdPkgBucket(tx,
				chanID); err != nil {

				return err
			}
		}

		return nil
	}
}

func genAfterMigration(deleted, untouched []int) func(kvdb.RwTx) error {
	return func(tx kvdb.RwTx) error {
		fwdPkgBkt := tx.ReadBucket(fwdPackagesKey)
		if fwdPkgBkt == nil {
			return errors.New("unable to find bucket")
		}

		// Reading deleted buckets should return nil
		for _, id := range deleted {
			chanID := lnwire.NewShortChanIDFromInt(uint64(id))
			sourceKey := makeLogKey(chanID.ToUint64())
			sourceBkt := fwdPkgBkt.NestedReadBucket(sourceKey[:])
			if sourceBkt != nil {
				return fmt.Errorf(
					"expected bucket to be deleted: %v",
					id,
				)
			}
		}

		// Reading untouched buckets should return not nil
		for _, id := range untouched {
			chanID := lnwire.NewShortChanIDFromInt(uint64(id))
			sourceKey := makeLogKey(chanID.ToUint64())
			sourceBkt := fwdPkgBkt.NestedReadBucket(sourceKey[:])
			if sourceBkt == nil {
				return fmt.Errorf(
					"expected bucket to not be deleted: %v",
					id,
				)
			}
		}

		return nil
	}
}

// createTestCloseChannelSummery creates a CloseChannelSummery for testing.
func createTestCloseChannelSummery(tx kvdb.RwTx, isPending bool,
	chanID lnwire.ShortChannelID) error {

	closedChanBucket, err := tx.CreateTopLevelBucket(closedChannelBucket)
	if err != nil {
		return err
	}

	outputPoint := wire.OutPoint{Hash: key, Index: rand.Uint32()}

	ccs := &mig.ChannelCloseSummary{
		ChanPoint:      outputPoint,
		ShortChanID:    chanID,
		ChainHash:      key,
		ClosingTXID:    testTx.TxHash(),
		CloseHeight:    100,
		RemotePub:      pubKey,
		Capacity:       btcutil.Amount(10000),
		SettledBalance: btcutil.Amount(50000),
		CloseType:      mig.RemoteForceClose,
		IsPending:      isPending,
		// optional fields
		RemoteCurrentRevocation: pubKey,
		RemoteNextRevocation:    pubKey,
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

func createTestFwdPkgBucket(tx kvdb.RwTx, chanID lnwire.ShortChannelID) error {
	fwdPkgBkt, err := tx.CreateTopLevelBucket(fwdPackagesKey)
	if err != nil {
		return err
	}

	source := makeLogKey(chanID.ToUint64())
	if _, err := fwdPkgBkt.CreateBucketIfNotExists(source[:]); err != nil {
		return err
	}

	return nil
}

func serializeChannelCloseSummary(
	w io.Writer, cs *mig.ChannelCloseSummary) error {

	err := mig.WriteElements(
		w,
		cs.ChanPoint, cs.ShortChanID, cs.ChainHash, cs.ClosingTXID,
		cs.CloseHeight, cs.RemotePub, cs.Capacity, cs.SettledBalance,
		cs.TimeLockedBalance, cs.CloseType, cs.IsPending,
	)
	if err != nil {
		return err
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
