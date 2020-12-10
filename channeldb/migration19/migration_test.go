package migration19

import (
	"fmt"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/channeldb/migtest"
	"github.com/lightningnetwork/lnd/lnwire"
)

// ZEROS is the empty value for PaymentHash field.
var ZEROS = [32]byte{}

// TestMigrateForwardingEvents tests that all the forwarding logs have patched
// the new PaymentHash field with zero values. It also tests that when there
// are no events, the migration will exit early.
func TestMigrateForwardingEvents(t *testing.T) {
	migrationTests := []struct {
		name                string
		beforeMigrationFunc func(kvdb.RwTx) error
		afterMigrationFunc  func(kvdb.RwTx) error
	}{

		{

			name:                "no forwarding logs",
			beforeMigrationFunc: genBeforeMigration(0),
			afterMigrationFunc:  genAfterMigration(true),
		},
		{

			name:                "patch all forwarding logs",
			beforeMigrationFunc: genBeforeMigration(100),
			afterMigrationFunc:  genAfterMigration(false),
		},
	}

	for _, tt := range migrationTests {
		test := tt
		t.Run(test.name, func(t *testing.T) {
			migtest.ApplyMigration(
				t,
				test.beforeMigrationFunc,
				test.afterMigrationFunc,
				MigrateForwardingEvents,
				false,
			)
		})
	}

}

// genBeforeMigration creates a number of forwarding events specified by
// numEvents.
func genBeforeMigration(numEvents int) func(kvdb.RwTx) error {
	return func(tx kvdb.RwTx) error {
		// If no events are created, the forwardingLogBucket won't be
		// created, thus our migration will exit early.
		if numEvents == 0 {
			return nil
		}

		// Create the bucket.
		fwdLogBkt, err := tx.CreateTopLevelBucket(forwardingLogBucket)
		if err != nil {
			return err
		}

		// Create events without the PaymentHash field.
		for i := 0; i < numEvents; i++ {
			event := &OldForwardingEvent{
				Timestamp:      time.Now(),
				AmtIn:          lnwire.NewMSatFromSatoshis(100),
				AmtOut:         lnwire.NewMSatFromSatoshis(100),
				IncomingChanID: lnwire.NewShortChanIDFromInt(1),
				OutgoingChanID: lnwire.NewShortChanIDFromInt(2),
			}
			if err := storeOldEvent(fwdLogBkt, event); err != nil {
				return err
			}
		}

		return nil
	}
}

// genAfterMigration checks that all the forwarding events are patched with a
// zero-value PaymentHash field. It takes a boolean field earlyExit to indicate
// whether the migration has exited early.
func genAfterMigration(earlyExit bool) func(kvdb.RwTx) error {
	return func(tx kvdb.RwTx) error {
		// Read the bucket first. If earlyExit is true, it means there
		// is no bucket.
		fwdLogBkt := tx.ReadWriteBucket(forwardingLogBucket)
		if earlyExit {
			if fwdLogBkt == nil {
				return nil
			}
			// Expected the bucket to be nil, instead we found it,
			// return an error.
			return fmt.Errorf(
				"expected forwardingLogBucket to be nil",
			)
		}

		// The earlyExit is false, indicates the bucket should exist.
		if fwdLogBkt == nil {
			return fmt.Errorf(
				"expected forwardingLogBucket to be created",
			)
		}

		// Iterate all the events and check that they all have
		// zero-value PaymentHash fields.
		if err := fwdLogBkt.ForEach(func(k, v []byte) error {
			event, err := decodeForwardingEvent(v)
			if err != nil {
				return err
			}

			if event.PaymentHash != ZEROS {
				return fmt.Errorf("payment hash not matched: "+
					"expected: %v, got: %v",
					ZEROS, event.PaymentHash,
				)
			}

			return nil
		}); err != nil {
			return err
		}

		return nil
	}
}
