package migration19

import (
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
)

var (

	// forwardingLogBucket is the bucket that we'll use to store the
	// forwarding log. The forwarding log contains a time series database
	// of the forwarding history of a lightning daemon. Each key within the
	// bucket is a timestamp (in nano seconds since the unix epoch), and
	// the value a slice of a forwarding event for that timestamp.
	forwardingLogBucket = []byte("circuit-fwd-log")
)

// MigrateForwardingEvents patches a new PaymentHash field to all the
// forwarding events. It reads all the old forwarding events and then patches
// a 32-byte zeros as their new PaymentHash values.
func MigrateForwardingEvents(tx kvdb.RwTx) error {
	log.Infof("Migrating PaymentHash for Forwarding logs")

	// Read the forwardingLogBucket first. If the bucket is nil, we can exit
	// the migration early.
	fwdLogBkt := tx.ReadWriteBucket(forwardingLogBucket)
	if fwdLogBkt == nil {
		return nil
	}

	// Iterate all forwarding events.
	if err := fwdLogBkt.ForEach(func(k, v []byte) error {
		// Instead of decoding/encoding the old/new forwarding events,
		// we first create a 64-byte empty slice, then copy the 32-byte
		// old event data to the slice and overwrite the old event with
		// it. The new PaymentHash field now has a value of 32-byte
		// zeros, thus the migration is finished.
		var eventBytes [forwardingEventSize]byte
		copy(eventBytes[:], v)

		if err := fwdLogBkt.Put(k, eventBytes[:]); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
