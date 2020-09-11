package migration18

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	mig "github.com/lightningnetwork/lnd/channeldb/migration_01_to_11"
)

var (
	// closedChannelBucket stores summarization information concerning
	// previously open, but now closed channels.
	closedChannelBucket = []byte("closed-chan-bucket")

	// fwdPackagesKey is the root-level bucket that all forwarding packages
	// are written. This bucket is further subdivided based on the short
	// channel ID of each channel.
	fwdPackagesKey = []byte("fwd-packages")
)

// MigrateFwdPkgCleanup deletes all the forwarding packages of closed channels.
// It determines the closed channels by iterating closedChannelBucket. The
// ShortChanID found in the ChannelCloseSummary is then used as a key to query
// the forwarding packages bucket. If a match is found, it will be deleted.
func MigrateFwdPkgCleanup(tx kvdb.RwTx) error {
	log.Infof("Deleting forwarding packages for closed channels")

	// Find all closed channel summaries, which are stored in the
	// closeBucket.
	closeBucket := tx.ReadBucket(closedChannelBucket)
	if closeBucket == nil {
		return nil
	}

	var chanSummaries []*mig.ChannelCloseSummary

	// appendSummary is a function closure to help put deserialized close
	// summeries into chanSummaries.
	appendSummary := func(_ []byte, summaryBytes []byte) error {
		summaryReader := bytes.NewReader(summaryBytes)
		chanSummary, err := deserializeCloseChannelSummary(
			summaryReader,
		)
		if err != nil {
			return err
		}

		// Skip pending channels
		if chanSummary.IsPending {
			return nil
		}

		chanSummaries = append(chanSummaries, chanSummary)
		return nil
	}

	if err := closeBucket.ForEach(appendSummary); err != nil {
		return err
	}

	// Now we will load the forwarding packages bucket, delete all the
	// nested buckets whose source matches the ShortChanID found in the
	// closed channel summeraries.
	fwdPkgBkt := tx.ReadWriteBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil
	}

	// Iterate over all close channels and remove their forwarding packages.
	for _, summery := range chanSummaries {
		sourceBytes := makeLogKey(summery.ShortChanID.ToUint64())

		// First, we will try to find the corresponding bucket. If there
		// is not a nested bucket matching the ShortChanID, we will skip
		// it.
		if fwdPkgBkt.NestedReadBucket(sourceBytes[:]) == nil {
			continue
		}
		// Otherwise, wipe all the forwarding packages.
		if err := fwdPkgBkt.DeleteNestedBucket(
			sourceBytes[:]); err != nil {

			return err
		}
	}

	log.Infof(
		"Deletion of forwarding packages of closed channels complete!",
	)
	return nil
}

// deserializeCloseChannelSummary will decode a CloseChannelSummary with no
// optional fields.
func deserializeCloseChannelSummary(
	r io.Reader) (*mig.ChannelCloseSummary, error) {

	c := &mig.ChannelCloseSummary{}
	err := mig.ReadElements(
		r,
		&c.ChanPoint, &c.ShortChanID, &c.ChainHash, &c.ClosingTXID,
		&c.CloseHeight, &c.RemotePub, &c.Capacity, &c.SettledBalance,
		&c.TimeLockedBalance, &c.CloseType, &c.IsPending,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// makeLogKey converts a uint64 into an 8 byte array.
func makeLogKey(updateNum uint64) [8]byte {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], updateNum)
	return key
}
