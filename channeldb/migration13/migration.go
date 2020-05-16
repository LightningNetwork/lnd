package migration13

import (
	"encoding/binary"
	"fmt"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
)

var (
	paymentsRootBucket = []byte("payments-root-bucket")

	// paymentCreationInfoKey is a key used in the payment's sub-bucket to
	// store the creation info of the payment.
	paymentCreationInfoKey = []byte("payment-creation-info")

	// paymentFailInfoKey is a key used in the payment's sub-bucket to
	// store information about the reason a payment failed.
	paymentFailInfoKey = []byte("payment-fail-info")

	// paymentAttemptInfoKey is a key used in the payment's sub-bucket to
	// store the info about the latest attempt that was done for the
	// payment in question.
	paymentAttemptInfoKey = []byte("payment-attempt-info")

	// paymentSettleInfoKey is a key used in the payment's sub-bucket to
	// store the settle info of the payment.
	paymentSettleInfoKey = []byte("payment-settle-info")

	// paymentHtlcsBucket is a bucket where we'll store the information
	// about the HTLCs that were attempted for a payment.
	paymentHtlcsBucket = []byte("payment-htlcs-bucket")

	// htlcAttemptInfoKey is a key used in a HTLC's sub-bucket to store the
	// info about the attempt that was done for the HTLC in question.
	htlcAttemptInfoKey = []byte("htlc-attempt-info")

	// htlcSettleInfoKey is a key used in a HTLC's sub-bucket to store the
	// settle info, if any.
	htlcSettleInfoKey = []byte("htlc-settle-info")

	// htlcFailInfoKey is a key used in a HTLC's sub-bucket to store
	// failure information, if any.
	htlcFailInfoKey = []byte("htlc-fail-info")

	byteOrder = binary.BigEndian

	// failInfo is an empty fail info value for the legacy pre MPP
	// payments.
	failInfo = []byte{
		// Fail time unknown.
		0, 0, 0, 0, 0, 0, 0, 0,

		// Zero length wire message.
		0,

		// Failure reason unknown.
		0,

		// Failure source index zero.
		0, 0, 0, 0,
	}
)

// MigrateMPP migrates the payments to a new structure that accommodates for mpp
// payments.
func MigrateMPP(tx kvdb.RwTx) error {
	log.Infof("Migrating payments to mpp structure")

	// Iterate over all payments and store their indexing keys. This is
	// needed, because no modifications are allowed inside a Bucket.ForEach
	// loop.
	paymentsBucket := tx.ReadWriteBucket(paymentsRootBucket)
	if paymentsBucket == nil {
		return nil
	}

	var paymentKeys [][]byte
	err := paymentsBucket.ForEach(func(k, v []byte) error {
		paymentKeys = append(paymentKeys, k)
		return nil
	})
	if err != nil {
		return err
	}

	// With all keys retrieved, start the migration.
	var (
		zero      [8]byte
		attemptID [8]byte
	)
	for _, k := range paymentKeys {
		bucket := paymentsBucket.NestedReadWriteBucket(k)

		// We only expect sub-buckets to be found in
		// this top-level bucket.
		if bucket == nil {
			return fmt.Errorf("non bucket element in " +
				"payments bucket")
		}

		// Fetch old format creation info.
		creationInfo := bucket.Get(paymentCreationInfoKey)
		if creationInfo == nil {
			return fmt.Errorf("creation info not found")
		}

		// Make a copy because bbolt doesn't allow this value to be
		// changed in-place.
		newCreationInfo := make([]byte, len(creationInfo))
		copy(newCreationInfo, creationInfo)

		// Convert to nano seconds.
		timeBytes := newCreationInfo[32+8 : 32+8+8]
		time := byteOrder.Uint64(timeBytes)
		timeNs := time * 1000000000
		byteOrder.PutUint64(timeBytes, timeNs)

		// Write back new format creation info.
		err := bucket.Put(paymentCreationInfoKey, newCreationInfo)
		if err != nil {
			return err
		}

		// No migration needed if there is no attempt stored.
		attemptInfo := bucket.Get(paymentAttemptInfoKey)
		if attemptInfo == nil {
			continue
		}

		// Delete attempt info on the payment level.
		if err := bucket.Delete(paymentAttemptInfoKey); err != nil {
			return err
		}

		// Save attempt id for later use.
		copy(attemptID[:], attemptInfo[:8])

		// Copy over the attempt info into a new slice, the last 8
		// bytes will be zero to mark a zero attempt time.
		newAttemptInfo := make([]byte, len(attemptInfo))
		copy(newAttemptInfo, attemptInfo[8:])

		// Create bucket that contains all htlcs.
		htlcsBucket, err := bucket.CreateBucket(paymentHtlcsBucket)
		if err != nil {
			return err
		}

		// Create an htlc for this attempt.
		htlcBucket, err := htlcsBucket.CreateBucket(attemptID[:])
		if err != nil {
			return err
		}

		// Save migrated attempt info.
		err = htlcBucket.Put(htlcAttemptInfoKey, newAttemptInfo)
		if err != nil {
			return err
		}

		// Migrate settle info.
		settleInfo := bucket.Get(paymentSettleInfoKey)
		if settleInfo != nil {
			// Payment-level settle info can be deleted.
			err := bucket.Delete(paymentSettleInfoKey)
			if err != nil {
				return err
			}

			// Append unknown (zero) settle time.
			settleInfo = append(settleInfo, zero[:]...)

			// Save settle info.
			err = htlcBucket.Put(htlcSettleInfoKey, settleInfo)
			if err != nil {
				return err
			}

			// Migration for settled htlc completed.
			continue
		}

		// If there is no payment-level failure reason, the payment is
		// still in flight and nothing else needs to be migrated.
		// Otherwise the payment-level failure reason can remain
		// unchanged.
		inFlight := bucket.Get(paymentFailInfoKey) == nil
		if inFlight {
			continue
		}

		// The htlc failed. Add htlc fail info with reason unknown. We
		// don't have access to the original failure reason anymore.
		err = htlcBucket.Put(htlcFailInfoKey, failInfo)
		if err != nil {
			return err
		}
	}

	log.Infof("Migration of payments to mpp structure complete!")

	return nil
}
