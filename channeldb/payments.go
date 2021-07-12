package channeldb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// paymentsRootBucket is the name of the top-level bucket within the
	// database that stores all data related to payments. Within this
	// bucket, each payment hash its own sub-bucket keyed by its payment
	// hash.
	//
	// Bucket hierarchy:
	//
	// root-bucket
	//      |
	//      |-- <paymenthash>
	//      |        |--sequence-key: <sequence number>
	//      |        |--creation-info-key: <creation info>
	//      |        |--fail-info-key: <(optional) fail info>
	//      |        |
	//      |        |--payment-htlcs-bucket (shard-bucket)
	//      |        |        |
	//      |        |        |-- <htlc attempt ID>
	//      |        |        |       |--htlc-attempt-info-key: <htlc attempt info>
	//      |        |        |       |--htlc-settle-info-key: <(optional) settle info>
	//      |        |        |       |--htlc-fail-info-key: <(optional) fail info>
	//      |        |        |
	//      |        |        |-- <htlc attempt ID>
	//      |        |        |       |
	//      |        |       ...     ...
	//      |        |
	//      |        |
	//      |        |--duplicate-bucket (only for old, completed payments)
	//      |                 |
	//      |                 |-- <seq-num>
	//      |                 |       |--sequence-key: <sequence number>
	//      |                 |       |--creation-info-key: <creation info>
	//      |                 |       |--attempt-info-key: <attempt info>
	//      |                 |       |--settle-info-key: <settle info>
	//      |                 |       |--fail-info-key: <fail info>
	//      |                 |
	//      |                 |-- <seq-num>
	//      |                 |       |
	//      |                ...     ...
	//      |
	//      |-- <paymenthash>
	//      |        |
	//      |       ...
	//     ...
	//
	paymentsRootBucket = []byte("payments-root-bucket")

	// paymentSequenceKey is a key used in the payment's sub-bucket to
	// store the sequence number of the payment.
	paymentSequenceKey = []byte("payment-sequence-key")

	// paymentCreationInfoKey is a key used in the payment's sub-bucket to
	// store the creation info of the payment.
	paymentCreationInfoKey = []byte("payment-creation-info")

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

	// paymentFailInfoKey is a key used in the payment's sub-bucket to
	// store information about the reason a payment failed.
	paymentFailInfoKey = []byte("payment-fail-info")

	// paymentsIndexBucket is the name of the top-level bucket within the
	// database that stores an index of payment sequence numbers to its
	// payment hash.
	// payments-sequence-index-bucket
	// 	|--<sequence-number>: <payment hash>
	// 	|--...
	// 	|--<sequence-number>: <payment hash>
	paymentsIndexBucket = []byte("payments-index-bucket")
)

var (
	// ErrNoSequenceNumber is returned if we lookup a payment which does
	// not have a sequence number.
	ErrNoSequenceNumber = errors.New("sequence number not found")

	// ErrDuplicateNotFound is returned when we lookup a payment by its
	// index and cannot find a payment with a matching sequence number.
	ErrDuplicateNotFound = errors.New("duplicate payment not found")

	// ErrNoDuplicateBucket is returned when we expect to find duplicates
	// when looking up a payment from its index, but the payment does not
	// have any.
	ErrNoDuplicateBucket = errors.New("expected duplicate bucket")

	// ErrNoDuplicateNestedBucket is returned if we do not find duplicate
	// payments in their own sub-bucket.
	ErrNoDuplicateNestedBucket = errors.New("nested duplicate bucket not " +
		"found")
)

// FailureReason encodes the reason a payment ultimately failed.
type FailureReason byte

const (
	// FailureReasonTimeout indicates that the payment did timeout before a
	// successful payment attempt was made.
	FailureReasonTimeout FailureReason = 0

	// FailureReasonNoRoute indicates no successful route to the
	// destination was found during path finding.
	FailureReasonNoRoute FailureReason = 1

	// FailureReasonError indicates that an unexpected error happened during
	// payment.
	FailureReasonError FailureReason = 2

	// FailureReasonPaymentDetails indicates that either the hash is unknown
	// or the final cltv delta or amount is incorrect.
	FailureReasonPaymentDetails FailureReason = 3

	// FailureReasonInsufficientBalance indicates that we didn't have enough
	// balance to complete the payment.
	FailureReasonInsufficientBalance FailureReason = 4

	// TODO(halseth): cancel state.

	// TODO(joostjager): Add failure reasons for:
	// LocalLiquidityInsufficient, RemoteCapacityInsufficient.
)

// Error returns a human readable error string for the FailureReason.
func (r FailureReason) Error() string {
	return r.String()
}

// String returns a human readable FailureReason.
func (r FailureReason) String() string {
	switch r {
	case FailureReasonTimeout:
		return "timeout"
	case FailureReasonNoRoute:
		return "no_route"
	case FailureReasonError:
		return "error"
	case FailureReasonPaymentDetails:
		return "incorrect_payment_details"
	case FailureReasonInsufficientBalance:
		return "insufficient_balance"
	}

	return "unknown"
}

// PaymentStatus represent current status of payment
type PaymentStatus byte

const (
	// StatusUnknown is the status where a payment has never been initiated
	// and hence is unknown.
	StatusUnknown PaymentStatus = 0

	// StatusInFlight is the status where a payment has been initiated, but
	// a response has not been received.
	StatusInFlight PaymentStatus = 1

	// StatusSucceeded is the status where a payment has been initiated and
	// the payment was completed successfully.
	StatusSucceeded PaymentStatus = 2

	// StatusFailed is the status where a payment has been initiated and a
	// failure result has come back.
	StatusFailed PaymentStatus = 3
)

// String returns readable representation of payment status.
func (ps PaymentStatus) String() string {
	switch ps {
	case StatusUnknown:
		return "Unknown"
	case StatusInFlight:
		return "In Flight"
	case StatusSucceeded:
		return "Succeeded"
	case StatusFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// PaymentCreationInfo is the information necessary to have ready when
// initiating a payment, moving it into state InFlight.
type PaymentCreationInfo struct {
	// PaymentIdentifier is the hash this payment is paying to in case of
	// non-AMP payments, and the SetID for AMP payments.
	PaymentIdentifier lntypes.Hash

	// Value is the amount we are paying.
	Value lnwire.MilliSatoshi

	// CreationTime is the time when this payment was initiated.
	CreationTime time.Time

	// PaymentRequest is the full payment request, if any.
	PaymentRequest []byte
}

// FetchPayments returns all sent payments found in the DB.
//
// nolint: dupl
func (db *DB) FetchPayments() ([]*MPPayment, error) {
	var payments []*MPPayment

	err := kvdb.View(db, func(tx kvdb.RTx) error {
		paymentsBucket := tx.ReadBucket(paymentsRootBucket)
		if paymentsBucket == nil {
			return nil
		}

		return paymentsBucket.ForEach(func(k, v []byte) error {
			bucket := paymentsBucket.NestedReadBucket(k)
			if bucket == nil {
				// We only expect sub-buckets to be found in
				// this top-level bucket.
				return fmt.Errorf("non bucket element in " +
					"payments bucket")
			}

			p, err := fetchPayment(bucket)
			if err != nil {
				return err
			}

			payments = append(payments, p)

			// For older versions of lnd, duplicate payments to a
			// payment has was possible. These will be found in a
			// sub-bucket indexed by their sequence number if
			// available.
			duplicatePayments, err := fetchDuplicatePayments(bucket)
			if err != nil {
				return err
			}

			payments = append(payments, duplicatePayments...)
			return nil
		})
	}, func() {
		payments = nil
	})
	if err != nil {
		return nil, err
	}

	// Before returning, sort the payments by their sequence number.
	sort.Slice(payments, func(i, j int) bool {
		return payments[i].SequenceNum < payments[j].SequenceNum
	})

	return payments, nil
}

func fetchCreationInfo(bucket kvdb.RBucket) (*PaymentCreationInfo, error) {
	b := bucket.Get(paymentCreationInfoKey)
	if b == nil {
		return nil, fmt.Errorf("creation info not found")
	}

	r := bytes.NewReader(b)
	return deserializePaymentCreationInfo(r)
}

func fetchPayment(bucket kvdb.RBucket) (*MPPayment, error) {
	seqBytes := bucket.Get(paymentSequenceKey)
	if seqBytes == nil {
		return nil, fmt.Errorf("sequence number not found")
	}

	sequenceNum := binary.BigEndian.Uint64(seqBytes)

	// Get the PaymentCreationInfo.
	creationInfo, err := fetchCreationInfo(bucket)
	if err != nil {
		return nil, err

	}

	var htlcs []HTLCAttempt
	htlcsBucket := bucket.NestedReadBucket(paymentHtlcsBucket)
	if htlcsBucket != nil {
		// Get the payment attempts. This can be empty.
		htlcs, err = fetchHtlcAttempts(htlcsBucket)
		if err != nil {
			return nil, err
		}
	}

	// Get failure reason if available.
	var failureReason *FailureReason
	b := bucket.Get(paymentFailInfoKey)
	if b != nil {
		reason := FailureReason(b[0])
		failureReason = &reason
	}

	// Go through all HTLCs for this payment, noting whether we have any
	// settled HTLC, and any still in-flight.
	var inflight, settled bool
	for _, h := range htlcs {
		if h.Failure != nil {
			continue
		}

		if h.Settle != nil {
			settled = true
			continue
		}

		// If any of the HTLCs are not failed nor settled, we
		// still have inflight HTLCs.
		inflight = true
	}

	// Use the DB state to determine the status of the payment.
	var paymentStatus PaymentStatus

	switch {

	// If any of the the HTLCs did succeed and there are no HTLCs in
	// flight, the payment succeeded.
	case !inflight && settled:
		paymentStatus = StatusSucceeded

	// If we have no in-flight HTLCs, and the payment failure is set, the
	// payment is considered failed.
	case !inflight && failureReason != nil:
		paymentStatus = StatusFailed

	// Otherwise it is still in flight.
	default:
		paymentStatus = StatusInFlight
	}

	return &MPPayment{
		SequenceNum:   sequenceNum,
		Info:          creationInfo,
		HTLCs:         htlcs,
		FailureReason: failureReason,
		Status:        paymentStatus,
	}, nil
}

// fetchHtlcAttempts retrives all htlc attempts made for the payment found in
// the given bucket.
func fetchHtlcAttempts(bucket kvdb.RBucket) ([]HTLCAttempt, error) {
	htlcs := make([]HTLCAttempt, 0)

	err := bucket.ForEach(func(k, _ []byte) error {
		aid := byteOrder.Uint64(k)
		htlcBucket := bucket.NestedReadBucket(k)

		attemptInfo, err := fetchHtlcAttemptInfo(
			htlcBucket,
		)
		if err != nil {
			return err
		}
		attemptInfo.AttemptID = aid

		htlc := HTLCAttempt{
			HTLCAttemptInfo: *attemptInfo,
		}

		// Settle info might be nil.
		htlc.Settle, err = fetchHtlcSettleInfo(htlcBucket)
		if err != nil {
			return err
		}

		// Failure info might be nil.
		htlc.Failure, err = fetchHtlcFailInfo(htlcBucket)
		if err != nil {
			return err
		}

		htlcs = append(htlcs, htlc)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return htlcs, nil
}

// fetchHtlcAttemptInfo fetches the payment attempt info for this htlc from the
// bucket.
func fetchHtlcAttemptInfo(bucket kvdb.RBucket) (*HTLCAttemptInfo, error) {
	b := bucket.Get(htlcAttemptInfoKey)
	if b == nil {
		return nil, errNoAttemptInfo
	}

	r := bytes.NewReader(b)
	return deserializeHTLCAttemptInfo(r)
}

// fetchHtlcSettleInfo retrieves the settle info for the htlc. If the htlc isn't
// settled, nil is returned.
func fetchHtlcSettleInfo(bucket kvdb.RBucket) (*HTLCSettleInfo, error) {
	b := bucket.Get(htlcSettleInfoKey)
	if b == nil {
		// Settle info is optional.
		return nil, nil
	}

	r := bytes.NewReader(b)
	return deserializeHTLCSettleInfo(r)
}

// fetchHtlcFailInfo retrieves the failure info for the htlc. If the htlc hasn't
// failed, nil is returned.
func fetchHtlcFailInfo(bucket kvdb.RBucket) (*HTLCFailInfo, error) {
	b := bucket.Get(htlcFailInfoKey)
	if b == nil {
		// Fail info is optional.
		return nil, nil
	}

	r := bytes.NewReader(b)
	return deserializeHTLCFailInfo(r)
}

// PaymentsQuery represents a query to the payments database starting or ending
// at a certain offset index. The number of retrieved records can be limited.
type PaymentsQuery struct {
	// IndexOffset determines the starting point of the payments query and
	// is always exclusive. In normal order, the query starts at the next
	// higher (available) index compared to IndexOffset. In reversed order,
	// the query ends at the next lower (available) index compared to the
	// IndexOffset. In the case of a zero index_offset, the query will start
	// with the oldest payment when paginating forwards, or will end with
	// the most recent payment when paginating backwards.
	IndexOffset uint64

	// MaxPayments is the maximal number of payments returned in the
	// payments query.
	MaxPayments uint64

	// Reversed gives a meaning to the IndexOffset. If reversed is set to
	// true, the query will fetch payments with indices lower than the
	// IndexOffset, otherwise, it will return payments with indices greater
	// than the IndexOffset.
	Reversed bool

	// If IncludeIncomplete is true, then return payments that have not yet
	// fully completed. This means that pending payments, as well as failed
	// payments will show up if this field is set to true.
	IncludeIncomplete bool
}

// PaymentsResponse contains the result of a query to the payments database.
// It includes the set of payments that match the query and integers which
// represent the index of the first and last item returned in the series of
// payments. These integers allow callers to resume their query in the event
// that the query's response exceeds the max number of returnable events.
type PaymentsResponse struct {
	// Payments is the set of payments returned from the database for the
	// PaymentsQuery.
	Payments []*MPPayment

	// FirstIndexOffset is the index of the first element in the set of
	// returned MPPayments. Callers can use this to resume their query
	// in the event that the slice has too many events to fit into a single
	// response. The offset can be used to continue reverse pagination.
	FirstIndexOffset uint64

	// LastIndexOffset is the index of the last element in the set of
	// returned MPPayments. Callers can use this to resume their query
	// in the event that the slice has too many events to fit into a single
	// response. The offset can be used to continue forward pagination.
	LastIndexOffset uint64
}

// QueryPayments is a query to the payments database which is restricted
// to a subset of payments by the payments query, containing an offset
// index and a maximum number of returned payments.
func (db *DB) QueryPayments(query PaymentsQuery) (PaymentsResponse, error) {
	var resp PaymentsResponse

	if err := kvdb.View(db, func(tx kvdb.RTx) error {
		// Get the root payments bucket.
		paymentsBucket := tx.ReadBucket(paymentsRootBucket)
		if paymentsBucket == nil {
			return nil
		}

		// Get the index bucket which maps sequence number -> payment
		// hash and duplicate bool. If we have a payments bucket, we
		// should have an indexes bucket as well.
		indexes := tx.ReadBucket(paymentsIndexBucket)
		if indexes == nil {
			return fmt.Errorf("index bucket does not exist")
		}

		// accumulatePayments gets payments with the sequence number
		// and hash provided and adds them to our list of payments if
		// they meet the criteria of our query. It returns the number
		// of payments that were added.
		accumulatePayments := func(sequenceKey, hash []byte) (bool,
			error) {

			r := bytes.NewReader(hash)
			paymentHash, err := deserializePaymentIndex(r)
			if err != nil {
				return false, err
			}

			payment, err := fetchPaymentWithSequenceNumber(
				tx, paymentHash, sequenceKey,
			)
			if err != nil {
				return false, err
			}

			// To keep compatibility with the old API, we only
			// return non-succeeded payments if requested.
			if payment.Status != StatusSucceeded &&
				!query.IncludeIncomplete {

				return false, err
			}

			// At this point, we've exhausted the offset, so we'll
			// begin collecting invoices found within the range.
			resp.Payments = append(resp.Payments, payment)
			return true, nil
		}

		// Create a paginator which reads from our sequence index bucket
		// with the parameters provided by the payments query.
		paginator := newPaginator(
			indexes.ReadCursor(), query.Reversed, query.IndexOffset,
			query.MaxPayments,
		)

		// Run a paginated query, adding payments to our response.
		if err := paginator.query(accumulatePayments); err != nil {
			return err
		}

		return nil
	}, func() {
		resp = PaymentsResponse{}
	}); err != nil {
		return resp, err
	}

	// Need to swap the payments slice order if reversed order.
	if query.Reversed {
		for l, r := 0, len(resp.Payments)-1; l < r; l, r = l+1, r-1 {
			resp.Payments[l], resp.Payments[r] =
				resp.Payments[r], resp.Payments[l]
		}
	}

	// Set the first and last index of the returned payments so that the
	// caller can resume from this point later on.
	if len(resp.Payments) > 0 {
		resp.FirstIndexOffset = resp.Payments[0].SequenceNum
		resp.LastIndexOffset =
			resp.Payments[len(resp.Payments)-1].SequenceNum
	}

	return resp, nil
}

// fetchPaymentWithSequenceNumber get the payment which matches the payment hash
// *and* sequence number provided from the database. This is required because
// we previously had more than one payment per hash, so we have multiple indexes
// pointing to a single payment; we want to retrieve the correct one.
func fetchPaymentWithSequenceNumber(tx kvdb.RTx, paymentHash lntypes.Hash,
	sequenceNumber []byte) (*MPPayment, error) {

	// We can now lookup the payment keyed by its hash in
	// the payments root bucket.
	bucket, err := fetchPaymentBucket(tx, paymentHash)
	if err != nil {
		return nil, err
	}

	// A single payment hash can have multiple payments associated with it.
	// We lookup our sequence number first, to determine whether this is
	// the payment we are actually looking for.
	seqBytes := bucket.Get(paymentSequenceKey)
	if seqBytes == nil {
		return nil, ErrNoSequenceNumber
	}

	// If this top level payment has the sequence number we are looking for,
	// return it.
	if bytes.Equal(seqBytes, sequenceNumber) {
		return fetchPayment(bucket)
	}

	// If we were not looking for the top level payment, we are looking for
	// one of our duplicate payments. We need to iterate through the seq
	// numbers in this bucket to find the correct payments. If we do not
	// find a duplicate payments bucket here, something is wrong.
	dup := bucket.NestedReadBucket(duplicatePaymentsBucket)
	if dup == nil {
		return nil, ErrNoDuplicateBucket
	}

	var duplicatePayment *MPPayment
	err = dup.ForEach(func(k, v []byte) error {
		subBucket := dup.NestedReadBucket(k)
		if subBucket == nil {
			// We one bucket for each duplicate to be found.
			return ErrNoDuplicateNestedBucket
		}

		seqBytes := subBucket.Get(duplicatePaymentSequenceKey)
		if seqBytes == nil {
			return err
		}

		// If this duplicate payment is not the sequence number we are
		// looking for, we can continue.
		if !bytes.Equal(seqBytes, sequenceNumber) {
			return nil
		}

		duplicatePayment, err = fetchDuplicatePayment(subBucket)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// If none of the duplicate payments matched our sequence number, we
	// failed to find the payment with this sequence number; something is
	// wrong.
	if duplicatePayment == nil {
		return nil, ErrDuplicateNotFound
	}

	return duplicatePayment, nil
}

// DeletePayments deletes all completed and failed payments from the DB. If
// failedOnly is set, only failed payments will be considered for deletion. If
// failedHtlsOnly is set, the payment itself won't be deleted, only failed HTLC
// attempts.
func (db *DB) DeletePayments(failedOnly, failedHtlcsOnly bool) error {
	var (
		// deleteBuckets is the set of payment buckets we need
		// to delete.
		deleteBuckets [][]byte

		// deleteIndexes is the set of indexes pointing to these
		// payments that need to be deleted.
		deleteIndexes [][]byte

		// deleteHtlcs maps a payment hash to the HTLC IDs we
		// want to delete for that payment.
		deleteHtlcs = make(map[lntypes.Hash][][]byte)
	)

	err := kvdb.View(db, func(tx kvdb.RTx) error {
		payments := tx.ReadBucket(paymentsRootBucket)
		if payments == nil {
			return nil
		}

		return payments.ForEach(func(k, _ []byte) error {
			bucket := payments.NestedReadBucket(k)
			if bucket == nil {
				// We only expect sub-buckets to be found in
				// this top-level bucket.
				return fmt.Errorf("non bucket element in " +
					"payments bucket")
			}

			// If the status is InFlight, we cannot safely delete
			// the payment information, so we return early.
			paymentStatus, err := fetchPaymentStatus(bucket)
			if err != nil {
				return err
			}

			// If the status is InFlight, we cannot safely delete
			// the payment information, so we return early.
			if paymentStatus == StatusInFlight {
				return nil
			}

			// If we requested to only delete failed payments, we
			// can return if this one is not.
			if failedOnly && paymentStatus != StatusFailed {
				return nil
			}

			// If we are only deleting failed HTLCs, fetch them.
			if failedHtlcsOnly {
				htlcsBucket := bucket.NestedReadBucket(
					paymentHtlcsBucket,
				)

				var htlcs []HTLCAttempt
				if htlcsBucket != nil {
					htlcs, err = fetchHtlcAttempts(
						htlcsBucket,
					)
					if err != nil {
						return err
					}
				}

				// Now iterate though them and save the bucket
				// keys for the failed HTLCs.
				var toDelete [][]byte
				for _, h := range htlcs {
					if h.Failure == nil {
						continue
					}

					htlcIDBytes := make([]byte, 8)
					binary.BigEndian.PutUint64(
						htlcIDBytes, h.AttemptID,
					)

					toDelete = append(toDelete, htlcIDBytes)
				}

				hash, err := lntypes.MakeHash(k)
				if err != nil {
					return err
				}

				deleteHtlcs[hash] = toDelete

				// We return, we are only deleting attempts.
				return nil
			}

			// Add the bucket to the set of buckets we can delete.
			deleteBuckets = append(deleteBuckets, k)

			// Get all the sequence number associated with the
			// payment, including duplicates.
			seqNrs, err := fetchSequenceNumbers(bucket)
			if err != nil {
				return err
			}

			deleteIndexes = append(deleteIndexes, seqNrs...)
			return nil
		})
	}, func() {})
	if err != nil {
		return err
	}

	delHtlcAttempts := func(batch map[lntypes.Hash][][]byte) error {
		return kvdb.Update(db, func(tx kvdb.RwTx) error {
			payments := tx.ReadWriteBucket(paymentsRootBucket)
			if payments == nil {
				return nil
			}

			// Delete the failed HTLC attempts we found.
			for hash, htlcIDs := range batch {
				bucket := payments.NestedReadWriteBucket(
					hash[:],
				)
				htlcsBucket := bucket.NestedReadWriteBucket(
					paymentHtlcsBucket,
				)

				for _, aid := range htlcIDs {
					err := htlcsBucket.DeleteNestedBucket(
						aid,
					)
					if err != nil {
						return err
					}
				}
			}

			return nil
		}, func() {})
	}

	delPayments := func(batch [][]byte) error {
		return kvdb.Update(db, func(tx kvdb.RwTx) error {
			payments := tx.ReadWriteBucket(paymentsRootBucket)
			if payments == nil {
				return nil
			}

			for _, k := range batch {
				err := payments.DeleteNestedBucket(k)
				if err != nil {
					return err
				}
			}

			return nil
		}, func() {})
	}

	delIndex := func(batch [][]byte) error {
		return kvdb.Update(db, func(tx kvdb.RwTx) error {
			payments := tx.ReadWriteBucket(paymentsRootBucket)
			if payments == nil {
				return nil
			}

			// Get our index bucket and delete all indexes pointing
			// to the payments we are deleting.
			indexBucket := tx.ReadWriteBucket(paymentsIndexBucket)
			for _, k := range batch {
				if err := indexBucket.Delete(k); err != nil {
					return err
				}
			}

			return nil
		}, func() {})
	}

	// Run batched deletes to reduce the size of each commit. Let's do the
	// HTLC attempts first.
	log.Debugf("Deleting %d failed HTLC attempts...", len(deleteHtlcs))
	const numOpsPerBatch = 1000
	numHtlcsDropped := 0
	htlcBatch := make(map[lntypes.Hash][][]byte, numOpsPerBatch)
	for hash, htlcIDs := range deleteHtlcs {
		htlcBatch[hash] = htlcIDs

		if len(htlcBatch) == numOpsPerBatch {
			if err := delHtlcAttempts(htlcBatch); err != nil {
				return err
			}
			htlcBatch = make(
				map[lntypes.Hash][][]byte, numOpsPerBatch,
			)
			numHtlcsDropped += numOpsPerBatch

			log.Debugf("Deleted %d of %d failed HTLC attempts",
				numHtlcsDropped, len(deleteHtlcs))
		}
	}

	// There might be a batch that didn't get full yet, let's flush that.
	if err := delHtlcAttempts(htlcBatch); err != nil {
		return err
	}

	// Now batch the payment buckets themselves.
	log.Debugf("Done deleting attempts, removing %d payments...",
		len(deleteBuckets))
	paymentBatch := make([][]byte, 0, numOpsPerBatch)
	for idx, payment := range deleteBuckets {
		paymentBatch = append(paymentBatch, payment)

		batchFull := idx%numOpsPerBatch == 0 ||
			idx == len(deleteBuckets)-1

		if idx > 0 && batchFull {
			if err := delPayments(paymentBatch); err != nil {
				return err
			}
			paymentBatch = make([][]byte, 0, numOpsPerBatch)

			log.Debugf("Deleted %d of %d payments", idx,
				len(deleteBuckets))
		}
	}

	// And finally the indices.
	log.Debugf("Done deleting payments, removing %d indices...",
		len(deleteIndexes))
	indexBatch := make([][]byte, 0, numOpsPerBatch)
	for idx, index := range deleteIndexes {
		indexBatch = append(indexBatch, index)

		batchFull := idx%numOpsPerBatch == 0 ||
			idx == len(deleteIndexes)-1

		if idx > 0 && batchFull {
			if err := delIndex(indexBatch); err != nil {
				return err
			}
			indexBatch = make([][]byte, 0, numOpsPerBatch)

			log.Debugf("Deleted %d of %d indices", idx,
				len(deleteIndexes))
		}
	}

	log.Debugf("Done deleting indices")
	return nil
}

// fetchSequenceNumbers fetches all the sequence numbers associated with a
// payment, including those belonging to any duplicate payments.
func fetchSequenceNumbers(paymentBucket kvdb.RBucket) ([][]byte, error) {
	seqNum := paymentBucket.Get(paymentSequenceKey)
	if seqNum == nil {
		return nil, errors.New("expected sequence number")
	}

	sequenceNumbers := [][]byte{seqNum}

	// Get the duplicate payments bucket, if it has no duplicates, just
	// return early with the payment sequence number.
	duplicates := paymentBucket.NestedReadBucket(duplicatePaymentsBucket)
	if duplicates == nil {
		return sequenceNumbers, nil
	}

	// If we do have duplicated, they are keyed by sequence number, so we
	// iterate through the duplicates bucket and add them to our set of
	// sequence numbers.
	if err := duplicates.ForEach(func(k, v []byte) error {
		sequenceNumbers = append(sequenceNumbers, k)
		return nil
	}); err != nil {
		return nil, err
	}

	return sequenceNumbers, nil
}

// nolint: dupl
func serializePaymentCreationInfo(w io.Writer, c *PaymentCreationInfo) error {
	var scratch [8]byte

	if _, err := w.Write(c.PaymentIdentifier[:]); err != nil {
		return err
	}

	byteOrder.PutUint64(scratch[:], uint64(c.Value))
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	if err := serializeTime(w, c.CreationTime); err != nil {
		return err
	}

	byteOrder.PutUint32(scratch[:4], uint32(len(c.PaymentRequest)))
	if _, err := w.Write(scratch[:4]); err != nil {
		return err
	}

	if _, err := w.Write(c.PaymentRequest[:]); err != nil {
		return err
	}

	return nil
}

func deserializePaymentCreationInfo(r io.Reader) (*PaymentCreationInfo, error) {
	var scratch [8]byte

	c := &PaymentCreationInfo{}

	if _, err := io.ReadFull(r, c.PaymentIdentifier[:]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(r, scratch[:]); err != nil {
		return nil, err
	}
	c.Value = lnwire.MilliSatoshi(byteOrder.Uint64(scratch[:]))

	creationTime, err := deserializeTime(r)
	if err != nil {
		return nil, err
	}
	c.CreationTime = creationTime

	if _, err := io.ReadFull(r, scratch[:4]); err != nil {
		return nil, err
	}

	reqLen := uint32(byteOrder.Uint32(scratch[:4]))
	payReq := make([]byte, reqLen)
	if reqLen > 0 {
		if _, err := io.ReadFull(r, payReq); err != nil {
			return nil, err
		}
	}
	c.PaymentRequest = payReq

	return c, nil
}

func serializeHTLCAttemptInfo(w io.Writer, a *HTLCAttemptInfo) error {
	if err := WriteElements(w, a.sessionKey); err != nil {
		return err
	}

	if err := SerializeRoute(w, a.Route); err != nil {
		return err
	}

	if err := serializeTime(w, a.AttemptTime); err != nil {
		return err
	}

	// If the hash is nil we can just return.
	if a.Hash == nil {
		return nil
	}

	if _, err := w.Write(a.Hash[:]); err != nil {
		return err
	}

	return nil
}

func deserializeHTLCAttemptInfo(r io.Reader) (*HTLCAttemptInfo, error) {
	a := &HTLCAttemptInfo{}
	err := ReadElements(r, &a.sessionKey)
	if err != nil {
		return nil, err
	}

	a.Route, err = DeserializeRoute(r)
	if err != nil {
		return nil, err
	}

	a.AttemptTime, err = deserializeTime(r)
	if err != nil {
		return nil, err
	}

	hash := lntypes.Hash{}
	_, err = io.ReadFull(r, hash[:])

	switch {

	// Older payment attempts wouldn't have the hash set, in which case we
	// can just return.
	case err == io.EOF, err == io.ErrUnexpectedEOF:
		return a, nil

	case err != nil:
		return nil, err

	default:
	}

	a.Hash = &hash

	return a, nil
}

func serializeHop(w io.Writer, h *route.Hop) error {
	if err := WriteElements(w,
		h.PubKeyBytes[:],
		h.ChannelID,
		h.OutgoingTimeLock,
		h.AmtToForward,
	); err != nil {
		return err
	}

	if err := binary.Write(w, byteOrder, h.LegacyPayload); err != nil {
		return err
	}

	// For legacy payloads, we don't need to write any TLV records, so
	// we'll write a zero indicating the our serialized TLV map has no
	// records.
	if h.LegacyPayload {
		return WriteElements(w, uint32(0))
	}

	// Gather all non-primitive TLV records so that they can be serialized
	// as a single blob.
	//
	// TODO(conner): add migration to unify all fields in a single TLV
	// blobs. The split approach will cause headaches down the road as more
	// fields are added, which we can avoid by having a single TLV stream
	// for all payload fields.
	var records []tlv.Record
	if h.MPP != nil {
		records = append(records, h.MPP.Record())
	}

	// Final sanity check to absolutely rule out custom records that are not
	// custom and write into the standard range.
	if err := h.CustomRecords.Validate(); err != nil {
		return err
	}

	// Convert custom records to tlv and add to the record list.
	// MapToRecords sorts the list, so adding it here will keep the list
	// canonical.
	tlvRecords := tlv.MapToRecords(h.CustomRecords)
	records = append(records, tlvRecords...)

	// Otherwise, we'll transform our slice of records into a map of the
	// raw bytes, then serialize them in-line with a length (number of
	// elements) prefix.
	mapRecords, err := tlv.RecordsToMap(records)
	if err != nil {
		return err
	}

	numRecords := uint32(len(mapRecords))
	if err := WriteElements(w, numRecords); err != nil {
		return err
	}

	for recordType, rawBytes := range mapRecords {
		if err := WriteElements(w, recordType); err != nil {
			return err
		}

		if err := wire.WriteVarBytes(w, 0, rawBytes); err != nil {
			return err
		}
	}

	return nil
}

// maxOnionPayloadSize is the largest Sphinx payload possible, so we don't need
// to read/write a TLV stream larger than this.
const maxOnionPayloadSize = 1300

func deserializeHop(r io.Reader) (*route.Hop, error) {
	h := &route.Hop{}

	var pub []byte
	if err := ReadElements(r, &pub); err != nil {
		return nil, err
	}
	copy(h.PubKeyBytes[:], pub)

	if err := ReadElements(r,
		&h.ChannelID, &h.OutgoingTimeLock, &h.AmtToForward,
	); err != nil {
		return nil, err
	}

	// TODO(roasbeef): change field to allow LegacyPayload false to be the
	// legacy default?
	err := binary.Read(r, byteOrder, &h.LegacyPayload)
	if err != nil {
		return nil, err
	}

	var numElements uint32
	if err := ReadElements(r, &numElements); err != nil {
		return nil, err
	}

	// If there're no elements, then we can return early.
	if numElements == 0 {
		return h, nil
	}

	tlvMap := make(map[uint64][]byte)
	for i := uint32(0); i < numElements; i++ {
		var tlvType uint64
		if err := ReadElements(r, &tlvType); err != nil {
			return nil, err
		}

		rawRecordBytes, err := wire.ReadVarBytes(
			r, 0, maxOnionPayloadSize, "tlv",
		)
		if err != nil {
			return nil, err
		}

		tlvMap[tlvType] = rawRecordBytes
	}

	// If the MPP type is present, remove it from the generic TLV map and
	// parse it back into a proper MPP struct.
	//
	// TODO(conner): add migration to unify all fields in a single TLV
	// blobs. The split approach will cause headaches down the road as more
	// fields are added, which we can avoid by having a single TLV stream
	// for all payload fields.
	mppType := uint64(record.MPPOnionType)
	if mppBytes, ok := tlvMap[mppType]; ok {
		delete(tlvMap, mppType)

		var (
			mpp    = &record.MPP{}
			mppRec = mpp.Record()
			r      = bytes.NewReader(mppBytes)
		)
		err := mppRec.Decode(r, uint64(len(mppBytes)))
		if err != nil {
			return nil, err
		}
		h.MPP = mpp
	}

	h.CustomRecords = tlvMap

	return h, nil
}

// SerializeRoute serializes a route.
func SerializeRoute(w io.Writer, r route.Route) error {
	if err := WriteElements(w,
		r.TotalTimeLock, r.TotalAmount, r.SourcePubKey[:],
	); err != nil {
		return err
	}

	if err := WriteElements(w, uint32(len(r.Hops))); err != nil {
		return err
	}

	for _, h := range r.Hops {
		if err := serializeHop(w, h); err != nil {
			return err
		}
	}

	return nil
}

// DeserializeRoute deserializes a route.
func DeserializeRoute(r io.Reader) (route.Route, error) {
	rt := route.Route{}
	if err := ReadElements(r,
		&rt.TotalTimeLock, &rt.TotalAmount,
	); err != nil {
		return rt, err
	}

	var pub []byte
	if err := ReadElements(r, &pub); err != nil {
		return rt, err
	}
	copy(rt.SourcePubKey[:], pub)

	var numHops uint32
	if err := ReadElements(r, &numHops); err != nil {
		return rt, err
	}

	var hops []*route.Hop
	for i := uint32(0); i < numHops; i++ {
		hop, err := deserializeHop(r)
		if err != nil {
			return rt, err
		}
		hops = append(hops, hop)
	}
	rt.Hops = hops

	return rt, nil
}
