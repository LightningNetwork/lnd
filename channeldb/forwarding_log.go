package channeldb

import (
	"bytes"
	"io"
	"sort"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// forwardingLogBucket is the bucket that we'll use to store the
	// forwarding log. The forwarding log contains a time series database
	// of the forwarding history of a lightning daemon. Each key within the
	// bucket is a timestamp (in nano seconds since the unix epoch), and
	// the value a slice of a forwarding event for that timestamp.
	forwardingLogBucket = []byte("circuit-fwd-log")
)

const (
	// forwardingEventSize is the size of a forwarding event. The breakdown
	// is as follows:
	//
	//  * 8 byte incoming chan ID || 8 byte outgoing chan ID ||
	//    8 byte value in || 8 byte value out || 32 byte payment hash
	//
	// From the value in and value out, callers can easily compute the
	// total fee extract from a forwarding event.
	forwardingEventSize = 64

	// MaxResponseEvents is the max number of forwarding events that will
	// be returned by a single query response. This size was selected to
	// safely remain under gRPC's 4MiB message size response limit. As each
	// full forwarding event (including the timestamp) is 72 bytes, we can
	// safely return 50k entries in a single response.
	MaxResponseEvents = 50000
)

// ForwardingLog returns an instance of the ForwardingLog object backed by the
// target database instance.
func (d *DB) ForwardingLog() *ForwardingLog {
	return &ForwardingLog{
		db: d,
	}
}

// ForwardingLog is a time series database that logs the fulfilment of payment
// circuits by a lightning network daemon. The log contains a series of
// forwarding events which map a timestamp to a forwarding event. A forwarding
// event describes which channels were used to create+settle a circuit, and the
// amount involved. Subtracting the outgoing amount from the incoming amount
// reveals the fee charged for the forwarding service.
type ForwardingLog struct {
	db *DB
}

// ForwardingEvent is an event in the forwarding log's time series. Each
// forwarding event logs the creation and tear-down of a payment circuit. A
// circuit is created once an incoming HTLC has been fully forwarded, and
// destroyed once the payment has been settled.
type ForwardingEvent struct {
	// Timestamp is the settlement time of this payment circuit.
	Timestamp time.Time

	// IncomingChanID is the incoming channel ID of the payment circuit.
	IncomingChanID lnwire.ShortChannelID

	// OutgoingChanID is the outgoing channel ID of the payment circuit.
	OutgoingChanID lnwire.ShortChannelID

	// AmtIn is the amount of the incoming HTLC. Subtracting this from the
	// outgoing amount gives the total fees of this payment circuit.
	AmtIn lnwire.MilliSatoshi

	// AmtOut is the amount of the outgoing HTLC. Subtracting the incoming
	// amount from this gives the total fees for this payment circuit.
	AmtOut lnwire.MilliSatoshi

	// PaymentHash is the payment hash of the payment circuit.
	PaymentHash [32]byte
}

// encodeForwardingEvent writes out the target forwarding event to the passed
// io.Writer, using the expected DB format. Note that the timestamp isn't
// serialized as this will be the key value within the bucket.
func encodeForwardingEvent(w io.Writer, f *ForwardingEvent) error {
	return WriteElements(
		w, f.IncomingChanID, f.OutgoingChanID, f.AmtIn, f.AmtOut,
		f.PaymentHash,
	)
}

// decodeForwardingEvent attempts to decode the raw bytes of a serialized
// forwarding event into the target ForwardingEvent. Note that the timestamp
// won't be decoded, as the caller is expected to set this due to the bucket
// structure of the forwarding log.
func decodeForwardingEvent(r io.Reader, f *ForwardingEvent) error {
	return ReadElements(
		r, &f.IncomingChanID, &f.OutgoingChanID, &f.AmtIn, &f.AmtOut,
		&f.PaymentHash,
	)
}

// AddForwardingEvents adds a series of forwarding events to the database.
// Before inserting, the set of events will be sorted according to their
// timestamp. This ensures that all writes to disk are sequential.
func (f *ForwardingLog) AddForwardingEvents(events []ForwardingEvent) error {
	// Before we create the database transaction, we'll ensure that the set
	// of forwarding events are properly sorted according to their
	// timestamp and that no duplicate timestamps exist to avoid collisions
	// in the key we are going to store the events under.
	makeUniqueTimestamps(events)

	var timestamp [8]byte

	return kvdb.Batch(f.db.Backend, func(tx kvdb.RwTx) error {
		// First, we'll fetch the bucket that stores our time series
		// log.
		logBucket, err := tx.CreateTopLevelBucket(
			forwardingLogBucket,
		)
		if err != nil {
			return err
		}

		// With the bucket obtained, we can now begin to write out the
		// series of events.
		for _, event := range events {
			err := storeEvent(logBucket, event, timestamp[:])
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// storeEvent tries to store a forwarding event into the given bucket by trying
// to avoid collisions. If a key for the event timestamp already exists in the
// database, the timestamp is incremented in nanosecond intervals until a "free"
// slot is found.
func storeEvent(bucket walletdb.ReadWriteBucket, event ForwardingEvent,
	timestampScratchSpace []byte) error {

	// First, we'll serialize this timestamp into our
	// timestamp buffer.
	byteOrder.PutUint64(
		timestampScratchSpace, uint64(event.Timestamp.UnixNano()),
	)

	// Next we'll loop until we find a "free" slot in the bucket to store
	// the event under. This should almost never happen unless we're running
	// on a system that has a very bad system clock that doesn't properly
	// resolve to nanosecond scale. We try up to 100 times (which would come
	// to a maximum shift of 0.1 microsecond which is acceptable for most
	// use cases). If we don't find a free slot, we just give up and let
	// the collision happen. Something must be wrong with the data in that
	// case, even on a very fast machine forwarding payments _will_ take a
	// few microseconds at least so we should find a nanosecond slot
	// somewhere.
	const maxTries = 100
	tries := 0
	for tries < maxTries {
		val := bucket.Get(timestampScratchSpace)
		if val == nil {
			break
		}

		// Collision, try the next nanosecond timestamp.
		nextNano := event.Timestamp.UnixNano() + 1
		event.Timestamp = time.Unix(0, nextNano)
		byteOrder.PutUint64(timestampScratchSpace, uint64(nextNano))
		tries++
	}

	// With the key encoded, we'll then encode the event
	// into our buffer, then write it out to disk.
	var eventBytes [forwardingEventSize]byte
	eventBuf := bytes.NewBuffer(eventBytes[0:0:forwardingEventSize])
	err := encodeForwardingEvent(eventBuf, &event)
	if err != nil {
		return err
	}
	return bucket.Put(timestampScratchSpace, eventBuf.Bytes())
}

// ForwardingEventQuery represents a query to the forwarding log payment
// circuit time series database. The query allows a caller to retrieve all
// records for a particular time slice, offset in that time slice, limiting the
// total number of responses returned.
type ForwardingEventQuery struct {
	// StartTime is the start time of the time slice.
	StartTime time.Time

	// EndTime is the end time of the time slice.
	EndTime time.Time

	// IndexOffset is the offset within the time slice to start at. This
	// can be used to start the response at a particular record.
	IndexOffset uint32

	// NumMaxEvents is the max number of events to return.
	NumMaxEvents uint32
}

// ForwardingLogTimeSlice is the response to a forwarding query. It includes
// the original query, the set  events that match the query, and an integer
// which represents the offset index of the last item in the set of retuned
// events. This integer allows callers to resume their query using this offset
// in the event that the query's response exceeds the max number of returnable
// events.
type ForwardingLogTimeSlice struct {
	ForwardingEventQuery

	// ForwardingEvents is the set of events in our time series that answer
	// the query embedded above.
	ForwardingEvents []ForwardingEvent

	// LastIndexOffset is the index of the last element in the set of
	// returned ForwardingEvents above. Callers can use this to resume
	// their query in the event that the time slice has too many events to
	// fit into a single response.
	LastIndexOffset uint32
}

// Query allows a caller to query the forwarding event time series for a
// particular time slice. The caller can control the precise time as well as
// the number of events to be returned.
//
// TODO(roasbeef): rename?
func (f *ForwardingLog) Query(q ForwardingEventQuery) (ForwardingLogTimeSlice, error) {
	var resp ForwardingLogTimeSlice

	// If the user provided an index offset, then we'll not know how many
	// records we need to skip. We'll also keep track of the record offset
	// as that's part of the final return value.
	recordsToSkip := q.IndexOffset
	recordOffset := q.IndexOffset

	err := kvdb.View(f.db, func(tx kvdb.RTx) error {
		// If the bucket wasn't found, then there aren't any events to
		// be returned.
		logBucket := tx.ReadBucket(forwardingLogBucket)
		if logBucket == nil {
			return ErrNoForwardingEvents
		}

		// We'll be using a cursor to seek into the database, so we'll
		// populate byte slices that represent the start of the key
		// space we're interested in, and the end.
		var startTime, endTime [8]byte
		byteOrder.PutUint64(startTime[:], uint64(q.StartTime.UnixNano()))
		byteOrder.PutUint64(endTime[:], uint64(q.EndTime.UnixNano()))

		// If we know that a set of log events exists, then we'll begin
		// our seek through the log in order to satisfy the query.
		// We'll continue until either we reach the end of the range,
		// or reach our max number of events.
		logCursor := logBucket.ReadCursor()
		timestamp, events := logCursor.Seek(startTime[:])
		for ; timestamp != nil && bytes.Compare(timestamp, endTime[:]) <= 0; timestamp, events = logCursor.Next() {
			// If our current return payload exceeds the max number
			// of events, then we'll exit now.
			if uint32(len(resp.ForwardingEvents)) >= q.NumMaxEvents {
				return nil
			}

			// If we're not yet past the user defined offset, then
			// we'll continue to seek forward.
			if recordsToSkip > 0 {
				recordsToSkip--
				continue
			}

			currentTime := time.Unix(
				0, int64(byteOrder.Uint64(timestamp)),
			)

			// At this point, we've skipped enough records to start
			// to collate our query. For each record, we'll
			// increment the final record offset so the querier can
			// utilize pagination to seek further.
			readBuf := bytes.NewReader(events)
			for readBuf.Len() != 0 {
				var event ForwardingEvent
				err := decodeForwardingEvent(readBuf, &event)
				if err != nil {
					return err
				}

				event.Timestamp = currentTime
				resp.ForwardingEvents = append(resp.ForwardingEvents, event)

				recordOffset++
			}
		}

		return nil
	}, func() {
		resp = ForwardingLogTimeSlice{
			ForwardingEventQuery: q,
		}
	})
	if err != nil && err != ErrNoForwardingEvents {
		return ForwardingLogTimeSlice{}, err
	}

	resp.LastIndexOffset = recordOffset

	return resp, nil
}

// makeUniqueTimestamps takes a slice of forwarding events, sorts it by the
// event timestamps and then makes sure there are no duplicates in the
// timestamps. If duplicates are found, some of the timestamps are increased on
// the nanosecond scale until only unique values remain. This is a fix to
// address the problem that in some environments (looking at you, Windows) the
// system clock has such a bad resolution that two serial invocations of
// time.Now() might return the same timestamp, even if some time has elapsed
// between the calls.
func makeUniqueTimestamps(events []ForwardingEvent) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	// Now that we know the events are sorted by timestamp, we can go
	// through the list and fix all duplicates until only unique values
	// remain.
	for outer := 0; outer < len(events)-1; outer++ {
		current := events[outer].Timestamp.UnixNano()
		next := events[outer+1].Timestamp.UnixNano()

		// We initially sorted the slice. So if the current is now
		// greater or equal to the next one, it's either because it's a
		// duplicate or because we increased the current in the last
		// iteration.
		if current >= next {
			next = current + 1
			events[outer+1].Timestamp = time.Unix(0, next)
		}
	}
}
