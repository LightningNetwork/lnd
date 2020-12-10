package migration19

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	mig "github.com/lightningnetwork/lnd/channeldb/migration_01_to_11"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	// oldForwardingEventSize is the size of an old forwarding event.
	// The breakdown is as follows:
	//  * 8 byte incoming chan ID || 8 byte outgoing chan ID ||
	//    8 byte value in || 8 byte value out
	oldForwardingEventSize = 32

	// forwardingEventSize is the size of a new forwarding event.
	// The breakdown is as follows:
	//  * 8 byte incoming chan ID || 8 byte outgoing chan ID ||
	//    8 byte value in || 8 byte value out || 32 byte payment hash
	forwardingEventSize = 64
)

// OldForwardingEvent is an event in the forwarding log's time series.
type OldForwardingEvent struct {
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
}

// ForwardingEvent is the new forwarding event that has the PaymentHash field.
type ForwardingEvent struct {
	OldForwardingEvent

	// PaymentHash is the payment hash of the payment circuit.
	PaymentHash [32]byte
}

// decodeForwardingEvent attempts to decode the raw bytes of a serialized
// forwarding event into the target ForwardingEvent. This decoding method is
// used specifically for new ForwardingEvents which have the field PaymentHash.
func decodeForwardingEvent(v []byte) (*ForwardingEvent, error) {
	var e = &ForwardingEvent{}

	eventReader := bytes.NewReader(v)
	if err := mig.ReadElements(
		eventReader, &e.IncomingChanID, &e.OutgoingChanID,
		&e.AmtIn, &e.AmtOut, &e.PaymentHash,
	); err != nil {
		return nil, err
	}

	return e, nil
}

// storeOldEvent saves a OldForwardingEvent. This method is used to create
// testing events.
func storeOldEvent(bucket walletdb.ReadWriteBucket, event *OldForwardingEvent) error {
	// Make the key using the event's timestamp.
	var timestampScratchSpace [8]byte
	binary.BigEndian.PutUint64(
		timestampScratchSpace[:], uint64(event.Timestamp.UnixNano()),
	)

	// Encode the event into our buffer, then write it out to disk.
	var eventBytes [oldForwardingEventSize]byte
	eventBuf := bytes.NewBuffer(eventBytes[0:0:oldForwardingEventSize])

	if err := mig.WriteElements(
		eventBuf, event.IncomingChanID, event.OutgoingChanID,
		event.AmtIn, event.AmtOut,
	); err != nil {
		return nil
	}
	return bucket.Put(timestampScratchSpace[:], eventBuf.Bytes())
}
