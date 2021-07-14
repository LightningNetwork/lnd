// +build gofuzz

package lnwirefuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_open_channel is used by go-fuzz.
func Fuzz_open_channel(data []byte) int {
	// Prefix with MsgOpenChannel.
	data = prefixWithMsgType(data, lnwire.MsgOpenChannel)

	// We have to do this here instead of in fuzz.Harness so that
	// reflect.DeepEqual isn't called. Because of the UpfrontShutdownScript
	// encoding, the first message and second message aren't deeply equal since
	// the first has a nil slice and the other has an empty slice.

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Make sure byte array length (excluding 2 bytes for message type) is
	// less than max payload size for the wire message.
	payloadLen := uint32(len(data)) - 2
	if payloadLen > lnwire.MaxMsgBody {
		return 1
	}

	msg, err := lnwire.ReadMessage(r, 0)
	if err != nil {
		return 1
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	if _, err := lnwire.WriteMessage(&b, msg, 0); err != nil {
		// Could not serialize message into bytes buffer, panic
		panic(err)
	}

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := lnwire.ReadMessage(&b, 0)
	if err != nil {
		// Could not deserialize message from bytes buffer, panic
		panic(err)
	}

	// Now compare every field instead of using reflect.DeepEqual.
	// For UpfrontShutdownScript, we only compare bytes. This probably takes
	// up more branches than necessary, but that's fine for now.
	var shouldPanic bool
	first := msg.(*lnwire.OpenChannel)
	second := newMsg.(*lnwire.OpenChannel)

	if !first.ChainHash.IsEqual(&second.ChainHash) {
		shouldPanic = true
	}

	if !bytes.Equal(first.PendingChannelID[:], second.PendingChannelID[:]) {
		shouldPanic = true
	}

	if first.FundingAmount != second.FundingAmount {
		shouldPanic = true
	}

	if first.PushAmount != second.PushAmount {
		shouldPanic = true
	}

	if first.DustLimit != second.DustLimit {
		shouldPanic = true
	}

	if first.MaxValueInFlight != second.MaxValueInFlight {
		shouldPanic = true
	}

	if first.ChannelReserve != second.ChannelReserve {
		shouldPanic = true
	}

	if first.HtlcMinimum != second.HtlcMinimum {
		shouldPanic = true
	}

	if first.FeePerKiloWeight != second.FeePerKiloWeight {
		shouldPanic = true
	}

	if first.CsvDelay != second.CsvDelay {
		shouldPanic = true
	}

	if first.MaxAcceptedHTLCs != second.MaxAcceptedHTLCs {
		shouldPanic = true
	}

	if !first.FundingKey.IsEqual(second.FundingKey) {
		shouldPanic = true
	}

	if !first.RevocationPoint.IsEqual(second.RevocationPoint) {
		shouldPanic = true
	}

	if !first.PaymentPoint.IsEqual(second.PaymentPoint) {
		shouldPanic = true
	}

	if !first.DelayedPaymentPoint.IsEqual(second.DelayedPaymentPoint) {
		shouldPanic = true
	}

	if !first.HtlcPoint.IsEqual(second.HtlcPoint) {
		shouldPanic = true
	}

	if !first.FirstCommitmentPoint.IsEqual(second.FirstCommitmentPoint) {
		shouldPanic = true
	}

	if first.ChannelFlags != second.ChannelFlags {
		shouldPanic = true
	}

	if !bytes.Equal(first.UpfrontShutdownScript, second.UpfrontShutdownScript) {
		shouldPanic = true
	}

	if shouldPanic {
		panic("original message and deserialized message are not equal")
	}

	// Add this input to the corpus.
	return 1
}
