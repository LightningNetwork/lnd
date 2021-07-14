// +build gofuzz

package lnwirefuzz

import (
	"bytes"
	"encoding/binary"
	"reflect"

	"github.com/lightningnetwork/lnd/lnwire"
)

// prefixWithMsgType takes []byte and adds a wire protocol prefix
// to make the []byte into an actual message to be used in fuzzing.
func prefixWithMsgType(data []byte, prefix lnwire.MessageType) []byte {
	var prefixBytes [2]byte
	binary.BigEndian.PutUint16(prefixBytes[:], uint16(prefix))
	data = append(prefixBytes[:], data...)
	return data
}

// harness performs the actual fuzz testing of the appropriate wire message.
// This function will check that the passed-in message passes wire length checks,
// is a valid message once deserialized, and passes a sequence of serialization
// and deserialization checks. Returns an int that determines whether the input
// is unique or not.
func harness(data []byte) int {
	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Check that the created message is not greater than the maximum
	// message size.
	if len(data) > lnwire.MaxMessagePayload {
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

	if !reflect.DeepEqual(msg, newMsg) {
		// Deserialized message and original message are not deeply equal.
		panic("original message and deserialized message are not deeply equal")
	}

	return 1
}
