// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_pong is used by go-fuzz.
func Fuzz_pong(data []byte) int {
	// Prefix with MsgPong.
	data = prefixWithMsgType(data, lnwire.MsgPong)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
