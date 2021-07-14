// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_ping is used by go-fuzz.
func Fuzz_ping(data []byte) int {
	// Prefix with MsgPing.
	data = prefixWithMsgType(data, lnwire.MsgPing)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
