// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_error is used by go-fuzz.
func Fuzz_error(data []byte) int {
	// Prefix with MsgError.
	data = prefixWithMsgType(data, lnwire.MsgError)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
