// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_init is used by go-fuzz.
func Fuzz_init(data []byte) int {
	// Prefix with MsgInit.
	data = prefixWithMsgType(data, lnwire.MsgInit)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
