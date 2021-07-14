// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_funding_locked is used by go-fuzz.
func Fuzz_funding_locked(data []byte) int {
	// Prefix with MsgFundingLocked.
	data = prefixWithMsgType(data, lnwire.MsgFundingLocked)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
