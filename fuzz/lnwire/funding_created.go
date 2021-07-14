// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_funding_created is used by go-fuzz.
func Fuzz_funding_created(data []byte) int {
	// Prefix with MsgFundingCreated.
	data = prefixWithMsgType(data, lnwire.MsgFundingCreated)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
