// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_funding_signed is used by go-fuzz.
func Fuzz_funding_signed(data []byte) int {
	// Prefix with MsgFundingSigned.
	prefixWithMsgType(data, lnwire.MsgFundingSigned)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
