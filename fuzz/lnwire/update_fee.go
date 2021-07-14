// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_update_fee is used by go-fuzz.
func Fuzz_update_fee(data []byte) int {
	// Prefix with MsgUpdateFee.
	data = prefixWithMsgType(data, lnwire.MsgUpdateFee)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
