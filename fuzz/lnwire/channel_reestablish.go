// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_channel_reestablish is used by go-fuzz.
func Fuzz_channel_reestablish(data []byte) int {
	// Prefix with MsgChannelReestablish.
	data = prefixWithMsgType(data, lnwire.MsgChannelReestablish)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
