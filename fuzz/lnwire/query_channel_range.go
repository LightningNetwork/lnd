// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_query_channel_range is used by go-fuzz.
func Fuzz_query_channel_range(data []byte) int {
	// Prefix with MsgQueryChannelRange.
	data = prefixWithMsgType(data, lnwire.MsgQueryChannelRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
