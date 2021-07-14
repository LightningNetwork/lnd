// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_channel_update is used by go-fuzz.
func Fuzz_channel_update(data []byte) int {
	// Prefix with MsgChannelUpdate.
	data = prefixWithMsgType(data, lnwire.MsgChannelUpdate)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
