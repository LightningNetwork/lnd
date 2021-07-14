// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_channel_announcement is used by go-fuzz.
func Fuzz_channel_announcement(data []byte) int {
	// Prefix with MsgChannelAnnouncement.
	data = prefixWithMsgType(data, lnwire.MsgChannelAnnouncement)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
