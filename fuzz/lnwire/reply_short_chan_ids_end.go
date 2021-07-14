// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_reply_short_chan_ids_end is used by go-fuzz.
func Fuzz_reply_short_chan_ids_end(data []byte) int {
	// Prefix with MsgReplyShortChanIDsEnd.
	data = prefixWithMsgType(data, lnwire.MsgReplyShortChanIDsEnd)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
