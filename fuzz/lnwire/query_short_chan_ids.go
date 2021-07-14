// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_query_short_chan_ids is used by go-fuzz.
func Fuzz_query_short_chan_ids(data []byte) int {
	// Prefix with MsgQueryShortChanIDs.
	data = prefixWithMsgType(data, lnwire.MsgQueryShortChanIDs)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
