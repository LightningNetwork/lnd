// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_gossip_timestamp_range is used by go-fuzz.
func Fuzz_gossip_timestamp_range(data []byte) int {
	// Prefix with MsgGossipTimestampRange.
	data = prefixWithMsgType(data, lnwire.MsgGossipTimestampRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
