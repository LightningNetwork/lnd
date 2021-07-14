// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_announce_signatures is used by go-fuzz.
func Fuzz_announce_signatures(data []byte) int {
	// Prefix with MsgAnnounceSignatures.
	data = prefixWithMsgType(data, lnwire.MsgAnnounceSignatures)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
