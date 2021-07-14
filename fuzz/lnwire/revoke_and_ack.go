// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_revoke_and_ack is used by go-fuzz.
func Fuzz_revoke_and_ack(data []byte) int {
	// Prefix with MsgRevokeAndAck.
	data = prefixWithMsgType(data, lnwire.MsgRevokeAndAck)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
