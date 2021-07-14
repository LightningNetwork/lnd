// +build gofuzz

package lnwirefuzz

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_commit_sig is used by go-fuzz.
func Fuzz_commit_sig(data []byte) int {
	// Prefix with MsgCommitSig.
	data = prefixWithMsgType(data, lnwire.MsgCommitSig)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
