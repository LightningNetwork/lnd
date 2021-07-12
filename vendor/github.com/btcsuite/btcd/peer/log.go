// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
)

const (
	// maxRejectReasonLen is the maximum length of a sanitized reject reason
	// that will be logged.
	maxRejectReasonLen = 250
)

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var log btclog.Logger

// The default amount of logging is none.
func init() {
	DisableLog()
}

// DisableLog disables all library log output.  Logging output is disabled
// by default until UseLogger is called.
func DisableLog() {
	log = btclog.Disabled
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger btclog.Logger) {
	log = logger
}

// LogClosure is a closure that can be printed with %v to be used to
// generate expensive-to-create data for a detailed log level and avoid doing
// the work if the data isn't printed.
type logClosure func() string

func (c logClosure) String() string {
	return c()
}

func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// formatLockTime returns a transaction lock time as a human-readable string.
func formatLockTime(lockTime uint32) string {
	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the lockTimeThreshold.  When it is under the
	// threshold it is a block height.
	if lockTime < txscript.LockTimeThreshold {
		return fmt.Sprintf("height %d", lockTime)
	}

	return time.Unix(int64(lockTime), 0).String()
}

// invSummary returns an inventory message as a human-readable string.
func invSummary(invList []*wire.InvVect) string {
	// No inventory.
	invLen := len(invList)
	if invLen == 0 {
		return "empty"
	}

	// One inventory item.
	if invLen == 1 {
		iv := invList[0]
		switch iv.Type {
		case wire.InvTypeError:
			return fmt.Sprintf("error %s", iv.Hash)
		case wire.InvTypeWitnessBlock:
			return fmt.Sprintf("witness block %s", iv.Hash)
		case wire.InvTypeBlock:
			return fmt.Sprintf("block %s", iv.Hash)
		case wire.InvTypeWitnessTx:
			return fmt.Sprintf("witness tx %s", iv.Hash)
		case wire.InvTypeTx:
			return fmt.Sprintf("tx %s", iv.Hash)
		}

		return fmt.Sprintf("unknown (%d) %s", uint32(iv.Type), iv.Hash)
	}

	// More than one inv item.
	return fmt.Sprintf("size %d", invLen)
}

// locatorSummary returns a block locator as a human-readable string.
func locatorSummary(locator []*chainhash.Hash, stopHash *chainhash.Hash) string {
	if len(locator) > 0 {
		return fmt.Sprintf("locator %s, stop %s", locator[0], stopHash)
	}

	return fmt.Sprintf("no locator, stop %s", stopHash)

}

// sanitizeString strips any characters which are even remotely dangerous, such
// as html control characters, from the passed string.  It also limits it to
// the passed maximum size, which can be 0 for unlimited.  When the string is
// limited, it will also add "..." to the string to indicate it was truncated.
func sanitizeString(str string, maxLength uint) string {
	const safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY" +
		"Z01234567890 .,;_/:?@"

	// Strip any characters not in the safeChars string removed.
	str = strings.Map(func(r rune) rune {
		if strings.ContainsRune(safeChars, r) {
			return r
		}
		return -1
	}, str)

	// Limit the string to the max allowed length.
	if maxLength > 0 && uint(len(str)) > maxLength {
		str = str[:maxLength]
		str = str + "..."
	}
	return str
}

// messageSummary returns a human-readable string which summarizes a message.
// Not all messages have or need a summary.  This is used for debug logging.
func messageSummary(msg wire.Message) string {
	switch msg := msg.(type) {
	case *wire.MsgVersion:
		return fmt.Sprintf("agent %s, pver %d, block %d",
			msg.UserAgent, msg.ProtocolVersion, msg.LastBlock)

	case *wire.MsgVerAck:
		// No summary.

	case *wire.MsgGetAddr:
		// No summary.

	case *wire.MsgAddr:
		return fmt.Sprintf("%d addr", len(msg.AddrList))

	case *wire.MsgPing:
		// No summary - perhaps add nonce.

	case *wire.MsgPong:
		// No summary - perhaps add nonce.

	case *wire.MsgAlert:
		// No summary.

	case *wire.MsgMemPool:
		// No summary.

	case *wire.MsgTx:
		return fmt.Sprintf("hash %s, %d inputs, %d outputs, lock %s",
			msg.TxHash(), len(msg.TxIn), len(msg.TxOut),
			formatLockTime(msg.LockTime))

	case *wire.MsgBlock:
		header := &msg.Header
		return fmt.Sprintf("hash %s, ver %d, %d tx, %s", msg.BlockHash(),
			header.Version, len(msg.Transactions), header.Timestamp)

	case *wire.MsgInv:
		return invSummary(msg.InvList)

	case *wire.MsgNotFound:
		return invSummary(msg.InvList)

	case *wire.MsgGetData:
		return invSummary(msg.InvList)

	case *wire.MsgGetBlocks:
		return locatorSummary(msg.BlockLocatorHashes, &msg.HashStop)

	case *wire.MsgGetHeaders:
		return locatorSummary(msg.BlockLocatorHashes, &msg.HashStop)

	case *wire.MsgHeaders:
		return fmt.Sprintf("num %d", len(msg.Headers))

	case *wire.MsgGetCFHeaders:
		return fmt.Sprintf("start_height=%d, stop_hash=%v",
			msg.StartHeight, msg.StopHash)

	case *wire.MsgCFHeaders:
		return fmt.Sprintf("stop_hash=%v, num_filter_hashes=%d",
			msg.StopHash, len(msg.FilterHashes))

	case *wire.MsgReject:
		// Ensure the variable length strings don't contain any
		// characters which are even remotely dangerous such as HTML
		// control characters, etc.  Also limit them to sane length for
		// logging.
		rejCommand := sanitizeString(msg.Cmd, wire.CommandSize)
		rejReason := sanitizeString(msg.Reason, maxRejectReasonLen)
		summary := fmt.Sprintf("cmd %v, code %v, reason %v", rejCommand,
			msg.Code, rejReason)
		if rejCommand == wire.CmdBlock || rejCommand == wire.CmdTx {
			summary += fmt.Sprintf(", hash %v", msg.Hash)
		}
		return summary
	}

	// No summary for other messages.
	return ""
}
