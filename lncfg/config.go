package lncfg

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	// DefaultConfigFilename is the default configuration file name lnd
	// tries to load.
	DefaultConfigFilename = "lnd.conf"

	// DefaultMaxPendingChannels is the default maximum number of incoming
	// pending channels permitted per peer.
	DefaultMaxPendingChannels = 1

	// DefaultMaxOpenChannels is the default maximum number of open
	// channels allowed for the node. A value of 0 means no limit applied.
	DefaultMaxOpenChannels = 0

	// DefaultMaxOpenChannels is the default maximum number of open
	// channels allowed for the node. A value of 0 means no limit applied.
	DefaultApplyLimitsToAPI = false

	// DefaultIncomingBroadcastDelta defines the number of blocks before the
	// expiry of an incoming htlc at which we force close the channel. We
	// only go to chain if we also have the preimage to actually pull in the
	// htlc. BOLT #2 suggests 7 blocks. We use a few more for extra safety.
	// Within this window we need to get our sweep or 2nd level success tx
	// confirmed, because after that the remote party is also able to claim
	// the htlc using the timeout path.
	DefaultIncomingBroadcastDelta = 10

	// DefaultFinalCltvRejectDelta defines the number of blocks before the
	// expiry of an incoming exit hop htlc at which we cancel it back
	// immediately. It is an extra safety measure over the final cltv
	// requirement as it is defined in the invoice. It ensures that we
	// cancel back htlcs that, when held on to, may cause us to force close
	// the channel because we enter the incoming broadcast window. Bolt #11
	// suggests 9 blocks here. We use a few more for additional safety.
	//
	// There is still a small gap that remains between receiving the
	// RevokeAndAck and canceling back. If a new block arrives within that
	// window, we may still force close the channel. There is currently no
	// way to reject an UpdateAddHtlc of which we already know that it will
	// push us in the broadcast window.
	DefaultFinalCltvRejectDelta = DefaultIncomingBroadcastDelta + 3

	// DefaultOutgoingBroadcastDelta defines the number of blocks before the
	// expiry of an outgoing htlc at which we force close the channel. We
	// are not in a hurry to force close, because there is nothing to claim
	// for us. We do need to time the htlc out, because there may be an
	// incoming htlc that will time out too (albeit later). Bolt #2 suggests
	// a value of -1 here, but we allow one block less to prevent potential
	// confusion around the negative value. It means we force close the
	// channel at exactly the htlc expiry height.
	DefaultOutgoingBroadcastDelta = 0

	// DefaultOutgoingCltvRejectDelta defines the number of blocks before
	// the expiry of an outgoing htlc at which we don't want to offer it to
	// the next peer anymore. If that happens, we cancel back the incoming
	// htlc. This is to prevent the situation where we have an outstanding
	// htlc that brings or will soon bring us inside the outgoing broadcast
	// window and trigger us to force close the channel. Bolt #2 suggests a
	// value of 0. We pad it a bit, to prevent a slow round trip to the next
	// peer and a block arriving during that round trip to trigger force
	// closure.
	DefaultOutgoingCltvRejectDelta = DefaultOutgoingBroadcastDelta + 3
)

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// NormalizeNetwork returns the common name of a network type used to create
// file paths. This allows differently versioned networks to use the same path.
func NormalizeNetwork(network string) string {
	if strings.HasPrefix(network, "testnet") {
		return "testnet"
	}

	return network
}
