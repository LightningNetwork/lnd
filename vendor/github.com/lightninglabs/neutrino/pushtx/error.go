package pushtx

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/wire"
)

// BroadcastErrorCode uniquely identifies the broadcast error.
type BroadcastErrorCode uint8

const (
	// Unknown is the code used when a transaction has been rejected by some
	// unknown reason by a peer.
	Unknown BroadcastErrorCode = iota

	// Invalid is the code used when a transaction has been deemed invalid
	// by a peer.
	Invalid

	// InsufficientFee is the code used when a transaction has been deemed
	// as having an insufficient fee by a peer.
	InsufficientFee

	// Mempool is the code used when a transaction already exists in a
	// peer's mempool.
	Mempool

	// Confirmed is the code used when a transaction has been deemed as
	// confirmed in the chain by a peer.
	Confirmed
)

func (c BroadcastErrorCode) String() string {
	switch c {
	case Invalid:
		return "Invalid"
	case InsufficientFee:
		return "InsufficientFee"
	case Mempool:
		return "Mempool"
	case Confirmed:
		return "Confirmed"
	default:
		return "Unknown"
	}
}

// BroadcastError is an error type that encompasses the different possible
// broadcast errors returned by the network.
type BroadcastError struct {
	// Code is the uniquely identifying code of the broadcast error.
	Code BroadcastErrorCode

	// Reason is the string detailing the reason as to why the transaction
	// was rejected.
	Reason string
}

// A compile-time constraint to ensure BroadcastError satisfies the error
// interface.
var _ error = (*BroadcastError)(nil)

// Error returns the reason of the broadcast error.
func (e *BroadcastError) Error() string {
	return e.Reason
}

// IsBroadcastError is a helper function that can be used to determine whether
// an error is a BroadcastError that matches any of the specified codes.
func IsBroadcastError(err error, codes ...BroadcastErrorCode) bool {
	broadcastErr, ok := err.(*BroadcastError)
	if !ok {
		return false
	}

	for _, code := range codes {
		if broadcastErr.Code == code {
			return true
		}
	}

	return false
}

// ParseBroadcastError maps a peer's reject message for a transaction to a
// BroadcastError.
func ParseBroadcastError(msg *wire.MsgReject, peerAddr string) *BroadcastError {
	// We'll determine the appropriate broadcast error code by looking at
	// the reject's message code and reason. The only reject codes returned
	// from peers (bitcoind and btcd) when attempting to accept a
	// transaction into their mempool are:
	//   RejectInvalid, RejectNonstandard, RejectInsufficientFee,
	//   RejectDuplicate
	var code BroadcastErrorCode
	switch {
	// The cases below apply for reject messages sent from any kind of peer.
	case msg.Code == wire.RejectInvalid || msg.Code == wire.RejectNonstandard:
		code = Invalid

	case msg.Code == wire.RejectInsufficientFee:
		code = InsufficientFee

	// The cases below apply for reject messages sent from bitcoind peers.
	//
	// If the transaction double spends an unconfirmed transaction in the
	// peer's mempool, then we'll deem it as invalid.
	case msg.Code == wire.RejectDuplicate &&
		strings.Contains(msg.Reason, "txn-mempool-conflict"):
		code = Invalid

	// If the transaction was rejected due to it already existing in the
	// peer's mempool, then return an error signaling so.
	case msg.Code == wire.RejectDuplicate &&
		strings.Contains(msg.Reason, "txn-already-in-mempool"):
		code = Mempool

	// If the transaction was rejected due to it already existing in the
	// chain according to our peer, then we'll return an error signaling so.
	case msg.Code == wire.RejectDuplicate &&
		strings.Contains(msg.Reason, "txn-already-known"):
		code = Confirmed

	// The cases below apply for reject messages sent from btcd peers.
	//
	// If the transaction double spends an unconfirmed transaction in the
	// peer's mempool, then we'll deem it as invalid.
	case msg.Code == wire.RejectDuplicate &&
		strings.Contains(msg.Reason, "already spent"):
		code = Invalid

	// If the transaction was rejected due to it already existing in the
	// peer's mempool, then return an error signaling so.
	case msg.Code == wire.RejectDuplicate &&
		strings.Contains(msg.Reason, "already have transaction"):
		code = Mempool

	// If the transaction was rejected due to it already existing in the
	// chain according to our peer, then we'll return an error signaling so.
	case msg.Code == wire.RejectDuplicate &&
		strings.Contains(msg.Reason, "transaction already exists"):
		code = Confirmed

	// Any other reject messages will use the unknown code.
	default:
		code = Unknown
	}

	reason := fmt.Sprintf("rejected by %v: %v", peerAddr, msg.Reason)
	return &BroadcastError{Code: code, Reason: reason}
}
