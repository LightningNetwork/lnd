// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txrules provides transaction rules that should be followed by
// transaction authors for wide mempool acceptance and quick mining.
package txrules

import (
	"errors"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
const DefaultRelayFeePerKb btcutil.Amount = 1e3

// GetDustThreshold is used to define the amount below which output will be
// determined as dust. Threshold is determined as 3 times the relay fee.
func GetDustThreshold(scriptSize int, relayFeePerKb btcutil.Amount) btcutil.Amount {
	// Calculate the total (estimated) cost to the network.  This is
	// calculated using the serialize size of the output plus the serial
	// size of a transaction input which redeems it.  The output is assumed
	// to be compressed P2PKH as this is the most common script type.  Use
	// the average size of a compressed P2PKH redeem input (148) rather than
	// the largest possible (txsizes.RedeemP2PKHInputSize).
	totalSize := 8 + wire.VarIntSerializeSize(uint64(scriptSize)) +
		scriptSize + 148

	byteFee := relayFeePerKb / 1000
	relayFee := btcutil.Amount(totalSize) * byteFee
	return 3 * relayFee
}

// IsDustAmount determines whether a transaction output value and script length would
// cause the output to be considered dust.  Transactions with dust outputs are
// not standard and are rejected by mempools with default policies.
func IsDustAmount(amount btcutil.Amount, scriptSize int, relayFeePerKb btcutil.Amount) bool {
	return amount < GetDustThreshold(scriptSize, relayFeePerKb)
}

// IsDustOutput determines whether a transaction output is considered dust.
// Transactions with dust outputs are not standard and are rejected by mempools
// with default policies.
func IsDustOutput(output *wire.TxOut, relayFeePerKb btcutil.Amount) bool {
	// Unspendable outputs which solely carry data are not checked for dust.
	if txscript.GetScriptClass(output.PkScript) == txscript.NullDataTy {
		return false
	}

	// All other unspendable outputs are considered dust.
	if txscript.IsUnspendable(output.PkScript) {
		return true
	}

	return IsDustAmount(btcutil.Amount(output.Value), len(output.PkScript),
		relayFeePerKb)
}

// Transaction rule violations
var (
	ErrAmountNegative   = errors.New("transaction output amount is negative")
	ErrAmountExceedsMax = errors.New("transaction output amount exceeds maximum value")
	ErrOutputIsDust     = errors.New("transaction output is dust")
)

// CheckOutput performs simple consensus and policy tests on a transaction
// output.
func CheckOutput(output *wire.TxOut, relayFeePerKb btcutil.Amount) error {
	if output.Value < 0 {
		return ErrAmountNegative
	}
	if output.Value > btcutil.MaxSatoshi {
		return ErrAmountExceedsMax
	}
	if IsDustOutput(output, relayFeePerKb) {
		return ErrOutputIsDust
	}
	return nil
}

// FeeForSerializeSize calculates the required fee for a transaction of some
// arbitrary size given a mempool's relay fee policy.
func FeeForSerializeSize(relayFeePerKb btcutil.Amount, txSerializeSize int) btcutil.Amount {
	fee := relayFeePerKb * btcutil.Amount(txSerializeSize) / 1000

	if fee == 0 && relayFeePerKb > 0 {
		fee = relayFeePerKb
	}

	if fee < 0 || fee > btcutil.MaxSatoshi {
		fee = btcutil.MaxSatoshi
	}

	return fee
}
