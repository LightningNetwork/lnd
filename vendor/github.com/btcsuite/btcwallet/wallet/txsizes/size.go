// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txsizes

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
)

// Worst case script and input/output size estimates.
const (
	// RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that redeems a compressed P2PKH output.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	RedeemP2PKHSigScriptSize = 1 + 73 + 1 + 33

	// P2PKHPkScriptSize is the size of a transaction output script that
	// pays to a compressed pubkey hash.  It is calculated as:
	//
	//   - OP_DUP
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	//   - OP_EQUALVERIFY
	//   - OP_CHECKSIG
	P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

	// RedeemP2PKHInputSize is the worst case (largest) serialize size of a
	// transaction input redeeming a compressed P2PKH output.  It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 107
	//   - 107 bytes signature script
	//   - 4 bytes sequence
	RedeemP2PKHInputSize = 32 + 4 + 1 + RedeemP2PKHSigScriptSize + 4

	// P2PKHOutputSize is the serialize size of a transaction output with a
	// P2PKH output script.  It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 25
	//   - 25 bytes P2PKH output script
	P2PKHOutputSize = 8 + 1 + P2PKHPkScriptSize

	// P2WPKHPkScriptSize is the size of a transaction output script that
	// pays to a witness pubkey hash. It is calculated as:
	//
	//   - OP_0
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	P2WPKHPkScriptSize = 1 + 1 + 20

	// P2WPKHOutputSize is the serialize size of a transaction output with a
	// P2WPKH output script. It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 22
	//   - 22 bytes P2PKH output script
	P2WPKHOutputSize = 8 + 1 + P2WPKHPkScriptSize

	// RedeemP2WPKHScriptSize is the size of a transaction input script
	// that spends a pay-to-witness-public-key hash (P2WPKH). The redeem
	// script for P2WPKH spends MUST be empty.
	RedeemP2WPKHScriptSize = 0

	// RedeemP2WPKHInputSize is the worst case size of a transaction
	// input redeeming a P2WPKH output. It is calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte encoding empty redeem script
	//   - 0 bytes redeem script
	//   - 4 bytes sequence
	RedeemP2WPKHInputSize = 32 + 4 + 1 + RedeemP2WPKHScriptSize + 4

	// RedeemNestedP2WPKHScriptSize is the worst case size of a transaction
	// input script that redeems a pay-to-witness-key hash nested in P2SH
	// (P2SH-P2WPKH). It is calculated as:
	//
	//   - 1 byte compact int encoding value 22
	//   - OP_0
	//   - 1 byte compact int encoding value 20
	//   - 20 byte key hash
	RedeemNestedP2WPKHScriptSize = 1 + 1 + 1 + 20

	// RedeemNestedP2WPKHInputSize is the worst case size of a
	// transaction input redeeming a P2SH-P2WPKH output. It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 23
	//   - 23 bytes redeem script (scriptSig)
	//   - 4 bytes sequence
	RedeemNestedP2WPKHInputSize = 32 + 4 + 1 +
		RedeemNestedP2WPKHScriptSize + 4

	// RedeemP2WPKHInputWitnessWeight is the worst case weight of
	// a witness for spending P2WPKH and nested P2WPKH outputs. It
	// is calculated as:
	//
	//   - 1 wu compact int encoding value 2 (number of items)
	//   - 1 wu compact int encoding value 73
	//   - 72 wu DER signature + 1 wu sighash
	//   - 1 wu compact int encoding value 33
	//   - 33 wu serialized compressed pubkey
	RedeemP2WPKHInputWitnessWeight = 1 + 1 + 73 + 1 + 33
)

// SumOutputSerializeSizes sums up the serialized size of the supplied outputs.
func SumOutputSerializeSizes(outputs []*wire.TxOut) (serializeSize int) {
	for _, txOut := range outputs {
		serializeSize += txOut.SerializeSize()
	}
	return serializeSize
}

// EstimateSerializeSize returns a worst case serialize size estimate for a
// signed transaction that spends inputCount number of compressed P2PKH outputs
// and contains each transaction output from txOuts.  The estimated size is
// incremented for an additional P2PKH change output if addChangeOutput is true.
func EstimateSerializeSize(inputCount int, txOuts []*wire.TxOut, addChangeOutput bool) int {
	changeSize := 0
	outputCount := len(txOuts)
	if addChangeOutput {
		changeSize = P2PKHOutputSize
		outputCount++
	}

	// 8 additional bytes are for version and locktime
	return 8 + wire.VarIntSerializeSize(uint64(inputCount)) +
		wire.VarIntSerializeSize(uint64(outputCount)) +
		inputCount*RedeemP2PKHInputSize +
		SumOutputSerializeSizes(txOuts) +
		changeSize
}

// EstimateVirtualSize returns a worst case virtual size estimate for a
// signed transaction that spends the given number of P2PKH, P2WPKH and
// (nested) P2SH-P2WPKH outputs, and contains each transaction output
// from txOuts. The estimate is incremented for an additional P2PKH
// change output if addChangeOutput is true.
func EstimateVirtualSize(numP2PKHIns, numP2WPKHIns, numNestedP2WPKHIns int,
	txOuts []*wire.TxOut, addChangeOutput bool) int {
	changeSize := 0
	outputCount := len(txOuts)
	if addChangeOutput {
		// We are always using P2WPKH as change output.
		changeSize = P2WPKHOutputSize
		outputCount++
	}

	// Version 4 bytes + LockTime 4 bytes + Serialized var int size for the
	// number of transaction inputs and outputs + size of redeem scripts +
	// the size out the serialized outputs and change.
	baseSize := 8 +
		wire.VarIntSerializeSize(
			uint64(numP2PKHIns+numP2WPKHIns+numNestedP2WPKHIns)) +
		wire.VarIntSerializeSize(uint64(len(txOuts))) +
		numP2PKHIns*RedeemP2PKHInputSize +
		numP2WPKHIns*RedeemP2WPKHInputSize +
		numNestedP2WPKHIns*RedeemNestedP2WPKHInputSize +
		SumOutputSerializeSizes(txOuts) +
		changeSize

	// If this transaction has any witness inputs, we must count the
	// witness data.
	witnessWeight := 0
	if numP2WPKHIns+numNestedP2WPKHIns > 0 {
		// Additional 2 weight units for segwit marker + flag.
		witnessWeight = 2 +
			wire.VarIntSerializeSize(
				uint64(numP2WPKHIns+numNestedP2WPKHIns)) +
			numP2WPKHIns*RedeemP2WPKHInputWitnessWeight +
			numNestedP2WPKHIns*RedeemP2WPKHInputWitnessWeight
	}

	// We add 3 to the witness weight to make sure the result is
	// always rounded up.
	return baseSize + (witnessWeight+3)/blockchain.WitnessScaleFactor
}
