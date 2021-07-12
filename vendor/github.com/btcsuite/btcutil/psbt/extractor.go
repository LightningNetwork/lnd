// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// The Extractor requires provision of a single PSBT
// in which all necessary signatures are encoded, and
// uses it to construct a fully valid network serialized
// transaction.

import (
	"bytes"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Extract takes a finalized psbt.Packet and outputs a finalized transaction
// instance. Note that if the PSBT is in-complete, then an error
// ErrIncompletePSBT will be returned. As the extracted transaction has been
// fully finalized, it will be ready for network broadcast once returned.
func Extract(p *Packet) (*wire.MsgTx, error) {
	// If the packet isn't complete, then we'll return an error as it
	// doesn't have all the required witness data.
	if !p.IsComplete() {
		return nil, ErrIncompletePSBT
	}

	// First, we'll make a copy of the underlying unsigned transaction (the
	// initial template) so we don't mutate it during our activates below.
	finalTx := p.UnsignedTx.Copy()

	// For each input, we'll now populate any relevant witness and
	// sigScript data.
	for i, tin := range finalTx.TxIn {
		// We'll grab the corresponding internal packet input which
		// matches this materialized transaction input and emplace that
		// final sigScript (if present).
		pInput := p.Inputs[i]
		if pInput.FinalScriptSig != nil {
			tin.SignatureScript = pInput.FinalScriptSig
		}

		// Similarly, if there's a final witness, then we'll also need
		// to extract that as well, parsing the lower-level transaction
		// encoding.
		if pInput.FinalScriptWitness != nil {
			// In order to set the witness, need to re-deserialize
			// the field as encoded within the PSBT packet.  For
			// each input, the witness is encoded as a stack with
			// one or more items.
			witnessReader := bytes.NewReader(
				pInput.FinalScriptWitness,
			)

			// First we extract the number of witness elements
			// encoded in the above witnessReader.
			witCount, err := wire.ReadVarInt(witnessReader, 0)
			if err != nil {
				return nil, err
			}

			// Now that we know how may inputs we'll need, we'll
			// construct a packing slice, then read out each input
			// (with a varint prefix) from the witnessReader.
			tin.Witness = make(wire.TxWitness, witCount)
			for j := uint64(0); j < witCount; j++ {
				wit, err := wire.ReadVarBytes(
					witnessReader, 0, txscript.MaxScriptSize, "witness",
				)
				if err != nil {
					return nil, err
				}
				tin.Witness[j] = wit
			}
		}
	}

	return finalTx, nil
}
