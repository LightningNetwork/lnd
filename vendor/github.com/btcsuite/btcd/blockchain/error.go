// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
)

// DeploymentError identifies an error that indicates a deployment ID was
// specified that does not exist.
type DeploymentError uint32

// Error returns the assertion error as a human-readable string and satisfies
// the error interface.
func (e DeploymentError) Error() string {
	return fmt.Sprintf("deployment ID %d does not exist", uint32(e))
}

// AssertError identifies an error that indicates an internal code consistency
// issue and should be treated as a critical and unrecoverable error.
type AssertError string

// Error returns the assertion error as a human-readable string and satisfies
// the error interface.
func (e AssertError) Error() string {
	return "assertion failed: " + string(e)
}

// ErrorCode identifies a kind of error.
type ErrorCode int

// These constants are used to identify a specific RuleError.
const (
	// ErrDuplicateBlock indicates a block with the same hash already
	// exists.
	ErrDuplicateBlock ErrorCode = iota

	// ErrBlockTooBig indicates the serialized block size exceeds the
	// maximum allowed size.
	ErrBlockTooBig

	// ErrBlockWeightTooHigh indicates that the block's computed weight
	// metric exceeds the maximum allowed value.
	ErrBlockWeightTooHigh

	// ErrBlockVersionTooOld indicates the block version is too old and is
	// no longer accepted since the majority of the network has upgraded
	// to a newer version.
	ErrBlockVersionTooOld

	// ErrInvalidTime indicates the time in the passed block has a precision
	// that is more than one second.  The chain consensus rules require
	// timestamps to have a maximum precision of one second.
	ErrInvalidTime

	// ErrTimeTooOld indicates the time is either before the median time of
	// the last several blocks per the chain consensus rules or prior to the
	// most recent checkpoint.
	ErrTimeTooOld

	// ErrTimeTooNew indicates the time is too far in the future as compared
	// the current time.
	ErrTimeTooNew

	// ErrDifficultyTooLow indicates the difficulty for the block is lower
	// than the difficulty required by the most recent checkpoint.
	ErrDifficultyTooLow

	// ErrUnexpectedDifficulty indicates specified bits do not align with
	// the expected value either because it doesn't match the calculated
	// valued based on difficulty regarted rules or it is out of the valid
	// range.
	ErrUnexpectedDifficulty

	// ErrHighHash indicates the block does not hash to a value which is
	// lower than the required target difficultly.
	ErrHighHash

	// ErrBadMerkleRoot indicates the calculated merkle root does not match
	// the expected value.
	ErrBadMerkleRoot

	// ErrBadCheckpoint indicates a block that is expected to be at a
	// checkpoint height does not match the expected one.
	ErrBadCheckpoint

	// ErrForkTooOld indicates a block is attempting to fork the block chain
	// before the most recent checkpoint.
	ErrForkTooOld

	// ErrCheckpointTimeTooOld indicates a block has a timestamp before the
	// most recent checkpoint.
	ErrCheckpointTimeTooOld

	// ErrNoTransactions indicates the block does not have a least one
	// transaction.  A valid block must have at least the coinbase
	// transaction.
	ErrNoTransactions

	// ErrNoTxInputs indicates a transaction does not have any inputs.  A
	// valid transaction must have at least one input.
	ErrNoTxInputs

	// ErrNoTxOutputs indicates a transaction does not have any outputs.  A
	// valid transaction must have at least one output.
	ErrNoTxOutputs

	// ErrTxTooBig indicates a transaction exceeds the maximum allowed size
	// when serialized.
	ErrTxTooBig

	// ErrBadTxOutValue indicates an output value for a transaction is
	// invalid in some way such as being out of range.
	ErrBadTxOutValue

	// ErrDuplicateTxInputs indicates a transaction references the same
	// input more than once.
	ErrDuplicateTxInputs

	// ErrBadTxInput indicates a transaction input is invalid in some way
	// such as referencing a previous transaction outpoint which is out of
	// range or not referencing one at all.
	ErrBadTxInput

	// ErrMissingTxOut indicates a transaction output referenced by an input
	// either does not exist or has already been spent.
	ErrMissingTxOut

	// ErrUnfinalizedTx indicates a transaction has not been finalized.
	// A valid block may only contain finalized transactions.
	ErrUnfinalizedTx

	// ErrDuplicateTx indicates a block contains an identical transaction
	// (or at least two transactions which hash to the same value).  A
	// valid block may only contain unique transactions.
	ErrDuplicateTx

	// ErrOverwriteTx indicates a block contains a transaction that has
	// the same hash as a previous transaction which has not been fully
	// spent.
	ErrOverwriteTx

	// ErrImmatureSpend indicates a transaction is attempting to spend a
	// coinbase that has not yet reached the required maturity.
	ErrImmatureSpend

	// ErrSpendTooHigh indicates a transaction is attempting to spend more
	// value than the sum of all of its inputs.
	ErrSpendTooHigh

	// ErrBadFees indicates the total fees for a block are invalid due to
	// exceeding the maximum possible value.
	ErrBadFees

	// ErrTooManySigOps indicates the total number of signature operations
	// for a transaction or block exceed the maximum allowed limits.
	ErrTooManySigOps

	// ErrFirstTxNotCoinbase indicates the first transaction in a block
	// is not a coinbase transaction.
	ErrFirstTxNotCoinbase

	// ErrMultipleCoinbases indicates a block contains more than one
	// coinbase transaction.
	ErrMultipleCoinbases

	// ErrBadCoinbaseScriptLen indicates the length of the signature script
	// for a coinbase transaction is not within the valid range.
	ErrBadCoinbaseScriptLen

	// ErrBadCoinbaseValue indicates the amount of a coinbase value does
	// not match the expected value of the subsidy plus the sum of all fees.
	ErrBadCoinbaseValue

	// ErrMissingCoinbaseHeight indicates the coinbase transaction for a
	// block does not start with the serialized block block height as
	// required for version 2 and higher blocks.
	ErrMissingCoinbaseHeight

	// ErrBadCoinbaseHeight indicates the serialized block height in the
	// coinbase transaction for version 2 and higher blocks does not match
	// the expected value.
	ErrBadCoinbaseHeight

	// ErrScriptMalformed indicates a transaction script is malformed in
	// some way.  For example, it might be longer than the maximum allowed
	// length or fail to parse.
	ErrScriptMalformed

	// ErrScriptValidation indicates the result of executing transaction
	// script failed.  The error covers any failure when executing scripts
	// such signature verification failures and execution past the end of
	// the stack.
	ErrScriptValidation

	// ErrUnexpectedWitness indicates that a block includes transactions
	// with witness data, but doesn't also have a witness commitment within
	// the coinbase transaction.
	ErrUnexpectedWitness

	// ErrInvalidWitnessCommitment indicates that a block's witness
	// commitment is not well formed.
	ErrInvalidWitnessCommitment

	// ErrWitnessCommitmentMismatch indicates that the witness commitment
	// included in the block's coinbase transaction doesn't match the
	// manually computed witness commitment.
	ErrWitnessCommitmentMismatch

	// ErrPreviousBlockUnknown indicates that the previous block is not known.
	ErrPreviousBlockUnknown

	// ErrInvalidAncestorBlock indicates that an ancestor of this block has
	// already failed validation.
	ErrInvalidAncestorBlock

	// ErrPrevBlockNotBest indicates that the block's previous block is not the
	// current chain tip. This is not a block validation rule, but is required
	// for block proposals submitted via getblocktemplate RPC.
	ErrPrevBlockNotBest
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrDuplicateBlock:            "ErrDuplicateBlock",
	ErrBlockTooBig:               "ErrBlockTooBig",
	ErrBlockVersionTooOld:        "ErrBlockVersionTooOld",
	ErrBlockWeightTooHigh:        "ErrBlockWeightTooHigh",
	ErrInvalidTime:               "ErrInvalidTime",
	ErrTimeTooOld:                "ErrTimeTooOld",
	ErrTimeTooNew:                "ErrTimeTooNew",
	ErrDifficultyTooLow:          "ErrDifficultyTooLow",
	ErrUnexpectedDifficulty:      "ErrUnexpectedDifficulty",
	ErrHighHash:                  "ErrHighHash",
	ErrBadMerkleRoot:             "ErrBadMerkleRoot",
	ErrBadCheckpoint:             "ErrBadCheckpoint",
	ErrForkTooOld:                "ErrForkTooOld",
	ErrCheckpointTimeTooOld:      "ErrCheckpointTimeTooOld",
	ErrNoTransactions:            "ErrNoTransactions",
	ErrNoTxInputs:                "ErrNoTxInputs",
	ErrNoTxOutputs:               "ErrNoTxOutputs",
	ErrTxTooBig:                  "ErrTxTooBig",
	ErrBadTxOutValue:             "ErrBadTxOutValue",
	ErrDuplicateTxInputs:         "ErrDuplicateTxInputs",
	ErrBadTxInput:                "ErrBadTxInput",
	ErrMissingTxOut:              "ErrMissingTxOut",
	ErrUnfinalizedTx:             "ErrUnfinalizedTx",
	ErrDuplicateTx:               "ErrDuplicateTx",
	ErrOverwriteTx:               "ErrOverwriteTx",
	ErrImmatureSpend:             "ErrImmatureSpend",
	ErrSpendTooHigh:              "ErrSpendTooHigh",
	ErrBadFees:                   "ErrBadFees",
	ErrTooManySigOps:             "ErrTooManySigOps",
	ErrFirstTxNotCoinbase:        "ErrFirstTxNotCoinbase",
	ErrMultipleCoinbases:         "ErrMultipleCoinbases",
	ErrBadCoinbaseScriptLen:      "ErrBadCoinbaseScriptLen",
	ErrBadCoinbaseValue:          "ErrBadCoinbaseValue",
	ErrMissingCoinbaseHeight:     "ErrMissingCoinbaseHeight",
	ErrBadCoinbaseHeight:         "ErrBadCoinbaseHeight",
	ErrScriptMalformed:           "ErrScriptMalformed",
	ErrScriptValidation:          "ErrScriptValidation",
	ErrUnexpectedWitness:         "ErrUnexpectedWitness",
	ErrInvalidWitnessCommitment:  "ErrInvalidWitnessCommitment",
	ErrWitnessCommitmentMismatch: "ErrWitnessCommitmentMismatch",
	ErrPreviousBlockUnknown:      "ErrPreviousBlockUnknown",
	ErrInvalidAncestorBlock:      "ErrInvalidAncestorBlock",
	ErrPrevBlockNotBest:          "ErrPrevBlockNotBest",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// RuleError identifies a rule violation.  It is used to indicate that
// processing of a block or transaction failed due to one of the many validation
// rules.  The caller can use type assertions to determine if a failure was
// specifically due to a rule violation and access the ErrorCode field to
// ascertain the specific reason for the rule violation.
type RuleError struct {
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
}

// Error satisfies the error interface and prints human-readable errors.
func (e RuleError) Error() string {
	return e.Description
}

// ruleError creates an RuleError given a set of arguments.
func ruleError(c ErrorCode, desc string) RuleError {
	return RuleError{ErrorCode: c, Description: desc}
}
