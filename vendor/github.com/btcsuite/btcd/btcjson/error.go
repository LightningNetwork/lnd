// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"fmt"
)

// ErrorCode identifies a kind of error.  These error codes are NOT used for
// JSON-RPC response errors.
type ErrorCode int

// These constants are used to identify a specific RuleError.
const (
	// ErrDuplicateMethod indicates a command with the specified method
	// already exists.
	ErrDuplicateMethod ErrorCode = iota

	// ErrInvalidUsageFlags indicates one or more unrecognized flag bits
	// were specified.
	ErrInvalidUsageFlags

	// ErrInvalidType indicates a type was passed that is not the required
	// type.
	ErrInvalidType

	// ErrEmbeddedType indicates the provided command struct contains an
	// embedded type which is not not supported.
	ErrEmbeddedType

	// ErrUnexportedField indiciates the provided command struct contains an
	// unexported field which is not supported.
	ErrUnexportedField

	// ErrUnsupportedFieldType indicates the type of a field in the provided
	// command struct is not one of the supported types.
	ErrUnsupportedFieldType

	// ErrNonOptionalField indicates a non-optional field was specified
	// after an optional field.
	ErrNonOptionalField

	// ErrNonOptionalDefault indicates a 'jsonrpcdefault' struct tag was
	// specified for a non-optional field.
	ErrNonOptionalDefault

	// ErrMismatchedDefault indicates a 'jsonrpcdefault' struct tag contains
	// a value that doesn't match the type of the field.
	ErrMismatchedDefault

	// ErrUnregisteredMethod indicates a method was specified that has not
	// been registered.
	ErrUnregisteredMethod

	// ErrMissingDescription indicates a description required to generate
	// help is missing.
	ErrMissingDescription

	// ErrNumParams inidcates the number of params supplied do not
	// match the requirements of the associated command.
	ErrNumParams

	// numErrorCodes is the maximum error code number used in tests.
	numErrorCodes
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrDuplicateMethod:      "ErrDuplicateMethod",
	ErrInvalidUsageFlags:    "ErrInvalidUsageFlags",
	ErrInvalidType:          "ErrInvalidType",
	ErrEmbeddedType:         "ErrEmbeddedType",
	ErrUnexportedField:      "ErrUnexportedField",
	ErrUnsupportedFieldType: "ErrUnsupportedFieldType",
	ErrNonOptionalField:     "ErrNonOptionalField",
	ErrNonOptionalDefault:   "ErrNonOptionalDefault",
	ErrMismatchedDefault:    "ErrMismatchedDefault",
	ErrUnregisteredMethod:   "ErrUnregisteredMethod",
	ErrMissingDescription:   "ErrMissingDescription",
	ErrNumParams:            "ErrNumParams",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// Error identifies a general error.  This differs from an RPCError in that this
// error typically is used more by the consumers of the package as opposed to
// RPCErrors which are intended to be returned to the client across the wire via
// a JSON-RPC Response.  The caller can use type assertions to determine the
// specific error and access the ErrorCode field.
type Error struct {
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	return e.Description
}

// makeError creates an Error given a set of arguments.
func makeError(c ErrorCode, desc string) Error {
	return Error{ErrorCode: c, Description: desc}
}
