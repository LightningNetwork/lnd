// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"encoding/json"
	"fmt"
)

// RPCErrorCode represents an error code to be used as a part of an RPCError
// which is in turn used in a JSON-RPC Response object.
//
// A specific type is used to help ensure the wrong errors aren't used.
type RPCErrorCode int

// RPCError represents an error that is used as a part of a JSON-RPC Response
// object.
type RPCError struct {
	Code    RPCErrorCode `json:"code,omitempty"`
	Message string       `json:"message,omitempty"`
}

// Guarantee RPCError satisfies the builtin error interface.
var _, _ error = RPCError{}, (*RPCError)(nil)

// Error returns a string describing the RPC error.  This satisfies the
// builtin error interface.
func (e RPCError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

// NewRPCError constructs and returns a new JSON-RPC error that is suitable
// for use in a JSON-RPC Response object.
func NewRPCError(code RPCErrorCode, message string) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
	}
}

// IsValidIDType checks that the ID field (which can go in any of the JSON-RPC
// requests, responses, or notifications) is valid.  JSON-RPC 1.0 allows any
// valid JSON type.  JSON-RPC 2.0 (which bitcoind follows for some parts) only
// allows string, number, or null, so this function restricts the allowed types
// to that list.  This function is only provided in case the caller is manually
// marshalling for some reason.    The functions which accept an ID in this
// package already call this function to ensure the provided id is valid.
func IsValidIDType(id interface{}) bool {
	switch id.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64,
		string,
		nil:
		return true
	default:
		return false
	}
}

// Request is a type for raw JSON-RPC 1.0 requests.  The Method field identifies
// the specific command type which in turns leads to different parameters.
// Callers typically will not use this directly since this package provides a
// statically typed command infrastructure which handles creation of these
// requests, however this struct it being exported in case the caller wants to
// construct raw requests for some reason.
type Request struct {
	Jsonrpc string            `json:"jsonrpc"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
	ID      interface{}       `json:"id"`
}

// NewRequest returns a new JSON-RPC 1.0 request object given the provided id,
// method, and parameters.  The parameters are marshalled into a json.RawMessage
// for the Params field of the returned request object.  This function is only
// provided in case the caller wants to construct raw requests for some reason.
//
// Typically callers will instead want to create a registered concrete command
// type with the NewCmd or New<Foo>Cmd functions and call the MarshalCmd
// function with that command to generate the marshalled JSON-RPC request.
func NewRequest(id interface{}, method string, params []interface{}) (*Request, error) {
	if !IsValidIDType(id) {
		str := fmt.Sprintf("the id of type '%T' is invalid", id)
		return nil, makeError(ErrInvalidType, str)
	}

	rawParams := make([]json.RawMessage, 0, len(params))
	for _, param := range params {
		marshalledParam, err := json.Marshal(param)
		if err != nil {
			return nil, err
		}
		rawMessage := json.RawMessage(marshalledParam)
		rawParams = append(rawParams, rawMessage)
	}

	return &Request{
		Jsonrpc: "1.0",
		ID:      id,
		Method:  method,
		Params:  rawParams,
	}, nil
}

// Response is the general form of a JSON-RPC response.  The type of the Result
// field varies from one command to the next, so it is implemented as an
// interface.  The ID field has to be a pointer for Go to put a null in it when
// empty.
type Response struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
	ID     *interface{}    `json:"id"`
}

// NewResponse returns a new JSON-RPC response object given the provided id,
// marshalled result, and RPC error.  This function is only provided in case the
// caller wants to construct raw responses for some reason.
//
// Typically callers will instead want to create the fully marshalled JSON-RPC
// response to send over the wire with the MarshalResponse function.
func NewResponse(id interface{}, marshalledResult []byte, rpcErr *RPCError) (*Response, error) {
	if !IsValidIDType(id) {
		str := fmt.Sprintf("the id of type '%T' is invalid", id)
		return nil, makeError(ErrInvalidType, str)
	}

	pid := &id
	return &Response{
		Result: marshalledResult,
		Error:  rpcErr,
		ID:     pid,
	}, nil
}

// MarshalResponse marshals the passed id, result, and RPCError to a JSON-RPC
// response byte slice that is suitable for transmission to a JSON-RPC client.
func MarshalResponse(id interface{}, result interface{}, rpcErr *RPCError) ([]byte, error) {
	marshalledResult, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	response, err := NewResponse(id, marshalledResult, rpcErr)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&response)
}
