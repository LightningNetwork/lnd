// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// UsageFlag define flags that specify additional properties about the
// circumstances under which a command can be used.
type UsageFlag uint32

const (
	// UFWalletOnly indicates that the command can only be used with an RPC
	// server that supports wallet commands.
	UFWalletOnly UsageFlag = 1 << iota

	// UFWebsocketOnly indicates that the command can only be used when
	// communicating with an RPC server over websockets.  This typically
	// applies to notifications and notification registration functions
	// since neiher makes since when using a single-shot HTTP-POST request.
	UFWebsocketOnly

	// UFNotification indicates that the command is actually a notification.
	// This means when it is marshalled, the ID must be nil.
	UFNotification

	// highestUsageFlagBit is the maximum usage flag bit and is used in the
	// stringer and tests to ensure all of the above constants have been
	// tested.
	highestUsageFlagBit
)

// Map of UsageFlag values back to their constant names for pretty printing.
var usageFlagStrings = map[UsageFlag]string{
	UFWalletOnly:    "UFWalletOnly",
	UFWebsocketOnly: "UFWebsocketOnly",
	UFNotification:  "UFNotification",
}

// String returns the UsageFlag in human-readable form.
func (fl UsageFlag) String() string {
	// No flags are set.
	if fl == 0 {
		return "0x0"
	}

	// Add individual bit flags.
	s := ""
	for flag := UFWalletOnly; flag < highestUsageFlagBit; flag <<= 1 {
		if fl&flag == flag {
			s += usageFlagStrings[flag] + "|"
			fl -= flag
		}
	}

	// Add remaining value as raw hex.
	s = strings.TrimRight(s, "|")
	if fl != 0 {
		s += "|0x" + strconv.FormatUint(uint64(fl), 16)
	}
	s = strings.TrimLeft(s, "|")
	return s
}

// methodInfo keeps track of information about each registered method such as
// the parameter information.
type methodInfo struct {
	maxParams    int
	numReqParams int
	numOptParams int
	defaults     map[int]reflect.Value
	flags        UsageFlag
	usage        string
}

var (
	// These fields are used to map the registered types to method names.
	registerLock         sync.RWMutex
	methodToConcreteType = make(map[string]reflect.Type)
	methodToInfo         = make(map[string]methodInfo)
	concreteTypeToMethod = make(map[reflect.Type]string)
)

// baseKindString returns the base kind for a given reflect.Type after
// indirecting through all pointers.
func baseKindString(rt reflect.Type) string {
	numIndirects := 0
	for rt.Kind() == reflect.Ptr {
		numIndirects++
		rt = rt.Elem()
	}

	return fmt.Sprintf("%s%s", strings.Repeat("*", numIndirects), rt.Kind())
}

// isAcceptableKind returns whether or not the passed field type is a supported
// type.  It is called after the first pointer indirection, so further pointers
// are not supported.
func isAcceptableKind(kind reflect.Kind) bool {
	switch kind {
	case reflect.Chan:
		fallthrough
	case reflect.Complex64:
		fallthrough
	case reflect.Complex128:
		fallthrough
	case reflect.Func:
		fallthrough
	case reflect.Ptr:
		fallthrough
	case reflect.Interface:
		return false
	}

	return true
}

// RegisterCmd registers a new command that will automatically marshal to and
// from JSON-RPC with full type checking and positional parameter support.  It
// also accepts usage flags which identify the circumstances under which the
// command can be used.
//
// This package automatically registers all of the exported commands by default
// using this function, however it is also exported so callers can easily
// register custom types.
//
// The type format is very strict since it needs to be able to automatically
// marshal to and from JSON-RPC 1.0.  The following enumerates the requirements:
//
//   - The provided command must be a single pointer to a struct
//   - All fields must be exported
//   - The order of the positional parameters in the marshalled JSON will be in
//     the same order as declared in the struct definition
//   - Struct embedding is not supported
//   - Struct fields may NOT be channels, functions, complex, or interface
//   - A field in the provided struct with a pointer is treated as optional
//   - Multiple indirections (i.e **int) are not supported
//   - Once the first optional field (pointer) is encountered, the remaining
//     fields must also be optional fields (pointers) as required by positional
//     params
//   - A field that has a 'jsonrpcdefault' struct tag must be an optional field
//     (pointer)
//
// NOTE: This function only needs to be able to examine the structure of the
// passed struct, so it does not need to be an actual instance.  Therefore, it
// is recommended to simply pass a nil pointer cast to the appropriate type.
// For example, (*FooCmd)(nil).
func RegisterCmd(method string, cmd interface{}, flags UsageFlag) error {
	registerLock.Lock()
	defer registerLock.Unlock()

	if _, ok := methodToConcreteType[method]; ok {
		str := fmt.Sprintf("method %q is already registered", method)
		return makeError(ErrDuplicateMethod, str)
	}

	// Ensure that no unrecognized flag bits were specified.
	if ^(highestUsageFlagBit-1)&flags != 0 {
		str := fmt.Sprintf("invalid usage flags specified for method "+
			"%s: %v", method, flags)
		return makeError(ErrInvalidUsageFlags, str)
	}

	rtp := reflect.TypeOf(cmd)
	if rtp.Kind() != reflect.Ptr {
		str := fmt.Sprintf("type must be *struct not '%s (%s)'", rtp,
			rtp.Kind())
		return makeError(ErrInvalidType, str)
	}
	rt := rtp.Elem()
	if rt.Kind() != reflect.Struct {
		str := fmt.Sprintf("type must be *struct not '%s (*%s)'",
			rtp, rt.Kind())
		return makeError(ErrInvalidType, str)
	}

	// Enumerate the struct fields to validate them and gather parameter
	// information.
	numFields := rt.NumField()
	numOptFields := 0
	defaults := make(map[int]reflect.Value)
	for i := 0; i < numFields; i++ {
		rtf := rt.Field(i)
		if rtf.Anonymous {
			str := fmt.Sprintf("embedded fields are not supported "+
				"(field name: %q)", rtf.Name)
			return makeError(ErrEmbeddedType, str)
		}
		if rtf.PkgPath != "" {
			str := fmt.Sprintf("unexported fields are not supported "+
				"(field name: %q)", rtf.Name)
			return makeError(ErrUnexportedField, str)
		}

		// Disallow types that can't be JSON encoded.  Also, determine
		// if the field is optional based on it being a pointer.
		var isOptional bool
		switch kind := rtf.Type.Kind(); kind {
		case reflect.Ptr:
			isOptional = true
			kind = rtf.Type.Elem().Kind()
			fallthrough
		default:
			if !isAcceptableKind(kind) {
				str := fmt.Sprintf("unsupported field type "+
					"'%s (%s)' (field name %q)", rtf.Type,
					baseKindString(rtf.Type), rtf.Name)
				return makeError(ErrUnsupportedFieldType, str)
			}
		}

		// Count the optional fields and ensure all fields after the
		// first optional field are also optional.
		if isOptional {
			numOptFields++
		} else {
			if numOptFields > 0 {
				str := fmt.Sprintf("all fields after the first "+
					"optional field must also be optional "+
					"(field name %q)", rtf.Name)
				return makeError(ErrNonOptionalField, str)
			}
		}

		// Ensure the default value can be unsmarshalled into the type
		// and that defaults are only specified for optional fields.
		if tag := rtf.Tag.Get("jsonrpcdefault"); tag != "" {
			if !isOptional {
				str := fmt.Sprintf("required fields must not "+
					"have a default specified (field name "+
					"%q)", rtf.Name)
				return makeError(ErrNonOptionalDefault, str)
			}

			rvf := reflect.New(rtf.Type.Elem())
			err := json.Unmarshal([]byte(tag), rvf.Interface())
			if err != nil {
				str := fmt.Sprintf("default value of %q is "+
					"the wrong type (field name %q)", tag,
					rtf.Name)
				return makeError(ErrMismatchedDefault, str)
			}
			defaults[i] = rvf
		}
	}

	// Update the registration maps.
	methodToConcreteType[method] = rtp
	methodToInfo[method] = methodInfo{
		maxParams:    numFields,
		numReqParams: numFields - numOptFields,
		numOptParams: numOptFields,
		defaults:     defaults,
		flags:        flags,
	}
	concreteTypeToMethod[rtp] = method
	return nil
}

// MustRegisterCmd performs the same function as RegisterCmd except it panics
// if there is an error.  This should only be called from package init
// functions.
func MustRegisterCmd(method string, cmd interface{}, flags UsageFlag) {
	if err := RegisterCmd(method, cmd, flags); err != nil {
		panic(fmt.Sprintf("failed to register type %q: %v\n", method,
			err))
	}
}

// RegisteredCmdMethods returns a sorted list of methods for all registered
// commands.
func RegisteredCmdMethods() []string {
	registerLock.Lock()
	defer registerLock.Unlock()

	methods := make([]string, 0, len(methodToInfo))
	for k := range methodToInfo {
		methods = append(methods, k)
	}

	sort.Strings(methods)
	return methods
}
