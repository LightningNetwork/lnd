// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// makeParams creates a slice of interface values for the given struct.
func makeParams(rt reflect.Type, rv reflect.Value) []interface{} {
	numFields := rt.NumField()
	params := make([]interface{}, 0, numFields)
	for i := 0; i < numFields; i++ {
		rtf := rt.Field(i)
		rvf := rv.Field(i)
		if rtf.Type.Kind() == reflect.Ptr {
			if rvf.IsNil() {
				break
			}
			rvf.Elem()
		}
		params = append(params, rvf.Interface())
	}

	return params
}

// MarshalCmd marshals the passed command to a JSON-RPC request byte slice that
// is suitable for transmission to an RPC server.  The provided command type
// must be a registered type.  All commands provided by this package are
// registered by default.
func MarshalCmd(id interface{}, cmd interface{}) ([]byte, error) {
	// Look up the cmd type and error out if not registered.
	rt := reflect.TypeOf(cmd)
	registerLock.RLock()
	method, ok := concreteTypeToMethod[rt]
	registerLock.RUnlock()
	if !ok {
		str := fmt.Sprintf("%q is not registered", method)
		return nil, makeError(ErrUnregisteredMethod, str)
	}

	// The provided command must not be nil.
	rv := reflect.ValueOf(cmd)
	if rv.IsNil() {
		str := "the specified command is nil"
		return nil, makeError(ErrInvalidType, str)
	}

	// Create a slice of interface values in the order of the struct fields
	// while respecting pointer fields as optional params and only adding
	// them if they are non-nil.
	params := makeParams(rt.Elem(), rv.Elem())

	// Generate and marshal the final JSON-RPC request.
	rawCmd, err := NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rawCmd)
}

// checkNumParams ensures the supplied number of params is at least the minimum
// required number for the command and less than the maximum allowed.
func checkNumParams(numParams int, info *methodInfo) error {
	if numParams < info.numReqParams || numParams > info.maxParams {
		if info.numReqParams == info.maxParams {
			str := fmt.Sprintf("wrong number of params (expected "+
				"%d, received %d)", info.numReqParams,
				numParams)
			return makeError(ErrNumParams, str)
		}

		str := fmt.Sprintf("wrong number of params (expected "+
			"between %d and %d, received %d)", info.numReqParams,
			info.maxParams, numParams)
		return makeError(ErrNumParams, str)
	}

	return nil
}

// populateDefaults populates default values into any remaining optional struct
// fields that did not have parameters explicitly provided.  The caller should
// have previously checked that the number of parameters being passed is at
// least the required number of parameters to avoid unnecessary work in this
// function, but since required fields never have default values, it will work
// properly even without the check.
func populateDefaults(numParams int, info *methodInfo, rv reflect.Value) {
	// When there are no more parameters left in the supplied parameters,
	// any remaining struct fields must be optional.  Thus, populate them
	// with their associated default value as needed.
	for i := numParams; i < info.maxParams; i++ {
		rvf := rv.Field(i)
		if defaultVal, ok := info.defaults[i]; ok {
			rvf.Set(defaultVal)
		}
	}
}

// UnmarshalCmd unmarshals a JSON-RPC request into a suitable concrete command
// so long as the method type contained within the marshalled request is
// registered.
func UnmarshalCmd(r *Request) (interface{}, error) {
	registerLock.RLock()
	rtp, ok := methodToConcreteType[r.Method]
	info := methodToInfo[r.Method]
	registerLock.RUnlock()
	if !ok {
		str := fmt.Sprintf("%q is not registered", r.Method)
		return nil, makeError(ErrUnregisteredMethod, str)
	}
	rt := rtp.Elem()
	rvp := reflect.New(rt)
	rv := rvp.Elem()

	// Ensure the number of parameters are correct.
	numParams := len(r.Params)
	if err := checkNumParams(numParams, &info); err != nil {
		return nil, err
	}

	// Loop through each of the struct fields and unmarshal the associated
	// parameter into them.
	for i := 0; i < numParams; i++ {
		rvf := rv.Field(i)
		// Unmarshal the parameter into the struct field.
		concreteVal := rvf.Addr().Interface()
		if err := json.Unmarshal(r.Params[i], &concreteVal); err != nil {
			// The most common error is the wrong type, so
			// explicitly detect that error and make it nicer.
			fieldName := strings.ToLower(rt.Field(i).Name)
			if jerr, ok := err.(*json.UnmarshalTypeError); ok {
				str := fmt.Sprintf("parameter #%d '%s' must "+
					"be type %v (got %v)", i+1, fieldName,
					jerr.Type, jerr.Value)
				return nil, makeError(ErrInvalidType, str)
			}

			// Fallback to showing the underlying error.
			str := fmt.Sprintf("parameter #%d '%s' failed to "+
				"unmarshal: %v", i+1, fieldName, err)
			return nil, makeError(ErrInvalidType, str)
		}
	}

	// When there are less supplied parameters than the total number of
	// params, any remaining struct fields must be optional.  Thus, populate
	// them with their associated default value as needed.
	if numParams < info.maxParams {
		populateDefaults(numParams, &info, rv)
	}

	return rvp.Interface(), nil
}

// isNumeric returns whether the passed reflect kind is a signed or unsigned
// integer of any magnitude or a float of any magnitude.
func isNumeric(kind reflect.Kind) bool {
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Float32, reflect.Float64:

		return true
	}

	return false
}

// typesMaybeCompatible returns whether the source type can possibly be
// assigned to the destination type.  This is intended as a relatively quick
// check to weed out obviously invalid conversions.
func typesMaybeCompatible(dest reflect.Type, src reflect.Type) bool {
	// The same types are obviously compatible.
	if dest == src {
		return true
	}

	// When both types are numeric, they are potentially compatible.
	srcKind := src.Kind()
	destKind := dest.Kind()
	if isNumeric(destKind) && isNumeric(srcKind) {
		return true
	}

	if srcKind == reflect.String {
		// Strings can potentially be converted to numeric types.
		if isNumeric(destKind) {
			return true
		}

		switch destKind {
		// Strings can potentially be converted to bools by
		// strconv.ParseBool.
		case reflect.Bool:
			return true

		// Strings can be converted to any other type which has as
		// underlying type of string.
		case reflect.String:
			return true

		// Strings can potentially be converted to arrays, slice,
		// structs, and maps via json.Unmarshal.
		case reflect.Array, reflect.Slice, reflect.Struct, reflect.Map:
			return true
		}
	}

	return false
}

// baseType returns the type of the argument after indirecting through all
// pointers along with how many indirections were necessary.
func baseType(arg reflect.Type) (reflect.Type, int) {
	var numIndirects int
	for arg.Kind() == reflect.Ptr {
		arg = arg.Elem()
		numIndirects++
	}
	return arg, numIndirects
}

// assignField is the main workhorse for the NewCmd function which handles
// assigning the provided source value to the destination field.  It supports
// direct type assignments, indirection, conversion of numeric types, and
// unmarshaling of strings into arrays, slices, structs, and maps via
// json.Unmarshal.
func assignField(paramNum int, fieldName string, dest reflect.Value, src reflect.Value) error {
	// Just error now when the types have no chance of being compatible.
	destBaseType, destIndirects := baseType(dest.Type())
	srcBaseType, srcIndirects := baseType(src.Type())
	if !typesMaybeCompatible(destBaseType, srcBaseType) {
		str := fmt.Sprintf("parameter #%d '%s' must be type %v (got "+
			"%v)", paramNum, fieldName, destBaseType, srcBaseType)
		return makeError(ErrInvalidType, str)
	}

	// Check if it's possible to simply set the dest to the provided source.
	// This is the case when the base types are the same or they are both
	// pointers that can be indirected to be the same without needing to
	// create pointers for the destination field.
	if destBaseType == srcBaseType && srcIndirects >= destIndirects {
		for i := 0; i < srcIndirects-destIndirects; i++ {
			src = src.Elem()
		}
		dest.Set(src)
		return nil
	}

	// When the destination has more indirects than the source, the extra
	// pointers have to be created.  Only create enough pointers to reach
	// the same level of indirection as the source so the dest can simply be
	// set to the provided source when the types are the same.
	destIndirectsRemaining := destIndirects
	if destIndirects > srcIndirects {
		indirectDiff := destIndirects - srcIndirects
		for i := 0; i < indirectDiff; i++ {
			dest.Set(reflect.New(dest.Type().Elem()))
			dest = dest.Elem()
			destIndirectsRemaining--
		}
	}

	if destBaseType == srcBaseType {
		dest.Set(src)
		return nil
	}

	// Make any remaining pointers needed to get to the base dest type since
	// the above direct assign was not possible and conversions are done
	// against the base types.
	for i := 0; i < destIndirectsRemaining; i++ {
		dest.Set(reflect.New(dest.Type().Elem()))
		dest = dest.Elem()
	}

	// Indirect through to the base source value.
	for src.Kind() == reflect.Ptr {
		src = src.Elem()
	}

	// Perform supported type conversions.
	switch src.Kind() {
	// Source value is a signed integer of various magnitude.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Int64:

		switch dest.Kind() {
		// Destination is a signed integer of various magnitude.
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
			reflect.Int64:

			srcInt := src.Int()
			if dest.OverflowInt(srcInt) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}

			dest.SetInt(srcInt)

		// Destination is an unsigned integer of various magnitude.
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
			reflect.Uint64:

			srcInt := src.Int()
			if srcInt < 0 || dest.OverflowUint(uint64(srcInt)) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetUint(uint64(srcInt))

		default:
			str := fmt.Sprintf("parameter #%d '%s' must be type "+
				"%v (got %v)", paramNum, fieldName, destBaseType,
				srcBaseType)
			return makeError(ErrInvalidType, str)
		}

	// Source value is an unsigned integer of various magnitude.
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64:

		switch dest.Kind() {
		// Destination is a signed integer of various magnitude.
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
			reflect.Int64:

			srcUint := src.Uint()
			if srcUint > uint64(1<<63)-1 {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			if dest.OverflowInt(int64(srcUint)) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetInt(int64(srcUint))

		// Destination is an unsigned integer of various magnitude.
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
			reflect.Uint64:

			srcUint := src.Uint()
			if dest.OverflowUint(srcUint) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetUint(srcUint)

		default:
			str := fmt.Sprintf("parameter #%d '%s' must be type "+
				"%v (got %v)", paramNum, fieldName, destBaseType,
				srcBaseType)
			return makeError(ErrInvalidType, str)
		}

	// Source value is a float.
	case reflect.Float32, reflect.Float64:
		destKind := dest.Kind()
		if destKind != reflect.Float32 && destKind != reflect.Float64 {
			str := fmt.Sprintf("parameter #%d '%s' must be type "+
				"%v (got %v)", paramNum, fieldName, destBaseType,
				srcBaseType)
			return makeError(ErrInvalidType, str)
		}

		srcFloat := src.Float()
		if dest.OverflowFloat(srcFloat) {
			str := fmt.Sprintf("parameter #%d '%s' overflows "+
				"destination type %v", paramNum, fieldName,
				destBaseType)
			return makeError(ErrInvalidType, str)
		}
		dest.SetFloat(srcFloat)

	// Source value is a string.
	case reflect.String:
		switch dest.Kind() {
		// String -> bool
		case reflect.Bool:
			b, err := strconv.ParseBool(src.String())
			if err != nil {
				str := fmt.Sprintf("parameter #%d '%s' must "+
					"parse to a %v", paramNum, fieldName,
					destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetBool(b)

		// String -> signed integer of varying size.
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
			reflect.Int64:

			srcInt, err := strconv.ParseInt(src.String(), 0, 0)
			if err != nil {
				str := fmt.Sprintf("parameter #%d '%s' must "+
					"parse to a %v", paramNum, fieldName,
					destBaseType)
				return makeError(ErrInvalidType, str)
			}
			if dest.OverflowInt(srcInt) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetInt(srcInt)

		// String -> unsigned integer of varying size.
		case reflect.Uint, reflect.Uint8, reflect.Uint16,
			reflect.Uint32, reflect.Uint64:

			srcUint, err := strconv.ParseUint(src.String(), 0, 0)
			if err != nil {
				str := fmt.Sprintf("parameter #%d '%s' must "+
					"parse to a %v", paramNum, fieldName,
					destBaseType)
				return makeError(ErrInvalidType, str)
			}
			if dest.OverflowUint(srcUint) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetUint(srcUint)

		// String -> float of varying size.
		case reflect.Float32, reflect.Float64:
			srcFloat, err := strconv.ParseFloat(src.String(), 0)
			if err != nil {
				str := fmt.Sprintf("parameter #%d '%s' must "+
					"parse to a %v", paramNum, fieldName,
					destBaseType)
				return makeError(ErrInvalidType, str)
			}
			if dest.OverflowFloat(srcFloat) {
				str := fmt.Sprintf("parameter #%d '%s' "+
					"overflows destination type %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.SetFloat(srcFloat)

		// String -> string (typecast).
		case reflect.String:
			dest.SetString(src.String())

		// String -> arrays, slices, structs, and maps via
		// json.Unmarshal.
		case reflect.Array, reflect.Slice, reflect.Struct, reflect.Map:
			concreteVal := dest.Addr().Interface()
			err := json.Unmarshal([]byte(src.String()), &concreteVal)
			if err != nil {
				str := fmt.Sprintf("parameter #%d '%s' must "+
					"be valid JSON which unsmarshals to a %v",
					paramNum, fieldName, destBaseType)
				return makeError(ErrInvalidType, str)
			}
			dest.Set(reflect.ValueOf(concreteVal).Elem())
		}
	}

	return nil
}

// NewCmd provides a generic mechanism to create a new command that can marshal
// to a JSON-RPC request while respecting the requirements of the provided
// method.  The method must have been registered with the package already along
// with its type definition.  All methods associated with the commands exported
// by this package are already registered by default.
//
// The arguments are most efficient when they are the exact same type as the
// underlying field in the command struct associated with the the method,
// however this function also will perform a variety of conversions to make it
// more flexible.  This allows, for example, command line args which are strings
// to be passed unaltered.  In particular, the following conversions are
// supported:
//
//   - Conversion between any size signed or unsigned integer so long as the
//     value does not overflow the destination type
//   - Conversion between float32 and float64 so long as the value does not
//     overflow the destination type
//   - Conversion from string to boolean for everything strconv.ParseBool
//     recognizes
//   - Conversion from string to any size integer for everything
//     strconv.ParseInt and strconv.ParseUint recognizes
//   - Conversion from string to any size float for everything
//     strconv.ParseFloat recognizes
//   - Conversion from string to arrays, slices, structs, and maps by treating
//     the string as marshalled JSON and calling json.Unmarshal into the
//     destination field
func NewCmd(method string, args ...interface{}) (interface{}, error) {
	// Look up details about the provided method.  Any methods that aren't
	// registered are an error.
	registerLock.RLock()
	rtp, ok := methodToConcreteType[method]
	info := methodToInfo[method]
	registerLock.RUnlock()
	if !ok {
		str := fmt.Sprintf("%q is not registered", method)
		return nil, makeError(ErrUnregisteredMethod, str)
	}

	// Ensure the number of parameters are correct.
	numParams := len(args)
	if err := checkNumParams(numParams, &info); err != nil {
		return nil, err
	}

	// Create the appropriate command type for the method.  Since all types
	// are enforced to be a pointer to a struct at registration time, it's
	// safe to indirect to the struct now.
	rvp := reflect.New(rtp.Elem())
	rv := rvp.Elem()
	rt := rtp.Elem()

	// Loop through each of the struct fields and assign the associated
	// parameter into them after checking its type validity.
	for i := 0; i < numParams; i++ {
		// Attempt to assign each of the arguments to the according
		// struct field.
		rvf := rv.Field(i)
		fieldName := strings.ToLower(rt.Field(i).Name)
		err := assignField(i+1, fieldName, rvf, reflect.ValueOf(args[i]))
		if err != nil {
			return nil, err
		}
	}

	return rvp.Interface(), nil
}
