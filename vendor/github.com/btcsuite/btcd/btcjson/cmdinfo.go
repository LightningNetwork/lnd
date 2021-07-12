// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"fmt"
	"reflect"
	"strings"
)

// CmdMethod returns the method for the passed command.  The provided command
// type must be a registered type.  All commands provided by this package are
// registered by default.
func CmdMethod(cmd interface{}) (string, error) {
	// Look up the cmd type and error out if not registered.
	rt := reflect.TypeOf(cmd)
	registerLock.RLock()
	method, ok := concreteTypeToMethod[rt]
	registerLock.RUnlock()
	if !ok {
		str := fmt.Sprintf("%q is not registered", method)
		return "", makeError(ErrUnregisteredMethod, str)
	}

	return method, nil
}

// MethodUsageFlags returns the usage flags for the passed command method.  The
// provided method must be associated with a registered type.  All commands
// provided by this package are registered by default.
func MethodUsageFlags(method string) (UsageFlag, error) {
	// Look up details about the provided method and error out if not
	// registered.
	registerLock.RLock()
	info, ok := methodToInfo[method]
	registerLock.RUnlock()
	if !ok {
		str := fmt.Sprintf("%q is not registered", method)
		return 0, makeError(ErrUnregisteredMethod, str)
	}

	return info.flags, nil
}

// subStructUsage returns a string for use in the one-line usage for the given
// sub struct.  Note that this is specifically for fields which consist of
// structs (or an array/slice of structs) as opposed to the top-level command
// struct.
//
// Any fields that include a jsonrpcusage struct tag will use that instead of
// being automatically generated.
func subStructUsage(structType reflect.Type) string {
	numFields := structType.NumField()
	fieldUsages := make([]string, 0, numFields)
	for i := 0; i < structType.NumField(); i++ {
		rtf := structType.Field(i)

		// When the field has a jsonrpcusage struct tag specified use
		// that instead of automatically generating it.
		if tag := rtf.Tag.Get("jsonrpcusage"); tag != "" {
			fieldUsages = append(fieldUsages, tag)
			continue
		}

		// Create the name/value entry for the field while considering
		// the type of the field.  Not all possible types are covered
		// here and when one of the types not specifically covered is
		// encountered, the field name is simply reused for the value.
		fieldName := strings.ToLower(rtf.Name)
		fieldValue := fieldName
		fieldKind := rtf.Type.Kind()
		switch {
		case isNumeric(fieldKind):
			if fieldKind == reflect.Float32 || fieldKind == reflect.Float64 {
				fieldValue = "n.nnn"
			} else {
				fieldValue = "n"
			}
		case fieldKind == reflect.String:
			fieldValue = `"value"`

		case fieldKind == reflect.Struct:
			fieldValue = subStructUsage(rtf.Type)

		case fieldKind == reflect.Array || fieldKind == reflect.Slice:
			fieldValue = subArrayUsage(rtf.Type, fieldName)
		}

		usage := fmt.Sprintf("%q:%s", fieldName, fieldValue)
		fieldUsages = append(fieldUsages, usage)
	}

	return fmt.Sprintf("{%s}", strings.Join(fieldUsages, ","))
}

// subArrayUsage returns a string for use in the one-line usage for the given
// array or slice.  It also contains logic to convert plural field names to
// singular so the generated usage string reads better.
func subArrayUsage(arrayType reflect.Type, fieldName string) string {
	// Convert plural field names to singular.  Only works for English.
	singularFieldName := fieldName
	if strings.HasSuffix(fieldName, "ies") {
		singularFieldName = strings.TrimSuffix(fieldName, "ies")
		singularFieldName = singularFieldName + "y"
	} else if strings.HasSuffix(fieldName, "es") {
		singularFieldName = strings.TrimSuffix(fieldName, "es")
	} else if strings.HasSuffix(fieldName, "s") {
		singularFieldName = strings.TrimSuffix(fieldName, "s")
	}

	elemType := arrayType.Elem()
	switch elemType.Kind() {
	case reflect.String:
		return fmt.Sprintf("[%q,...]", singularFieldName)

	case reflect.Struct:
		return fmt.Sprintf("[%s,...]", subStructUsage(elemType))
	}

	// Fall back to simply showing the field name in array syntax.
	return fmt.Sprintf(`[%s,...]`, singularFieldName)
}

// fieldUsage returns a string for use in the one-line usage for the struct
// field of a command.
//
// Any fields that include a jsonrpcusage struct tag will use that instead of
// being automatically generated.
func fieldUsage(structField reflect.StructField, defaultVal *reflect.Value) string {
	// When the field has a jsonrpcusage struct tag specified use that
	// instead of automatically generating it.
	if tag := structField.Tag.Get("jsonrpcusage"); tag != "" {
		return tag
	}

	// Indirect the pointer if needed.
	fieldType := structField.Type
	if fieldType.Kind() == reflect.Ptr {
		fieldType = fieldType.Elem()
	}

	// When there is a default value, it must also be a pointer due to the
	// rules enforced by RegisterCmd.
	if defaultVal != nil {
		indirect := defaultVal.Elem()
		defaultVal = &indirect
	}

	// Handle certain types uniquely to provide nicer usage.
	fieldName := strings.ToLower(structField.Name)
	switch fieldType.Kind() {
	case reflect.String:
		if defaultVal != nil {
			return fmt.Sprintf("%s=%q", fieldName,
				defaultVal.Interface())
		}

		return fmt.Sprintf("%q", fieldName)

	case reflect.Array, reflect.Slice:
		return subArrayUsage(fieldType, fieldName)

	case reflect.Struct:
		return subStructUsage(fieldType)
	}

	// Simply return the field name when none of the above special cases
	// apply.
	if defaultVal != nil {
		return fmt.Sprintf("%s=%v", fieldName, defaultVal.Interface())
	}
	return fieldName
}

// methodUsageText returns a one-line usage string for the provided command and
// method info.  This is the main work horse for the exported MethodUsageText
// function.
func methodUsageText(rtp reflect.Type, defaults map[int]reflect.Value, method string) string {
	// Generate the individual usage for each field in the command.  Several
	// simplifying assumptions are made here because the RegisterCmd
	// function has already rigorously enforced the layout.
	rt := rtp.Elem()
	numFields := rt.NumField()
	reqFieldUsages := make([]string, 0, numFields)
	optFieldUsages := make([]string, 0, numFields)
	for i := 0; i < numFields; i++ {
		rtf := rt.Field(i)
		var isOptional bool
		if kind := rtf.Type.Kind(); kind == reflect.Ptr {
			isOptional = true
		}

		var defaultVal *reflect.Value
		if defVal, ok := defaults[i]; ok {
			defaultVal = &defVal
		}

		// Add human-readable usage to the appropriate slice that is
		// later used to generate the one-line usage.
		usage := fieldUsage(rtf, defaultVal)
		if isOptional {
			optFieldUsages = append(optFieldUsages, usage)
		} else {
			reqFieldUsages = append(reqFieldUsages, usage)
		}
	}

	// Generate and return the one-line usage string.
	usageStr := method
	if len(reqFieldUsages) > 0 {
		usageStr += " " + strings.Join(reqFieldUsages, " ")
	}
	if len(optFieldUsages) > 0 {
		usageStr += fmt.Sprintf(" (%s)", strings.Join(optFieldUsages, " "))
	}
	return usageStr
}

// MethodUsageText returns a one-line usage string for the provided method.  The
// provided method must be associated with a registered type.  All commands
// provided by this package are registered by default.
func MethodUsageText(method string) (string, error) {
	// Look up details about the provided method and error out if not
	// registered.
	registerLock.RLock()
	rtp, ok := methodToConcreteType[method]
	info := methodToInfo[method]
	registerLock.RUnlock()
	if !ok {
		str := fmt.Sprintf("%q is not registered", method)
		return "", makeError(ErrUnregisteredMethod, str)
	}

	// When the usage for this method has already been generated, simply
	// return it.
	if info.usage != "" {
		return info.usage, nil
	}

	// Generate and store the usage string for future calls and return it.
	usage := methodUsageText(rtp, info.defaults, method)
	registerLock.Lock()
	info.usage = usage
	methodToInfo[method] = info
	registerLock.Unlock()
	return usage, nil
}
