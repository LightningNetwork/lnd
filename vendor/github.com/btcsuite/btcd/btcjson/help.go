// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"text/tabwriter"
)

// baseHelpDescs house the various help labels, types, and example values used
// when generating help.  The per-command synopsis, field descriptions,
// conditions, and result descriptions are to be provided by the caller.
var baseHelpDescs = map[string]string{
	// Misc help labels and output.
	"help-arguments":      "Arguments",
	"help-arguments-none": "None",
	"help-result":         "Result",
	"help-result-nothing": "Nothing",
	"help-default":        "default",
	"help-optional":       "optional",
	"help-required":       "required",

	// JSON types.
	"json-type-numeric": "numeric",
	"json-type-string":  "string",
	"json-type-bool":    "boolean",
	"json-type-array":   "array of ",
	"json-type-object":  "object",
	"json-type-value":   "value",

	// JSON examples.
	"json-example-string":   "value",
	"json-example-bool":     "true|false",
	"json-example-map-data": "data",
	"json-example-unknown":  "unknown",
}

// descLookupFunc is a function which is used to lookup a description given
// a key.
type descLookupFunc func(string) string

// reflectTypeToJSONType returns a string that represents the JSON type
// associated with the provided Go type.
func reflectTypeToJSONType(xT descLookupFunc, rt reflect.Type) string {
	kind := rt.Kind()
	if isNumeric(kind) {
		return xT("json-type-numeric")
	}

	switch kind {
	case reflect.String:
		return xT("json-type-string")

	case reflect.Bool:
		return xT("json-type-bool")

	case reflect.Array, reflect.Slice:
		return xT("json-type-array") + reflectTypeToJSONType(xT,
			rt.Elem())

	case reflect.Struct:
		return xT("json-type-object")

	case reflect.Map:
		return xT("json-type-object")
	}

	return xT("json-type-value")
}

// resultStructHelp returns a slice of strings containing the result help output
// for a struct.  Each line makes use of tabs to separate the relevant pieces so
// a tabwriter can be used later to line everything up.  The descriptions are
// pulled from the active help descriptions map based on the lowercase version
// of the provided reflect type and json name (or the lowercase version of the
// field name if no json tag was specified).
func resultStructHelp(xT descLookupFunc, rt reflect.Type, indentLevel int) []string {
	indent := strings.Repeat(" ", indentLevel)
	typeName := strings.ToLower(rt.Name())

	// Generate the help for each of the fields in the result struct.
	numField := rt.NumField()
	results := make([]string, 0, numField)
	for i := 0; i < numField; i++ {
		rtf := rt.Field(i)

		// The field name to display is the json name when it's
		// available, otherwise use the lowercase field name.
		var fieldName string
		if tag := rtf.Tag.Get("json"); tag != "" {
			fieldName = strings.Split(tag, ",")[0]
		} else {
			fieldName = strings.ToLower(rtf.Name)
		}

		// Deference pointer if needed.
		rtfType := rtf.Type
		if rtfType.Kind() == reflect.Ptr {
			rtfType = rtf.Type.Elem()
		}

		// Generate the JSON example for the result type of this struct
		// field.  When it is a complex type, examine the type and
		// adjust the opening bracket and brace combination accordingly.
		fieldType := reflectTypeToJSONType(xT, rtfType)
		fieldDescKey := typeName + "-" + fieldName
		fieldExamples, isComplex := reflectTypeToJSONExample(xT,
			rtfType, indentLevel, fieldDescKey)
		if isComplex {
			var brace string
			kind := rtfType.Kind()
			if kind == reflect.Array || kind == reflect.Slice {
				brace = "[{"
			} else {
				brace = "{"
			}
			result := fmt.Sprintf("%s\"%s\": %s\t(%s)\t%s", indent,
				fieldName, brace, fieldType, xT(fieldDescKey))
			results = append(results, result)
			results = append(results, fieldExamples...)
		} else {
			result := fmt.Sprintf("%s\"%s\": %s,\t(%s)\t%s", indent,
				fieldName, fieldExamples[0], fieldType,
				xT(fieldDescKey))
			results = append(results, result)
		}
	}

	return results
}

// reflectTypeToJSONExample generates example usage in the format used by the
// help output.  It handles arrays, slices and structs recursively.  The output
// is returned as a slice of lines so the final help can be nicely aligned via
// a tab writer.  A bool is also returned which specifies whether or not the
// type results in a complex JSON object since they need to be handled
// differently.
func reflectTypeToJSONExample(xT descLookupFunc, rt reflect.Type, indentLevel int, fieldDescKey string) ([]string, bool) {
	// Indirect pointer if needed.
	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	kind := rt.Kind()
	if isNumeric(kind) {
		if kind == reflect.Float32 || kind == reflect.Float64 {
			return []string{"n.nnn"}, false
		}

		return []string{"n"}, false
	}

	switch kind {
	case reflect.String:
		return []string{`"` + xT("json-example-string") + `"`}, false

	case reflect.Bool:
		return []string{xT("json-example-bool")}, false

	case reflect.Struct:
		indent := strings.Repeat(" ", indentLevel)
		results := resultStructHelp(xT, rt, indentLevel+1)

		// An opening brace is needed for the first indent level.  For
		// all others, it will be included as a part of the previous
		// field.
		if indentLevel == 0 {
			newResults := make([]string, len(results)+1)
			newResults[0] = "{"
			copy(newResults[1:], results)
			results = newResults
		}

		// The closing brace has a comma after it except for the first
		// indent level.  The final tabs are necessary so the tab writer
		// lines things up properly.
		closingBrace := indent + "}"
		if indentLevel > 0 {
			closingBrace += ","
		}
		results = append(results, closingBrace+"\t\t")
		return results, true

	case reflect.Array, reflect.Slice:
		results, isComplex := reflectTypeToJSONExample(xT, rt.Elem(),
			indentLevel, fieldDescKey)

		// When the result is complex, it is because this is an array of
		// objects.
		if isComplex {
			// When this is at indent level zero, there is no
			// previous field to house the opening array bracket, so
			// replace the opening object brace with the array
			// syntax.  Also, replace the final closing object brace
			// with the variadiac array closing syntax.
			indent := strings.Repeat(" ", indentLevel)
			if indentLevel == 0 {
				results[0] = indent + "[{"
				results[len(results)-1] = indent + "},...]"
				return results, true
			}

			// At this point, the indent level is greater than 0, so
			// the opening array bracket and object brace are
			// already a part of the previous field.  However, the
			// closing entry is a simple object brace, so replace it
			// with the variadiac array closing syntax.  The final
			// tabs are necessary so the tab writer lines things up
			// properly.
			results[len(results)-1] = indent + "},...],\t\t"
			return results, true
		}

		// It's an array of primitives, so return the formatted text
		// accordingly.
		return []string{fmt.Sprintf("[%s,...]", results[0])}, false

	case reflect.Map:
		indent := strings.Repeat(" ", indentLevel)
		results := make([]string, 0, 3)

		// An opening brace is needed for the first indent level.  For
		// all others, it will be included as a part of the previous
		// field.
		if indentLevel == 0 {
			results = append(results, indent+"{")
		}

		// Maps are a bit special in that they need to have the key,
		// value, and description of the object entry specifically
		// called out.
		innerIndent := strings.Repeat(" ", indentLevel+1)
		result := fmt.Sprintf("%s%q: %s, (%s) %s", innerIndent,
			xT(fieldDescKey+"--key"), xT(fieldDescKey+"--value"),
			reflectTypeToJSONType(xT, rt), xT(fieldDescKey+"--desc"))
		results = append(results, result)
		results = append(results, innerIndent+"...")

		results = append(results, indent+"}")
		return results, true
	}

	return []string{xT("json-example-unknown")}, false
}

// resultTypeHelp generates and returns formatted help for the provided result
// type.
func resultTypeHelp(xT descLookupFunc, rt reflect.Type, fieldDescKey string) string {
	// Generate the JSON example for the result type.
	results, isComplex := reflectTypeToJSONExample(xT, rt, 0, fieldDescKey)

	// When this is a primitive type, add the associated JSON type and
	// result description into the final string, format it accordingly,
	// and return it.
	if !isComplex {
		return fmt.Sprintf("%s (%s) %s", results[0],
			reflectTypeToJSONType(xT, rt), xT(fieldDescKey))
	}

	// At this point, this is a complex type that already has the JSON types
	// and descriptions in the results.  Thus, use a tab writer to nicely
	// align the help text.
	var formatted bytes.Buffer
	w := new(tabwriter.Writer)
	w.Init(&formatted, 0, 4, 1, ' ', 0)
	for i, text := range results {
		if i == len(results)-1 {
			fmt.Fprintf(w, text)
		} else {
			fmt.Fprintln(w, text)
		}
	}
	w.Flush()
	return formatted.String()
}

// argTypeHelp returns the type of provided command argument as a string in the
// format used by the help output.  In particular, it includes the JSON type
// (boolean, numeric, string, array, object) along with optional and the default
// value if applicable.
func argTypeHelp(xT descLookupFunc, structField reflect.StructField, defaultVal *reflect.Value) string {
	// Indirect the pointer if needed and track if it's an optional field.
	fieldType := structField.Type
	var isOptional bool
	if fieldType.Kind() == reflect.Ptr {
		fieldType = fieldType.Elem()
		isOptional = true
	}

	// When there is a default value, it must also be a pointer due to the
	// rules enforced by RegisterCmd.
	if defaultVal != nil {
		indirect := defaultVal.Elem()
		defaultVal = &indirect
	}

	// Convert the field type to a JSON type.
	details := make([]string, 0, 3)
	details = append(details, reflectTypeToJSONType(xT, fieldType))

	// Add optional and default value to the details if needed.
	if isOptional {
		details = append(details, xT("help-optional"))

		// Add the default value if there is one.  This is only checked
		// when the field is optional since a non-optional field can't
		// have a default value.
		if defaultVal != nil {
			val := defaultVal.Interface()
			if defaultVal.Kind() == reflect.String {
				val = fmt.Sprintf(`"%s"`, val)
			}
			str := fmt.Sprintf("%s=%v", xT("help-default"), val)
			details = append(details, str)
		}
	} else {
		details = append(details, xT("help-required"))
	}

	return strings.Join(details, ", ")
}

// argHelp generates and returns formatted help for the provided command.
func argHelp(xT descLookupFunc, rtp reflect.Type, defaults map[int]reflect.Value, method string) string {
	// Return now if the command has no arguments.
	rt := rtp.Elem()
	numFields := rt.NumField()
	if numFields == 0 {
		return ""
	}

	// Generate the help for each argument in the command.  Several
	// simplifying assumptions are made here because the RegisterCmd
	// function has already rigorously enforced the layout.
	args := make([]string, 0, numFields)
	for i := 0; i < numFields; i++ {
		rtf := rt.Field(i)
		var defaultVal *reflect.Value
		if defVal, ok := defaults[i]; ok {
			defaultVal = &defVal
		}

		fieldName := strings.ToLower(rtf.Name)
		helpText := fmt.Sprintf("%d.\t%s\t(%s)\t%s", i+1, fieldName,
			argTypeHelp(xT, rtf, defaultVal),
			xT(method+"-"+fieldName))
		args = append(args, helpText)

		// For types which require a JSON object, or an array of JSON
		// objects, generate the full syntax for the argument.
		fieldType := rtf.Type
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}
		kind := fieldType.Kind()
		switch kind {
		case reflect.Struct:
			fieldDescKey := fmt.Sprintf("%s-%s", method, fieldName)
			resultText := resultTypeHelp(xT, fieldType, fieldDescKey)
			args = append(args, resultText)

		case reflect.Map:
			fieldDescKey := fmt.Sprintf("%s-%s", method, fieldName)
			resultText := resultTypeHelp(xT, fieldType, fieldDescKey)
			args = append(args, resultText)

		case reflect.Array, reflect.Slice:
			fieldDescKey := fmt.Sprintf("%s-%s", method, fieldName)
			if rtf.Type.Elem().Kind() == reflect.Struct {
				resultText := resultTypeHelp(xT, fieldType,
					fieldDescKey)
				args = append(args, resultText)
			}
		}
	}

	// Add argument names, types, and descriptions if there are any.  Use a
	// tab writer to nicely align the help text.
	var formatted bytes.Buffer
	w := new(tabwriter.Writer)
	w.Init(&formatted, 0, 4, 1, ' ', 0)
	for _, text := range args {
		fmt.Fprintln(w, text)
	}
	w.Flush()
	return formatted.String()
}

// methodHelp generates and returns the help output for the provided command
// and method info.  This is the main work horse for the exported MethodHelp
// function.
func methodHelp(xT descLookupFunc, rtp reflect.Type, defaults map[int]reflect.Value, method string, resultTypes []interface{}) string {
	// Start off with the method usage and help synopsis.
	help := fmt.Sprintf("%s\n\n%s\n", methodUsageText(rtp, defaults, method),
		xT(method+"--synopsis"))

	// Generate the help for each argument in the command.
	if argText := argHelp(xT, rtp, defaults, method); argText != "" {
		help += fmt.Sprintf("\n%s:\n%s", xT("help-arguments"),
			argText)
	} else {
		help += fmt.Sprintf("\n%s:\n%s\n", xT("help-arguments"),
			xT("help-arguments-none"))
	}

	// Generate the help text for each result type.
	resultTexts := make([]string, 0, len(resultTypes))
	for i := range resultTypes {
		rtp := reflect.TypeOf(resultTypes[i])
		fieldDescKey := fmt.Sprintf("%s--result%d", method, i)
		if resultTypes[i] == nil {
			resultText := xT("help-result-nothing")
			resultTexts = append(resultTexts, resultText)
			continue
		}

		resultText := resultTypeHelp(xT, rtp.Elem(), fieldDescKey)
		resultTexts = append(resultTexts, resultText)
	}

	// Add result types and descriptions.  When there is more than one
	// result type, also add the condition which triggers it.
	if len(resultTexts) > 1 {
		for i, resultText := range resultTexts {
			condKey := fmt.Sprintf("%s--condition%d", method, i)
			help += fmt.Sprintf("\n%s (%s):\n%s\n",
				xT("help-result"), xT(condKey), resultText)
		}
	} else if len(resultTexts) > 0 {
		help += fmt.Sprintf("\n%s:\n%s\n", xT("help-result"),
			resultTexts[0])
	} else {
		help += fmt.Sprintf("\n%s:\n%s\n", xT("help-result"),
			xT("help-result-nothing"))
	}
	return help
}

// isValidResultType returns whether the passed reflect kind is one of the
// acceptable types for results.
func isValidResultType(kind reflect.Kind) bool {
	if isNumeric(kind) {
		return true
	}

	switch kind {
	case reflect.String, reflect.Struct, reflect.Array, reflect.Slice,
		reflect.Bool, reflect.Map:

		return true
	}

	return false
}

// GenerateHelp generates and returns help output for the provided method and
// result types given a map to provide the appropriate keys for the method
// synopsis, field descriptions, conditions, and result descriptions.  The
// method must be associated with a registered type.  All commands provided by
// this package are registered by default.
//
// The resultTypes must be pointer-to-types which represent the specific types
// of values the command returns.  For example, if the command only returns a
// boolean value, there should only be a single entry of (*bool)(nil).  Note
// that each type must be a single pointer to the type.  Therefore, it is
// recommended to simply pass a nil pointer cast to the appropriate type as
// previously shown.
//
// The provided descriptions map must contain all of the keys or an error will
// be returned which includes the missing key, or the final missing key when
// there is more than one key missing.  The generated help in the case of such
// an error will use the key in place of the description.
//
// The following outlines the required keys:
//   "<method>--synopsis"             Synopsis for the command
//   "<method>-<lowerfieldname>"      Description for each command argument
//   "<typename>-<lowerfieldname>"    Description for each object field
//   "<method>--condition<#>"         Description for each result condition
//   "<method>--result<#>"            Description for each primitive result num
//
// Notice that the "special" keys synopsis, condition<#>, and result<#> are
// preceded by a double dash to ensure they don't conflict with field names.
//
// The condition keys are only required when there is more than on result type,
// and the result key for a given result type is only required if it's not an
// object.
//
// For example, consider the 'help' command itself.  There are two possible
// returns depending on the provided parameters.  So, the help would be
// generated by calling the function as follows:
//   GenerateHelp("help", descs, (*string)(nil), (*string)(nil)).
//
// The following keys would then be required in the provided descriptions map:
//
//   "help--synopsis":   "Returns a list of all commands or help for ...."
//   "help-command":     "The command to retrieve help for",
//   "help--condition0": "no command provided"
//   "help--condition1": "command specified"
//   "help--result0":    "List of commands"
//   "help--result1":    "Help for specified command"
func GenerateHelp(method string, descs map[string]string, resultTypes ...interface{}) (string, error) {
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

	// Validate each result type is a pointer to a supported type (or nil).
	for i, resultType := range resultTypes {
		if resultType == nil {
			continue
		}

		rtp := reflect.TypeOf(resultType)
		if rtp.Kind() != reflect.Ptr {
			str := fmt.Sprintf("result #%d (%v) is not a pointer",
				i, rtp.Kind())
			return "", makeError(ErrInvalidType, str)
		}

		elemKind := rtp.Elem().Kind()
		if !isValidResultType(elemKind) {
			str := fmt.Sprintf("result #%d (%v) is not an allowed "+
				"type", i, elemKind)
			return "", makeError(ErrInvalidType, str)
		}
	}

	// Create a closure for the description lookup function which falls back
	// to the base help descriptions map for unrecognized keys and tracks
	// and missing keys.
	var missingKey string
	xT := func(key string) string {
		if desc, ok := descs[key]; ok {
			return desc
		}
		if desc, ok := baseHelpDescs[key]; ok {
			return desc
		}

		missingKey = key
		return key
	}

	// Generate and return the help for the method.
	help := methodHelp(xT, rtp, info.defaults, method, resultTypes)
	if missingKey != "" {
		return help, makeError(ErrMissingDescription, missingKey)
	}
	return help, nil
}
