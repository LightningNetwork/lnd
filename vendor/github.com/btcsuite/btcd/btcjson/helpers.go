// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

// Bool is a helper routine that allocates a new bool value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Bool(v bool) *bool {
	p := new(bool)
	*p = v
	return p
}

// Int is a helper routine that allocates a new int value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Int(v int) *int {
	p := new(int)
	*p = v
	return p
}

// Uint is a helper routine that allocates a new uint value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Uint(v uint) *uint {
	p := new(uint)
	*p = v
	return p
}

// Int32 is a helper routine that allocates a new int32 value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Int32(v int32) *int32 {
	p := new(int32)
	*p = v
	return p
}

// Uint32 is a helper routine that allocates a new uint32 value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Uint32(v uint32) *uint32 {
	p := new(uint32)
	*p = v
	return p
}

// Int64 is a helper routine that allocates a new int64 value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Int64(v int64) *int64 {
	p := new(int64)
	*p = v
	return p
}

// Uint64 is a helper routine that allocates a new uint64 value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Uint64(v uint64) *uint64 {
	p := new(uint64)
	*p = v
	return p
}

// Float64 is a helper routine that allocates a new float64 value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func Float64(v float64) *float64 {
	p := new(float64)
	*p = v
	return p
}

// String is a helper routine that allocates a new string value to store v and
// returns a pointer to it.  This is useful when assigning optional parameters.
func String(v string) *string {
	p := new(string)
	*p = v
	return p
}
