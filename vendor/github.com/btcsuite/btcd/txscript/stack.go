// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"encoding/hex"
	"fmt"
)

// asBool gets the boolean value of the byte array.
func asBool(t []byte) bool {
	for i := range t {
		if t[i] != 0 {
			// Negative 0 is also considered false.
			if i == len(t)-1 && t[i] == 0x80 {
				return false
			}
			return true
		}
	}
	return false
}

// fromBool converts a boolean into the appropriate byte array.
func fromBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return nil
}

// stack represents a stack of immutable objects to be used with bitcoin
// scripts.  Objects may be shared, therefore in usage if a value is to be
// changed it *must* be deep-copied first to avoid changing other values on the
// stack.
type stack struct {
	stk               [][]byte
	verifyMinimalData bool
}

// Depth returns the number of items on the stack.
func (s *stack) Depth() int32 {
	return int32(len(s.stk))
}

// PushByteArray adds the given back array to the top of the stack.
//
// Stack transformation: [... x1 x2] -> [... x1 x2 data]
func (s *stack) PushByteArray(so []byte) {
	s.stk = append(s.stk, so)
}

// PushInt converts the provided scriptNum to a suitable byte array then pushes
// it onto the top of the stack.
//
// Stack transformation: [... x1 x2] -> [... x1 x2 int]
func (s *stack) PushInt(val scriptNum) {
	s.PushByteArray(val.Bytes())
}

// PushBool converts the provided boolean to a suitable byte array then pushes
// it onto the top of the stack.
//
// Stack transformation: [... x1 x2] -> [... x1 x2 bool]
func (s *stack) PushBool(val bool) {
	s.PushByteArray(fromBool(val))
}

// PopByteArray pops the value off the top of the stack and returns it.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func (s *stack) PopByteArray() ([]byte, error) {
	return s.nipN(0)
}

// PopInt pops the value off the top of the stack, converts it into a script
// num, and returns it.  The act of converting to a script num enforces the
// consensus rules imposed on data interpreted as numbers.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func (s *stack) PopInt() (scriptNum, error) {
	so, err := s.PopByteArray()
	if err != nil {
		return 0, err
	}

	return makeScriptNum(so, s.verifyMinimalData, defaultScriptNumLen)
}

// PopBool pops the value off the top of the stack, converts it into a bool, and
// returns it.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func (s *stack) PopBool() (bool, error) {
	so, err := s.PopByteArray()
	if err != nil {
		return false, err
	}

	return asBool(so), nil
}

// PeekByteArray returns the Nth item on the stack without removing it.
func (s *stack) PeekByteArray(idx int32) ([]byte, error) {
	sz := int32(len(s.stk))
	if idx < 0 || idx >= sz {
		str := fmt.Sprintf("index %d is invalid for stack size %d", idx,
			sz)
		return nil, scriptError(ErrInvalidStackOperation, str)
	}

	return s.stk[sz-idx-1], nil
}

// PeekInt returns the Nth item on the stack as a script num without removing
// it.  The act of converting to a script num enforces the consensus rules
// imposed on data interpreted as numbers.
func (s *stack) PeekInt(idx int32) (scriptNum, error) {
	so, err := s.PeekByteArray(idx)
	if err != nil {
		return 0, err
	}

	return makeScriptNum(so, s.verifyMinimalData, defaultScriptNumLen)
}

// PeekBool returns the Nth item on the stack as a bool without removing it.
func (s *stack) PeekBool(idx int32) (bool, error) {
	so, err := s.PeekByteArray(idx)
	if err != nil {
		return false, err
	}

	return asBool(so), nil
}

// nipN is an internal function that removes the nth item on the stack and
// returns it.
//
// Stack transformation:
// nipN(0): [... x1 x2 x3] -> [... x1 x2]
// nipN(1): [... x1 x2 x3] -> [... x1 x3]
// nipN(2): [... x1 x2 x3] -> [... x2 x3]
func (s *stack) nipN(idx int32) ([]byte, error) {
	sz := int32(len(s.stk))
	if idx < 0 || idx > sz-1 {
		str := fmt.Sprintf("index %d is invalid for stack size %d", idx,
			sz)
		return nil, scriptError(ErrInvalidStackOperation, str)
	}

	so := s.stk[sz-idx-1]
	if idx == 0 {
		s.stk = s.stk[:sz-1]
	} else if idx == sz-1 {
		s1 := make([][]byte, sz-1)
		copy(s1, s.stk[1:])
		s.stk = s1
	} else {
		s1 := s.stk[sz-idx : sz]
		s.stk = s.stk[:sz-idx-1]
		s.stk = append(s.stk, s1...)
	}
	return so, nil
}

// NipN removes the Nth object on the stack
//
// Stack transformation:
// NipN(0): [... x1 x2 x3] -> [... x1 x2]
// NipN(1): [... x1 x2 x3] -> [... x1 x3]
// NipN(2): [... x1 x2 x3] -> [... x2 x3]
func (s *stack) NipN(idx int32) error {
	_, err := s.nipN(idx)
	return err
}

// Tuck copies the item at the top of the stack and inserts it before the 2nd
// to top item.
//
// Stack transformation: [... x1 x2] -> [... x2 x1 x2]
func (s *stack) Tuck() error {
	so2, err := s.PopByteArray()
	if err != nil {
		return err
	}
	so1, err := s.PopByteArray()
	if err != nil {
		return err
	}
	s.PushByteArray(so2) // stack [... x2]
	s.PushByteArray(so1) // stack [... x2 x1]
	s.PushByteArray(so2) // stack [... x2 x1 x2]

	return nil
}

// DropN removes the top N items from the stack.
//
// Stack transformation:
// DropN(1): [... x1 x2] -> [... x1]
// DropN(2): [... x1 x2] -> [...]
func (s *stack) DropN(n int32) error {
	if n < 1 {
		str := fmt.Sprintf("attempt to drop %d items from stack", n)
		return scriptError(ErrInvalidStackOperation, str)
	}

	for ; n > 0; n-- {
		_, err := s.PopByteArray()
		if err != nil {
			return err
		}
	}
	return nil
}

// DupN duplicates the top N items on the stack.
//
// Stack transformation:
// DupN(1): [... x1 x2] -> [... x1 x2 x2]
// DupN(2): [... x1 x2] -> [... x1 x2 x1 x2]
func (s *stack) DupN(n int32) error {
	if n < 1 {
		str := fmt.Sprintf("attempt to dup %d stack items", n)
		return scriptError(ErrInvalidStackOperation, str)
	}

	// Iteratively duplicate the value n-1 down the stack n times.
	// This leaves an in-order duplicate of the top n items on the stack.
	for i := n; i > 0; i-- {
		so, err := s.PeekByteArray(n - 1)
		if err != nil {
			return err
		}
		s.PushByteArray(so)
	}
	return nil
}

// RotN rotates the top 3N items on the stack to the left N times.
//
// Stack transformation:
// RotN(1): [... x1 x2 x3] -> [... x2 x3 x1]
// RotN(2): [... x1 x2 x3 x4 x5 x6] -> [... x3 x4 x5 x6 x1 x2]
func (s *stack) RotN(n int32) error {
	if n < 1 {
		str := fmt.Sprintf("attempt to rotate %d stack items", n)
		return scriptError(ErrInvalidStackOperation, str)
	}

	// Nip the 3n-1th item from the stack to the top n times to rotate
	// them up to the head of the stack.
	entry := 3*n - 1
	for i := n; i > 0; i-- {
		so, err := s.nipN(entry)
		if err != nil {
			return err
		}

		s.PushByteArray(so)
	}
	return nil
}

// SwapN swaps the top N items on the stack with those below them.
//
// Stack transformation:
// SwapN(1): [... x1 x2] -> [... x2 x1]
// SwapN(2): [... x1 x2 x3 x4] -> [... x3 x4 x1 x2]
func (s *stack) SwapN(n int32) error {
	if n < 1 {
		str := fmt.Sprintf("attempt to swap %d stack items", n)
		return scriptError(ErrInvalidStackOperation, str)
	}

	entry := 2*n - 1
	for i := n; i > 0; i-- {
		// Swap 2n-1th entry to top.
		so, err := s.nipN(entry)
		if err != nil {
			return err
		}

		s.PushByteArray(so)
	}
	return nil
}

// OverN copies N items N items back to the top of the stack.
//
// Stack transformation:
// OverN(1): [... x1 x2 x3] -> [... x1 x2 x3 x2]
// OverN(2): [... x1 x2 x3 x4] -> [... x1 x2 x3 x4 x1 x2]
func (s *stack) OverN(n int32) error {
	if n < 1 {
		str := fmt.Sprintf("attempt to perform over on %d stack items",
			n)
		return scriptError(ErrInvalidStackOperation, str)
	}

	// Copy 2n-1th entry to top of the stack.
	entry := 2*n - 1
	for ; n > 0; n-- {
		so, err := s.PeekByteArray(entry)
		if err != nil {
			return err
		}
		s.PushByteArray(so)
	}

	return nil
}

// PickN copies the item N items back in the stack to the top.
//
// Stack transformation:
// PickN(0): [x1 x2 x3] -> [x1 x2 x3 x3]
// PickN(1): [x1 x2 x3] -> [x1 x2 x3 x2]
// PickN(2): [x1 x2 x3] -> [x1 x2 x3 x1]
func (s *stack) PickN(n int32) error {
	so, err := s.PeekByteArray(n)
	if err != nil {
		return err
	}
	s.PushByteArray(so)

	return nil
}

// RollN moves the item N items back in the stack to the top.
//
// Stack transformation:
// RollN(0): [x1 x2 x3] -> [x1 x2 x3]
// RollN(1): [x1 x2 x3] -> [x1 x3 x2]
// RollN(2): [x1 x2 x3] -> [x2 x3 x1]
func (s *stack) RollN(n int32) error {
	so, err := s.nipN(n)
	if err != nil {
		return err
	}

	s.PushByteArray(so)

	return nil
}

// String returns the stack in a readable format.
func (s *stack) String() string {
	var result string
	for _, stack := range s.stk {
		if len(stack) == 0 {
			result += "00000000  <empty>\n"
		}
		result += hex.Dump(stack)
	}

	return result
}
