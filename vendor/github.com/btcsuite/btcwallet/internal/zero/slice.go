// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This file implements range-based zeroing, which as of Go 1.5 is
// optimized using a Duff's device.

package zero

import "math/big"

// Bytes sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
//
// In general, prefer to use the fixed-sized zeroing functions (Bytea*)
// when zeroing bytes as they are much more efficient than the variable
// sized zeroing func Bytes.
func Bytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// BigInt sets all bytes in the passed big int to zero and then sets the
// value to 0.  This differs from simply setting the value in that it
// specifically clears the underlying bytes whereas simply setting the value
// does not.  This is mostly useful to forcefully clear private keys.
func BigInt(x *big.Int) {
	b := x.Bits()
	for i := range b {
		b[i] = 0
	}
	x.SetInt64(0)
}
