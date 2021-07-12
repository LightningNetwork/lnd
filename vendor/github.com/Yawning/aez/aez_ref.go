// aez_ref.go - Generic fallback routines.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build !amd64 gccgo appengine noasm

package aez

func xorBytes1x16(a, b, dst []byte) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func xorBytes4x16(a, b, c, d, dst []byte) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i] ^ c[i] ^ d[i]
	}
}

func (e *eState) aezCorePass1(in, out []byte, X *[blockSize]byte, sz int) {
	e.aezCorePass1Slow(in, out, X, sz)
}

func (e *eState) aezCorePass2(in, out []byte, Y, S *[blockSize]byte, sz int) {
	e.aezCorePass2Slow(in, out, Y, S, sz)
}

func platformInit() {
	// Nothing special to do here.
}
