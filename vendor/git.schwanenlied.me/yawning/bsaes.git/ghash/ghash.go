// Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
// Copyright (c) 2017 Yawning Angel <yawning at schwanenlied dot me>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package ghash is a constant time 64 bit optimized GHASH implementation.
package ghash

import "encoding/binary"

const blockSize = 16

func bmul64(x, y uint64) uint64 {
	x0 := x & 0x1111111111111111
	x1 := x & 0x2222222222222222
	x2 := x & 0x4444444444444444
	x3 := x & 0x8888888888888888
	y0 := y & 0x1111111111111111
	y1 := y & 0x2222222222222222
	y2 := y & 0x4444444444444444
	y3 := y & 0x8888888888888888
	z0 := (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
	z1 := (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
	z2 := (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
	z3 := (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
	z0 &= 0x1111111111111111
	z1 &= 0x2222222222222222
	z2 &= 0x4444444444444444
	z3 &= 0x8888888888888888
	return z0 | z1 | z2 | z3
}

func rev64(x uint64) uint64 {
	x = ((x & 0x5555555555555555) << 1) | ((x >> 1) & 0x5555555555555555)
	x = ((x & 0x3333333333333333) << 2) | ((x >> 2) & 0x3333333333333333)
	x = ((x & 0x0F0F0F0F0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0F)
	x = ((x & 0x00FF00FF00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF00FF00FF)
	x = ((x & 0x0000FFFF0000FFFF) << 16) | ((x >> 16) & 0x0000FFFF0000FFFF)
	return (x << 32) | (x >> 32)
}

// Ghash calculates the GHASH of data, with key h, and input y, and stores the
// resulting digest in y.
func Ghash(y, h *[blockSize]byte, data []byte) {
	var tmp [blockSize]byte
	var src []byte

	buf := data
	l := len(buf)

	y1 := binary.BigEndian.Uint64(y[:])
	y0 := binary.BigEndian.Uint64(y[8:])
	h1 := binary.BigEndian.Uint64(h[:])
	h0 := binary.BigEndian.Uint64(h[8:])
	h0r := rev64(h0)
	h1r := rev64(h1)
	h2 := h0 ^ h1
	h2r := h0r ^ h1r

	for l > 0 {
		if l >= blockSize {
			src = buf
			buf = buf[blockSize:]
			l -= blockSize
		} else {
			copy(tmp[:], buf)
			src = tmp[:]
			l = 0
		}
		y1 ^= binary.BigEndian.Uint64(src)
		y0 ^= binary.BigEndian.Uint64(src[8:])

		y0r := rev64(y0)
		y1r := rev64(y1)
		y2 := y0 ^ y1
		y2r := y0r ^ y1r

		z0 := bmul64(y0, h0)
		z1 := bmul64(y1, h1)
		z2 := bmul64(y2, h2)
		z0h := bmul64(y0r, h0r)
		z1h := bmul64(y1r, h1r)
		z2h := bmul64(y2r, h2r)
		z2 ^= z0 ^ z1
		z2h ^= z0h ^ z1h
		z0h = rev64(z0h) >> 1
		z1h = rev64(z1h) >> 1
		z2h = rev64(z2h) >> 1

		v0 := z0
		v1 := z0h ^ z2
		v2 := z1 ^ z2h
		v3 := z1h

		v3 = (v3 << 1) | (v2 >> 63)
		v2 = (v2 << 1) | (v1 >> 63)
		v1 = (v1 << 1) | (v0 >> 63)
		v0 = (v0 << 1)

		v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
		v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
		v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
		v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)

		y0 = v2
		y1 = v3
	}

	binary.BigEndian.PutUint64(y[:], y1)
	binary.BigEndian.PutUint64(y[8:], y0)
}
