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

package ct64

func InvSbox(q *[8]uint64) {
	// See ct32/Impl32.InvSbox(). This is the natural extension
	// to 64-bit registers.
	var q0, q1, q2, q3, q4, q5, q6, q7 uint64

	q0 = ^q[0]
	q1 = ^q[1]
	q2 = q[2]
	q3 = q[3]
	q4 = q[4]
	q5 = ^q[5]
	q6 = ^q[6]
	q7 = q[7]
	q[7] = q1 ^ q4 ^ q6
	q[6] = q0 ^ q3 ^ q5
	q[5] = q7 ^ q2 ^ q4
	q[4] = q6 ^ q1 ^ q3
	q[3] = q5 ^ q0 ^ q2
	q[2] = q4 ^ q7 ^ q1
	q[1] = q3 ^ q6 ^ q0
	q[0] = q2 ^ q5 ^ q7

	Sbox(q)

	q0 = ^q[0]
	q1 = ^q[1]
	q2 = q[2]
	q3 = q[3]
	q4 = q[4]
	q5 = ^q[5]
	q6 = ^q[6]
	q7 = q[7]
	q[7] = q1 ^ q4 ^ q6
	q[6] = q0 ^ q3 ^ q5
	q[5] = q7 ^ q2 ^ q4
	q[4] = q6 ^ q1 ^ q3
	q[3] = q5 ^ q0 ^ q2
	q[2] = q4 ^ q7 ^ q1
	q[1] = q3 ^ q6 ^ q0
	q[0] = q2 ^ q5 ^ q7
}

func InvShiftRows(q *[8]uint64) {
	for i, x := range q {
		q[i] = (x & 0x000000000000FFFF) |
			((x & 0x000000000FFF0000) << 4) |
			((x & 0x00000000F0000000) >> 12) |
			((x & 0x000000FF00000000) << 8) |
			((x & 0x0000FF0000000000) >> 8) |
			((x & 0x000F000000000000) << 12) |
			((x & 0xFFF0000000000000) >> 4)
	}
}

func InvMixColumns(q *[8]uint64) {
	q0 := q[0]
	q1 := q[1]
	q2 := q[2]
	q3 := q[3]
	q4 := q[4]
	q5 := q[5]
	q6 := q[6]
	q7 := q[7]
	r0 := (q0 >> 16) | (q0 << 48)
	r1 := (q1 >> 16) | (q1 << 48)
	r2 := (q2 >> 16) | (q2 << 48)
	r3 := (q3 >> 16) | (q3 << 48)
	r4 := (q4 >> 16) | (q4 << 48)
	r5 := (q5 >> 16) | (q5 << 48)
	r6 := (q6 >> 16) | (q6 << 48)
	r7 := (q7 >> 16) | (q7 << 48)

	q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ rotr32(q0^q5^q6^r0^r5)
	q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ rotr32(q1^q5^q7^r1^r5^r6)
	q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ rotr32(q0^q2^q6^r2^r6^r7)
	q[3] = q0 ^ q1 ^ q2 ^ q5 ^ q6 ^ r0 ^ r2 ^ r3 ^ r5 ^ rotr32(q0^q1^q3^q5^q6^q7^r0^r3^r5^r7)
	q[4] = q1 ^ q2 ^ q3 ^ q5 ^ r1 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7 ^ rotr32(q1^q2^q4^q5^q7^r1^r4^r5^r6)
	q[5] = q2 ^ q3 ^ q4 ^ q6 ^ r2 ^ r4 ^ r5 ^ r6 ^ r7 ^ rotr32(q2^q3^q5^q6^r2^r5^r6^r7)
	q[6] = q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7 ^ rotr32(q3^q4^q6^q7^r3^r6^r7)
	q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ rotr32(q4^q5^q7^r4^r7)
}

func decrypt(numRounds int, skey []uint64, q *[8]uint64) {
	AddRoundKey(q, skey[numRounds<<3:])
	for u := numRounds - 1; u > 0; u-- {
		InvShiftRows(q)
		InvSbox(q)
		AddRoundKey(q, skey[u<<3:])
		InvMixColumns(q)
	}
	InvShiftRows(q)
	InvSbox(q)
	AddRoundKey(q, skey)
}
