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

package ct32

func ShiftRows(q *[8]uint32) {
	for i, x := range q {
		q[i] = (x & 0x000000FF) |
			((x & 0x0000FC00) >> 2) | ((x & 0x00000300) << 6) |
			((x & 0x00F00000) >> 4) | ((x & 0x000F0000) << 4) |
			((x & 0xC0000000) >> 6) | ((x & 0x3F000000) << 2)
	}
}

func MixColumns(q *[8]uint32) {
	var q0, q1, q2, q3, q4, q5, q6, q7 uint32
	var r0, r1, r2, r3, r4, r5, r6, r7 uint32

	q0 = q[0]
	q1 = q[1]
	q2 = q[2]
	q3 = q[3]
	q4 = q[4]
	q5 = q[5]
	q6 = q[6]
	q7 = q[7]
	r0 = (q0 >> 8) | (q0 << 24)
	r1 = (q1 >> 8) | (q1 << 24)
	r2 = (q2 >> 8) | (q2 << 24)
	r3 = (q3 >> 8) | (q3 << 24)
	r4 = (q4 >> 8) | (q4 << 24)
	r5 = (q5 >> 8) | (q5 << 24)
	r6 = (q6 >> 8) | (q6 << 24)
	r7 = (q7 >> 8) | (q7 << 24)

	q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0^r0)
	q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1^r1)
	q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2^r2)
	q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3^r3)
	q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4^r4)
	q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5^r5)
	q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6^r6)
	q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7^r7)
}

func encrypt(numRounds int, skey []uint32, q *[8]uint32) {
	AddRoundKey(q, skey)
	for u := 1; u < numRounds; u++ {
		Sbox(q)
		ShiftRows(q)
		MixColumns(q)
		AddRoundKey(q, skey[u<<3:])
	}
	Sbox(q)
	ShiftRows(q)
	AddRoundKey(q, skey[numRounds<<3:])
}
