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

// Package ct32 is a 32 bit optimized AES implementation that processes 2
// blocks at a time.
package ct32

import (
	"crypto/cipher"
	"encoding/binary"

	"git.schwanenlied.me/yawning/bsaes.git/internal/modes"
)

var rcon = [10]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}

func Sbox(q *[8]uint32) {
	// This S-box implementation is a straightforward translation of
	// the circuit described by Boyar and Peralta in "A new
	// combinational logic minimization technique with applications
	// to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	//
	// Note that variables x* (input) and s* (output) are numbered
	// in "reverse" order (x0 is the high bit, x7 is the low bit).

	var (
		x0, x1, x2, x3, x4, x5, x6, x7                   uint32
		y1, y2, y3, y4, y5, y6, y7, y8, y9               uint32
		y10, y11, y12, y13, y14, y15, y16, y17, y18, y19 uint32
		y20, y21                                         uint32
		z0, z1, z2, z3, z4, z5, z6, z7, z8, z9           uint32
		z10, z11, z12, z13, z14, z15, z16, z17           uint32
		t0, t1, t2, t3, t4, t5, t6, t7, t8, t9           uint32
		t10, t11, t12, t13, t14, t15, t16, t17, t18, t19 uint32
		t20, t21, t22, t23, t24, t25, t26, t27, t28, t29 uint32
		t30, t31, t32, t33, t34, t35, t36, t37, t38, t39 uint32
		t40, t41, t42, t43, t44, t45, t46, t47, t48, t49 uint32
		t50, t51, t52, t53, t54, t55, t56, t57, t58, t59 uint32
		t60, t61, t62, t63, t64, t65, t66, t67           uint32
		s0, s1, s2, s3, s4, s5, s6, s7                   uint32
	)

	x0 = q[7]
	x1 = q[6]
	x2 = q[5]
	x3 = q[4]
	x4 = q[3]
	x5 = q[2]
	x6 = q[1]
	x7 = q[0]

	//
	// Top linear transformation.
	//
	y14 = x3 ^ x5
	y13 = x0 ^ x6
	y9 = x0 ^ x3
	y8 = x0 ^ x5
	t0 = x1 ^ x2
	y1 = t0 ^ x7
	y4 = y1 ^ x3
	y12 = y13 ^ y14
	y2 = y1 ^ x0
	y5 = y1 ^ x6
	y3 = y5 ^ y8
	t1 = x4 ^ y12
	y15 = t1 ^ x5
	y20 = t1 ^ x1
	y6 = y15 ^ x7
	y10 = y15 ^ t0
	y11 = y20 ^ y9
	y7 = x7 ^ y11
	y17 = y10 ^ y11
	y19 = y10 ^ y8
	y16 = t0 ^ y11
	y21 = y13 ^ y16
	y18 = x0 ^ y16

	//
	// Non-linear section.
	//
	t2 = y12 & y15
	t3 = y3 & y6
	t4 = t3 ^ t2
	t5 = y4 & x7
	t6 = t5 ^ t2
	t7 = y13 & y16
	t8 = y5 & y1
	t9 = t8 ^ t7
	t10 = y2 & y7
	t11 = t10 ^ t7
	t12 = y9 & y11
	t13 = y14 & y17
	t14 = t13 ^ t12
	t15 = y8 & y10
	t16 = t15 ^ t12
	t17 = t4 ^ t14
	t18 = t6 ^ t16
	t19 = t9 ^ t14
	t20 = t11 ^ t16
	t21 = t17 ^ y20
	t22 = t18 ^ y19
	t23 = t19 ^ y21
	t24 = t20 ^ y18

	t25 = t21 ^ t22
	t26 = t21 & t23
	t27 = t24 ^ t26
	t28 = t25 & t27
	t29 = t28 ^ t22
	t30 = t23 ^ t24
	t31 = t22 ^ t26
	t32 = t31 & t30
	t33 = t32 ^ t24
	t34 = t23 ^ t33
	t35 = t27 ^ t33
	t36 = t24 & t35
	t37 = t36 ^ t34
	t38 = t27 ^ t36
	t39 = t29 & t38
	t40 = t25 ^ t39

	t41 = t40 ^ t37
	t42 = t29 ^ t33
	t43 = t29 ^ t40
	t44 = t33 ^ t37
	t45 = t42 ^ t41
	z0 = t44 & y15
	z1 = t37 & y6
	z2 = t33 & x7
	z3 = t43 & y16
	z4 = t40 & y1
	z5 = t29 & y7
	z6 = t42 & y11
	z7 = t45 & y17
	z8 = t41 & y10
	z9 = t44 & y12
	z10 = t37 & y3
	z11 = t33 & y4
	z12 = t43 & y13
	z13 = t40 & y5
	z14 = t29 & y2
	z15 = t42 & y9
	z16 = t45 & y14
	z17 = t41 & y8

	//
	// Bottom linear transformation.
	//
	t46 = z15 ^ z16
	t47 = z10 ^ z11
	t48 = z5 ^ z13
	t49 = z9 ^ z10
	t50 = z2 ^ z12
	t51 = z2 ^ z5
	t52 = z7 ^ z8
	t53 = z0 ^ z3
	t54 = z6 ^ z7
	t55 = z16 ^ z17
	t56 = z12 ^ t48
	t57 = t50 ^ t53
	t58 = z4 ^ t46
	t59 = z3 ^ t54
	t60 = t46 ^ t57
	t61 = z14 ^ t57
	t62 = t52 ^ t58
	t63 = t49 ^ t58
	t64 = z4 ^ t59
	t65 = t61 ^ t62
	t66 = z1 ^ t63
	s0 = t59 ^ t63
	s6 = t56 ^ (^t62)
	s7 = t48 ^ (^t60)
	t67 = t64 ^ t65
	s3 = t53 ^ t66
	s4 = t51 ^ t66
	s5 = t47 ^ t65
	s1 = t64 ^ (^s3)
	s2 = t55 ^ (^t67)

	q[7] = s0
	q[6] = s1
	q[5] = s2
	q[4] = s3
	q[3] = s4
	q[2] = s5
	q[1] = s6
	q[0] = s7
}

func Ortho(q []uint32) {
	_ = q[7] // Early bounds check.

	const cl2, ch2 = 0x55555555, 0xAAAAAAAA
	q[0], q[1] = (q[0]&cl2)|((q[1]&cl2)<<1), ((q[0]&ch2)>>1)|(q[1]&ch2)
	q[2], q[3] = (q[2]&cl2)|((q[3]&cl2)<<1), ((q[2]&ch2)>>1)|(q[3]&ch2)
	q[4], q[5] = (q[4]&cl2)|((q[5]&cl2)<<1), ((q[4]&ch2)>>1)|(q[5]&ch2)
	q[6], q[7] = (q[6]&cl2)|((q[7]&cl2)<<1), ((q[6]&ch2)>>1)|(q[7]&ch2)

	const cl4, ch4 = 0x33333333, 0xCCCCCCCC
	q[0], q[2] = (q[0]&cl4)|((q[2]&cl4)<<2), ((q[0]&ch4)>>2)|(q[2]&ch4)
	q[1], q[3] = (q[1]&cl4)|((q[3]&cl4)<<2), ((q[1]&ch4)>>2)|(q[3]&ch4)
	q[4], q[6] = (q[4]&cl4)|((q[6]&cl4)<<2), ((q[4]&ch4)>>2)|(q[6]&ch4)
	q[5], q[7] = (q[5]&cl4)|((q[7]&cl4)<<2), ((q[5]&ch4)>>2)|(q[7]&ch4)

	const cl8, ch8 = 0x0F0F0F0F, 0xF0F0F0F0
	q[0], q[4] = (q[0]&cl8)|((q[4]&cl8)<<4), ((q[0]&ch8)>>4)|(q[4]&ch8)
	q[1], q[5] = (q[1]&cl8)|((q[5]&cl8)<<4), ((q[1]&ch8)>>4)|(q[5]&ch8)
	q[2], q[6] = (q[2]&cl8)|((q[6]&cl8)<<4), ((q[2]&ch8)>>4)|(q[6]&ch8)
	q[3], q[7] = (q[3]&cl8)|((q[7]&cl8)<<4), ((q[3]&ch8)>>4)|(q[7]&ch8)
}

func AddRoundKey(q *[8]uint32, sk []uint32) {
	_ = sk[7] // Early bounds check.

	q[0] ^= sk[0]
	q[1] ^= sk[1]
	q[2] ^= sk[2]
	q[3] ^= sk[3]
	q[4] ^= sk[4]
	q[5] ^= sk[5]
	q[6] ^= sk[6]
	q[7] ^= sk[7]
}

func subWord(x uint32) uint32 {
	var q [8]uint32

	for i := range q {
		q[i] = x
	}
	Ortho(q[:])
	Sbox(&q)
	Ortho(q[:])
	x = q[0]
	memwipeU32(q[:])
	return x
}

func Keysched(compSkey []uint32, key []byte) int {
	numRounds := 0
	keyLen := len(key)
	switch keyLen {
	case 16:
		numRounds = 10
	case 24:
		numRounds = 12
	case 32:
		numRounds = 14
	default:
		panic("aes/impl32: Keysched: invalid key length")
	}

	var skey [120]uint32
	var tmp uint32
	nk := keyLen >> 2
	nkf := (numRounds + 1) << 2
	for i := 0; i < nk; i++ {
		tmp = binary.LittleEndian.Uint32(key[i<<2:])
		skey[(i<<1)+0] = tmp
		skey[(i<<1)+1] = tmp
	}
	for i, j, k := nk, 0, 0; i < nkf; i++ {
		if j == 0 {
			tmp = (tmp << 24) | (tmp >> 8)
			tmp = subWord(tmp) ^ uint32(rcon[k])
		} else if nk > 6 && j == 4 {
			tmp = subWord(tmp)
		}
		tmp ^= skey[(i-nk)<<1]
		skey[(i<<1)+0] = tmp
		skey[(i<<1)+1] = tmp
		if j++; j == nk {
			j = 0
			k++
		}
	}
	for i := 0; i < nkf; i += 4 {
		Ortho(skey[i<<1:])
	}
	for i, j := 0, 0; i < nkf; i, j = i+1, j+2 {
		compSkey[i] = (skey[j+0] & 0x55555555) | (skey[j+1] & 0xAAAAAAAA)
	}

	memwipeU32(skey[:])

	return numRounds
}

func SkeyExpand(skey []uint32, numRounds int, compSkey []uint32) {
	n := (numRounds + 1) << 2
	for u, v := 0, 0; u < n; u, v = u+1, v+2 {
		x := compSkey[u]
		y := compSkey[u]

		x &= 0x55555555
		skey[v+0] = x | (x << 1)
		y &= 0xAAAAAAAA
		skey[v+1] = y | (y >> 1)
	}
}

func RkeyOrtho(q []uint32, key []byte) {
	for i := 0; i < 4; i++ {
		x := binary.LittleEndian.Uint32(key[i<<2:])
		q[(i<<1)+0] = x
		q[(i<<1)+1] = x
	}
	Ortho(q[:])
	for i, j := 0, 0; i < 4; i, j = i+1, j+2 {
		x := (q[j+0] & 0x55555555) | (q[j+1] & 0xAAAAAAAA)
		y := x

		x &= 0x55555555
		q[j+0] = x | (x << 1)
		y &= 0xAAAAAAAA
		q[j+1] = y | (y >> 1)
	}
}

func Load4xU32(q *[8]uint32, src []byte) {
	q[0] = binary.LittleEndian.Uint32(src[:])
	q[2] = binary.LittleEndian.Uint32(src[4:])
	q[4] = binary.LittleEndian.Uint32(src[8:])
	q[6] = binary.LittleEndian.Uint32(src[12:])
	q[1] = 0
	q[3] = 0
	q[5] = 0
	q[7] = 0
	Ortho(q[:])
}

func Load8xU32(q *[8]uint32, src0, src1 []byte) {
	src := [][]byte{src0, src1}
	for i, s := range src {
		q[i] = binary.LittleEndian.Uint32(s[:])
		q[i+2] = binary.LittleEndian.Uint32(s[4:])
		q[i+4] = binary.LittleEndian.Uint32(s[8:])
		q[i+6] = binary.LittleEndian.Uint32(s[12:])
	}
	Ortho(q[:])
}

func Store4xU32(dst []byte, q *[8]uint32) {
	Ortho(q[:])
	binary.LittleEndian.PutUint32(dst[:], q[0])
	binary.LittleEndian.PutUint32(dst[4:], q[2])
	binary.LittleEndian.PutUint32(dst[8:], q[4])
	binary.LittleEndian.PutUint32(dst[12:], q[6])
}

func Store8xU32(dst0, dst1 []byte, q *[8]uint32) {
	Ortho(q[:])
	dst := [][]byte{dst0, dst1}
	for i, d := range dst {
		binary.LittleEndian.PutUint32(d[:], q[i])
		binary.LittleEndian.PutUint32(d[4:], q[i+2])
		binary.LittleEndian.PutUint32(d[8:], q[i+4])
		binary.LittleEndian.PutUint32(d[12:], q[i+6])
	}
}

func rotr16(x uint32) uint32 {
	return (x << 16) | (x >> 16)
}

func memwipeU32(s []uint32) {
	for i := range s {
		s[i] = 0
	}
}

type block struct {
	modes.BlockModesImpl

	skExp     [120]uint32
	numRounds int
	wasReset  bool
}

func (b *block) BlockSize() int {
	return 16
}

func (b *block) Stride() int {
	return 2
}

func (b *block) Encrypt(dst, src []byte) {
	var q [8]uint32

	if b.wasReset {
		panic("bsaes/ct32: Encrypt() called after Reset()")
	}

	Load4xU32(&q, src)
	encrypt(b.numRounds, b.skExp[:], &q)
	Store4xU32(dst, &q)
}

func (b *block) Decrypt(dst, src []byte) {
	var q [8]uint32

	if b.wasReset {
		panic("bsaes/ct32: Decrypt() called after Reset()")
	}

	Load4xU32(&q, src)
	decrypt(b.numRounds, b.skExp[:], &q)
	Store4xU32(dst, &q)
}

func (b *block) BulkEncrypt(dst, src []byte) {
	var q [8]uint32

	if b.wasReset {
		panic("bsaes/ct32: BulkEncrypt() called after Reset()")
	}

	Load8xU32(&q, src[0:], src[16:])
	encrypt(b.numRounds, b.skExp[:], &q)
	Store8xU32(dst[0:], dst[16:], &q)
}

func (b *block) BulkDecrypt(dst, src []byte) {
	var q [8]uint32

	if b.wasReset {
		panic("bsaes/ct32: BulkDecrypt() called after Reset()")
	}

	Load8xU32(&q, src[0:], src[16:])
	decrypt(b.numRounds, b.skExp[:], &q)
	Store8xU32(dst[0:], dst[16:], &q)
}

func (b *block) Reset() {
	if !b.wasReset {
		b.wasReset = true
		memwipeU32(b.skExp[:])
	}
}

// NewCipher creates and returns a new cipher.Block, backed by a Impl32.
func NewCipher(key []byte) cipher.Block {
	var skey [60]uint32
	defer memwipeU32(skey[:])

	b := new(block)
	b.numRounds = Keysched(skey[:], key)
	SkeyExpand(b.skExp[:], b.numRounds, skey[:])

	b.BlockModesImpl.Init(b)

	return b
}
