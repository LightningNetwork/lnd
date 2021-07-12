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

// Package ct64 is a 64 bit optimized AES implementation that processes 4
// blocks at a time.
package ct64

import (
	"crypto/cipher"
	"encoding/binary"

	"git.schwanenlied.me/yawning/bsaes.git/internal/modes"
)

var rcon = [10]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}

func Sbox(q *[8]uint64) {
	// This S-box implementation is a straightforward translation of
	// the circuit described by Boyar and Peralta in "A new
	// combinational logic minimization technique with applications
	// to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	//
	// Note that variables x* (input) and s* (output) are numbered
	// in "reverse" order (x0 is the high bit, x7 is the low bit).

	var x0, x1, x2, x3, x4, x5, x6, x7 uint64
	var y1, y2, y3, y4, y5, y6, y7, y8, y9 uint64
	var y10, y11, y12, y13, y14, y15, y16, y17, y18, y19 uint64
	var y20, y21 uint64
	var z0, z1, z2, z3, z4, z5, z6, z7, z8, z9 uint64
	var z10, z11, z12, z13, z14, z15, z16, z17 uint64
	var t0, t1, t2, t3, t4, t5, t6, t7, t8, t9 uint64
	var t10, t11, t12, t13, t14, t15, t16, t17, t18, t19 uint64
	var t20, t21, t22, t23, t24, t25, t26, t27, t28, t29 uint64
	var t30, t31, t32, t33, t34, t35, t36, t37, t38, t39 uint64
	var t40, t41, t42, t43, t44, t45, t46, t47, t48, t49 uint64
	var t50, t51, t52, t53, t54, t55, t56, t57, t58, t59 uint64
	var t60, t61, t62, t63, t64, t65, t66, t67 uint64
	var s0, s1, s2, s3, s4, s5, s6, s7 uint64

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

func Ortho(q []uint64) {
	_ = q[7] // Early bounds check.

	const cl2, ch2 = 0x5555555555555555, 0xAAAAAAAAAAAAAAAA
	q[0], q[1] = (q[0]&cl2)|((q[1]&cl2)<<1), ((q[0]&ch2)>>1)|(q[1]&ch2)
	q[2], q[3] = (q[2]&cl2)|((q[3]&cl2)<<1), ((q[2]&ch2)>>1)|(q[3]&ch2)
	q[4], q[5] = (q[4]&cl2)|((q[5]&cl2)<<1), ((q[4]&ch2)>>1)|(q[5]&ch2)
	q[6], q[7] = (q[6]&cl2)|((q[7]&cl2)<<1), ((q[6]&ch2)>>1)|(q[7]&ch2)

	const cl4, ch4 = 0x3333333333333333, 0xCCCCCCCCCCCCCCCC
	q[0], q[2] = (q[0]&cl4)|((q[2]&cl4)<<2), ((q[0]&ch4)>>2)|(q[2]&ch4)
	q[1], q[3] = (q[1]&cl4)|((q[3]&cl4)<<2), ((q[1]&ch4)>>2)|(q[3]&ch4)
	q[4], q[6] = (q[4]&cl4)|((q[6]&cl4)<<2), ((q[4]&ch4)>>2)|(q[6]&ch4)
	q[5], q[7] = (q[5]&cl4)|((q[7]&cl4)<<2), ((q[5]&ch4)>>2)|(q[7]&ch4)

	const cl8, ch8 = 0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0
	q[0], q[4] = (q[0]&cl8)|((q[4]&cl8)<<4), ((q[0]&ch8)>>4)|(q[4]&ch8)
	q[1], q[5] = (q[1]&cl8)|((q[5]&cl8)<<4), ((q[1]&ch8)>>4)|(q[5]&ch8)
	q[2], q[6] = (q[2]&cl8)|((q[6]&cl8)<<4), ((q[2]&ch8)>>4)|(q[6]&ch8)
	q[3], q[7] = (q[3]&cl8)|((q[7]&cl8)<<4), ((q[3]&ch8)>>4)|(q[7]&ch8)
}

func InterleaveIn(q0, q1 *uint64, w []uint32) {
	_ = w[3]
	x0, x1, x2, x3 := uint64(w[0]), uint64(w[1]), uint64(w[2]), uint64(w[3])
	x0 |= (x0 << 16)
	x1 |= (x1 << 16)
	x2 |= (x2 << 16)
	x3 |= (x3 << 16)
	x0 &= 0x0000FFFF0000FFFF
	x1 &= 0x0000FFFF0000FFFF
	x2 &= 0x0000FFFF0000FFFF
	x3 &= 0x0000FFFF0000FFFF
	x0 |= (x0 << 8)
	x1 |= (x1 << 8)
	x2 |= (x2 << 8)
	x3 |= (x3 << 8)
	x0 &= 0x00FF00FF00FF00FF
	x1 &= 0x00FF00FF00FF00FF
	x2 &= 0x00FF00FF00FF00FF
	x3 &= 0x00FF00FF00FF00FF
	*q0 = x0 | (x2 << 8)
	*q1 = x1 | (x3 << 8)
}

func InterleaveOut(w []uint32, q0, q1 uint64) {
	var x0, x1, x2, x3 uint64

	_ = w[3]
	x0 = q0 & 0x00FF00FF00FF00FF
	x1 = q1 & 0x00FF00FF00FF00FF
	x2 = (q0 >> 8) & 0x00FF00FF00FF00FF
	x3 = (q1 >> 8) & 0x00FF00FF00FF00FF
	x0 |= (x0 >> 8)
	x1 |= (x1 >> 8)
	x2 |= (x2 >> 8)
	x3 |= (x3 >> 8)
	x0 &= 0x0000FFFF0000FFFF
	x1 &= 0x0000FFFF0000FFFF
	x2 &= 0x0000FFFF0000FFFF
	x3 &= 0x0000FFFF0000FFFF
	w[0] = uint32(x0) | uint32(x0>>16)
	w[1] = uint32(x1) | uint32(x1>>16)
	w[2] = uint32(x2) | uint32(x2>>16)
	w[3] = uint32(x3) | uint32(x3>>16)
}

func AddRoundKey(q *[8]uint64, sk []uint64) {
	_ = sk[7]

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
	var q [8]uint64

	q[0] = uint64(x)
	Ortho(q[:])
	Sbox(&q)
	Ortho(q[:])
	x = uint32(q[0])
	memwipeU64(q[:])
	return x
}

func Keysched(compSkey []uint64, key []byte) int {
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

	var skey [60]uint32
	nk := keyLen >> 2
	nkf := (numRounds + 1) << 2
	for i := 0; i < nk; i++ {
		skey[i] = binary.LittleEndian.Uint32(key[i<<2:])
	}
	tmp := skey[(keyLen>>2)-1]
	for i, j, k := nk, 0, 0; i < nkf; i++ {
		if j == 0 {
			tmp = (tmp << 24) | (tmp >> 8)
			tmp = subWord(tmp) ^ uint32(rcon[k])
		} else if nk > 6 && j == 4 {
			tmp = subWord(tmp)
		}
		tmp ^= skey[i-nk]
		skey[i] = tmp
		if j++; j == nk {
			j = 0
			k++
		}
	}

	var q [8]uint64
	for i, j := 0, 0; i < nkf; i, j = i+4, j+2 {
		InterleaveIn(&q[0], &q[4], skey[i:])
		q[1] = q[0]
		q[2] = q[0]
		q[3] = q[0]
		q[5] = q[4]
		q[6] = q[4]
		q[7] = q[4]
		Ortho(q[:])
		compSkey[j+0] = (q[0] & 0x1111111111111111) |
			(q[1] & 0x2222222222222222) | (q[2] & 0x4444444444444444) |
			(q[3] & 0x8888888888888888)
		compSkey[j+1] = (q[4] & 0x1111111111111111) |
			(q[5] & 0x2222222222222222) | (q[6] & 0x4444444444444444) |
			(q[7] & 0x8888888888888888)
	}

	for i := range skey {
		skey[i] = 0
	}
	memwipeU64(q[:])

	return numRounds
}

func SkeyExpand(skey []uint64, numRounds int, compSkey []uint64) {
	n := (numRounds + 1) << 1
	for u, v := 0, 0; u < n; u, v = u+1, v+4 {
		x0 := compSkey[u]
		x1, x2, x3 := x0, x0, x0
		x0 &= 0x1111111111111111
		x1 &= 0x2222222222222222
		x2 &= 0x4444444444444444
		x3 &= 0x8888888888888888
		x1 >>= 1
		x2 >>= 2
		x3 >>= 3
		skey[v+0] = (x0 << 4) - x0
		skey[v+1] = (x1 << 4) - x1
		skey[v+2] = (x2 << 4) - x2
		skey[v+3] = (x3 << 4) - x3
	}
}

func RkeyOrtho(qq []uint64, key []byte) {
	var skey [16]uint32
	var compSkey [16]uint64

	for i := 0; i < 4; i++ {
		skey[i] = binary.LittleEndian.Uint32(key[i<<2:])
	}

	var q [8]uint64
	for i, j := 0, 0; i < 4; i, j = i+4, j+2 {
		InterleaveIn(&q[0], &q[4], skey[i:])
		q[1] = q[0]
		q[2] = q[0]
		q[3] = q[0]
		q[5] = q[4]
		q[6] = q[4]
		q[7] = q[4]
		Ortho(q[:])
		compSkey[j+0] = (q[0] & 0x1111111111111111) |
			(q[1] & 0x2222222222222222) | (q[2] & 0x4444444444444444) |
			(q[3] & 0x8888888888888888)
		compSkey[j+1] = (q[4] & 0x1111111111111111) |
			(q[5] & 0x2222222222222222) | (q[6] & 0x4444444444444444) |
			(q[7] & 0x8888888888888888)
	}

	for u, v := 0, 0; u < 4; u, v = u+1, v+4 {
		x0 := compSkey[u]
		x1, x2, x3 := x0, x0, x0
		x0 &= 0x1111111111111111
		x1 &= 0x2222222222222222
		x2 &= 0x4444444444444444
		x3 &= 0x8888888888888888
		x1 >>= 1
		x2 >>= 2
		x3 >>= 3
		qq[v+0] = (x0 << 4) - x0
		qq[v+1] = (x1 << 4) - x1
		qq[v+2] = (x2 << 4) - x2
		qq[v+3] = (x3 << 4) - x3
	}

	for i := range skey {
		skey[i] = 0
	}
	memwipeU64(compSkey[:])
	memwipeU64(q[:])
}

func Load4xU32(q *[8]uint64, src []byte) {
	var w [4]uint32

	w[0] = binary.LittleEndian.Uint32(src[:])
	w[1] = binary.LittleEndian.Uint32(src[4:])
	w[2] = binary.LittleEndian.Uint32(src[8:])
	w[3] = binary.LittleEndian.Uint32(src[12:])
	InterleaveIn(&q[0], &q[4], w[:])
	Ortho(q[:])
}

func Load16xU32(q *[8]uint64, src0, src1, src2, src3 []byte) {
	var w [4]uint32

	src := [][]byte{src0, src1, src2, src3}
	for i, s := range src {
		w[0] = binary.LittleEndian.Uint32(s[:])
		w[1] = binary.LittleEndian.Uint32(s[4:])
		w[2] = binary.LittleEndian.Uint32(s[8:])
		w[3] = binary.LittleEndian.Uint32(s[12:])
		InterleaveIn(&q[i], &q[i+4], w[:])
	}
	Ortho(q[:])
}

func Store4xU32(dst []byte, q *[8]uint64) {
	var w [4]uint32

	Ortho(q[:])
	InterleaveOut(w[:], q[0], q[4])
	binary.LittleEndian.PutUint32(dst[:], w[0])
	binary.LittleEndian.PutUint32(dst[4:], w[1])
	binary.LittleEndian.PutUint32(dst[8:], w[2])
	binary.LittleEndian.PutUint32(dst[12:], w[3])
}

func Store16xU32(dst0, dst1, dst2, dst3 []byte, q *[8]uint64) {
	var w [4]uint32

	dst := [][]byte{dst0, dst1, dst2, dst3}
	Ortho(q[:])
	for i, d := range dst {
		InterleaveOut(w[:], q[i], q[i+4])
		binary.LittleEndian.PutUint32(d[:], w[0])
		binary.LittleEndian.PutUint32(d[4:], w[1])
		binary.LittleEndian.PutUint32(d[8:], w[2])
		binary.LittleEndian.PutUint32(d[12:], w[3])
	}
}

func rotr32(x uint64) uint64 {
	return (x << 32) | (x >> 32)
}

func memwipeU64(s []uint64) {
	for i := range s {
		s[i] = 0
	}
}

type block struct {
	modes.BlockModesImpl

	skExp     [120]uint64
	numRounds int
	wasReset  bool
}

func (b *block) BlockSize() int {
	return 16
}

func (b *block) Stride() int {
	return 4
}

func (b *block) Encrypt(dst, src []byte) {
	var q [8]uint64

	if b.wasReset {
		panic("bsaes/ct64: Encrypt() called after Reset()")
	}

	Load4xU32(&q, src[:])
	encrypt(b.numRounds, b.skExp[:], &q)
	Store4xU32(dst[:], &q)
}

func (b *block) Decrypt(dst, src []byte) {
	var q [8]uint64

	if b.wasReset {
		panic("bsaes/ct64: Decrypt() called after Reset()")
	}

	Load4xU32(&q, src[:])
	decrypt(b.numRounds, b.skExp[:], &q)
	Store4xU32(dst[:], &q)
}

func (b *block) BulkEncrypt(dst, src []byte) {
	var q [8]uint64

	if b.wasReset {
		panic("bsaes/ct64: BulkEncrypt() called after Reset()")
	}

	Load16xU32(&q, src[0:], src[16:], src[32:], src[48:])
	encrypt(b.numRounds, b.skExp[:], &q)
	Store16xU32(dst[0:], dst[16:], dst[32:], dst[48:], &q)
}

func (b *block) BulkDecrypt(dst, src []byte) {
	var q [8]uint64

	if b.wasReset {
		panic("bsaes/ct64: BulkDecrypt() called after Reset()")
	}

	Load16xU32(&q, src[0:], src[16:], src[32:], src[48:])
	decrypt(b.numRounds, b.skExp[:], &q)
	Store16xU32(dst[0:], dst[16:], dst[32:], dst[48:], &q)
}

func (b *block) Reset() {
	if !b.wasReset {
		b.wasReset = true
		memwipeU64(b.skExp[:])
	}
}

// NewCipher creates and returns a new cipher.Block, backed by a Impl64.
func NewCipher(key []byte) cipher.Block {
	var skey [30]uint64
	defer memwipeU64(skey[:])

	b := new(block)
	b.numRounds = Keysched(skey[:], key)
	SkeyExpand(b.skExp[:], b.numRounds, skey[:])

	b.BlockModesImpl.Init(b)

	return b
}
