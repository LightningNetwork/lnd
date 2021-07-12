// round_bitsliced64.go - 64bit constant time AES round function.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package aez

import "git.schwanenlied.me/yawning/bsaes.git/ct64"

type roundB64 struct {
	skey [32]uint64 // I, J, L, 0
}

func newRoundB64(extractedKey *[extractedKeySize]byte) aesImpl {
	r := new(roundB64)
	for i := 0; i < 3; i++ {
		ct64.RkeyOrtho(r.skey[i*8:], extractedKey[i*16:])
	}

	return r
}

func (r *roundB64) Reset() {
	memwipeU64(r.skey[:])
}

func (r *roundB64) AES4(j, i, l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint64
	xorBytes4x16(j[:], i[:], l[:], src, dst[:])

	ct64.Load4xU32(&q, dst[:])
	r.round(&q, r.skey[8:])  // J
	r.round(&q, r.skey[0:])  // I
	r.round(&q, r.skey[16:]) // L
	r.round(&q, r.skey[24:]) // zero
	ct64.Store4xU32(dst[:], &q)

	memwipeU64(q[:])
}

func (r *roundB64) aes4x4(
	j0, i0, l0 *[blockSize]byte, src0 []byte, dst0 *[blockSize]byte,
	j1, i1, l1 *[blockSize]byte, src1 []byte, dst1 *[blockSize]byte,
	j2, i2, l2 *[blockSize]byte, src2 []byte, dst2 *[blockSize]byte,
	j3, i3, l3 *[blockSize]byte, src3 []byte, dst3 *[blockSize]byte) {
	var q [8]uint64
	xorBytes4x16(j0[:], i0[:], l0[:], src0, dst0[:])
	xorBytes4x16(j1[:], i1[:], l1[:], src1, dst1[:])
	xorBytes4x16(j2[:], i2[:], l2[:], src2, dst2[:])
	xorBytes4x16(j3[:], i3[:], l3[:], src3, dst3[:])

	ct64.Load16xU32(&q, dst0[:], dst1[:], dst2[:], dst3[:])
	r.round(&q, r.skey[8:])  // J
	r.round(&q, r.skey[0:])  // I
	r.round(&q, r.skey[16:]) // L
	r.round(&q, r.skey[24:]) // zero
	ct64.Store16xU32(dst0[:], dst1[:], dst2[:], dst3[:], &q)

	memwipeU64(q[:])
}

func (r *roundB64) AES10(l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint64
	xorBytes1x16(src, l[:], dst[:])

	ct64.Load4xU32(&q, dst[:])
	for i := 0; i < 3; i++ {
		r.round(&q, r.skey[0:])  // I
		r.round(&q, r.skey[8:])  // J
		r.round(&q, r.skey[16:]) // L
	}
	r.round(&q, r.skey[0:]) // I
	ct64.Store4xU32(dst[:], &q)

	memwipeU64(q[:])
}

func (r *roundB64) round(q *[8]uint64, k []uint64) {
	ct64.Sbox(q)
	ct64.ShiftRows(q)
	ct64.MixColumns(q)
	ct64.AddRoundKey(q, k)
}

func (r *roundB64) aezCorePass1(e *eState, in, out []byte, X *[blockSize]byte, sz int) {
	var tmp0, tmp1, tmp2, tmp3, I [blockSize]byte

	copy(I[:], e.I[1][:])
	i := 1

	// Process 8 * 16 bytes at a time in a loop.
	for mult := false; sz >= 8*blockSize; mult = !mult {
		r.aes4x4(&e.J[0], &I, &e.L[(i+0)%8], in[blockSize:], &tmp0,
			&e.J[0], &I, &e.L[(i+1)%8], in[blockSize*3:], &tmp1,
			&e.J[0], &I, &e.L[(i+2)%8], in[blockSize*5:], &tmp2,
			&e.J[0], &I, &e.L[(i+3)%8], in[blockSize*7:], &tmp3) // E(1,i) ... E(1,i+3)
		xorBytes1x16(in[:], tmp0[:], out[:])
		xorBytes1x16(in[blockSize*2:], tmp1[:], out[blockSize*2:])
		xorBytes1x16(in[blockSize*4:], tmp2[:], out[blockSize*4:])
		xorBytes1x16(in[blockSize*6:], tmp3[:], out[blockSize*6:])

		r.aes4x4(&zero, &e.I[0], &e.L[0], out[:], &tmp0,
			&zero, &e.I[0], &e.L[0], out[blockSize*2:], &tmp1,
			&zero, &e.I[0], &e.L[0], out[blockSize*4:], &tmp2,
			&zero, &e.I[0], &e.L[0], out[blockSize*6:], &tmp3) // E(0,0) x4
		xorBytes1x16(in[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(in[blockSize*3:], tmp1[:], out[blockSize*3:])
		xorBytes1x16(in[blockSize*5:], tmp2[:], out[blockSize*5:])
		xorBytes1x16(in[blockSize*7:], tmp3[:], out[blockSize*7:])

		xorBytes1x16(out[blockSize:], X[:], X[:])
		xorBytes1x16(out[blockSize*3:], X[:], X[:])
		xorBytes1x16(out[blockSize*5:], X[:], X[:])
		xorBytes1x16(out[blockSize*7:], X[:], X[:])

		sz -= 8 * blockSize
		in, out = in[128:], out[128:]
		if mult { // Multiply every other pass.
			doubleBlock(&I)
		}
		i += 4
	}

	// XXX/performance: 4 * 16 bytes at a time.

	for sz > 0 {
		r.AES4(&e.J[0], &I, &e.L[i%8], in[blockSize:], &tmp0) // E(1,i)
		xorBytes1x16(in[:], tmp0[:], out[:])
		r.AES4(&zero, &e.I[0], &e.L[0], out[:], &tmp0) // E(0,0)
		xorBytes1x16(in[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out[blockSize:], X[:], X[:])

		sz -= 2 * blockSize
		in, out = in[32:], out[32:]
		if i%8 == 0 {
			doubleBlock(&I)
		}
		i++
	}

	memwipe(tmp0[:])
	memwipe(tmp1[:])
	memwipe(tmp2[:])
	memwipe(tmp3[:])
	memwipe(I[:])
}

func (r *roundB64) aezCorePass2(e *eState, out []byte, Y, S *[blockSize]byte, sz int) {
	var tmp0, tmp1, tmp2, tmp3, I [blockSize]byte

	copy(I[:], e.I[1][:])
	i := 1

	// Process 8 * 16 bytes at a time in a loop.
	for mult := false; sz >= 8*blockSize; mult = !mult {
		r.aes4x4(&e.J[1], &I, &e.L[(i+0)%8], S[:], &tmp0,
			&e.J[1], &I, &e.L[(i+1)%8], S[:], &tmp1,
			&e.J[1], &I, &e.L[(i+2)%8], S[:], &tmp2,
			&e.J[1], &I, &e.L[(i+3)%8], S[:], &tmp3) // E(2,i) .. E(2,i+3)
		xorBytes1x16(out, tmp0[:], out[:])
		xorBytes1x16(out[blockSize*2:], tmp1[:], out[blockSize*2:])
		xorBytes1x16(out[blockSize*4:], tmp2[:], out[blockSize*4:])
		xorBytes1x16(out[blockSize*6:], tmp3[:], out[blockSize*6:])
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out[blockSize*3:], tmp1[:], out[blockSize*3:])
		xorBytes1x16(out[blockSize*5:], tmp2[:], out[blockSize*5:])
		xorBytes1x16(out[blockSize*7:], tmp3[:], out[blockSize*7:])
		xorBytes1x16(out, Y[:], Y[:])
		xorBytes1x16(out[blockSize*2:], Y[:], Y[:])
		xorBytes1x16(out[blockSize*4:], Y[:], Y[:])
		xorBytes1x16(out[blockSize*6:], Y[:], Y[:])

		r.aes4x4(&zero, &e.I[0], &e.L[0], out[blockSize:], &tmp0,
			&zero, &e.I[0], &e.L[0], out[blockSize*3:], &tmp1,
			&zero, &e.I[0], &e.L[0], out[blockSize*5:], &tmp2,
			&zero, &e.I[0], &e.L[0], out[blockSize*7:], &tmp3) // E(0,0)x4
		xorBytes1x16(out, tmp0[:], out[:])
		xorBytes1x16(out[blockSize*2:], tmp1[:], out[blockSize*2:])
		xorBytes1x16(out[blockSize*4:], tmp2[:], out[blockSize*4:])
		xorBytes1x16(out[blockSize*6:], tmp3[:], out[blockSize*6:])

		r.aes4x4(&e.J[0], &I, &e.L[(i+0)%8], out[:], &tmp0,
			&e.J[0], &I, &e.L[(i+1)%8], out[blockSize*2:], &tmp1,
			&e.J[0], &I, &e.L[(i+2)%8], out[blockSize*4:], &tmp2,
			&e.J[0], &I, &e.L[(i+3)%8], out[blockSize*6:], &tmp3) // E(1,i) ...  E(1,i+3)
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out[blockSize*3:], tmp1[:], out[blockSize*3:])
		xorBytes1x16(out[blockSize*5:], tmp2[:], out[blockSize*5:])
		xorBytes1x16(out[blockSize*7:], tmp3[:], out[blockSize*7:])

		swapBlocks(&tmp0, out)
		swapBlocks(&tmp0, out[blockSize*2:])
		swapBlocks(&tmp0, out[blockSize*4:])
		swapBlocks(&tmp0, out[blockSize*6:])

		sz -= 8 * blockSize
		out = out[128:]
		if mult { // Multiply every other pass.
			doubleBlock(&I)
		}
		i += 4
	}

	// XXX/performance: 4 * 16 bytes at a time.

	for sz > 0 {
		r.AES4(&e.J[1], &I, &e.L[i%8], S[:], &tmp0) // E(2,i)
		xorBytes1x16(out, tmp0[:], out[:])
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out, Y[:], Y[:])

		r.AES4(&zero, &e.I[0], &e.L[0], out[blockSize:], &tmp0) // E(0,0)
		xorBytes1x16(out, tmp0[:], out[:])

		r.AES4(&e.J[0], &I, &e.L[i%8], out[:], &tmp0) // E(1,i)
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])

		swapBlocks(&tmp0, out)

		sz -= 2 * blockSize
		out = out[32:]
		if i%8 == 0 {
			doubleBlock(&I)
		}
		i++
	}

	memwipe(tmp0[:])
	memwipe(tmp1[:])
	memwipe(tmp2[:])
	memwipe(tmp3[:])
	memwipe(I[:])
}

func memwipeU64(s []uint64) {
	for i := range s {
		s[i] = 0
	}
}
