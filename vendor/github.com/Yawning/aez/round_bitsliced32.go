// round_bitsliced32.go - 32 bit Constant time AES round function.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package aez

import "git.schwanenlied.me/yawning/bsaes.git/ct32"

type roundB32 struct {
	skey [32]uint32 // I, J, L, 0
}

func newRoundB32(extractedKey *[extractedKeySize]byte) aesImpl {
	r := new(roundB32)
	for i := 0; i < 3; i++ {
		ct32.RkeyOrtho(r.skey[i*8:], extractedKey[i*16:])
	}

	return r
}

func (r *roundB32) Reset() {
	memwipeU32(r.skey[:])
}

func (r *roundB32) AES4(j, i, l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint32
	xorBytes4x16(j[:], i[:], l[:], src, dst[:])

	ct32.Load4xU32(&q, dst[:])
	r.round(&q, r.skey[8:])  // J
	r.round(&q, r.skey[0:])  // I
	r.round(&q, r.skey[16:]) // L
	r.round(&q, r.skey[24:]) // zero
	ct32.Store4xU32(dst[:], &q)

	memwipeU32(q[:])
}

func (r *roundB32) aes4x2(
	j0, i0, l0 *[blockSize]byte, src0 []byte, dst0 *[blockSize]byte,
	j1, i1, l1 *[blockSize]byte, src1 []byte, dst1 *[blockSize]byte) {
	// XXX/performance: Fairly sure i, src, and dst are the only things
	// that are ever different here so XORs can be pruned.

	var q [8]uint32
	xorBytes4x16(j0[:], i0[:], l0[:], src0, dst0[:])
	xorBytes4x16(j1[:], i1[:], l1[:], src1, dst1[:])

	ct32.Load8xU32(&q, dst0[:], dst1[:])
	r.round(&q, r.skey[8:])  // J
	r.round(&q, r.skey[0:])  // I
	r.round(&q, r.skey[16:]) // L
	r.round(&q, r.skey[24:]) // zero
	ct32.Store8xU32(dst0[:], dst1[:], &q)

	memwipeU32(q[:])
}

func (r *roundB32) AES10(l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint32
	xorBytes1x16(src, l[:], dst[:])

	ct32.Load4xU32(&q, dst[:])
	for i := 0; i < 3; i++ {
		r.round(&q, r.skey[0:])  // I
		r.round(&q, r.skey[8:])  // J
		r.round(&q, r.skey[16:]) // L
	}
	r.round(&q, r.skey[0:]) // I
	ct32.Store4xU32(dst[:], &q)

	memwipeU32(q[:])
}

func (r *roundB32) round(q *[8]uint32, k []uint32) {
	ct32.Sbox(q)
	ct32.ShiftRows(q)
	ct32.MixColumns(q)
	ct32.AddRoundKey(q, k)
}

func (r *roundB32) aezCorePass1(e *eState, in, out []byte, X *[blockSize]byte, sz int) {
	var tmp0, tmp1, I [blockSize]byte

	copy(I[:], e.I[1][:])
	i := 1

	// Process 4 * 16 bytes at a time in a loop.
	for sz >= 4*blockSize {
		r.aes4x2(&e.J[0], &I, &e.L[(i+0)%8], in[blockSize:], &tmp0,
			&e.J[0], &I, &e.L[(i+1)%8], in[blockSize*3:], &tmp1) // E(1,i), E(1,i+1)
		xorBytes1x16(in[:], tmp0[:], out[:])
		xorBytes1x16(in[blockSize*2:], tmp1[:], out[blockSize*2:])

		r.aes4x2(&zero, &e.I[0], &e.L[0], out[:], &tmp0,
			&zero, &e.I[0], &e.L[0], out[blockSize*2:], &tmp1) // E(0,0), E(0,0)
		xorBytes1x16(in[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(in[blockSize*3:], tmp1[:], out[blockSize*3:])

		xorBytes1x16(out[blockSize:], X[:], X[:])
		xorBytes1x16(out[blockSize*3:], X[:], X[:])

		sz -= 4 * blockSize
		in, out = in[64:], out[64:]
		if (i+1)%8 == 0 {
			doubleBlock(&I)
		}
		i += 2
	}
	if sz > 0 {
		r.AES4(&e.J[0], &I, &e.L[i%8], in[blockSize:], &tmp0) // E(1,i)
		xorBytes1x16(in[:], tmp0[:], out[:])
		r.AES4(&zero, &e.I[0], &e.L[0], out[:], &tmp0) // E(0,0)
		xorBytes1x16(in[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out[blockSize:], X[:], X[:])
	}

	memwipe(tmp0[:])
	memwipe(tmp1[:])
	memwipe(I[:])
}

func (r *roundB32) aezCorePass2(e *eState, out []byte, Y, S *[blockSize]byte, sz int) {
	var tmp0, tmp1, I [blockSize]byte

	copy(I[:], e.I[1][:])
	i := 1

	// Process 4 * 16 bytes at a time in a loop.
	for sz >= 4*blockSize {
		r.aes4x2(&e.J[1], &I, &e.L[(i+0)%8], S[:], &tmp0,
			&e.J[1], &I, &e.L[(i+1)%8], S[:], &tmp1) // E(2,i)
		xorBytes1x16(out, tmp0[:], out[:])
		xorBytes1x16(out[blockSize*2:], tmp1[:], out[blockSize*2:])
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out[blockSize*3:], tmp1[:], out[blockSize*3:])
		xorBytes1x16(out, Y[:], Y[:])
		xorBytes1x16(out[blockSize*2:], Y[:], Y[:])

		r.aes4x2(&zero, &e.I[0], &e.L[0], out[blockSize:], &tmp0,
			&zero, &e.I[0], &e.L[0], out[blockSize*3:], &tmp1) // E(0,0)
		xorBytes1x16(out, tmp0[:], out[:])
		xorBytes1x16(out[blockSize*2:], tmp1[:], out[blockSize*2:])

		r.aes4x2(&e.J[0], &I, &e.L[(i+0)%8], out[:], &tmp0,
			&e.J[0], &I, &e.L[(i+1)%8], out[blockSize*2:], &tmp1) // E(1,i)
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out[blockSize*3:], tmp1[:], out[blockSize*3:])

		swapBlocks(&tmp0, out)
		swapBlocks(&tmp0, out[blockSize*2:])

		sz -= 4 * blockSize
		out = out[64:]
		if (i+1)%8 == 0 {
			doubleBlock(&I)
		}
		i += 2
	}
	if sz > 0 {
		r.AES4(&e.J[1], &I, &e.L[i%8], S[:], &tmp0) // E(2,i)
		xorBytes1x16(out, tmp0[:], out[:])
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])
		xorBytes1x16(out, Y[:], Y[:])

		r.AES4(&zero, &e.I[0], &e.L[0], out[blockSize:], &tmp0) // E(0,0)
		xorBytes1x16(out, tmp0[:], out[:])

		r.AES4(&e.J[0], &I, &e.L[i%8], out[:], &tmp0) // E(1,i)
		xorBytes1x16(out[blockSize:], tmp0[:], out[blockSize:])

		swapBlocks(&tmp0, out)
	}

	memwipe(tmp0[:])
	memwipe(tmp1[:])
	memwipe(I[:])
}

func memwipeU32(b []uint32) {
	for i := range b {
		b[i] = 0
	}
}
