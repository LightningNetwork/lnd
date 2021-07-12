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

package modes

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"git.schwanenlied.me/yawning/bsaes.git/ghash"
)

const (
	gcmNonceSize = 96 / 8
	gcmTagSize   = 16
)

func (m *BlockModesImpl) NewGCM(size int) (cipher.AEAD, error) {
	ecb := m.b.(bulkECBAble)
	if ecb.BlockSize() != blockSize {
		return nil, errors.New("bsaes/NewGCM: GCM requires 128 bit block sizes")
	}

	return newGCMImpl(ecb, size), nil
}

type gcmImpl struct {
	ecb bulkECBAble

	nonceSize int
	stride    int
}

func (g *gcmImpl) NonceSize() int {
	return g.nonceSize
}

func (g *gcmImpl) Overhead() int {
	return gcmTagSize
}

func (g *gcmImpl) deriveNonceVals(h, j, preCounterBlock *[blockSize]byte, nonce []byte) {
	g.ecb.Encrypt(h[:], h[:])
	if len(nonce) == gcmNonceSize {
		copy(j[:], nonce[:gcmNonceSize])
		j[blockSize-1] = 1
	} else {
		var p [blockSize]byte
		ghash.Ghash(j, h, nonce)
		binary.BigEndian.PutUint32(p[12:], uint32(len(nonce))<<3)
		ghash.Ghash(j, h, p[:])
	}
	g.ecb.Encrypt(preCounterBlock[:], j[:])
}

func (g *gcmImpl) gctr(iv *[blockSize]byte, dst, src []byte) {
	idx := g.stride * blockSize
	buf := make([]byte, g.stride*blockSize)
	inc32(iv)

	for len(src) > 0 {
		if idx >= len(buf) {
			for i := 0; i < g.stride; i++ {
				copy(buf[i*blockSize:], iv[:])
				inc32(iv)
			}
			g.ecb.BulkEncrypt(buf, buf)
			idx = 0
		}

		n := len(buf) - idx
		if sLen := len(src); sLen < n {
			n = sLen
		}
		for i, v := range src[:n] {
			dst[i] = v ^ buf[idx+i]
		}

		dst, src = dst[n:], src[n:]
		idx += n
	}

	for i := range buf {
		buf[i] = 0
	}
}

func (g *gcmImpl) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("bsaes/gcmImpl.Seal: nonce with invalid size provided")
	}

	// Yes, this always allocates.  It makes life easier.
	sz := len(plaintext)
	if uint64(sz) > 0xfffffffe0 { // len(P) <= 2^39 - 256 (bits)
		panic("bsaes/gcmImpl.Seal: plaintext too large")
	}
	out := make([]byte, sz+gcmTagSize)

	// Define H, block J0, and the pre-counter block.
	var h, j, preCounterBlock [blockSize]byte
	g.deriveNonceVals(&h, &j, &preCounterBlock, nonce)

	// Let C=GCTR K(inc32(J0), P).
	g.gctr(&j, out, plaintext)

	// S = GHASH H (A || 0 v || C || 0 u || [len(A)] 64 || [len(C)] 64).
	var s, p [blockSize]byte
	ghash.Ghash(&s, &h, additionalData)
	ghash.Ghash(&s, &h, out[:sz])
	binary.BigEndian.PutUint32(p[4:], uint32(len(additionalData))<<3)
	binary.BigEndian.PutUint32(p[12:], uint32(sz)<<3)
	ghash.Ghash(&s, &h, p[:])

	// Let T = MSB t(GCTR K(J0, S))
	for i, v := range preCounterBlock {
		out[sz+i] = s[i] ^ v
	}

	dst = append(dst, out...)
	return dst
}

var errFail = errors.New("cipher: message authentication failed")

func (g *gcmImpl) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("bsaes/gcmImpl.Seal: nonce with invalid size provided")
	}

	sz := len(ciphertext)
	if sz < gcmTagSize {
		return nil, errFail
	}
	sz -= gcmTagSize
	if uint64(sz) > 0xfffffffe0 {
		return nil, errFail
	}

	// Define H, block J0, and the pre-counter block.
	var h, j, preCounterBlock [blockSize]byte
	g.deriveNonceVals(&h, &j, &preCounterBlock, nonce)

	// S = GHASH H (A || 0 v || C || 0 u || [len(A)] 64 || [len(C)] 64).
	var s, p [blockSize]byte
	ghash.Ghash(&s, &h, additionalData)
	ghash.Ghash(&s, &h, ciphertext[:sz])
	binary.BigEndian.PutUint32(p[4:], uint32(len(additionalData))<<3)
	binary.BigEndian.PutUint32(p[12:], uint32(sz)<<3)
	ghash.Ghash(&s, &h, p[:])
	for i, v := range preCounterBlock {
		s[i] ^= v
	}

	if subtle.ConstantTimeCompare(s[:], ciphertext[sz:]) != 1 {
		return nil, errFail
	}

	out := make([]byte, sz)
	g.gctr(&j, out, ciphertext[:sz])
	dst = append(dst, out...)

	return dst, nil
}

func inc32(ctr *[blockSize]byte) {
	v := binary.BigEndian.Uint32(ctr[12:]) + 1
	binary.BigEndian.PutUint32(ctr[12:], v)
}

func newGCMImpl(ecb bulkECBAble, size int) cipher.AEAD {
	g := new(gcmImpl)
	g.ecb = ecb
	g.nonceSize = size
	g.stride = g.ecb.Stride()
	return g
}
