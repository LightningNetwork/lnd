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

import "crypto/cipher"

const blockSize = 16 // Always AES.

type bulkECBAble interface {
	cipher.Block

	// Stride returns the number of BlockSize-ed blocks that should be passed
	// to BulkEncrypt.
	Stride() int

	// Reset clears the block cipher state such that key material no longer
	// appears in process memory.
	Reset()

	// Encrypt encrypts the Stride blocks of plaintext src, and places the
	// resulting output in the ciphertext dst.
	BulkEncrypt(dst, src []byte)

	// BulkECBDecrypt decrypts the Stride blocks of plaintext src,
	// and places the resulting output in the ciphertext dst.
	BulkDecrypt(dst, src []byte)
}

// BlockModesImpl is a collection of unexported `crypto/cipher` block cipher
// mode special case implementations.
type BlockModesImpl struct {
	b cipher.Block
}

func (m *BlockModesImpl) Init(b cipher.Block) {
	m.b = b
}
