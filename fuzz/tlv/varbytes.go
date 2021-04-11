// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_varbytes is used by go-fuzz.
func Fuzz_varbytes(data []byte) int {
	l := len(data)

	r := bytes.NewReader(data)

	var (
		val  []byte
		val2 []byte
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DVarBytes(r, &val, &buf, uint64(l)); err != nil {
		return 1
	}

	if err := tlv.EVarBytes(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())
	l2 := len(b.Bytes())

	if err := tlv.DVarBytes(r2, &val2, &buf, uint64(l2)); err != nil {
		return 1
	}

	if !bytes.Equal(val, val2) {
		panic("values not equal")
	}

	return 1
}
