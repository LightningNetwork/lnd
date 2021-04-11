// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_uint8 is used by go-fuzz.
func Fuzz_uint8(data []byte) int {
	if len(data) > 1 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  uint8
		val2 uint8
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DUint8(r, &val, &buf, 1); err != nil {
		return 1
	}

	if err := tlv.EUint8(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DUint8(r2, &val2, &buf, 1); err != nil {
		return 1
	}

	if val != val2 {
		panic("values not equal")
	}

	return 1
}
