// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_uint16 is used by go-fuzz.
func Fuzz_uint16(data []byte) int {
	if len(data) > 2 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  uint16
		val2 uint16
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DUint16(r, &val, &buf, 2); err != nil {
		return 1
	}

	if err := tlv.EUint16(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DUint16(r2, &val2, &buf, 2); err != nil {
		return 1
	}

	if val != val2 {
		panic("values not equal")
	}

	return 1
}
