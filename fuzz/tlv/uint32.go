// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_uint32 is used by go-fuzz.
func Fuzz_uint32(data []byte) int {
	if len(data) > 4 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  uint32
		val2 uint32
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DUint32(r, &val, &buf, 4); err != nil {
		return 1
	}

	if err := tlv.EUint32(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DUint32(r2, &val2, &buf, 4); err != nil {
		return 1
	}

	if val != val2 {
		panic("values not equal")
	}

	return 1
}
