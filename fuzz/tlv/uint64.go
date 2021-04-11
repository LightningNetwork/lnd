// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_uint64 is used by go-fuzz.
func Fuzz_uint64(data []byte) int {
	if len(data) > 8 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  uint64
		val2 uint64
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DUint64(r, &val, &buf, 8); err != nil {
		return 1
	}

	if err := tlv.EUint64(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DUint64(r2, &val2, &buf, 8); err != nil {
		return 1
	}

	if val != val2 {
		panic("values not equal")
	}

	return 1
}
