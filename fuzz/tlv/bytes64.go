// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_bytes64 is used by go-fuzz.
func Fuzz_bytes64(data []byte) int {
	if len(data) > 64 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  [64]byte
		val2 [64]byte
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DBytes64(r, &val, &buf, 64); err != nil {
		return 1
	}

	if err := tlv.EBytes64(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DBytes64(r2, &val2, &buf, 64); err != nil {
		return 1
	}

	if !bytes.Equal(val[:], val2[:]) {
		panic("values not equal")
	}

	return 1
}
