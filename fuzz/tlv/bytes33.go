// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_bytes33 is used by go-fuzz.
func Fuzz_bytes33(data []byte) int {
	if len(data) > 33 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  [33]byte
		val2 [33]byte
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DBytes33(r, &val, &buf, 33); err != nil {
		return 1
	}

	if err := tlv.EBytes33(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DBytes33(r2, &val2, &buf, 33); err != nil {
		return 1
	}

	if !bytes.Equal(val[:], val2[:]) {
		panic("values not equal")
	}

	return 1
}
