// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_varint is used by go-fuzz.
func Fuzz_varint(data []byte) int {
	r := bytes.NewReader(data)

	var (
		val  uint64
		val2 uint64
		err  error
		buf  [8]byte
		b    bytes.Buffer
	)

	val, err = tlv.ReadVarInt(r, &buf)
	if err != nil {
		return 1
	}

	if err := tlv.WriteVarInt(&b, val, &buf); err != nil {
		return 1
	}

	// A byte comparison isn't performed here since ReadVarInt doesn't read
	// all of the bytes from data and so b.Bytes() won't be equal to data.

	r2 := bytes.NewReader(b.Bytes())

	val2, err = tlv.ReadVarInt(r2, &buf)
	if err != nil {
		return 1
	}

	if val != val2 {
		panic("values not equal")
	}

	return 1
}
