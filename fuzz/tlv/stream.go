// +build gofuzz

package tlvfuzz

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_stream is used by go-fuzz.
func Fuzz_stream(data []byte) int {
	var (
		val  uint8
		val2 uint16
		val3 uint32
		val4 uint64
		val5 [32]byte
		val6 [33]byte
		val7 *btcec.PublicKey
		val8 [64]byte
		val9 []byte

		b bytes.Buffer
	)

	stream := tlv.MustNewStream(
		tlv.MakePrimitiveRecord(1, &val),
		tlv.MakePrimitiveRecord(2, &val2),
		tlv.MakePrimitiveRecord(3, &val3),
		tlv.MakePrimitiveRecord(4, &val4),
		tlv.MakePrimitiveRecord(5, &val5),
		tlv.MakePrimitiveRecord(6, &val6),
		tlv.MakePrimitiveRecord(7, &val7),
		tlv.MakePrimitiveRecord(8, &val8),
		tlv.MakePrimitiveRecord(9, &val9),
	)

	r := bytes.NewReader(data)

	if err := stream.Decode(r); err != nil {
		return 1
	}

	if err := stream.Encode(&b); err != nil {
		return 1
	}

	return 1
}
