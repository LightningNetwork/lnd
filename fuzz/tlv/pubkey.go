// +build gofuzz

package tlvfuzz

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/tlv"
)

// Fuzz_pubkey is used by go-fuzz.
func Fuzz_pubkey(data []byte) int {
	if len(data) > 33 {
		return 1
	}

	r := bytes.NewReader(data)

	var (
		val  *btcec.PublicKey
		val2 *btcec.PublicKey
		buf  [8]byte
		b    bytes.Buffer
	)

	if err := tlv.DPubKey(r, &val, &buf, 33); err != nil {
		return 1
	}

	if err := tlv.EPubKey(&b, &val, &buf); err != nil {
		return 1
	}

	if !bytes.Equal(b.Bytes(), data) {
		panic("bytes not equal")
	}

	r2 := bytes.NewReader(b.Bytes())

	if err := tlv.DPubKey(r2, &val2, &buf, 33); err != nil {
		return 1
	}

	if !val.IsEqual(val2) {
		panic("values not equal")
	}

	return 1
}
