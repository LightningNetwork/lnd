// +build gofuzz

package lnwirefuzz

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"

	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_query_short_chan_ids_zlib is used by go-fuzz.
func Fuzz_query_short_chan_ids_zlib(data []byte) int {

	var buf bytes.Buffer
	zlibWriter := zlib.NewWriter(&buf)
	_, err := zlibWriter.Write(data)
	if err != nil {
		// Zlib bug?
		panic(err)
	}

	if err := zlibWriter.Close(); err != nil {
		// Zlib bug?
		panic(err)
	}

	compressedPayload := buf.Bytes()

	chainhash := []byte("00000000000000000000000000000000")
	numBytesInBody := len(compressedPayload) + 1
	zlibByte := []byte("\x01")

	bodyBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bodyBytes, uint16(numBytesInBody))

	payload := append(chainhash, bodyBytes...)
	payload = append(payload, zlibByte...)
	payload = append(payload, compressedPayload...)

	// Prefix with MsgQueryShortChanIDs.
	payload = prefixWithMsgType(payload, lnwire.MsgQueryShortChanIDs)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(payload)
}
