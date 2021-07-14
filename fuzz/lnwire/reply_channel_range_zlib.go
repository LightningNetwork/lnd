// +build gofuzz

package lnwirefuzz

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"

	"github.com/lightningnetwork/lnd/lnwire"
)

// Fuzz_reply_channel_range_zlib is used by go-fuzz.
func Fuzz_reply_channel_range_zlib(data []byte) int {

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

	// Initialize some []byte vars which will prefix our payload
	chainhash := []byte("00000000000000000000000000000000")
	firstBlockHeight := []byte("\x00\x00\x00\x00")
	numBlocks := []byte("\x00\x00\x00\x00")
	completeByte := []byte("\x00")

	numBytesInBody := len(compressedPayload) + 1
	zlibByte := []byte("\x01")

	bodyBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bodyBytes, uint16(numBytesInBody))

	payload := append(chainhash, firstBlockHeight...)
	payload = append(payload, numBlocks...)
	payload = append(payload, completeByte...)
	payload = append(payload, bodyBytes...)
	payload = append(payload, zlibByte...)
	payload = append(payload, compressedPayload...)

	// Prefix with MsgReplyChannelRange.
	payload = prefixWithMsgType(payload, lnwire.MsgReplyChannelRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(payload)
}
