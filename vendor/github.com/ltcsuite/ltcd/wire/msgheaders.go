// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MaxBlockHeadersPerMsg is the maximum number of block headers that can be in
// a single bitcoin headers message.
const MaxBlockHeadersPerMsg = 2000

// MsgHeaders implements the Message interface and represents a bitcoin headers
// message.  It is used to deliver block header information in response
// to a getheaders message (MsgGetHeaders).  The maximum number of block headers
// per message is currently 2000.  See MsgGetHeaders for details on requesting
// the headers.
type MsgHeaders struct {
	Headers []*BlockHeader
}

// AddBlockHeader adds a new block header to the message.
func (msg *MsgHeaders) AddBlockHeader(bh *BlockHeader) error {
	if len(msg.Headers)+1 > MaxBlockHeadersPerMsg {
		str := fmt.Sprintf("too many block headers in message [max %v]",
			MaxBlockHeadersPerMsg)
		return messageError("MsgHeaders.AddBlockHeader", str)
	}

	msg.Headers = append(msg.Headers, bh)
	return nil
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgHeaders) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Limit to max block headers per message.
	if count > MaxBlockHeadersPerMsg {
		str := fmt.Sprintf("too many block headers for message "+
			"[count %v, max %v]", count, MaxBlockHeadersPerMsg)
		return messageError("MsgHeaders.BtcDecode", str)
	}

	// Create a contiguous slice of headers to deserialize into in order to
	// reduce the number of allocations.
	headers := make([]BlockHeader, count)
	msg.Headers = make([]*BlockHeader, 0, count)
	for i := uint64(0); i < count; i++ {
		bh := &headers[i]
		err := readBlockHeader(r, pver, bh)
		if err != nil {
			return err
		}

		txCount, err := ReadVarInt(r, pver)
		if err != nil {
			return err
		}

		// Ensure the transaction count is zero for headers.
		if txCount > 0 {
			str := fmt.Sprintf("block headers may not contain "+
				"transactions [count %v]", txCount)
			return messageError("MsgHeaders.BtcDecode", str)
		}
		msg.AddBlockHeader(bh)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgHeaders) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Limit to max block headers per message.
	count := len(msg.Headers)
	if count > MaxBlockHeadersPerMsg {
		str := fmt.Sprintf("too many block headers for message "+
			"[count %v, max %v]", count, MaxBlockHeadersPerMsg)
		return messageError("MsgHeaders.BtcEncode", str)
	}

	err := WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, bh := range msg.Headers {
		err := writeBlockHeader(w, pver, bh)
		if err != nil {
			return err
		}

		// The wire protocol encoding always includes a 0 for the number
		// of transactions on header messages.  This is really just an
		// artifact of the way the original implementation serializes
		// block headers, but it is required.
		err = WriteVarInt(w, pver, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgHeaders) Command() string {
	return CmdHeaders
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgHeaders) MaxPayloadLength(pver uint32) uint32 {
	// Num headers (varInt) + max allowed headers (header length + 1 byte
	// for the number of transactions which is always 0).
	return MaxVarIntPayload + ((MaxBlockHeaderPayload + 1) *
		MaxBlockHeadersPerMsg)
}

// NewMsgHeaders returns a new bitcoin headers message that conforms to the
// Message interface.  See MsgHeaders for details.
func NewMsgHeaders() *MsgHeaders {
	return &MsgHeaders{
		Headers: make([]*BlockHeader, 0, MaxBlockHeadersPerMsg),
	}
}
