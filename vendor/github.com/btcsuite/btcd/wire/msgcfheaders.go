// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	// MaxCFHeaderPayload is the maximum byte size of a committed
	// filter header.
	MaxCFHeaderPayload = chainhash.HashSize

	// MaxCFHeadersPerMsg is the maximum number of committed filter headers
	// that can be in a single bitcoin cfheaders message.
	MaxCFHeadersPerMsg = 2000
)

// MsgCFHeaders implements the Message interface and represents a bitcoin
// cfheaders message.  It is used to deliver committed filter header information
// in response to a getcfheaders message (MsgGetCFHeaders). The maximum number
// of committed filter headers per message is currently 2000. See
// MsgGetCFHeaders for details on requesting the headers.
type MsgCFHeaders struct {
	FilterType       FilterType
	StopHash         chainhash.Hash
	PrevFilterHeader chainhash.Hash
	FilterHashes     []*chainhash.Hash
}

// AddCFHash adds a new filter hash to the message.
func (msg *MsgCFHeaders) AddCFHash(hash *chainhash.Hash) error {
	if len(msg.FilterHashes)+1 > MaxCFHeadersPerMsg {
		str := fmt.Sprintf("too many block headers in message [max %v]",
			MaxBlockHeadersPerMsg)
		return messageError("MsgCFHeaders.AddCFHash", str)
	}

	msg.FilterHashes = append(msg.FilterHashes, hash)
	return nil
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgCFHeaders) BtcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.FilterType)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, &msg.StopHash)
	if err != nil {
		return err
	}

	// Read prev filter header
	err = readElement(r, &msg.PrevFilterHeader)
	if err != nil {
		return err
	}

	// Read number of filter headers
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Limit to max committed filter headers per message.
	if count > MaxCFHeadersPerMsg {
		str := fmt.Sprintf("too many committed filter headers for "+
			"message [count %v, max %v]", count,
			MaxBlockHeadersPerMsg)
		return messageError("MsgCFHeaders.BtcDecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into in order to
	// reduce the number of allocations.
	msg.FilterHashes = make([]*chainhash.Hash, 0, count)
	for i := uint64(0); i < count; i++ {
		var cfh chainhash.Hash
		err := readElement(r, &cfh)
		if err != nil {
			return err
		}
		msg.AddCFHash(&cfh)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgCFHeaders) BtcEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.FilterType)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.StopHash)
	if err != nil {
		return err
	}

	// Write prev filter header
	err = writeElement(w, msg.PrevFilterHeader)
	if err != nil {
		return err
	}

	// Limit to max committed headers per message.
	count := len(msg.FilterHashes)
	if count > MaxCFHeadersPerMsg {
		str := fmt.Sprintf("too many committed filter headers for "+
			"message [count %v, max %v]", count,
			MaxBlockHeadersPerMsg)
		return messageError("MsgCFHeaders.BtcEncode", str)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, cfh := range msg.FilterHashes {
		err := writeElement(w, cfh)
		if err != nil {
			return err
		}
	}

	return nil
}

// Deserialize decodes a filter header from r into the receiver using a format
// that is suitable for long-term storage such as a database. This function
// differs from BtcDecode in that BtcDecode decodes from the bitcoin wire
// protocol as it was sent across the network.  The wire encoding can
// technically differ depending on the protocol version and doesn't even really
// need to match the format of a stored filter header at all. As of the time
// this comment was written, the encoded filter header is the same in both
// instances, but there is a distinct difference and separating the two allows
// the API to be flexible enough to deal with changes.
func (msg *MsgCFHeaders) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// and the stable long-term storage format.  As a result, make use of
	// BtcDecode.
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgCFHeaders) Command() string {
	return CmdCFHeaders
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgCFHeaders) MaxPayloadLength(pver uint32) uint32 {
	// Hash size + filter type + num headers (varInt) +
	// (header size * max headers).
	return 1 + chainhash.HashSize + chainhash.HashSize + MaxVarIntPayload +
		(MaxCFHeaderPayload * MaxCFHeadersPerMsg)
}

// NewMsgCFHeaders returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFHeaders for details.
func NewMsgCFHeaders() *MsgCFHeaders {
	return &MsgCFHeaders{
		FilterHashes: make([]*chainhash.Hash, 0, MaxCFHeadersPerMsg),
	}
}
