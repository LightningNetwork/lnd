// Copyright (c) 2014-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgFilterClear implements the Message interface and represents a bitcoin
// filterclear message which is used to reset a Bloom filter.
//
// This message was not added until protocol version BIP0037Version and has
// no payload.
type MsgFilterClear struct{}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgFilterClear) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterclear message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterClear.BtcDecode", str)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgFilterClear) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterclear message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterClear.BtcEncode", str)
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgFilterClear) Command() string {
	return CmdFilterClear
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgFilterClear) MaxPayloadLength(pver uint32) uint32 {
	return 0
}

// NewMsgFilterClear returns a new bitcoin filterclear message that conforms to the Message
// interface.  See MsgFilterClear for details.
func NewMsgFilterClear() *MsgFilterClear {
	return &MsgFilterClear{}
}
