package lnwire

import (
	"bytes"
	"errors"
	"io"
)

// CustomTypeStart is the start of the custom type range for peer messages as
// defined in BOLT 01.
var CustomTypeStart MessageType = 32768

// Custom represents an application-defined wire message.
type Custom struct {
	Type MessageType
	Data []byte
}

// A compile time check to ensure FundingCreated implements the lnwire.Message
// interface.
var _ Message = (*Custom)(nil)

// NewCustom instanties a new custom message.
func NewCustom(msgType MessageType, data []byte) (*Custom, error) {
	if msgType < CustomTypeStart {
		return nil, errors.New("msg type not in custom range")
	}

	return &Custom{
		Type: msgType,
		Data: data,
	}, nil
}

// Encode serializes the target Custom message into the passed io.Writer
// implementation.
//
// This is part of the lnwire.Message interface.
func (c *Custom) Encode(w io.Writer, pver uint32) error {
	_, err := w.Write(c.Data)
	return err
}

// Decode deserializes the serialized Custom message stored in the passed
// io.Reader into the target Custom message.
//
// This is part of the lnwire.Message interface.
func (c *Custom) Decode(r io.Reader, pver uint32) error {
	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return err
	}

	c.Data = b.Bytes()

	return nil
}

// MsgType returns the uint32 code which uniquely identifies this message as a
// Custom message on the wire.
//
// This is part of the lnwire.Message interface.
func (c *Custom) MsgType() MessageType {
	return c.Type
}
