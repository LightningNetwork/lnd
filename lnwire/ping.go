package lnwire

import (
	"bytes"
	"io"
)

// PingPayload is a set of opaque bytes used to pad out a ping message.
type PingPayload []byte

// Ping defines a message which is sent by peers periodically to determine if
// the connection is still valid. Each ping message carries the number of bytes
// to pad the pong response with, and also a number of bytes to be ignored at
// the end of the ping message (which is padding).
type Ping struct {
	// NumPongBytes is the number of bytes the pong response to this
	// message should carry.
	NumPongBytes uint16

	// PaddingBytes is a set of opaque bytes used to pad out this ping
	// message. Using this field in conjunction to the one above, it's
	// possible for node to generate fake cover traffic.
	PaddingBytes PingPayload
}

// NewPing returns a new Ping message.
func NewPing(numBytes uint16) *Ping {
	return &Ping{
		NumPongBytes: numBytes,
	}
}

// A compile time check to ensure Ping implements the lnwire.Message interface.
var _ Message = (*Ping)(nil)

// Decode deserializes a serialized Ping message stored in the passed io.Reader
// observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (p *Ping) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&p.NumPongBytes,
		&p.PaddingBytes)
}

// Encode serializes the target Ping into the passed io.Writer observing the
// protocol version specified.
//
// This is part of the lnwire.Message interface.
func (p *Ping) Encode(w *bytes.Buffer, pver uint32) error {
	return WriteElements(w,
		p.NumPongBytes,
		p.PaddingBytes)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (p *Ping) MsgType() MessageType {
	return MsgPing
}
