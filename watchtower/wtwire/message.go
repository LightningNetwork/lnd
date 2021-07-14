package wtwire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// MaxMessagePayload is the maximum bytes a message can be regardless of other
// individual limits imposed by messages themselves.
const MaxMessagePayload = 65535 // 65KB

// MessageType is the unique 2 byte big-endian integer that indicates the type
// of message on the wire. All messages have a very simple header which
// consists simply of 2-byte message type. We omit a length field, and checksum
// as the Watchtower Protocol is intended to be encapsulated within a
// confidential+authenticated cryptographic messaging protocol.
type MessageType uint16

// The currently defined message types within this current version of the
// Watchtower protocol.
const (
	// MsgInit identifies an encoded Init message.
	MsgInit MessageType = 600

	// MsgError identifies an encoded Error message.
	MsgError MessageType = 601

	// MsgCreateSession identifies an encoded CreateSession message.
	MsgCreateSession MessageType = 602

	// MsgCreateSessionReply identifies an encoded CreateSessionReply message.
	MsgCreateSessionReply MessageType = 603

	// MsgStateUpdate identifies an encoded StateUpdate message.
	MsgStateUpdate MessageType = 604

	// MsgStateUpdateReply identifies an encoded StateUpdateReply message.
	MsgStateUpdateReply MessageType = 605

	// MsgDeleteSession identifies an encoded DeleteSession message.
	MsgDeleteSession MessageType = 606

	// MsgDeleteSessionReply identifies an encoded DeleteSessionReply
	// message.
	MsgDeleteSessionReply MessageType = 607
)

// String returns a human readable description of the message type.
func (m MessageType) String() string {
	switch m {
	case MsgInit:
		return "Init"
	case MsgCreateSession:
		return "MsgCreateSession"
	case MsgCreateSessionReply:
		return "MsgCreateSessionReply"
	case MsgStateUpdate:
		return "MsgStateUpdate"
	case MsgStateUpdateReply:
		return "MsgStateUpdateReply"
	case MsgDeleteSession:
		return "MsgDeleteSession"
	case MsgDeleteSessionReply:
		return "MsgDeleteSessionReply"
	case MsgError:
		return "Error"
	default:
		return "<unknown>"
	}
}

// Serializable is an interface which defines a lightning wire serializable
// object.
type Serializable interface {
	// Decode reads the bytes stream and converts it to the object.
	Decode(io.Reader, uint32) error

	// Encode converts object to the bytes stream and write it into the
	// write buffer.
	Encode(io.Writer, uint32) error
}

// Message is an interface that defines a lightning wire protocol message. The
// interface is general in order to allow implementing types full control over
// the representation of its data.
type Message interface {
	Serializable

	// MsgType returns a MessageType that uniquely identifies the message to
	// be encoded.
	MsgType() MessageType

	// MaxMessagePayload is the maximum serialized length that a particular
	// message type can take.
	MaxPayloadLength(uint32) uint32
}

// makeEmptyMessage creates a new empty message of the proper concrete type
// based on the passed message type.
func makeEmptyMessage(msgType MessageType) (Message, error) {
	var msg Message

	switch msgType {
	case MsgInit:
		msg = &Init{}
	case MsgCreateSession:
		msg = &CreateSession{}
	case MsgCreateSessionReply:
		msg = &CreateSessionReply{}
	case MsgStateUpdate:
		msg = &StateUpdate{}
	case MsgStateUpdateReply:
		msg = &StateUpdateReply{}
	case MsgDeleteSession:
		msg = &DeleteSession{}
	case MsgDeleteSessionReply:
		msg = &DeleteSessionReply{}
	case MsgError:
		msg = &Error{}
	default:
		return nil, fmt.Errorf("unknown message type [%d]", msgType)
	}

	return msg, nil
}

// WriteMessage writes a lightning Message to w including the necessary header
// information and returns the number of bytes written.
func WriteMessage(w io.Writer, msg Message, pver uint32) (int, error) {
	totalBytes := 0

	// Encode the message payload itself into a temporary buffer.
	// TODO(roasbeef): create buffer pool
	var bw bytes.Buffer
	if err := msg.Encode(&bw, pver); err != nil {
		return totalBytes, err
	}
	payload := bw.Bytes()
	lenp := len(payload)

	// Enforce maximum overall message payload.
	if lenp > MaxMessagePayload {
		return totalBytes, fmt.Errorf("message payload is too large - "+
			"encoded %d bytes, but maximum message payload is %d bytes",
			lenp, MaxMessagePayload)
	}

	// Enforce maximum message payload on the message type.
	mpl := msg.MaxPayloadLength(pver)
	if uint32(lenp) > mpl {
		return totalBytes, fmt.Errorf("message payload is too large - "+
			"encoded %d bytes, but maximum message payload of "+
			"type %v is %d bytes", lenp, msg.MsgType(), mpl)
	}

	// With the initial sanity checks complete, we'll now write out the
	// message type itself.
	var mType [2]byte
	binary.BigEndian.PutUint16(mType[:], uint16(msg.MsgType()))
	n, err := w.Write(mType[:])
	totalBytes += n
	if err != nil {
		return totalBytes, err
	}

	// With the message type written, we'll now write out the raw payload
	// itself.
	n, err = w.Write(payload)
	totalBytes += n

	return totalBytes, err
}

// ReadMessage reads, validates, and parses the next Watchtower message from r
// for the provided protocol version.
func ReadMessage(r io.Reader, pver uint32) (Message, error) {
	// First, we'll read out the first two bytes of the message so we can
	// create the proper empty message.
	var mType [2]byte
	if _, err := io.ReadFull(r, mType[:]); err != nil {
		return nil, err
	}

	msgType := MessageType(binary.BigEndian.Uint16(mType[:]))

	// Now that we know the target message type, we can create the proper
	// empty message type and decode the message into it.
	msg, err := makeEmptyMessage(msgType)
	if err != nil {
		return nil, err
	}
	if err := msg.Decode(r, pver); err != nil {
		return nil, err
	}

	return msg, nil
}
