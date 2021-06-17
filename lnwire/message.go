// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// code derived from https://github .com/btcsuite/btcd/blob/master/wire/message.go
// Copyright (C) 2015-2017 The Lightning Network Developers

package lnwire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// MessageType is the unique 2 byte big-endian integer that indicates the type
// of message on the wire. All messages have a very simple header which
// consists simply of 2-byte message type. We omit a length field, and checksum
// as the Lightning Protocol is intended to be encapsulated within a
// confidential+authenticated cryptographic messaging protocol.
type MessageType uint16

// The currently defined message types within this current version of the
// Lightning protocol.
const (
	MsgInit                    MessageType = 16
	MsgError                               = 17
	MsgPing                                = 18
	MsgPong                                = 19
	MsgOpenChannel                         = 32
	MsgAcceptChannel                       = 33
	MsgFundingCreated                      = 34
	MsgFundingSigned                       = 35
	MsgFundingLocked                       = 36
	MsgShutdown                            = 38
	MsgClosingSigned                       = 39
	MsgUpdateAddHTLC                       = 128
	MsgUpdateFulfillHTLC                   = 130
	MsgUpdateFailHTLC                      = 131
	MsgCommitSig                           = 132
	MsgRevokeAndAck                        = 133
	MsgUpdateFee                           = 134
	MsgUpdateFailMalformedHTLC             = 135
	MsgChannelReestablish                  = 136
	MsgChannelAnnouncement                 = 256
	MsgNodeAnnouncement                    = 257
	MsgChannelUpdate                       = 258
	MsgAnnounceSignatures                  = 259
	MsgQueryShortChanIDs                   = 261
	MsgReplyShortChanIDsEnd                = 262
	MsgQueryChannelRange                   = 263
	MsgReplyChannelRange                   = 264
	MsgGossipTimestampRange                = 265
)

// ErrorEncodeMessage is used when failed to encode the message payload.
func ErrorEncodeMessage(err error) error {
	return fmt.Errorf("failed to encode message to buffer, got %w", err)
}

// ErrorWriteMessageType is used when failed to write the message type.
func ErrorWriteMessageType(err error) error {
	return fmt.Errorf("failed to write message type, got %w", err)
}

// ErrorPayloadTooLarge is used when the payload size exceeds the
// MaxMsgBody.
func ErrorPayloadTooLarge(size int) error {
	return fmt.Errorf(
		"message payload is too large - encoded %d bytes, "+
			"but maximum message payload is %d bytes",
		size, MaxMsgBody,
	)

}

// String return the string representation of message type.
func (t MessageType) String() string {
	switch t {
	case MsgInit:
		return "Init"
	case MsgOpenChannel:
		return "MsgOpenChannel"
	case MsgAcceptChannel:
		return "MsgAcceptChannel"
	case MsgFundingCreated:
		return "MsgFundingCreated"
	case MsgFundingSigned:
		return "MsgFundingSigned"
	case MsgFundingLocked:
		return "FundingLocked"
	case MsgShutdown:
		return "Shutdown"
	case MsgClosingSigned:
		return "ClosingSigned"
	case MsgUpdateAddHTLC:
		return "UpdateAddHTLC"
	case MsgUpdateFailHTLC:
		return "UpdateFailHTLC"
	case MsgUpdateFulfillHTLC:
		return "UpdateFulfillHTLC"
	case MsgCommitSig:
		return "CommitSig"
	case MsgRevokeAndAck:
		return "RevokeAndAck"
	case MsgUpdateFailMalformedHTLC:
		return "UpdateFailMalformedHTLC"
	case MsgChannelReestablish:
		return "ChannelReestablish"
	case MsgError:
		return "Error"
	case MsgChannelAnnouncement:
		return "ChannelAnnouncement"
	case MsgChannelUpdate:
		return "ChannelUpdate"
	case MsgNodeAnnouncement:
		return "NodeAnnouncement"
	case MsgPing:
		return "Ping"
	case MsgAnnounceSignatures:
		return "AnnounceSignatures"
	case MsgPong:
		return "Pong"
	case MsgUpdateFee:
		return "UpdateFee"
	case MsgQueryShortChanIDs:
		return "QueryShortChanIDs"
	case MsgReplyShortChanIDsEnd:
		return "ReplyShortChanIDsEnd"
	case MsgQueryChannelRange:
		return "QueryChannelRange"
	case MsgReplyChannelRange:
		return "ReplyChannelRange"
	case MsgGossipTimestampRange:
		return "GossipTimestampRange"
	default:
		return "<unknown>"
	}
}

// UnknownMessage is an implementation of the error interface that allows the
// creation of an error in response to an unknown message.
type UnknownMessage struct {
	messageType MessageType
}

// Error returns a human readable string describing the error.
//
// This is part of the error interface.
func (u *UnknownMessage) Error() string {
	return fmt.Sprintf("unable to parse message of unknown type: %v",
		u.messageType)
}

// Serializable is an interface which defines a lightning wire serializable
// object.
type Serializable interface {
	// Decode reads the bytes stream and converts it to the object.
	Decode(io.Reader, uint32) error

	// Encode converts object to the bytes stream and write it into the
	// writer.
	Encode(io.Writer, uint32) error
}

// Message is an interface that defines a lightning wire protocol message. The
// interface is general in order to allow implementing types full control over
// the representation of its data.
type Message interface {
	Serializable
	MsgType() MessageType
}

// makeEmptyMessage creates a new empty message of the proper concrete type
// based on the passed message type.
func makeEmptyMessage(msgType MessageType) (Message, error) {
	var msg Message

	switch msgType {
	case MsgInit:
		msg = &Init{}
	case MsgOpenChannel:
		msg = &OpenChannel{}
	case MsgAcceptChannel:
		msg = &AcceptChannel{}
	case MsgFundingCreated:
		msg = &FundingCreated{}
	case MsgFundingSigned:
		msg = &FundingSigned{}
	case MsgFundingLocked:
		msg = &FundingLocked{}
	case MsgShutdown:
		msg = &Shutdown{}
	case MsgClosingSigned:
		msg = &ClosingSigned{}
	case MsgUpdateAddHTLC:
		msg = &UpdateAddHTLC{}
	case MsgUpdateFailHTLC:
		msg = &UpdateFailHTLC{}
	case MsgUpdateFulfillHTLC:
		msg = &UpdateFulfillHTLC{}
	case MsgCommitSig:
		msg = &CommitSig{}
	case MsgRevokeAndAck:
		msg = &RevokeAndAck{}
	case MsgUpdateFee:
		msg = &UpdateFee{}
	case MsgUpdateFailMalformedHTLC:
		msg = &UpdateFailMalformedHTLC{}
	case MsgChannelReestablish:
		msg = &ChannelReestablish{}
	case MsgError:
		msg = &Error{}
	case MsgChannelAnnouncement:
		msg = &ChannelAnnouncement{}
	case MsgChannelUpdate:
		msg = &ChannelUpdate{}
	case MsgNodeAnnouncement:
		msg = &NodeAnnouncement{}
	case MsgPing:
		msg = &Ping{}
	case MsgAnnounceSignatures:
		msg = &AnnounceSignatures{}
	case MsgPong:
		msg = &Pong{}
	case MsgQueryShortChanIDs:
		msg = &QueryShortChanIDs{}
	case MsgReplyShortChanIDsEnd:
		msg = &ReplyShortChanIDsEnd{}
	case MsgQueryChannelRange:
		msg = &QueryChannelRange{}
	case MsgReplyChannelRange:
		msg = &ReplyChannelRange{}
	case MsgGossipTimestampRange:
		msg = &GossipTimestampRange{}
	default:
		return nil, &UnknownMessage{msgType}
	}

	return msg, nil
}

// WriteMessage writes a lightning Message to a buffer including the necessary
// header information and returns the number of bytes written. If any error is
// encountered, the buffer passed will be reset to its original state since we
// don't want any broken bytes left. In other words, no bytes will be written
// if there's an error. Either all or none of the message bytes will be written
// to the buffer.
//
// NOTE: this method is not concurrent safe.
func WriteMessage(buf *bytes.Buffer, msg Message, pver uint32) (int, error) {
	// Record the size of the bytes already written in buffer.
	oldByteSize := buf.Len()

	// cleanBrokenBytes is a helper closure that helps reset the buffer to
	// its original state. It truncates all the bytes written in current
	// scope.
	var cleanBrokenBytes = func(b *bytes.Buffer) int {
		b.Truncate(oldByteSize)
		return 0
	}

	// Write the message type.
	var mType [2]byte
	binary.BigEndian.PutUint16(mType[:], uint16(msg.MsgType()))
	msgTypeBytes, err := buf.Write(mType[:])
	if err != nil {
		return cleanBrokenBytes(buf), ErrorWriteMessageType(err)
	}

	// Use the write buffer to encode our message.
	if err := msg.Encode(buf, pver); err != nil {
		return cleanBrokenBytes(buf), ErrorEncodeMessage(err)
	}

	// Enforce maximum overall message payload. The write buffer now has
	// the size of len(originalBytes) + len(payload) + len(type). We want
	// to enforce the payload here, so we subtract it by the length of the
	// type and old bytes.
	lenp := buf.Len() - oldByteSize - msgTypeBytes
	if lenp > MaxMsgBody {
		return cleanBrokenBytes(buf), ErrorPayloadTooLarge(lenp)
	}

	return buf.Len() - oldByteSize, nil
}

// ReadMessage reads, validates, and parses the next Lightning message from r
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
