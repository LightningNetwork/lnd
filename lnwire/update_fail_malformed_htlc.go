package lnwire

import (
	"bytes"
	"crypto/sha256"
	"io"
)

// UpdateFailMalformedHTLC is sent by either the payment forwarder or by
// payment receiver to the payment sender in order to notify it that the onion
// blob can't be parsed. For that reason we send this message instead of
// obfuscate the onion failure.
type UpdateFailMalformedHTLC struct {
	// ChanID is the particular active channel that this
	// UpdateFailMalformedHTLC is bound to.
	ChanID ChannelID

	// ID references which HTLC on the remote node's commitment transaction
	// has timed out.
	ID uint64

	// ShaOnionBlob hash of the onion blob on which can't be parsed by the
	// node in the payment path.
	ShaOnionBlob [sha256.Size]byte

	// FailureCode the exact reason why onion blob haven't been parsed.
	FailureCode FailCode

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// A compile time check to ensure UpdateFailMalformedHTLC implements the
// lnwire.Message interface.
var _ Message = (*UpdateFailMalformedHTLC)(nil)

// Decode deserializes a serialized UpdateFailMalformedHTLC message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *UpdateFailMalformedHTLC) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&c.ChanID,
		&c.ID,
		c.ShaOnionBlob[:],
		&c.FailureCode,
		&c.ExtraData,
	)
}

// Encode serializes the target UpdateFailMalformedHTLC into the passed
// io.Writer observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *UpdateFailMalformedHTLC) Encode(w *bytes.Buffer,
	pver uint32) error {

	if err := WriteChannelID(w, c.ChanID); err != nil {
		return err
	}

	if err := WriteUint64(w, c.ID); err != nil {
		return err
	}

	if err := WriteBytes(w, c.ShaOnionBlob[:]); err != nil {
		return err
	}

	if err := WriteFailCode(w, c.FailureCode); err != nil {
		return err
	}

	return WriteBytes(w, c.ExtraData)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *UpdateFailMalformedHTLC) MsgType() MessageType {
	return MsgUpdateFailMalformedHTLC
}

// TargetChanID returns the channel id of the link for which this message is
// intended.
//
// NOTE: Part of peer.LinkUpdater interface.
func (c *UpdateFailMalformedHTLC) TargetChanID() ChannelID {
	return c.ChanID
}
