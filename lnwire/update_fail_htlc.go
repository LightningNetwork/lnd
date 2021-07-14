package lnwire

import (
	"bytes"
	"io"
)

// OpaqueReason is an opaque encrypted byte slice that encodes the exact
// failure reason and additional some supplemental data. The contents of this
// slice can only be decrypted by the sender of the original HTLC.
type OpaqueReason []byte

// UpdateFailHTLC is sent by Alice to Bob in order to remove a previously added
// HTLC. Upon receipt of an UpdateFailHTLC the HTLC should be removed from the
// next commitment transaction, with the UpdateFailHTLC propagated backwards in
// the route to fully undo the HTLC.
type UpdateFailHTLC struct {
	// ChanIDPoint is the particular active channel that this
	// UpdateFailHTLC is bound to.
	ChanID ChannelID

	// ID references which HTLC on the remote node's commitment transaction
	// has timed out.
	ID uint64

	// Reason is an onion-encrypted blob that details why the HTLC was
	// failed. This blob is only fully decryptable by the initiator of the
	// HTLC message.
	Reason OpaqueReason

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// A compile time check to ensure UpdateFailHTLC implements the lnwire.Message
// interface.
var _ Message = (*UpdateFailHTLC)(nil)

// Decode deserializes a serialized UpdateFailHTLC message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *UpdateFailHTLC) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&c.ChanID,
		&c.ID,
		&c.Reason,
		&c.ExtraData,
	)
}

// Encode serializes the target UpdateFailHTLC into the passed io.Writer observing
// the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *UpdateFailHTLC) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteChannelID(w, c.ChanID); err != nil {
		return err
	}

	if err := WriteUint64(w, c.ID); err != nil {
		return err
	}

	if err := WriteOpaqueReason(w, c.Reason); err != nil {
		return err
	}

	return WriteBytes(w, c.ExtraData)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *UpdateFailHTLC) MsgType() MessageType {
	return MsgUpdateFailHTLC
}

// TargetChanID returns the channel id of the link for which this message is
// intended.
//
// NOTE: Part of peer.LinkUpdater interface.
func (c *UpdateFailHTLC) TargetChanID() ChannelID {
	return c.ChanID
}
