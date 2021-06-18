package lnwire

import (
	"bytes"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// ReplyShortChanIDsEnd is a message that marks the end of a streaming message
// response to an initial QueryShortChanIDs message. This marks that the
// receiver of the original QueryShortChanIDs for the target chain has either
// sent all adequate responses it knows of, or doesn't know of any short chan
// ID's for the target chain.
type ReplyShortChanIDsEnd struct {
	// ChainHash denotes the target chain that we're respond to a short
	// chan ID query for.
	ChainHash chainhash.Hash

	// Complete will be set to 0 if we don't know of the chain that the
	// remote peer sent their query for. Otherwise, we'll set this to 1 in
	// order to indicate that we've sent all known responses for the prior
	// set of short chan ID's in the corresponding QueryShortChanIDs
	// message.
	Complete uint8

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// NewReplyShortChanIDsEnd creates a new empty ReplyShortChanIDsEnd message.
func NewReplyShortChanIDsEnd() *ReplyShortChanIDsEnd {
	return &ReplyShortChanIDsEnd{}
}

// A compile time check to ensure ReplyShortChanIDsEnd implements the
// lnwire.Message interface.
var _ Message = (*ReplyShortChanIDsEnd)(nil)

// Decode deserializes a serialized ReplyShortChanIDsEnd message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *ReplyShortChanIDsEnd) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		c.ChainHash[:],
		&c.Complete,
		&c.ExtraData,
	)
}

// Encode serializes the target ReplyShortChanIDsEnd into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *ReplyShortChanIDsEnd) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteBytes(w, c.ChainHash[:]); err != nil {
		return err
	}

	if err := WriteUint8(w, c.Complete); err != nil {
		return err
	}

	return WriteBytes(w, c.ExtraData)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *ReplyShortChanIDsEnd) MsgType() MessageType {
	return MsgReplyShortChanIDsEnd
}
