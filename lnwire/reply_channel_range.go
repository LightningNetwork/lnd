package lnwire

import (
	"bytes"
	"io"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// ReplyChannelRange is the response to the QueryChannelRange message. It
// includes the original query, and the next streaming chunk of encoded short
// channel ID's as the response. We'll also include a byte that indicates if
// this is the last query in the message.
type ReplyChannelRange struct {
	// ChainHash denotes the target chain that we're trying to synchronize
	// channel graph state for.
	ChainHash chainhash.Hash

	// FirstBlockHeight is the first block in the query range. The
	// responder should send all new short channel IDs from this block
	// until this block plus the specified number of blocks.
	FirstBlockHeight uint32

	// NumBlocks is the number of blocks beyond the first block that short
	// channel ID's should be sent for.
	NumBlocks uint32

	// Complete denotes if this is the conclusion of the set of streaming
	// responses to the original query.
	Complete uint8

	// EncodingType is a signal to the receiver of the message that
	// indicates exactly how the set of short channel ID's that follow have
	// been encoded.
	EncodingType ShortChanIDEncoding

	// ShortChanIDs is a slice of decoded short channel ID's.
	ShortChanIDs []ShortChannelID

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData

	// noSort indicates whether or not to sort the short channel ids before
	// writing them out.
	//
	// NOTE: This should only be used for testing.
	noSort bool
}

// NewReplyChannelRange creates a new empty ReplyChannelRange message.
func NewReplyChannelRange() *ReplyChannelRange {
	return &ReplyChannelRange{}
}

// A compile time check to ensure ReplyChannelRange implements the
// lnwire.Message interface.
var _ Message = (*ReplyChannelRange)(nil)

// Decode deserializes a serialized ReplyChannelRange message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *ReplyChannelRange) Decode(r io.Reader, pver uint32) error {
	err := ReadElements(r,
		c.ChainHash[:],
		&c.FirstBlockHeight,
		&c.NumBlocks,
		&c.Complete,
	)
	if err != nil {
		return err
	}

	c.EncodingType, c.ShortChanIDs, err = decodeShortChanIDs(r)
	if err != nil {
		return err
	}

	return c.ExtraData.Decode(r)
}

// Encode serializes the target ReplyChannelRange into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *ReplyChannelRange) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteBytes(w, c.ChainHash[:]); err != nil {
		return err
	}

	if err := WriteUint32(w, c.FirstBlockHeight); err != nil {
		return err
	}

	if err := WriteUint32(w, c.NumBlocks); err != nil {
		return err
	}

	if err := WriteUint8(w, c.Complete); err != nil {
		return err
	}

	err := encodeShortChanIDs(w, c.EncodingType, c.ShortChanIDs, c.noSort)
	if err != nil {
		return err
	}

	return WriteBytes(w, c.ExtraData)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *ReplyChannelRange) MsgType() MessageType {
	return MsgReplyChannelRange
}

// LastBlockHeight returns the last block height covered by the range of a
// QueryChannelRange message.
func (c *ReplyChannelRange) LastBlockHeight() uint32 {
	// Handle overflows by casting to uint64.
	lastBlockHeight := uint64(c.FirstBlockHeight) + uint64(c.NumBlocks) - 1
	if lastBlockHeight > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(lastBlockHeight)
}
