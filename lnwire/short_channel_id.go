package lnwire

import (
	"fmt"
)

// ShortChannelID represents the set of data which is needed to retrieve all
// necessary data to validate the channel existence.
type ShortChannelID struct {
	// BlockHeight is the height of the block where funding transaction
	// located.
	//
	// NOTE: This field is limited to 3 bytes.
	BlockHeight uint32

	// TxIndex is a position of funding transaction within a block.
	//
	// NOTE: This field is limited to 3 bytes.
	TxIndex uint32

	// TxPosition indicating transaction output which pays to the channel.
	TxPosition uint16
}

// NewShortChanIDFromInt returns a new ShortChannelID which is the decoded
// version of the compact channel ID encoded within the uint64. The format of
// the compact channel ID is as follows: 3 bytes for the block height, 3 bytes
// for the transaction index, and 2 bytes for the output index.
func NewShortChanIDFromInt(chanID uint64) ShortChannelID {
	return ShortChannelID{
		BlockHeight: uint32(chanID >> 40),
		TxIndex:     uint32(chanID>>16) & 0xFFFFFF,
		TxPosition:  uint16(chanID),
	}
}

// NewFakeShortChanIDFromInt generates a new short channel that its block
// height is between 2^17 = 131072 and 2^17 + 2^18 - 1 = 393215
func NewFakeShortChanIDFromInt(chanID uint64) ShortChannelID {
	c := NewShortChanIDFromInt(chanID)
	c.BlockHeight = (c.BlockHeight >> 6) + (1 << 17)
	return c
}

// IsFake test if this is a fake channel id. It does it by making sure the
// block height is between 2^17 = 131072 and 2^17 + 2^18 - 1 = 393215
func (c ShortChannelID) IsFake() bool {
	return c.BlockHeight >= (1<<17) && c.BlockHeight < (3<<17)
}

// ToUint64 converts the ShortChannelID into a compact format encoded within a
// uint64 (8 bytes).
func (c ShortChannelID) ToUint64() uint64 {
	// TODO(roasbeef): explicit error on overflow?
	return ((uint64(c.BlockHeight) << 40) | (uint64(c.TxIndex) << 16) |
		(uint64(c.TxPosition)))
}

// String generates a human-readable representation of the channel ID.
func (c ShortChannelID) String() string {
	return fmt.Sprintf("%d:%d:%d", c.BlockHeight, c.TxIndex, c.TxPosition)
}
