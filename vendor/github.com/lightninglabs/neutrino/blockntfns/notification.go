package blockntfns

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

// BlockNtfn is an interface that coalesces all the different types of block
// notifications.
type BlockNtfn interface {
	// Header returns the header of the block for which this notification is
	// for.
	Header() wire.BlockHeader

	// Height returns the height of the block for which this notification is
	// for.
	Height() uint32

	// ChainTip returns the header of the new tip of the chain after
	// processing the block being connected/disconnected.
	ChainTip() wire.BlockHeader
}

// Connected is a block notification that gets dispatched to clients when the
// filter header of a new block has been found that extends the current chain.
type Connected struct {
	header wire.BlockHeader
	height uint32
}

// A compile-time check to ensure Connected satisfies the BlockNtfn interface.
var _ BlockNtfn = (*Connected)(nil)

// NewBlockConnected creates a new Connected notification for the given block.
func NewBlockConnected(header wire.BlockHeader, height uint32) *Connected {
	return &Connected{header: header, height: height}
}

// Header returns the header of the block extending the chain.
func (n *Connected) Header() wire.BlockHeader {
	return n.header
}

// Height returns the height of the block extending the chain.
func (n *Connected) Height() uint32 {
	return n.height
}

// ChainTip returns the header of the new tip of the chain after processing the
// block being connected.
func (n *Connected) ChainTip() wire.BlockHeader {
	return n.header
}

// String returns the string representation of a Connected notification.
func (n *Connected) String() string {
	return fmt.Sprintf("block connected (height=%d, hash=%v)", n.height,
		n.header.BlockHash())
}

// Disconnected if a notification that gets dispatched to clients when a reorg
// has been detected at the tip of the chain.
type Disconnected struct {
	headerDisconnected wire.BlockHeader
	heightDisconnected uint32
	chainTip           wire.BlockHeader
}

// A compile-time check to ensure Disconnected satisfies the BlockNtfn
// interface.
var _ BlockNtfn = (*Disconnected)(nil)

// NewBlockDisconnected creates a Disconnected notification for the given block.
func NewBlockDisconnected(headerDisconnected wire.BlockHeader,
	heightDisconnected uint32, chainTip wire.BlockHeader) *Disconnected {

	return &Disconnected{
		headerDisconnected: headerDisconnected,
		heightDisconnected: heightDisconnected,
		chainTip:           chainTip,
	}
}

// Header returns the header of the block being disconnected.
func (n *Disconnected) Header() wire.BlockHeader {
	return n.headerDisconnected
}

// Height returns the height of the block being disconnected.
func (n *Disconnected) Height() uint32 {
	return n.heightDisconnected
}

// ChainTip returns the header of the new tip of the chain after processing the
// block being disconnected.
func (n *Disconnected) ChainTip() wire.BlockHeader {
	return n.chainTip
}

// String returns the string representation of a Disconnected notification.
func (n *Disconnected) String() string {
	return fmt.Sprintf("block disconnected (height=%d, hash=%v)",
		n.heightDisconnected, n.headerDisconnected.BlockHash())
}
