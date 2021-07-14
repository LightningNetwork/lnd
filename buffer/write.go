package buffer

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// WriteSize represents the size of the maximum plaintext message than can be
// sent using brontide. The buffer does not include extra space for the MAC, as
// that is applied by the Noise protocol after encrypting the plaintext.
const WriteSize = lnwire.MaxSliceLength

// Write is static byte array occupying to maximum-allowed plaintext-message
// size.
type Write [WriteSize]byte

// Recycle zeroes the Write, making it fresh for another use.
func (b *Write) Recycle() {
	RecycleSlice(b[:])
}
