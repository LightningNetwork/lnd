package buffer

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// ReadSize represents the size of the maximum message that can be read off the
// wire by brontide. The buffer is used to hold the ciphertext while the
// brontide state machine decrypts the message.
const ReadSize = lnwire.MaxSliceLength + 16

// Read is a static byte array sized to the maximum-allowed Lightning message
// size, plus 16 bytes for the MAC.
type Read [ReadSize]byte

// Recycle zeroes the Read, making it fresh for another use.
func (b *Read) Recycle() {
	RecycleSlice(b[:])
}
