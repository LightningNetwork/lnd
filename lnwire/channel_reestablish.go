package lnwire

import (
	"bytes"
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// ChannelReestablish is a message sent between peers that have an existing
// open channel upon connection reestablishment. This message allows both sides
// to report their local state, and their current knowledge of the state of the
// remote commitment chain. If a deviation is detected and can be recovered
// from, then the necessary messages will be retransmitted. If the level of
// desynchronization is irreconcilable, then the channel will be force closed.
type ChannelReestablish struct {
	// ChanID is the channel ID of the channel state we're attempting to
	// synchronize with the remote party.
	ChanID ChannelID

	// NextLocalCommitHeight is the next local commitment height of the
	// sending party. If the height of the sender's commitment chain from
	// the receiver's Pov is one less that this number, then the sender
	// should re-send the *exact* same proposed commitment.
	//
	// In other words, the receiver should re-send their last sent
	// commitment iff:
	//
	//  * NextLocalCommitHeight == remoteCommitChain.Height
	//
	// This covers the case of a lost commitment which was sent by the
	// sender of this message, but never received by the receiver of this
	// message.
	NextLocalCommitHeight uint64

	// RemoteCommitTailHeight is the height of the receiving party's
	// unrevoked commitment from the PoV of the sender of this message. If
	// the height of the receiver's commitment is *one more* than this
	// value, then their prior RevokeAndAck message should be
	// retransmitted.
	//
	// In other words, the receiver should re-send their last sent
	// RevokeAndAck message iff:
	//
	//  * localCommitChain.tail().Height == RemoteCommitTailHeight + 1
	//
	// This covers the case of a lost revocation, wherein the receiver of
	// the message sent a revocation for a prior state, but the sender of
	// the message never fully processed it.
	RemoteCommitTailHeight uint64

	// LastRemoteCommitSecret is the last commitment secret that the
	// receiving node has sent to the sending party. This will be the
	// secret of the last revoked commitment transaction. Including this
	// provides proof that the sending node at least knows of this state,
	// as they couldn't have produced it if it wasn't sent, as the value
	// can be authenticated by querying the shachain or the receiving
	// party.
	LastRemoteCommitSecret [32]byte

	// LocalUnrevokedCommitPoint is the commitment point used in the
	// current un-revoked commitment transaction of the sending party.
	LocalUnrevokedCommitPoint *btcec.PublicKey

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// A compile time check to ensure ChannelReestablish implements the
// lnwire.Message interface.
var _ Message = (*ChannelReestablish)(nil)

// Encode serializes the target ChannelReestablish into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (a *ChannelReestablish) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteChannelID(w, a.ChanID); err != nil {
		return err
	}

	if err := WriteUint64(w, a.NextLocalCommitHeight); err != nil {
		return err
	}

	if err := WriteUint64(w, a.RemoteCommitTailHeight); err != nil {
		return err
	}

	// If the commit point wasn't sent, then we won't write out any of the
	// remaining fields as they're optional.
	if a.LocalUnrevokedCommitPoint == nil {
		// However, we'll still write out the extra data if it's
		// present.
		//
		// NOTE: This is here primarily for the quickcheck tests, in
		// practice, we'll always populate this field.
		return WriteBytes(w, a.ExtraData)
	}

	// Otherwise, we'll write out the remaining elements.
	if err := WriteBytes(w, a.LastRemoteCommitSecret[:]); err != nil {
		return err
	}

	if err := WritePublicKey(w, a.LocalUnrevokedCommitPoint); err != nil {
		return err
	}
	return WriteBytes(w, a.ExtraData)
}

// Decode deserializes a serialized ChannelReestablish stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (a *ChannelReestablish) Decode(r io.Reader, pver uint32) error {
	err := ReadElements(r,
		&a.ChanID,
		&a.NextLocalCommitHeight,
		&a.RemoteCommitTailHeight,
	)
	if err != nil {
		return err
	}

	// This message has currently defined optional fields. As a result,
	// we'll only proceed if there's still bytes remaining within the
	// reader.
	//
	// We'll manually parse out the optional fields in order to be able to
	// still utilize the io.Reader interface.

	// We'll first attempt to read the optional commit secret, if we're at
	// the EOF, then this means the field wasn't included so we can exit
	// early.
	var buf [32]byte
	_, err = io.ReadFull(r, buf[:32])
	if err == io.EOF {
		// If there aren't any more bytes, then we'll emplace an empty
		// extra data to make our quickcheck tests happy.
		a.ExtraData = make([]byte, 0)
		return nil
	} else if err != nil {
		return err
	}

	// If the field is present, then we'll copy it over and proceed.
	copy(a.LastRemoteCommitSecret[:], buf[:])

	// We'll conclude by parsing out the commitment point. We don't check
	// the error in this case, as it has included the commit secret, then
	// they MUST also include the commit point.
	if err = ReadElement(r, &a.LocalUnrevokedCommitPoint); err != nil {
		return err
	}

	return a.ExtraData.Decode(r)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (a *ChannelReestablish) MsgType() MessageType {
	return MsgChannelReestablish
}
