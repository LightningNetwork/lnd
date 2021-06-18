package lnwire

import (
	"bytes"
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// FundingLocked is the message that both parties to a new channel creation
// send once they have observed the funding transaction being confirmed on the
// blockchain. FundingLocked contains the signatures necessary for the channel
// participants to advertise the existence of the channel to the rest of the
// network.
type FundingLocked struct {
	// ChanID is the outpoint of the channel's funding transaction. This
	// can be used to query for the channel in the database.
	ChanID ChannelID

	// NextPerCommitmentPoint is the secret that can be used to revoke the
	// next commitment transaction for the channel.
	NextPerCommitmentPoint *btcec.PublicKey

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// NewFundingLocked creates a new FundingLocked message, populating it with the
// necessary IDs and revocation secret.
func NewFundingLocked(cid ChannelID, npcp *btcec.PublicKey) *FundingLocked {
	return &FundingLocked{
		ChanID:                 cid,
		NextPerCommitmentPoint: npcp,
		ExtraData:              make([]byte, 0),
	}
}

// A compile time check to ensure FundingLocked implements the lnwire.Message
// interface.
var _ Message = (*FundingLocked)(nil)

// Decode deserializes the serialized FundingLocked message stored in the
// passed io.Reader into the target FundingLocked using the deserialization
// rules defined by the passed protocol version.
//
// This is part of the lnwire.Message interface.
func (c *FundingLocked) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&c.ChanID,
		&c.NextPerCommitmentPoint,
		&c.ExtraData,
	)
}

// Encode serializes the target FundingLocked message into the passed io.Writer
// implementation. Serialization will observe the rules defined by the passed
// protocol version.
//
// This is part of the lnwire.Message interface.
func (c *FundingLocked) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteChannelID(w, c.ChanID); err != nil {
		return err
	}

	if err := WritePublicKey(w, c.NextPerCommitmentPoint); err != nil {
		return err
	}

	return WriteBytes(w, c.ExtraData)
}

// MsgType returns the uint32 code which uniquely identifies this message as a
// FundingLocked message on the wire.
//
// This is part of the lnwire.Message interface.
func (c *FundingLocked) MsgType() MessageType {
	return MsgFundingLocked
}
