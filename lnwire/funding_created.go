package lnwire

import (
	"bytes"
	"io"

	"github.com/btcsuite/btcd/wire"
)

// FundingCreated is sent from Alice (the initiator) to Bob (the responder),
// once Alice receives Bob's contributions as well as his channel constraints.
// Once bob receives this message, he'll gain access to an immediately
// broadcastable commitment transaction and will reply with a signature for
// Alice's version of the commitment transaction.
type FundingCreated struct {
	// PendingChannelID serves to uniquely identify the future channel
	// created by the initiated single funder workflow.
	PendingChannelID [32]byte

	// FundingPoint is the outpoint of the funding transaction created by
	// Alice. With this, Bob is able to generate both his version and
	// Alice's version of the commitment transaction.
	FundingPoint wire.OutPoint

	// CommitSig is Alice's signature from Bob's version of the commitment
	// transaction.
	CommitSig Sig

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// A compile time check to ensure FundingCreated implements the lnwire.Message
// interface.
var _ Message = (*FundingCreated)(nil)

// Encode serializes the target FundingCreated into the passed io.Writer
// implementation. Serialization will observe the rules defined by the passed
// protocol version.
//
// This is part of the lnwire.Message interface.
func (f *FundingCreated) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteBytes(w, f.PendingChannelID[:]); err != nil {
		return err
	}

	if err := WriteOutPoint(w, f.FundingPoint); err != nil {
		return err
	}

	if err := WriteSig(w, f.CommitSig); err != nil {
		return err
	}

	return WriteBytes(w, f.ExtraData)
}

// Decode deserializes the serialized FundingCreated stored in the passed
// io.Reader into the target FundingCreated using the deserialization rules
// defined by the passed protocol version.
//
// This is part of the lnwire.Message interface.
func (f *FundingCreated) Decode(r io.Reader, pver uint32) error {
	return ReadElements(
		r, f.PendingChannelID[:], &f.FundingPoint, &f.CommitSig,
		&f.ExtraData,
	)
}

// MsgType returns the uint32 code which uniquely identifies this message as a
// FundingCreated on the wire.
//
// This is part of the lnwire.Message interface.
func (f *FundingCreated) MsgType() MessageType {
	return MsgFundingCreated
}
