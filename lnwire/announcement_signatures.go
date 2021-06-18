package lnwire

import (
	"bytes"
	"io"
)

// AnnounceSignatures is a direct message between two endpoints of a
// channel and serves as an opt-in mechanism to allow the announcement of
// the channel to the rest of the network. It contains the necessary
// signatures by the sender to construct the channel announcement message.
type AnnounceSignatures struct {
	// ChannelID is the unique description of the funding transaction.
	// Channel id is better for users and debugging and short channel id is
	// used for quick test on existence of the particular utxo inside the
	// block chain, because it contains information about block.
	ChannelID ChannelID

	// ShortChannelID is the unique description of the funding
	// transaction. It is constructed with the most significant 3 bytes
	// as the block height, the next 3 bytes indicating the transaction
	// index within the block, and the least significant two bytes
	// indicating the output index which pays to the channel.
	ShortChannelID ShortChannelID

	// NodeSignature is the signature which contains the signed announce
	// channel message, by this signature we proof that we possess of the
	// node pub key and creating the reference node_key -> bitcoin_key.
	NodeSignature Sig

	// BitcoinSignature is the signature which contains the signed node
	// public key, by this signature we proof that we possess of the
	// bitcoin key and and creating the reverse reference bitcoin_key ->
	// node_key.
	BitcoinSignature Sig

	// ExtraOpaqueData is the set of data that was appended to this
	// message, some of which we may not actually know how to iterate or
	// parse. By holding onto this data, we ensure that we're able to
	// properly validate the set of signatures that cover these new fields,
	// and ensure we're able to make upgrades to the network in a forwards
	// compatible manner.
	ExtraOpaqueData ExtraOpaqueData
}

// A compile time check to ensure AnnounceSignatures implements the
// lnwire.Message interface.
var _ Message = (*AnnounceSignatures)(nil)

// Decode deserializes a serialized AnnounceSignatures stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (a *AnnounceSignatures) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&a.ChannelID,
		&a.ShortChannelID,
		&a.NodeSignature,
		&a.BitcoinSignature,
		&a.ExtraOpaqueData,
	)
}

// Encode serializes the target AnnounceSignatures into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (a *AnnounceSignatures) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteChannelID(w, a.ChannelID); err != nil {
		return err
	}

	if err := WriteShortChannelID(w, a.ShortChannelID); err != nil {
		return err
	}

	if err := WriteSig(w, a.NodeSignature); err != nil {
		return err
	}

	if err := WriteSig(w, a.BitcoinSignature); err != nil {
		return err
	}

	return WriteBytes(w, a.ExtraOpaqueData)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (a *AnnounceSignatures) MsgType() MessageType {
	return MsgAnnounceSignatures
}
