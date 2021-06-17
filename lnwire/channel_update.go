package lnwire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// ChanUpdateMsgFlags is a bitfield that signals whether optional fields are
// present in the ChannelUpdate.
type ChanUpdateMsgFlags uint8

const (
	// ChanUpdateOptionMaxHtlc is a bit that indicates whether the
	// optional htlc_maximum_msat field is present in this ChannelUpdate.
	ChanUpdateOptionMaxHtlc ChanUpdateMsgFlags = 1 << iota
)

// String returns the bitfield flags as a string.
func (c ChanUpdateMsgFlags) String() string {
	return fmt.Sprintf("%08b", c)
}

// HasMaxHtlc returns true if the htlc_maximum_msat option bit is set in the
// message flags.
func (c ChanUpdateMsgFlags) HasMaxHtlc() bool {
	return c&ChanUpdateOptionMaxHtlc != 0
}

// ChanUpdateChanFlags is a bitfield that signals various options concerning a
// particular channel edge. Each bit is to be examined in order to determine
// how the ChannelUpdate message is to be interpreted.
type ChanUpdateChanFlags uint8

const (
	// ChanUpdateDirection indicates the direction of a channel update. If
	// this bit is set to 0 if Node1 (the node with the "smaller" Node ID)
	// is updating the channel, and to 1 otherwise.
	ChanUpdateDirection ChanUpdateChanFlags = 1 << iota

	// ChanUpdateDisabled is a bit that indicates if the channel edge
	// selected by the ChanUpdateDirection bit is to be treated as being
	// disabled.
	ChanUpdateDisabled
)

// IsDisabled determines whether the channel flags has the disabled bit set.
func (c ChanUpdateChanFlags) IsDisabled() bool {
	return c&ChanUpdateDisabled == ChanUpdateDisabled
}

// String returns the bitfield flags as a string.
func (c ChanUpdateChanFlags) String() string {
	return fmt.Sprintf("%08b", c)
}

// ChannelUpdate message is used after channel has been initially announced.
// Each side independently announces its fees and minimum expiry for HTLCs and
// other parameters. Also this message is used to redeclare initially set
// channel parameters.
type ChannelUpdate struct {
	// Signature is used to validate the announced data and prove the
	// ownership of node id.
	Signature Sig

	// ChainHash denotes the target chain that this channel was opened
	// within. This value should be the genesis hash of the target chain.
	// Along with the short channel ID, this uniquely identifies the
	// channel globally in a blockchain.
	ChainHash chainhash.Hash

	// ShortChannelID is the unique description of the funding transaction.
	ShortChannelID ShortChannelID

	// Timestamp allows ordering in the case of multiple announcements. We
	// should ignore the message if timestamp is not greater than
	// the last-received.
	Timestamp uint32

	// MessageFlags is a bitfield that describes whether optional fields
	// are present in this update. Currently, the least-significant bit
	// must be set to 1 if the optional field MaxHtlc is present.
	MessageFlags ChanUpdateMsgFlags

	// ChannelFlags is a bitfield that describes additional meta-data
	// concerning how the update is to be interpreted. Currently, the
	// least-significant bit must be set to 0 if the creating node
	// corresponds to the first node in the previously sent channel
	// announcement and 1 otherwise. If the second bit is set, then the
	// channel is set to be disabled.
	ChannelFlags ChanUpdateChanFlags

	// TimeLockDelta is the minimum number of blocks this node requires to
	// be added to the expiry of HTLCs. This is a security parameter
	// determined by the node operator. This value represents the required
	// gap between the time locks of the incoming and outgoing HTLC's set
	// to this node.
	TimeLockDelta uint16

	// HtlcMinimumMsat is the minimum HTLC value which will be accepted.
	HtlcMinimumMsat MilliSatoshi

	// BaseFee is the base fee that must be used for incoming HTLC's to
	// this particular channel. This value will be tacked onto the required
	// for a payment independent of the size of the payment.
	BaseFee uint32

	// FeeRate is the fee rate that will be charged per millionth of a
	// satoshi.
	FeeRate uint32

	// HtlcMaximumMsat is the maximum HTLC value which will be accepted.
	HtlcMaximumMsat MilliSatoshi

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraOpaqueData ExtraOpaqueData
}

// A compile time check to ensure ChannelUpdate implements the lnwire.Message
// interface.
var _ Message = (*ChannelUpdate)(nil)

// Decode deserializes a serialized ChannelUpdate stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (a *ChannelUpdate) Decode(r io.Reader, pver uint32) error {
	err := ReadElements(r,
		&a.Signature,
		a.ChainHash[:],
		&a.ShortChannelID,
		&a.Timestamp,
		&a.MessageFlags,
		&a.ChannelFlags,
		&a.TimeLockDelta,
		&a.HtlcMinimumMsat,
		&a.BaseFee,
		&a.FeeRate,
	)
	if err != nil {
		return err
	}

	// Now check whether the max HTLC field is present and read it if so.
	if a.MessageFlags.HasMaxHtlc() {
		if err := ReadElements(r, &a.HtlcMaximumMsat); err != nil {
			return err
		}
	}

	return a.ExtraOpaqueData.Decode(r)
}

// Encode serializes the target ChannelUpdate into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (a *ChannelUpdate) Encode(w *bytes.Buffer, pver uint32) error {
	err := WriteElements(w,
		a.Signature,
		a.ChainHash[:],
		a.ShortChannelID,
		a.Timestamp,
		a.MessageFlags,
		a.ChannelFlags,
		a.TimeLockDelta,
		a.HtlcMinimumMsat,
		a.BaseFee,
		a.FeeRate,
	)
	if err != nil {
		return err
	}

	// Now append optional fields if they are set. Currently, the only
	// optional field is max HTLC.
	if a.MessageFlags.HasMaxHtlc() {
		if err := WriteElements(w, a.HtlcMaximumMsat); err != nil {
			return err
		}
	}

	// Finally, append any extra opaque data.
	return a.ExtraOpaqueData.Encode(w)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (a *ChannelUpdate) MsgType() MessageType {
	return MsgChannelUpdate
}

// DataToSign is used to retrieve part of the announcement message which should
// be signed.
func (a *ChannelUpdate) DataToSign() ([]byte, error) {

	// We should not include the signatures itself.
	var w bytes.Buffer
	err := WriteElements(&w,
		a.ChainHash[:],
		a.ShortChannelID,
		a.Timestamp,
		a.MessageFlags,
		a.ChannelFlags,
		a.TimeLockDelta,
		a.HtlcMinimumMsat,
		a.BaseFee,
		a.FeeRate,
	)
	if err != nil {
		return nil, err
	}

	// Now append optional fields if they are set. Currently, the only
	// optional field is max HTLC.
	if a.MessageFlags.HasMaxHtlc() {
		if err := WriteElements(&w, a.HtlcMaximumMsat); err != nil {
			return nil, err
		}
	}

	// Finally, append any extra opaque data.
	if err := a.ExtraOpaqueData.Encode(&w); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}
