package lnwire

import (
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// ChannelTypeRecordType is the type of the experimental record used
	// to denote which channel type is being negotiated.
	ChannelTypeRecordType tlv.Type = 1
)

// ChannelType represents a specific channel type as a set of feature bits that
// comprise it.
type ChannelType RawFeatureVector

// featureBitLen returns the length in bytes of the encoded feature bits.
func (c ChannelType) featureBitLen() uint64 {
	fv := RawFeatureVector(c)
	return uint64(fv.SerializeSize())
}

// Record returns a TLV record that can be used to encode/decode the channel
// type from a given TLV stream.
func (c *ChannelType) Record() tlv.Record {
	return tlv.MakeDynamicRecord(
		ChannelTypeRecordType, c, c.featureBitLen, channelTypeEncoder,
		channelTypeDecoder,
	)
}

// channelTypeEncoder is a custom TLV encoder for the ChannelType record.
func channelTypeEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*ChannelType); ok {
		// Encode the feature bits as a byte slice without its length
		// prepended, as that's already taken care of by the TLV record.
		fv := RawFeatureVector(*v)
		return fv.encode(w, fv.SerializeSize(), 8)
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.ChannelType")
}

// channelTypeDecoder is a custom TLV decoder for the ChannelType record.
func channelTypeDecoder(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if v, ok := val.(*ChannelType); ok {
		fv := NewRawFeatureVector()
		if err := fv.decode(r, int(l), 8); err != nil {
			return err
		}
		*v = ChannelType(*fv)
		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.ChannelType")
}
