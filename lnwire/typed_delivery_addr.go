package lnwire

import (
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// DeliveryAddrType is the TLV record type for delivery addreses within
	// the name space of the OpenChannel and AcceptChannel messages.
	DeliveryAddrType = 0

	// deliveryAddressMaxSize is the maximum expected size in bytes of a
	// DeliveryAddress based on the types of scripts we know.
	// Following are the known scripts and their sizes in bytes.
	// - pay to witness script hash: 34
	// - pay to pubkey hash: 25
	// - pay to script hash: 22
	// - pay to witness pubkey hash: 22.
	deliveryAddressMaxSize = 34
)

// DeliveryAddress is used to communicate the address to which funds from a
// closed channel should be sent. The address can be a p2wsh, p2pkh, p2sh or
// p2wpkh.
type DeliveryAddress []byte

// Record returns a TLV record that can be used to encode the delivery
// address within the ExtraData TLV stream. This was introduced in order to
// allow the OpenChannel/AcceptChannel messages to properly be extended with
// TLV types.
func (d *DeliveryAddress) Record() tlv.Record {
	addrBytes := (*[]byte)(d)

	return tlv.MakeDynamicRecord(
		DeliveryAddrType, addrBytes,
		func() uint64 {
			return uint64(len(*addrBytes))
		},
		tlv.EVarBytes, tlv.DVarBytes,
	)
}
