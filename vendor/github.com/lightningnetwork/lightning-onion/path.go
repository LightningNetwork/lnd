package sphinx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
)

// HopData is the information destined for individual hops. It is a fixed size
// 64 bytes, prefixed with a 1 byte realm that indicates how to interpret it.
// For now we simply assume it's the bitcoin realm (0x00) and hence the format
// is fixed. The last 32 bytes are always the HMAC to be passed to the next
// hop, or zero if this is the packet is not to be forwarded, since this is the
// last hop.
type HopData struct {
	// Realm denotes the "real" of target chain of the next hop. For
	// bitcoin, this value will be 0x00.
	Realm [RealmByteSize]byte

	// NextAddress is the address of the next hop that this packet should
	// be forward to.
	NextAddress [AddressSize]byte

	// ForwardAmount is the HTLC amount that the next hop should forward.
	// This value should take into account the fee require by this
	// particular hop, and the cumulative fee for the entire route.
	ForwardAmount uint64

	// OutgoingCltv is the value of the outgoing absolute time-lock that
	// should be included in the HTLC forwarded.
	OutgoingCltv uint32

	// ExtraBytes is the set of unused bytes within the onion payload. This
	// extra set of bytes can be utilized by higher level applications to
	// package additional data within the per-hop payload, or signal that a
	// portion of the remaining set of hops are to be consumed as Extra
	// Onion Blobs.
	//
	// TODO(roasbeef): rename to padding bytes?
	ExtraBytes [NumPaddingBytes]byte
}

// Encode writes the serialized version of the target HopData into the passed
// io.Writer.
func (hd *HopData) Encode(w io.Writer) error {
	if _, err := w.Write(hd.Realm[:]); err != nil {
		return err
	}

	if _, err := w.Write(hd.NextAddress[:]); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, hd.ForwardAmount); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, hd.OutgoingCltv); err != nil {
		return err
	}

	if _, err := w.Write(hd.ExtraBytes[:]); err != nil {
		return err
	}

	return nil
}

// Decodes populates the target HopData with the contents of a serialized
// HopData packed into the passed io.Reader.
func (hd *HopData) Decode(r io.Reader) error {
	if _, err := io.ReadFull(r, hd.Realm[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, hd.NextAddress[:]); err != nil {
		return err
	}

	err := binary.Read(r, binary.BigEndian, &hd.ForwardAmount)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &hd.OutgoingCltv)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, hd.ExtraBytes[:])
	return err
}

// PayloadType denotes the type of the payload included in the onion packet.
// Serialization of a raw HopPayload will depend on the payload type, as some
// include a varint length prefix, while others just encode the raw payload.
type PayloadType uint8

const (
	// PayloadLegacy is the legacy payload type. It includes a fixed 32
	// bytes, 12 of which are padding, and uses a "zero length" (the old
	// realm) prefix.
	PayloadLegacy PayloadType = iota

	// PayloadTLV is the new modern TLV based format. This payload includes
	// a set of opaque bytes with a varint length prefix. The varint used
	// is the same CompactInt as used in the Bitcoin protocol.
	PayloadTLV
)

// HopPayload is a slice of bytes and associated payload-type that are destined
// for a specific hop in the PaymentPath. The payload itself is treated as an
// opaque data field by the onion router. The included Type field informs the
// serialization/deserialziation of the raw payload.
type HopPayload struct {
	// Type is the type of the payload.
	Type PayloadType

	// Payload is the raw bytes of the per-hop payload for this hop.
	// Depending on the realm, this pay be the regular legacy hop data, or
	// a set of opaque blobs to be parsed by higher layers.
	Payload []byte

	// HMAC is an HMAC computed over the entire per-hop payload that also
	// includes the higher-level (optional) associated data bytes.
	HMAC [HMACSize]byte
}

// NewHopPayload creates a new hop payload given an optional set of forwarding
// instructions for a hop, and a set of optional opaque extra onion bytes to
// drop off at the target hop. If both values are not specified, then an error
// is returned.
func NewHopPayload(hopData *HopData, eob []byte) (HopPayload, error) {
	var (
		h HopPayload
		b bytes.Buffer
	)

	// We can't proceed if neither the hop data or the EOB has been
	// specified by the caller.
	switch {
	case hopData == nil && len(eob) == 0:
		return h, fmt.Errorf("either hop data or eob must " +
			"be specified")

	case hopData != nil && len(eob) > 0:
		return h, fmt.Errorf("cannot provide both hop data AND an eob")

	}

	// If the hop data is specified, then we'll write that now, as it
	// should proceed the EOB portion of the payload.
	if hopData != nil {
		if err := hopData.Encode(&b); err != nil {
			return h, nil
		}

		// We'll also mark that this particular hop will be using the
		// legacy format as the modern format packs the existing hop
		// data information into the EOB space as a TLV stream.
		h.Type = PayloadLegacy
	} else {
		// Otherwise, we'll write out the raw EOB which contains a set
		// of opaque bytes that the recipient can decode to make a
		// forwarding decision.
		if _, err := b.Write(eob); err != nil {
			return h, nil
		}

		h.Type = PayloadTLV
	}

	h.Payload = b.Bytes()

	return h, nil
}

// NumBytes returns the number of bytes it will take to serialize the full
// payload. Depending on the payload type, this may include some additional
// signalling bytes.
func (hp *HopPayload) NumBytes() int {
	// The base size is the size of the raw payload, and the size of the
	// HMAC.
	size := len(hp.Payload) + HMACSize

	// If this is the new TLV format, then we'll also accumulate the number
	// of bytes that it would take to encode the size of the payload.
	if hp.Type == PayloadTLV {
		payloadSize := len(hp.Payload)
		size += int(wire.VarIntSerializeSize(uint64(payloadSize)))
	}

	return size
}

// Encode encodes the hop payload into the passed writer.
func (hp *HopPayload) Encode(w io.Writer) error {
	switch hp.Type {

	// For the legacy payload, we don't need to add any additional bytes as
	// our realm byte serves as our zero prefix byte.
	case PayloadLegacy:
		break

	// For the TLV payload, we'll first prepend the length of the payload
	// as a var-int.
	case PayloadTLV:
		var b [8]byte
		err := WriteVarInt(w, uint64(len(hp.Payload)), &b)
		if err != nil {
			return err
		}
	}

	// Finally, we'll write out the raw payload, then the HMAC in series.
	if _, err := w.Write(hp.Payload); err != nil {
		return err
	}
	if _, err := w.Write(hp.HMAC[:]); err != nil {
		return err
	}

	return nil
}

// Decode unpacks an encoded HopPayload from the passed reader into the target
// HopPayload.
func (hp *HopPayload) Decode(r io.Reader) error {
	bufReader := bufio.NewReader(r)

	// In order to properly parse the payload, we'll need to check the
	// first byte. We'll use a bufio reader to peek at it without consuming
	// it from the buffer.
	peekByte, err := bufReader.Peek(1)
	if err != nil {
		return err
	}

	var payloadSize uint32

	switch int(peekByte[0]) {
	// If the first byte is a zero (the realm), then this is the normal
	// payload.
	case 0x00:
		// Our size is just the payload, without the HMAC. This means
		// that this is the legacy payload type.
		payloadSize = LegacyHopDataSize - HMACSize
		hp.Type = PayloadLegacy

	default:
		// Otherwise, this is the new TLV based payload type, so we'll
		// extract the payload length encoded as a var-int.
		var b [8]byte
		varInt, err := ReadVarInt(bufReader, &b)
		if err != nil {
			return err
		}

		payloadSize = uint32(varInt)
		hp.Type = PayloadTLV
	}

	// Now that we know the payload size, we'll create a  new buffer to
	// read it out in full.
	//
	// TODO(roasbeef): can avoid all these copies
	hp.Payload = make([]byte, payloadSize)
	if _, err := io.ReadFull(bufReader, hp.Payload[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(bufReader, hp.HMAC[:]); err != nil {
		return err
	}

	return nil
}

// HopData attempts to extract a set of forwarding instructions from the target
// HopPayload. If the realm isn't what we expect, then an error is returned.
// This method also returns the left over EOB that remain after the hop data
// has been parsed. Callers may want to map this blob into something more
// concrete.
func (hp *HopPayload) HopData() (*HopData, error) {
	payloadReader := bytes.NewBuffer(hp.Payload)

	// If this isn't the "base" realm, then we can't extract the expected
	// hop payload structure from the payload.
	if hp.Type != PayloadLegacy {
		return nil, nil
	}

	// Now that we know the payload has the structure we expect, we'll
	// decode the payload into the HopData.
	var hd HopData
	if err := hd.Decode(payloadReader); err != nil {
		return nil, err
	}

	return &hd, nil
}

// NumMaxHops is the maximum path length. There is a maximum of 1300 bytes in
// the routing info block. Legacy hop payloads are always 65 bytes, while tlv
// payloads are at least 47 bytes (tlvlen 1, amt 2, timelock 2, nextchan 10,
// hmac 32) for the intermediate hops and 37 bytes (tlvlen 1, amt 2, timelock 2,
// hmac 32) for the exit hop. The maximum path length can therefore only be
// reached by using tlv payloads only. With that, the maximum number of
// intermediate hops is: Floor((1300 - 37) / 47) = 26. Including the exit hop,
// the maximum path length is 27 hops.
const NumMaxHops = 27

// PaymentPath represents a series of hops within the Lightning Network
// starting at a sender and terminating at a receiver. Each hop contains a set
// of mandatory data which contains forwarding instructions for that hop.
// Additionally, we can also transmit additional data to each hop by utilizing
// the un-used hops (see TrueRouteLength()) to pack in additional data. In
// order to do this, we encrypt the several hops with the same node public key,
// and unroll the extra data into the space used for route forwarding
// information.
type PaymentPath [NumMaxHops]OnionHop

// OnionHop represents an abstract hop (a link between two nodes) within the
// Lightning Network. A hop is composed of the incoming node (able to decrypt
// the encrypted routing information), and the routing information itself.
// Optionally, the crafter of a route can indicate that additional data aside
// from the routing information is be delivered, which will manifest as
// additional hops to pack the data.
type OnionHop struct {
	// NodePub is the target node for this hop. The payload will enter this
	// hop, it'll decrypt the routing information, and hand off the
	// internal packet to the next hop.
	NodePub btcec.PublicKey

	// HopPayload is the opaque payload provided to this node. If the
	// HopData above is specified, then it'll be packed into this payload.
	HopPayload HopPayload
}

// IsEmpty returns true if the hop isn't populated.
func (o OnionHop) IsEmpty() bool {
	return o.NodePub.X == nil || o.NodePub.Y == nil
}

// NodeKeys returns a slice pointing to node keys that this route comprises of.
// The size of the returned slice will be TrueRouteLength().
func (p *PaymentPath) NodeKeys() []*btcec.PublicKey {
	var nodeKeys [NumMaxHops]*btcec.PublicKey

	routeLen := p.TrueRouteLength()
	for i := 0; i < routeLen; i++ {
		nodeKeys[i] = &p[i].NodePub
	}

	return nodeKeys[:routeLen]
}

// TrueRouteLength returns the "true" length of the PaymentPath. The max
// payment path is NumMaxHops size, but in practice routes are much smaller.
// This method will return the number of actual hops (nodes) involved in this
// route. For references, a direct path has a length of 1, path through an
// intermediate node has a length of 2 (3 nodes involved).
func (p *PaymentPath) TrueRouteLength() int {
	var routeLength int
	for _, hop := range p {
		// When we hit the first empty hop, we know we're now in the
		// zero'd out portion of the array.
		if hop.IsEmpty() {
			return routeLength
		}

		routeLength++
	}

	return routeLength
}

// TotalPayloadSize returns the sum of the size of each payload in the "true"
// route.
func (p *PaymentPath) TotalPayloadSize() int {
	var totalSize int
	for _, hop := range p {
		if hop.IsEmpty() {
			continue
		}

		totalSize += hop.HopPayload.NumBytes()
	}

	return totalSize
}
