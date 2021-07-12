package macaroon

import (
	"bytes"
	"fmt"
)

// field names, as defined in libmacaroons
const (
	fieldNameLocation       = "location"
	fieldNameIdentifier     = "identifier"
	fieldNameSignature      = "signature"
	fieldNameCaveatId       = "cid"
	fieldNameVerificationId = "vid"
	fieldNameCaveatLocation = "cl"
)

// maxPacketV1Len is the maximum allowed length of a packet in the v1 macaroon
// serialization format.
const maxPacketV1Len = 0xffff

// The original macaroon binary encoding is made from a sequence
// of "packets", each of which has a field name and some data.
// The encoding is:
//
// - four ascii hex digits holding the entire packet size (including
// the digits themselves).
//
// - the field name, followed by an ascii space.
//
// - the raw data
//
// - a newline (\n) character
//
// The packet struct below holds a reference into Macaroon.data.
type packetV1 struct {
	// ftype holds the field name of the packet.
	fieldName []byte

	// data holds the packet's data.
	data []byte

	// len holds the total length in bytes
	// of the packet, including any header.
	totalLen int
}

// parsePacket parses the packet at the start of the
// given data.
func parsePacketV1(data []byte) (packetV1, error) {
	if len(data) < 6 {
		return packetV1{}, fmt.Errorf("packet too short")
	}
	plen, ok := parseSizeV1(data)
	if !ok {
		return packetV1{}, fmt.Errorf("cannot parse size")
	}
	if plen > len(data) {
		return packetV1{}, fmt.Errorf("packet size too big")
	}
	if plen < 4 {
		return packetV1{}, fmt.Errorf("packet size too small")
	}
	data = data[4:plen]
	i := bytes.IndexByte(data, ' ')
	if i <= 0 {
		return packetV1{}, fmt.Errorf("cannot parse field name")
	}
	fieldName := data[0:i]
	if data[len(data)-1] != '\n' {
		return packetV1{}, fmt.Errorf("no terminating newline found")
	}
	return packetV1{
		fieldName: fieldName,
		data:      data[i+1 : len(data)-1],
		totalLen:  plen,
	}, nil
}

// appendPacketV1 appends a packet with the given field name
// and data to the given buffer. If the field and data were
// too long to be encoded, it returns nil, false; otherwise
// it returns the appended buffer.
func appendPacketV1(buf []byte, field string, data []byte) ([]byte, bool) {
	plen := packetV1Size(field, data)
	if plen > maxPacketV1Len {
		return nil, false
	}
	buf = appendSizeV1(buf, plen)
	buf = append(buf, field...)
	buf = append(buf, ' ')
	buf = append(buf, data...)
	buf = append(buf, '\n')
	return buf, true
}

func packetV1Size(field string, data []byte) int {
	return 4 + len(field) + 1 + len(data) + 1
}

var hexDigits = []byte("0123456789abcdef")

func appendSizeV1(data []byte, size int) []byte {
	return append(data,
		hexDigits[size>>12],
		hexDigits[(size>>8)&0xf],
		hexDigits[(size>>4)&0xf],
		hexDigits[size&0xf],
	)
}

func parseSizeV1(data []byte) (int, bool) {
	d0, ok0 := asciiHex(data[0])
	d1, ok1 := asciiHex(data[1])
	d2, ok2 := asciiHex(data[2])
	d3, ok3 := asciiHex(data[3])
	return d0<<12 + d1<<8 + d2<<4 + d3, ok0 && ok1 && ok2 && ok3
}

func asciiHex(b byte) (int, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b) - '0', true
	case b >= 'a' && b <= 'f':
		return int(b) - 'a' + 0xa, true
	}
	return 0, false
}

func isASCIIHex(b byte) bool {
	_, ok := asciiHex(b)
	return ok
}
