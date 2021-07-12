package macaroon

import (
	"encoding/binary"
	"fmt"
)

type fieldType int

// Field constants as used in the binary encoding.
const (
	fieldEOS            fieldType = 0
	fieldLocation       fieldType = 1
	fieldIdentifier     fieldType = 2
	fieldVerificationId fieldType = 4
	fieldSignature      fieldType = 6
)

type packetV2 struct {
	// fieldType holds the type of the field.
	fieldType fieldType

	// data holds the packet's data.
	data []byte
}

// parseSectionV2 parses a sequence of packets
// in data. The sequence is terminated by a packet
// with a field type of fieldEOS.
func parseSectionV2(data []byte) ([]byte, []packetV2, error) {
	prevFieldType := fieldType(-1)
	var packets []packetV2
	for {
		if len(data) == 0 {
			return nil, nil, fmt.Errorf("section extends past end of buffer")
		}
		rest, p, err := parsePacketV2(data)
		if err != nil {
			return nil, nil, err
		}
		if p.fieldType == fieldEOS {
			return rest, packets, nil
		}
		if p.fieldType <= prevFieldType {
			return nil, nil, fmt.Errorf("fields out of order")
		}
		packets = append(packets, p)
		prevFieldType = p.fieldType
		data = rest
	}
}

// parsePacketV2 parses a V2 data package at the start
// of the given data.
// The format of a packet is as follows:
//
//	fieldType(varint) payloadLen(varint) data[payloadLen bytes]
//
// apart from fieldEOS which has no payloadLen or data (it's
// a single zero byte).
func parsePacketV2(data []byte) ([]byte, packetV2, error) {
	data, ft, err := parseVarint(data)
	if err != nil {
		return nil, packetV2{}, err
	}
	p := packetV2{
		fieldType: fieldType(ft),
	}
	if p.fieldType == fieldEOS {
		return data, p, nil
	}
	data, payloadLen, err := parseVarint(data)
	if err != nil {
		return nil, packetV2{}, err
	}
	if payloadLen > len(data) {
		return nil, packetV2{}, fmt.Errorf("field data extends past end of buffer")
	}
	p.data = data[0:payloadLen]
	return data[payloadLen:], p, nil
}

// parseVarint parses the variable-length integer
// at the start of the given data and returns rest
// of the buffer and the number.
func parseVarint(data []byte) ([]byte, int, error) {
	val, n := binary.Uvarint(data)
	if n > 0 {
		if val > 0x7fffffff {
			return nil, 0, fmt.Errorf("varint value out of range")
		}
		return data[n:], int(val), nil
	}
	if n == 0 {
		return nil, 0, fmt.Errorf("varint value extends past end of buffer")
	}
	return nil, 0, fmt.Errorf("varint value out of range")
}

func appendPacketV2(data []byte, p packetV2) []byte {
	data = appendVarint(data, int(p.fieldType))
	if p.fieldType != fieldEOS {
		data = appendVarint(data, len(p.data))
		data = append(data, p.data...)
	}
	return data
}

func appendEOSV2(data []byte) []byte {
	return append(data, 0)
}

func appendVarint(data []byte, x int) []byte {
	var buf [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(buf[:], uint64(x))
	return append(data, buf[:n]...)
}
