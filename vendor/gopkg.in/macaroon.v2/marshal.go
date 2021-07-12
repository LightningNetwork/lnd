package macaroon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Version specifies the version of a macaroon.
// In version 1, the macaroon id and all caveats
// must be UTF-8-compatible strings, and the
// size of any part of the macaroon may not exceed
// approximately 64K. In version 2,
// all field may be arbitrary binary blobs.
type Version uint16

const (
	// V1 specifies version 1 macaroons.
	V1 Version = 1

	// V2 specifies version 2 macaroons.
	V2 Version = 2

	// LatestVersion holds the latest supported version.
	LatestVersion = V2
)

// String returns a string representation of the version;
// for example V1 formats as "v1".
func (v Version) String() string {
	return fmt.Sprintf("v%d", v)
}

// Version returns the version of the macaroon.
func (m *Macaroon) Version() Version {
	return m.version
}

// MarshalJSON implements json.Marshaler by marshaling the
// macaroon in JSON format. The serialisation format is determined
// by the macaroon's version.
func (m *Macaroon) MarshalJSON() ([]byte, error) {
	switch m.version {
	case V1:
		return m.marshalJSONV1()
	case V2:
		return m.marshalJSONV2()
	default:
		return nil, fmt.Errorf("unknown version %v", m.version)
	}
}

// UnmarshalJSON implements json.Unmarshaller by unmarshaling
// the given macaroon in JSON format. It accepts both V1 and V2
// forms encoded forms, and also a base64-encoded JSON string
// containing the binary-marshaled macaroon.
//
// After unmarshaling, the macaroon's version will reflect
// the version that it was unmarshaled as.
func (m *Macaroon) UnmarshalJSON(data []byte) error {
	if data[0] == '"' {
		// It's a string, so it must be a base64-encoded binary form.
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		data, err := Base64Decode([]byte(s))
		if err != nil {
			return err
		}
		if err := m.UnmarshalBinary(data); err != nil {
			return err
		}
		return nil
	}
	// Not a string; try to unmarshal into both kinds of macaroon object.
	// This assumes that neither format has any fields in common.
	// For subsequent versions we may need to change this approach.
	type MacaroonJSONV1 macaroonJSONV1
	type MacaroonJSONV2 macaroonJSONV2
	var both struct {
		*MacaroonJSONV1
		*MacaroonJSONV2
	}
	if err := json.Unmarshal(data, &both); err != nil {
		return err
	}
	switch {
	case both.MacaroonJSONV1 != nil && both.MacaroonJSONV2 != nil:
		return fmt.Errorf("cannot determine macaroon encoding version")
	case both.MacaroonJSONV1 != nil:
		if err := m.initJSONV1((*macaroonJSONV1)(both.MacaroonJSONV1)); err != nil {
			return err
		}
		m.version = V1
	case both.MacaroonJSONV2 != nil:
		if err := m.initJSONV2((*macaroonJSONV2)(both.MacaroonJSONV2)); err != nil {
			return err
		}
		m.version = V2
	default:
		return fmt.Errorf("invalid JSON macaroon encoding")
	}
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
// It accepts both V1 and V2 binary encodings.
func (m *Macaroon) UnmarshalBinary(data []byte) error {
	// Copy the data to avoid retaining references to it
	// in the internal data structures.
	data = append([]byte(nil), data...)
	_, err := m.parseBinary(data)
	return err
}

// parseBinary parses the macaroon in binary format
// from the given data and returns where the parsed data ends.
//
// It retains references to data.
func (m *Macaroon) parseBinary(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty macaroon data")
	}
	v := data[0]
	if v == 2 {
		// Version 2 binary format.
		data, err := m.parseBinaryV2(data)
		if err != nil {
			return nil, fmt.Errorf("unmarshal v2: %v", err)
		}
		m.version = V2
		return data, nil
	}
	if isASCIIHex(v) {
		// It's a hex digit - version 1 binary format
		data, err := m.parseBinaryV1(data)
		if err != nil {
			return nil, fmt.Errorf("unmarshal v1: %v", err)
		}
		m.version = V1
		return data, nil
	}
	return nil, fmt.Errorf("cannot determine data format of binary-encoded macaroon")
}

// MarshalBinary implements encoding.BinaryMarshaler by
// formatting the macaroon according to the version specified
// by MarshalAs.
func (m *Macaroon) MarshalBinary() ([]byte, error) {
	return m.appendBinary(nil)
}

// appendBinary appends the binary-formatted macaroon to
// the given data, formatting it according to the macaroon's
// version.
func (m *Macaroon) appendBinary(data []byte) ([]byte, error) {
	switch m.version {
	case V1:
		return m.appendBinaryV1(data)
	case V2:
		return m.appendBinaryV2(data), nil
	default:
		return nil, fmt.Errorf("bad macaroon version %v", m.version)
	}
}

// Slice defines a collection of macaroons. By convention, the
// first macaroon in the slice is a primary macaroon and the rest
// are discharges for its third party caveats.
type Slice []*Macaroon

// MarshalBinary implements encoding.BinaryMarshaler.
func (s Slice) MarshalBinary() ([]byte, error) {
	var data []byte
	var err error
	for _, m := range s {
		data, err = m.appendBinary(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal macaroon %q: %v", m.Id(), err)
		}
	}
	return data, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
// It accepts all known binary encodings for the data - all the
// embedded macaroons need not be encoded in the same format.
func (s *Slice) UnmarshalBinary(data []byte) error {
	// Prevent the internal data structures from holding onto the
	// slice by copying it first.
	data = append([]byte(nil), data...)
	*s = (*s)[:0]
	for len(data) > 0 {
		var m Macaroon
		rest, err := m.parseBinary(data)
		if err != nil {
			return fmt.Errorf("cannot unmarshal macaroon: %v", err)
		}
		*s = append(*s, &m)
		data = rest
	}
	return nil
}

const (
	padded = 1 << iota
	stdEncoding
)

var codecs = [4]*base64.Encoding{
	0:                    base64.RawURLEncoding,
	padded:               base64.URLEncoding,
	stdEncoding:          base64.RawStdEncoding,
	stdEncoding | padded: base64.StdEncoding,
}

// Base64Decode base64-decodes the given data.
// It accepts both standard and URL encodings, both
// padded and unpadded.
func Base64Decode(data []byte) ([]byte, error) {
	encoding := 0
	if len(data) > 0 && data[len(data)-1] == '=' {
		encoding |= padded
	}
	for _, b := range data {
		if b == '/' || b == '+' {
			encoding |= stdEncoding
			break
		}
	}
	codec := codecs[encoding]
	buf := make([]byte, codec.DecodedLen(len(data)))
	n, err := codec.Decode(buf, data)
	if err == nil {
		return buf[0:n], nil
	}
	return nil, err
}
