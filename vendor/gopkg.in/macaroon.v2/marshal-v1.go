package macaroon

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// macaroonJSONV1 defines the V1 JSON format for macaroons.
type macaroonJSONV1 struct {
	Caveats    []caveatJSONV1 `json:"caveats"`
	Location   string         `json:"location"`
	Identifier string         `json:"identifier"`
	Signature  string         `json:"signature"` // hex-encoded
}

// caveatJSONV1 defines the V1 JSON format for caveats within a macaroon.
type caveatJSONV1 struct {
	CID      string `json:"cid"`
	VID      string `json:"vid,omitempty"`
	Location string `json:"cl,omitempty"`
}

// marshalJSONV1 marshals the macaroon to the V1 JSON format.
func (m *Macaroon) marshalJSONV1() ([]byte, error) {
	if !utf8.Valid(m.id) {
		return nil, fmt.Errorf("macaroon id is not valid UTF-8")
	}
	mjson := macaroonJSONV1{
		Location:   m.location,
		Identifier: string(m.id),
		Signature:  hex.EncodeToString(m.sig[:]),
		Caveats:    make([]caveatJSONV1, len(m.caveats)),
	}
	for i, cav := range m.caveats {
		if !utf8.Valid(cav.Id) {
			return nil, fmt.Errorf("caveat id is not valid UTF-8")
		}
		mjson.Caveats[i] = caveatJSONV1{
			Location: cav.Location,
			CID:      string(cav.Id),
			VID:      base64.RawURLEncoding.EncodeToString(cav.VerificationId),
		}
	}
	data, err := json.Marshal(mjson)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal json data: %v", err)
	}
	return data, nil
}

// initJSONV1 initializes m from the JSON-unmarshaled data
// held in mjson.
func (m *Macaroon) initJSONV1(mjson *macaroonJSONV1) error {
	m.init([]byte(mjson.Identifier), mjson.Location, V1)
	sig, err := hex.DecodeString(mjson.Signature)
	if err != nil {
		return fmt.Errorf("cannot decode macaroon signature %q: %v", m.sig, err)
	}
	if len(sig) != hashLen {
		return fmt.Errorf("signature has unexpected length %d", len(sig))
	}
	copy(m.sig[:], sig)
	m.caveats = m.caveats[:0]
	for _, cav := range mjson.Caveats {
		vid, err := Base64Decode([]byte(cav.VID))
		if err != nil {
			return fmt.Errorf("cannot decode verification id %q: %v", cav.VID, err)
		}
		m.appendCaveat([]byte(cav.CID), vid, cav.Location)
	}
	return nil
}

// The original (v1) binary format of a macaroon is as follows.
// Each identifier represents a v1 packet.
//
// location
// identifier
// (
//	caveatId?
//	verificationId?
//	caveatLocation?
// )*
// signature

// parseBinaryV1 parses the given data in V1 format into the macaroon. The macaroon's
// internal data structures will retain references to the data. It
// returns the data after the end of the macaroon.
func (m *Macaroon) parseBinaryV1(data []byte) ([]byte, error) {
	var err error

	loc, err := expectPacketV1(data, fieldNameLocation)
	if err != nil {
		return nil, err
	}
	data = data[loc.totalLen:]
	id, err := expectPacketV1(data, fieldNameIdentifier)
	if err != nil {
		return nil, err
	}
	data = data[id.totalLen:]
	m.init(id.data, string(loc.data), V1)
	var cav Caveat
	for {
		p, err := parsePacketV1(data)
		if err != nil {
			return nil, err
		}
		data = data[p.totalLen:]
		switch field := string(p.fieldName); field {
		case fieldNameSignature:
			// At the end of the caveats we find the signature.
			if cav.Id != nil {
				m.caveats = append(m.caveats, cav)
			}
			if len(p.data) != hashLen {
				return nil, fmt.Errorf("signature has unexpected length %d", len(p.data))
			}
			copy(m.sig[:], p.data)
			return data, nil
		case fieldNameCaveatId:
			if cav.Id != nil {
				m.caveats = append(m.caveats, cav)
				cav = Caveat{}
			}
			cav.Id = p.data
		case fieldNameVerificationId:
			if cav.VerificationId != nil {
				return nil, fmt.Errorf("repeated field %q in caveat", fieldNameVerificationId)
			}
			cav.VerificationId = p.data
		case fieldNameCaveatLocation:
			if cav.Location != "" {
				return nil, fmt.Errorf("repeated field %q in caveat", fieldNameLocation)
			}
			cav.Location = string(p.data)
		default:
			return nil, fmt.Errorf("unexpected field %q", field)
		}
	}
}

func expectPacketV1(data []byte, kind string) (packetV1, error) {
	p, err := parsePacketV1(data)
	if err != nil {
		return packetV1{}, err
	}
	if field := string(p.fieldName); field != kind {
		return packetV1{}, fmt.Errorf("unexpected field %q; expected %s", field, kind)
	}
	return p, nil
}

// appendBinaryV1 appends the binary encoding of m to data.
func (m *Macaroon) appendBinaryV1(data []byte) ([]byte, error) {
	var ok bool
	data, ok = appendPacketV1(data, fieldNameLocation, []byte(m.location))
	if !ok {
		return nil, fmt.Errorf("failed to append location to macaroon, packet is too long")
	}
	data, ok = appendPacketV1(data, fieldNameIdentifier, m.id)
	if !ok {
		return nil, fmt.Errorf("failed to append identifier to macaroon, packet is too long")
	}
	for _, cav := range m.caveats {
		data, ok = appendPacketV1(data, fieldNameCaveatId, cav.Id)
		if !ok {
			return nil, fmt.Errorf("failed to append caveat id to macaroon, packet is too long")
		}
		if cav.VerificationId == nil {
			continue
		}
		data, ok = appendPacketV1(data, fieldNameVerificationId, cav.VerificationId)
		if !ok {
			return nil, fmt.Errorf("failed to append verification id to macaroon, packet is too long")
		}
		data, ok = appendPacketV1(data, fieldNameCaveatLocation, []byte(cav.Location))
		if !ok {
			return nil, fmt.Errorf("failed to append verification id to macaroon, packet is too long")
		}
	}
	data, ok = appendPacketV1(data, fieldNameSignature, m.sig[:])
	if !ok {
		return nil, fmt.Errorf("failed to append signature to macaroon, packet is too long")
	}
	return data, nil
}
