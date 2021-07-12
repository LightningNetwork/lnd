// Package macaroonpb is an internal package that allows us to hide the internal
// serialization details of macaroon ids.
package macaroonpb

import (
	"github.com/golang/protobuf/proto"
)

//go:generate  protoc --go_out . id.proto

// MarshalBinary implements encoding.BinaryMarshal.
func (id *MacaroonId) MarshalBinary() ([]byte, error) {
	return proto.Marshal(id)
}

// UnmarshalBinary implements encoding.UnmarshalBinary.
func (id *MacaroonId) UnmarshalBinary(data []byte) error {
	return proto.Unmarshal(data, id)
}
