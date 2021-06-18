package lnwire

import (
	"bytes"
	"fmt"
	"image/color"
	"io"
	"net"
	"unicode/utf8"
)

// ErrUnknownAddrType is an error returned if we encounter an unknown address type
// when parsing addresses.
type ErrUnknownAddrType struct {
	addrType addressType
}

// Error returns a human readable string describing the error.
//
// NOTE: implements the error interface.
func (e ErrUnknownAddrType) Error() string {
	return fmt.Sprintf("unknown address type: %v", e.addrType)
}

// ErrInvalidNodeAlias is an error returned if a node alias we parse on the
// wire is invalid, as in it has non UTF-8 characters.
type ErrInvalidNodeAlias struct{}

// Error returns a human readable string describing the error.
//
// NOTE: implements the error interface.
func (e ErrInvalidNodeAlias) Error() string {
	return "node alias has non-utf8 characters"
}

// NodeAlias is a hex encoded UTF-8 string that may be displayed as an
// alternative to the node's ID. Notice that aliases are not unique and may be
// freely chosen by the node operators.
type NodeAlias [32]byte

// NewNodeAlias creates a new instance of a NodeAlias. Verification is
// performed on the passed string to ensure it meets the alias requirements.
func NewNodeAlias(s string) (NodeAlias, error) {
	var n NodeAlias

	if len(s) > 32 {
		return n, fmt.Errorf("alias too large: max is %v, got %v", 32,
			len(s))
	}

	if !utf8.ValidString(s) {
		return n, &ErrInvalidNodeAlias{}
	}

	copy(n[:], []byte(s))
	return n, nil
}

// String returns a utf8 string representation of the alias bytes.
func (n NodeAlias) String() string {
	// Trim trailing zero-bytes for presentation
	return string(bytes.Trim(n[:], "\x00"))
}

// NodeAnnouncement message is used to announce the presence of a Lightning
// node and also to signal that the node is accepting incoming connections.
// Each NodeAnnouncement authenticating the advertised information within the
// announcement via a signature using the advertised node pubkey.
type NodeAnnouncement struct {
	// Signature is used to prove the ownership of node id.
	Signature Sig

	// Features is the list of protocol features this node supports.
	Features *RawFeatureVector

	// Timestamp allows ordering in the case of multiple announcements.
	Timestamp uint32

	// NodeID is a public key which is used as node identification.
	NodeID [33]byte

	// RGBColor is used to customize their node's appearance in maps and
	// graphs
	RGBColor color.RGBA

	// Alias is used to customize their node's appearance in maps and
	// graphs
	Alias NodeAlias

	// Address includes two specification fields: 'ipv6' and 'port' on
	// which the node is accepting incoming connections.
	Addresses []net.Addr

	// ExtraOpaqueData is the set of data that was appended to this
	// message, some of which we may not actually know how to iterate or
	// parse. By holding onto this data, we ensure that we're able to
	// properly validate the set of signatures that cover these new fields,
	// and ensure we're able to make upgrades to the network in a forwards
	// compatible manner.
	ExtraOpaqueData ExtraOpaqueData
}

// A compile time check to ensure NodeAnnouncement implements the
// lnwire.Message interface.
var _ Message = (*NodeAnnouncement)(nil)

// Decode deserializes a serialized NodeAnnouncement stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (a *NodeAnnouncement) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&a.Signature,
		&a.Features,
		&a.Timestamp,
		&a.NodeID,
		&a.RGBColor,
		&a.Alias,
		&a.Addresses,
		&a.ExtraOpaqueData,
	)
}

// Encode serializes the target NodeAnnouncement into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (a *NodeAnnouncement) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteSig(w, a.Signature); err != nil {
		return err
	}

	if err := WriteRawFeatureVector(w, a.Features); err != nil {
		return err
	}

	if err := WriteUint32(w, a.Timestamp); err != nil {
		return err
	}

	if err := WriteBytes(w, a.NodeID[:]); err != nil {
		return err
	}

	if err := WriteColorRGBA(w, a.RGBColor); err != nil {
		return err
	}

	if err := WriteNodeAlias(w, a.Alias); err != nil {
		return err
	}

	if err := WriteNetAddrs(w, a.Addresses); err != nil {
		return err
	}

	return WriteBytes(w, a.ExtraOpaqueData)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (a *NodeAnnouncement) MsgType() MessageType {
	return MsgNodeAnnouncement
}

// DataToSign returns the part of the message that should be signed.
func (a *NodeAnnouncement) DataToSign() ([]byte, error) {

	// We should not include the signatures itself.
	buffer := make([]byte, 0, MaxMsgBody)
	buf := bytes.NewBuffer(buffer)

	if err := WriteRawFeatureVector(buf, a.Features); err != nil {
		return nil, err
	}

	if err := WriteUint32(buf, a.Timestamp); err != nil {
		return nil, err
	}

	if err := WriteBytes(buf, a.NodeID[:]); err != nil {
		return nil, err
	}

	if err := WriteColorRGBA(buf, a.RGBColor); err != nil {
		return nil, err
	}

	if err := WriteNodeAlias(buf, a.Alias); err != nil {
		return nil, err
	}

	if err := WriteNetAddrs(buf, a.Addresses); err != nil {
		return nil, err
	}

	if err := WriteBytes(buf, a.ExtraOpaqueData); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
