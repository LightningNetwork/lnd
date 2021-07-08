package tor

import (
	"encoding/base32"
	"net"
	"strconv"
)

const (
	// base32Alphabet is the alphabet used for encoding and decoding v2 and
	// v3 onion addresses.
	base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

	// OnionSuffix is the ".onion" suffix for v2 and v3 onion addresses.
	OnionSuffix = ".onion"

	// OnionSuffixLen is the length of the ".onion" suffix.
	OnionSuffixLen = len(OnionSuffix)

	// V2DecodedLen is the length of a decoded v2 onion service.
	V2DecodedLen = 10

	// V2Len is the length of a v2 onion service including the ".onion"
	// suffix.
	V2Len = 22

	// V3DecodedLen is the length of a decoded v3 onion service.
	V3DecodedLen = 35

	// V3Len is the length of a v2 onion service including the ".onion"
	// suffix.
	V3Len = 62
)

var (
	// Base32Encoding represents the Tor's base32-encoding scheme for v2 and
	// v3 onion addresses.
	Base32Encoding = base32.NewEncoding(base32Alphabet)
)

// OnionAddr represents a Tor network end point onion address.
type OnionAddr struct {
	// OnionService is the host of the onion address.
	OnionService string

	// Port is the port of the onion address.
	Port int

	// PrivateKey is the onion address' private key. Only returned if requested.
	PrivateKey string
}

// A compile-time check to ensure that OnionAddr implements the net.Addr
// interface.
var _ net.Addr = (*OnionAddr)(nil)

// String returns the string representation of an onion address.
func (o *OnionAddr) String() string {
	return net.JoinHostPort(o.OnionService, strconv.Itoa(o.Port))
}

// Network returns the network that this implementation of net.Addr will use.
// In this case, because Tor only allows TCP connections, the network is "tcp".
func (o *OnionAddr) Network() string {
	return "tcp"
}
