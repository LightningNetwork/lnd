package banman

import (
	"io"
	"net"
)

// ipType represents the different types of IP addresses supported by the
// BanStore interface.
type ipType = byte

const (
	// ipv4 represents an IP address of type IPv4.
	ipv4 ipType = 0

	// ipv6 represents an IP address of type IPv6.
	ipv6 ipType = 1
)

// encodeIPNet serializes the IP network into the given reader.
func encodeIPNet(w io.Writer, ipNet *net.IPNet) error {
	// Determine the appropriate IP type for the IP address contained in the
	// network.
	var (
		ip     []byte
		ipType ipType
	)
	switch {
	case ipNet.IP.To4() != nil:
		ip = ipNet.IP.To4()
		ipType = ipv4
	case ipNet.IP.To16() != nil:
		ip = ipNet.IP.To16()
		ipType = ipv6
	default:
		return ErrUnsupportedIP
	}

	// Write the IP type first in order to properly identify it when
	// deserializing it, followed by the IP itself and its mask.
	if _, err := w.Write([]byte{ipType}); err != nil {
		return err
	}
	if _, err := w.Write(ip); err != nil {
		return err
	}
	if _, err := w.Write([]byte(ipNet.Mask)); err != nil {
		return err
	}

	return nil
}

// decodeIPNet deserialized an IP network from the given reader.
func decodeIPNet(r io.Reader) (*net.IPNet, error) {
	// Read the IP address type and determine whether it is supported.
	var ipType [1]byte
	if _, err := r.Read(ipType[:]); err != nil {
		return nil, err
	}

	var ipLen int
	switch ipType[0] {
	case ipv4:
		ipLen = net.IPv4len
	case ipv6:
		ipLen = net.IPv6len
	default:
		return nil, ErrUnsupportedIP
	}

	// Once we have the type and its corresponding length, attempt to read
	// it and its mask.
	ip := make([]byte, ipLen)
	if _, err := r.Read(ip[:]); err != nil {
		return nil, err
	}
	mask := make([]byte, ipLen)
	if _, err := r.Read(mask[:]); err != nil {
		return nil, err
	}
	return &net.IPNet{IP: ip, Mask: mask}, nil
}
