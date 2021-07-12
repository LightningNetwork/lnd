package banman

import (
	"net"
)

var (
	// defaultIPv4Mask is the default IPv4 mask used when parsing IP
	// networks from an address. This ensures that the IP network only
	// contains *one* IP address -- the one specified.
	defaultIPv4Mask = net.CIDRMask(32, 32)

	// defaultIPv6Mask is the default IPv6 mask used when parsing IP
	// networks from an address. This ensures that the IP network only
	// contains *one* IP address -- the one specified.
	defaultIPv6Mask = net.CIDRMask(128, 128)
)

// ParseIPNet parses the IP network that contains the given address. An optional
// mask can be provided, to expand the scope of the IP network, otherwise the
// IP's default is used.
//
// NOTE: This assumes that the address has already been resolved.
func ParseIPNet(addr string, mask net.IPMask) (*net.IPNet, error) {
	// If the address includes a port, we'll remove it.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Address doesn't include a port.
		host = addr
	}

	// Parse the IP from the host to ensure it is supported.
	ip := net.ParseIP(host)
	switch {
	case ip.To4() != nil:
		if mask == nil {
			mask = defaultIPv4Mask
		}
	case ip.To16() != nil:
		if mask == nil {
			mask = defaultIPv6Mask
		}
	default:
		return nil, ErrUnsupportedIP
	}

	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}
