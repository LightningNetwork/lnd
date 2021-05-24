package lncfg

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tor"
)

var (
	loopBackAddrs = []string{"localhost", "127.0.0.1", "[::1]"}
)

// TCPResolver is a function signature that resolves an address on a given
// network.
type TCPResolver = func(network, addr string) (*net.TCPAddr, error)

// NormalizeAddresses returns a new slice with all the passed addresses
// normalized with the given default port and all duplicates removed.
func NormalizeAddresses(addrs []string, defaultPort string,
	tcpResolver TCPResolver) ([]net.Addr, error) {

	result := make([]net.Addr, 0, len(addrs))
	seen := map[string]struct{}{}

	for _, addr := range addrs {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, tcpResolver,
		)
		if err != nil {
			return nil, err
		}

		if _, ok := seen[parsedAddr.String()]; !ok {
			result = append(result, parsedAddr)
			seen[parsedAddr.String()] = struct{}{}
		}
	}

	return result, nil
}

// EnforceSafeAuthentication enforces "safe" authentication taking into account
// the interfaces that the RPC servers are listening on, and if macaroons and
// TLS is activated or not. To protect users from using dangerous config
// combinations, we'll prevent disabling authentication if the server is
// listening on a public interface.
func EnforceSafeAuthentication(addrs []net.Addr, macaroonsActive,
	tlsActive bool) error {

	// We'll now examine all addresses that this RPC server is listening
	// on. If it's a localhost address or a private address, we'll skip it,
	// otherwise, we'll return an error if macaroons are inactive.
	for _, addr := range addrs {
		if IsLoopback(addr.String()) || IsUnix(addr) || IsPrivate(addr) {
			continue
		}

		if !macaroonsActive {
			return fmt.Errorf("detected RPC server listening on "+
				"publicly reachable interface %v with "+
				"authentication disabled! Refusing to start "+
				"with --no-macaroons specified", addr)
		}

		if !tlsActive {
			return fmt.Errorf("detected RPC server listening on "+
				"publicly reachable interface %v with "+
				"encryption disabled! Refusing to start "+
				"with --no-rest-tls specified", addr)
		}
	}

	return nil
}

// parseNetwork parses the network type of the given address.
func parseNetwork(addr net.Addr) string {
	switch addr := addr.(type) {
	// TCP addresses resolved through net.ResolveTCPAddr give a default
	// network of "tcp", so we'll map back the correct network for the given
	// address. This ensures that we can listen on the correct interface
	// (IPv4 vs IPv6).
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return "tcp4"
		}
		return "tcp6"

	default:
		return addr.Network()
	}
}

// ListenOnAddress creates a listener that listens on the given address.
func ListenOnAddress(addr net.Addr) (net.Listener, error) {
	return net.Listen(parseNetwork(addr), addr.String())
}

// TLSListenOnAddress creates a TLS listener that listens on the given address.
func TLSListenOnAddress(addr net.Addr,
	config *tls.Config) (net.Listener, error) {
	return tls.Listen(parseNetwork(addr), addr.String(), config)
}

// IsLoopback returns true if an address describes a loopback interface.
func IsLoopback(addr string) bool {
	for _, loopback := range loopBackAddrs {
		if strings.Contains(addr, loopback) {
			return true
		}
	}

	return false
}

// isIPv6Host returns true if the host is IPV6 and false otherwise.
func isIPv6Host(host string) bool {
	v6Addr := net.ParseIP(host)
	if v6Addr == nil {
		return false
	}

	// The documentation states that if the IP address is an IPv6 address,
	// then To4() will return nil.
	return v6Addr.To4() == nil
}

// IsUnix returns true if an address describes an Unix socket address.
func IsUnix(addr net.Addr) bool {
	return strings.HasPrefix(addr.Network(), "unix")
}

// IsPrivate returns true if the address is private. The definitions are,
//   https://en.wikipedia.org/wiki/Link-local_address
//   https://en.wikipedia.org/wiki/Multicast_address
//   Local IPv4 addresses, https://tools.ietf.org/html/rfc1918
//   Local IPv6 addresses, https://tools.ietf.org/html/rfc4193
func IsPrivate(addr net.Addr) bool {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		// Check 169.254.0.0/16 and fe80::/10.
		if addr.IP.IsLinkLocalUnicast() {
			return true
		}

		// Check 224.0.0.0/4 and ff00::/8.
		if addr.IP.IsLinkLocalMulticast() {
			return true
		}

		// Check 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
		if ip4 := addr.IP.To4(); ip4 != nil {
			return ip4[0] == 10 ||
				(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
				(ip4[0] == 192 && ip4[1] == 168)
		}

		// Check fc00::/7.
		return len(addr.IP) == net.IPv6len && addr.IP[0]&0xfe == 0xfc

	default:
		return false
	}
}

// ParseAddressString converts an address in string format to a net.Addr that is
// compatible with lnd. UDP is not supported because lnd needs reliable
// connections. We accept a custom function to resolve any TCP addresses so
// that caller is able control exactly how resolution is performed.
func ParseAddressString(strAddress string, defaultPort string,
	tcpResolver TCPResolver) (net.Addr, error) {

	var parsedNetwork, parsedAddr string

	// Addresses can either be in network://address:port format,
	// network:address:port, address:port, or just port. We want to support
	// all possible types.
	if strings.Contains(strAddress, "://") {
		parts := strings.Split(strAddress, "://")
		parsedNetwork, parsedAddr = parts[0], parts[1]
	} else if strings.Contains(strAddress, ":") {
		parts := strings.Split(strAddress, ":")
		parsedNetwork = parts[0]
		parsedAddr = strings.Join(parts[1:], ":")
	}

	// Only TCP and Unix socket addresses are valid. We can't use IP or
	// UDP only connections for anything we do in lnd.
	switch parsedNetwork {
	case "unix", "unixpacket":
		return net.ResolveUnixAddr(parsedNetwork, parsedAddr)

	case "tcp", "tcp4", "tcp6":
		return tcpResolver(
			parsedNetwork, verifyPort(parsedAddr, defaultPort),
		)

	case "ip", "ip4", "ip6", "udp", "udp4", "udp6", "unixgram":
		return nil, fmt.Errorf("only TCP or unix socket "+
			"addresses are supported: %s", parsedAddr)

	default:
		// We'll now possibly apply the default port, use the local
		// host short circuit, or parse out an all interfaces listen.
		addrWithPort := verifyPort(strAddress, defaultPort)
		rawHost, rawPort, _ := net.SplitHostPort(addrWithPort)

		// If we reach this point, then we'll check to see if we have
		// an onion addresses, if so, we can directly pass the raw
		// address and port to create the proper address.
		if tor.IsOnionHost(rawHost) {
			portNum, err := strconv.Atoi(rawPort)
			if err != nil {
				return nil, err
			}

			return &tor.OnionAddr{
				OnionService: rawHost,
				Port:         portNum,
			}, nil
		}

		// Otherwise, we'll attempt the resolve the host. The Tor
		// resolver is unable to resolve local or IPv6 addresses, so
		// we'll use the system resolver instead.
		if rawHost == "" || IsLoopback(rawHost) ||
			isIPv6Host(rawHost) {

			return net.ResolveTCPAddr("tcp", addrWithPort)
		}

		// If we've reached this point, then it's possible that this
		// resolve returns an error if it isn't able to resolve the
		// host. For eaxmple, local entries in /etc/hosts will fail to
		// be resolved by Tor. In order to handle this case, we'll fall
		// back to the normal system resolver if we fail with an
		// identifiable error.
		addr, err := tcpResolver("tcp", addrWithPort)
		if err != nil {
			switch err.Error() {
			case "tor host is unreachable",
				"tor general error",
				"tor general failure":

				return net.ResolveTCPAddr("tcp", addrWithPort)
			default:
				return nil, err
			}
		}

		return addr, nil
	}
}

// ParseLNAddressString converts a string of the form <pubkey>@<addr> into an
// lnwire.NetAddress. The <pubkey> must be presented in hex, and result in a
// 33-byte, compressed public key that lies on the secp256k1 curve. The <addr>
// may be any address supported by ParseAddressString. If no port is specified,
// the defaultPort will be used. Any tcp addresses that need resolving will be
// resolved using the custom TCPResolver.
func ParseLNAddressString(strAddress string, defaultPort string,
	tcpResolver TCPResolver) (*lnwire.NetAddress, error) {

	// Split the address string around the @ sign.
	parts := strings.Split(strAddress, "@")

	// The string is malformed if there are not exactly two parts.
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid lightning address %s: "+
			"must be of the form <pubkey-hex>@<addr>", strAddress)
	}

	// Now, take the first portion as the hex pubkey, and the latter as the
	// address string.
	parsedPubKey, parsedAddr := parts[0], parts[1]

	// Decode the hex pubkey to get the raw compressed pubkey bytes.
	pubKeyBytes, err := hex.DecodeString(parsedPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid lightning address pubkey: %v", err)
	}

	// The compressed pubkey should have a length of exactly 33 bytes.
	if len(pubKeyBytes) != 33 {
		return nil, fmt.Errorf("invalid lightning address pubkey: "+
			"length must be 33 bytes, found %d", len(pubKeyBytes))
	}

	// Parse the pubkey bytes to verify that it corresponds to valid public
	// key on the secp256k1 curve.
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("invalid lightning address pubkey: %v", err)
	}

	// Finally, parse the address string using our generic address parser.
	addr, err := ParseAddressString(parsedAddr, defaultPort, tcpResolver)
	if err != nil {
		return nil, fmt.Errorf("invalid lightning address address: %v", err)
	}

	return &lnwire.NetAddress{
		IdentityKey: pubKey,
		Address:     addr,
	}, nil
}

// verifyPort makes sure that an address string has both a host and a port. If
// there is no port found, the default port is appended. If the address is just
// a port, then we'll assume that the user is using the short cut to specify a
// localhost:port address.
func verifyPort(address string, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If the address itself is just an integer, then we'll assume
		// that we're mapping this directly to a localhost:port pair.
		// This ensures we maintain the legacy behavior.
		if _, err := strconv.Atoi(address); err == nil {
			return net.JoinHostPort("localhost", address)
		}

		// Otherwise, we'll assume that the address just failed to
		// attach its own port, so we'll use the default port. In the
		// case of IPv6 addresses, if the host is already surrounded by
		// brackets, then we'll avoid using the JoinHostPort function,
		// since it will always add a pair of brackets.
		if strings.HasPrefix(address, "[") {
			return address + ":" + defaultPort
		}
		return net.JoinHostPort(address, defaultPort)
	}

	// In the case that both the host and port are empty, we'll use the
	// default port.
	if host == "" && port == "" {
		return ":" + defaultPort
	}

	return address
}

// ClientAddressDialer creates a gRPC dialer that can also dial unix socket
// addresses instead of just TCP addresses.
func ClientAddressDialer(defaultPort string) func(context.Context,
	string) (net.Conn, error) {

	return func(ctx context.Context, addr string) (net.Conn, error) {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, net.ResolveTCPAddr,
		)
		if err != nil {
			return nil, err
		}

		d := net.Dialer{}
		return d.DialContext(
			ctx, parsedAddr.Network(), parsedAddr.String(),
		)
	}
}
