// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

// maxNetAddressPayload returns the max payload size for a bitcoin NetAddress
// based on the protocol version.
func maxNetAddressPayload(pver uint32) uint32 {
	// Services 8 bytes + ip 16 bytes + port 2 bytes.
	plen := uint32(26)

	// NetAddressTimeVersion added a timestamp field.
	if pver >= NetAddressTimeVersion {
		// Timestamp 4 bytes.
		plen += 4
	}

	return plen
}

// NetAddress defines information about a peer on the network including the time
// it was last seen, the services it supports, its IP address, and port.
type NetAddress struct {
	// Last time the address was seen.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.  This field is
	// not present in the bitcoin version message (MsgVersion) nor was it
	// added until protocol version >= NetAddressTimeVersion.
	Timestamp time.Time

	// Bitfield which identifies the services supported by the address.
	Services ServiceFlag

	// IP address of the peer.
	IP net.IP

	// Port the peer is using.  This is encoded in big endian on the wire
	// which differs from most everything else.
	Port uint16
}

// HasService returns whether the specified service is supported by the address.
func (na *NetAddress) HasService(service ServiceFlag) bool {
	return na.Services&service == service
}

// AddService adds service as a supported service by the peer generating the
// message.
func (na *NetAddress) AddService(service ServiceFlag) {
	na.Services |= service
}

// NewNetAddressIPPort returns a new NetAddress using the provided IP, port, and
// supported services with defaults for the remaining fields.
func NewNetAddressIPPort(ip net.IP, port uint16, services ServiceFlag) *NetAddress {
	return NewNetAddressTimestamp(time.Now(), services, ip, port)
}

// NewNetAddressTimestamp returns a new NetAddress using the provided
// timestamp, IP, port, and supported services. The timestamp is rounded to
// single second precision.
func NewNetAddressTimestamp(
	timestamp time.Time, services ServiceFlag, ip net.IP, port uint16) *NetAddress {
	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	na := NetAddress{
		Timestamp: time.Unix(timestamp.Unix(), 0),
		Services:  services,
		IP:        ip,
		Port:      port,
	}
	return &na
}

// NewNetAddress returns a new NetAddress using the provided TCP address and
// supported services with defaults for the remaining fields.
func NewNetAddress(addr *net.TCPAddr, services ServiceFlag) *NetAddress {
	return NewNetAddressIPPort(addr.IP, uint16(addr.Port), services)
}

// readNetAddress reads an encoded NetAddress from r depending on the protocol
// version and whether or not the timestamp is included per ts.  Some messages
// like version do not include the timestamp.
func readNetAddress(r io.Reader, pver uint32, na *NetAddress, ts bool) error {
	var ip [16]byte

	// NOTE: The bitcoin protocol uses a uint32 for the timestamp so it will
	// stop working somewhere around 2106.  Also timestamp wasn't added until
	// protocol version >= NetAddressTimeVersion
	if ts && pver >= NetAddressTimeVersion {
		err := readElement(r, (*uint32Time)(&na.Timestamp))
		if err != nil {
			return err
		}
	}

	err := readElements(r, &na.Services, &ip)
	if err != nil {
		return err
	}
	// Sigh.  Bitcoin protocol mixes little and big endian.
	port, err := binarySerializer.Uint16(r, bigEndian)
	if err != nil {
		return err
	}

	*na = NetAddress{
		Timestamp: na.Timestamp,
		Services:  na.Services,
		IP:        net.IP(ip[:]),
		Port:      port,
	}
	return nil
}

// writeNetAddress serializes a NetAddress to w depending on the protocol
// version and whether or not the timestamp is included per ts.  Some messages
// like version do not include the timestamp.
func writeNetAddress(w io.Writer, pver uint32, na *NetAddress, ts bool) error {
	// NOTE: The bitcoin protocol uses a uint32 for the timestamp so it will
	// stop working somewhere around 2106.  Also timestamp wasn't added until
	// until protocol version >= NetAddressTimeVersion.
	if ts && pver >= NetAddressTimeVersion {
		err := writeElement(w, uint32(na.Timestamp.Unix()))
		if err != nil {
			return err
		}
	}

	// Ensure to always write 16 bytes even if the ip is nil.
	var ip [16]byte
	if na.IP != nil {
		copy(ip[:], na.IP.To16())
	}
	err := writeElements(w, na.Services, ip)
	if err != nil {
		return err
	}

	// Sigh.  Bitcoin protocol mixes little and big endian.
	return binary.Write(w, bigEndian, na.Port)
}
