// Copyright 2012 Samuel Stauffer. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

/*
Current limitations:

	- GSS-API authentication is not supported
	- only SOCKS version 5 is supported
	- TCP bind and UDP not yet supported

Example http client over SOCKS5:

	proxy := &socks.Proxy{"127.0.0.1:1080"}
	tr := &http.Transport{
		Dial: proxy.Dial,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://example.com")
*/
package socks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	protocolVersion = 5

	defaultPort = 1080

	authNone             = 0
	authGssApi           = 1
	authUsernamePassword = 2
	authUnavailable      = 0xff

	commandTcpConnect   = 1
	commandTcpBind      = 2
	commandUdpAssociate = 3

	addressTypeIPv4   = 1
	addressTypeDomain = 3
	addressTypeIPv6   = 4

	statusRequestGranted          = 0
	statusGeneralFailure          = 1
	statusConnectionNotAllowed    = 2
	statusNetworkUnreachable      = 3
	statusHostUnreachable         = 4
	statusConnectionRefused       = 5
	statusTtlExpired              = 6
	statusCommandNotSupport       = 7
	statusAddressTypeNotSupported = 8
)

var (
	ErrAuthFailed             = errors.New("authentication failed")
	ErrInvalidProxyResponse   = errors.New("invalid proxy response")
	ErrNoAcceptableAuthMethod = errors.New("no acceptable authentication method")

	statusErrors = map[byte]error{
		statusGeneralFailure:          errors.New("general failure"),
		statusConnectionNotAllowed:    errors.New("connection not allowed by ruleset"),
		statusNetworkUnreachable:      errors.New("network unreachable"),
		statusHostUnreachable:         errors.New("host unreachable"),
		statusConnectionRefused:       errors.New("connection refused by destination host"),
		statusTtlExpired:              errors.New("TTL expired"),
		statusCommandNotSupport:       errors.New("command not supported / protocol error"),
		statusAddressTypeNotSupported: errors.New("address type not supported"),
	}
)

type Proxy struct {
	Addr         string
	Username     string
	Password     string
	TorIsolation bool
}

func (p *Proxy) Dial(network, addr string) (net.Conn, error) {
	return p.dial(network, addr, 0)
}

func (p *Proxy) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return p.dial(network, addr, timeout)
}

func (p *Proxy) dial(network, addr string, timeout time.Duration) (net.Conn, error) {
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", p.Addr, timeout)
	if err != nil {
		return nil, err
	}

	var user, pass string
	if p.TorIsolation {
		var b [16]byte
		_, err := io.ReadFull(rand.Reader, b[:])
		if err != nil {
			conn.Close()
			return nil, err
		}
		user = hex.EncodeToString(b[0:8])
		pass = hex.EncodeToString(b[8:16])
	} else {
		user = p.Username
		pass = p.Password
	}
	buf := make([]byte, 32+len(host)+len(user)+len(pass))

	// Initial greeting
	buf[0] = protocolVersion
	if user != "" {
		buf = buf[:4]
		buf[1] = 2 // num auth methods
		buf[2] = authNone
		buf[3] = authUsernamePassword
	} else {
		buf = buf[:3]
		buf[1] = 1 // num auth methods
		buf[2] = authNone
	}

	_, err = conn.Write(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Server's auth choice

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != protocolVersion {
		conn.Close()
		return nil, ErrInvalidProxyResponse
	}
	err = nil
	switch buf[1] {
	default:
		err = ErrInvalidProxyResponse
	case authUnavailable:
		err = ErrNoAcceptableAuthMethod
	case authGssApi:
		err = ErrNoAcceptableAuthMethod
	case authUsernamePassword:
		buf = buf[:3+len(user)+len(pass)]
		buf[0] = 1 // version
		buf[1] = byte(len(user))
		copy(buf[2:], user)
		buf[2+len(user)] = byte(len(pass))
		copy(buf[3+len(user):], pass)
		if _, err = conn.Write(buf); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err = io.ReadFull(conn, buf[:2]); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[0] != 1 { // version
			err = ErrInvalidProxyResponse
		} else if buf[1] != 0 { // 0 = succes, else auth failed
			err = ErrAuthFailed
		}
	case authNone:
		// Do nothing
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Command / connection request

	buf = buf[:7+len(host)]
	buf[0] = protocolVersion
	buf[1] = commandTcpConnect
	buf[2] = 0 // reserved
	buf[3] = addressTypeDomain
	buf[4] = byte(len(host))
	copy(buf[5:], host)
	buf[5+len(host)] = byte(port >> 8)
	buf[6+len(host)] = byte(port & 0xff)
	if _, err := conn.Write(buf); err != nil {
		conn.Close()
		return nil, err
	}

	// Server response

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		conn.Close()
		return nil, err
	}

	if buf[0] != protocolVersion {
		conn.Close()
		return nil, ErrInvalidProxyResponse
	}

	if buf[1] != statusRequestGranted {
		conn.Close()
		err := statusErrors[buf[1]]
		if err == nil {
			err = ErrInvalidProxyResponse
		}
		return nil, err
	}

	paddr := &ProxiedAddr{Net: network}

	switch buf[3] {
	default:
		conn.Close()
		return nil, ErrInvalidProxyResponse
	case addressTypeIPv4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			conn.Close()
			return nil, err
		}
		paddr.Host = net.IP(buf).String()
	case addressTypeIPv6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			conn.Close()
			return nil, err
		}
		paddr.Host = net.IP(buf).String()
	case addressTypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			conn.Close()
			return nil, err
		}
		domainLen := buf[0]
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			conn.Close()
			return nil, err
		}
		paddr.Host = string(buf[:domainLen])
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		conn.Close()
		return nil, err
	}
	paddr.Port = int(buf[0])<<8 | int(buf[1])

	return &proxiedConn{
		conn:       conn,
		boundAddr:  paddr,
		remoteAddr: &ProxiedAddr{network, host, port},
	}, nil
}
