// Copyright 2012 Samuel Stauffer. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

package socks

import (
	"net"
	"time"
)

type proxiedConn struct {
	conn       net.Conn
	remoteAddr *ProxiedAddr
	boundAddr  *ProxiedAddr
}

func (c *proxiedConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *proxiedConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *proxiedConn) Close() error {
	return c.conn.Close()
}

func (c *proxiedConn) LocalAddr() net.Addr {
	if c.boundAddr != nil {
		return c.boundAddr
	}
	return c.conn.LocalAddr()
}

func (c *proxiedConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.conn.RemoteAddr()
}

func (c *proxiedConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *proxiedConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *proxiedConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
