// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build appengine

package btcutil

import (
	"net"
)

// interfaceAddrs returns a list of the system's network interface addresses.
// It is wrapped here so that we can substitute it for a no-op function that
// returns an empty slice of net.Addr when building for systems that do not
// allow access to net.InterfaceAddrs().
func interfaceAddrs() ([]net.Addr, error) {
	return []net.Addr{}, nil
}
