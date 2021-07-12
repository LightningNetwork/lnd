// Copyright 2012 Samuel Stauffer. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

package socks

import "fmt"

type ProxiedAddr struct {
	Net  string
	Host string
	Port int
}

func (a *ProxiedAddr) Network() string {
	return a.Net
}

func (a *ProxiedAddr) String() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}
