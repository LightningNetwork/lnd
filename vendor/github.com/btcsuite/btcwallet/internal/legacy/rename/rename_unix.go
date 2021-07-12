// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build !windows,!plan9

package rename

import (
	"os"
)

// Atomic provides an atomic file rename.  newpath is replaced if it
// already exists.
func Atomic(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
