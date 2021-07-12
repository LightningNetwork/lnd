// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletdbtest

// Tester is an interface type that can be implemented by *testing.T.  This
// allows drivers to call into the non-test API using their own test contexts.
type Tester interface {
	Error(...interface{})
	Errorf(string, ...interface{})
	Fail()
	FailNow()
	Failed() bool
	Fatal(...interface{})
	Fatalf(string, ...interface{})
	Log(...interface{})
	Logf(string, ...interface{})
	Parallel()
	Skip(...interface{})
	SkipNow()
	Skipf(string, ...interface{})
	Skipped() bool
}
