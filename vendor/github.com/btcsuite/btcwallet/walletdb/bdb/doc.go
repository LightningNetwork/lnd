// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package bdb implements an instance of walletdb that uses boltdb for the backing
datastore.

Usage

This package is only a driver to the walletdb package and provides the database
type of "bdb". The only parameters the Open and Create functions take is the
database path as a string, and an option for the database to not sync its
freelist to disk as a bool:

	db, err := walletdb.Open("bdb", "path/to/database.db", true)
	if err != nil {
		// Handle error
	}

	db, err := walletdb.Create("bdb", "path/to/database.db", true)
	if err != nil {
		// Handle error
	}
*/
package bdb
