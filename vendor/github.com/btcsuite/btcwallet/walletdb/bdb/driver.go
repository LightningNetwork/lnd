// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"fmt"

	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	dbType = "bdb"
)

// parseArgs parses the arguments from the walletdb Open/Create methods.
func parseArgs(funcName string, args ...interface{}) (string, bool, error) {
	if len(args) != 2 {
		return "", false, fmt.Errorf("invalid arguments to %s.%s -- "+
			"expected database path and no-freelist-sync option",
			dbType, funcName)
	}

	dbPath, ok := args[0].(string)
	if !ok {
		return "", false, fmt.Errorf("first argument to %s.%s is "+
			"invalid -- expected database path string", dbType,
			funcName)
	}

	noFreelistSync, ok := args[1].(bool)
	if !ok {
		return "", false, fmt.Errorf("second argument to %s.%s is "+
			"invalid -- expected no-freelist-sync bool", dbType,
			funcName)
	}

	return dbPath, noFreelistSync, nil
}

// openDBDriver is the callback provided during driver registration that opens
// an existing database for use.
func openDBDriver(args ...interface{}) (walletdb.DB, error) {
	dbPath, noFreelistSync, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbPath, noFreelistSync, false)
}

// createDBDriver is the callback provided during driver registration that
// creates, initializes, and opens a database for use.
func createDBDriver(args ...interface{}) (walletdb.DB, error) {
	dbPath, noFreelistSync, err := parseArgs("Create", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbPath, noFreelistSync, true)
}

func init() {
	// Register the driver.
	driver := walletdb.Driver{
		DbType: dbType,
		Create: createDBDriver,
		Open:   openDBDriver,
	}
	if err := walletdb.RegisterDriver(driver); err != nil {
		panic(fmt.Sprintf("Failed to regiser database driver '%s': %v",
			dbType, err))
	}
}
