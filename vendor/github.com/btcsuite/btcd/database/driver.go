// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"fmt"

	"github.com/btcsuite/btclog"
)

// Driver defines a structure for backend drivers to use when they registered
// themselves as a backend which implements the DB interface.
type Driver struct {
	// DbType is the identifier used to uniquely identify a specific
	// database driver.  There can be only one driver with the same name.
	DbType string

	// Create is the function that will be invoked with all user-specified
	// arguments to create the database.  This function must return
	// ErrDbExists if the database already exists.
	Create func(args ...interface{}) (DB, error)

	// Open is the function that will be invoked with all user-specified
	// arguments to open the database.  This function must return
	// ErrDbDoesNotExist if the database has not already been created.
	Open func(args ...interface{}) (DB, error)

	// UseLogger uses a specified Logger to output package logging info.
	UseLogger func(logger btclog.Logger)
}

// driverList holds all of the registered database backends.
var drivers = make(map[string]*Driver)

// RegisterDriver adds a backend database driver to available interfaces.
// ErrDbTypeRegistered will be returned if the database type for the driver has
// already been registered.
func RegisterDriver(driver Driver) error {
	if _, exists := drivers[driver.DbType]; exists {
		str := fmt.Sprintf("driver %q is already registered",
			driver.DbType)
		return makeError(ErrDbTypeRegistered, str, nil)
	}

	drivers[driver.DbType] = &driver
	return nil
}

// SupportedDrivers returns a slice of strings that represent the database
// drivers that have been registered and are therefore supported.
func SupportedDrivers() []string {
	supportedDBs := make([]string, 0, len(drivers))
	for _, drv := range drivers {
		supportedDBs = append(supportedDBs, drv.DbType)
	}
	return supportedDBs
}

// Create initializes and opens a database for the specified type.  The
// arguments are specific to the database type driver.  See the documentation
// for the database driver for further details.
//
// ErrDbUnknownType will be returned if the the database type is not registered.
func Create(dbType string, args ...interface{}) (DB, error) {
	drv, exists := drivers[dbType]
	if !exists {
		str := fmt.Sprintf("driver %q is not registered", dbType)
		return nil, makeError(ErrDbUnknownType, str, nil)
	}

	return drv.Create(args...)
}

// Open opens an existing database for the specified type.  The arguments are
// specific to the database type driver.  See the documentation for the database
// driver for further details.
//
// ErrDbUnknownType will be returned if the the database type is not registered.
func Open(dbType string, args ...interface{}) (DB, error) {
	drv, exists := drivers[dbType]
	if !exists {
		str := fmt.Sprintf("driver %q is not registered", dbType)
		return nil, makeError(ErrDbUnknownType, str, nil)
	}

	return drv.Open(args...)
}
