package postgres

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	dbType = "postgres"
)

// parseArgs parses the arguments from the walletdb Open/Create methods.
func parseArgs(funcName string, args ...interface{}) (context.Context,
	*Config, string, error) {

	if len(args) != 3 {
		return nil, nil, "", fmt.Errorf("invalid number of arguments "+
			"to %s.%s -- expected: context.Context, "+
			"postgres.Config, string", dbType, funcName,
		)
	}

	ctx, ok := args[0].(context.Context)
	if !ok {
		return nil, nil, "", fmt.Errorf("argument 0 to %s.%s is "+
			"invalid -- expected: context.Context",
			dbType, funcName,
		)
	}

	config, ok := args[1].(*Config)
	if !ok {
		return nil, nil, "", fmt.Errorf("argument 1 to %s.%s is "+
			"invalid -- expected: postgres.Config",
			dbType, funcName,
		)
	}

	prefix, ok := args[2].(string)
	if !ok {
		return nil, nil, "", fmt.Errorf("argument 2 to %s.%s is "+
			"invalid -- expected string", dbType,
			funcName)
	}

	return ctx, config, prefix, nil
}

// createDBDriver is the callback provided during driver registration that
// creates, initializes, and opens a database for use.
func createDBDriver(args ...interface{}) (walletdb.DB, error) {
	ctx, config, prefix, err := parseArgs("Create", args...)
	if err != nil {
		return nil, err
	}

	return newPostgresBackend(ctx, config.Dsn, prefix)
}

// openDBDriver is the callback provided during driver registration that opens
// an existing database for use.
func openDBDriver(args ...interface{}) (walletdb.DB, error) {
	ctx, config, prefix, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}

	return newPostgresBackend(ctx, config.Dsn, prefix)
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
