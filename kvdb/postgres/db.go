package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/jackc/pgx/v4/stdlib"
)

const (
	// hexTableId is the table name for top-level buckets data under a key
	// that cannot be mapped to a distinct table.
	hexTableId = "hex"

	// sequenceTableId is the table name that holds top-level bucket
	// sequence numbers.
	sequenceTableId = "sequence"

	// systemTablePrefixExtension is the prefix given to system tables.
	systemTablePrefixExtension = "sys"
)

// KV stores a key/value pair.
type KV struct {
	key string
	val string
}

// db holds a reference to the postgres connection connection.
type db struct {
	// dsn is the postgres connection string.
	dsn string

	// prefix is the table name prefix that is used to simulate namespaces.
	// We don't use schemas because at least sqlite does not support that.
	prefix string

	// ctx is the overall context for the database driver.
	//
	// TODO: This is an anti-pattern that is in place until the kvdb
	// interface supports a context.
	ctx context.Context

	// db is the underlying database connection instance.
	db *sql.DB

	// lock is the global write lock that ensures single writer.
	lock sync.RWMutex

	// hexTableName is the name of the table that contains the data for all
	// top-level buckets that have keys that cannot be mapped to a distinct
	// sql table.
	hexTableName string

	// sequenceTableName is the name of the table that holds the sequence
	// numbers for for all top-level buckets that have keys that cannot be
	// mapped to a distinct sql table.
	sequenceTableName string
}

// Enforce db implements the walletdb.DB interface.
var _ walletdb.DB = (*db)(nil)

// newPostgresBackend returns a db object initialized with the passed backend
// config. If postgres connection cannot be estabished, then returns error.
func newPostgresBackend(ctx context.Context, dsn, prefix string) (*db, error) {
	dbConn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	if prefix == "" {
		return nil, errors.New("empty postgres prefix")
	}

	// Compose system table names.
	hexTableName := fmt.Sprintf(
		"%s%s_%s", prefix, systemTablePrefixExtension, hexTableId,
	)

	sequenceTableName := fmt.Sprintf(
		"%s%s_%s", prefix, systemTablePrefixExtension, sequenceTableId,
	)

	hexCreateTableSql := getCreateTableSql(hexTableName)

	// Create schema and system tables.
	_, err = dbConn.ExecContext(ctx, `
	CREATE SCHEMA IF NOT EXISTS public;

	CREATE TABLE IF NOT EXISTS public.`+sequenceTableName+`
	(
		table_name TEXT NOT NULL PRIMARY KEY,
		sequence BIGINT
	);
	`+hexCreateTableSql)
	if err != nil {
		_ = dbConn.Close()

		return nil, err
	}

	backend := &db{
		dsn:               dsn,
		prefix:            prefix,
		ctx:               ctx,
		db:                dbConn,
		hexTableName:      hexTableName,
		sequenceTableName: sequenceTableName,
	}

	return backend, nil
}

// getPrefixedTableName returns a table name for this prefix (namespace).
func (db *db) getPrefixedTableName(table string) string {
	return fmt.Sprintf("%s_%s", db.prefix, table)
}

// catchPanic executes the specified function. If a panic occurs, it is returned
// as an error value.
func catchPanic(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	err = f()

	return
}

// View opens a database read transaction and executes the function f with the
// transaction passed as a parameter. After f exits, the transaction is rolled
// back. If f errors, its error is returned, not a rollback error (if any
// occur). The passed reset function is called before the start of the
// transaction and can be used to reset intermediate state. As callers may
// expect retries of the f closure (depending on the database backend used), the
// reset function will be called before each retry respectively.
func (db *db) View(f func(tx walletdb.ReadTx) error, reset func()) error {
	// TODO: Reset necessary here and in Update?
	reset()

	tx, err := newReadWriteTx(db, true)
	if err != nil {
		return err
	}

	err = catchPanic(func() error { return f(tx) })
	if err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

// Update opens a database read/write transaction and executes the function f
// with the transaction passed as a parameter. After f exits, if f did not
// error, the transaction is committed. Otherwise, if f did error, the
// transaction is rolled back. If the rollback fails, the original error
// returned by f is still returned. If the commit fails, the commit error is
// returned. As callers may expect retries of the f closure, the reset function
// will be called before each retry respectively.
func (db *db) Update(f func(tx walletdb.ReadWriteTx) error, reset func()) (err error) {
	reset()

	tx, err := newReadWriteTx(db, false)
	if err != nil {
		return err
	}

	err = catchPanic(func() error { return f(tx) })
	if err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

// PrintStats returns all collected stats pretty printed into a string.
func (db *db) PrintStats() string {
	return ""
}

// BeginReadWriteTx opens a database read+write transaction.
func (db *db) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	return newReadWriteTx(db, false)
}

// BeginReadTx opens a database read transaction.
func (db *db) BeginReadTx() (walletdb.ReadTx, error) {
	return newReadWriteTx(db, true)
}

// Copy writes a copy of the database to the provided writer.  This call will
// start a read-only transaction to perform all operations.
// This function is part of the walletdb.Db interface implementation.
func (db *db) Copy(w io.Writer) error {
	return errors.New("not implemented")
}

// Close cleanly shuts down the database and syncs all data.
// This function is part of the walletdb.Db interface implementation.
func (db *db) Close() error {
	db.db.Close()

	return nil
}
