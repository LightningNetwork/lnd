package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/stretchr/testify/require"
)

const (
	dsn    = "postgres://postgres:postgres@localhost:9876/postgres?sslmode=disable"
	prefix = "test"
)

func clearTestDb(t *testing.T) {
	dbConn, err := sql.Open("pgx", dsn)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS public CASCADE;")
	require.NoError(t, err)
}

func openTestDb(t *testing.T) *db {
	clearTestDb(t)

	db, err := newPostgresBackend(context.Background(), dsn, prefix)
	require.NoError(t, err)

	return db
}

type fixture struct {
	t        *testing.T
	tempDir  string
	postgres *embeddedpostgres.EmbeddedPostgres
}

func NewFixture(t *testing.T) *fixture {
	postgres := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Port(9876))

	err := postgres.Start()
	require.NoError(t, err)

	return &fixture{
		t:        t,
		postgres: postgres,
	}
}

func (b *fixture) Cleanup() {
	b.postgres.Stop()
}

func (b *fixture) NewBackend() walletdb.DB {
	clearTestDb(b.t)
	db := openTestDb(b.t)

	return db
}

func (b *fixture) Dump() map[string]interface{} {
	dbConn, err := sql.Open("pgx", dsn)
	require.NoError(b.t, err)

	rows, err := dbConn.Query(
		"SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public'",
	)
	require.NoError(b.t, err)

	var tables []string
	for rows.Next() {
		var table string
		err := rows.Scan(&table)
		require.NoError(b.t, err)

		tables = append(tables, table)
	}

	result := make(map[string]interface{})

	for _, table := range tables {
		rows, err := dbConn.Query("SELECT * FROM " + table)
		require.NoError(b.t, err)

		cols, err := rows.Columns()
		require.NoError(b.t, err)
		colCount := len(cols)

		var tableRows []map[string]interface{}
		for rows.Next() {
			values := make([]interface{}, colCount)
			valuePtrs := make([]interface{}, colCount)
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			err := rows.Scan(valuePtrs...)
			require.NoError(b.t, err)

			tableData := make(map[string]interface{})
			for i, v := range values {
				// Cast byte slices to string to keep the
				// expected database contents in test code more
				// readable.
				if ar, ok := v.([]uint8); ok {
					v = string(ar)
				}
				tableData[cols[i]] = v
			}

			tableRows = append(tableRows, tableData)
		}

		result[table] = tableRows
	}

	return result
}
