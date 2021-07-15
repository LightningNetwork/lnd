package kvdb

import (
	"fmt"
	"time"
)

// BoltBackendConfig is a struct that holds settings specific to the bolt
// database backend.
type BoltBackendConfig struct {
	// DBPath is the directory path in which the database file should be
	// stored.
	DBPath string

	// DBFileName is the name of the database file.
	DBFileName string

	// NoFreelistSync, if true, prevents the database from syncing its
	// freelist to disk, resulting in improved performance at the expense of
	// increased startup time.
	NoFreelistSync bool

	// AutoCompact specifies if a Bolt based database backend should be
	// automatically compacted on startup (if the minimum age of the
	// database file is reached). This will require additional disk space
	// for the compacted copy of the database but will result in an overall
	// lower database size after the compaction.
	AutoCompact bool

	// AutoCompactMinAge specifies the minimum time that must have passed
	// since a bolt database file was last compacted for the compaction to
	// be considered again.
	AutoCompactMinAge time.Duration

	// DBTimeout specifies the timeout value to use when opening the wallet
	// database.
	DBTimeout time.Duration
}

// GetBoltBackend opens (or creates if doesn't exits) a bbolt backed database
// and returns a kvdb.Backend wrapping it.
func GetBoltBackend(cfg *BoltBackendConfig) (Backend, error) {
	return nil, fmt.Errorf("bolt backend not supported in WebAssembly")
}

func GetTestBackend(path, name string) (Backend, func(), error) {
	return nil, nil, fmt.Errorf("bolt backend not supported in WebAssembly")
}
