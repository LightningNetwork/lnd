package kvdb

import "time"

const (
	// BoltBackendName is the name of the backend that should be passed into
	// kvdb.Create to initialize a new instance of kvdb.Backend backed by a
	// live instance of bbolt.
	BoltBackendName = "bdb"

	// EtcdBackendName is the name of the backend that should be passed into
	// kvdb.Create to initialize a new instance of kvdb.Backend backed by a
	// live instance of etcd.
	EtcdBackendName = "etcd"

	PostgresBackendName = "postgres"

	// DefaultBoltAutoCompactMinAge is the default minimum time that must
	// have passed since a bolt database file was last compacted for the
	// compaction to be considered again.
	DefaultBoltAutoCompactMinAge = time.Hour * 24 * 7

	// DefaultDBTimeout specifies the default timeout value when opening
	// the bbolt database.
	DefaultDBTimeout = time.Second * 60
)

// BoltConfig holds bolt configuration.
type BoltConfig struct {
	SyncFreelist bool `long:"nofreelistsync" description:"Whether the databases used within lnd should sync their freelist to disk. This is disabled by default resulting in improved memory performance during operation, but with an increase in startup time."`

	AutoCompact bool `long:"auto-compact" description:"Whether the databases used within lnd should automatically be compacted on every startup (and if the database has the configured minimum age). This is disabled by default because it requires additional disk space to be available during the compaction that is freed afterwards. In general compaction leads to smaller database files."`

	AutoCompactMinAge time.Duration `long:"auto-compact-min-age" description:"How long ago the last compaction of a database file must be for it to be considered for auto compaction again. Can be set to 0 to compact on every startup."`

	DBTimeout time.Duration `long:"dbtimeout" description:"Specify the timeout value used when opening the database."`
}
