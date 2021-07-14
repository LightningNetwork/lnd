// +build kvdb_etcd

package etcd

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/namespace"
	"go.etcd.io/etcd/pkg/transport"
)

const (
	// etcdConnectionTimeout is the timeout until successful connection to
	// the etcd instance.
	etcdConnectionTimeout = 10 * time.Second

	// etcdLongTimeout is a timeout for longer taking etcd operatons.
	etcdLongTimeout = 30 * time.Second

	// etcdDefaultRootBucketId is used as the root bucket key. Note that
	// the actual key is not visible, since all bucket keys are hashed.
	etcdDefaultRootBucketId = "@"
)

// callerStats holds commit stats for a specific caller. Currently it only
// holds the max stat, meaning that for a particular caller the largest
// commit set is recorded.
type callerStats struct {
	count       int
	commitStats CommitStats
}

func (s callerStats) String() string {
	return fmt.Sprintf("count: %d, retries: %d, rset: %d, wset: %d",
		s.count, s.commitStats.Retries, s.commitStats.Rset,
		s.commitStats.Wset)
}

// commitStatsCollector collects commit stats for commits succeeding
// and also for commits failing.
type commitStatsCollector struct {
	sync.RWMutex
	succ map[string]*callerStats
	fail map[string]*callerStats
}

// newCommitStatsColletor creates a new commitStatsCollector instance.
func newCommitStatsColletor() *commitStatsCollector {
	return &commitStatsCollector{
		succ: make(map[string]*callerStats),
		fail: make(map[string]*callerStats),
	}
}

// PrintStats returns collected stats pretty printed into a string.
func (c *commitStatsCollector) PrintStats() string {
	c.RLock()
	defer c.RUnlock()

	s := "\nFailure:\n"
	for k, v := range c.fail {
		s += fmt.Sprintf("%s\t%s\n", k, v)
	}

	s += "\nSuccess:\n"
	for k, v := range c.succ {
		s += fmt.Sprintf("%s\t%s\n", k, v)
	}

	return s
}

// updateStatsMap updatess commit stats map for a caller.
func updateStatMap(
	caller string, stats CommitStats, m map[string]*callerStats) {

	if _, ok := m[caller]; !ok {
		m[caller] = &callerStats{}
	}

	curr := m[caller]
	curr.count++

	// Update only if the total commit set is greater or equal.
	currTotal := curr.commitStats.Rset + curr.commitStats.Wset
	if currTotal <= (stats.Rset + stats.Wset) {
		curr.commitStats = stats
	}
}

// callback is an STM commit stats callback passed which can be passed
// using a WithCommitStatsCallback to the STM upon construction.
func (c *commitStatsCollector) callback(succ bool, stats CommitStats) {
	caller := "unknown"

	// Get the caller. As this callback is called from
	// the backend interface that means we need to ascend
	// 4 frames in the callstack.
	_, file, no, ok := runtime.Caller(4)
	if ok {
		caller = fmt.Sprintf("%s#%d", file, no)
	}

	c.Lock()
	defer c.Unlock()

	if succ {
		updateStatMap(caller, stats, c.succ)
	} else {
		updateStatMap(caller, stats, c.fail)
	}
}

// db holds a reference to the etcd client connection.
type db struct {
	cfg                  Config
	ctx                  context.Context
	cli                  *clientv3.Client
	commitStatsCollector *commitStatsCollector
	txQueue              *commitQueue
}

// Enforce db implements the walletdb.DB interface.
var _ walletdb.DB = (*db)(nil)

// newEtcdBackend returns a db object initialized with the passed backend
// config. If etcd connection cannot be established, then returns error.
func newEtcdBackend(ctx context.Context, cfg Config) (*db, error) {
	clientCfg := clientv3.Config{
		Context:            ctx,
		Endpoints:          []string{cfg.Host},
		DialTimeout:        etcdConnectionTimeout,
		Username:           cfg.User,
		Password:           cfg.Pass,
		MaxCallSendMsgSize: 16384*1024 - 1,
	}

	if !cfg.DisableTLS {
		tlsInfo := transport.TLSInfo{
			CertFile:           cfg.CertFile,
			KeyFile:            cfg.KeyFile,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}

		tlsConfig, err := tlsInfo.ClientConfig()
		if err != nil {
			return nil, err
		}

		clientCfg.TLS = tlsConfig
	}

	cli, err := clientv3.New(clientCfg)
	if err != nil {
		return nil, err
	}

	// Apply the namespace.
	cli.KV = namespace.NewKV(cli.KV, cfg.Namespace)
	cli.Watcher = namespace.NewWatcher(cli.Watcher, cfg.Namespace)
	cli.Lease = namespace.NewLease(cli.Lease, cfg.Namespace)

	backend := &db{
		cfg:     cfg,
		ctx:     ctx,
		cli:     cli,
		txQueue: NewCommitQueue(ctx),
	}

	if cfg.CollectStats {
		backend.commitStatsCollector = newCommitStatsColletor()
	}

	return backend, nil
}

// getSTMOptions creates all STM options based on the backend config.
func (db *db) getSTMOptions() []STMOptionFunc {
	opts := []STMOptionFunc{
		WithAbortContext(db.ctx),
	}

	if db.cfg.CollectStats {
		opts = append(opts,
			WithCommitStatsCallback(db.commitStatsCollector.callback),
		)
	}

	return opts
}

// View opens a database read transaction and executes the function f with the
// transaction passed as a parameter. After f exits, the transaction is rolled
// back. If f errors, its error is returned, not a rollback error (if any
// occur). The passed reset function is called before the start of the
// transaction and can be used to reset intermediate state. As callers may
// expect retries of the f closure (depending on the database backend used), the
// reset function will be called before each retry respectively.
func (db *db) View(f func(tx walletdb.ReadTx) error, reset func()) error {
	apply := func(stm STM) error {
		reset()
		return f(newReadWriteTx(stm, etcdDefaultRootBucketId))
	}

	return RunSTM(db.cli, apply, db.txQueue, db.getSTMOptions()...)
}

// Update opens a database read/write transaction and executes the function f
// with the transaction passed as a parameter. After f exits, if f did not
// error, the transaction is committed. Otherwise, if f did error, the
// transaction is rolled back. If the rollback fails, the original error
// returned by f is still returned. If the commit fails, the commit error is
// returned. As callers may expect retries of the f closure, the reset function
// will be called before each retry respectively.
func (db *db) Update(f func(tx walletdb.ReadWriteTx) error, reset func()) error {
	apply := func(stm STM) error {
		reset()
		return f(newReadWriteTx(stm, etcdDefaultRootBucketId))
	}

	return RunSTM(db.cli, apply, db.txQueue, db.getSTMOptions()...)
}

// PrintStats returns all collected stats pretty printed into a string.
func (db *db) PrintStats() string {
	if db.commitStatsCollector != nil {
		return db.commitStatsCollector.PrintStats()
	}

	return ""
}

// BeginReadWriteTx opens a database read+write transaction.
func (db *db) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	return newReadWriteTx(
		NewSTM(db.cli, db.txQueue, db.getSTMOptions()...),
		etcdDefaultRootBucketId,
	), nil
}

// BeginReadTx opens a database read transaction.
func (db *db) BeginReadTx() (walletdb.ReadTx, error) {
	return newReadWriteTx(
		NewSTM(db.cli, db.txQueue, db.getSTMOptions()...),
		etcdDefaultRootBucketId,
	), nil
}

// Copy writes a copy of the database to the provided writer.  This call will
// start a read-only transaction to perform all operations.
// This function is part of the walletdb.Db interface implementation.
func (db *db) Copy(w io.Writer) error {
	ctx, cancel := context.WithTimeout(db.ctx, etcdLongTimeout)
	defer cancel()

	readCloser, err := db.cli.Snapshot(ctx)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, readCloser)

	return err
}

// Close cleanly shuts down the database and syncs all data.
// This function is part of the walletdb.Db interface implementation.
func (db *db) Close() error {
	return db.cli.Close()
}
