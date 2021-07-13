// +build kvdb_etcd

package etcd

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/namespace"
)

const (
	// testEtcdTimeout is used for all RPC calls initiated by the test fixture.
	testEtcdTimeout = 5 * time.Second
)

// EtcdTestFixture holds internal state of the etcd test fixture.
type EtcdTestFixture struct {
	t       *testing.T
	cli     *clientv3.Client
	config  *Config
	cleanup func()
}

// NewTestEtcdInstance creates an embedded etcd instance for testing, listening
// on random open ports. Returns the connection config and a cleanup func that
// will stop the etcd instance.
func NewTestEtcdInstance(t *testing.T, path string) (*Config, func()) {
	t.Helper()

	config, cleanup, err := NewEmbeddedEtcdInstance(path, 0, 0)
	if err != nil {
		t.Fatalf("error while staring embedded etcd instance: %v", err)
	}

	return config, cleanup
}

// NewTestEtcdTestFixture creates a new etcd-test fixture. This is helper
// object to facilitate etcd tests and ensure pre and post conditions.
func NewEtcdTestFixture(t *testing.T) *EtcdTestFixture {
	tmpDir, err := ioutil.TempDir("", "etcd")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}

	config, etcdCleanup := NewTestEtcdInstance(t, tmpDir)

	cli, err := clientv3.New(clientv3.Config{
		Endpoints: []string{config.Host},
		Username:  config.User,
		Password:  config.Pass,
	})
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("unable to create etcd test fixture: %v", err)
	}

	// Apply the default namespace (since that's what we use in tests).
	cli.KV = namespace.NewKV(cli.KV, defaultNamespace)
	cli.Watcher = namespace.NewWatcher(cli.Watcher, defaultNamespace)
	cli.Lease = namespace.NewLease(cli.Lease, defaultNamespace)

	return &EtcdTestFixture{
		t:      t,
		cli:    cli,
		config: config,
		cleanup: func() {
			etcdCleanup()
			os.RemoveAll(tmpDir)
		},
	}
}

func (f *EtcdTestFixture) NewBackend() walletdb.DB {
	db, err := newEtcdBackend(context.TODO(), f.BackendConfig())
	require.NoError(f.t, err)

	return db
}

// Put puts a string key/value into the test etcd database.
func (f *EtcdTestFixture) Put(key, value string) {
	ctx, cancel := context.WithTimeout(context.TODO(), testEtcdTimeout)
	defer cancel()

	_, err := f.cli.Put(ctx, key, value)
	if err != nil {
		f.t.Fatalf("etcd test fixture failed to put: %v", err)
	}
}

// Get queries a key and returns the stored value from the test etcd database.
func (f *EtcdTestFixture) Get(key string) string {
	ctx, cancel := context.WithTimeout(context.TODO(), testEtcdTimeout)
	defer cancel()

	resp, err := f.cli.Get(ctx, key)
	if err != nil {
		f.t.Fatalf("etcd test fixture failed to get: %v", err)
	}

	if len(resp.Kvs) > 0 {
		return string(resp.Kvs[0].Value)
	}

	return ""
}

// Dump scans and returns all key/values from the test etcd database.
func (f *EtcdTestFixture) Dump() map[string]string {
	ctx, cancel := context.WithTimeout(context.TODO(), testEtcdTimeout)
	defer cancel()

	resp, err := f.cli.Get(ctx, "\x00", clientv3.WithFromKey())
	if err != nil {
		f.t.Fatalf("etcd test fixture failed to get: %v", err)
	}

	result := make(map[string]string)
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = string(kv.Value)
	}

	return result
}

// BackendConfig returns the backend config for connecting to theembedded
// etcd instance.
func (f *EtcdTestFixture) BackendConfig() Config {
	return *f.config
}

// Cleanup should be called at test fixture teardown to stop the embedded
// etcd instance and remove all temp db files form the filesystem.
func (f *EtcdTestFixture) Cleanup() {
	f.cleanup()
}
