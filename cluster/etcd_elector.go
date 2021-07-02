// +build kvdb_etcd

package cluster

import (
	"context"
	"time"

	"github.com/lightningnetwork/lnd/kvdb/etcd"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	"go.etcd.io/etcd/client/v3/namespace"
)

const (
	// etcdConnectionTimeout is the timeout until successful connection to
	// the etcd instance.
	etcdConnectionTimeout = 10 * time.Second
)

// Enforce that etcdLeaderElector implements the LeaderElector interface.
var _ LeaderElector = (*etcdLeaderElector)(nil)

// etcdLeaderElector is an implemetation of LeaderElector using etcd as the
// election governor.
type etcdLeaderElector struct {
	id       string
	ctx      context.Context
	cli      *clientv3.Client
	session  *concurrency.Session
	election *concurrency.Election
}

// newEtcdLeaderElector constructs a new etcdLeaderElector.
func newEtcdLeaderElector(ctx context.Context, id, electionPrefix string,
	cfg *etcd.Config) (*etcdLeaderElector, error) {

	clientCfg := clientv3.Config{
		Context:     ctx,
		Endpoints:   []string{cfg.Host},
		DialTimeout: etcdConnectionTimeout,
		Username:    cfg.User,
		Password:    cfg.Pass,
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
		log.Errorf("Unable to connect to etcd: %v", err)
		return nil, err
	}

	// Apply the namespace.
	cli.KV = namespace.NewKV(cli.KV, cfg.Namespace)
	cli.Watcher = namespace.NewWatcher(cli.Watcher, cfg.Namespace)
	cli.Lease = namespace.NewLease(cli.Lease, cfg.Namespace)
	log.Infof("Applied namespace to leader elector: %v", cfg.Namespace)

	session, err := concurrency.NewSession(cli)
	if err != nil {
		log.Errorf("Unable to start new leader election session: %v",
			err)
		return nil, err
	}

	return &etcdLeaderElector{
		id:      id,
		ctx:     ctx,
		cli:     cli,
		session: session,
		election: concurrency.NewElection(
			session, electionPrefix,
		),
	}, nil
}

// Leader returns the leader value for the current election.
func (e *etcdLeaderElector) Leader(ctx context.Context) (string, error) {
	resp, err := e.election.Leader(ctx)
	if err != nil {
		return "", err
	}

	return string(resp.Kvs[0].Value), nil
}

// Campaign will start a new leader election campaign. Campaign will block until
// the elector context is canceled or the the caller is elected as the leader.
func (e *etcdLeaderElector) Campaign(ctx context.Context) error {
	return e.election.Campaign(ctx, e.id)
}

// Resign resigns the leader role allowing other election members to take
// the place.
func (e *etcdLeaderElector) Resign() error {
	return e.election.Resign(context.Background())
}
