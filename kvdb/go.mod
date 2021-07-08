module github.com/lightningnetwork/lnd/kvdb

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcwallet/walletdb v1.3.5-0.20210513043850-3a2f12e3a954
	github.com/lightningnetwork/lnd/healthcheck v1.0.0
	github.com/stretchr/testify v1.7.0
	go.etcd.io/bbolt v1.3.6
	go.etcd.io/etcd/client/pkg/v3 v3.5.0
	go.etcd.io/etcd/client/v3 v3.5.0
	go.etcd.io/etcd/server/v3 v3.5.0
)

go 1.15
