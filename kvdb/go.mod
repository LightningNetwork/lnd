module github.com/lightningnetwork/lnd/kvdb

require (
	github.com/JackC/pgx v3.6.2+incompatible
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcwallet/walletdb v1.3.5-0.20210513043850-3a2f12e3a954
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/fergusstrange/embedded-postgres v1.7.0
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.14.3 // indirect
	github.com/jackc/pgx v3.6.2+incompatible // indirect
	github.com/jackc/pgx/v4 v4.11.0
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/lightningnetwork/lnd/healthcheck v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5 // indirect
	go.etcd.io/bbolt v1.3.5-0.20200615073812-232d8fc87f50
	go.etcd.io/etcd v3.4.14+incompatible
	go.uber.org/zap v1.14.1 // indirect
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
)

// Fix incompatibility of etcd go.mod package.
// See https://github.com/etcd-io/etcd/issues/11154
replace go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b

go 1.15
