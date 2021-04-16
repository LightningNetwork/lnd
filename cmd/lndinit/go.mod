module github.com/lightningnetwork/lnd/cmd/lndinit

require (
	github.com/jessevdk/go-flags v1.4.0
	github.com/kkdai/bstream v1.0.0
	github.com/lightningnetwork/lnd v0.13.0-beta
)

replace github.com/lightningnetwork/lnd => ../../

// Fix incompatibility of etcd go.mod package.
// See https://github.com/etcd-io/etcd/issues/11154
replace go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b

go 1.15
