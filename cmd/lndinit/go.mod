module github.com/lightningnetwork/lnd/cmd/lndinit

require (
	github.com/btcsuite/btcd v0.21.0-beta.0.20210513141527-ee5896bad5be
	github.com/btcsuite/btcwallet v0.12.1-0.20210519225359-6ab9b615576f
	github.com/jessevdk/go-flags v1.4.0
	github.com/kkdai/bstream v1.0.0
	github.com/lightningnetwork/lnd v0.13.0-beta
	k8s.io/api v0.18.3
	k8s.io/apimachinery v0.18.3
	k8s.io/client-go v0.18.3
)

replace github.com/lightningnetwork/lnd => ../../

// Fix incompatibility of etcd go.mod package.
// See https://github.com/etcd-io/etcd/issues/11154
replace go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b

go 1.15
