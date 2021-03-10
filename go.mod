module github.com/lightningnetwork/lnd

require (
	git.schwanenlied.me/yawning/bsaes.git v0.0.0-20180720073208-c0276d75487e // indirect
	github.com/NebulousLabs/fastrand v0.0.0-20181203155948-6fb6489aac4e // indirect
	github.com/NebulousLabs/go-upnp v0.0.0-20180202185039-29b680b06c82
	github.com/Yawning/aez v0.0.0-20180114000226-4dad034d9db2
	github.com/btcsuite/btcd v0.21.0-beta.0.20201208033208-6bd4c64a54fa
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcutil v1.0.2
	github.com/btcsuite/btcutil/psbt v1.0.3-0.20200826194809-5f93e33af2b0
	github.com/btcsuite/btcwallet v0.11.1-0.20201207233335-415f37ff11a1
	github.com/btcsuite/btcwallet/wallet/txauthor v1.0.0
	github.com/btcsuite/btcwallet/wallet/txrules v1.0.0
	github.com/btcsuite/btcwallet/walletdb v1.3.4
	github.com/btcsuite/btcwallet/wtxmgr v1.2.0
	github.com/coreos/etcd v3.3.22+incompatible
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/go-errors/errors v1.0.1
	github.com/go-openapi/strfmt v0.19.5 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.3.2
	github.com/google/btree v1.0.0 // indirect
	github.com/gorilla/websocket v1.4.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.14.3
	github.com/jackpal/gateway v1.0.5
	github.com/jackpal/go-nat-pmp v0.0.0-20170405195558-28a68d0c24ad
	github.com/jedib0t/go-pretty v4.3.0+incompatible
	github.com/jessevdk/go-flags v1.4.0
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/jrick/logrotate v1.0.0
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/juju/clock v0.0.0-20190205081909-9c5c9712527c // indirect
	github.com/juju/errors v0.0.0-20190806202954-0232dcc7464d // indirect
	github.com/juju/loggo v0.0.0-20190526231331-6e530bcce5d8 // indirect
	github.com/juju/retry v0.0.0-20180821225755-9058e192b216 // indirect
	github.com/juju/testing v0.0.0-20190723135506-ce30eb24acd2 // indirect
	github.com/juju/utils v0.0.0-20180820210520-bf9cc5bdd62d // indirect
	github.com/juju/version v0.0.0-20180108022336-b64dbd566305 // indirect
	github.com/kkdai/bstream v0.0.0-20181106074824-b3251f7901ec
	github.com/lightninglabs/neutrino v0.11.1-0.20201210023533-e1978372d15e
	github.com/lightninglabs/protobuf-hex-display v1.3.3-0.20191212020323-b444784ce75d
	github.com/lightningnetwork/lightning-onion v1.0.2-0.20200501022730-3c8c8d0b89ea
	github.com/lightningnetwork/lnd/cert v1.0.3
	github.com/lightningnetwork/lnd/clock v1.0.1
	github.com/lightningnetwork/lnd/queue v1.0.4
	github.com/lightningnetwork/lnd/ticker v1.0.0
	github.com/ltcsuite/ltcd v0.0.0-20190101042124-f37f8bf35796
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/miekg/dns v0.0.0-20171125082028-79bfde677fa8
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/prometheus/client_golang v0.9.3
	github.com/soheilhy/cmux v0.1.4 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5 // indirect
	github.com/tv42/zbase32 v0.0.0-20160707012821-501572607d02
	github.com/urfave/cli v1.18.0
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
	go.etcd.io/bbolt v1.3.5-0.20200615073812-232d8fc87f50
	go.uber.org/zap v1.14.1 // indirect
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/net v0.0.0-20191002035440-2ec189313ef0
	golang.org/x/sys v0.0.0-20200202164722-d101bd2416d5
	golang.org/x/time v0.0.0-20180412165947-fbb02b2291d2
	google.golang.org/grpc v1.24.0
	gopkg.in/errgo.v1 v1.0.1 // indirect
	gopkg.in/macaroon-bakery.v2 v2.0.1
	gopkg.in/macaroon.v2 v2.0.0
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace github.com/lightningnetwork/lnd/ticker => ./ticker

replace github.com/lightningnetwork/lnd/queue => ./queue

replace github.com/lightningnetwork/lnd/cert => ./cert

replace github.com/lightningnetwork/lnd/clock => ./clock

replace git.schwanenlied.me/yawning/bsaes.git => github.com/Yawning/bsaes v0.0.0-20180720073208-c0276d75487e

replace github.com/btcsuite/btcwallet => github.com/guggero/btcwallet v0.11.1-0.20210129085417-f930f83c71e6

go 1.13
