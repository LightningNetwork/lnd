rpctest
=======

[![Build Status](http://img.shields.io/travis/btcsuite/btcd.svg)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/integration/rpctest)

Package rpctest provides a btcd-specific RPC testing harness crafting and
executing integration tests by driving a `btcd` instance via the `RPC`
interface. Each instance of an active harness comes equipped with a simple
in-memory HD wallet capable of properly syncing to the generated chain,
creating new addresses, and crafting fully signed transactions paying to an
arbitrary set of outputs.

This package was designed specifically to act as an RPC testing harness for
`btcd`. However, the constructs presented are general enough to be adapted to
any project wishing to programmatically drive a `btcd` instance of its
systems/integration tests.

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/integration/rpctest
```

## License

Package rpctest is licensed under the [copyfree](http://copyfree.org) ISC
License.

