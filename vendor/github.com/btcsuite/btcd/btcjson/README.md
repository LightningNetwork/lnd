btcjson
=======

[![Build Status](https://travis-ci.org/btcsuite/btcd.png?branch=master)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/btcjson)

Package btcjson implements concrete types for marshalling to and from the
bitcoin JSON-RPC API.  A comprehensive suite of tests is provided to ensure
proper functionality.

Although this package was primarily written for the btcsuite, it has
intentionally been designed so it can be used as a standalone package for any
projects needing to marshal to and from bitcoin JSON-RPC requests and responses.

Note that although it's possible to use this package directly to implement an
RPC client, it is not recommended since it is only intended as an infrastructure
package.  Instead, RPC clients should use the
[btcrpcclient](https://github.com/btcsuite/btcrpcclient) package which provides
a full blown RPC client with many features such as automatic connection
management, websocket support, automatic notification re-registration on
reconnect, and conversion from the raw underlying RPC types (strings, floats,
ints, etc) to higher-level types with many nice and useful properties.

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/btcjson
```

## Examples

* [Marshal Command](http://godoc.org/github.com/btcsuite/btcd/btcjson#example-MarshalCmd)  
  Demonstrates how to create and marshal a command into a JSON-RPC request.

* [Unmarshal Command](http://godoc.org/github.com/btcsuite/btcd/btcjson#example-UnmarshalCmd)  
  Demonstrates how to unmarshal a JSON-RPC request and then unmarshal the
  concrete request into a concrete command.

* [Marshal Response](http://godoc.org/github.com/btcsuite/btcd/btcjson#example-MarshalResponse)  
  Demonstrates how to marshal a JSON-RPC response.

* [Unmarshal Response](http://godoc.org/github.com/btcsuite/btcd/btcjson#example-package--UnmarshalResponse)  
  Demonstrates how to unmarshal a JSON-RPC response and then unmarshal the
  result field in the response to a concrete type.

## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from the btcsuite developers.  To
verify the signature perform the following:

- Download the public key from the Conformal website at
  https://opensource.conformal.com/GIT-GPG-KEY-conformal.txt

- Import the public key into your GPG keyring:
  ```bash
  gpg --import GIT-GPG-KEY-conformal.txt
  ```

- Verify the release tag with the following command where `TAG_NAME` is a
  placeholder for the specific tag:
  ```bash
  git tag -v TAG_NAME
  ```

## License

Package btcjson is licensed under the [copyfree](http://copyfree.org) ISC
License.
