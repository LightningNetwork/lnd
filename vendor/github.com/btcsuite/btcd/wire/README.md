wire
====

[![Build Status](http://img.shields.io/travis/btcsuite/btcd.svg)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/wire)
=======

Package wire implements the bitcoin wire protocol.  A comprehensive suite of
tests with 100% test coverage is provided to ensure proper functionality.

There is an associated blog post about the release of this package
[here](https://blog.conformal.com/btcwire-the-bitcoin-wire-protocol-package-from-btcd/).

This package has intentionally been designed so it can be used as a standalone
package for any projects needing to interface with bitcoin peers at the wire
protocol level.

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/wire
```

## Bitcoin Message Overview

The bitcoin protocol consists of exchanging messages between peers. Each message
is preceded by a header which identifies information about it such as which
bitcoin network it is a part of, its type, how big it is, and a checksum to
verify validity. All encoding and decoding of message headers is handled by this
package.

To accomplish this, there is a generic interface for bitcoin messages named
`Message` which allows messages of any type to be read, written, or passed
around through channels, functions, etc. In addition, concrete implementations
of most of the currently supported bitcoin messages are provided. For these
supported messages, all of the details of marshalling and unmarshalling to and
from the wire using bitcoin encoding are handled so the caller doesn't have to
concern themselves with the specifics.

## Reading Messages Example

In order to unmarshal bitcoin messages from the wire, use the `ReadMessage`
function. It accepts any `io.Reader`, but typically this will be a `net.Conn`
to a remote node running a bitcoin peer.  Example syntax is:

```Go
	// Use the most recent protocol version supported by the package and the
	// main bitcoin network.
	pver := wire.ProtocolVersion
	btcnet := wire.MainNet

	// Reads and validates the next bitcoin message from conn using the
	// protocol version pver and the bitcoin network btcnet.  The returns
	// are a wire.Message, a []byte which contains the unmarshalled
	// raw payload, and a possible error.
	msg, rawPayload, err := wire.ReadMessage(conn, pver, btcnet)
	if err != nil {
		// Log and handle the error
	}
```

See the package documentation for details on determining the message type.

## Writing Messages Example

In order to marshal bitcoin messages to the wire, use the `WriteMessage`
function. It accepts any `io.Writer`, but typically this will be a `net.Conn`
to a remote node running a bitcoin peer. Example syntax to request addresses
from a remote peer is:

```Go
	// Use the most recent protocol version supported by the package and the
	// main bitcoin network.
	pver := wire.ProtocolVersion
	btcnet := wire.MainNet

	// Create a new getaddr bitcoin message.
	msg := wire.NewMsgGetAddr()

	// Writes a bitcoin message msg to conn using the protocol version
	// pver, and the bitcoin network btcnet.  The return is a possible
	// error.
	err := wire.WriteMessage(conn, msg, pver, btcnet)
	if err != nil {
		// Log and handle the error
	}
```

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

Package wire is licensed under the [copyfree](http://copyfree.org) ISC
License.
