peer
====

[![Build Status](http://img.shields.io/travis/btcsuite/btcd.svg)](https://travis-ci.org/btcsuite/btcd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/btcsuite/btcd/peer)

Package peer provides a common base for creating and managing bitcoin network
peers.

This package has intentionally been designed so it can be used as a standalone
package for any projects needing a full featured bitcoin peer base to build on.

## Overview

This package builds upon the wire package, which provides the fundamental
primitives necessary to speak the bitcoin wire protocol, in order to simplify
the process of creating fully functional peers.  In essence, it provides a
common base for creating concurrent safe fully validating nodes, Simplified
Payment Verification (SPV) nodes, proxies, etc.

A quick overview of the major features peer provides are as follows:

 - Provides a basic concurrent safe bitcoin peer for handling bitcoin
   communications via the peer-to-peer protocol
 - Full duplex reading and writing of bitcoin protocol messages
 - Automatic handling of the initial handshake process including protocol
   version negotiation
 - Asynchronous message queueing of outbound messages with optional channel for
   notification when the message is actually sent
 - Flexible peer configuration
   - Caller is responsible for creating outgoing connections and listening for
     incoming connections so they have flexibility to establish connections as
     they see fit (proxies, etc)
   - User agent name and version
   - Bitcoin network
   - Service support signalling (full nodes, bloom filters, etc)
   - Maximum supported protocol version
   - Ability to register callbacks for handling bitcoin protocol messages
 - Inventory message batching and send trickling with known inventory detection
   and avoidance
 - Automatic periodic keep-alive pinging and pong responses
 - Random nonce generation and self connection detection
 - Proper handling of bloom filter related commands when the caller does not
   specify the related flag to signal support
   - Disconnects the peer when the protocol version is high enough
   - Does not invoke the related callbacks for older protocol versions
 - Snapshottable peer statistics such as the total number of bytes read and
   written, the remote address, user agent, and negotiated protocol version
 - Helper functions pushing addresses, getblocks, getheaders, and reject
   messages
   - These could all be sent manually via the standard message output function,
     but the helpers provide additional nice functionality such as duplicate
     filtering and address randomization
 - Ability to wait for shutdown/disconnect
 - Comprehensive test coverage

## Installation and Updating

```bash
$ go get -u github.com/btcsuite/btcd/peer
```

## Examples

* [New Outbound Peer Example](https://godoc.org/github.com/btcsuite/btcd/peer#example-package--NewOutboundPeer)  
  Demonstrates the basic process for initializing and creating an outbound peer.
  Peers negotiate by exchanging version and verack messages.  For demonstration,
  a simple handler for the version message is attached to the peer.

## License

Package peer is licensed under the [copyfree](http://copyfree.org) ISC License.
