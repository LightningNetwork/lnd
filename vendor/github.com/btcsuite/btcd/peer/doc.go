// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package peer provides a common base for creating and managing Bitcoin network
peers.

Overview

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
 - Asynchronous message queuing of outbound messages with optional channel for
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

Peer Configuration

All peer configuration is handled with the Config struct.  This allows the
caller to specify things such as the user agent name and version, the bitcoin
network to use, which services it supports, and callbacks to invoke when bitcoin
messages are received.  See the documentation for each field of the Config
struct for more details.

Inbound and Outbound Peers

A peer can either be inbound or outbound.  The caller is responsible for
establishing the connection to remote peers and listening for incoming peers.
This provides high flexibility for things such as connecting via proxies, acting
as a proxy, creating bridge peers, choosing whether to listen for inbound peers,
etc.

NewOutboundPeer and NewInboundPeer functions must be followed by calling Connect
with a net.Conn instance to the peer.  This will start all async I/O goroutines
and initiate the protocol negotiation process.  Once finished with the peer call
Disconnect to disconnect from the peer and clean up all resources.
WaitForDisconnect can be used to block until peer disconnection and resource
cleanup has completed.

Callbacks

In order to do anything useful with a peer, it is necessary to react to bitcoin
messages.  This is accomplished by creating an instance of the MessageListeners
struct with the callbacks to be invoke specified and setting the Listeners field
of the Config struct specified when creating a peer to it.

For convenience, a callback hook for all of the currently supported bitcoin
messages is exposed which receives the peer instance and the concrete message
type.  In addition, a hook for OnRead is provided so even custom messages types
for which this package does not directly provide a hook, as long as they
implement the wire.Message interface, can be used.  Finally, the OnWrite hook
is provided, which in conjunction with OnRead, can be used to track server-wide
byte counts.

It is often useful to use closures which encapsulate state when specifying the
callback handlers.  This provides a clean method for accessing that state when
callbacks are invoked.

Queuing Messages and Inventory

The QueueMessage function provides the fundamental means to send messages to the
remote peer.  As the name implies, this employs a non-blocking queue.  A done
channel which will be notified when the message is actually sent can optionally
be specified.  There are certain message types which are better sent using other
functions which provide additional functionality.

Of special interest are inventory messages.  Rather than manually sending MsgInv
messages via Queuemessage, the inventory vectors should be queued using the
QueueInventory function.  It employs batching and trickling along with
intelligent known remote peer inventory detection and avoidance through the use
of a most-recently used algorithm.

Message Sending Helper Functions

In addition to the bare QueueMessage function previously described, the
PushAddrMsg, PushGetBlocksMsg, PushGetHeadersMsg, and PushRejectMsg functions
are provided as a convenience.  While it is of course possible to create and
send these message manually via QueueMessage, these helper functions provided
additional useful functionality that is typically desired.

For example, the PushAddrMsg function automatically limits the addresses to the
maximum number allowed by the message and randomizes the chosen addresses when
there are too many.  This allows the caller to simply provide a slice of known
addresses, such as that returned by the addrmgr package, without having to worry
about the details.

Next, the PushGetBlocksMsg and PushGetHeadersMsg functions will construct proper
messages using a block locator and ignore back to back duplicate requests.

Finally, the PushRejectMsg function can be used to easily create and send an
appropriate reject message based on the provided parameters as well as
optionally provides a flag to cause it to block until the message is actually
sent.

Peer Statistics

A snapshot of the current peer statistics can be obtained with the StatsSnapshot
function.  This includes statistics such as the total number of bytes read and
written, the remote address, user agent, and negotiated protocol version.

Logging

This package provides extensive logging capabilities through the UseLogger
function which allows a btclog.Logger to be specified.  For example, logging at
the debug level provides summaries of every message sent and received, and
logging at the trace level provides full dumps of parsed messages as well as the
raw message bytes using a format similar to hexdump -C.

Bitcoin Improvement Proposals

This package supports all BIPS supported by the wire package.
(https://godoc.org/github.com/btcsuite/btcd/wire#hdr-Bitcoin_Improvement_Proposals)
*/
package peer
