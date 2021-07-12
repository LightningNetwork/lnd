// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package wire implements the bitcoin wire protocol.

For the complete details of the bitcoin protocol, see the official wiki entry
at https://en.bitcoin.it/wiki/Protocol_specification.  The following only serves
as a quick overview to provide information on how to use the package.

At a high level, this package provides support for marshalling and unmarshalling
supported bitcoin messages to and from the wire.  This package does not deal
with the specifics of message handling such as what to do when a message is
received.  This provides the caller with a high level of flexibility.

Bitcoin Message Overview

The bitcoin protocol consists of exchanging messages between peers.  Each
message is preceded by a header which identifies information about it such as
which bitcoin network it is a part of, its type, how big it is, and a checksum
to verify validity.  All encoding and decoding of message headers is handled by
this package.

To accomplish this, there is a generic interface for bitcoin messages named
Message which allows messages of any type to be read, written, or passed around
through channels, functions, etc.  In addition, concrete implementations of most
of the currently supported bitcoin messages are provided.  For these supported
messages, all of the details of marshalling and unmarshalling to and from the
wire using bitcoin encoding are handled so the caller doesn't have to concern
themselves with the specifics.

Message Interaction

The following provides a quick summary of how the bitcoin messages are intended
to interact with one another.  As stated above, these interactions are not
directly handled by this package.  For more in-depth details about the
appropriate interactions, see the official bitcoin protocol wiki entry at
https://en.bitcoin.it/wiki/Protocol_specification.

The initial handshake consists of two peers sending each other a version message
(MsgVersion) followed by responding with a verack message (MsgVerAck).  Both
peers use the information in the version message (MsgVersion) to negotiate
things such as protocol version and supported services with each other.  Once
the initial handshake is complete, the following chart indicates message
interactions in no particular order.

	Peer A Sends                          Peer B Responds
	----------------------------------------------------------------------------
	getaddr message (MsgGetAddr)          addr message (MsgAddr)
	getblocks message (MsgGetBlocks)      inv message (MsgInv)
	inv message (MsgInv)                  getdata message (MsgGetData)
	getdata message (MsgGetData)          block message (MsgBlock) -or-
	                                      tx message (MsgTx) -or-
	                                      notfound message (MsgNotFound)
	getheaders message (MsgGetHeaders)    headers message (MsgHeaders)
	ping message (MsgPing)                pong message (MsgHeaders)* -or-
	                                      (none -- Ability to send message is enough)

	NOTES:
	* The pong message was not added until later protocol versions as defined
	  in BIP0031.  The BIP0031Version constant can be used to detect a recent
	  enough protocol version for this purpose (version > BIP0031Version).

Common Parameters

There are several common parameters that arise when using this package to read
and write bitcoin messages.  The following sections provide a quick overview of
these parameters so the next sections can build on them.

Protocol Version

The protocol version should be negotiated with the remote peer at a higher
level than this package via the version (MsgVersion) message exchange, however,
this package provides the wire.ProtocolVersion constant which indicates the
latest protocol version this package supports and is typically the value to use
for all outbound connections before a potentially lower protocol version is
negotiated.

Bitcoin Network

The bitcoin network is a magic number which is used to identify the start of a
message and which bitcoin network the message applies to.  This package provides
the following constants:

	wire.MainNet
	wire.TestNet  (Regression test network)
	wire.TestNet3 (Test network version 3)
	wire.SimNet   (Simulation test network)

Determining Message Type

As discussed in the bitcoin message overview section, this package reads
and writes bitcoin messages using a generic interface named Message.  In
order to determine the actual concrete type of the message, use a type
switch or type assertion.  An example of a type switch follows:

	// Assumes msg is already a valid concrete message such as one created
	// via NewMsgVersion or read via ReadMessage.
	switch msg := msg.(type) {
	case *wire.MsgVersion:
		// The message is a pointer to a MsgVersion struct.
		fmt.Printf("Protocol version: %v", msg.ProtocolVersion)
	case *wire.MsgBlock:
		// The message is a pointer to a MsgBlock struct.
		fmt.Printf("Number of tx in block: %v", msg.Header.TxnCount)
	}

Reading Messages

In order to unmarshall bitcoin messages from the wire, use the ReadMessage
function.  It accepts any io.Reader, but typically this will be a net.Conn to
a remote node running a bitcoin peer.  Example syntax is:

	// Reads and validates the next bitcoin message from conn using the
	// protocol version pver and the bitcoin network btcnet.  The returns
	// are a wire.Message, a []byte which contains the unmarshalled
	// raw payload, and a possible error.
	msg, rawPayload, err := wire.ReadMessage(conn, pver, btcnet)
	if err != nil {
		// Log and handle the error
	}

Writing Messages

In order to marshall bitcoin messages to the wire, use the WriteMessage
function.  It accepts any io.Writer, but typically this will be a net.Conn to
a remote node running a bitcoin peer.  Example syntax to request addresses
from a remote peer is:

	// Create a new getaddr bitcoin message.
	msg := wire.NewMsgGetAddr()

	// Writes a bitcoin message msg to conn using the protocol version
	// pver, and the bitcoin network btcnet.  The return is a possible
	// error.
	err := wire.WriteMessage(conn, msg, pver, btcnet)
	if err != nil {
		// Log and handle the error
	}

Errors

Errors returned by this package are either the raw errors provided by underlying
calls to read/write from streams such as io.EOF, io.ErrUnexpectedEOF, and
io.ErrShortWrite, or of type wire.MessageError.  This allows the caller to
differentiate between general IO errors and malformed messages through type
assertions.

Bitcoin Improvement Proposals

This package includes spec changes outlined by the following BIPs:

	BIP0014 (https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki)
	BIP0031 (https://github.com/bitcoin/bips/blob/master/bip-0031.mediawiki)
	BIP0035 (https://github.com/bitcoin/bips/blob/master/bip-0035.mediawiki)
	BIP0037 (https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki)
	BIP0111	(https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki)
	BIP0130 (https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki)
	BIP0133 (https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki)
*/
package wire
