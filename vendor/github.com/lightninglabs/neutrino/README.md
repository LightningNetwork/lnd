# Neutrino: Privacy-Preserving Bitcoin Light Client

[![Build Status](https://travis-ci.org/lightninglabs/neutrino.svg?branch=master)](https://travis-ci.org/lightninglabs/neutrino)
[![Godoc](https://godoc.org/github.com/lightninglabs/neutrino?status.svg)](https://godoc.org/github.com/lightninglabs/neutrino)
[![Coverage Status](https://coveralls.io/repos/github/lightninglabs/neutrino/badge.svg?branch=master)](https://coveralls.io/github/lightninglabs/neutrino?branch=master)

Neutrino is an **experimental** Bitcoin light client written in Go and designed with mobile Lightning Network clients in mind. It uses a [new proposal](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-June/014474.html) for compact block filters to minimize bandwidth and storage use on the client side, while attempting to preserve privacy and minimize processor load on full nodes serving light clients.

## Mechanism of operation
The light client synchronizes only block headers and a chain of compact block filter headers specifying the correct filters for each block. Filters are loaded lazily and stored in the database upon request; blocks are loaded lazily and not saved. There are multiple [known major issues](https://github.com/lightninglabs/neutrino/issues) with the client, so it is **not recommended** to use it with real money at this point.

## Usage
The client is instantiated as an object using `NewChainService` and then started. Upon start, the client sets up its database and other relevant files and connects to the p2p network. At this point, it becomes possible to query the client.

### Queries
There are various types of queries supported by the client. There are many ways to access the database, for example, to get block headers by height and hash; in addition, it's possible to get a full block from the network using `GetBlockFromNetwork` by hash. However, the most useful methods are specifically tailored to scan the blockchain for data relevant to a wallet or a smart contract platform such as a [Lightning Network node like `lnd`](https://github.com/lightningnetwork/lnd). These are described below.

#### Rescan
`Rescan` allows a wallet to scan a chain for specific TXIDs, outputs, and addresses. A start and end block may be specified along with other options. If no end block is specified, the rescan continues until stopped. If no start block is specified, the rescan begins with the latest known block. While a rescan runs, it notifies the client of each connected and disconnected block; the notifications follow the [btcjson](https://github.com/btcsuite/btcd/blob/master/btcjson/chainsvrwsntfns.go) format with the option to use any of the relevant notifications. It's important to note that "recvtx" and "redeemingtx" notifications are only sent when a transaction is confirmed, not when it enters the mempool; the client does not currently support accepting 0-confirmation transactions.

#### GetUtxo
`GetUtxo` allows a wallet or smart contract platform to check that a UTXO exists on the blockchain and has not been spent. It is **highly recommended** to specify a start block; otherwise, in the event that the UTXO doesn't exist on the blockchain, the client will download all the filters back to block 1 searching for it. The client scans from the tip of the chain backwards, stopping when it finds the UTXO having been either spent or created; if it finds neither, it keeps scanning backwards until it hits the specified start block or, if a start block isn't specified, the first block in the blockchain. It returns a `SpendReport` containing either a `TxOut` including the `PkScript` required to spend the output, or containing information about the spending transaction, spending input, and block height in which the spending transaction was seen.

### Stopping the client
Calling `Stop` on the `ChainService` client allows the user to stop the client; the method doesn't return until the `ChainService` is cleanly shut down.
