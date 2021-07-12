// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chain

import (
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// RPCClient represents a persistent client connection to a bitcoin RPC server
// for information regarding the current best block chain.
type RPCClient struct {
	*rpcclient.Client
	connConfig        *rpcclient.ConnConfig // Work around unexported field
	chainParams       *chaincfg.Params
	reconnectAttempts int

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	currentBlock        chan *waddrmgr.BlockStamp

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex
}

// NewRPCClient creates a client connection to the server described by the
// connect string.  If disableTLS is false, the remote RPC certificate must be
// provided in the certs slice.  The connection is not established immediately,
// but must be done using the Start method.  If the remote server does not
// operate on the same bitcoin network as described by the passed chain
// parameters, the connection will be disconnected.
func NewRPCClient(chainParams *chaincfg.Params, connect, user, pass string, certs []byte,
	disableTLS bool, reconnectAttempts int) (*RPCClient, error) {

	if reconnectAttempts < 0 {
		return nil, errors.New("reconnectAttempts must be positive")
	}

	client := &RPCClient{
		connConfig: &rpcclient.ConnConfig{
			Host:                 connect,
			Endpoint:             "ws",
			User:                 user,
			Pass:                 pass,
			Certificates:         certs,
			DisableAutoReconnect: false,
			DisableConnectOnNew:  true,
			DisableTLS:           disableTLS,
		},
		chainParams:         chainParams,
		reconnectAttempts:   reconnectAttempts,
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan *waddrmgr.BlockStamp),
		quit:                make(chan struct{}),
	}
	ntfnCallbacks := &rpcclient.NotificationHandlers{
		OnClientConnected:   client.onClientConnect,
		OnBlockConnected:    client.onBlockConnected,
		OnBlockDisconnected: client.onBlockDisconnected,
		OnRecvTx:            client.onRecvTx,
		OnRedeemingTx:       client.onRedeemingTx,
		OnRescanFinished:    client.onRescanFinished,
		OnRescanProgress:    client.onRescanProgress,
	}
	rpcClient, err := rpcclient.New(client.connConfig, ntfnCallbacks)
	if err != nil {
		return nil, err
	}
	client.Client = rpcClient
	return client, nil
}

// BackEnd returns the name of the driver.
func (c *RPCClient) BackEnd() string {
	return "btcd"
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *RPCClient) Start() error {
	err := c.Connect(c.reconnectAttempts)
	if err != nil {
		return err
	}

	// Verify that the server is running on the expected network.
	net, err := c.GetCurrentNet()
	if err != nil {
		c.Disconnect()
		return err
	}
	if net != c.chainParams.Net {
		c.Disconnect()
		return errors.New("mismatched networks")
	}

	c.quitMtx.Lock()
	c.started = true
	c.quitMtx.Unlock()

	c.wg.Add(1)
	go c.handler()
	return nil
}

// Stop disconnects the client and signals the shutdown of all goroutines
// started by Start.
func (c *RPCClient) Stop() {
	c.quitMtx.Lock()
	select {
	case <-c.quit:
	default:
		close(c.quit)
		c.Client.Shutdown()

		if !c.started {
			close(c.dequeueNotification)
		}
	}
	c.quitMtx.Unlock()
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (c *RPCClient) IsCurrent() bool {
	bestHash, _, err := c.GetBestBlock()
	if err != nil {
		return false
	}
	bestHeader, err := c.GetBlockHeader(bestHash)
	if err != nil {
		return false
	}
	return bestHeader.Timestamp.After(time.Now().Add(-isCurrentDelta))
}

// Rescan wraps the normal Rescan command with an additional paramter that
// allows us to map an oupoint to the address in the chain that it pays to.
// This is useful when using BIP 158 filters as they include the prev pkScript
// rather than the full outpoint.
func (c *RPCClient) Rescan(startHash *chainhash.Hash, addrs []btcutil.Address,
	outPoints map[wire.OutPoint]btcutil.Address) error {

	flatOutpoints := make([]*wire.OutPoint, 0, len(outPoints))
	for ops := range outPoints {
		flatOutpoints = append(flatOutpoints, &ops)
	}

	return c.Client.Rescan(startHash, addrs, flatOutpoints)
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *RPCClient) WaitForShutdown() {
	c.Client.WaitForShutdown()
	c.wg.Wait()
}

// Notifications returns a channel of parsed notifications sent by the remote
// bitcoin RPC server.  This channel must be continually read or the process
// may abort for running out memory, as unread notifications are queued for
// later reads.
func (c *RPCClient) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *RPCClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-c.currentBlock:
		return bs, nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. For each requested block, the corresponding compact
// filter will first be checked for matches, skipping those that do not report
// anything. If the filter returns a postive match, the full block will be
// fetched and filtered. This method returns a FilterBlocksReponse for the first
// block containing a matching address. If no matches are found in the range of
// blocks requested, the returned response will be nil.
func (c *RPCClient) FilterBlocks(
	req *FilterBlocksRequest) (*FilterBlocksResponse, error) {

	blockFilterer := NewBlockFilterer(c.chainParams, req)

	// Construct the watchlist using the addresses and outpoints contained
	// in the filter blocks request.
	watchList, err := buildFilterBlocksWatchList(req)
	if err != nil {
		return nil, err
	}

	// Iterate over the requested blocks, fetching the compact filter for
	// each one, and matching it against the watchlist generated above. If
	// the filter returns a positive match, the full block is then requested
	// and scanned for addresses using the block filterer.
	for i, blk := range req.Blocks {
		rawFilter, err := c.GetCFilter(&blk.Hash, wire.GCSFilterRegular)
		if err != nil {
			return nil, err
		}

		// Ensure the filter is large enough to be deserialized.
		if len(rawFilter.Data) < 4 {
			continue
		}

		filter, err := gcs.FromNBytes(
			builder.DefaultP, builder.DefaultM, rawFilter.Data,
		)
		if err != nil {
			return nil, err
		}

		// Skip any empty filters.
		if filter.N() == 0 {
			continue
		}

		key := builder.DeriveKey(&blk.Hash)
		matched, err := filter.MatchAny(key, watchList)
		if err != nil {
			return nil, err
		} else if !matched {
			continue
		}

		log.Infof("Fetching block height=%d hash=%v",
			blk.Height, blk.Hash)

		rawBlock, err := c.GetBlock(&blk.Hash)
		if err != nil {
			return nil, err
		}

		if !blockFilterer.FilterBlock(rawBlock) {
			continue
		}

		// If any external or internal addresses were detected in this
		// block, we return them to the caller so that the rescan
		// windows can widened with subsequent addresses. The
		// `BatchIndex` is returned so that the caller can compute the
		// *next* block from which to begin again.
		resp := &FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          blk,
			FoundExternalAddrs: blockFilterer.FoundExternal,
			FoundInternalAddrs: blockFilterer.FoundInternal,
			FoundOutPoints:     blockFilterer.FoundOutPoints,
			RelevantTxns:       blockFilterer.RelevantTxns,
		}

		return resp, nil
	}

	// No addresses were found for this range.
	return nil, nil
}

// parseBlock parses a btcws definition of the block a tx is mined it to the
// Block structure of the wtxmgr package, and the block index.  This is done
// here since rpcclient doesn't parse this nicely for us.
func parseBlock(block *btcjson.BlockDetails) (*wtxmgr.BlockMeta, error) {
	if block == nil {
		return nil, nil
	}
	blkHash, err := chainhash.NewHashFromStr(block.Hash)
	if err != nil {
		return nil, err
	}
	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Height: block.Height,
			Hash:   *blkHash,
		},
		Time: time.Unix(block.Time, 0),
	}
	return blk, nil
}

func (c *RPCClient) onClientConnect() {
	select {
	case c.enqueueNotification <- ClientConnected{}:
	case <-c.quit:
	}
}

func (c *RPCClient) onBlockConnected(hash *chainhash.Hash, height int32, time time.Time) {
	select {
	case c.enqueueNotification <- BlockConnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *RPCClient) onBlockDisconnected(hash *chainhash.Hash, height int32, time time.Time) {
	select {
	case c.enqueueNotification <- BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRecvTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	blk, err := parseBlock(block)
	if err != nil {
		// Log and drop improper notification.
		log.Errorf("recvtx notification bad block: %v", err)
		return
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx(), time.Now())
	if err != nil {
		log.Errorf("Cannot create transaction record for relevant "+
			"tx: %v", err)
		return
	}
	select {
	case c.enqueueNotification <- RelevantTx{rec, blk}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRedeemingTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	// Handled exactly like recvtx notifications.
	c.onRecvTx(tx, block)
}

func (c *RPCClient) onRescanProgress(hash *chainhash.Hash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanProgress{hash, height, blkTime}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRescanFinished(hash *chainhash.Hash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanFinished{hash, height, blkTime}:
	case <-c.quit:
	}

}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *RPCClient) handler() {
	hash, height, err := c.GetBestBlock()
	if err != nil {
		log.Errorf("Failed to receive best block from chain server: %v", err)
		c.Stop()
		c.wg.Done()
		return
	}

	bs := &waddrmgr.BlockStamp{Hash: *hash, Height: height}

	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	var notifications []interface{}
	enqueue := c.enqueueNotification
	var dequeue chan interface{}
	var next interface{}
out:
	for {
		select {
		case n, ok := <-enqueue:
			if !ok {
				// If no notifications are queued for handling,
				// the queue is finished.
				if len(notifications) == 0 {
					break out
				}
				// nil channel so no more reads can occur.
				enqueue = nil
				continue
			}
			if len(notifications) == 0 {
				next = n
				dequeue = c.dequeueNotification
			}
			notifications = append(notifications, n)

		case dequeue <- next:
			if n, ok := next.(BlockConnected); ok {
				bs = &waddrmgr.BlockStamp{
					Height: n.Height,
					Hash:   n.Hash,
				}
			}

			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				// If no more notifications can be enqueued, the
				// queue is finished.
				if enqueue == nil {
					break out
				}
				dequeue = nil
			}

		case c.currentBlock <- bs:

		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
	c.wg.Done()
}

// POSTClient creates the equivalent HTTP POST rpcclient.Client.
func (c *RPCClient) POSTClient() (*rpcclient.Client, error) {
	configCopy := *c.connConfig
	configCopy.HTTPPostMode = true
	return rpcclient.New(&configCopy, nil)
}
