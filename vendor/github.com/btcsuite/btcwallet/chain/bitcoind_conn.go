package chain

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/gozmq"
)

const (
	// rawBlockZMQCommand is the command used to receive raw block
	// notifications from bitcoind through ZMQ.
	rawBlockZMQCommand = "rawblock"

	// rawTxZMQCommand is the command used to receive raw transaction
	// notifications from bitcoind through ZMQ.
	rawTxZMQCommand = "rawtx"

	// maxRawBlockSize is the maximum size in bytes for a raw block received
	// from bitcoind through ZMQ.
	maxRawBlockSize = 4e6

	// maxRawTxSize is the maximum size in bytes for a raw transaction
	// received from bitcoind through ZMQ.
	maxRawTxSize = maxRawBlockSize

	// seqNumLen is the length of the sequence number of a message sent from
	// bitcoind through ZMQ.
	seqNumLen = 4
)

// BitcoindConn represents a persistent client connection to a bitcoind node
// that listens for events read from a ZMQ connection.
type BitcoindConn struct {
	started int32 // To be used atomically.
	stopped int32 // To be used atomically.

	// rescanClientCounter is an atomic counter that assigns a unique ID to
	// each new bitcoind rescan client using the current bitcoind
	// connection.
	rescanClientCounter uint64

	// chainParams identifies the current network the bitcoind node is
	// running on.
	chainParams *chaincfg.Params

	// client is the RPC client to the bitcoind node.
	client *rpcclient.Client

	// zmqBlockConn is the ZMQ connection we'll use to read raw block
	// events.
	zmqBlockConn *gozmq.Conn

	// zmqTxConn is the ZMQ connection we'll use to read raw transaction
	// events.
	zmqTxConn *gozmq.Conn

	// rescanClients is the set of active bitcoind rescan clients to which
	// ZMQ event notfications will be sent to.
	rescanClientsMtx sync.Mutex
	rescanClients    map[uint64]*BitcoindClient

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewBitcoindConn creates a client connection to the node described by the host
// string. The ZMQ connections are established immediately to ensure liveness.
// If the remote node does not operate on the same bitcoin network as described
// by the passed chain parameters, the connection will be disconnected.
func NewBitcoindConn(chainParams *chaincfg.Params,
	host, user, pass, zmqBlockHost, zmqTxHost string,
	zmqPollInterval time.Duration) (*BitcoindConn, error) {

	clientCfg := &rpcclient.ConnConfig{
		Host:                 host,
		User:                 user,
		Pass:                 pass,
		DisableAutoReconnect: false,
		DisableConnectOnNew:  true,
		DisableTLS:           true,
		HTTPPostMode:         true,
	}

	client, err := rpcclient.New(clientCfg, nil)
	if err != nil {
		return nil, err
	}

	// Establish two different ZMQ connections to bitcoind to retrieve block
	// and transaction event notifications. We'll use two as a separation of
	// concern to ensure one type of event isn't dropped from the connection
	// queue due to another type of event filling it up.
	zmqBlockConn, err := gozmq.Subscribe(
		zmqBlockHost, []string{rawBlockZMQCommand}, zmqPollInterval,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to subscribe for zmq block "+
			"events: %v", err)
	}

	zmqTxConn, err := gozmq.Subscribe(
		zmqTxHost, []string{rawTxZMQCommand}, zmqPollInterval,
	)
	if err != nil {
		zmqBlockConn.Close()
		return nil, fmt.Errorf("unable to subscribe for zmq tx "+
			"events: %v", err)
	}

	conn := &BitcoindConn{
		chainParams:   chainParams,
		client:        client,
		zmqBlockConn:  zmqBlockConn,
		zmqTxConn:     zmqTxConn,
		rescanClients: make(map[uint64]*BitcoindClient),
		quit:          make(chan struct{}),
	}

	return conn, nil
}

// Start attempts to establish a RPC and ZMQ connection to a bitcoind node. If
// successful, a goroutine is spawned to read events from the ZMQ connection.
// It's possible for this function to fail due to a limited number of connection
// attempts. This is done to prevent waiting forever on the connection to be
// established in the case that the node is down.
func (c *BitcoindConn) Start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	// Verify that the node is running on the expected network.
	net, err := c.getCurrentNet()
	if err != nil {
		return err
	}
	if net != c.chainParams.Net {
		return fmt.Errorf("expected network %v, got %v",
			c.chainParams.Net, net)
	}

	c.wg.Add(2)
	go c.blockEventHandler()
	go c.txEventHandler()

	return nil
}

// Stop terminates the RPC and ZMQ connection to a bitcoind node and removes any
// active rescan clients.
func (c *BitcoindConn) Stop() {
	if !atomic.CompareAndSwapInt32(&c.stopped, 0, 1) {
		return
	}

	for _, client := range c.rescanClients {
		client.Stop()
	}

	close(c.quit)
	c.client.Shutdown()
	c.zmqBlockConn.Close()
	c.zmqTxConn.Close()

	c.client.WaitForShutdown()
	c.wg.Wait()
}

// blockEventHandler reads raw blocks events from the ZMQ block socket and
// forwards them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (c *BitcoindConn) blockEventHandler() {
	defer c.wg.Done()

	log.Info("Started listening for bitcoind block notifications via ZMQ "+
		"on", c.zmqBlockConn.RemoteAddr())

	// Set up the buffers we expect our messages to consume. ZMQ
	// messages from bitcoind include three parts: the command, the
	// data, and the sequence number.
	//
	// We'll allocate a fixed data slice that we'll reuse when reading
	// blocks from bitcoind through ZMQ. There's no need to recycle this
	// slice (zero out) after using it, as further reads will overwrite the
	// slice and we'll only be deserializing the bytes needed.
	var (
		command [len(rawBlockZMQCommand)]byte
		seqNum  [seqNumLen]byte
		data    = make([]byte, maxRawBlockSize)
	)

	for {
		// Before attempting to read from the ZMQ socket, we'll make
		// sure to check if we've been requested to shut down.
		select {
		case <-c.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			bufs = [][]byte{command[:], data, seqNum[:]}
			err  error
		)
		bufs, err = c.zmqBlockConn.Receive(bufs)
		if err != nil {
			// EOF should only be returned if the connection was
			// explicitly closed, so we can exit at this point.
			if err == io.EOF {
				return
			}

			// It's possible that the connection to the socket
			// continuously times out, so we'll prevent logging this
			// error to prevent spamming the logs.
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				log.Trace("Re-establishing timed out ZMQ " +
					"block connection")
				continue
			}

			log.Errorf("Unable to receive ZMQ %v message: %v",
				rawBlockZMQCommand, err)
			continue
		}

		// We have an event! We'll now ensure it is a block event,
		// deserialize it, and report it to the different rescan
		// clients.
		eventType := string(bufs[0])
		switch eventType {
		case rawBlockZMQCommand:
			block := &wire.MsgBlock{}
			r := bytes.NewReader(bufs[1])
			if err := block.Deserialize(r); err != nil {
				log.Errorf("Unable to deserialize block: %v",
					err)
				continue
			}

			c.rescanClientsMtx.Lock()
			for _, client := range c.rescanClients {
				select {
				case client.zmqBlockNtfns <- block:
				case <-client.quit:
				case <-c.quit:
					c.rescanClientsMtx.Unlock()
					return
				}
			}
			c.rescanClientsMtx.Unlock()
		default:
			// It's possible that the message wasn't fully read if
			// bitcoind shuts down, which will produce an unreadable
			// event type. To prevent from logging it, we'll make
			// sure it conforms to the ASCII standard.
			if eventType == "" || !isASCII(eventType) {
				continue
			}

			log.Warnf("Received unexpected event type from %v "+
				"subscription: %v", rawBlockZMQCommand,
				eventType)
		}
	}
}

// txEventHandler reads raw blocks events from the ZMQ block socket and forwards
// them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (c *BitcoindConn) txEventHandler() {
	defer c.wg.Done()

	log.Info("Started listening for bitcoind transaction notifications "+
		"via ZMQ on", c.zmqTxConn.RemoteAddr())

	// Set up the buffers we expect our messages to consume. ZMQ
	// messages from bitcoind include three parts: the command, the
	// data, and the sequence number.
	//
	// We'll allocate a fixed data slice that we'll reuse when reading
	// transactions from bitcoind through ZMQ. There's no need to recycle
	// this slice (zero out) after using it, as further reads will overwrite
	// the slice and we'll only be deserializing the bytes needed.
	var (
		command [len(rawTxZMQCommand)]byte
		seqNum  [seqNumLen]byte
		data    = make([]byte, maxRawTxSize)
	)

	for {
		// Before attempting to read from the ZMQ socket, we'll make
		// sure to check if we've been requested to shut down.
		select {
		case <-c.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			bufs = [][]byte{command[:], data, seqNum[:]}
			err  error
		)
		bufs, err = c.zmqTxConn.Receive(bufs)
		if err != nil {
			// EOF should only be returned if the connection was
			// explicitly closed, so we can exit at this point.
			if err == io.EOF {
				return
			}

			// It's possible that the connection to the socket
			// continuously times out, so we'll prevent logging this
			// error to prevent spamming the logs.
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				log.Trace("Re-establishing timed out ZMQ " +
					"transaction connection")
				continue
			}

			log.Errorf("Unable to receive ZMQ %v message: %v",
				rawTxZMQCommand, err)
			continue
		}

		// We have an event! We'll now ensure it is a transaction event,
		// deserialize it, and report it to the different rescan
		// clients.
		eventType := string(bufs[0])
		switch eventType {
		case rawTxZMQCommand:
			tx := &wire.MsgTx{}
			r := bytes.NewReader(bufs[1])
			if err := tx.Deserialize(r); err != nil {
				log.Errorf("Unable to deserialize "+
					"transaction: %v", err)
				continue
			}

			c.rescanClientsMtx.Lock()
			for _, client := range c.rescanClients {
				select {
				case client.zmqTxNtfns <- tx:
				case <-client.quit:
				case <-c.quit:
					c.rescanClientsMtx.Unlock()
					return
				}
			}
			c.rescanClientsMtx.Unlock()
		default:
			// It's possible that the message wasn't fully read if
			// bitcoind shuts down, which will produce an unreadable
			// event type. To prevent from logging it, we'll make
			// sure it conforms to the ASCII standard.
			if eventType == "" || !isASCII(eventType) {
				continue
			}

			log.Warnf("Received unexpected event type from %v "+
				"subscription: %v", rawTxZMQCommand, eventType)
		}
	}
}

// getCurrentNet returns the network on which the bitcoind node is running.
func (c *BitcoindConn) getCurrentNet() (wire.BitcoinNet, error) {
	hash, err := c.client.GetBlockHash(0)
	if err != nil {
		return 0, err
	}

	switch *hash {
	case *chaincfg.TestNet3Params.GenesisHash:
		return chaincfg.TestNet3Params.Net, nil
	case *chaincfg.RegressionNetParams.GenesisHash:
		return chaincfg.RegressionNetParams.Net, nil
	case *chaincfg.MainNetParams.GenesisHash:
		return chaincfg.MainNetParams.Net, nil
	default:
		return 0, fmt.Errorf("unknown network with genesis hash %v", hash)
	}
}

// NewBitcoindClient returns a bitcoind client using the current bitcoind
// connection. This allows us to share the same connection using multiple
// clients.
func (c *BitcoindConn) NewBitcoindClient() *BitcoindClient {
	return &BitcoindClient{
		quit: make(chan struct{}),

		id: atomic.AddUint64(&c.rescanClientCounter, 1),

		chainParams: c.chainParams,
		chainConn:   c,

		rescanUpdate:     make(chan interface{}),
		watchedAddresses: make(map[string]struct{}),
		watchedOutPoints: make(map[wire.OutPoint]struct{}),
		watchedTxs:       make(map[chainhash.Hash]struct{}),

		notificationQueue: NewConcurrentQueue(20),
		zmqTxNtfns:        make(chan *wire.MsgTx),
		zmqBlockNtfns:     make(chan *wire.MsgBlock),

		mempool:        make(map[chainhash.Hash]struct{}),
		expiredMempool: make(map[int32]map[chainhash.Hash]struct{}),
	}
}

// AddClient adds a client to the set of active rescan clients of the current
// chain connection. This allows the connection to include the specified client
// in its notification delivery.
//
// NOTE: This function is safe for concurrent access.
func (c *BitcoindConn) AddClient(client *BitcoindClient) {
	c.rescanClientsMtx.Lock()
	defer c.rescanClientsMtx.Unlock()

	c.rescanClients[client.id] = client
}

// RemoveClient removes the client with the given ID from the set of active
// rescan clients. Once removed, the client will no longer receive block and
// transaction notifications from the chain connection.
//
// NOTE: This function is safe for concurrent access.
func (c *BitcoindConn) RemoveClient(id uint64) {
	c.rescanClientsMtx.Lock()
	defer c.rescanClientsMtx.Unlock()

	delete(c.rescanClients, id)
}

// isASCII is a helper method that checks whether all bytes in `data` would be
// printable ASCII characters if interpreted as a string.
func isASCII(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
