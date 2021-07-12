package pushtx

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino/blockntfns"
)

var (
	// ErrBroadcastStopped is an error returned when we attempt to process a
	// request to broadcast a transaction but the Broadcaster has already
	// been stopped.
	ErrBroadcasterStopped = errors.New("broadcaster has been stopped")
)

const (
	// DefaultRebroadcastInterval is the default period that we'll wait
	// between blocks to attempt another rebroadcast.
	DefaultRebroadcastInterval = time.Minute
)

// broadcastReq is an internal message the Broadcaster will use to process
// transaction broadcast requests.
type broadcastReq struct {
	tx      *wire.MsgTx
	errChan chan error
}

// Config contains all of the external dependencies required for the Broadcaster
// to properly carry out its duties.
type Config struct {
	// Broadcast broadcasts a transaction to the network. We expect certain
	// BroadcastError's to be returned to handle special cases, namely
	// errors with the codes Mempool and Confirmed.
	Broadcast func(*wire.MsgTx) error

	// SubscribeBlocks returns a block subscription that delivers block
	// notifications in order. This will be used to rebroadcast all
	// transactions once a new block arrives.
	SubscribeBlocks func() (*blockntfns.Subscription, error)

	// RebroadcastInterval is the interval that we'll continually try to
	// re-broadcast transactions in-between new block arrival.
	RebroadcastInterval time.Duration
}

// Broadcaster is a subsystem responsible for reliably broadcasting transactions
// to the network. Each transaction will be rebroadcast upon every new block
// being connected/disconnected to/from the chain.
type Broadcaster struct {
	start sync.Once
	stop  sync.Once

	cfg Config

	// broadcastReqs is a channel through which new transaction broadcast
	// requests from external callers will be streamed through.
	broadcastReqs chan *broadcastReq

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewBroadcaster creates a new Broadcaster backed by the given config.
func NewBroadcaster(cfg *Config) *Broadcaster {
	b := &Broadcaster{
		cfg:           *cfg,
		broadcastReqs: make(chan *broadcastReq),
		quit:          make(chan struct{}),
	}

	return b
}

// Start starts all of the necessary steps for the Broadcaster to begin properly
// carrying out its duties.
func (b *Broadcaster) Start() error {
	var err error
	b.start.Do(func() {
		sub, err := b.cfg.SubscribeBlocks()
		if err != nil {
			err = fmt.Errorf("unable to subscribe for block "+
				"notifications: %v", err)
			return
		}

		b.wg.Add(1)
		go b.broadcastHandler(sub)
	})
	return err
}

// Stop halts the Broadcaster from rebroadcasting pending transactions.
func (b *Broadcaster) Stop() {
	b.stop.Do(func() {
		close(b.quit)
		b.wg.Wait()
	})
}

// broadcastHandler is the main event handler of the Broadcaster responsible for
// handling new broadcast requests, rebroadcasting transactions upon every new
// block, etc.
//
// NOTE: This must be run as a goroutine.
func (b *Broadcaster) broadcastHandler(sub *blockntfns.Subscription) {
	defer b.wg.Done()
	defer sub.Cancel()

	log.Infof("Broadcaster now active")

	// transactions is the set of transactions we have broadcast so far,
	// and are still not confirmed.
	transactions := make(map[chainhash.Hash]*wire.MsgTx)

	// confChan is a channel used to notify the broadcast handler about
	// confirmed transactions.
	confChan := make(chan chainhash.Hash)

	// The rebroadcast semaphore is used to ensure we have only one
	// rebroadcast running at a time.
	rebroadcastSem := make(chan struct{}, 1)
	rebroadcastSem <- struct{}{}

	// triggerRebroadcast is a helper method that checks whether the
	// rebroadcast semaphore is available, and if it is spawns a goroutine
	// to rebroadcast all pending transactions.
	triggerRebroadcast := func() {
		select {
		// If the rebroadcast semaphore is available, start a
		// new goroutine to exectue a rebroadcast.
		case <-rebroadcastSem:
		default:
			log.Tracef("Existing rebroadcast still in " +
				"progress")
			return
		}

		// Make a copy of the current set of transactions to hand to
		// the goroutine.
		txs := make(map[chainhash.Hash]*wire.MsgTx)
		for k, v := range transactions {
			txs[k] = v.Copy()
		}

		b.wg.Add(1)
		go func() {
			defer b.wg.Done()

			b.rebroadcast(txs, confChan)
			rebroadcastSem <- struct{}{}
		}()

	}

	reBroadcastTicker := time.NewTicker(b.cfg.RebroadcastInterval)
	defer reBroadcastTicker.Stop()

	for {
		select {
		// A new broadcast request was submitted by an external caller.
		case req := <-b.broadcastReqs:
			err := b.cfg.Broadcast(req.tx)
			if err != nil && !IsBroadcastError(err, Mempool) {
				log.Errorf("Broadcast attempt failed: %v", err)
				req.errChan <- err
				continue
			}

			transactions[req.tx.TxHash()] = req.tx
			req.errChan <- nil

		// A tx was confirmed, and we can remove it from our set of
		// transactions.
		case txHash := <-confChan:
			delete(transactions, txHash)

		// A new block notification has arrived, so we'll rebroadcast
		// all of our pending transactions.
		case _, ok := <-sub.Notifications:
			if !ok {
				log.Warn("Unable to rebroadcast transactions: " +
					"block subscription was canceled")
				continue
			}
			triggerRebroadcast()

		// Between blocks, we'll also try to attempt additional
		// re-broadcasts to ensure a timely confirmation.
		case <-reBroadcastTicker.C:
			triggerRebroadcast()

		case <-b.quit:
			return
		}
	}
}

// rebroadcast rebroadcasts all of the currently pending transactions. Care has
// been taken to ensure that the transactions are sorted in their dependency
// order to prevent peers from deeming our transactions as invalid due to
// broadcasting them before their pending dependencies.
func (b *Broadcaster) rebroadcast(txs map[chainhash.Hash]*wire.MsgTx,
	confChan chan<- chainhash.Hash) {

	// Return immediately if there are no transactions to re-broadcast.
	if len(txs) == 0 {
		return
	}

	log.Debugf("Re-broadcasting %d transactions", len(txs))

	sortedTxs := wtxmgr.DependencySort(txs)
	for _, tx := range sortedTxs {
		// Before attempting to broadcast this transaction, we check
		// whether we are shutting down.
		select {
		case <-b.quit:
			return
		default:
		}

		err := b.cfg.Broadcast(tx)
		switch {
		// If the transaction has already confirmed on-chain, we can
		// stop broadcasting it further.
		//
		// TODO(wilmer); This should ideally be implemented by checking
		// the chain ourselves rather than trusting our peers.
		case IsBroadcastError(err, Confirmed):
			log.Debugf("Re-broadcast of txid=%v, now confirmed!",
				tx.TxHash())

			select {
			case confChan <- tx.TxHash():
			case <-b.quit:
				return
			}
			continue

		// If the transaction already exists within our peers' mempool,
		// we'll continue to rebroadcast it to ensure it actually
		// propagates throughout the network.
		//
		// TODO(wilmer): Rate limit peers that have already accepted our
		// transaction into their mempool to prevent resending to them
		// every time.
		case IsBroadcastError(err, Mempool):
			log.Debugf("Re-broadcast of txid=%v, still "+
				"pending...", tx.TxHash())

			continue

		case err != nil:
			log.Errorf("Unable to rebroadcast transaction %v: %v",
				tx.TxHash(), err)
			continue
		}
	}
}

// Broadcast submits a request to the Broadcaster to reliably broadcast the
// given transaction. An error won't be returned if the transaction already
// exists within the mempool. Any transaction broadcast through this method will
// be rebroadcast upon every change of the tip of the chain.
func (b *Broadcaster) Broadcast(tx *wire.MsgTx) error {
	errChan := make(chan error, 1)

	select {
	case b.broadcastReqs <- &broadcastReq{
		tx:      tx,
		errChan: errChan,
	}:
	case <-b.quit:
		return ErrBroadcasterStopped
	}

	select {
	case err := <-errChan:
		return err
	case <-b.quit:
		return ErrBroadcasterStopped
	}
}
