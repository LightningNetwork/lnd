package neutrinonotify

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/queue"
)

const (
	// notifierType uniquely identifies this concrete implementation of the
	// ChainNotifier interface.
	notifierType = "neutrino"
)

// NeutrinoNotifier is a version of ChainNotifier that's backed by the neutrino
// Bitcoin light client. Unlike other implementations, this implementation
// speaks directly to the p2p network. As a result, this implementation of the
// ChainNotifier interface is much more light weight that other implementation
// which rely of receiving notification over an RPC interface backed by a
// running full node.
//
// TODO(roasbeef): heavily consolidate with NeutrinoNotifier code
//  * maybe combine into single package?
type NeutrinoNotifier struct {
	epochClientCounter uint64 // To be used atomically.

	start   sync.Once
	active  int32 // To be used atomically.
	stopped int32 // To be used atomically.

	bestBlockMtx sync.RWMutex
	bestBlock    chainntnfs.BlockEpoch

	p2pNode   *neutrino.ChainService
	chainView *neutrino.Rescan

	chainConn *NeutrinoChainConn

	notificationCancels  chan interface{}
	notificationRegistry chan interface{}

	txNotifier *chainntnfs.TxNotifier

	blockEpochClients map[uint64]*blockEpochRegistration

	rescanErr <-chan error

	chainUpdates *queue.ConcurrentQueue
	txUpdates    *queue.ConcurrentQueue

	// spendHintCache is a cache used to query and update the latest height
	// hints for an outpoint. Each height hint represents the earliest
	// height at which the outpoint could have been spent within the chain.
	spendHintCache chainntnfs.SpendHintCache

	// confirmHintCache is a cache used to query the latest height hints for
	// a transaction. Each height hint represents the earliest height at
	// which the transaction could have confirmed within the chain.
	confirmHintCache chainntnfs.ConfirmHintCache

	// blockCache is an LRU block cache.
	blockCache *blockcache.BlockCache

	wg   sync.WaitGroup
	quit chan struct{}
}

// Ensure NeutrinoNotifier implements the ChainNotifier interface at compile time.
var _ chainntnfs.ChainNotifier = (*NeutrinoNotifier)(nil)

// New creates a new instance of the NeutrinoNotifier concrete implementation
// of the ChainNotifier interface.
//
// NOTE: The passed neutrino node should already be running and active before
// being passed into this function.
func New(node *neutrino.ChainService, spendHintCache chainntnfs.SpendHintCache,
	confirmHintCache chainntnfs.ConfirmHintCache,
	blockCache *blockcache.BlockCache) *NeutrinoNotifier {

	return &NeutrinoNotifier{
		notificationCancels:  make(chan interface{}),
		notificationRegistry: make(chan interface{}),

		blockEpochClients: make(map[uint64]*blockEpochRegistration),

		p2pNode:   node,
		chainConn: &NeutrinoChainConn{node},

		rescanErr: make(chan error),

		chainUpdates: queue.NewConcurrentQueue(1000),
		txUpdates:    queue.NewConcurrentQueue(10),

		spendHintCache:   spendHintCache,
		confirmHintCache: confirmHintCache,

		blockCache: blockCache,

		quit: make(chan struct{}),
	}
}

// Start contacts the running neutrino light client and kicks off an initial
// empty rescan.
func (n *NeutrinoNotifier) Start() error {
	var startErr error
	n.start.Do(func() {
		startErr = n.startNotifier()
	})
	return startErr
}

// Stop shuts down the NeutrinoNotifier.
func (n *NeutrinoNotifier) Stop() error {
	// Already shutting down?
	if atomic.AddInt32(&n.stopped, 1) != 1 {
		return nil
	}

	close(n.quit)
	n.wg.Wait()

	n.chainUpdates.Stop()
	n.txUpdates.Stop()

	// Notify all pending clients of our shutdown by closing the related
	// notification channels.
	for _, epochClient := range n.blockEpochClients {
		close(epochClient.cancelChan)
		epochClient.wg.Wait()

		close(epochClient.epochChan)
	}
	n.txNotifier.TearDown()

	return nil
}

// Started returns true if this instance has been started, and false otherwise.
func (n *NeutrinoNotifier) Started() bool {
	return atomic.LoadInt32(&n.active) != 0
}

func (n *NeutrinoNotifier) startNotifier() error {
	// Start our concurrent queues before starting the rescan, to ensure
	// onFilteredBlockConnected and onRelavantTx callbacks won't be
	// blocked.
	n.chainUpdates.Start()
	n.txUpdates.Start()

	// First, we'll obtain the latest block height of the p2p node. We'll
	// start the auto-rescan from this point. Once a caller actually wishes
	// to register a chain view, the rescan state will be rewound
	// accordingly.
	startingPoint, err := n.p2pNode.BestBlock()
	if err != nil {
		n.txUpdates.Stop()
		n.chainUpdates.Stop()
		return err
	}
	n.bestBlock.Hash = &startingPoint.Hash
	n.bestBlock.Height = startingPoint.Height

	n.txNotifier = chainntnfs.NewTxNotifier(
		uint32(n.bestBlock.Height), chainntnfs.ReorgSafetyLimit,
		n.confirmHintCache, n.spendHintCache,
	)

	// Next, we'll create our set of rescan options. Currently it's
	// required that a user MUST set an addr/outpoint/txid when creating a
	// rescan. To get around this, we'll add a "zero" outpoint, that won't
	// actually be matched.
	var zeroInput neutrino.InputWithScript
	rescanOptions := []neutrino.RescanOption{
		neutrino.StartBlock(startingPoint),
		neutrino.QuitChan(n.quit),
		neutrino.NotificationHandlers(
			rpcclient.NotificationHandlers{
				OnFilteredBlockConnected:    n.onFilteredBlockConnected,
				OnFilteredBlockDisconnected: n.onFilteredBlockDisconnected,
				OnRedeemingTx:               n.onRelevantTx,
			},
		),
		neutrino.WatchInputs(zeroInput),
	}

	// Finally, we'll create our rescan struct, start it, and launch all
	// the goroutines we need to operate this ChainNotifier instance.
	n.chainView = neutrino.NewRescan(
		&neutrino.RescanChainSource{
			ChainService: n.p2pNode,
		},
		rescanOptions...,
	)
	n.rescanErr = n.chainView.Start()

	n.wg.Add(1)
	go n.notificationDispatcher()

	// Set the active flag now that we've completed the full
	// startup.
	atomic.StoreInt32(&n.active, 1)

	return nil
}

// filteredBlock represents a new block which has been connected to the main
// chain. The slice of transactions will only be populated if the block
// includes a transaction that confirmed one of our watched txids, or spends
// one of the outputs currently being watched.
type filteredBlock struct {
	hash   chainhash.Hash
	height uint32
	txns   []*btcutil.Tx

	// connected is true if this update is a new block and false if it is a
	// disconnected block.
	connect bool
}

// rescanFilterUpdate represents a request that will be sent to the
// notificaionRegistry in order to prevent race conditions between the filter
// update and new block notifications.
type rescanFilterUpdate struct {
	updateOptions []neutrino.UpdateOption
	errChan       chan error
}

// onFilteredBlockConnected is a callback which is executed each a new block is
// connected to the end of the main chain.
func (n *NeutrinoNotifier) onFilteredBlockConnected(height int32,
	header *wire.BlockHeader, txns []*btcutil.Tx) {

	// Append this new chain update to the end of the queue of new chain
	// updates.
	select {
	case n.chainUpdates.ChanIn() <- &filteredBlock{
		hash:    header.BlockHash(),
		height:  uint32(height),
		txns:    txns,
		connect: true,
	}:
	case <-n.quit:
	}
}

// onFilteredBlockDisconnected is a callback which is executed each time a new
// block has been disconnected from the end of the mainchain due to a re-org.
func (n *NeutrinoNotifier) onFilteredBlockDisconnected(height int32,
	header *wire.BlockHeader) {

	// Append this new chain update to the end of the queue of new chain
	// disconnects.
	select {
	case n.chainUpdates.ChanIn() <- &filteredBlock{
		hash:    header.BlockHash(),
		height:  uint32(height),
		connect: false,
	}:
	case <-n.quit:
	}
}

// relevantTx represents a relevant transaction to the notifier that fulfills
// any outstanding spend requests.
type relevantTx struct {
	tx      *btcutil.Tx
	details *btcjson.BlockDetails
}

// onRelevantTx is a callback that proxies relevant transaction notifications
// from the backend to the notifier's main event handler.
func (n *NeutrinoNotifier) onRelevantTx(tx *btcutil.Tx, details *btcjson.BlockDetails) {
	select {
	case n.txUpdates.ChanIn() <- &relevantTx{tx, details}:
	case <-n.quit:
	}
}

// connectFilteredBlock ...
func (n *NeutrinoNotifier) connectFilteredBlock(update *filteredBlock) {
	n.bestBlockMtx.Lock()
	if update.height != uint32(n.bestBlock.Height+1) {
		chainntnfs.Log.Infof("Missed blocks, " +
			"attempting to catch up")

		_, missedBlocks, err :=
			chainntnfs.HandleMissedBlocks(
				n.chainConn,
				n.txNotifier,
				n.bestBlock,
				int32(update.height),
				false,
			)
		if err != nil {
			chainntnfs.Log.Error(err)
			n.bestBlockMtx.Unlock()
			return
		}

		for _, block := range missedBlocks {
			filteredBlock, err :=
				n.getFilteredBlock(block)
			if err != nil {
				chainntnfs.Log.Error(err)
				n.bestBlockMtx.Unlock()
				return
			}
			err = n.handleBlockConnected(filteredBlock)
			if err != nil {
				chainntnfs.Log.Error(err)
				n.bestBlockMtx.Unlock()
				return
			}
		}
	}

	err := n.handleBlockConnected(update)
	if err != nil {
		chainntnfs.Log.Error(err)
	}

	n.bestBlockMtx.Unlock()
}

// disconnectFilteredBlock ...
func (n *NeutrinoNotifier) disconnectFilteredBlock(update *filteredBlock) {
	n.bestBlockMtx.Lock()

	if update.height != uint32(n.bestBlock.Height) {
		chainntnfs.Log.Infof("Missed disconnected " +
			"blocks, attempting to catch up")
	}
	newBestBlock, err := chainntnfs.RewindChain(
		n.chainConn, n.txNotifier, n.bestBlock,
		int32(update.height-1),
	)
	if err != nil {
		chainntnfs.Log.Errorf("Unable to rewind chain "+
			"from height %d to height %d: %v",
			n.bestBlock.Height, update.height-1, err)
	}

	n.bestBlock = newBestBlock
	n.bestBlockMtx.Unlock()
}

// notificationDispatcher is the primary goroutine which handles client
// notification registrations, as well as notification dispatches.
func (n *NeutrinoNotifier) notificationDispatcher() {
	defer n.wg.Done()

	for {
		select {
		case cancelMsg := <-n.notificationCancels:
			switch msg := cancelMsg.(type) {
			case *epochCancel:
				chainntnfs.Log.Infof("Cancelling epoch "+
					"notification, epoch_id=%v", msg.epochID)

				// First, we'll lookup the original
				// registration in order to stop the active
				// queue goroutine.
				reg := n.blockEpochClients[msg.epochID]
				reg.epochQueue.Stop()

				// Next, close the cancel channel for this
				// specific client, and wait for the client to
				// exit.
				close(n.blockEpochClients[msg.epochID].cancelChan)
				n.blockEpochClients[msg.epochID].wg.Wait()

				// Once the client has exited, we can then
				// safely close the channel used to send epoch
				// notifications, in order to notify any
				// listeners that the intent has been
				// canceled.
				close(n.blockEpochClients[msg.epochID].epochChan)
				delete(n.blockEpochClients, msg.epochID)
			}

		case registerMsg := <-n.notificationRegistry:
			switch msg := registerMsg.(type) {
			case *chainntnfs.HistoricalConfDispatch:
				// We'll start a historical rescan chain of the
				// chain asynchronously to prevent blocking
				// potentially long rescans.
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()

					confDetails, err := n.historicalConfDetails(
						msg.ConfRequest,
						msg.StartHeight, msg.EndHeight,
					)
					if err != nil {
						chainntnfs.Log.Error(err)
						return
					}

					// If the historical dispatch finished
					// without error, we will invoke
					// UpdateConfDetails even if none were
					// found. This allows the notifier to
					// begin safely updating the height hint
					// cache at tip, since any pending
					// rescans have now completed.
					err = n.txNotifier.UpdateConfDetails(
						msg.ConfRequest, confDetails,
					)
					if err != nil {
						chainntnfs.Log.Error(err)
					}
				}()

			case *blockEpochRegistration:
				chainntnfs.Log.Infof("New block epoch subscription")

				n.blockEpochClients[msg.epochID] = msg

				// If the client did not provide their best
				// known block, then we'll immediately dispatch
				// a notification for the current tip.
				if msg.bestBlock == nil {
					n.notifyBlockEpochClient(
						msg, n.bestBlock.Height,
						n.bestBlock.Hash,
					)

					msg.errorChan <- nil
					continue
				}

				// Otherwise, we'll attempt to deliver the
				// backlog of notifications from their best
				// known block.
				n.bestBlockMtx.Lock()
				bestHeight := n.bestBlock.Height
				n.bestBlockMtx.Unlock()

				missedBlocks, err := chainntnfs.GetClientMissedBlocks(
					n.chainConn, msg.bestBlock, bestHeight,
					false,
				)
				if err != nil {
					msg.errorChan <- err
					continue
				}

				for _, block := range missedBlocks {
					n.notifyBlockEpochClient(
						msg, block.Height, block.Hash,
					)
				}

				msg.errorChan <- nil

			case *rescanFilterUpdate:
				err := n.chainView.Update(msg.updateOptions...)
				if err != nil {
					chainntnfs.Log.Errorf("Unable to "+
						"update rescan filter: %v", err)
				}

				// Drain the queue here.
			outer:
				for {
					select {
					case item := <-n.chainUpdates.ChanOut():
						update := item.(*filteredBlock)
						if update.connect {
							n.connectFilteredBlock(update)
							break
						}
						n.disconnectFilteredBlock(update)
					default:
						break outer
					}
				}

				msg.errChan <- err
			}

		case item := <-n.chainUpdates.ChanOut():
			update := item.(*filteredBlock)
			if update.connect {
				n.connectFilteredBlock(update)
				continue
			}

			n.disconnectFilteredBlock(update)

		case txUpdate := <-n.txUpdates.ChanOut():
			// A new relevant transaction notification has been
			// received from the backend. We'll attempt to process
			// it to determine if it fulfills any outstanding
			// confirmation and/or spend requests and dispatch
			// notifications for them.
			update := txUpdate.(*relevantTx)
			err := n.txNotifier.ProcessRelevantSpendTx(
				update.tx, uint32(update.details.Height),
			)
			if err != nil {
				chainntnfs.Log.Errorf("Unable to process "+
					"transaction %v: %v", update.tx.Hash(),
					err)
			}

		case err := <-n.rescanErr:
			chainntnfs.Log.Errorf("Error during rescan: %v", err)

		case <-n.quit:
			return

		}
	}
}

// historicalConfDetails looks up whether a confirmation request (txid/output
// script) has already been included in a block in the active chain and, if so,
// returns details about said block.
func (n *NeutrinoNotifier) historicalConfDetails(confRequest chainntnfs.ConfRequest,
	startHeight, endHeight uint32) (*chainntnfs.TxConfirmation, error) {

	// Starting from the height hint, we'll walk forwards in the chain to
	// see if this transaction/output script has already been confirmed.
	for scanHeight := endHeight; scanHeight >= startHeight && scanHeight > 0; scanHeight-- {
		// Ensure we haven't been requested to shut down before
		// processing the next height.
		select {
		case <-n.quit:
			return nil, chainntnfs.ErrChainNotifierShuttingDown
		default:
		}

		// First, we'll fetch the block header for this height so we
		// can compute the current block hash.
		blockHash, err := n.p2pNode.GetBlockHash(int64(scanHeight))
		if err != nil {
			return nil, fmt.Errorf("unable to get header for height=%v: %v",
				scanHeight, err)
		}

		// With the hash computed, we can now fetch the basic filter for this
		// height. Since the range of required items is known we avoid
		// roundtrips by requesting a batched response and save bandwidth by
		// limiting the max number of items per batch. Since neutrino populates
		// its underline filters cache with the batch response, the next call
		// will execute a network query only once per batch and not on every
		// iteration.
		regFilter, err := n.p2pNode.GetCFilter(
			*blockHash, wire.GCSFilterRegular,
			neutrino.NumRetries(5),
			neutrino.OptimisticReverseBatch(),
			neutrino.MaxBatchSize(int64(scanHeight-startHeight+1)),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve regular filter for "+
				"height=%v: %v", scanHeight, err)
		}

		// In the case that the filter exists, we'll attempt to see if
		// any element in it matches our target public key script.
		key := builder.DeriveKey(blockHash)
		match, err := regFilter.Match(key, confRequest.PkScript.Script())
		if err != nil {
			return nil, fmt.Errorf("unable to query filter: %v", err)
		}

		// If there's no match, then we can continue forward to the
		// next block.
		if !match {
			continue
		}

		// In the case that we do have a match, we'll fetch the block
		// from the network so we can find the positional data required
		// to send the proper response.
		block, err := n.GetBlock(*blockHash)
		if err != nil {
			return nil, fmt.Errorf("unable to get block from network: %v", err)
		}

		// For every transaction in the block, check which one matches
		// our request. If we find one that does, we can dispatch its
		// confirmation details.
		for i, tx := range block.Transactions() {
			if !confRequest.MatchesTx(tx.MsgTx()) {
				continue
			}

			return &chainntnfs.TxConfirmation{
				Tx:          tx.MsgTx(),
				BlockHash:   blockHash,
				BlockHeight: scanHeight,
				TxIndex:     uint32(i),
			}, nil
		}
	}

	return nil, nil
}

// handleBlockConnected applies a chain update for a new block. Any watched
// transactions included this block will processed to either send notifications
// now or after numConfirmations confs.
//
// NOTE: This method must be called with the bestBlockMtx lock held.
func (n *NeutrinoNotifier) handleBlockConnected(newBlock *filteredBlock) error {
	// We'll extend the txNotifier's height with the information of this new
	// block, which will handle all of the notification logic for us.
	err := n.txNotifier.ConnectTip(
		&newBlock.hash, newBlock.height, newBlock.txns,
	)
	if err != nil {
		return fmt.Errorf("unable to connect tip: %v", err)
	}

	chainntnfs.Log.Infof("New block: height=%v, sha=%v", newBlock.height,
		newBlock.hash)

	// Now that we've guaranteed the new block extends the txNotifier's
	// current tip, we'll proceed to dispatch notifications to all of our
	// registered clients whom have had notifications fulfilled. Before
	// doing so, we'll make sure update our in memory state in order to
	// satisfy any client requests based upon the new block.
	n.bestBlock.Hash = &newBlock.hash
	n.bestBlock.Height = int32(newBlock.height)

	n.notifyBlockEpochs(int32(newBlock.height), &newBlock.hash)
	return n.txNotifier.NotifyHeight(newBlock.height)
}

// getFilteredBlock is a utility to retrieve the full filtered block from a block epoch.
func (n *NeutrinoNotifier) getFilteredBlock(epoch chainntnfs.BlockEpoch) (*filteredBlock, error) {
	rawBlock, err := n.GetBlock(*epoch.Hash)
	if err != nil {
		return nil, fmt.Errorf("unable to get block: %v", err)
	}

	txns := rawBlock.Transactions()

	block := &filteredBlock{
		hash:    *epoch.Hash,
		height:  uint32(epoch.Height),
		txns:    txns,
		connect: true,
	}
	return block, nil
}

// notifyBlockEpochs notifies all registered block epoch clients of the newly
// connected block to the main chain.
func (n *NeutrinoNotifier) notifyBlockEpochs(newHeight int32, newSha *chainhash.Hash) {
	for _, client := range n.blockEpochClients {
		n.notifyBlockEpochClient(client, newHeight, newSha)
	}
}

// notifyBlockEpochClient sends a registered block epoch client a notification
// about a specific block.
func (n *NeutrinoNotifier) notifyBlockEpochClient(epochClient *blockEpochRegistration,
	height int32, sha *chainhash.Hash) {

	epoch := &chainntnfs.BlockEpoch{
		Height: height,
		Hash:   sha,
	}

	select {
	case epochClient.epochQueue.ChanIn() <- epoch:
	case <-epochClient.cancelChan:
	case <-n.quit:
	}
}

// RegisterSpendNtfn registers an intent to be notified once the target
// outpoint/output script has been spent by a transaction on-chain. When
// intending to be notified of the spend of an output script, a nil outpoint
// must be used. The heightHint should represent the earliest height in the
// chain of the transaction that spent the outpoint/output script.
//
// Once a spend of has been detected, the details of the spending event will be
// sent across the 'Spend' channel.
func (n *NeutrinoNotifier) RegisterSpendNtfn(outpoint *wire.OutPoint,
	pkScript []byte, heightHint uint32) (*chainntnfs.SpendEvent, error) {

	// Register the conf notification with the TxNotifier. A non-nil value
	// for `dispatch` will be returned if we are required to perform a
	// manual scan for the confirmation. Otherwise the notifier will begin
	// watching at tip for the transaction to confirm.
	ntfn, err := n.txNotifier.RegisterSpend(outpoint, pkScript, heightHint)
	if err != nil {
		return nil, err
	}

	// To determine whether this outpoint has been spent on-chain, we'll
	// update our filter to watch for the transaction at tip and we'll also
	// dispatch a historical rescan to determine if it has been spent in the
	// past.
	//
	// We'll update our filter first to ensure we can immediately detect the
	// spend at tip.
	if outpoint == nil {
		outpoint = &chainntnfs.ZeroOutPoint
	}
	inputToWatch := neutrino.InputWithScript{
		OutPoint: *outpoint,
		PkScript: pkScript,
	}
	updateOptions := []neutrino.UpdateOption{
		neutrino.AddInputs(inputToWatch),
		neutrino.DisableDisconnectedNtfns(true),
	}

	// We'll use the txNotifier's tip as the starting point of our filter
	// update. In the case of an output script spend request, we'll check if
	// we should perform a historical rescan and start from there, as we
	// cannot do so with GetUtxo since it matches outpoints.
	rewindHeight := ntfn.Height
	if ntfn.HistoricalDispatch != nil && *outpoint == chainntnfs.ZeroOutPoint {
		rewindHeight = ntfn.HistoricalDispatch.StartHeight
	}
	updateOptions = append(updateOptions, neutrino.Rewind(rewindHeight))

	errChan := make(chan error, 1)
	select {
	case n.notificationRegistry <- &rescanFilterUpdate{
		updateOptions: updateOptions,
		errChan:       errChan,
	}:
	case <-n.quit:
		return nil, chainntnfs.ErrChainNotifierShuttingDown
	}

	select {
	case err = <-errChan:
	case <-n.quit:
		return nil, chainntnfs.ErrChainNotifierShuttingDown
	}
	if err != nil {
		return nil, fmt.Errorf("unable to update filter: %v", err)
	}

	// If the txNotifier didn't return any details to perform a historical
	// scan of the chain, or if we already performed one like in the case of
	// output script spend requests, then we can return early as there's
	// nothing left for us to do.
	if ntfn.HistoricalDispatch == nil || *outpoint == chainntnfs.ZeroOutPoint {
		return ntfn.Event, nil
	}

	// With the filter updated, we'll dispatch our historical rescan to
	// ensure we detect the spend if it happened in the past.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()

		// We'll ensure that neutrino is caught up to the starting
		// height before we attempt to fetch the UTXO from the chain.
		// If we're behind, then we may miss a notification dispatch.
		for {
			n.bestBlockMtx.RLock()
			currentHeight := uint32(n.bestBlock.Height)
			n.bestBlockMtx.RUnlock()

			if currentHeight >= ntfn.HistoricalDispatch.StartHeight {
				break
			}

			select {
			case <-time.After(time.Millisecond * 200):
			case <-n.quit:
				return
			}
		}

		n.bestBlockMtx.RLock()
		currentHeight := uint32(n.bestBlock.Height)
		n.bestBlockMtx.RUnlock()

		ntfn.HistoricalDispatch.EndHeight = currentHeight

		spendReport, err := n.p2pNode.GetUtxo(
			neutrino.WatchInputs(inputToWatch),
			neutrino.StartBlock(&headerfs.BlockStamp{
				Height: int32(ntfn.HistoricalDispatch.StartHeight),
			}),
			neutrino.EndBlock(&headerfs.BlockStamp{
				Height: int32(ntfn.HistoricalDispatch.EndHeight),
			}),
			neutrino.ProgressHandler(func(processedHeight uint32) {
				// We persist the rescan progress to achieve incremental
				// behavior across restarts, otherwise long rescans may
				// start from the beginning with every restart.
				err := n.spendHintCache.CommitSpendHint(
					processedHeight,
					ntfn.HistoricalDispatch.SpendRequest)
				if err != nil {
					chainntnfs.Log.Errorf("Failed to update rescan "+
						"progress: %v", err)
				}
			}),
			neutrino.QuitChan(n.quit),
		)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			chainntnfs.Log.Errorf("Failed getting UTXO: %v", err)
			return
		}

		// If a spend report was returned, and the transaction is present, then
		// this means that the output is already spent.
		var spendDetails *chainntnfs.SpendDetail
		if spendReport != nil && spendReport.SpendingTx != nil {
			spendingTxHash := spendReport.SpendingTx.TxHash()
			spendDetails = &chainntnfs.SpendDetail{
				SpentOutPoint:     outpoint,
				SpenderTxHash:     &spendingTxHash,
				SpendingTx:        spendReport.SpendingTx,
				SpenderInputIndex: spendReport.SpendingInputIndex,
				SpendingHeight:    int32(spendReport.SpendingTxHeight),
			}
		}

		// Finally, no matter whether the rescan found a spend in the past or
		// not, we'll mark our historical rescan as complete to ensure the
		// outpoint's spend hint gets updated upon connected/disconnected
		// blocks.
		err = n.txNotifier.UpdateSpendDetails(
			ntfn.HistoricalDispatch.SpendRequest, spendDetails,
		)
		if err != nil {
			chainntnfs.Log.Errorf("Failed to update spend details: %v", err)
			return
		}
	}()

	return ntfn.Event, nil
}

// RegisterConfirmationsNtfn registers an intent to be notified once the target
// txid/output script has reached numConfs confirmations on-chain. When
// intending to be notified of the confirmation of an output script, a nil txid
// must be used. The heightHint should represent the earliest height at which
// the txid/output script could have been included in the chain.
//
// Progress on the number of confirmations left can be read from the 'Updates'
// channel. Once it has reached all of its confirmations, a notification will be
// sent across the 'Confirmed' channel.
func (n *NeutrinoNotifier) RegisterConfirmationsNtfn(txid *chainhash.Hash,
	pkScript []byte,
	numConfs, heightHint uint32) (*chainntnfs.ConfirmationEvent, error) {

	// Register the conf notification with the TxNotifier. A non-nil value
	// for `dispatch` will be returned if we are required to perform a
	// manual scan for the confirmation. Otherwise the notifier will begin
	// watching at tip for the transaction to confirm.
	ntfn, err := n.txNotifier.RegisterConf(
		txid, pkScript, numConfs, heightHint,
	)
	if err != nil {
		return nil, err
	}

	// To determine whether this transaction has confirmed on-chain, we'll
	// update our filter to watch for the transaction at tip and we'll also
	// dispatch a historical rescan to determine if it has confirmed in the
	// past.
	//
	// We'll update our filter first to ensure we can immediately detect the
	// confirmation at tip. To do so, we'll map the script into an address
	// type so we can instruct neutrino to match if the transaction
	// containing the script is found in a block.
	params := n.p2pNode.ChainParams()
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, &params)
	if err != nil {
		return nil, fmt.Errorf("unable to extract script: %v", err)
	}

	// We'll send the filter update request to the notifier's main event
	// handler and wait for its response.
	errChan := make(chan error, 1)
	select {
	case n.notificationRegistry <- &rescanFilterUpdate{
		updateOptions: []neutrino.UpdateOption{
			neutrino.AddAddrs(addrs...),
			neutrino.Rewind(ntfn.Height),
			neutrino.DisableDisconnectedNtfns(true),
		},
		errChan: errChan,
	}:
	case <-n.quit:
		return nil, chainntnfs.ErrChainNotifierShuttingDown
	}

	select {
	case err = <-errChan:
	case <-n.quit:
		return nil, chainntnfs.ErrChainNotifierShuttingDown
	}
	if err != nil {
		return nil, fmt.Errorf("unable to update filter: %v", err)
	}

	// If a historical rescan was not requested by the txNotifier, then we
	// can return to the caller.
	if ntfn.HistoricalDispatch == nil {
		return ntfn.Event, nil
	}

	// Grab the current best height.
	n.bestBlockMtx.RLock()
	currentHeight := uint32(n.bestBlock.Height)
	n.bestBlockMtx.RUnlock()

	ntfn.HistoricalDispatch.EndHeight = currentHeight

	// Finally, with the filter updated, we can dispatch the historical
	// rescan to ensure we can detect if the event happened in the past.
	select {
	case n.notificationRegistry <- ntfn.HistoricalDispatch:
	case <-n.quit:
		return nil, chainntnfs.ErrChainNotifierShuttingDown
	}

	return ntfn.Event, nil
}

// GetBlock is used to retrieve the block with the given hash. Since the block
// cache used by neutrino will be the same as that used by LND (since it is
// passed to neutrino on initialisation), the neutrino GetBlock method can be
// called directly since it already uses the block cache. However, neutrino
// does not lock the block cache mutex for the given block hash and so that is
// done here.
func (n *NeutrinoNotifier) GetBlock(hash chainhash.Hash) (
	*btcutil.Block, error) {

	n.blockCache.HashMutex.Lock(lntypes.Hash(hash))
	defer n.blockCache.HashMutex.Unlock(lntypes.Hash(hash))

	return n.p2pNode.GetBlock(hash)
}

// blockEpochRegistration represents a client's intent to receive a
// notification with each newly connected block.
type blockEpochRegistration struct {
	epochID uint64

	epochChan chan *chainntnfs.BlockEpoch

	epochQueue *queue.ConcurrentQueue

	cancelChan chan struct{}

	bestBlock *chainntnfs.BlockEpoch

	errorChan chan error

	wg sync.WaitGroup
}

// epochCancel is a message sent to the NeutrinoNotifier when a client wishes
// to cancel an outstanding epoch notification that has yet to be dispatched.
type epochCancel struct {
	epochID uint64
}

// RegisterBlockEpochNtfn returns a BlockEpochEvent which subscribes the
// caller to receive notifications, of each new block connected to the main
// chain. Clients have the option of passing in their best known block, which
// the notifier uses to check if they are behind on blocks and catch them up. If
// they do not provide one, then a notification will be dispatched immediately
// for the current tip of the chain upon a successful registration.
func (n *NeutrinoNotifier) RegisterBlockEpochNtfn(
	bestBlock *chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {

	reg := &blockEpochRegistration{
		epochQueue: queue.NewConcurrentQueue(20),
		epochChan:  make(chan *chainntnfs.BlockEpoch, 20),
		cancelChan: make(chan struct{}),
		epochID:    atomic.AddUint64(&n.epochClientCounter, 1),
		bestBlock:  bestBlock,
		errorChan:  make(chan error, 1),
	}
	reg.epochQueue.Start()

	// Before we send the request to the main goroutine, we'll launch a new
	// goroutine to proxy items added to our queue to the client itself.
	// This ensures that all notifications are received *in order*.
	reg.wg.Add(1)
	go func() {
		defer reg.wg.Done()

		for {
			select {
			case ntfn := <-reg.epochQueue.ChanOut():
				blockNtfn := ntfn.(*chainntnfs.BlockEpoch)
				select {
				case reg.epochChan <- blockNtfn:

				case <-reg.cancelChan:
					return

				case <-n.quit:
					return
				}

			case <-reg.cancelChan:
				return

			case <-n.quit:
				return
			}
		}
	}()

	select {
	case <-n.quit:
		// As we're exiting before the registration could be sent,
		// we'll stop the queue now ourselves.
		reg.epochQueue.Stop()

		return nil, errors.New("chainntnfs: system interrupt while " +
			"attempting to register for block epoch notification.")
	case n.notificationRegistry <- reg:
		return &chainntnfs.BlockEpochEvent{
			Epochs: reg.epochChan,
			Cancel: func() {
				cancel := &epochCancel{
					epochID: reg.epochID,
				}

				// Submit epoch cancellation to notification dispatcher.
				select {
				case n.notificationCancels <- cancel:
					// Cancellation is being handled, drain the epoch channel until it is
					// closed before yielding to caller.
					for {
						select {
						case _, ok := <-reg.epochChan:
							if !ok {
								return
							}
						case <-n.quit:
							return
						}
					}
				case <-n.quit:
				}
			},
		}, nil
	}
}

// NeutrinoChainConn is a wrapper around neutrino's chain backend in order
// to satisfy the chainntnfs.ChainConn interface.
type NeutrinoChainConn struct {
	p2pNode *neutrino.ChainService
}

// GetBlockHeader returns the block header for a hash.
func (n *NeutrinoChainConn) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	return n.p2pNode.GetBlockHeader(blockHash)
}

// GetBlockHeaderVerbose returns a verbose block header result for a hash. This
// result only contains the height with a nil hash.
func (n *NeutrinoChainConn) GetBlockHeaderVerbose(blockHash *chainhash.Hash) (
	*btcjson.GetBlockHeaderVerboseResult, error) {

	height, err := n.p2pNode.GetBlockHeight(blockHash)
	if err != nil {
		return nil, err
	}
	// Since only the height is used from the result, leave the hash nil.
	return &btcjson.GetBlockHeaderVerboseResult{Height: int32(height)}, nil
}

// GetBlockHash returns the hash from a block height.
func (n *NeutrinoChainConn) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	return n.p2pNode.GetBlockHash(blockHeight)
}
