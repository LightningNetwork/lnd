package bitcoindnotify

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

const (
	// notifierType uniquely identifies this concrete implementation of the
	// ChainNotifier interface.
	notifierType = "bitcoind"

	// reorgSafetyLimit is assumed maximum depth of a chain reorganization.
	// After this many confirmation, transaction confirmation info will be
	// pruned.
	reorgSafetyLimit = 100
)

var (
	// ErrChainNotifierShuttingDown is used when we are trying to
	// measure a spend notification when notifier is already stopped.
	ErrChainNotifierShuttingDown = errors.New("chainntnfs: system interrupt " +
		"while attempting to register for spend notification.")

	// ErrTransactionNotFound is an error returned when we attempt to find a
	// transaction by manually scanning the chain within a specific range
	// but it is not found.
	ErrTransactionNotFound = errors.New("transaction not found within range")
)

// chainUpdate encapsulates an update to the current main chain. This struct is
// used as an element within an unbounded queue in order to avoid blocking the
// main rpc dispatch rule.
type chainUpdate struct {
	blockHash   *chainhash.Hash
	blockHeight int32
}

// TODO(roasbeef): generalize struct below:
//  * move chans to config
//  * extract common code
//  * allow outside callers to handle send conditions

// BitcoindNotifier implements the ChainNotifier interface using a bitcoind
// chain client. Multiple concurrent clients are supported. All notifications
// are achieved via non-blocking sends on client channels.
type BitcoindNotifier struct {
	confClientCounter  uint64 // To be used atomically.
	spendClientCounter uint64 // To be used atomically.
	epochClientCounter uint64 // To be used atomically.

	started int32 // To be used atomically.
	stopped int32 // To be used atomically.

	chainConn *chain.BitcoindClient

	notificationCancels  chan interface{}
	notificationRegistry chan interface{}

	spendNotifications map[wire.OutPoint]map[uint64]*spendNotification

	txConfNotifier *chainntnfs.TxConfNotifier

	blockEpochClients map[uint64]*blockEpochRegistration

	bestBlock chainntnfs.BlockEpoch

	// hintCache is a cache used to query and update the latest height
	// hints for an outpoint or txid. Each height hint represents the
	// earliest height at which the entry could have been spent or confirmed
	// within the chain.
	hintCache chainntnfs.HintCache

	wg   sync.WaitGroup
	quit chan struct{}
}

// Ensure BitcoindNotifier implements the ChainNotifier interface at compile
// time.
var _ chainntnfs.ChainNotifier = (*BitcoindNotifier)(nil)

// New returns a new BitcoindNotifier instance. This function assumes the
// bitcoind node  detailed in the passed configuration is already running, and
// willing to accept RPC requests and new zmq clients.
func New(chainConn *chain.BitcoindConn,
	hintCache chainntnfs.HintCache) *BitcoindNotifier {

	notifier := &BitcoindNotifier{
		notificationCancels:  make(chan interface{}),
		notificationRegistry: make(chan interface{}),

		blockEpochClients: make(map[uint64]*blockEpochRegistration),

		spendNotifications: make(map[wire.OutPoint]map[uint64]*spendNotification),

		hintCache: hintCache,

		quit: make(chan struct{}),
	}

	notifier.chainConn = chainConn.NewBitcoindClient()

	return notifier
}

// Start connects to the running bitcoind node over websockets, registers for
// block notifications, and finally launches all related helper goroutines.
func (b *BitcoindNotifier) Start() error {
	// Already started?
	if atomic.AddInt32(&b.started, 1) != 1 {
		return nil
	}

	// Connect to bitcoind, and register for notifications on connected,
	// and disconnected blocks.
	if err := b.chainConn.Start(); err != nil {
		return err
	}
	if err := b.chainConn.NotifyBlocks(); err != nil {
		return err
	}
	if err := b.hintCache.Start(); err != nil {
		return err
	}

	currentHash, currentHeight, err := b.chainConn.GetBestBlock()
	if err != nil {
		return err
	}

	b.txConfNotifier = chainntnfs.NewTxConfNotifier(
		uint32(currentHeight), reorgSafetyLimit, b.hintCache,
	)

	b.bestBlock = chainntnfs.BlockEpoch{
		Height: currentHeight,
		Hash:   currentHash,
	}

	b.wg.Add(1)
	go b.notificationDispatcher()

	return nil
}

// Stop shutsdown the BitcoindNotifier.
func (b *BitcoindNotifier) Stop() error {
	// Already shutting down?
	if atomic.AddInt32(&b.stopped, 1) != 1 {
		return nil
	}

	// Shutdown the rpc client, this gracefully disconnects from bitcoind,
	// and cleans up all related resources.
	b.chainConn.Stop()

	close(b.quit)
	b.wg.Wait()

	b.hintCache.Stop()

	// Notify all pending clients of our shutdown by closing the related
	// notification channels.
	for _, spendClients := range b.spendNotifications {
		for _, spendClient := range spendClients {
			close(spendClient.spendChan)
		}
	}
	for _, epochClient := range b.blockEpochClients {
		close(epochClient.cancelChan)
		epochClient.wg.Wait()

		close(epochClient.epochChan)
	}
	b.txConfNotifier.TearDown()

	return nil
}

// blockNtfn packages a notification of a connected/disconnected block along
// with its height at the time.
type blockNtfn struct {
	sha    *chainhash.Hash
	height int32
}

// notificationDispatcher is the primary goroutine which handles client
// notification registrations, as well as notification dispatches.
func (b *BitcoindNotifier) notificationDispatcher() {
out:
	for {
		select {
		case cancelMsg := <-b.notificationCancels:
			switch msg := cancelMsg.(type) {
			case *spendCancel:
				chainntnfs.Log.Infof("Cancelling spend "+
					"notification for out_point=%v, "+
					"spend_id=%v", msg.op, msg.spendID)

				// Before we attempt to close the spendChan,
				// ensure that the notification hasn't already
				// yet been dispatched.
				if outPointClients, ok := b.spendNotifications[msg.op]; ok {
					close(outPointClients[msg.spendID].spendChan)
					delete(b.spendNotifications[msg.op], msg.spendID)
				}

			case *epochCancel:
				chainntnfs.Log.Infof("Cancelling epoch "+
					"notification, epoch_id=%v", msg.epochID)

				// First, we'll lookup the original
				// registration in order to stop the active
				// queue goroutine.
				reg := b.blockEpochClients[msg.epochID]
				reg.epochQueue.Stop()

				// Next, close the cancel channel for this
				// specific client, and wait for the client to
				// exit.
				close(b.blockEpochClients[msg.epochID].cancelChan)
				b.blockEpochClients[msg.epochID].wg.Wait()

				// Once the client has exited, we can then
				// safely close the channel used to send epoch
				// notifications, in order to notify any
				// listeners that the intent has been
				// cancelled.
				close(b.blockEpochClients[msg.epochID].epochChan)
				delete(b.blockEpochClients, msg.epochID)

			}
		case registerMsg := <-b.notificationRegistry:
			switch msg := registerMsg.(type) {
			case *spendNotification:
				chainntnfs.Log.Infof("New spend subscription: "+
					"utxo=%v", msg.targetOutpoint)
				op := *msg.targetOutpoint

				if _, ok := b.spendNotifications[op]; !ok {
					b.spendNotifications[op] = make(map[uint64]*spendNotification)
				}
				b.spendNotifications[op][msg.spendID] = msg

			case *confirmationNotification:
				chainntnfs.Log.Infof("New confirmation "+
					"subscription: txid=%v, numconfs=%v",
					msg.TxID, msg.NumConfirmations)

				currentHeight := uint32(b.bestBlock.Height)

				// Look up whether the transaction is already
				// included in the active chain. We'll do this
				// in a goroutine to prevent blocking
				// potentially long rescans.
				b.wg.Add(1)
				go func() {
					defer b.wg.Done()

					confDetails, _, err := b.historicalConfDetails(
						msg.TxID, msg.heightHint,
						currentHeight,
					)
					if err != nil {
						chainntnfs.Log.Error(err)
						return
					}

					if confDetails != nil {
						err := b.txConfNotifier.UpdateConfDetails(
							*msg.TxID, msg.ConfID,
							confDetails,
						)
						if err != nil {
							chainntnfs.Log.Error(err)
						}
					}
				}()

			case *blockEpochRegistration:
				chainntnfs.Log.Infof("New block epoch subscription")
				b.blockEpochClients[msg.epochID] = msg
				if msg.bestBlock != nil {
					missedBlocks, err :=
						chainntnfs.GetClientMissedBlocks(
							b.chainConn, msg.bestBlock,
							b.bestBlock.Height, true,
						)
					if err != nil {
						msg.errorChan <- err
						continue
					}
					for _, block := range missedBlocks {
						b.notifyBlockEpochClient(msg,
							block.Height, block.Hash)
					}
				}
				msg.errorChan <- nil

			case chain.RelevantTx:
				b.handleRelevantTx(msg, b.bestBlock.Height)
			}

		case ntfn := <-b.chainConn.Notifications():
			switch item := ntfn.(type) {
			case chain.BlockConnected:
				blockHeader, err :=
					b.chainConn.GetBlockHeader(&item.Hash)
				if err != nil {
					chainntnfs.Log.Errorf("Unable to fetch "+
						"block header: %v", err)
					continue
				}

				if blockHeader.PrevBlock != *b.bestBlock.Hash {
					// Handle the case where the notifier
					// missed some blocks from its chain
					// backend.
					chainntnfs.Log.Infof("Missed blocks, " +
						"attempting to catch up")
					newBestBlock, missedBlocks, err :=
						chainntnfs.HandleMissedBlocks(
							b.chainConn,
							b.txConfNotifier,
							b.bestBlock, item.Height,
							true,
						)

					if err != nil {
						// Set the bestBlock here in case
						// a catch up partially completed.
						b.bestBlock = newBestBlock
						chainntnfs.Log.Error(err)
						continue
					}

					for _, block := range missedBlocks {
						err := b.handleBlockConnected(block)
						if err != nil {
							chainntnfs.Log.Error(err)
							continue out
						}
					}
				}

				newBlock := chainntnfs.BlockEpoch{
					Height: item.Height,
					Hash:   &item.Hash,
				}
				if err := b.handleBlockConnected(newBlock); err != nil {
					chainntnfs.Log.Error(err)
				}

				continue

			case chain.BlockDisconnected:
				if item.Height != b.bestBlock.Height {
					chainntnfs.Log.Infof("Missed disconnected" +
						"blocks, attempting to catch up")
				}

				newBestBlock, err := chainntnfs.RewindChain(
					b.chainConn, b.txConfNotifier,
					b.bestBlock, item.Height-1,
				)
				if err != nil {
					chainntnfs.Log.Errorf("Unable to rewind chain "+
						"from height %d to height %d: %v",
						b.bestBlock.Height, item.Height-1, err)
				}

				// Set the bestBlock here in case a chain
				// rewind partially completed.
				b.bestBlock = newBestBlock

			case chain.RelevantTx:
				b.handleRelevantTx(item, b.bestBlock.Height)
			}

		case <-b.quit:
			break out
		}
	}
	b.wg.Done()
}

// handleRelevantTx notifies any clients of a relevant transaction.
func (b *BitcoindNotifier) handleRelevantTx(tx chain.RelevantTx, bestHeight int32) {
	msgTx := tx.TxRecord.MsgTx

	// We only care about notifying on confirmed spends, so in case this is
	// a mempool spend, we can continue, and wait for the spend to appear
	// in chain.
	if tx.Block == nil {
		return
	}

	// First, check if this transaction spends an output
	// that has an existing spend notification for it.
	for i, txIn := range msgTx.TxIn {
		prevOut := txIn.PreviousOutPoint

		// If this transaction indeed does spend an
		// output which we have a registered
		// notification for, then create a spend
		// summary, finally sending off the details to
		// the notification subscriber.
		if clients, ok := b.spendNotifications[prevOut]; ok {
			spenderSha := msgTx.TxHash()
			spendDetails := &chainntnfs.SpendDetail{
				SpentOutPoint:     &prevOut,
				SpenderTxHash:     &spenderSha,
				SpendingTx:        &msgTx,
				SpenderInputIndex: uint32(i),
			}
			spendDetails.SpendingHeight = tx.Block.Height

			for _, ntfn := range clients {
				chainntnfs.Log.Infof("Dispatching confirmed "+
					"spend notification for outpoint=%v "+
					"at height %v", ntfn.targetOutpoint,
					spendDetails.SpendingHeight)
				ntfn.spendChan <- spendDetails

				// Close spendChan to ensure that any calls to
				// Cancel will not block. This is safe to do
				// since the channel is buffered, and the
				// message can still be read by the receiver.
				close(ntfn.spendChan)
			}
			delete(b.spendNotifications, prevOut)
		}
	}
}

// historicalConfDetails looks up whether a transaction is already included in a
// block in the active chain and, if so, returns details about the confirmation.
func (b *BitcoindNotifier) historicalConfDetails(txid *chainhash.Hash,
	heightHint, currentHeight uint32) (*chainntnfs.TxConfirmation,
	chainntnfs.TxConfStatus, error) {

	// We'll first attempt to retrieve the transaction using the node's
	// txindex.
	txConf, txStatus, err := b.confDetailsFromTxIndex(txid)

	// We'll then check the status of the transaction lookup returned to
	// determine whether we should proceed with any fallback methods.
	switch {

	// We failed querying the index for the transaction, fall back to
	// scanning manually.
	case err != nil:
		chainntnfs.Log.Debugf("Failed getting conf details from "+
			"index (%v), scanning manually", err)
		return b.confDetailsManually(txid, heightHint, currentHeight)

	// The transaction was found within the node's mempool.
	case txStatus == chainntnfs.TxFoundMempool:

	// The transaction was found within the node's txindex.
	case txStatus == chainntnfs.TxFoundIndex:

	// The transaction was not found within the node's mempool or txindex.
	case txStatus == chainntnfs.TxNotFoundIndex:

	// Unexpected txStatus returned.
	default:
		return nil, txStatus,
			fmt.Errorf("Got unexpected txConfStatus: %v", txStatus)
	}

	return txConf, txStatus, nil
}

// confDetailsFromTxIndex looks up whether a transaction is already included in
// a block in the active chain by using the backend node's transaction index.
// If the transaction is found its TxConfStatus is returned. If it was found in
// the mempool this will be TxFoundMempool, if it is found in a block this will
// be TxFoundIndex. Otherwise TxNotFoundIndex is returned. If the tx is found
// in a block its confirmation details are also returned.
func (b *BitcoindNotifier) confDetailsFromTxIndex(txid *chainhash.Hash,
) (*chainntnfs.TxConfirmation, chainntnfs.TxConfStatus, error) {

	// If the transaction has some or all of its confirmations required,
	// then we may be able to dispatch it immediately.
	tx, err := b.chainConn.GetRawTransactionVerbose(txid)
	if err != nil {
		// If the transaction lookup was successful, but it wasn't found
		// within the index itself, then we can exit early. We'll also
		// need to look at the error message returned as the error code
		// is used for multiple errors.
		txNotFoundErr := "No such mempool or blockchain transaction"
		jsonErr, ok := err.(*btcjson.RPCError)
		if ok && jsonErr.Code == btcjson.ErrRPCNoTxInfo &&
			strings.Contains(jsonErr.Message, txNotFoundErr) {

			return nil, chainntnfs.TxNotFoundIndex, nil
		}

		return nil, chainntnfs.TxNotFoundIndex,
			fmt.Errorf("unable to query for txid %v: %v", txid, err)
	}

	// Make sure we actually retrieved a transaction that is included in a
	// block. If not, the transaction must be unconfirmed (in the mempool),
	// and we'll return TxFoundMempool together with a nil TxConfirmation.
	if tx.BlockHash == "" {
		return nil, chainntnfs.TxFoundMempool, nil
	}

	// As we need to fully populate the returned TxConfirmation struct,
	// grab the block in which the transaction was confirmed so we can
	// locate its exact index within the block.
	blockHash, err := chainhash.NewHashFromStr(tx.BlockHash)
	if err != nil {
		return nil, chainntnfs.TxNotFoundIndex,
			fmt.Errorf("unable to get block hash %v for "+
				"historical dispatch: %v", tx.BlockHash, err)
	}

	block, err := b.chainConn.GetBlockVerbose(blockHash)
	if err != nil {
		return nil, chainntnfs.TxNotFoundIndex,
			fmt.Errorf("unable to get block with hash %v for "+
				"historical dispatch: %v", blockHash, err)
	}

	// If the block was obtained, locate the transaction's index within the
	// block so we can give the subscriber full confirmation details.
	targetTxidStr := txid.String()
	for txIndex, txHash := range block.Tx {
		if txHash == targetTxidStr {
			details := &chainntnfs.TxConfirmation{
				BlockHash:   blockHash,
				BlockHeight: uint32(block.Height),
				TxIndex:     uint32(txIndex),
			}
			return details, chainntnfs.TxFoundIndex, nil
		}
	}

	// We return an error because we should have found the transaction
	// within the block, but didn't.
	return nil, chainntnfs.TxNotFoundIndex,
		fmt.Errorf("unable to locate tx %v in block %v", txid,
			blockHash)
}

// confDetailsManually looks up whether a transaction is already included in a
// block in the active chain by scanning the chain's blocks, starting from the
// earliest height the transaction could have been included in, to the current
// height in the chain. If the transaction is found, its confirmation details
// are returned. Otherwise, nil is returned.
func (b *BitcoindNotifier) confDetailsManually(txid *chainhash.Hash,
	heightHint, currentHeight uint32) (*chainntnfs.TxConfirmation,
	chainntnfs.TxConfStatus, error) {

	targetTxidStr := txid.String()

	// Begin scanning blocks at every height to determine where the
	// transaction was included in.
	for height := heightHint; height <= currentHeight; height++ {
		// Ensure we haven't been requested to shut down before
		// processing the next height.
		select {
		case <-b.quit:
			return nil, chainntnfs.TxNotFoundManually,
				ErrChainNotifierShuttingDown
		default:
		}

		blockHash, err := b.chainConn.GetBlockHash(int64(height))
		if err != nil {
			return nil, chainntnfs.TxNotFoundManually,
				fmt.Errorf("unable to get hash from block "+
					"with height %d", height)
		}

		block, err := b.chainConn.GetBlockVerbose(blockHash)
		if err != nil {
			return nil, chainntnfs.TxNotFoundManually,
				fmt.Errorf("unable to get block with hash "+
					"%v: %v", blockHash, err)
		}

		for txIndex, txHash := range block.Tx {
			// If we're able to find the transaction in this block,
			// return its confirmation details.
			if txHash == targetTxidStr {
				details := &chainntnfs.TxConfirmation{
					BlockHash:   blockHash,
					BlockHeight: height,
					TxIndex:     uint32(txIndex),
				}
				return details, chainntnfs.TxFoundManually, nil
			}
		}
	}

	// If we reach here, then we were not able to find the transaction
	// within a block, so we avoid returning an error.
	return nil, chainntnfs.TxNotFoundManually, nil
}

// handleBlockConnected applies a chain update for a new block. Any watched
// transactions included this block will processed to either send notifications
// now or after numConfirmations confs.
func (b *BitcoindNotifier) handleBlockConnected(block chainntnfs.BlockEpoch) error {
	rawBlock, err := b.chainConn.GetBlock(block.Hash)
	if err != nil {
		return fmt.Errorf("unable to get block: %v", err)
	}

	txns := btcutil.NewBlock(rawBlock).Transactions()
	err = b.txConfNotifier.ConnectTip(
		block.Hash, uint32(block.Height), txns)
	if err != nil {
		return fmt.Errorf("unable to connect tip: %v", err)
	}

	chainntnfs.Log.Infof("New block: height=%v, sha=%v", block.Height,
		block.Hash)

	// Finally, we'll update the spend height hint for all of our watched
	// outpoints that have not been spent yet. This is safe to do as we do
	// not watch already spent outpoints for spend notifications.
	ops := make([]wire.OutPoint, 0, len(b.spendNotifications))
	for op := range b.spendNotifications {
		ops = append(ops, op)
	}

	if len(ops) > 0 {
		err := b.hintCache.CommitSpendHint(
			uint32(block.Height), ops...,
		)
		if err != nil {
			// The error is not fatal since we are connecting a
			// block, and advancing the spend hint is an optimistic
			// optimization.
			chainntnfs.Log.Errorf("Unable to update spend hint to "+
				"%d for %v: %v", block.Height, ops, err)
		}
	}

	// We want to set the best block before dispatching notifications so
	// if any subscribers make queries based on their received block epoch,
	// our state is fully updated in time.
	b.bestBlock = block

	// Lastly we'll notify any subscribed clients of the block.
	b.notifyBlockEpochs(block.Height, block.Hash)

	return nil
}

// notifyBlockEpochs notifies all registered block epoch clients of the newly
// connected block to the main chain.
func (b *BitcoindNotifier) notifyBlockEpochs(newHeight int32, newSha *chainhash.Hash) {
	for _, client := range b.blockEpochClients {
		b.notifyBlockEpochClient(client, newHeight, newSha)
	}
}

// notifyBlockEpochClient sends a registered block epoch client a notification
// about a specific block.
func (b *BitcoindNotifier) notifyBlockEpochClient(epochClient *blockEpochRegistration,
	height int32, sha *chainhash.Hash) {

	epoch := &chainntnfs.BlockEpoch{
		Height: height,
		Hash:   sha,
	}

	select {
	case epochClient.epochQueue.ChanIn() <- epoch:
	case <-epochClient.cancelChan:
	case <-b.quit:
	}
}

// spendNotification couples a target outpoint along with the channel used for
// notifications once a spend of the outpoint has been detected.
type spendNotification struct {
	targetOutpoint *wire.OutPoint

	spendChan chan *chainntnfs.SpendDetail

	spendID uint64

	heightHint uint32
}

// spendCancel is a message sent to the BitcoindNotifier when a client wishes
// to cancel an outstanding spend notification that has yet to be dispatched.
type spendCancel struct {
	// op is the target outpoint of the notification to be cancelled.
	op wire.OutPoint

	// spendID the ID of the notification to cancel.
	spendID uint64
}

// RegisterSpendNtfn registers an intent to be notified once the target
// outpoint has been spent by a transaction on-chain. Once a spend of the target
// outpoint has been detected, the details of the spending event will be sent
// across the 'Spend' channel. The heightHint should represent the earliest
// height in the chain where the transaction could have been spent in.
func (b *BitcoindNotifier) RegisterSpendNtfn(outpoint *wire.OutPoint,
	pkScript []byte, heightHint uint32) (*chainntnfs.SpendEvent, error) {

	// Before proceeding to register the notification, we'll query our
	// height hint cache to determine whether a better one exists.
	if hint, err := b.hintCache.QuerySpendHint(*outpoint); err == nil {
		if hint > heightHint {
			chainntnfs.Log.Debugf("Using height hint %d retrieved "+
				"from cache for %v", hint, outpoint)
			heightHint = hint
		}
	}

	// Construct a notification request for the outpoint and send it to the
	// main event loop.
	ntfn := &spendNotification{
		targetOutpoint: outpoint,
		spendChan:      make(chan *chainntnfs.SpendDetail, 1),
		spendID:        atomic.AddUint64(&b.spendClientCounter, 1),
	}

	select {
	case <-b.quit:
		return nil, ErrChainNotifierShuttingDown
	case b.notificationRegistry <- ntfn:
	}

	if err := b.chainConn.NotifySpent([]*wire.OutPoint{outpoint}); err != nil {
		return nil, err
	}

	// The following conditional checks to ensure that when a spend
	// notification is registered, the output hasn't already been spent. If
	// the output is no longer in the UTXO set, the chain will be rescanned
	// from the point where the output was added. The rescan will dispatch
	// the notification.
	txOut, err := b.chainConn.GetTxOut(&outpoint.Hash, outpoint.Index, true)
	if err != nil {
		return nil, err
	}

	// If the output is unspent, then we'll write it to the cache with the
	// given height hint. This allows us to increase the height hint as the
	// chain extends and the output remains unspent.
	if txOut != nil {
		err := b.hintCache.CommitSpendHint(heightHint, *outpoint)
		if err != nil {
			// The error is not fatal, so we should not return an
			// error to the caller.
			chainntnfs.Log.Error("Unable to update spend hint to "+
				"%d for %v: %v", heightHint, *outpoint, err)
		}
	} else {
		// Otherwise, we'll determine when the output was spent.
		//
		// First, we'll attempt to retrieve the transaction's block hash
		// using the backend's transaction index.
		tx, err := b.chainConn.GetRawTransactionVerbose(&outpoint.Hash)
		if err != nil {
			// Avoid returning an error if the transaction was not
			// found to proceed with fallback methods.
			jsonErr, ok := err.(*btcjson.RPCError)
			if !ok || jsonErr.Code != btcjson.ErrRPCNoTxInfo {
				return nil, fmt.Errorf("unable to query for "+
					"txid %v: %v", outpoint.Hash, err)
			}
		}

		var blockHash *chainhash.Hash
		if tx != nil && tx.BlockHash != "" {
			// If we're able to retrieve a valid block hash from the
			// transaction, then we'll use it as our rescan starting
			// point.
			blockHash, err = chainhash.NewHashFromStr(tx.BlockHash)
			if err != nil {
				return nil, err
			}
		} else {
			// Otherwise, we'll attempt to retrieve the hash for the
			// block at the heightHint.
			blockHash, err = b.chainConn.GetBlockHash(
				int64(heightHint),
			)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve "+
					"hash for block with height %d: %v",
					heightHint, err)
			}
		}

		// We'll only scan old blocks if the transaction has actually
		// been included within a block. Otherwise, we'll encounter an
		// error when scanning for blocks. This can happens in the case
		// of a race condition, wherein the output itself is unspent,
		// and only arrives in the mempool after the getxout call.
		if blockHash != nil {
			// Rescan all the blocks until the current one.
			startHeight, err := b.chainConn.GetBlockHeight(
				blockHash,
			)
			if err != nil {
				return nil, err
			}

			_, endHeight, err := b.chainConn.GetBestBlock()
			if err != nil {
				return nil, err
			}

			// In order to ensure we don't block the caller on what
			// may be a long rescan, we'll launch a goroutine to do
			// so in the background.
			b.wg.Add(1)
			go func() {
				defer b.wg.Done()

				err := b.dispatchSpendDetailsManually(
					*outpoint, startHeight, endHeight,
				)
				if err != nil {
					chainntnfs.Log.Errorf("Rescan for spend "+
						"notification txout(%x) "+
						"failed: %v", outpoint, err)
				}
			}()
		}
	}

	return &chainntnfs.SpendEvent{
		Spend: ntfn.spendChan,
		Cancel: func() {
			cancel := &spendCancel{
				op:      *outpoint,
				spendID: ntfn.spendID,
			}

			// Submit spend cancellation to notification dispatcher.
			select {
			case b.notificationCancels <- cancel:
				// Cancellation is being handled, drain the
				// spend chan until it is closed before yielding
				// to the caller.
				for {
					select {
					case _, ok := <-ntfn.spendChan:
						if !ok {
							return
						}
					case <-b.quit:
						return
					}
				}
			case <-b.quit:
			}
		},
	}, nil
}

// disaptchSpendDetailsManually attempts to manually scan the chain within the
// given height range for a transaction that spends the given outpoint. If one
// is found, it's spending details are sent to the notifier dispatcher, which
// will then dispatch the notification to all of its clients.
func (b *BitcoindNotifier) dispatchSpendDetailsManually(op wire.OutPoint,
	startHeight, endHeight int32) error {

	// Begin scanning blocks at every height to determine if the outpoint
	// was spent.
	for height := startHeight; height <= endHeight; height++ {
		// Ensure we haven't been requested to shut down before
		// processing the next height.
		select {
		case <-b.quit:
			return ErrChainNotifierShuttingDown
		default:
		}

		blockHash, err := b.chainConn.GetBlockHash(int64(height))
		if err != nil {
			return fmt.Errorf("unable to retrieve hash for block "+
				"with height %d: %v", height, err)
		}
		block, err := b.chainConn.GetBlock(blockHash)
		if err != nil {
			return fmt.Errorf("unable to retrieve block with hash "+
				"%v: %v", blockHash, err)
		}

		for _, tx := range block.Transactions {
			for _, in := range tx.TxIn {
				if in.PreviousOutPoint != op {
					continue
				}

				// If this transaction input spends the
				// outpoint, we'll gather the details of the
				// spending transaction and dispatch a spend
				// notification to our clients.
				relTx := chain.RelevantTx{
					TxRecord: &wtxmgr.TxRecord{
						MsgTx:    *tx,
						Hash:     tx.TxHash(),
						Received: block.Header.Timestamp,
					},
					Block: &wtxmgr.BlockMeta{
						Block: wtxmgr.Block{
							Hash:   *blockHash,
							Height: height,
						},
						Time: block.Header.Timestamp,
					},
				}

				select {
				case b.notificationRegistry <- relTx:
				case <-b.quit:
					return ErrChainNotifierShuttingDown
				}

				return nil
			}
		}
	}

	return ErrTransactionNotFound
}

// confirmationNotification represents a client's intent to receive a
// notification once the target txid reaches numConfirmations confirmations.
type confirmationNotification struct {
	chainntnfs.ConfNtfn
	heightHint uint32
}

// RegisterConfirmationsNtfn registers a notification with BitcoindNotifier
// which will be triggered once the txid reaches numConfs number of
// confirmations.
func (b *BitcoindNotifier) RegisterConfirmationsNtfn(txid *chainhash.Hash,
	_ []byte, numConfs, heightHint uint32) (*chainntnfs.ConfirmationEvent, error) {

	// Before proceeding to register the notification, we'll query our
	// height hint cache to determine whether a better one exists.
	if hint, err := b.hintCache.QueryConfirmHint(*txid); err == nil {
		if hint > heightHint {
			chainntnfs.Log.Debugf("Using height hint %d retrieved "+
				"from cache for %v", hint, txid)
			heightHint = hint
		}
	}

	// Construct a notification request for the transaction and send it to
	// the main event loop.
	ntfn := &confirmationNotification{
		ConfNtfn: chainntnfs.ConfNtfn{
			ConfID:           atomic.AddUint64(&b.confClientCounter, 1),
			TxID:             txid,
			NumConfirmations: numConfs,
			Event:            chainntnfs.NewConfirmationEvent(numConfs),
		},
		heightHint: heightHint,
	}

	if err := b.txConfNotifier.Register(&ntfn.ConfNtfn); err != nil {
		return nil, err
	}

	select {
	case b.notificationRegistry <- ntfn:
		return ntfn.Event, nil
	case <-b.quit:
		return nil, ErrChainNotifierShuttingDown
	}
}

// blockEpochRegistration represents a client's intent to receive a
// notification with each newly connected block.
type blockEpochRegistration struct {
	epochID uint64

	epochChan chan *chainntnfs.BlockEpoch

	epochQueue *chainntnfs.ConcurrentQueue

	bestBlock *chainntnfs.BlockEpoch

	errorChan chan error

	cancelChan chan struct{}

	wg sync.WaitGroup
}

// epochCancel is a message sent to the BitcoindNotifier when a client wishes
// to cancel an outstanding epoch notification that has yet to be dispatched.
type epochCancel struct {
	epochID uint64
}

// RegisterBlockEpochNtfn returns a BlockEpochEvent which subscribes the
// caller to receive notifications, of each new block connected to the main
// chain. Clients have the option of passing in their best known block, which
// the notifier uses to check if they are behind on blocks and catch them up.
func (b *BitcoindNotifier) RegisterBlockEpochNtfn(
	bestBlock *chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {

	reg := &blockEpochRegistration{
		epochQueue: chainntnfs.NewConcurrentQueue(20),
		epochChan:  make(chan *chainntnfs.BlockEpoch, 20),
		cancelChan: make(chan struct{}),
		epochID:    atomic.AddUint64(&b.epochClientCounter, 1),
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

				case <-b.quit:
					return
				}

			case <-reg.cancelChan:
				return

			case <-b.quit:
				return
			}
		}
	}()

	select {
	case <-b.quit:
		// As we're exiting before the registration could be sent,
		// we'll stop the queue now ourselves.
		reg.epochQueue.Stop()

		return nil, errors.New("chainntnfs: system interrupt while " +
			"attempting to register for block epoch notification.")
	case b.notificationRegistry <- reg:
		return &chainntnfs.BlockEpochEvent{
			Epochs: reg.epochChan,
			Cancel: func() {
				cancel := &epochCancel{
					epochID: reg.epochID,
				}

				// Submit epoch cancellation to notification dispatcher.
				select {
				case b.notificationCancels <- cancel:
					// Cancellation is being handled, drain the epoch channel until it is
					// closed before yielding to caller.
					for {
						select {
						case _, ok := <-reg.epochChan:
							if !ok {
								return
							}
						case <-b.quit:
							return
						}
					}
				case <-b.quit:
				}
			},
		}, nil
	}
}
