// NOTE: THIS API IS UNSTABLE RIGHT NOW AND WILL GO MOSTLY PRIVATE SOON.

package neutrino

import (
	"bytes"
	"container/list"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/blockntfns"
	"github.com/lightninglabs/neutrino/chainsync"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/lightninglabs/neutrino/headerlist"
	"github.com/lightninglabs/neutrino/query"
)

const (
	// maxTimeOffset is the maximum duration a block time is allowed to be
	// ahead of the curent time. This is currently 2 hours.
	maxTimeOffset = 2 * time.Hour

	// numMaxMemHeaders is the max number of headers to store in memory for
	// a particular peer. By bounding this value, we're able to closely
	// control our effective memory usage during initial sync and re-org
	// handling. This value should be set a "sane" re-org size, such that
	// we're able to properly handle re-orgs in size strictly less than
	// this value.
	numMaxMemHeaders = 10000

	// retryTimeout is the time we'll wait between failed queries to fetch
	// filter checkpoints and headers.
	retryTimeout = 3 * time.Second

	// maxCFCheckptsPerQuery is the maximum number of filter header
	// checkpoints we can query for within a single message over the wire.
	maxCFCheckptsPerQuery = wire.MaxCFHeadersPerMsg / wire.CFCheckptInterval
)

// filterStoreLookup
type filterStoreLookup func(*ChainService) *headerfs.FilterHeaderStore

var (
	// filterTypes is a map of filter types to synchronize to a lookup
	// function for the service's store for that filter type.
	filterTypes = map[wire.FilterType]filterStoreLookup{
		wire.GCSFilterRegular: func(
			s *ChainService) *headerfs.FilterHeaderStore {

			return s.RegFilterHeaders
		},
	}
)

// zeroHash is the zero value hash (all zeros).  It is defined as a convenience.
var zeroHash chainhash.Hash

// newPeerMsg signifies a newly connected peer to the block handler.
type newPeerMsg struct {
	peer *ServerPeer
}

// invMsg packages a bitcoin inv message and the peer it came from together
// so the block handler has access to that information.
type invMsg struct {
	inv  *wire.MsgInv
	peer *ServerPeer
}

// headersMsg packages a bitcoin headers message and the peer it came from
// together so the block handler has access to that information.
type headersMsg struct {
	headers *wire.MsgHeaders
	peer    *ServerPeer
}

// donePeerMsg signifies a newly disconnected peer to the block handler.
type donePeerMsg struct {
	peer *ServerPeer
}

// txMsg packages a bitcoin tx message and the peer it came from together
// so the block handler has access to that information.
type txMsg struct {
	tx   *btcutil.Tx
	peer *ServerPeer
}

// blockManagerCfg holds options and dependencies needed by the blockManager
// during operation.
type blockManagerCfg struct {
	// ChainParams is the chain that we're running on.
	ChainParams chaincfg.Params

	// BlockHeaders is the store where blockheaders are persistently
	// stored.
	BlockHeaders headerfs.BlockHeaderStore

	// RegFilterHeaders is the store where filter headers for the regular
	// compact filters are persistently stored.
	RegFilterHeaders *headerfs.FilterHeaderStore

	// TimeSource is used to access a time estimate based on the clocks of
	// the connected peers.
	TimeSource blockchain.MedianTimeSource

	// QueryDispatcher is used to make queries to connected Bitcoin peers.
	QueryDispatcher query.Dispatcher

	// BanPeer bans and disconnects the given peer.
	BanPeer func(addr string, reason banman.Reason) error

	// GetBlock fetches a block from the p2p network.
	GetBlock func(chainhash.Hash, ...QueryOption) (*btcutil.Block, error)

	// firstPeerSignal is a channel that's sent upon once the main daemon
	// has made its first peer connection. We use this to ensure we don't
	// try to perform any queries before we have our first peer.
	firstPeerSignal <-chan struct{}

	queryAllPeers func(
		queryMsg wire.Message,
		checkResponse func(sp *ServerPeer, resp wire.Message,
			quit chan<- struct{}, peerQuit chan<- struct{}),
		options ...QueryOption)
}

// blockManager provides a concurrency safe block manager for handling all
// incoming blocks.
type blockManager struct {
	started  int32
	shutdown int32

	cfg *blockManagerCfg

	// blkHeaderProgressLogger is a progress logger that we'll use to
	// update the number of blocker headers we've processed in the past 10
	// seconds within the log.
	blkHeaderProgressLogger *headerProgressLogger

	// fltrHeaderProgessLogger is a process logger similar to the one
	// above, but we'll use it to update the progress of the set of filter
	// headers that we've verified in the past 10 seconds.
	fltrHeaderProgessLogger *headerProgressLogger

	// genesisHeader is the filter header of the genesis block.
	genesisHeader chainhash.Hash

	// headerTip will be set to the current block header tip at all times.
	// Callers MUST hold the lock below each time they read/write from
	// this field.
	headerTip uint32

	// headerTipHash will be set to the hash of the current block header
	// tip at all times.  Callers MUST hold the lock below each time they
	// read/write from this field.
	headerTipHash chainhash.Hash

	// newHeadersMtx is the mutex that should be held when reading/writing
	// the headerTip variable above.
	//
	// NOTE: When using this mutex along with newFilterHeadersMtx at the
	// same time, newHeadersMtx should always be acquired first.
	newHeadersMtx sync.RWMutex

	// newHeadersSignal is condition variable which will be used to notify
	// any waiting callers (via Broadcast()) that the tip of the current
	// chain has changed. This is useful when callers need to know we have
	// a new tip, but not necessarily each block that was connected during
	// switch over.
	newHeadersSignal *sync.Cond

	// filterHeaderTip will be set to the height of the current filter
	// header tip at all times.  Callers MUST hold the lock below each time
	// they read/write from this field.
	filterHeaderTip uint32

	// filterHeaderTipHash will be set to the current block hash of the
	// block at height filterHeaderTip at all times.  Callers MUST hold the
	// lock below each time they read/write from this field.
	filterHeaderTipHash chainhash.Hash

	// newFilterHeadersMtx is the mutex that should be held when
	// reading/writing the filterHeaderTip variable above.
	//
	// NOTE: When using this mutex along with newHeadersMtx at the same
	// time, newHeadersMtx should always be acquired first.
	newFilterHeadersMtx sync.RWMutex

	// newFilterHeadersSignal is condition variable which will be used to
	// notify any waiting callers (via Broadcast()) that the tip of the
	// current filter header chain has changed. This is useful when callers
	// need to know we have a new tip, but not necessarily each filter
	// header that was connected during switch over.
	newFilterHeadersSignal *sync.Cond

	// syncPeer points to the peer that we're currently syncing block
	// headers from.
	syncPeer *ServerPeer

	// syncPeerMutex protects the above syncPeer pointer at all times.
	syncPeerMutex sync.RWMutex

	// peerChan is a channel for messages that come from peers
	peerChan chan interface{}

	// blockNtfnChan is a channel in which the latest block notifications
	// for the tip of the chain will be sent upon.
	blockNtfnChan chan blockntfns.BlockNtfn

	wg   sync.WaitGroup
	quit chan struct{}

	headerList     headerlist.Chain
	reorgList      headerlist.Chain
	startHeader    *headerlist.Node
	nextCheckpoint *chaincfg.Checkpoint
	lastRequested  chainhash.Hash

	minRetargetTimespan int64 // target timespan / adjustment factor
	maxRetargetTimespan int64 // target timespan * adjustment factor
	blocksPerRetarget   int32 // target timespan / target time per block
}

// newBlockManager returns a new bitcoin block manager.  Use Start to begin
// processing asynchronous block and inv updates.
func newBlockManager(cfg *blockManagerCfg) (*blockManager, error) {

	targetTimespan := int64(cfg.ChainParams.TargetTimespan / time.Second)
	targetTimePerBlock := int64(cfg.ChainParams.TargetTimePerBlock / time.Second)
	adjustmentFactor := cfg.ChainParams.RetargetAdjustmentFactor

	bm := blockManager{
		cfg:           cfg,
		peerChan:      make(chan interface{}, MaxPeers*3),
		blockNtfnChan: make(chan blockntfns.BlockNtfn),
		blkHeaderProgressLogger: newBlockProgressLogger(
			"Processed", "block", log,
		),
		fltrHeaderProgessLogger: newBlockProgressLogger(
			"Verified", "filter header", log,
		),
		headerList: headerlist.NewBoundedMemoryChain(
			numMaxMemHeaders,
		),
		reorgList: headerlist.NewBoundedMemoryChain(
			numMaxMemHeaders,
		),
		quit:                make(chan struct{}),
		blocksPerRetarget:   int32(targetTimespan / targetTimePerBlock),
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
	}

	// Next we'll create the two signals that goroutines will use to wait
	// on a particular header chain height before starting their normal
	// duties.
	bm.newHeadersSignal = sync.NewCond(&bm.newHeadersMtx)
	bm.newFilterHeadersSignal = sync.NewCond(&bm.newFilterHeadersMtx)

	// We fetch the genesis header to use for verifying the first received
	// interval.
	genesisHeader, err := cfg.RegFilterHeaders.FetchHeaderByHeight(0)
	if err != nil {
		return nil, err
	}
	bm.genesisHeader = *genesisHeader

	// Initialize the next checkpoint based on the current height.
	header, height, err := cfg.BlockHeaders.ChainTip()
	if err != nil {
		return nil, err
	}
	bm.nextCheckpoint = bm.findNextHeaderCheckpoint(int32(height))
	bm.headerList.ResetHeaderState(headerlist.Node{
		Header: *header,
		Height: int32(height),
	})
	bm.headerTip = height
	bm.headerTipHash = header.BlockHash()

	// Finally, we'll set the filter header tip so any goroutines waiting
	// on the condition obtain the correct initial state.
	_, bm.filterHeaderTip, err = cfg.RegFilterHeaders.ChainTip()
	if err != nil {
		return nil, err
	}

	// We must also ensure the the filter header tip hash is set to the
	// block hash at the filter tip height.
	fh, err := cfg.BlockHeaders.FetchHeaderByHeight(bm.filterHeaderTip)
	if err != nil {
		return nil, err
	}
	bm.filterHeaderTipHash = fh.BlockHash()

	return &bm, nil
}

// Start begins the core block handler which processes block and inv messages.
func (b *blockManager) Start() {
	// Already started?
	if atomic.AddInt32(&b.started, 1) != 1 {
		return
	}

	log.Trace("Starting block manager")
	b.wg.Add(2)
	go b.blockHandler()
	go func() {
		defer b.wg.Done()

		log.Debug("Waiting for peer connection...")

		// Before starting the cfHandler we want to make sure we are
		// connected with at least one peer.
		select {
		case <-b.cfg.firstPeerSignal:
		case <-b.quit:
			return
		}

		log.Debug("Peer connected, starting cfHandler.")
		b.cfHandler()
	}()
}

// Stop gracefully shuts down the block manager by stopping all asynchronous
// handlers and waiting for them to finish.
func (b *blockManager) Stop() error {
	if atomic.AddInt32(&b.shutdown, 1) != 1 {
		log.Warnf("Block manager is already in the process of " +
			"shutting down")
		return nil
	}

	// We'll send out update signals before the quit to ensure that any
	// goroutines waiting on them will properly exit.
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Millisecond * 50)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}

			b.newHeadersSignal.Broadcast()
			b.newFilterHeadersSignal.Broadcast()
		}
	}()

	log.Infof("Block manager shutting down")
	close(b.quit)
	b.wg.Wait()

	close(done)
	return nil
}

// NewPeer informs the block manager of a newly active peer.
func (b *blockManager) NewPeer(sp *ServerPeer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	select {
	case b.peerChan <- &newPeerMsg{peer: sp}:
	case <-b.quit:
		return
	}
}

// handleNewPeerMsg deals with new peers that have signalled they may be
// considered as a sync peer (they have already successfully negotiated).  It
// also starts syncing if needed.  It is invoked from the syncHandler
// goroutine.
func (b *blockManager) handleNewPeerMsg(peers *list.List, sp *ServerPeer) {
	// Ignore if in the process of shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	log.Infof("New valid peer %s (%s)", sp, sp.UserAgent())

	// Ignore the peer if it's not a sync candidate.
	if !b.isSyncCandidate(sp) {
		return
	}

	// Add the peer as a candidate to sync from.
	peers.PushBack(sp)

	// If we're current with our sync peer and the new peer is advertising
	// a higher block than the newest one we know of, request headers from
	// the new peer.
	_, height, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		log.Criticalf("Couldn't retrieve block header chain tip: %s",
			err)
		return
	}
	if height < uint32(sp.StartingHeight()) && b.BlockHeadersSynced() {
		locator, err := b.cfg.BlockHeaders.LatestBlockLocator()
		if err != nil {
			log.Criticalf("Couldn't retrieve latest block "+
				"locator: %s", err)
			return
		}
		stopHash := &zeroHash
		sp.PushGetHeadersMsg(locator, stopHash)
	}

	// Start syncing by choosing the best candidate if needed.
	b.startSync(peers)
}

// DonePeer informs the blockmanager that a peer has disconnected.
func (b *blockManager) DonePeer(sp *ServerPeer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	select {
	case b.peerChan <- &donePeerMsg{peer: sp}:
	case <-b.quit:
		return
	}
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It
// removes the peer as a candidate for syncing and in the case where it was the
// current sync peer, attempts to select a new best peer to sync from.  It is
// invoked from the syncHandler goroutine.
func (b *blockManager) handleDonePeerMsg(peers *list.List, sp *ServerPeer) {
	// Remove the peer from the list of candidate peers.
	for e := peers.Front(); e != nil; e = e.Next() {
		if e.Value == sp {
			peers.Remove(e)
			break
		}
	}

	log.Infof("Lost peer %s", sp)

	// Attempt to find a new peer to sync from if the quitting peer is the
	// sync peer.  Also, reset the header state.
	if b.SyncPeer() != nil && b.SyncPeer() == sp {
		b.syncPeerMutex.Lock()
		b.syncPeer = nil
		b.syncPeerMutex.Unlock()
		header, height, err := b.cfg.BlockHeaders.ChainTip()
		if err != nil {
			return
		}
		b.headerList.ResetHeaderState(headerlist.Node{
			Header: *header,
			Height: int32(height),
		})
		b.startSync(peers)
	}
}

// cfHandler is the cfheader download handler for the block manager. It must be
// run as a goroutine. It requests and processes cfheaders messages in a
// separate goroutine from the peer handlers.
func (b *blockManager) cfHandler() {
	defer log.Trace("Committed filter header handler done")

	var (
		// allCFCheckpoints is a map from our peers to the list of
		// filter checkpoints they respond to us with. We'll attempt to
		// get filter checkpoints immediately up to the latest block
		// checkpoint we've got stored to avoid doing unnecessary
		// fetches as the block headers are catching up.
		allCFCheckpoints map[string][]*chainhash.Hash

		// lastCp will point to the latest block checkpoint we have for
		// the active chain, if any.
		lastCp chaincfg.Checkpoint

		// blockCheckpoints is the list of block checkpoints for the
		// active chain.
		blockCheckpoints = b.cfg.ChainParams.Checkpoints
	)

	// Set the variable to the latest block checkpoint if we have any for
	// this chain. Otherwise this block checkpoint will just stay at height
	// 0, which will prompt us to look at the block headers to fetch
	// checkpoints below.
	if len(blockCheckpoints) > 0 {
		lastCp = blockCheckpoints[len(blockCheckpoints)-1]
	}

waitForHeaders:
	// We'll wait until the main header sync is either finished or the
	// filter headers are lagging at least a checkpoint interval behind the
	// block headers, before we actually start to sync the set of
	// cfheaders. We do this to speed up the sync, as the check pointed
	// sync is faster, than fetching each header from each peer during the
	// normal "at tip" syncing.
	log.Infof("Waiting for more block headers, then will start "+
		"cfheaders sync from height %v...", b.filterHeaderTip)

	b.newHeadersSignal.L.Lock()
	b.newFilterHeadersMtx.RLock()
	for !(b.filterHeaderTip+wire.CFCheckptInterval <= b.headerTip || b.BlockHeadersSynced()) {
		b.newFilterHeadersMtx.RUnlock()
		b.newHeadersSignal.Wait()

		// While we're awake, we'll quickly check to see if we need to
		// quit early.
		select {
		case <-b.quit:
			b.newHeadersSignal.L.Unlock()
			return
		default:

		}

		// Re-acquire the lock in order to check for the filter header
		// tip at the next iteration of the loop.
		b.newFilterHeadersMtx.RLock()
	}
	b.newFilterHeadersMtx.RUnlock()
	b.newHeadersSignal.L.Unlock()

	// Now that the block headers are finished or ahead of the filter
	// headers, we'll grab the current chain tip so we can base our filter
	// header sync off of that.
	lastHeader, lastHeight, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		log.Critical(err)
		return
	}
	lastHash := lastHeader.BlockHash()

	b.newFilterHeadersMtx.RLock()
	log.Infof("Starting cfheaders sync from (block_height=%v, "+
		"block_hash=%v) to (block_height=%v, block_hash=%v)",
		b.filterHeaderTip, b.filterHeaderTipHash, lastHeight,
		lastHeader.BlockHash())
	b.newFilterHeadersMtx.RUnlock()

	fType := wire.GCSFilterRegular
	store := b.cfg.RegFilterHeaders

	log.Infof("Starting cfheaders sync for filter_type=%v", fType)

	// If we have less than a full checkpoint's worth of blocks, such as on
	// simnet, we don't really need to request checkpoints as we'll get 0
	// from all peers. We can go on and just request the cfheaders.
	var goodCheckpoints []*chainhash.Hash
	for len(goodCheckpoints) == 0 && lastHeight >= wire.CFCheckptInterval {

		// Quit if requested.
		select {
		case <-b.quit:
			return
		default:
		}

		// If the height now exceeds the height at which we fetched the
		// checkpoints last time, we must query our peers again.
		if minCheckpointHeight(allCFCheckpoints) < lastHeight {
			// Start by getting the filter checkpoints up to the
			// height of our block header chain. If we have a chain
			// checkpoint that is past this height, we use that
			// instead. We do this so we don't have to fetch all
			// filter checkpoints each time our block header chain
			// advances.
			// TODO(halseth): fetch filter checkpoints up to the
			// best block of the connected peers.
			bestHeight := lastHeight
			bestHash := lastHash
			if bestHeight < uint32(lastCp.Height) {
				bestHeight = uint32(lastCp.Height)
				bestHash = *lastCp.Hash
			}

			log.Debugf("Getting filter checkpoints up to "+
				"height=%v, hash=%v", bestHeight, bestHash)
			allCFCheckpoints = b.getCheckpts(&bestHash, fType)
			if len(allCFCheckpoints) == 0 {
				log.Warnf("Unable to fetch set of " +
					"candidate checkpoints, trying again...")

				select {
				case <-time.After(retryTimeout):
				case <-b.quit:
					return
				}
				continue
			}
		}

		// Cap the received checkpoints at the current height, as we
		// can only verify checkpoints up to the height we have block
		// headers for.
		checkpoints := make(map[string][]*chainhash.Hash)
		for p, cps := range allCFCheckpoints {
			for i, cp := range cps {
				height := uint32(i+1) * wire.CFCheckptInterval
				if height > lastHeight {
					break
				}
				checkpoints[p] = append(checkpoints[p], cp)
			}
		}

		// See if we can detect which checkpoint list is correct. If
		// not, we will cycle again.
		goodCheckpoints, err = b.resolveConflict(
			checkpoints, store, fType,
		)
		if err != nil {
			log.Warnf("got error attempting to determine correct "+
				"cfheader checkpoints: %v, trying again", err)
		}
		if len(goodCheckpoints) == 0 {
			select {
			case <-time.After(retryTimeout):
			case <-b.quit:
				return
			}
		}
	}

	// Get all the headers up to the last known good checkpoint.
	b.getCheckpointedCFHeaders(
		goodCheckpoints, store, fType,
	)

	// Now we check the headers again. If the block headers are not yet
	// current, then we go back to the loop waiting for them to finish.
	if !b.BlockHeadersSynced() {
		goto waitForHeaders
	}

	// If block headers are current, but the filter header tip is still
	// lagging more than a checkpoint interval behind the block header tip,
	// we also go back to the loop to utilize the faster check pointed
	// fetching.
	b.newHeadersMtx.RLock()
	b.newFilterHeadersMtx.RLock()
	if b.filterHeaderTip+wire.CFCheckptInterval <= b.headerTip {
		b.newFilterHeadersMtx.RUnlock()
		b.newHeadersMtx.RUnlock()
		goto waitForHeaders
	}
	b.newFilterHeadersMtx.RUnlock()
	b.newHeadersMtx.RUnlock()

	log.Infof("Fully caught up with cfheaders at height "+
		"%v, waiting at tip for new blocks", lastHeight)

	// Now that we've been fully caught up to the tip of the current header
	// chain, we'll wait here for a signal that more blocks have been
	// connected. If this happens then we'll do another round to fetch the
	// new set of filter new set of filter headers
	for {
		// We'll wait until the filter header tip and the header tip
		// are mismatched.
		b.newHeadersSignal.L.Lock()
		b.newFilterHeadersMtx.RLock()
		for b.filterHeaderTipHash == b.headerTipHash {
			// We'll wait here until we're woken up by the
			// broadcast signal.
			b.newFilterHeadersMtx.RUnlock()
			b.newHeadersSignal.Wait()

			// Before we proceed, we'll check if we need to exit at
			// all.
			select {
			case <-b.quit:
				b.newHeadersSignal.L.Unlock()
				return
			default:
			}

			// Re-acquire the lock in order to check for the filter
			// header tip at the next iteration of the loop.
			b.newFilterHeadersMtx.RLock()
		}
		b.newFilterHeadersMtx.RUnlock()
		b.newHeadersSignal.L.Unlock()

		// At this point, we know that there're a set of new filter
		// headers to fetch, so we'll grab them now.
		if err = b.getUncheckpointedCFHeaders(
			store, fType,
		); err != nil {
			log.Debugf("couldn't get uncheckpointed headers for "+
				"%v: %v", fType, err)

			select {
			case <-time.After(retryTimeout):
			case <-b.quit:
				return
			}
		}

		// Quit if requested.
		select {
		case <-b.quit:
			return
		default:
		}
	}
}

// getUncheckpointedCFHeaders gets the next batch of cfheaders from the
// network, if it can, and resolves any conflicts between them. It then writes
// any verified headers to the store.
func (b *blockManager) getUncheckpointedCFHeaders(
	store *headerfs.FilterHeaderStore, fType wire.FilterType) error {

	// Get the filter header store's chain tip.
	filterTip, filtHeight, err := store.ChainTip()
	if err != nil {
		return fmt.Errorf("error getting filter chain tip: %v", err)
	}
	blockHeader, blockHeight, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		return fmt.Errorf("error getting block chain tip: %v", err)
	}

	// If the block height is somehow before the filter height, then this
	// means that we may still be handling a re-org, so we'll bail our so
	// we can retry after a timeout.
	if blockHeight < filtHeight {
		return fmt.Errorf("reorg in progress, waiting to get "+
			"uncheckpointed cfheaders (block height %d, filter "+
			"height %d", blockHeight, filtHeight)
	}

	// If the heights match, then we're fully synced, so we don't need to
	// do anything from there.
	if blockHeight == filtHeight {
		log.Tracef("cfheaders already caught up to blocks")
		return nil
	}

	log.Infof("Attempting to fetch set of un-checkpointed filters "+
		"at height=%v, hash=%v", blockHeight, blockHeader.BlockHash())

	// Query all peers for the responses.
	startHeight := filtHeight + 1
	headers, numHeaders := b.getCFHeadersForAllPeers(startHeight, fType)

	// Ban any peer that responds with the wrong prev filter header.
	for peer, msg := range headers {
		if msg.PrevFilterHeader != *filterTip {
			err := b.cfg.BanPeer(peer, banman.InvalidFilterHeader)
			if err != nil {
				log.Errorf("Unable to ban peer %v: %v", peer, err)
			}
			delete(headers, peer)
		}
	}

	if len(headers) == 0 {
		return fmt.Errorf("couldn't get cfheaders from peers")
	}

	// For each header, go through and check whether all headers messages
	// have the same filter hash. If we find a difference, get the block,
	// calculate the filter, and throw out any mismatching peers.
	for i := 0; i < numHeaders; i++ {
		if checkForCFHeaderMismatch(headers, i) {
			targetHeight := startHeight + uint32(i)

			badPeers, err := b.detectBadPeers(
				headers, targetHeight, uint32(i), fType,
			)
			if err != nil {
				return err
			}

			log.Warnf("Banning %v peers due to invalid filter "+
				"headers", len(badPeers))

			for _, peer := range badPeers {
				err := b.cfg.BanPeer(
					peer, banman.InvalidFilterHeader,
				)
				if err != nil {
					log.Errorf("Unable to ban peer %v: %v",
						peer, err)
				}
				delete(headers, peer)
			}
		}
	}

	// Get the longest filter hash chain and write it to the store.
	key, maxLen := "", 0
	for peer, msg := range headers {
		if len(msg.FilterHashes) > maxLen {
			key, maxLen = peer, len(msg.FilterHashes)
		}
	}

	// We'll now fetch the set of pristine headers from the map. If ALL the
	// peers were banned, then we won't have a set of headers at all. We'll
	// return nil so we can go to the top of the loop and fetch from a new
	// set of peers.
	pristineHeaders, ok := headers[key]
	if !ok {
		return fmt.Errorf("All peers served bogus headers! Retrying " +
			"with new set")
	}

	_, _, err = b.writeCFHeadersMsg(pristineHeaders, store)
	return err
}

// checkpointedCFHeadersQuery holds all information necessary to perform and
// handle a query for checkpointed filter headers.
type checkpointedCFHeadersQuery struct {
	blockMgr    *blockManager
	msgs        []wire.Message
	checkpoints []*chainhash.Hash
	stopHashes  map[chainhash.Hash]uint32
	headerChan  chan *wire.MsgCFHeaders
}

// requests creates the query.Requests for this CF headers query.
func (c *checkpointedCFHeadersQuery) requests() []*query.Request {
	var reqs []*query.Request
	for _, m := range c.msgs {
		reqs = append(reqs, &query.Request{
			Req:        m,
			HandleResp: c.handleResponse,
		})
	}
	return reqs
}

// handleResponse is the internal response handler used for requests for this
// CFHeaders query.
func (c *checkpointedCFHeadersQuery) handleResponse(req, resp wire.Message,
	peerAddr string) query.Progress {

	r, ok := resp.(*wire.MsgCFHeaders)
	if !ok {
		// We are only looking for cfheaders messages.
		return query.Progress{
			Finished:   false,
			Progressed: false,
		}
	}

	q, ok := req.(*wire.MsgGetCFHeaders)
	if !ok {
		// We sent a getcfheaders message, so that's what we should be
		// comparing against.
		return query.Progress{
			Finished:   false,
			Progressed: false,
		}
	}

	// The response doesn't match the query.
	if q.FilterType != r.FilterType || q.StopHash != r.StopHash {
		return query.Progress{
			Finished:   false,
			Progressed: false,
		}
	}

	checkPointIndex, ok := c.stopHashes[r.StopHash]
	if !ok {
		// We never requested a matching stop hash.
		return query.Progress{
			Finished:   false,
			Progressed: false,
		}
	}

	// Use either the genesis header or the previous checkpoint index as
	// the previous checkpoint when verifying that the filter headers in
	// the response match up.
	prevCheckpoint := &c.blockMgr.genesisHeader
	if checkPointIndex > 0 {
		prevCheckpoint = c.checkpoints[checkPointIndex-1]
	}

	// The index of the next checkpoint will depend on whether the query
	// was able to allocate maxCFCheckptsPerQuery.
	nextCheckPointIndex := checkPointIndex + maxCFCheckptsPerQuery - 1
	if nextCheckPointIndex >= uint32(len(c.checkpoints)) {
		nextCheckPointIndex = uint32(len(c.checkpoints)) - 1
	}
	nextCheckpoint := c.checkpoints[nextCheckPointIndex]

	// The response doesn't match the checkpoint.
	if !verifyCheckpoint(prevCheckpoint, nextCheckpoint, r) {
		log.Warnf("Checkpoints at index %v don't match response!!!",
			checkPointIndex)

		// If the peer gives us a header that doesn't match what we
		// know to be the best checkpoint, then we'll ban the peer so
		// we can re-allocate the query elsewhere.
		err := c.blockMgr.cfg.BanPeer(
			peerAddr, banman.InvalidFilterHeaderCheckpoint,
		)
		if err != nil {
			log.Errorf("Unable to ban peer %v: %v", peerAddr, err)
		}

		return query.Progress{
			Finished:   false,
			Progressed: false,
		}
	}

	// At this point, the response matches the query, and the relevant
	// checkpoint we got earlier, so we'll deliver the verified headers on
	// the headerChan.  We'll also return a Progress indicating the query
	// finished, that the peer looking for the answer to this query can
	// move on to the next query.
	select {
	case c.headerChan <- r:
	case <-c.blockMgr.quit:
		return query.Progress{
			Finished:   false,
			Progressed: false,
		}
	}

	return query.Progress{
		Finished:   true,
		Progressed: true,
	}
}

// getCheckpointedCFHeaders catches a filter header store up with the
// checkpoints we got from the network. It assumes that the filter header store
// matches the checkpoints up to the tip of the store.
func (b *blockManager) getCheckpointedCFHeaders(checkpoints []*chainhash.Hash,
	store *headerfs.FilterHeaderStore, fType wire.FilterType) {

	// We keep going until we've caught up the filter header store with the
	// latest known checkpoint.
	curHeader, curHeight, err := store.ChainTip()
	if err != nil {
		panic(fmt.Sprintf("failed getting chaintip from filter "+
			"store: %v", err))
	}

	initialFilterHeader := curHeader

	log.Infof("Fetching set of checkpointed cfheaders filters from "+
		"height=%v, hash=%v", curHeight, curHeader)

	// The starting interval is the checkpoint index that we'll be starting
	// from based on our current height in the filter header index.
	startingInterval := curHeight / wire.CFCheckptInterval

	log.Infof("Starting to query for cfheaders from "+
		"checkpoint_interval=%v, checkpoints=%v", startingInterval,
		len(checkpoints))

	// We'll determine how many queries we'll make based on our starting
	// interval and our set of checkpoints. Each query will attempt to fetch
	// maxCFCheckptsPerQuery intervals worth of filter headers. If
	// maxCFCheckptsPerQuery is not a factor of the number of checkpoint
	// intervals to fetch, then an additional query will exist that spans
	// the remaining checkpoint intervals.
	numCheckpts := uint32(len(checkpoints)) - startingInterval
	numQueries := (numCheckpts + maxCFCheckptsPerQuery - 1) / maxCFCheckptsPerQuery
	queryMsgs := make([]wire.Message, 0, numQueries)

	// We'll also create an additional set of maps that we'll use to
	// re-order the responses as we get them in.
	queryResponses := make(map[uint32]*wire.MsgCFHeaders, numQueries)
	stopHashes := make(map[chainhash.Hash]uint32, numQueries)

	// Generate all of the requests we'll be batching and space to store
	// the responses. Also make a map of stophash to index to make it
	// easier to match against incoming responses.
	//
	// TODO(roasbeef): extract to func to test
	currentInterval := startingInterval
	for currentInterval < uint32(len(checkpoints)) {
		// Each checkpoint is spaced wire.CFCheckptInterval after the
		// prior one, so we'll fetch headers in batches using the
		// checkpoints as a guide. Our queries will consist of
		// maxCFCheckptsPerQuery unless we don't have enough checkpoints
		// to do so. In that case, our query will consist of whatever is
		// left.
		startHeightRange := uint32(
			currentInterval*wire.CFCheckptInterval,
		) + 1

		nextInterval := currentInterval + maxCFCheckptsPerQuery
		if nextInterval > uint32(len(checkpoints)) {
			nextInterval = uint32(len(checkpoints))
		}
		endHeightRange := uint32(nextInterval * wire.CFCheckptInterval)

		log.Tracef("Checkpointed cfheaders request start_range=%v, "+
			"end_range=%v", startHeightRange, endHeightRange)

		// In order to fetch the range, we'll need the block header for
		// the end of the height range.
		stopHeader, err := b.cfg.BlockHeaders.FetchHeaderByHeight(
			endHeightRange,
		)
		if err != nil {
			panic(fmt.Sprintf("failed getting block header at "+
				"height %v: %v", endHeightRange, err))
		}
		stopHash := stopHeader.BlockHash()

		// Once we have the stop hash, we can construct the query
		// message itself.
		queryMsg := wire.NewMsgGetCFHeaders(
			fType, uint32(startHeightRange), &stopHash,
		)

		// We'll mark that the ith interval is queried by this message,
		// and also map the stop hash back to the index of this message.
		queryMsgs = append(queryMsgs, queryMsg)
		stopHashes[stopHash] = currentInterval

		// With the query starting at the current interval constructed,
		// we'll move onto the next one.
		currentInterval = nextInterval
	}

	batchesCount := len(queryMsgs)
	if batchesCount == 0 {
		return
	}

	log.Infof("Attempting to query for %v cfheader batches", batchesCount)

	// We'll track the next interval we expect to receive headers for.
	currentInterval = startingInterval

	// With the set of messages constructed, we'll now request the batch
	// all at once. This message will distributed the header requests
	// amongst all active peers, effectively sharding each query
	// dynamically.
	headerChan := make(chan *wire.MsgCFHeaders, len(queryMsgs))
	q := checkpointedCFHeadersQuery{
		blockMgr:    b,
		msgs:        queryMsgs,
		checkpoints: checkpoints,
		stopHashes:  stopHashes,
		headerChan:  headerChan,
	}

	// Hand the queries to the work manager, and consume the verified
	// responses as they come back.
	errChan := b.cfg.QueryDispatcher.Query(
		q.requests(), query.Cancel(b.quit),
	)

	// Keep waiting for more headers as long as we haven't received an
	// answer for our last checkpoint, and no error is encountered.
	for {
		var r *wire.MsgCFHeaders
		select {
		case r = <-headerChan:
		case err := <-errChan:
			switch {
			case err == query.ErrWorkManagerShuttingDown:
				return
			case err != nil:
				log.Errorf("Query finished with error before "+
					"all responses received: %v", err)
				return
			}

			// The query did finish succesfully, but continue to
			// allow picking up the last header sent on the
			// headerChan.
			continue

		case <-b.quit:
			return
		}

		checkPointIndex := stopHashes[r.StopHash]

		// Find the first and last height for the blocks
		// represented by this message.
		startHeight := checkPointIndex*wire.CFCheckptInterval + 1
		lastHeight := startHeight + uint32(len(r.FilterHashes)) - 1

		log.Debugf("Got cfheaders from height=%v to "+
			"height=%v, prev_hash=%v", startHeight,
			lastHeight, r.PrevFilterHeader)

		// If this is out of order but not yet written, we can
		// verify that the checkpoints match, and then store
		// them.
		if startHeight > curHeight+1 {
			log.Debugf("Got response for headers at "+
				"height=%v, only at height=%v, stashing",
				startHeight, curHeight)
		}

		// If this is out of order stuff that's already been
		// written, we can ignore it.
		if lastHeight <= curHeight {
			log.Debugf("Received out of order reply "+
				"end_height=%v, already written", lastHeight)
			continue
		}

		// Add the verified response to our cache.
		queryResponses[checkPointIndex] = r

		// Then, we cycle through any cached messages, adding
		// them to the batch and deleting them from the cache.
		for {
			// If we don't yet have the next response, then
			// we'll break out so we can wait for the peers
			// to respond with this message.
			r, ok := queryResponses[currentInterval]
			if !ok {
				break
			}

			// We have another response to write, so delete
			// it from the cache and write it.
			delete(queryResponses, currentInterval)

			log.Debugf("Writing cfheaders at height=%v to "+
				"next checkpoint", curHeight)

			// If this is the very first range we've requested, we
			// may already have a portion of the headers written to
			// disk.
			//
			// TODO(roasbeef): can eventually special case handle
			// this at the top
			if bytes.Equal(curHeader[:], initialFilterHeader[:]) {
				// So we'll set the prev header to our best
				// known header, and seek within the header
				// range a bit so we don't write any duplicate
				// headers.
				r.PrevFilterHeader = *curHeader
				offset := curHeight + 1 - startHeight
				r.FilterHashes = r.FilterHashes[offset:]

				log.Debugf("Using offset %d for initial "+
					"filter header range (new prev_hash=%v)",
					offset, r.PrevFilterHeader)
			}

			// As we write the set of headers to disk, we
			// also obtain the hash of the last filter
			// header we've written to disk so we can
			// properly set the PrevFilterHeader field of
			// the next message.
			curHeader, curHeight, err = b.writeCFHeadersMsg(r, store)
			if err != nil {
				panic(fmt.Sprintf("couldn't write "+
					"cfheaders msg: %v", err))
			}

			// Update the next interval to write to reflect our
			// current height.
			currentInterval = curHeight / wire.CFCheckptInterval
		}

		// If the current interval is beyond our checkpoints,
		// we are done.
		if currentInterval >= uint32(len(checkpoints)) {
			log.Infof("Successfully got filter headers "+
				"for %d checkpoints", len(checkpoints))
			break
		}
	}
}

// writeCFHeadersMsg writes a cfheaders message to the specified store. It
// assumes that everything is being written in order. The hints are required to
// store the correct block heights for the filters. We also return final
// constructed cfheader in this range as this lets callers populate the prev
// filter header field in the next message range before writing to disk, and
// the current height after writing the headers.
func (b *blockManager) writeCFHeadersMsg(msg *wire.MsgCFHeaders,
	store *headerfs.FilterHeaderStore) (*chainhash.Hash, uint32, error) {

	// Check that the PrevFilterHeader is the same as the last stored so we
	// can prevent misalignment.
	tip, tipHeight, err := store.ChainTip()
	if err != nil {
		return nil, 0, err
	}
	if *tip != msg.PrevFilterHeader {
		return nil, 0, fmt.Errorf("attempt to write cfheaders out of "+
			"order! Tip=%v (height=%v), prev_hash=%v.", *tip,
			tipHeight, msg.PrevFilterHeader)
	}

	// Cycle through the headers and compute each header based on the prev
	// header and the filter hash from the cfheaders response entries.
	lastHeader := msg.PrevFilterHeader
	headerBatch := make([]headerfs.FilterHeader, 0, len(msg.FilterHashes))
	for _, hash := range msg.FilterHashes {
		// header = dsha256(filterHash || prevHeader)
		lastHeader = chainhash.DoubleHashH(
			append(hash[:], lastHeader[:]...),
		)

		headerBatch = append(headerBatch, headerfs.FilterHeader{
			FilterHash: lastHeader,
		})
	}

	numHeaders := len(headerBatch)

	// We'll now query for the set of block headers which match each of
	// these filters headers in their corresponding chains. Our query will
	// return the headers for the entire checkpoint interval ending at the
	// designated stop hash.
	blockHeaders := b.cfg.BlockHeaders
	matchingBlockHeaders, startHeight, err := blockHeaders.FetchHeaderAncestors(
		uint32(numHeaders-1), &msg.StopHash,
	)
	if err != nil {
		return nil, 0, err
	}

	// The final height in our range will be offset to the end of this
	// particular checkpoint interval.
	lastHeight := startHeight + uint32(numHeaders) - 1
	lastBlockHeader := matchingBlockHeaders[numHeaders-1]
	lastHash := lastBlockHeader.BlockHash()

	// We only need to set the height and hash of the very last filter
	// header in the range to ensure that the index properly updates the
	// tip of the chain.
	headerBatch[numHeaders-1].HeaderHash = lastHash
	headerBatch[numHeaders-1].Height = lastHeight

	log.Debugf("Writing filter headers up to height=%v, hash=%v, "+
		"new_tip=%v", lastHeight, lastHash, lastHeader)

	// Write the header batch.
	err = store.WriteHeaders(headerBatch...)
	if err != nil {
		return nil, 0, err
	}

	// We'll also set the new header tip and notify any peers that the tip
	// has changed as well. Unlike the set of notifications below, this is
	// for sub-system that only need to know the height has changed rather
	// than know each new header that's been added to the tip.
	b.newFilterHeadersMtx.Lock()
	b.filterHeaderTip = lastHeight
	b.filterHeaderTipHash = lastHash
	b.newFilterHeadersMtx.Unlock()
	b.newFilterHeadersSignal.Broadcast()

	// Notify subscribers, and also update the filter header progress
	// logger at the same time.
	for i, header := range matchingBlockHeaders {
		header := header

		headerHeight := startHeight + uint32(i)
		b.fltrHeaderProgessLogger.LogBlockHeight(
			header.Timestamp, int32(headerHeight),
		)

		b.onBlockConnected(header, headerHeight)
	}

	return &lastHeader, lastHeight, nil
}

// rollBackToHeight rolls back all blocks until it hits the specified height.
// It sends notifications along the way.
func (b *blockManager) rollBackToHeight(height uint32) (*headerfs.BlockStamp, error) {
	header, headerHeight, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		return nil, err
	}
	bs := &headerfs.BlockStamp{
		Height: int32(headerHeight),
		Hash:   header.BlockHash(),
	}

	_, regHeight, err := b.cfg.RegFilterHeaders.ChainTip()
	if err != nil {
		return nil, err
	}

	for uint32(bs.Height) > height {
		header, headerHeight, err := b.cfg.BlockHeaders.FetchHeader(&bs.Hash)
		if err != nil {
			return nil, err
		}

		newTip := &header.PrevBlock

		// Only roll back filter headers if they've caught up this far.
		if uint32(bs.Height) <= regHeight {
			newFilterTip, err := b.cfg.RegFilterHeaders.RollbackLastBlock(newTip)
			if err != nil {
				return nil, err
			}
			regHeight = uint32(newFilterTip.Height)
		}

		bs, err = b.cfg.BlockHeaders.RollbackLastBlock()
		if err != nil {
			return nil, err
		}

		// Notifications are asynchronous, so we include the previous
		// header in the disconnected notification in case we're rolling
		// back farther and the notification subscriber needs it but
		// can't read it before it's deleted from the store.
		prevHeader, _, err := b.cfg.BlockHeaders.FetchHeader(newTip)
		if err != nil {
			return nil, err
		}

		// Now we send the block disconnected notifications.
		b.onBlockDisconnected(
			*header, headerHeight, *prevHeader,
		)
	}
	return bs, nil
}

// minCheckpointHeight returns the height of the last filter checkpoint for the
// shortest checkpoint list among the given lists.
func minCheckpointHeight(checkpoints map[string][]*chainhash.Hash) uint32 {
	// If the map is empty, return 0 immediately.
	if len(checkpoints) == 0 {
		return 0
	}

	// Otherwise return the length of the shortest one.
	minHeight := uint32(math.MaxUint32)
	for _, cps := range checkpoints {
		height := uint32(len(cps) * wire.CFCheckptInterval)
		if height < minHeight {
			minHeight = height
		}
	}
	return minHeight
}

// verifyHeaderCheckpoint verifies that a CFHeaders message matches the passed
// checkpoints. It assumes everything else has been checked, including filter
// type and stop hash matches, and returns true if matching and false if not.
func verifyCheckpoint(prevCheckpoint, nextCheckpoint *chainhash.Hash,
	cfheaders *wire.MsgCFHeaders) bool {

	if *prevCheckpoint != cfheaders.PrevFilterHeader {
		return false
	}

	lastHeader := cfheaders.PrevFilterHeader
	for _, hash := range cfheaders.FilterHashes {
		lastHeader = chainhash.DoubleHashH(
			append(hash[:], lastHeader[:]...),
		)
	}

	return lastHeader == *nextCheckpoint
}

// resolveConflict finds the correct checkpoint information, rewinds the header
// store if it's incorrect, and bans any peers giving us incorrect header
// information.
func (b *blockManager) resolveConflict(
	checkpoints map[string][]*chainhash.Hash,
	store *headerfs.FilterHeaderStore, fType wire.FilterType) (
	[]*chainhash.Hash, error) {

	// First check the served checkpoints against the hardcoded ones.
	for peer, cp := range checkpoints {
		for i, header := range cp {
			height := uint32((i + 1) * wire.CFCheckptInterval)
			err := chainsync.ControlCFHeader(
				b.cfg.ChainParams, fType, height, header,
			)
			if err == chainsync.ErrCheckpointMismatch {
				log.Warnf("Banning peer=%v since served "+
					"checkpoints didn't match our "+
					"checkpoint at height %d", peer, height)

				err := b.cfg.BanPeer(
					peer, banman.InvalidFilterHeaderCheckpoint,
				)
				if err != nil {
					log.Errorf("Unable to ban peer %v: %v",
						peer, err)
				}
				delete(checkpoints, peer)
				break
			}
			if err != nil {
				return nil, err
			}
		}
	}

	if len(checkpoints) == 0 {
		return nil, fmt.Errorf("no peer is serving good cfheader " +
			"checkpoints")
	}

	// Check if the remaining checkpoints are sane.
	heightDiff, err := checkCFCheckptSanity(checkpoints, store)
	if err != nil {
		return nil, err
	}

	// If we got -1, we have full agreement between all peers and the store.
	if heightDiff == -1 {
		// Take the first peer's checkpoint list and return it.
		for _, checkpts := range checkpoints {
			return checkpts, nil
		}
	}

	log.Warnf("Detected mismatch at index=%v for checkpoints!!!", heightDiff)

	// Delete any responses that have fewer checkpoints than where we see a
	// mismatch.
	for peer, checkpts := range checkpoints {
		if len(checkpts) < heightDiff {
			delete(checkpoints, peer)
		}
	}

	if len(checkpoints) == 0 {
		return nil, fmt.Errorf("no peer is serving good cfheaders")
	}

	// Now we get all of the mismatched CFHeaders from peers, and check
	// which ones are valid.
	// TODO(halseth): check if peer serves headers that matches its checkpoints
	startHeight := uint32(heightDiff) * wire.CFCheckptInterval
	headers, numHeaders := b.getCFHeadersForAllPeers(startHeight, fType)

	// Make sure we're working off the same baseline. Otherwise, we want to
	// go back and get checkpoints again.
	var hash chainhash.Hash
	for _, msg := range headers {
		if hash == zeroHash {
			hash = msg.PrevFilterHeader
		} else if hash != msg.PrevFilterHeader {
			return nil, fmt.Errorf("mismatch between filter " +
				"headers expected to be the same")
		}
	}

	// For each header, go through and check whether all headers messages
	// have the same filter hash. If we find a difference, get the block,
	// calculate the filter, and throw out any mismatching peers.
	for i := 0; i < numHeaders; i++ {
		if checkForCFHeaderMismatch(headers, i) {
			// Get the block header for this height, along with the
			// block as well.
			targetHeight := startHeight + uint32(i)

			badPeers, err := b.detectBadPeers(
				headers, targetHeight, uint32(i), fType,
			)
			if err != nil {
				return nil, err
			}

			log.Warnf("Banning %v peers due to invalid filter "+
				"headers", len(badPeers))

			for _, peer := range badPeers {
				err := b.cfg.BanPeer(
					peer, banman.InvalidFilterHeader,
				)
				if err != nil {
					log.Errorf("Unable to ban peer %v: %v",
						peer, err)
				}
				delete(headers, peer)
				delete(checkpoints, peer)
			}
		}
	}

	// Any mismatches have now been thrown out. Delete any checkpoint
	// lists that don't have matching headers, as these are peers that
	// didn't respond, and ban them from future queries.
	for peer := range checkpoints {
		if _, ok := headers[peer]; !ok {
			err := b.cfg.BanPeer(
				peer, banman.InvalidFilterHeaderCheckpoint,
			)
			if err != nil {
				log.Errorf("Unable to ban peer %v: %v", peer,
					err)
			}
			delete(checkpoints, peer)
		}
	}

	// Check sanity again. If we're sane, return a matching checkpoint
	// list. If not, return an error and download checkpoints from
	// remaining peers.
	heightDiff, err = checkCFCheckptSanity(checkpoints, store)
	if err != nil {
		return nil, err
	}

	// If we got -1, we have full agreement between all peers and the store.
	if heightDiff == -1 {
		// Take the first peer's checkpoint list and return it.
		for _, checkpts := range checkpoints {
			return checkpts, nil
		}
	}

	// Otherwise, return an error and allow the loop which calls this
	// function to call it again with the new set of peers.
	return nil, fmt.Errorf("got mismatched checkpoints")
}

// checkForCFHeaderMismatch checks all peers' responses at a specific position
// and detects a mismatch. It returns true if a mismatch has occurred.
func checkForCFHeaderMismatch(headers map[string]*wire.MsgCFHeaders,
	idx int) bool {

	// First, see if we have a mismatch.
	hash := zeroHash
	for _, msg := range headers {
		if len(msg.FilterHashes) <= idx {
			continue
		}

		if hash == zeroHash {
			hash = *msg.FilterHashes[idx]
			continue
		}

		if hash != *msg.FilterHashes[idx] {
			// We've found a mismatch!
			return true
		}
	}

	return false
}

// detectBadPeers fetches filters and the block at the given height to attempt
// to detect which peers are serving bad filters.
func (b *blockManager) detectBadPeers(headers map[string]*wire.MsgCFHeaders,
	targetHeight, filterIndex uint32,
	fType wire.FilterType) ([]string, error) {

	log.Warnf("Detected cfheader mismatch at height=%v!!!", targetHeight)

	// Get the block header for this height.
	header, err := b.cfg.BlockHeaders.FetchHeaderByHeight(targetHeight)
	if err != nil {
		return nil, err
	}

	// Fetch filters from the peers in question.
	// TODO(halseth): query only peers from headers map.
	filtersFromPeers := b.fetchFilterFromAllPeers(
		targetHeight, header.BlockHash(), fType,
	)

	var badPeers []string
	for peer, msg := range headers {
		filter, ok := filtersFromPeers[peer]

		// If a peer did not respond, ban it immediately.
		if !ok {
			log.Warnf("Peer %v did not respond to filter "+
				"request, considering bad", peer)
			badPeers = append(badPeers, peer)
			continue
		}

		// If the peer is serving filters that isn't consistent with
		// its filter hashes, ban it.
		hash, err := builder.GetFilterHash(filter)
		if err != nil {
			return nil, err
		}
		if hash != *msg.FilterHashes[filterIndex] {
			log.Warnf("Peer %v serving filters not consistent "+
				"with filter hashes, considering bad.", peer)
			badPeers = append(badPeers, peer)
		}
	}

	if len(badPeers) != 0 {
		return badPeers, nil
	}

	// If all peers responded with consistent filters and hashes, get the
	// block and use it to detect who is serving bad filters.
	block, err := b.cfg.GetBlock(header.BlockHash())
	if err != nil {
		return nil, err
	}

	log.Warnf("Attempting to reconcile cfheader mismatch amongst %v peers",
		len(headers))

	return resolveFilterMismatchFromBlock(
		block.MsgBlock(), fType, filtersFromPeers,

		// We'll require a strict majority of our peers to agree on
		// filters.
		(len(filtersFromPeers)+2)/2,
	)
}

// resolveFilterMismatchFromBlock will attempt to cross-reference each filter
// in filtersFromPeers with the given block, based on what we can reconstruct
// and verify from the filter in question. We'll return all the peers that
// returned what we believe to be an invalid filter. The threshold argument is
// the minimum number of peers we need to agree on a filter before banning the
// other peers.
//
// We'll use a few strategies to figure out which peers we believe serve
// invalid filters:
//	1. If a peers' filter doesn't match on a script that must match, we know
//	the filter is invalid.
//	2. If a peers' filter matches on a script that _should not_ match, it
//	is potentially invalid. In this case we ban peers that matches more
//	such scripts than other peers.
//	3. If we cannot detect which filters are invalid from the block
//	contents, we ban peers serving filters different from the majority of
//	peers.
func resolveFilterMismatchFromBlock(block *wire.MsgBlock,
	fType wire.FilterType, filtersFromPeers map[string]*gcs.Filter,
	threshold int) ([]string, error) {

	badPeers := make(map[string]struct{})

	blockHash := block.BlockHash()
	filterKey := builder.DeriveKey(&blockHash)

	log.Infof("Attempting to pinpoint mismatch in cfheaders for block=%v",
		block.Header.BlockHash())

	// Based on the type of filter, our verification algorithm will differ.
	// Only regular filters are currently defined.
	if fType != wire.GCSFilterRegular {
		return nil, fmt.Errorf("unknown filter: %v", fType)
	}

	// With the current set of items that we can fetch from the p2p
	// network, we're forced to only verify what we can at this point. So
	// we'll just ensure that each of the filters returned contains the
	// expected outputs in the block. We don't have the prev outs so we
	// cannot fully verify the filter.
	//
	// TODO(roasbeef): update after BLOCK_WITH_PREV_OUTS is a thing

	// Since we don't expect OP_RETURN scripts to be included in the block,
	// we keep a counter for how many matches for each peer. Since there
	// might be false positives, an honest peer might still match on
	// OP_RETURNS, but we can attempt to ban peers that have more matches
	// than other peers.
	opReturnMatches := make(map[string]int)

	// We'll now run through each peer and ensure that each output
	// script is included in the filter that they responded with to
	// our query.
peerVerification:
	for peerAddr, filter := range filtersFromPeers {
		// We'll ensure that all the filters include every output
		// script within the block.
		//
		// TODO(roasbeef): eventually just do a comparison against
		// decompressed filters
		for _, tx := range block.Transactions {
			for _, txOut := range tx.TxOut {
				switch {
				// If the script itself is blank, then we'll
				// skip this as it doesn't contain any useful
				// information.
				case len(txOut.PkScript) == 0:
					continue

				// We'll also skip any OP_RETURN scripts as
				// well since we don't index these in order to
				// avoid a circular dependency.
				case txOut.PkScript[0] == txscript.OP_RETURN:
					// Previous versions of the filters did
					// include OP_RETURNs. To be able
					// disconnect bad peers still serving
					// these old filters we attempt to
					// check if there's an unexpected
					// match. Since there might be false
					// positives, an OP_RETURN can still
					// match filters not including them.
					// Therefore, we count the number of
					// such unexpected matches for each
					// peer, such that we can ban peers
					// matching more than the rest.
					match, err := filter.Match(
						filterKey, txOut.PkScript,
					)
					if err != nil {
						// Mark peer bad if we cannot
						// match on its filter.
						log.Warnf("Unable to check "+
							"filter match for "+
							"peer %v, marking as "+
							"bad: %v", peerAddr,
							err)

						badPeers[peerAddr] = struct{}{}
						continue peerVerification
					}

					// If it matches on the OP_RETURN
					// output, we increase the op return
					// counter.
					if match {
						opReturnMatches[peerAddr]++
					}
					continue
				}

				match, err := filter.Match(
					filterKey, txOut.PkScript,
				)
				if err != nil {
					// If we're unable to query this
					// filter, then we'll immediately ban
					// this peer.
					log.Warnf("Unable to check filter "+
						"match for peer %v, marking "+
						"as bad: %v", peerAddr, err)

					badPeers[peerAddr] = struct{}{}
					continue peerVerification
				}

				if match {
					continue
				}

				// If this filter doesn't match, then we'll
				// mark this peer as bad and move on to the
				// next peer.
				badPeers[peerAddr] = struct{}{}
				continue peerVerification
			}
		}
	}

	// TODO: We can add an after-the-fact countermeasure here against
	// eclipse attacks. If the checkpoints don't match the store, we can
	// check whether the store or the checkpoints we got from the network
	// are correct.

	// Return the bad peers if we have already found some.
	if len(badPeers) > 0 {
		invalidPeers := make([]string, 0, len(badPeers))
		for peer := range badPeers {
			invalidPeers = append(invalidPeers, peer)
		}

		return invalidPeers, nil
	}

	// If we couldn't immediately detect bad peers, we check if some peers
	// were matching more OP_RETURNS than the rest.
	mostMatches := 0
	for _, cnt := range opReturnMatches {
		if cnt > mostMatches {
			mostMatches = cnt
		}
	}

	// Gather up the peers with the most OP_RETURN matches.
	var potentialBans []string
	for peer, cnt := range opReturnMatches {
		if cnt == mostMatches {
			potentialBans = append(potentialBans, peer)
		}
	}

	// If only a few peers had matching OP_RETURNS, we assume they are bad.
	numRemaining := len(filtersFromPeers) - len(potentialBans)
	if len(potentialBans) > 0 && numRemaining >= threshold {
		log.Warnf("Found %d peers serving filters with unexpected "+
			"OP_RETURNS. %d peers remaining", len(potentialBans),
			numRemaining)

		return potentialBans, nil
	}

	// If all peers where serving filters consistent with the block, we
	// cannot know for sure which one is dishonest (since we don't have the
	// prevouts to deterministically reconstruct the filter). In this
	// situation we go with the majority.
	count := make(map[chainhash.Hash]int)
	best := 0
	for _, filter := range filtersFromPeers {
		hash, err := builder.GetFilterHash(filter)
		if err != nil {
			return nil, err
		}

		count[hash]++
		if count[hash] > best {
			best = count[hash]
		}
	}

	// If the number of peers serving the most common filter didn't match
	// our threshold, there's not more we can do.
	if best < threshold {
		return nil, fmt.Errorf("only %d peers serving consistent "+
			"filters, need %d", best, threshold)
	}

	// Mark all peers serving a filter other than the most common one as
	// bad.
	for peerAddr, filter := range filtersFromPeers {
		hash, err := builder.GetFilterHash(filter)
		if err != nil {
			return nil, err
		}

		if count[hash] < best {
			log.Warnf("Peer %v is serving filter with hash(%v) "+
				"other than majority, marking as bad",
				peerAddr, hash)
			badPeers[peerAddr] = struct{}{}
		}
	}

	invalidPeers := make([]string, 0, len(badPeers))
	for peer := range badPeers {
		invalidPeers = append(invalidPeers, peer)
	}

	return invalidPeers, nil
}

// getCFHeadersForAllPeers runs a query for cfheaders at a specific height and
// returns a map of responses from all peers. The second return value is the
// number for cfheaders in each response.
func (b *blockManager) getCFHeadersForAllPeers(height uint32,
	fType wire.FilterType) (map[string]*wire.MsgCFHeaders, int) {

	// Create the map we're returning.
	headers := make(map[string]*wire.MsgCFHeaders)

	// Get the header we expect at either the tip of the block header store
	// or at the end of the maximum-size response message, whichever is
	// larger.
	stopHeader, stopHeight, err := b.cfg.BlockHeaders.ChainTip()
	if stopHeight-height >= wire.MaxCFHeadersPerMsg {
		stopHeader, err = b.cfg.BlockHeaders.FetchHeaderByHeight(
			height + wire.MaxCFHeadersPerMsg - 1,
		)
		if err != nil {
			return nil, 0
		}

		// We'll make sure we also update our stopHeight so we know how
		// many headers to expect below.
		stopHeight = height + wire.MaxCFHeadersPerMsg - 1
	}

	// Calculate the hash and use it to create the query message.
	stopHash := stopHeader.BlockHash()
	msg := wire.NewMsgGetCFHeaders(fType, height, &stopHash)
	numHeaders := int(stopHeight - height + 1)

	// Send the query to all peers and record their responses in the map.
	b.cfg.queryAllPeers(
		msg,
		func(sp *ServerPeer, resp wire.Message, quit chan<- struct{},
			peerQuit chan<- struct{}) {
			switch m := resp.(type) {
			case *wire.MsgCFHeaders:
				if m.StopHash == stopHash &&
					m.FilterType == fType &&
					len(m.FilterHashes) == numHeaders {

					headers[sp.Addr()] = m

					// We got an answer from this peer so
					// that peer's goroutine can stop.
					close(peerQuit)
				}
			}
		},
	)

	return headers, numHeaders
}

// fetchFilterFromAllPeers attempts to fetch a filter for the target filter
// type and blocks from all peers connected to the block manager. This method
// returns a map which allows the caller to match a peer to the filter it
// responded with.
func (b *blockManager) fetchFilterFromAllPeers(
	height uint32, blockHash chainhash.Hash,
	filterType wire.FilterType) map[string]*gcs.Filter {

	// We'll use this map to collate all responses we receive from each
	// peer.
	filterResponses := make(map[string]*gcs.Filter)

	// We'll now request the target filter from each peer, using a stop
	// hash at the target block hash to ensure we only get a single filter.
	fitlerReqMsg := wire.NewMsgGetCFilters(filterType, height, &blockHash)
	b.cfg.queryAllPeers(
		fitlerReqMsg,
		func(sp *ServerPeer, resp wire.Message, quit chan<- struct{},
			peerQuit chan<- struct{}) {

			switch response := resp.(type) {
			// We're only interested in "cfilter" messages.
			case *wire.MsgCFilter:
				// If the response doesn't match our request.
				// Ignore this message.
				if blockHash != response.BlockHash ||
					filterType != response.FilterType {
					return
				}

				// Now that we know we have the proper filter,
				// we'll decode it into an object the caller
				// can utilize.
				gcsFilter, err := gcs.FromNBytes(
					builder.DefaultP, builder.DefaultM,
					response.Data,
				)
				if err != nil {
					// Malformed filter data. We can ignore
					// this message.
					return
				}

				// Now that we're able to properly parse this
				// filter, we'll assign it to its source peer,
				// and wait for the next response.
				filterResponses[sp.Addr()] = gcsFilter

			default:
			}
		},
	)

	return filterResponses
}

// getCheckpts runs a query for cfcheckpts against all peers and returns a map
// of responses.
func (b *blockManager) getCheckpts(lastHash *chainhash.Hash,
	fType wire.FilterType) map[string][]*chainhash.Hash {

	checkpoints := make(map[string][]*chainhash.Hash)
	getCheckptMsg := wire.NewMsgGetCFCheckpt(fType, lastHash)
	b.cfg.queryAllPeers(
		getCheckptMsg,
		func(sp *ServerPeer, resp wire.Message, quit chan<- struct{},
			peerQuit chan<- struct{}) {
			switch m := resp.(type) {
			case *wire.MsgCFCheckpt:
				if m.FilterType == fType &&
					m.StopHash == *lastHash {
					checkpoints[sp.Addr()] = m.FilterHeaders
					close(peerQuit)
				}
			}
		},
	)
	return checkpoints
}

// checkCFCheckptSanity checks whether all peers which have responded agree.
// If so, it returns -1; otherwise, it returns the earliest index at which at
// least one of the peers differs. The checkpoints are also checked against the
// existing store up to the tip of the store. If all of the peers match but
// the store doesn't, the height at which the mismatch occurs is returned.
func checkCFCheckptSanity(cp map[string][]*chainhash.Hash,
	headerStore *headerfs.FilterHeaderStore) (int, error) {

	// Get the known best header to compare against checkpoints.
	_, storeTip, err := headerStore.ChainTip()
	if err != nil {
		return 0, err
	}

	// Determine the maximum length of each peer's checkpoint list. If they
	// differ, we don't return yet because we want to make sure they match
	// up to the shortest one.
	maxLen := 0
	for _, checkpoints := range cp {
		if len(checkpoints) > maxLen {
			maxLen = len(checkpoints)
		}
	}

	// Compare the actual checkpoints against each other and anything
	// stored in the header store.
	for i := 0; i < maxLen; i++ {
		var checkpoint chainhash.Hash
		for _, checkpoints := range cp {
			if i >= len(checkpoints) {
				continue
			}
			if checkpoint == zeroHash {
				checkpoint = *checkpoints[i]
			}
			if checkpoint != *checkpoints[i] {
				log.Warnf("mismatch at %v, expected %v got "+
					"%v", i, checkpoint, checkpoints[i])
				return i, nil
			}
		}

		ckptHeight := uint32((i + 1) * wire.CFCheckptInterval)

		if ckptHeight <= storeTip {
			header, err := headerStore.FetchHeaderByHeight(
				ckptHeight,
			)
			if err != nil {
				return i, err
			}

			if *header != checkpoint {
				log.Warnf("mismatch at height %v, expected %v got "+
					"%v", ckptHeight, header, checkpoint)
				return i, nil
			}
		}
	}

	return -1, nil
}

// blockHandler is the main handler for the block manager.  It must be run as a
// goroutine.  It processes block and inv messages in a separate goroutine from
// the peer handlers so the block (MsgBlock) messages are handled by a single
// thread without needing to lock memory data structures.  This is important
// because the block manager controls which blocks are needed and how
// the fetching should proceed.
func (b *blockManager) blockHandler() {
	defer b.wg.Done()

	candidatePeers := list.New()
out:
	for {
		// Now check peer messages and quit channels.
		select {
		case m := <-b.peerChan:
			switch msg := m.(type) {
			case *newPeerMsg:
				b.handleNewPeerMsg(candidatePeers, msg.peer)

			case *invMsg:
				b.handleInvMsg(msg)

			case *headersMsg:
				b.handleHeadersMsg(msg)

			case *donePeerMsg:
				b.handleDonePeerMsg(candidatePeers, msg.peer)

			default:
				log.Warnf("Invalid message type in block "+
					"handler: %T", msg)
			}

		case <-b.quit:
			break out
		}
	}

	log.Trace("Block handler done")
}

// SyncPeer returns the current sync peer.
func (b *blockManager) SyncPeer() *ServerPeer {
	b.syncPeerMutex.Lock()
	defer b.syncPeerMutex.Unlock()

	return b.syncPeer
}

// isSyncCandidate returns whether or not the peer is a candidate to consider
// syncing from.
func (b *blockManager) isSyncCandidate(sp *ServerPeer) bool {
	// The peer is not a candidate for sync if it's not a full node.
	return sp.Services()&wire.SFNodeNetwork == wire.SFNodeNetwork
}

// findNextHeaderCheckpoint returns the next checkpoint after the passed height.
// It returns nil when there is not one either because the height is already
// later than the final checkpoint or there are none for the current network.
func (b *blockManager) findNextHeaderCheckpoint(height int32) *chaincfg.Checkpoint {
	// There is no next checkpoint if there are none for this current
	// network.
	checkpoints := b.cfg.ChainParams.Checkpoints
	if len(checkpoints) == 0 {
		return nil
	}

	// There is no next checkpoint if the height is already after the final
	// checkpoint.
	finalCheckpoint := &checkpoints[len(checkpoints)-1]
	if height >= finalCheckpoint.Height {
		return nil
	}

	// Find the next checkpoint.
	nextCheckpoint := finalCheckpoint
	for i := len(checkpoints) - 2; i >= 0; i-- {
		if height >= checkpoints[i].Height {
			break
		}
		nextCheckpoint = &checkpoints[i]
	}
	return nextCheckpoint
}

// findPreviousHeaderCheckpoint returns the last checkpoint before the passed
// height. It returns a checkpoint matching the genesis block when the height
// is earlier than the first checkpoint or there are no checkpoints for the
// current network. This is used for resetting state when a malicious peer
// sends us headers that don't lead up to a known checkpoint.
func (b *blockManager) findPreviousHeaderCheckpoint(height int32) *chaincfg.Checkpoint {
	// Start with the genesis block - earliest checkpoint to which our code
	// will want to reset
	prevCheckpoint := &chaincfg.Checkpoint{
		Height: 0,
		Hash:   b.cfg.ChainParams.GenesisHash,
	}

	// Find the latest checkpoint lower than height or return genesis block
	// if there are none.
	checkpoints := b.cfg.ChainParams.Checkpoints
	for i := 0; i < len(checkpoints); i++ {
		if height <= checkpoints[i].Height {
			break
		}
		prevCheckpoint = &checkpoints[i]
	}

	return prevCheckpoint
}

// startSync will choose the best peer among the available candidate peers to
// download/sync the blockchain from.  When syncing is already running, it
// simply returns.  It also examines the candidates for any which are no longer
// candidates and removes them as needed.
func (b *blockManager) startSync(peers *list.List) {
	// Return now if we're already syncing.
	if b.syncPeer != nil {
		return
	}

	_, bestHeight, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		log.Errorf("Failed to get hash and height for the "+
			"latest block: %s", err)
		return
	}

	var bestPeer *ServerPeer
	var enext *list.Element
	for e := peers.Front(); e != nil; e = enext {
		enext = e.Next()
		sp := e.Value.(*ServerPeer)

		// Remove sync candidate peers that are no longer candidates
		// due to passing their latest known block.
		//
		// NOTE: The < is intentional as opposed to <=.  While
		// techcnically the peer doesn't have a later block when it's
		// equal, it will likely have one soon so it is a reasonable
		// choice.  It also allows the case where both are at 0 such as
		// during regression test.
		if sp.LastBlock() < int32(bestHeight) {
			peers.Remove(e)
			continue
		}

		// TODO: Use a better algorithm to choose the best peer.
		// For now, just pick the candidate with the highest last block.
		if bestPeer == nil || sp.LastBlock() > bestPeer.LastBlock() {
			bestPeer = sp
		}
	}

	// Start syncing from the best peer if one was selected.
	if bestPeer != nil {
		locator, err := b.cfg.BlockHeaders.LatestBlockLocator()
		if err != nil {
			log.Errorf("Failed to get block locator for the "+
				"latest block: %s", err)
			return
		}

		log.Infof("Syncing to block height %d from peer %s",
			bestPeer.LastBlock(), bestPeer.Addr())

		// Now that we know we have a new sync peer, we'll lock it in
		// within the proper attribute.
		b.syncPeerMutex.Lock()
		b.syncPeer = bestPeer
		b.syncPeerMutex.Unlock()

		// By default will use the zero hash as our stop hash to query
		// for all the headers beyond our view of the network based on
		// our latest block locator.
		stopHash := &zeroHash

		// If we're still within the range of the set checkpoints, then
		// we'll use the next checkpoint to guide the set of headers we
		// fetch, setting our stop hash to the next checkpoint hash.
		if b.nextCheckpoint != nil && int32(bestHeight) < b.nextCheckpoint.Height {
			log.Infof("Downloading headers for blocks %d to "+
				"%d from peer %s", bestHeight+1,
				b.nextCheckpoint.Height, bestPeer.Addr())

			stopHash = b.nextCheckpoint.Hash
		} else {
			log.Infof("Fetching set of headers from tip "+
				"(height=%v) from peer %s", bestHeight,
				bestPeer.Addr())
		}

		// With our stop hash selected, we'll kick off the sync from
		// this peer with an initial GetHeaders message.
		b.SyncPeer().PushGetHeadersMsg(locator, stopHash)
	} else {
		log.Warnf("No sync peer candidates available")
	}
}

// IsFullySynced returns whether or not the block manager believed it is fully
// synced to the connected peers, meaning both block headers and filter headers
// are current.
func (b *blockManager) IsFullySynced() bool {
	_, blockHeaderHeight, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		return false
	}

	_, filterHeaderHeight, err := b.cfg.RegFilterHeaders.ChainTip()
	if err != nil {
		return false
	}

	// If the block headers and filter headers are not at the same height,
	// we cannot be fully synced.
	if blockHeaderHeight != filterHeaderHeight {
		return false
	}

	// Block and filter headers being at the same height, return whether
	// our block headers are synced.
	return b.BlockHeadersSynced()
}

// BlockHeadersSynced returns whether or not the block manager believes its
// block headers are synced with the connected peers.
func (b *blockManager) BlockHeadersSynced() bool {
	b.syncPeerMutex.RLock()
	defer b.syncPeerMutex.RUnlock()

	// Figure out the latest block we know.
	header, height, err := b.cfg.BlockHeaders.ChainTip()
	if err != nil {
		return false
	}

	// There is no last checkpoint if checkpoints are disabled or there are
	// none for this current network.
	checkpoints := b.cfg.ChainParams.Checkpoints
	if len(checkpoints) != 0 {
		// We aren't current if the newest block we know of isn't ahead
		// of all checkpoints.
		if checkpoints[len(checkpoints)-1].Height >= int32(height) {
			return false
		}
	}

	// If we have a syncPeer and are below the block we are syncing to, we
	// are not current.
	if b.syncPeer != nil && int32(height) < b.syncPeer.LastBlock() {
		return false
	}

	// If our time source (median times of all the connected peers) is at
	// least 24 hours ahead of our best known block, we aren't current.
	minus24Hours := b.cfg.TimeSource.AdjustedTime().Add(-24 * time.Hour)
	if header.Timestamp.Before(minus24Hours) {
		return false
	}

	// If we have no sync peer, we can assume we're current for now.
	if b.syncPeer == nil {
		return true
	}

	// If we have a syncPeer and the peer reported a higher known block
	// height on connect than we know the peer already has, we're probably
	// not current. If the peer is lying to us, other code will disconnect
	// it and then we'll re-check and notice that we're actually current.
	return b.syncPeer.LastBlock() >= b.syncPeer.StartingHeight()
}

// QueueInv adds the passed inv message and peer to the block handling queue.
func (b *blockManager) QueueInv(inv *wire.MsgInv, sp *ServerPeer) {
	// No channel handling here because peers do not need to block on inv
	// messages.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	select {
	case b.peerChan <- &invMsg{inv: inv, peer: sp}:
	case <-b.quit:
		return
	}
}

// handleInvMsg handles inv messages from all peers.
// We examine the inventory advertised by the remote peer and act accordingly.
func (b *blockManager) handleInvMsg(imsg *invMsg) {
	// Attempt to find the final block in the inventory list.  There may
	// not be one.
	lastBlock := -1
	invVects := imsg.inv.InvList
	for i := len(invVects) - 1; i >= 0; i-- {
		if invVects[i].Type == wire.InvTypeBlock {
			lastBlock = i
			break
		}
	}

	// If this inv contains a block announcement, and this isn't coming from
	// our current sync peer or we're current, then update the last
	// announced block for this peer. We'll use this information later to
	// update the heights of peers based on blocks we've accepted that they
	// previously announced.
	if lastBlock != -1 && (imsg.peer != b.SyncPeer() || b.BlockHeadersSynced()) {
		imsg.peer.UpdateLastAnnouncedBlock(&invVects[lastBlock].Hash)
	}

	// Ignore invs from peers that aren't the sync if we are not current.
	// Helps prevent dealing with orphans.
	if imsg.peer != b.SyncPeer() && !b.BlockHeadersSynced() {
		return
	}

	// If our chain is current and a peer announces a block we already
	// know of, then update their current block height.
	if lastBlock != -1 && b.BlockHeadersSynced() {
		height, err := b.cfg.BlockHeaders.HeightFromHash(&invVects[lastBlock].Hash)
		if err == nil {
			imsg.peer.UpdateLastBlockHeight(int32(height))
		}
	}

	// Add blocks to the cache of known inventory for the peer.
	for _, iv := range invVects {
		if iv.Type == wire.InvTypeBlock {
			imsg.peer.AddKnownInventory(iv)
		}
	}

	// If this is the sync peer or we're current, get the headers for the
	// announced blocks and update the last announced block.
	if lastBlock != -1 && (imsg.peer == b.SyncPeer() || b.BlockHeadersSynced()) {
		lastEl := b.headerList.Back()
		var lastHash chainhash.Hash
		if lastEl != nil {
			lastHash = lastEl.Header.BlockHash()
		}

		// Only send getheaders if we don't already know about the last
		// block hash being announced.
		if lastHash != invVects[lastBlock].Hash && lastEl != nil &&
			b.lastRequested != invVects[lastBlock].Hash {

			// Make a locator starting from the latest known header
			// we've processed.
			locator := make(blockchain.BlockLocator, 0,
				wire.MaxBlockLocatorsPerMsg)
			locator = append(locator, &lastHash)

			// Add locator from the database as backup.
			knownLocator, err := b.cfg.BlockHeaders.LatestBlockLocator()
			if err == nil {
				locator = append(locator, knownLocator...)
			}

			// Get headers based on locator.
			err = imsg.peer.PushGetHeadersMsg(locator,
				&invVects[lastBlock].Hash)
			if err != nil {
				log.Warnf("Failed to send getheaders message "+
					"to peer %s: %s", imsg.peer.Addr(), err)
				return
			}
			b.lastRequested = invVects[lastBlock].Hash
		}
	}
}

// QueueHeaders adds the passed headers message and peer to the block handling
// queue.
func (b *blockManager) QueueHeaders(headers *wire.MsgHeaders, sp *ServerPeer) {
	// No channel handling here because peers do not need to block on
	// headers messages.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	select {
	case b.peerChan <- &headersMsg{headers: headers, peer: sp}:
	case <-b.quit:
		return
	}
}

// handleHeadersMsg handles headers messages from all peers.
func (b *blockManager) handleHeadersMsg(hmsg *headersMsg) {
	msg := hmsg.headers
	numHeaders := len(msg.Headers)

	// Nothing to do for an empty headers message.
	if numHeaders == 0 {
		return
	}

	// For checking to make sure blocks aren't too far in the future as of
	// the time we receive the headers message.
	maxTimestamp := b.cfg.TimeSource.AdjustedTime().
		Add(maxTimeOffset)

	// We'll attempt to write the entire batch of validated headers
	// atomically in order to improve peformance.
	headerWriteBatch := make([]headerfs.BlockHeader, 0, len(msg.Headers))

	// Process all of the received headers ensuring each one connects to
	// the previous and that checkpoints match.
	receivedCheckpoint := false
	var (
		finalHash   *chainhash.Hash
		finalHeight int32
	)
	for i, blockHeader := range msg.Headers {
		blockHash := blockHeader.BlockHash()
		finalHash = &blockHash

		// Ensure there is a previous header to compare against.
		prevNodeEl := b.headerList.Back()
		if prevNodeEl == nil {
			log.Warnf("Header list does not contain a previous" +
				"element as expected -- disconnecting peer")
			hmsg.peer.Disconnect()
			return
		}

		// Ensure the header properly connects to the previous one,
		// that the proof of work is good, and that the header's
		// timestamp isn't too far in the future, and add it to the
		// list of headers.
		node := headerlist.Node{Header: *blockHeader}
		prevNode := prevNodeEl
		prevHash := prevNode.Header.BlockHash()
		if prevHash.IsEqual(&blockHeader.PrevBlock) {
			err := b.checkHeaderSanity(blockHeader, maxTimestamp,
				false)
			if err != nil {
				log.Warnf("Header doesn't pass sanity check: "+
					"%s -- disconnecting peer", err)
				hmsg.peer.Disconnect()
				return
			}

			node.Height = prevNode.Height + 1
			finalHeight = node.Height

			// This header checks out, so we'll add it to our write
			// batch.
			headerWriteBatch = append(headerWriteBatch, headerfs.BlockHeader{
				BlockHeader: blockHeader,
				Height:      uint32(node.Height),
			})

			hmsg.peer.UpdateLastBlockHeight(node.Height)

			b.blkHeaderProgressLogger.LogBlockHeight(
				blockHeader.Timestamp, node.Height,
			)

			// Finally initialize the header ->
			// map[filterHash]*peer map for filter header
			// validation purposes later.
			e := b.headerList.PushBack(node)
			if b.startHeader == nil {
				b.startHeader = e
			}
		} else {
			// The block doesn't connect to the last block we know.
			// We will need to do some additional checks to process
			// possible reorganizations or incorrect chain on
			// either our or the peer's side.
			//
			// If we got these headers from a peer that's not our
			// sync peer, they might not be aligned correctly or
			// even on the right chain. Just ignore the rest of the
			// message. However, if we're current, this might be a
			// reorg, in which case we'll either change our sync
			// peer or disconnect the peer that sent us these bad
			// headers.
			if hmsg.peer != b.SyncPeer() && !b.BlockHeadersSynced() {
				return
			}

			// Check if this is the last block we know of. This is
			// a shortcut for sendheaders so that each redundant
			// header doesn't cause a disk read.
			if blockHash == prevHash {
				continue
			}

			// Check if this block is known. If so, we continue to
			// the next one.
			_, _, err := b.cfg.BlockHeaders.FetchHeader(&blockHash)
			if err == nil {
				continue
			}

			// Check if the previous block is known. If it is, this
			// is probably a reorg based on the estimated latest
			// block that matches between us and the peer as
			// derived from the block locator we sent to request
			// these headers. Otherwise, the headers don't connect
			// to anything we know and we should disconnect the
			// peer.
			backHead, backHeight, err := b.cfg.BlockHeaders.FetchHeader(
				&blockHeader.PrevBlock,
			)
			if err != nil {
				log.Warnf("Received block header that does not"+
					" properly connect to the chain from"+
					" peer %s (%s) -- disconnecting",
					hmsg.peer.Addr(), err)
				hmsg.peer.Disconnect()
				return
			}

			// We've found a branch we weren't aware of. If the
			// branch is earlier than the latest synchronized
			// checkpoint, it's invalid and we need to disconnect
			// the reporting peer.
			prevCheckpoint := b.findPreviousHeaderCheckpoint(
				prevNode.Height,
			)
			if backHeight < uint32(prevCheckpoint.Height) {
				log.Errorf("Attempt at a reorg earlier than a "+
					"checkpoint past which we've already "+
					"synchronized -- disconnecting peer "+
					"%s", hmsg.peer.Addr())
				hmsg.peer.Disconnect()
				return
			}

			// Check the sanity of the new branch. If any of the
			// blocks don't pass sanity checks, disconnect the
			// peer.  We also keep track of the work represented by
			// these headers so we can compare it to the work in
			// the known good chain.
			b.reorgList.ResetHeaderState(headerlist.Node{
				Header: *backHead,
				Height: int32(backHeight),
			})
			totalWork := big.NewInt(0)
			for j, reorgHeader := range msg.Headers[i:] {
				err = b.checkHeaderSanity(reorgHeader,
					maxTimestamp, true)
				if err != nil {
					log.Warnf("Header doesn't pass sanity"+
						" check: %s -- disconnecting "+
						"peer", err)
					hmsg.peer.Disconnect()
					return
				}
				totalWork.Add(totalWork,
					blockchain.CalcWork(reorgHeader.Bits))
				b.reorgList.PushBack(headerlist.Node{
					Header: *reorgHeader,
					Height: int32(backHeight+1) + int32(j),
				})
			}
			log.Tracef("Sane reorg attempted. Total work from "+
				"reorg chain: %v", totalWork)

			// All the headers pass sanity checks. Now we calculate
			// the total work for the known chain.
			knownWork := big.NewInt(0)

			// This should NEVER be nil because the most recent
			// block is always pushed back by resetHeaderState
			knownEl := b.headerList.Back()
			var knownHead *wire.BlockHeader
			for j := uint32(prevNode.Height); j > backHeight; j-- {
				if knownEl != nil {
					knownHead = &knownEl.Header
					knownEl = knownEl.Prev()
				} else {
					knownHead, _, err = b.cfg.BlockHeaders.FetchHeader(
						&knownHead.PrevBlock)
					if err != nil {
						log.Criticalf("Can't get block"+
							"header for hash %s: "+
							"%v",
							knownHead.PrevBlock,
							err)
						// Should we panic here?
					}
				}
				knownWork.Add(knownWork,
					blockchain.CalcWork(knownHead.Bits))
			}

			log.Tracef("Total work from known chain: %v", knownWork)

			// Compare the two work totals and reject the new chain
			// if it doesn't have more work than the previously
			// known chain. Disconnect if it's actually less than
			// the known chain.
			switch knownWork.Cmp(totalWork) {
			case 1:
				log.Warnf("Reorg attempt that has less work "+
					"than known chain from peer %s -- "+
					"disconnecting", hmsg.peer.Addr())
				hmsg.peer.Disconnect()
				fallthrough
			case 0:
				return
			default:
			}

			// At this point, we have a valid reorg, so we roll
			// back the existing chain and add the new block
			// header.  We also change the sync peer. Then we can
			// continue with the rest of the headers in the message
			// as if nothing has happened.
			b.syncPeerMutex.Lock()
			b.syncPeer = hmsg.peer
			b.syncPeerMutex.Unlock()
			_, err = b.rollBackToHeight(backHeight)
			if err != nil {
				panic(fmt.Sprintf("Rollback failed: %s", err))
				// Should we panic here?
			}

			hdrs := headerfs.BlockHeader{
				BlockHeader: blockHeader,
				Height:      backHeight + 1,
			}
			err = b.cfg.BlockHeaders.WriteHeaders(hdrs)
			if err != nil {
				log.Criticalf("Couldn't write block to "+
					"database: %s", err)
				// Should we panic here?
			}

			b.headerList.ResetHeaderState(headerlist.Node{
				Header: *backHead,
				Height: int32(backHeight),
			})
			b.headerList.PushBack(headerlist.Node{
				Header: *blockHeader,
				Height: int32(backHeight + 1),
			})
		}

		// Verify the header at the next checkpoint height matches.
		if b.nextCheckpoint != nil && node.Height == b.nextCheckpoint.Height {
			nodeHash := node.Header.BlockHash()
			if nodeHash.IsEqual(b.nextCheckpoint.Hash) {
				receivedCheckpoint = true
				log.Infof("Verified downloaded block "+
					"header against checkpoint at height "+
					"%d/hash %s", node.Height, nodeHash)
			} else {
				log.Warnf("Block header at height %d/hash "+
					"%s from peer %s does NOT match "+
					"expected checkpoint hash of %s -- "+
					"disconnecting", node.Height,
					nodeHash, hmsg.peer.Addr(),
					b.nextCheckpoint.Hash)

				prevCheckpoint := b.findPreviousHeaderCheckpoint(
					node.Height,
				)

				log.Infof("Rolling back to previous validated "+
					"checkpoint at height %d/hash %s",
					prevCheckpoint.Height,
					prevCheckpoint.Hash)

				_, err := b.rollBackToHeight(uint32(
					prevCheckpoint.Height),
				)
				if err != nil {
					log.Criticalf("Rollback failed: %s",
						err)
					// Should we panic here?
				}

				hmsg.peer.Disconnect()
				return
			}
			break
		}
	}

	log.Tracef("Writing header batch of %v block headers",
		len(headerWriteBatch))

	if len(headerWriteBatch) > 0 {
		// With all the headers in this batch validated, we'll write
		// them all in a single transaction such that this entire batch
		// is atomic.
		err := b.cfg.BlockHeaders.WriteHeaders(headerWriteBatch...)
		if err != nil {
			log.Errorf("Unable to write block headers: %v", err)
			return
		}
	}

	// When this header is a checkpoint, find the next checkpoint.
	if receivedCheckpoint {
		b.nextCheckpoint = b.findNextHeaderCheckpoint(finalHeight)
	}

	// If not current, request the next batch of headers starting from the
	// latest known header and ending with the next checkpoint.
	if b.cfg.ChainParams.Net == chaincfg.SimNetParams.Net || !b.BlockHeadersSynced() {
		locator := blockchain.BlockLocator([]*chainhash.Hash{finalHash})
		nextHash := zeroHash
		if b.nextCheckpoint != nil {
			nextHash = *b.nextCheckpoint.Hash
		}
		err := hmsg.peer.PushGetHeadersMsg(locator, &nextHash)
		if err != nil {
			log.Warnf("Failed to send getheaders message to "+
				"peer %s: %s", hmsg.peer.Addr(), err)
			return
		}
	}

	// Since we have a new set of headers written to disk, we'll send out a
	// new signal to notify any waiting sub-systems that they can now maybe
	// proceed do to us extending the header chain.
	b.newHeadersMtx.Lock()
	b.headerTip = uint32(finalHeight)
	b.headerTipHash = *finalHash
	b.newHeadersMtx.Unlock()
	b.newHeadersSignal.Broadcast()
}

// checkHeaderSanity checks the PoW, and timestamp of a block header.
func (b *blockManager) checkHeaderSanity(blockHeader *wire.BlockHeader,
	maxTimestamp time.Time, reorgAttempt bool) error {
	diff, err := b.calcNextRequiredDifficulty(
		blockHeader.Timestamp, reorgAttempt)
	if err != nil {
		return err
	}
	stubBlock := btcutil.NewBlock(&wire.MsgBlock{
		Header: *blockHeader,
	})
	err = blockchain.CheckProofOfWork(stubBlock,
		blockchain.CompactToBig(diff))
	if err != nil {
		return err
	}
	// Ensure the block time is not too far in the future.
	if blockHeader.Timestamp.After(maxTimestamp) {
		return fmt.Errorf("block timestamp of %v is too far in the "+
			"future", blockHeader.Timestamp)
	}
	return nil
}

// calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous block node based on the difficulty retarget rules.
func (b *blockManager) calcNextRequiredDifficulty(newBlockTime time.Time,
	reorgAttempt bool) (uint32, error) {

	hList := b.headerList
	if reorgAttempt {
		hList = b.reorgList
	}

	lastNode := hList.Back()

	// Genesis block.
	if lastNode == nil {
		return b.cfg.ChainParams.PowLimitBits, nil
	}

	// Return the previous block's difficulty requirements if this block
	// is not at a difficulty retarget interval.
	if (lastNode.Height+1)%b.blocksPerRetarget != 0 {
		// For networks that support it, allow special reduction of the
		// required difficulty once too much time has elapsed without
		// mining a block.
		if b.cfg.ChainParams.ReduceMinDifficulty {
			// Return minimum difficulty when more than the desired
			// amount of time has elapsed without mining a block.
			reductionTime := int64(
				b.cfg.ChainParams.MinDiffReductionTime /
					time.Second)
			allowMinTime := lastNode.Header.Timestamp.Unix() +
				reductionTime
			if newBlockTime.Unix() > allowMinTime {
				return b.cfg.ChainParams.PowLimitBits, nil
			}

			// The block was mined within the desired timeframe, so
			// return the difficulty for the last block which did
			// not have the special minimum difficulty rule applied.
			prevBits, err := b.findPrevTestNetDifficulty(hList)
			if err != nil {
				return 0, err
			}
			return prevBits, nil
		}

		// For the main network (or any unrecognized networks), simply
		// return the previous block's difficulty requirements.
		return lastNode.Header.Bits, nil
	}

	// Get the block node at the previous retarget (targetTimespan days
	// worth of blocks).
	firstNode, err := b.cfg.BlockHeaders.FetchHeaderByHeight(
		uint32(lastNode.Height + 1 - b.blocksPerRetarget),
	)
	if err != nil {
		return 0, err
	}

	// Limit the amount of adjustment that can occur to the previous
	// difficulty.
	actualTimespan := lastNode.Header.Timestamp.Unix() -
		firstNode.Timestamp.Unix()
	adjustedTimespan := actualTimespan
	if actualTimespan < b.minRetargetTimespan {
		adjustedTimespan = b.minRetargetTimespan
	} else if actualTimespan > b.maxRetargetTimespan {
		adjustedTimespan = b.maxRetargetTimespan
	}

	// Calculate new target difficulty as:
	//  currentDifficulty * (adjustedTimespan / targetTimespan)
	// The result uses integer division which means it will be slightly
	// rounded down.  Bitcoind also uses integer division to calculate this
	// result.
	oldTarget := blockchain.CompactToBig(lastNode.Header.Bits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(adjustedTimespan))
	targetTimeSpan := int64(b.cfg.ChainParams.TargetTimespan /
		time.Second)
	newTarget.Div(newTarget, big.NewInt(targetTimeSpan))

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(b.cfg.ChainParams.PowLimit) > 0 {
		newTarget.Set(b.cfg.ChainParams.PowLimit)
	}

	// Log new target difficulty and return it.  The new target logging is
	// intentionally converting the bits back to a number instead of using
	// newTarget since conversion to the compact representation loses
	// precision.
	newTargetBits := blockchain.BigToCompact(newTarget)
	log.Debugf("Difficulty retarget at block height %d", lastNode.Height+1)
	log.Debugf("Old target %08x (%064x)", lastNode.Header.Bits, oldTarget)
	log.Debugf("New target %08x (%064x)", newTargetBits,
		blockchain.CompactToBig(newTargetBits))
	log.Debugf("Actual timespan %v, adjusted timespan %v, target timespan %v",
		time.Duration(actualTimespan)*time.Second,
		time.Duration(adjustedTimespan)*time.Second,
		b.cfg.ChainParams.TargetTimespan)

	return newTargetBits, nil
}

// findPrevTestNetDifficulty returns the difficulty of the previous block which
// did not have the special testnet minimum difficulty rule applied.
func (b *blockManager) findPrevTestNetDifficulty(hList headerlist.Chain) (uint32, error) {
	startNode := hList.Back()

	// Genesis block.
	if startNode == nil {
		return b.cfg.ChainParams.PowLimitBits, nil
	}

	// Search backwards through the chain for the last block without
	// the special rule applied.
	iterEl := startNode
	iterNode := &startNode.Header
	iterHeight := startNode.Height
	for iterNode != nil && iterHeight%b.blocksPerRetarget != 0 &&
		iterNode.Bits == b.cfg.ChainParams.PowLimitBits {

		// Get the previous block node.  This function is used over
		// simply accessing iterNode.parent directly as it will
		// dynamically create previous block nodes as needed.  This
		// helps allow only the pieces of the chain that are needed
		// to remain in memory.
		iterHeight--
		el := iterEl.Prev()
		if el != nil {
			iterNode = &el.Header
		} else {
			node, err := b.cfg.BlockHeaders.FetchHeaderByHeight(
				uint32(iterHeight),
			)
			if err != nil {
				log.Errorf("GetBlockByHeight: %s", err)
				return 0, err
			}
			iterNode = node
		}
	}

	// Return the found difficulty or the minimum difficulty if no
	// appropriate block was found.
	lastBits := b.cfg.ChainParams.PowLimitBits
	if iterNode != nil {
		lastBits = iterNode.Bits
	}
	return lastBits, nil
}

// onBlockConnected queues a block notification that extends the current chain.
func (b *blockManager) onBlockConnected(header wire.BlockHeader, height uint32) {
	select {
	case b.blockNtfnChan <- blockntfns.NewBlockConnected(header, height):
	case <-b.quit:
	}
}

// onBlockDisconnected queues a block notification that reorgs the current
// chain.
func (b *blockManager) onBlockDisconnected(headerDisconnected wire.BlockHeader,
	heightDisconnected uint32, newChainTip wire.BlockHeader) {

	select {
	case b.blockNtfnChan <- blockntfns.NewBlockDisconnected(
		headerDisconnected, heightDisconnected, newChainTip,
	):
	case <-b.quit:
	}
}

// Notifications exposes a receive-only channel in which the latest block
// notifications for the tip of the chain can be received.
func (b *blockManager) Notifications() <-chan blockntfns.BlockNtfn {
	return b.blockNtfnChan
}

// NotificationsSinceHeight returns a backlog of block notifications starting
// from the given height to the tip of the chain. When providing a height of 0,
// a backlog will not be delivered.
func (b *blockManager) NotificationsSinceHeight(
	height uint32) ([]blockntfns.BlockNtfn, uint32, error) {

	b.newFilterHeadersMtx.RLock()
	bestHeight := b.filterHeaderTip
	b.newFilterHeadersMtx.RUnlock()

	// If a height of 0 is provided by the caller, then a backlog of
	// notifications is not needed.
	if height == 0 {
		return nil, bestHeight, nil
	}

	// If the best height matches the filter header tip, then we're done and
	// don't need to proceed any further.
	if bestHeight == height {
		return nil, bestHeight, nil
	}

	// If the request has a height later than a height we've yet to come
	// across in the chain, we'll return an error to indicate so to the
	// caller.
	if height > bestHeight {
		return nil, 0, fmt.Errorf("request with height %d is greater "+
			"than best height known %d", height, bestHeight)
	}

	// Otherwise, we need to read block headers from disk to deliver a
	// backlog to the caller before we proceed.
	blocks := make([]blockntfns.BlockNtfn, 0, bestHeight-height)
	for i := height + 1; i <= bestHeight; i++ {
		header, err := b.cfg.BlockHeaders.FetchHeaderByHeight(i)
		if err != nil {
			return nil, 0, err
		}

		blocks = append(blocks, blockntfns.NewBlockConnected(*header, i))
	}

	return blocks, bestHeight, nil
}
