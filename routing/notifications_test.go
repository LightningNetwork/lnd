package routing

import (
	"bytes"
	"fmt"
	"image/color"
	"net"
	"sync"
	"testing"
	"time"

	prand "math/rand"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/chainview"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

var (
	testAddr = &net.TCPAddr{IP: (net.IP)([]byte{0xA, 0x0, 0x0, 0x1}),
		Port: 9000}
	testAddrs = []net.Addr{testAddr}

	testFeatures = lnwire.NewFeatureVector(nil, lnwire.Features)

	testHash = [32]byte{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x88, 0xa3, 0xef, 0xb9,
		0x6a, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	testTime = time.Date(2018, time.January, 9, 14, 00, 00, 0, time.UTC)

	priv1, _    = btcec.NewPrivateKey(btcec.S256())
	bitcoinKey1 = priv1.PubKey()

	priv2, _    = btcec.NewPrivateKey(btcec.S256())
	bitcoinKey2 = priv2.PubKey()
)

func createTestNode() (*channeldb.LightningNode, error) {
	updateTime := prand.Int63()

	priv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, errors.Errorf("unable create private key: %v", err)
	}

	pub := priv.PubKey().SerializeCompressed()
	n := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           time.Unix(updateTime, 0),
		Addresses:            testAddrs,
		Color:                color.RGBA{1, 2, 3, 0},
		Alias:                "kek" + string(pub[:]),
		AuthSigBytes:         testSig.Serialize(),
		Features:             testFeatures,
	}
	copy(n.PubKeyBytes[:], pub)

	return n, nil
}

func randEdgePolicy(chanID *lnwire.ShortChannelID,
	node *channeldb.LightningNode) *channeldb.ChannelEdgePolicy {

	return &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 chanID.ToUint64(),
		LastUpdate:                time.Unix(int64(prand.Int31()), 0),
		TimeLockDelta:             uint16(prand.Int63()),
		MinHTLC:                   lnwire.MilliSatoshi(prand.Int31()),
		MaxHTLC:                   lnwire.MilliSatoshi(prand.Int31()),
		FeeBaseMSat:               lnwire.MilliSatoshi(prand.Int31()),
		FeeProportionalMillionths: lnwire.MilliSatoshi(prand.Int31()),
		Node:                      node,
	}
}

func createChannelEdge(ctx *testCtx, bitcoinKey1, bitcoinKey2 []byte,
	chanValue btcutil.Amount, fundingHeight uint32) (*wire.MsgTx, *wire.OutPoint,
	*lnwire.ShortChannelID, error) {

	fundingTx := wire.NewMsgTx(2)
	_, tx, err := input.GenFundingPkScript(
		bitcoinKey1,
		bitcoinKey2,
		int64(chanValue),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	fundingTx.TxOut = append(fundingTx.TxOut, tx)
	chanUtxo := wire.OutPoint{
		Hash:  fundingTx.TxHash(),
		Index: 0,
	}

	// With the utxo constructed, we'll mark it as closed.
	ctx.chain.addUtxo(chanUtxo, tx)

	// Our fake channel will be "confirmed" at height 101.
	chanID := &lnwire.ShortChannelID{
		BlockHeight: fundingHeight,
		TxIndex:     0,
		TxPosition:  0,
	}

	return fundingTx, &chanUtxo, chanID, nil
}

type mockChain struct {
	blocks     map[chainhash.Hash]*wire.MsgBlock
	blockIndex map[uint32]chainhash.Hash

	utxos map[wire.OutPoint]wire.TxOut

	bestHeight int32

	sync.RWMutex
}

// A compile time check to ensure mockChain implements the
// lnwallet.BlockChainIO interface.
var _ lnwallet.BlockChainIO = (*mockChain)(nil)

func newMockChain(currentHeight uint32) *mockChain {
	return &mockChain{
		bestHeight: int32(currentHeight),
		blocks:     make(map[chainhash.Hash]*wire.MsgBlock),
		utxos:      make(map[wire.OutPoint]wire.TxOut),
		blockIndex: make(map[uint32]chainhash.Hash),
	}
}

func (m *mockChain) setBestBlock(height int32) {
	m.Lock()
	defer m.Unlock()

	m.bestHeight = height
}

func (m *mockChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	m.RLock()
	defer m.RUnlock()

	blockHash := m.blockIndex[uint32(m.bestHeight)]

	return &blockHash, m.bestHeight, nil
}

func (m *mockChain) GetTransaction(txid *chainhash.Hash) (*wire.MsgTx, error) {
	return nil, nil
}

func (m *mockChain) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	m.RLock()
	defer m.RUnlock()

	hash, ok := m.blockIndex[uint32(blockHeight)]
	if !ok {
		return nil, fmt.Errorf("block number out of range: %v",
			blockHeight)
	}

	return &hash, nil
}

func (m *mockChain) addUtxo(op wire.OutPoint, out *wire.TxOut) {
	m.Lock()
	m.utxos[op] = *out
	m.Unlock()
}

func (m *mockChain) delUtxo(op wire.OutPoint) {
	m.Lock()
	delete(m.utxos, op)
	m.Unlock()
}

func (m *mockChain) GetUtxo(op *wire.OutPoint, _ []byte, _ uint32,
	_ <-chan struct{}) (*wire.TxOut, error) {
	m.RLock()
	defer m.RUnlock()

	utxo, ok := m.utxos[*op]
	if !ok {
		return nil, btcwallet.ErrOutputSpent
	}

	return &utxo, nil
}

func (m *mockChain) addBlock(block *wire.MsgBlock, height uint32, nonce uint32) {
	m.Lock()
	block.Header.Nonce = nonce
	hash := block.Header.BlockHash()
	m.blocks[hash] = block
	m.blockIndex[height] = hash
	m.Unlock()
}

func (m *mockChain) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	m.RLock()
	defer m.RUnlock()

	block, ok := m.blocks[*blockHash]
	if !ok {
		return nil, fmt.Errorf("block not found")
	}

	return block, nil
}

type mockChainView struct {
	sync.RWMutex

	newBlocks   chan *chainview.FilteredBlock
	staleBlocks chan *chainview.FilteredBlock

	chain lnwallet.BlockChainIO

	filter map[wire.OutPoint]struct{}

	quit chan struct{}
}

// A compile time check to ensure mockChainView implements the
// chainview.FilteredChainView.
var _ chainview.FilteredChainView = (*mockChainView)(nil)

func newMockChainView(chain lnwallet.BlockChainIO) *mockChainView {
	return &mockChainView{
		chain:       chain,
		newBlocks:   make(chan *chainview.FilteredBlock, 10),
		staleBlocks: make(chan *chainview.FilteredBlock, 10),
		filter:      make(map[wire.OutPoint]struct{}),
		quit:        make(chan struct{}),
	}
}

func (m *mockChainView) Reset() {
	m.filter = make(map[wire.OutPoint]struct{})
	m.quit = make(chan struct{})
	m.newBlocks = make(chan *chainview.FilteredBlock, 10)
	m.staleBlocks = make(chan *chainview.FilteredBlock, 10)
}

func (m *mockChainView) UpdateFilter(ops []channeldb.EdgePoint, updateHeight uint32) error {
	m.Lock()
	defer m.Unlock()

	for _, op := range ops {
		m.filter[op.OutPoint] = struct{}{}
	}

	return nil
}

func (m *mockChainView) notifyBlock(hash chainhash.Hash, height uint32,
	txns []*wire.MsgTx) {

	m.RLock()
	defer m.RUnlock()

	select {
	case m.newBlocks <- &chainview.FilteredBlock{
		Hash:         hash,
		Height:       height,
		Transactions: txns,
	}:
	case <-m.quit:
		return
	}
}

func (m *mockChainView) notifyStaleBlock(hash chainhash.Hash, height uint32,
	txns []*wire.MsgTx) {

	m.RLock()
	defer m.RUnlock()

	select {
	case m.staleBlocks <- &chainview.FilteredBlock{
		Hash:         hash,
		Height:       height,
		Transactions: txns,
	}:
	case <-m.quit:
		return
	}
}

func (m *mockChainView) FilteredBlocks() <-chan *chainview.FilteredBlock {
	return m.newBlocks
}

func (m *mockChainView) DisconnectedBlocks() <-chan *chainview.FilteredBlock {
	return m.staleBlocks
}

func (m *mockChainView) FilterBlock(blockHash *chainhash.Hash) (*chainview.FilteredBlock, error) {

	block, err := m.chain.GetBlock(blockHash)
	if err != nil {
		return nil, err
	}

	filteredBlock := &chainview.FilteredBlock{
		Hash: *blockHash,
	}
	for _, tx := range block.Transactions {
		for _, txIn := range tx.TxIn {
			prevOp := txIn.PreviousOutPoint
			if _, ok := m.filter[prevOp]; ok {
				filteredBlock.Transactions = append(
					filteredBlock.Transactions, tx,
				)

				m.Lock()
				delete(m.filter, prevOp)
				m.Unlock()

				break
			}
		}
	}

	return filteredBlock, nil
}

func (m *mockChainView) Start() error {
	return nil
}

func (m *mockChainView) Stop() error {
	close(m.quit)
	return nil
}

// TestEdgeUpdateNotification tests that when edges are updated or added,
// a proper notification is sent of to all registered clients.
func TestEdgeUpdateNotification(t *testing.T) {
	t.Parallel()

	ctx, cleanUp := createTestCtxSingleNode(t, 0)
	defer cleanUp()

	// First we'll create the utxo for the channel to be "closed"
	const chanValue = 10000
	fundingTx, chanPoint, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(), bitcoinKey2.SerializeCompressed(),
		chanValue, 0)
	if err != nil {
		t.Fatalf("unable create channel edge: %v", err)
	}

	// We'll also add a record for the block that included our funding
	// transaction.
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	// Next we'll create two test nodes that the fake channel will be open
	// between.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}

	// Finally, to conclude our test set up, we'll create a channel
	// update to announce the created channel between the two nodes.
	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// With the channel edge now in place, we'll subscribe for topology
	// notifications.
	ntfnClient, err := ctx.router.SubscribeTopology()
	if err != nil {
		t.Fatalf("unable to subscribe for channel notifications: %v", err)
	}

	// Create random policy edges that are stemmed to the channel id
	// created above.
	edge1 := randEdgePolicy(chanID, node1)
	edge1.ChannelFlags = 0
	edge2 := randEdgePolicy(chanID, node2)
	edge2.ChannelFlags = 1

	if err := ctx.router.UpdateEdge(edge1); err != nil {
		t.Fatalf("unable to add edge update: %v", err)
	}
	if err := ctx.router.UpdateEdge(edge2); err != nil {
		t.Fatalf("unable to add edge update: %v", err)
	}

	assertEdgeCorrect := func(t *testing.T, edgeUpdate *ChannelEdgeUpdate,
		edgeAnn *channeldb.ChannelEdgePolicy) {
		if edgeUpdate.ChanID != edgeAnn.ChannelID {
			t.Fatalf("channel ID of edge doesn't match: "+
				"expected %v, got %v", chanID.ToUint64(), edgeUpdate.ChanID)
		}
		if edgeUpdate.ChanPoint != *chanPoint {
			t.Fatalf("channel don't match: expected %v, got %v",
				chanPoint, edgeUpdate.ChanPoint)
		}
		// TODO(roasbeef): this is a hack, needs to be removed
		// after commitment fees are dynamic.
		if edgeUpdate.Capacity != chanValue {
			t.Fatalf("capacity of edge doesn't match: "+
				"expected %v, got %v", chanValue, edgeUpdate.Capacity)
		}
		if edgeUpdate.MinHTLC != edgeAnn.MinHTLC {
			t.Fatalf("min HTLC of edge doesn't match: "+
				"expected %v, got %v", edgeAnn.MinHTLC,
				edgeUpdate.MinHTLC)
		}
		if edgeUpdate.MaxHTLC != edgeAnn.MaxHTLC {
			t.Fatalf("max HTLC of edge doesn't match: "+
				"expected %v, got %v", edgeAnn.MaxHTLC,
				edgeUpdate.MaxHTLC)
		}
		if edgeUpdate.BaseFee != edgeAnn.FeeBaseMSat {
			t.Fatalf("base fee of edge doesn't match: "+
				"expected %v, got %v", edgeAnn.FeeBaseMSat,
				edgeUpdate.BaseFee)
		}
		if edgeUpdate.FeeRate != edgeAnn.FeeProportionalMillionths {
			t.Fatalf("fee rate of edge doesn't match: "+
				"expected %v, got %v", edgeAnn.FeeProportionalMillionths,
				edgeUpdate.FeeRate)
		}
		if edgeUpdate.TimeLockDelta != edgeAnn.TimeLockDelta {
			t.Fatalf("time lock delta of edge doesn't match: "+
				"expected %v, got %v", edgeAnn.TimeLockDelta,
				edgeUpdate.TimeLockDelta)
		}
	}

	// Create lookup map for notifications we are intending to receive. Entries
	// are removed from the map when the anticipated notification is received.
	var waitingFor = map[route.Vertex]int{
		route.Vertex(node1.PubKeyBytes): 1,
		route.Vertex(node2.PubKeyBytes): 2,
	}

	node1Pub, err := node1.PubKey()
	if err != nil {
		t.Fatalf("unable to encode key: %v", err)
	}
	node2Pub, err := node2.PubKey()
	if err != nil {
		t.Fatalf("unable to encode key: %v", err)
	}

	const numEdgePolicies = 2
	for i := 0; i < numEdgePolicies; i++ {
		select {
		case ntfn := <-ntfnClient.TopologyChanges:
			// For each processed announcement we should only receive a
			// single announcement in a batch.
			if len(ntfn.ChannelEdgeUpdates) != 1 {
				t.Fatalf("expected 1 notification, instead have %v",
					len(ntfn.ChannelEdgeUpdates))
			}

			edgeUpdate := ntfn.ChannelEdgeUpdates[0]
			nodeVertex := route.NewVertex(edgeUpdate.AdvertisingNode)

			if idx, ok := waitingFor[nodeVertex]; ok {
				switch idx {
				case 1:
					// Received notification corresponding to edge1.
					assertEdgeCorrect(t, edgeUpdate, edge1)
					if !edgeUpdate.AdvertisingNode.IsEqual(node1Pub) {
						t.Fatal("advertising node mismatch")
					}
					if !edgeUpdate.ConnectingNode.IsEqual(node2Pub) {
						t.Fatal("connecting node mismatch")
					}

				case 2:
					// Received notification corresponding to edge2.
					assertEdgeCorrect(t, edgeUpdate, edge2)
					if !edgeUpdate.AdvertisingNode.IsEqual(node2Pub) {
						t.Fatal("advertising node mismatch")
					}
					if !edgeUpdate.ConnectingNode.IsEqual(node1Pub) {
						t.Fatal("connecting node mismatch")
					}

				default:
					t.Fatal("invalid edge index")
				}

				// Remove entry from waitingFor map to ensure
				// we don't double count a repeat notification.
				delete(waitingFor, nodeVertex)

			} else {
				t.Fatal("unexpected edge update received")
			}

		case <-time.After(time.Second * 5):
			t.Fatal("edge update not received")
		}
	}
}

// TestNodeUpdateNotification tests that notifications are sent out when nodes
// either join the network for the first time, or update their authenticated
// attributes with new data.
func TestNodeUpdateNotification(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	// We only accept node announcements from nodes having a known channel,
	// so create one now.
	const chanValue = 10000
	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		chanValue, startingBlockHeight)
	if err != nil {
		t.Fatalf("unable create channel edge: %v", err)
	}

	// We'll also add a record for the block that included our funding
	// transaction.
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	// Create two nodes acting as endpoints in the created channel, and use
	// them to trigger notifications by sending updated node announcement
	// messages.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}

	testFeaturesBuf := new(bytes.Buffer)
	require.NoError(t, testFeatures.Encode(testFeaturesBuf))

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	// Adding the edge will add the nodes to the graph, but with no info
	// except the pubkey known.
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// Create a new client to receive notifications.
	ntfnClient, err := ctx.router.SubscribeTopology()
	if err != nil {
		t.Fatalf("unable to subscribe for channel notifications: %v", err)
	}

	// Change network topology by adding the updated info for the two nodes
	// to the channel router.
	if err := ctx.router.AddNode(node1); err != nil {
		t.Fatalf("unable to add node: %v", err)
	}
	if err := ctx.router.AddNode(node2); err != nil {
		t.Fatalf("unable to add node: %v", err)
	}

	assertNodeNtfnCorrect := func(t *testing.T, ann *channeldb.LightningNode,
		nodeUpdate *NetworkNodeUpdate) {

		nodeKey, _ := ann.PubKey()

		// The notification received should directly map the
		// announcement originally sent.
		if nodeUpdate.Addresses[0] != ann.Addresses[0] {
			t.Fatalf("node address doesn't match: expected %v, got %v",
				nodeUpdate.Addresses[0], ann.Addresses[0])
		}
		if !nodeUpdate.IdentityKey.IsEqual(nodeKey) {
			t.Fatalf("node identity keys don't match: expected %x, "+
				"got %x", nodeKey.SerializeCompressed(),
				nodeUpdate.IdentityKey.SerializeCompressed())
		}

		featuresBuf := new(bytes.Buffer)
		require.NoError(t, nodeUpdate.Features.Encode(featuresBuf))

		require.Equal(
			t, testFeaturesBuf.Bytes(), featuresBuf.Bytes(),
		)

		if nodeUpdate.Alias != ann.Alias {
			t.Fatalf("node alias doesn't match: expected %v, got %v",
				ann.Alias, nodeUpdate.Alias)
		}
		if nodeUpdate.Color != EncodeHexColor(ann.Color) {
			t.Fatalf("node color doesn't match: expected %v, got %v",
				EncodeHexColor(ann.Color), nodeUpdate.Color)
		}
	}

	// Create lookup map for notifications we are intending to receive. Entries
	// are removed from the map when the anticipated notification is received.
	var waitingFor = map[route.Vertex]int{
		route.Vertex(node1.PubKeyBytes): 1,
		route.Vertex(node2.PubKeyBytes): 2,
	}

	// Exactly two notifications should be sent, each corresponding to the
	// node announcement messages sent above.
	const numAnns = 2
	for i := 0; i < numAnns; i++ {
		select {
		case ntfn := <-ntfnClient.TopologyChanges:
			// For each processed announcement we should only receive a
			// single announcement in a batch.
			if len(ntfn.NodeUpdates) != 1 {
				t.Fatalf("expected 1 notification, instead have %v",
					len(ntfn.NodeUpdates))
			}

			nodeUpdate := ntfn.NodeUpdates[0]
			nodeVertex := route.NewVertex(nodeUpdate.IdentityKey)
			if idx, ok := waitingFor[nodeVertex]; ok {
				switch idx {
				case 1:
					// Received notification corresponding to node1.
					assertNodeNtfnCorrect(t, node1, nodeUpdate)

				case 2:
					// Received notification corresponding to node2.
					assertNodeNtfnCorrect(t, node2, nodeUpdate)

				default:
					t.Fatal("invalid node index")
				}

				// Remove entry from waitingFor map to ensure we don't double count a
				// repeat notification.
				delete(waitingFor, nodeVertex)

			} else {
				t.Fatal("unexpected node update received")
			}

		case <-time.After(time.Second * 5):
			t.Fatal("node update not received")
		}
	}

	// If we receive a new update from a node (with a higher timestamp),
	// then it should trigger a new notification.
	// TODO(roasbeef): assume monotonic time.
	nodeUpdateAnn := *node1
	nodeUpdateAnn.LastUpdate = node1.LastUpdate.Add(300 * time.Millisecond)

	// Add new node topology update to the channel router.
	if err := ctx.router.AddNode(&nodeUpdateAnn); err != nil {
		t.Fatalf("unable to add node: %v", err)
	}

	// Once again a notification should be received reflecting the up to
	// date node announcement.
	select {
	case ntfn := <-ntfnClient.TopologyChanges:
		// For each processed announcement we should only receive a
		// single announcement in a batch.
		if len(ntfn.NodeUpdates) != 1 {
			t.Fatalf("expected 1 notification, instead have %v",
				len(ntfn.NodeUpdates))
		}

		nodeUpdate := ntfn.NodeUpdates[0]
		assertNodeNtfnCorrect(t, &nodeUpdateAnn, nodeUpdate)

	case <-time.After(time.Second * 5):
		t.Fatal("update not received")
	}
}

// TestNotificationCancellation tests that notifications are properly canceled
// when the client wishes to exit.
func TestNotificationCancellation(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	// Create a new client to receive notifications.
	ntfnClient, err := ctx.router.SubscribeTopology()
	if err != nil {
		t.Fatalf("unable to subscribe for channel notifications: %v", err)
	}

	// We'll create the utxo for a new channel.
	const chanValue = 10000
	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		chanValue, startingBlockHeight)
	if err != nil {
		t.Fatalf("unable create channel edge: %v", err)
	}

	// We'll also add a record for the block that included our funding
	// transaction.
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	// We'll create a fresh new node topology update to feed to the channel
	// router.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}

	// Before we send the message to the channel router, we'll cancel the
	// notifications for this client. As a result, the notification
	// triggered by accepting the channel announcements shouldn't be sent
	// to the client.
	ntfnClient.Cancel()

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	if err := ctx.router.AddNode(node1); err != nil {
		t.Fatalf("unable to add node: %v", err)
	}

	if err := ctx.router.AddNode(node2); err != nil {
		t.Fatalf("unable to add node: %v", err)
	}

	select {
	// The notifications shouldn't be sent, however, the channel should be
	// closed, causing the second read-value to be false.
	case _, ok := <-ntfnClient.TopologyChanges:
		if !ok {
			return
		}

		t.Fatal("notification sent but shouldn't have been")

	case <-time.After(time.Second * 5):
		t.Fatal("notification client never canceled")
	}
}

// TestChannelCloseNotification tests that channel closure notifications are
// properly dispatched to all registered clients.
func TestChannelCloseNotification(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	// First we'll create the utxo for the channel to be "closed"
	const chanValue = 10000
	fundingTx, chanUtxo, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(), bitcoinKey2.SerializeCompressed(),
		chanValue, startingBlockHeight)
	if err != nil {
		t.Fatalf("unable create channel edge: %v", err)
	}

	// We'll also add a record for the block that included our funding
	// transaction.
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	// Next we'll create two test nodes that the fake channel will be open
	// between.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}

	// Finally, to conclude our test set up, we'll create a channel
	// announcement to announce the created channel between the two nodes.
	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// With the channel edge now in place, we'll subscribe for topology
	// notifications.
	ntfnClient, err := ctx.router.SubscribeTopology()
	if err != nil {
		t.Fatalf("unable to subscribe for channel notifications: %v", err)
	}

	// Next, we'll simulate the closure of our channel by generating a new
	// block at height 102 which spends the original multi-sig output of
	// the channel.
	blockHeight := uint32(102)
	newBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			{
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: *chanUtxo,
					},
				},
			},
		},
	}
	ctx.chain.addBlock(newBlock, blockHeight, blockHeight)
	ctx.chainView.notifyBlock(newBlock.Header.BlockHash(), blockHeight,
		newBlock.Transactions)

	// The notification registered above should be sent, if not we'll time
	// out and mark the test as failed.
	select {
	case ntfn := <-ntfnClient.TopologyChanges:
		// We should have exactly a single notification for the channel
		// "closed" above.
		closedChans := ntfn.ClosedChannels
		if len(closedChans) == 0 {
			t.Fatal("close channel ntfn not populated")
		} else if len(closedChans) != 1 {
			t.Fatalf("only one should have been detected as closed, "+
				"instead %v were", len(closedChans))
		}

		// Ensure that the notification we received includes the proper
		// update the for the channel that was closed in the generated
		// block.
		closedChan := closedChans[0]
		if closedChan.ChanID != chanID.ToUint64() {
			t.Fatalf("channel ID of closed channel doesn't match: "+
				"expected %v, got %v", chanID.ToUint64(), closedChan.ChanID)
		}
		// TODO(roasbeef): this is a hack, needs to be removed
		// after commitment fees are dynamic.
		if closedChan.Capacity != chanValue {
			t.Fatalf("capacity of closed channel doesn't match: "+
				"expected %v, got %v", chanValue, closedChan.Capacity)
		}
		if closedChan.ClosedHeight != blockHeight {
			t.Fatalf("close height of closed channel doesn't match: "+
				"expected %v, got %v", blockHeight, closedChan.ClosedHeight)
		}
		if closedChan.ChanPoint != *chanUtxo {
			t.Fatalf("chan point of closed channel doesn't match: "+
				"expected %v, got %v", chanUtxo, closedChan.ChanPoint)
		}

	case <-time.After(time.Second * 5):
		t.Fatal("notification not sent")
	}
}

// TestEncodeHexColor tests that the string used to represent a node color is
// correctly encoded.
func TestEncodeHexColor(t *testing.T) {
	var colorTestCases = []struct {
		R       uint8
		G       uint8
		B       uint8
		encoded string
		isValid bool
	}{
		{0, 0, 0, "#000000", true},
		{255, 255, 255, "#ffffff", true},
		{255, 117, 215, "#ff75d7", true},
		{0, 0, 0, "000000", false},
		{1, 2, 3, "", false},
		{1, 2, 3, "#", false},
	}

	for _, tc := range colorTestCases {
		encoded := EncodeHexColor(color.RGBA{tc.R, tc.G, tc.B, 0})
		if (encoded == tc.encoded) != tc.isValid {
			t.Fatalf("incorrect color encoding, "+
				"want: %v, got: %v", tc.encoded, encoded)
		}
	}
}
