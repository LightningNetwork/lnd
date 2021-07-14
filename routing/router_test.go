package routing

import (
	"bytes"
	"fmt"
	"image/color"
	"math"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/zpay32"
)

var uniquePaymentID uint64 = 1 // to be used atomically

type testCtx struct {
	router *ChannelRouter

	graph *channeldb.ChannelGraph

	aliases map[string]route.Vertex

	privKeys map[string]*btcec.PrivateKey

	channelIDs map[route.Vertex]map[route.Vertex]uint64

	chain *mockChain

	chainView *mockChainView
}

func (c *testCtx) getChannelIDFromAlias(t *testing.T, a, b string) uint64 {
	vertexA, ok := c.aliases[a]
	require.True(t, ok, "cannot find aliases for %s", a)

	vertexB, ok := c.aliases[b]
	require.True(t, ok, "cannot find aliases for %s", b)

	channelIDMap, ok := c.channelIDs[vertexA]
	require.True(t, ok, "cannot find channelID map %s(%s)", vertexA, a)

	channelID, ok := channelIDMap[vertexB]
	require.True(t, ok, "cannot find channelID using %s(%s)", vertexB, b)

	return channelID
}

func (c *testCtx) RestartRouter(t *testing.T) {
	// First, we'll reset the chainView's state as it doesn't persist the
	// filter between restarts.
	c.chainView.Reset()

	// With the chainView reset, we'll now re-create the router itself, and
	// start it.
	router, err := New(Config{
		Graph:              c.graph,
		Chain:              c.chain,
		ChainView:          c.chainView,
		Payer:              &mockPaymentAttemptDispatcherOld{},
		Control:            makeMockControlTower(),
		ChannelPruneExpiry: time.Hour * 24,
		GraphPruneInterval: time.Hour * 2,
	})
	require.NoError(t, err, "unable to create router")
	require.NoError(t, router.Start(), "unable to start router")

	// Finally, we'll swap out the pointer in the testCtx with this fresh
	// instance of the router.
	c.router = router
}

func createTestCtxFromGraphInstance(t *testing.T,
	startingHeight uint32, graphInstance *testGraphInstance,
	strictPruning bool) (*testCtx, func()) {

	return createTestCtxFromGraphInstanceAssumeValid(
		t, startingHeight, graphInstance, false, strictPruning,
	)
}

func createTestCtxFromGraphInstanceAssumeValid(t *testing.T,
	startingHeight uint32, graphInstance *testGraphInstance,
	assumeValid bool, strictPruning bool) (*testCtx, func()) {

	// We'll initialize an instance of the channel router with mock
	// versions of the chain and channel notifier. As we don't need to test
	// any p2p functionality, the peer send and switch send messages won't
	// be populated.
	chain := newMockChain(startingHeight)
	chainView := newMockChainView(chain)

	pathFindingConfig := PathFindingConfig{
		MinProbability: 0.01,
		AttemptCost:    100,
	}

	mcConfig := &MissionControlConfig{
		ProbabilityEstimatorCfg: ProbabilityEstimatorCfg{
			PenaltyHalfLife:       time.Hour,
			AprioriHopProbability: 0.9,
			AprioriWeight:         0.5,
		},
	}

	mc, err := NewMissionControl(
		graphInstance.graph.Database(), route.Vertex{},
		mcConfig,
	)
	require.NoError(t, err, "failed to create missioncontrol")

	sessionSource := &SessionSource{
		Graph: graphInstance.graph,
		QueryBandwidth: func(e *channeldb.ChannelEdgeInfo,
			_ *lnwire.MilliSatoshi) lnwire.MilliSatoshi {

			return lnwire.NewMSatFromSatoshis(e.Capacity)
		},
		PathFindingConfig: pathFindingConfig,
		MissionControl:    mc,
	}

	router, err := New(Config{
		Graph:              graphInstance.graph,
		Chain:              chain,
		ChainView:          chainView,
		Payer:              &mockPaymentAttemptDispatcherOld{},
		Control:            makeMockControlTower(),
		MissionControl:     mc,
		SessionSource:      sessionSource,
		ChannelPruneExpiry: time.Hour * 24,
		GraphPruneInterval: time.Hour * 2,
		QueryBandwidth: func(e *channeldb.ChannelEdgeInfo,
			_ *lnwire.MilliSatoshi) lnwire.MilliSatoshi {

			return lnwire.NewMSatFromSatoshis(e.Capacity)
		},
		NextPaymentID: func() (uint64, error) {
			next := atomic.AddUint64(&uniquePaymentID, 1)
			return next, nil
		},
		PathFindingConfig:   pathFindingConfig,
		Clock:               clock.NewTestClock(time.Unix(1, 0)),
		AssumeChannelValid:  assumeValid,
		StrictZombiePruning: strictPruning,
	})
	require.NoError(t, err, "unable to create router")
	require.NoError(t, router.Start(), "unable to start router")

	ctx := &testCtx{
		router:     router,
		graph:      graphInstance.graph,
		aliases:    graphInstance.aliasMap,
		privKeys:   graphInstance.privKeyMap,
		channelIDs: graphInstance.channelIDs,
		chain:      chain,
		chainView:  chainView,
	}

	cleanUp := func() {
		ctx.router.Stop()
		graphInstance.cleanUp()
	}

	return ctx, cleanUp
}

func createTestCtxSingleNode(t *testing.T,
	startingHeight uint32) (*testCtx, func()) {

	var (
		graph      *channeldb.ChannelGraph
		sourceNode *channeldb.LightningNode
		cleanup    func()
		err        error
	)

	graph, cleanup, err = makeTestGraph()
	require.NoError(t, err, "failed to make test graph")

	sourceNode, err = createTestNode()
	require.NoError(t, err, "failed to create test node")

	require.NoError(t,
		graph.SetSourceNode(sourceNode), "failed to set source node",
	)

	graphInstance := &testGraphInstance{
		graph:   graph,
		cleanUp: cleanup,
	}

	return createTestCtxFromGraphInstance(
		t, startingHeight, graphInstance, false,
	)
}

func createTestCtxFromFile(t *testing.T,
	startingHeight uint32, testGraph string) (*testCtx, func()) {

	// We'll attempt to locate and parse out the file
	// that encodes the graph that our tests should be run against.
	graphInstance, err := parseTestGraph(testGraph)
	require.NoError(t, err, "unable to create test graph")

	return createTestCtxFromGraphInstance(
		t, startingHeight, graphInstance, false,
	)
}

// Add valid signature to channel update simulated as error received from the
// network.
func signErrChanUpdate(t *testing.T, key *btcec.PrivateKey,
	errChanUpdate *lnwire.ChannelUpdate) {

	chanUpdateMsg, err := errChanUpdate.DataToSign()
	require.NoError(t, err, "failed to retrieve data to sign")

	digest := chainhash.DoubleHashB(chanUpdateMsg)
	sig, err := key.Sign(digest)
	require.NoError(t, err, "failed to sign msg")

	errChanUpdate.Signature, err = lnwire.NewSigFromSignature(sig)
	require.NoError(t, err, "failed to create new signature")
}

// TestFindRoutesWithFeeLimit asserts that routes found by the FindRoutes method
// within the channel router contain a total fee less than or equal to the fee
// limit.
func TestFindRoutesWithFeeLimit(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// This test will attempt to find routes from roasbeef to sophon for 100
	// satoshis with a fee limit of 10 satoshis. There are two routes from
	// roasbeef to sophon:
	//	1. roasbeef -> songoku -> sophon
	//	2. roasbeef -> phamnuwen -> sophon
	// The second route violates our fee limit, so we should only expect to
	// see the first route.
	target := ctx.aliases["sophon"]
	paymentAmt := lnwire.NewMSatFromSatoshis(100)
	restrictions := &RestrictParams{
		FeeLimit:          lnwire.NewMSatFromSatoshis(10),
		ProbabilitySource: noProbabilitySource,
		CltvLimit:         math.MaxUint32,
	}

	route, err := ctx.router.FindRoute(
		ctx.router.selfNode.PubKeyBytes,
		target, paymentAmt, restrictions, nil, nil,
		MinCLTVDelta,
	)
	require.NoError(t, err, "unable to find any routes")

	require.Falsef(t,
		route.TotalFees() > restrictions.FeeLimit,
		"route exceeded fee limit: %v", spew.Sdump(route),
	)

	hops := route.Hops
	require.Equal(t, 2, len(hops), "expected 2 hops")

	require.Equalf(t,
		ctx.aliases["songoku"], hops[0].PubKeyBytes,
		"expected first hop through songoku, got %s",
		getAliasFromPubKey(hops[0].PubKeyBytes, ctx.aliases),
	)
}

// TestSendPaymentRouteFailureFallback tests that when sending a payment, if
// one of the target routes is seen as unavailable, then the next route in the
// queue is used instead. This process should continue until either a payment
// succeeds, or all routes have been exhausted.
func TestSendPaymentRouteFailureFallback(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// Craft a LightningPayment struct that'll send a payment from roasbeef
	// to luo ji for 1000 satoshis, with a maximum of 1000 satoshis in fees.
	var payHash lntypes.Hash
	paymentAmt := lnwire.NewMSatFromSatoshis(1000)
	payment := LightningPayment{
		Target:      ctx.aliases["sophon"],
		Amount:      paymentAmt,
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
	}

	var preImage [32]byte
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))

	// Get the channel ID.
	roasbeefSongoku := lnwire.NewShortChanIDFromInt(
		ctx.getChannelIDFromAlias(t, "roasbeef", "songoku"),
	)

	// We'll modify the SendToSwitch method that's been set within the
	// router's configuration to ignore the path that has son goku as the
	// first hop. This should force the router to instead take the
	// the more costly path (through pham nuwen).
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop == roasbeefSongoku {
				return [32]byte{}, htlcswitch.NewForwardingError(
					// TODO(roasbeef): temp node failure
					//  should be?
					&lnwire.FailTemporaryChannelFailure{},
					1,
				)
			}

			return preImage, nil
		})

	// Send off the payment request to the router, route through pham nuwen
	// should've been selected as a fall back and succeeded correctly.
	paymentPreImage, route, err := ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable to send payment")

	// The route selected should have two hops
	require.Equal(t, 2, len(route.Hops), "incorrect route length")

	// The preimage should match up with the once created above.
	if !bytes.Equal(paymentPreImage[:], preImage[:]) {
		t.Fatalf("incorrect preimage used: expected %x got %x",
			preImage[:], paymentPreImage[:])
	}

	// The route should have pham nuwen as the first hop.
	require.Equalf(t,
		ctx.aliases["phamnuwen"], route.Hops[0].PubKeyBytes,
		"route should go through phamnuwen as first hop, instead "+
			"passes through: %v",
		getAliasFromPubKey(route.Hops[0].PubKeyBytes, ctx.aliases),
	)
}

// TestChannelUpdateValidation tests that a failed payment with an associated
// channel update will only be applied to the graph when the update contains a
// valid signature.
func TestChannelUpdateValidation(t *testing.T) {
	t.Parallel()

	// Setup a three node network.
	chanCapSat := btcutil.Amount(100000)
	feeRate := lnwire.MilliSatoshi(400)
	testChannels := []*testChannel{
		symmetricTestChannel("a", "b", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: feeRate,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 1),
		symmetricTestChannel("b", "c", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: feeRate,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 2),
	}

	testGraph, err := createTestGraphFromChannels(testChannels, "a")
	require.NoError(t, err, "unable to create graph")
	defer testGraph.cleanUp()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromGraphInstance(
		t, startingBlockHeight, testGraph, true,
	)
	defer cleanUp()

	// Assert that the initially configured fee is retrieved correctly.
	_, policy, _, err := ctx.router.GetChannelByID(
		lnwire.NewShortChanIDFromInt(1))
	require.NoError(t, err, "cannot retrieve channel")

	require.Equal(t,
		feeRate, policy.FeeProportionalMillionths, "invalid fee",
	)

	// Setup a route from source a to destination c. The route will be used
	// in a call to SendToRoute. SendToRoute also applies channel updates,
	// but it saves us from including RequestRoute in the test scope too.
	hop1 := ctx.aliases["b"]
	hop2 := ctx.aliases["c"]
	hops := []*route.Hop{
		{
			ChannelID:     1,
			PubKeyBytes:   hop1,
			LegacyPayload: true,
		},
		{
			ChannelID:     2,
			PubKeyBytes:   hop2,
			LegacyPayload: true,
		},
	}

	rt, err := route.NewRouteFromHops(
		lnwire.MilliSatoshi(10000), 100,
		ctx.aliases["a"], hops,
	)
	require.NoError(t, err, "unable to create route")

	// Set up a channel update message with an invalid signature to be
	// returned to the sender.
	var invalidSignature [64]byte
	errChanUpdate := lnwire.ChannelUpdate{
		Signature:      invalidSignature,
		FeeRate:        500,
		ShortChannelID: lnwire.NewShortChanIDFromInt(1),
		Timestamp:      uint32(testTime.Add(time.Minute).Unix()),
	}

	// We'll modify the SendToSwitch method so that it simulates a failed
	// payment with an error originating from the first hop of the route.
	// The unsigned channel update is attached to the failure message.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {
			return [32]byte{}, htlcswitch.NewForwardingError(
				&lnwire.FailFeeInsufficient{
					Update: errChanUpdate,
				},
				1,
			)
		})

	// The payment parameter is mostly redundant in SendToRoute. Can be left
	// empty for this test.
	var payment lntypes.Hash

	// Send off the payment request to the router. The specified route
	// should be attempted and the channel update should be received by
	// router and ignored because it is missing a valid signature.
	_, err = ctx.router.SendToRoute(payment, rt)
	require.Error(t, err, "expected route to fail with channel update")

	_, policy, _, err = ctx.router.GetChannelByID(
		lnwire.NewShortChanIDFromInt(1))
	require.NoError(t, err, "cannot retrieve channel")

	require.Equal(t,
		feeRate, policy.FeeProportionalMillionths,
		"fee updated without valid signature",
	)

	// Next, add a signature to the channel update.
	signErrChanUpdate(t, testGraph.privKeyMap["b"], &errChanUpdate)

	// Retry the payment using the same route as before.
	_, err = ctx.router.SendToRoute(payment, rt)
	if err == nil {
		t.Fatalf("expected route to fail with channel update")
	}

	// This time a valid signature was supplied and the policy change should
	// have been applied to the graph.
	_, policy, _, err = ctx.router.GetChannelByID(
		lnwire.NewShortChanIDFromInt(1))
	require.NoError(t, err, "cannot retrieve channel")

	require.Equal(t,
		lnwire.MilliSatoshi(500), policy.FeeProportionalMillionths,
		"fee not updated even though signature is valid",
	)
}

// TestSendPaymentErrorRepeatedFeeInsufficient tests that if we receive
// multiple fee related errors from a channel that we're attempting to route
// through, then we'll prune the channel after the second attempt.
func TestSendPaymentErrorRepeatedFeeInsufficient(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// Get the channel ID.
	roasbeefSongokuChanID := ctx.getChannelIDFromAlias(
		t, "roasbeef", "songoku",
	)
	songokuSophonChanID := ctx.getChannelIDFromAlias(
		t, "songoku", "sophon",
	)

	// Craft a LightningPayment struct that'll send a payment from roasbeef
	// to sophon for 1000 satoshis.
	var payHash lntypes.Hash
	amt := lnwire.NewMSatFromSatoshis(1000)
	payment := LightningPayment{
		Target:      ctx.aliases["sophon"],
		Amount:      amt,
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
	}

	var preImage [32]byte
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))

	// We'll also fetch the first outgoing channel edge from son goku
	// to sophon. We'll obtain this as we'll need to to generate the
	// FeeInsufficient error that we'll send back.
	_, _, edgeUpdateToFail, err := ctx.graph.FetchChannelEdgesByID(
		songokuSophonChanID,
	)
	require.NoError(t, err, "unable to fetch chan id")

	errChanUpdate := lnwire.ChannelUpdate{
		ShortChannelID: lnwire.NewShortChanIDFromInt(
			songokuSophonChanID,
		),
		Timestamp:       uint32(edgeUpdateToFail.LastUpdate.Unix()),
		MessageFlags:    edgeUpdateToFail.MessageFlags,
		ChannelFlags:    edgeUpdateToFail.ChannelFlags,
		TimeLockDelta:   edgeUpdateToFail.TimeLockDelta,
		HtlcMinimumMsat: edgeUpdateToFail.MinHTLC,
		HtlcMaximumMsat: edgeUpdateToFail.MaxHTLC,
		BaseFee:         uint32(edgeUpdateToFail.FeeBaseMSat),
		FeeRate:         uint32(edgeUpdateToFail.FeeProportionalMillionths),
	}

	signErrChanUpdate(t, ctx.privKeys["songoku"], &errChanUpdate)

	// We'll now modify the SendToSwitch method to return an error for the
	// outgoing channel to Son goku. This will be a fee related error, so
	// it should only cause the edge to be pruned after the second attempt.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			roasbeefSongoku := lnwire.NewShortChanIDFromInt(
				roasbeefSongokuChanID,
			)
			if firstHop == roasbeefSongoku {
				return [32]byte{}, htlcswitch.NewForwardingError(
					// Within our error, we'll add a
					// channel update which is meant to
					// reflect the new fee schedule for the
					// node/channel.
					&lnwire.FailFeeInsufficient{
						Update: errChanUpdate,
					}, 1,
				)
			}

			return preImage, nil
		})

	// Send off the payment request to the router, route through phamnuwen
	// should've been selected as a fall back and succeeded correctly.
	paymentPreImage, route, err := ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable to send payment")

	// The route selected should have two hops
	require.Equal(t, 2, len(route.Hops), "incorrect route length")

	// The preimage should match up with the once created above.
	require.Equal(t, preImage[:], paymentPreImage[:], "incorrect preimage")

	// The route should have pham nuwen as the first hop.
	require.Equalf(t,
		ctx.aliases["phamnuwen"], route.Hops[0].PubKeyBytes,
		"route should go through pham nuwen as first hop, "+
			"instead passes through: %v",
		getAliasFromPubKey(route.Hops[0].PubKeyBytes, ctx.aliases),
	)
}

// TestSendPaymentErrorFeeInsufficientPrivateEdge tests that if we receive
// a fee related error from a private channel that we're attempting to route
// through, then we'll update the fees in the route hints and successfully
// route through the private channel in the second attempt.
//
// The test will send a payment from roasbeef to elst, available paths are,
// path1: roasbeef -> songoku -> sophon -> elst, total fee: 210k
// path2: roasbeef -> phamnuwen -> sophon -> elst, total fee: 220k
// path3: roasbeef -> songoku ->(private channel) elst
// We will setup the path3 to have the lowest fee so it's always the preferred
// path.
func TestSendPaymentErrorFeeInsufficientPrivateEdge(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// Get the channel ID.
	roasbeefSongoku := lnwire.NewShortChanIDFromInt(
		ctx.getChannelIDFromAlias(t, "roasbeef", "songoku"),
	)

	var (
		payHash          lntypes.Hash
		preImage         [32]byte
		amt              = lnwire.NewMSatFromSatoshis(1000)
		privateChannelID = uint64(55555)
		feeBaseMSat      = uint32(15)
		expiryDelta      = uint16(32)
		sgNode           = ctx.aliases["songoku"]
	)

	sgNodeID, err := btcec.ParsePubKey(sgNode[:], btcec.S256())
	require.NoError(t, err)

	// Craft a LightningPayment struct that'll send a payment from roasbeef
	// to elst, through a private channel between songoku and elst for
	// 1000 satoshis. This route has lowest fees compared with the rest.
	// This also holds when the private channel fee is updated to a higher
	// value.
	payment := LightningPayment{
		Target:      ctx.aliases["elst"],
		Amount:      amt,
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
		RouteHints: [][]zpay32.HopHint{{
			// Add a private channel between songoku and elst.
			zpay32.HopHint{
				NodeID:          sgNodeID,
				ChannelID:       privateChannelID,
				FeeBaseMSat:     feeBaseMSat,
				CLTVExpiryDelta: expiryDelta,
			},
		}},
	}

	// Prepare an error update for the private channel, with twice the
	// original fee.
	updatedFeeBaseMSat := feeBaseMSat * 2
	errChanUpdate := lnwire.ChannelUpdate{
		ShortChannelID: lnwire.NewShortChanIDFromInt(privateChannelID),
		Timestamp:      uint32(testTime.Add(time.Minute).Unix()),
		BaseFee:        updatedFeeBaseMSat,
		TimeLockDelta:  expiryDelta,
	}
	signErrChanUpdate(t, ctx.privKeys["songoku"], &errChanUpdate)

	// We'll now modify the SendHTLC method to return an error for the
	// outgoing channel to songoku.
	errorReturned := false
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop != roasbeefSongoku || errorReturned {
				return preImage, nil
			}

			errorReturned = true
			return [32]byte{}, htlcswitch.NewForwardingError(
				// Within our error, we'll add a
				// channel update which is meant to
				// reflect the new fee schedule for the
				// node/channel.
				&lnwire.FailFeeInsufficient{
					Update: errChanUpdate,
				}, 1,
			)
		})

	// Send off the payment request to the router, route through son
	// goku and then across the private channel to elst.
	paymentPreImage, route, err := ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable to send payment")

	require.True(t, errorReturned,
		"failed to simulate error in the first payment attempt",
	)

	// The route selected should have two hops. Make sure that,
	//   path: roasbeef -> son goku -> sophon -> elst
	//   path: roasbeef -> pham nuwen -> sophon -> elst
	// are not selected instead.
	require.Equal(t, 2, len(route.Hops), "incorrect route length")

	// The preimage should match up with the one created above.
	require.Equal(t,
		paymentPreImage[:], preImage[:], "incorrect preimage used",
	)

	// The route should have son goku as the first hop.
	require.Equal(t, route.Hops[0].PubKeyBytes, ctx.aliases["songoku"],
		"route should go through son goku as first hop",
	)

	// The route should pass via the private channel.
	require.Equal(t,
		privateChannelID, route.FinalHop().ChannelID,
		"route did not pass through private channel "+
			"between pham nuwen and elst",
	)

	// The route should have the updated fee.
	require.Equal(t,
		lnwire.MilliSatoshi(updatedFeeBaseMSat).String(),
		route.HopFee(0).String(),
		"fee to forward to the private channel not matched",
	)
}

// TestSendPaymentPrivateEdgeUpdateFeeExceedsLimit tests that upon receiving a
// ChannelUpdate in a fee related error from the private channel, we won't
// choose the route in our second attempt if the updated fee exceeds our fee
// limit specified in the payment.
//
// The test will send a payment from roasbeef to elst, available paths are,
// path1: roasbeef -> songoku -> sophon -> elst, total fee: 210k
// path2: roasbeef -> phamnuwen -> sophon -> elst, total fee: 220k
// path3: roasbeef -> songoku ->(private channel) elst
// We will setup the path3 to have the lowest fee and then update it with a fee
// exceeds our fee limit, thus this route won't be chosen.
func TestSendPaymentPrivateEdgeUpdateFeeExceedsLimit(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// Get the channel ID.
	roasbeefSongoku := lnwire.NewShortChanIDFromInt(
		ctx.getChannelIDFromAlias(t, "roasbeef", "songoku"),
	)

	var (
		payHash          lntypes.Hash
		preImage         [32]byte
		amt              = lnwire.NewMSatFromSatoshis(1000)
		privateChannelID = uint64(55555)
		feeBaseMSat      = uint32(15)
		expiryDelta      = uint16(32)
		sgNode           = ctx.aliases["songoku"]
		feeLimit         = lnwire.MilliSatoshi(500000)
	)

	sgNodeID, err := btcec.ParsePubKey(sgNode[:], btcec.S256())
	require.NoError(t, err)

	// Craft a LightningPayment struct that'll send a payment from roasbeef
	// to elst, through a private channel between songoku and elst for
	// 1000 satoshis. This route has lowest fees compared with the rest.
	payment := LightningPayment{
		Target:      ctx.aliases["elst"],
		Amount:      amt,
		FeeLimit:    feeLimit,
		paymentHash: &payHash,
		RouteHints: [][]zpay32.HopHint{{
			// Add a private channel between songoku and elst.
			zpay32.HopHint{
				NodeID:          sgNodeID,
				ChannelID:       privateChannelID,
				FeeBaseMSat:     feeBaseMSat,
				CLTVExpiryDelta: expiryDelta,
			},
		}},
	}

	// Prepare an error update for the private channel. The updated fee
	// will exceeds the feeLimit.
	updatedFeeBaseMSat := feeBaseMSat + uint32(feeLimit)
	errChanUpdate := lnwire.ChannelUpdate{
		ShortChannelID: lnwire.NewShortChanIDFromInt(privateChannelID),
		Timestamp:      uint32(testTime.Add(time.Minute).Unix()),
		BaseFee:        updatedFeeBaseMSat,
		TimeLockDelta:  expiryDelta,
	}
	signErrChanUpdate(t, ctx.privKeys["songoku"], &errChanUpdate)

	// We'll now modify the SendHTLC method to return an error for the
	// outgoing channel to songoku.
	errorReturned := false
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop != roasbeefSongoku || errorReturned {
				return preImage, nil
			}

			errorReturned = true
			return [32]byte{}, htlcswitch.NewForwardingError(
				// Within our error, we'll add a
				// channel update which is meant to
				// reflect the new fee schedule for the
				// node/channel.
				&lnwire.FailFeeInsufficient{
					Update: errChanUpdate,
				}, 1,
			)
		})

	// Send off the payment request to the router, route through son
	// goku and then across the private channel to elst.
	paymentPreImage, route, err := ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable to send payment")

	require.True(t, errorReturned,
		"failed to simulate error in the first payment attempt",
	)

	// The route selected should have three hops. Make sure that,
	//   path1: roasbeef -> son goku -> sophon -> elst
	//   path2: roasbeef -> pham nuwen -> sophon -> elst
	//   path3: roasbeef -> sophon -> (private channel) else
	// path1 is selected.
	require.Equal(t, 3, len(route.Hops), "incorrect route length")

	// The preimage should match up with the one created above.
	require.Equal(t,
		paymentPreImage[:], preImage[:], "incorrect preimage used",
	)

	// The route should have son goku as the first hop.
	require.Equal(t, route.Hops[0].PubKeyBytes, ctx.aliases["songoku"],
		"route should go through son goku as the first hop",
	)

	// The route should have sophon as the first hop.
	require.Equal(t, route.Hops[1].PubKeyBytes, ctx.aliases["sophon"],
		"route should go through sophon as the second hop",
	)
	// The route should pass via the public channel.
	require.Equal(t, route.FinalHop().PubKeyBytes, ctx.aliases["elst"],
		"route should go through elst as the final hop",
	)
}

// TestSendPaymentErrorNonFinalTimeLockErrors tests that if we receive either
// an ExpiryTooSoon or a IncorrectCltvExpiry error from a node, then we prune
// that node from the available graph witin a mission control session. This
// test ensures that we'll route around errors due to nodes not knowing the
// current block height.
func TestSendPaymentErrorNonFinalTimeLockErrors(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// Craft a LightningPayment struct that'll send a payment from roasbeef
	// to sophon for 1k satoshis.
	var payHash lntypes.Hash
	amt := lnwire.NewMSatFromSatoshis(1000)
	payment := LightningPayment{
		Target:      ctx.aliases["sophon"],
		Amount:      amt,
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
	}

	var preImage [32]byte
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))

	// We'll also fetch the first outgoing channel edge from roasbeef to
	// son goku. This edge will be included in the time lock related expiry
	// errors that we'll get back due to disagrements in what the current
	// block height is.
	chanID := ctx.getChannelIDFromAlias(t, "roasbeef", "songoku")
	roasbeefSongoku := lnwire.NewShortChanIDFromInt(chanID)

	_, _, edgeUpdateToFail, err := ctx.graph.FetchChannelEdgesByID(chanID)
	require.NoError(t, err, "unable to fetch chan id")

	errChanUpdate := lnwire.ChannelUpdate{
		ShortChannelID:  lnwire.NewShortChanIDFromInt(chanID),
		Timestamp:       uint32(edgeUpdateToFail.LastUpdate.Unix()),
		MessageFlags:    edgeUpdateToFail.MessageFlags,
		ChannelFlags:    edgeUpdateToFail.ChannelFlags,
		TimeLockDelta:   edgeUpdateToFail.TimeLockDelta,
		HtlcMinimumMsat: edgeUpdateToFail.MinHTLC,
		HtlcMaximumMsat: edgeUpdateToFail.MaxHTLC,
		BaseFee:         uint32(edgeUpdateToFail.FeeBaseMSat),
		FeeRate:         uint32(edgeUpdateToFail.FeeProportionalMillionths),
	}

	// We'll now modify the SendToSwitch method to return an error for the
	// outgoing channel to son goku. Since this is a time lock related
	// error, we should fail the payment flow all together, as Goku is the
	// only channel to Sophon.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop == roasbeefSongoku {
				return [32]byte{}, htlcswitch.NewForwardingError(
					&lnwire.FailExpiryTooSoon{
						Update: errChanUpdate,
					}, 1,
				)
			}

			return preImage, nil
		})

	// assertExpectedPath is a helper function that asserts the returned
	// route properly routes around the failure we've introduced in the
	// graph.
	assertExpectedPath := func(retPreImage [32]byte, route *route.Route) {
		// The route selected should have two hops
		require.Equal(t, 2, len(route.Hops), "incorrect route length")

		// The preimage should match up with the once created above.
		require.Equal(t,
			preImage[:], retPreImage[:], "incorrect preimage used",
		)

		// The route should have satoshi as the first hop.
		require.Equalf(t,
			ctx.aliases["phamnuwen"], route.Hops[0].PubKeyBytes,
			"route should go through phamnuwen as first hop, "+
				"instead passes through: %v",
			getAliasFromPubKey(
				route.Hops[0].PubKeyBytes, ctx.aliases,
			),
		)
	}

	// Send off the payment request to the router, this payment should
	// succeed as we should actually go through Pham Nuwen in order to get
	// to Sophon, even though he has higher fees.
	paymentPreImage, rt, err := ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable to send payment")

	assertExpectedPath(paymentPreImage, rt)

	// We'll now modify the error return an IncorrectCltvExpiry error
	// instead, this should result in the same behavior of roasbeef routing
	// around the faulty Son Goku node.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop == roasbeefSongoku {
				return [32]byte{}, htlcswitch.NewForwardingError(
					&lnwire.FailIncorrectCltvExpiry{
						Update: errChanUpdate,
					}, 1,
				)
			}

			return preImage, nil
		})

	// Once again, Roasbeef should route around Goku since they disagree
	// w.r.t to the block height, and instead go through Pham Nuwen. We
	// flip a bit in the payment hash to allow resending this payment.
	payment.paymentHash[1] ^= 1
	paymentPreImage, rt, err = ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable to send payment")

	assertExpectedPath(paymentPreImage, rt)
}

// TestSendPaymentErrorPathPruning tests that the send of candidate routes
// properly gets pruned in response to ForwardingError response from the
// underlying SendToSwitch function.
func TestSendPaymentErrorPathPruning(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// Craft a LightningPayment struct that'll send a payment from roasbeef
	// to luo ji for 1000 satoshis, with a maximum of 1000 satoshis in fees.
	var payHash lntypes.Hash
	paymentAmt := lnwire.NewMSatFromSatoshis(1000)
	payment := LightningPayment{
		Target:      ctx.aliases["sophon"],
		Amount:      paymentAmt,
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
	}

	var preImage [32]byte
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))

	roasbeefSongoku := lnwire.NewShortChanIDFromInt(
		ctx.getChannelIDFromAlias(t, "roasbeef", "songoku"),
	)
	roasbeefPhanNuwen := lnwire.NewShortChanIDFromInt(
		ctx.getChannelIDFromAlias(t, "roasbeef", "phamnuwen"),
	)

	// First, we'll modify the SendToSwitch method to return an error
	// indicating that the channel from roasbeef to son goku is not operable
	// with an UnknownNextPeer.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop == roasbeefSongoku {
				// We'll first simulate an error from the first
				// hop to simulate the channel from songoku to
				// sophon not having enough capacity.
				return [32]byte{}, htlcswitch.NewForwardingError(
					&lnwire.FailTemporaryChannelFailure{},
					1,
				)
			}

			// Next, we'll create an error from phan nuwen to
			// indicate that the sophon node is not longer online,
			// which should prune out the rest of the routes.
			if firstHop == roasbeefPhanNuwen {
				return [32]byte{}, htlcswitch.NewForwardingError(
					&lnwire.FailUnknownNextPeer{}, 1,
				)
			}

			return preImage, nil
		})

	ctx.router.cfg.MissionControl.(*MissionControl).ResetHistory()

	// When we try to dispatch that payment, we should receive an error as
	// both attempts should fail and cause both routes to be pruned.
	_, _, err := ctx.router.SendPayment(&payment)
	require.Error(t, err, "payment didn't return error")

	// The final error returned should also indicate that the peer wasn't
	// online (the last error we returned).
	require.Equal(t, channeldb.FailureReasonNoRoute, err)

	// Inspect the two attempts that were made before the payment failed.
	p, err := ctx.router.cfg.Control.FetchPayment(payHash)
	require.NoError(t, err)

	require.Equal(t, 2, len(p.HTLCs), "expected two attempts")

	// We expect the first attempt to have failed with a
	// TemporaryChannelFailure, the second with UnknownNextPeer.
	msg := p.HTLCs[0].Failure.Message
	_, ok := msg.(*lnwire.FailTemporaryChannelFailure)
	require.True(t, ok, "unexpected fail message")

	msg = p.HTLCs[1].Failure.Message
	_, ok = msg.(*lnwire.FailUnknownNextPeer)
	require.True(t, ok, "unexpected fail message")

	err = ctx.router.cfg.MissionControl.(*MissionControl).ResetHistory()
	require.NoError(t, err, "reset history failed")

	// Next, we'll modify the SendToSwitch method to indicate that the
	// connection between songoku and isn't up.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop == roasbeefSongoku {
				failure := htlcswitch.NewForwardingError(
					&lnwire.FailUnknownNextPeer{}, 1,
				)
				return [32]byte{}, failure
			}

			return preImage, nil
		})

	// This shouldn't return an error, as we'll make a payment attempt via
	// the pham nuwen channel based on the assumption that there might be an
	// intermittent issue with the songoku <-> sophon channel.
	paymentPreImage, rt, err := ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable send payment")

	// This path should go: roasbeef -> pham nuwen -> sophon
	require.Equal(t, 2, len(rt.Hops), "incorrect route length")
	require.Equal(t, preImage[:], paymentPreImage[:], "incorrect preimage")
	require.Equalf(t,
		ctx.aliases["phamnuwen"], rt.Hops[0].PubKeyBytes,
		"route should go through phamnuwen as first hop, "+
			"instead passes through: %v",
		getAliasFromPubKey(rt.Hops[0].PubKeyBytes, ctx.aliases),
	)

	ctx.router.cfg.MissionControl.(*MissionControl).ResetHistory()

	// Finally, we'll modify the SendToSwitch function to indicate that the
	// roasbeef -> luoji channel has insufficient capacity. This should
	// again cause us to instead go via the satoshi route.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			if firstHop == roasbeefSongoku {
				// We'll first simulate an error from the first
				// outgoing link to simulate the channel from luo ji to
				// roasbeef not having enough capacity.
				return [32]byte{}, htlcswitch.NewForwardingError(
					&lnwire.FailTemporaryChannelFailure{},
					1,
				)
			}
			return preImage, nil
		})

	// We flip a bit in the payment hash to allow resending this payment.
	payment.paymentHash[1] ^= 1
	paymentPreImage, rt, err = ctx.router.SendPayment(&payment)
	require.NoError(t, err, "unable send payment")

	// This should succeed finally.  The route selected should have two
	// hops.
	require.Equal(t, 2, len(rt.Hops), "incorrect route length")

	// The preimage should match up with the once created above.
	require.Equal(t, preImage[:], paymentPreImage[:], "incorrect preimage")

	// The route should have satoshi as the first hop.
	require.Equalf(t,
		ctx.aliases["phamnuwen"], rt.Hops[0].PubKeyBytes,
		"route should go through phamnuwen as first hop, "+
			"instead passes through: %v",
		getAliasFromPubKey(rt.Hops[0].PubKeyBytes, ctx.aliases),
	)
}

// TestAddProof checks that we can update the channel proof after channel
// info was added to the database.
func TestAddProof(t *testing.T) {
	t.Parallel()

	ctx, cleanup := createTestCtxSingleNode(t, 0)
	defer cleanup()

	// Before creating out edge, we'll create two new nodes within the
	// network that the channel will connect.
	node1, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	// In order to be able to add the edge we should have a valid funding
	// UTXO within the blockchain.
	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(), bitcoinKey2.SerializeCompressed(),
		100, 0)
	if err != nil {
		t.Fatalf("unable create channel edge: %v", err)
	}
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	// After utxo was recreated adding the edge without the proof.
	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof:     nil,
	}
	copy(edge.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// Now we'll attempt to update the proof and check that it has been
	// properly updated.
	if err := ctx.router.AddProof(*chanID, &testAuthProof); err != nil {
		t.Fatalf("unable to add proof: %v", err)
	}

	info, _, _, err := ctx.router.GetChannelByID(*chanID)
	if err != nil {
		t.Fatalf("unable to get channel: %v", err)
	}
	if info.AuthProof == nil {
		t.Fatal("proof have been updated")
	}
}

// TestIgnoreNodeAnnouncement tests that adding a node to the router that is
// not known from any channel announcement, leads to the announcement being
// ignored.
func TestIgnoreNodeAnnouncement(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	pub := priv1.PubKey()
	node := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           time.Unix(123, 0),
		Addresses:            testAddrs,
		Color:                color.RGBA{1, 2, 3, 0},
		Alias:                "node11",
		AuthSigBytes:         testSig.Serialize(),
		Features:             testFeatures,
	}
	copy(node.PubKeyBytes[:], pub.SerializeCompressed())

	err := ctx.router.AddNode(node)
	if !IsError(err, ErrIgnored) {
		t.Fatalf("expected to get ErrIgnore, instead got: %v", err)
	}
}

// TestIgnoreChannelEdgePolicyForUnknownChannel checks that a router will
// ignore a channel policy for a channel not in the graph.
func TestIgnoreChannelEdgePolicyForUnknownChannel(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101

	// Setup an initially empty network.
	testChannels := []*testChannel{}
	testGraph, err := createTestGraphFromChannels(
		testChannels, "roasbeef",
	)
	if err != nil {
		t.Fatalf("unable to create graph: %v", err)
	}
	defer testGraph.cleanUp()

	ctx, cleanUp := createTestCtxFromGraphInstance(
		t, startingBlockHeight, testGraph, false,
	)
	defer cleanUp()

	var pub1 [33]byte
	copy(pub1[:], priv1.PubKey().SerializeCompressed())

	var pub2 [33]byte
	copy(pub2[:], priv2.PubKey().SerializeCompressed())

	// Add the edge between the two unknown nodes to the graph, and check
	// that the nodes are found after the fact.
	fundingTx, _, chanID, err := createChannelEdge(
		ctx, bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(), 10000, 500,
	)
	if err != nil {
		t.Fatalf("unable to create channel edge: %v", err)
	}
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID.ToUint64(),
		NodeKey1Bytes:    pub1,
		NodeKey2Bytes:    pub2,
		BitcoinKey1Bytes: pub1,
		BitcoinKey2Bytes: pub2,
		AuthProof:        nil,
	}
	edgePolicy := &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                testTime,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}

	// Attempt to update the edge. This should be ignored, since the edge
	// is not yet added to the router.
	err = ctx.router.UpdateEdge(edgePolicy)
	if !IsError(err, ErrIgnored) {
		t.Fatalf("expected to get ErrIgnore, instead got: %v", err)
	}

	// Add the edge.
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("expected to be able to add edge to the channel graph,"+
			" even though the vertexes were unknown: %v.", err)
	}

	// Now updating the edge policy should succeed.
	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}
}

// TestAddEdgeUnknownVertexes tests that if an edge is added that contains two
// vertexes which we don't know of, the edge should be available for use
// regardless. This is due to the fact that we don't actually need node
// announcements for the channel vertexes to be able to use the channel.
func TestAddEdgeUnknownVertexes(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	var pub1 [33]byte
	copy(pub1[:], priv1.PubKey().SerializeCompressed())

	var pub2 [33]byte
	copy(pub2[:], priv2.PubKey().SerializeCompressed())

	// The two nodes we are about to add should not exist yet.
	_, exists1, err := ctx.graph.HasLightningNode(pub1)
	if err != nil {
		t.Fatalf("unable to query graph: %v", err)
	}
	if exists1 {
		t.Fatalf("node already existed")
	}
	_, exists2, err := ctx.graph.HasLightningNode(pub2)
	if err != nil {
		t.Fatalf("unable to query graph: %v", err)
	}
	if exists2 {
		t.Fatalf("node already existed")
	}

	// Add the edge between the two unknown nodes to the graph, and check
	// that the nodes are found after the fact.
	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		10000, 500,
	)
	if err != nil {
		t.Fatalf("unable to create channel edge: %v", err)
	}
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID.ToUint64(),
		NodeKey1Bytes:    pub1,
		NodeKey2Bytes:    pub2,
		BitcoinKey1Bytes: pub1,
		BitcoinKey2Bytes: pub2,
		AuthProof:        nil,
	}
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("expected to be able to add edge to the channel graph,"+
			" even though the vertexes were unknown: %v.", err)
	}

	// We must add the edge policy to be able to use the edge for route
	// finding.
	edgePolicy := &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                testTime,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}
	edgePolicy.ChannelFlags = 0

	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}

	// Create edge in the other direction as well.
	edgePolicy = &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                testTime,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}
	edgePolicy.ChannelFlags = 1

	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}

	// After adding the edge between the two previously unknown nodes, they
	// should have been added to the graph.
	_, exists1, err = ctx.graph.HasLightningNode(pub1)
	if err != nil {
		t.Fatalf("unable to query graph: %v", err)
	}
	if !exists1 {
		t.Fatalf("node1 was not added to the graph")
	}
	_, exists2, err = ctx.graph.HasLightningNode(pub2)
	if err != nil {
		t.Fatalf("unable to query graph: %v", err)
	}
	if !exists2 {
		t.Fatalf("node2 was not added to the graph")
	}

	// We will connect node1 to the rest of the test graph, and make sure
	// we can find a route to node2, which will use the just added channel
	// edge.

	// We will connect node 1 to "sophon"
	connectNode := ctx.aliases["sophon"]
	connectNodeKey, err := btcec.ParsePubKey(connectNode[:], btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	var (
		pubKey1 *btcec.PublicKey
		pubKey2 *btcec.PublicKey
	)
	node1Bytes := priv1.PubKey().SerializeCompressed()
	node2Bytes := connectNode
	if bytes.Compare(node1Bytes[:], node2Bytes[:]) == -1 {
		pubKey1 = priv1.PubKey()
		pubKey2 = connectNodeKey
	} else {
		pubKey1 = connectNodeKey
		pubKey2 = priv1.PubKey()
	}

	fundingTx, _, chanID, err = createChannelEdge(ctx,
		pubKey1.SerializeCompressed(), pubKey2.SerializeCompressed(),
		10000, 510)
	if err != nil {
		t.Fatalf("unable to create channel edge: %v", err)
	}
	fundingBlock = &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	edge = &channeldb.ChannelEdgeInfo{
		ChannelID: chanID.ToUint64(),
		AuthProof: nil,
	}
	copy(edge.NodeKey1Bytes[:], node1Bytes)
	edge.NodeKey2Bytes = node2Bytes
	copy(edge.BitcoinKey1Bytes[:], node1Bytes)
	edge.BitcoinKey2Bytes = node2Bytes

	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge to the channel graph: %v.", err)
	}

	edgePolicy = &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                testTime,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}
	edgePolicy.ChannelFlags = 0

	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}

	edgePolicy = &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                testTime,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}
	edgePolicy.ChannelFlags = 1

	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}

	// We should now be able to find a route to node 2.
	paymentAmt := lnwire.NewMSatFromSatoshis(100)
	targetNode := priv2.PubKey()
	var targetPubKeyBytes route.Vertex
	copy(targetPubKeyBytes[:], targetNode.SerializeCompressed())
	_, err = ctx.router.FindRoute(
		ctx.router.selfNode.PubKeyBytes,
		targetPubKeyBytes, paymentAmt, noRestrictions, nil, nil,
		MinCLTVDelta,
	)
	if err != nil {
		t.Fatalf("unable to find any routes: %v", err)
	}

	// Now check that we can update the node info for the partial node
	// without messing up the channel graph.
	n1 := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           time.Unix(123, 0),
		Addresses:            testAddrs,
		Color:                color.RGBA{1, 2, 3, 0},
		Alias:                "node11",
		AuthSigBytes:         testSig.Serialize(),
		Features:             testFeatures,
	}
	copy(n1.PubKeyBytes[:], priv1.PubKey().SerializeCompressed())

	if err := ctx.router.AddNode(n1); err != nil {
		t.Fatalf("could not add node: %v", err)
	}

	n2 := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           time.Unix(123, 0),
		Addresses:            testAddrs,
		Color:                color.RGBA{1, 2, 3, 0},
		Alias:                "node22",
		AuthSigBytes:         testSig.Serialize(),
		Features:             testFeatures,
	}
	copy(n2.PubKeyBytes[:], priv2.PubKey().SerializeCompressed())

	if err := ctx.router.AddNode(n2); err != nil {
		t.Fatalf("could not add node: %v", err)
	}

	// Should still be able to find the route, and the info should be
	// updated.
	_, err = ctx.router.FindRoute(
		ctx.router.selfNode.PubKeyBytes,
		targetPubKeyBytes, paymentAmt, noRestrictions, nil, nil,
		MinCLTVDelta,
	)
	if err != nil {
		t.Fatalf("unable to find any routes: %v", err)
	}

	copy1, err := ctx.graph.FetchLightningNode(nil, pub1)
	if err != nil {
		t.Fatalf("unable to fetch node: %v", err)
	}

	if copy1.Alias != n1.Alias {
		t.Fatalf("fetched node not equal to original")
	}

	copy2, err := ctx.graph.FetchLightningNode(nil, pub2)
	if err != nil {
		t.Fatalf("unable to fetch node: %v", err)
	}

	if copy2.Alias != n2.Alias {
		t.Fatalf("fetched node not equal to original")
	}
}

// TestWakeUpOnStaleBranch tests that upon startup of the ChannelRouter, if the
// the chain previously reflected in the channel graph is stale (overtaken by a
// longer chain), the channel router will prune the graph for any channels
// confirmed on the stale chain, and resync to the main chain.
func TestWakeUpOnStaleBranch(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	const chanValue = 10000

	// chanID1 will not be reorged out.
	var chanID1 uint64

	// chanID2 will be reorged out.
	var chanID2 uint64

	// Create 10 common blocks, confirming chanID1.
	for i := uint32(1); i <= 10; i++ {
		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		height := startingBlockHeight + i
		if i == 5 {
			fundingTx, _, chanID, err := createChannelEdge(ctx,
				bitcoinKey1.SerializeCompressed(),
				bitcoinKey2.SerializeCompressed(),
				chanValue, height)
			if err != nil {
				t.Fatalf("unable create channel edge: %v", err)
			}
			block.Transactions = append(block.Transactions,
				fundingTx)
			chanID1 = chanID.ToUint64()

		}
		ctx.chain.addBlock(block, height, rand.Uint32())
		ctx.chain.setBestBlock(int32(height))
		ctx.chainView.notifyBlock(block.BlockHash(), height,
			[]*wire.MsgTx{})
	}

	// Give time to process new blocks
	time.Sleep(time.Millisecond * 500)

	_, forkHeight, err := ctx.chain.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to ge best block: %v", err)
	}

	// Create 10 blocks on the minority chain, confirming chanID2.
	for i := uint32(1); i <= 10; i++ {
		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		height := uint32(forkHeight) + i
		if i == 5 {
			fundingTx, _, chanID, err := createChannelEdge(ctx,
				bitcoinKey1.SerializeCompressed(),
				bitcoinKey2.SerializeCompressed(),
				chanValue, height)
			if err != nil {
				t.Fatalf("unable create channel edge: %v", err)
			}
			block.Transactions = append(block.Transactions,
				fundingTx)
			chanID2 = chanID.ToUint64()
		}
		ctx.chain.addBlock(block, height, rand.Uint32())
		ctx.chain.setBestBlock(int32(height))
		ctx.chainView.notifyBlock(block.BlockHash(), height,
			[]*wire.MsgTx{})
	}
	// Give time to process new blocks
	time.Sleep(time.Millisecond * 500)

	// Now add the two edges to the channel graph, and check that they
	// correctly show up in the database.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}

	edge1 := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID1,
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge1.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge1.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if err := ctx.router.AddEdge(edge1); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	edge2 := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID2,
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge2.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge2.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if err := ctx.router.AddEdge(edge2); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// Check that the fundingTxs are in the graph db.
	_, _, has, isZombie, err := ctx.graph.HasChannelEdge(chanID1)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID1)
	}
	if !has {
		t.Fatalf("could not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	_, _, has, isZombie, err = ctx.graph.HasChannelEdge(chanID2)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID2)
	}
	if !has {
		t.Fatalf("could not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	// Stop the router, so we can reorg the chain while its offline.
	if err := ctx.router.Stop(); err != nil {
		t.Fatalf("unable to stop router: %v", err)
	}

	// Create a 15 block fork.
	for i := uint32(1); i <= 15; i++ {
		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		height := uint32(forkHeight) + i
		ctx.chain.addBlock(block, height, rand.Uint32())
		ctx.chain.setBestBlock(int32(height))
	}

	// Give time to process new blocks.
	time.Sleep(time.Millisecond * 500)

	// Create new router with same graph database.
	router, err := New(Config{
		Graph:              ctx.graph,
		Chain:              ctx.chain,
		ChainView:          ctx.chainView,
		Payer:              &mockPaymentAttemptDispatcherOld{},
		Control:            makeMockControlTower(),
		ChannelPruneExpiry: time.Hour * 24,
		GraphPruneInterval: time.Hour * 2,

		// We'll set the delay to zero to prune immediately.
		FirstTimePruneDelay: 0,
	})
	if err != nil {
		t.Fatalf("unable to create router %v", err)
	}

	// It should resync to the longer chain on startup.
	if err := router.Start(); err != nil {
		t.Fatalf("unable to start router: %v", err)
	}

	// The channel with chanID2 should not be in the database anymore,
	// since it is not confirmed on the longest chain. chanID1 should
	// still be.
	_, _, has, isZombie, err = ctx.graph.HasChannelEdge(chanID1)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID1)
	}
	if !has {
		t.Fatalf("did not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	_, _, has, isZombie, err = ctx.graph.HasChannelEdge(chanID2)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID2)
	}
	if has {
		t.Fatalf("found edge in graph")
	}
	if isZombie {
		t.Fatal("reorged edge should not be marked as zombie")
	}
}

// TestDisconnectedBlocks checks that the router handles a reorg happening when
// it is active.
func TestDisconnectedBlocks(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	const chanValue = 10000

	// chanID1 will not be reorged out, while chanID2 will be reorged out.
	var chanID1, chanID2 uint64

	// Create 10 common blocks, confirming chanID1.
	for i := uint32(1); i <= 10; i++ {
		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		height := startingBlockHeight + i
		if i == 5 {
			fundingTx, _, chanID, err := createChannelEdge(ctx,
				bitcoinKey1.SerializeCompressed(),
				bitcoinKey2.SerializeCompressed(),
				chanValue, height)
			if err != nil {
				t.Fatalf("unable create channel edge: %v", err)
			}
			block.Transactions = append(block.Transactions,
				fundingTx)
			chanID1 = chanID.ToUint64()

		}
		ctx.chain.addBlock(block, height, rand.Uint32())
		ctx.chain.setBestBlock(int32(height))
		ctx.chainView.notifyBlock(block.BlockHash(), height,
			[]*wire.MsgTx{})
	}

	// Give time to process new blocks
	time.Sleep(time.Millisecond * 500)

	_, forkHeight, err := ctx.chain.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get best block: %v", err)
	}

	// Create 10 blocks on the minority chain, confirming chanID2.
	var minorityChain []*wire.MsgBlock
	for i := uint32(1); i <= 10; i++ {
		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		height := uint32(forkHeight) + i
		if i == 5 {
			fundingTx, _, chanID, err := createChannelEdge(ctx,
				bitcoinKey1.SerializeCompressed(),
				bitcoinKey2.SerializeCompressed(),
				chanValue, height)
			if err != nil {
				t.Fatalf("unable create channel edge: %v", err)
			}
			block.Transactions = append(block.Transactions,
				fundingTx)
			chanID2 = chanID.ToUint64()
		}
		minorityChain = append(minorityChain, block)
		ctx.chain.addBlock(block, height, rand.Uint32())
		ctx.chain.setBestBlock(int32(height))
		ctx.chainView.notifyBlock(block.BlockHash(), height,
			[]*wire.MsgTx{})
	}
	// Give time to process new blocks
	time.Sleep(time.Millisecond * 500)

	// Now add the two edges to the channel graph, and check that they
	// correctly show up in the database.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}

	edge1 := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID1,
		NodeKey1Bytes:    node1.PubKeyBytes,
		NodeKey2Bytes:    node2.PubKeyBytes,
		BitcoinKey1Bytes: node1.PubKeyBytes,
		BitcoinKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge1.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge1.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if err := ctx.router.AddEdge(edge1); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	edge2 := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID2,
		NodeKey1Bytes:    node1.PubKeyBytes,
		NodeKey2Bytes:    node2.PubKeyBytes,
		BitcoinKey1Bytes: node1.PubKeyBytes,
		BitcoinKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge2.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge2.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if err := ctx.router.AddEdge(edge2); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// Check that the fundingTxs are in the graph db.
	_, _, has, isZombie, err := ctx.graph.HasChannelEdge(chanID1)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID1)
	}
	if !has {
		t.Fatalf("could not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	_, _, has, isZombie, err = ctx.graph.HasChannelEdge(chanID2)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID2)
	}
	if !has {
		t.Fatalf("could not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	// Create a 15 block fork. We first let the chainView notify the router
	// about stale blocks, before sending the now connected blocks. We do
	// this because we expect this order from the chainview.
	for i := len(minorityChain) - 1; i >= 0; i-- {
		block := minorityChain[i]
		height := uint32(forkHeight) + uint32(i) + 1
		ctx.chainView.notifyStaleBlock(block.BlockHash(), height,
			block.Transactions)
	}
	for i := uint32(1); i <= 15; i++ {
		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		height := uint32(forkHeight) + i
		ctx.chain.addBlock(block, height, rand.Uint32())
		ctx.chain.setBestBlock(int32(height))
		ctx.chainView.notifyBlock(block.BlockHash(), height,
			block.Transactions)
	}

	// Give time to process new blocks
	time.Sleep(time.Millisecond * 500)

	// chanID2 should not be in the database anymore, since it is not
	// confirmed on the longest chain. chanID1 should still be.
	_, _, has, isZombie, err = ctx.graph.HasChannelEdge(chanID1)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID1)
	}
	if !has {
		t.Fatalf("did not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	_, _, has, isZombie, err = ctx.graph.HasChannelEdge(chanID2)
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID2)
	}
	if has {
		t.Fatalf("found edge in graph")
	}
	if isZombie {
		t.Fatal("reorged edge should not be marked as zombie")
	}
}

// TestChansClosedOfflinePruneGraph tests that if channels we know of are
// closed while we're offline, then once we resume operation of the
// ChannelRouter, then the channels are properly pruned.
func TestRouterChansClosedOfflinePruneGraph(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	const chanValue = 10000

	// First, we'll create a channel, to be mined shortly at height 102.
	block102 := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{},
	}
	nextHeight := startingBlockHeight + 1
	fundingTx1, chanUTXO, chanID1, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		chanValue, uint32(nextHeight))
	if err != nil {
		t.Fatalf("unable create channel edge: %v", err)
	}
	block102.Transactions = append(block102.Transactions, fundingTx1)
	ctx.chain.addBlock(block102, uint32(nextHeight), rand.Uint32())
	ctx.chain.setBestBlock(int32(nextHeight))
	ctx.chainView.notifyBlock(block102.BlockHash(), uint32(nextHeight),
		[]*wire.MsgTx{})

	// We'll now create the edges and nodes within the database required
	// for the ChannelRouter to properly recognize the channel we added
	// above.
	node1, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	node2, err := createTestNode()
	if err != nil {
		t.Fatalf("unable to create test node: %v", err)
	}
	edge1 := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID1.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
		AuthProof: &channeldb.ChannelAuthProof{
			NodeSig1Bytes:    testSig.Serialize(),
			NodeSig2Bytes:    testSig.Serialize(),
			BitcoinSig1Bytes: testSig.Serialize(),
			BitcoinSig2Bytes: testSig.Serialize(),
		},
	}
	copy(edge1.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge1.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())
	if err := ctx.router.AddEdge(edge1); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// The router should now be aware of the channel we created above.
	_, _, hasChan, isZombie, err := ctx.graph.HasChannelEdge(chanID1.ToUint64())
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID1)
	}
	if !hasChan {
		t.Fatalf("could not find edge in graph")
	}
	if isZombie {
		t.Fatal("edge was marked as zombie")
	}

	// With the transaction included, and the router's database state
	// updated, we'll now mine 5 additional blocks on top of it.
	for i := 0; i < 5; i++ {
		nextHeight++

		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}
		ctx.chain.addBlock(block, uint32(nextHeight), rand.Uint32())
		ctx.chain.setBestBlock(int32(nextHeight))
		ctx.chainView.notifyBlock(block.BlockHash(), uint32(nextHeight),
			[]*wire.MsgTx{})
	}

	// At this point, our starting height should be 107.
	_, chainHeight, err := ctx.chain.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get best block: %v", err)
	}
	if chainHeight != 107 {
		t.Fatalf("incorrect chain height: expected %v, got %v",
			107, chainHeight)
	}

	// Next, we'll "shut down" the router in order to simulate downtime.
	if err := ctx.router.Stop(); err != nil {
		t.Fatalf("unable to shutdown router: %v", err)
	}

	// While the router is "offline" we'll mine 5 additional blocks, with
	// the second block closing the channel we created above.
	for i := 0; i < 5; i++ {
		nextHeight++

		block := &wire.MsgBlock{
			Transactions: []*wire.MsgTx{},
		}

		if i == 2 {
			// For the second block, we'll add a transaction that
			// closes the channel we created above by spending the
			// output.
			closingTx := wire.NewMsgTx(2)
			closingTx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: *chanUTXO,
			})
			block.Transactions = append(block.Transactions,
				closingTx)
		}

		ctx.chain.addBlock(block, uint32(nextHeight), rand.Uint32())
		ctx.chain.setBestBlock(int32(nextHeight))
		ctx.chainView.notifyBlock(block.BlockHash(), uint32(nextHeight),
			[]*wire.MsgTx{})
	}

	// At this point, our starting height should be 112.
	_, chainHeight, err = ctx.chain.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get best block: %v", err)
	}
	if chainHeight != 112 {
		t.Fatalf("incorrect chain height: expected %v, got %v",
			112, chainHeight)
	}

	// Now we'll re-start the ChannelRouter. It should recognize that it's
	// behind the main chain and prune all the blocks that it missed while
	// it was down.
	ctx.RestartRouter(t)

	// At this point, the channel that was pruned should no longer be known
	// by the router.
	_, _, hasChan, isZombie, err = ctx.graph.HasChannelEdge(chanID1.ToUint64())
	if err != nil {
		t.Fatalf("error looking for edge: %v", chanID1)
	}
	if hasChan {
		t.Fatalf("channel was found in graph but shouldn't have been")
	}
	if isZombie {
		t.Fatal("closed channel should not be marked as zombie")
	}
}

// TestPruneChannelGraphStaleEdges ensures that we properly prune stale edges
// from the channel graph.
func TestPruneChannelGraphStaleEdges(t *testing.T) {
	t.Parallel()

	freshTimestamp := time.Now()
	staleTimestamp := time.Unix(0, 0)

	// We'll create the following test graph so that two of the channels
	// are pruned.
	testChannels := []*testChannel{
		// No edges.
		{
			Node1:     &testChannelEnd{Alias: "a"},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 1,
		},

		// Only one edge with a stale timestamp.
		{
			Node1: &testChannelEnd{
				Alias: "d",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: staleTimestamp,
				},
			},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 2,
		},

		// Only one edge with a stale timestamp, but it's the source
		// node so it won't get pruned.
		{
			Node1: &testChannelEnd{
				Alias: "a",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: staleTimestamp,
				},
			},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 3,
		},

		// Only one edge with a fresh timestamp.
		{
			Node1: &testChannelEnd{
				Alias: "a",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: freshTimestamp,
				},
			},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 4,
		},

		// One edge fresh, one edge stale. This will be pruned with
		// strict pruning activated.
		{
			Node1: &testChannelEnd{
				Alias: "c",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: freshTimestamp,
				},
			},
			Node2: &testChannelEnd{
				Alias: "d",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: staleTimestamp,
				},
			},
			Capacity:  100000,
			ChannelID: 5,
		},

		// Both edges fresh.
		symmetricTestChannel("g", "h", 100000, &testChannelPolicy{
			LastUpdate: freshTimestamp,
		}, 6),

		// Both edges stale, only one pruned. This should be pruned for
		// both normal and strict pruning.
		symmetricTestChannel("e", "f", 100000, &testChannelPolicy{
			LastUpdate: staleTimestamp,
		}, 7),
	}

	for _, strictPruning := range []bool{true, false} {
		// We'll create our test graph and router backed with these test
		// channels we've created.
		testGraph, err := createTestGraphFromChannels(testChannels, "a")
		if err != nil {
			t.Fatalf("unable to create test graph: %v", err)
		}
		defer testGraph.cleanUp()

		const startingHeight = 100
		ctx, cleanUp := createTestCtxFromGraphInstance(
			t, startingHeight, testGraph, strictPruning,
		)
		defer cleanUp()

		// All of the channels should exist before pruning them.
		assertChannelsPruned(t, ctx.graph, testChannels)

		// Proceed to prune the channels - only the last one should be pruned.
		if err := ctx.router.pruneZombieChans(); err != nil {
			t.Fatalf("unable to prune zombie channels: %v", err)
		}

		// We expect channels that have either both edges stale, or one edge
		// stale with both known.
		var prunedChannels []uint64
		if strictPruning {
			prunedChannels = []uint64{2, 5, 7}
		} else {
			prunedChannels = []uint64{2, 7}
		}
		assertChannelsPruned(t, ctx.graph, testChannels, prunedChannels...)
	}
}

// TestPruneChannelGraphDoubleDisabled test that we can properly prune channels
// with both edges disabled from our channel graph.
func TestPruneChannelGraphDoubleDisabled(t *testing.T) {
	t.Parallel()

	t.Run("no_assumechannelvalid", func(t *testing.T) {
		testPruneChannelGraphDoubleDisabled(t, false)
	})
	t.Run("assumechannelvalid", func(t *testing.T) {
		testPruneChannelGraphDoubleDisabled(t, true)
	})
}

func testPruneChannelGraphDoubleDisabled(t *testing.T, assumeValid bool) {
	// We'll create the following test graph so that only the last channel
	// is pruned. We'll use a fresh timestamp to ensure they're not pruned
	// according to that heuristic.
	timestamp := time.Now()
	testChannels := []*testChannel{
		// Channel from self shouldn't be pruned.
		symmetricTestChannel(
			"self", "a", 100000, &testChannelPolicy{
				LastUpdate: timestamp,
				Disabled:   true,
			}, 99,
		),

		// No edges.
		{
			Node1:     &testChannelEnd{Alias: "a"},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 1,
		},

		// Only one edge disabled.
		{
			Node1: &testChannelEnd{
				Alias: "a",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: timestamp,
					Disabled:   true,
				},
			},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 2,
		},

		// Only one edge enabled.
		{
			Node1: &testChannelEnd{
				Alias: "a",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: timestamp,
					Disabled:   false,
				},
			},
			Node2:     &testChannelEnd{Alias: "b"},
			Capacity:  100000,
			ChannelID: 3,
		},

		// One edge disabled, one edge enabled.
		{
			Node1: &testChannelEnd{
				Alias: "a",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: timestamp,
					Disabled:   true,
				},
			},
			Node2: &testChannelEnd{
				Alias: "b",
				testChannelPolicy: &testChannelPolicy{
					LastUpdate: timestamp,
					Disabled:   false,
				},
			},
			Capacity:  100000,
			ChannelID: 1,
		},

		// Both edges enabled.
		symmetricTestChannel("c", "d", 100000, &testChannelPolicy{
			LastUpdate: timestamp,
			Disabled:   false,
		}, 2),

		// Both edges disabled, only one pruned.
		symmetricTestChannel("e", "f", 100000, &testChannelPolicy{
			LastUpdate: timestamp,
			Disabled:   true,
		}, 3),
	}

	// We'll create our test graph and router backed with these test
	// channels we've created.
	testGraph, err := createTestGraphFromChannels(testChannels, "self")
	if err != nil {
		t.Fatalf("unable to create test graph: %v", err)
	}
	defer testGraph.cleanUp()

	const startingHeight = 100
	ctx, cleanUp := createTestCtxFromGraphInstanceAssumeValid(
		t, startingHeight, testGraph, assumeValid, false,
	)
	defer cleanUp()

	// All the channels should exist within the graph before pruning them
	// when not using AssumeChannelValid, otherwise we should have pruned
	// the last channel on startup.
	if !assumeValid {
		assertChannelsPruned(t, ctx.graph, testChannels)
	} else {
		// Sleep to allow the pruning to finish.
		time.Sleep(200 * time.Millisecond)

		prunedChannel := testChannels[len(testChannels)-1].ChannelID
		assertChannelsPruned(t, ctx.graph, testChannels, prunedChannel)
	}

	if err := ctx.router.pruneZombieChans(); err != nil {
		t.Fatalf("unable to prune zombie channels: %v", err)
	}

	// If we attempted to prune them without AssumeChannelValid being set,
	// none should be pruned. Otherwise the last channel should still be
	// pruned.
	if !assumeValid {
		assertChannelsPruned(t, ctx.graph, testChannels)
	} else {
		prunedChannel := testChannels[len(testChannels)-1].ChannelID
		assertChannelsPruned(t, ctx.graph, testChannels, prunedChannel)
	}
}

// TestFindPathFeeWeighting tests that the findPath method will properly prefer
// routes with lower fees over routes with lower time lock values. This is
// meant to exercise the fact that the internal findPath method ranks edges
// with the square of the total fee in order bias towards lower fees.
func TestFindPathFeeWeighting(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	var preImage [32]byte
	copy(preImage[:], bytes.Repeat([]byte{9}, 32))

	sourceNode, err := ctx.graph.SourceNode()
	if err != nil {
		t.Fatalf("unable to fetch source node: %v", err)
	}

	amt := lnwire.MilliSatoshi(100)

	target := ctx.aliases["luoji"]

	// We'll now attempt a path finding attempt using this set up. Due to
	// the edge weighting, we should select the direct path over the 2 hop
	// path even though the direct path has a higher potential time lock.
	path, err := dbFindPath(
		ctx.graph, nil, &mockBandwidthHints{},
		noRestrictions,
		testPathFindingConfig,
		sourceNode.PubKeyBytes, target, amt, 0,
	)
	if err != nil {
		t.Fatalf("unable to find path: %v", err)
	}

	// The route that was chosen should be exactly one hop, and should be
	// directly to luoji.
	if len(path) != 1 {
		t.Fatalf("expected path length of 1, instead was: %v", len(path))
	}
	if path[0].Node.Alias != "luoji" {
		t.Fatalf("wrong node: %v", path[0].Node.Alias)
	}
}

// TestIsStaleNode tests that the IsStaleNode method properly detects stale
// node announcements.
func TestIsStaleNode(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	// Before we can insert a node in to the database, we need to create a
	// channel that it's linked to.
	var (
		pub1 [33]byte
		pub2 [33]byte
	)
	copy(pub1[:], priv1.PubKey().SerializeCompressed())
	copy(pub2[:], priv2.PubKey().SerializeCompressed())

	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		10000, 500)
	if err != nil {
		t.Fatalf("unable to create channel edge: %v", err)
	}
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID.ToUint64(),
		NodeKey1Bytes:    pub1,
		NodeKey2Bytes:    pub2,
		BitcoinKey1Bytes: pub1,
		BitcoinKey2Bytes: pub2,
		AuthProof:        nil,
	}
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// Before we add the node, if we query for staleness, we should get
	// false, as we haven't added the full node.
	updateTimeStamp := time.Unix(123, 0)
	if ctx.router.IsStaleNode(pub1, updateTimeStamp) {
		t.Fatalf("incorrectly detected node as stale")
	}

	// With the node stub in the database, we'll add the fully node
	// announcement to the database.
	n1 := &channeldb.LightningNode{
		HaveNodeAnnouncement: true,
		LastUpdate:           updateTimeStamp,
		Addresses:            testAddrs,
		Color:                color.RGBA{1, 2, 3, 0},
		Alias:                "node11",
		AuthSigBytes:         testSig.Serialize(),
		Features:             testFeatures,
	}
	copy(n1.PubKeyBytes[:], priv1.PubKey().SerializeCompressed())
	if err := ctx.router.AddNode(n1); err != nil {
		t.Fatalf("could not add node: %v", err)
	}

	// If we use the same timestamp and query for staleness, we should get
	// true.
	if !ctx.router.IsStaleNode(pub1, updateTimeStamp) {
		t.Fatalf("failure to detect stale node update")
	}

	// If we update the timestamp and once again query for staleness, it
	// should report false.
	newTimeStamp := time.Unix(1234, 0)
	if ctx.router.IsStaleNode(pub1, newTimeStamp) {
		t.Fatalf("incorrectly detected node as stale")
	}
}

// TestIsKnownEdge tests that the IsKnownEdge method properly detects stale
// channel announcements.
func TestIsKnownEdge(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxSingleNode(t, startingBlockHeight)
	defer cleanUp()

	// First, we'll create a new channel edge (just the info) and insert it
	// into the database.
	var (
		pub1 [33]byte
		pub2 [33]byte
	)
	copy(pub1[:], priv1.PubKey().SerializeCompressed())
	copy(pub2[:], priv2.PubKey().SerializeCompressed())

	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		10000, 500)
	if err != nil {
		t.Fatalf("unable to create channel edge: %v", err)
	}
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID.ToUint64(),
		NodeKey1Bytes:    pub1,
		NodeKey2Bytes:    pub2,
		BitcoinKey1Bytes: pub1,
		BitcoinKey2Bytes: pub2,
		AuthProof:        nil,
	}
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// Now that the edge has been inserted, query is the router already
	// knows of the edge should return true.
	if !ctx.router.IsKnownEdge(*chanID) {
		t.Fatalf("router should detect edge as known")
	}
}

// TestIsStaleEdgePolicy tests that the IsStaleEdgePolicy properly detects
// stale channel edge update announcements.
func TestIsStaleEdgePolicy(t *testing.T) {
	t.Parallel()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromFile(
		t, startingBlockHeight, basicGraphFilePath,
	)
	defer cleanUp()

	// First, we'll create a new channel edge (just the info) and insert it
	// into the database.
	var (
		pub1 [33]byte
		pub2 [33]byte
	)
	copy(pub1[:], priv1.PubKey().SerializeCompressed())
	copy(pub2[:], priv2.PubKey().SerializeCompressed())

	fundingTx, _, chanID, err := createChannelEdge(ctx,
		bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(),
		10000, 500)
	if err != nil {
		t.Fatalf("unable to create channel edge: %v", err)
	}
	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	// If we query for staleness before adding the edge, we should get
	// false.
	updateTimeStamp := time.Unix(123, 0)
	if ctx.router.IsStaleEdgePolicy(*chanID, updateTimeStamp, 0) {
		t.Fatalf("router failed to detect fresh edge policy")
	}
	if ctx.router.IsStaleEdgePolicy(*chanID, updateTimeStamp, 1) {
		t.Fatalf("router failed to detect fresh edge policy")
	}

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:        chanID.ToUint64(),
		NodeKey1Bytes:    pub1,
		NodeKey2Bytes:    pub2,
		BitcoinKey1Bytes: pub1,
		BitcoinKey2Bytes: pub2,
		AuthProof:        nil,
	}
	if err := ctx.router.AddEdge(edge); err != nil {
		t.Fatalf("unable to add edge: %v", err)
	}

	// We'll also add two edge policies, one for each direction.
	edgePolicy := &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                updateTimeStamp,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}
	edgePolicy.ChannelFlags = 0
	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}

	edgePolicy = &channeldb.ChannelEdgePolicy{
		SigBytes:                  testSig.Serialize(),
		ChannelID:                 edge.ChannelID,
		LastUpdate:                updateTimeStamp,
		TimeLockDelta:             10,
		MinHTLC:                   1,
		FeeBaseMSat:               10,
		FeeProportionalMillionths: 10000,
	}
	edgePolicy.ChannelFlags = 1
	if err := ctx.router.UpdateEdge(edgePolicy); err != nil {
		t.Fatalf("unable to update edge policy: %v", err)
	}

	// Now that the edges have been added, an identical (chanID, flag,
	// timestamp) tuple for each edge should be detected as a stale edge.
	if !ctx.router.IsStaleEdgePolicy(*chanID, updateTimeStamp, 0) {
		t.Fatalf("router failed to detect stale edge policy")
	}
	if !ctx.router.IsStaleEdgePolicy(*chanID, updateTimeStamp, 1) {
		t.Fatalf("router failed to detect stale edge policy")
	}

	// If we now update the timestamp for both edges, the router should
	// detect that this tuple represents a fresh edge.
	updateTimeStamp = time.Unix(9999, 0)
	if ctx.router.IsStaleEdgePolicy(*chanID, updateTimeStamp, 0) {
		t.Fatalf("router failed to detect fresh edge policy")
	}
	if ctx.router.IsStaleEdgePolicy(*chanID, updateTimeStamp, 1) {
		t.Fatalf("router failed to detect fresh edge policy")
	}
}

// TestEmptyRoutesGenerateSphinxPacket tests that the generateSphinxPacket
// function is able to gracefully handle being passed a nil set of hops for the
// route by the caller.
func TestEmptyRoutesGenerateSphinxPacket(t *testing.T) {
	t.Parallel()

	sessionKey, _ := btcec.NewPrivateKey(btcec.S256())
	emptyRoute := &route.Route{}
	_, _, err := generateSphinxPacket(emptyRoute, testHash[:], sessionKey)
	if err != route.ErrNoRouteHopsProvided {
		t.Fatalf("expected empty hops error: instead got: %v", err)
	}
}

// TestUnknownErrorSource tests that if the source of an error is unknown, all
// edges along the route will be pruned.
func TestUnknownErrorSource(t *testing.T) {
	t.Parallel()

	// Setup a network. It contains two paths to c: a->b->c and an
	// alternative a->d->c.
	chanCapSat := btcutil.Amount(100000)
	testChannels := []*testChannel{
		symmetricTestChannel("a", "b", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 1),
		symmetricTestChannel("b", "c", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 3),
		symmetricTestChannel("a", "d", chanCapSat, &testChannelPolicy{
			Expiry:      144,
			FeeRate:     400,
			FeeBaseMsat: 100000,
			MinHTLC:     1,
			MaxHTLC:     lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 2),
		symmetricTestChannel("d", "c", chanCapSat, &testChannelPolicy{
			Expiry:      144,
			FeeRate:     400,
			FeeBaseMsat: 100000,
			MinHTLC:     1,
			MaxHTLC:     lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 4),
	}

	testGraph, err := createTestGraphFromChannels(testChannels, "a")
	defer testGraph.cleanUp()
	if err != nil {
		t.Fatalf("unable to create graph: %v", err)
	}

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromGraphInstance(
		t, startingBlockHeight, testGraph, false,
	)
	defer cleanUp()

	// Create a payment to node c.
	var payHash lntypes.Hash
	payment := LightningPayment{
		Target:      ctx.aliases["c"],
		Amount:      lnwire.NewMSatFromSatoshis(1000),
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
	}

	// We'll modify the SendToSwitch method so that it simulates hop b as a
	// node that returns an unparsable failure if approached via the a->b
	// channel.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			// If channel a->b is used, return an error without
			// source and message. The sender won't know the origin
			// of the error.
			if firstHop.ToUint64() == 1 {
				return [32]byte{},
					htlcswitch.ErrUnreadableFailureMessage
			}

			// Otherwise the payment succeeds.
			return lntypes.Preimage{}, nil
		})

	// Send off the payment request to the router. The expectation is that
	// the route a->b->c is tried first. An unreadable faiure is returned
	// which should pruning the channel a->b. We expect the payment to
	// succeed via a->d.
	_, _, err = ctx.router.SendPayment(&payment)
	if err != nil {
		t.Fatalf("expected payment to succeed, but got: %v", err)
	}

	// Next we modify payment result to return an unknown failure.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			// If channel a->b is used, simulate that the failure
			// couldn't be decoded (FailureMessage is nil).
			if firstHop.ToUint64() == 2 {
				return [32]byte{},
					htlcswitch.NewUnknownForwardingError(1)
			}

			// Otherwise the payment succeeds.
			return lntypes.Preimage{}, nil
		})

	// Send off the payment request to the router. We expect the payment to
	// fail because both routes have been pruned.
	payHash = lntypes.Hash{1}
	payment.paymentHash = &payHash
	_, _, err = ctx.router.SendPayment(&payment)
	if err == nil {
		t.Fatalf("expected payment to fail")
	}
}

// assertChannelsPruned ensures that only the given channels are pruned from the
// graph out of the set of all channels.
func assertChannelsPruned(t *testing.T, graph *channeldb.ChannelGraph,
	channels []*testChannel, prunedChanIDs ...uint64) {

	t.Helper()

	pruned := make(map[uint64]struct{}, len(channels))
	for _, chanID := range prunedChanIDs {
		pruned[chanID] = struct{}{}
	}

	for _, channel := range channels {
		_, shouldPrune := pruned[channel.ChannelID]
		_, _, exists, isZombie, err := graph.HasChannelEdge(
			channel.ChannelID,
		)
		if err != nil {
			t.Fatalf("unable to determine existence of "+
				"channel=%v in the graph: %v",
				channel.ChannelID, err)
		}
		if !shouldPrune && !exists {
			t.Fatalf("expected channel=%v to exist within "+
				"the graph", channel.ChannelID)
		}
		if shouldPrune && exists {
			t.Fatalf("expected channel=%v to not exist "+
				"within the graph", channel.ChannelID)
		}
		if !shouldPrune && isZombie {
			t.Fatalf("expected channel=%v to not be marked "+
				"as zombie", channel.ChannelID)
		}
		if shouldPrune && !isZombie {
			t.Fatalf("expected channel=%v to be marked as "+
				"zombie", channel.ChannelID)
		}
	}
}

// TestSendToRouteStructuredError asserts that SendToRoute returns a structured
// error.
func TestSendToRouteStructuredError(t *testing.T) {
	t.Parallel()

	// Setup a three node network.
	chanCapSat := btcutil.Amount(100000)
	testChannels := []*testChannel{
		symmetricTestChannel("a", "b", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 1),
		symmetricTestChannel("b", "c", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 2),
	}

	testGraph, err := createTestGraphFromChannels(testChannels, "a")
	if err != nil {
		t.Fatalf("unable to create graph: %v", err)
	}
	defer testGraph.cleanUp()

	const startingBlockHeight = 101
	ctx, cleanUp := createTestCtxFromGraphInstance(
		t, startingBlockHeight, testGraph, false,
	)
	defer cleanUp()

	// Set up an init channel for the control tower, such that we can make
	// sure the payment is initiated correctly.
	init := make(chan initArgs, 1)
	ctx.router.cfg.Control.(*mockControlTowerOld).init = init

	// Setup a route from source a to destination c. The route will be used
	// in a call to SendToRoute. SendToRoute also applies channel updates,
	// but it saves us from including RequestRoute in the test scope too.
	const payAmt = lnwire.MilliSatoshi(10000)
	hop1 := ctx.aliases["b"]
	hop2 := ctx.aliases["c"]
	hops := []*route.Hop{
		{
			ChannelID:     1,
			PubKeyBytes:   hop1,
			AmtToForward:  payAmt,
			LegacyPayload: true,
		},
		{
			ChannelID:     2,
			PubKeyBytes:   hop2,
			AmtToForward:  payAmt,
			LegacyPayload: true,
		},
	}

	rt, err := route.NewRouteFromHops(payAmt, 100, ctx.aliases["a"], hops)
	if err != nil {
		t.Fatalf("unable to create route: %v", err)
	}

	finalHopIndex := len(hops)
	testCases := map[int]lnwire.FailureMessage{
		finalHopIndex: lnwire.NewFailIncorrectDetails(payAmt, 100),
		1: &lnwire.FailFeeInsufficient{
			Update: lnwire.ChannelUpdate{},
		},
	}

	for failIndex, errorType := range testCases {
		failIndex := failIndex
		errorType := errorType

		t.Run(fmt.Sprintf("%T", errorType), func(t *testing.T) {
			// We'll modify the SendToSwitch method so that it
			// simulates a failed payment with an error originating
			// from the final hop in the route.
			ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
				func(firstHop lnwire.ShortChannelID) ([32]byte, error) {
					return [32]byte{}, htlcswitch.NewForwardingError(
						errorType, failIndex,
					)
				},
			)

			// The payment parameter is mostly redundant in
			// SendToRoute.  Can be left empty for this test.
			var payment lntypes.Hash

			// Send off the payment request to the router. The
			// specified route should be attempted and the channel
			// update should be received by router and ignored
			// because it is missing a valid
			// signature.
			_, err = ctx.router.SendToRoute(payment, rt)

			fErr, ok := err.(*htlcswitch.ForwardingError)
			require.True(
				t, ok, "expected forwarding error, got: %T", err,
			)

			require.IsType(
				t, errorType, fErr.WireMessage(),
				"expected type %T got %T", errorType,
				fErr.WireMessage(),
			)

			// Check that the correct values were used when
			// initiating the payment.
			select {
			case initVal := <-init:
				if initVal.c.Value != payAmt {
					t.Fatalf("expected %v, got %v", payAmt,
						initVal.c.Value)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("initPayment not called")
			}
		})
	}
}

// TestSendToRouteMultiShardSend checks that a 3-shard payment can be executed
// using SendToRoute.
func TestSendToRouteMultiShardSend(t *testing.T) {
	t.Parallel()

	ctx, cleanup := createTestCtxSingleNode(t, 0)
	defer cleanup()

	const numShards = 3
	const payAmt = lnwire.MilliSatoshi(numShards * 10000)
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	// Create a simple 1-hop route that we will use for all three shards.
	hops := []*route.Hop{
		{
			ChannelID:    1,
			PubKeyBytes:  node.PubKeyBytes,
			AmtToForward: payAmt / numShards,
			MPP:          record.NewMPP(payAmt, [32]byte{}),
		},
	}

	sourceNode, err := ctx.graph.SourceNode()
	if err != nil {
		t.Fatal(err)
	}

	rt, err := route.NewRouteFromHops(
		payAmt, 100, sourceNode.PubKeyBytes, hops,
	)
	if err != nil {
		t.Fatalf("unable to create route: %v", err)
	}

	// The first shard we send we'll fail immediately, to check that we are
	// still allowed to retry with other shards after a failed one.
	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {
			return [32]byte{}, htlcswitch.NewForwardingError(
				&lnwire.FailFeeInsufficient{
					Update: lnwire.ChannelUpdate{},
				}, 1,
			)
		})

	// The payment parameter is mostly redundant in SendToRoute. Can be left
	// empty for this test.
	var payment lntypes.Hash

	// Send the shard using the created route, and expect an error to be
	// returned.
	_, err = ctx.router.SendToRoute(payment, rt)
	if err == nil {
		t.Fatalf("expected forwarding error")
	}

	// Now we'll modify the SendToSwitch method again to wait until all
	// three shards are initiated before returning a result. We do this by
	// signalling when the method has been called, and then stop to wait
	// for the test to deliver the final result on the channel below.
	waitForResultSignal := make(chan struct{}, numShards)
	results := make(chan lntypes.Preimage, numShards)

	ctx.router.cfg.Payer.(*mockPaymentAttemptDispatcherOld).setPaymentResult(
		func(firstHop lnwire.ShortChannelID) ([32]byte, error) {

			// Signal that the shard has been initiated and is
			// waiting for a result.
			waitForResultSignal <- struct{}{}

			// Wait for a result before returning it.
			res, ok := <-results
			if !ok {
				return [32]byte{}, fmt.Errorf("failure")
			}
			return res, nil
		})

	// Launch three shards by calling SendToRoute in three goroutines,
	// returning their final error on the channel.
	errChan := make(chan error)
	successes := make(chan lntypes.Preimage)

	for i := 0; i < numShards; i++ {
		go func() {
			attempt, err := ctx.router.SendToRoute(payment, rt)
			if err != nil {
				errChan <- err
				return
			}

			successes <- attempt.Settle.Preimage
		}()
	}

	// Wait for all shards to signal they have been initiated.
	for i := 0; i < numShards; i++ {
		select {
		case <-waitForResultSignal:
		case <-time.After(5 * time.Second):
			t.Fatalf("not waiting for results")
		}
	}

	// Deliver a dummy preimage to all the shard handlers.
	preimage := lntypes.Preimage{}
	preimage[4] = 42
	for i := 0; i < numShards; i++ {
		results <- preimage
	}

	// Finally expect all shards to return with the above preimage.
	for i := 0; i < numShards; i++ {
		select {
		case p := <-successes:
			if p != preimage {
				t.Fatalf("preimage mismatch")
			}
		case err := <-errChan:
			t.Fatalf("unexpected error from SendToRoute: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatalf("result not received")
		}
	}
}

// TestSendToRouteMaxHops asserts that SendToRoute fails when using a route that
// exceeds the maximum number of hops.
func TestSendToRouteMaxHops(t *testing.T) {
	t.Parallel()

	// Setup a two node network.
	chanCapSat := btcutil.Amount(100000)
	testChannels := []*testChannel{
		symmetricTestChannel("a", "b", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 1),
	}

	testGraph, err := createTestGraphFromChannels(testChannels, "a")
	if err != nil {
		t.Fatalf("unable to create graph: %v", err)
	}
	defer testGraph.cleanUp()

	const startingBlockHeight = 101

	ctx, cleanUp := createTestCtxFromGraphInstance(
		t, startingBlockHeight, testGraph, false,
	)
	defer cleanUp()

	// Create a 30 hop route that exceeds the maximum hop limit.
	const payAmt = lnwire.MilliSatoshi(10000)
	hopA := ctx.aliases["a"]
	hopB := ctx.aliases["b"]

	var hops []*route.Hop
	for i := 0; i < 15; i++ {
		hops = append(hops, &route.Hop{
			ChannelID:     1,
			PubKeyBytes:   hopB,
			AmtToForward:  payAmt,
			LegacyPayload: true,
		})

		hops = append(hops, &route.Hop{
			ChannelID:     1,
			PubKeyBytes:   hopA,
			AmtToForward:  payAmt,
			LegacyPayload: true,
		})
	}

	rt, err := route.NewRouteFromHops(payAmt, 100, ctx.aliases["a"], hops)
	if err != nil {
		t.Fatalf("unable to create route: %v", err)
	}

	// Send off the payment request to the router. We expect an error back
	// indicating that the route is too long.
	var payment lntypes.Hash
	_, err = ctx.router.SendToRoute(payment, rt)
	if err != route.ErrMaxRouteHopsExceeded {
		t.Fatalf("expected ErrMaxRouteHopsExceeded, but got %v", err)
	}
}

// TestBuildRoute tests whether correct routes are built.
func TestBuildRoute(t *testing.T) {
	// Setup a three node network.
	chanCapSat := btcutil.Amount(100000)
	paymentAddrFeatures := lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(lnwire.PaymentAddrOptional),
		lnwire.Features,
	)
	testChannels := []*testChannel{
		// Create two local channels from a. The bandwidth is estimated
		// in this test as the channel capacity. For building routes, we
		// expected the channel with the largest estimated bandwidth to
		// be selected.
		symmetricTestChannel("a", "b", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 20000,
			MinHTLC: lnwire.NewMSatFromSatoshis(5),
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 1),
		symmetricTestChannel("a", "b", chanCapSat/2, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 20000,
			MinHTLC: lnwire.NewMSatFromSatoshis(5),
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat / 2),
		}, 6),

		// Create two channels from b to c. For building routes, we
		// expect the lowest cost channel to be selected. Note that this
		// isn't a situation that we are expecting in reality. Routing
		// nodes are recommended to keep their channel policies towards
		// the same peer identical.
		symmetricTestChannel("b", "c", chanCapSat, &testChannelPolicy{
			Expiry:   144,
			FeeRate:  50000,
			MinHTLC:  lnwire.NewMSatFromSatoshis(20),
			MaxHTLC:  lnwire.NewMSatFromSatoshis(120),
			Features: paymentAddrFeatures,
		}, 2),
		symmetricTestChannel("b", "c", chanCapSat, &testChannelPolicy{
			Expiry:   144,
			FeeRate:  60000,
			MinHTLC:  lnwire.NewMSatFromSatoshis(20),
			MaxHTLC:  lnwire.NewMSatFromSatoshis(120),
			Features: paymentAddrFeatures,
		}, 7),

		symmetricTestChannel("a", "e", chanCapSat, &testChannelPolicy{
			Expiry:   144,
			FeeRate:  80000,
			MinHTLC:  lnwire.NewMSatFromSatoshis(5),
			MaxHTLC:  lnwire.NewMSatFromSatoshis(10),
			Features: paymentAddrFeatures,
		}, 5),
		symmetricTestChannel("e", "c", chanCapSat, &testChannelPolicy{
			Expiry:   144,
			FeeRate:  100000,
			MinHTLC:  lnwire.NewMSatFromSatoshis(20),
			MaxHTLC:  lnwire.NewMSatFromSatoshis(chanCapSat),
			Features: paymentAddrFeatures,
		}, 4),
	}

	testGraph, err := createTestGraphFromChannels(testChannels, "a")
	if err != nil {
		t.Fatalf("unable to create graph: %v", err)
	}
	defer testGraph.cleanUp()

	const startingBlockHeight = 101

	ctx, cleanUp := createTestCtxFromGraphInstance(
		t, startingBlockHeight, testGraph, false,
	)
	defer cleanUp()

	checkHops := func(rt *route.Route, expected []uint64,
		payAddr [32]byte) {

		t.Helper()

		if len(rt.Hops) != len(expected) {
			t.Fatal("hop count mismatch")
		}
		for i, hop := range rt.Hops {
			if hop.ChannelID != expected[i] {
				t.Fatalf("expected channel %v at pos %v, but "+
					"got channel %v",
					expected[i], i, hop.ChannelID)
			}
		}

		lastHop := rt.Hops[len(rt.Hops)-1]
		require.NotNil(t, lastHop.MPP)
		require.Equal(t, lastHop.MPP.PaymentAddr(), payAddr)
	}

	var payAddr [32]byte
	_, err = rand.Read(payAddr[:])
	require.NoError(t, err)

	// Create hop list from the route node pubkeys.
	hops := []route.Vertex{
		ctx.aliases["b"], ctx.aliases["c"],
	}
	amt := lnwire.NewMSatFromSatoshis(100)

	// Build the route for the given amount.
	rt, err := ctx.router.BuildRoute(
		&amt, hops, nil, 40, &payAddr,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Check that we get the expected route back. The total amount should be
	// the amount to deliver to hop c (100 sats) plus the max fee for the
	// connection b->c (6 sats).
	checkHops(rt, []uint64{1, 7}, payAddr)
	if rt.TotalAmount != 106000 {
		t.Fatalf("unexpected total amount %v", rt.TotalAmount)
	}

	// Build the route for the minimum amount.
	rt, err = ctx.router.BuildRoute(
		nil, hops, nil, 40, &payAddr,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Check that we get the expected route back. The minimum that we can
	// send from b to c is 20 sats. Hop b charges 1200 msat for the
	// forwarding. The channel between hop a and b can carry amounts in the
	// range [5, 100], so 21200 msats is the minimum amount for this route.
	checkHops(rt, []uint64{1, 7}, payAddr)
	if rt.TotalAmount != 21200 {
		t.Fatalf("unexpected total amount %v", rt.TotalAmount)
	}

	// Test a route that contains incompatible channel htlc constraints.
	// There is no amount that can pass through both channel 5 and 4.
	hops = []route.Vertex{
		ctx.aliases["e"], ctx.aliases["c"],
	}
	_, err = ctx.router.BuildRoute(
		nil, hops, nil, 40, nil,
	)
	errNoChannel, ok := err.(ErrNoChannel)
	if !ok {
		t.Fatalf("expected incompatible policies error, but got %v",
			err)
	}
	if errNoChannel.position != 0 {
		t.Fatalf("unexpected no channel error position")
	}
	if errNoChannel.fromNode != ctx.aliases["a"] {
		t.Fatalf("unexpected no channel error node")
	}
}

// edgeCreationModifier is an enum-like type used to modify steps that are
// skipped when creating a channel in the test context.
type edgeCreationModifier uint8

const (
	// edgeCreationNoFundingTx is used to skip adding the funding
	// transaction of an edge to the chain.
	edgeCreationNoFundingTx edgeCreationModifier = iota

	// edgeCreationNoUTXO is used to skip adding the UTXO of a channel to
	// the UTXO set.
	edgeCreationNoUTXO

	// edgeCreationBadScript is used to create the edge, but use the wrong
	// scrip which should cause it to fail output validation.
	edgeCreationBadScript
)

// newChannelEdgeInfo is a helper function used to create a new channel edge,
// possibly skipping adding it to parts of the chain/state as well.
func newChannelEdgeInfo(ctx *testCtx, fundingHeight uint32,
	ecm edgeCreationModifier) (*channeldb.ChannelEdgeInfo, error) {

	node1, err := createTestNode()
	if err != nil {
		return nil, err
	}
	node2, err := createTestNode()
	if err != nil {
		return nil, err
	}

	fundingTx, _, chanID, err := createChannelEdge(
		ctx, bitcoinKey1.SerializeCompressed(),
		bitcoinKey2.SerializeCompressed(), 100, fundingHeight,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create edge: %w", err)
	}

	edge := &channeldb.ChannelEdgeInfo{
		ChannelID:     chanID.ToUint64(),
		NodeKey1Bytes: node1.PubKeyBytes,
		NodeKey2Bytes: node2.PubKeyBytes,
	}
	copy(edge.BitcoinKey1Bytes[:], bitcoinKey1.SerializeCompressed())
	copy(edge.BitcoinKey2Bytes[:], bitcoinKey2.SerializeCompressed())

	if ecm == edgeCreationNoFundingTx {
		return edge, nil
	}

	fundingBlock := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{fundingTx},
	}
	ctx.chain.addBlock(fundingBlock, chanID.BlockHeight, chanID.BlockHeight)

	if ecm == edgeCreationNoUTXO {
		ctx.chain.delUtxo(wire.OutPoint{
			Hash: fundingTx.TxHash(),
		})
	}

	if ecm == edgeCreationBadScript {
		fundingTx.TxOut[0].PkScript[0] ^= 1
	}

	return edge, nil
}

func assertChanChainRejection(t *testing.T, ctx *testCtx,
	edge *channeldb.ChannelEdgeInfo, failCode errorCode) {

	t.Helper()

	err := ctx.router.AddEdge(edge)
	if !IsError(err, failCode) {
		t.Fatalf("validation should have failed: %v", err)
	}

	// This channel should now be present in the zombie channel index.
	_, _, _, isZombie, err := ctx.graph.HasChannelEdge(
		edge.ChannelID,
	)
	require.Nil(t, err)
	require.True(t, isZombie, "edge should be marked as zombie")
}

// TestChannelOnChainRejectionZombie tests that if we fail validating a channel
// due to some sort of on-chain rejection (no funding transaction, or invalid
// UTXO), then we'll mark the channel as a zombie.
func TestChannelOnChainRejectionZombie(t *testing.T) {
	t.Parallel()

	ctx, cleanup := createTestCtxSingleNode(t, 0)
	defer cleanup()

	// To start,  we'll make an edge for the channel, but we won't add the
	// funding transaction to the mock blockchain, which should cause the
	// validation to fail below.
	edge, err := newChannelEdgeInfo(ctx, 1, edgeCreationNoFundingTx)
	require.Nil(t, err)

	// We expect this to fail as the transaction isn't present in the
	// chain (nor the block).
	assertChanChainRejection(t, ctx, edge, ErrNoFundingTransaction)

	// Next, we'll make another channel edge, but actually add it to the
	// graph this time.
	edge, err = newChannelEdgeInfo(ctx, 2, edgeCreationNoUTXO)
	require.Nil(t, err)

	// Instead now, we'll remove it from the set of UTXOs which should
	// cause the spentness validation to fail.
	assertChanChainRejection(t, ctx, edge, ErrChannelSpent)

	// If we cause the funding transaction the chain to fail validation, we
	// should see similar behavior.
	edge, err = newChannelEdgeInfo(ctx, 3, edgeCreationBadScript)
	require.Nil(t, err)
	assertChanChainRejection(t, ctx, edge, ErrInvalidFundingOutput)
}

func createDummyTestGraph(t *testing.T) *testGraphInstance {
	// Setup two simple channels such that we can mock sending along this
	// route.
	chanCapSat := btcutil.Amount(100000)
	testChannels := []*testChannel{
		symmetricTestChannel("a", "b", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 1),
		symmetricTestChannel("b", "c", chanCapSat, &testChannelPolicy{
			Expiry:  144,
			FeeRate: 400,
			MinHTLC: 1,
			MaxHTLC: lnwire.NewMSatFromSatoshis(chanCapSat),
		}, 2),
	}

	testGraph, err := createTestGraphFromChannels(testChannels, "a")
	require.NoError(t, err, "failed to create graph")
	return testGraph
}

func createDummyLightningPayment(t *testing.T,
	target route.Vertex, amt lnwire.MilliSatoshi) *LightningPayment {

	var preImage lntypes.Preimage
	_, err := rand.Read(preImage[:])
	require.NoError(t, err, "unable to generate preimage")

	payHash := preImage.Hash()

	return &LightningPayment{
		Target:      target,
		Amount:      amt,
		FeeLimit:    noFeeLimit,
		paymentHash: &payHash,
	}
}

// TestSendMPPaymentSucceed tests that we can successfully send a MPPayment via
// router.SendPayment. This test mainly focuses on testing the logic of the
// method resumePayment is implemented as expected.
func TestSendMPPaymentSucceed(t *testing.T) {
	const startingBlockHeight = 101

	// Create mockers to initialize the router.
	controlTower := &mockControlTower{}
	sessionSource := &mockPaymentSessionSource{}
	missionControl := &mockMissionControl{}
	payer := &mockPaymentAttemptDispatcher{}
	chain := newMockChain(startingBlockHeight)
	chainView := newMockChainView(chain)
	testGraph := createDummyTestGraph(t)

	// Define the behavior of the mockers to the point where we can
	// successfully start the router.
	controlTower.On("FetchInFlightPayments").Return(
		[]*channeldb.MPPayment{}, nil,
	)
	payer.On("CleanStore", mock.Anything).Return(nil)

	// Create and start the router.
	router, err := New(Config{
		Control:        controlTower,
		SessionSource:  sessionSource,
		MissionControl: missionControl,
		Payer:          payer,

		// TODO(yy): create new mocks for the chain and chainview.
		Chain:     chain,
		ChainView: chainView,

		// TODO(yy): mock the graph once it's changed into interface.
		Graph: testGraph.graph,

		Clock:              clock.NewTestClock(time.Unix(1, 0)),
		GraphPruneInterval: time.Hour * 2,
		NextPaymentID: func() (uint64, error) {
			next := atomic.AddUint64(&uniquePaymentID, 1)
			return next, nil
		},
	})
	require.NoError(t, err, "failed to create router")

	// Make sure the router can start and stop without error.
	require.NoError(t, router.Start(), "router failed to start")
	defer func() {
		require.NoError(t, router.Stop(), "router failed to stop")
	}()

	// Once the router is started, check that the mocked methods are called
	// as expected.
	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)

	// Mock the methods to the point where we are inside the function
	// resumePayment.
	paymentAmt := lnwire.MilliSatoshi(10000)
	req := createDummyLightningPayment(
		t, testGraph.aliasMap["c"], paymentAmt,
	)
	identifier := lntypes.Hash(req.Identifier())
	session := &mockPaymentSession{}
	sessionSource.On("NewPaymentSession", req).Return(session, nil)
	controlTower.On("InitPayment", identifier, mock.Anything).Return(nil)

	// The following mocked methods are called inside resumePayment. Note
	// that the payment object below will determine the state of the
	// paymentLifecycle.
	payment := &channeldb.MPPayment{}
	controlTower.On("FetchPayment", identifier).Return(payment, nil)

	// Create a route that can send 1/4 of the total amount. This value
	// will be returned by calling RequestRoute.
	shard, err := createTestRoute(paymentAmt/4, testGraph.aliasMap)
	require.NoError(t, err, "failed to create route")
	session.On("RequestRoute",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(shard, nil)

	// Make a new htlc attempt with zero fee and append it to the payment's
	// HTLCs when calling RegisterAttempt.
	activeAttempt := makeActiveAttempt(int(paymentAmt/4), 0)
	controlTower.On("RegisterAttempt",
		identifier, mock.Anything,
	).Return(nil).Run(func(args mock.Arguments) {
		payment.HTLCs = append(payment.HTLCs, activeAttempt)
	})

	// Create a buffered chan and it will be returned by GetPaymentResult.
	payer.resultChan = make(chan *htlcswitch.PaymentResult, 10)
	payer.On("GetPaymentResult",
		mock.Anything, identifier, mock.Anything,
	).Run(func(args mock.Arguments) {
		// Before the mock method is returned, we send the result to
		// the read-only chan.
		payer.resultChan <- &htlcswitch.PaymentResult{}
	})

	// Simple mocking the rest.
	payer.On("SendHTLC",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(nil)
	missionControl.On("ReportPaymentSuccess",
		mock.Anything, mock.Anything,
	).Return(nil)

	// Mock SettleAttempt by changing one of the HTLCs to be settled.
	preimage := lntypes.Preimage{1, 2, 3}
	settledAttempt := makeSettledAttempt(
		int(paymentAmt/4), 0, preimage,
	)
	controlTower.On("SettleAttempt",
		identifier, mock.Anything, mock.Anything,
	).Return(&settledAttempt, nil).Run(func(args mock.Arguments) {
		// Whenever this method is invoked, we will mark the first
		// active attempt settled and exit.
		for i, attempt := range payment.HTLCs {
			if attempt.Settle == nil {
				attempt.Settle = &channeldb.HTLCSettleInfo{
					Preimage: preimage,
				}
				payment.HTLCs[i] = attempt
				return
			}
		}
	})

	// Call the actual method SendPayment on router. This is place inside a
	// goroutine so we can set a timeout for the whole test, in case
	// anything goes wrong and the test never finishes.
	done := make(chan struct{})
	var p lntypes.Hash
	go func() {
		p, _, err = router.SendPayment(req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("SendPayment didn't exit")
	}

	// Finally, validate the returned values and check that the mock
	// methods are called as expected.
	require.NoError(t, err, "send payment failed")
	require.EqualValues(t, preimage, p, "preimage not match")

	// Note that we also implicitly check the methods such as FailAttempt,
	// ReportPaymentFail, etc, are not called because we never mocked them
	// in this test. If any of the unexpected methods was called, the test
	// would fail.
	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)
	sessionSource.AssertExpectations(t)
	session.AssertExpectations(t)
	missionControl.AssertExpectations(t)
}

// TestSendMPPaymentSucceedOnExtraShards tests that we need extra attempts if
// there are failed ones,so that a payment is successfully sent. This test
// mainly focuses on testing the logic of the method resumePayment is
// implemented as expected.
func TestSendMPPaymentSucceedOnExtraShards(t *testing.T) {
	const startingBlockHeight = 101

	// Create mockers to initialize the router.
	controlTower := &mockControlTower{}
	sessionSource := &mockPaymentSessionSource{}
	missionControl := &mockMissionControl{}
	payer := &mockPaymentAttemptDispatcher{}
	chain := newMockChain(startingBlockHeight)
	chainView := newMockChainView(chain)
	testGraph := createDummyTestGraph(t)

	// Define the behavior of the mockers to the point where we can
	// successfully start the router.
	controlTower.On("FetchInFlightPayments").Return(
		[]*channeldb.MPPayment{}, nil,
	)
	payer.On("CleanStore", mock.Anything).Return(nil)

	// Create and start the router.
	router, err := New(Config{
		Control:        controlTower,
		SessionSource:  sessionSource,
		MissionControl: missionControl,
		Payer:          payer,

		// TODO(yy): create new mocks for the chain and chainview.
		Chain:     chain,
		ChainView: chainView,

		// TODO(yy): mock the graph once it's changed into interface.
		Graph: testGraph.graph,

		Clock:              clock.NewTestClock(time.Unix(1, 0)),
		GraphPruneInterval: time.Hour * 2,
		NextPaymentID: func() (uint64, error) {
			next := atomic.AddUint64(&uniquePaymentID, 1)
			return next, nil
		},
	})
	require.NoError(t, err, "failed to create router")

	// Make sure the router can start and stop without error.
	require.NoError(t, router.Start(), "router failed to start")
	defer func() {
		require.NoError(t, router.Stop(), "router failed to stop")
	}()

	// Once the router is started, check that the mocked methods are called
	// as expected.
	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)

	// Mock the methods to the point where we are inside the function
	// resumePayment.
	paymentAmt := lnwire.MilliSatoshi(20000)
	req := createDummyLightningPayment(
		t, testGraph.aliasMap["c"], paymentAmt,
	)
	identifier := lntypes.Hash(req.Identifier())
	session := &mockPaymentSession{}
	sessionSource.On("NewPaymentSession", req).Return(session, nil)
	controlTower.On("InitPayment", identifier, mock.Anything).Return(nil)

	// The following mocked methods are called inside resumePayment. Note
	// that the payment object below will determine the state of the
	// paymentLifecycle.
	payment := &channeldb.MPPayment{}
	controlTower.On("FetchPayment", identifier).Return(payment, nil)

	// Create a route that can send 1/4 of the total amount. This value
	// will be returned by calling RequestRoute.
	shard, err := createTestRoute(paymentAmt/4, testGraph.aliasMap)
	require.NoError(t, err, "failed to create route")
	session.On("RequestRoute",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(shard, nil)

	// Make a new htlc attempt with zero fee and append it to the payment's
	// HTLCs when calling RegisterAttempt.
	activeAttempt := makeActiveAttempt(int(paymentAmt/4), 0)
	controlTower.On("RegisterAttempt",
		identifier, mock.Anything,
	).Return(nil).Run(func(args mock.Arguments) {
		payment.HTLCs = append(payment.HTLCs, activeAttempt)
	})

	// Create a buffered chan and it will be returned by GetPaymentResult.
	payer.resultChan = make(chan *htlcswitch.PaymentResult, 10)

	// We use the failAttemptCount to track how many attempts we want to
	// fail. Each time the following mock method is called, the count gets
	// updated.
	failAttemptCount := 0
	payer.On("GetPaymentResult",
		mock.Anything, identifier, mock.Anything,
	).Run(func(args mock.Arguments) {
		// Before the mock method is returned, we send the result to
		// the read-only chan.

		// Update the counter.
		failAttemptCount++

		// We will make the first two attempts failed with temporary
		// error.
		if failAttemptCount <= 2 {
			payer.resultChan <- &htlcswitch.PaymentResult{
				Error: htlcswitch.NewForwardingError(
					&lnwire.FailTemporaryChannelFailure{},
					1,
				),
			}
			return
		}

		// Otherwise we will mark the attempt succeeded.
		payer.resultChan <- &htlcswitch.PaymentResult{}
	})

	// Mock the FailAttempt method to fail one of the attempts.
	var failedAttempt channeldb.HTLCAttempt
	controlTower.On("FailAttempt",
		identifier, mock.Anything, mock.Anything,
	).Return(&failedAttempt, nil).Run(func(args mock.Arguments) {
		// Whenever this method is invoked, we will mark the first
		// active attempt as failed and exit.
		for i, attempt := range payment.HTLCs {
			if attempt.Settle != nil || attempt.Failure != nil {
				continue
			}

			attempt.Failure = &channeldb.HTLCFailInfo{}
			failedAttempt = attempt
			payment.HTLCs[i] = attempt
			return
		}

	})

	// Setup ReportPaymentFail to return nil reason and error so the
	// payment won't fail.
	missionControl.On("ReportPaymentFail",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, nil)

	// Simple mocking the rest.
	payer.On("SendHTLC",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(nil)
	missionControl.On("ReportPaymentSuccess",
		mock.Anything, mock.Anything,
	).Return(nil)

	// Mock SettleAttempt by changing one of the HTLCs to be settled.
	preimage := lntypes.Preimage{1, 2, 3}
	settledAttempt := makeSettledAttempt(
		int(paymentAmt/4), 0, preimage,
	)
	controlTower.On("SettleAttempt",
		identifier, mock.Anything, mock.Anything,
	).Return(&settledAttempt, nil).Run(func(args mock.Arguments) {
		// Whenever this method is invoked, we will mark the first
		// active attempt settled and exit.
		for i, attempt := range payment.HTLCs {
			if attempt.Settle != nil || attempt.Failure != nil {
				continue
			}

			attempt.Settle = &channeldb.HTLCSettleInfo{
				Preimage: preimage,
			}
			payment.HTLCs[i] = attempt
			return
		}
	})

	// Call the actual method SendPayment on router. This is place inside a
	// goroutine so we can set a timeout for the whole test, in case
	// anything goes wrong and the test never finishes.
	done := make(chan struct{})
	var p lntypes.Hash
	go func() {
		p, _, err = router.SendPayment(req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("SendPayment didn't exit")
	}

	// Finally, validate the returned values and check that the mock
	// methods are called as expected.
	require.NoError(t, err, "send payment failed")
	require.EqualValues(t, preimage, p, "preimage not match")

	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)
	sessionSource.AssertExpectations(t)
	session.AssertExpectations(t)
	missionControl.AssertExpectations(t)
}

// TestSendMPPaymentFailed tests that when one of the shard fails with a
// terminal error, the router will stop attempting and the payment will fail.
// This test mainly focuses on testing the logic of the method resumePayment
// is implemented as expected.
func TestSendMPPaymentFailed(t *testing.T) {
	const startingBlockHeight = 101

	// Create mockers to initialize the router.
	controlTower := &mockControlTower{}
	sessionSource := &mockPaymentSessionSource{}
	missionControl := &mockMissionControl{}
	payer := &mockPaymentAttemptDispatcher{}
	chain := newMockChain(startingBlockHeight)
	chainView := newMockChainView(chain)
	testGraph := createDummyTestGraph(t)

	// Define the behavior of the mockers to the point where we can
	// successfully start the router.
	controlTower.On("FetchInFlightPayments").Return(
		[]*channeldb.MPPayment{}, nil,
	)
	payer.On("CleanStore", mock.Anything).Return(nil)

	// Create and start the router.
	router, err := New(Config{
		Control:        controlTower,
		SessionSource:  sessionSource,
		MissionControl: missionControl,
		Payer:          payer,

		// TODO(yy): create new mocks for the chain and chainview.
		Chain:     chain,
		ChainView: chainView,

		// TODO(yy): mock the graph once it's changed into interface.
		Graph: testGraph.graph,

		Clock:              clock.NewTestClock(time.Unix(1, 0)),
		GraphPruneInterval: time.Hour * 2,
		NextPaymentID: func() (uint64, error) {
			next := atomic.AddUint64(&uniquePaymentID, 1)
			return next, nil
		},
	})
	require.NoError(t, err, "failed to create router")

	// Make sure the router can start and stop without error.
	require.NoError(t, router.Start(), "router failed to start")
	defer func() {
		require.NoError(t, router.Stop(), "router failed to stop")
	}()

	// Once the router is started, check that the mocked methods are called
	// as expected.
	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)

	// Mock the methods to the point where we are inside the function
	// resumePayment.
	paymentAmt := lnwire.MilliSatoshi(10000)
	req := createDummyLightningPayment(
		t, testGraph.aliasMap["c"], paymentAmt,
	)
	identifier := lntypes.Hash(req.Identifier())
	session := &mockPaymentSession{}
	sessionSource.On("NewPaymentSession", req).Return(session, nil)
	controlTower.On("InitPayment", identifier, mock.Anything).Return(nil)

	// The following mocked methods are called inside resumePayment. Note
	// that the payment object below will determine the state of the
	// paymentLifecycle.
	payment := &channeldb.MPPayment{}
	controlTower.On("FetchPayment", identifier).Return(payment, nil)

	// Create a route that can send 1/4 of the total amount. This value
	// will be returned by calling RequestRoute.
	shard, err := createTestRoute(paymentAmt/4, testGraph.aliasMap)
	require.NoError(t, err, "failed to create route")
	session.On("RequestRoute",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(shard, nil)

	// Make a new htlc attempt with zero fee and append it to the payment's
	// HTLCs when calling RegisterAttempt.
	activeAttempt := makeActiveAttempt(int(paymentAmt/4), 0)
	controlTower.On("RegisterAttempt",
		identifier, mock.Anything,
	).Return(nil).Run(func(args mock.Arguments) {
		payment.HTLCs = append(payment.HTLCs, activeAttempt)
	})

	// Create a buffered chan and it will be returned by GetPaymentResult.
	payer.resultChan = make(chan *htlcswitch.PaymentResult, 10)

	// We use the failAttemptCount to track how many attempts we want to
	// fail. Each time the following mock method is called, the count gets
	// updated.
	failAttemptCount := 0
	payer.On("GetPaymentResult",
		mock.Anything, identifier, mock.Anything,
	).Run(func(args mock.Arguments) {
		// Before the mock method is returned, we send the result to
		// the read-only chan.

		// Update the counter.
		failAttemptCount++

		// We fail the first attempt with terminal error.
		if failAttemptCount == 1 {
			payer.resultChan <- &htlcswitch.PaymentResult{
				Error: htlcswitch.NewForwardingError(
					&lnwire.FailIncorrectDetails{},
					1,
				),
			}
			return

		}

		// We will make the rest attempts failed with temporary error.
		payer.resultChan <- &htlcswitch.PaymentResult{
			Error: htlcswitch.NewForwardingError(
				&lnwire.FailTemporaryChannelFailure{},
				1,
			),
		}
	})

	// Mock the FailAttempt method to fail one of the attempts.
	var failedAttempt channeldb.HTLCAttempt
	controlTower.On("FailAttempt",
		identifier, mock.Anything, mock.Anything,
	).Return(&failedAttempt, nil).Run(func(args mock.Arguments) {
		// Whenever this method is invoked, we will mark the first
		// active attempt as failed and exit.
		for i, attempt := range payment.HTLCs {
			if attempt.Settle != nil || attempt.Failure != nil {
				continue
			}

			attempt.Failure = &channeldb.HTLCFailInfo{}
			failedAttempt = attempt
			payment.HTLCs[i] = attempt
			return
		}

	})

	// Setup ReportPaymentFail to return nil reason and error so the
	// payment won't fail.
	var called bool
	failureReason := channeldb.FailureReasonPaymentDetails
	missionControl.On("ReportPaymentFail",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, nil).Run(func(args mock.Arguments) {
		// We only return the terminal error once, thus when the method
		// is called, we will return it with a nil error.
		if called {
			missionControl.failReason = nil
			return
		}

		// If it's the first time calling this method, we will return a
		// terminal error.
		missionControl.failReason = &failureReason
		payment.FailureReason = &failureReason
		called = true
	})

	// Simple mocking the rest.
	controlTower.On("Fail", identifier, failureReason).Return(nil)
	payer.On("SendHTLC",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(nil)

	// Call the actual method SendPayment on router. This is place inside a
	// goroutine so we can set a timeout for the whole test, in case
	// anything goes wrong and the test never finishes.
	done := make(chan struct{})
	var p lntypes.Hash
	go func() {
		p, _, err = router.SendPayment(req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("SendPayment didn't exit")
	}

	// Finally, validate the returned values and check that the mock
	// methods are called as expected.
	require.Error(t, err, "expected send payment error")
	require.EqualValues(t, [32]byte{}, p, "preimage not match")

	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)
	sessionSource.AssertExpectations(t)
	session.AssertExpectations(t)
	missionControl.AssertExpectations(t)
}

// TestSendMPPaymentFailedWithShardsInFlight tests that when the payment is in
// terminal state, even if we have shards in flight, we still fail the payment
// and exit. This test mainly focuses on testing the logic of the method
// resumePayment is implemented as expected.
func TestSendMPPaymentFailedWithShardsInFlight(t *testing.T) {
	const startingBlockHeight = 101

	// Create mockers to initialize the router.
	controlTower := &mockControlTower{}
	sessionSource := &mockPaymentSessionSource{}
	missionControl := &mockMissionControl{}
	payer := &mockPaymentAttemptDispatcher{}
	chain := newMockChain(startingBlockHeight)
	chainView := newMockChainView(chain)
	testGraph := createDummyTestGraph(t)

	// Define the behavior of the mockers to the point where we can
	// successfully start the router.
	controlTower.On("FetchInFlightPayments").Return(
		[]*channeldb.MPPayment{}, nil,
	)
	payer.On("CleanStore", mock.Anything).Return(nil)

	// Create and start the router.
	router, err := New(Config{
		Control:        controlTower,
		SessionSource:  sessionSource,
		MissionControl: missionControl,
		Payer:          payer,

		// TODO(yy): create new mocks for the chain and chainview.
		Chain:     chain,
		ChainView: chainView,

		// TODO(yy): mock the graph once it's changed into interface.
		Graph: testGraph.graph,

		Clock:              clock.NewTestClock(time.Unix(1, 0)),
		GraphPruneInterval: time.Hour * 2,
		NextPaymentID: func() (uint64, error) {
			next := atomic.AddUint64(&uniquePaymentID, 1)
			return next, nil
		},
	})
	require.NoError(t, err, "failed to create router")

	// Make sure the router can start and stop without error.
	require.NoError(t, router.Start(), "router failed to start")
	defer func() {
		require.NoError(t, router.Stop(), "router failed to stop")
	}()

	// Once the router is started, check that the mocked methods are called
	// as expected.
	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)

	// Mock the methods to the point where we are inside the function
	// resumePayment.
	paymentAmt := lnwire.MilliSatoshi(10000)
	req := createDummyLightningPayment(
		t, testGraph.aliasMap["c"], paymentAmt,
	)
	identifier := lntypes.Hash(req.Identifier())
	session := &mockPaymentSession{}
	sessionSource.On("NewPaymentSession", req).Return(session, nil)
	controlTower.On("InitPayment", identifier, mock.Anything).Return(nil)

	// The following mocked methods are called inside resumePayment. Note
	// that the payment object below will determine the state of the
	// paymentLifecycle.
	payment := &channeldb.MPPayment{}
	controlTower.On("FetchPayment", identifier).Return(payment, nil)

	// Create a route that can send 1/4 of the total amount. This value
	// will be returned by calling RequestRoute.
	shard, err := createTestRoute(paymentAmt/4, testGraph.aliasMap)
	require.NoError(t, err, "failed to create route")
	session.On("RequestRoute",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(shard, nil)

	// Make a new htlc attempt with zero fee and append it to the payment's
	// HTLCs when calling RegisterAttempt.
	activeAttempt := makeActiveAttempt(int(paymentAmt/4), 0)
	controlTower.On("RegisterAttempt",
		identifier, mock.Anything,
	).Return(nil).Run(func(args mock.Arguments) {
		payment.HTLCs = append(payment.HTLCs, activeAttempt)
	})

	// Create a buffered chan and it will be returned by GetPaymentResult.
	payer.resultChan = make(chan *htlcswitch.PaymentResult, 10)

	// We use the failAttemptCount to track how many attempts we want to
	// fail. Each time the following mock method is called, the count gets
	// updated.
	failAttemptCount := 0
	payer.On("GetPaymentResult",
		mock.Anything, identifier, mock.Anything,
	).Run(func(args mock.Arguments) {
		// Before the mock method is returned, we send the result to
		// the read-only chan.

		// Update the counter.
		failAttemptCount++

		// We fail the first attempt with terminal error.
		if failAttemptCount == 1 {
			payer.resultChan <- &htlcswitch.PaymentResult{
				Error: htlcswitch.NewForwardingError(
					&lnwire.FailIncorrectDetails{},
					1,
				),
			}
			return

		}

		// For the rest attempts we will NOT send anything to the
		// resultChan, thus making all the shards in active state,
		// neither settled or failed.
	})

	// Mock the FailAttempt method to fail EXACTLY once.
	var failedAttempt channeldb.HTLCAttempt
	controlTower.On("FailAttempt",
		identifier, mock.Anything, mock.Anything,
	).Return(&failedAttempt, nil).Run(func(args mock.Arguments) {
		// Whenever this method is invoked, we will mark the first
		// active attempt as failed and exit.
		failedAttempt = payment.HTLCs[0]
		failedAttempt.Failure = &channeldb.HTLCFailInfo{}
		payment.HTLCs[0] = failedAttempt
	}).Once()

	// Setup ReportPaymentFail to return nil reason and error so the
	// payment won't fail.
	failureReason := channeldb.FailureReasonPaymentDetails
	missionControl.On("ReportPaymentFail",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(failureReason, nil).Run(func(args mock.Arguments) {
		missionControl.failReason = &failureReason
		payment.FailureReason = &failureReason
	}).Once()

	// Simple mocking the rest.
	controlTower.On("Fail", identifier, failureReason).Return(nil).Once()
	payer.On("SendHTLC",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(nil)

	// Call the actual method SendPayment on router. This is place inside a
	// goroutine so we can set a timeout for the whole test, in case
	// anything goes wrong and the test never finishes.
	done := make(chan struct{})
	var p lntypes.Hash
	go func() {
		p, _, err = router.SendPayment(req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("SendPayment didn't exit")
	}

	// Finally, validate the returned values and check that the mock
	// methods are called as expected.
	require.Error(t, err, "expected send payment error")
	require.EqualValues(t, [32]byte{}, p, "preimage not match")

	controlTower.AssertExpectations(t)
	payer.AssertExpectations(t)
	sessionSource.AssertExpectations(t)
	session.AssertExpectations(t)
	missionControl.AssertExpectations(t)
}
