package itest

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// AddToNodeLog adds a line to the log file and asserts there's no error.
func AddToNodeLog(t *testing.T,
	node *lntest.HarnessNode, logLine string) {

	err := node.AddToLog(logLine)
	require.NoError(t, err, "unable to add to log")
}

// openChannelStream blocks until an OpenChannel request for a channel funding
// by alice succeeds. If it does, a stream client is returned to receive events
// about the opening channel.
func openChannelStream(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, alice, bob *lntest.HarnessNode,
	p lntest.OpenChannelParams) lnrpc.Lightning_OpenChannelClient {

	t.t.Helper()

	// Wait until we are able to fund a channel successfully. This wait
	// prevents us from erroring out when trying to create a channel while
	// the node is starting up.
	var chanOpenUpdate lnrpc.Lightning_OpenChannelClient
	err := wait.NoError(func() error {
		var err error
		chanOpenUpdate, err = net.OpenChannel(ctx, alice, bob, p)
		return err
	}, defaultTimeout)
	require.NoError(t.t, err, "unable to open channel")

	return chanOpenUpdate
}

// openChannelAndAssert attempts to open a channel with the specified
// parameters extended from Alice to Bob. Additionally, two items are asserted
// after the channel is considered open: the funding transaction should be
// found within a block, and that Alice can report the status of the new
// channel.
func openChannelAndAssert(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, alice, bob *lntest.HarnessNode,
	p lntest.OpenChannelParams) *lnrpc.ChannelPoint {

	t.t.Helper()

	chanOpenUpdate := openChannelStream(ctx, t, net, alice, bob, p)

	// Mine 6 blocks, then wait for Alice's node to notify us that the
	// channel has been opened. The funding transaction should be found
	// within the first newly mined block. We mine 6 blocks so that in the
	// case that the channel is public, it is announced to the network.
	block := mineBlocks(t, net, 6, 1)[0]

	fundingChanPoint, err := net.WaitForChannelOpen(ctx, chanOpenUpdate)
	require.NoError(t.t, err, "error while waiting for channel open")

	fundingTxID, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
	require.NoError(t.t, err, "unable to get txid")

	assertTxInBlock(t, block, fundingTxID)

	// The channel should be listed in the peer information returned by
	// both peers.
	chanPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: fundingChanPoint.OutputIndex,
	}
	require.NoError(
		t.t, net.AssertChannelExists(ctx, alice, &chanPoint),
		"unable to assert channel existence",
	)
	require.NoError(
		t.t, net.AssertChannelExists(ctx, bob, &chanPoint),
		"unable to assert channel existence",
	)

	return fundingChanPoint
}

// graphSubscription houses the proxied update and error chans for a node's
// graph subscriptions.
type graphSubscription struct {
	updateChan chan *lnrpc.GraphTopologyUpdate
	errChan    chan error
	quit       chan struct{}
}

// subscribeGraphNotifications subscribes to channel graph updates and launches
// a goroutine that forwards these to the returned channel.
func subscribeGraphNotifications(ctxb context.Context, t *harnessTest,
	node *lntest.HarnessNode) graphSubscription {

	// We'll first start by establishing a notification client which will
	// send us notifications upon detected changes in the channel graph.
	req := &lnrpc.GraphTopologySubscription{}
	ctx, cancelFunc := context.WithCancel(ctxb)
	topologyClient, err := node.SubscribeChannelGraph(ctx, req)
	require.NoError(t.t, err, "unable to create topology client")

	// We'll launch a goroutine that will be responsible for proxying all
	// notifications recv'd from the client into the channel below.
	errChan := make(chan error, 1)
	quit := make(chan struct{})
	graphUpdates := make(chan *lnrpc.GraphTopologyUpdate, 20)
	go func() {
		for {
			defer cancelFunc()

			select {
			case <-quit:
				return
			default:
				graphUpdate, err := topologyClient.Recv()
				select {
				case <-quit:
					return
				default:
				}

				if err == io.EOF {
					return
				} else if err != nil {
					select {
					case errChan <- err:
					case <-quit:
					}
					return
				}

				select {
				case graphUpdates <- graphUpdate:
				case <-quit:
					return
				}
			}
		}
	}()

	return graphSubscription{
		updateChan: graphUpdates,
		errChan:    errChan,
		quit:       quit,
	}
}

func waitForGraphSync(t *harnessTest, node *lntest.HarnessNode) {
	t.t.Helper()

	err := wait.Predicate(func() bool {
		ctxb := context.Background()
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		resp, err := node.GetInfo(ctxt, &lnrpc.GetInfoRequest{})
		require.NoError(t.t, err)

		return resp.SyncedToGraph
	}, defaultTimeout)
	require.NoError(t.t, err)
}

// closeChannelAndAssert attempts to close a channel identified by the passed
// channel point owned by the passed Lightning node. A fully blocking channel
// closure is attempted, therefore the passed context should be a child derived
// via timeout from a base parent. Additionally, once the channel has been
// detected as closed, an assertion checks that the transaction is found within
// a block. Finally, this assertion verifies that the node always sends out a
// disable update when closing the channel if the channel was previously
// enabled.
//
// NOTE: This method assumes that the provided funding point is confirmed
// on-chain AND that the edge exists in the node's channel graph. If the funding
// transactions was reorged out at some point, use closeReorgedChannelAndAssert.
func closeChannelAndAssert(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, node *lntest.HarnessNode,
	fundingChanPoint *lnrpc.ChannelPoint, force bool) *chainhash.Hash {

	return closeChannelAndAssertType(
		ctx, t, net, node, fundingChanPoint, false, force,
	)
}

func closeChannelAndAssertType(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, node *lntest.HarnessNode,
	fundingChanPoint *lnrpc.ChannelPoint,
	anchors, force bool) *chainhash.Hash {

	// Fetch the current channel policy. If the channel is currently
	// enabled, we will register for graph notifications before closing to
	// assert that the node sends out a disabling update as a result of the
	// channel being closed.
	curPolicy := getChannelPolicies(
		t, node, node.PubKeyStr, fundingChanPoint,
	)[0]
	expectDisable := !curPolicy.Disabled

	// If the current channel policy is enabled, begin subscribing the graph
	// updates before initiating the channel closure.
	var graphSub *graphSubscription
	if expectDisable {
		sub := subscribeGraphNotifications(ctx, t, node)
		graphSub = &sub
		defer close(graphSub.quit)
	}

	closeUpdates, _, err := net.CloseChannel(
		ctx, node, fundingChanPoint, force,
	)
	require.NoError(t.t, err, "unable to close channel")

	// If the channel policy was enabled prior to the closure, wait until we
	// received the disabled update.
	if expectDisable {
		curPolicy.Disabled = true
		waitForChannelUpdate(
			t, *graphSub,
			[]expectedChanUpdate{
				{node.PubKeyStr, curPolicy, fundingChanPoint},
			},
		)
	}

	return assertChannelClosed(
		ctx, t, net, node, fundingChanPoint, anchors, closeUpdates,
	)
}

// closeReorgedChannelAndAssert attempts to close a channel identified by the
// passed channel point owned by the passed Lightning node. A fully blocking
// channel closure is attempted, therefore the passed context should be a child
// derived via timeout from a base parent. Additionally, once the channel has
// been detected as closed, an assertion checks that the transaction is found
// within a block.
//
// NOTE: This method does not verify that the node sends a disable update for
// the closed channel.
func closeReorgedChannelAndAssert(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, node *lntest.HarnessNode,
	fundingChanPoint *lnrpc.ChannelPoint, force bool) *chainhash.Hash {

	closeUpdates, _, err := net.CloseChannel(ctx, node, fundingChanPoint, force)
	require.NoError(t.t, err, "unable to close channel")

	return assertChannelClosed(
		ctx, t, net, node, fundingChanPoint, false, closeUpdates,
	)
}

// assertChannelClosed asserts that the channel is properly cleaned up after
// initiating a cooperative or local close.
func assertChannelClosed(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, node *lntest.HarnessNode,
	fundingChanPoint *lnrpc.ChannelPoint, anchors bool,
	closeUpdates lnrpc.Lightning_CloseChannelClient) *chainhash.Hash {

	txid, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
	require.NoError(t.t, err, "unable to get txid")
	chanPointStr := fmt.Sprintf("%v:%v", txid, fundingChanPoint.OutputIndex)

	// If the channel appears in list channels, ensure that its state
	// contains ChanStatusCoopBroadcasted.
	ctxt, _ := context.WithTimeout(ctx, defaultTimeout)
	listChansRequest := &lnrpc.ListChannelsRequest{}
	listChansResp, err := node.ListChannels(ctxt, listChansRequest)
	require.NoError(t.t, err, "unable to query for list channels")

	for _, channel := range listChansResp.Channels {
		// Skip other channels.
		if channel.ChannelPoint != chanPointStr {
			continue
		}

		// Assert that the channel is in coop broadcasted.
		require.Contains(
			t.t, channel.ChanStatusFlags,
			channeldb.ChanStatusCoopBroadcasted.String(),
			"channel not coop broadcasted",
		)
	}

	// At this point, the channel should now be marked as being in the
	// state of "waiting close".
	ctxt, _ = context.WithTimeout(ctx, defaultTimeout)
	pendingChansRequest := &lnrpc.PendingChannelsRequest{}
	pendingChanResp, err := node.PendingChannels(ctxt, pendingChansRequest)
	require.NoError(t.t, err, "unable to query for pending channels")

	var found bool
	for _, pendingClose := range pendingChanResp.WaitingCloseChannels {
		if pendingClose.Channel.ChannelPoint == chanPointStr {
			found = true
			break
		}
	}
	require.True(t.t, found, "channel not marked as waiting close")

	// We'll now, generate a single block, wait for the final close status
	// update, then ensure that the closing transaction was included in the
	// block. If there are anchors, we also expect an anchor sweep.
	expectedTxes := 1
	if anchors {
		expectedTxes = 2
	}

	block := mineBlocks(t, net, 1, expectedTxes)[0]

	closingTxid, err := net.WaitForChannelClose(ctx, closeUpdates)
	require.NoError(t.t, err, "error while waiting for channel close")

	assertTxInBlock(t, block, closingTxid)

	// Finally, the transaction should no longer be in the waiting close
	// state as we've just mined a block that should include the closing
	// transaction.
	err = wait.Predicate(func() bool {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		pendingChanResp, err := node.PendingChannels(
			ctx, pendingChansRequest,
		)
		if err != nil {
			return false
		}

		for _, pendingClose := range pendingChanResp.WaitingCloseChannels {
			if pendingClose.Channel.ChannelPoint == chanPointStr {
				return false
			}
		}

		return true
	}, defaultTimeout)
	require.NoError(
		t.t, err, "closing transaction not marked as fully closed",
	)

	return closingTxid
}

// findForceClosedChannel searches a pending channel response for a particular
// channel, returning the force closed channel upon success.
func findForceClosedChannel(pendingChanResp *lnrpc.PendingChannelsResponse,
	op fmt.Stringer) (*lnrpc.PendingChannelsResponse_ForceClosedChannel,
	error) {

	for _, forceClose := range pendingChanResp.PendingForceClosingChannels {
		if forceClose.Channel.ChannelPoint == op.String() {
			return forceClose, nil
		}
	}

	return nil, errors.New("channel not marked as force closed")
}

// findWaitingCloseChannel searches a pending channel response for a particular
// channel, returning the waiting close channel upon success.
func findWaitingCloseChannel(pendingChanResp *lnrpc.PendingChannelsResponse,
	op fmt.Stringer) (*lnrpc.PendingChannelsResponse_WaitingCloseChannel,
	error) {

	for _, waitingClose := range pendingChanResp.WaitingCloseChannels {
		if waitingClose.Channel.ChannelPoint == op.String() {
			return waitingClose, nil
		}
	}

	return nil, errors.New("channel not marked as waiting close")
}

// waitForChannelPendingForceClose waits for the node to report that the
// channel is pending force close, and that the UTXO nursery is aware of it.
func waitForChannelPendingForceClose(ctx context.Context,
	node *lntest.HarnessNode, fundingChanPoint *lnrpc.ChannelPoint) error {

	txid, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
	if err != nil {
		return err
	}

	op := wire.OutPoint{
		Hash:  *txid,
		Index: fundingChanPoint.OutputIndex,
	}

	return wait.NoError(func() error {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		pendingChanResp, err := node.PendingChannels(
			ctx, pendingChansRequest,
		)
		if err != nil {
			return fmt.Errorf("unable to get pending channels: %v",
				err)
		}

		forceClose, err := findForceClosedChannel(pendingChanResp, &op)
		if err != nil {
			return err
		}

		// We must wait until the UTXO nursery has received the channel
		// and is aware of its maturity height.
		if forceClose.MaturityHeight == 0 {
			return fmt.Errorf("channel had maturity height of 0")
		}

		return nil
	}, defaultTimeout)
}

// lnrpcForceCloseChannel is a short type alias for a ridiculously long type
// name in the lnrpc package.
type lnrpcForceCloseChannel = lnrpc.PendingChannelsResponse_ForceClosedChannel

// waitForNumChannelPendingForceClose waits for the node to report a certain
// number of channels in state pending force close.
func waitForNumChannelPendingForceClose(ctx context.Context,
	node *lntest.HarnessNode, expectedNum int,
	perChanCheck func(channel *lnrpcForceCloseChannel) error) error {

	return wait.NoError(func() error {
		resp, err := node.PendingChannels(
			ctx, &lnrpc.PendingChannelsRequest{},
		)
		if err != nil {
			return fmt.Errorf("unable to get pending channels: %v",
				err)
		}

		forceCloseChans := resp.PendingForceClosingChannels
		if len(forceCloseChans) != expectedNum {
			return fmt.Errorf("%v should have %d pending "+
				"force close channels but has %d",
				node.Cfg.Name, expectedNum,
				len(forceCloseChans))
		}

		if perChanCheck != nil {
			for _, forceCloseChan := range forceCloseChans {
				err := perChanCheck(forceCloseChan)
				if err != nil {
					return err
				}
			}
		}

		return nil
	}, defaultTimeout)
}

// cleanupForceClose mines a force close commitment found in the mempool and
// the following sweep transaction from the force closing node.
func cleanupForceClose(t *harnessTest, net *lntest.NetworkHarness,
	node *lntest.HarnessNode, chanPoint *lnrpc.ChannelPoint) {
	ctxb := context.Background()

	// Wait for the channel to be marked pending force close.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	err := waitForChannelPendingForceClose(ctxt, node, chanPoint)
	require.NoError(t.t, err, "channel not pending force close")

	// Mine enough blocks for the node to sweep its funds from the force
	// closed channel.
	//
	// The commit sweep resolver is able to broadcast the sweep tx up to
	// one block before the CSV elapses, so wait until defaulCSV-1.
	_, err = net.Miner.Client.Generate(defaultCSV - 1)
	require.NoError(t.t, err, "unable to generate blocks")

	// The node should now sweep the funds, clean up by mining the sweeping
	// tx.
	mineBlocks(t, net, 1, 1)
}

// numOpenChannelsPending sends an RPC request to a node to get a count of the
// node's channels that are currently in a pending state (with a broadcast, but
// not confirmed funding transaction).
func numOpenChannelsPending(ctxt context.Context,
	node *lntest.HarnessNode) (int, error) {

	pendingChansRequest := &lnrpc.PendingChannelsRequest{}
	resp, err := node.PendingChannels(ctxt, pendingChansRequest)
	if err != nil {
		return 0, err
	}
	return len(resp.PendingOpenChannels), nil
}

// assertNumOpenChannelsPending asserts that a pair of nodes have the expected
// number of pending channels between them.
func assertNumOpenChannelsPending(ctxt context.Context, t *harnessTest,
	alice, bob *lntest.HarnessNode, expected int) {

	err := wait.NoError(func() error {
		aliceNumChans, err := numOpenChannelsPending(ctxt, alice)
		if err != nil {
			return fmt.Errorf("error fetching alice's node (%v) "+
				"pending channels %v", alice.NodeID, err)
		}
		bobNumChans, err := numOpenChannelsPending(ctxt, bob)
		if err != nil {
			return fmt.Errorf("error fetching bob's node (%v) "+
				"pending channels %v", bob.NodeID, err)
		}

		aliceStateCorrect := aliceNumChans == expected
		if !aliceStateCorrect {
			return fmt.Errorf("number of pending channels for "+
				"alice incorrect. expected %v, got %v",
				expected, aliceNumChans)
		}

		bobStateCorrect := bobNumChans == expected
		if !bobStateCorrect {
			return fmt.Errorf("number of pending channels for bob "+
				"incorrect. expected %v, got %v", expected,
				bobNumChans)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)
}

// assertNumConnections asserts number current connections between two peers.
func assertNumConnections(t *harnessTest, alice, bob *lntest.HarnessNode,
	expected int) {
	ctxb := context.Background()
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)

	err := wait.NoError(func() error {
		aNumPeers, err := alice.ListPeers(
			ctxt, &lnrpc.ListPeersRequest{},
		)
		if err != nil {
			return fmt.Errorf(
				"unable to fetch %s's node (%v) list peers %v",
				alice.Name(), alice.NodeID, err,
			)
		}

		bNumPeers, err := bob.ListPeers(ctxt, &lnrpc.ListPeersRequest{})
		if err != nil {
			return fmt.Errorf(
				"unable to fetch %s's node (%v) list peers %v",
				bob.Name(), bob.NodeID, err,
			)
		}

		if len(aNumPeers.Peers) != expected {
			return fmt.Errorf(
				"number of peers connected to %s is "+
					"incorrect: expected %v, got %v",
				alice.Name(), expected, len(aNumPeers.Peers),
			)
		}
		if len(bNumPeers.Peers) != expected {
			return fmt.Errorf(
				"number of peers connected to %s is "+
					"incorrect: expected %v, got %v",
				bob.Name(), expected, len(bNumPeers.Peers),
			)
		}

		return nil

	}, defaultTimeout)
	require.NoError(t.t, err)
}

// shutdownAndAssert shuts down the given node and asserts that no errors
// occur.
func shutdownAndAssert(net *lntest.NetworkHarness, t *harnessTest,
	node *lntest.HarnessNode) {

	// The process may not be in a state to always shutdown immediately, so
	// we'll retry up to a hard limit to ensure we eventually shutdown.
	err := wait.NoError(func() error {
		return net.ShutdownNode(node)
	}, defaultTimeout)
	require.NoErrorf(t.t, err, "unable to shutdown %v", node.Name())
}

// assertChannelBalanceResp makes a ChannelBalance request and checks the
// returned response matches the expected.
func assertChannelBalanceResp(t *harnessTest,
	node *lntest.HarnessNode,
	expected *lnrpc.ChannelBalanceResponse) { // nolint:interfacer

	resp := getChannelBalance(t, node)
	require.True(t.t, proto.Equal(expected, resp), "balance is incorrect")
}

// getChannelBalance gets the channel balance.
func getChannelBalance(t *harnessTest,
	node *lntest.HarnessNode) *lnrpc.ChannelBalanceResponse {

	t.t.Helper()

	ctxt, _ := context.WithTimeout(context.Background(), defaultTimeout)
	req := &lnrpc.ChannelBalanceRequest{}
	resp, err := node.ChannelBalance(ctxt, req)

	require.NoError(t.t, err, "unable to get node's balance")
	return resp
}

// expectedChanUpdate houses params we expect a ChannelUpdate to advertise.
type expectedChanUpdate struct {
	advertisingNode string
	expectedPolicy  *lnrpc.RoutingPolicy
	chanPoint       *lnrpc.ChannelPoint
}

// txStr returns the string representation of the channel's funding transaction.
func txStr(chanPoint *lnrpc.ChannelPoint) string {
	fundingTxID, err := lnrpc.GetChanPointFundingTxid(chanPoint)
	if err != nil {
		return ""
	}
	cp := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: chanPoint.OutputIndex,
	}
	return cp.String()
}

// waitForChannelUpdate waits for a node to receive the expected channel
// updates.
func waitForChannelUpdate(t *harnessTest, subscription graphSubscription,
	expUpdates []expectedChanUpdate) {

	// Create an array indicating which expected channel updates we have
	// received.
	found := make([]bool, len(expUpdates))
out:
	for {
		select {
		case graphUpdate := <-subscription.updateChan:
			for _, update := range graphUpdate.ChannelUpdates {
				require.NotZerof(
					t.t, len(expUpdates),
					"received unexpected channel "+
						"update from %v for channel %v",
					update.AdvertisingNode,
					update.ChanId,
				)

				// For each expected update, check if it matches
				// the update we just received.
				for i, exp := range expUpdates {
					fundingTxStr := txStr(update.ChanPoint)
					if fundingTxStr != txStr(exp.chanPoint) {
						continue
					}

					if update.AdvertisingNode !=
						exp.advertisingNode {
						continue
					}

					err := checkChannelPolicy(
						update.RoutingPolicy,
						exp.expectedPolicy,
					)
					if err != nil {
						continue
					}

					// We got a policy update that matched
					// the values and channel point of what
					// we expected, mark it as found.
					found[i] = true

					// If we have no more channel updates
					// we are waiting for, break out of the
					// loop.
					rem := 0
					for _, f := range found {
						if !f {
							rem++
						}
					}

					if rem == 0 {
						break out
					}

					// Since we found a match among the
					// expected updates, break out of the
					// inner loop.
					break
				}
			}
		case err := <-subscription.errChan:
			t.Fatalf("unable to recv graph update: %v", err)
		case <-time.After(defaultTimeout):
			if len(expUpdates) == 0 {
				return
			}
			t.Fatalf("did not receive channel update")
		}
	}
}

// assertNoChannelUpdates ensures that no ChannelUpdates are sent via the
// graphSubscription. This method will block for the provided duration before
// returning to the caller if successful.
func assertNoChannelUpdates(t *harnessTest, subscription graphSubscription,
	duration time.Duration) {

	timeout := time.After(duration)
	for {
		select {
		case graphUpdate := <-subscription.updateChan:
			require.Zero(
				t.t, len(graphUpdate.ChannelUpdates),
				"no channel updates were expected",
			)

		case err := <-subscription.errChan:
			t.Fatalf("graph subscription failure: %v", err)

		case <-timeout:
			// No updates received, success.
			return
		}
	}
}

// getChannelPolicies queries the channel graph and retrieves the current edge
// policies for the provided channel points.
func getChannelPolicies(t *harnessTest, node *lntest.HarnessNode,
	advertisingNode string,
	chanPoints ...*lnrpc.ChannelPoint) []*lnrpc.RoutingPolicy {

	ctxb := context.Background()

	descReq := &lnrpc.ChannelGraphRequest{
		IncludeUnannounced: true,
	}
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	chanGraph, err := node.DescribeGraph(ctxt, descReq)
	require.NoError(t.t, err, "unable to query for alice's graph")

	var policies []*lnrpc.RoutingPolicy
	err = wait.NoError(func() error {
	out:
		for _, chanPoint := range chanPoints {
			for _, e := range chanGraph.Edges {
				if e.ChanPoint != txStr(chanPoint) {
					continue
				}

				if e.Node1Pub == advertisingNode {
					policies = append(policies,
						e.Node1Policy)
				} else {
					policies = append(policies,
						e.Node2Policy)
				}

				continue out
			}

			// If we've iterated over all the known edges and we weren't
			// able to find this specific one, then we'll fail.
			return fmt.Errorf("did not find edge %v", txStr(chanPoint))
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)

	return policies
}

// assertChannelPolicy asserts that the passed node's known channel policy for
// the passed chanPoint is consistent with the expected policy values.
func assertChannelPolicy(t *harnessTest, node *lntest.HarnessNode,
	advertisingNode string, expectedPolicy *lnrpc.RoutingPolicy,
	chanPoints ...*lnrpc.ChannelPoint) {

	policies := getChannelPolicies(t, node, advertisingNode, chanPoints...)
	for _, policy := range policies {
		err := checkChannelPolicy(policy, expectedPolicy)
		if err != nil {
			t.Fatalf(err.Error())
		}
	}
}

// checkChannelPolicy checks that the policy matches the expected one.
func checkChannelPolicy(policy, expectedPolicy *lnrpc.RoutingPolicy) error {
	if policy.FeeBaseMsat != expectedPolicy.FeeBaseMsat {
		return fmt.Errorf("expected base fee %v, got %v",
			expectedPolicy.FeeBaseMsat, policy.FeeBaseMsat)
	}
	if policy.FeeRateMilliMsat != expectedPolicy.FeeRateMilliMsat {
		return fmt.Errorf("expected fee rate %v, got %v",
			expectedPolicy.FeeRateMilliMsat,
			policy.FeeRateMilliMsat)
	}
	if policy.TimeLockDelta != expectedPolicy.TimeLockDelta {
		return fmt.Errorf("expected time lock delta %v, got %v",
			expectedPolicy.TimeLockDelta,
			policy.TimeLockDelta)
	}
	if policy.MinHtlc != expectedPolicy.MinHtlc {
		return fmt.Errorf("expected min htlc %v, got %v",
			expectedPolicy.MinHtlc, policy.MinHtlc)
	}
	if policy.MaxHtlcMsat != expectedPolicy.MaxHtlcMsat {
		return fmt.Errorf("expected max htlc %v, got %v",
			expectedPolicy.MaxHtlcMsat, policy.MaxHtlcMsat)
	}
	if policy.Disabled != expectedPolicy.Disabled {
		return errors.New("edge should be disabled but isn't")
	}

	return nil
}

// assertMinerBlockHeightDelta ensures that tempMiner is 'delta' blocks ahead
// of miner.
func assertMinerBlockHeightDelta(t *harnessTest,
	miner, tempMiner *rpctest.Harness, delta int32) {

	// Ensure the chain lengths are what we expect.
	var predErr error
	err := wait.Predicate(func() bool {
		_, tempMinerHeight, err := tempMiner.Client.GetBestBlock()
		if err != nil {
			predErr = fmt.Errorf("unable to get current "+
				"blockheight %v", err)
			return false
		}

		_, minerHeight, err := miner.Client.GetBestBlock()
		if err != nil {
			predErr = fmt.Errorf("unable to get current "+
				"blockheight %v", err)
			return false
		}

		if tempMinerHeight != minerHeight+delta {
			predErr = fmt.Errorf("expected new miner(%d) to be %d "+
				"blocks ahead of original miner(%d)",
				tempMinerHeight, delta, minerHeight)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}
}

func checkCommitmentMaturity(
	forceClose *lnrpc.PendingChannelsResponse_ForceClosedChannel,
	maturityHeight uint32, blocksTilMaturity int32) error {

	if forceClose.MaturityHeight != maturityHeight {
		return fmt.Errorf("expected commitment maturity height to be "+
			"%d, found %d instead", maturityHeight,
			forceClose.MaturityHeight)
	}
	if forceClose.BlocksTilMaturity != blocksTilMaturity {
		return fmt.Errorf("expected commitment blocks til maturity to "+
			"be %d, found %d instead", blocksTilMaturity,
			forceClose.BlocksTilMaturity)
	}

	return nil
}

// checkForceClosedChannelNumHtlcs verifies that a force closed channel has the
// proper number of htlcs.
func checkPendingChannelNumHtlcs(
	forceClose *lnrpc.PendingChannelsResponse_ForceClosedChannel,
	expectedNumHtlcs int) error {

	if len(forceClose.PendingHtlcs) != expectedNumHtlcs {
		return fmt.Errorf("expected force closed channel to have %d "+
			"pending htlcs, found %d instead", expectedNumHtlcs,
			len(forceClose.PendingHtlcs))
	}

	return nil
}

// checkNumForceClosedChannels checks that a pending channel response has the
// expected number of force closed channels.
func checkNumForceClosedChannels(pendingChanResp *lnrpc.PendingChannelsResponse,
	expectedNumChans int) error {

	if len(pendingChanResp.PendingForceClosingChannels) != expectedNumChans {
		return fmt.Errorf("expected to find %d force closed channels, "+
			"got %d", expectedNumChans,
			len(pendingChanResp.PendingForceClosingChannels))
	}

	return nil
}

// checkNumWaitingCloseChannels checks that a pending channel response has the
// expected number of channels waiting for closing tx to confirm.
func checkNumWaitingCloseChannels(pendingChanResp *lnrpc.PendingChannelsResponse,
	expectedNumChans int) error {

	if len(pendingChanResp.WaitingCloseChannels) != expectedNumChans {
		return fmt.Errorf("expected to find %d channels waiting "+
			"closure, got %d", expectedNumChans,
			len(pendingChanResp.WaitingCloseChannels))
	}

	return nil
}

// checkPendingHtlcStageAndMaturity uniformly tests all pending htlc's belonging
// to a force closed channel, testing for the expected stage number, blocks till
// maturity, and the maturity height.
func checkPendingHtlcStageAndMaturity(
	forceClose *lnrpc.PendingChannelsResponse_ForceClosedChannel,
	stage, maturityHeight uint32, blocksTillMaturity int32) error {

	for _, pendingHtlc := range forceClose.PendingHtlcs {
		if pendingHtlc.Stage != stage {
			return fmt.Errorf("expected pending htlc to be stage "+
				"%d, found %d", stage, pendingHtlc.Stage)
		}
		if pendingHtlc.MaturityHeight != maturityHeight {
			return fmt.Errorf("expected pending htlc maturity "+
				"height to be %d, instead has %d",
				maturityHeight, pendingHtlc.MaturityHeight)
		}
		if pendingHtlc.BlocksTilMaturity != blocksTillMaturity {
			return fmt.Errorf("expected pending htlc blocks til "+
				"maturity to be %d, instead has %d",
				blocksTillMaturity,
				pendingHtlc.BlocksTilMaturity)
		}
	}

	return nil
}

// assertReports checks that the count of resolutions we have present per
// type matches a set of expected resolutions.
func assertReports(ctxb context.Context, t *harnessTest,
	node *lntest.HarnessNode, channelPoint wire.OutPoint,
	expected map[string]*lnrpc.Resolution) {

	// Get our node's closed channels.
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	closed, err := node.ClosedChannels(
		ctxt, &lnrpc.ClosedChannelsRequest{},
	)
	require.NoError(t.t, err)

	var resolutions []*lnrpc.Resolution
	for _, close := range closed.Channels {
		if close.ChannelPoint == channelPoint.String() {
			resolutions = close.Resolutions
			break
		}
	}

	require.NotNil(t.t, resolutions)
	require.Equal(t.t, len(expected), len(resolutions))

	for _, res := range resolutions {
		outPointStr := fmt.Sprintf("%v:%v", res.Outpoint.TxidStr,
			res.Outpoint.OutputIndex)

		expected, ok := expected[outPointStr]
		require.True(t.t, ok)
		require.Equal(t.t, expected, res)
	}
}

// assertSweepFound looks up a sweep in a nodes list of broadcast sweeps.
func assertSweepFound(ctx context.Context, t *testing.T, node *lntest.HarnessNode,
	sweep string, verbose bool) {

	// List all sweeps that alice's node had broadcast.
	ctx, _ = context.WithTimeout(ctx, defaultTimeout)
	sweepResp, err := node.WalletKitClient.ListSweeps(
		ctx, &walletrpc.ListSweepsRequest{
			Verbose: verbose,
		},
	)
	require.NoError(t, err)

	var found bool
	if verbose {
		found = findSweepInDetails(t, sweep, sweepResp)
	} else {
		found = findSweepInTxids(t, sweep, sweepResp)
	}

	require.True(t, found, "sweep: %v not found", sweep)
}

func findSweepInTxids(t *testing.T, sweepTxid string,
	sweepResp *walletrpc.ListSweepsResponse) bool {

	sweepTxIDs := sweepResp.GetTransactionIds()
	require.NotNil(t, sweepTxIDs, "expected transaction ids")
	require.Nil(t, sweepResp.GetTransactionDetails())

	// Check that the sweep tx we have just produced is present.
	for _, tx := range sweepTxIDs.TransactionIds {
		if tx == sweepTxid {
			return true
		}
	}

	return false
}

func findSweepInDetails(t *testing.T, sweepTxid string,
	sweepResp *walletrpc.ListSweepsResponse) bool {

	sweepDetails := sweepResp.GetTransactionDetails()
	require.NotNil(t, sweepDetails, "expected transaction details")
	require.Nil(t, sweepResp.GetTransactionIds())

	for _, tx := range sweepDetails.Transactions {
		if tx.TxHash == sweepTxid {
			return true
		}
	}

	return false
}

// assertAmountSent generates a closure which queries listchannels for sndr and
// rcvr, and asserts that sndr sent amt satoshis, and that rcvr received amt
// satoshis.
//
// NOTE: This method assumes that each node only has one channel, and it is the
// channel used to send the payment.
func assertAmountSent(amt btcutil.Amount, sndr, rcvr *lntest.HarnessNode) func() error {
	return func() error {
		// Both channels should also have properly accounted from the
		// amount that has been sent/received over the channel.
		listReq := &lnrpc.ListChannelsRequest{}
		ctxb := context.Background()
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		sndrListChannels, err := sndr.ListChannels(ctxt, listReq)
		if err != nil {
			return fmt.Errorf("unable to query for %s's channel "+
				"list: %v", sndr.Name(), err)
		}
		sndrSatoshisSent := sndrListChannels.Channels[0].TotalSatoshisSent
		if sndrSatoshisSent != int64(amt) {
			return fmt.Errorf("%s's satoshis sent is incorrect "+
				"got %v, expected %v", sndr.Name(),
				sndrSatoshisSent, amt)
		}

		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		rcvrListChannels, err := rcvr.ListChannels(ctxt, listReq)
		if err != nil {
			return fmt.Errorf("unable to query for %s's channel "+
				"list: %v", rcvr.Name(), err)
		}
		rcvrSatoshisReceived := rcvrListChannels.Channels[0].TotalSatoshisReceived
		if rcvrSatoshisReceived != int64(amt) {
			return fmt.Errorf("%s's satoshis received is "+
				"incorrect got %v, expected %v", rcvr.Name(),
				rcvrSatoshisReceived, amt)
		}

		return nil
	}
}

// assertLastHTLCError checks that the last sent HTLC of the last payment sent
// by the given node failed with the expected failure code.
func assertLastHTLCError(t *harnessTest, node *lntest.HarnessNode,
	code lnrpc.Failure_FailureCode) {

	req := &lnrpc.ListPaymentsRequest{
		IncludeIncomplete: true,
	}
	ctxt, _ := context.WithTimeout(context.Background(), defaultTimeout)
	paymentsResp, err := node.ListPayments(ctxt, req)
	require.NoError(t.t, err, "error when obtaining payments")

	payments := paymentsResp.Payments
	require.NotZero(t.t, len(payments), "no payments found")

	payment := payments[len(payments)-1]
	htlcs := payment.Htlcs
	require.NotZero(t.t, len(htlcs), "no htlcs")

	htlc := htlcs[len(htlcs)-1]
	require.NotNil(t.t, htlc.Failure, "expected failure")

	require.Equal(t.t, code, htlc.Failure.Code, "unexpected failure code")
}

func assertChannelConstraintsEqual(
	t *harnessTest, want, got *lnrpc.ChannelConstraints) {

	t.t.Helper()

	require.Equal(t.t, want.CsvDelay, got.CsvDelay, "CsvDelay mismatched")
	require.Equal(
		t.t, want.ChanReserveSat, got.ChanReserveSat,
		"ChanReserveSat mismatched",
	)
	require.Equal(
		t.t, want.DustLimitSat, got.DustLimitSat,
		"DustLimitSat mismatched",
	)
	require.Equal(
		t.t, want.MaxPendingAmtMsat, got.MaxPendingAmtMsat,
		"MaxPendingAmtMsat mismatched",
	)
	require.Equal(
		t.t, want.MinHtlcMsat, got.MinHtlcMsat,
		"MinHtlcMsat mismatched",
	)
	require.Equal(
		t.t, want.MaxAcceptedHtlcs, got.MaxAcceptedHtlcs,
		"MaxAcceptedHtlcs mismatched",
	)
}

// assertAmountPaid checks that the ListChannels command of the provided
// node list the total amount sent and received as expected for the
// provided channel.
func assertAmountPaid(t *harnessTest, channelName string,
	node *lntest.HarnessNode, chanPoint wire.OutPoint, amountSent,
	amountReceived int64) {
	ctxb := context.Background()

	checkAmountPaid := func() error {
		listReq := &lnrpc.ListChannelsRequest{}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		resp, err := node.ListChannels(ctxt, listReq)
		if err != nil {
			return fmt.Errorf("unable to for node's "+
				"channels: %v", err)
		}
		for _, channel := range resp.Channels {
			if channel.ChannelPoint != chanPoint.String() {
				continue
			}

			if channel.TotalSatoshisSent != amountSent {
				return fmt.Errorf("%v: incorrect amount"+
					" sent: %v != %v", channelName,
					channel.TotalSatoshisSent,
					amountSent)
			}
			if channel.TotalSatoshisReceived !=
				amountReceived {
				return fmt.Errorf("%v: incorrect amount"+
					" received: %v != %v",
					channelName,
					channel.TotalSatoshisReceived,
					amountReceived)
			}

			return nil
		}
		return fmt.Errorf("channel not found")
	}

	// As far as HTLC inclusion in commitment transaction might be
	// postponed we will try to check the balance couple of times,
	// and then if after some period of time we receive wrong
	// balance return the error.
	// TODO(roasbeef): remove sleep after invoice notification hooks
	// are in place
	var timeover uint32
	go func() {
		<-time.After(defaultTimeout)
		atomic.StoreUint32(&timeover, 1)
	}()

	for {
		isTimeover := atomic.LoadUint32(&timeover) == 1
		if err := checkAmountPaid(); err != nil {
			require.Falsef(
				t.t, isTimeover,
				"Check amount Paid failed: %v", err,
			)
		} else {
			break
		}
	}
}

// assertNumPendingChannels checks that a PendingChannels response from the
// node reports the expected number of pending channels.
func assertNumPendingChannels(t *harnessTest, node *lntest.HarnessNode,
	expWaitingClose, expPendingForceClose int) {
	ctxb := context.Background()

	var predErr error
	err := wait.Predicate(func() bool {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := node.PendingChannels(ctxt,
			pendingChansRequest)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		n := len(pendingChanResp.WaitingCloseChannels)
		if n != expWaitingClose {
			predErr = fmt.Errorf("expected to find %d channels "+
				"waiting close, found %d", expWaitingClose, n)
			return false
		}
		n = len(pendingChanResp.PendingForceClosingChannels)
		if n != expPendingForceClose {
			predErr = fmt.Errorf("expected to find %d channel "+
				"pending force close, found %d", expPendingForceClose, n)
			return false
		}
		return true
	}, defaultTimeout)
	require.NoErrorf(t.t, err, "got err: %v", predErr)
}

// assertDLPExecuted asserts that Dave is a node that has recovered their state
// form scratch. Carol should then force close on chain, with Dave sweeping his
// funds immediately, and Carol sweeping her fund after her CSV delay is up. If
// the blankSlate value is true, then this means that Dave won't need to sweep
// on chain as he has no funds in the channel.
func assertDLPExecuted(net *lntest.NetworkHarness, t *harnessTest,
	carol *lntest.HarnessNode, carolStartingBalance int64,
	dave *lntest.HarnessNode, daveStartingBalance int64,
	anchors bool) {

	// Increase the fee estimate so that the following force close tx will
	// be cpfp'ed.
	net.SetFeeEstimate(30000)

	// We disabled auto-reconnect for some tests to avoid timing issues.
	// To make sure the nodes are initiating DLP now, we have to manually
	// re-connect them.
	ctxb := context.Background()
	net.EnsureConnected(ctxb, t.t, carol, dave)

	// Upon reconnection, the nodes should detect that Dave is out of sync.
	// Carol should force close the channel using her latest commitment.
	expectedTxes := 1
	if anchors {
		expectedTxes = 2
	}
	_, err := waitForNTxsInMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(
		t.t, err,
		"unable to find Carol's force close tx in mempool",
	)

	// Channel should be in the state "waiting close" for Carol since she
	// broadcasted the force close tx.
	assertNumPendingChannels(t, carol, 1, 0)

	// Dave should also consider the channel "waiting close", as he noticed
	// the channel was out of sync, and is now waiting for a force close to
	// hit the chain.
	assertNumPendingChannels(t, dave, 1, 0)

	// Restart Dave to make sure he is able to sweep the funds after
	// shutdown.
	require.NoError(t.t, net.RestartNode(dave, nil), "Node restart failed")

	// Generate a single block, which should confirm the closing tx.
	_ = mineBlocks(t, net, 1, expectedTxes)[0]

	// Dave should sweep his funds immediately, as they are not timelocked.
	// We also expect Dave to sweep his anchor, if present.

	_, err = waitForNTxsInMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(t.t, err, "unable to find Dave's sweep tx in mempool")

	// Dave should consider the channel pending force close (since he is
	// waiting for his sweep to confirm).
	assertNumPendingChannels(t, dave, 0, 1)

	// Carol is considering it "pending force close", as we must wait
	// before she can sweep her outputs.
	assertNumPendingChannels(t, carol, 0, 1)

	// Mine the sweep tx.
	_ = mineBlocks(t, net, 1, expectedTxes)[0]

	// Now Dave should consider the channel fully closed.
	assertNumPendingChannels(t, dave, 0, 0)

	// We query Dave's balance to make sure it increased after the channel
	// closed. This checks that he was able to sweep the funds he had in
	// the channel.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	balReq := &lnrpc.WalletBalanceRequest{}
	daveBalResp, err := dave.WalletBalance(ctxt, balReq)
	require.NoError(t.t, err, "unable to get dave's balance")

	daveBalance := daveBalResp.ConfirmedBalance
	require.Greater(
		t.t, daveBalance, daveStartingBalance, "balance not increased",
	)

	// After the Carol's output matures, she should also reclaim her funds.
	//
	// The commit sweep resolver publishes the sweep tx at defaultCSV-1 and
	// we already mined one block after the commitmment was published, so
	// take that into account.
	mineBlocks(t, net, defaultCSV-1-1, 0)
	carolSweep, err := waitForTxInMempool(
		net.Miner.Client, minerMempoolTimeout,
	)
	require.NoError(t.t, err, "unable to find Carol's sweep tx in mempool")
	block := mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, carolSweep)

	// Now the channel should be fully closed also from Carol's POV.
	assertNumPendingChannels(t, carol, 0, 0)

	// Make sure Carol got her balance back.
	err = wait.NoError(func() error {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		carolBalResp, err := carol.WalletBalance(ctxt, balReq)
		if err != nil {
			return fmt.Errorf("unable to get carol's balance: %v", err)
		}

		carolBalance := carolBalResp.ConfirmedBalance
		if carolBalance <= carolStartingBalance {
			return fmt.Errorf("expected carol to have balance "+
				"above %d, instead had %v", carolStartingBalance,
				carolBalance)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)

	assertNodeNumChannels(t, dave, 0)
	assertNodeNumChannels(t, carol, 0)
}

// verifyCloseUpdate is used to verify that a closed channel update is of the
// expected type.
func verifyCloseUpdate(chanUpdate *lnrpc.ChannelEventUpdate,
	closeType lnrpc.ChannelCloseSummary_ClosureType,
	closeInitiator lnrpc.Initiator) error {

	// We should receive one inactive and one closed notification
	// for each channel.
	switch update := chanUpdate.Channel.(type) {
	case *lnrpc.ChannelEventUpdate_InactiveChannel:
		if chanUpdate.Type != lnrpc.ChannelEventUpdate_INACTIVE_CHANNEL {
			return fmt.Errorf("update type mismatch: expected %v, got %v",
				lnrpc.ChannelEventUpdate_INACTIVE_CHANNEL,
				chanUpdate.Type)
		}
	case *lnrpc.ChannelEventUpdate_ClosedChannel:
		if chanUpdate.Type !=
			lnrpc.ChannelEventUpdate_CLOSED_CHANNEL {
			return fmt.Errorf("update type mismatch: expected %v, got %v",
				lnrpc.ChannelEventUpdate_CLOSED_CHANNEL,
				chanUpdate.Type)
		}

		if update.ClosedChannel.CloseType != closeType {
			return fmt.Errorf("channel closure type "+
				"mismatch: expected %v, got %v",
				closeType,
				update.ClosedChannel.CloseType)
		}

		if update.ClosedChannel.CloseInitiator != closeInitiator {
			return fmt.Errorf("expected close intiator: %v, got: %v",
				closeInitiator,
				update.ClosedChannel.CloseInitiator)
		}

	default:
		return fmt.Errorf("channel update channel of wrong type, "+
			"expected closed channel, got %T",
			update)
	}

	return nil
}

// assertNodeNumChannels polls the provided node's list channels rpc until it
// reaches the desired number of total channels.
func assertNodeNumChannels(t *harnessTest, node *lntest.HarnessNode,
	numChannels int) {
	ctxb := context.Background()

	// Poll node for its list of channels.
	req := &lnrpc.ListChannelsRequest{}

	var predErr error
	pred := func() bool {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		chanInfo, err := node.ListChannels(ctxt, req)
		if err != nil {
			predErr = fmt.Errorf("unable to query for node's "+
				"channels: %v", err)
			return false
		}

		// Return true if the query returned the expected number of
		// channels.
		num := len(chanInfo.Channels)
		if num != numChannels {
			predErr = fmt.Errorf("expected %v channels, got %v",
				numChannels, num)
			return false
		}
		return true
	}

	require.NoErrorf(
		t.t, wait.Predicate(pred, defaultTimeout),
		"node has incorrect number of channels: %v", predErr,
	)
}

func assertSyncType(t *harnessTest, node *lntest.HarnessNode,
	peer string, syncType lnrpc.Peer_SyncType) {

	t.t.Helper()

	ctxb := context.Background()
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	resp, err := node.ListPeers(ctxt, &lnrpc.ListPeersRequest{})
	require.NoError(t.t, err)

	for _, rpcPeer := range resp.Peers {
		if rpcPeer.PubKey != peer {
			continue
		}

		require.Equal(t.t, syncType, rpcPeer.SyncType)
		return
	}

	t.t.Fatalf("unable to find peer: %s", peer)
}

// assertActiveHtlcs makes sure all the passed nodes have the _exact_ HTLCs
// matching payHashes on _all_ their channels.
func assertActiveHtlcs(nodes []*lntest.HarnessNode, payHashes ...[]byte) error {
	ctxb := context.Background()

	req := &lnrpc.ListChannelsRequest{}
	for _, node := range nodes {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		nodeChans, err := node.ListChannels(ctxt, req)
		if err != nil {
			return fmt.Errorf("unable to get node chans: %v", err)
		}

		for _, channel := range nodeChans.Channels {
			// Record all payment hashes active for this channel.
			htlcHashes := make(map[string]struct{})
			for _, htlc := range channel.PendingHtlcs {
				h := hex.EncodeToString(htlc.HashLock)
				_, ok := htlcHashes[h]
				if ok {
					return fmt.Errorf("duplicate HashLock")
				}
				htlcHashes[h] = struct{}{}
			}

			// Channel should have exactly the payHashes active.
			if len(payHashes) != len(htlcHashes) {
				return fmt.Errorf("node %x had %v htlcs active, "+
					"expected %v", node.PubKey[:],
					len(htlcHashes), len(payHashes))
			}

			// Make sure all the payHashes are active.
			for _, payHash := range payHashes {
				h := hex.EncodeToString(payHash)
				if _, ok := htlcHashes[h]; ok {
					continue
				}
				return fmt.Errorf("node %x didn't have the "+
					"payHash %v active", node.PubKey[:],
					h)
			}
		}
	}

	return nil
}

func assertNumActiveHtlcsChanPoint(node *lntest.HarnessNode,
	chanPoint wire.OutPoint, numHtlcs int) error {
	ctxb := context.Background()

	req := &lnrpc.ListChannelsRequest{}
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	nodeChans, err := node.ListChannels(ctxt, req)
	if err != nil {
		return err
	}

	for _, channel := range nodeChans.Channels {
		if channel.ChannelPoint != chanPoint.String() {
			continue
		}

		if len(channel.PendingHtlcs) != numHtlcs {
			return fmt.Errorf("expected %v active HTLCs, got %v",
				numHtlcs, len(channel.PendingHtlcs))
		}
		return nil
	}

	return fmt.Errorf("channel point %v not found", chanPoint)
}

func assertNumActiveHtlcs(nodes []*lntest.HarnessNode, numHtlcs int) error {
	ctxb := context.Background()

	req := &lnrpc.ListChannelsRequest{}
	for _, node := range nodes {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		nodeChans, err := node.ListChannels(ctxt, req)
		if err != nil {
			return err
		}

		for _, channel := range nodeChans.Channels {
			if len(channel.PendingHtlcs) != numHtlcs {
				return fmt.Errorf("expected %v HTLCs, got %v",
					numHtlcs, len(channel.PendingHtlcs))
			}
		}
	}

	return nil
}

func assertSpendingTxInMempool(t *harnessTest, miner *rpcclient.Client,
	timeout time.Duration, chanPoint wire.OutPoint) chainhash.Hash {

	tx := getSpendingTxInMempool(t, miner, timeout, chanPoint)
	return tx.TxHash()
}

// getSpendingTxInMempool waits for a transaction spending the given outpoint to
// appear in the mempool and returns that tx in full.
func getSpendingTxInMempool(t *harnessTest, miner *rpcclient.Client,
	timeout time.Duration, chanPoint wire.OutPoint) *wire.MsgTx {

	breakTimeout := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-breakTimeout:
			t.Fatalf("didn't find tx in mempool")
		case <-ticker.C:
			mempool, err := miner.GetRawMempool()
			require.NoError(t.t, err, "unable to get mempool")

			if len(mempool) == 0 {
				continue
			}

			for _, txid := range mempool {
				tx, err := miner.GetRawTransaction(txid)
				require.NoError(t.t, err, "unable to fetch tx")

				msgTx := tx.MsgTx()
				for _, txIn := range msgTx.TxIn {
					if txIn.PreviousOutPoint == chanPoint {
						return msgTx
					}
				}
			}
		}
	}
}

// assertTxLabel is a helper function which finds a target tx in our set
// of transactions and checks that it has the desired label.
func assertTxLabel(ctx context.Context, t *harnessTest,
	node *lntest.HarnessNode, targetTx, label string) {

	// List all transactions relevant to our wallet, and find the tx so that
	// we can check the correct label has been set.
	ctxt, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	txResp, err := node.GetTransactions(
		ctxt, &lnrpc.GetTransactionsRequest{},
	)
	require.NoError(t.t, err, "could not get transactions")

	// Find our transaction in the set of transactions returned and check
	// its label.
	for _, txn := range txResp.Transactions {
		if txn.TxHash == targetTx {
			require.Equal(t.t, label, txn.Label, "labels not match")
		}
	}
}

// sendAndAssertSuccess sends the given payment requests and asserts that the
// payment completes successfully.
func sendAndAssertSuccess(ctx context.Context, t *harnessTest, node *lntest.HarnessNode,
	req *routerrpc.SendPaymentRequest) *lnrpc.Payment {

	var result *lnrpc.Payment
	err := wait.NoError(func() error {
		stream, err := node.RouterClient.SendPaymentV2(ctx, req)
		if err != nil {
			return fmt.Errorf("unable to send payment: %v", err)
		}

		result, err = getPaymentResult(stream)
		if err != nil {
			return fmt.Errorf("unable to get payment result: %v",
				err)
		}

		if result.Status != lnrpc.Payment_SUCCEEDED {
			return fmt.Errorf("payment failed: %v", result.Status)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)

	return result
}

// sendAndAssertFailure sends the given payment requests and asserts that the
// payment fails with the expected reason.
func sendAndAssertFailure(t *harnessTest, node *lntest.HarnessNode,
	req *routerrpc.SendPaymentRequest,
	failureReason lnrpc.PaymentFailureReason) *lnrpc.Payment {

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	stream, err := node.RouterClient.SendPaymentV2(ctx, req)
	require.NoError(t.t, err, "unable to send payment")

	result, err := getPaymentResult(stream)
	require.NoError(t.t, err, "unable to get payment result")

	require.Equal(
		t.t, lnrpc.Payment_FAILED, result.Status,
		"payment was expected to fail, but succeeded",
	)

	require.Equal(
		t.t, failureReason, result.FailureReason,
		"payment failureReason not matched",
	)

	return result
}

// getPaymentResult reads a final result from the stream and returns it.
func getPaymentResult(stream routerrpc.Router_SendPaymentV2Client) (
	*lnrpc.Payment, error) {

	for {
		payment, err := stream.Recv()
		if err != nil {
			return nil, err
		}

		if payment.Status != lnrpc.Payment_IN_FLIGHT {
			return payment, nil
		}
	}
}

// assertNumUTXOs waits for the given number of UTXOs to be available or fails
// if that isn't the case before the default timeout.
func assertNumUTXOs(t *testing.T, node *lntest.HarnessNode, expectedUtxos int) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	err := wait.NoError(func() error {
		resp, err := node.ListUnspent( // nolint:staticcheck
			ctxt, &lnrpc.ListUnspentRequest{
				MinConfs: 1,
				MaxConfs: math.MaxInt32,
			},
		)
		if err != nil {
			return fmt.Errorf("error listing unspent: %v", err)
		}

		if len(resp.Utxos) != expectedUtxos {
			return fmt.Errorf("not enough UTXOs, got %d wanted %d",
				len(resp.Utxos), expectedUtxos)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t, err, "wait for listunspent")
}
