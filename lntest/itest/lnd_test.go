package itest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/labels"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnrpc/watchtowerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/wtclientrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	// defaultSplitTranches is the default number of tranches we split the
	// test cases into.
	defaultSplitTranches uint = 1

	// defaultRunTranche is the default index of the test cases tranche that
	// we run.
	defaultRunTranche uint = 0
)

var (
	// testCasesSplitParts is the number of tranches the test cases should
	// be split into. By default this is set to 1, so no splitting happens.
	// If this value is increased, then the -runtranche flag must be
	// specified as well to indicate which part should be run in the current
	// invocation.
	testCasesSplitTranches = flag.Uint(
		"splittranches", defaultSplitTranches, "split the test cases "+
			"in this many tranches and run the tranche at "+
			"0-based index specified by the -runtranche flag",
	)

	// testCasesRunTranche is the 0-based index of the split test cases
	// tranche to run in the current invocation.
	testCasesRunTranche = flag.Uint(
		"runtranche", defaultRunTranche, "run the tranche of the "+
			"split test cases with the given (0-based) index",
	)

	// dbBackendFlag specifies the backend to use
	dbBackendFlag = flag.String("dbbackend", "bbolt", "Database backend (bbolt, etcd)")
)

// getTestCaseSplitTranche returns the sub slice of the test cases that should
// be run as the current split tranche as well as the index and slice offset of
// the tranche.
func getTestCaseSplitTranche() ([]*testCase, uint, uint) {
	numTranches := defaultSplitTranches
	if testCasesSplitTranches != nil {
		numTranches = *testCasesSplitTranches
	}
	runTranche := defaultRunTranche
	if testCasesRunTranche != nil {
		runTranche = *testCasesRunTranche
	}

	// There's a special flake-hunt mode where we run the same test multiple
	// times in parallel. In that case the tranche index is equal to the
	// thread ID, but we need to actually run all tests for the regex
	// selection to work.
	threadID := runTranche
	if numTranches == 1 {
		runTranche = 0
	}

	numCases := uint(len(allTestCases))
	testsPerTranche := numCases / numTranches
	trancheOffset := runTranche * testsPerTranche
	trancheEnd := trancheOffset + testsPerTranche
	if trancheEnd > numCases || runTranche == numTranches-1 {
		trancheEnd = numCases
	}

	return allTestCases[trancheOffset:trancheEnd], threadID, trancheOffset
}

func rpcPointToWirePoint(t *harnessTest, chanPoint *lnrpc.ChannelPoint) wire.OutPoint {
	txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}

	return wire.OutPoint{
		Hash:  *txid,
		Index: chanPoint.OutputIndex,
	}
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
	if err != nil {
		t.Fatalf("unable to open channel: %v", err)
	}

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
	if err != nil {
		t.Fatalf("error while waiting for channel open: %v", err)
	}
	fundingTxID, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	assertTxInBlock(t, block, fundingTxID)

	// The channel should be listed in the peer information returned by
	// both peers.
	chanPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: fundingChanPoint.OutputIndex,
	}
	if err := net.AssertChannelExists(ctx, alice, &chanPoint); err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}
	if err := net.AssertChannelExists(ctx, bob, &chanPoint); err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}

	return fundingChanPoint
}

// closeChannelAndAssert attempts to close a channel identified by the passed
// channel point owned by the passed Lightning node. A fully blocking channel
// closure is attempted, therefore the passed context should be a child derived
// via timeout from a base parent. Additionally, once the channel has been
// detected as closed, an assertion checks that the transaction is found within
// a block. Finally, this assertion verifies that the node always sends out a
// disable update when closing the channel if the channel was previously enabled.
//
// NOTE: This method assumes that the provided funding point is confirmed
// on-chain AND that the edge exists in the node's channel graph. If the funding
// transactions was reorged out at some point, use closeReorgedChannelAndAssert.
func closeChannelAndAssert(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, node *lntest.HarnessNode,
	fundingChanPoint *lnrpc.ChannelPoint, force bool) *chainhash.Hash {

	return closeChannelAndAssertType(ctx, t, net, node, fundingChanPoint, false, force)
}

func closeChannelAndAssertType(ctx context.Context, t *harnessTest,
	net *lntest.NetworkHarness, node *lntest.HarnessNode,
	fundingChanPoint *lnrpc.ChannelPoint, anchors, force bool) *chainhash.Hash {

	// Fetch the current channel policy. If the channel is currently
	// enabled, we will register for graph notifications before closing to
	// assert that the node sends out a disabling update as a result of the
	// channel being closed.
	curPolicy := getChannelPolicies(t, node, node.PubKeyStr, fundingChanPoint)[0]
	expectDisable := !curPolicy.Disabled

	// If the current channel policy is enabled, begin subscribing the graph
	// updates before initiating the channel closure.
	var graphSub *graphSubscription
	if expectDisable {
		sub := subscribeGraphNotifications(ctx, t, node)
		graphSub = &sub
		defer close(graphSub.quit)
	}

	closeUpdates, _, err := net.CloseChannel(ctx, node, fundingChanPoint, force)
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	chanPointStr := fmt.Sprintf("%v:%v", txid, fundingChanPoint.OutputIndex)

	// If the channel appears in list channels, ensure that its state
	// contains ChanStatusCoopBroadcasted.
	ctxt, _ := context.WithTimeout(ctx, defaultTimeout)
	listChansRequest := &lnrpc.ListChannelsRequest{}
	listChansResp, err := node.ListChannels(ctxt, listChansRequest)
	if err != nil {
		t.Fatalf("unable to query for list channels: %v", err)
	}
	for _, channel := range listChansResp.Channels {
		// Skip other channels.
		if channel.ChannelPoint != chanPointStr {
			continue
		}

		// Assert that the channel is in coop broadcasted.
		if !strings.Contains(channel.ChanStatusFlags,
			channeldb.ChanStatusCoopBroadcasted.String()) {
			t.Fatalf("channel not coop broadcasted, "+
				"got: %v", channel.ChanStatusFlags)
		}
	}

	// At this point, the channel should now be marked as being in the
	// state of "waiting close".
	ctxt, _ = context.WithTimeout(ctx, defaultTimeout)
	pendingChansRequest := &lnrpc.PendingChannelsRequest{}
	pendingChanResp, err := node.PendingChannels(ctxt, pendingChansRequest)
	if err != nil {
		t.Fatalf("unable to query for pending channels: %v", err)
	}
	var found bool
	for _, pendingClose := range pendingChanResp.WaitingCloseChannels {
		if pendingClose.Channel.ChannelPoint == chanPointStr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("channel not marked as waiting close")
	}

	// We'll now, generate a single block, wait for the final close status
	// update, then ensure that the closing transaction was included in the
	// block. If there are anchors, we also expect an anchor sweep.
	expectedTxes := 1
	if anchors {
		expectedTxes = 2
	}

	block := mineBlocks(t, net, 1, expectedTxes)[0]

	closingTxid, err := net.WaitForChannelClose(ctx, closeUpdates)
	if err != nil {
		t.Fatalf("error while waiting for channel close: %v", err)
	}

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
	if err != nil {
		t.Fatalf("closing transaction not marked as fully closed")
	}

	return closingTxid
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
	if err != nil {
		t.Fatalf("channel not pending force close: %v", err)
	}

	// Mine enough blocks for the node to sweep its funds from the force
	// closed channel.
	//
	// The commit sweep resolver is able to broadcast the sweep tx up to
	// one block before the CSV elapses, so wait until defaulCSV-1.
	_, err = net.Miner.Client.Generate(defaultCSV - 1)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	// The node should now sweep the funds, clean up by mining the sweeping
	// tx.
	mineBlocks(t, net, 1, 1)
}

// numOpenChannelsPending sends an RPC request to a node to get a count of the
// node's channels that are currently in a pending state (with a broadcast, but
// not confirmed funding transaction).
func numOpenChannelsPending(ctxt context.Context, node *lntest.HarnessNode) (int, error) {
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
	if err != nil {
		t.Fatalf(err.Error())
	}
}

// assertNumConnections asserts number current connections between two peers.
func assertNumConnections(t *harnessTest, alice, bob *lntest.HarnessNode,
	expected int) {
	ctxb := context.Background()

	const nPolls = 10

	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()

	for i := nPolls - 1; i >= 0; i-- {
		select {
		case <-tick.C:
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			aNumPeers, err := alice.ListPeers(ctxt, &lnrpc.ListPeersRequest{})
			if err != nil {
				t.Fatalf("unable to fetch alice's node (%v) list peers %v",
					alice.NodeID, err)
			}

			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			bNumPeers, err := bob.ListPeers(ctxt, &lnrpc.ListPeersRequest{})
			if err != nil {
				t.Fatalf("unable to fetch bob's node (%v) list peers %v",
					bob.NodeID, err)
			}
			if len(aNumPeers.Peers) != expected {
				// Continue polling if this is not the final
				// loop.
				if i > 0 {
					continue
				}
				t.Fatalf("number of peers connected to alice is incorrect: "+
					"expected %v, got %v", expected, len(aNumPeers.Peers))
			}
			if len(bNumPeers.Peers) != expected {
				// Continue polling if this is not the final
				// loop.
				if i > 0 {
					continue
				}
				t.Fatalf("number of peers connected to bob is incorrect: "+
					"expected %v, got %v", expected, len(bNumPeers.Peers))
			}

			// Alice and Bob both have the required number of
			// peers, stop polling and return to caller.
			return
		}
	}
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
	if err != nil {
		t.Fatalf("unable to shutdown %v: %v", node.Name(), err)
	}
}

// completePaymentRequests sends payments from a lightning node to complete all
// payment requests. If the awaitResponse parameter is true, this function
// does not return until all payments successfully complete without errors.
func completePaymentRequests(ctx context.Context, client lnrpc.LightningClient,
	routerClient routerrpc.RouterClient, paymentRequests []string,
	awaitResponse bool) error {

	// We start by getting the current state of the client's channels. This
	// is needed to ensure the payments actually have been committed before
	// we return.
	ctxt, _ := context.WithTimeout(ctx, defaultTimeout)
	req := &lnrpc.ListChannelsRequest{}
	listResp, err := client.ListChannels(ctxt, req)
	if err != nil {
		return err
	}

	// send sends a payment and returns an error if it doesn't succeeded.
	send := func(payReq string) error {
		ctxc, cancel := context.WithCancel(ctx)
		defer cancel()

		payStream, err := routerClient.SendPaymentV2(
			ctxc,
			&routerrpc.SendPaymentRequest{
				PaymentRequest: payReq,
				TimeoutSeconds: 60,
				FeeLimitMsat:   noFeeLimitMsat,
			},
		)
		if err != nil {
			return err
		}

		resp, err := getPaymentResult(payStream)
		if err != nil {
			return err
		}
		if resp.Status != lnrpc.Payment_SUCCEEDED {
			return errors.New(resp.FailureReason)
		}

		return nil
	}

	// Launch all payments simultaneously.
	results := make(chan error)
	for _, payReq := range paymentRequests {
		payReqCopy := payReq
		go func() {
			err := send(payReqCopy)
			if awaitResponse {
				results <- err
			}
		}()
	}

	// If awaiting a response, verify that all payments succeeded.
	if awaitResponse {
		for range paymentRequests {
			err := <-results
			if err != nil {
				return err
			}
		}
		return nil
	}

	// We are not waiting for feedback in the form of a response, but we
	// should still wait long enough for the server to receive and handle
	// the send before cancelling the request. We wait for the number of
	// updates to one of our channels has increased before we return.
	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctx, defaultTimeout)
		newListResp, err := client.ListChannels(ctxt, req)
		if err != nil {
			return false
		}

		// If the number of open channels is now lower than before
		// attempting the payments, it means one of the payments
		// triggered a force closure (for example, due to an incorrect
		// preimage). Return early since it's clear the payment was
		// attempted.
		if len(newListResp.Channels) < len(listResp.Channels) {
			return true
		}

		for _, c1 := range listResp.Channels {
			for _, c2 := range newListResp.Channels {
				if c1.ChannelPoint != c2.ChannelPoint {
					continue
				}

				// If this channel has an increased numbr of
				// updates, we assume the payments are
				// committed, and we can return.
				if c2.NumUpdates > c1.NumUpdates {
					return true
				}
			}
		}

		return false
	}, defaultTimeout)
	if err != nil {
		return err
	}

	return nil
}

// makeFakePayHash creates random pre image hash
func makeFakePayHash(t *harnessTest) []byte {
	randBuf := make([]byte, 32)

	if _, err := rand.Read(randBuf); err != nil {
		t.Fatalf("internal error, cannot generate random string: %v", err)
	}

	return randBuf
}

// createPayReqs is a helper method that will create a slice of payment
// requests for the given node.
func createPayReqs(node *lntest.HarnessNode, paymentAmt btcutil.Amount,
	numInvoices int) ([]string, [][]byte, []*lnrpc.Invoice, error) {

	payReqs := make([]string, numInvoices)
	rHashes := make([][]byte, numInvoices)
	invoices := make([]*lnrpc.Invoice, numInvoices)
	for i := 0; i < numInvoices; i++ {
		preimage := make([]byte, 32)
		_, err := rand.Read(preimage)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to generate "+
				"preimage: %v", err)
		}
		invoice := &lnrpc.Invoice{
			Memo:      "testing",
			RPreimage: preimage,
			Value:     int64(paymentAmt),
		}
		ctxt, _ := context.WithTimeout(
			context.Background(), defaultTimeout,
		)
		resp, err := node.AddInvoice(ctxt, invoice)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to add "+
				"invoice: %v", err)
		}

		// Set the payment address in the invoice so the caller can
		// properly use it.
		invoice.PaymentAddr = resp.PaymentAddr

		payReqs[i] = resp.PaymentRequest
		rHashes[i] = resp.RHash
		invoices[i] = invoice
	}
	return payReqs, rHashes, invoices, nil
}

// getChanInfo is a helper method for getting channel info for a node's sole
// channel.
func getChanInfo(ctx context.Context, node *lntest.HarnessNode) (
	*lnrpc.Channel, error) {

	req := &lnrpc.ListChannelsRequest{}
	channelInfo, err := node.ListChannels(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(channelInfo.Channels) != 1 {
		return nil, fmt.Errorf("node should only have a single "+
			"channel, instead it has %v", len(channelInfo.Channels))
	}

	return channelInfo.Channels[0], nil
}

// testGetRecoveryInfo checks whether lnd gives the right information about
// the wallet recovery process.
func testGetRecoveryInfo(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, create a new node with strong passphrase and grab the mnemonic
	// used for key derivation. This will bring up Carol with an empty
	// wallet, and such that she is synced up.
	password := []byte("The Magic Words are Squeamish Ossifrage")
	carol, mnemonic, _, err := net.NewNodeWithSeed(
		"Carol", nil, password, false,
	)
	if err != nil {
		t.Fatalf("unable to create node with seed; %v", err)
	}

	shutdownAndAssert(net, t, carol)

	checkInfo := func(expectedRecoveryMode, expectedRecoveryFinished bool,
		expectedProgress float64, recoveryWindow int32) {

		// Restore Carol, passing in the password, mnemonic, and
		// desired recovery window.
		node, err := net.RestoreNodeWithSeed(
			"Carol", nil, password, mnemonic, recoveryWindow, nil,
		)
		if err != nil {
			t.Fatalf("unable to restore node: %v", err)
		}

		// Wait for Carol to sync to the chain.
		_, minerHeight, err := net.Miner.Client.GetBestBlock()
		if err != nil {
			t.Fatalf("unable to get current blockheight %v", err)
		}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		err = waitForNodeBlockHeight(ctxt, node, minerHeight)
		if err != nil {
			t.Fatalf("unable to sync to chain: %v", err)
		}

		// Query carol for her current wallet recovery progress.
		var (
			recoveryMode     bool
			recoveryFinished bool
			progress         float64
		)

		err = wait.Predicate(func() bool {
			// Verify that recovery info gives the right response.
			req := &lnrpc.GetRecoveryInfoRequest{}
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			resp, err := node.GetRecoveryInfo(ctxt, req)
			if err != nil {
				t.Fatalf("unable to query recovery info: %v", err)
			}

			recoveryMode = resp.RecoveryMode
			recoveryFinished = resp.RecoveryFinished
			progress = resp.Progress

			if recoveryMode != expectedRecoveryMode ||
				recoveryFinished != expectedRecoveryFinished ||
				progress != expectedProgress {
				return false
			}

			return true
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("expected recovery mode to be %v, got %v, "+
				"expected recovery finished to be %v, got %v, "+
				"expected progress %v, got %v",
				expectedRecoveryMode, recoveryMode,
				expectedRecoveryFinished, recoveryFinished,
				expectedProgress, progress,
			)
		}

		// Lastly, shutdown this Carol so we can move on to the next
		// restoration.
		shutdownAndAssert(net, t, node)
	}

	// Restore Carol with a recovery window of 0. Since it's not in recovery
	// mode, the recovery info will give a response with recoveryMode=false,
	// recoveryFinished=false, and progress=0
	checkInfo(false, false, 0, 0)

	// Change the recovery windown to be 1 to turn on recovery mode. Since the
	// current chain height is the same as the birthday height, it should
	// indicate the recovery process is finished.
	checkInfo(true, true, 1, 1)

	// We now go ahead 5 blocks. Because the wallet's syncing process is
	// controlled by a goroutine in the background, it will catch up quickly.
	// This makes the recovery progress back to 1.
	mineBlocks(t, net, 5, 0)
	checkInfo(true, true, 1, 1)
}

// testOnchainFundRecovery checks lnd's ability to rescan for onchain outputs
// when providing a valid aezeed that owns outputs on the chain. This test
// performs multiple restorations using the same seed and various recovery
// windows to ensure we detect funds properly.
func testOnchainFundRecovery(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, create a new node with strong passphrase and grab the mnemonic
	// used for key derivation. This will bring up Carol with an empty
	// wallet, and such that she is synced up.
	password := []byte("The Magic Words are Squeamish Ossifrage")
	carol, mnemonic, _, err := net.NewNodeWithSeed(
		"Carol", nil, password, false,
	)
	if err != nil {
		t.Fatalf("unable to create node with seed; %v", err)
	}
	shutdownAndAssert(net, t, carol)

	// Create a closure for testing the recovery of Carol's wallet. This
	// method takes the expected value of Carol's balance when using the
	// given recovery window. Additionally, the caller can specify an action
	// to perform on the restored node before the node is shutdown.
	restoreCheckBalance := func(expAmount int64, expectedNumUTXOs uint32,
		recoveryWindow int32, fn func(*lntest.HarnessNode)) {

		// Restore Carol, passing in the password, mnemonic, and
		// desired recovery window.
		node, err := net.RestoreNodeWithSeed(
			"Carol", nil, password, mnemonic, recoveryWindow, nil,
		)
		if err != nil {
			t.Fatalf("unable to restore node: %v", err)
		}

		// Query carol for her current wallet balance, and also that we
		// gain the expected number of UTXOs.
		var (
			currBalance  int64
			currNumUTXOs uint32
		)
		err = wait.Predicate(func() bool {
			req := &lnrpc.WalletBalanceRequest{}
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			resp, err := node.WalletBalance(ctxt, req)
			if err != nil {
				t.Fatalf("unable to query wallet balance: %v",
					err)
			}
			currBalance = resp.ConfirmedBalance

			utxoReq := &lnrpc.ListUnspentRequest{
				MaxConfs: math.MaxInt32,
			}
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			utxoResp, err := node.ListUnspent(ctxt, utxoReq)
			if err != nil {
				t.Fatalf("unable to query utxos: %v", err)
			}
			currNumUTXOs = uint32(len(utxoResp.Utxos))

			// Verify that Carol's balance and number of UTXOs
			// matches what's expected.
			if expAmount != currBalance {
				return false
			}
			if currNumUTXOs != expectedNumUTXOs {
				return false
			}

			return true
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("expected restored node to have %d satoshis, "+
				"instead has %d satoshis, expected %d utxos "+
				"instead has %d", expAmount, currBalance,
				expectedNumUTXOs, currNumUTXOs)
		}

		// If the user provided a callback, execute the commands against
		// the restored Carol.
		if fn != nil {
			fn(node)
		}

		// Lastly, shutdown this Carol so we can move on to the next
		// restoration.
		shutdownAndAssert(net, t, node)
	}

	// Create a closure-factory for building closures that can generate and
	// skip a configurable number of addresses, before finally sending coins
	// to a next generated address. The returned closure will apply the same
	// behavior to both default P2WKH and NP2WKH scopes.
	skipAndSend := func(nskip int) func(*lntest.HarnessNode) {
		return func(node *lntest.HarnessNode) {
			newP2WKHAddrReq := &lnrpc.NewAddressRequest{
				Type: AddrTypeWitnessPubkeyHash,
			}

			newNP2WKHAddrReq := &lnrpc.NewAddressRequest{
				Type: AddrTypeNestedPubkeyHash,
			}

			// Generate and skip the number of addresses requested.
			for i := 0; i < nskip; i++ {
				ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
				_, err = node.NewAddress(ctxt, newP2WKHAddrReq)
				if err != nil {
					t.Fatalf("unable to generate new "+
						"p2wkh address: %v", err)
				}

				ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
				_, err = node.NewAddress(ctxt, newNP2WKHAddrReq)
				if err != nil {
					t.Fatalf("unable to generate new "+
						"np2wkh address: %v", err)
				}
			}

			// Send one BTC to the next P2WKH address.
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			net.SendCoins(
				ctxt, t.t, btcutil.SatoshiPerBitcoin, node,
			)

			// And another to the next NP2WKH address.
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			net.SendCoinsNP2WKH(
				ctxt, t.t, btcutil.SatoshiPerBitcoin, node,
			)
		}
	}

	// Restore Carol with a recovery window of 0. Since no coins have been
	// sent, her balance should be zero.
	//
	// After, one BTC is sent to both her first external P2WKH and NP2WKH
	// addresses.
	restoreCheckBalance(0, 0, 0, skipAndSend(0))

	// Check that restoring without a look-ahead results in having no funds
	// in the wallet, even though they exist on-chain.
	restoreCheckBalance(0, 0, 0, nil)

	// Now, check that using a look-ahead of 1 recovers the balance from
	// the two transactions above. We should also now have 2 UTXOs in the
	// wallet at the end of the recovery attempt.
	//
	// After, we will generate and skip 9 P2WKH and NP2WKH addresses, and
	// send another BTC to the subsequent 10th address in each derivation
	// path.
	restoreCheckBalance(2*btcutil.SatoshiPerBitcoin, 2, 1, skipAndSend(9))

	// Check that using a recovery window of 9 does not find the two most
	// recent txns.
	restoreCheckBalance(2*btcutil.SatoshiPerBitcoin, 2, 9, nil)

	// Extending our recovery window to 10 should find the most recent
	// transactions, leaving the wallet with 4 BTC total. We should also
	// learn of the two additional UTXOs created above.
	//
	// After, we will skip 19 more addrs, sending to the 20th address past
	// our last found address, and repeat the same checks.
	restoreCheckBalance(4*btcutil.SatoshiPerBitcoin, 4, 10, skipAndSend(19))

	// Check that recovering with a recovery window of 19 fails to find the
	// most recent transactions.
	restoreCheckBalance(4*btcutil.SatoshiPerBitcoin, 4, 19, nil)

	// Ensure that using a recovery window of 20 succeeds with all UTXOs
	// found and the final balance reflected.

	// After these checks are done, we'll want to make sure we can also
	// recover change address outputs.  This is mainly motivated by a now
	// fixed bug in the wallet in which change addresses could at times be
	// created outside of the default key scopes. Recovery only used to be
	// performed on the default key scopes, so ideally this test case
	// would've caught the bug earlier. Carol has received 6 BTC so far from
	// the miner, we'll send 5 back to ensure all of her UTXOs get spent to
	// avoid fee discrepancies and a change output is formed.
	const minerAmt = 5 * btcutil.SatoshiPerBitcoin
	const finalBalance = 6 * btcutil.SatoshiPerBitcoin
	promptChangeAddr := func(node *lntest.HarnessNode) {
		minerAddr, err := net.Miner.NewAddress()
		if err != nil {
			t.Fatalf("unable to create new miner address: %v", err)
		}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		resp, err := node.SendCoins(ctxt, &lnrpc.SendCoinsRequest{
			Addr:   minerAddr.String(),
			Amount: minerAmt,
		})
		if err != nil {
			t.Fatalf("unable to send coins to miner: %v", err)
		}
		txid, err := waitForTxInMempool(
			net.Miner.Client, minerMempoolTimeout,
		)
		if err != nil {
			t.Fatalf("transaction not found in mempool: %v", err)
		}
		if resp.Txid != txid.String() {
			t.Fatalf("txid mismatch: %v vs %v", resp.Txid,
				txid.String())
		}
		block := mineBlocks(t, net, 1, 1)[0]
		assertTxInBlock(t, block, txid)
	}
	restoreCheckBalance(finalBalance, 6, 20, promptChangeAddr)

	// We should expect a static fee of 27750 satoshis for spending 6 inputs
	// (3 P2WPKH, 3 NP2WPKH) to two P2WPKH outputs. Carol should therefore
	// only have one UTXO present (the change output) of 6 - 5 - fee BTC.
	const fee = 27750
	restoreCheckBalance(finalBalance-minerAmt-fee, 1, 21, nil)
}

// nodeArgsForCommitType returns the command line flag to supply to enable this
// commitment type.
func nodeArgsForCommitType(commitType lnrpc.CommitmentType) []string {
	switch commitType {
	case lnrpc.CommitmentType_LEGACY:
		return []string{"--protocol.legacy.committweak"}
	case lnrpc.CommitmentType_STATIC_REMOTE_KEY:
		return []string{}
	case lnrpc.CommitmentType_ANCHORS:
		return []string{"--protocol.anchors"}
	}

	return nil
}

// calcStaticFee calculates appropriate fees for commitment transactions.  This
// function provides a simple way to allow test balance assertions to take fee
// calculations into account.
func calcStaticFee(commitType lnrpc.CommitmentType, numHTLCs int) btcutil.Amount {
	const htlcWeight = input.HTLCWeight
	var (
		feePerKw     = chainfee.SatPerKVByte(50000).FeePerKWeight()
		commitWeight = input.CommitWeight
		anchors      = btcutil.Amount(0)
	)

	// The anchor commitment type is slightly heavier, and we must also add
	// the value of the two anchors to the resulting fee the initiator
	// pays. In addition the fee rate is capped at 10 sat/vbyte for anchor
	// channels.
	if commitType == lnrpc.CommitmentType_ANCHORS {
		feePerKw = chainfee.SatPerKVByte(
			lnwallet.DefaultAnchorsCommitMaxFeeRateSatPerVByte * 1000,
		).FeePerKWeight()
		commitWeight = input.AnchorCommitWeight
		anchors = 2 * anchorSize
	}

	return feePerKw.FeeForWeight(int64(commitWeight+htlcWeight*numHTLCs)) +
		anchors
}

// channelCommitType retrieves the active channel commitment type for the given
// chan point.
func channelCommitType(node *lntest.HarnessNode,
	chanPoint *lnrpc.ChannelPoint) (lnrpc.CommitmentType, error) {

	ctxb := context.Background()
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)

	req := &lnrpc.ListChannelsRequest{}
	channels, err := node.ListChannels(ctxt, req)
	if err != nil {
		return 0, fmt.Errorf("listchannels failed: %v", err)
	}

	for _, c := range channels.Channels {
		if c.ChannelPoint == txStr(chanPoint) {
			return c.CommitmentType, nil
		}
	}

	return 0, fmt.Errorf("channel point %v not found", chanPoint)
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

// testPaymentFollowingChannelOpen tests that the channel transition from
// 'pending' to 'open' state does not cause any inconsistencies within other
// subsystems trying to update the channel state in the db. We follow this
// transition with a payment that updates the commitment state and verify that
// the pending state is up to date.
func testPaymentFollowingChannelOpen(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const paymentAmt = btcutil.Amount(100)
	channelCapacity := paymentAmt * 1000

	// We first establish a channel between Alice and Bob.
	ctxt, cancel := context.WithTimeout(ctxb, channelOpenTimeout)
	defer cancel()
	pendingUpdate, err := net.OpenPendingChannel(
		ctxt, net.Alice, net.Bob, channelCapacity, 0,
	)
	if err != nil {
		t.Fatalf("unable to open channel: %v", err)
	}

	// At this point, the channel's funding transaction will have been
	// broadcast, but not confirmed. Alice and Bob's nodes
	// should reflect this when queried via RPC.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	assertNumOpenChannelsPending(ctxt, t, net.Alice, net.Bob, 1)

	// We are restarting Bob's node to let the link be created for the
	// pending channel.
	if err := net.RestartNode(net.Bob, nil); err != nil {
		t.Fatalf("Bob restart failed: %v", err)
	}

	// We ensure that Bob reconnects to Alice.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, net.Bob, net.Alice)

	// We mine one block for the channel to be confirmed.
	_ = mineBlocks(t, net, 6, 1)[0]

	// We verify that the channel is open from both nodes point of view.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	assertNumOpenChannelsPending(ctxt, t, net.Alice, net.Bob, 0)

	// With the channel open, we'll create invoices for Bob that Alice will
	// pay to in order to advance the state of the channel.
	bobPayReqs, _, _, err := createPayReqs(
		net.Bob, paymentAmt, 1,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Send payment to Bob so that a channel update to disk will be
	// executed.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	sendAndAssertSuccess(
		ctxt, t, net.Alice, &routerrpc.SendPaymentRequest{
			PaymentRequest: bobPayReqs[0],
			TimeoutSeconds: 60,
			FeeLimitSat:    1000000,
		},
	)

	// At this point we want to make sure the channel is opened and not
	// pending.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	res, err := net.Bob.ListChannels(ctxt, &lnrpc.ListChannelsRequest{})
	if err != nil {
		t.Fatalf("unable to list bob channels: %v", err)
	}
	if len(res.Channels) == 0 {
		t.Fatalf("bob list of channels is empty")
	}

	// Finally, immediately close the channel. This function will also
	// block until the channel is closed and will additionally assert the
	// relevant channel closing post conditions.
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: pendingUpdate.Txid,
		},
		OutputIndex: pendingUpdate.OutputIndex,
	}
	ctxt, cancel = context.WithTimeout(ctxb, channelCloseTimeout)
	defer cancel()
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
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

// expectedChanUpdate houses params we expect a ChannelUpdate to advertise.
type expectedChanUpdate struct {
	advertisingNode string
	expectedPolicy  *lnrpc.RoutingPolicy
	chanPoint       *lnrpc.ChannelPoint
}

// calculateMaxHtlc re-implements the RequiredRemoteChannelReserve of the
// funding manager's config, which corresponds to the maximum MaxHTLC value we
// allow users to set when updating a channel policy.
func calculateMaxHtlc(chanCap btcutil.Amount) uint64 {
	reserve := lnwire.NewMSatFromSatoshis(chanCap / 100)
	max := lnwire.NewMSatFromSatoshis(chanCap) - reserve
	return uint64(max)
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
				if len(expUpdates) == 0 {
					t.Fatalf("received unexpected channel "+
						"update from %v for channel %v",
						update.AdvertisingNode,
						update.ChanId)
				}

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
			if len(graphUpdate.ChannelUpdates) > 0 {
				t.Fatalf("received %d channel updates when "+
					"none were expected",
					len(graphUpdate.ChannelUpdates))
			}

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

// testUpdateChannelPolicy tests that policy updates made to a channel
// gets propagated to other nodes in the network.
func testUpdateChannelPolicy(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		defaultFeeBase       = 1000
		defaultFeeRate       = 1
		defaultTimeLockDelta = chainreg.DefaultBitcoinTimeLockDelta
		defaultMinHtlc       = 1000
	)
	defaultMaxHtlc := calculateMaxHtlc(funding.MaxBtcFundingAmount)

	// Launch notification clients for all nodes, such that we can
	// get notified when they discover new channels and updates in the
	// graph.
	aliceSub := subscribeGraphNotifications(ctxb, t, net.Alice)
	defer close(aliceSub.quit)
	bobSub := subscribeGraphNotifications(ctxb, t, net.Bob)
	defer close(bobSub.quit)

	chanAmt := funding.MaxBtcFundingAmount
	pushAmt := chanAmt / 2

	// Create a channel Alice->Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)

	// We add all the nodes' update channels to a slice, such that we can
	// make sure they all receive the expected updates.
	graphSubs := []graphSubscription{aliceSub, bobSub}
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob}

	// Alice and Bob should see each other's ChannelUpdates, advertising the
	// default routing policies.
	expectedPolicy := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      defaultFeeBase,
		FeeRateMilliMsat: defaultFeeRate,
		TimeLockDelta:    defaultTimeLockDelta,
		MinHtlc:          defaultMinHtlc,
		MaxHtlcMsat:      defaultMaxHtlc,
	}

	for _, graphSub := range graphSubs {
		waitForChannelUpdate(
			t, graphSub,
			[]expectedChanUpdate{
				{net.Alice.PubKeyStr, expectedPolicy, chanPoint},
				{net.Bob.PubKeyStr, expectedPolicy, chanPoint},
			},
		)
	}

	// They should now know about the default policies.
	for _, node := range nodes {
		assertChannelPolicy(
			t, node, net.Alice.PubKeyStr, expectedPolicy, chanPoint,
		)
		assertChannelPolicy(
			t, node, net.Bob.PubKeyStr, expectedPolicy, chanPoint,
		)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't report channel: %v", err)
	}
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}

	// Create Carol with options to rate limit channel updates up to 2 per
	// day, and create a new channel Bob->Carol.
	carol := net.NewNode(
		t.t, "Carol", []string{
			"--gossip.max-channel-update-burst=2",
			"--gossip.channel-update-interval=24h",
		},
	)

	// Clean up carol's node when the test finishes.
	defer shutdownAndAssert(net, t, carol)

	carolSub := subscribeGraphNotifications(ctxb, t, carol)
	defer close(carolSub.quit)

	graphSubs = append(graphSubs, carolSub)
	nodes = append(nodes, carol)

	// Send some coins to Carol that can be used for channel funding.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	net.ConnectNodes(ctxb, t.t, carol, net.Bob)

	// Open the channel Carol->Bob with a custom min_htlc value set. Since
	// Carol is opening the channel, she will require Bob to not forward
	// HTLCs smaller than this value, and hence he should advertise it as
	// part of his ChannelUpdate.
	const customMinHtlc = 5000
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint2 := openChannelAndAssert(
		ctxt, t, net, carol, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
			MinHtlc: customMinHtlc,
		},
	)

	expectedPolicyBob := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      defaultFeeBase,
		FeeRateMilliMsat: defaultFeeRate,
		TimeLockDelta:    defaultTimeLockDelta,
		MinHtlc:          customMinHtlc,
		MaxHtlcMsat:      defaultMaxHtlc,
	}
	expectedPolicyCarol := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      defaultFeeBase,
		FeeRateMilliMsat: defaultFeeRate,
		TimeLockDelta:    defaultTimeLockDelta,
		MinHtlc:          defaultMinHtlc,
		MaxHtlcMsat:      defaultMaxHtlc,
	}

	for _, graphSub := range graphSubs {
		waitForChannelUpdate(
			t, graphSub,
			[]expectedChanUpdate{
				{net.Bob.PubKeyStr, expectedPolicyBob, chanPoint2},
				{carol.PubKeyStr, expectedPolicyCarol, chanPoint2},
			},
		)
	}

	// Check that all nodes now know about the updated policies.
	for _, node := range nodes {
		assertChannelPolicy(
			t, node, net.Bob.PubKeyStr, expectedPolicyBob,
			chanPoint2,
		)
		assertChannelPolicy(
			t, node, carol.PubKeyStr, expectedPolicyCarol,
			chanPoint2,
		)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint2)
	if err != nil {
		t.Fatalf("alice didn't report channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint2)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint2)
	if err != nil {
		t.Fatalf("carol didn't report channel: %v", err)
	}

	// First we'll try to send a payment from Alice to Carol with an amount
	// less than the min_htlc value required by Carol. This payment should
	// fail, as the channel Bob->Carol cannot carry HTLCs this small.
	payAmt := btcutil.Amount(4)
	invoice := &lnrpc.Invoice{
		Memo:  "testing",
		Value: int64(payAmt),
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient,
		[]string{resp.PaymentRequest}, true,
	)

	// Alice knows about the channel policy of Carol and should therefore
	// not be able to find a path during routing.
	expErr := lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE
	if err.Error() != expErr.String() {
		t.Fatalf("expected %v, instead got %v", expErr, err)
	}

	// Now we try to send a payment over the channel with a value too low
	// to be accepted. First we query for a route to route a payment of
	// 5000 mSAT, as this is accepted.
	payAmt = btcutil.Amount(5)
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey:         carol.PubKeyStr,
		Amt:            int64(payAmt),
		FinalCltvDelta: defaultTimeLockDelta,
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	routes, err := net.Alice.QueryRoutes(ctxt, routesReq)
	if err != nil {
		t.Fatalf("unable to get route: %v", err)
	}

	if len(routes.Routes) != 1 {
		t.Fatalf("expected to find 1 route, got %v", len(routes.Routes))
	}

	// We change the route to carry a payment of 4000 mSAT instead of 5000
	// mSAT.
	payAmt = btcutil.Amount(4)
	amtSat := int64(payAmt)
	amtMSat := int64(lnwire.NewMSatFromSatoshis(payAmt))
	routes.Routes[0].Hops[0].AmtToForward = amtSat
	routes.Routes[0].Hops[0].AmtToForwardMsat = amtMSat
	routes.Routes[0].Hops[1].AmtToForward = amtSat
	routes.Routes[0].Hops[1].AmtToForwardMsat = amtMSat

	// Send the payment with the modified value.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	alicePayStream, err := net.Alice.SendToRoute(ctxt)
	if err != nil {
		t.Fatalf("unable to create payment stream for alice: %v", err)
	}
	sendReq := &lnrpc.SendToRouteRequest{
		PaymentHash: resp.RHash,
		Route:       routes.Routes[0],
	}

	err = alicePayStream.Send(sendReq)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// We expect this payment to fail, and that the min_htlc value is
	// communicated back to us, since the attempted HTLC value was too low.
	sendResp, err := alicePayStream.Recv()
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// Expected as part of the error message.
	substrs := []string{
		"AmountBelowMinimum",
		"HtlcMinimumMsat: (lnwire.MilliSatoshi) 5000 mSAT",
	}
	for _, s := range substrs {
		if !strings.Contains(sendResp.PaymentError, s) {
			t.Fatalf("expected error to contain \"%v\", instead "+
				"got %v", s, sendResp.PaymentError)
		}
	}

	// Make sure sending using the original value succeeds.
	payAmt = btcutil.Amount(5)
	amtSat = int64(payAmt)
	amtMSat = int64(lnwire.NewMSatFromSatoshis(payAmt))
	routes.Routes[0].Hops[0].AmtToForward = amtSat
	routes.Routes[0].Hops[0].AmtToForwardMsat = amtMSat
	routes.Routes[0].Hops[1].AmtToForward = amtSat
	routes.Routes[0].Hops[1].AmtToForwardMsat = amtMSat

	// Manually set the MPP payload a new for each payment since
	// the payment addr will change with each invoice, although we
	// can re-use the route itself.
	route := routes.Routes[0]
	route.Hops[len(route.Hops)-1].TlvPayload = true
	route.Hops[len(route.Hops)-1].MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  resp.PaymentAddr,
		TotalAmtMsat: amtMSat,
	}

	sendReq = &lnrpc.SendToRouteRequest{
		PaymentHash: resp.RHash,
		Route:       route,
	}

	err = alicePayStream.Send(sendReq)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	sendResp, err = alicePayStream.Recv()
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	if sendResp.PaymentError != "" {
		t.Fatalf("expected payment to succeed, instead got %v",
			sendResp.PaymentError)
	}

	// With our little cluster set up, we'll update the fees and the max htlc
	// size for the Bob side of the Alice->Bob channel, and make sure
	// all nodes learn about it.
	baseFee := int64(1500)
	feeRate := int64(12)
	timeLockDelta := uint32(66)
	maxHtlc := uint64(500000)

	expectedPolicy = &lnrpc.RoutingPolicy{
		FeeBaseMsat:      baseFee,
		FeeRateMilliMsat: testFeeBase * feeRate,
		TimeLockDelta:    timeLockDelta,
		MinHtlc:          defaultMinHtlc,
		MaxHtlcMsat:      maxHtlc,
	}

	req := &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   baseFee,
		FeeRate:       float64(feeRate),
		TimeLockDelta: timeLockDelta,
		MaxHtlcMsat:   maxHtlc,
		Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPoint,
		},
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if _, err := net.Bob.UpdateChannelPolicy(ctxt, req); err != nil {
		t.Fatalf("unable to get alice's balance: %v", err)
	}

	// Wait for all nodes to have seen the policy update done by Bob.
	for _, graphSub := range graphSubs {
		waitForChannelUpdate(
			t, graphSub,
			[]expectedChanUpdate{
				{net.Bob.PubKeyStr, expectedPolicy, chanPoint},
			},
		)
	}

	// Check that all nodes now know about Bob's updated policy.
	for _, node := range nodes {
		assertChannelPolicy(
			t, node, net.Bob.PubKeyStr, expectedPolicy, chanPoint,
		)
	}

	// Now that all nodes have received the new channel update, we'll try
	// to send a payment from Alice to Carol to ensure that Alice has
	// internalized this fee update. This shouldn't affect the route that
	// Alice takes though: we updated the Alice -> Bob channel and she
	// doesn't pay for transit over that channel as it's direct.
	// Note that the payment amount is >= the min_htlc value for the
	// channel Bob->Carol, so it should successfully be forwarded.
	payAmt = btcutil.Amount(5)
	invoice = &lnrpc.Invoice{
		Memo:  "testing",
		Value: int64(payAmt),
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err = carol.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient,
		[]string{resp.PaymentRequest}, true,
	)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// We'll now open a channel from Alice directly to Carol.
	net.ConnectNodes(ctxb, t.t, net.Alice, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint3 := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint3)
	if err != nil {
		t.Fatalf("alice didn't report channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint3)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}

	// Make a global update, and check that both channels' new policies get
	// propagated.
	baseFee = int64(800)
	feeRate = int64(123)
	timeLockDelta = uint32(22)
	maxHtlc *= 2

	expectedPolicy.FeeBaseMsat = baseFee
	expectedPolicy.FeeRateMilliMsat = testFeeBase * feeRate
	expectedPolicy.TimeLockDelta = timeLockDelta
	expectedPolicy.MaxHtlcMsat = maxHtlc

	req = &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   baseFee,
		FeeRate:       float64(feeRate),
		TimeLockDelta: timeLockDelta,
		MaxHtlcMsat:   maxHtlc,
	}
	req.Scope = &lnrpc.PolicyUpdateRequest_Global{}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.UpdateChannelPolicy(ctxt, req)
	if err != nil {
		t.Fatalf("unable to update alice's channel policy: %v", err)
	}

	// Wait for all nodes to have seen the policy updates for both of
	// Alice's channels.
	for _, graphSub := range graphSubs {
		waitForChannelUpdate(
			t, graphSub,
			[]expectedChanUpdate{
				{net.Alice.PubKeyStr, expectedPolicy, chanPoint},
				{net.Alice.PubKeyStr, expectedPolicy, chanPoint3},
			},
		)
	}

	// And finally check that all nodes remembers the policy update they
	// received.
	for _, node := range nodes {
		assertChannelPolicy(
			t, node, net.Alice.PubKeyStr, expectedPolicy,
			chanPoint, chanPoint3,
		)
	}

	// Now, to test that Carol is properly rate limiting incoming updates,
	// we'll send two more update from Alice. Carol should accept the first,
	// but not the second, as she only allows two updates per day and a day
	// has yet to elapse from the previous update.
	const numUpdatesTilRateLimit = 2
	for i := 0; i < numUpdatesTilRateLimit; i++ {
		prevAlicePolicy := *expectedPolicy
		baseFee *= 2
		expectedPolicy.FeeBaseMsat = baseFee
		req.BaseFeeMsat = baseFee

		ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
		defer cancel()
		_, err = net.Alice.UpdateChannelPolicy(ctxt, req)
		if err != nil {
			t.Fatalf("unable to update alice's channel policy: %v", err)
		}

		// Wait for all nodes to have seen the policy updates for both
		// of Alice's channels. Carol will not see the last update as
		// the limit has been reached.
		for idx, graphSub := range graphSubs {
			expUpdates := []expectedChanUpdate{
				{net.Alice.PubKeyStr, expectedPolicy, chanPoint},
				{net.Alice.PubKeyStr, expectedPolicy, chanPoint3},
			}
			// Carol was added last, which is why we check the last
			// index.
			if i == numUpdatesTilRateLimit-1 && idx == len(graphSubs)-1 {
				expUpdates = nil
			}
			waitForChannelUpdate(t, graphSub, expUpdates)
		}

		// And finally check that all nodes remembers the policy update
		// they received. Since Carol didn't receive the last update,
		// she still has Alice's old policy.
		for idx, node := range nodes {
			policy := expectedPolicy
			// Carol was added last, which is why we check the last
			// index.
			if i == numUpdatesTilRateLimit-1 && idx == len(nodes)-1 {
				policy = &prevAlicePolicy
			}
			assertChannelPolicy(
				t, node, net.Alice.PubKeyStr, policy, chanPoint,
				chanPoint3,
			)
		}
	}

	// Close the channels.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPoint2, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint3, false)
}

// waitForNodeBlockHeight queries the node for its current block height until
// it reaches the passed height.
func waitForNodeBlockHeight(ctx context.Context, node *lntest.HarnessNode,
	height int32) error {
	var predErr error
	err := wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctx, defaultTimeout)
		info, err := node.GetInfo(ctxt, &lnrpc.GetInfoRequest{})
		if err != nil {
			predErr = err
			return false
		}

		if int32(info.BlockHeight) != height {
			predErr = fmt.Errorf("expected block height to "+
				"be %v, was %v", height, info.BlockHeight)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		return predErr
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

// testOpenChannelAfterReorg tests that in the case where we have an open
// channel where the funding tx gets reorged out, the channel will no
// longer be present in the node's routing table.
func testOpenChannelAfterReorg(net *lntest.NetworkHarness, t *harnessTest) {
	// Skip test for neutrino, as we cannot disconnect the miner at will.
	// TODO(halseth): remove when either can disconnect at will, or restart
	// node with connection to new miner.
	if net.BackendCfg.Name() == lntest.NeutrinoBackendName {
		t.Skipf("skipping reorg test for neutrino backend")
	}

	var (
		ctxb = context.Background()
		temp = "temp"
	)

	// Set up a new miner that we can use to cause a reorg.
	tempLogDir := fmt.Sprintf("%s/.tempminerlogs", lntest.GetLogDir())
	logFilename := "output-open_channel_reorg-temp_miner.log"
	tempMiner, tempMinerCleanUp, err := lntest.NewMiner(
		tempLogDir, logFilename, harnessNetParams,
		&rpcclient.NotificationHandlers{}, lntest.GetBtcdBinary(),
	)
	require.NoError(t.t, err, "failed to create temp miner")
	defer func() {
		require.NoError(
			t.t, tempMinerCleanUp(),
			"failed to clean up temp miner",
		)
	}()

	// Setup the temp miner
	require.NoError(
		t.t, tempMiner.SetUp(false, 0), "unable to set up mining node",
	)

	// We start by connecting the new miner to our original miner,
	// such that it will sync to our original chain.
	err = net.Miner.Client.Node(
		btcjson.NConnect, tempMiner.P2PAddress(), &temp,
	)
	if err != nil {
		t.Fatalf("unable to remove node: %v", err)
	}
	nodeSlice := []*rpctest.Harness{net.Miner, tempMiner}
	if err := rpctest.JoinNodes(nodeSlice, rpctest.Blocks); err != nil {
		t.Fatalf("unable to join node on blocks: %v", err)
	}

	// The two miners should be on the same blockheight.
	assertMinerBlockHeightDelta(t, net.Miner, tempMiner, 0)

	// We disconnect the two miners, such that we can mine two different
	// chains and can cause a reorg later.
	err = net.Miner.Client.Node(
		btcjson.NDisconnect, tempMiner.P2PAddress(), &temp,
	)
	if err != nil {
		t.Fatalf("unable to remove node: %v", err)
	}

	// Create a new channel that requires 1 confs before it's considered
	// open, then broadcast the funding transaction
	chanAmt := funding.MaxBtcFundingAmount
	pushAmt := btcutil.Amount(0)
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	pendingUpdate, err := net.OpenPendingChannel(ctxt, net.Alice, net.Bob,
		chanAmt, pushAmt)
	if err != nil {
		t.Fatalf("unable to open channel: %v", err)
	}

	// Wait for miner to have seen the funding tx. The temporary miner is
	// disconnected, and won't see the transaction.
	_, err = waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("failed to find funding tx in mempool: %v", err)
	}

	// At this point, the channel's funding transaction will have been
	// broadcast, but not confirmed, and the channel should be pending.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, net.Alice, net.Bob, 1)

	fundingTxID, err := chainhash.NewHash(pendingUpdate.Txid)
	if err != nil {
		t.Fatalf("unable to convert funding txid into chainhash.Hash:"+
			" %v", err)
	}

	// We now cause a fork, by letting our original miner mine 10 blocks,
	// and our new miner mine 15. This will also confirm our pending
	// channel on the original miner's chain, which should be considered
	// open.
	block := mineBlocks(t, net, 10, 1)[0]
	assertTxInBlock(t, block, fundingTxID)
	if _, err := tempMiner.Client.Generate(15); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	// Ensure the chain lengths are what we expect, with the temp miner
	// being 5 blocks ahead.
	assertMinerBlockHeightDelta(t, net.Miner, tempMiner, 5)

	// Wait for Alice to sync to the original miner's chain.
	_, minerHeight, err := net.Miner.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get current blockheight %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForNodeBlockHeight(ctxt, net.Alice, minerHeight)
	if err != nil {
		t.Fatalf("unable to sync to chain: %v", err)
	}

	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: pendingUpdate.Txid,
		},
		OutputIndex: pendingUpdate.OutputIndex,
	}

	// Ensure channel is no longer pending.
	assertNumOpenChannelsPending(ctxt, t, net.Alice, net.Bob, 0)

	// Wait for Alice and Bob to recognize and advertise the new channel
	// generated above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't advertise channel before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't advertise channel before "+
			"timeout: %v", err)
	}

	// Alice should now have 1 edge in her graph.
	req := &lnrpc.ChannelGraphRequest{
		IncludeUnannounced: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	chanGraph, err := net.Alice.DescribeGraph(ctxt, req)
	if err != nil {
		t.Fatalf("unable to query for alice's routing table: %v", err)
	}

	numEdges := len(chanGraph.Edges)
	if numEdges != 1 {
		t.Fatalf("expected to find one edge in the graph, found %d",
			numEdges)
	}

	// Now we disconnect Alice's chain backend from the original miner, and
	// connect the two miners together. Since the temporary miner knows
	// about a longer chain, both miners should sync to that chain.
	err = net.BackendCfg.DisconnectMiner()
	if err != nil {
		t.Fatalf("unable to remove node: %v", err)
	}

	// Connecting to the temporary miner should now cause our original
	// chain to be re-orged out.
	err = net.Miner.Client.Node(
		btcjson.NConnect, tempMiner.P2PAddress(), &temp,
	)
	if err != nil {
		t.Fatalf("unable to remove node: %v", err)
	}

	nodes := []*rpctest.Harness{tempMiner, net.Miner}
	if err := rpctest.JoinNodes(nodes, rpctest.Blocks); err != nil {
		t.Fatalf("unable to join node on blocks: %v", err)
	}

	// Once again they should be on the same chain.
	assertMinerBlockHeightDelta(t, net.Miner, tempMiner, 0)

	// Now we disconnect the two miners, and connect our original miner to
	// our chain backend once again.
	err = net.Miner.Client.Node(
		btcjson.NDisconnect, tempMiner.P2PAddress(), &temp,
	)
	if err != nil {
		t.Fatalf("unable to remove node: %v", err)
	}

	err = net.BackendCfg.ConnectMiner()
	if err != nil {
		t.Fatalf("unable to remove node: %v", err)
	}

	// This should have caused a reorg, and Alice should sync to the longer
	// chain, where the funding transaction is not confirmed.
	_, tempMinerHeight, err := tempMiner.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get current blockheight %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForNodeBlockHeight(ctxt, net.Alice, tempMinerHeight)
	if err != nil {
		t.Fatalf("unable to sync to chain: %v", err)
	}

	// Since the fundingtx was reorged out, Alice should now have no edges
	// in her graph.
	req = &lnrpc.ChannelGraphRequest{
		IncludeUnannounced: true,
	}

	var predErr error
	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		chanGraph, err = net.Alice.DescribeGraph(ctxt, req)
		if err != nil {
			predErr = fmt.Errorf("unable to query for alice's routing table: %v", err)
			return false
		}

		numEdges = len(chanGraph.Edges)
		if numEdges != 0 {
			predErr = fmt.Errorf("expected to find no edge in the graph, found %d",
				numEdges)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	// Cleanup by mining the funding tx again, then closing the channel.
	block = mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, fundingTxID)

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeReorgedChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
}

// testDisconnectingTargetPeer performs a test which disconnects Alice-peer from
// Bob-peer and then re-connects them again. We expect Alice to be able to
// disconnect at any point.
func testDisconnectingTargetPeer(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// We'll start both nodes with a high backoff so that they don't
	// reconnect automatically during our test.
	args := []string{
		"--minbackoff=1m",
		"--maxbackoff=1m",
	}

	alice := net.NewNode(t.t, "Alice", args)
	defer shutdownAndAssert(net, t, alice)

	bob := net.NewNode(t.t, "Bob", args)
	defer shutdownAndAssert(net, t, bob)

	// Start by connecting Alice and Bob with no channels.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, bob)

	// Check existing connection.
	assertNumConnections(t, alice, bob, 1)

	// Give Alice some coins so she can fund a channel.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, alice)

	chanAmt := funding.MaxBtcFundingAmount
	pushAmt := btcutil.Amount(0)

	// Create a new channel that requires 1 confs before it's considered
	// open, then broadcast the funding transaction
	const numConfs = 1
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	pendingUpdate, err := net.OpenPendingChannel(
		ctxt, alice, bob, chanAmt, pushAmt,
	)
	if err != nil {
		t.Fatalf("unable to open channel: %v", err)
	}

	// At this point, the channel's funding transaction will have been
	// broadcast, but not confirmed. Alice and Bob's nodes should reflect
	// this when queried via RPC.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, alice, bob, 1)

	// Disconnect Alice-peer from Bob-peer and get error causes by one
	// pending channel with detach node is existing.
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("Bob's peer was disconnected from Alice's"+
			" while one pending channel is existing: err %v", err)
	}

	time.Sleep(time.Millisecond * 300)

	// Assert that the connection was torn down.
	assertNumConnections(t, alice, bob, 0)

	fundingTxID, err := chainhash.NewHash(pendingUpdate.Txid)
	if err != nil {
		t.Fatalf("unable to convert funding txid into chainhash.Hash:"+
			" %v", err)
	}

	// Mine a block, then wait for Alice's node to notify us that the
	// channel has been opened. The funding transaction should be found
	// within the newly mined block.
	block := mineBlocks(t, net, numConfs, 1)[0]
	assertTxInBlock(t, block, fundingTxID)

	// At this point, the channel should be fully opened and there should be
	// no pending channels remaining for either node.
	time.Sleep(time.Millisecond * 300)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)

	assertNumOpenChannelsPending(ctxt, t, alice, bob, 0)

	// Reconnect the nodes so that the channel can become active.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, bob)

	// The channel should be listed in the peer information returned by both
	// peers.
	outPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: pendingUpdate.OutputIndex,
	}

	// Check both nodes to ensure that the channel is ready for operation.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.AssertChannelExists(ctxt, alice, &outPoint); err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.AssertChannelExists(ctxt, bob, &outPoint); err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}

	// Disconnect Alice-peer from Bob-peer and get error causes by one
	// active channel with detach node is existing.
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("Bob's peer was disconnected from Alice's"+
			" while one active channel is existing: err %v", err)
	}

	// Check existing connection.
	assertNumConnections(t, alice, bob, 0)

	// Reconnect both nodes before force closing the channel.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, bob)

	// Finally, immediately close the channel. This function will also block
	// until the channel is closed and will additionally assert the relevant
	// channel closing post conditions.
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: pendingUpdate.Txid,
		},
		OutputIndex: pendingUpdate.OutputIndex,
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, alice, chanPoint, true)

	// Disconnect Alice-peer from Bob-peer without getting error about
	// existing channels.
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("unable to disconnect Bob's peer from Alice's: err %v",
			err)
	}

	// Check zero peer connections.
	assertNumConnections(t, alice, bob, 0)

	// Finally, re-connect both nodes.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, bob)

	// Check existing connection.
	assertNumConnections(t, alice, net.Bob, 1)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, alice, chanPoint)
}

// testFundingPersistence is intended to ensure that the Funding Manager
// persists the state of new channels prior to broadcasting the channel's
// funding transaction. This ensures that the daemon maintains an up-to-date
// representation of channels if the system is restarted or disconnected.
// testFundingPersistence mirrors testBasicChannelFunding, but adds restarts
// and checks for the state of channels with unconfirmed funding transactions.
func testChannelFundingPersistence(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	chanAmt := funding.MaxBtcFundingAmount
	pushAmt := btcutil.Amount(0)

	// As we need to create a channel that requires more than 1
	// confirmation before it's open, with the current set of defaults,
	// we'll need to create a new node instance.
	const numConfs = 5
	carolArgs := []string{fmt.Sprintf("--bitcoin.defaultchanconfs=%v", numConfs)}
	carol := net.NewNode(t.t, "Carol", carolArgs)

	// Clean up carol's node when the test finishes.
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, carol)

	// Create a new channel that requires 5 confs before it's considered
	// open, then broadcast the funding transaction
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	pendingUpdate, err := net.OpenPendingChannel(ctxt, net.Alice, carol,
		chanAmt, pushAmt)
	if err != nil {
		t.Fatalf("unable to open channel: %v", err)
	}

	// At this point, the channel's funding transaction will have been
	// broadcast, but not confirmed. Alice and Bob's nodes should reflect
	// this when queried via RPC.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, net.Alice, carol, 1)

	// Restart both nodes to test that the appropriate state has been
	// persisted and that both nodes recover gracefully.
	if err := net.RestartNode(net.Alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	fundingTxID, err := chainhash.NewHash(pendingUpdate.Txid)
	if err != nil {
		t.Fatalf("unable to convert funding txid into chainhash.Hash:"+
			" %v", err)
	}
	fundingTxStr := fundingTxID.String()

	// Mine a block, then wait for Alice's node to notify us that the
	// channel has been opened. The funding transaction should be found
	// within the newly mined block.
	block := mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, fundingTxID)

	// Get the height that our transaction confirmed at.
	_, height, err := net.Miner.Client.GetBestBlock()
	require.NoError(t.t, err, "could not get best block")

	// Restart both nodes to test that the appropriate state has been
	// persisted and that both nodes recover gracefully.
	if err := net.RestartNode(net.Alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// The following block ensures that after both nodes have restarted,
	// they have reconnected before the execution of the next test.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, net.Alice, carol)

	// Next, mine enough blocks s.t the channel will open with a single
	// additional block mined.
	if _, err := net.Miner.Client.Generate(3); err != nil {
		t.Fatalf("unable to mine blocks: %v", err)
	}

	// Assert that our wallet has our opening transaction with a label
	// that does not have a channel ID set yet, because we have not
	// reached our required confirmations.
	tx := findTxAtHeight(ctxt, t, height, fundingTxStr, net.Alice)

	// At this stage, we expect the transaction to be labelled, but not with
	// our channel ID because our transaction has not yet confirmed.
	label := labels.MakeLabel(labels.LabelTypeChannelOpen, nil)
	require.Equal(t.t, label, tx.Label, "open channel label wrong")

	// Both nodes should still show a single channel as pending.
	time.Sleep(time.Second * 1)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, net.Alice, carol, 1)

	// Finally, mine the last block which should mark the channel as open.
	if _, err := net.Miner.Client.Generate(1); err != nil {
		t.Fatalf("unable to mine blocks: %v", err)
	}

	// At this point, the channel should be fully opened and there should
	// be no pending channels remaining for either node.
	time.Sleep(time.Second * 1)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, net.Alice, carol, 0)

	// The channel should be listed in the peer information returned by
	// both peers.
	outPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: pendingUpdate.OutputIndex,
	}

	// Re-lookup our transaction in the block that it confirmed in.
	tx = findTxAtHeight(ctxt, t, height, fundingTxStr, net.Alice)

	// Create an additional check for our channel assertion that will
	// check that our label is as expected.
	check := func(channel *lnrpc.Channel) {
		shortChanID := lnwire.NewShortChanIDFromInt(
			channel.ChanId,
		)

		label := labels.MakeLabel(
			labels.LabelTypeChannelOpen, &shortChanID,
		)
		require.Equal(t.t, label, tx.Label,
			"open channel label not updated")
	}

	// Check both nodes to ensure that the channel is ready for operation.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.AssertChannelExists(ctxt, net.Alice, &outPoint, check)
	if err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.AssertChannelExists(ctxt, carol, &outPoint); err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}

	// Finally, immediately close the channel. This function will also
	// block until the channel is closed and will additionally assert the
	// relevant channel closing post conditions.
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: pendingUpdate.Txid,
		},
		OutputIndex: pendingUpdate.OutputIndex,
	}
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
}

// findTxAtHeight gets all of the transactions that a node's wallet has a record
// of at the target height, and finds and returns the tx with the target txid,
// failing if it is not found.
func findTxAtHeight(ctx context.Context, t *harnessTest, height int32,
	target string, node *lntest.HarnessNode) *lnrpc.Transaction {

	txns, err := node.LightningClient.GetTransactions(
		ctx, &lnrpc.GetTransactionsRequest{
			StartHeight: height,
			EndHeight:   height,
		},
	)
	require.NoError(t.t, err, "could not get transactions")

	for _, tx := range txns.Transactions {
		if tx.TxHash == target {
			return tx
		}
	}

	return nil
}

// testChannelBalance creates a new channel between Alice and Bob, then checks
// channel balance to be equal amount specified while creation of channel.
func testChannelBalance(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// Open a channel with 0.16 BTC between Alice and Bob, ensuring the
	// channel has been opened properly.
	amount := funding.MaxBtcFundingAmount

	// Creates a helper closure to be used below which asserts the proper
	// response to a channel balance RPC.
	checkChannelBalance := func(node *lntest.HarnessNode,
		local, remote btcutil.Amount) {

		expectedResponse := &lnrpc.ChannelBalanceResponse{
			LocalBalance: &lnrpc.Amount{
				Sat:  uint64(local),
				Msat: uint64(lnwire.NewMSatFromSatoshis(local)),
			},
			RemoteBalance: &lnrpc.Amount{
				Sat: uint64(remote),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					remote,
				)),
			},
			UnsettledLocalBalance:    &lnrpc.Amount{},
			UnsettledRemoteBalance:   &lnrpc.Amount{},
			PendingOpenLocalBalance:  &lnrpc.Amount{},
			PendingOpenRemoteBalance: &lnrpc.Amount{},
			// Deprecated fields.
			Balance: int64(local),
		}
		assertChannelBalanceResp(t, node, expectedResponse)
	}

	// Before beginning, make sure alice and bob are connected.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, net.Alice, net.Bob)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: amount,
		},
	)

	// Wait for both Alice and Bob to recognize this new channel.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't advertise channel before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't advertise channel before "+
			"timeout: %v", err)
	}

	cType, err := channelCommitType(net.Alice, chanPoint)
	if err != nil {
		t.Fatalf("unable to get channel type: %v", err)
	}

	// As this is a single funder channel, Alice's balance should be
	// exactly 0.5 BTC since now state transitions have taken place yet.
	checkChannelBalance(net.Alice, amount-calcStaticFee(cType, 0), 0)

	// Ensure Bob currently has no available balance within the channel.
	checkChannelBalance(net.Bob, 0, amount-calcStaticFee(cType, 0))

	// Finally close the channel between Alice and Bob, asserting that the
	// channel has been properly closed on-chain.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
}

// testChannelUnsettledBalance will test that the UnsettledBalance field
// is updated according to the number of Pending Htlcs.
// Alice will send Htlcs to Carol while she is in hodl mode. This will result
// in a build of pending Htlcs. We expect the channels unsettled balance to
// equal the sum of all the Pending Htlcs.
func testChannelUnsettledBalance(net *lntest.NetworkHarness, t *harnessTest) {
	const chanAmt = btcutil.Amount(1000000)
	ctxb := context.Background()

	// Creates a helper closure to be used below which asserts the proper
	// response to a channel balance RPC.
	checkChannelBalance := func(node *lntest.HarnessNode,
		local, remote, unsettledLocal, unsettledRemote btcutil.Amount) {

		expectedResponse := &lnrpc.ChannelBalanceResponse{
			LocalBalance: &lnrpc.Amount{
				Sat: uint64(local),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					local,
				)),
			},
			RemoteBalance: &lnrpc.Amount{
				Sat: uint64(remote),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					remote,
				)),
			},
			UnsettledLocalBalance: &lnrpc.Amount{
				Sat: uint64(unsettledLocal),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					unsettledLocal,
				)),
			},
			UnsettledRemoteBalance: &lnrpc.Amount{
				Sat: uint64(unsettledRemote),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					unsettledRemote,
				)),
			},
			PendingOpenLocalBalance:  &lnrpc.Amount{},
			PendingOpenRemoteBalance: &lnrpc.Amount{},
			// Deprecated fields.
			Balance: int64(local),
		}
		assertChannelBalanceResp(t, node, expectedResponse)
	}

	// Create carol in hodl mode.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	defer shutdownAndAssert(net, t, carol)

	// Connect Alice to Carol.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxb, t.t, net.Alice, carol)

	// Open a channel between Alice and Carol.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Wait for Alice and Carol to receive the channel edge from the
	// funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPointAlice)
	if err != nil {
		t.Fatalf("alice didn't see the alice->carol channel before "+
			"timeout: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointAlice)
	if err != nil {
		t.Fatalf("alice didn't see the alice->carol channel before "+
			"timeout: %v", err)
	}

	cType, err := channelCommitType(net.Alice, chanPointAlice)
	require.NoError(t.t, err, "unable to get channel type")

	// Check alice's channel balance, which should have zero remote and zero
	// pending balance.
	checkChannelBalance(net.Alice, chanAmt-calcStaticFee(cType, 0), 0, 0, 0)

	// Check carol's channel balance, which should have zero local and zero
	// pending balance.
	checkChannelBalance(carol, 0, chanAmt-calcStaticFee(cType, 0), 0, 0)

	// Channel should be ready for payments.
	const (
		payAmt      = 100
		numInvoices = 6
	)

	// Simulateneously send numInvoices payments from Alice to Carol.
	carolPubKey := carol.PubKey[:]
	errChan := make(chan error)
	for i := 0; i < numInvoices; i++ {
		go func() {
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			_, err := net.Alice.RouterClient.SendPaymentV2(ctxt,
				&routerrpc.SendPaymentRequest{
					Dest:           carolPubKey,
					Amt:            int64(payAmt),
					PaymentHash:    makeFakePayHash(t),
					FinalCltvDelta: chainreg.DefaultBitcoinTimeLockDelta,
					TimeoutSeconds: 60,
					FeeLimitMsat:   noFeeLimitMsat,
				})

			if err != nil {
				errChan <- err
			}
		}()
	}

	// Test that the UnsettledBalance for both Alice and Carol
	// is equal to the amount of invoices * payAmt.
	var unsettledErr error
	nodes := []*lntest.HarnessNode{net.Alice, carol}
	err = wait.Predicate(func() bool {
		// There should be a number of PendingHtlcs equal
		// to the amount of Invoices sent.
		unsettledErr = assertNumActiveHtlcs(nodes, numInvoices)
		if unsettledErr != nil {
			return false
		}

		// Set the amount expected for the Unsettled Balance for
		// this channel.
		expectedBalance := numInvoices * payAmt

		// Check each nodes UnsettledBalance field.
		for _, node := range nodes {
			// Get channel info for the node.
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			chanInfo, err := getChanInfo(ctxt, node)
			if err != nil {
				unsettledErr = err
				return false
			}

			// Check that UnsettledBalance is what we expect.
			if int(chanInfo.UnsettledBalance) != expectedBalance {
				unsettledErr = fmt.Errorf("unsettled balance failed "+
					"expected: %v, received: %v", expectedBalance,
					chanInfo.UnsettledBalance)
				return false
			}
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("unsettled balace error: %v", unsettledErr)
	}

	// Check for payment errors.
	select {
	case err := <-errChan:
		t.Fatalf("payment error: %v", err)
	default:
	}

	// Check alice's channel balance, which should have a remote unsettled
	// balance that equals to the amount of invoices * payAmt. The remote
	// balance remains zero.
	aliceLocal := chanAmt - calcStaticFee(cType, 0) - numInvoices*payAmt
	checkChannelBalance(net.Alice, aliceLocal, 0, 0, numInvoices*payAmt)

	// Check carol's channel balance, which should have a local unsettled
	// balance that equals to the amount of invoices * payAmt. The local
	// balance remains zero.
	checkChannelBalance(carol, 0, aliceLocal, numInvoices*payAmt, 0)

	// Force and assert the channel closure.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, true)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, net.Alice, chanPointAlice)
}

// findForceClosedChannel searches a pending channel response for a particular
// channel, returning the force closed channel upon success.
func findForceClosedChannel(pendingChanResp *lnrpc.PendingChannelsResponse,
	op *wire.OutPoint) (*lnrpc.PendingChannelsResponse_ForceClosedChannel, error) {

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
	op *wire.OutPoint) (*lnrpc.PendingChannelsResponse_WaitingCloseChannel, error) {

	for _, waitingClose := range pendingChanResp.WaitingCloseChannels {
		if waitingClose.Channel.ChannelPoint == op.String() {
			return waitingClose, nil
		}
	}

	return nil, errors.New("channel not marked as waiting close")
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

// padCLTV is a small helper function that pads a cltv value with a block
// padding.
func padCLTV(cltv uint32) uint32 {
	return cltv + uint32(routing.BlockPadding)
}

// testChannelForceClosure performs a test to exercise the behavior of "force"
// closing a channel or unilaterally broadcasting the latest local commitment
// state on-chain. The test creates a new channel between Alice and Carol, then
// force closes the channel after some cursory assertions. Within the test, a
// total of 3 + n transactions will be broadcast, representing the commitment
// transaction, a transaction sweeping the local CSV delayed output, a
// transaction sweeping the CSV delayed 2nd-layer htlcs outputs, and n
// htlc timeout transactions, where n is the number of payments Alice attempted
// to send to Carol.  This test includes several restarts to ensure that the
// transaction output states are persisted throughout the forced closure
// process.
//
// TODO(roasbeef): also add an unsettled HTLC before force closing.
func testChannelForceClosure(net *lntest.NetworkHarness, t *harnessTest) {
	// We'll test the scenario for some of the commitment types, to ensure
	// outputs can be swept.
	commitTypes := []lnrpc.CommitmentType{
		lnrpc.CommitmentType_LEGACY,
		lnrpc.CommitmentType_ANCHORS,
	}

	for _, commitType := range commitTypes {
		commitType := commitType
		testName := fmt.Sprintf("committype=%v", commitType)
		logLine := fmt.Sprintf(
			"---- channel force close subtest %s ----\n",
			testName,
		)
		AddToNodeLog(t.t, net.Alice, logLine)

		success := t.t.Run(testName, func(t *testing.T) {
			ht := newHarnessTest(t, net)

			args := nodeArgsForCommitType(commitType)
			alice := net.NewNode(ht.t, "Alice", args)
			defer shutdownAndAssert(net, ht, alice)

			// Since we'd like to test failure scenarios with
			// outstanding htlcs, we'll introduce another node into
			// our test network: Carol.
			carolArgs := []string{"--hodl.exit-settle"}
			carolArgs = append(carolArgs, args...)
			carol := net.NewNode(ht.t, "Carol", carolArgs)
			defer shutdownAndAssert(net, ht, carol)

			// Each time, we'll send Alice  new set of coins in
			// order to fund the channel.
			ctxt, _ := context.WithTimeout(
				context.Background(), defaultTimeout,
			)
			net.SendCoins(ctxt, t, btcutil.SatoshiPerBitcoin, alice)

			// Also give Carol some coins to allow her to sweep her
			// anchor.
			net.SendCoins(ctxt, t, btcutil.SatoshiPerBitcoin, carol)

			channelForceClosureTest(
				net, ht, alice, carol, commitType,
			)
		})
		if !success {
			return
		}
	}
}

func channelForceClosureTest(net *lntest.NetworkHarness, t *harnessTest,
	alice, carol *lntest.HarnessNode, commitType lnrpc.CommitmentType) {

	ctxb := context.Background()

	const (
		chanAmt     = btcutil.Amount(10e6)
		pushAmt     = btcutil.Amount(5e6)
		paymentAmt  = 100000
		numInvoices = 6
	)

	const commitFeeRate = 20000
	net.SetFeeEstimate(commitFeeRate)

	// TODO(roasbeef): should check default value in config here
	// instead, or make delay a param
	defaultCLTV := uint32(chainreg.DefaultBitcoinTimeLockDelta)

	// We must let Alice have an open channel before she can send a node
	// announcement, so we open a channel with Carol,
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, carol)

	// Before we start, obtain Carol's current wallet balance, we'll check
	// to ensure that at the end of the force closure by Alice, Carol
	// recognizes his new on-chain output.
	carolBalReq := &lnrpc.WalletBalanceRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalResp, err := carol.WalletBalance(ctxt, carolBalReq)
	if err != nil {
		t.Fatalf("unable to get carol's balance: %v", err)
	}

	carolStartingBalance := carolBalResp.ConfirmedBalance

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, alice, carol,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)

	// Wait for Alice and Carol to receive the channel edge from the
	// funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't see the alice->carol channel before "+
			"timeout: %v", err)
	}
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't see the alice->carol channel before "+
			"timeout: %v", err)
	}

	// Send payments from Alice to Carol, since Carol is htlchodl mode, the
	// htlc outputs should be left unsettled, and should be swept by the
	// utxo nursery.
	carolPubKey := carol.PubKey[:]
	for i := 0; i < numInvoices; i++ {
		ctx, cancel := context.WithCancel(ctxb)
		defer cancel()

		_, err := alice.RouterClient.SendPaymentV2(
			ctx,
			&routerrpc.SendPaymentRequest{
				Dest:           carolPubKey,
				Amt:            int64(paymentAmt),
				PaymentHash:    makeFakePayHash(t),
				FinalCltvDelta: chainreg.DefaultBitcoinTimeLockDelta,
				TimeoutSeconds: 60,
				FeeLimitMsat:   noFeeLimitMsat,
			},
		)
		if err != nil {
			t.Fatalf("unable to send alice htlc: %v", err)
		}
	}

	// Once the HTLC has cleared, all the nodes n our mini network should
	// show that the HTLC has been locked in.
	nodes := []*lntest.HarnessNode{alice, carol}
	var predErr error
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodes, numInvoices)
		if predErr != nil {
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Fetch starting height of this test so we can compute the block
	// heights we expect certain events to take place.
	_, curHeight, err := net.Miner.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get best block height")
	}

	// Using the current height of the chain, derive the relevant heights
	// for incubating two-stage htlcs.
	var (
		startHeight           = uint32(curHeight)
		commCsvMaturityHeight = startHeight + 1 + defaultCSV
		htlcExpiryHeight      = padCLTV(startHeight + defaultCLTV)
		htlcCsvMaturityHeight = padCLTV(startHeight + defaultCLTV + 1 + defaultCSV)
	)

	// If we are dealing with an anchor channel type, the sweeper will
	// sweep the HTLC second level output one block earlier (than the
	// nursery that waits an additional block, and handles non-anchor
	// channels). So we set a maturity height that is one less.
	if commitType == lnrpc.CommitmentType_ANCHORS {
		htlcCsvMaturityHeight = padCLTV(
			startHeight + defaultCLTV + defaultCSV,
		)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceChan, err := getChanInfo(ctxt, alice)
	if err != nil {
		t.Fatalf("unable to get alice's channel info: %v", err)
	}
	if aliceChan.NumUpdates == 0 {
		t.Fatalf("alice should see at least one update to her channel")
	}

	// Now that the channel is open and we have unsettled htlcs, immediately
	// execute a force closure of the channel. This will also assert that
	// the commitment transaction was immediately broadcast in order to
	// fulfill the force closure request.
	const actualFeeRate = 30000
	net.SetFeeEstimate(actualFeeRate)

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	_, closingTxID, err := net.CloseChannel(ctxt, alice, chanPoint, true)
	if err != nil {
		t.Fatalf("unable to execute force channel closure: %v", err)
	}

	// Now that the channel has been force closed, it should show up in the
	// PendingChannels RPC under the waiting close section.
	pendingChansRequest := &lnrpc.PendingChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	pendingChanResp, err := alice.PendingChannels(ctxt, pendingChansRequest)
	if err != nil {
		t.Fatalf("unable to query for pending channels: %v", err)
	}
	err = checkNumWaitingCloseChannels(pendingChanResp, 1)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Compute the outpoint of the channel, which we will use repeatedly to
	// locate the pending channel information in the rpc responses.
	txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	op := wire.OutPoint{
		Hash:  *txid,
		Index: chanPoint.OutputIndex,
	}

	waitingClose, err := findWaitingCloseChannel(pendingChanResp, &op)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Immediately after force closing, all of the funds should be in limbo.
	if waitingClose.LimboBalance == 0 {
		t.Fatalf("all funds should still be in limbo")
	}

	// Create a map of outpoints to expected resolutions for alice and carol
	// which we will add reports to as we sweep outputs.
	var (
		aliceReports = make(map[string]*lnrpc.Resolution)
		carolReports = make(map[string]*lnrpc.Resolution)
	)

	// The several restarts in this test are intended to ensure that when a
	// channel is force-closed, the UTXO nursery has persisted the state of
	// the channel in the closure process and will recover the correct state
	// when the system comes back on line. This restart tests state
	// persistence at the beginning of the process, when the commitment
	// transaction has been broadcast but not yet confirmed in a block.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Mine a block which should confirm the commitment transaction
	// broadcast as a result of the force closure. If there are anchors, we
	// also expect the anchor sweep tx to be in the mempool.
	expectedTxes := 1
	expectedFeeRate := commitFeeRate
	if commitType == lnrpc.CommitmentType_ANCHORS {
		expectedTxes = 2
		expectedFeeRate = actualFeeRate
	}

	sweepTxns, err := getNTxsFromMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("failed to find commitment in miner mempool: %v", err)
	}

	// Verify fee rate of the commitment tx plus anchor if present.
	var totalWeight, totalFee int64
	for _, tx := range sweepTxns {
		utx := btcutil.NewTx(tx)
		totalWeight += blockchain.GetTransactionWeight(utx)

		fee, err := getTxFee(net.Miner.Client, tx)
		require.NoError(t.t, err)
		totalFee += int64(fee)
	}
	feeRate := totalFee * 1000 / totalWeight

	// Allow some deviation because weight estimates during tx generation
	// are estimates.
	require.InEpsilon(t.t, expectedFeeRate, feeRate, 0.005)

	// Find alice's commit sweep and anchor sweep (if present) in the
	// mempool.
	aliceCloseTx := waitingClose.Commitments.LocalTxid
	_, aliceAnchor := findCommitAndAnchor(
		t, net, sweepTxns, aliceCloseTx,
	)

	// If we expect anchors, add alice's anchor to our expected set of
	// reports.
	if commitType == lnrpc.CommitmentType_ANCHORS {
		aliceReports[aliceAnchor.OutPoint.String()] = &lnrpc.Resolution{
			ResolutionType: lnrpc.ResolutionType_ANCHOR,
			Outcome:        lnrpc.ResolutionOutcome_CLAIMED,
			SweepTxid:      aliceAnchor.SweepTx,
			Outpoint: &lnrpc.OutPoint{
				TxidBytes:   aliceAnchor.OutPoint.Hash[:],
				TxidStr:     aliceAnchor.OutPoint.Hash.String(),
				OutputIndex: aliceAnchor.OutPoint.Index,
			},
			AmountSat: uint64(anchorSize),
		}
	}

	if _, err := net.Miner.Client.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Now that the commitment has been confirmed, the channel should be
	// marked as force closed.
	err = wait.NoError(func() error {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			return fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
		}

		err = checkNumForceClosedChannels(pendingChanResp, 1)
		if err != nil {
			return err
		}

		forceClose, err := findForceClosedChannel(pendingChanResp, &op)
		if err != nil {
			return err
		}

		// Now that the channel has been force closed, it should now
		// have the height and number of blocks to confirm populated.
		err = checkCommitmentMaturity(
			forceClose, commCsvMaturityHeight, int32(defaultCSV),
		)
		if err != nil {
			return err
		}

		// None of our outputs have been swept, so they should all be in
		// limbo. For anchors, we expect the anchor amount to be
		// recovered.
		if forceClose.LimboBalance == 0 {
			return errors.New("all funds should still be in " +
				"limbo")
		}
		expectedRecoveredBalance := int64(0)
		if commitType == lnrpc.CommitmentType_ANCHORS {
			expectedRecoveredBalance = anchorSize
		}
		if forceClose.RecoveredBalance != expectedRecoveredBalance {
			return errors.New("no funds should yet be shown " +
				"as recovered")
		}

		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	// The following restart is intended to ensure that outputs from the
	// force close commitment transaction have been persisted once the
	// transaction has been confirmed, but before the outputs are spendable
	// (the "kindergarten" bucket.)
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Carol's sweep tx should be in the mempool already, as her output is
	// not timelocked. If there are anchors, we also expect Carol's anchor
	// sweep now.
	sweepTxns, err = getNTxsFromMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("failed to find Carol's sweep in miner mempool: %v",
			err)
	}

	// Calculate the total fee Carol paid.
	var totalFeeCarol btcutil.Amount
	for _, tx := range sweepTxns {
		fee, err := getTxFee(net.Miner.Client, tx)
		require.NoError(t.t, err)

		totalFeeCarol += fee
	}

	// We look up the sweep txns we have found in mempool and create
	// expected resolutions for carol.
	carolCommit, carolAnchor := findCommitAndAnchor(
		t, net, sweepTxns, aliceCloseTx,
	)

	// If we have anchors, add an anchor resolution for carol.
	if commitType == lnrpc.CommitmentType_ANCHORS {
		carolReports[carolAnchor.OutPoint.String()] = &lnrpc.Resolution{
			ResolutionType: lnrpc.ResolutionType_ANCHOR,
			Outcome:        lnrpc.ResolutionOutcome_CLAIMED,
			SweepTxid:      carolAnchor.SweepTx,
			AmountSat:      anchorSize,
			Outpoint: &lnrpc.OutPoint{
				TxidBytes:   carolAnchor.OutPoint.Hash[:],
				TxidStr:     carolAnchor.OutPoint.Hash.String(),
				OutputIndex: carolAnchor.OutPoint.Index,
			},
		}
	}

	// Currently within the codebase, the default CSV is 4 relative blocks.
	// For the persistence test, we generate two blocks, then trigger
	// a restart and then generate the final block that should trigger
	// the creation of the sweep transaction.
	if _, err := net.Miner.Client.Generate(defaultCSV - 2); err != nil {
		t.Fatalf("unable to mine blocks: %v", err)
	}

	// The following restart checks to ensure that outputs in the
	// kindergarten bucket are persisted while waiting for the required
	// number of confirmations to be reported.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Alice should see the channel in her set of pending force closed
	// channels with her funds still in limbo.
	var aliceBalance int64
	err = wait.NoError(func() error {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			return fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
		}

		err = checkNumForceClosedChannels(pendingChanResp, 1)
		if err != nil {
			return err
		}

		forceClose, err := findForceClosedChannel(
			pendingChanResp, &op,
		)
		if err != nil {
			return err
		}

		// Make a record of the balances we expect for alice and carol.
		aliceBalance = forceClose.Channel.LocalBalance

		// At this point, the nursery should show that the commitment
		// output has 2 block left before its CSV delay expires. In
		// total, we have mined exactly defaultCSV blocks, so the htlc
		// outputs should also reflect that this many blocks have
		// passed.
		err = checkCommitmentMaturity(
			forceClose, commCsvMaturityHeight, 2,
		)
		if err != nil {
			return err
		}

		// All funds should still be shown in limbo.
		if forceClose.LimboBalance == 0 {
			return errors.New("all funds should still be in " +
				"limbo")
		}
		expectedRecoveredBalance := int64(0)
		if commitType == lnrpc.CommitmentType_ANCHORS {
			expectedRecoveredBalance = anchorSize
		}
		if forceClose.RecoveredBalance != expectedRecoveredBalance {
			return errors.New("no funds should yet be shown " +
				"as recovered")
		}

		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Generate an additional block, which should cause the CSV delayed
	// output from the commitment txn to expire.
	if _, err := net.Miner.Client.Generate(1); err != nil {
		t.Fatalf("unable to mine blocks: %v", err)
	}

	// At this point, the CSV will expire in the next block, meaning that
	// the sweeping transaction should now be broadcast. So we fetch the
	// node's mempool to ensure it has been properly broadcast.
	sweepingTXID, err := waitForTxInMempool(
		net.Miner.Client, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("failed to get sweep tx from mempool: %v", err)
	}

	// Fetch the sweep transaction, all input it's spending should be from
	// the commitment transaction which was broadcast on-chain.
	sweepTx, err := net.Miner.Client.GetRawTransaction(sweepingTXID)
	if err != nil {
		t.Fatalf("unable to fetch sweep tx: %v", err)
	}
	for _, txIn := range sweepTx.MsgTx().TxIn {
		if !closingTxID.IsEqual(&txIn.PreviousOutPoint.Hash) {
			t.Fatalf("sweep transaction not spending from commit "+
				"tx %v, instead spending %v",
				closingTxID, txIn.PreviousOutPoint)
		}
	}

	// We expect a resolution which spends our commit output.
	output := sweepTx.MsgTx().TxIn[0].PreviousOutPoint
	aliceReports[output.String()] = &lnrpc.Resolution{
		ResolutionType: lnrpc.ResolutionType_COMMIT,
		Outcome:        lnrpc.ResolutionOutcome_CLAIMED,
		SweepTxid:      sweepingTXID.String(),
		Outpoint: &lnrpc.OutPoint{
			TxidBytes:   output.Hash[:],
			TxidStr:     output.Hash.String(),
			OutputIndex: output.Index,
		},
		AmountSat: uint64(aliceBalance),
	}

	carolReports[carolCommit.OutPoint.String()] = &lnrpc.Resolution{
		ResolutionType: lnrpc.ResolutionType_COMMIT,
		Outcome:        lnrpc.ResolutionOutcome_CLAIMED,
		Outpoint: &lnrpc.OutPoint{
			TxidBytes:   carolCommit.OutPoint.Hash[:],
			TxidStr:     carolCommit.OutPoint.Hash.String(),
			OutputIndex: carolCommit.OutPoint.Index,
		},
		AmountSat: uint64(pushAmt),
		SweepTxid: carolCommit.SweepTx,
	}

	// Check that we can find the commitment sweep in our set of known
	// sweeps, using the simple transaction id ListSweeps output.
	assertSweepFound(ctxb, t.t, alice, sweepingTXID.String(), false)

	// Restart Alice to ensure that she resumes watching the finalized
	// commitment sweep txid.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Next, we mine an additional block which should include the sweep
	// transaction as the input scripts and the sequence locks on the
	// inputs should be properly met.
	blockHash, err := net.Miner.Client.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
	block, err := net.Miner.Client.GetBlock(blockHash[0])
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}

	assertTxInBlock(t, block, sweepTx.Hash())

	// Update current height
	_, curHeight, err = net.Miner.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get best block height")
	}

	err = wait.Predicate(func() bool {
		// Now that the commit output has been fully swept, check to see
		// that the channel remains open for the pending htlc outputs.
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}

		err = checkNumForceClosedChannels(pendingChanResp, 1)
		if err != nil {
			predErr = err
			return false
		}

		// The commitment funds will have been recovered after the
		// commit txn was included in the last block. The htlc funds
		// will be shown in limbo.
		forceClose, err := findForceClosedChannel(pendingChanResp, &op)
		if err != nil {
			predErr = err
			return false
		}
		predErr = checkPendingChannelNumHtlcs(forceClose, numInvoices)
		if predErr != nil {
			return false
		}
		predErr = checkPendingHtlcStageAndMaturity(
			forceClose, 1, htlcExpiryHeight,
			int32(htlcExpiryHeight)-curHeight,
		)
		if predErr != nil {
			return false
		}
		if forceClose.LimboBalance == 0 {
			predErr = fmt.Errorf("expected funds in limbo, found 0")
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	// Compute the height preceding that which will cause the htlc CLTV
	// timeouts will expire. The outputs entered at the same height as the
	// output spending from the commitment txn, so we must deduct the number
	// of blocks we have generated since adding it to the nursery, and take
	// an additional block off so that we end up one block shy of the expiry
	// height, and add the block padding.
	cltvHeightDelta := padCLTV(defaultCLTV - defaultCSV - 1 - 1)

	// Advance the blockchain until just before the CLTV expires, nothing
	// exciting should have happened during this time.
	if _, err := net.Miner.Client.Generate(cltvHeightDelta); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// We now restart Alice, to ensure that she will broadcast the presigned
	// htlc timeout txns after the delay expires after experiencing a while
	// waiting for the htlc outputs to incubate.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Alice should now see the channel in her set of pending force closed
	// channels with one pending HTLC.
	err = wait.NoError(func() error {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			return fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
		}

		err = checkNumForceClosedChannels(pendingChanResp, 1)
		if err != nil {
			return err
		}

		forceClose, err := findForceClosedChannel(
			pendingChanResp, &op,
		)
		if err != nil {
			return err
		}

		// We should now be at the block just before the utxo nursery
		// will attempt to broadcast the htlc timeout transactions.
		err = checkPendingChannelNumHtlcs(forceClose, numInvoices)
		if err != nil {
			return err
		}
		err = checkPendingHtlcStageAndMaturity(
			forceClose, 1, htlcExpiryHeight, 1,
		)
		if err != nil {
			return err
		}

		// Now that our commitment confirmation depth has been
		// surpassed, we should now see a non-zero recovered balance.
		// All htlc outputs are still left in limbo, so it should be
		// non-zero as well.
		if forceClose.LimboBalance == 0 {
			return errors.New("htlc funds should still be in " +
				"limbo")
		}

		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Now, generate the block which will cause Alice to broadcast the
	// presigned htlc timeout txns.
	if _, err = net.Miner.Client.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Since Alice had numInvoices (6) htlcs extended to Carol before force
	// closing, we expect Alice to broadcast an htlc timeout txn for each
	// one.
	expectedTxes = numInvoices

	// In case of anchors, the timeout txs will be aggregated into one.
	if commitType == lnrpc.CommitmentType_ANCHORS {
		expectedTxes = 1
	}

	// Wait for them all to show up in the mempool.
	htlcTxIDs, err := waitForNTxsInMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("unable to find htlc timeout txns in mempool: %v", err)
	}

	// Retrieve each htlc timeout txn from the mempool, and ensure it is
	// well-formed. This entails verifying that each only spends from
	// output, and that that output is from the commitment txn. In case
	// this is an anchor channel, the transactions are aggregated by the
	// sweeper into one.
	numInputs := 1
	if commitType == lnrpc.CommitmentType_ANCHORS {
		numInputs = numInvoices + 1
	}

	// Construct a map of the already confirmed htlc timeout outpoints,
	// that will count the number of times each is spent by the sweep txn.
	// We prepopulate it in this way so that we can later detect if we are
	// spending from an output that was not a confirmed htlc timeout txn.
	var htlcTxOutpointSet = make(map[wire.OutPoint]int)

	var htlcLessFees uint64
	for _, htlcTxID := range htlcTxIDs {
		// Fetch the sweep transaction, all input it's spending should
		// be from the commitment transaction which was broadcast
		// on-chain. In case of an anchor type channel, we expect one
		// extra input that is not spending from the commitment, that
		// is added for fees.
		htlcTx, err := net.Miner.Client.GetRawTransaction(htlcTxID)
		if err != nil {
			t.Fatalf("unable to fetch sweep tx: %v", err)
		}

		// Ensure the htlc transaction has the expected number of
		// inputs.
		inputs := htlcTx.MsgTx().TxIn
		if len(inputs) != numInputs {
			t.Fatalf("htlc transaction should only have %d txin, "+
				"has %d", numInputs, len(htlcTx.MsgTx().TxIn))
		}

		// The number of outputs should be the same.
		outputs := htlcTx.MsgTx().TxOut
		if len(outputs) != numInputs {
			t.Fatalf("htlc transaction should only have %d"+
				"txout, has: %v", numInputs, len(outputs))
		}

		// Ensure all the htlc transaction inputs are spending from the
		// commitment transaction, except if this is an extra input
		// added to pay for fees for anchor channels.
		nonCommitmentInputs := 0
		for i, txIn := range inputs {
			if !closingTxID.IsEqual(&txIn.PreviousOutPoint.Hash) {
				nonCommitmentInputs++

				if nonCommitmentInputs > 1 {
					t.Fatalf("htlc transaction not "+
						"spending from commit "+
						"tx %v, instead spending %v",
						closingTxID,
						txIn.PreviousOutPoint)
				}

				// This was an extra input added to pay fees,
				// continue to the next one.
				continue
			}

			// For each htlc timeout transaction, we expect a
			// resolver report recording this on chain resolution
			// for both alice and carol.
			outpoint := txIn.PreviousOutPoint
			resolutionOutpoint := &lnrpc.OutPoint{
				TxidBytes:   outpoint.Hash[:],
				TxidStr:     outpoint.Hash.String(),
				OutputIndex: outpoint.Index,
			}

			// We expect alice to have a timeout tx resolution with
			// an amount equal to the payment amount.
			aliceReports[outpoint.String()] = &lnrpc.Resolution{
				ResolutionType: lnrpc.ResolutionType_OUTGOING_HTLC,
				Outcome:        lnrpc.ResolutionOutcome_FIRST_STAGE,
				SweepTxid:      htlcTx.Hash().String(),
				Outpoint:       resolutionOutpoint,
				AmountSat:      uint64(paymentAmt),
			}

			// We expect carol to have a resolution with an
			// incoming htlc timeout which reflects the full amount
			// of the htlc. It has no spend tx, because carol stops
			// monitoring the htlc once it has timed out.
			carolReports[outpoint.String()] = &lnrpc.Resolution{
				ResolutionType: lnrpc.ResolutionType_INCOMING_HTLC,
				Outcome:        lnrpc.ResolutionOutcome_TIMEOUT,
				SweepTxid:      "",
				Outpoint:       resolutionOutpoint,
				AmountSat:      uint64(paymentAmt),
			}

			// Recorf the HTLC outpoint, such that we can later
			// check whether it gets swept
			op := wire.OutPoint{
				Hash:  *htlcTxID,
				Index: uint32(i),
			}
			htlcTxOutpointSet[op] = 0
		}

		// We record the htlc amount less fees here, so that we know
		// what value to expect for the second stage of our htlc
		// htlc resolution.
		htlcLessFees = uint64(outputs[0].Value)
	}

	// With the htlc timeout txns still in the mempool, we restart Alice to
	// verify that she can resume watching the htlc txns she broadcasted
	// before crashing.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Generate a block that mines the htlc timeout txns. Doing so now
	// activates the 2nd-stage CSV delayed outputs.
	if _, err = net.Miner.Client.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Alice is restarted here to ensure that she promptly moved the crib
	// outputs to the kindergarten bucket after the htlc timeout txns were
	// confirmed.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Advance the chain until just before the 2nd-layer CSV delays expire.
	// For anchor channels thhis is one block earlier.
	numBlocks := uint32(defaultCSV - 1)
	if commitType == lnrpc.CommitmentType_ANCHORS {
		numBlocks = defaultCSV - 2

	}
	_, err = net.Miner.Client.Generate(numBlocks)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Restart Alice to ensure that she can recover from a failure before
	// having graduated the htlc outputs in the kindergarten bucket.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Now that the channel has been fully swept, it should no longer show
	// incubated, check to see that Alice's node still reports the channel
	// as pending force closed.
	err = wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err = alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		err = checkNumForceClosedChannels(pendingChanResp, 1)
		if err != nil {
			predErr = err
			return false
		}

		forceClose, err := findForceClosedChannel(pendingChanResp, &op)
		if err != nil {
			predErr = err
			return false
		}

		if forceClose.LimboBalance == 0 {
			predErr = fmt.Errorf("htlc funds should still be in limbo")
			return false
		}

		predErr = checkPendingChannelNumHtlcs(forceClose, numInvoices)
		if predErr != nil {
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	// Generate a block that causes Alice to sweep the htlc outputs in the
	// kindergarten bucket.
	if _, err := net.Miner.Client.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Wait for the single sweep txn to appear in the mempool.
	htlcSweepTxID, err := waitForTxInMempool(
		net.Miner.Client, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("failed to get sweep tx from mempool: %v", err)
	}

	// Fetch the htlc sweep transaction from the mempool.
	htlcSweepTx, err := net.Miner.Client.GetRawTransaction(htlcSweepTxID)
	if err != nil {
		t.Fatalf("unable to fetch sweep tx: %v", err)
	}
	// Ensure the htlc sweep transaction only has one input for each htlc
	// Alice extended before force closing.
	if len(htlcSweepTx.MsgTx().TxIn) != numInvoices {
		t.Fatalf("htlc transaction should have %d txin, "+
			"has %d", numInvoices, len(htlcSweepTx.MsgTx().TxIn))
	}
	outputCount := len(htlcSweepTx.MsgTx().TxOut)
	if outputCount != 1 {
		t.Fatalf("htlc sweep transaction should have one output, has: "+
			"%v", outputCount)
	}

	// Ensure that each output spends from exactly one htlc timeout output.
	for _, txIn := range htlcSweepTx.MsgTx().TxIn {
		outpoint := txIn.PreviousOutPoint
		// Check that the input is a confirmed htlc timeout txn.
		if _, ok := htlcTxOutpointSet[outpoint]; !ok {
			t.Fatalf("htlc sweep output not spending from htlc "+
				"tx, instead spending output %v", outpoint)
		}
		// Increment our count for how many times this output was spent.
		htlcTxOutpointSet[outpoint]++

		// Check that each is only spent once.
		if htlcTxOutpointSet[outpoint] > 1 {
			t.Fatalf("htlc sweep tx has multiple spends from "+
				"outpoint %v", outpoint)
		}

		// Since we have now swept our htlc timeout tx, we expect to
		// have timeout resolutions for each of our htlcs.
		output := txIn.PreviousOutPoint
		aliceReports[output.String()] = &lnrpc.Resolution{
			ResolutionType: lnrpc.ResolutionType_OUTGOING_HTLC,
			Outcome:        lnrpc.ResolutionOutcome_TIMEOUT,
			SweepTxid:      htlcSweepTx.Hash().String(),
			Outpoint: &lnrpc.OutPoint{
				TxidBytes:   output.Hash[:],
				TxidStr:     output.Hash.String(),
				OutputIndex: output.Index,
			},
			AmountSat: htlcLessFees,
		}
	}

	// Check that each HTLC output was spent exactly onece.
	for op, num := range htlcTxOutpointSet {
		if num != 1 {
			t.Fatalf("HTLC outpoint %v was spent %v times", op, num)
		}
	}

	// Check that we can find the htlc sweep in our set of sweeps using
	// the verbose output of the listsweeps output.
	assertSweepFound(ctxb, t.t, alice, htlcSweepTx.Hash().String(), true)

	// The following restart checks to ensure that the nursery store is
	// storing the txid of the previously broadcast htlc sweep txn, and that
	// it begins watching that txid after restarting.
	if err := net.RestartNode(alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Now that the channel has been fully swept, it should no longer show
	// incubated, check to see that Alice's node still reports the channel
	// as pending force closed.
	err = wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		err = checkNumForceClosedChannels(pendingChanResp, 1)
		if err != nil {
			predErr = err
			return false
		}

		// All htlcs should show zero blocks until maturity, as
		// evidenced by having checked the sweep transaction in the
		// mempool.
		forceClose, err := findForceClosedChannel(pendingChanResp, &op)
		if err != nil {
			predErr = err
			return false
		}
		predErr = checkPendingChannelNumHtlcs(forceClose, numInvoices)
		if predErr != nil {
			return false
		}
		err = checkPendingHtlcStageAndMaturity(
			forceClose, 2, htlcCsvMaturityHeight, 0,
		)
		if err != nil {
			predErr = err
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	// Generate the final block that sweeps all htlc funds into the user's
	// wallet, and make sure the sweep is in this block.
	block = mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, htlcSweepTxID)

	// Now that the channel has been fully swept, it should no longer show
	// up within the pending channels RPC.
	err = wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}

		predErr = checkNumForceClosedChannels(pendingChanResp, 0)
		if predErr != nil {
			return false
		}

		// In addition to there being no pending channels, we verify
		// that pending channels does not report any money still in
		// limbo.
		if pendingChanResp.TotalLimboBalance != 0 {
			predErr = errors.New("no user funds should be left " +
				"in limbo after incubation")
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	// At this point, Carol should now be aware of her new immediately
	// spendable on-chain balance, as it was Alice who broadcast the
	// commitment transaction.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalResp, err = carol.WalletBalance(ctxt, carolBalReq)
	require.NoError(t.t, err, "unable to get carol's balance")

	// Carol's expected balance should be its starting balance plus the
	// push amount sent by Alice and minus the miner fee paid.
	carolExpectedBalance := btcutil.Amount(carolStartingBalance) +
		pushAmt - totalFeeCarol

	// In addition, if this is an anchor-enabled channel, further add the
	// anchor size.
	if commitType == lnrpc.CommitmentType_ANCHORS {
		carolExpectedBalance += btcutil.Amount(anchorSize)
	}

	require.Equal(
		t.t, carolExpectedBalance,
		btcutil.Amount(carolBalResp.ConfirmedBalance),
		"carol's balance is incorrect",
	)

	// Finally, we check that alice and carol have the set of resolutions
	// we expect.
	assertReports(ctxb, t, alice, op, aliceReports)
	assertReports(ctxb, t, carol, op, carolReports)
}

type sweptOutput struct {
	OutPoint wire.OutPoint
	SweepTx  string
}

// findCommitAndAnchor looks for a commitment sweep and anchor sweep in the
// mempool. Our anchor output is identified by having multiple inputs, because
// we have to bring another input to add fees to the anchor. Note that the
// anchor swept output may be nil if the channel did not have anchors.
func findCommitAndAnchor(t *harnessTest, net *lntest.NetworkHarness,
	sweepTxns []*wire.MsgTx, closeTx string) (*sweptOutput, *sweptOutput) {

	var commitSweep, anchorSweep *sweptOutput

	for _, tx := range sweepTxns {
		txHash := tx.TxHash()
		sweepTx, err := net.Miner.Client.GetRawTransaction(&txHash)
		require.NoError(t.t, err)

		// We expect our commitment sweep to have a single input, and,
		// our anchor sweep to have more inputs (because the wallet
		// needs to add balance to the anchor amount). We find their
		// sweep txids here to setup appropriate resolutions. We also
		// need to find the outpoint for our resolution, which we do by
		// matching the inputs to the sweep to the close transaction.
		inputs := sweepTx.MsgTx().TxIn
		if len(inputs) == 1 {
			commitSweep = &sweptOutput{
				OutPoint: inputs[0].PreviousOutPoint,
				SweepTx:  txHash.String(),
			}
		} else {
			// Since we have more than one input, we run through
			// them to find the outpoint that spends from the close
			// tx. This will be our anchor output.
			for _, txin := range inputs {
				outpointStr := txin.PreviousOutPoint.Hash.String()
				if outpointStr == closeTx {
					anchorSweep = &sweptOutput{
						OutPoint: txin.PreviousOutPoint,
						SweepTx:  txHash.String(),
					}
				}
			}
		}
	}

	return commitSweep, anchorSweep
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
	if err != nil {
		t.Fatalf("error when obtaining payments: %v", err)
	}

	payments := paymentsResp.Payments
	if len(payments) == 0 {
		t.Fatalf("no payments found")
	}

	payment := payments[len(payments)-1]
	htlcs := payment.Htlcs
	if len(htlcs) == 0 {
		t.Fatalf("no htlcs")
	}

	htlc := htlcs[len(htlcs)-1]
	if htlc.Failure == nil {
		t.Fatalf("expected failure")
	}

	if htlc.Failure.Code != code {
		t.Fatalf("expected failure %v, got %v", code, htlc.Failure.Code)
	}
}

// testSphinxReplayPersistence verifies that replayed onion packets are rejected
// by a remote peer after a restart. We use a combination of unsafe
// configuration arguments to force Carol to replay the same sphinx packet after
// reconnecting to Dave, and compare the returned failure message with what we
// expect for replayed onion packets.
func testSphinxReplayPersistence(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// Open a channel with 100k satoshis between Carol and Dave with Carol being
	// the sole funder of the channel.
	chanAmt := btcutil.Amount(100000)

	// First, we'll create Dave, the receiver, and start him in hodl mode.
	dave := net.NewNode(t.t, "Dave", []string{"--hodl.exit-settle"})

	// We must remember to shutdown the nodes we created for the duration
	// of the tests, only leaving the two seed nodes (Alice and Bob) within
	// our test network.
	defer shutdownAndAssert(net, t, dave)

	// Next, we'll create Carol and establish a channel to from her to
	// Dave. Carol is started in both unsafe-replay which will cause her to
	// replay any pending Adds held in memory upon reconnection.
	carol := net.NewNode(t.t, "Carol", []string{"--unsafe-replay"})
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Next, we'll create Fred who is going to initiate the payment and
	// establish a channel to from him to Carol. We can't perform this test
	// by paying from Carol directly to Dave, because the '--unsafe-replay'
	// setup doesn't apply to locally added htlcs. In that case, the
	// mailbox, that is responsible for generating the replay, is bypassed.
	fred := net.NewNode(t.t, "Fred", nil)
	defer shutdownAndAssert(net, t, fred)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, fred, carol)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, fred)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointFC := openChannelAndAssert(
		ctxt, t, net, fred, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Now that the channel is open, create an invoice for Dave which
	// expects a payment of 1000 satoshis from Carol paid via a particular
	// preimage.
	const paymentAmt = 1000
	preimage := bytes.Repeat([]byte("A"), 32)
	invoice := &lnrpc.Invoice{
		Memo:      "testing",
		RPreimage: preimage,
		Value:     paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	invoiceResp, err := dave.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	// Wait for all channels to be recognized and advertized.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't advertise channel before "+
			"timeout: %v", err)
	}
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't advertise channel before "+
			"timeout: %v", err)
	}
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointFC)
	if err != nil {
		t.Fatalf("alice didn't advertise channel before "+
			"timeout: %v", err)
	}
	err = fred.WaitForNetworkChannelOpen(ctxt, chanPointFC)
	if err != nil {
		t.Fatalf("bob didn't advertise channel before "+
			"timeout: %v", err)
	}

	// With the invoice for Dave added, send a payment from Fred paying
	// to the above generated invoice.
	ctx, cancel := context.WithCancel(ctxb)
	defer cancel()

	payStream, err := fred.RouterClient.SendPaymentV2(
		ctx,
		&routerrpc.SendPaymentRequest{
			PaymentRequest: invoiceResp.PaymentRequest,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
		},
	)
	if err != nil {
		t.Fatalf("unable to open payment stream: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Dave's invoice should not be marked as settled.
	payHash := &lnrpc.PaymentHash{
		RHash: invoiceResp.RHash,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	dbInvoice, err := dave.LookupInvoice(ctxt, payHash)
	if err != nil {
		t.Fatalf("unable to lookup invoice: %v", err)
	}
	if dbInvoice.Settled {
		t.Fatalf("dave's invoice should not be marked as settled: %v",
			spew.Sdump(dbInvoice))
	}

	// With the payment sent but hedl, all balance related stats should not
	// have changed.
	err = wait.InvariantNoError(
		assertAmountSent(0, carol, dave), 3*time.Second,
	)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// With the first payment sent, restart dave to make sure he is
	// persisting the information required to detect replayed sphinx
	// packets.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("unable to restart dave: %v", err)
	}

	// Carol should retransmit the Add hedl in her mailbox on startup. Dave
	// should not accept the replayed Add, and actually fail back the
	// pending payment. Even though he still holds the original settle, if
	// he does fail, it is almost certainly caused by the sphinx replay
	// protection, as it is the only validation we do in hodl mode.
	result, err := getPaymentResult(payStream)
	if err != nil {
		t.Fatalf("unable to receive payment response: %v", err)
	}

	// Assert that Fred receives the expected failure after Carol sent a
	// duplicate packet that fails due to sphinx replay detection.
	if result.Status == lnrpc.Payment_SUCCEEDED {
		t.Fatalf("expected payment error")
	}
	assertLastHTLCError(t, fred, lnrpc.Failure_INVALID_ONION_KEY)

	// Since the payment failed, the balance should still be left
	// unaltered.
	err = wait.InvariantNoError(
		assertAmountSent(0, carol, dave), 3*time.Second,
	)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPoint, true)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, carol, chanPoint)
}

func assertChannelConstraintsEqual(
	t *harnessTest, want, got *lnrpc.ChannelConstraints) {

	t.t.Helper()

	if want.CsvDelay != got.CsvDelay {
		t.Fatalf("CsvDelay mismatched, want: %v, got: %v",
			want.CsvDelay, got.CsvDelay,
		)
	}

	if want.ChanReserveSat != got.ChanReserveSat {
		t.Fatalf("ChanReserveSat mismatched, want: %v, got: %v",
			want.ChanReserveSat, got.ChanReserveSat,
		)
	}

	if want.DustLimitSat != got.DustLimitSat {
		t.Fatalf("DustLimitSat mismatched, want: %v, got: %v",
			want.DustLimitSat, got.DustLimitSat,
		)
	}

	if want.MaxPendingAmtMsat != got.MaxPendingAmtMsat {
		t.Fatalf("MaxPendingAmtMsat mismatched, want: %v, got: %v",
			want.MaxPendingAmtMsat, got.MaxPendingAmtMsat,
		)
	}

	if want.MinHtlcMsat != got.MinHtlcMsat {
		t.Fatalf("MinHtlcMsat mismatched, want: %v, got: %v",
			want.MinHtlcMsat, got.MinHtlcMsat,
		)
	}

	if want.MaxAcceptedHtlcs != got.MaxAcceptedHtlcs {
		t.Fatalf("MaxAcceptedHtlcs mismatched, want: %v, got: %v",
			want.MaxAcceptedHtlcs, got.MaxAcceptedHtlcs,
		)
	}
}

// testListChannels checks that the response from ListChannels is correct. It
// tests the values in all ChannelConstraints are returned as expected. Once
// ListChannels becomes mature, a test against all fields in ListChannels should
// be performed.
func testListChannels(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const aliceRemoteMaxHtlcs = 50
	const bobRemoteMaxHtlcs = 100

	// Create two fresh nodes and open a channel between them.
	alice := net.NewNode(t.t, "Alice", nil)
	defer shutdownAndAssert(net, t, alice)

	bob := net.NewNode(
		t.t, "Bob", []string{
			fmt.Sprintf(
				"--default-remote-max-htlcs=%v",
				bobRemoteMaxHtlcs,
			),
		},
	)
	defer shutdownAndAssert(net, t, bob)

	// Connect Alice to Bob.
	net.ConnectNodes(ctxb, t.t, alice, bob)

	// Give Alice some coins so she can fund a channel.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, alice)

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel. The minial HTLC amount is set to
	// 4200 msats.
	const customizedMinHtlc = 4200

	chanAmt := btcutil.Amount(100000)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, alice, bob,
		lntest.OpenChannelParams{
			Amt:            chanAmt,
			MinHtlc:        customizedMinHtlc,
			RemoteMaxHtlcs: aliceRemoteMaxHtlcs,
		},
	)

	// Wait for Alice and Bob to receive the channel edge from the
	// funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't see the alice->bob channel before "+
			"timeout: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't see the bob->alice channel before "+
			"timeout: %v", err)
	}

	// Alice should have one channel opened with Bob.
	assertNodeNumChannels(t, alice, 1)
	// Bob should have one channel opened with Alice.
	assertNodeNumChannels(t, bob, 1)

	// Get the ListChannel response from Alice.
	listReq := &lnrpc.ListChannelsRequest{}
	ctxb = context.Background()
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := alice.ListChannels(ctxt, listReq)
	if err != nil {
		t.Fatalf("unable to query for %s's channel list: %v",
			alice.Name(), err)
	}

	// Check the returned response is correct.
	aliceChannel := resp.Channels[0]

	// defaultConstraints is a ChannelConstraints with default values. It is
	// used to test against Alice's local channel constraints.
	defaultConstraints := &lnrpc.ChannelConstraints{
		CsvDelay:          4,
		ChanReserveSat:    1000,
		DustLimitSat:      uint64(lnwallet.DefaultDustLimit()),
		MaxPendingAmtMsat: 99000000,
		MinHtlcMsat:       1,
		MaxAcceptedHtlcs:  bobRemoteMaxHtlcs,
	}
	assertChannelConstraintsEqual(
		t, defaultConstraints, aliceChannel.LocalConstraints,
	)

	// customizedConstraints is a ChannelConstraints with customized values.
	// Ideally, all these values can be passed in when creating the channel.
	// Currently, only the MinHtlcMsat is customized. It is used to check
	// against Alice's remote channel constratins.
	customizedConstraints := &lnrpc.ChannelConstraints{
		CsvDelay:          4,
		ChanReserveSat:    1000,
		DustLimitSat:      uint64(lnwallet.DefaultDustLimit()),
		MaxPendingAmtMsat: 99000000,
		MinHtlcMsat:       customizedMinHtlc,
		MaxAcceptedHtlcs:  aliceRemoteMaxHtlcs,
	}
	assertChannelConstraintsEqual(
		t, customizedConstraints, aliceChannel.RemoteConstraints,
	)

	// Get the ListChannel response for Bob.
	listReq = &lnrpc.ListChannelsRequest{}
	ctxb = context.Background()
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err = bob.ListChannels(ctxt, listReq)
	if err != nil {
		t.Fatalf("unable to query for %s's channel "+
			"list: %v", bob.Name(), err)
	}

	bobChannel := resp.Channels[0]
	if bobChannel.ChannelPoint != aliceChannel.ChannelPoint {
		t.Fatalf("Bob's channel point mismatched, want: %s, got: %s",
			chanPoint.String(), bobChannel.ChannelPoint,
		)
	}

	// Check channel constraints match. Alice's local channel constraint should
	// be equal to Bob's remote channel constraint, and her remote one should
	// be equal to Bob's local one.
	assertChannelConstraintsEqual(
		t, aliceChannel.LocalConstraints, bobChannel.RemoteConstraints,
	)
	assertChannelConstraintsEqual(
		t, aliceChannel.RemoteConstraints, bobChannel.LocalConstraints,
	)

}

// testUpdateChanStatus checks that calls to the UpdateChanStatus RPC update
// the channel graph as expected, and that channel state is properly updated
// in the presence of interleaved node disconnects / reconnects.
func testUpdateChanStatus(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// Create two fresh nodes and open a channel between them.
	alice := net.NewNode(
		t.t, "Alice", []string{
			"--minbackoff=10s",
			"--chan-enable-timeout=1.5s",
			"--chan-disable-timeout=3s",
			"--chan-status-sample-interval=.5s",
		},
	)
	defer shutdownAndAssert(net, t, alice)

	bob := net.NewNode(
		t.t, "Bob", []string{
			"--minbackoff=10s",
			"--chan-enable-timeout=1.5s",
			"--chan-disable-timeout=3s",
			"--chan-status-sample-interval=.5s",
		},
	)
	defer shutdownAndAssert(net, t, bob)

	// Connect Alice to Bob.
	net.ConnectNodes(ctxb, t.t, alice, bob)

	// Give Alice some coins so she can fund a channel.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, alice)

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	chanAmt := btcutil.Amount(100000)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, alice, bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Wait for Alice and Bob to receive the channel edge from the
	// funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't see the alice->bob channel before "+
			"timeout: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't see the bob->alice channel before "+
			"timeout: %v", err)
	}

	// Launch a node for Carol which will connect to Alice and Bob in
	// order to receive graph updates. This will ensure that the
	// channel updates are propagated throughout the network.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, bob, carol)

	carolSub := subscribeGraphNotifications(ctxb, t, carol)
	defer close(carolSub.quit)

	// sendReq sends an UpdateChanStatus request to the given node.
	sendReq := func(node *lntest.HarnessNode, chanPoint *lnrpc.ChannelPoint,
		action routerrpc.ChanStatusAction) {

		req := &routerrpc.UpdateChanStatusRequest{
			ChanPoint: chanPoint,
			Action:    action,
		}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		_, err = node.RouterClient.UpdateChanStatus(ctxt, req)
		if err != nil {
			t.Fatalf("unable to call UpdateChanStatus for %s's node: %v",
				node.Name(), err)
		}
	}

	// assertEdgeDisabled ensures that a given node has the correct
	// Disabled state for a channel.
	assertEdgeDisabled := func(node *lntest.HarnessNode,
		chanPoint *lnrpc.ChannelPoint, disabled bool) {

		var predErr error
		err = wait.Predicate(func() bool {
			req := &lnrpc.ChannelGraphRequest{
				IncludeUnannounced: true,
			}
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			chanGraph, err := node.DescribeGraph(ctxt, req)
			if err != nil {
				predErr = fmt.Errorf("unable to query node %v's graph: %v", node, err)
				return false
			}
			numEdges := len(chanGraph.Edges)
			if numEdges != 1 {
				predErr = fmt.Errorf("expected to find 1 edge in the graph, found %d", numEdges)
				return false
			}
			edge := chanGraph.Edges[0]
			if edge.ChanPoint != chanPoint.GetFundingTxidStr() {
				predErr = fmt.Errorf("expected chan_point %v, got %v",
					chanPoint.GetFundingTxidStr(), edge.ChanPoint)
			}
			var policy *lnrpc.RoutingPolicy
			if node.PubKeyStr == edge.Node1Pub {
				policy = edge.Node1Policy
			} else {
				policy = edge.Node2Policy
			}
			if disabled != policy.Disabled {
				predErr = fmt.Errorf("expected policy.Disabled to be %v, "+
					"but policy was %v", disabled, policy)
				return false
			}
			return true
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("%v", predErr)
		}
	}

	// When updating the state of the channel between Alice and Bob, we
	// should expect to see channel updates with the default routing
	// policy. The value of "Disabled" will depend on the specific
	// scenario being tested.
	expectedPolicy := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      int64(chainreg.DefaultBitcoinBaseFeeMSat),
		FeeRateMilliMsat: int64(chainreg.DefaultBitcoinFeeRate),
		TimeLockDelta:    chainreg.DefaultBitcoinTimeLockDelta,
		MinHtlc:          1000, // default value
		MaxHtlcMsat:      calculateMaxHtlc(chanAmt),
	}

	// Initially, the channel between Alice and Bob should not be
	// disabled.
	assertEdgeDisabled(alice, chanPoint, false)

	// Manually disable the channel and ensure that a "Disabled = true"
	// update is propagated.
	sendReq(alice, chanPoint, routerrpc.ChanStatusAction_DISABLE)
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{alice.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// Re-enable the channel and ensure that a "Disabled = false" update
	// is propagated.
	sendReq(alice, chanPoint, routerrpc.ChanStatusAction_ENABLE)
	expectedPolicy.Disabled = false
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{alice.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// Manually enabling a channel should NOT prevent subsequent
	// disconnections from automatically disabling the channel again
	// (we don't want to clutter the network with channels that are
	// falsely advertised as enabled when they don't work).
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("unable to disconnect Alice from Bob: %v", err)
	}
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{alice.PubKeyStr, expectedPolicy, chanPoint},
			{bob.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// Reconnecting the nodes should propagate a "Disabled = false" update.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, alice, bob)
	expectedPolicy.Disabled = false
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{alice.PubKeyStr, expectedPolicy, chanPoint},
			{bob.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// Manually disabling the channel should prevent a subsequent
	// disconnect / reconnect from re-enabling the channel on
	// Alice's end. Note the asymmetry between manual enable and
	// manual disable!
	sendReq(alice, chanPoint, routerrpc.ChanStatusAction_DISABLE)

	// Alice sends out the "Disabled = true" update in response to
	// the ChanStatusAction_DISABLE request.
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{alice.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("unable to disconnect Alice from Bob: %v", err)
	}

	// Bob sends a "Disabled = true" update upon detecting the
	// disconnect.
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{bob.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// Bob sends a "Disabled = false" update upon detecting the
	// reconnect.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, alice, bob)
	expectedPolicy.Disabled = false
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{bob.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// However, since we manually disabled the channel on Alice's end,
	// the policy on Alice's end should still be "Disabled = true". Again,
	// note the asymmetry between manual enable and manual disable!
	assertEdgeDisabled(alice, chanPoint, true)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("unable to disconnect Alice from Bob: %v", err)
	}

	// Bob sends a "Disabled = true" update upon detecting the
	// disconnect.
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{bob.PubKeyStr, expectedPolicy, chanPoint},
		},
	)

	// After restoring automatic channel state management on Alice's end,
	// BOTH Alice and Bob should set the channel state back to "enabled"
	// on reconnect.
	sendReq(alice, chanPoint, routerrpc.ChanStatusAction_AUTO)
	net.EnsureConnected(ctxt, t.t, alice, bob)
	expectedPolicy.Disabled = false
	waitForChannelUpdate(
		t, carolSub,
		[]expectedChanUpdate{
			{alice.PubKeyStr, expectedPolicy, chanPoint},
			{bob.PubKeyStr, expectedPolicy, chanPoint},
		},
	)
	assertEdgeDisabled(alice, chanPoint, false)
}

func testListPayments(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First start by deleting all payments that Alice knows of. This will
	// allow us to execute the test with a clean state for Alice.
	delPaymentsReq := &lnrpc.DeleteAllPaymentsRequest{}
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	if _, err := net.Alice.DeleteAllPayments(ctxt, delPaymentsReq); err != nil {
		t.Fatalf("unable to delete payments: %v", err)
	}

	// Check that there are no payments before test.
	reqInit := &lnrpc.ListPaymentsRequest{}
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	paymentsRespInit, err := net.Alice.ListPayments(ctxt, reqInit)
	if err != nil {
		t.Fatalf("error when obtaining Alice payments: %v", err)
	}
	if len(paymentsRespInit.Payments) != 0 {
		t.Fatalf("incorrect number of payments, got %v, want %v",
			len(paymentsRespInit.Payments), 0)
	}

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	chanAmt := btcutil.Amount(100000)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Now that the channel is open, create an invoice for Bob which
	// expects a payment of 1000 satoshis from Alice paid via a particular
	// preimage.
	const paymentAmt = 1000
	preimage := bytes.Repeat([]byte("B"), 32)
	invoice := &lnrpc.Invoice{
		Memo:      "testing",
		RPreimage: preimage,
		Value:     paymentAmt,
	}
	addInvoiceCtxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	invoiceResp, err := net.Bob.AddInvoice(addInvoiceCtxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	// Wait for Alice to recognize and advertise the new channel generated
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint); err != nil {
		t.Fatalf("alice didn't advertise channel before "+
			"timeout: %v", err)
	}
	if err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint); err != nil {
		t.Fatalf("bob didn't advertise channel before "+
			"timeout: %v", err)
	}

	// With the invoice for Bob added, send a payment towards Alice paying
	// to the above generated invoice.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	sendAndAssertSuccess(
		ctxt, t, net.Alice,
		&routerrpc.SendPaymentRequest{
			PaymentRequest: invoiceResp.PaymentRequest,
			TimeoutSeconds: 60,
			FeeLimitSat:    1000000,
		},
	)

	// Grab Alice's list of payments, she should show the existence of
	// exactly one payment.
	req := &lnrpc.ListPaymentsRequest{}
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	paymentsResp, err := net.Alice.ListPayments(ctxt, req)
	if err != nil {
		t.Fatalf("error when obtaining Alice payments: %v", err)
	}
	if len(paymentsResp.Payments) != 1 {
		t.Fatalf("incorrect number of payments, got %v, want %v",
			len(paymentsResp.Payments), 1)
	}
	p := paymentsResp.Payments[0]
	path := p.Htlcs[len(p.Htlcs)-1].Route.Hops

	// Ensure that the stored path shows a direct payment to Bob with no
	// other nodes in-between.
	if len(path) != 1 || path[0].PubKey != net.Bob.PubKeyStr {
		t.Fatalf("incorrect path")
	}

	// The payment amount should also match our previous payment directly.
	if p.Value != paymentAmt {
		t.Fatalf("incorrect amount, got %v, want %v",
			p.Value, paymentAmt)
	}

	// The payment hash (or r-hash) should have been stored correctly.
	correctRHash := hex.EncodeToString(invoiceResp.RHash)
	if !reflect.DeepEqual(p.PaymentHash, correctRHash) {
		t.Fatalf("incorrect RHash, got %v, want %v",
			p.PaymentHash, correctRHash)
	}

	// As we made a single-hop direct payment, there should have been no fee
	// applied.
	if p.Fee != 0 {
		t.Fatalf("incorrect Fee, got %v, want %v", p.Fee, 0)
	}

	// Finally, verify that the payment request returned by the rpc matches
	// the invoice that we paid.
	if p.PaymentRequest != invoiceResp.PaymentRequest {
		t.Fatalf("incorrect payreq, got: %v, want: %v",
			p.PaymentRequest, invoiceResp.PaymentRequest)
	}

	// Delete all payments from Alice. DB should have no payments.
	delReq := &lnrpc.DeleteAllPaymentsRequest{}
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	_, err = net.Alice.DeleteAllPayments(ctxt, delReq)
	if err != nil {
		t.Fatalf("Can't delete payments at the end: %v", err)
	}

	// Check that there are no payments after test.
	listReq := &lnrpc.ListPaymentsRequest{}
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	paymentsResp, err = net.Alice.ListPayments(ctxt, listReq)
	if err != nil {
		t.Fatalf("error when obtaining Alice payments: %v", err)
	}
	if len(paymentsResp.Payments) != 0 {
		t.Fatalf("incorrect number of payments, got %v, want %v",
			len(paymentsRespInit.Payments), 0)
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
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
			if isTimeover {
				t.Fatalf("Check amount Paid failed: %v", err)
			}
		} else {
			break
		}
	}
}

// updateChannelPolicy updates the channel policy of node to the
// given fees and timelock delta. This function blocks until
// listenerNode has received the policy update.
func updateChannelPolicy(t *harnessTest, node *lntest.HarnessNode,
	chanPoint *lnrpc.ChannelPoint, baseFee int64, feeRate int64,
	timeLockDelta uint32, maxHtlc uint64, listenerNode *lntest.HarnessNode) {

	ctxb := context.Background()

	expectedPolicy := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      baseFee,
		FeeRateMilliMsat: feeRate,
		TimeLockDelta:    timeLockDelta,
		MinHtlc:          1000, // default value
		MaxHtlcMsat:      maxHtlc,
	}

	updateFeeReq := &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   baseFee,
		FeeRate:       float64(feeRate) / testFeeBase,
		TimeLockDelta: timeLockDelta,
		Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPoint,
		},
		MaxHtlcMsat: maxHtlc,
	}

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	if _, err := node.UpdateChannelPolicy(ctxt, updateFeeReq); err != nil {
		t.Fatalf("unable to update chan policy: %v", err)
	}

	// Wait for listener node to receive the channel update from node.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	graphSub := subscribeGraphNotifications(ctxt, t, listenerNode)
	defer close(graphSub.quit)

	waitForChannelUpdate(
		t, graphSub,
		[]expectedChanUpdate{
			{node.PubKeyStr, expectedPolicy, chanPoint},
		},
	)
}

// testUnannouncedChannels checks unannounced channels are not returned by
// describeGraph RPC request unless explicitly asked for.
func testUnannouncedChannels(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	amount := funding.MaxBtcFundingAmount

	// Open a channel between Alice and Bob, ensuring the
	// channel has been opened properly.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanOpenUpdate := openChannelStream(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: amount,
		},
	)

	// Mine 2 blocks, and check that the channel is opened but not yet
	// announced to the network.
	mineBlocks(t, net, 2, 1)

	// One block is enough to make the channel ready for use, since the
	// nodes have defaultNumConfs=1 set.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	fundingChanPoint, err := net.WaitForChannelOpen(ctxt, chanOpenUpdate)
	if err != nil {
		t.Fatalf("error while waiting for channel open: %v", err)
	}

	// Alice should have 1 edge in her graph.
	req := &lnrpc.ChannelGraphRequest{
		IncludeUnannounced: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	chanGraph, err := net.Alice.DescribeGraph(ctxt, req)
	if err != nil {
		t.Fatalf("unable to query alice's graph: %v", err)
	}

	numEdges := len(chanGraph.Edges)
	if numEdges != 1 {
		t.Fatalf("expected to find 1 edge in the graph, found %d", numEdges)
	}

	// Channels should not be announced yet, hence Alice should have no
	// announced edges in her graph.
	req.IncludeUnannounced = false
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	chanGraph, err = net.Alice.DescribeGraph(ctxt, req)
	if err != nil {
		t.Fatalf("unable to query alice's graph: %v", err)
	}

	numEdges = len(chanGraph.Edges)
	if numEdges != 0 {
		t.Fatalf("expected to find 0 announced edges in the graph, found %d",
			numEdges)
	}

	// Mine 4 more blocks, and check that the channel is now announced.
	mineBlocks(t, net, 4, 0)

	// Give the network a chance to learn that auth proof is confirmed.
	var predErr error
	err = wait.Predicate(func() bool {
		// The channel should now be announced. Check that Alice has 1
		// announced edge.
		req.IncludeUnannounced = false
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		chanGraph, err = net.Alice.DescribeGraph(ctxt, req)
		if err != nil {
			predErr = fmt.Errorf("unable to query alice's graph: %v", err)
			return false
		}

		numEdges = len(chanGraph.Edges)
		if numEdges != 1 {
			predErr = fmt.Errorf("expected to find 1 announced edge in "+
				"the graph, found %d", numEdges)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// The channel should now be announced. Check that Alice has 1 announced
	// edge.
	req.IncludeUnannounced = false
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	chanGraph, err = net.Alice.DescribeGraph(ctxt, req)
	if err != nil {
		t.Fatalf("unable to query alice's graph: %v", err)
	}

	numEdges = len(chanGraph.Edges)
	if numEdges != 1 {
		t.Fatalf("expected to find 1 announced edge in the graph, found %d",
			numEdges)
	}

	// Close the channel used during the test.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, fundingChanPoint, false)
}

func testInvoiceSubscriptions(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(500000)

	// Open a channel with 500k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Next create a new invoice for Bob requesting 1k satoshis.
	// TODO(roasbeef): make global list of invoices for each node to re-use
	// and avoid collisions
	const paymentAmt = 1000
	invoice := &lnrpc.Invoice{
		Memo:      "testing",
		RPreimage: makeFakePayHash(t),
		Value:     paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	invoiceResp, err := net.Bob.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}
	lastAddIndex := invoiceResp.AddIndex

	// Create a new invoice subscription client for Bob, the notification
	// should be dispatched shortly below.
	req := &lnrpc.InvoiceSubscription{}
	ctx, cancelInvoiceSubscription := context.WithCancel(ctxb)
	bobInvoiceSubscription, err := net.Bob.SubscribeInvoices(ctx, req)
	if err != nil {
		t.Fatalf("unable to subscribe to bob's invoice updates: %v", err)
	}

	var settleIndex uint64
	quit := make(chan struct{})
	updateSent := make(chan struct{})
	go func() {
		invoiceUpdate, err := bobInvoiceSubscription.Recv()
		select {
		case <-quit:
			// Received cancellation
			return
		default:
		}

		if err != nil {
			t.Fatalf("unable to recv invoice update: %v", err)
		}

		// The invoice update should exactly match the invoice created
		// above, but should now be settled and have SettleDate
		if !invoiceUpdate.Settled { // nolint:staticcheck
			t.Fatalf("invoice not settled but should be")
		}
		if invoiceUpdate.SettleDate == 0 {
			t.Fatalf("invoice should have non zero settle date, but doesn't")
		}

		if !bytes.Equal(invoiceUpdate.RPreimage, invoice.RPreimage) {
			t.Fatalf("payment preimages don't match: expected %v, got %v",
				invoice.RPreimage, invoiceUpdate.RPreimage)
		}

		if invoiceUpdate.SettleIndex == 0 {
			t.Fatalf("invoice should have settle index")
		}

		settleIndex = invoiceUpdate.SettleIndex

		close(updateSent)
	}()

	// Wait for the channel to be recognized by both Alice and Bob before
	// continuing the rest of the test.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		// TODO(roasbeef): will need to make num blocks to advertise a
		// node param
		close(quit)
		t.Fatalf("channel not seen by alice before timeout: %v", err)
	}

	// With the assertion above set up, send a payment from Alice to Bob
	// which should finalize and settle the invoice.
	sendReq := &routerrpc.SendPaymentRequest{
		PaymentRequest: invoiceResp.PaymentRequest,
		TimeoutSeconds: 60,
		FeeLimitMsat:   noFeeLimitMsat,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	stream, err := net.Alice.RouterClient.SendPaymentV2(ctxt, sendReq)
	if err != nil {
		close(quit)
		t.Fatalf("unable to send payment: %v", err)
	}
	result, err := getPaymentResult(stream)
	if err != nil {
		close(quit)
		t.Fatalf("cannot get payment result: %v", err)
	}
	if result.Status != lnrpc.Payment_SUCCEEDED {
		close(quit)
		t.Fatalf("error when attempting recv: %v", result.Status)
	}

	select {
	case <-time.After(time.Second * 10):
		close(quit)
		t.Fatalf("update not sent after 10 seconds")
	case <-updateSent: // Fall through on success
	}

	// With the base case working, we'll now cancel Bob's current
	// subscription in order to exercise the backlog fill behavior.
	cancelInvoiceSubscription()

	// We'll now add 3 more invoices to Bob's invoice registry.
	const numInvoices = 3
	payReqs, _, newInvoices, err := createPayReqs(
		net.Bob, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Now that the set of invoices has been added, we'll re-register for
	// streaming invoice notifications for Bob, this time specifying the
	// add invoice of the last prior invoice.
	req = &lnrpc.InvoiceSubscription{
		AddIndex: lastAddIndex,
	}
	ctx, cancelInvoiceSubscription = context.WithCancel(ctxb)
	bobInvoiceSubscription, err = net.Bob.SubscribeInvoices(ctx, req)
	if err != nil {
		t.Fatalf("unable to subscribe to bob's invoice updates: %v", err)
	}

	// Since we specified a value of the prior add index above, we should
	// now immediately get the invoices we just added as we should get the
	// backlog of notifications.
	for i := 0; i < numInvoices; i++ {
		invoiceUpdate, err := bobInvoiceSubscription.Recv()
		if err != nil {
			t.Fatalf("unable to receive subscription")
		}

		// We should now get the ith invoice we added, as they should
		// be returned in order.
		if invoiceUpdate.Settled { // nolint:staticcheck
			t.Fatalf("should have only received add events")
		}
		originalInvoice := newInvoices[i]
		rHash := sha256.Sum256(originalInvoice.RPreimage)
		if !bytes.Equal(invoiceUpdate.RHash, rHash[:]) {
			t.Fatalf("invoices have mismatched payment hashes: "+
				"expected %x, got %x", rHash[:],
				invoiceUpdate.RHash)
		}
	}

	cancelInvoiceSubscription()

	// We'll now have Bob settle out the remainder of these invoices so we
	// can test that all settled invoices are properly notified.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// With the set of invoices paid, we'll now cancel the old
	// subscription, and create a new one for Bob, this time using the
	// settle index to obtain the backlog of settled invoices.
	req = &lnrpc.InvoiceSubscription{
		SettleIndex: settleIndex,
	}
	ctx, cancelInvoiceSubscription = context.WithCancel(ctxb)
	bobInvoiceSubscription, err = net.Bob.SubscribeInvoices(ctx, req)
	if err != nil {
		t.Fatalf("unable to subscribe to bob's invoice updates: %v", err)
	}

	defer cancelInvoiceSubscription()

	// As we specified the index of the past settle index, we should now
	// receive notifications for the three HTLCs that we just settled. As
	// the order that the HTLCs will be settled in is partially randomized,
	// we'll use a map to assert that the proper set has been settled.
	settledInvoices := make(map[[32]byte]struct{})
	for _, invoice := range newInvoices {
		rHash := sha256.Sum256(invoice.RPreimage)
		settledInvoices[rHash] = struct{}{}
	}
	for i := 0; i < numInvoices; i++ {
		invoiceUpdate, err := bobInvoiceSubscription.Recv()
		if err != nil {
			t.Fatalf("unable to receive subscription")
		}

		// We should now get the ith invoice we added, as they should
		// be returned in order.
		if !invoiceUpdate.Settled { // nolint:staticcheck
			t.Fatalf("should have only received settle events")
		}

		var rHash [32]byte
		copy(rHash[:], invoiceUpdate.RHash)
		if _, ok := settledInvoices[rHash]; !ok {
			t.Fatalf("unknown invoice settled: %x", rHash)
		}

		delete(settledInvoices, rHash)
	}

	// At this point, all the invoices should be fully settled.
	if len(settledInvoices) != 0 {
		t.Fatalf("not all invoices settled")
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
}

// channelSubscription houses the proxied update and error chans for a node's
// channel subscriptions.
type channelSubscription struct {
	updateChan chan *lnrpc.ChannelEventUpdate
	errChan    chan error
	quit       chan struct{}
}

// subscribeChannelNotifications subscribes to channel updates and launches a
// goroutine that forwards these to the returned channel.
func subscribeChannelNotifications(ctxb context.Context, t *harnessTest,
	node *lntest.HarnessNode) channelSubscription {

	// We'll first start by establishing a notification client which will
	// send us notifications upon channels becoming active, inactive or
	// closed.
	req := &lnrpc.ChannelEventSubscription{}
	ctx, cancelFunc := context.WithCancel(ctxb)

	chanUpdateClient, err := node.SubscribeChannelEvents(ctx, req)
	if err != nil {
		t.Fatalf("unable to create channel update client: %v", err)
	}

	// We'll launch a goroutine that will be responsible for proxying all
	// notifications recv'd from the client into the channel below.
	errChan := make(chan error, 1)
	quit := make(chan struct{})
	chanUpdates := make(chan *lnrpc.ChannelEventUpdate, 20)
	go func() {
		defer cancelFunc()
		for {
			select {
			case <-quit:
				return
			default:
				chanUpdate, err := chanUpdateClient.Recv()
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
				case chanUpdates <- chanUpdate:
				case <-quit:
					return
				}
			}
		}
	}()

	return channelSubscription{
		updateChan: chanUpdates,
		errChan:    errChan,
		quit:       quit,
	}
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

// testBasicChannelCreationAndUpdates tests multiple channel opening and closing,
// and ensures that if a node is subscribed to channel updates they will be
// received correctly for both cooperative and force closed channels.
func testBasicChannelCreationAndUpdates(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()
	const (
		numChannels = 2
		amount      = funding.MaxBtcFundingAmount
	)

	// Subscribe Bob and Alice to channel event notifications.
	bobChanSub := subscribeChannelNotifications(ctxb, t, net.Bob)
	defer close(bobChanSub.quit)

	aliceChanSub := subscribeChannelNotifications(ctxb, t, net.Alice)
	defer close(aliceChanSub.quit)

	// Open the channel between Alice and Bob, asserting that the
	// channel has been properly open on-chain.
	chanPoints := make([]*lnrpc.ChannelPoint, numChannels)
	for i := 0; i < numChannels; i++ {
		ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
		chanPoints[i] = openChannelAndAssert(
			ctxt, t, net, net.Alice, net.Bob,
			lntest.OpenChannelParams{
				Amt: amount,
			},
		)
	}

	// Since each of the channels just became open, Bob and Alice should
	// each receive an open and an active notification for each channel.
	var numChannelUpds int
	const totalNtfns = 3 * numChannels
	verifyOpenUpdatesReceived := func(sub channelSubscription) error {
		numChannelUpds = 0
		for numChannelUpds < totalNtfns {
			select {
			case update := <-sub.updateChan:
				switch update.Type {
				case lnrpc.ChannelEventUpdate_PENDING_OPEN_CHANNEL:
					if numChannelUpds%3 != 0 {
						return fmt.Errorf("expected " +
							"open or active" +
							"channel ntfn, got pending open " +
							"channel ntfn instead")
					}
				case lnrpc.ChannelEventUpdate_OPEN_CHANNEL:
					if numChannelUpds%3 != 1 {
						return fmt.Errorf("expected " +
							"pending open or active" +
							"channel ntfn, got open" +
							"channel ntfn instead")
					}
				case lnrpc.ChannelEventUpdate_ACTIVE_CHANNEL:
					if numChannelUpds%3 != 2 {
						return fmt.Errorf("expected " +
							"pending open or open" +
							"channel ntfn, got active " +
							"channel ntfn instead")
					}
				default:
					return fmt.Errorf("update type mismatch: "+
						"expected open or active channel "+
						"notification, got: %v",
						update.Type)
				}
				numChannelUpds++
			case <-time.After(time.Second * 10):
				return fmt.Errorf("timeout waiting for channel "+
					"notifications, only received %d/%d "+
					"chanupds", numChannelUpds,
					totalNtfns)
			}
		}

		return nil
	}

	if err := verifyOpenUpdatesReceived(bobChanSub); err != nil {
		t.Fatalf("error verifying open updates: %v", err)
	}
	if err := verifyOpenUpdatesReceived(aliceChanSub); err != nil {
		t.Fatalf("error verifying open updates: %v", err)
	}

	// Close the channel between Alice and Bob, asserting that the channel
	// has been properly closed on-chain.
	for i, chanPoint := range chanPoints {
		ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)

		// Force close half of the channels.
		force := i%2 == 0
		closeChannelAndAssert(ctx, t, net, net.Alice, chanPoint, force)
		if force {
			cleanupForceClose(t, net, net.Alice, chanPoint)
		}
	}

	// verifyCloseUpdatesReceived is used to verify that Alice and Bob
	// receive the correct channel updates in order.
	verifyCloseUpdatesReceived := func(sub channelSubscription,
		forceType lnrpc.ChannelCloseSummary_ClosureType,
		closeInitiator lnrpc.Initiator) error {

		// Ensure one inactive and one closed notification is received for each
		// closed channel.
		numChannelUpds := 0
		for numChannelUpds < 2*numChannels {
			expectedCloseType := lnrpc.ChannelCloseSummary_COOPERATIVE_CLOSE

			// Every other channel should be force closed. If this
			// channel was force closed, set the expected close type
			// the the type passed in.
			force := (numChannelUpds/2)%2 == 0
			if force {
				expectedCloseType = forceType
			}

			select {
			case chanUpdate := <-sub.updateChan:
				err := verifyCloseUpdate(
					chanUpdate, expectedCloseType,
					closeInitiator,
				)
				if err != nil {
					return err
				}

				numChannelUpds++
			case err := <-sub.errChan:
				return err
			case <-time.After(time.Second * 10):
				return fmt.Errorf("timeout waiting "+
					"for channel notifications, only "+
					"received %d/%d chanupds",
					numChannelUpds, 2*numChannels)
			}
		}

		return nil
	}

	// Verify Bob receives all closed channel notifications. He should
	// receive a remote force close notification for force closed channels.
	// All channels (cooperatively and force closed) should have a remote
	// close initiator because Alice closed the channels.
	if err := verifyCloseUpdatesReceived(bobChanSub,
		lnrpc.ChannelCloseSummary_REMOTE_FORCE_CLOSE,
		lnrpc.Initiator_INITIATOR_REMOTE); err != nil {
		t.Fatalf("errored verifying close updates: %v", err)
	}

	// Verify Alice receives all closed channel notifications. She should
	// receive a remote force close notification for force closed channels.
	// All channels (cooperatively and force closed) should have a local
	// close initiator because Alice closed the channels.
	if err := verifyCloseUpdatesReceived(aliceChanSub,
		lnrpc.ChannelCloseSummary_LOCAL_FORCE_CLOSE,
		lnrpc.Initiator_INITIATOR_LOCAL); err != nil {
		t.Fatalf("errored verifying close updates: %v", err)
	}
}

// testMaxPendingChannels checks that error is returned from remote peer if
// max pending channel number was exceeded and that '--maxpendingchannels' flag
// exists and works properly.
func testMaxPendingChannels(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	maxPendingChannels := lncfg.DefaultMaxPendingChannels + 1
	amount := funding.MaxBtcFundingAmount

	// Create a new node (Carol) with greater number of max pending
	// channels.
	args := []string{
		fmt.Sprintf("--maxpendingchannels=%v", maxPendingChannels),
	}
	carol := net.NewNode(t.t, "Carol", args)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalance := btcutil.Amount(maxPendingChannels) * amount
	net.SendCoins(ctxt, t.t, carolBalance, carol)

	// Send open channel requests without generating new blocks thereby
	// increasing pool of pending channels. Then check that we can't open
	// the channel if the number of pending channels exceed max value.
	openStreams := make([]lnrpc.Lightning_OpenChannelClient, maxPendingChannels)
	for i := 0; i < maxPendingChannels; i++ {
		ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
		stream := openChannelStream(
			ctxt, t, net, net.Alice, carol,
			lntest.OpenChannelParams{
				Amt: amount,
			},
		)
		openStreams[i] = stream
	}

	// Carol exhausted available amount of pending channels, next open
	// channel request should cause ErrorGeneric to be sent back to Alice.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	_, err := net.OpenChannel(
		ctxt, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: amount,
		},
	)

	if err == nil {
		t.Fatalf("error wasn't received")
	} else if !strings.Contains(
		err.Error(), lnwire.ErrMaxPendingChannels.Error(),
	) {
		t.Fatalf("not expected error was received: %v", err)
	}

	// For now our channels are in pending state, in order to not interfere
	// with other tests we should clean up - complete opening of the
	// channel and then close it.

	// Mine 6 blocks, then wait for node's to notify us that the channel has
	// been opened. The funding transactions should be found within the
	// first newly mined block. 6 blocks make sure the funding transaction
	// has enough confirmations to be announced publicly.
	block := mineBlocks(t, net, 6, maxPendingChannels)[0]

	chanPoints := make([]*lnrpc.ChannelPoint, maxPendingChannels)
	for i, stream := range openStreams {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		fundingChanPoint, err := net.WaitForChannelOpen(ctxt, stream)
		if err != nil {
			t.Fatalf("error while waiting for channel open: %v", err)
		}

		fundingTxID, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
		if err != nil {
			t.Fatalf("unable to get txid: %v", err)
		}

		// Ensure that the funding transaction enters a block, and is
		// properly advertised by Alice.
		assertTxInBlock(t, block, fundingTxID)
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = net.Alice.WaitForNetworkChannelOpen(ctxt, fundingChanPoint)
		if err != nil {
			t.Fatalf("channel not seen on network before "+
				"timeout: %v", err)
		}

		// The channel should be listed in the peer information
		// returned by both peers.
		chanPoint := wire.OutPoint{
			Hash:  *fundingTxID,
			Index: fundingChanPoint.OutputIndex,
		}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		if err := net.AssertChannelExists(ctxt, net.Alice, &chanPoint); err != nil {
			t.Fatalf("unable to assert channel existence: %v", err)
		}

		chanPoints[i] = fundingChanPoint
	}

	// Next, close the channel between Alice and Carol, asserting that the
	// channel has been properly closed on-chain.
	for _, chanPoint := range chanPoints {
		ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
		closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
	}
}

// getNTxsFromMempool polls until finding the desired number of transactions in
// the provided miner's mempool and returns the full transactions to the caller.
func getNTxsFromMempool(miner *rpcclient.Client, n int,
	timeout time.Duration) ([]*wire.MsgTx, error) {

	txids, err := waitForNTxsInMempool(miner, n, timeout)
	if err != nil {
		return nil, err
	}

	var txes []*wire.MsgTx
	for _, txid := range txids {
		tx, err := miner.GetRawTransaction(txid)
		if err != nil {
			return nil, err
		}
		txes = append(txes, tx.MsgTx())
	}
	return txes, nil
}

// getTxFee retrieves parent transactions and reconstructs the fee paid.
func getTxFee(miner *rpcclient.Client, tx *wire.MsgTx) (btcutil.Amount, error) {
	var balance btcutil.Amount
	for _, in := range tx.TxIn {
		parentHash := in.PreviousOutPoint.Hash
		rawTx, err := miner.GetRawTransaction(&parentHash)
		if err != nil {
			return 0, err
		}
		parent := rawTx.MsgTx()
		balance += btcutil.Amount(
			parent.TxOut[in.PreviousOutPoint.Index].Value,
		)
	}

	for _, out := range tx.TxOut {
		balance -= btcutil.Amount(out.Value)
	}

	return balance, nil
}

// testFailingChannel tests that we will fail the channel by force closing ii
// in the case where a counterparty tries to settle an HTLC with the wrong
// preimage.
func testFailingChannel(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		paymentAmt = 10000
	)

	chanAmt := lnd.MaxFundingAmount

	// We'll introduce Carol, which will settle any incoming invoice with a
	// totally unrelated preimage.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.bogus-settle"})
	defer shutdownAndAssert(net, t, carol)

	// Let Alice connect and open a channel to Carol,
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// With the channel open, we'll create a invoice for Carol that Alice
	// will attempt to pay.
	preimage := bytes.Repeat([]byte{byte(192)}, 32)
	invoice := &lnrpc.Invoice{
		Memo:      "testing",
		RPreimage: preimage,
		Value:     paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}
	carolPayReqs := []string{resp.PaymentRequest}

	// Wait for Alice to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't see the alice->carol channel before "+
			"timeout: %v", err)
	}

	// Send the payment from Alice to Carol. We expect Carol to attempt to
	// settle this payment with the wrong preimage.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient, carolPayReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Since Alice detects that Carol is trying to trick her by providing a
	// fake preimage, she should fail and force close the channel.
	var predErr error
	err = wait.Predicate(func() bool {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := net.Alice.PendingChannels(ctxt,
			pendingChansRequest)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		n := len(pendingChanResp.WaitingCloseChannels)
		if n != 1 {
			predErr = fmt.Errorf("Expected to find %d channels "+
				"waiting close, found %d", 1, n)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// Mine a block to confirm the broadcasted commitment.
	block := mineBlocks(t, net, 1, 1)[0]
	if len(block.Transactions) != 2 {
		t.Fatalf("transaction wasn't mined")
	}

	// The channel should now show up as force closed both for Alice and
	// Carol.
	err = wait.Predicate(func() bool {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := net.Alice.PendingChannels(ctxt,
			pendingChansRequest)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		n := len(pendingChanResp.WaitingCloseChannels)
		if n != 0 {
			predErr = fmt.Errorf("Expected to find %d channels "+
				"waiting close, found %d", 0, n)
			return false
		}
		n = len(pendingChanResp.PendingForceClosingChannels)
		if n != 1 {
			predErr = fmt.Errorf("expected to find %d channel "+
				"pending force close, found %d", 1, n)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	err = wait.Predicate(func() bool {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := carol.PendingChannels(ctxt,
			pendingChansRequest)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		n := len(pendingChanResp.PendingForceClosingChannels)
		if n != 1 {
			predErr = fmt.Errorf("expected to find %d channel "+
				"pending force close, found %d", 1, n)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// Carol will use the correct preimage to resolve the HTLC on-chain.
	_, err = waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Carol's resolve tx in mempool: %v", err)
	}

	// Mine enough blocks for Alice to sweep her funds from the force
	// closed channel.
	_, err = net.Miner.Client.Generate(defaultCSV - 1)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	// Wait for the sweeping tx to be broadcast.
	_, err = waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Alice's sweep tx in mempool: %v", err)
	}

	// Mine the sweep.
	_, err = net.Miner.Client.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	// No pending channels should be left.
	err = wait.Predicate(func() bool {
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := net.Alice.PendingChannels(ctxt,
			pendingChansRequest)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}
		n := len(pendingChanResp.PendingForceClosingChannels)
		if n != 0 {
			predErr = fmt.Errorf("expected to find %d channel "+
				"pending force close, found %d", 0, n)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}
}

// testGarbageCollectLinkNodes tests that we properly garbase collect link nodes
// from the database and the set of persistent connections within the server.
func testGarbageCollectLinkNodes(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt = 1000000
	)

	// Open a channel between Alice and Bob which will later be
	// cooperatively closed.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	coopChanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Create Carol's node and connect Alice to her.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, carol)

	// Open a channel between Alice and Carol which will later be force
	// closed.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	forceCloseChanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Now, create Dave's a node and also open a channel between Alice and
	// him. This link will serve as the only persistent link throughout
	// restarts in this test.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	net.ConnectNodes(ctxt, t.t, net.Alice, dave)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	persistentChanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// isConnected is a helper closure that checks if a peer is connected to
	// Alice.
	isConnected := func(pubKey string) bool {
		req := &lnrpc.ListPeersRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		resp, err := net.Alice.ListPeers(ctxt, req)
		if err != nil {
			t.Fatalf("unable to retrieve alice's peers: %v", err)
		}

		for _, peer := range resp.Peers {
			if peer.PubKey == pubKey {
				return true
			}
		}

		return false
	}

	// Restart both Bob and Carol to ensure Alice is able to reconnect to
	// them.
	if err := net.RestartNode(net.Bob, nil); err != nil {
		t.Fatalf("unable to restart bob's node: %v", err)
	}
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("unable to restart carol's node: %v", err)
	}

	require.Eventually(t.t, func() bool {
		return isConnected(net.Bob.PubKeyStr)
	}, defaultTimeout, 20*time.Millisecond)
	require.Eventually(t.t, func() bool {
		return isConnected(carol.PubKeyStr)
	}, defaultTimeout, 20*time.Millisecond)

	// We'll also restart Alice to ensure she can reconnect to her peers
	// with open channels.
	if err := net.RestartNode(net.Alice, nil); err != nil {
		t.Fatalf("unable to restart alice's node: %v", err)
	}

	require.Eventually(t.t, func() bool {
		return isConnected(net.Bob.PubKeyStr)
	}, defaultTimeout, 20*time.Millisecond)
	require.Eventually(t.t, func() bool {
		return isConnected(carol.PubKeyStr)
	}, defaultTimeout, 20*time.Millisecond)
	require.Eventually(t.t, func() bool {
		return isConnected(dave.PubKeyStr)
	}, defaultTimeout, 20*time.Millisecond)
	err := wait.Predicate(func() bool {
		return isConnected(dave.PubKeyStr)
	}, defaultTimeout)

	// testReconnection is a helper closure that restarts the nodes at both
	// ends of a channel to ensure they do not reconnect after restarting.
	// When restarting Alice, we'll first need to ensure she has
	// reestablished her connection with Dave, as they still have an open
	// channel together.
	testReconnection := func(node *lntest.HarnessNode) {
		// Restart both nodes, to trigger the pruning logic.
		if err := net.RestartNode(node, nil); err != nil {
			t.Fatalf("unable to restart %v's node: %v",
				node.Name(), err)
		}

		if err := net.RestartNode(net.Alice, nil); err != nil {
			t.Fatalf("unable to restart alice's node: %v", err)
		}

		// Now restart both nodes and make sure they don't reconnect.
		if err := net.RestartNode(node, nil); err != nil {
			t.Fatalf("unable to restart %v's node: %v", node.Name(),
				err)
		}
		err = wait.Invariant(func() bool {
			return !isConnected(node.PubKeyStr)
		}, 5*time.Second)
		if err != nil {
			t.Fatalf("alice reconnected to %v", node.Name())
		}

		if err := net.RestartNode(net.Alice, nil); err != nil {
			t.Fatalf("unable to restart alice's node: %v", err)
		}
		err = wait.Predicate(func() bool {
			return isConnected(dave.PubKeyStr)
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("alice didn't reconnect to Dave")
		}

		err = wait.Invariant(func() bool {
			return !isConnected(node.PubKeyStr)
		}, 5*time.Second)
		if err != nil {
			t.Fatalf("alice reconnected to %v", node.Name())
		}
	}

	// Now, we'll close the channel between Alice and Bob and ensure there
	// is no reconnection logic between the both once the channel is fully
	// closed.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, coopChanPoint, false)

	testReconnection(net.Bob)

	// We'll do the same with Alice and Carol, but this time we'll force
	// close the channel instead.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, forceCloseChanPoint, true)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, net.Alice, forceCloseChanPoint)

	// We'll need to mine some blocks in order to mark the channel fully
	// closed.
	_, err = net.Miner.Client.Generate(chainreg.DefaultBitcoinTimeLockDelta - defaultCSV)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	// Before we test reconnection, we'll ensure that the channel has been
	// fully cleaned up for both Carol and Alice.
	var predErr error
	pendingChansRequest := &lnrpc.PendingChannelsRequest{}
	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err := net.Alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}

		predErr = checkNumForceClosedChannels(pendingChanResp, 0)
		if predErr != nil {
			return false
		}

		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		pendingChanResp, err = carol.PendingChannels(
			ctxt, pendingChansRequest,
		)
		if err != nil {
			predErr = fmt.Errorf("unable to query for pending "+
				"channels: %v", err)
			return false
		}

		predErr = checkNumForceClosedChannels(pendingChanResp, 0)

		return predErr == nil

	}, defaultTimeout)
	if err != nil {
		t.Fatalf("channels not marked as fully resolved: %v", predErr)
	}

	testReconnection(carol)

	// Finally, we'll ensure that Bob and Carol no longer show in Alice's
	// channel graph.
	describeGraphReq := &lnrpc.ChannelGraphRequest{
		IncludeUnannounced: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	channelGraph, err := net.Alice.DescribeGraph(ctxt, describeGraphReq)
	if err != nil {
		t.Fatalf("unable to query for alice's channel graph: %v", err)
	}
	for _, node := range channelGraph.Nodes {
		if node.PubKey == net.Bob.PubKeyStr {
			t.Fatalf("did not expect to find bob in the channel " +
				"graph, but did")
		}
		if node.PubKey == carol.PubKeyStr {
			t.Fatalf("did not expect to find carol in the channel " +
				"graph, but did")
		}
	}

	// Now that the test is done, we can also close the persistent link.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, persistentChanPoint, false)
}

// testRevokedCloseRetribution tests that Carol is able carry out
// retribution in the event that she fails immediately after detecting Bob's
// breach txn in the mempool.
func testRevokedCloseRetribution(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt     = funding.MaxBtcFundingAmount
		paymentAmt  = 10000
		numInvoices = 6
	)

	// Carol will be the breached party. We set --nolisten to ensure Bob
	// won't be able to connect to her and trigger the channel data
	// protection logic automatically. We also can't have Carol
	// automatically re-connect too early, otherwise DLP would be initiated
	// instead of the breach we want to provoke.
	carol := net.NewNode(
		t.t, "Carol",
		[]string{"--hodl.exit-settle", "--nolisten", "--minbackoff=1h"},
	)
	defer shutdownAndAssert(net, t, carol)

	// We must let Bob communicate with Carol before they are able to open
	// channel, so we connect Bob and Carol,
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Bob)

	// Before we make a channel, we'll load up Carol with some coins sent
	// directly from the miner.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	// In order to test Carol's response to an uncooperative channel
	// closure by Bob, we'll first open up a channel between them with a
	// 0.5 BTC value.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, carol, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// With the channel open, we'll create a few invoices for Bob that
	// Carol will pay to in order to advance the state of the channel.
	bobPayReqs, _, _, err := createPayReqs(
		net.Bob, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Wait for Carol to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("carol didn't see the carol->bob channel before "+
			"timeout: %v", err)
	}

	// Send payments from Carol to Bob using 3 of Bob's payment hashes
	// generated above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient, bobPayReqs[:numInvoices/2],
		true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Next query for Bob's channel state, as we sent 3 payments of 10k
	// satoshis each, Bob should now see his balance as being 30k satoshis.
	var bobChan *lnrpc.Channel
	var predErr error
	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		bChan, err := getChanInfo(ctxt, net.Bob)
		if err != nil {
			t.Fatalf("unable to get bob's channel info: %v", err)
		}
		if bChan.LocalBalance != 30000 {
			predErr = fmt.Errorf("bob's balance is incorrect, "+
				"got %v, expected %v", bChan.LocalBalance,
				30000)
			return false
		}

		bobChan = bChan
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// Grab Bob's current commitment height (update number), we'll later
	// revert him to this state after additional updates to force him to
	// broadcast this soon to be revoked state.
	bobStateNumPreCopy := bobChan.NumUpdates

	// With the temporary file created, copy Bob's current state into the
	// temporary file we created above. Later after more updates, we'll
	// restore this state.
	if err := net.BackupDb(net.Bob); err != nil {
		t.Fatalf("unable to copy database files: %v", err)
	}

	// Finally, send payments from Carol to Bob, consuming Bob's remaining
	// payment hashes.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient, bobPayReqs[numInvoices/2:],
		true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	bobChan, err = getChanInfo(ctxt, net.Bob)
	if err != nil {
		t.Fatalf("unable to get bob chan info: %v", err)
	}

	// Now we shutdown Bob, copying over the his temporary database state
	// which has the *prior* channel state over his current most up to date
	// state. With this, we essentially force Bob to travel back in time
	// within the channel's history.
	if err = net.RestartNode(net.Bob, func() error {
		return net.RestoreDb(net.Bob)
	}); err != nil {
		t.Fatalf("unable to restart node: %v", err)
	}

	// Now query for Bob's channel state, it should show that he's at a
	// state number in the past, not the *latest* state.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	bobChan, err = getChanInfo(ctxt, net.Bob)
	if err != nil {
		t.Fatalf("unable to get bob chan info: %v", err)
	}
	if bobChan.NumUpdates != bobStateNumPreCopy {
		t.Fatalf("db copy failed: %v", bobChan.NumUpdates)
	}

	// Now force Bob to execute a *force* channel closure by unilaterally
	// broadcasting his current channel state. This is actually the
	// commitment transaction of a prior *revoked* state, so he'll soon
	// feel the wrath of Carol's retribution.
	var closeUpdates lnrpc.Lightning_CloseChannelClient
	force := true
	err = wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctxb, channelCloseTimeout)
		closeUpdates, _, err = net.CloseChannel(ctxt, net.Bob, chanPoint, force)
		if err != nil {
			predErr = err
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("unable to close channel: %v", predErr)
	}

	// Wait for Bob's breach transaction to show up in the mempool to ensure
	// that Carol's node has started waiting for confirmations.
	_, err = waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Bob's breach tx in mempool: %v", err)
	}

	// Here, Carol sees Bob's breach transaction in the mempool, but is waiting
	// for it to confirm before continuing her retribution. We restart Carol to
	// ensure that she is persisting her retribution state and continues
	// watching for the breach transaction to confirm even after her node
	// restarts.
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("unable to restart Carol's node: %v", err)
	}

	// Finally, generate a single block, wait for the final close status
	// update, then ensure that the closing transaction was included in the
	// block.
	block := mineBlocks(t, net, 1, 1)[0]

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	breachTXID, err := net.WaitForChannelClose(ctxt, closeUpdates)
	if err != nil {
		t.Fatalf("error while waiting for channel close: %v", err)
	}
	assertTxInBlock(t, block, breachTXID)

	// Query the mempool for Carol's justice transaction, this should be
	// broadcast as Bob's contract breaching transaction gets confirmed
	// above.
	justiceTXID, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Carol's justice tx in mempool: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Query for the mempool transaction found above. Then assert that all
	// the inputs of this transaction are spending outputs generated by
	// Bob's breach transaction above.
	justiceTx, err := net.Miner.Client.GetRawTransaction(justiceTXID)
	if err != nil {
		t.Fatalf("unable to query for justice tx: %v", err)
	}
	for _, txIn := range justiceTx.MsgTx().TxIn {
		if !bytes.Equal(txIn.PreviousOutPoint.Hash[:], breachTXID[:]) {
			t.Fatalf("justice tx not spending commitment utxo "+
				"instead is: %v", txIn.PreviousOutPoint)
		}
	}

	// We restart Carol here to ensure that she persists her retribution state
	// and successfully continues exacting retribution after restarting. At
	// this point, Carol has broadcast the justice transaction, but it hasn't
	// been confirmed yet; when Carol restarts, she should start waiting for
	// the justice transaction to confirm again.
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("unable to restart Carol's node: %v", err)
	}

	// Now mine a block, this transaction should include Carol's justice
	// transaction which was just accepted into the mempool.
	block = mineBlocks(t, net, 1, 1)[0]

	// The block should have exactly *two* transactions, one of which is
	// the justice transaction.
	if len(block.Transactions) != 2 {
		t.Fatalf("transaction wasn't mined")
	}
	justiceSha := block.Transactions[1].TxHash()
	if !bytes.Equal(justiceTx.Hash()[:], justiceSha[:]) {
		t.Fatalf("justice tx wasn't mined")
	}

	assertNodeNumChannels(t, carol, 0)

	// Mine enough blocks for Bob's channel arbitrator to wrap up the
	// references to the breached channel. The chanarb waits for commitment
	// tx's confHeight+CSV-1 blocks and since we've already mined one that
	// included the justice tx we only need to mine extra DefaultCSV-2
	// blocks to unlock it.
	mineBlocks(t, net, lntest.DefaultCSV-2, 0)

	assertNumPendingChannels(t, net.Bob, 0, 0)
}

// testRevokedCloseRetributionZeroValueRemoteOutput tests that Dave is able
// carry out retribution in the event that she fails in state where the remote
// commitment output has zero-value.
func testRevokedCloseRetributionZeroValueRemoteOutput(net *lntest.NetworkHarness,
	t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt     = funding.MaxBtcFundingAmount
		paymentAmt  = 10000
		numInvoices = 6
	)

	// Since we'd like to test some multi-hop failure scenarios, we'll
	// introduce another node into our test network: Carol.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	defer shutdownAndAssert(net, t, carol)

	// Dave will be the breached party. We set --nolisten to ensure Carol
	// won't be able to connect to him and trigger the channel data
	// protection logic automatically. We also can't have Dave automatically
	// re-connect too early, otherwise DLP would be initiated instead of the
	// breach we want to provoke.
	dave := net.NewNode(
		t.t, "Dave",
		[]string{"--hodl.exit-settle", "--nolisten", "--minbackoff=1h"},
	)
	defer shutdownAndAssert(net, t, dave)

	// We must let Dave have an open channel before she can send a node
	// announcement, so we open a channel with Carol,
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, carol)

	// Before we make a channel, we'll load up Dave with some coins sent
	// directly from the miner.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	// In order to test Dave's response to an uncooperative channel
	// closure by Carol, we'll first open up a channel between them with a
	// 0.5 BTC value.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, dave, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// With the channel open, we'll create a few invoices for Carol that
	// Dave will pay to in order to advance the state of the channel.
	carolPayReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Wait for Dave to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("dave didn't see the dave->carol channel before "+
			"timeout: %v", err)
	}

	// Next query for Carol's channel state, as we sent 0 payments, Carol
	// should now see her balance as being 0 satoshis.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolChan, err := getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol's channel info: %v", err)
	}
	if carolChan.LocalBalance != 0 {
		t.Fatalf("carol's balance is incorrect, got %v, expected %v",
			carolChan.LocalBalance, 0)
	}

	// Grab Carol's current commitment height (update number), we'll later
	// revert her to this state after additional updates to force him to
	// broadcast this soon to be revoked state.
	carolStateNumPreCopy := carolChan.NumUpdates

	// With the temporary file created, copy Carol's current state into the
	// temporary file we created above. Later after more updates, we'll
	// restore this state.
	if err := net.BackupDb(carol); err != nil {
		t.Fatalf("unable to copy database files: %v", err)
	}

	// Finally, send payments from Dave to Carol, consuming Carol's remaining
	// payment hashes.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, dave, dave.RouterClient, carolPayReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol chan info: %v", err)
	}

	// Now we shutdown Carol, copying over the his temporary database state
	// which has the *prior* channel state over his current most up to date
	// state. With this, we essentially force Carol to travel back in time
	// within the channel's history.
	if err = net.RestartNode(carol, func() error {
		return net.RestoreDb(carol)
	}); err != nil {
		t.Fatalf("unable to restart node: %v", err)
	}

	// Now query for Carol's channel state, it should show that he's at a
	// state number in the past, not the *latest* state.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolChan, err = getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol chan info: %v", err)
	}
	if carolChan.NumUpdates != carolStateNumPreCopy {
		t.Fatalf("db copy failed: %v", carolChan.NumUpdates)
	}

	// Now force Carol to execute a *force* channel closure by unilaterally
	// broadcasting his current channel state. This is actually the
	// commitment transaction of a prior *revoked* state, so he'll soon
	// feel the wrath of Dave's retribution.
	var (
		closeUpdates lnrpc.Lightning_CloseChannelClient
		closeTxID    *chainhash.Hash
		closeErr     error
	)

	force := true
	err = wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctxb, channelCloseTimeout)
		closeUpdates, closeTxID, closeErr = net.CloseChannel(
			ctxt, carol, chanPoint, force,
		)
		return closeErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("unable to close channel: %v", closeErr)
	}

	// Query the mempool for the breaching closing transaction, this should
	// be broadcast by Carol when she force closes the channel above.
	txid, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Carol's force close tx in mempool: %v",
			err)
	}
	if *txid != *closeTxID {
		t.Fatalf("expected closeTx(%v) in mempool, instead found %v",
			closeTxID, txid)
	}

	// Finally, generate a single block, wait for the final close status
	// update, then ensure that the closing transaction was included in the
	// block.
	block := mineBlocks(t, net, 1, 1)[0]

	// Here, Dave receives a confirmation of Carol's breach transaction.
	// We restart Dave to ensure that she is persisting her retribution
	// state and continues exacting justice after her node restarts.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("unable to stop Dave's node: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	breachTXID, err := net.WaitForChannelClose(ctxt, closeUpdates)
	if err != nil {
		t.Fatalf("error while waiting for channel close: %v", err)
	}
	assertTxInBlock(t, block, breachTXID)

	// Query the mempool for Dave's justice transaction, this should be
	// broadcast as Carol's contract breaching transaction gets confirmed
	// above.
	justiceTXID, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Dave's justice tx in mempool: %v",
			err)
	}
	time.Sleep(100 * time.Millisecond)

	// Query for the mempool transaction found above. Then assert that all
	// the inputs of this transaction are spending outputs generated by
	// Carol's breach transaction above.
	justiceTx, err := net.Miner.Client.GetRawTransaction(justiceTXID)
	if err != nil {
		t.Fatalf("unable to query for justice tx: %v", err)
	}
	for _, txIn := range justiceTx.MsgTx().TxIn {
		if !bytes.Equal(txIn.PreviousOutPoint.Hash[:], breachTXID[:]) {
			t.Fatalf("justice tx not spending commitment utxo "+
				"instead is: %v", txIn.PreviousOutPoint)
		}
	}

	// We restart Dave here to ensure that he persists her retribution state
	// and successfully continues exacting retribution after restarting. At
	// this point, Dave has broadcast the justice transaction, but it hasn't
	// been confirmed yet; when Dave restarts, she should start waiting for
	// the justice transaction to confirm again.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("unable to restart Dave's node: %v", err)
	}

	// Now mine a block, this transaction should include Dave's justice
	// transaction which was just accepted into the mempool.
	block = mineBlocks(t, net, 1, 1)[0]

	// The block should have exactly *two* transactions, one of which is
	// the justice transaction.
	if len(block.Transactions) != 2 {
		t.Fatalf("transaction wasn't mined")
	}
	justiceSha := block.Transactions[1].TxHash()
	if !bytes.Equal(justiceTx.Hash()[:], justiceSha[:]) {
		t.Fatalf("justice tx wasn't mined")
	}

	assertNodeNumChannels(t, dave, 0)
}

// testRevokedCloseRetributionRemoteHodl tests that Dave properly responds to a
// channel breach made by the remote party, specifically in the case that the
// remote party breaches before settling extended HTLCs.
func testRevokedCloseRetributionRemoteHodl(net *lntest.NetworkHarness,
	t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt     = funding.MaxBtcFundingAmount
		pushAmt     = 200000
		paymentAmt  = 10000
		numInvoices = 6
	)

	// Since this test will result in the counterparty being left in a
	// weird state, we will introduce another node into our test network:
	// Carol.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	defer shutdownAndAssert(net, t, carol)

	// We'll also create a new node Dave, who will have a channel with
	// Carol, and also use similar settings so we can broadcast a commit
	// with active HTLCs. Dave will be the breached party. We set
	// --nolisten to ensure Carol won't be able to connect to him and
	// trigger the channel data protection logic automatically.
	dave := net.NewNode(
		t.t, "Dave",
		[]string{"--hodl.exit-settle", "--nolisten"},
	)
	defer shutdownAndAssert(net, t, dave)

	// We must let Dave communicate with Carol before they are able to open
	// channel, so we connect Dave and Carol,
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, carol)

	// Before we make a channel, we'll load up Dave with some coins sent
	// directly from the miner.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	// In order to test Dave's response to an uncooperative channel closure
	// by Carol, we'll first open up a channel between them with a
	// funding.MaxBtcFundingAmount (2^24) satoshis value.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, dave, carol,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)

	// With the channel open, we'll create a few invoices for Carol that
	// Dave will pay to in order to advance the state of the channel.
	carolPayReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// We'll introduce a closure to validate that Carol's current balance
	// matches the given expected amount.
	checkCarolBalance := func(expectedAmt int64) {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		carolChan, err := getChanInfo(ctxt, carol)
		if err != nil {
			t.Fatalf("unable to get carol's channel info: %v", err)
		}
		if carolChan.LocalBalance != expectedAmt {
			t.Fatalf("carol's balance is incorrect, "+
				"got %v, expected %v", carolChan.LocalBalance,
				expectedAmt)
		}
	}

	// We'll introduce another closure to validate that Carol's current
	// number of updates is at least as large as the provided minimum
	// number.
	checkCarolNumUpdatesAtLeast := func(minimum uint64) {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		carolChan, err := getChanInfo(ctxt, carol)
		if err != nil {
			t.Fatalf("unable to get carol's channel info: %v", err)
		}
		if carolChan.NumUpdates < minimum {
			t.Fatalf("carol's numupdates is incorrect, want %v "+
				"to be at least %v", carolChan.NumUpdates,
				minimum)
		}
	}

	// Wait for Dave to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("dave didn't see the dave->carol channel before "+
			"timeout: %v", err)
	}

	// Ensure that carol's balance starts with the amount we pushed to her.
	checkCarolBalance(pushAmt)

	// Send payments from Dave to Carol using 3 of Carol's payment hashes
	// generated above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, dave, dave.RouterClient, carolPayReqs[:numInvoices/2],
		false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// At this point, we'll also send over a set of HTLC's from Carol to
	// Dave. This ensures that the final revoked transaction has HTLC's in
	// both directions.
	davePayReqs, _, _, err := createPayReqs(
		dave, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Send payments from Carol to Dave using 3 of Dave's payment hashes
	// generated above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient, davePayReqs[:numInvoices/2],
		false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Next query for Carol's channel state, as we sent 3 payments of 10k
	// satoshis each, however Carol should now see her balance as being
	// equal to the push amount in satoshis since she has not settled.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolChan, err := getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol's channel info: %v", err)
	}

	// Grab Carol's current commitment height (update number), we'll later
	// revert her to this state after additional updates to force her to
	// broadcast this soon to be revoked state.
	carolStateNumPreCopy := carolChan.NumUpdates

	// Ensure that carol's balance still reflects the original amount we
	// pushed to her, minus the HTLCs she just sent to Dave.
	checkCarolBalance(pushAmt - 3*paymentAmt)

	// Since Carol has not settled, she should only see at least one update
	// to her channel.
	checkCarolNumUpdatesAtLeast(1)

	// With the temporary file created, copy Carol's current state into the
	// temporary file we created above. Later after more updates, we'll
	// restore this state.
	if err := net.BackupDb(carol); err != nil {
		t.Fatalf("unable to copy database files: %v", err)
	}

	// Finally, send payments from Dave to Carol, consuming Carol's
	// remaining payment hashes.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, dave, dave.RouterClient, carolPayReqs[numInvoices/2:],
		false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Ensure that carol's balance still shows the amount we originally
	// pushed to her (minus the HTLCs she sent to Bob), and that at least
	// one more update has occurred.
	time.Sleep(500 * time.Millisecond)
	checkCarolBalance(pushAmt - 3*paymentAmt)
	checkCarolNumUpdatesAtLeast(carolStateNumPreCopy + 1)

	// Suspend Dave, such that Carol won't reconnect at startup, triggering
	// the data loss protection.
	restartDave, err := net.SuspendNode(dave)
	if err != nil {
		t.Fatalf("unable to suspend Dave: %v", err)
	}

	// Now we shutdown Carol, copying over the her temporary database state
	// which has the *prior* channel state over her current most up to date
	// state. With this, we essentially force Carol to travel back in time
	// within the channel's history.
	if err = net.RestartNode(carol, func() error {
		return net.RestoreDb(carol)
	}); err != nil {
		t.Fatalf("unable to restart node: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Ensure that Carol's view of the channel is consistent with the state
	// of the channel just before it was snapshotted.
	checkCarolBalance(pushAmt - 3*paymentAmt)
	checkCarolNumUpdatesAtLeast(1)

	// Now query for Carol's channel state, it should show that she's at a
	// state number in the past, *not* the latest state.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolChan, err = getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol chan info: %v", err)
	}
	if carolChan.NumUpdates != carolStateNumPreCopy {
		t.Fatalf("db copy failed: %v", carolChan.NumUpdates)
	}

	// Now force Carol to execute a *force* channel closure by unilaterally
	// broadcasting her current channel state. This is actually the
	// commitment transaction of a prior *revoked* state, so she'll soon
	// feel the wrath of Dave's retribution.
	force := true
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeUpdates, closeTxID, err := net.CloseChannel(ctxt, carol,
		chanPoint, force)
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	// Query the mempool for the breaching closing transaction, this should
	// be broadcast by Carol when she force closes the channel above.
	txid, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Carol's force close tx in mempool: %v",
			err)
	}
	if *txid != *closeTxID {
		t.Fatalf("expected closeTx(%v) in mempool, instead found %v",
			closeTxID, txid)
	}

	// Generate a single block to mine the breach transaction.
	block := mineBlocks(t, net, 1, 1)[0]

	// We resurrect Dave to ensure he will be exacting justice after his
	// node restarts.
	if err := restartDave(); err != nil {
		t.Fatalf("unable to stop Dave's node: %v", err)
	}

	// Finally, wait for the final close status update, then ensure that
	// the closing transaction was included in the block.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	breachTXID, err := net.WaitForChannelClose(ctxt, closeUpdates)
	if err != nil {
		t.Fatalf("error while waiting for channel close: %v", err)
	}
	if *breachTXID != *closeTxID {
		t.Fatalf("expected breach ID(%v) to be equal to close ID (%v)",
			breachTXID, closeTxID)
	}
	assertTxInBlock(t, block, breachTXID)

	// Query the mempool for Dave's justice transaction, this should be
	// broadcast as Carol's contract breaching transaction gets confirmed
	// above. Since Carol might have had the time to take some of the HTLC
	// outputs to the second level before Dave broadcasts his justice tx,
	// we'll search through the mempool for a tx that matches the number of
	// expected inputs in the justice tx.
	var predErr error
	var justiceTxid *chainhash.Hash
	errNotFound := errors.New("justice tx not found")
	findJusticeTx := func() (*chainhash.Hash, error) {
		mempool, err := net.Miner.Client.GetRawMempool()
		if err != nil {
			return nil, fmt.Errorf("unable to get mempool from "+
				"miner: %v", err)
		}

		for _, txid := range mempool {
			// Check that the justice tx has the appropriate number
			// of inputs.
			tx, err := net.Miner.Client.GetRawTransaction(txid)
			if err != nil {
				return nil, fmt.Errorf("unable to query for "+
					"txs: %v", err)
			}

			exNumInputs := 2 + numInvoices
			if len(tx.MsgTx().TxIn) == exNumInputs {
				return txid, nil
			}
		}
		return nil, errNotFound
	}

	err = wait.Predicate(func() bool {
		txid, err := findJusticeTx()
		if err != nil {
			predErr = err
			return false
		}

		justiceTxid = txid
		return true
	}, defaultTimeout)
	if err != nil && predErr == errNotFound {
		// If Dave is unable to broadcast his justice tx on first
		// attempt because of the second layer transactions, he will
		// wait until the next block epoch before trying again. Because
		// of this, we'll mine a block if we cannot find the justice tx
		// immediately. Since we cannot tell for sure how many
		// transactions will be in the mempool at this point, we pass 0
		// as the last argument, indicating we don't care what's in the
		// mempool.
		mineBlocks(t, net, 1, 0)
		err = wait.Predicate(func() bool {
			txid, err := findJusticeTx()
			if err != nil {
				predErr = err
				return false
			}

			justiceTxid = txid
			return true
		}, defaultTimeout)
	}
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	justiceTx, err := net.Miner.Client.GetRawTransaction(justiceTxid)
	if err != nil {
		t.Fatalf("unable to query for justice tx: %v", err)
	}

	// isSecondLevelSpend checks that the passed secondLevelTxid is a
	// potentitial second level spend spending from the commit tx.
	isSecondLevelSpend := func(commitTxid, secondLevelTxid *chainhash.Hash) bool {
		secondLevel, err := net.Miner.Client.GetRawTransaction(
			secondLevelTxid)
		if err != nil {
			t.Fatalf("unable to query for tx: %v", err)
		}

		// A second level spend should have only one input, and one
		// output.
		if len(secondLevel.MsgTx().TxIn) != 1 {
			return false
		}
		if len(secondLevel.MsgTx().TxOut) != 1 {
			return false
		}

		// The sole input should be spending from the commit tx.
		txIn := secondLevel.MsgTx().TxIn[0]

		return bytes.Equal(txIn.PreviousOutPoint.Hash[:], commitTxid[:])
	}

	// Check that all the inputs of this transaction are spending outputs
	// generated by Carol's breach transaction above.
	for _, txIn := range justiceTx.MsgTx().TxIn {
		if bytes.Equal(txIn.PreviousOutPoint.Hash[:], breachTXID[:]) {
			continue
		}

		// If the justice tx is spending from an output that was not on
		// the breach tx, Carol might have had the time to take an
		// output to the second level. In that case, check that the
		// justice tx is spending this second level output.
		if isSecondLevelSpend(breachTXID, &txIn.PreviousOutPoint.Hash) {
			continue
		}
		t.Fatalf("justice tx not spending commitment utxo "+
			"instead is: %v", txIn.PreviousOutPoint)
	}
	time.Sleep(100 * time.Millisecond)

	// We restart Dave here to ensure that he persists he retribution state
	// and successfully continues exacting retribution after restarting. At
	// this point, Dave has broadcast the justice transaction, but it
	// hasn't been confirmed yet; when Dave restarts, he should start
	// waiting for the justice transaction to confirm again.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("unable to restart Dave's node: %v", err)
	}

	// Now mine a block, this transaction should include Dave's justice
	// transaction which was just accepted into the mempool.
	block = mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, justiceTxid)

	// Dave should have no open channels.
	assertNodeNumChannels(t, dave, 0)
}

// testRevokedCloseRetributionAltruistWatchtower establishes a channel between
// Carol and Dave, where Carol is using a third node Willy as her watchtower.
// After sending some payments, Dave reverts his state and force closes to
// trigger a breach. Carol is kept offline throughout the process and the test
// asserts that Willy responds by broadcasting the justice transaction on
// Carol's behalf sweeping her funds without a reward.
func testRevokedCloseRetributionAltruistWatchtower(net *lntest.NetworkHarness,
	t *harnessTest) {

	testCases := []struct {
		name    string
		anchors bool
	}{{
		name:    "anchors",
		anchors: true,
	}, {
		name:    "legacy",
		anchors: false,
	}}

	for _, tc := range testCases {
		tc := tc

		success := t.t.Run(tc.name, func(tt *testing.T) {
			ht := newHarnessTest(tt, net)
			ht.RunTestCase(&testCase{
				name: tc.name,
				test: func(net1 *lntest.NetworkHarness, t1 *harnessTest) {
					testRevokedCloseRetributionAltruistWatchtowerCase(
						net1, t1, tc.anchors,
					)
				},
			})
		})

		if !success {
			// Log failure time to help relate the lnd logs to the
			// failure.
			t.Logf("Failure time: %v", time.Now().Format(
				"2006-01-02 15:04:05.000",
			))

			break
		}
	}
}

func testRevokedCloseRetributionAltruistWatchtowerCase(
	net *lntest.NetworkHarness, t *harnessTest, anchors bool) {

	ctxb := context.Background()
	const (
		chanAmt     = funding.MaxBtcFundingAmount
		paymentAmt  = 10000
		numInvoices = 6
		externalIP  = "1.2.3.4"
	)

	// Since we'd like to test some multi-hop failure scenarios, we'll
	// introduce another node into our test network: Carol.
	carolArgs := []string{"--hodl.exit-settle"}
	if anchors {
		carolArgs = append(carolArgs, "--protocol.anchors")
	}
	carol := net.NewNode(t.t, "Carol", carolArgs)
	defer shutdownAndAssert(net, t, carol)

	// Willy the watchtower will protect Dave from Carol's breach. He will
	// remain online in order to punish Carol on Dave's behalf, since the
	// breach will happen while Dave is offline.
	willy := net.NewNode(t.t, "Willy", []string{
		"--watchtower.active",
		"--watchtower.externalip=" + externalIP,
	})
	defer shutdownAndAssert(net, t, willy)

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	willyInfo, err := willy.Watchtower.GetInfo(
		ctxt, &watchtowerrpc.GetInfoRequest{},
	)
	if err != nil {
		t.Fatalf("unable to getinfo from willy: %v", err)
	}

	// Assert that Willy has one listener and it is 0.0.0.0:9911 or
	// [::]:9911. Since no listener is explicitly specified, one of these
	// should be the default depending on whether the host supports IPv6 or
	// not.
	if len(willyInfo.Listeners) != 1 {
		t.Fatalf("Willy should have 1 listener, has %d",
			len(willyInfo.Listeners))
	}
	listener := willyInfo.Listeners[0]
	if listener != "0.0.0.0:9911" && listener != "[::]:9911" {
		t.Fatalf("expected listener on 0.0.0.0:9911 or [::]:9911, "+
			"got %v", listener)
	}

	// Assert the Willy's URIs properly display the chosen external IP.
	if len(willyInfo.Uris) != 1 {
		t.Fatalf("Willy should have 1 uri, has %d",
			len(willyInfo.Uris))
	}
	if !strings.Contains(willyInfo.Uris[0], externalIP) {
		t.Fatalf("expected uri with %v, got %v",
			externalIP, willyInfo.Uris[0])
	}

	// Dave will be the breached party. We set --nolisten to ensure Carol
	// won't be able to connect to him and trigger the channel data
	// protection logic automatically.
	daveArgs := []string{
		"--nolisten",
		"--wtclient.active",
	}
	if anchors {
		daveArgs = append(daveArgs, "--protocol.anchors")
	}
	dave := net.NewNode(t.t, "Dave", daveArgs)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	addTowerReq := &wtclientrpc.AddTowerRequest{
		Pubkey:  willyInfo.Pubkey,
		Address: listener,
	}
	if _, err := dave.WatchtowerClient.AddTower(ctxt, addTowerReq); err != nil {
		t.Fatalf("unable to add willy's watchtower: %v", err)
	}

	// We must let Dave have an open channel before she can send a node
	// announcement, so we open a channel with Carol,
	net.ConnectNodes(ctxb, t.t, dave, carol)

	// Before we make a channel, we'll load up Dave with some coins sent
	// directly from the miner.
	net.SendCoins(ctxb, t.t, btcutil.SatoshiPerBitcoin, dave)

	// In order to test Dave's response to an uncooperative channel
	// closure by Carol, we'll first open up a channel between them with a
	// 0.5 BTC value.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, dave, carol,
		lntest.OpenChannelParams{
			Amt:     3 * (chanAmt / 4),
			PushAmt: chanAmt / 4,
		},
	)

	// With the channel open, we'll create a few invoices for Carol that
	// Dave will pay to in order to advance the state of the channel.
	carolPayReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Wait for Dave to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("dave didn't see the dave->carol channel before "+
			"timeout: %v", err)
	}

	// Next query for Carol's channel state, as we sent 0 payments, Carol
	// should still see her balance as the push amount, which is 1/4 of the
	// capacity.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolChan, err := getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol's channel info: %v", err)
	}
	if carolChan.LocalBalance != int64(chanAmt/4) {
		t.Fatalf("carol's balance is incorrect, got %v, expected %v",
			carolChan.LocalBalance, chanAmt/4)
	}

	// Grab Carol's current commitment height (update number), we'll later
	// revert her to this state after additional updates to force him to
	// broadcast this soon to be revoked state.
	carolStateNumPreCopy := carolChan.NumUpdates

	// With the temporary file created, copy Carol's current state into the
	// temporary file we created above. Later after more updates, we'll
	// restore this state.
	if err := net.BackupDb(carol); err != nil {
		t.Fatalf("unable to copy database files: %v", err)
	}

	// Finally, send payments from Dave to Carol, consuming Carol's remaining
	// payment hashes.
	err = completePaymentRequests(
		ctxb, dave, dave.RouterClient, carolPayReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	daveBalReq := &lnrpc.WalletBalanceRequest{}
	daveBalResp, err := dave.WalletBalance(ctxt, daveBalReq)
	if err != nil {
		t.Fatalf("unable to get dave's balance: %v", err)
	}

	davePreSweepBalance := daveBalResp.ConfirmedBalance

	// Wait until the backup has been accepted by the watchtower before
	// shutting down Dave.
	err = wait.NoError(func() error {
		ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
		defer cancel()
		bkpStats, err := dave.WatchtowerClient.Stats(ctxt,
			&wtclientrpc.StatsRequest{},
		)
		if err != nil {
			return err

		}
		if bkpStats == nil {
			return errors.New("no active backup sessions")
		}
		if bkpStats.NumBackups == 0 {
			return errors.New("no backups accepted")
		}

		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("unable to verify backup task completed: %v", err)
	}

	// Shutdown Dave to simulate going offline for an extended period of
	// time. Once he's not watching, Carol will try to breach the channel.
	restart, err := net.SuspendNode(dave)
	if err != nil {
		t.Fatalf("unable to suspend Dave: %v", err)
	}

	// Now we shutdown Carol, copying over the his temporary database state
	// which has the *prior* channel state over his current most up to date
	// state. With this, we essentially force Carol to travel back in time
	// within the channel's history.
	if err = net.RestartNode(carol, func() error {
		return net.RestoreDb(carol)
	}); err != nil {
		t.Fatalf("unable to restart node: %v", err)
	}

	// Now query for Carol's channel state, it should show that he's at a
	// state number in the past, not the *latest* state.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolChan, err = getChanInfo(ctxt, carol)
	if err != nil {
		t.Fatalf("unable to get carol chan info: %v", err)
	}
	if carolChan.NumUpdates != carolStateNumPreCopy {
		t.Fatalf("db copy failed: %v", carolChan.NumUpdates)
	}

	// Now force Carol to execute a *force* channel closure by unilaterally
	// broadcasting his current channel state. This is actually the
	// commitment transaction of a prior *revoked* state, so he'll soon
	// feel the wrath of Dave's retribution.
	closeUpdates, closeTxID, err := net.CloseChannel(
		ctxb, carol, chanPoint, true,
	)
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	// Query the mempool for the breaching closing transaction, this should
	// be broadcast by Carol when she force closes the channel above.
	txid, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Carol's force close tx in mempool: %v",
			err)
	}
	if *txid != *closeTxID {
		t.Fatalf("expected closeTx(%v) in mempool, instead found %v",
			closeTxID, txid)
	}

	// Finally, generate a single block, wait for the final close status
	// update, then ensure that the closing transaction was included in the
	// block.
	block := mineBlocks(t, net, 1, 1)[0]

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	breachTXID, err := net.WaitForChannelClose(ctxt, closeUpdates)
	if err != nil {
		t.Fatalf("error while waiting for channel close: %v", err)
	}
	assertTxInBlock(t, block, breachTXID)

	// Query the mempool for Dave's justice transaction, this should be
	// broadcast as Carol's contract breaching transaction gets confirmed
	// above.
	justiceTXID, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Dave's justice tx in mempool: %v",
			err)
	}
	time.Sleep(100 * time.Millisecond)

	// Query for the mempool transaction found above. Then assert that all
	// the inputs of this transaction are spending outputs generated by
	// Carol's breach transaction above.
	justiceTx, err := net.Miner.Client.GetRawTransaction(justiceTXID)
	if err != nil {
		t.Fatalf("unable to query for justice tx: %v", err)
	}
	for _, txIn := range justiceTx.MsgTx().TxIn {
		if !bytes.Equal(txIn.PreviousOutPoint.Hash[:], breachTXID[:]) {
			t.Fatalf("justice tx not spending commitment utxo "+
				"instead is: %v", txIn.PreviousOutPoint)
		}
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	willyBalReq := &lnrpc.WalletBalanceRequest{}
	willyBalResp, err := willy.WalletBalance(ctxt, willyBalReq)
	if err != nil {
		t.Fatalf("unable to get willy's balance: %v", err)
	}

	if willyBalResp.ConfirmedBalance != 0 {
		t.Fatalf("willy should have 0 balance before mining "+
			"justice transaction, instead has %d",
			willyBalResp.ConfirmedBalance)
	}

	// Now mine a block, this transaction should include Dave's justice
	// transaction which was just accepted into the mempool.
	block = mineBlocks(t, net, 1, 1)[0]

	// The block should have exactly *two* transactions, one of which is
	// the justice transaction.
	if len(block.Transactions) != 2 {
		t.Fatalf("transaction wasn't mined")
	}
	justiceSha := block.Transactions[1].TxHash()
	if !bytes.Equal(justiceTx.Hash()[:], justiceSha[:]) {
		t.Fatalf("justice tx wasn't mined")
	}

	// Ensure that Willy doesn't get any funds, as he is acting as an
	// altruist watchtower.
	var predErr error
	err = wait.Invariant(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		willyBalReq := &lnrpc.WalletBalanceRequest{}
		willyBalResp, err := willy.WalletBalance(ctxt, willyBalReq)
		if err != nil {
			t.Fatalf("unable to get willy's balance: %v", err)
		}

		if willyBalResp.ConfirmedBalance != 0 {
			predErr = fmt.Errorf("Expected Willy to have no funds "+
				"after justice transaction was mined, found %v",
				willyBalResp)
			return false
		}

		return true
	}, time.Second*5)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// Restart Dave, who will still think his channel with Carol is open.
	// We should him to detect the breach, but realize that the funds have
	// then been swept to his wallet by Willy.
	err = restart()
	if err != nil {
		t.Fatalf("unable to restart dave: %v", err)
	}

	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		daveBalReq := &lnrpc.ChannelBalanceRequest{}
		daveBalResp, err := dave.ChannelBalance(ctxt, daveBalReq)
		if err != nil {
			t.Fatalf("unable to get dave's balance: %v", err)
		}

		if daveBalResp.LocalBalance.Sat != 0 {
			predErr = fmt.Errorf("Dave should end up with zero "+
				"channel balance, instead has %d",
				daveBalResp.LocalBalance.Sat)
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	assertNumPendingChannels(t, dave, 0, 0)

	err = wait.Predicate(func() bool {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		daveBalReq := &lnrpc.WalletBalanceRequest{}
		daveBalResp, err := dave.WalletBalance(ctxt, daveBalReq)
		if err != nil {
			t.Fatalf("unable to get dave's balance: %v", err)
		}

		if daveBalResp.ConfirmedBalance <= davePreSweepBalance {
			predErr = fmt.Errorf("Dave should have more than %d "+
				"after sweep, instead has %d",
				davePreSweepBalance,
				daveBalResp.ConfirmedBalance)
			return false
		}

		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// Dave should have no open channels.
	assertNodeNumChannels(t, dave, 0)
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
			predErr = fmt.Errorf("Expected to find %d channels "+
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
	if err != nil {
		t.Fatalf("%v", predErr)
	}
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
	if err != nil {
		t.Fatalf("unable to find Carol's force close tx in mempool: %v",
			err)
	}

	// Channel should be in the state "waiting close" for Carol since she
	// broadcasted the force close tx.
	assertNumPendingChannels(t, carol, 1, 0)

	// Dave should also consider the channel "waiting close", as he noticed
	// the channel was out of sync, and is now waiting for a force close to
	// hit the chain.
	assertNumPendingChannels(t, dave, 1, 0)

	// Restart Dave to make sure he is able to sweep the funds after
	// shutdown.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Generate a single block, which should confirm the closing tx.
	_ = mineBlocks(t, net, 1, expectedTxes)[0]

	// Dave should sweep his funds immediately, as they are not timelocked.
	// We also expect Dave to sweep his anchor, if present.

	_, err = waitForNTxsInMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("unable to find Dave's sweep tx in mempool: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unable to get dave's balance: %v", err)
	}

	daveBalance := daveBalResp.ConfirmedBalance
	if daveBalance <= daveStartingBalance {
		t.Fatalf("expected dave to have balance above %d, "+
			"instead had %v", daveStartingBalance, daveBalance)
	}

	// After the Carol's output matures, she should also reclaim her funds.
	//
	// The commit sweep resolver publishes the sweep tx at defaultCSV-1 and
	// we already mined one block after the commitmment was published, so
	// take that into account.
	mineBlocks(t, net, defaultCSV-1-1, 0)
	carolSweep, err := waitForTxInMempool(
		net.Miner.Client, minerMempoolTimeout,
	)
	if err != nil {
		t.Fatalf("unable to find Carol's sweep tx in mempool: %v", err)
	}
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
	if err != nil {
		t.Fatalf(err.Error())
	}

	assertNodeNumChannels(t, dave, 0)
	assertNodeNumChannels(t, carol, 0)
}

// testDataLossProtection tests that if one of the nodes in a channel
// relationship lost state, they will detect this during channel sync, and the
// up-to-date party will force close the channel, giving the outdated party the
// opportunity to sweep its output.
func testDataLossProtection(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()
	const (
		chanAmt     = funding.MaxBtcFundingAmount
		paymentAmt  = 10000
		numInvoices = 6
	)

	// Carol will be the up-to-date party. We set --nolisten to ensure Dave
	// won't be able to connect to her and trigger the channel data
	// protection logic automatically. We also can't have Carol
	// automatically re-connect too early, otherwise DLP would be initiated
	// at the wrong moment.
	carol := net.NewNode(
		t.t, "Carol", []string{"--nolisten", "--minbackoff=1h"},
	)
	defer shutdownAndAssert(net, t, carol)

	// Dave will be the party losing his state.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	// Before we make a channel, we'll load up Carol with some coins sent
	// directly from the miner.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	// timeTravel is a method that will make Carol open a channel to the
	// passed node, settle a series of payments, then reset the node back
	// to the state before the payments happened. When this method returns
	// the node will be unaware of the new state updates. The returned
	// function can be used to restart the node in this state.
	timeTravel := func(node *lntest.HarnessNode) (func() error,
		*lnrpc.ChannelPoint, int64, error) {

		// We must let the node communicate with Carol before they are
		// able to open channel, so we connect them.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		net.EnsureConnected(ctxt, t.t, carol, node)

		// We'll first open up a channel between them with a 0.5 BTC
		// value.
		ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
		chanPoint := openChannelAndAssert(
			ctxt, t, net, carol, node,
			lntest.OpenChannelParams{
				Amt: chanAmt,
			},
		)

		// With the channel open, we'll create a few invoices for the
		// node that Carol will pay to in order to advance the state of
		// the channel.
		// TODO(halseth): have dangling HTLCs on the commitment, able to
		// retrieve funds?
		payReqs, _, _, err := createPayReqs(
			node, paymentAmt, numInvoices,
		)
		if err != nil {
			t.Fatalf("unable to create pay reqs: %v", err)
		}

		// Wait for Carol to receive the channel edge from the funding
		// manager.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
		if err != nil {
			t.Fatalf("carol didn't see the carol->%s channel "+
				"before timeout: %v", node.Name(), err)
		}

		// Send payments from Carol using 3 of the payment hashes
		// generated above.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = completePaymentRequests(
			ctxt, carol, carol.RouterClient,
			payReqs[:numInvoices/2], true,
		)
		if err != nil {
			t.Fatalf("unable to send payments: %v", err)
		}

		// Next query for the node's channel state, as we sent 3
		// payments of 10k satoshis each, it should now see his balance
		// as being 30k satoshis.
		var nodeChan *lnrpc.Channel
		var predErr error
		err = wait.Predicate(func() bool {
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			bChan, err := getChanInfo(ctxt, node)
			if err != nil {
				t.Fatalf("unable to get channel info: %v", err)
			}
			if bChan.LocalBalance != 30000 {
				predErr = fmt.Errorf("balance is incorrect, "+
					"got %v, expected %v",
					bChan.LocalBalance, 30000)
				return false
			}

			nodeChan = bChan
			return true
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("%v", predErr)
		}

		// Grab the current commitment height (update number), we'll
		// later revert him to this state after additional updates to
		// revoke this state.
		stateNumPreCopy := nodeChan.NumUpdates

		// With the temporary file created, copy the current state into
		// the temporary file we created above. Later after more
		// updates, we'll restore this state.
		if err := net.BackupDb(node); err != nil {
			t.Fatalf("unable to copy database files: %v", err)
		}

		// Finally, send more payments from , using the remaining
		// payment hashes.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = completePaymentRequests(
			ctxt, carol, carol.RouterClient,
			payReqs[numInvoices/2:], true,
		)
		if err != nil {
			t.Fatalf("unable to send payments: %v", err)
		}

		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		nodeChan, err = getChanInfo(ctxt, node)
		if err != nil {
			t.Fatalf("unable to get dave chan info: %v", err)
		}

		// Now we shutdown the node, copying over the its temporary
		// database state which has the *prior* channel state over his
		// current most up to date state. With this, we essentially
		// force the node to travel back in time within the channel's
		// history.
		if err = net.RestartNode(node, func() error {
			return net.RestoreDb(node)
		}); err != nil {
			t.Fatalf("unable to restart node: %v", err)
		}

		// Make sure the channel is still there from the PoV of the
		// node.
		assertNodeNumChannels(t, node, 1)

		// Now query for the channel state, it should show that it's at
		// a state number in the past, not the *latest* state.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		nodeChan, err = getChanInfo(ctxt, node)
		if err != nil {
			t.Fatalf("unable to get dave chan info: %v", err)
		}
		if nodeChan.NumUpdates != stateNumPreCopy {
			t.Fatalf("db copy failed: %v", nodeChan.NumUpdates)
		}

		balReq := &lnrpc.WalletBalanceRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		balResp, err := node.WalletBalance(ctxt, balReq)
		if err != nil {
			t.Fatalf("unable to get dave's balance: %v", err)
		}

		restart, err := net.SuspendNode(node)
		if err != nil {
			t.Fatalf("unable to suspend node: %v", err)
		}

		return restart, chanPoint, balResp.ConfirmedBalance, nil
	}

	// Reset Dave to a state where he has an outdated channel state.
	restartDave, _, daveStartingBalance, err := timeTravel(dave)
	if err != nil {
		t.Fatalf("unable to time travel dave: %v", err)
	}

	// We make a note of the nodes' current on-chain balances, to make sure
	// they are able to retrieve the channel funds eventually,
	balReq := &lnrpc.WalletBalanceRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalResp, err := carol.WalletBalance(ctxt, balReq)
	if err != nil {
		t.Fatalf("unable to get carol's balance: %v", err)
	}
	carolStartingBalance := carolBalResp.ConfirmedBalance

	// Restart Dave to trigger a channel resync.
	if err := restartDave(); err != nil {
		t.Fatalf("unable to restart dave: %v", err)
	}

	// Assert that once Dave comes up, they reconnect, Carol force closes
	// on chain, and both of them properly carry out the DLP protocol.
	assertDLPExecuted(
		net, t, carol, carolStartingBalance, dave, daveStartingBalance,
		false,
	)

	// As a second part of this test, we will test the scenario where a
	// channel is closed while Dave is offline, loses his state and comes
	// back online. In this case the node should attempt to resync the
	// channel, and the peer should resend a channel sync message for the
	// closed channel, such that Dave can retrieve his funds.
	//
	// We start by letting Dave time travel back to an outdated state.
	restartDave, chanPoint2, daveStartingBalance, err := timeTravel(dave)
	if err != nil {
		t.Fatalf("unable to time travel eve: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalResp, err = carol.WalletBalance(ctxt, balReq)
	if err != nil {
		t.Fatalf("unable to get carol's balance: %v", err)
	}
	carolStartingBalance = carolBalResp.ConfirmedBalance

	// Now let Carol force close the channel while Dave is offline.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPoint2, true)

	// Wait for the channel to be marked pending force close.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForChannelPendingForceClose(ctxt, carol, chanPoint2)
	if err != nil {
		t.Fatalf("channel not pending force close: %v", err)
	}

	// Mine enough blocks for Carol to sweep her funds.
	mineBlocks(t, net, defaultCSV-1, 0)

	carolSweep, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Carol's sweep tx in mempool: %v", err)
	}
	block := mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, carolSweep)

	// Now the channel should be fully closed also from Carol's POV.
	assertNumPendingChannels(t, carol, 0, 0)

	// Make sure Carol got her balance back.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalResp, err = carol.WalletBalance(ctxt, balReq)
	if err != nil {
		t.Fatalf("unable to get carol's balance: %v", err)
	}
	carolBalance := carolBalResp.ConfirmedBalance
	if carolBalance <= carolStartingBalance {
		t.Fatalf("expected carol to have balance above %d, "+
			"instead had %v", carolStartingBalance,
			carolBalance)
	}

	assertNodeNumChannels(t, carol, 0)

	// When Dave comes online, he will reconnect to Carol, try to resync
	// the channel, but it will already be closed. Carol should resend the
	// information Dave needs to sweep his funds.
	if err := restartDave(); err != nil {
		t.Fatalf("unable to restart Eve: %v", err)
	}

	// Dave should sweep his funds.
	_, err = waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("unable to find Dave's sweep tx in mempool: %v", err)
	}

	// Mine a block to confirm the sweep, and make sure Dave got his
	// balance back.
	mineBlocks(t, net, 1, 1)
	assertNodeNumChannels(t, dave, 0)

	err = wait.NoError(func() error {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		daveBalResp, err := dave.WalletBalance(ctxt, balReq)
		if err != nil {
			return fmt.Errorf("unable to get dave's balance: %v",
				err)
		}

		daveBalance := daveBalResp.ConfirmedBalance
		if daveBalance <= daveStartingBalance {
			return fmt.Errorf("expected dave to have balance "+
				"above %d, intead had %v", daveStartingBalance,
				daveBalance)
		}

		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", err)
	}
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

	if err := wait.Predicate(pred, defaultTimeout); err != nil {
		t.Fatalf("node has incorrect number of channels: %v", predErr)
	}
}

// testRejectHTLC tests that a node can be created with the flag --rejecthtlc.
// This means that the node will reject all forwarded HTLCs but can still
// accept direct HTLCs as well as send HTLCs.
func testRejectHTLC(net *lntest.NetworkHarness, t *harnessTest) {
	//             RejectHTLC
	// Alice ------> Carol ------> Bob
	//
	const chanAmt = btcutil.Amount(1000000)
	ctxb := context.Background()

	// Create Carol with reject htlc flag.
	carol := net.NewNode(t.t, "Carol", []string{"--rejecthtlc"})
	defer shutdownAndAssert(net, t, carol)

	// Connect Alice to Carol.
	net.ConnectNodes(ctxb, t.t, net.Alice, carol)

	// Connect Carol to Bob.
	net.ConnectNodes(ctxb, t.t, carol, net.Bob)

	// Send coins to Carol.
	net.SendCoins(ctxb, t.t, btcutil.SatoshiPerBitcoin, carol)

	// Send coins to Alice.
	net.SendCoins(ctxb, t.t, btcutil.SatoshiPerBitcent, net.Alice)

	// Open a channel between Alice and Carol.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Open a channel between Carol and Bob.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Channel should be ready for payments.
	const payAmt = 100

	// Helper closure to generate a random pre image.
	genPreImage := func() []byte {
		preimage := make([]byte, 32)

		_, err := rand.Read(preimage)
		if err != nil {
			t.Fatalf("unable to generate preimage: %v", err)
		}

		return preimage
	}

	// Create an invoice from Carol of 100 satoshis.
	// We expect Alice to be able to pay this invoice.
	preimage := genPreImage()

	carolInvoice := &lnrpc.Invoice{
		Memo:      "testing - alice should pay carol",
		RPreimage: preimage,
		Value:     payAmt,
	}

	// Carol adds the invoice to her database.
	resp, err := carol.AddInvoice(ctxb, carolInvoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	// Alice pays Carols invoice.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient,
		[]string{resp.PaymentRequest}, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments from alice to carol: %v", err)
	}

	// Create an invoice from Bob of 100 satoshis.
	// We expect Carol to be able to pay this invoice.
	preimage = genPreImage()

	bobInvoice := &lnrpc.Invoice{
		Memo:      "testing - carol should pay bob",
		RPreimage: preimage,
		Value:     payAmt,
	}

	// Bob adds the invoice to his database.
	resp, err = net.Bob.AddInvoice(ctxb, bobInvoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	// Carol pays Bobs invoice.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient,
		[]string{resp.PaymentRequest}, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments from carol to bob: %v", err)
	}

	// Create an invoice from Bob of 100 satoshis.
	// Alice attempts to pay Bob but this should fail, since we are
	// using Carol as a hop and her node will reject onward HTLCs.
	preimage = genPreImage()

	bobInvoice = &lnrpc.Invoice{
		Memo:      "testing - alice tries to pay bob",
		RPreimage: preimage,
		Value:     payAmt,
	}

	// Bob adds the invoice to his database.
	resp, err = net.Bob.AddInvoice(ctxb, bobInvoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	// Alice attempts to pay Bobs invoice. This payment should be rejected since
	// we are using Carol as an intermediary hop, Carol is running lnd with
	// --rejecthtlc.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient,
		[]string{resp.PaymentRequest}, true,
	)
	if err == nil {
		t.Fatalf(
			"should have been rejected, carol will not accept forwarded htlcs",
		)
	}

	assertLastHTLCError(t, net.Alice, lnrpc.Failure_CHANNEL_DISABLED)

	// Close all channels.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
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
	if err != nil {
		t.Fatalf("unable to create topology client: %v", err)
	}

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

func testGraphTopologyNotifications(net *lntest.NetworkHarness, t *harnessTest) {
	t.t.Run("pinned", func(t *testing.T) {
		ht := newHarnessTest(t, net)
		testGraphTopologyNtfns(net, ht, true)
	})
	t.t.Run("unpinned", func(t *testing.T) {
		ht := newHarnessTest(t, net)
		testGraphTopologyNtfns(net, ht, false)
	})
}

func testGraphTopologyNtfns(net *lntest.NetworkHarness, t *harnessTest, pinned bool) {
	ctxb := context.Background()

	const chanAmt = funding.MaxBtcFundingAmount

	// Spin up Bob first, since we will need to grab his pubkey when
	// starting Alice to test pinned syncing.
	bob := net.NewNode(t.t, "bob", nil)
	defer shutdownAndAssert(net, t, bob)

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	bobInfo, err := bob.GetInfo(ctxt, &lnrpc.GetInfoRequest{})
	require.NoError(t.t, err)
	bobPubkey := bobInfo.IdentityPubkey

	// For unpinned syncing, start Alice as usual. Otherwise grab Bob's
	// pubkey to include in his pinned syncer set.
	var aliceArgs []string
	if pinned {
		aliceArgs = []string{
			"--numgraphsyncpeers=0",
			fmt.Sprintf("--gossip.pinned-syncers=%s", bobPubkey),
		}
	}

	alice := net.NewNode(t.t, "alice", aliceArgs)
	defer shutdownAndAssert(net, t, alice)

	// Connect Alice and Bob.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, alice, bob)

	// Alice stimmy.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, alice)

	// Bob stimmy.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, bob)

	// Assert that Bob has the correct sync type before proceeeding.
	if pinned {
		assertSyncType(t, alice, bobPubkey, lnrpc.Peer_PINNED_SYNC)
	} else {
		assertSyncType(t, alice, bobPubkey, lnrpc.Peer_ACTIVE_SYNC)
	}

	// Regardless of syncer type, ensure that both peers report having
	// completed their initial sync before continuing to make a channel.
	waitForGraphSync(t, alice)

	// Let Alice subscribe to graph notifications.
	graphSub := subscribeGraphNotifications(ctxb, t, alice)
	defer close(graphSub.quit)

	// Open a new channel between Alice and Bob.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, alice, bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// The channel opening above should have triggered a few notifications
	// sent to the notification client. We'll expect two channel updates,
	// and two node announcements.
	var numChannelUpds int
	var numNodeAnns int
	for numChannelUpds < 2 && numNodeAnns < 2 {
		select {
		// Ensure that a new update for both created edges is properly
		// dispatched to our registered client.
		case graphUpdate := <-graphSub.updateChan:
			// Process all channel updates prsented in this update
			// message.
			for _, chanUpdate := range graphUpdate.ChannelUpdates {
				switch chanUpdate.AdvertisingNode {
				case alice.PubKeyStr:
				case bob.PubKeyStr:
				default:
					t.Fatalf("unknown advertising node: %v",
						chanUpdate.AdvertisingNode)
				}
				switch chanUpdate.ConnectingNode {
				case alice.PubKeyStr:
				case bob.PubKeyStr:
				default:
					t.Fatalf("unknown connecting node: %v",
						chanUpdate.ConnectingNode)
				}

				if chanUpdate.Capacity != int64(chanAmt) {
					t.Fatalf("channel capacities mismatch:"+
						" expected %v, got %v", chanAmt,
						btcutil.Amount(chanUpdate.Capacity))
				}
				numChannelUpds++
			}

			for _, nodeUpdate := range graphUpdate.NodeUpdates {
				switch nodeUpdate.IdentityKey {
				case alice.PubKeyStr:
				case bob.PubKeyStr:
				default:
					t.Fatalf("unknown node: %v",
						nodeUpdate.IdentityKey)
				}
				numNodeAnns++
			}
		case err := <-graphSub.errChan:
			t.Fatalf("unable to recv graph update: %v", err)
		case <-time.After(time.Second * 10):
			t.Fatalf("timeout waiting for graph notifications, "+
				"only received %d/2 chanupds and %d/2 nodeanns",
				numChannelUpds, numNodeAnns)
		}
	}

	_, blockHeight, err := net.Miner.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get current blockheight %v", err)
	}

	// Now we'll test that updates are properly sent after channels are closed
	// within the network.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, alice, chanPoint, false)

	// Now that the channel has been closed, we should receive a
	// notification indicating so.
out:
	for {
		select {
		case graphUpdate := <-graphSub.updateChan:
			if len(graphUpdate.ClosedChans) != 1 {
				continue
			}

			closedChan := graphUpdate.ClosedChans[0]
			if closedChan.ClosedHeight != uint32(blockHeight+1) {
				t.Fatalf("close heights of channel mismatch: "+
					"expected %v, got %v", blockHeight+1,
					closedChan.ClosedHeight)
			}
			chanPointTxid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			closedChanTxid, err := lnrpc.GetChanPointFundingTxid(
				closedChan.ChanPoint,
			)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			if !bytes.Equal(closedChanTxid[:], chanPointTxid[:]) {
				t.Fatalf("channel point hash mismatch: "+
					"expected %v, got %v", chanPointTxid,
					closedChanTxid)
			}
			if closedChan.ChanPoint.OutputIndex != chanPoint.OutputIndex {
				t.Fatalf("output index mismatch: expected %v, "+
					"got %v", chanPoint.OutputIndex,
					closedChan.ChanPoint)
			}

			break out

		case err := <-graphSub.errChan:
			t.Fatalf("unable to recv graph update: %v", err)
		case <-time.After(time.Second * 10):
			t.Fatalf("notification for channel closure not " +
				"sent")
		}
	}

	// For the final portion of the test, we'll ensure that once a new node
	// appears in the network, the proper notification is dispatched. Note
	// that a node that does not have any channels open is ignored, so first
	// we disconnect Alice and Bob, open a channel between Bob and Carol,
	// and finally connect Alice to Bob again.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, alice, bob); err != nil {
		t.Fatalf("unable to disconnect alice and bob: %v", err)
	}
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, bob, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint = openChannelAndAssert(
		ctxt, t, net, bob, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Reconnect Alice and Bob. This should result in the nodes syncing up
	// their respective graph state, with the new addition being the
	// existence of Carol in the graph, and also the channel between Bob
	// and Carol. Note that we will also receive a node announcement from
	// Bob, since a node will update its node announcement after a new
	// channel is opened.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, alice, bob)

	// We should receive an update advertising the newly connected node,
	// Bob's new node announcement, and the channel between Bob and Carol.
	numNodeAnns = 0
	numChannelUpds = 0
	for numChannelUpds < 2 && numNodeAnns < 1 {
		select {
		case graphUpdate := <-graphSub.updateChan:
			for _, nodeUpdate := range graphUpdate.NodeUpdates {
				switch nodeUpdate.IdentityKey {
				case carol.PubKeyStr:
				case bob.PubKeyStr:
				default:
					t.Fatalf("unknown node update pubey: %v",
						nodeUpdate.IdentityKey)
				}
				numNodeAnns++
			}

			for _, chanUpdate := range graphUpdate.ChannelUpdates {
				switch chanUpdate.AdvertisingNode {
				case carol.PubKeyStr:
				case bob.PubKeyStr:
				default:
					t.Fatalf("unknown advertising node: %v",
						chanUpdate.AdvertisingNode)
				}
				switch chanUpdate.ConnectingNode {
				case carol.PubKeyStr:
				case bob.PubKeyStr:
				default:
					t.Fatalf("unknown connecting node: %v",
						chanUpdate.ConnectingNode)
				}

				if chanUpdate.Capacity != int64(chanAmt) {
					t.Fatalf("channel capacities mismatch:"+
						" expected %v, got %v", chanAmt,
						btcutil.Amount(chanUpdate.Capacity))
				}
				numChannelUpds++
			}
		case err := <-graphSub.errChan:
			t.Fatalf("unable to recv graph update: %v", err)
		case <-time.After(time.Second * 10):
			t.Fatalf("timeout waiting for graph notifications, "+
				"only received %d/2 chanupds and %d/2 nodeanns",
				numChannelUpds, numNodeAnns)
		}
	}

	// Close the channel between Bob and Carol.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, bob, chanPoint, false)
}

// testNodeAnnouncement ensures that when a node is started with one or more
// external IP addresses specified on the command line, that those addresses
// announced to the network and reported in the network graph.
func testNodeAnnouncement(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	aliceSub := subscribeGraphNotifications(ctxb, t, net.Alice)
	defer close(aliceSub.quit)

	advertisedAddrs := []string{
		"192.168.1.1:8333",
		"[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8337",
		"bkb6azqggsaiskzi.onion:9735",
		"fomvuglh6h6vcag73xo5t5gv56ombih3zr2xvplkpbfd7wrog4swjwid.onion:1234",
	}

	var lndArgs []string
	for _, addr := range advertisedAddrs {
		lndArgs = append(lndArgs, "--externalip="+addr)
	}

	dave := net.NewNode(t.t, "Dave", lndArgs)
	defer shutdownAndAssert(net, t, dave)

	// We must let Dave have an open channel before he can send a node
	// announcement, so we open a channel with Bob,
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Bob, dave)

	// Alice shouldn't receive any new updates yet since the channel has yet
	// to be opened.
	select {
	case <-aliceSub.updateChan:
		t.Fatalf("received unexpected update from dave")
	case <-time.After(time.Second):
	}

	// We'll then go ahead and open a channel between Bob and Dave. This
	// ensures that Alice receives the node announcement from Bob as part of
	// the announcement broadcast.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Bob, dave,
		lntest.OpenChannelParams{
			Amt: 1000000,
		},
	)

	assertAddrs := func(addrsFound []string, targetAddrs ...string) {
		addrs := make(map[string]struct{}, len(addrsFound))
		for _, addr := range addrsFound {
			addrs[addr] = struct{}{}
		}

		for _, addr := range targetAddrs {
			if _, ok := addrs[addr]; !ok {
				t.Fatalf("address %v not found in node "+
					"announcement", addr)
			}
		}
	}

	waitForAddrsInUpdate := func(graphSub graphSubscription,
		nodePubKey string, targetAddrs ...string) {

		for {
			select {
			case graphUpdate := <-graphSub.updateChan:
				for _, update := range graphUpdate.NodeUpdates {
					if update.IdentityKey == nodePubKey {
						assertAddrs(
							update.Addresses, // nolint:staticcheck
							targetAddrs...,
						)
						return
					}
				}
			case err := <-graphSub.errChan:
				t.Fatalf("unable to recv graph update: %v", err)
			case <-time.After(defaultTimeout):
				t.Fatalf("did not receive node ann update")
			}
		}
	}

	// We'll then wait for Alice to receive Dave's node announcement
	// including the expected advertised addresses from Bob since they
	// should already be connected.
	waitForAddrsInUpdate(
		aliceSub, dave.PubKeyStr, advertisedAddrs...,
	)

	// Close the channel between Bob and Dave.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPoint, false)
}

func testNodeSignVerify(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	chanAmt := funding.MaxBtcFundingAmount
	pushAmt := btcutil.Amount(100000)

	// Create a channel between alice and bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	aliceBobCh := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)

	aliceMsg := []byte("alice msg")

	// alice signs "alice msg" and sends her signature to bob.
	sigReq := &lnrpc.SignMessageRequest{Msg: aliceMsg}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	sigResp, err := net.Alice.SignMessage(ctxt, sigReq)
	if err != nil {
		t.Fatalf("SignMessage rpc call failed: %v", err)
	}
	aliceSig := sigResp.Signature

	// bob verifying alice's signature should succeed since alice and bob are
	// connected.
	verifyReq := &lnrpc.VerifyMessageRequest{Msg: aliceMsg, Signature: aliceSig}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	verifyResp, err := net.Bob.VerifyMessage(ctxt, verifyReq)
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("alice's signature didn't validate")
	}
	if verifyResp.Pubkey != net.Alice.PubKeyStr {
		t.Fatalf("alice's signature doesn't contain alice's pubkey.")
	}

	// carol is a new node that is unconnected to alice or bob.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	carolMsg := []byte("carol msg")

	// carol signs "carol msg" and sends her signature to bob.
	sigReq = &lnrpc.SignMessageRequest{Msg: carolMsg}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	sigResp, err = carol.SignMessage(ctxt, sigReq)
	if err != nil {
		t.Fatalf("SignMessage rpc call failed: %v", err)
	}
	carolSig := sigResp.Signature

	// bob verifying carol's signature should fail since they are not connected.
	verifyReq = &lnrpc.VerifyMessageRequest{Msg: carolMsg, Signature: carolSig}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	verifyResp, err = net.Bob.VerifyMessage(ctxt, verifyReq)
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if verifyResp.Valid {
		t.Fatalf("carol's signature should not be valid")
	}
	if verifyResp.Pubkey != carol.PubKeyStr {
		t.Fatalf("carol's signature doesn't contain her pubkey")
	}

	// Close the channel between alice and bob.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, aliceBobCh, false)
}

// testAsyncPayments tests the performance of the async payments.
func testAsyncPayments(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		paymentAmt = 100
	)

	// First establish a channel with a capacity equals to the overall
	// amount of payments, between Alice and Bob, at the end of the test
	// Alice should send all money from her side to Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	channelCapacity := btcutil.Amount(paymentAmt * 2000)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: channelCapacity,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	info, err := getChanInfo(ctxt, net.Alice)
	if err != nil {
		t.Fatalf("unable to get alice channel info: %v", err)
	}

	// We'll create a number of invoices equal the max number of HTLCs that
	// can be carried in one direction. The number on the commitment will
	// likely be lower, but we can't guarantee that any more HTLCs will
	// succeed due to the limited path diversity and inability of the router
	// to retry via another path.
	numInvoices := int(input.MaxHTLCNumber / 2)

	bobAmt := int64(numInvoices * paymentAmt)
	aliceAmt := info.LocalBalance - bobAmt

	// With the channel open, we'll create invoices for Bob that Alice
	// will pay to in order to advance the state of the channel.
	bobPayReqs, _, _, err := createPayReqs(
		net.Bob, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Wait for Alice to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't see the alice->bob channel before "+
			"timeout: %v", err)
	}

	// Simultaneously send payments from Alice to Bob using of Bob's payment
	// hashes generated above.
	now := time.Now()
	errChan := make(chan error)
	statusChan := make(chan *lnrpc.Payment)
	for i := 0; i < numInvoices; i++ {
		payReq := bobPayReqs[i]
		go func() {
			ctxt, _ = context.WithTimeout(ctxb, lntest.AsyncBenchmarkTimeout)
			stream, err := net.Alice.RouterClient.SendPaymentV2(
				ctxt,
				&routerrpc.SendPaymentRequest{
					PaymentRequest: payReq,
					TimeoutSeconds: 60,
					FeeLimitMsat:   noFeeLimitMsat,
				},
			)
			if err != nil {
				errChan <- err
			}
			result, err := getPaymentResult(stream)
			if err != nil {
				errChan <- err
			}

			statusChan <- result
		}()
	}

	// Wait until all the payments have settled.
	for i := 0; i < numInvoices; i++ {
		select {
		case result := <-statusChan:
			if result.Status == lnrpc.Payment_SUCCEEDED {
				continue
			}

		case err := <-errChan:
			t.Fatalf("payment error: %v", err)
		}
	}

	// All payments have been sent, mark the finish time.
	timeTaken := time.Since(now)

	// Next query for Bob's and Alice's channel states, in order to confirm
	// that all payment have been successful transmitted.

	// Wait for the revocation to be received so alice no longer has pending
	// htlcs listed and has correct balances. This is needed due to the fact
	// that we now pipeline the settles.
	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		aliceChan, err := getChanInfo(ctxt, net.Alice)
		if err != nil {
			return false
		}
		if len(aliceChan.PendingHtlcs) != 0 {
			return false
		}
		if aliceChan.RemoteBalance != bobAmt {
			return false
		}
		if aliceChan.LocalBalance != aliceAmt {
			return false
		}

		return true
	}, time.Second*5)
	if err != nil {
		t.Fatalf("failed to assert alice's pending htlcs and/or remote/local balance")
	}

	// Wait for Bob to receive revocation from Alice.
	time.Sleep(2 * time.Second)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	bobChan, err := getChanInfo(ctxt, net.Bob)
	if err != nil {
		t.Fatalf("unable to get bob's channel info: %v", err)
	}
	if len(bobChan.PendingHtlcs) != 0 {
		t.Fatalf("bob's pending htlcs is incorrect, got %v, "+
			"expected %v", len(bobChan.PendingHtlcs), 0)
	}
	if bobChan.LocalBalance != bobAmt {
		t.Fatalf("bob's local balance is incorrect, got %v, expected"+
			" %v", bobChan.LocalBalance, bobAmt)
	}
	if bobChan.RemoteBalance != aliceAmt {
		t.Fatalf("bob's remote balance is incorrect, got %v, "+
			"expected %v", bobChan.RemoteBalance, aliceAmt)
	}

	t.Log("\tBenchmark info: Elapsed time: ", timeTaken)
	t.Log("\tBenchmark info: TPS: ", float64(numInvoices)/timeTaken.Seconds())

	// Finally, immediately close the channel. This function will also
	// block until the channel is closed and will additionally assert the
	// relevant channel closing post conditions.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
}

// testBidirectionalAsyncPayments tests that nodes are able to send the
// payments to each other in async manner without blocking.
func testBidirectionalAsyncPayments(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		paymentAmt = 1000
	)

	// First establish a channel with a capacity equals to the overall
	// amount of payments, between Alice and Bob, at the end of the test
	// Alice should send all money from her side to Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     paymentAmt * 2000,
			PushAmt: paymentAmt * 1000,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	info, err := getChanInfo(ctxt, net.Alice)
	if err != nil {
		t.Fatalf("unable to get alice channel info: %v", err)
	}

	// We'll create a number of invoices equal the max number of HTLCs that
	// can be carried in one direction. The number on the commitment will
	// likely be lower, but we can't guarantee that any more HTLCs will
	// succeed due to the limited path diversity and inability of the router
	// to retry via another path.
	numInvoices := int(input.MaxHTLCNumber / 2)

	// Nodes should exchange the same amount of money and because of this
	// at the end balances should remain the same.
	aliceAmt := info.LocalBalance
	bobAmt := info.RemoteBalance

	// With the channel open, we'll create invoices for Bob that Alice
	// will pay to in order to advance the state of the channel.
	bobPayReqs, _, _, err := createPayReqs(
		net.Bob, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// With the channel open, we'll create invoices for Alice that Bob
	// will pay to in order to advance the state of the channel.
	alicePayReqs, _, _, err := createPayReqs(
		net.Alice, paymentAmt, numInvoices,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Wait for Alice to receive the channel edge from the funding manager.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint); err != nil {
		t.Fatalf("alice didn't see the alice->bob channel before "+
			"timeout: %v", err)
	}
	if err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint); err != nil {
		t.Fatalf("bob didn't see the bob->alice channel before "+
			"timeout: %v", err)
	}

	// Reset mission control to prevent previous payment results from
	// interfering with this test. A new channel has been opened, but
	// mission control operates on node pairs.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.RouterClient.ResetMissionControl(
		ctxt, &routerrpc.ResetMissionControlRequest{},
	)
	if err != nil {
		t.Fatalf("unable to reset mc for alice: %v", err)
	}

	// Send payments from Alice to Bob and from Bob to Alice in async
	// manner.
	errChan := make(chan error)
	statusChan := make(chan *lnrpc.Payment)

	send := func(node *lntest.HarnessNode, payReq string) {
		go func() {
			ctxt, _ = context.WithTimeout(
				ctxb, lntest.AsyncBenchmarkTimeout,
			)
			stream, err := node.RouterClient.SendPaymentV2(
				ctxt,
				&routerrpc.SendPaymentRequest{
					PaymentRequest: payReq,
					TimeoutSeconds: 60,
					FeeLimitMsat:   noFeeLimitMsat,
				},
			)
			if err != nil {
				errChan <- err
			}
			result, err := getPaymentResult(stream)
			if err != nil {
				errChan <- err
			}

			statusChan <- result
		}()
	}

	for i := 0; i < numInvoices; i++ {
		send(net.Bob, alicePayReqs[i])
		send(net.Alice, bobPayReqs[i])
	}

	// Expect all payments to succeed.
	for i := 0; i < 2*numInvoices; i++ {
		select {
		case result := <-statusChan:
			if result.Status != lnrpc.Payment_SUCCEEDED {
				t.Fatalf("payment error: %v", result.Status)
			}

		case err := <-errChan:
			t.Fatalf("payment error: %v", err)
		}
	}

	// Wait for Alice and Bob to receive revocations messages, and update
	// states, i.e. balance info.
	time.Sleep(1 * time.Second)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceInfo, err := getChanInfo(ctxt, net.Alice)
	if err != nil {
		t.Fatalf("unable to get bob's channel info: %v", err)
	}
	if aliceInfo.RemoteBalance != bobAmt {
		t.Fatalf("alice's remote balance is incorrect, got %v, "+
			"expected %v", aliceInfo.RemoteBalance, bobAmt)
	}
	if aliceInfo.LocalBalance != aliceAmt {
		t.Fatalf("alice's local balance is incorrect, got %v, "+
			"expected %v", aliceInfo.LocalBalance, aliceAmt)
	}
	if len(aliceInfo.PendingHtlcs) != 0 {
		t.Fatalf("alice's pending htlcs is incorrect, got %v, "+
			"expected %v", len(aliceInfo.PendingHtlcs), 0)
	}

	// Next query for Bob's and Alice's channel states, in order to confirm
	// that all payment have been successful transmitted.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	bobInfo, err := getChanInfo(ctxt, net.Bob)
	if err != nil {
		t.Fatalf("unable to get bob's channel info: %v", err)
	}

	if bobInfo.LocalBalance != bobAmt {
		t.Fatalf("bob's local balance is incorrect, got %v, expected"+
			" %v", bobInfo.LocalBalance, bobAmt)
	}
	if bobInfo.RemoteBalance != aliceAmt {
		t.Fatalf("bob's remote balance is incorrect, got %v, "+
			"expected %v", bobInfo.RemoteBalance, aliceAmt)
	}
	if len(bobInfo.PendingHtlcs) != 0 {
		t.Fatalf("bob's pending htlcs is incorrect, got %v, "+
			"expected %v", len(bobInfo.PendingHtlcs), 0)
	}

	// Finally, immediately close the channel. This function will also
	// block until the channel is closed and will additionally assert the
	// relevant channel closing post conditions.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPoint, false)
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
			if err != nil {
				t.Fatalf("unable to get mempool: %v", err)
			}

			if len(mempool) == 0 {
				continue
			}

			for _, txid := range mempool {
				tx, err := miner.GetRawTransaction(txid)
				if err != nil {
					t.Fatalf("unable to fetch tx: %v", err)
				}

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

// testSwitchCircuitPersistence creates a multihop network to ensure the sender
// and intermediaries are persisting their open payment circuits. After
// forwarding a packet via an outgoing link, all are restarted, and expected to
// forward a response back from the receiver once back online.
//
// The general flow of this test:
//   1. Carol --> Dave --> Alice --> Bob  forward payment
//   2.        X        X         X  Bob  restart sender and intermediaries
//   3. Carol <-- Dave <-- Alice <-- Bob  expect settle to propagate
func testSwitchCircuitPersistence(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(1000000)
	const pushAmt = btcutil.Amount(900000)
	var networkChans []*lnrpc.ChannelPoint

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointAlice)

	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAlice)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAlice.OutputIndex,
	}

	// As preliminary setup, we'll create two new nodes: Carol and Dave,
	// such that we now have a 4 ndoe, 3 channel topology. Dave will make
	// a channel with Alice, and Carol with Dave. After this setup, the
	// network topology should now look like:
	//     Carol -> Dave -> Alice -> Bob
	//
	// First, we'll create Dave and establish a channel to Alice.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, net.Alice)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointDave := openChannelAndAssert(
		ctxt, t, net, dave, net.Alice,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointDave)
	daveChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointDave)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	daveFundPoint := wire.OutPoint{
		Hash:  *daveChanTXID,
		Index: chanPointDave.OutputIndex,
	}

	// Next, we'll create Carol and establish a channel to from her to
	// Dave. Carol is started in htlchodl mode so that we can disconnect the
	// intermediary hops before starting the settle.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointCarol)

	carolChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointCarol)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	carolFundPoint := wire.OutPoint{
		Hash:  *carolChanTXID,
		Index: chanPointCarol.OutputIndex,
	}

	// Wait for all nodes to have seen all channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol, dave}
	nodeNames := []string{"Alice", "Bob", "Carol", "Dave"}
	for _, chanPoint := range networkChans {
		for i, node := range nodes {
			txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			point := wire.OutPoint{
				Hash:  *txid,
				Index: chanPoint.OutputIndex,
			}

			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			err = node.WaitForNetworkChannelOpen(ctxt, chanPoint)
			if err != nil {
				t.Fatalf("%s(%d): timeout waiting for "+
					"channel(%s) open: %v", nodeNames[i],
					node.NodeID, point, err)
			}
		}
	}

	// Create 5 invoices for Carol, which expect a payment from Bob for 1k
	// satoshis with a different preimage each time.
	const numPayments = 5
	const paymentAmt = 1000
	payReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// We'll wait for all parties to recognize the new channels within the
	// network.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPointDave)
	if err != nil {
		t.Fatalf("dave didn't advertise his channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("carol didn't advertise her channel in time: %v",
			err)
	}

	time.Sleep(time.Millisecond * 50)

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Wait until all nodes in the network have 5 outstanding htlcs.
	var predErr error
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodes, numPayments)
		if predErr != nil {
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Restart the intermediaries and the sender.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	if err := net.RestartNode(net.Alice, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	if err := net.RestartNode(net.Bob, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Ensure all of the intermediate links are reconnected.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, net.Alice, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, net.Bob, net.Alice)

	// Ensure all nodes in the network still have 5 outstanding htlcs.
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodes, numPayments)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Now restart carol without hodl mode, to settle back the outstanding
	// payments.
	carol.SetExtraArgs(nil)
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, carol)

	// After the payments settle, there should be no active htlcs on any of
	// the nodes in the network.
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodes, 0)
		return predErr == nil

	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when
	// creating the seed nodes in the network.
	const baseFee = 1

	// At this point all the channels within our proto network should be
	// shifted by 5k satoshis in the direction of Carol, the sink within the
	// payment flow generated above. The order of asserts corresponds to
	// increasing of time is needed to embed the HTLC in commitment
	// transaction, in channel Bob->Alice->David->Carol, order is Carol,
	// David, Alice, Bob.
	var amountPaid = int64(5000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*numPayments))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*numPayments), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*numPayments)*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*numPayments)*2, int64(0))

	// Lastly, we will send one more payment to ensure all channels are
	// still functioning properly.
	finalInvoice := &lnrpc.Invoice{
		Memo:  "testing",
		Value: paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.AddInvoice(ctxt, finalInvoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	payReqs = []string{resp.PaymentRequest}

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	amountPaid = int64(6000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*(numPayments+1)))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*(numPayments+1)), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*(numPayments+1))*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*(numPayments+1))*2, int64(0))

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, dave, chanPointDave, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// testSwitchOfflineDelivery constructs a set of multihop payments, and tests
// that the returning payments are not lost if a peer on the backwards path is
// offline when the settle/fails are received. We expect the payments to be
// buffered in memory, and transmitted as soon as the disconnect link comes back
// online.
//
// The general flow of this test:
//   1. Carol --> Dave --> Alice --> Bob  forward payment
//   2. Carol --- Dave  X  Alice --- Bob  disconnect intermediaries
//   3. Carol --- Dave  X  Alice <-- Bob  settle last hop
//   4. Carol <-- Dave <-- Alice --- Bob  reconnect, expect settle to propagate
func testSwitchOfflineDelivery(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(1000000)
	const pushAmt = btcutil.Amount(900000)
	var networkChans []*lnrpc.ChannelPoint

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointAlice)

	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAlice)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAlice.OutputIndex,
	}

	// As preliminary setup, we'll create two new nodes: Carol and Dave,
	// such that we now have a 4 ndoe, 3 channel topology. Dave will make
	// a channel with Alice, and Carol with Dave. After this setup, the
	// network topology should now look like:
	//     Carol -> Dave -> Alice -> Bob
	//
	// First, we'll create Dave and establish a channel to Alice.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, net.Alice)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointDave := openChannelAndAssert(
		ctxt, t, net, dave, net.Alice,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointDave)
	daveChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointDave)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	daveFundPoint := wire.OutPoint{
		Hash:  *daveChanTXID,
		Index: chanPointDave.OutputIndex,
	}

	// Next, we'll create Carol and establish a channel to from her to
	// Dave. Carol is started in htlchodl mode so that we can disconnect the
	// intermediary hops before starting the settle.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointCarol)

	carolChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointCarol)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	carolFundPoint := wire.OutPoint{
		Hash:  *carolChanTXID,
		Index: chanPointCarol.OutputIndex,
	}

	// Wait for all nodes to have seen all channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol, dave}
	nodeNames := []string{"Alice", "Bob", "Carol", "Dave"}
	for _, chanPoint := range networkChans {
		for i, node := range nodes {
			txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			point := wire.OutPoint{
				Hash:  *txid,
				Index: chanPoint.OutputIndex,
			}

			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			err = node.WaitForNetworkChannelOpen(ctxt, chanPoint)
			if err != nil {
				t.Fatalf("%s(%d): timeout waiting for "+
					"channel(%s) open: %v", nodeNames[i],
					node.NodeID, point, err)
			}
		}
	}

	// Create 5 invoices for Carol, which expect a payment from Bob for 1k
	// satoshis with a different preimage each time.
	const numPayments = 5
	const paymentAmt = 1000
	payReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// We'll wait for all parties to recognize the new channels within the
	// network.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPointDave)
	if err != nil {
		t.Fatalf("dave didn't advertise his channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("carol didn't advertise her channel in time: %v",
			err)
	}

	// Make sure all nodes are fully synced before we continue.
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	for _, node := range nodes {
		err := node.WaitForBlockchainSync(ctxt)
		if err != nil {
			t.Fatalf("unable to wait for sync: %v", err)
		}
	}

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Wait for all of the payments to reach Carol.
	var predErr error
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodes, numPayments)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// First, disconnect Dave and Alice so that their link is broken.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, dave, net.Alice); err != nil {
		t.Fatalf("unable to disconnect alice from dave: %v", err)
	}

	// Then, reconnect them to ensure Dave doesn't just fail back the htlc.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, net.Alice)

	// Wait to ensure that the payment remain are not failed back after
	// reconnecting. All node should report the number payments initiated
	// for the duration of the interval.
	err = wait.Invariant(func() bool {
		predErr = assertNumActiveHtlcs(nodes, numPayments)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc change: %v", predErr)
	}

	// Now, disconnect Dave from Alice again before settling back the
	// payment.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, dave, net.Alice); err != nil {
		t.Fatalf("unable to disconnect alice from dave: %v", err)
	}

	// Now restart carol without hodl mode, to settle back the outstanding
	// payments.
	carol.SetExtraArgs(nil)
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Wait for Carol to report no outstanding htlcs.
	carolNode := []*lntest.HarnessNode{carol}
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(carolNode, 0)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Make sure all nodes are fully synced again.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	for _, node := range nodes {
		err := node.WaitForBlockchainSync(ctxt)
		if err != nil {
			t.Fatalf("unable to wait for sync: %v", err)
		}
	}

	// Now that the settles have reached Dave, reconnect him with Alice,
	// allowing the settles to return to the sender.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, net.Alice)

	// Wait until all outstanding htlcs in the network have been settled.
	err = wait.Predicate(func() bool {
		return assertNumActiveHtlcs(nodes, 0) == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when
	// creating the seed nodes in the network.
	const baseFee = 1

	// At this point all the channels within our proto network should be
	// shifted by 5k satoshis in the direction of Carol, the sink within the
	// payment flow generated above. The order of asserts corresponds to
	// increasing of time is needed to embed the HTLC in commitment
	// transaction, in channel Bob->Alice->David->Carol, order is Carol,
	// David, Alice, Bob.
	var amountPaid = int64(5000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*numPayments))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*numPayments), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*numPayments)*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*numPayments)*2, int64(0))

	// Lastly, we will send one more payment to ensure all channels are
	// still functioning properly.
	finalInvoice := &lnrpc.Invoice{
		Memo:  "testing",
		Value: paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.AddInvoice(ctxt, finalInvoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	payReqs = []string{resp.PaymentRequest}

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	amountPaid = int64(6000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*(numPayments+1)))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*(numPayments+1)), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*(numPayments+1))*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*(numPayments+1))*2, int64(0))

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, dave, chanPointDave, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// testSwitchOfflineDeliveryPersistence constructs a set of multihop payments,
// and tests that the returning payments are not lost if a peer on the backwards
// path is offline when the settle/fails are received AND the peer buffering the
// responses is completely restarts. We expect the payments to be reloaded from
// disk, and transmitted as soon as the intermediaries are reconnected.
//
// The general flow of this test:
//   1. Carol --> Dave --> Alice --> Bob  forward payment
//   2. Carol --- Dave  X  Alice --- Bob  disconnect intermediaries
//   3. Carol --- Dave  X  Alice <-- Bob  settle last hop
//   4. Carol --- Dave  X         X  Bob  restart Alice
//   5. Carol <-- Dave <-- Alice --- Bob  expect settle to propagate
func testSwitchOfflineDeliveryPersistence(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(1000000)
	const pushAmt = btcutil.Amount(900000)
	var networkChans []*lnrpc.ChannelPoint

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointAlice)

	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAlice)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAlice.OutputIndex,
	}

	// As preliminary setup, we'll create two new nodes: Carol and Dave,
	// such that we now have a 4 ndoe, 3 channel topology. Dave will make
	// a channel with Alice, and Carol with Dave. After this setup, the
	// network topology should now look like:
	//     Carol -> Dave -> Alice -> Bob
	//
	// First, we'll create Dave and establish a channel to Alice.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, net.Alice)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointDave := openChannelAndAssert(
		ctxt, t, net, dave, net.Alice,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)

	networkChans = append(networkChans, chanPointDave)
	daveChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointDave)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	daveFundPoint := wire.OutPoint{
		Hash:  *daveChanTXID,
		Index: chanPointDave.OutputIndex,
	}

	// Next, we'll create Carol and establish a channel to from her to
	// Dave. Carol is started in htlchodl mode so that we can disconnect the
	// intermediary hops before starting the settle.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointCarol)

	carolChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointCarol)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	carolFundPoint := wire.OutPoint{
		Hash:  *carolChanTXID,
		Index: chanPointCarol.OutputIndex,
	}

	// Wait for all nodes to have seen all channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol, dave}
	nodeNames := []string{"Alice", "Bob", "Carol", "Dave"}
	for _, chanPoint := range networkChans {
		for i, node := range nodes {
			txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			point := wire.OutPoint{
				Hash:  *txid,
				Index: chanPoint.OutputIndex,
			}

			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			err = node.WaitForNetworkChannelOpen(ctxt, chanPoint)
			if err != nil {
				t.Fatalf("%s(%d): timeout waiting for "+
					"channel(%s) open: %v", nodeNames[i],
					node.NodeID, point, err)
			}
		}
	}

	// Create 5 invoices for Carol, which expect a payment from Bob for 1k
	// satoshis with a different preimage each time.
	const numPayments = 5
	const paymentAmt = 1000
	payReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// We'll wait for all parties to recognize the new channels within the
	// network.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPointDave)
	if err != nil {
		t.Fatalf("dave didn't advertise his channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("carol didn't advertise her channel in time: %v",
			err)
	}

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	var predErr error
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodes, numPayments)
		return predErr == nil

	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Disconnect the two intermediaries, Alice and Dave, by shutting down
	// Alice.
	if err := net.StopNode(net.Alice); err != nil {
		t.Fatalf("unable to shutdown alice: %v", err)
	}

	// Now restart carol without hodl mode, to settle back the outstanding
	// payments.
	carol.SetExtraArgs(nil)
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Make Carol and Dave are reconnected before waiting for the htlcs to
	// clear.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, carol)

	// Wait for Carol to report no outstanding htlcs, and also for Dav to
	// receive all the settles from Carol.
	carolNode := []*lntest.HarnessNode{carol}
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(carolNode, 0)
		if predErr != nil {
			return false
		}

		predErr = assertNumActiveHtlcsChanPoint(dave, carolFundPoint, 0)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Finally, restart dave who received the settles, but was unable to
	// deliver them to Alice since they were disconnected.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("unable to restart dave: %v", err)
	}
	if err = net.RestartNode(net.Alice, nil); err != nil {
		t.Fatalf("unable to restart alice: %v", err)
	}

	// Force Dave and Alice to reconnect before waiting for the htlcs to
	// clear.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, net.Alice)

	// After reconnection succeeds, the settles should be propagated all
	// the way back to the sender. All nodes should report no active htlcs.
	err = wait.Predicate(func() bool {
		return assertNumActiveHtlcs(nodes, 0) == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when
	// creating the seed nodes in the network.
	const baseFee = 1

	// At this point all the channels within our proto network should be
	// shifted by 5k satoshis in the direction of Carol, the sink within the
	// payment flow generated above. The order of asserts corresponds to
	// increasing of time is needed to embed the HTLC in commitment
	// transaction, in channel Bob->Alice->David->Carol, order is Carol,
	// David, Alice, Bob.
	var amountPaid = int64(5000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*numPayments))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*numPayments), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*numPayments)*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*numPayments)*2, int64(0))

	// Lastly, we will send one more payment to ensure all channels are
	// still functioning properly.
	finalInvoice := &lnrpc.Invoice{
		Memo:  "testing",
		Value: paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.AddInvoice(ctxt, finalInvoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	payReqs = []string{resp.PaymentRequest}

	// Before completing the final payment request, ensure that the
	// connection between Dave and Carol has been healed.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, carol)

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	amountPaid = int64(6000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*(numPayments+1)))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*(numPayments+1)), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*(numPayments+1))*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*(numPayments+1))*2, int64(0))

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, dave, chanPointDave, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// testSwitchOfflineDeliveryOutgoingOffline constructs a set of multihop payments,
// and tests that the returning payments are not lost if a peer on the backwards
// path is offline when the settle/fails are received AND the peer buffering the
// responses is completely restarts. We expect the payments to be reloaded from
// disk, and transmitted as soon as the intermediaries are reconnected.
//
// The general flow of this test:
//   1. Carol --> Dave --> Alice --> Bob  forward payment
//   2. Carol --- Dave  X  Alice --- Bob  disconnect intermediaries
//   3. Carol --- Dave  X  Alice <-- Bob  settle last hop
//   4. Carol --- Dave  X         X       shutdown Bob, restart Alice
//   5. Carol <-- Dave <-- Alice  X       expect settle to propagate
func testSwitchOfflineDeliveryOutgoingOffline(
	net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(1000000)
	const pushAmt = btcutil.Amount(900000)
	var networkChans []*lnrpc.ChannelPoint

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointAlice)

	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAlice)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAlice.OutputIndex,
	}

	// As preliminary setup, we'll create two new nodes: Carol and Dave,
	// such that we now have a 4 ndoe, 3 channel topology. Dave will make
	// a channel with Alice, and Carol with Dave. After this setup, the
	// network topology should now look like:
	//     Carol -> Dave -> Alice -> Bob
	//
	// First, we'll create Dave and establish a channel to Alice.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, net.Alice)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointDave := openChannelAndAssert(
		ctxt, t, net, dave, net.Alice,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointDave)
	daveChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointDave)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	daveFundPoint := wire.OutPoint{
		Hash:  *daveChanTXID,
		Index: chanPointDave.OutputIndex,
	}

	// Next, we'll create Carol and establish a channel to from her to
	// Dave. Carol is started in htlchodl mode so that we can disconnect the
	// intermediary hops before starting the settle.
	carol := net.NewNode(t.t, "Carol", []string{"--hodl.exit-settle"})
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: pushAmt,
		},
	)
	networkChans = append(networkChans, chanPointCarol)

	carolChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointCarol)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	carolFundPoint := wire.OutPoint{
		Hash:  *carolChanTXID,
		Index: chanPointCarol.OutputIndex,
	}

	// Wait for all nodes to have seen all channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol, dave}
	nodeNames := []string{"Alice", "Bob", "Carol", "Dave"}
	for _, chanPoint := range networkChans {
		for i, node := range nodes {
			txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			point := wire.OutPoint{
				Hash:  *txid,
				Index: chanPoint.OutputIndex,
			}

			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			err = node.WaitForNetworkChannelOpen(ctxt, chanPoint)
			if err != nil {
				t.Fatalf("%s(%d): timeout waiting for "+
					"channel(%s) open: %v", nodeNames[i],
					node.NodeID, point, err)
			}
		}
	}

	// Create 5 invoices for Carol, which expect a payment from Bob for 1k
	// satoshis with a different preimage each time.
	const numPayments = 5
	const paymentAmt = 1000
	payReqs, _, _, err := createPayReqs(
		carol, paymentAmt, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// We'll wait for all parties to recognize the new channels within the
	// network.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPointDave)
	if err != nil {
		t.Fatalf("dave didn't advertise his channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("carol didn't advertise her channel in time: %v",
			err)
	}

	// Using Carol as the source, pay to the 5 invoices from Bob created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Bob, net.Bob.RouterClient, payReqs, false,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Wait for all payments to reach Carol.
	var predErr error
	err = wait.Predicate(func() bool {
		return assertNumActiveHtlcs(nodes, numPayments) == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Disconnect the two intermediaries, Alice and Dave, so that when carol
	// restarts, the response will be held by Dave.
	if err := net.StopNode(net.Alice); err != nil {
		t.Fatalf("unable to shutdown alice: %v", err)
	}

	// Now restart carol without hodl mode, to settle back the outstanding
	// payments.
	carol.SetExtraArgs(nil)
	if err := net.RestartNode(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}

	// Wait for Carol to report no outstanding htlcs.
	carolNode := []*lntest.HarnessNode{carol}
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(carolNode, 0)
		if predErr != nil {
			return false
		}

		predErr = assertNumActiveHtlcsChanPoint(dave, carolFundPoint, 0)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// Now check that the total amount was transferred from Dave to Carol.
	// The amount transferred should be exactly equal to the invoice total
	// payment amount, 5k satsohis.
	const amountPaid = int64(5000)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", carol,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Dave(local) => Carol(remote)", dave,
		carolFundPoint, amountPaid, int64(0))

	// Shutdown carol and leave her offline for the rest of the test. This
	// is critical, as we wish to see if Dave can propragate settles even if
	// the outgoing link is never revived.
	shutdownAndAssert(net, t, carol)

	// Now restart Dave, ensuring he is both persisting the settles, and is
	// able to reforward them to Alice after recovering from a restart.
	if err := net.RestartNode(dave, nil); err != nil {
		t.Fatalf("unable to restart dave: %v", err)
	}
	if err = net.RestartNode(net.Alice, nil); err != nil {
		t.Fatalf("unable to restart alice: %v", err)
	}

	// Ensure that Dave is reconnected to Alice before waiting for the
	// htlcs to clear.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, net.Alice)

	// Since Carol has been shutdown permanently, we will wait until all
	// other nodes in the network report no active htlcs.
	nodesMinusCarol := []*lntest.HarnessNode{net.Bob, net.Alice, dave}
	err = wait.Predicate(func() bool {
		predErr = assertNumActiveHtlcs(nodesMinusCarol, 0)
		return predErr == nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("htlc mismatch: %v", predErr)
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when
	// creating the seed nodes in the network.
	const baseFee = 1

	// At this point, all channels (minus Carol, who is shutdown) should
	// show a shift of 5k satoshis towards Carol.  The order of asserts
	// corresponds to increasing of time is needed to embed the HTLC in
	// commitment transaction, in channel Bob->Alice->David, order is
	// David, Alice, Bob.
	assertAmountPaid(t, "Alice(local) => Dave(remote)", dave,
		daveFundPoint, int64(0), amountPaid+(baseFee*numPayments))
	assertAmountPaid(t, "Alice(local) => Dave(remote)", net.Alice,
		daveFundPoint, amountPaid+(baseFee*numPayments), int64(0))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Alice,
		aliceFundPoint, int64(0), amountPaid+((baseFee*numPayments)*2))
	assertAmountPaid(t, "Bob(local) => Alice(remote)", net.Bob,
		aliceFundPoint, amountPaid+(baseFee*numPayments)*2, int64(0))

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, dave, chanPointDave, false)
}

// testSendUpdateDisableChannel ensures that a channel update with the disable
// flag set is sent once a channel has been either unilaterally or cooperatively
// closed.
func testSendUpdateDisableChannel(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt = 100000
	)

	// Open a channel between Alice and Bob and Alice and Carol. These will
	// be closed later on in order to trigger channel update messages
	// marking the channels as disabled.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAliceBob := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	carol := net.NewNode(
		t.t, "Carol", []string{
			"--minbackoff=10s",
			"--chan-enable-timeout=1.5s",
			"--chan-disable-timeout=3s",
			"--chan-status-sample-interval=.5s",
		})
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAliceCarol := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// We create a new node Eve that has an inactive channel timeout of
	// just 2 seconds (down from the default 20m). It will be used to test
	// channel updates for channels going inactive.
	eve := net.NewNode(
		t.t, "Eve", []string{
			"--minbackoff=10s",
			"--chan-enable-timeout=1.5s",
			"--chan-disable-timeout=3s",
			"--chan-status-sample-interval=.5s",
		})
	defer shutdownAndAssert(net, t, eve)

	// Give Eve some coins.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, eve)

	// Connect Eve to Carol and Bob, and open a channel to carol.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, eve, carol)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, eve, net.Bob)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointEveCarol := openChannelAndAssert(
		ctxt, t, net, eve, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Launch a node for Dave which will connect to Bob in order to receive
	// graph updates from. This will ensure that the channel updates are
	// propagated throughout the network.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Bob, dave)

	daveSub := subscribeGraphNotifications(ctxb, t, dave)
	defer close(daveSub.quit)

	// We should expect to see a channel update with the default routing
	// policy, except that it should indicate the channel is disabled.
	expectedPolicy := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      int64(chainreg.DefaultBitcoinBaseFeeMSat),
		FeeRateMilliMsat: int64(chainreg.DefaultBitcoinFeeRate),
		TimeLockDelta:    chainreg.DefaultBitcoinTimeLockDelta,
		MinHtlc:          1000, // default value
		MaxHtlcMsat:      calculateMaxHtlc(chanAmt),
		Disabled:         true,
	}

	// Let Carol go offline. Since Eve has an inactive timeout of 2s, we
	// expect her to send an update disabling the channel.
	restartCarol, err := net.SuspendNode(carol)
	if err != nil {
		t.Fatalf("unable to suspend carol: %v", err)
	}
	waitForChannelUpdate(
		t, daveSub,
		[]expectedChanUpdate{
			{eve.PubKeyStr, expectedPolicy, chanPointEveCarol},
		},
	)

	// We restart Carol. Since the channel now becomes active again, Eve
	// should send a ChannelUpdate setting the channel no longer disabled.
	if err := restartCarol(); err != nil {
		t.Fatalf("unable to restart carol: %v", err)
	}

	expectedPolicy.Disabled = false
	waitForChannelUpdate(
		t, daveSub,
		[]expectedChanUpdate{
			{eve.PubKeyStr, expectedPolicy, chanPointEveCarol},
		},
	)

	// Now we'll test a long disconnection. Disconnect Carol and Eve and
	// ensure they both detect each other as disabled. Their min backoffs
	// are high enough to not interfere with disabling logic.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, carol, eve); err != nil {
		t.Fatalf("unable to disconnect Carol from Eve: %v", err)
	}

	// Wait for a disable from both Carol and Eve to come through.
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, daveSub,
		[]expectedChanUpdate{
			{eve.PubKeyStr, expectedPolicy, chanPointEveCarol},
			{carol.PubKeyStr, expectedPolicy, chanPointEveCarol},
		},
	)

	// Reconnect Carol and Eve, this should cause them to reenable the
	// channel from both ends after a short delay.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, carol, eve)

	expectedPolicy.Disabled = false
	waitForChannelUpdate(
		t, daveSub,
		[]expectedChanUpdate{
			{eve.PubKeyStr, expectedPolicy, chanPointEveCarol},
			{carol.PubKeyStr, expectedPolicy, chanPointEveCarol},
		},
	)

	// Now we'll test a short disconnection. Disconnect Carol and Eve, then
	// reconnect them after one second so that their scheduled disables are
	// aborted. One second is twice the status sample interval, so this
	// should allow for the disconnect to be detected, but still leave time
	// to cancel the announcement before the 3 second inactive timeout is
	// hit.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.DisconnectNodes(ctxt, carol, eve); err != nil {
		t.Fatalf("unable to disconnect Carol from Eve: %v", err)
	}
	time.Sleep(time.Second)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, eve, carol)

	// Since the disable should have been canceled by both Carol and Eve, we
	// expect no channel updates to appear on the network.
	assertNoChannelUpdates(t, daveSub, 4*time.Second)

	// Close Alice's channels with Bob and Carol cooperatively and
	// unilaterally respectively.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	_, _, err = net.CloseChannel(ctxt, net.Alice, chanPointAliceBob, false)
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	_, _, err = net.CloseChannel(ctxt, net.Alice, chanPointAliceCarol, true)
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	// Now that the channel close processes have been started, we should
	// receive an update marking each as disabled.
	expectedPolicy.Disabled = true
	waitForChannelUpdate(
		t, daveSub,
		[]expectedChanUpdate{
			{net.Alice.PubKeyStr, expectedPolicy, chanPointAliceBob},
			{net.Alice.PubKeyStr, expectedPolicy, chanPointAliceCarol},
		},
	)

	// Finally, close the channels by mining the closing transactions.
	mineBlocks(t, net, 1, 2)

	// Also do this check for Eve's channel with Carol.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	_, _, err = net.CloseChannel(ctxt, eve, chanPointEveCarol, false)
	if err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	waitForChannelUpdate(
		t, daveSub,
		[]expectedChanUpdate{
			{eve.PubKeyStr, expectedPolicy, chanPointEveCarol},
		},
	)
	mineBlocks(t, net, 1, 1)

	// And finally, clean up the force closed channel by mining the
	// sweeping transaction.
	cleanupForceClose(t, net, net.Alice, chanPointAliceCarol)
}

// testAbandonChannel abandones a channel and asserts that it is no
// longer open and not in one of the pending closure states. It also
// verifies that the abandoned channel is reported as closed with close
// type 'abandoned'.
func testAbandonChannel(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First establish a channel between Alice and Bob.
	channelParam := lntest.OpenChannelParams{
		Amt:     funding.MaxBtcFundingAmount,
		PushAmt: btcutil.Amount(100000),
	}

	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob, channelParam,
	)
	txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	chanPointStr := fmt.Sprintf("%v:%v", txid, chanPoint.OutputIndex)

	// Wait for channel to be confirmed open.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("alice didn't report channel: %v", err)
	}
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}

	// Now that the channel is open, we'll obtain its channel ID real quick
	// so we can use it to query the graph below.
	listReq := &lnrpc.ListChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceChannelList, err := net.Alice.ListChannels(ctxt, listReq)
	if err != nil {
		t.Fatalf("unable to fetch alice's channels: %v", err)
	}
	var chanID uint64
	for _, channel := range aliceChannelList.Channels {
		if channel.ChannelPoint == chanPointStr {
			chanID = channel.ChanId
		}
	}

	if chanID == 0 {
		t.Fatalf("unable to find channel")
	}

	// To make sure the channel is removed from the backup file as well when
	// being abandoned, grab a backup snapshot so we can compare it with the
	// later state.
	bkupBefore, err := ioutil.ReadFile(net.Alice.ChanBackupPath())
	if err != nil {
		t.Fatalf("could not get channel backup before abandoning "+
			"channel: %v", err)
	}

	// Send request to abandon channel.
	abandonChannelRequest := &lnrpc.AbandonChannelRequest{
		ChannelPoint: chanPoint,
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.AbandonChannel(ctxt, abandonChannelRequest)
	if err != nil {
		t.Fatalf("unable to abandon channel: %v", err)
	}

	// Assert that channel in no longer open.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceChannelList, err = net.Alice.ListChannels(ctxt, listReq)
	if err != nil {
		t.Fatalf("unable to list channels: %v", err)
	}
	if len(aliceChannelList.Channels) != 0 {
		t.Fatalf("alice should only have no channels open, "+
			"instead she has %v",
			len(aliceChannelList.Channels))
	}

	// Assert that channel is not pending closure.
	pendingReq := &lnrpc.PendingChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	alicePendingList, err := net.Alice.PendingChannels(ctxt, pendingReq)
	if err != nil {
		t.Fatalf("unable to list pending channels: %v", err)
	}
	if len(alicePendingList.PendingClosingChannels) != 0 { //nolint:staticcheck
		t.Fatalf("alice should only have no pending closing channels, "+
			"instead she has %v",
			len(alicePendingList.PendingClosingChannels)) //nolint:staticcheck
	}
	if len(alicePendingList.PendingForceClosingChannels) != 0 {
		t.Fatalf("alice should only have no pending force closing "+
			"channels instead she has %v",
			len(alicePendingList.PendingForceClosingChannels))
	}
	if len(alicePendingList.WaitingCloseChannels) != 0 {
		t.Fatalf("alice should only have no waiting close "+
			"channels instead she has %v",
			len(alicePendingList.WaitingCloseChannels))
	}

	// Assert that channel is listed as abandoned.
	closedReq := &lnrpc.ClosedChannelsRequest{
		Abandoned: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceClosedList, err := net.Alice.ClosedChannels(ctxt, closedReq)
	if err != nil {
		t.Fatalf("unable to list closed channels: %v", err)
	}
	if len(aliceClosedList.Channels) != 1 {
		t.Fatalf("alice should only have a single abandoned channel, "+
			"instead she has %v",
			len(aliceClosedList.Channels))
	}

	// Ensure that the channel can no longer be found in the channel graph.
	_, err = net.Alice.GetChanInfo(ctxb, &lnrpc.ChanInfoRequest{
		ChanId: chanID,
	})
	if !strings.Contains(err.Error(), "marked as zombie") {
		t.Fatalf("channel shouldn't be found in the channel " +
			"graph!")
	}

	// Make sure the channel is no longer in the channel backup list.
	err = wait.Predicate(func() bool {
		bkupAfter, err := ioutil.ReadFile(net.Alice.ChanBackupPath())
		if err != nil {
			t.Fatalf("could not get channel backup before "+
				"abandoning channel: %v", err)
		}

		return len(bkupAfter) < len(bkupBefore)
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("channel wasn't removed from channel backup file")
	}

	// Calling AbandonChannel again, should result in no new errors, as the
	// channel has already been removed.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.AbandonChannel(ctxt, abandonChannelRequest)
	if err != nil {
		t.Fatalf("unable to abandon channel a second time: %v", err)
	}

	// Now that we're done with the test, the channel can be closed. This
	// is necessary to avoid unexpected outcomes of other tests that use
	// Bob's lnd instance.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPoint, true)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, net.Bob, chanPoint)
}

// testSweepAllCoins tests that we're able to properly sweep all coins from the
// wallet into a single target address at the specified fee rate.
func testSweepAllCoins(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, we'll make a new node, ainz who'll we'll use to test wallet
	// sweeping.
	ainz := net.NewNode(t.t, "Ainz", nil)
	defer shutdownAndAssert(net, t, ainz)

	// Next, we'll give Ainz exactly 2 utxos of 1 BTC each, with one of
	// them being p2wkh and the other being a n2wpkh address.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, ainz)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoinsNP2WKH(ctxt, t.t, btcutil.SatoshiPerBitcoin, ainz)

	// Ensure that we can't send coins to our own Pubkey.
	info, err := ainz.GetInfo(ctxt, &lnrpc.GetInfoRequest{})
	if err != nil {
		t.Fatalf("unable to get node info: %v", err)
	}

	// Create a label that we will used to label the transaction with.
	sendCoinsLabel := "send all coins"

	sweepReq := &lnrpc.SendCoinsRequest{
		Addr:    info.IdentityPubkey,
		SendAll: true,
		Label:   sendCoinsLabel,
	}
	_, err = ainz.SendCoins(ctxt, sweepReq)
	if err == nil {
		t.Fatalf("expected SendCoins to users own pubkey to fail")
	}

	// Ensure that we can't send coins to another users Pubkey.
	info, err = net.Alice.GetInfo(ctxt, &lnrpc.GetInfoRequest{})
	if err != nil {
		t.Fatalf("unable to get node info: %v", err)
	}

	sweepReq = &lnrpc.SendCoinsRequest{
		Addr:    info.IdentityPubkey,
		SendAll: true,
		Label:   sendCoinsLabel,
	}
	_, err = ainz.SendCoins(ctxt, sweepReq)
	if err == nil {
		t.Fatalf("expected SendCoins to Alices pubkey to fail")
	}

	// With the two coins above mined, we'll now instruct ainz to sweep all
	// the coins to an external address not under its control.
	// We will first attempt to send the coins to addresses that are not
	// compatible with the current network. This is to test that the wallet
	// will prevent any onchain transactions to addresses that are not on the
	// same network as the user.

	// Send coins to a testnet3 address.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	sweepReq = &lnrpc.SendCoinsRequest{
		Addr:    "tb1qfc8fusa98jx8uvnhzavxccqlzvg749tvjw82tg",
		SendAll: true,
		Label:   sendCoinsLabel,
	}
	_, err = ainz.SendCoins(ctxt, sweepReq)
	if err == nil {
		t.Fatalf("expected SendCoins to different network to fail")
	}

	// Send coins to a mainnet address.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	sweepReq = &lnrpc.SendCoinsRequest{
		Addr:    "1MPaXKp5HhsLNjVSqaL7fChE3TVyrTMRT3",
		SendAll: true,
		Label:   sendCoinsLabel,
	}
	_, err = ainz.SendCoins(ctxt, sweepReq)
	if err == nil {
		t.Fatalf("expected SendCoins to different network to fail")
	}

	// Send coins to a compatible address.
	minerAddr, err := net.Miner.NewAddress()
	if err != nil {
		t.Fatalf("unable to create new miner addr: %v", err)
	}

	sweepReq = &lnrpc.SendCoinsRequest{
		Addr:    minerAddr.String(),
		SendAll: true,
		Label:   sendCoinsLabel,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = ainz.SendCoins(ctxt, sweepReq)
	if err != nil {
		t.Fatalf("unable to sweep coins: %v", err)
	}

	// We'll mine a block which should include the sweep transaction we
	// generated above.
	block := mineBlocks(t, net, 1, 1)[0]

	// The sweep transaction should have exactly two inputs as we only had
	// two UTXOs in the wallet.
	sweepTx := block.Transactions[1]
	if len(sweepTx.TxIn) != 2 {
		t.Fatalf("expected 2 inputs instead have %v", len(sweepTx.TxIn))
	}

	sweepTxStr := sweepTx.TxHash().String()
	assertTxLabel(ctxb, t, ainz, sweepTxStr, sendCoinsLabel)

	// While we are looking at labels, we test our label transaction command
	// to make sure it is behaving as expected. First, we try to label our
	// transaction with an empty label, and check that we fail as expected.
	sweepHash := sweepTx.TxHash()
	_, err = ainz.WalletKitClient.LabelTransaction(
		ctxt, &walletrpc.LabelTransactionRequest{
			Txid:      sweepHash[:],
			Label:     "",
			Overwrite: false,
		},
	)
	if err == nil {
		t.Fatalf("expected error for zero transaction label")
	}

	// Our error will be wrapped in a rpc error, so we check that it
	// contains the error we expect.
	errZeroLabel := "cannot label transaction with empty label"
	if !strings.Contains(err.Error(), errZeroLabel) {
		t.Fatalf("expected: zero label error, got: %v", err)
	}

	// Next, we try to relabel our transaction without setting the overwrite
	// boolean. We expect this to fail, because the wallet requires setting
	// of this param to prevent accidental overwrite of labels.
	_, err = ainz.WalletKitClient.LabelTransaction(
		ctxt, &walletrpc.LabelTransactionRequest{
			Txid:      sweepHash[:],
			Label:     "label that will not work",
			Overwrite: false,
		},
	)
	if err == nil {
		t.Fatalf("expected error for tx already labelled")
	}

	// Our error will be wrapped in a rpc error, so we check that it
	// contains the error we expect.
	if !strings.Contains(err.Error(), wallet.ErrTxLabelExists.Error()) {
		t.Fatalf("expected: label exists, got: %v", err)
	}

	// Finally, we overwrite our label with a new label, which should not
	// fail.
	newLabel := "new sweep tx label"
	_, err = ainz.WalletKitClient.LabelTransaction(
		ctxt, &walletrpc.LabelTransactionRequest{
			Txid:      sweepHash[:],
			Label:     newLabel,
			Overwrite: true,
		},
	)
	if err != nil {
		t.Fatalf("could not label tx: %v", err)
	}

	assertTxLabel(ctxb, t, ainz, sweepTxStr, newLabel)

	// Finally, Ainz should now have no coins at all within his wallet.
	balReq := &lnrpc.WalletBalanceRequest{}
	resp, err := ainz.WalletBalance(ctxt, balReq)
	if err != nil {
		t.Fatalf("unable to get ainz's balance: %v", err)
	}
	switch {
	case resp.ConfirmedBalance != 0:
		t.Fatalf("expected no confirmed balance, instead have %v",
			resp.ConfirmedBalance)

	case resp.UnconfirmedBalance != 0:
		t.Fatalf("expected no unconfirmed balance, instead have %v",
			resp.UnconfirmedBalance)
	}

	// If we try again, but this time specifying an amount, then the call
	// should fail.
	sweepReq.Amount = 10000
	_, err = ainz.SendCoins(ctxt, sweepReq)
	if err == nil {
		t.Fatalf("sweep attempt should fail")
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
	if err != nil {
		t.Fatalf("could not get transactions: %v", err)
	}

	// Find our transaction in the set of transactions returned and check
	// its label.
	for _, txn := range txResp.Transactions {
		if txn.TxHash == targetTx {
			if txn.Label != label {
				t.Fatalf("expected label: %v, got: %v",
					label, txn.Label)
			}
		}
	}
}

// deriveFundingShim creates a channel funding shim by deriving the necessary
// keys on both sides.
func deriveFundingShim(net *lntest.NetworkHarness, t *harnessTest,
	carol, dave *lntest.HarnessNode, chanSize btcutil.Amount,
	thawHeight uint32, keyIndex int32, publish bool) (*lnrpc.FundingShim,
	*lnrpc.ChannelPoint, *chainhash.Hash) {

	ctxb := context.Background()
	keyLoc := &signrpc.KeyLocator{
		KeyFamily: 9999,
		KeyIndex:  keyIndex,
	}
	carolFundingKey, err := carol.WalletKitClient.DeriveKey(ctxb, keyLoc)
	require.NoError(t.t, err)
	daveFundingKey, err := dave.WalletKitClient.DeriveKey(ctxb, keyLoc)
	require.NoError(t.t, err)

	// Now that we have the multi-sig keys for each party, we can manually
	// construct the funding transaction. We'll instruct the backend to
	// immediately create and broadcast a transaction paying out an exact
	// amount. Normally this would reside in the mempool, but we just
	// confirm it now for simplicity.
	_, fundingOutput, err := input.GenFundingPkScript(
		carolFundingKey.RawKeyBytes, daveFundingKey.RawKeyBytes,
		int64(chanSize),
	)
	require.NoError(t.t, err)

	var txid *chainhash.Hash
	targetOutputs := []*wire.TxOut{fundingOutput}
	if publish {
		txid, err = net.Miner.SendOutputsWithoutChange(
			targetOutputs, 5,
		)
		require.NoError(t.t, err)
	} else {
		tx, err := net.Miner.CreateTransaction(targetOutputs, 5, false)
		require.NoError(t.t, err)

		txHash := tx.TxHash()
		txid = &txHash
	}

	// At this point, we can being our external channel funding workflow.
	// We'll start by generating a pending channel ID externally that will
	// be used to track this new funding type.
	var pendingChanID [32]byte
	_, err = rand.Read(pendingChanID[:])
	require.NoError(t.t, err)

	// Now that we have the pending channel ID, Dave (our responder) will
	// register the intent to receive a new channel funding workflow using
	// the pending channel ID.
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: txid[:],
		},
	}
	chanPointShim := &lnrpc.ChanPointShim{
		Amt:       int64(chanSize),
		ChanPoint: chanPoint,
		LocalKey: &lnrpc.KeyDescriptor{
			RawKeyBytes: daveFundingKey.RawKeyBytes,
			KeyLoc: &lnrpc.KeyLocator{
				KeyFamily: daveFundingKey.KeyLoc.KeyFamily,
				KeyIndex:  daveFundingKey.KeyLoc.KeyIndex,
			},
		},
		RemoteKey:     carolFundingKey.RawKeyBytes,
		PendingChanId: pendingChanID[:],
		ThawHeight:    thawHeight,
	}
	fundingShim := &lnrpc.FundingShim{
		Shim: &lnrpc.FundingShim_ChanPointShim{
			ChanPointShim: chanPointShim,
		},
	}
	_, err = dave.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_ShimRegister{
			ShimRegister: fundingShim,
		},
	})
	require.NoError(t.t, err)

	// If we attempt to register the same shim (has the same pending chan
	// ID), then we should get an error.
	_, err = dave.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_ShimRegister{
			ShimRegister: fundingShim,
		},
	})
	if err == nil {
		t.Fatalf("duplicate pending channel ID funding shim " +
			"registration should trigger an error")
	}

	// We'll take the chan point shim we just registered for Dave (the
	// responder), and swap the local/remote keys before we feed it in as
	// Carol's funding shim as the initiator.
	fundingShim.GetChanPointShim().LocalKey = &lnrpc.KeyDescriptor{
		RawKeyBytes: carolFundingKey.RawKeyBytes,
		KeyLoc: &lnrpc.KeyLocator{
			KeyFamily: carolFundingKey.KeyLoc.KeyFamily,
			KeyIndex:  carolFundingKey.KeyLoc.KeyIndex,
		},
	}
	fundingShim.GetChanPointShim().RemoteKey = daveFundingKey.RawKeyBytes

	return fundingShim, chanPoint, txid
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
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	result, err := getPaymentResult(stream)
	if err != nil {
		t.Fatalf("unable to get payment result: %v", err)
	}

	if result.Status != lnrpc.Payment_FAILED {
		t.Fatalf("payment was expected to fail, but succeeded")
	}

	if result.FailureReason != failureReason {
		t.Fatalf("payment should have been rejected due to "+
			"%v, but got %v", failureReason, result.Status)
	}

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

// TestLightningNetworkDaemon performs a series of integration tests amongst a
// programmatically driven network of lnd nodes.
func TestLightningNetworkDaemon(t *testing.T) {
	// If no tests are registered, then we can exit early.
	if len(allTestCases) == 0 {
		t.Skip("integration tests not selected with flag 'rpctest'")
	}

	// Parse testing flags that influence our test execution.
	logDir := lntest.GetLogDir()
	require.NoError(t, os.MkdirAll(logDir, 0700))
	testCases, trancheIndex, trancheOffset := getTestCaseSplitTranche()
	lntest.ApplyPortOffset(uint32(trancheIndex) * 1000)

	// Before we start any node, we need to make sure that any btcd node
	// that is started through the RPC harness uses a unique port as well to
	// avoid any port collisions.
	rpctest.ListenAddressGenerator = lntest.GenerateBtcdListenerAddresses

	// Declare the network harness here to gain access to its
	// 'OnTxAccepted' call back.
	var lndHarness *lntest.NetworkHarness

	// Create an instance of the btcd's rpctest.Harness that will act as
	// the miner for all tests. This will be used to fund the wallets of
	// the nodes within the test network and to drive blockchain related
	// events within the network. Revert the default setting of accepting
	// non-standard transactions on simnet to reject them. Transactions on
	// the lightning network should always be standard to get better
	// guarantees of getting included in to blocks.
	//
	// We will also connect it to our chain backend.
	minerLogDir := fmt.Sprintf("%s/.minerlogs", logDir)
	miner, minerCleanUp, err := lntest.NewMiner(
		minerLogDir, "output_btcd_miner.log", harnessNetParams,
		&rpcclient.NotificationHandlers{}, lntest.GetBtcdBinary(),
	)
	require.NoError(t, err, "failed to create new miner")
	defer func() {
		require.NoError(t, minerCleanUp(), "failed to clean up miner")
	}()

	// Start a chain backend.
	chainBackend, cleanUp, err := lntest.NewBackend(
		miner.P2PAddress(), harnessNetParams,
	)
	require.NoError(t, err, "new backend")
	defer func() {
		require.NoError(t, cleanUp(), "cleanup")
	}()

	// Before we start anything, we want to overwrite some of the connection
	// settings to make the tests more robust. We might need to restart the
	// miner while there are already blocks present, which will take a bit
	// longer than the 1 second the default settings amount to. Doubling
	// both values will give us retries up to 4 seconds.
	miner.MaxConnRetries = rpctest.DefaultMaxConnectionRetries * 2
	miner.ConnectionRetryTimeout = rpctest.DefaultConnectionRetryTimeout * 2

	// Set up miner and connect chain backend to it.
	require.NoError(t, miner.SetUp(true, 50))
	require.NoError(t, miner.Client.NotifyNewTransactions(false))
	require.NoError(t, chainBackend.ConnectMiner(), "connect miner")

	// Parse database backend
	var dbBackend lntest.DatabaseBackend
	switch *dbBackendFlag {
	case "bbolt":
		dbBackend = lntest.BackendBbolt

	case "etcd":
		dbBackend = lntest.BackendEtcd

	default:
		require.Fail(t, "unknown db backend")
	}

	// Now we can set up our test harness (LND instance), with the chain
	// backend we just created.
	ht := newHarnessTest(t, nil)
	binary := ht.getLndBinary()
	lndHarness, err = lntest.NewNetworkHarness(
		miner, chainBackend, binary, dbBackend,
	)
	if err != nil {
		ht.Fatalf("unable to create lightning network harness: %v", err)
	}
	defer lndHarness.Stop()

	// Spawn a new goroutine to watch for any fatal errors that any of the
	// running lnd processes encounter. If an error occurs, then the test
	// case should naturally as a result and we log the server error here to
	// help debug.
	go func() {
		for {
			select {
			case err, more := <-lndHarness.ProcessErrors():
				if !more {
					return
				}
				ht.Logf("lnd finished with error (stderr):\n%v",
					err)
			}
		}
	}()

	// Next mine enough blocks in order for segwit and the CSV package
	// soft-fork to activate on SimNet.
	numBlocks := harnessNetParams.MinerConfirmationWindow * 2
	if _, err := miner.Client.Generate(numBlocks); err != nil {
		ht.Fatalf("unable to generate blocks: %v", err)
	}

	// With the btcd harness created, we can now complete the
	// initialization of the network. args - list of lnd arguments,
	// example: "--debuglevel=debug"
	// TODO(roasbeef): create master balanced channel with all the monies?
	aliceBobArgs := []string{
		"--default-remote-max-htlcs=483",
	}

	// Run the subset of the test cases selected in this tranche.
	for idx, testCase := range testCases {
		testCase := testCase
		name := fmt.Sprintf("%02d-of-%d/%s/%s",
			trancheOffset+uint(idx)+1, len(allTestCases),
			chainBackend.Name(), testCase.name)

		success := t.Run(name, func(t1 *testing.T) {
			cleanTestCaseName := strings.ReplaceAll(
				testCase.name, " ", "_",
			)

			err = lndHarness.SetUp(
				t1, cleanTestCaseName, aliceBobArgs,
			)
			require.NoError(t1,
				err, "unable to set up test lightning network",
			)
			defer func() {
				require.NoError(t1, lndHarness.TearDown())
			}()

			lndHarness.EnsureConnected(
				context.Background(), t1,
				lndHarness.Alice, lndHarness.Bob,
			)

			logLine := fmt.Sprintf(
				"STARTING ============ %v ============\n",
				testCase.name,
			)

			AddToNodeLog(t, lndHarness.Alice, logLine)
			AddToNodeLog(t, lndHarness.Bob, logLine)

			// Start every test with the default static fee estimate.
			lndHarness.SetFeeEstimate(12500)

			// Create a separate harness test for the testcase to
			// avoid overwriting the external harness test that is
			// tied to the parent test.
			ht := newHarnessTest(t1, lndHarness)
			ht.RunTestCase(testCase)
		})

		// Stop at the first failure. Mimic behavior of original test
		// framework.
		if !success {
			// Log failure time to help relate the lnd logs to the
			// failure.
			t.Logf("Failure time: %v", time.Now().Format(
				"2006-01-02 15:04:05.000",
			))
			break
		}
	}
}
