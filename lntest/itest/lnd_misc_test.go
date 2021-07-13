package itest

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

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
	if dbInvoice.Settled { // nolint:staticcheck
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

// testGarbageCollectLinkNodes tests that we properly garbage collect link nodes
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
		ctxt, t, net, net.Alice, net.Bob, lntest.OpenChannelParams{
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
		ctxt, t, net, net.Alice, carol, lntest.OpenChannelParams{
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
		ctxt, t, net, net.Alice, dave, lntest.OpenChannelParams{
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
	require.NoError(t.t, err, "alice bob get channel funding txid")
	chanPointStr := fmt.Sprintf("%v:%v", txid, chanPoint.OutputIndex)

	// Wait for channel to be confirmed open.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err, "alice wait for network channel open")
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err, "bob wait for network channel open")

	// Now that the channel is open, we'll obtain its channel ID real quick
	// so we can use it to query the graph below.
	listReq := &lnrpc.ListChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceChannelList, err := net.Alice.ListChannels(ctxt, listReq)
	require.NoError(t.t, err)
	var chanID uint64
	for _, channel := range aliceChannelList.Channels {
		if channel.ChannelPoint == chanPointStr {
			chanID = channel.ChanId
		}
	}

	require.NotZero(t.t, chanID, "unable to find channel")

	// To make sure the channel is removed from the backup file as well when
	// being abandoned, grab a backup snapshot so we can compare it with the
	// later state.
	bkupBefore, err := ioutil.ReadFile(net.Alice.ChanBackupPath())
	require.NoError(t.t, err, "channel backup before abandoning channel")

	// Send request to abandon channel.
	abandonChannelRequest := &lnrpc.AbandonChannelRequest{
		ChannelPoint: chanPoint,
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.AbandonChannel(ctxt, abandonChannelRequest)
	require.NoError(t.t, err, "abandon channel")

	// Assert that channel in no longer open.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceChannelList, err = net.Alice.ListChannels(ctxt, listReq)
	require.NoError(t.t, err, "list channels")
	require.Zero(t.t, len(aliceChannelList.Channels), "alice open channels")

	// Assert that channel is not pending closure.
	pendingReq := &lnrpc.PendingChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	alicePendingList, err := net.Alice.PendingChannels(ctxt, pendingReq)
	require.NoError(t.t, err, "alice list pending channels")
	require.Zero(
		t.t, len(alicePendingList.PendingClosingChannels), //nolint:staticcheck
		"alice pending channels",
	)
	require.Zero(
		t.t, len(alicePendingList.PendingForceClosingChannels),
		"alice pending force close channels",
	)
	require.Zero(
		t.t, len(alicePendingList.WaitingCloseChannels),
		"alice waiting close channels",
	)

	// Assert that channel is listed as abandoned.
	closedReq := &lnrpc.ClosedChannelsRequest{
		Abandoned: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceClosedList, err := net.Alice.ClosedChannels(ctxt, closedReq)
	require.NoError(t.t, err, "alice list closed channels")
	require.Len(t.t, aliceClosedList.Channels, 1, "alice closed channels")

	// Ensure that the channel can no longer be found in the channel graph.
	err = wait.NoError(func() error {
		_, err := net.Alice.GetChanInfo(ctxb, &lnrpc.ChanInfoRequest{
			ChanId: chanID,
		})
		if err == nil {
			return fmt.Errorf("expected error but got nil")
		}

		if !strings.Contains(err.Error(), "marked as zombie") {
			return fmt.Errorf("expected error to contain '%s' but "+
				"was '%v'", "marked as zombie", err)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err, "marked as zombie")

	// Make sure the channel is no longer in the channel backup list.
	err = wait.NoError(func() error {
		bkupAfter, err := ioutil.ReadFile(net.Alice.ChanBackupPath())
		if err != nil {
			return fmt.Errorf("could not get channel backup "+
				"before abandoning channel: %v", err)
		}

		if len(bkupAfter) >= len(bkupBefore) {
			return fmt.Errorf("expected backups after to be less "+
				"than %d but was %d", bkupBefore, bkupAfter)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err, "channel removed from backup file")

	// Calling AbandonChannel again, should result in no new errors, as the
	// channel has already been removed.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.AbandonChannel(ctxt, abandonChannelRequest)
	require.NoError(t.t, err, "abandon channel second time")

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
