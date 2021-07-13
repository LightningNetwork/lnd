package itest

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testMultiHopHtlcLocalTimeout tests that in a multi-hop HTLC scenario, if the
// outgoing HTLC is about to time out, then we'll go to chain in order to claim
// it using the HTLC timeout transaction. Any dust HTLC's should be immediately
// canceled backwards. Once the timeout has been reached, then we should sweep
// it on-chain, and cancel the HTLC backwards.
func testMultiHopHtlcLocalTimeout(net *lntest.NetworkHarness, t *harnessTest,
	alice, bob *lntest.HarnessNode, c lnrpc.CommitmentType) {

	ctxb := context.Background()

	// First, we'll create a three hop network: Alice -> Bob -> Carol, with
	// Carol refusing to actually settle or directly cancel any HTLC's
	// self.
	aliceChanPoint, bobChanPoint, carol := createThreeHopNetwork(
		t, net, alice, bob, true, c,
	)

	// Clean up carol's node when the test finishes.
	defer shutdownAndAssert(net, t, carol)

	time.Sleep(time.Second * 1)

	// Now that our channels are set up, we'll send two HTLC's from Alice
	// to Carol. The first HTLC will be universally considered "dust",
	// while the second will be a proper fully valued HTLC.
	const (
		dustHtlcAmt    = btcutil.Amount(100)
		htlcAmt        = btcutil.Amount(300_000)
		finalCltvDelta = 40
	)

	ctx, cancel := context.WithCancel(ctxb)
	defer cancel()

	// We'll create two random payment hashes unknown to carol, then send
	// each of them by manually specifying the HTLC details.
	carolPubKey := carol.PubKey[:]
	dustPayHash := makeFakePayHash(t)
	payHash := makeFakePayHash(t)

	_, err := alice.RouterClient.SendPaymentV2(
		ctx, &routerrpc.SendPaymentRequest{
			Dest:           carolPubKey,
			Amt:            int64(dustHtlcAmt),
			PaymentHash:    dustPayHash,
			FinalCltvDelta: finalCltvDelta,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
		},
	)
	require.NoError(t.t, err)

	_, err = alice.RouterClient.SendPaymentV2(
		ctx, &routerrpc.SendPaymentRequest{
			Dest:           carolPubKey,
			Amt:            int64(htlcAmt),
			PaymentHash:    payHash,
			FinalCltvDelta: finalCltvDelta,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
		},
	)
	require.NoError(t.t, err)

	// Verify that all nodes in the path now have two HTLC's with the
	// proper parameters.
	nodes := []*lntest.HarnessNode{alice, bob, carol}
	err = wait.NoError(func() error {
		return assertActiveHtlcs(nodes, dustPayHash, payHash)
	}, defaultTimeout)
	require.NoError(t.t, err)

	// Increase the fee estimate so that the following force close tx will
	// be cpfp'ed.
	net.SetFeeEstimate(30000)

	// We'll now mine enough blocks to trigger Bob's broadcast of his
	// commitment transaction due to the fact that the HTLC is about to
	// timeout. With the default outgoing broadcast delta of zero, this will
	// be the same height as the htlc expiry height.
	numBlocks := padCLTV(
		uint32(finalCltvDelta - lncfg.DefaultOutgoingBroadcastDelta),
	)
	_, err = net.Miner.Client.Generate(numBlocks)
	require.NoError(t.t, err)

	// Bob's force close transaction should now be found in the mempool. If
	// there are anchors, we also expect Bob's anchor sweep.
	expectedTxes := 1
	if c == lnrpc.CommitmentType_ANCHORS {
		expectedTxes = 2
	}

	bobFundingTxid, err := lnrpc.GetChanPointFundingTxid(bobChanPoint)
	require.NoError(t.t, err)
	_, err = waitForNTxsInMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(t.t, err)
	closeTx := getSpendingTxInMempool(
		t, net.Miner.Client, minerMempoolTimeout, wire.OutPoint{
			Hash:  *bobFundingTxid,
			Index: bobChanPoint.OutputIndex,
		},
	)
	closeTxid := closeTx.TxHash()

	// Mine a block to confirm the closing transaction.
	mineBlocks(t, net, 1, expectedTxes)

	// At this point, Bob should have canceled backwards the dust HTLC
	// that we sent earlier. This means Alice should now only have a single
	// HTLC on her channel.
	nodes = []*lntest.HarnessNode{alice}
	err = wait.NoError(func() error {
		return assertActiveHtlcs(nodes, payHash)
	}, defaultTimeout)
	require.NoError(t.t, err)

	// With the closing transaction confirmed, we should expect Bob's HTLC
	// timeout transaction to be broadcast due to the expiry being reached.
	// If there are anchors, we also expect Carol's anchor sweep now.
	txes, err := getNTxsFromMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(t.t, err)

	// Lookup the timeout transaction that is expected to spend from the
	// closing tx. We distinguish it from a possibly anchor sweep by value.
	var htlcTimeout *chainhash.Hash
	for _, tx := range txes {
		prevOp := tx.TxIn[0].PreviousOutPoint
		require.Equal(t.t, closeTxid, prevOp.Hash)

		// Assume that the timeout tx doesn't spend an output of exactly
		// the size of the anchor.
		if closeTx.TxOut[prevOp.Index].Value != anchorSize {
			hash := tx.TxHash()
			htlcTimeout = &hash
		}
	}
	require.NotNil(t.t, htlcTimeout)

	// We'll mine the remaining blocks in order to generate the sweep
	// transaction of Bob's commitment output. The commitment was just
	// mined at the current tip and the sweep will be broadcast so it can
	// be mined at the tip+defaultCSV'th block, so mine one less to be able
	// to make mempool assertions.
	mineBlocks(t, net, defaultCSV-1, expectedTxes)

	// Check that the sweep spends from the mined commitment.
	txes, err = getNTxsFromMempool(net.Miner.Client, 1, minerMempoolTimeout)
	require.NoError(t.t, err)
	assertAllTxesSpendFrom(t, txes, closeTxid)

	// Bob's pending channel report should show that he has a commitment
	// output awaiting sweeping, and also that there's an outgoing HTLC
	// output pending.
	pendingChansRequest := &lnrpc.PendingChannelsRequest{}
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	pendingChanResp, err := bob.PendingChannels(ctxt, pendingChansRequest)
	require.NoError(t.t, err)

	require.NotZero(t.t, len(pendingChanResp.PendingForceClosingChannels))
	forceCloseChan := pendingChanResp.PendingForceClosingChannels[0]
	require.NotZero(t.t, forceCloseChan.LimboBalance)
	require.NotZero(t.t, len(forceCloseChan.PendingHtlcs))

	// Mine a block to confirm Bob's commit sweep tx and assert it was in
	// fact mined.
	block := mineBlocks(t, net, 1, 1)[0]
	commitSweepTxid := txes[0].TxHash()
	assertTxInBlock(t, block, &commitSweepTxid)

	// Mine an additional block to prompt Bob to broadcast their second
	// layer sweep due to the CSV on the HTLC timeout output.
	mineBlocks(t, net, 1, 0)
	assertSpendingTxInMempool(
		t, net.Miner.Client, minerMempoolTimeout, wire.OutPoint{
			Hash:  *htlcTimeout,
			Index: 0,
		},
	)

	// The block should have confirmed Bob's HTLC timeout transaction.
	// Therefore, at this point, there should be no active HTLC's on the
	// commitment transaction from Alice -> Bob.
	nodes = []*lntest.HarnessNode{alice}
	err = wait.NoError(func() error {
		return assertNumActiveHtlcs(nodes, 0)
	}, defaultTimeout)
	require.NoError(t.t, err)

	// At this point, Bob should show that the pending HTLC has advanced to
	// the second stage and is to be swept.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	pendingChanResp, err = bob.PendingChannels(ctxt, pendingChansRequest)
	require.NoError(t.t, err)
	forceCloseChan = pendingChanResp.PendingForceClosingChannels[0]
	require.Equal(t.t, uint32(2), forceCloseChan.PendingHtlcs[0].Stage)

	// Next, we'll mine a final block that should confirm the second-layer
	// sweeping transaction.
	_, err = net.Miner.Client.Generate(1)
	require.NoError(t.t, err)

	// Once this transaction has been confirmed, Bob should detect that he
	// no longer has any pending channels.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForNumChannelPendingForceClose(ctxt, bob, 0, nil)
	require.NoError(t.t, err)

	// Coop close channel, expect no anchors.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssertType(
		ctxt, t, net, alice, aliceChanPoint, false, false,
	)
}
