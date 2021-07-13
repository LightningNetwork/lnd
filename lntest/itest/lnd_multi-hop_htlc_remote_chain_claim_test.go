package itest

import (
	"context"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
)

// testMultiHopHtlcRemoteChainClaim tests that in the multi-hop HTLC scenario,
// if the remote party goes to chain while we have an incoming HTLC, then when
// we found out the preimage via the witness beacon, we properly settle the
// HTLC directly on-chain using the preimage in order to ensure that we don't
// lose any funds.
func testMultiHopHtlcRemoteChainClaim(net *lntest.NetworkHarness, t *harnessTest,
	alice, bob *lntest.HarnessNode, c lnrpc.CommitmentType) {

	ctxb := context.Background()

	// First, we'll create a three hop network: Alice -> Bob -> Carol, with
	// Carol refusing to actually settle or directly cancel any HTLC's
	// self.
	aliceChanPoint, bobChanPoint, carol := createThreeHopNetwork(
		t, net, alice, bob, false, c,
	)

	// Clean up carol's node when the test finishes.
	defer shutdownAndAssert(net, t, carol)

	// With the network active, we'll now add a new hodl invoice at Carol's
	// end. Make sure the cltv expiry delta is large enough, otherwise Bob
	// won't send out the outgoing htlc.
	const invoiceAmt = 100000
	preimage := lntypes.Preimage{1, 2, 5}
	payHash := preimage.Hash()
	invoiceReq := &invoicesrpc.AddHoldInvoiceRequest{
		Value:      invoiceAmt,
		CltvExpiry: 40,
		Hash:       payHash[:],
	}
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	carolInvoice, err := carol.AddHoldInvoice(ctxt, invoiceReq)
	require.NoError(t.t, err)

	// Now that we've created the invoice, we'll send a single payment from
	// Alice to Carol. We won't wait for the response however, as Carol
	// will not immediately settle the payment.
	ctx, cancel := context.WithCancel(ctxb)
	defer cancel()

	_, err = alice.RouterClient.SendPaymentV2(
		ctx, &routerrpc.SendPaymentRequest{
			PaymentRequest: carolInvoice.PaymentRequest,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
		},
	)
	require.NoError(t.t, err)

	// At this point, all 3 nodes should now have an active channel with
	// the created HTLC pending on all of them.
	nodes := []*lntest.HarnessNode{alice, bob, carol}
	err = wait.NoError(func() error {
		return assertActiveHtlcs(nodes, payHash[:])
	}, defaultTimeout)
	require.NoError(t.t, err)

	// Wait for carol to mark invoice as accepted. There is a small gap to
	// bridge between adding the htlc to the channel and executing the exit
	// hop logic.
	waitForInvoiceAccepted(t, carol, payHash)

	// Increase the fee estimate so that the following force close tx will
	// be cpfp'ed.
	net.SetFeeEstimate(30000)

	// Next, Alice decides that she wants to exit the channel, so she'll
	// immediately force close the channel by broadcast her commitment
	// transaction.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	aliceForceClose := closeChannelAndAssertType(
		ctxt, t, net, alice, aliceChanPoint,
		c == lnrpc.CommitmentType_ANCHORS, true,
	)

	// Wait for the channel to be marked pending force close.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForChannelPendingForceClose(ctxt, alice, aliceChanPoint)
	require.NoError(t.t, err)

	// After closeChannelAndAssertType returns, it has mined a block so now
	// bob will attempt to redeem his anchor commitment (if the channel
	// type is of that type).
	if c == lnrpc.CommitmentType_ANCHORS {
		_, err = waitForNTxsInMempool(
			net.Miner.Client, 1, minerMempoolTimeout,
		)
		if err != nil {
			t.Fatalf("unable to find bob's anchor commit sweep: %v",
				err)
		}
	}

	// Mine enough blocks for Alice to sweep her funds from the force
	// closed channel. closeChannelAndAssertType() already mined a block
	// containing the commitment tx and the commit sweep tx will be
	// broadcast immediately before it can be included in a block, so mine
	// one less than defaultCSV in order to perform mempool assertions.
	_, err = net.Miner.Client.Generate(defaultCSV - 1)
	require.NoError(t.t, err)

	// Alice should now sweep her funds.
	_, err = waitForNTxsInMempool(
		net.Miner.Client, 1, minerMempoolTimeout,
	)
	require.NoError(t.t, err)

	// Suspend bob, so Carol is forced to go on chain.
	restartBob, err := net.SuspendNode(bob)
	require.NoError(t.t, err)

	// Settle invoice. This will just mark the invoice as settled, as there
	// is no link anymore to remove the htlc from the commitment tx. For
	// this test, it is important to actually settle and not leave the
	// invoice in the accepted state, because without a known preimage, the
	// channel arbitrator won't go to chain.
	ctx, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	_, err = carol.SettleInvoice(ctx, &invoicesrpc.SettleInvoiceMsg{
		Preimage: preimage[:],
	})
	require.NoError(t.t, err)

	// We'll now mine enough blocks so Carol decides that she needs to go
	// on-chain to claim the HTLC as Bob has been inactive.
	numBlocks := padCLTV(uint32(
		invoiceReq.CltvExpiry-lncfg.DefaultIncomingBroadcastDelta,
	) - defaultCSV)

	_, err = net.Miner.Client.Generate(numBlocks)
	require.NoError(t.t, err)

	expectedTxes := 1
	if c == lnrpc.CommitmentType_ANCHORS {
		expectedTxes = 2
	}

	// Carol's commitment transaction should now be in the mempool. If
	// there are anchors, Carol also sweeps her anchor.
	_, err = waitForNTxsInMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(t.t, err)
	bobFundingTxid, err := lnrpc.GetChanPointFundingTxid(bobChanPoint)
	require.NoError(t.t, err)
	carolFundingPoint := wire.OutPoint{
		Hash:  *bobFundingTxid,
		Index: bobChanPoint.OutputIndex,
	}

	// The closing transaction should be spending from the funding
	// transaction.
	closingTx := getSpendingTxInMempool(
		t, net.Miner.Client, minerMempoolTimeout, carolFundingPoint,
	)
	closingTxid := closingTx.TxHash()

	// Mine a block, which should contain: the commitment, possibly an
	// anchor sweep and the coinbase tx.
	block := mineBlocks(t, net, 1, expectedTxes)[0]
	require.Len(t.t, block.Transactions, expectedTxes+1)
	assertTxInBlock(t, block, &closingTxid)

	// Restart bob again.
	err = restartBob()
	require.NoError(t.t, err)

	// After the force close transacion is mined, Carol should broadcast her
	// second level HTLC transacion. Bob will broadcast a sweep tx to sweep
	// his output in the channel with Carol. He can do this immediately, as
	// the output is not timelocked since Carol was the one force closing.
	// If there are anchors, Bob should also sweep his.
	expectedTxes = 2
	if c == lnrpc.CommitmentType_ANCHORS {
		expectedTxes = 3
	}
	txes, err := getNTxsFromMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(t.t, err)

	// All transactions should be pending from the commitment transaction.
	assertAllTxesSpendFrom(t, txes, closingTxid)

	// Mine a block to confirm the two transactions (+ coinbase).
	block = mineBlocks(t, net, 1, expectedTxes)[0]
	require.Len(t.t, block.Transactions, expectedTxes+1)

	// Keep track of the second level tx maturity.
	carolSecondLevelCSV := uint32(defaultCSV)

	// When Bob notices Carol's second level transaction in the block, he
	// will extract the preimage and broadcast a sweep tx to directly claim
	// the HTLC in his (already closed) channel with Alice.
	bobHtlcSweep, err := waitForTxInMempool(
		net.Miner.Client, minerMempoolTimeout,
	)
	require.NoError(t.t, err)

	// It should spend from the commitment in the channel with Alice.
	tx, err := net.Miner.Client.GetRawTransaction(bobHtlcSweep)
	require.NoError(t.t, err)
	require.Equal(
		t.t, *aliceForceClose, tx.MsgTx().TxIn[0].PreviousOutPoint.Hash,
	)

	// We'll now mine a block which should confirm Bob's HTLC sweep
	// transaction.
	block = mineBlocks(t, net, 1, 1)[0]
	require.Len(t.t, block.Transactions, 2)
	assertTxInBlock(t, block, bobHtlcSweep)
	carolSecondLevelCSV--

	// Now that the sweeping transaction has been confirmed, Bob should now
	// recognize that all contracts have been fully resolved, and show no
	// pending close channels.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForNumChannelPendingForceClose(ctxt, bob, 0, nil)
	require.NoError(t.t, err)

	// If we then mine 3 additional blocks, Carol's second level tx will
	// mature, and she should pull the funds.
	_, err = net.Miner.Client.Generate(carolSecondLevelCSV)
	require.NoError(t.t, err)

	carolSweep, err := waitForTxInMempool(
		net.Miner.Client, minerMempoolTimeout,
	)
	require.NoError(t.t, err)

	// When Carol's sweep gets confirmed, she should have no more pending
	// channels.
	block = mineBlocks(t, net, 1, 1)[0]
	assertTxInBlock(t, block, carolSweep)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = waitForNumChannelPendingForceClose(ctxt, carol, 0, nil)
	require.NoError(t.t, err)

	// The invoice should show as settled for Carol, indicating that it was
	// swept on-chain.
	invoicesReq := &lnrpc.ListInvoiceRequest{}
	invoicesResp, err := carol.ListInvoices(ctxb, invoicesReq)
	require.NoError(t.t, err)
	require.Len(t.t, invoicesResp.Invoices, 1)
	invoice := invoicesResp.Invoices[0]
	require.Equal(t.t, lnrpc.Invoice_SETTLED, invoice.State)
	require.Equal(t.t, int64(invoiceAmt), invoice.AmtPaidSat)

	// Finally, check that the Alice's payment is correctly marked
	// succeeded.
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	err = checkPaymentStatus(
		ctxt, alice, preimage, lnrpc.Payment_SUCCEEDED,
	)
	require.NoError(t.t, err)
}
