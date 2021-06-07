package itest

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/stretchr/testify/require"
)

// testPsbtChanFunding makes sure a channel can be opened between carol and dave
// by using a Partially Signed Bitcoin Transaction that funds the channel
// multisig funding output.
func testPsbtChanFunding(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()
	const chanSize = funding.MaxBtcFundingAmount

	// First, we'll create two new nodes that we'll use to open channels
	// between for this test. Dave gets some coins that will be used to
	// fund the PSBT, just to make sure that Carol has an empty wallet.
	carol, err := net.NewNode("carol", nil)
	require.NoError(t.t, err)
	defer shutdownAndAssert(net, t, carol)

	dave, err := net.NewNode("dave", nil)
	require.NoError(t.t, err)
	defer shutdownAndAssert(net, t, dave)
	err = net.SendCoins(ctxb, btcutil.SatoshiPerBitcoin, dave)
	if err != nil {
		t.Fatalf("unable to send coins to dave: %v", err)
	}

	// Before we start the test, we'll ensure both sides are connected so
	// the funding flow can be properly executed.
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	err = net.EnsureConnected(ctxt, carol, dave)
	require.NoError(t.t, err)
	err = net.EnsureConnected(ctxt, carol, net.Alice)
	require.NoError(t.t, err)

	// At this point, we can begin our PSBT channel funding workflow. We'll
	// start by generating a pending channel ID externally that will be used
	// to track this new funding type.
	var pendingChanID [32]byte
	_, err = rand.Read(pendingChanID[:])
	require.NoError(t.t, err)

	// We'll also test batch funding of two channels so we need another ID.
	var pendingChanID2 [32]byte
	_, err = rand.Read(pendingChanID2[:])
	require.NoError(t.t, err)

	// Now that we have the pending channel ID, Carol will open the channel
	// by specifying a PSBT shim. We use the NoPublish flag here to avoid
	// publishing the whole batch TX too early.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	chanUpdates, tempPsbt, err := openChannelPsbt(
		ctxt, carol, dave, lntest.OpenChannelParams{
			Amt: chanSize,
			FundingShim: &lnrpc.FundingShim{
				Shim: &lnrpc.FundingShim_PsbtShim{
					PsbtShim: &lnrpc.PsbtShim{
						PendingChanId: pendingChanID[:],
						NoPublish:     true,
					},
				},
			},
		},
	)
	require.NoError(t.t, err)

	// Let's add a second channel to the batch. This time between Carol and
	// Alice. We will publish the batch TX once this channel funding is
	// complete.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	chanUpdates2, psbtBytes2, err := openChannelPsbt(
		ctxt, carol, net.Alice, lntest.OpenChannelParams{
			Amt: chanSize,
			FundingShim: &lnrpc.FundingShim{
				Shim: &lnrpc.FundingShim_PsbtShim{
					PsbtShim: &lnrpc.PsbtShim{
						PendingChanId: pendingChanID2[:],
						NoPublish:     false,
						BasePsbt:      tempPsbt,
					},
				},
			},
		},
	)
	require.NoError(t.t, err)

	// We'll now ask Dave's wallet to fund the PSBT for us. This will return
	// a packet with inputs and outputs set but without any witness data.
	// This is exactly what we need for the next step.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	fundReq := &walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_Psbt{
			Psbt: psbtBytes2,
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
	}
	fundResp, err := dave.WalletKitClient.FundPsbt(ctxt, fundReq)
	require.NoError(t.t, err)

	// We have a PSBT that has no witness data yet, which is exactly what we
	// need for the next step: Verify the PSBT with the funding intents.
	_, err = carol.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtVerify{
			PsbtVerify: &lnrpc.FundingPsbtVerify{
				PendingChanId: pendingChanID[:],
				FundedPsbt:    fundResp.FundedPsbt,
			},
		},
	})
	require.NoError(t.t, err)
	_, err = carol.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtVerify{
			PsbtVerify: &lnrpc.FundingPsbtVerify{
				PendingChanId: pendingChanID2[:],
				FundedPsbt:    fundResp.FundedPsbt,
			},
		},
	})
	require.NoError(t.t, err)

	// Now we'll ask Dave's wallet to sign the PSBT so we can finish the
	// funding flow.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	finalizeReq := &walletrpc.FinalizePsbtRequest{
		FundedPsbt: fundResp.FundedPsbt,
	}
	finalizeRes, err := dave.WalletKitClient.FinalizePsbt(ctxt, finalizeReq)
	require.NoError(t.t, err)

	// We've signed our PSBT now, let's pass it to the intent again.
	_, err = carol.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtFinalize{
			PsbtFinalize: &lnrpc.FundingPsbtFinalize{
				PendingChanId: pendingChanID[:],
				SignedPsbt:    finalizeRes.SignedPsbt,
			},
		},
	})
	require.NoError(t.t, err)

	// Consume the "channel pending" update. This waits until the funding
	// transaction was fully compiled.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	updateResp, err := receiveChanUpdate(ctxt, chanUpdates)
	require.NoError(t.t, err)
	upd, ok := updateResp.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	require.True(t.t, ok)
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: upd.ChanPending.Txid,
		},
		OutputIndex: upd.ChanPending.OutputIndex,
	}

	// No transaction should have been published yet.
	mempool, err := net.Miner.Client.GetRawMempool()
	require.NoError(t.t, err)
	require.Equal(t.t, 0, len(mempool))

	// Let's progress the second channel now. This time we'll use the raw
	// wire format transaction directly.
	require.NoError(t.t, err)
	_, err = carol.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtFinalize{
			PsbtFinalize: &lnrpc.FundingPsbtFinalize{
				PendingChanId: pendingChanID2[:],
				FinalRawTx:    finalizeRes.RawFinalTx,
			},
		},
	})
	require.NoError(t.t, err)

	// Consume the "channel pending" update for the second channel. This
	// waits until the funding transaction was fully compiled and in this
	// case published.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	updateResp2, err := receiveChanUpdate(ctxt, chanUpdates2)
	require.NoError(t.t, err)
	upd2, ok := updateResp2.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	require.True(t.t, ok)
	chanPoint2 := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: upd2.ChanPending.Txid,
		},
		OutputIndex: upd2.ChanPending.OutputIndex,
	}

	// Great, now we can mine a block to get the transaction confirmed, then
	// wait for the new channel to be propagated through the network.
	var finalTx wire.MsgTx
	err = finalTx.Deserialize(bytes.NewReader(finalizeRes.RawFinalTx))
	require.NoError(t.t, err)

	txHash := finalTx.TxHash()
	block := mineBlocks(t, net, 6, 1)[0]
	assertTxInBlock(t, block, &txHash)
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint2)
	require.NoError(t.t, err)

	// With the channel open, ensure that it is counted towards Carol's
	// total channel balance.
	balReq := &lnrpc.ChannelBalanceRequest{}
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	balRes, err := carol.ChannelBalance(ctxt, balReq)
	require.NoError(t.t, err)
	require.NotEqual(t.t, int64(0), balRes.LocalBalance.Sat)

	// Next, to make sure the channel functions as normal, we'll make some
	// payments within the channel.
	payAmt := btcutil.Amount(100000)
	invoice := &lnrpc.Invoice{
		Memo:  "new chans",
		Value: int64(payAmt),
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := dave.AddInvoice(ctxt, invoice)
	require.NoError(t.t, err)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient, []string{resp.PaymentRequest},
		true,
	)
	require.NoError(t.t, err)

	// To conclude, we'll close the newly created channel between Carol and
	// Dave. This function will also block until the channel is closed and
	// will additionally assert the relevant channel closing post
	// conditions.
	ctxt, cancel = context.WithTimeout(ctxb, channelCloseTimeout)
	defer cancel()
	closeChannelAndAssert(ctxt, t, net, carol, chanPoint, false)
}

// testPsbtChanFundingExternal makes sure a channel can be opened between carol
// and dave by using a Partially Signed Bitcoin Transaction that funds the
// channel multisig funding output and is fully funded by an external third
// party.
func testPsbtChanFundingExternal(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()
	const chanSize = funding.MaxBtcFundingAmount

	// First, we'll create two new nodes that we'll use to open channels
	// between for this test. Both these nodes have an empty wallet as Alice
	// will be funding the channel.
	carol, err := net.NewNode("carol", nil)
	require.NoError(t.t, err)
	defer shutdownAndAssert(net, t, carol)

	dave, err := net.NewNode("dave", nil)
	require.NoError(t.t, err)
	defer shutdownAndAssert(net, t, dave)

	// Before we start the test, we'll ensure both sides are connected so
	// the funding flow can be properly executed.
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	err = net.EnsureConnected(ctxt, carol, dave)
	require.NoError(t.t, err)
	err = net.EnsureConnected(ctxt, carol, net.Alice)
	require.NoError(t.t, err)

	// At this point, we can begin our PSBT channel funding workflow. We'll
	// start by generating a pending channel ID externally that will be used
	// to track this new funding type.
	var pendingChanID [32]byte
	_, err = rand.Read(pendingChanID[:])
	require.NoError(t.t, err)

	// We'll also test batch funding of two channels so we need another ID.
	var pendingChanID2 [32]byte
	_, err = rand.Read(pendingChanID2[:])
	require.NoError(t.t, err)

	// Now that we have the pending channel ID, Carol will open the channel
	// by specifying a PSBT shim. We use the NoPublish flag here to avoid
	// publishing the whole batch TX too early.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	chanUpdates, tempPsbt, err := openChannelPsbt(
		ctxt, carol, dave, lntest.OpenChannelParams{
			Amt: chanSize,
			FundingShim: &lnrpc.FundingShim{
				Shim: &lnrpc.FundingShim_PsbtShim{
					PsbtShim: &lnrpc.PsbtShim{
						PendingChanId: pendingChanID[:],
						NoPublish:     true,
					},
				},
			},
		},
	)
	require.NoError(t.t, err)

	// Let's add a second channel to the batch. This time between Carol and
	// Alice. We will publish the batch TX once this channel funding is
	// complete.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	chanUpdates2, psbtBytes2, err := openChannelPsbt(
		ctxt, carol, net.Alice, lntest.OpenChannelParams{
			Amt: chanSize,
			FundingShim: &lnrpc.FundingShim{
				Shim: &lnrpc.FundingShim_PsbtShim{
					PsbtShim: &lnrpc.PsbtShim{
						PendingChanId: pendingChanID2[:],
						NoPublish:     true,
						BasePsbt:      tempPsbt,
					},
				},
			},
		},
	)
	require.NoError(t.t, err)

	// We'll now ask Alice's wallet to fund the PSBT for us. This will
	// return a packet with inputs and outputs set but without any witness
	// data. This is exactly what we need for the next step.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	fundReq := &walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_Psbt{
			Psbt: psbtBytes2,
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
	}
	fundResp, err := net.Alice.WalletKitClient.FundPsbt(ctxt, fundReq)
	require.NoError(t.t, err)

	// We have a PSBT that has no witness data yet, which is exactly what we
	// need for the next step: Verify the PSBT with the funding intents.
	// We tell the PSBT intent to skip the finalize step because we know the
	// final transaction will not be broadcast by Carol herself but by
	// Alice. And we assume that Alice is a third party that is not in
	// direct communication with Carol and won't send the signed TX to her
	// before broadcasting it. So we cannot call the finalize step but
	// instead just tell lnd to wait for a TX to be published/confirmed.
	_, err = carol.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtVerify{
			PsbtVerify: &lnrpc.FundingPsbtVerify{
				PendingChanId: pendingChanID[:],
				FundedPsbt:    fundResp.FundedPsbt,
				SkipFinalize:  true,
			},
		},
	})
	require.NoError(t.t, err)
	_, err = carol.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtVerify{
			PsbtVerify: &lnrpc.FundingPsbtVerify{
				PendingChanId: pendingChanID2[:],
				FundedPsbt:    fundResp.FundedPsbt,
				SkipFinalize:  true,
			},
		},
	})
	require.NoError(t.t, err)

	// Consume the "channel pending" update. This waits until the funding
	// transaction was fully compiled for both channels.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	updateResp, err := receiveChanUpdate(ctxt, chanUpdates)
	require.NoError(t.t, err)
	upd, ok := updateResp.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	require.True(t.t, ok)
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: upd.ChanPending.Txid,
		},
		OutputIndex: upd.ChanPending.OutputIndex,
	}
	updateResp2, err := receiveChanUpdate(ctxt, chanUpdates2)
	require.NoError(t.t, err)
	upd2, ok := updateResp2.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	require.True(t.t, ok)
	chanPoint2 := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: upd2.ChanPending.Txid,
		},
		OutputIndex: upd2.ChanPending.OutputIndex,
	}
	numPending, err := numOpenChannelsPending(ctxt, carol)
	require.NoError(t.t, err)
	require.Equal(t.t, 2, numPending)

	// Now we'll ask Alice's wallet to sign the PSBT so we can finish the
	// funding flow.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	finalizeReq := &walletrpc.FinalizePsbtRequest{
		FundedPsbt: fundResp.FundedPsbt,
	}
	finalizeRes, err := net.Alice.WalletKitClient.FinalizePsbt(
		ctxt, finalizeReq,
	)
	require.NoError(t.t, err)

	// No transaction should have been published yet.
	mempool, err := net.Miner.Client.GetRawMempool()
	require.NoError(t.t, err)
	require.Equal(t.t, 0, len(mempool))

	// Great, now let's publish the final raw transaction.
	var finalTx wire.MsgTx
	err = finalTx.Deserialize(bytes.NewReader(finalizeRes.RawFinalTx))
	require.NoError(t.t, err)

	txHash := finalTx.TxHash()
	_, err = net.Miner.Client.SendRawTransaction(&finalTx, false)
	require.NoError(t.t, err)

	// Now we can mine a block to get the transaction confirmed, then wait
	// for the new channel to be propagated through the network.
	block := mineBlocks(t, net, 6, 1)[0]
	assertTxInBlock(t, block, &txHash)
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint2)
	require.NoError(t.t, err)

	// With the channel open, ensure that it is counted towards Carol's
	// total channel balance.
	balReq := &lnrpc.ChannelBalanceRequest{}
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	balRes, err := carol.ChannelBalance(ctxt, balReq)
	require.NoError(t.t, err)
	require.NotEqual(t.t, int64(0), balRes.LocalBalance.Sat)

	// Next, to make sure the channel functions as normal, we'll make some
	// payments within the channel.
	payAmt := btcutil.Amount(100000)
	invoice := &lnrpc.Invoice{
		Memo:  "new chans",
		Value: int64(payAmt),
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := dave.AddInvoice(ctxt, invoice)
	require.NoError(t.t, err)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient, []string{resp.PaymentRequest},
		true,
	)
	require.NoError(t.t, err)

	// To conclude, we'll close the newly created channel between Carol and
	// Dave. This function will also block until the channels are closed and
	// will additionally assert the relevant channel closing post
	// conditions.
	ctxt, cancel = context.WithTimeout(ctxb, channelCloseTimeout)
	defer cancel()
	closeChannelAndAssert(ctxt, t, net, carol, chanPoint, false)
	closeChannelAndAssert(ctxt, t, net, carol, chanPoint2, false)
}

// openChannelPsbt attempts to open a channel between srcNode and destNode with
// the passed channel funding parameters. If the passed context has a timeout,
// then if the timeout is reached before the channel pending notification is
// received, an error is returned. An error is returned if the expected step
// of funding the PSBT is not received from the source node.
func openChannelPsbt(ctx context.Context, srcNode, destNode *lntest.HarnessNode,
	p lntest.OpenChannelParams) (lnrpc.Lightning_OpenChannelClient, []byte,
	error) {

	// Wait until srcNode and destNode have the latest chain synced.
	// Otherwise, we may run into a check within the funding manager that
	// prevents any funding workflows from being kicked off if the chain
	// isn't yet synced.
	if err := srcNode.WaitForBlockchainSync(ctx); err != nil {
		return nil, nil, fmt.Errorf("unable to sync srcNode chain: %v",
			err)
	}
	if err := destNode.WaitForBlockchainSync(ctx); err != nil {
		return nil, nil, fmt.Errorf("unable to sync destNode chain: %v",
			err)
	}

	// Send the request to open a channel to the source node now. This will
	// open a long-lived stream where we'll receive status updates about the
	// progress of the channel.
	respStream, err := srcNode.OpenChannel(ctx, &lnrpc.OpenChannelRequest{
		NodePubkey:         destNode.PubKey[:],
		LocalFundingAmount: int64(p.Amt),
		PushSat:            int64(p.PushAmt),
		Private:            p.Private,
		SpendUnconfirmed:   p.SpendUnconfirmed,
		MinHtlcMsat:        int64(p.MinHtlc),
		FundingShim:        p.FundingShim,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open channel between "+
			"source and dest: %v", err)
	}

	// Consume the "PSBT funding ready" update. This waits until the node
	// notifies us that the PSBT can now be funded.
	resp, err := receiveChanUpdate(ctx, respStream)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to consume channel update "+
			"message: %v", err)
	}
	upd, ok := resp.Update.(*lnrpc.OpenStatusUpdate_PsbtFund)
	if !ok {
		return nil, nil, fmt.Errorf("expected PSBT funding update, "+
			"instead got %v", resp)
	}
	return respStream, upd.PsbtFund.Psbt, nil
}

// receiveChanUpdate waits until a message is received on the stream or the
// context is canceled. The context must have a timeout or must be canceled
// in case no message is received, otherwise this function will block forever.
func receiveChanUpdate(ctx context.Context,
	stream lnrpc.Lightning_OpenChannelClient) (*lnrpc.OpenStatusUpdate,
	error) {

	chanMsg := make(chan *lnrpc.OpenStatusUpdate)
	errChan := make(chan error)
	go func() {
		// Consume one message. This will block until the message is
		// received.
		resp, err := stream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		chanMsg <- resp
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before chan pending " +
			"update sent")

	case err := <-errChan:
		return nil, err

	case updateMsg := <-chanMsg:
		return updateMsg, nil
	}
}
