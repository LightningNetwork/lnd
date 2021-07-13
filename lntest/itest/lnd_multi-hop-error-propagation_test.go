package itest

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lnwire"
)

func testHtlcErrorPropagation(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// In this test we wish to exercise the daemon's correct parsing,
	// handling, and propagation of errors that occur while processing a
	// multi-hop payment.
	const chanAmt = funding.MaxBtcFundingAmount

	// First establish a channel with a capacity of 0.5 BTC between Alice
	// and Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPointAlice); err != nil {
		t.Fatalf("channel not seen by alice before timeout: %v", err)
	}

	cType, err := channelCommitType(net.Alice, chanPointAlice)
	if err != nil {
		t.Fatalf("unable to get channel type: %v", err)
	}

	commitFee := calcStaticFee(cType, 0)
	assertBaseBalance := func() {
		// Alice has opened a channel with Bob with zero push amount, so
		// it's remote balance is zero.
		expBalanceAlice := &lnrpc.ChannelBalanceResponse{
			LocalBalance: &lnrpc.Amount{
				Sat: uint64(chanAmt - commitFee),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					chanAmt - commitFee,
				)),
			},
			RemoteBalance:            &lnrpc.Amount{},
			UnsettledLocalBalance:    &lnrpc.Amount{},
			UnsettledRemoteBalance:   &lnrpc.Amount{},
			PendingOpenLocalBalance:  &lnrpc.Amount{},
			PendingOpenRemoteBalance: &lnrpc.Amount{},
			// Deprecated fields.
			Balance: int64(chanAmt - commitFee),
		}
		assertChannelBalanceResp(t, net.Alice, expBalanceAlice)

		// Bob has a channel with Alice and another with Carol, so it's
		// local and remote balances are both chanAmt - commitFee.
		expBalanceBob := &lnrpc.ChannelBalanceResponse{
			LocalBalance: &lnrpc.Amount{
				Sat: uint64(chanAmt - commitFee),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					chanAmt - commitFee,
				)),
			},
			RemoteBalance: &lnrpc.Amount{
				Sat: uint64(chanAmt - commitFee),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					chanAmt - commitFee,
				)),
			},
			UnsettledLocalBalance:    &lnrpc.Amount{},
			UnsettledRemoteBalance:   &lnrpc.Amount{},
			PendingOpenLocalBalance:  &lnrpc.Amount{},
			PendingOpenRemoteBalance: &lnrpc.Amount{},
			// Deprecated fields.
			Balance: int64(chanAmt - commitFee),
		}
		assertChannelBalanceResp(t, net.Bob, expBalanceBob)
	}

	// Since we'd like to test some multi-hop failure scenarios, we'll
	// introduce another node into our test network: Carol.
	carol := net.NewNode(t.t, "Carol", nil)

	// Next, we'll create a connection from Bob to Carol, and open a
	// channel between them so we have the topology: Alice -> Bob -> Carol.
	// The channel created will be of lower capacity that the one created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Bob, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	const bobChanAmt = funding.MaxBtcFundingAmount
	chanPointBob := openChannelAndAssert(
		ctxt, t, net, net.Bob, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Ensure that Alice has Carol in her routing table before proceeding.
	nodeInfoReq := &lnrpc.NodeInfoRequest{
		PubKey: carol.PubKeyStr,
	}
	checkTableTimeout := time.After(time.Second * 10)
	checkTableTicker := time.NewTicker(100 * time.Millisecond)
	defer checkTableTicker.Stop()

out:
	// TODO(roasbeef): make into async hook for node announcements
	for {
		select {
		case <-checkTableTicker.C:
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			_, err := net.Alice.GetNodeInfo(ctxt, nodeInfoReq)
			if err != nil && strings.Contains(err.Error(),
				"unable to find") {

				continue
			}

			break out
		case <-checkTableTimeout:
			t.Fatalf("carol's node announcement didn't propagate within " +
				"the timeout period")
		}
	}

	// With the channels, open we can now start to test our multi-hop error
	// scenarios. First, we'll generate an invoice from carol that we'll
	// use to test some error cases.
	const payAmt = 10000
	invoiceReq := &lnrpc.Invoice{
		Memo:  "kek99",
		Value: payAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolInvoice, err := carol.AddInvoice(ctxt, invoiceReq)
	if err != nil {
		t.Fatalf("unable to generate carol invoice: %v", err)
	}

	carolPayReq, err := carol.DecodePayReq(ctxb,
		&lnrpc.PayReqString{
			PayReq: carolInvoice.PaymentRequest,
		})
	if err != nil {
		t.Fatalf("unable to decode generated payment request: %v", err)
	}

	// Before we send the payment, ensure that the announcement of the new
	// channel has been processed by Alice.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPointBob); err != nil {
		t.Fatalf("channel not seen by alice before timeout: %v", err)
	}

	// Before we start sending payments, subscribe to htlc events for each
	// node.
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	aliceEvents, err := net.Alice.RouterClient.SubscribeHtlcEvents(
		ctxt, &routerrpc.SubscribeHtlcEventsRequest{},
	)
	if err != nil {
		t.Fatalf("could not subscribe events: %v", err)
	}

	bobEvents, err := net.Bob.RouterClient.SubscribeHtlcEvents(
		ctxt, &routerrpc.SubscribeHtlcEventsRequest{},
	)
	if err != nil {
		t.Fatalf("could not subscribe events: %v", err)
	}

	carolEvents, err := carol.RouterClient.SubscribeHtlcEvents(
		ctxt, &routerrpc.SubscribeHtlcEventsRequest{},
	)
	if err != nil {
		t.Fatalf("could not subscribe events: %v", err)
	}

	// For the first scenario, we'll test the cancellation of an HTLC with
	// an unknown payment hash.
	// TODO(roasbeef): return failure response rather than failing entire
	// stream on payment error.
	sendReq := &routerrpc.SendPaymentRequest{
		PaymentHash:    makeFakePayHash(t),
		Dest:           carol.PubKey[:],
		Amt:            payAmt,
		FinalCltvDelta: int32(carolPayReq.CltvExpiry),
		TimeoutSeconds: 60,
		FeeLimitMsat:   noFeeLimitMsat,
		MaxParts:       1,
	}
	sendAndAssertFailure(
		t, net.Alice,
		sendReq, lnrpc.PaymentFailureReason_FAILURE_REASON_INCORRECT_PAYMENT_DETAILS,
	)
	assertLastHTLCError(
		t, net.Alice,
		lnrpc.Failure_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	)

	// We expect alice and bob to each have one forward and one forward
	// fail event at this stage.
	assertHtlcEvents(t, 1, 1, 0, routerrpc.HtlcEvent_SEND, aliceEvents)
	assertHtlcEvents(t, 1, 1, 0, routerrpc.HtlcEvent_FORWARD, bobEvents)

	// Carol should have a link failure because the htlc failed on her
	// incoming link.
	assertLinkFailure(
		t, routerrpc.HtlcEvent_RECEIVE,
		routerrpc.FailureDetail_UNKNOWN_INVOICE, carolEvents,
	)

	// The balances of all parties should be the same as initially since
	// the HTLC was canceled.
	assertBaseBalance()

	// Next, we'll test the case of a recognized payHash but, an incorrect
	// value on the extended HTLC.
	htlcAmt := lnwire.NewMSatFromSatoshis(1000)
	sendReq = &routerrpc.SendPaymentRequest{
		PaymentHash:    carolInvoice.RHash,
		Dest:           carol.PubKey[:],
		Amt:            int64(htlcAmt.ToSatoshis()), // 10k satoshis are expected.
		FinalCltvDelta: int32(carolPayReq.CltvExpiry),
		TimeoutSeconds: 60,
		FeeLimitMsat:   noFeeLimitMsat,
		MaxParts:       1,
	}
	sendAndAssertFailure(
		t, net.Alice,
		sendReq, lnrpc.PaymentFailureReason_FAILURE_REASON_INCORRECT_PAYMENT_DETAILS,
	)
	assertLastHTLCError(
		t, net.Alice,
		lnrpc.Failure_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	)

	// We expect alice and bob to each have one forward and one forward
	// fail event at this stage.
	assertHtlcEvents(t, 1, 1, 0, routerrpc.HtlcEvent_SEND, aliceEvents)
	assertHtlcEvents(t, 1, 1, 0, routerrpc.HtlcEvent_FORWARD, bobEvents)

	// Carol should have a link failure because the htlc failed on her
	// incoming link.
	assertLinkFailure(
		t, routerrpc.HtlcEvent_RECEIVE,
		routerrpc.FailureDetail_INVOICE_UNDERPAID, carolEvents,
	)

	// The balances of all parties should be the same as initially since
	// the HTLC was canceled.
	assertBaseBalance()

	// Next we'll test an error that occurs mid-route due to an outgoing
	// link having insufficient capacity. In order to do so, we'll first
	// need to unbalance the link connecting Bob<->Carol.
	//
	// To do so, we'll push most of the funds in the channel over to
	// Alice's side, leaving on 10k satoshis of available balance for bob.
	// There's a max payment amount, so we'll have to do this
	// incrementally.
	chanReserve := int64(chanAmt / 100)
	amtToSend := int64(chanAmt) - chanReserve - 20000
	amtSent := int64(0)
	for amtSent != amtToSend {
		// We'll send in chunks of the max payment amount. If we're
		// about to send too much, then we'll only send the amount
		// remaining.
		toSend := int64(math.MaxUint32)
		if toSend+amtSent > amtToSend {
			toSend = amtToSend - amtSent
		}

		invoiceReq = &lnrpc.Invoice{
			Value: toSend,
		}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		carolInvoice2, err := carol.AddInvoice(ctxt, invoiceReq)
		if err != nil {
			t.Fatalf("unable to generate carol invoice: %v", err)
		}

		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		sendAndAssertSuccess(
			ctxt, t, net.Bob,
			&routerrpc.SendPaymentRequest{
				PaymentRequest: carolInvoice2.PaymentRequest,
				TimeoutSeconds: 60,
				FeeLimitMsat:   noFeeLimitMsat,
				MaxParts:       1,
			},
		)

		// For each send bob makes, we need to check that bob has a
		// forward and settle event for his send, and carol has a
		// settle event for her receive.
		assertHtlcEvents(
			t, 1, 0, 1, routerrpc.HtlcEvent_SEND, bobEvents,
		)
		assertHtlcEvents(
			t, 0, 0, 1, routerrpc.HtlcEvent_RECEIVE, carolEvents,
		)

		amtSent += toSend
	}

	// At this point, Alice has 50mil satoshis on her side of the channel,
	// but Bob only has 10k available on his side of the channel. So a
	// payment from Alice to Carol worth 100k satoshis should fail.
	invoiceReq = &lnrpc.Invoice{
		Value: 100000,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolInvoice3, err := carol.AddInvoice(ctxt, invoiceReq)
	if err != nil {
		t.Fatalf("unable to generate carol invoice: %v", err)
	}

	sendReq = &routerrpc.SendPaymentRequest{
		PaymentRequest: carolInvoice3.PaymentRequest,
		TimeoutSeconds: 60,
		FeeLimitMsat:   noFeeLimitMsat,
		MaxParts:       1,
	}
	sendAndAssertFailure(
		t, net.Alice,
		sendReq, lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE,
	)
	assertLastHTLCError(
		t, net.Alice, lnrpc.Failure_TEMPORARY_CHANNEL_FAILURE,
	)

	// Alice should have a forwarding event and a forwarding failure.
	assertHtlcEvents(t, 1, 1, 0, routerrpc.HtlcEvent_SEND, aliceEvents)

	// Bob should have a link failure because the htlc failed on his
	// outgoing link.
	assertLinkFailure(
		t, routerrpc.HtlcEvent_FORWARD,
		routerrpc.FailureDetail_INSUFFICIENT_BALANCE, bobEvents,
	)

	// Generate new invoice to not pay same invoice twice.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolInvoice, err = carol.AddInvoice(ctxt, invoiceReq)
	if err != nil {
		t.Fatalf("unable to generate carol invoice: %v", err)
	}

	// For our final test, we'll ensure that if a target link isn't
	// available for what ever reason then the payment fails accordingly.
	//
	// We'll attempt to complete the original invoice we created with Carol
	// above, but before we do so, Carol will go offline, resulting in a
	// failed payment.
	shutdownAndAssert(net, t, carol)

	// Reset mission control to forget the temporary channel failure above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Alice.RouterClient.ResetMissionControl(
		ctxt, &routerrpc.ResetMissionControlRequest{},
	)
	if err != nil {
		t.Fatalf("unable to reset mission control: %v", err)
	}

	sendAndAssertFailure(
		t, net.Alice,
		&routerrpc.SendPaymentRequest{
			PaymentRequest: carolInvoice.PaymentRequest,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
			MaxParts:       1,
		},
		lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE,
	)
	assertLastHTLCError(t, net.Alice, lnrpc.Failure_UNKNOWN_NEXT_PEER)

	// Alice should have a forwarding event and subsequent fail.
	assertHtlcEvents(t, 1, 1, 0, routerrpc.HtlcEvent_SEND, aliceEvents)

	// Bob should have a link failure because he could not find the next
	// peer.
	assertLinkFailure(
		t, routerrpc.HtlcEvent_FORWARD,
		routerrpc.FailureDetail_NO_DETAIL, bobEvents,
	)

	// Finally, immediately close the channel. This function will also
	// block until the channel is closed and will additionally assert the
	// relevant channel closing post conditions.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)

	// Force close Bob's final channel.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPointBob, true)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, net.Bob, chanPointBob)
}

// assertLinkFailure checks that the stream provided has a single link failure
// the the failure detail provided.
func assertLinkFailure(t *harnessTest,
	eventType routerrpc.HtlcEvent_EventType,
	failureDetail routerrpc.FailureDetail,
	client routerrpc.Router_SubscribeHtlcEventsClient) {

	event := assertEventAndType(t, eventType, client)

	linkFail, ok := event.Event.(*routerrpc.HtlcEvent_LinkFailEvent)
	if !ok {
		t.Fatalf("expected forwarding failure, got: %T", linkFail)
	}

	if linkFail.LinkFailEvent.FailureDetail != failureDetail {
		t.Fatalf("expected: %v, got: %v", failureDetail,
			linkFail.LinkFailEvent.FailureDetail)
	}
}
