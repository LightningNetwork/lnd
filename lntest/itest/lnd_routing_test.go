package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type singleHopSendToRouteCase struct {
	name string

	// streaming tests streaming SendToRoute if true, otherwise tests
	// synchronous SenToRoute.
	streaming bool

	// routerrpc submits the request to the routerrpc subserver if true,
	// otherwise submits to the main rpc server.
	routerrpc bool
}

var singleHopSendToRouteCases = []singleHopSendToRouteCase{
	{
		name: "regular main sync",
	},
	{
		name:      "regular main stream",
		streaming: true,
	},
	{
		name:      "regular routerrpc sync",
		routerrpc: true,
	},
	{
		name: "mpp main sync",
	},
	{
		name:      "mpp main stream",
		streaming: true,
	},
	{
		name:      "mpp routerrpc sync",
		routerrpc: true,
	},
}

// testSingleHopSendToRoute tests that payments are properly processed through a
// provided route with a single hop. We'll create the following network
// topology:
//      Carol --100k--> Dave
// We'll query the daemon for routes from Carol to Dave and then send payments
// by feeding the route back into the various SendToRoute RPC methods. Here we
// test all three SendToRoute endpoints, forcing each to perform both a regular
// payment and an MPP payment.
func testSingleHopSendToRoute(net *lntest.NetworkHarness, t *harnessTest) {
	for _, test := range singleHopSendToRouteCases {
		test := test

		t.t.Run(test.name, func(t1 *testing.T) {
			ht := newHarnessTest(t1, t.lndHarness)
			ht.RunTestCase(&testCase{
				name: test.name,
				test: func(_ *lntest.NetworkHarness, tt *harnessTest) {
					testSingleHopSendToRouteCase(net, tt, test)
				},
			})
		})
	}
}

func testSingleHopSendToRouteCase(net *lntest.NetworkHarness, t *harnessTest,
	test singleHopSendToRouteCase) {

	const chanAmt = btcutil.Amount(100000)
	const paymentAmtSat = 1000
	const numPayments = 5
	const amountPaid = int64(numPayments * paymentAmtSat)

	ctxb := context.Background()
	var networkChans []*lnrpc.ChannelPoint

	// Create Carol and Dave, then establish a channel between them. Carol
	// is the sole funder of the channel with 100k satoshis. The network
	// topology should look like:
	// Carol -> 100k -> Dave
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	// Open a channel with 100k satoshis between Carol and Dave with Carol
	// being the sole funder of the channel.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
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
	nodes := []*lntest.HarnessNode{carol, dave}
	for _, chanPoint := range networkChans {
		for _, node := range nodes {
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
					"channel(%s) open: %v", node.Name(),
					node.NodeID, point, err)
			}
		}
	}

	// Create invoices for Dave, which expect a payment from Carol.
	payReqs, rHashes, _, err := createPayReqs(
		dave, paymentAmtSat, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Reconstruct payment addresses.
	var payAddrs [][]byte
	for _, payReq := range payReqs {
		ctx, _ := context.WithTimeout(
			context.Background(), defaultTimeout,
		)
		resp, err := dave.DecodePayReq(
			ctx,
			&lnrpc.PayReqString{PayReq: payReq},
		)
		if err != nil {
			t.Fatalf("decode pay req: %v", err)
		}
		payAddrs = append(payAddrs, resp.PaymentAddr)
	}

	// Assert Carol and Dave are synced to the chain before proceeding, to
	// ensure the queried route will have a valid final CLTV once the HTLC
	// reaches Dave.
	_, minerHeight, err := net.Miner.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("unable to get best height: %v", err)
	}
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	require.NoError(t.t, waitForNodeBlockHeight(ctxt, carol, minerHeight))
	require.NoError(t.t, waitForNodeBlockHeight(ctxt, dave, minerHeight))

	// Query for routes to pay from Carol to Dave using the default CLTV
	// config.
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey: dave.PubKeyStr,
		Amt:    paymentAmtSat,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	routes, err := carol.QueryRoutes(ctxt, routesReq)
	if err != nil {
		t.Fatalf("unable to get route from %s: %v",
			carol.Name(), err)
	}

	// There should only be one route to try, so take the first item.
	r := routes.Routes[0]

	// Construct a closure that will set MPP fields on the route, which
	// allows us to test MPP payments.
	setMPPFields := func(i int) {
		hop := r.Hops[len(r.Hops)-1]
		hop.TlvPayload = true
		hop.MppRecord = &lnrpc.MPPRecord{
			PaymentAddr:  payAddrs[i],
			TotalAmtMsat: paymentAmtSat * 1000,
		}
	}

	// Construct closures for each of the payment types covered:
	//  - main rpc server sync
	//  - main rpc server streaming
	//  - routerrpc server sync
	sendToRouteSync := func() {
		for i, rHash := range rHashes {
			setMPPFields(i)

			sendReq := &lnrpc.SendToRouteRequest{
				PaymentHash: rHash,
				Route:       r,
			}
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			resp, err := carol.SendToRouteSync(
				ctxt, sendReq,
			)
			if err != nil {
				t.Fatalf("unable to send to route for "+
					"%s: %v", carol.Name(), err)
			}
			if resp.PaymentError != "" {
				t.Fatalf("received payment error from %s: %v",
					carol.Name(), resp.PaymentError)
			}
		}
	}
	sendToRouteStream := func() {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		alicePayStream, err := carol.SendToRoute(ctxt) // nolint:staticcheck
		if err != nil {
			t.Fatalf("unable to create payment stream for "+
				"carol: %v", err)
		}

		for i, rHash := range rHashes {
			setMPPFields(i)

			sendReq := &lnrpc.SendToRouteRequest{
				PaymentHash: rHash,
				Route:       routes.Routes[0],
			}
			err := alicePayStream.Send(sendReq)

			if err != nil {
				t.Fatalf("unable to send payment: %v", err)
			}

			resp, err := alicePayStream.Recv()
			if err != nil {
				t.Fatalf("unable to send payment: %v", err)
			}
			if resp.PaymentError != "" {
				t.Fatalf("received payment error: %v",
					resp.PaymentError)
			}
		}
	}
	sendToRouteRouterRPC := func() {
		for i, rHash := range rHashes {
			setMPPFields(i)

			sendReq := &routerrpc.SendToRouteRequest{
				PaymentHash: rHash,
				Route:       r,
			}
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			resp, err := carol.RouterClient.SendToRouteV2(
				ctxt, sendReq,
			)
			if err != nil {
				t.Fatalf("unable to send to route for "+
					"%s: %v", carol.Name(), err)
			}
			if resp.Failure != nil {
				t.Fatalf("received payment error from %s: %v",
					carol.Name(), resp.Failure)
			}
		}
	}

	// Using Carol as the node as the source, send the payments
	// synchronously via the the routerrpc's SendToRoute, or via the main RPC
	// server's SendToRoute streaming or sync calls.
	switch {
	case !test.routerrpc && test.streaming:
		sendToRouteStream()
	case !test.routerrpc && !test.streaming:
		sendToRouteSync()
	case test.routerrpc && !test.streaming:
		sendToRouteRouterRPC()
	default:
		t.Fatalf("routerrpc does not support streaming send_to_route")
	}

	// Verify that the payment's from Carol's PoV have the correct payment
	// hash and amount.
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	paymentsResp, err := carol.ListPayments(
		ctxt, &lnrpc.ListPaymentsRequest{},
	)
	if err != nil {
		t.Fatalf("error when obtaining %s payments: %v",
			carol.Name(), err)
	}
	if len(paymentsResp.Payments) != numPayments {
		t.Fatalf("incorrect number of payments, got %v, want %v",
			len(paymentsResp.Payments), numPayments)
	}

	for i, p := range paymentsResp.Payments {
		// Assert that the payment hashes for each payment match up.
		rHashHex := hex.EncodeToString(rHashes[i])
		if p.PaymentHash != rHashHex {
			t.Fatalf("incorrect payment hash for payment %d, "+
				"want: %s got: %s",
				i, rHashHex, p.PaymentHash)
		}

		// Assert that each payment has no invoice since the payment was
		// completed using SendToRoute.
		if p.PaymentRequest != "" {
			t.Fatalf("incorrect payment request for payment: %d, "+
				"want: \"\", got: %s",
				i, p.PaymentRequest)
		}

		// Assert the payment amount is correct.
		if p.ValueSat != paymentAmtSat {
			t.Fatalf("incorrect payment amt for payment %d, "+
				"want: %d, got: %d",
				i, paymentAmtSat, p.ValueSat)
		}

		// Assert exactly one htlc was made.
		if len(p.Htlcs) != 1 {
			t.Fatalf("expected 1 htlc for payment %d, got: %d",
				i, len(p.Htlcs))
		}

		// Assert the htlc's route is populated.
		htlc := p.Htlcs[0]
		if htlc.Route == nil {
			t.Fatalf("expected route for payment %d", i)
		}

		// Assert the hop has exactly one hop.
		if len(htlc.Route.Hops) != 1 {
			t.Fatalf("expected 1 hop for payment %d, got: %d",
				i, len(htlc.Route.Hops))
		}

		// If this is an MPP test, assert the MPP record's fields are
		// properly populated. Otherwise the hop should not have an MPP
		// record.
		hop := htlc.Route.Hops[0]
		if hop.MppRecord == nil {
			t.Fatalf("expected mpp record for mpp payment")
		}

		if hop.MppRecord.TotalAmtMsat != paymentAmtSat*1000 {
			t.Fatalf("incorrect mpp total msat for payment %d "+
				"want: %d, got: %d",
				i, paymentAmtSat*1000,
				hop.MppRecord.TotalAmtMsat)
		}

		expAddr := payAddrs[i]
		if !bytes.Equal(hop.MppRecord.PaymentAddr, expAddr) {
			t.Fatalf("incorrect mpp payment addr for payment %d "+
				"want: %x, got: %x",
				i, expAddr, hop.MppRecord.PaymentAddr)
		}
	}

	// Verify that the invoices's from Dave's PoV have the correct payment
	// hash and amount.
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	invoicesResp, err := dave.ListInvoices(
		ctxt, &lnrpc.ListInvoiceRequest{},
	)
	if err != nil {
		t.Fatalf("error when obtaining %s payments: %v",
			dave.Name(), err)
	}
	if len(invoicesResp.Invoices) != numPayments {
		t.Fatalf("incorrect number of invoices, got %v, want %v",
			len(invoicesResp.Invoices), numPayments)
	}

	for i, inv := range invoicesResp.Invoices {
		// Assert that the payment hashes match up.
		if !bytes.Equal(inv.RHash, rHashes[i]) {
			t.Fatalf("incorrect payment hash for invoice %d, "+
				"want: %x got: %x",
				i, rHashes[i], inv.RHash)
		}

		// Assert that the amount paid to the invoice is correct.
		if inv.AmtPaidSat != paymentAmtSat {
			t.Fatalf("incorrect payment amt for invoice %d, "+
				"want: %d, got %d",
				i, paymentAmtSat, inv.AmtPaidSat)
		}
	}

	// At this point all the channels within our proto network should be
	// shifted by 5k satoshis in the direction of Dave, the sink within the
	// payment flow generated above. The order of asserts corresponds to
	// increasing of time is needed to embed the HTLC in commitment
	// transaction, in channel Carol->Dave, order is Dave and then Carol.
	assertAmountPaid(t, "Carol(local) => Dave(remote)", dave,
		carolFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Carol(local) => Dave(remote)", carol,
		carolFundPoint, amountPaid, int64(0))

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// testMultiHopSendToRoute tests that payments are properly processed
// through a provided route. We'll create the following network topology:
//      Alice --100k--> Bob --100k--> Carol
// We'll query the daemon for routes from Alice to Carol and then
// send payments through the routes.
func testMultiHopSendToRoute(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(100000)
	var networkChans []*lnrpc.ChannelPoint

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
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

	// Create Carol and establish a channel from Bob. Bob is the sole funder
	// of the channel with 100k satoshis. The network topology should look like:
	// Alice -> Bob -> Carol
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Bob)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, net.Bob)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBob := openChannelAndAssert(
		ctxt, t, net, net.Bob, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	networkChans = append(networkChans, chanPointBob)
	bobChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointBob)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	bobFundPoint := wire.OutPoint{
		Hash:  *bobChanTXID,
		Index: chanPointBob.OutputIndex,
	}

	// Wait for all nodes to have seen all channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol}
	nodeNames := []string{"Alice", "Bob", "Carol"}
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

	// Create 5 invoices for Carol, which expect a payment from Alice for 1k
	// satoshis with a different preimage each time.
	const (
		numPayments = 5
		paymentAmt  = 1000
	)
	_, rHashes, invoices, err := createPayReqs(
		carol, paymentAmt, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Construct a route from Alice to Carol for each of the invoices
	// created above.  We set FinalCltvDelta to 40 since by default
	// QueryRoutes returns the last hop with a final cltv delta of 9 where
	// as the default in htlcswitch is 40.
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey:         carol.PubKeyStr,
		Amt:            paymentAmt,
		FinalCltvDelta: chainreg.DefaultBitcoinTimeLockDelta,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	routes, err := net.Alice.QueryRoutes(ctxt, routesReq)
	if err != nil {
		t.Fatalf("unable to get route: %v", err)
	}

	// We'll wait for all parties to recognize the new channels within the
	// network.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointBob)
	if err != nil {
		t.Fatalf("bob didn't advertise his channel in time: %v", err)
	}

	time.Sleep(time.Millisecond * 50)

	// Using Alice as the source, pay to the 5 invoices from Carol created
	// above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)

	for i, rHash := range rHashes {
		// Manually set the MPP payload a new for each payment since
		// the payment addr will change with each invoice, although we
		// can re-use the route itself.
		route := *routes.Routes[0]
		route.Hops[len(route.Hops)-1].TlvPayload = true
		route.Hops[len(route.Hops)-1].MppRecord = &lnrpc.MPPRecord{
			PaymentAddr: invoices[i].PaymentAddr,
			TotalAmtMsat: int64(
				lnwire.NewMSatFromSatoshis(paymentAmt),
			),
		}

		sendReq := &routerrpc.SendToRouteRequest{
			PaymentHash: rHash,
			Route:       &route,
		}
		resp, err := net.Alice.RouterClient.SendToRouteV2(ctxt, sendReq)
		if err != nil {
			t.Fatalf("unable to send payment: %v", err)
		}

		if resp.Failure != nil {
			t.Fatalf("received payment error: %v", resp.Failure)
		}
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when
	// creating the seed nodes in the network.
	const baseFee = 1

	// At this point all the channels within our proto network should be
	// shifted by 5k satoshis in the direction of Carol, the sink within the
	// payment flow generated above. The order of asserts corresponds to
	// increasing of time is needed to embed the HTLC in commitment
	// transaction, in channel Alice->Bob->Carol, order is Carol, Bob,
	// Alice.
	const amountPaid = int64(5000)
	assertAmountPaid(t, "Bob(local) => Carol(remote)", carol,
		bobFundPoint, int64(0), amountPaid)
	assertAmountPaid(t, "Bob(local) => Carol(remote)", net.Bob,
		bobFundPoint, amountPaid, int64(0))
	assertAmountPaid(t, "Alice(local) => Bob(remote)", net.Bob,
		aliceFundPoint, int64(0), amountPaid+(baseFee*numPayments))
	assertAmountPaid(t, "Alice(local) => Bob(remote)", net.Alice,
		aliceFundPoint, amountPaid+(baseFee*numPayments), int64(0))

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointBob, false)
}

// testSendToRouteErrorPropagation tests propagation of errors that occur
// while processing a multi-hop payment through an unknown route.
func testSendToRouteErrorPropagation(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(100000)

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPointAlice)
	if err != nil {
		t.Fatalf("alice didn't advertise her channel: %v", err)
	}

	// Create a new nodes (Carol and Charlie), load her with some funds,
	// then establish a connection between Carol and Charlie with a channel
	// that has identical capacity to the one created above.Then we will
	// get route via queryroutes call which will be fake route for Alice ->
	// Bob graph.
	//
	// The network topology should now look like: Alice -> Bob; Carol -> Charlie.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	charlie := net.NewNode(t.t, "Charlie", nil)
	defer shutdownAndAssert(net, t, charlie)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, charlie)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, charlie)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, charlie,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("carol didn't advertise her channel: %v", err)
	}

	// Query routes from Carol to Charlie which will be an invalid route
	// for Alice -> Bob.
	fakeReq := &lnrpc.QueryRoutesRequest{
		PubKey: charlie.PubKeyStr,
		Amt:    int64(1),
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	fakeRoute, err := carol.QueryRoutes(ctxt, fakeReq)
	if err != nil {
		t.Fatalf("unable get fake route: %v", err)
	}

	// Create 1 invoices for Bob, which expect a payment from Alice for 1k
	// satoshis
	const paymentAmt = 1000

	invoice := &lnrpc.Invoice{
		Memo:  "testing",
		Value: paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := net.Bob.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	rHash := resp.RHash

	// Using Alice as the source, pay to the 5 invoices from Bob created above.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	alicePayStream, err := net.Alice.SendToRoute(ctxt) // nolint:staticcheck
	if err != nil {
		t.Fatalf("unable to create payment stream for alice: %v", err)
	}

	sendReq := &lnrpc.SendToRouteRequest{
		PaymentHash: rHash,
		Route:       fakeRoute.Routes[0],
	}

	if err := alicePayStream.Send(sendReq); err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// At this place we should get an rpc error with notification
	// that edge is not found on hop(0)
	if _, err := alicePayStream.Recv(); err != nil && strings.Contains(err.Error(),
		"edge not found") {

	} else if err != nil {
		t.Fatalf("payment stream has been closed but fake route has consumed: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// testPrivateChannels tests that a private channel can be used for
// routing by the two endpoints of the channel, but is not known by
// the rest of the nodes in the graph.
func testPrivateChannels(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(100000)
	var networkChans []*lnrpc.ChannelPoint

	// We create the following topology:
	//
	// Dave --100k--> Alice --200k--> Bob
	//  ^		    ^
	//  |		    |
	// 100k		   100k
	//  |		    |
	//  +---- Carol ----+
	//
	// where the 100k channel between Carol and Alice is private.

	// Open a channel with 200k satoshis between Alice and Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt * 2,
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

	// Create Dave, and a channel to Alice of 100k.
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
			Amt: chanAmt,
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

	// Next, we'll create Carol and establish a channel from her to
	// Dave of 100k.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
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

	// Wait for all nodes to have seen all these channels, as they
	// are all public.
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
	// Now create a _private_ channel directly between Carol and
	// Alice of 100k.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Alice)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanOpenUpdate := openChannelStream(
		ctxt, t, net, carol, net.Alice,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			Private: true,
		},
	)
	if err != nil {
		t.Fatalf("unable to open channel: %v", err)
	}

	// One block is enough to make the channel ready for use, since the
	// nodes have defaultNumConfs=1 set.
	block := mineBlocks(t, net, 1, 1)[0]

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	chanPointPrivate, err := net.WaitForChannelOpen(ctxt, chanOpenUpdate)
	if err != nil {
		t.Fatalf("error while waiting for channel open: %v", err)
	}
	fundingTxID, err := lnrpc.GetChanPointFundingTxid(chanPointPrivate)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	assertTxInBlock(t, block, fundingTxID)

	// The channel should be listed in the peer information returned by
	// both peers.
	privateFundPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: chanPointPrivate.OutputIndex,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.AssertChannelExists(ctxt, carol, &privateFundPoint)
	if err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.AssertChannelExists(ctxt, net.Alice, &privateFundPoint)
	if err != nil {
		t.Fatalf("unable to assert channel existence: %v", err)
	}

	// The channel should be available for payments between Carol and Alice.
	// We check this by sending payments from Carol to Bob, that
	// collectively would deplete at least one of Carol's channels.

	// Create 2 invoices for Bob, each of 70k satoshis. Since each of
	// Carol's channels is of size 100k, these payments cannot succeed
	// by only using one of the channels.
	const numPayments = 2
	const paymentAmt = 70000
	payReqs, _, _, err := createPayReqs(
		net.Bob, paymentAmt, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	time.Sleep(time.Millisecond * 50)

	// Let Carol pay the invoices.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, carol, carol.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when
	// creating the seed nodes in the network.
	const baseFee = 1

	// Bob should have received 140k satoshis from Alice.
	assertAmountPaid(t, "Alice(local) => Bob(remote)", net.Bob,
		aliceFundPoint, int64(0), 2*paymentAmt)

	// Alice sent 140k to Bob.
	assertAmountPaid(t, "Alice(local) => Bob(remote)", net.Alice,
		aliceFundPoint, 2*paymentAmt, int64(0))

	// Alice received 70k + fee from Dave.
	assertAmountPaid(t, "Dave(local) => Alice(remote)", net.Alice,
		daveFundPoint, int64(0), paymentAmt+baseFee)

	// Dave sent 70k+fee to Alice.
	assertAmountPaid(t, "Dave(local) => Alice(remote)", dave,
		daveFundPoint, paymentAmt+baseFee, int64(0))

	// Dave received 70k+fee of two hops from Carol.
	assertAmountPaid(t, "Carol(local) => Dave(remote)", dave,
		carolFundPoint, int64(0), paymentAmt+baseFee*2)

	// Carol sent 70k+fee of two hops to Dave.
	assertAmountPaid(t, "Carol(local) => Dave(remote)", carol,
		carolFundPoint, paymentAmt+baseFee*2, int64(0))

	// Alice received 70k+fee from Carol.
	assertAmountPaid(t, "Carol(local) [private=>] Alice(remote)",
		net.Alice, privateFundPoint, int64(0), paymentAmt+baseFee)

	// Carol sent 70k+fee to Alice.
	assertAmountPaid(t, "Carol(local) [private=>] Alice(remote)",
		carol, privateFundPoint, paymentAmt+baseFee, int64(0))

	// Alice should also be able to route payments using this channel,
	// so send two payments of 60k back to Carol.
	const paymentAmt60k = 60000
	payReqs, _, _, err = createPayReqs(
		carol, paymentAmt60k, numPayments,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	time.Sleep(time.Millisecond * 50)

	// Let Bob pay the invoices.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments: %v", err)
	}

	// Finally, we make sure Dave and Bob does not know about the
	// private channel between Carol and Alice. We first mine
	// plenty of blocks, such that the channel would have been
	// announced in case it was public.
	mineBlocks(t, net, 10, 0)

	// We create a helper method to check how many edges each of the
	// nodes know about. Carol and Alice should know about 4, while
	// Bob and Dave should only know about 3, since one channel is
	// private.
	numChannels := func(node *lntest.HarnessNode, includeUnannounced bool) int {
		req := &lnrpc.ChannelGraphRequest{
			IncludeUnannounced: includeUnannounced,
		}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		chanGraph, err := node.DescribeGraph(ctxt, req)
		if err != nil {
			t.Fatalf("unable go describegraph: %v", err)
		}
		return len(chanGraph.Edges)
	}

	var predErr error
	err = wait.Predicate(func() bool {
		aliceChans := numChannels(net.Alice, true)
		if aliceChans != 4 {
			predErr = fmt.Errorf("expected Alice to know 4 edges, "+
				"had %v", aliceChans)
			return false
		}
		alicePubChans := numChannels(net.Alice, false)
		if alicePubChans != 3 {
			predErr = fmt.Errorf("expected Alice to know 3 public edges, "+
				"had %v", alicePubChans)
			return false
		}
		bobChans := numChannels(net.Bob, true)
		if bobChans != 3 {
			predErr = fmt.Errorf("expected Bob to know 3 edges, "+
				"had %v", bobChans)
			return false
		}
		carolChans := numChannels(carol, true)
		if carolChans != 4 {
			predErr = fmt.Errorf("expected Carol to know 4 edges, "+
				"had %v", carolChans)
			return false
		}
		carolPubChans := numChannels(carol, false)
		if carolPubChans != 3 {
			predErr = fmt.Errorf("expected Carol to know 3 public edges, "+
				"had %v", carolPubChans)
			return false
		}
		daveChans := numChannels(dave, true)
		if daveChans != 3 {
			predErr = fmt.Errorf("expected Dave to know 3 edges, "+
				"had %v", daveChans)
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("%v", predErr)
	}

	// Close all channels.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, dave, chanPointDave, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointPrivate, false)
}

// testUpdateChannelPolicyForPrivateChannel tests when a private channel
// updates its channel edge policy, we will use the updated policy to send our
// payment.
// The topology is created as: Alice -> Bob -> Carol, where Alice -> Bob is
// public and Bob -> Carol is private. After an invoice is created by Carol,
// Bob will update the base fee via UpdateChannelPolicy, we will test that
// Alice will not fail the payment and send it using the updated channel
// policy.
func testUpdateChannelPolicyForPrivateChannel(net *lntest.NetworkHarness,
	t *harnessTest) {

	ctxb := context.Background()
	defer ctxb.Done()

	// We'll create the following topology first,
	// Alice <--public:100k--> Bob <--private:100k--> Carol
	const chanAmt = btcutil.Amount(100000)

	// Open a channel with 100k satoshis between Alice and Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAliceBob := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	defer closeChannelAndAssert(
		ctxt, t, net, net.Alice, chanPointAliceBob, false,
	)

	// Get Alice's funding point.
	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAliceBob)
	require.NoError(t.t, err, "unable to get txid")
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAliceBob.OutputIndex,
	}

	// Create a new node Carol.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	// Connect Carol to Bob.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Bob)

	// Open a channel with 100k satoshis between Bob and Carol.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBobCarol := openChannelAndAssert(
		ctxt, t, net, net.Bob, carol,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			Private: true,
		},
	)
	defer closeChannelAndAssert(
		ctxt, t, net, net.Bob, chanPointBobCarol, false,
	)

	// Get Bob's funding point.
	bobChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointBobCarol)
	require.NoError(t.t, err, "unable to get txid")
	bobFundPoint := wire.OutPoint{
		Hash:  *bobChanTXID,
		Index: chanPointBobCarol.OutputIndex,
	}

	// We should have the following topology now,
	// Alice <--public:100k--> Bob <--private:100k--> Carol
	//
	// Now we will create an invoice for Carol.
	const paymentAmt = 20000
	invoice := &lnrpc.Invoice{
		Memo:    "routing hints",
		Value:   paymentAmt,
		Private: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.AddInvoice(ctxt, invoice)
	require.NoError(t.t, err, "unable to create invoice for carol")

	// Bob now updates the channel edge policy for the private channel.
	const (
		baseFeeMSat = 33000
	)
	timeLockDelta := uint32(chainreg.DefaultBitcoinTimeLockDelta)
	updateFeeReq := &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   baseFeeMSat,
		TimeLockDelta: timeLockDelta,
		Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPointBobCarol,
		},
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Bob.UpdateChannelPolicy(ctxt, updateFeeReq)
	require.NoError(t.t, err, "unable to update chan policy")

	// Alice pays the invoices. She will use the updated baseFeeMSat in the
	// payment
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	payReqs := []string{resp.PaymentRequest}
	require.NoError(t.t,
		completePaymentRequests(
			ctxt, net.Alice, net.Alice.RouterClient, payReqs, true,
		), "unable to send payment",
	)

	// Check that Alice did make the payment with two HTLCs, one failed and
	// one succeeded.
	ctxt, _ = context.WithTimeout(ctxt, defaultTimeout)
	paymentsResp, err := net.Alice.ListPayments(
		ctxt, &lnrpc.ListPaymentsRequest{},
	)
	require.NoError(t.t, err, "failed to obtain payments for Alice")
	require.Equal(t.t, 1, len(paymentsResp.Payments), "expected 1 payment")

	htlcs := paymentsResp.Payments[0].Htlcs
	require.Equal(t.t, 2, len(htlcs), "expected to have 2 HTLCs")
	require.Equal(
		t.t, lnrpc.HTLCAttempt_FAILED, htlcs[0].Status,
		"the first HTLC attempt should fail",
	)
	require.Equal(
		t.t, lnrpc.HTLCAttempt_SUCCEEDED, htlcs[1].Status,
		"the second HTLC attempt should succeed",
	)

	// Carol should have received 20k satoshis from Bob.
	assertAmountPaid(t, "Carol(remote) [<=private] Bob(local)",
		carol, bobFundPoint, 0, paymentAmt)

	// Bob should have sent 20k satoshis to Carol.
	assertAmountPaid(t, "Bob(local) [private=>] Carol(remote)",
		net.Bob, bobFundPoint, paymentAmt, 0)

	// Calcuate the amount in satoshis.
	amtExpected := int64(paymentAmt + baseFeeMSat/1000)

	// Bob should have received 20k satoshis + fee from Alice.
	assertAmountPaid(t, "Bob(remote) <= Alice(local)",
		net.Bob, aliceFundPoint, 0, amtExpected)

	// Alice should have sent 20k satoshis + fee to Bob.
	assertAmountPaid(t, "Alice(local) => Bob(remote)",
		net.Alice, aliceFundPoint, amtExpected, 0)
}

// testInvoiceRoutingHints tests that the routing hints for an invoice are
// created properly.
func testInvoiceRoutingHints(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt              = btcutil.Amount(100000)
		defaultFeeBase       = 1000
		defaultFeeRate       = 1
		defaultTimeLockDelta = chainreg.DefaultBitcoinTimeLockDelta
		defaultMinHtlc       = 1000
	)
	defaultMaxHtlc := calculateMaxHtlc(chanAmt)

	// Launch notification clients for Alice and Bob nodes so that they
	// can get notified when there are updates in channel policies.
	aliceSub := subscribeGraphNotifications(ctxb, t, net.Alice)
	defer close(aliceSub.quit)
	bobSub := subscribeGraphNotifications(ctxb, t, net.Bob)
	defer close(bobSub.quit)

	// Throughout this test, we'll be opening a channel between Alice and
	// several other parties.
	//
	// First, we'll create a private channel between Alice and Bob.
	// We'll include a push amount since we currently require channels to
	// have enough remote balance to cover the invoice's payment.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBob1 := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: chanAmt / 2,
			Private: true,
		},
	)

	listReq := &lnrpc.ListChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	listResp, err := net.Alice.ListChannels(ctxt, listReq)
	if err != nil {
		t.Fatalf("unable to retrieve alice's channels: %v", err)
	}

	// We'll need the short channel ID of the channel between Alice and Bob
	// to make sure the routing hint is for this channel.
	aliceBobChan1ID := listResp.Channels[0].ChanId

	// In order to test the selection of channel policies for hop
	// hints for non-strict forwarding on private channels, we open a
	// second private channel between Alice and Bob.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBob2 := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: chanAmt / 2,
			Private: true,
		},
	)

	// Get the short channel ID of this second channel between Alice and
	// Bob.
	listReq = &lnrpc.ListChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	listResp, err = net.Alice.ListChannels(ctxt, listReq)
	require.NoError(t.t, err, "unable to retrieve alice's channels: %v")

	var aliceBobChan2ID uint64
	for _, c := range listResp.Channels {
		if c.ChanId != aliceBobChan1ID {
			aliceBobChan2ID = c.ChanId
			break
		}
	}
	require.NotEqual(t.t, 0, aliceBobChan2ID,
		"channel between alice and bob not found")

	// Ensure that all the initial policy values for both channels are as
	// expected.
	expectedPolicy := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      defaultFeeBase,
		FeeRateMilliMsat: defaultFeeRate,
		TimeLockDelta:    defaultTimeLockDelta,
		MinHtlc:          defaultMinHtlc,
		MaxHtlcMsat:      defaultMaxHtlc,
	}

	graphSubs := []graphSubscription{aliceSub, bobSub}

	for _, graphSub := range graphSubs {
		waitForChannelUpdate(
			t, graphSub,
			[]expectedChanUpdate{
				{net.Alice.PubKeyStr, expectedPolicy, chanPointBob1},
				{net.Alice.PubKeyStr, expectedPolicy, chanPointBob2},
				{net.Bob.PubKeyStr, expectedPolicy, chanPointBob1},
				{net.Bob.PubKeyStr, expectedPolicy, chanPointBob2},
			},
		)
	}

	// Change the policy values of the second channel between Alice and
	// Bob so that it now has the maximal policy value between the two
	// channels in terms of fees. It is expected that only this channel and
	// its policy values will be included in the invoice hop hint.
	expectedPolicy = &lnrpc.RoutingPolicy{
		FeeBaseMsat:      defaultFeeBase * 2,
		FeeRateMilliMsat: testFeeBase * defaultFeeRate,
		TimeLockDelta:    defaultTimeLockDelta,
		MinHtlc:          defaultMinHtlc,
		MaxHtlcMsat:      defaultMaxHtlc,
	}

	updateFeeReq := &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   defaultFeeBase * 2,
		FeeRate:       float64(defaultFeeRate),
		TimeLockDelta: defaultTimeLockDelta,
		MaxHtlcMsat:   defaultMaxHtlc,
		Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPointBob2,
		},
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if _, err := net.Bob.UpdateChannelPolicy(ctxt, updateFeeReq); err != nil {
		t.Fatalf("unable to update chan policy: %v", err)
	}

	// Wait for Alice to receive the channel update from Bob.
	waitForChannelUpdate(
		t, aliceSub,
		[]expectedChanUpdate{
			{net.Bob.PubKeyStr, expectedPolicy, chanPointBob2},
		},
	)

	// Update the first channel between Alice and Bob so that it has a
	// larger CLTV delta than the second channel.
	// Although we expect the first channel to be used as a hop hint due
	// to its higher fee values, we expect this channels timelock delta
	// to be included in the hop hint since it is the maximum of the two.
	expectedPolicy = &lnrpc.RoutingPolicy{
		FeeBaseMsat:      defaultFeeBase,
		FeeRateMilliMsat: testFeeBase * defaultFeeRate,
		TimeLockDelta:    defaultTimeLockDelta + 10,
		MinHtlc:          defaultMinHtlc,
		MaxHtlcMsat:      defaultMaxHtlc,
	}

	updateFeeReq = &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   defaultFeeBase,
		FeeRate:       float64(defaultFeeRate),
		TimeLockDelta: defaultTimeLockDelta + 10,
		MaxHtlcMsat:   defaultMaxHtlc,
		Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPointBob1,
		},
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if _, err := net.Bob.UpdateChannelPolicy(ctxt, updateFeeReq); err != nil {
		t.Fatalf("unable to update chan policy: %v", err)
	}

	// Wait for Alice to receive the channel update from Bob.
	waitForChannelUpdate(
		t, aliceSub,
		[]expectedChanUpdate{
			{net.Bob.PubKeyStr, expectedPolicy, chanPointBob1},
		},
	)

	// Then, we'll create Carol's node and open a public channel between her
	// and Alice. This channel will not be considered as a routing hint due
	// to it being public.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: chanAmt / 2,
		},
	)

	// We'll also create a public channel between Bob and Carol to ensure
	// that Bob gets selected as the only routing hint. We do this as
	// we should only include routing hints for nodes that are publicly
	// advertised, otherwise we'd end up leaking information about nodes
	// that wish to stay unadvertised.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Bob, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBobCarol := openChannelAndAssert(
		ctxt, t, net, net.Bob, carol,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: chanAmt / 2,
		},
	)

	// Then, we'll create Dave's node and open a private channel between him
	// and Alice. We will not include a push amount in order to not consider
	// this channel as a routing hint as it will not have enough remote
	// balance for the invoice's amount.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, dave)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointDave := openChannelAndAssert(
		ctxt, t, net, net.Alice, dave,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			Private: true,
		},
	)

	// Finally, we'll create Eve's node and open a private channel between
	// her and Alice. This time though, we'll take Eve's node down after the
	// channel has been created to avoid populating routing hints for
	// inactive channels.
	eve := net.NewNode(t.t, "Eve", nil)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Alice, eve)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointEve := openChannelAndAssert(
		ctxt, t, net, net.Alice, eve,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			PushAmt: chanAmt / 2,
			Private: true,
		},
	)

	// Make sure all the channels have been opened.
	chanNames := []string{
		"alice-bob", "alice-carol", "bob-carol", "alice-dave",
		"alice-eve",
	}
	aliceChans := []*lnrpc.ChannelPoint{
		chanPointBob1, chanPointBob2, chanPointCarol, chanPointBobCarol,
		chanPointDave, chanPointEve,
	}
	for i, chanPoint := range aliceChans {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
		if err != nil {
			t.Fatalf("timed out waiting for channel open %s: %v",
				chanNames[i], err)
		}
	}

	// Now that the channels are open, we'll take down Eve's node.
	shutdownAndAssert(net, t, eve)

	// Create an invoice for Alice that will populate the routing hints.
	invoice := &lnrpc.Invoice{
		Memo:    "routing hints",
		Value:   int64(chanAmt / 4),
		Private: true,
	}

	// Due to the way the channels were set up above, the channel between
	// Alice and Bob should be the only channel used as a routing hint.
	var predErr error
	var decoded *lnrpc.PayReq
	err = wait.Predicate(func() bool {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		resp, err := net.Alice.AddInvoice(ctxt, invoice)
		if err != nil {
			predErr = fmt.Errorf("unable to add invoice: %v", err)
			return false
		}

		// We'll decode the invoice's payment request to determine which
		// channels were used as routing hints.
		payReq := &lnrpc.PayReqString{
			PayReq: resp.PaymentRequest,
		}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		decoded, err = net.Alice.DecodePayReq(ctxt, payReq)
		if err != nil {
			predErr = fmt.Errorf("unable to decode payment "+
				"request: %v", err)
			return false
		}

		if len(decoded.RouteHints) != 1 {
			predErr = fmt.Errorf("expected one route hint, got %d",
				len(decoded.RouteHints))
			return false
		}
		return true
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(predErr.Error())
	}

	hops := decoded.RouteHints[0].HopHints
	if len(hops) != 1 {
		t.Fatalf("expected one hop in route hint, got %d", len(hops))
	}
	chanID := hops[0].ChanId

	if chanID != aliceBobChan2ID {
		t.Fatalf("expected channel ID %d, got %d", aliceBobChan2ID,
			chanID)
	}

	if hops[0].FeeBaseMsat != defaultFeeBase*2 {
		t.Fatalf("expected base fee of %d, got %d",
			defaultFeeBase*2, hops[0].FeeBaseMsat)
	}

	if hops[0].CltvExpiryDelta != defaultTimeLockDelta+10 {
		t.Fatalf("expected cltv delta of %d, got %d",
			defaultTimeLockDelta+10, hops[0].CltvExpiryDelta)
	}

	// Now that we've confirmed the routing hints were added correctly, we
	// can close all the channels and shut down all the nodes created.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointBob1, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointBob2, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointCarol, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPointBobCarol, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointDave, false)

	// The channel between Alice and Eve should be force closed since Eve
	// is offline.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointEve, true)

	// Cleanup by mining the force close and sweep transaction.
	cleanupForceClose(t, net, net.Alice, chanPointEve)
}

// testMultiHopOverPrivateChannels tests that private channels can be used as
// intermediate hops in a route for payments.
func testMultiHopOverPrivateChannels(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// We'll test that multi-hop payments over private channels work as
	// intended. To do so, we'll create the following topology:
	//         private        public           private
	// Alice <--100k--> Bob <--100k--> Carol <--100k--> Dave
	const chanAmt = btcutil.Amount(100000)

	// First, we'll open a private channel between Alice and Bob with Alice
	// being the funder.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			Private: true,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := net.Alice.WaitForNetworkChannelOpen(ctxt, chanPointAlice)
	if err != nil {
		t.Fatalf("alice didn't see the channel alice <-> bob before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPointAlice)
	if err != nil {
		t.Fatalf("bob didn't see the channel alice <-> bob before "+
			"timeout: %v", err)
	}

	// Retrieve Alice's funding outpoint.
	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAlice)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAlice.OutputIndex,
	}

	// Next, we'll create Carol's node and open a public channel between
	// her and Bob with Bob being the funder.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, net.Bob, carol)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBob := openChannelAndAssert(
		ctxt, t, net, net.Bob, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Bob.WaitForNetworkChannelOpen(ctxt, chanPointBob)
	if err != nil {
		t.Fatalf("bob didn't see the channel bob <-> carol before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointBob)
	if err != nil {
		t.Fatalf("carol didn't see the channel bob <-> carol before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = net.Alice.WaitForNetworkChannelOpen(ctxt, chanPointBob)
	if err != nil {
		t.Fatalf("alice didn't see the channel bob <-> carol before "+
			"timeout: %v", err)
	}

	// Retrieve Bob's funding outpoint.
	bobChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointBob)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	bobFundPoint := wire.OutPoint{
		Hash:  *bobChanTXID,
		Index: chanPointBob.OutputIndex,
	}

	// Next, we'll create Dave's node and open a private channel between him
	// and Carol with Carol being the funder.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt:     chanAmt,
			Private: true,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("carol didn't see the channel carol <-> dave before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPointCarol)
	if err != nil {
		t.Fatalf("dave didn't see the channel carol <-> dave before "+
			"timeout: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = dave.WaitForNetworkChannelOpen(ctxt, chanPointBob)
	if err != nil {
		t.Fatalf("dave didn't see the channel bob <-> carol before "+
			"timeout: %v", err)
	}

	// Retrieve Carol's funding point.
	carolChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointCarol)
	if err != nil {
		t.Fatalf("unable to get txid: %v", err)
	}
	carolFundPoint := wire.OutPoint{
		Hash:  *carolChanTXID,
		Index: chanPointCarol.OutputIndex,
	}

	// Now that all the channels are set up according to the topology from
	// above, we can proceed to test payments. We'll create an invoice for
	// Dave of 20k satoshis and pay it with Alice. Since there is no public
	// route from Alice to Dave, we'll need to use the private channel
	// between Carol and Dave as a routing hint encoded in the invoice.
	const paymentAmt = 20000

	// Create the invoice for Dave.
	invoice := &lnrpc.Invoice{
		Memo:    "two hopz!",
		Value:   paymentAmt,
		Private: true,
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := dave.AddInvoice(ctxt, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice for dave: %v", err)
	}

	// Let Alice pay the invoice.
	payReqs := []string{resp.PaymentRequest}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = completePaymentRequests(
		ctxt, net.Alice, net.Alice.RouterClient, payReqs, true,
	)
	if err != nil {
		t.Fatalf("unable to send payments from alice to dave: %v", err)
	}

	// When asserting the amount of satoshis moved, we'll factor in the
	// default base fee, as we didn't modify the fee structure when opening
	// the channels.
	const baseFee = 1

	// Dave should have received 20k satoshis from Carol.
	assertAmountPaid(t, "Carol(local) [private=>] Dave(remote)",
		dave, carolFundPoint, 0, paymentAmt)

	// Carol should have sent 20k satoshis to Dave.
	assertAmountPaid(t, "Carol(local) [private=>] Dave(remote)",
		carol, carolFundPoint, paymentAmt, 0)

	// Carol should have received 20k satoshis + fee for one hop from Bob.
	assertAmountPaid(t, "Bob(local) => Carol(remote)",
		carol, bobFundPoint, 0, paymentAmt+baseFee)

	// Bob should have sent 20k satoshis + fee for one hop to Carol.
	assertAmountPaid(t, "Bob(local) => Carol(remote)",
		net.Bob, bobFundPoint, paymentAmt+baseFee, 0)

	// Bob should have received 20k satoshis + fee for two hops from Alice.
	assertAmountPaid(t, "Alice(local) [private=>] Bob(remote)", net.Bob,
		aliceFundPoint, 0, paymentAmt+baseFee*2)

	// Alice should have sent 20k satoshis + fee for two hops to Bob.
	assertAmountPaid(t, "Alice(local) [private=>] Bob(remote)", net.Alice,
		aliceFundPoint, paymentAmt+baseFee*2, 0)

	// At this point, the payment was successful. We can now close all the
	// channels and shutdown the nodes created throughout this test.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPointBob, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// computeFee calculates the payment fee as specified in BOLT07
func computeFee(baseFee, feeRate, amt lnwire.MilliSatoshi) lnwire.MilliSatoshi {
	return baseFee + amt*feeRate/1000000
}

// testQueryRoutes checks the response of queryroutes.
// We'll create the following network topology:
//      Alice --> Bob --> Carol --> Dave
// and query the daemon for routes from Alice to Dave.
func testQueryRoutes(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const chanAmt = btcutil.Amount(100000)
	var networkChans []*lnrpc.ChannelPoint

	// Open a channel between Alice and Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAlice := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	networkChans = append(networkChans, chanPointAlice)

	// Create Carol and establish a channel from Bob.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Bob)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, net.Bob)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBob := openChannelAndAssert(
		ctxt, t, net, net.Bob, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	networkChans = append(networkChans, chanPointBob)

	// Create Dave and establish a channel from Carol.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, carol)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarol := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	networkChans = append(networkChans, chanPointCarol)

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

	// Query for routes to pay from Alice to Dave.
	const paymentAmt = 1000
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey: dave.PubKeyStr,
		Amt:    paymentAmt,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	routesRes, err := net.Alice.QueryRoutes(ctxt, routesReq)
	if err != nil {
		t.Fatalf("unable to get route: %v", err)
	}

	const mSat = 1000
	feePerHopMSat := computeFee(1000, 1, paymentAmt*mSat)

	for i, route := range routesRes.Routes {
		expectedTotalFeesMSat :=
			lnwire.MilliSatoshi(len(route.Hops)-1) * feePerHopMSat
		expectedTotalAmtMSat := (paymentAmt * mSat) + expectedTotalFeesMSat

		if route.TotalFees != route.TotalFeesMsat/mSat { // nolint:staticcheck
			t.Fatalf("route %v: total fees %v (msat) does not "+
				"round down to %v (sat)",
				i, route.TotalFeesMsat, route.TotalFees) // nolint:staticcheck
		}
		if route.TotalFeesMsat != int64(expectedTotalFeesMSat) {
			t.Fatalf("route %v: total fees in msat expected %v got %v",
				i, expectedTotalFeesMSat, route.TotalFeesMsat)
		}

		if route.TotalAmt != route.TotalAmtMsat/mSat { // nolint:staticcheck
			t.Fatalf("route %v: total amt %v (msat) does not "+
				"round down to %v (sat)",
				i, route.TotalAmtMsat, route.TotalAmt) // nolint:staticcheck
		}
		if route.TotalAmtMsat != int64(expectedTotalAmtMSat) {
			t.Fatalf("route %v: total amt in msat expected %v got %v",
				i, expectedTotalAmtMSat, route.TotalAmtMsat)
		}

		// For all hops except the last, we check that fee equals feePerHop
		// and amount to forward deducts feePerHop on each hop.
		expectedAmtToForwardMSat := expectedTotalAmtMSat
		for j, hop := range route.Hops[:len(route.Hops)-1] {
			expectedAmtToForwardMSat -= feePerHopMSat

			if hop.Fee != hop.FeeMsat/mSat { // nolint:staticcheck
				t.Fatalf("route %v hop %v: fee %v (msat) does not "+
					"round down to %v (sat)",
					i, j, hop.FeeMsat, hop.Fee) // nolint:staticcheck
			}
			if hop.FeeMsat != int64(feePerHopMSat) {
				t.Fatalf("route %v hop %v: fee in msat expected %v got %v",
					i, j, feePerHopMSat, hop.FeeMsat)
			}

			if hop.AmtToForward != hop.AmtToForwardMsat/mSat { // nolint:staticcheck
				t.Fatalf("route %v hop %v: amt to forward %v (msat) does not "+
					"round down to %v (sat)",
					i, j, hop.AmtToForwardMsat, hop.AmtToForward) // nolint:staticcheck
			}
			if hop.AmtToForwardMsat != int64(expectedAmtToForwardMSat) {
				t.Fatalf("route %v hop %v: amt to forward in msat "+
					"expected %v got %v",
					i, j, expectedAmtToForwardMSat, hop.AmtToForwardMsat)
			}
		}
		// Last hop should have zero fee and amount to forward should equal
		// payment amount.
		hop := route.Hops[len(route.Hops)-1]

		if hop.Fee != 0 || hop.FeeMsat != 0 { // nolint:staticcheck
			t.Fatalf("route %v hop %v: fee expected 0 got %v (sat) %v (msat)",
				i, len(route.Hops)-1, hop.Fee, hop.FeeMsat) // nolint:staticcheck
		}

		if hop.AmtToForward != hop.AmtToForwardMsat/mSat { // nolint:staticcheck
			t.Fatalf("route %v hop %v: amt to forward %v (msat) does not "+
				"round down to %v (sat)",
				i, len(route.Hops)-1, hop.AmtToForwardMsat, hop.AmtToForward) // nolint:staticcheck
		}
		if hop.AmtToForwardMsat != paymentAmt*mSat {
			t.Fatalf("route %v hop %v: amt to forward in msat "+
				"expected %v got %v",
				i, len(route.Hops)-1, paymentAmt*mSat, hop.AmtToForwardMsat)
		}
	}

	// While we're here, we test updating mission control's config values
	// and assert that they are correctly updated and check that our mission
	// control import function updates appropriately.
	testMissionControlCfg(t.t, net.Alice)
	testMissionControlImport(
		t.t, net.Alice, net.Bob.PubKey[:], carol.PubKey[:],
	)

	// We clean up the test case by closing channels that were created for
	// the duration of the tests.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAlice, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPointBob, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarol, false)
}

// testMissionControlCfg tests getting and setting of a node's mission control
// config, resetting to the original values after testing so that no other
// tests are affected.
func testMissionControlCfg(t *testing.T, node *lntest.HarnessNode) {
	ctxb := context.Background()
	startCfg, err := node.RouterClient.GetMissionControlConfig(
		ctxb, &routerrpc.GetMissionControlConfigRequest{},
	)
	require.NoError(t, err)

	cfg := &routerrpc.MissionControlConfig{
		HalfLifeSeconds:             8000,
		HopProbability:              0.8,
		Weight:                      0.3,
		MaximumPaymentResults:       30,
		MinimumFailureRelaxInterval: 60,
	}

	_, err = node.RouterClient.SetMissionControlConfig(
		ctxb, &routerrpc.SetMissionControlConfigRequest{
			Config: cfg,
		},
	)
	require.NoError(t, err)

	resp, err := node.RouterClient.GetMissionControlConfig(
		ctxb, &routerrpc.GetMissionControlConfigRequest{},
	)
	require.NoError(t, err)
	require.True(t, proto.Equal(cfg, resp.Config))

	_, err = node.RouterClient.SetMissionControlConfig(
		ctxb, &routerrpc.SetMissionControlConfigRequest{
			Config: startCfg.Config,
		},
	)
	require.NoError(t, err)
}

// testMissionControlImport tests import of mission control results from an
// external source.
func testMissionControlImport(t *testing.T, node *lntest.HarnessNode,
	fromNode, toNode []byte) {

	ctxb := context.Background()

	// Reset mission control so that our query will return the default
	// probability for our first request.
	_, err := node.RouterClient.ResetMissionControl(
		ctxb, &routerrpc.ResetMissionControlRequest{},
	)
	require.NoError(t, err, "could not reset mission control")

	// Get our baseline probability for a 10 msat hop between our target
	// nodes.
	var amount int64 = 10
	probReq := &routerrpc.QueryProbabilityRequest{
		FromNode: fromNode,
		ToNode:   toNode,
		AmtMsat:  amount,
	}

	importHistory := &routerrpc.PairData{
		FailTime:    time.Now().Unix(),
		FailAmtMsat: amount,
	}

	// Assert that our history is not already equal to the value we want to
	// set. This should not happen because we have just cleared our state.
	resp1, err := node.RouterClient.QueryProbability(ctxb, probReq)
	require.NoError(t, err, "query probability failed")
	require.Zero(t, resp1.History.FailTime)
	require.Zero(t, resp1.History.FailAmtMsat)

	// Now, we import a single entry which tracks a failure of the amount
	// we want to query between our nodes.
	req := &routerrpc.XImportMissionControlRequest{
		Pairs: []*routerrpc.PairHistory{
			{
				NodeFrom: fromNode,
				NodeTo:   toNode,
				History:  importHistory,
			},
		},
	}

	_, err = node.RouterClient.XImportMissionControl(ctxb, req)
	require.NoError(t, err, "could not import config")

	resp2, err := node.RouterClient.QueryProbability(ctxb, probReq)
	require.NoError(t, err, "query probability failed")
	require.Equal(t, importHistory.FailTime, resp2.History.FailTime)
	require.Equal(t, importHistory.FailAmtMsat, resp2.History.FailAmtMsat)

	// Finally, check that we will fail if inconsistent sat/msat values are
	// set.
	importHistory.FailAmtSat = amount * 2
	_, err = node.RouterClient.XImportMissionControl(ctxb, req)
	require.Error(t, err, "mismatched import amounts succeeded")
}

// testRouteFeeCutoff tests that we are able to prevent querying routes and
// sending payments that incur a fee higher than the fee limit.
func testRouteFeeCutoff(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// For this test, we'll create the following topology:
	//
	//              --- Bob ---
	//            /             \
	// Alice ----                 ---- Dave
	//            \             /
	//              -- Carol --
	//
	// Alice will attempt to send payments to Dave that should not incur a
	// fee greater than the fee limit expressed as a percentage of the
	// amount and as a fixed amount of satoshis.
	const chanAmt = btcutil.Amount(100000)

	// Open a channel between Alice and Bob.
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAliceBob := openChannelAndAssert(
		ctxt, t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Create Carol's node and open a channel between her and Alice with
	// Alice being the funder.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Alice)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointAliceCarol := openChannelAndAssert(
		ctxt, t, net, net.Alice, carol,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Create Dave's node and open a channel between him and Bob with Bob
	// being the funder.
	dave := net.NewNode(t.t, "Dave", nil)
	defer shutdownAndAssert(net, t, dave)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, dave, net.Bob)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointBobDave := openChannelAndAssert(
		ctxt, t, net, net.Bob, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Open a channel between Carol and Dave.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, dave)
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPointCarolDave := openChannelAndAssert(
		ctxt, t, net, carol, dave,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Now that all the channels were set up, we'll wait for all the nodes
	// to have seen all the channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol, dave}
	nodeNames := []string{"alice", "bob", "carol", "dave"}
	networkChans := []*lnrpc.ChannelPoint{
		chanPointAliceBob, chanPointAliceCarol, chanPointBobDave,
		chanPointCarolDave,
	}
	for _, chanPoint := range networkChans {
		for i, node := range nodes {
			txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				t.Fatalf("unable to get txid: %v", err)
			}
			outpoint := wire.OutPoint{
				Hash:  *txid,
				Index: chanPoint.OutputIndex,
			}

			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			err = node.WaitForNetworkChannelOpen(ctxt, chanPoint)
			if err != nil {
				t.Fatalf("%s(%d) timed out waiting for "+
					"channel(%s) open: %v", nodeNames[i],
					node.NodeID, outpoint, err)
			}
		}
	}

	// The payments should only be successful across the route:
	//	Alice -> Bob -> Dave
	// Therefore, we'll update the fee policy on Carol's side for the
	// channel between her and Dave to invalidate the route:
	//	Alice -> Carol -> Dave
	baseFee := int64(10000)
	feeRate := int64(5)
	timeLockDelta := uint32(chainreg.DefaultBitcoinTimeLockDelta)
	maxHtlc := calculateMaxHtlc(chanAmt)

	expectedPolicy := &lnrpc.RoutingPolicy{
		FeeBaseMsat:      baseFee,
		FeeRateMilliMsat: testFeeBase * feeRate,
		TimeLockDelta:    timeLockDelta,
		MinHtlc:          1000, // default value
		MaxHtlcMsat:      maxHtlc,
	}

	updateFeeReq := &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   baseFee,
		FeeRate:       float64(feeRate),
		TimeLockDelta: timeLockDelta,
		MaxHtlcMsat:   maxHtlc,
		Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPointCarolDave,
		},
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if _, err := carol.UpdateChannelPolicy(ctxt, updateFeeReq); err != nil {
		t.Fatalf("unable to update chan policy: %v", err)
	}

	// Wait for Alice to receive the channel update from Carol.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceSub := subscribeGraphNotifications(ctxt, t, net.Alice)
	defer close(aliceSub.quit)

	waitForChannelUpdate(
		t, aliceSub,
		[]expectedChanUpdate{
			{carol.PubKeyStr, expectedPolicy, chanPointCarolDave},
		},
	)

	// We'll also need the channel IDs for Bob's channels in order to
	// confirm the route of the payments.
	listReq := &lnrpc.ListChannelsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	listResp, err := net.Bob.ListChannels(ctxt, listReq)
	if err != nil {
		t.Fatalf("unable to retrieve bob's channels: %v", err)
	}

	var aliceBobChanID, bobDaveChanID uint64
	for _, channel := range listResp.Channels {
		switch channel.RemotePubkey {
		case net.Alice.PubKeyStr:
			aliceBobChanID = channel.ChanId
		case dave.PubKeyStr:
			bobDaveChanID = channel.ChanId
		}
	}

	if aliceBobChanID == 0 {
		t.Fatalf("channel between alice and bob not found")
	}
	if bobDaveChanID == 0 {
		t.Fatalf("channel between bob and dave not found")
	}
	hopChanIDs := []uint64{aliceBobChanID, bobDaveChanID}

	// checkRoute is a helper closure to ensure the route contains the
	// correct intermediate hops.
	checkRoute := func(route *lnrpc.Route) {
		if len(route.Hops) != 2 {
			t.Fatalf("expected two hops, got %d", len(route.Hops))
		}

		for i, hop := range route.Hops {
			if hop.ChanId != hopChanIDs[i] {
				t.Fatalf("expected chan id %d, got %d",
					hopChanIDs[i], hop.ChanId)
			}
		}
	}

	// We'll be attempting to send two payments from Alice to Dave. One will
	// have a fee cutoff expressed as a percentage of the amount and the
	// other will have it expressed as a fixed amount of satoshis.
	const paymentAmt = 100
	carolFee := computeFee(lnwire.MilliSatoshi(baseFee), 1, paymentAmt)

	// testFeeCutoff is a helper closure that will ensure the different
	// types of fee limits work as intended when querying routes and sending
	// payments.
	testFeeCutoff := func(feeLimit *lnrpc.FeeLimit) {
		queryRoutesReq := &lnrpc.QueryRoutesRequest{
			PubKey:   dave.PubKeyStr,
			Amt:      paymentAmt,
			FeeLimit: feeLimit,
		}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		routesResp, err := net.Alice.QueryRoutes(ctxt, queryRoutesReq)
		if err != nil {
			t.Fatalf("unable to get routes: %v", err)
		}

		checkRoute(routesResp.Routes[0])

		invoice := &lnrpc.Invoice{Value: paymentAmt}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		invoiceResp, err := dave.AddInvoice(ctxt, invoice)
		if err != nil {
			t.Fatalf("unable to create invoice: %v", err)
		}

		sendReq := &routerrpc.SendPaymentRequest{
			PaymentRequest: invoiceResp.PaymentRequest,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
		}
		switch limit := feeLimit.Limit.(type) {
		case *lnrpc.FeeLimit_Fixed:
			sendReq.FeeLimitMsat = 1000 * limit.Fixed
		case *lnrpc.FeeLimit_Percent:
			sendReq.FeeLimitMsat = 1000 * paymentAmt * limit.Percent / 100
		}

		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		result := sendAndAssertSuccess(ctxt, t, net.Alice, sendReq)

		checkRoute(result.Htlcs[0].Route)
	}

	// We'll start off using percentages first. Since the fee along the
	// route using Carol as an intermediate hop is 10% of the payment's
	// amount, we'll use a lower percentage in order to invalid that route.
	feeLimitPercent := &lnrpc.FeeLimit{
		Limit: &lnrpc.FeeLimit_Percent{
			Percent: baseFee/1000 - 1,
		},
	}
	testFeeCutoff(feeLimitPercent)

	// Now we'll test using fixed fee limit amounts. Since we computed the
	// fee for the route using Carol as an intermediate hop earlier, we can
	// use a smaller value in order to invalidate that route.
	feeLimitFixed := &lnrpc.FeeLimit{
		Limit: &lnrpc.FeeLimit_Fixed{
			Fixed: int64(carolFee.ToSatoshis()) - 1,
		},
	}
	testFeeCutoff(feeLimitFixed)

	// Once we're done, close the channels and shut down the nodes created
	// throughout this test.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAliceBob, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Alice, chanPointAliceCarol, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, net.Bob, chanPointBobDave, false)
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPointCarolDave, false)
}
