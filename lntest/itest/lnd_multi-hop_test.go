package itest

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntypes"
)

func testMultiHopHtlcClaims(net *lntest.NetworkHarness, t *harnessTest) {

	type testCase struct {
		name string
		test func(net *lntest.NetworkHarness, t *harnessTest, alice,
			bob *lntest.HarnessNode, c lnrpc.CommitmentType)
	}

	subTests := []testCase{
		{
			// bob: outgoing our commit timeout
			// carol: incoming their commit watch and see timeout
			name: "local force close immediate expiry",
			test: testMultiHopHtlcLocalTimeout,
		},
		{
			// bob: outgoing watch and see, they sweep on chain
			// carol: incoming our commit, know preimage
			name: "receiver chain claim",
			test: testMultiHopReceiverChainClaim,
		},
		{
			// bob: outgoing our commit watch and see timeout
			// carol: incoming their commit watch and see timeout
			name: "local force close on-chain htlc timeout",
			test: testMultiHopLocalForceCloseOnChainHtlcTimeout,
		},
		{
			// bob: outgoing their commit watch and see timeout
			// carol: incoming our commit watch and see timeout
			name: "remote force close on-chain htlc timeout",
			test: testMultiHopRemoteForceCloseOnChainHtlcTimeout,
		},
		{
			// bob: outgoing our commit watch and see, they sweep on chain
			// bob: incoming our commit watch and learn preimage
			// carol: incoming their commit know preimage
			name: "local chain claim",
			test: testMultiHopHtlcLocalChainClaim,
		},
		{
			// bob: outgoing their commit watch and see, they sweep on chain
			// bob: incoming their commit watch and learn preimage
			// carol: incoming our commit know preimage
			name: "remote chain claim",
			test: testMultiHopHtlcRemoteChainClaim,
		},
		{
			// bob: outgoing and incoming, sweep all on chain
			name: "local htlc aggregation",
			test: testMultiHopHtlcAggregation,
		},
	}

	commitTypes := []lnrpc.CommitmentType{
		lnrpc.CommitmentType_LEGACY,
		lnrpc.CommitmentType_ANCHORS,
	}

	for _, commitType := range commitTypes {
		commitType := commitType
		testName := fmt.Sprintf("committype=%v", commitType.String())

		success := t.t.Run(testName, func(t *testing.T) {
			ht := newHarnessTest(t, net)

			args := nodeArgsForCommitType(commitType)
			alice := net.NewNode(t, "Alice", args)
			defer shutdownAndAssert(net, ht, alice)

			bob := net.NewNode(t, "Bob", args)
			defer shutdownAndAssert(net, ht, bob)

			ctxb := context.Background()
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			net.ConnectNodes(ctxt, t, alice, bob)

			for _, subTest := range subTests {
				subTest := subTest

				logLine := fmt.Sprintf(
					"---- multi-hop htlc subtest "+
						"%s/%s ----\n",
					testName, subTest.name,
				)
				AddToNodeLog(t, net.Alice, logLine)

				success := ht.t.Run(subTest.name, func(t *testing.T) {
					ht := newHarnessTest(t, net)

					// Start each test with the default
					// static fee estimate.
					net.SetFeeEstimate(12500)

					subTest.test(net, ht, alice, bob, commitType)
				})
				if !success {
					return
				}
			}
		})
		if !success {
			return
		}
	}
}

// waitForInvoiceAccepted waits until the specified invoice moved to the
// accepted state by the node.
func waitForInvoiceAccepted(t *harnessTest, node *lntest.HarnessNode,
	payHash lntypes.Hash) {

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	invoiceUpdates, err := node.SubscribeSingleInvoice(ctx,
		&invoicesrpc.SubscribeSingleInvoiceRequest{
			RHash: payHash[:],
		},
	)
	if err != nil {
		t.Fatalf("subscribe single invoice: %v", err)
	}

	for {
		update, err := invoiceUpdates.Recv()
		if err != nil {
			t.Fatalf("invoice update err: %v", err)
		}
		if update.State == lnrpc.Invoice_ACCEPTED {
			break
		}
	}
}

// checkPaymentStatus asserts that the given node list a payment with the given
// preimage has the expected status.
func checkPaymentStatus(ctxt context.Context, node *lntest.HarnessNode,
	preimage lntypes.Preimage, status lnrpc.Payment_PaymentStatus) error {

	req := &lnrpc.ListPaymentsRequest{
		IncludeIncomplete: true,
	}
	paymentsResp, err := node.ListPayments(ctxt, req)
	if err != nil {
		return fmt.Errorf("error when obtaining Alice payments: %v",
			err)
	}

	payHash := preimage.Hash()
	var found bool
	for _, p := range paymentsResp.Payments {
		if p.PaymentHash != payHash.String() {
			continue
		}

		found = true
		if p.Status != status {
			return fmt.Errorf("expected payment status "+
				"%v, got %v", status, p.Status)
		}

		switch status {

		// If this expected status is SUCCEEDED, we expect the final preimage.
		case lnrpc.Payment_SUCCEEDED:
			if p.PaymentPreimage != preimage.String() {
				return fmt.Errorf("preimage doesn't match: %v vs %v",
					p.PaymentPreimage, preimage.String())
			}

		// Otherwise we expect an all-zero preimage.
		default:
			if p.PaymentPreimage != (lntypes.Preimage{}).String() {
				return fmt.Errorf("expected zero preimage, got %v",
					p.PaymentPreimage)
			}
		}

	}

	if !found {
		return fmt.Errorf("payment with payment hash %v not found "+
			"in response", payHash)
	}

	return nil
}

func createThreeHopNetwork(t *harnessTest, net *lntest.NetworkHarness,
	alice, bob *lntest.HarnessNode, carolHodl bool, c lnrpc.CommitmentType) (
	*lnrpc.ChannelPoint, *lnrpc.ChannelPoint, *lntest.HarnessNode) {

	ctxb := context.Background()

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, alice, bob)

	// Make sure there are enough utxos for anchoring.
	for i := 0; i < 2; i++ {
		ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
		net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, alice)

		ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
		net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, bob)
	}

	// We'll start the test by creating a channel between Alice and Bob,
	// which will act as the first leg for out multi-hop HTLC.
	const chanAmt = 1000000
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	aliceChanPoint := openChannelAndAssert(
		ctxt, t, net, alice, bob,
		lntest.OpenChannelParams{
			Amt:            chanAmt,
			CommitmentType: c,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err := alice.WaitForNetworkChannelOpen(ctxt, aliceChanPoint)
	if err != nil {
		t.Fatalf("alice didn't report channel: %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = bob.WaitForNetworkChannelOpen(ctxt, aliceChanPoint)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}

	// Next, we'll create a new node "carol" and have Bob connect to her. If
	// the carolHodl flag is set, we'll make carol always hold onto the
	// HTLC, this way it'll force Bob to go to chain to resolve the HTLC.
	carolFlags := nodeArgsForCommitType(c)
	if carolHodl {
		carolFlags = append(carolFlags, "--hodl.exit-settle")
	}
	carol := net.NewNode(t.t, "Carol", carolFlags)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, bob, carol)

	// Make sure Carol has enough utxos for anchoring. Because the anchor by
	// itself often doesn't meet the dust limit, a utxo from the wallet
	// needs to be attached as an additional input. This can still lead to a
	// positively-yielding transaction.
	for i := 0; i < 2; i++ {
		ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
		net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)
	}

	// We'll then create a channel from Bob to Carol. After this channel is
	// open, our topology looks like:  A -> B -> C.
	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	bobChanPoint := openChannelAndAssert(
		ctxt, t, net, bob, carol,
		lntest.OpenChannelParams{
			Amt:            chanAmt,
			CommitmentType: c,
		},
	)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = bob.WaitForNetworkChannelOpen(ctxt, bobChanPoint)
	if err != nil {
		t.Fatalf("alice didn't report channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = carol.WaitForNetworkChannelOpen(ctxt, bobChanPoint)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	err = alice.WaitForNetworkChannelOpen(ctxt, bobChanPoint)
	if err != nil {
		t.Fatalf("bob didn't report channel: %v", err)
	}

	return aliceChanPoint, bobChanPoint, carol
}

// assertAllTxesSpendFrom asserts that all txes in the list spend from the given
// tx.
func assertAllTxesSpendFrom(t *harnessTest, txes []*wire.MsgTx,
	prevTxid chainhash.Hash) {

	for _, tx := range txes {
		if tx.TxIn[0].PreviousOutPoint.Hash != prevTxid {
			t.Fatalf("tx %v did not spend from %v",
				tx.TxHash(), prevTxid)
		}
	}
}
