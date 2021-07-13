package itest

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// testBasicChannelFunding performs a test exercising expected behavior from a
// basic funding workflow. The test creates a new channel between Alice and
// Bob, then immediately closes the channel after asserting some expected post
// conditions. Finally, the chain itself is checked to ensure the closing
// transaction was mined.
func testBasicChannelFunding(net *lntest.NetworkHarness, t *harnessTest) {

	ctxb := context.Background()

	// Run through the test with combinations of all the different
	// commitment types.
	allTypes := []lnrpc.CommitmentType{
		lnrpc.CommitmentType_LEGACY,
		lnrpc.CommitmentType_STATIC_REMOTE_KEY,
		lnrpc.CommitmentType_ANCHORS,
	}

	// testFunding is a function closure that takes Carol and Dave's
	// commitment types and test the funding flow.
	testFunding := func(carolCommitType, daveCommitType lnrpc.CommitmentType) {
		// Based on the current tweak variable for Carol, we'll
		// preferentially signal the legacy commitment format.  We do
		// the same for Dave shortly below.
		carolArgs := nodeArgsForCommitType(carolCommitType)
		carol := net.NewNode(t.t, "Carol", carolArgs)
		defer shutdownAndAssert(net, t, carol)

		// Each time, we'll send Carol a new set of coins in order to
		// fund the channel.
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

		daveArgs := nodeArgsForCommitType(daveCommitType)
		dave := net.NewNode(t.t, "Dave", daveArgs)
		defer shutdownAndAssert(net, t, dave)

		// Before we start the test, we'll ensure both sides are
		// connected to the funding flow can properly be executed.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		net.EnsureConnected(ctxt, t.t, carol, dave)

		carolChan, daveChan, closeChan, err := basicChannelFundingTest(
			t, net, carol, dave, nil,
		)
		require.NoError(t.t, err, "failed funding flow")

		// Both nodes should report the same commitment
		// type.
		chansCommitType := carolChan.CommitmentType
		require.Equal(
			t.t, chansCommitType,
			daveChan.CommitmentType,
			"commit types don't match",
		)

		// Now check that the commitment type reported
		// by both nodes is what we expect. It will be
		// the minimum of the two nodes' preference, in
		// the order Legacy, Tweakless, Anchors.
		expType := carolCommitType

		switch daveCommitType {

		// Dave supports anchors, type will be what
		// Carol supports.
		case lnrpc.CommitmentType_ANCHORS:

		// Dave only supports tweakless, channel will
		// be downgraded to this type if Carol supports
		// anchors.
		case lnrpc.CommitmentType_STATIC_REMOTE_KEY:
			if expType == lnrpc.CommitmentType_ANCHORS {
				expType = lnrpc.CommitmentType_STATIC_REMOTE_KEY
			}

		// Dave only supoprts legacy type, channel will
		// be downgraded to this type.
		case lnrpc.CommitmentType_LEGACY:
			expType = lnrpc.CommitmentType_LEGACY

		default:
			t.Fatalf("invalid commit type %v", daveCommitType)
		}

		// Check that the signalled type matches what we
		// expect.
		switch {
		case expType == lnrpc.CommitmentType_ANCHORS &&
			chansCommitType == lnrpc.CommitmentType_ANCHORS:

		case expType == lnrpc.CommitmentType_STATIC_REMOTE_KEY &&
			chansCommitType == lnrpc.CommitmentType_STATIC_REMOTE_KEY:

		case expType == lnrpc.CommitmentType_LEGACY &&
			chansCommitType == lnrpc.CommitmentType_LEGACY:

		default:
			t.Fatalf("expected nodes to signal "+
				"commit type %v, instead got "+
				"%v", expType, chansCommitType)
		}

		// As we've concluded this sub-test case we'll
		// now close out the channel for both sides.
		closeChan()
	}

test:
	// We'll test all possible combinations of the feature bit presence
	// that both nodes can signal for this new channel type. We'll make a
	// new Carol+Dave for each test instance as well.
	for _, carolCommitType := range allTypes {
		for _, daveCommitType := range allTypes {
			cc := carolCommitType
			dc := daveCommitType

			testName := fmt.Sprintf(
				"carol_commit=%v,dave_commit=%v", cc, dc,
			)

			logLine := fmt.Sprintf(
				"---- basic channel funding subtest %s ----\n",
				testName,
			)
			AddToNodeLog(t.t, net.Alice, logLine)

			success := t.t.Run(testName, func(t *testing.T) {
				testFunding(cc, dc)
			})

			if !success {
				break test
			}
		}
	}
}

// basicChannelFundingTest is a sub-test of the main testBasicChannelFunding
// test. Given two nodes: Alice and Bob, it'll assert proper channel creation,
// then return a function closure that should be called to assert proper
// channel closure.
func basicChannelFundingTest(t *harnessTest, net *lntest.NetworkHarness,
	alice *lntest.HarnessNode, bob *lntest.HarnessNode,
	fundingShim *lnrpc.FundingShim) (*lnrpc.Channel, *lnrpc.Channel,
	func(), error) {

	chanAmt := funding.MaxBtcFundingAmount
	pushAmt := btcutil.Amount(100000)
	satPerVbyte := btcutil.Amount(1)

	// Record nodes' channel balance before testing.
	aliceChannelBalance := getChannelBalance(t, alice)
	bobChannelBalance := getChannelBalance(t, bob)

	// Creates a helper closure to be used below which asserts the proper
	// response to a channel balance RPC.
	checkChannelBalance := func(node *lntest.HarnessNode,
		oldChannelBalance *lnrpc.ChannelBalanceResponse,
		local, remote btcutil.Amount) {

		newResp := oldChannelBalance

		newResp.LocalBalance.Sat += uint64(local)
		newResp.LocalBalance.Msat += uint64(
			lnwire.NewMSatFromSatoshis(local),
		)
		newResp.RemoteBalance.Sat += uint64(remote)
		newResp.RemoteBalance.Msat += uint64(
			lnwire.NewMSatFromSatoshis(remote),
		)
		// Deprecated fields.
		newResp.Balance += int64(local) // nolint:staticcheck
		assertChannelBalanceResp(t, node, newResp)
	}

	// First establish a channel with a capacity of 0.5 BTC between Alice
	// and Bob with Alice pushing 100k satoshis to Bob's side during
	// funding. This function will block until the channel itself is fully
	// open or an error occurs in the funding process. A series of
	// assertions will be executed to ensure the funding process completed
	// successfully.
	ctxb := context.Background()
	ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, t, net, alice, bob,
		lntest.OpenChannelParams{
			Amt:         chanAmt,
			PushAmt:     pushAmt,
			FundingShim: fundingShim,
			SatPerVByte: satPerVbyte,
		},
	)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)

	err := alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err, "alice didn't report channel")

	err = bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err, "bob didn't report channel")

	cType, err := channelCommitType(alice, chanPoint)
	require.NoError(t.t, err, "unable to get channnel type")

	// With the channel open, ensure that the amount specified above has
	// properly been pushed to Bob.
	aliceLocalBalance := chanAmt - pushAmt - calcStaticFee(cType, 0)
	checkChannelBalance(
		alice, aliceChannelBalance, aliceLocalBalance, pushAmt,
	)
	checkChannelBalance(
		bob, bobChannelBalance, pushAmt, aliceLocalBalance,
	)

	req := &lnrpc.ListChannelsRequest{}
	aliceChannel, err := alice.ListChannels(context.Background(), req)
	require.NoError(t.t, err, "unable to obtain chan")

	bobChannel, err := bob.ListChannels(context.Background(), req)
	require.NoError(t.t, err, "unable to obtain chan")

	closeChan := func() {
		// Finally, immediately close the channel. This function will
		// also block until the channel is closed and will additionally
		// assert the relevant channel closing post conditions.
		ctxt, _ := context.WithTimeout(ctxb, channelCloseTimeout)
		closeChannelAndAssert(ctxt, t, net, alice, chanPoint, false)
	}

	return aliceChannel.Channels[0], bobChannel.Channels[0], closeChan, nil
}

// testUnconfirmedChannelFunding tests that our unconfirmed change outputs can
// be used to fund channels.
func testUnconfirmedChannelFunding(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	const (
		chanAmt = funding.MaxBtcFundingAmount
		pushAmt = btcutil.Amount(100000)
	)

	// We'll start off by creating a node for Carol.
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	// We'll send her some confirmed funds.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, 2*chanAmt, carol)

	// Now let Carol send some funds to herself, making a unconfirmed
	// change output.
	addrReq := &lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := carol.NewAddress(ctxt, addrReq)
	require.NoError(t.t, err, "unable to get new address")

	sendReq := &lnrpc.SendCoinsRequest{
		Addr:   resp.Address,
		Amount: int64(chanAmt) / 5,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = carol.SendCoins(ctxt, sendReq)
	require.NoError(t.t, err, "unable to send coins")

	// Make sure the unconfirmed tx is seen in the mempool.
	_, err = waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	require.NoError(t.t, err, "failed to find tx in miner mempool")

	// Now, we'll connect her to Alice so that they can open a channel
	// together. The funding flow should select Carol's unconfirmed output
	// as she doesn't have any other funds since it's a new node.

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Alice)

	chanOpenUpdate := openChannelStream(
		ctxt, t, net, carol, net.Alice,
		lntest.OpenChannelParams{
			Amt:              chanAmt,
			PushAmt:          pushAmt,
			SpendUnconfirmed: true,
		},
	)

	// Creates a helper closure to be used below which asserts the proper
	// response to a channel balance RPC.
	checkChannelBalance := func(node *lntest.HarnessNode,
		local, remote, pendingLocal, pendingRemote btcutil.Amount) {
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
			PendingOpenLocalBalance: &lnrpc.Amount{
				Sat: uint64(pendingLocal),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					pendingLocal,
				)),
			},
			PendingOpenRemoteBalance: &lnrpc.Amount{
				Sat: uint64(pendingRemote),
				Msat: uint64(lnwire.NewMSatFromSatoshis(
					pendingRemote,
				)),
			},
			UnsettledLocalBalance:  &lnrpc.Amount{},
			UnsettledRemoteBalance: &lnrpc.Amount{},
			// Deprecated fields.
			Balance:            int64(local),
			PendingOpenBalance: int64(pendingLocal),
		}
		assertChannelBalanceResp(t, node, expectedResponse)
	}

	// As the channel is pending open, it's expected Carol has both zero
	// local and remote balances, and pending local/remote should not be
	// zero.
	//
	// Note that atm we haven't obtained the chanPoint yet, so we use the
	// type directly.
	cType := lnrpc.CommitmentType_STATIC_REMOTE_KEY
	carolLocalBalance := chanAmt - pushAmt - calcStaticFee(cType, 0)
	checkChannelBalance(carol, 0, 0, carolLocalBalance, pushAmt)

	// For Alice, her local/remote balances should be zero, and the
	// local/remote balances are the mirror of Carol's.
	checkChannelBalance(net.Alice, 0, 0, pushAmt, carolLocalBalance)

	// Confirm the channel and wait for it to be recognized by both
	// parties. Two transactions should be mined, the unconfirmed spend and
	// the funding tx.
	mineBlocks(t, net, 6, 2)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	chanPoint, err := net.WaitForChannelOpen(ctxt, chanOpenUpdate)
	require.NoError(t.t, err, "error while waitinng for channel open")

	// With the channel open, we'll check the balances on each side of the
	// channel as a sanity check to ensure things worked out as intended.
	checkChannelBalance(carol, carolLocalBalance, pushAmt, 0, 0)
	checkChannelBalance(net.Alice, pushAmt, carolLocalBalance, 0, 0)

	// Now that we're done with the test, the channel can be closed.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, carol, chanPoint, false)
}

// testexternalfundingchanpoint tests that we're able to carry out a normal
// channel funding workflow given a channel point that was constructed outside
// the main daemon.
func testExternalFundingChanPoint(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, we'll create two new nodes that we'll use to open channel
	// between for this test.
	carol := net.NewNode(t.t, "carol", nil)
	defer shutdownAndAssert(net, t, carol)

	dave := net.NewNode(t.t, "dave", nil)
	defer shutdownAndAssert(net, t, dave)

	// Carol will be funding the channel, so we'll send some coins over to
	// her and ensure they have enough confirmations before we proceed.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	// Before we start the test, we'll ensure both sides are connected to
	// the funding flow can properly be executed.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, carol, dave)

	// At this point, we're ready to simulate our external channel funding
	// flow. To start with, we'll create a pending channel with a shim for
	// a transaction that will never be published.
	const thawHeight uint32 = 10
	const chanSize = funding.MaxBtcFundingAmount
	fundingShim1, chanPoint1, _ := deriveFundingShim(
		net, t, carol, dave, chanSize, thawHeight, 1, false,
	)
	_ = openChannelStream(
		ctxb, t, net, carol, dave, lntest.OpenChannelParams{
			Amt:         chanSize,
			FundingShim: fundingShim1,
		},
	)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, carol, dave, 1)

	// That channel is now pending forever and normally would saturate the
	// max pending channel limit for both nodes. But because the channel is
	// externally funded, we should still be able to open another one. Let's
	// do exactly that now. For this one we publish the transaction so we
	// can mine it later.
	fundingShim2, chanPoint2, _ := deriveFundingShim(
		net, t, carol, dave, chanSize, thawHeight, 2, true,
	)

	// At this point, we'll now carry out the normal basic channel funding
	// test as everything should now proceed as normal (a regular channel
	// funding flow).
	carolChan, daveChan, _, err := basicChannelFundingTest(
		t, net, carol, dave, fundingShim2,
	)
	require.NoError(t.t, err)

	// Both channels should be marked as frozen with the proper thaw
	// height.
	require.Equal(
		t.t, thawHeight, carolChan.ThawHeight, "thaw height unmatched",
	)
	require.Equal(
		t.t, thawHeight, daveChan.ThawHeight, "thaw height unmatched",
	)

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

	// Now that the channels are open, and we've confirmed that they're
	// operational, we'll now ensure that the channels are frozen as
	// intended (if requested).
	//
	// First, we'll try to close the channel as Carol, the initiator. This
	// should fail as a frozen channel only allows the responder to
	// initiate a channel close.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	_, _, err = net.CloseChannel(ctxt, carol, chanPoint2, false)
	require.Error(t.t, err,
		"carol wasn't denied a co-op close attempt "+
			"for a frozen channel",
	)

	// Next we'll try but this time with Dave (the responder) as the
	// initiator. This time the channel should be closed as normal.
	ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
	closeChannelAndAssert(ctxt, t, net, dave, chanPoint2, false)

	// As a last step, we check if we still have the pending channel hanging
	// around because we never published the funding TX.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	assertNumOpenChannelsPending(ctxt, t, carol, dave, 1)

	// Let's make sure we can abandon it.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = carol.AbandonChannel(ctxt, &lnrpc.AbandonChannelRequest{
		ChannelPoint:           chanPoint1,
		PendingFundingShimOnly: true,
	})
	require.NoError(t.t, err)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = dave.AbandonChannel(ctxt, &lnrpc.AbandonChannelRequest{
		ChannelPoint:           chanPoint1,
		PendingFundingShimOnly: true,
	})
	require.NoError(t.t, err)

	// It should now not appear in the pending channels anymore.
	assertNumOpenChannelsPending(ctxt, t, carol, dave, 0)
}
