package itest

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/stretchr/testify/require"
)

// TODO(yy): move channel force closed related tests into this file.

// testCommitmentTransactionDeadline tests that the anchor sweep transaction is
// taking account of the deadline of the commitment transaction. It tests two
// scenarios:
//   1) when the CPFP is skipped, checks that the deadline is not used.
//   2) when the CPFP is used, checks that the deadline is applied.
// Note that whether the deadline is used or not is implicitly checked by its
// corresponding fee rates.
func testCommitmentTransactionDeadline(net *lntest.NetworkHarness,
	t *harnessTest) {

	// Get the default max fee rate used in sweeping the commitment
	// transaction.
	defaultMax := lnwallet.DefaultAnchorsCommitMaxFeeRateSatPerVByte
	maxPerKw := chainfee.SatPerKVByte(defaultMax * 1000).FeePerKWeight()

	const (
		// feeRateConfDefault(sat/kw) is used when no conf target is
		// set. This value will be returned by the fee estimator but
		// won't be used because our commitment fee rate is capped by
		// DefaultAnchorsCommitMaxFeeRateSatPerVByte.
		feeRateDefault = 20000

		// finalCTLV is used when Alice sends payment to Bob.
		finalCTLV = 144

		// deadline is used when Alice sweep the anchor. Notice there
		// is a block padding of 3 added, such that the value of
		// deadline is 147.
		deadline = uint32(finalCTLV + routing.BlockPadding)
	)

	// feeRateSmall(sat/kw) is used when we want to skip the CPFP
	// on anchor transactions. When the fee rate is smaller than
	// the parent's (commitment transaction) fee rate, the CPFP
	// will be skipped. Atm, the parent tx's fee rate is roughly
	// 2500 sat/kw in this test.
	feeRateSmall := maxPerKw / 2

	// feeRateLarge(sat/kw) is used when we want to use the anchor
	// transaction to CPFP our commitment transaction.
	feeRateLarge := maxPerKw * 2

	ctxt, cancel := context.WithTimeout(
		context.Background(), defaultTimeout,
	)
	defer cancel()

	// Before we start, set up the default fee rate and we will test the
	// actual fee rate against it to decide whether we are using the
	// deadline to perform fee estimation.
	net.SetFeeEstimate(feeRateDefault)

	// setupNode creates a new node and sends 1 btc to the node.
	setupNode := func(name string) *lntest.HarnessNode {
		// Create the node.
		args := []string{"--hodl.exit-settle"}
		args = append(args, nodeArgsForCommitType(lnrpc.CommitmentType_ANCHORS)...)
		node := net.NewNode(t.t, name, args)

		// Send some coins to the node.
		net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, node)
		return node
	}

	// calculateSweepFeeRate runs multiple steps to calculate the fee rate
	// used in sweeping the transactions.
	calculateSweepFeeRate := func(expectedSweepTxNum int) int64 {
		// Create two nodes, Alice and Bob.
		alice := setupNode("Alice")
		defer shutdownAndAssert(net, t, alice)

		bob := setupNode("Bob")
		defer shutdownAndAssert(net, t, bob)

		// Connect Alice to Bob.
		net.ConnectNodes(ctxt, t.t, alice, bob)

		// Open a channel between Alice and Bob.
		chanPoint := openChannelAndAssert(
			ctxt, t, net, alice, bob,
			lntest.OpenChannelParams{
				Amt:     10e6,
				PushAmt: 5e6,
			},
		)

		// Send a payment with a specified finalCTLVDelta, which will
		// be used as our deadline later on when Alice force closes the
		// channel.
		_, err := alice.RouterClient.SendPaymentV2(
			ctxt,
			&routerrpc.SendPaymentRequest{
				Dest:           bob.PubKey[:],
				Amt:            10e4,
				PaymentHash:    makeFakePayHash(t),
				FinalCltvDelta: finalCTLV,
				TimeoutSeconds: 60,
				FeeLimitMsat:   noFeeLimitMsat,
			},
		)
		require.NoError(t.t, err, "unable to send alice htlc")

		// Once the HTLC has cleared, all the nodes in our mini network
		// should show that the HTLC has been locked in.
		nodes := []*lntest.HarnessNode{alice, bob}
		err = wait.NoError(func() error {
			return assertNumActiveHtlcs(nodes, 1)
		}, defaultTimeout)
		require.NoError(t.t, err, "htlc mismatch")

		// Alice force closes the channel.
		_, _, err = net.CloseChannel(ctxt, alice, chanPoint, true)
		require.NoError(t.t, err, "unable to force close channel")

		// Now that the channel has been force closed, it should show
		// up in the PendingChannels RPC under the waiting close
		// section.
		pendingChansRequest := &lnrpc.PendingChannelsRequest{}
		pendingChanResp, err := alice.PendingChannels(
			ctxt, pendingChansRequest,
		)
		require.NoError(
			t.t, err, "unable to query for pending channels",
		)
		require.NoError(
			t.t, checkNumWaitingCloseChannels(pendingChanResp, 1),
		)

		// We should see only one sweep transaction because the anchor
		// sweep is skipped.
		sweepTxns, err := getNTxsFromMempool(
			net.Miner.Client,
			expectedSweepTxNum, minerMempoolTimeout,
		)
		require.NoError(
			t.t, err, "failed to find commitment tx in mempool",
		)

		// Mine a block to confirm these transactions such that they
		// don't remain in the mempool for any subsequent tests.
		_, err = net.Miner.Client.Generate(1)
		require.NoError(t.t, err, "unable to mine blocks")

		// Calculate the fee rate used.
		feeRate := calculateTxnsFeeRate(t.t, net.Miner, sweepTxns)

		return feeRate
	}

	// Setup our fee estimation for the deadline. Because the fee rate is
	// smaller than the parent tx's fee rate, this value won't be used and
	// we should see only one sweep tx in the mempool.
	net.SetFeeEstimateWithConf(feeRateSmall, deadline)

	// Calculate fee rate used.
	feeRate := calculateSweepFeeRate(1)

	// We expect the default max fee rate is used. Allow some deviation
	// because weight estimates during tx generation are estimates.
	require.InEpsilonf(
		t.t, int64(maxPerKw), feeRate, 0.01,
		"expected fee rate:%d, got fee rate:%d", maxPerKw, feeRate,
	)

	// Setup our fee estimation for the deadline. Because the fee rate is
	// greater than the parent tx's fee rate, this value will be used to
	// sweep the anchor transaction and we should see two sweep
	// transactions in the mempool.
	net.SetFeeEstimateWithConf(feeRateLarge, deadline)

	// Calculate fee rate used.
	feeRate = calculateSweepFeeRate(2)

	// We expect the anchor to be swept with the deadline, which has the
	// fee rate of feeRateLarge.
	require.InEpsilonf(
		t.t, int64(feeRateLarge), feeRate, 0.01,
		"expected fee rate:%d, got fee rate:%d", feeRateLarge, feeRate,
	)
}

// calculateTxnsFeeRate takes a list of transactions and estimates the fee rate
// used to sweep them.
func calculateTxnsFeeRate(t *testing.T,
	miner *rpctest.Harness, txns []*wire.MsgTx) int64 {

	var totalWeight, totalFee int64
	for _, tx := range txns {
		utx := btcutil.NewTx(tx)
		totalWeight += blockchain.GetTransactionWeight(utx)

		fee, err := getTxFee(miner.Client, tx)
		require.NoError(t, err)

		totalFee += int64(fee)
	}
	feeRate := totalFee * 1000 / totalWeight

	return feeRate
}
