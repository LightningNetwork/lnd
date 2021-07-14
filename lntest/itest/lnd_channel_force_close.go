package itest

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/stretchr/testify/require"
)

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
		args = append(args, commitTypeAnchors.Args()...)
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
	commitTypes := []commitType{
		commitTypeLegacy,
		commitTypeAnchors,
	}

	for _, channelType := range commitTypes {
		testName := fmt.Sprintf("committype=%v", channelType)
		logLine := fmt.Sprintf(
			"---- channel force close subtest %s ----\n",
			testName,
		)
		AddToNodeLog(t.t, net.Alice, logLine)

		channelType := channelType
		success := t.t.Run(testName, func(t *testing.T) {
			ht := newHarnessTest(t, net)

			args := channelType.Args()
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
				net, ht, alice, carol, channelType,
			)
		})
		if !success {
			return
		}
	}
}

func channelForceClosureTest(net *lntest.NetworkHarness, t *harnessTest,
	alice, carol *lntest.HarnessNode, channelType commitType) {

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

	// We need one additional UTXO for sweeping the remote anchor.
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, alice)

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
		return predErr == nil
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
	if channelType == commitTypeAnchors {
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

	// To give the neutrino backend some time to catch up with the chain, we
	// wait here until we have enough UTXOs to actually sweep the local and
	// remote anchor.
	const expectedUtxos = 2
	assertNumUTXOs(t.t, alice, expectedUtxos)

	// Mine a block which should confirm the commitment transaction
	// broadcast as a result of the force closure. If there are anchors, we
	// also expect the anchor sweep tx to be in the mempool.
	expectedTxes := 1
	expectedFeeRate := commitFeeRate
	if channelType == commitTypeAnchors {
		expectedTxes = 2
		expectedFeeRate = actualFeeRate
	}

	sweepTxns, err := getNTxsFromMempool(
		net.Miner.Client, expectedTxes, minerMempoolTimeout,
	)
	require.NoError(t.t, err, "sweep txns in miner mempool")

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
	_, aliceAnchor := findCommitAndAnchor(t, net, sweepTxns, aliceCloseTx)

	// If we expect anchors, add alice's anchor to our expected set of
	// reports.
	if channelType == commitTypeAnchors {
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
		if channelType == commitTypeAnchors {
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
	if channelType == commitTypeAnchors {
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
		if channelType == commitTypeAnchors {
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
	if channelType == commitTypeAnchors {
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
	if channelType == commitTypeAnchors {
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
	if channelType == commitTypeAnchors {
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
		return predErr == nil
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
	if channelType == commitTypeAnchors {
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

// padCLTV is a small helper function that pads a cltv value with a block
// padding.
func padCLTV(cltv uint32) uint32 {
	return cltv + uint32(routing.BlockPadding)
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
			predErr = fmt.Errorf("expected to find %d channels "+
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
			predErr = fmt.Errorf("expected to find %d channels "+
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
