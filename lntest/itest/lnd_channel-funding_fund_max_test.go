// +build rpctest

package itest

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// The standard fee rate used for a funding transaction.
var feeRate = chainfee.SatPerKWeight(12500)

type chanFundMaxTestCase struct {
	// name is the name of the target test case.
	name string

	// amount is the amount in the Carol's wallet.
	amount btcutil.Amount

	// pushAmt is the amount to be pushed to Dave.
	pushAmt btcutil.Amount

	// feeRate is an optional fee in satoshi/bytes used when opening a channel.
	feeRate btcutil.Amount

	// carolBalance is Carol's expected balance in her channel before
	// subtracting the reserved amount to pay for a commitment transaction.
	carolBalance btcutil.Amount

	// chanOpenShouldFail denotes if we expect the channel opening to fail.
	chanOpenShouldFail bool
}

func testChannelFundMax(net *lntest.NetworkHarness, ht *harnessTest) {
	ctxb := context.Background()

	// Create two new nodes that open a channel between each other for these
	// tests.
	carol, err := net.NewNode("carol", nil)
	if err != nil {
		ht.Fatalf("unable to start new node: %v", err)
	}
	defer shutdownAndAssert(net, ht, carol)

	dave, err := net.NewNode("dave", nil)
	if err != nil {
		ht.Fatalf("unable to start new node: %v", err)
	}
	defer shutdownAndAssert(net, ht, dave)

	// Ensure both sides are connected so the funding flow can be properly
	// executed.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	err = net.EnsureConnected(ctxt, carol, dave)
	if err != nil {
		ht.Fatalf("unable to connect peers: %v", err)
	}

	// Helper function that returns the fee estimate used for a tx
	// with the given number of inputs and the optional change output.
	// This matches the estimate done by the wallet.
	fundingFee := func(numInput int, change bool) btcutil.Amount {
		var weightEstimate input.TxWeightEstimator

		// All inputs.
		for i := 0; i < numInput; i++ {
			weightEstimate.AddP2WKHInput()
		}

		// The multisig funding output.
		weightEstimate.AddP2WSHOutput()

		// Optionally count a change output.
		if change {
			weightEstimate.AddP2WKHOutput()
		}

		totalWeight := int64(weightEstimate.Weight())
		return feeRate.FeeForWeight(totalWeight)
	}

	// Helper closure to assert the proper response to a channel balance RPC.
	checkChannelBalance := func(node lnrpc.LightningClient,
		amount btcutil.Amount) error {

		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		response, err := node.ChannelBalance(
			ctxt, &lnrpc.ChannelBalanceRequest{},
		)
		if err != nil {
			ht.Fatalf("unable to get channel balance: %v", err)
		}

		balance := btcutil.Amount(response.Balance)
		if balance != amount {
			return fmt.Errorf("channel balance wrong: got (%v), "+
				"want (%v)", balance, amount)
		}

		return nil
	}

	// Helper function to send coins to a node.
	sendCoinsAndAssert := func(amt btcutil.Amount,
		target *lntest.HarnessNode) {

		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		err = net.SendCoins(ctxt, amt, target)
		if err != nil {
			ht.Fatalf(
				"unable to send '%v' coins to %v: %v", amt,
				target.Name(), err,
			)
		}
	}

	// Helper function to sweep funds from a node wallet.
	var minerAddr btcutil.Address
	sweepNodeWalletAndAssert := func(node *lntest.HarnessNode) {
		// Send funds back to the miner node.
		if minerAddr == nil {
			var err error
			minerAddr, err = net.Miner.NewAddress()
			if err != nil {
				ht.Fatalf(
					"unable to create new miner address: %v",
					err,
				)
			}
		}

		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		if _, err := carol.SendCoins(ctxt, &lnrpc.SendCoinsRequest{
			Addr:    minerAddr.String(),
			SendAll: true,
		}); err != nil {
			ht.Fatalf("unable to sweep coins from node %v: %v",
				node.Name(), err)
		}

		// Ensures we don't leave any transaction in the mempool after sweeping.
		mineBlocks(ht, net, 1, 1)

		// Make sure all funds were swept.
		checkChannelBalance(node, 0)
	}

	runTestCase := func(carol, dave *lntest.HarnessNode,
		testCase *chanFundMaxTestCase) func(t *testing.T) {

		return func(t *testing.T) {
			sendCoinsAndAssert(testCase.amount, carol)
			defer func() {
				if testCase.amount <= 2000 {
					// Add additional funds to sweep "dust" UTXO.
					sendCoinsAndAssert(
						btcutil.Amount(100000), carol,
					)
				}

				// Remove all funds from Carol.
				sweepNodeWalletAndAssert(carol)
			}()

			// The parameters to try opening the channel with.
			chanParams := lntest.OpenChannelParams{
				Amt:         0,
				PushAmt:     testCase.pushAmt,
				SatPerVByte: testCase.feeRate,
				FundMax:     true,
			}

			// If we don't expect the channel opening to be
			// successful, simply check for an error.
			if testCase.chanOpenShouldFail {

				ctxt, _ = context.WithTimeout(
					ctxb, channelOpenTimeout,
				)

				_, err = net.OpenChannel(
					ctxt, carol, dave, chanParams,
				)

				if err == nil {
					t.Errorf("should not open channel "+
						"for: %v", testCase.name)
				}

				return
			}

			// Otherwise, if we expect to open a channel use the helper function.
			ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
			chanPoint := openChannelAndAssert(
				ctxt, ht, net, carol, dave, chanParams,
			)
			defer func() {
				// Close the channel between Carol and Dave, asserting
				// that the channel has been properly closed on-chain.
				ctxt, _ = context.WithTimeout(
					ctxb, channelCloseTimeout,
				)

				closeChannelAndAssert(
					ctxt, ht, net, carol, chanPoint, false,
				)
			}()

			cType, err := channelCommitType(carol, chanPoint)
			if err != nil {
				ht.Fatalf("unable to get channel type: %v", err)
			}

			// Carol's balance should be her amount subtracted by the
			// commitment transaciton fee.
			err = checkChannelBalance(
				carol, testCase.carolBalance-cType.calcStaticFee(0),
			)
			if err != nil {
				t.Errorf("carol's balance is wrong: %v", err)
			}

			// Ensure Dave's balance within the channel is equal to the push amount.
			err = checkChannelBalance(dave, testCase.pushAmt)
			if err != nil {
				t.Errorf("dave's balance is wrong: %v", err)
			}
		}
	}

	var testCases = []*chanFundMaxTestCase{
		{
			name:               "wallet amount is dust",
			amount:             2000,
			chanOpenShouldFail: true,
		},

		{
			name:   "wallet amount < min chan size (~18000sat)",
			amount: 18000,
			// Using a feeRate of 1 sat/vByte ensures that we test for
			// min chan size and not excessive fees.
			feeRate:            1,
			chanOpenShouldFail: true,
		},

		{
			name:   "wallet amount > min chan size (37000sat)",
			amount: 37000,
			// The transaction fee to open the channel must be subtracted from
			// Carol's balance (since wallet balance < max-chan-size).
			carolBalance: btcutil.Amount(37000) - fundingFee(1, false),
		},

		{
			name:         "wallet amount > max chan size (20000000sat)",
			amount:       20000000,
			carolBalance: lnd.MaxFundingAmount,
		},

		// Checks that to push corresponding amount to remote the local
		// amount is not increased above MaxFundingAmount.
		{
			name:               "wallet amount > max chan size, push amount == max-chan-size",
			amount:             20000000,
			pushAmt:            lnd.MaxFundingAmount,
			chanOpenShouldFail: true,
		},

		// Checks that enough local funds are kept in reserve before
		// allowing to push amount to remote.
		{
			name:               "wallet amount > max chan size, push amount == max-chan-size - 1",
			amount:             20000000,
			pushAmt:            lnd.MaxFundingAmount - 1,
			chanOpenShouldFail: true,
		},

		{
			name:         "wallet amount > max chan size, push amount 16766000",
			amount:       20000000,
			pushAmt:      16766000,
			carolBalance: lnd.MaxFundingAmount - 16766000,
		},
	}

	for _, testCase := range testCases {
		success := ht.t.Run(
			testCase.name, runTestCase(carol, dave, testCase),
		)

		// Stop at the first failure. Mimic behavior of original test
		// framework.
		if !success {
			break
		}
	}
}
