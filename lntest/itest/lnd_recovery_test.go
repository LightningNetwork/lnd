package itest

import (
	"context"
	"math"

	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
)

// testGetRecoveryInfo checks whether lnd gives the right information about
// the wallet recovery process.
func testGetRecoveryInfo(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, create a new node with strong passphrase and grab the mnemonic
	// used for key derivation. This will bring up Carol with an empty
	// wallet, and such that she is synced up.
	password := []byte("The Magic Words are Squeamish Ossifrage")
	carol, mnemonic, _, err := net.NewNodeWithSeed(
		"Carol", nil, password, false,
	)
	if err != nil {
		t.Fatalf("unable to create node with seed; %v", err)
	}

	shutdownAndAssert(net, t, carol)

	checkInfo := func(expectedRecoveryMode, expectedRecoveryFinished bool,
		expectedProgress float64, recoveryWindow int32) {

		// Restore Carol, passing in the password, mnemonic, and
		// desired recovery window.
		node, err := net.RestoreNodeWithSeed(
			"Carol", nil, password, mnemonic, "", recoveryWindow,
			nil,
		)
		if err != nil {
			t.Fatalf("unable to restore node: %v", err)
		}

		// Wait for Carol to sync to the chain.
		_, minerHeight, err := net.Miner.Node.GetBestBlock()
		if err != nil {
			t.Fatalf("unable to get current blockheight %v", err)
		}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		err = waitForNodeBlockHeight(ctxt, node, minerHeight)
		if err != nil {
			t.Fatalf("unable to sync to chain: %v", err)
		}

		// Query carol for her current wallet recovery progress.
		var (
			recoveryMode     bool
			recoveryFinished bool
			progress         float64
		)

		err = wait.Predicate(func() bool {
			// Verify that recovery info gives the right response.
			req := &lnrpc.GetRecoveryInfoRequest{}
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			resp, err := node.GetRecoveryInfo(ctxt, req)
			if err != nil {
				t.Fatalf("unable to query recovery info: %v", err)
			}

			recoveryMode = resp.RecoveryMode
			recoveryFinished = resp.RecoveryFinished
			progress = resp.Progress

			if recoveryMode != expectedRecoveryMode ||
				recoveryFinished != expectedRecoveryFinished ||
				progress != expectedProgress {
				return false
			}

			return true
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("expected recovery mode to be %v, got %v, "+
				"expected recovery finished to be %v, got %v, "+
				"expected progress %v, got %v",
				expectedRecoveryMode, recoveryMode,
				expectedRecoveryFinished, recoveryFinished,
				expectedProgress, progress,
			)
		}

		// Lastly, shutdown this Carol so we can move on to the next
		// restoration.
		shutdownAndAssert(net, t, node)
	}

	// Restore Carol with a recovery window of 0. Since it's not in recovery
	// mode, the recovery info will give a response with recoveryMode=false,
	// recoveryFinished=false, and progress=0
	checkInfo(false, false, 0, 0)

	// Change the recovery windown to be 1 to turn on recovery mode. Since the
	// current chain height is the same as the birthday height, it should
	// indicate the recovery process is finished.
	checkInfo(true, true, 1, 1)

	// We now go ahead 5 blocks. Because the wallet's syncing process is
	// controlled by a goroutine in the background, it will catch up quickly.
	// This makes the recovery progress back to 1.
	mineBlocks(t, net, 5, 0)
	checkInfo(true, true, 1, 1)
}

// testOnchainFundRecovery checks lnd's ability to rescan for onchain outputs
// when providing a valid aezeed that owns outputs on the chain. This test
// performs multiple restorations using the same seed and various recovery
// windows to ensure we detect funds properly.
func testOnchainFundRecovery(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, create a new node with strong passphrase and grab the mnemonic
	// used for key derivation. This will bring up Carol with an empty
	// wallet, and such that she is synced up.
	password := []byte("The Magic Words are Squeamish Ossifrage")
	carol, mnemonic, _, err := net.NewNodeWithSeed(
		"Carol", nil, password, false,
	)
	if err != nil {
		t.Fatalf("unable to create node with seed; %v", err)
	}
	shutdownAndAssert(net, t, carol)

	// Create a closure for testing the recovery of Carol's wallet. This
	// method takes the expected value of Carol's balance when using the
	// given recovery window. Additionally, the caller can specify an action
	// to perform on the restored node before the node is shutdown.
	restoreCheckBalance := func(expAmount int64, expectedNumUTXOs uint32,
		recoveryWindow int32, fn func(*lntest.HarnessNode)) {

		// Restore Carol, passing in the password, mnemonic, and
		// desired recovery window.
		node, err := net.RestoreNodeWithSeed(
			"Carol", nil, password, mnemonic, "", recoveryWindow,
			nil,
		)
		if err != nil {
			t.Fatalf("unable to restore node: %v", err)
		}

		// Query carol for her current wallet balance, and also that we
		// gain the expected number of UTXOs.
		var (
			currBalance  int64
			currNumUTXOs uint32
		)
		err = wait.Predicate(func() bool {
			req := &lnrpc.WalletBalanceRequest{}
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			resp, err := node.WalletBalance(ctxt, req)
			if err != nil {
				t.Fatalf("unable to query wallet balance: %v",
					err)
			}
			currBalance = resp.ConfirmedBalance

			utxoReq := &lnrpc.ListUnspentRequest{
				MaxConfs: math.MaxInt32,
			}
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			utxoResp, err := node.ListUnspent(ctxt, utxoReq)
			if err != nil {
				t.Fatalf("unable to query utxos: %v", err)
			}
			currNumUTXOs = uint32(len(utxoResp.Utxos))

			// Verify that Carol's balance and number of UTXOs
			// matches what's expected.
			if expAmount != currBalance {
				return false
			}
			if currNumUTXOs != expectedNumUTXOs {
				return false
			}

			return true
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("expected restored node to have %d satoshis, "+
				"instead has %d satoshis, expected %d utxos "+
				"instead has %d", expAmount, currBalance,
				expectedNumUTXOs, currNumUTXOs)
		}

		// If the user provided a callback, execute the commands against
		// the restored Carol.
		if fn != nil {
			fn(node)
		}

		// Lastly, shutdown this Carol so we can move on to the next
		// restoration.
		shutdownAndAssert(net, t, node)
	}

	// Create a closure-factory for building closures that can generate and
	// skip a configurable number of addresses, before finally sending coins
	// to a next generated address. The returned closure will apply the same
	// behavior to both default P2WKH and NP2WKH scopes.
	skipAndSend := func(nskip int) func(*lntest.HarnessNode) {
		return func(node *lntest.HarnessNode) {
			newP2WKHAddrReq := &lnrpc.NewAddressRequest{
				Type: AddrTypeWitnessPubkeyHash,
			}

			newNP2WKHAddrReq := &lnrpc.NewAddressRequest{
				Type: AddrTypeNestedPubkeyHash,
			}

			// Generate and skip the number of addresses requested.
			for i := 0; i < nskip; i++ {
				ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
				_, err = node.NewAddress(ctxt, newP2WKHAddrReq)
				if err != nil {
					t.Fatalf("unable to generate new "+
						"p2wkh address: %v", err)
				}

				ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
				_, err = node.NewAddress(ctxt, newNP2WKHAddrReq)
				if err != nil {
					t.Fatalf("unable to generate new "+
						"np2wkh address: %v", err)
				}
			}

			// Send one BTC to the next P2WKH address.
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			err = net.SendCoins(
				ctxt, btcutil.SatoshiPerBitcoin, node,
			)
			if err != nil {
				t.Fatalf("unable to send coins to node: %v",
					err)
			}

			// And another to the next NP2WKH address.
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			err = net.SendCoinsNP2WKH(
				ctxt, btcutil.SatoshiPerBitcoin, node,
			)
			if err != nil {
				t.Fatalf("unable to send coins to node: %v",
					err)
			}
		}
	}

	// Restore Carol with a recovery window of 0. Since no coins have been
	// sent, her balance should be zero.
	//
	// After, one BTC is sent to both her first external P2WKH and NP2WKH
	// addresses.
	restoreCheckBalance(0, 0, 0, skipAndSend(0))

	// Check that restoring without a look-ahead results in having no funds
	// in the wallet, even though they exist on-chain.
	restoreCheckBalance(0, 0, 0, nil)

	// Now, check that using a look-ahead of 1 recovers the balance from
	// the two transactions above. We should also now have 2 UTXOs in the
	// wallet at the end of the recovery attempt.
	//
	// After, we will generate and skip 9 P2WKH and NP2WKH addresses, and
	// send another BTC to the subsequent 10th address in each derivation
	// path.
	restoreCheckBalance(2*btcutil.SatoshiPerBitcoin, 2, 1, skipAndSend(9))

	// Check that using a recovery window of 9 does not find the two most
	// recent txns.
	restoreCheckBalance(2*btcutil.SatoshiPerBitcoin, 2, 9, nil)

	// Extending our recovery window to 10 should find the most recent
	// transactions, leaving the wallet with 4 BTC total. We should also
	// learn of the two additional UTXOs created above.
	//
	// After, we will skip 19 more addrs, sending to the 20th address past
	// our last found address, and repeat the same checks.
	restoreCheckBalance(4*btcutil.SatoshiPerBitcoin, 4, 10, skipAndSend(19))

	// Check that recovering with a recovery window of 19 fails to find the
	// most recent transactions.
	restoreCheckBalance(4*btcutil.SatoshiPerBitcoin, 4, 19, nil)

	// Ensure that using a recovery window of 20 succeeds with all UTXOs
	// found and the final balance reflected.

	// After these checks are done, we'll want to make sure we can also
	// recover change address outputs.  This is mainly motivated by a now
	// fixed bug in the wallet in which change addresses could at times be
	// created outside of the default key scopes. Recovery only used to be
	// performed on the default key scopes, so ideally this test case
	// would've caught the bug earlier. Carol has received 6 BTC so far from
	// the miner, we'll send 5 back to ensure all of her UTXOs get spent to
	// avoid fee discrepancies and a change output is formed.
	const minerAmt = 5 * btcutil.SatoshiPerBitcoin
	const finalBalance = 6 * btcutil.SatoshiPerBitcoin
	promptChangeAddr := func(node *lntest.HarnessNode) {
		minerAddr, err := net.Miner.NewAddress()
		if err != nil {
			t.Fatalf("unable to create new miner address: %v", err)
		}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		resp, err := node.SendCoins(ctxt, &lnrpc.SendCoinsRequest{
			Addr:   minerAddr.String(),
			Amount: minerAmt,
		})
		if err != nil {
			t.Fatalf("unable to send coins to miner: %v", err)
		}
		txid, err := waitForTxInMempool(
			net.Miner.Node, minerMempoolTimeout,
		)
		if err != nil {
			t.Fatalf("transaction not found in mempool: %v", err)
		}
		if resp.Txid != txid.String() {
			t.Fatalf("txid mismatch: %v vs %v", resp.Txid,
				txid.String())
		}
		block := mineBlocks(t, net, 1, 1)[0]
		assertTxInBlock(t, block, txid)
	}
	restoreCheckBalance(finalBalance, 6, 20, promptChangeAddr)

	// We should expect a static fee of 27750 satoshis for spending 6 inputs
	// (3 P2WPKH, 3 NP2WPKH) to two P2WPKH outputs. Carol should therefore
	// only have one UTXO present (the change output) of 6 - 5 - fee BTC.
	const fee = 27750
	restoreCheckBalance(finalBalance-minerAmt-fee, 1, 21, nil)
}
