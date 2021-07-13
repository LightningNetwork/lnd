package itest

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/stretchr/testify/require"
)

// testCPFP ensures that the daemon can bump an unconfirmed  transaction's fee
// rate by broadcasting a Child-Pays-For-Parent (CPFP) transaction.
//
// TODO(wilmer): Add RBF case once btcd supports it.
func testCPFP(net *lntest.NetworkHarness, t *harnessTest) {
	// Skip this test for neutrino, as it's not aware of mempool
	// transactions.
	if net.BackendCfg.Name() == lntest.NeutrinoBackendName {
		t.Skipf("skipping CPFP test for neutrino backend")
	}

	// We'll start the test by sending Alice some coins, which she'll use to
	// send to Bob.
	ctxb := context.Background()
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, net.Alice)

	// Create an address for Bob to send the coins to.
	addrReq := &lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := net.Bob.NewAddress(ctxt, addrReq)
	if err != nil {
		t.Fatalf("unable to get new address for bob: %v", err)
	}

	// Send the coins from Alice to Bob. We should expect a transaction to
	// be broadcast and seen in the mempool.
	sendReq := &lnrpc.SendCoinsRequest{
		Addr:   resp.Address,
		Amount: btcutil.SatoshiPerBitcoin,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	if _, err = net.Alice.SendCoins(ctxt, sendReq); err != nil {
		t.Fatalf("unable to send coins to bob: %v", err)
	}

	txid, err := waitForTxInMempool(net.Miner.Client, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("expected one mempool transaction: %v", err)
	}

	// We'll then extract the raw transaction from the mempool in order to
	// determine the index of Bob's output.
	tx, err := net.Miner.Client.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("unable to extract raw transaction from mempool: %v",
			err)
	}
	bobOutputIdx := -1
	for i, txOut := range tx.MsgTx().TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, net.Miner.ActiveNet,
		)
		if err != nil {
			t.Fatalf("unable to extract address from pkScript=%x: "+
				"%v", txOut.PkScript, err)
		}
		if addrs[0].String() == resp.Address {
			bobOutputIdx = i
		}
	}
	if bobOutputIdx == -1 {
		t.Fatalf("bob's output was not found within the transaction")
	}

	// Wait until bob has seen the tx and considers it as owned.
	op := &lnrpc.OutPoint{
		TxidBytes:   txid[:],
		OutputIndex: uint32(bobOutputIdx),
	}
	assertWalletUnspent(t, net.Bob, op)

	// We'll attempt to bump the fee of this transaction by performing a
	// CPFP from Alice's point of view.
	bumpFeeReq := &walletrpc.BumpFeeRequest{
		Outpoint: op,
		SatPerVbyte: uint64(
			sweep.DefaultMaxFeeRate.FeePerKVByte() / 2000,
		),
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = net.Bob.WalletKitClient.BumpFee(ctxt, bumpFeeReq)
	if err != nil {
		t.Fatalf("unable to bump fee: %v", err)
	}

	// We should now expect to see two transactions within the mempool, a
	// parent and its child.
	_, err = waitForNTxsInMempool(net.Miner.Client, 2, minerMempoolTimeout)
	if err != nil {
		t.Fatalf("expected two mempool transactions: %v", err)
	}

	// We should also expect to see the output being swept by the
	// UtxoSweeper. We'll ensure it's using the fee rate specified.
	pendingSweepsReq := &walletrpc.PendingSweepsRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	pendingSweepsResp, err := net.Bob.WalletKitClient.PendingSweeps(
		ctxt, pendingSweepsReq,
	)
	if err != nil {
		t.Fatalf("unable to retrieve pending sweeps: %v", err)
	}
	if len(pendingSweepsResp.PendingSweeps) != 1 {
		t.Fatalf("expected to find %v pending sweep(s), found %v", 1,
			len(pendingSweepsResp.PendingSweeps))
	}
	pendingSweep := pendingSweepsResp.PendingSweeps[0]
	if !bytes.Equal(pendingSweep.Outpoint.TxidBytes, op.TxidBytes) {
		t.Fatalf("expected output txid %x, got %x", op.TxidBytes,
			pendingSweep.Outpoint.TxidBytes)
	}
	if pendingSweep.Outpoint.OutputIndex != op.OutputIndex {
		t.Fatalf("expected output index %v, got %v", op.OutputIndex,
			pendingSweep.Outpoint.OutputIndex)
	}
	if pendingSweep.SatPerVbyte != bumpFeeReq.SatPerVbyte {
		t.Fatalf("expected sweep sat per vbyte %v, got %v",
			bumpFeeReq.SatPerVbyte, pendingSweep.SatPerVbyte)
	}

	// Mine a block to clean up the unconfirmed transactions.
	mineBlocks(t, net, 1, 2)

	// The input used to CPFP should no longer be pending.
	err = wait.NoError(func() error {
		req := &walletrpc.PendingSweepsRequest{}
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		resp, err := net.Bob.WalletKitClient.PendingSweeps(ctxt, req)
		if err != nil {
			return fmt.Errorf("unable to retrieve bob's pending "+
				"sweeps: %v", err)
		}
		if len(resp.PendingSweeps) != 0 {
			return fmt.Errorf("expected 0 pending sweeps, found %d",
				len(resp.PendingSweeps))
		}
		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf(err.Error())
	}
}

// testAnchorReservedValue tests that we won't allow sending transactions when
// that would take the value we reserve for anchor fee bumping out of our
// wallet.
func testAnchorReservedValue(net *lntest.NetworkHarness, t *harnessTest) {
	// Start two nodes supporting anchor channels.
	args := nodeArgsForCommitType(lnrpc.CommitmentType_ANCHORS)
	alice := net.NewNode(t.t, "Alice", args)
	defer shutdownAndAssert(net, t, alice)

	bob := net.NewNode(t.t, "Bob", args)
	defer shutdownAndAssert(net, t, bob)

	ctxb := context.Background()
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, alice, bob)

	// Send just enough coins for Alice to open a channel without a change
	// output.
	const (
		chanAmt = 1000000
		feeEst  = 8000
	)

	ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
	net.SendCoins(ctxt, t.t, chanAmt+feeEst, alice)

	// wallet, without a change output. This should not be allowed.
	resErr := lnwallet.ErrReservedValueInvalidated.Error()

	ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
	_, err := net.OpenChannel(
		ctxt, alice, bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)
	if err == nil || !strings.Contains(err.Error(), resErr) {
		t.Fatalf("expected failure, got: %v", err)
	}

	// Alice opens a smaller channel. This works since it will have a
	// change output.
	ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
	aliceChanPoint1 := openChannelAndAssert(
		ctxt, t, net, alice, bob,
		lntest.OpenChannelParams{
			Amt: chanAmt / 4,
		},
	)

	// If Alice tries to open another anchor channel to Bob, Bob should not
	// reject it as he is not contributing any funds.
	aliceChanPoint2 := openChannelAndAssert(
		ctxt, t, net, alice, bob, lntest.OpenChannelParams{
			Amt: chanAmt / 4,
		},
	)

	// Similarly, if Alice tries to open a legacy channel to Bob, Bob should
	// not reject it as he is not contributing any funds. We'll restart Bob
	// to remove his support for anchors.
	err = net.RestartNode(bob, nil)
	require.NoError(t.t, err)
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	aliceChanPoint3 := openChannelAndAssert(
		ctxt, t, net, alice, bob, lntest.OpenChannelParams{
			Amt: chanAmt / 4,
		},
	)

	chanPoints := []*lnrpc.ChannelPoint{
		aliceChanPoint1, aliceChanPoint2, aliceChanPoint3,
	}
	for _, chanPoint := range chanPoints {
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = alice.WaitForNetworkChannelOpen(ctxt, chanPoint)
		require.NoError(t.t, err)

		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = bob.WaitForNetworkChannelOpen(ctxt, chanPoint)
		require.NoError(t.t, err)
	}

	// Alice tries to send all coins to an internal address. This is
	// allowed, since the final wallet balance will still be above the
	// reserved value.
	addrReq := &lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	resp, err := alice.NewAddress(ctxt, addrReq)
	require.NoError(t.t, err)

	sweepReq := &lnrpc.SendCoinsRequest{
		Addr:    resp.Address,
		SendAll: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = alice.SendCoins(ctxt, sweepReq)
	require.NoError(t.t, err)

	block := mineBlocks(t, net, 1, 1)[0]

	// The sweep transaction should have exactly one input, the change from
	// the previous SendCoins call.
	sweepTx := block.Transactions[1]
	if len(sweepTx.TxIn) != 1 {
		t.Fatalf("expected 1 inputs instead have %v", len(sweepTx.TxIn))
	}

	// It should have a single output.
	if len(sweepTx.TxOut) != 1 {
		t.Fatalf("expected 1 output instead have %v", len(sweepTx.TxOut))
	}

	// Wait for Alice to see her balance as confirmed.
	waitForConfirmedBalance := func() int64 {
		var balance int64
		err := wait.NoError(func() error {
			req := &lnrpc.WalletBalanceRequest{}
			ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
			resp, err := alice.WalletBalance(ctxt, req)
			if err != nil {
				return err
			}

			if resp.TotalBalance == 0 {
				return fmt.Errorf("no balance")
			}

			if resp.UnconfirmedBalance > 0 {
				return fmt.Errorf("unconfirmed balance")
			}

			balance = resp.TotalBalance
			return nil
		}, defaultTimeout)
		require.NoError(t.t, err)

		return balance
	}

	_ = waitForConfirmedBalance()

	// Alice tries to send all funds to an external address, the reserved
	// value must stay in her wallet.
	minerAddr, err := net.Miner.NewAddress()
	require.NoError(t.t, err)

	sweepReq = &lnrpc.SendCoinsRequest{
		Addr:    minerAddr.String(),
		SendAll: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = alice.SendCoins(ctxt, sweepReq)
	require.NoError(t.t, err)

	// We'll mine a block which should include the sweep transaction we
	// generated above.
	block = mineBlocks(t, net, 1, 1)[0]

	// The sweep transaction should have exactly one inputs as we only had
	// the the single output from above in the wallet.
	sweepTx = block.Transactions[1]
	if len(sweepTx.TxIn) != 1 {
		t.Fatalf("expected 1 inputs instead have %v", len(sweepTx.TxIn))
	}

	// It should have two outputs, one being the miner address, the other
	// one being the reserve going back to our wallet.
	if len(sweepTx.TxOut) != 2 {
		t.Fatalf("expected 2 outputs instead have %v", len(sweepTx.TxOut))
	}

	// The reserved value is now back in Alice's wallet.
	aliceBalance := waitForConfirmedBalance()

	// Alice closes channel, should now be allowed to send everything to an
	// external address.
	for _, chanPoint := range chanPoints {
		closeChannelAndAssert(ctxt, t, net, alice, chanPoint, false)
	}

	newBalance := waitForConfirmedBalance()
	if newBalance <= aliceBalance {
		t.Fatalf("Alice's balance did not increase after channel close")
	}

	// We'll wait for the balance to reflect that the channel has been
	// closed and the funds are in the wallet.

	sweepReq = &lnrpc.SendCoinsRequest{
		Addr:    minerAddr.String(),
		SendAll: true,
	}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	_, err = alice.SendCoins(ctxt, sweepReq)
	require.NoError(t.t, err)

	// We'll mine a block which should include the sweep transaction we
	// generated above.
	block = mineBlocks(t, net, 1, 1)[0]

	// The sweep transaction should have four inputs, the change output from
	// the previous sweep, and the outputs from the coop closed channels.
	sweepTx = block.Transactions[1]
	if len(sweepTx.TxIn) != 4 {
		t.Fatalf("expected 4 inputs instead have %v", len(sweepTx.TxIn))
	}

	// It should have a single output.
	if len(sweepTx.TxOut) != 1 {
		t.Fatalf("expected 1 output instead have %v", len(sweepTx.TxOut))
	}
}
