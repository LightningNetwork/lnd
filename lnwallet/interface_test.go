package lnwallet_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainntnfs/btcdnotify"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
	"github.com/lightningnetwork/lnd/lnwire"
	"go.etcd.io/bbolt"
)

var (
	bobsPrivKey = []byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}

	// Use a hard-coded HD seed.
	testHdSeed = chainhash.Hash{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x88, 0xa3, 0xef, 0xb9,
		0x6a, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	aliceHDSeed = chainhash.Hash{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x18, 0xa3, 0xef, 0xb9,
		0x64, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}
	bobHDSeed = chainhash.Hash{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x98, 0xa3, 0xef, 0xb9,
		0x69, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	netParams = &chaincfg.RegressionNetParams
	chainHash = netParams.GenesisHash

	_, alicePub = btcec.PrivKeyFromBytes(btcec.S256(), testHdSeed[:])
	_, bobPub   = btcec.PrivKeyFromBytes(btcec.S256(), bobsPrivKey)

	// The number of confirmations required to consider any created channel
	// open.
	numReqConfs uint16 = 1

	csvDelay uint16 = 4

	bobAddr, _   = net.ResolveTCPAddr("tcp", "10.0.0.2:9000")
	aliceAddr, _ = net.ResolveTCPAddr("tcp", "10.0.0.3:9000")
)

// assertProperBalance asserts than the total value of the unspent outputs
// within the wallet are *exactly* amount. If unable to retrieve the current
// balance, or the assertion fails, the test will halt with a fatal error.
func assertProperBalance(t *testing.T, lw *lnwallet.LightningWallet,
	numConfirms int32, amount float64) {

	balance, err := lw.ConfirmedBalance(numConfirms)
	if err != nil {
		t.Fatalf("unable to query for balance: %v", err)
	}
	if balance.ToBTC() != amount {
		t.Fatalf("wallet credits not properly loaded, should have 40BTC, "+
			"instead have %v", balance)
	}
}

func assertReservationDeleted(res *lnwallet.ChannelReservation, t *testing.T) {
	if err := res.Cancel(); err == nil {
		t.Fatalf("reservation wasn't deleted from wallet")
	}
}

// mineAndAssertTxInBlock asserts that a transaction is included within the next
// block mined.
func mineAndAssertTxInBlock(t *testing.T, miner *rpctest.Harness,
	txid chainhash.Hash) {

	t.Helper()

	// First, we'll wait for the transaction to arrive in the mempool.
	if err := waitForMempoolTx(miner, &txid); err != nil {
		t.Fatalf("unable to find %v in the mempool: %v", txid, err)
	}

	// We'll mined a block to confirm it.
	blockHashes, err := miner.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate new block: %v", err)
	}

	// Finally, we'll check it was actually mined in this block.
	block, err := miner.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("unable to get block %v: %v", blockHashes[0], err)
	}
	if len(block.Transactions) != 2 {
		t.Fatalf("expected 2 transactions in block, found %d",
			len(block.Transactions))
	}
	txHash := block.Transactions[1].TxHash()
	if txHash != txid {
		t.Fatalf("expected transaction %v to be mined, found %v", txid,
			txHash)
	}
}

// newPkScript generates a new public key script of the given address type.
func newPkScript(t *testing.T, w *lnwallet.LightningWallet,
	addrType lnwallet.AddressType) []byte {

	t.Helper()

	addr, err := w.NewAddress(addrType, false)
	if err != nil {
		t.Fatalf("unable to create new address: %v", err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to create output script: %v", err)
	}

	return pkScript
}

// sendCoins is a helper function that encompasses all the things needed for two
// parties to send on-chain funds to each other.
func sendCoins(t *testing.T, miner *rpctest.Harness,
	sender, receiver *lnwallet.LightningWallet, output *wire.TxOut,
	feeRate chainfee.SatPerKWeight) *wire.MsgTx { //nolint:unparam

	t.Helper()

	tx, err := sender.SendOutputs([]*wire.TxOut{output}, 2500)
	if err != nil {
		t.Fatalf("unable to send transaction: %v", err)
	}

	mineAndAssertTxInBlock(t, miner, tx.TxHash())

	if err := waitForWalletSync(miner, sender); err != nil {
		t.Fatalf("unable to sync alice: %v", err)
	}
	if err := waitForWalletSync(miner, receiver); err != nil {
		t.Fatalf("unable to sync bob: %v", err)
	}

	return tx
}

// assertTxInWallet asserts that a transaction exists in the wallet with the
// expected confirmation status.
func assertTxInWallet(t *testing.T, w *lnwallet.LightningWallet,
	txHash chainhash.Hash, confirmed bool) {

	t.Helper()

	// If the backend is Neutrino, then we can't determine unconfirmed
	// transactions since it's not aware of the mempool.
	if !confirmed && w.BackEnd() == "neutrino" {
		return
	}

	// We'll fetch all of our transaction and go through each one until
	// finding the expected transaction with its expected confirmation
	// status.
	txs, err := w.ListTransactionDetails(0, btcwallet.UnconfirmedHeight)
	if err != nil {
		t.Fatalf("unable to retrieve transactions: %v", err)
	}
	for _, tx := range txs {
		if tx.Hash != txHash {
			continue
		}
		if tx.NumConfirmations <= 0 && confirmed {
			t.Fatalf("expected transaction %v to be confirmed",
				txHash)
		}
		if tx.NumConfirmations > 0 && !confirmed {
			t.Fatalf("expected transaction %v to be unconfirmed",
				txHash)
		}

		// We've found the transaction and it matches the desired
		// confirmation status, so we can exit.
		return
	}

	t.Fatalf("transaction %v not found", txHash)
}

func loadTestCredits(miner *rpctest.Harness, w *lnwallet.LightningWallet,
	numOutputs int, btcPerOutput float64) error {

	// For initial neutrino connection, wait a second.
	// TODO(aakselrod): Eliminate the need for this.
	switch w.BackEnd() {
	case "neutrino":
		time.Sleep(time.Second)
	}
	// Using the mining node, spend from a coinbase output numOutputs to
	// give us btcPerOutput with each output.
	satoshiPerOutput, err := btcutil.NewAmount(btcPerOutput)
	if err != nil {
		return fmt.Errorf("unable to create amt: %v", err)
	}
	expectedBalance, err := w.ConfirmedBalance(1)
	if err != nil {
		return err
	}
	expectedBalance += btcutil.Amount(int64(satoshiPerOutput) * int64(numOutputs))
	addrs := make([]btcutil.Address, 0, numOutputs)
	for i := 0; i < numOutputs; i++ {
		// Grab a fresh address from the wallet to house this output.
		walletAddr, err := w.NewAddress(lnwallet.WitnessPubKey, false)
		if err != nil {
			return err
		}

		script, err := txscript.PayToAddrScript(walletAddr)
		if err != nil {
			return err
		}

		addrs = append(addrs, walletAddr)

		output := &wire.TxOut{
			Value:    int64(satoshiPerOutput),
			PkScript: script,
		}
		if _, err := miner.SendOutputs([]*wire.TxOut{output}, 2500); err != nil {
			return err
		}
	}

	// TODO(roasbeef): shouldn't hardcode 10, use config param that dictates
	// how many confs we wait before opening a channel.
	// Generate 10 blocks with the mining node, this should mine all
	// numOutputs transactions created above. We generate 10 blocks here
	// in order to give all the outputs a "sufficient" number of confirmations.
	if _, err := miner.Node.Generate(10); err != nil {
		return err
	}

	// Wait until the wallet has finished syncing up to the main chain.
	ticker := time.NewTicker(100 * time.Millisecond)
	timeout := time.After(30 * time.Second)

	for range ticker.C {
		balance, err := w.ConfirmedBalance(1)
		if err != nil {
			return err
		}
		if balance == expectedBalance {
			break
		}
		select {
		case <-timeout:
			synced, _, err := w.IsSynced()
			if err != nil {
				return err
			}
			return fmt.Errorf("timed out after 30 seconds "+
				"waiting for balance %v, current balance %v, "+
				"synced: %t", expectedBalance, balance, synced)
		default:
		}
	}
	ticker.Stop()

	return nil
}

// createTestWallet creates a test LightningWallet will a total of 20BTC
// available for funding channels.
func createTestWallet(tempTestDir string, miningNode *rpctest.Harness,
	netParams *chaincfg.Params, notifier chainntnfs.ChainNotifier,
	wc lnwallet.WalletController, keyRing keychain.SecretKeyRing,
	signer input.Signer, bio lnwallet.BlockChainIO) (*lnwallet.LightningWallet, error) {

	dbDir := filepath.Join(tempTestDir, "cdb")
	cdb, err := channeldb.Open(dbDir)
	if err != nil {
		return nil, err
	}

	cfg := lnwallet.Config{
		Database:         cdb,
		Notifier:         notifier,
		SecretKeyRing:    keyRing,
		WalletController: wc,
		Signer:           signer,
		ChainIO:          bio,
		FeeEstimator:     chainfee.NewStaticEstimator(2500, 0),
		DefaultConstraints: channeldb.ChannelConstraints{
			DustLimit:        500,
			MaxPendingAmount: lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin) * 100,
			ChanReserve:      100,
			MinHTLC:          400,
			MaxAcceptedHtlcs: 900,
		},
		NetParams: *netParams,
	}

	wallet, err := lnwallet.NewLightningWallet(cfg)
	if err != nil {
		return nil, err
	}

	if err := wallet.Startup(); err != nil {
		return nil, err
	}

	// Load our test wallet with 20 outputs each holding 4BTC.
	if err := loadTestCredits(miningNode, wallet, 20, 4); err != nil {
		return nil, err
	}

	return wallet, nil
}

func testDualFundingReservationWorkflow(miner *rpctest.Harness,
	alice, bob *lnwallet.LightningWallet, t *testing.T) {

	fundingAmount, err := btcutil.NewAmount(5)
	if err != nil {
		t.Fatalf("unable to create amt: %v", err)
	}

	// In this scenario, we'll test a dual funder reservation, with each
	// side putting in 10 BTC.

	// Alice initiates a channel funded with 5 BTC for each side, so 10 BTC
	// total. She also generates 2 BTC in change.
	feePerKw, err := alice.Cfg.FeeEstimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}
	aliceReq := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		NodeID:           bobPub,
		NodeAddr:         bobAddr,
		LocalFundingAmt:  fundingAmount,
		RemoteFundingAmt: fundingAmount,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         0,
		Flags:            lnwire.FFAnnounceChannel,
	}
	aliceChanReservation, err := alice.InitChannelReservation(aliceReq)
	if err != nil {
		t.Fatalf("unable to initialize funding reservation: %v", err)
	}
	aliceChanReservation.SetNumConfsRequired(numReqConfs)
	channelConstraints := &channeldb.ChannelConstraints{
		DustLimit:        lnwallet.DefaultDustLimit(),
		ChanReserve:      fundingAmount / 100,
		MaxPendingAmount: lnwire.NewMSatFromSatoshis(fundingAmount),
		MinHTLC:          1,
		MaxAcceptedHtlcs: input.MaxHTLCNumber / 2,
		CsvDelay:         csvDelay,
	}
	err = aliceChanReservation.CommitConstraints(channelConstraints)
	if err != nil {
		t.Fatalf("unable to verify constraints: %v", err)
	}

	// The channel reservation should now be populated with a multi-sig key
	// from our HD chain, a change output with 3 BTC, and 2 outputs
	// selected of 4 BTC each. Additionally, the rest of the items needed
	// to fulfill a funding contribution should also have been filled in.
	aliceContribution := aliceChanReservation.OurContribution()
	if len(aliceContribution.Inputs) != 2 {
		t.Fatalf("outputs for funding tx not properly selected, have %v "+
			"outputs should have 2", len(aliceContribution.Inputs))
	}
	assertContributionInitPopulated(t, aliceContribution)

	// Bob does the same, generating his own contribution. He then also
	// receives' Alice's contribution, and consumes that so we can continue
	// the funding process.
	bobReq := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		NodeID:           alicePub,
		NodeAddr:         aliceAddr,
		LocalFundingAmt:  fundingAmount,
		RemoteFundingAmt: fundingAmount,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         0,
		Flags:            lnwire.FFAnnounceChannel,
	}
	bobChanReservation, err := bob.InitChannelReservation(bobReq)
	if err != nil {
		t.Fatalf("bob unable to init channel reservation: %v", err)
	}
	err = bobChanReservation.CommitConstraints(channelConstraints)
	if err != nil {
		t.Fatalf("unable to verify constraints: %v", err)
	}
	bobChanReservation.SetNumConfsRequired(numReqConfs)

	assertContributionInitPopulated(t, bobChanReservation.OurContribution())

	err = bobChanReservation.ProcessContribution(aliceContribution)
	if err != nil {
		t.Fatalf("bob unable to process alice's contribution: %v", err)
	}
	assertContributionInitPopulated(t, bobChanReservation.TheirContribution())

	bobContribution := bobChanReservation.OurContribution()

	// Bob then sends over his contribution, which will be consumed by
	// Alice. After this phase, Alice should have all the necessary
	// material required to craft the funding transaction and commitment
	// transactions.
	err = aliceChanReservation.ProcessContribution(bobContribution)
	if err != nil {
		t.Fatalf("alice unable to process bob's contribution: %v", err)
	}
	assertContributionInitPopulated(t, aliceChanReservation.TheirContribution())

	// At this point, all Alice's signatures should be fully populated.
	aliceFundingSigs, aliceCommitSig := aliceChanReservation.OurSignatures()
	if aliceFundingSigs == nil {
		t.Fatalf("alice's funding signatures not populated")
	}
	if aliceCommitSig == nil {
		t.Fatalf("alice's commit signatures not populated")
	}

	// Additionally, Bob's signatures should also be fully populated.
	bobFundingSigs, bobCommitSig := bobChanReservation.OurSignatures()
	if bobFundingSigs == nil {
		t.Fatalf("bob's funding signatures not populated")
	}
	if bobCommitSig == nil {
		t.Fatalf("bob's commit signatures not populated")
	}

	// To conclude, we'll consume first Alice's signatures with Bob, and
	// then the other way around.
	_, err = aliceChanReservation.CompleteReservation(
		bobFundingSigs, bobCommitSig,
	)
	if err != nil {
		for _, in := range aliceChanReservation.FinalFundingTx().TxIn {
			fmt.Println(in.PreviousOutPoint.String())
		}
		t.Fatalf("unable to consume alice's sigs: %v", err)
	}
	_, err = bobChanReservation.CompleteReservation(
		aliceFundingSigs, aliceCommitSig,
	)
	if err != nil {
		t.Fatalf("unable to consume bob's sigs: %v", err)
	}

	// At this point, the funding tx should have been populated.
	fundingTx := aliceChanReservation.FinalFundingTx()
	if fundingTx == nil {
		t.Fatalf("funding transaction never created!")
	}

	// The resulting active channel state should have been persisted to the
	// DB.
	fundingSha := fundingTx.TxHash()
	aliceChannels, err := alice.Cfg.Database.FetchOpenChannels(bobPub)
	if err != nil {
		t.Fatalf("unable to retrieve channel from DB: %v", err)
	}
	if !bytes.Equal(aliceChannels[0].FundingOutpoint.Hash[:], fundingSha[:]) {
		t.Fatalf("channel state not properly saved")
	}
	if !aliceChannels[0].ChanType.IsDualFunder() {
		t.Fatalf("channel not detected as dual funder")
	}
	bobChannels, err := bob.Cfg.Database.FetchOpenChannels(alicePub)
	if err != nil {
		t.Fatalf("unable to retrieve channel from DB: %v", err)
	}
	if !bytes.Equal(bobChannels[0].FundingOutpoint.Hash[:], fundingSha[:]) {
		t.Fatalf("channel state not properly saved")
	}
	if !bobChannels[0].ChanType.IsDualFunder() {
		t.Fatalf("channel not detected as dual funder")
	}

	// Let Alice publish the funding transaction.
	if err := alice.PublishTransaction(fundingTx); err != nil {
		t.Fatalf("unable to publish funding tx: %v", err)
	}

	// Mine a single block, the funding transaction should be included
	// within this block.
	err = waitForMempoolTx(miner, &fundingSha)
	if err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}
	blockHashes, err := miner.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
	block, err := miner.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("unable to find block: %v", err)
	}
	if len(block.Transactions) != 2 {
		t.Fatalf("funding transaction wasn't mined: %v", err)
	}
	blockTx := block.Transactions[1]
	if blockTx.TxHash() != fundingSha {
		t.Fatalf("incorrect transaction was mined")
	}

	assertReservationDeleted(aliceChanReservation, t)
	assertReservationDeleted(bobChanReservation, t)

	// Wait for wallets to catch up to prevent issues in subsequent tests.
	err = waitForWalletSync(miner, alice)
	if err != nil {
		t.Fatalf("unable to sync alice: %v", err)
	}
	err = waitForWalletSync(miner, bob)
	if err != nil {
		t.Fatalf("unable to sync bob: %v", err)
	}
}

func testFundingTransactionLockedOutputs(miner *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	// Create a single channel asking for 16 BTC total.
	fundingAmount, err := btcutil.NewAmount(8)
	if err != nil {
		t.Fatalf("unable to create amt: %v", err)
	}
	feePerKw, err := alice.Cfg.FeeEstimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}
	req := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		NodeID:           bobPub,
		NodeAddr:         bobAddr,
		LocalFundingAmt:  fundingAmount,
		RemoteFundingAmt: 0,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         0,
		Flags:            lnwire.FFAnnounceChannel,
		PendingChanID:    [32]byte{0, 1, 2, 3},
	}
	if _, err := alice.InitChannelReservation(req); err != nil {
		t.Fatalf("unable to initialize funding reservation 1: %v", err)
	}

	// Now attempt to reserve funds for another channel, this time
	// requesting 900 BTC. We only have around 64BTC worth of outpoints
	// that aren't locked, so this should fail.
	amt, err := btcutil.NewAmount(900)
	if err != nil {
		t.Fatalf("unable to create amt: %v", err)
	}
	failedReq := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		NodeID:           bobPub,
		NodeAddr:         bobAddr,
		LocalFundingAmt:  amt,
		RemoteFundingAmt: 0,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         0,
		Flags:            lnwire.FFAnnounceChannel,
		PendingChanID:    [32]byte{1, 2, 3, 4},
	}
	failedReservation, err := alice.InitChannelReservation(failedReq)
	if err == nil {
		t.Fatalf("not error returned, should fail on coin selection")
	}
	if _, ok := err.(*chanfunding.ErrInsufficientFunds); !ok {
		t.Fatalf("error not coinselect error: %v", err)
	}
	if failedReservation != nil {
		t.Fatalf("reservation should be nil")
	}
}

func testFundingCancellationNotEnoughFunds(miner *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	feePerKw, err := alice.Cfg.FeeEstimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}

	// Create a reservation for 44 BTC.
	fundingAmount, err := btcutil.NewAmount(44)
	if err != nil {
		t.Fatalf("unable to create amt: %v", err)
	}
	req := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		NodeID:           bobPub,
		NodeAddr:         bobAddr,
		LocalFundingAmt:  fundingAmount,
		RemoteFundingAmt: 0,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         0,
		Flags:            lnwire.FFAnnounceChannel,
		PendingChanID:    [32]byte{2, 3, 4, 5},
	}
	chanReservation, err := alice.InitChannelReservation(req)
	if err != nil {
		t.Fatalf("unable to initialize funding reservation: %v", err)
	}

	// Attempt to create another channel with 44 BTC, this should fail.
	req.PendingChanID = [32]byte{3, 4, 5, 6}
	_, err = alice.InitChannelReservation(req)
	if _, ok := err.(*chanfunding.ErrInsufficientFunds); !ok {
		t.Fatalf("coin selection succeeded should have insufficient funds: %v",
			err)
	}

	// Now cancel that old reservation.
	if err := chanReservation.Cancel(); err != nil {
		t.Fatalf("unable to cancel reservation: %v", err)
	}

	// Those outpoints should no longer be locked.
	lockedOutPoints := alice.LockedOutpoints()
	if len(lockedOutPoints) != 0 {
		t.Fatalf("outpoints still locked")
	}

	// Reservation ID should no longer be tracked.
	numReservations := alice.ActiveReservations()
	if len(alice.ActiveReservations()) != 0 {
		t.Fatalf("should have 0 reservations, instead have %v",
			numReservations)
	}

	// TODO(roasbeef): create method like Balance that ignores locked
	// outpoints, will let us fail early/fast instead of querying and
	// attempting coin selection.

	// Request to fund a new channel should now succeed.
	req.PendingChanID = [32]byte{4, 5, 6, 7, 8}
	if _, err := alice.InitChannelReservation(req); err != nil {
		t.Fatalf("unable to initialize funding reservation: %v", err)
	}
}

func testCancelNonExistentReservation(miner *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	feePerKw, err := alice.Cfg.FeeEstimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}

	// Create our own reservation, give it some ID.
	res, err := lnwallet.NewChannelReservation(
		10000, 10000, feePerKw, alice, 22, 10, &testHdSeed,
		lnwire.FFAnnounceChannel, lnwallet.CommitmentTypeTweakless,
		nil, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("unable to create res: %v", err)
	}

	// Attempt to cancel this reservation. This should fail, we know
	// nothing of it.
	if err := res.Cancel(); err == nil {
		t.Fatalf("canceled non-existent reservation")
	}
}

func testReservationInitiatorBalanceBelowDustCancel(miner *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	// We'll attempt to create a new reservation with an extremely high
	// commitment fee rate. This should push our balance into the negative
	// and result in a failure to create the reservation.
	const numBTC = 4
	fundingAmount, err := btcutil.NewAmount(numBTC)
	if err != nil {
		t.Fatalf("unable to create amt: %v", err)
	}

	feePerKw := chainfee.SatPerKWeight(
		numBTC * numBTC * btcutil.SatoshiPerBitcoin,
	)
	req := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		NodeID:           bobPub,
		NodeAddr:         bobAddr,
		LocalFundingAmt:  fundingAmount,
		RemoteFundingAmt: 0,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  1000,
		PushMSat:         0,
		Flags:            lnwire.FFAnnounceChannel,
		CommitType:       lnwallet.CommitmentTypeTweakless,
	}
	_, err = alice.InitChannelReservation(req)
	switch {
	case err == nil:
		t.Fatalf("initialization should have failed due to " +
			"insufficient local amount")

	case !strings.Contains(err.Error(), "funder balance too small"):
		t.Fatalf("incorrect error: %v", err)
	}
}

func assertContributionInitPopulated(t *testing.T, c *lnwallet.ChannelContribution) {
	_, _, line, _ := runtime.Caller(1)

	if c.FirstCommitmentPoint == nil {
		t.Fatalf("line #%v: commitment point not fond", line)
	}

	if c.CsvDelay == 0 {
		t.Fatalf("line #%v: csv delay not set", line)
	}

	if c.MultiSigKey.PubKey == nil {
		t.Fatalf("line #%v: multi-sig key not set", line)
	}
	if c.RevocationBasePoint.PubKey == nil {
		t.Fatalf("line #%v: revocation key not set", line)
	}
	if c.PaymentBasePoint.PubKey == nil {
		t.Fatalf("line #%v: payment key not set", line)
	}
	if c.DelayBasePoint.PubKey == nil {
		t.Fatalf("line #%v: delay key not set", line)
	}

	if c.DustLimit == 0 {
		t.Fatalf("line #%v: dust limit not set", line)
	}
	if c.MaxPendingAmount == 0 {
		t.Fatalf("line #%v: max pending amt not set", line)
	}
	if c.ChanReserve == 0 {
		t.Fatalf("line #%v: chan reserve not set", line)
	}
	if c.MinHTLC == 0 {
		t.Fatalf("line #%v: min htlc not set", line)
	}
	if c.MaxAcceptedHtlcs == 0 {
		t.Fatalf("line #%v: max accepted htlc's not set", line)
	}
}

func testSingleFunderReservationWorkflow(miner *rpctest.Harness,
	alice, bob *lnwallet.LightningWallet, t *testing.T,
	commitType lnwallet.CommitmentType,
	aliceChanFunder chanfunding.Assembler, fetchFundingTx func() *wire.MsgTx,
	pendingChanID [32]byte, thawHeight uint32) {

	// For this scenario, Alice will be the channel initiator while bob
	// will act as the responder to the workflow.

	// First, Alice will Initialize a reservation for a channel with 4 BTC
	// funded solely by us. We'll also initially push 1 BTC of the channel
	// towards Bob's side.
	fundingAmt, err := btcutil.NewAmount(4)
	if err != nil {
		t.Fatalf("unable to create amt: %v", err)
	}
	pushAmt := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	feePerKw, err := alice.Cfg.FeeEstimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}
	aliceReq := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		PendingChanID:    pendingChanID,
		NodeID:           bobPub,
		NodeAddr:         bobAddr,
		LocalFundingAmt:  fundingAmt,
		RemoteFundingAmt: 0,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         pushAmt,
		Flags:            lnwire.FFAnnounceChannel,
		CommitType:       commitType,
		ChanFunder:       aliceChanFunder,
	}
	aliceChanReservation, err := alice.InitChannelReservation(aliceReq)
	if err != nil {
		t.Fatalf("unable to init channel reservation: %v", err)
	}
	aliceChanReservation.SetNumConfsRequired(numReqConfs)
	channelConstraints := &channeldb.ChannelConstraints{
		DustLimit:        lnwallet.DefaultDustLimit(),
		ChanReserve:      fundingAmt / 100,
		MaxPendingAmount: lnwire.NewMSatFromSatoshis(fundingAmt),
		MinHTLC:          1,
		MaxAcceptedHtlcs: input.MaxHTLCNumber / 2,
		CsvDelay:         csvDelay,
	}
	err = aliceChanReservation.CommitConstraints(channelConstraints)
	if err != nil {
		t.Fatalf("unable to verify constraints: %v", err)
	}

	// Verify all contribution fields have been set properly, but only if
	// Alice is the funder herself.
	aliceContribution := aliceChanReservation.OurContribution()
	if fetchFundingTx == nil {
		if len(aliceContribution.Inputs) < 1 {
			t.Fatalf("outputs for funding tx not properly "+
				"selected, have %v outputs should at least 1",
				len(aliceContribution.Inputs))
		}
		if len(aliceContribution.ChangeOutputs) != 1 {
			t.Fatalf("coin selection failed, should have one "+
				"change outputs, instead have: %v",
				len(aliceContribution.ChangeOutputs))
		}
	}
	assertContributionInitPopulated(t, aliceContribution)

	// Next, Bob receives the initial request, generates a corresponding
	// reservation initiation, then consume Alice's contribution.
	bobReq := &lnwallet.InitFundingReserveMsg{
		ChainHash:        chainHash,
		PendingChanID:    pendingChanID,
		NodeID:           alicePub,
		NodeAddr:         aliceAddr,
		LocalFundingAmt:  0,
		RemoteFundingAmt: fundingAmt,
		CommitFeePerKw:   feePerKw,
		FundingFeePerKw:  feePerKw,
		PushMSat:         pushAmt,
		Flags:            lnwire.FFAnnounceChannel,
		CommitType:       commitType,
	}
	bobChanReservation, err := bob.InitChannelReservation(bobReq)
	if err != nil {
		t.Fatalf("unable to create bob reservation: %v", err)
	}
	err = bobChanReservation.CommitConstraints(channelConstraints)
	if err != nil {
		t.Fatalf("unable to verify constraints: %v", err)
	}
	bobChanReservation.SetNumConfsRequired(numReqConfs)

	// We'll ensure that Bob's contribution also gets generated properly.
	bobContribution := bobChanReservation.OurContribution()
	assertContributionInitPopulated(t, bobContribution)

	// With his contribution generated, he can now process Alice's
	// contribution.
	err = bobChanReservation.ProcessSingleContribution(aliceContribution)
	if err != nil {
		t.Fatalf("bob unable to process alice's contribution: %v", err)
	}
	assertContributionInitPopulated(t, bobChanReservation.TheirContribution())

	// Bob will next send over his contribution to Alice, we simulate this
	// by having Alice immediately process his contribution.
	err = aliceChanReservation.ProcessContribution(bobContribution)
	if err != nil {
		t.Fatalf("alice unable to process bob's contribution")
	}
	assertContributionInitPopulated(t, bobChanReservation.TheirContribution())

	// At this point, Alice should have generated all the signatures
	// required for the funding transaction, as well as Alice's commitment
	// signature to bob, but only if the funding transaction was
	// constructed internally.
	aliceRemoteContribution := aliceChanReservation.TheirContribution()
	aliceFundingSigs, aliceCommitSig := aliceChanReservation.OurSignatures()
	if fetchFundingTx == nil && aliceFundingSigs == nil {
		t.Fatalf("funding sigs not found")
	}
	if aliceCommitSig == nil {
		t.Fatalf("commitment sig not found")
	}

	// Additionally, the funding tx and the funding outpoint should have
	// been populated.
	if aliceChanReservation.FinalFundingTx() == nil && fetchFundingTx == nil {
		t.Fatalf("funding transaction never created!")
	}
	if aliceChanReservation.FundingOutpoint() == nil {
		t.Fatalf("funding outpoint never created!")
	}

	// Their funds should also be filled in.
	if len(aliceRemoteContribution.Inputs) != 0 {
		t.Fatalf("bob shouldn't have any inputs, instead has %v",
			len(aliceRemoteContribution.Inputs))
	}
	if len(aliceRemoteContribution.ChangeOutputs) != 0 {
		t.Fatalf("bob shouldn't have any change outputs, instead "+
			"has %v",
			aliceRemoteContribution.ChangeOutputs[0].Value)
	}

	// Next, Alice will send over her signature for Bob's commitment
	// transaction, as well as the funding outpoint.
	fundingPoint := aliceChanReservation.FundingOutpoint()
	_, err = bobChanReservation.CompleteReservationSingle(
		fundingPoint, aliceCommitSig,
	)
	if err != nil {
		t.Fatalf("bob unable to consume single reservation: %v", err)
	}

	// Finally, we'll conclude the reservation process by sending over
	// Bob's commitment signature, which is the final thing Alice needs to
	// be able to safely broadcast the funding transaction.
	_, bobCommitSig := bobChanReservation.OurSignatures()
	if bobCommitSig == nil {
		t.Fatalf("bob failed to generate commitment signature: %v", err)
	}
	_, err = aliceChanReservation.CompleteReservation(
		nil, bobCommitSig,
	)
	if err != nil {
		t.Fatalf("alice unable to complete reservation: %v", err)
	}

	// If the caller provided an alternative way to obtain the funding tx,
	// then we'll use that. Otherwise, we'll obtain it directly from Alice.
	var fundingTx *wire.MsgTx
	if fetchFundingTx != nil {
		fundingTx = fetchFundingTx()
	} else {
		fundingTx = aliceChanReservation.FinalFundingTx()
	}

	// The resulting active channel state should have been persisted to the
	// DB for both Alice and Bob.
	fundingSha := fundingTx.TxHash()
	aliceChannels, err := alice.Cfg.Database.FetchOpenChannels(bobPub)
	if err != nil {
		t.Fatalf("unable to retrieve channel from DB: %v", err)
	}
	if len(aliceChannels) != 1 {
		t.Fatalf("alice didn't save channel state: %v", err)
	}
	if !bytes.Equal(aliceChannels[0].FundingOutpoint.Hash[:], fundingSha[:]) {
		t.Fatalf("channel state not properly saved: %v vs %v",
			hex.EncodeToString(aliceChannels[0].FundingOutpoint.Hash[:]),
			hex.EncodeToString(fundingSha[:]))
	}
	if !aliceChannels[0].IsInitiator {
		t.Fatalf("alice not detected as channel initiator")
	}
	if !aliceChannels[0].ChanType.IsSingleFunder() {
		t.Fatalf("channel type is incorrect, expected %v instead got %v",
			channeldb.SingleFunderBit, aliceChannels[0].ChanType)
	}

	bobChannels, err := bob.Cfg.Database.FetchOpenChannels(alicePub)
	if err != nil {
		t.Fatalf("unable to retrieve channel from DB: %v", err)
	}
	if len(bobChannels) != 1 {
		t.Fatalf("bob didn't save channel state: %v", err)
	}
	if !bytes.Equal(bobChannels[0].FundingOutpoint.Hash[:], fundingSha[:]) {
		t.Fatalf("channel state not properly saved: %v vs %v",
			hex.EncodeToString(bobChannels[0].FundingOutpoint.Hash[:]),
			hex.EncodeToString(fundingSha[:]))
	}
	if bobChannels[0].IsInitiator {
		t.Fatalf("bob not detected as channel responder")
	}
	if !bobChannels[0].ChanType.IsSingleFunder() {
		t.Fatalf("channel type is incorrect, expected %v instead got %v",
			channeldb.SingleFunderBit, bobChannels[0].ChanType)
	}

	// Let Alice publish the funding transaction.
	if err := alice.PublishTransaction(fundingTx); err != nil {
		t.Fatalf("unable to publish funding tx: %v", err)
	}

	// Mine a single block, the funding transaction should be included
	// within this block.
	err = waitForMempoolTx(miner, &fundingSha)
	if err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}
	blockHashes, err := miner.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
	block, err := miner.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("unable to find block: %v", err)
	}
	if len(block.Transactions) != 2 {
		t.Fatalf("funding transaction wasn't mined: %d",
			len(block.Transactions))
	}
	blockTx := block.Transactions[1]
	if blockTx.TxHash() != fundingSha {
		t.Fatalf("incorrect transaction was mined")
	}

	// If a frozen channel was requested, then we expect that both channel
	// types show as being a frozen channel type.
	aliceChanFrozen := aliceChannels[0].ChanType.IsFrozen()
	bobChanFrozen := bobChannels[0].ChanType.IsFrozen()
	if thawHeight != 0 && (!aliceChanFrozen || !bobChanFrozen) {
		t.Fatalf("expected both alice and bob to have frozen chans: "+
			"alice_frozen=%v, bob_frozen=%v", aliceChanFrozen,
			bobChanFrozen)
	}
	if thawHeight != bobChannels[0].ThawHeight {
		t.Fatalf("wrong thaw height: expected %v got %v", thawHeight,
			bobChannels[0].ThawHeight)
	}
	if thawHeight != aliceChannels[0].ThawHeight {
		t.Fatalf("wrong thaw height: expected %v got %v", thawHeight,
			aliceChannels[0].ThawHeight)
	}

	assertReservationDeleted(aliceChanReservation, t)
	assertReservationDeleted(bobChanReservation, t)
}

func testListTransactionDetails(miner *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	// Create 5 new outputs spendable by the wallet.
	const numTxns = 5
	const outputAmt = btcutil.SatoshiPerBitcoin
	txids := make(map[chainhash.Hash]struct{})
	for i := 0; i < numTxns; i++ {
		addr, err := alice.NewAddress(lnwallet.WitnessPubKey, false)
		if err != nil {
			t.Fatalf("unable to create new address: %v", err)
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatalf("unable to create output script: %v", err)
		}

		output := &wire.TxOut{
			Value:    outputAmt,
			PkScript: script,
		}
		txid, err := miner.SendOutputs([]*wire.TxOut{output}, 2500)
		if err != nil {
			t.Fatalf("unable to send coinbase: %v", err)
		}
		txids[*txid] = struct{}{}
	}

	// Get the miner's current best block height before we mine blocks.
	_, startHeight, err := miner.Node.GetBestBlock()
	if err != nil {
		t.Fatalf("cannot get best block: %v", err)
	}

	// Generate 10 blocks to mine all the transactions created above.
	const numBlocksMined = 10
	blocks, err := miner.Node.Generate(numBlocksMined)
	if err != nil {
		t.Fatalf("unable to mine blocks: %v", err)
	}

	// Our new best block height should be our start height + the number of
	// blocks we just mined.
	chainTip := startHeight + numBlocksMined

	// Next, fetch all the current transaction details. We should find all
	// of our transactions between our start height before we generated
	// blocks, and our end height, which is the chain tip. This query does
	// not include unconfirmed transactions, since all of our transactions
	// should be confirmed.
	err = waitForWalletSync(miner, alice)
	if err != nil {
		t.Fatalf("Couldn't sync Alice's wallet: %v", err)
	}
	txDetails, err := alice.ListTransactionDetails(
		startHeight, chainTip,
	)
	if err != nil {
		t.Fatalf("unable to fetch tx details: %v", err)
	}

	// This is a mapping from:
	// blockHash -> transactionHash -> transactionOutputs
	blockTxOuts := make(map[chainhash.Hash]map[chainhash.Hash][]*wire.TxOut)

	// Each of the transactions created above should be found with the
	// proper details populated.
	for _, txDetail := range txDetails {
		if _, ok := txids[txDetail.Hash]; !ok {
			continue
		}

		if txDetail.NumConfirmations != numBlocksMined {
			t.Fatalf("num confs incorrect, got %v expected %v",
				txDetail.NumConfirmations, numBlocksMined)
		}
		if txDetail.Value != outputAmt {
			t.Fatalf("tx value incorrect, got %v expected %v",
				txDetail.Value, outputAmt)
		}

		if !bytes.Equal(txDetail.BlockHash[:], blocks[0][:]) {
			t.Fatalf("block hash mismatch, got %v expected %v",
				txDetail.BlockHash, blocks[0])
		}

		// This fetches the transactions in a block so that we can compare the
		// txouts stored in the mined transaction against the ones in the transaction
		// details
		if _, ok := blockTxOuts[*txDetail.BlockHash]; !ok {
			fetchedBlock, err := alice.Cfg.ChainIO.GetBlock(txDetail.BlockHash)
			if err != nil {
				t.Fatalf("err fetching block: %s", err)
			}

			transactions :=
				make(map[chainhash.Hash][]*wire.TxOut, len(fetchedBlock.Transactions))
			for _, tx := range fetchedBlock.Transactions {
				transactions[tx.TxHash()] = tx.TxOut
			}

			blockTxOuts[fetchedBlock.BlockHash()] = transactions
		}

		if txOuts, ok := blockTxOuts[*txDetail.BlockHash][txDetail.Hash]; !ok {
			t.Fatalf("tx (%v) not found in block (%v)",
				txDetail.Hash, txDetail.BlockHash)
		} else {
			var destinationAddresses []btcutil.Address

			for _, txOut := range txOuts {
				_, addrs, _, err :=
					txscript.ExtractPkScriptAddrs(txOut.PkScript, &alice.Cfg.NetParams)
				if err != nil {
					t.Fatalf("err extract script addresses: %s", err)
				}
				destinationAddresses = append(destinationAddresses, addrs...)
			}

			if !reflect.DeepEqual(txDetail.DestAddresses, destinationAddresses) {
				t.Fatalf("destination addresses mismatch, got %v expected %v",
					txDetail.DestAddresses, destinationAddresses)
			}
		}

		delete(txids, txDetail.Hash)
	}
	if len(txids) != 0 {
		t.Fatalf("all transactions not found in details: left=%v, "+
			"returned_set=%v", spew.Sdump(txids),
			spew.Sdump(txDetails))
	}

	// Next create a transaction paying to an output which isn't under the
	// wallet's control.
	minerAddr, err := miner.NewAddress()
	if err != nil {
		t.Fatalf("unable to generate address: %v", err)
	}
	outputScript, err := txscript.PayToAddrScript(minerAddr)
	if err != nil {
		t.Fatalf("unable to make output script: %v", err)
	}
	burnOutput := wire.NewTxOut(outputAmt, outputScript)
	burnTX, err := alice.SendOutputs([]*wire.TxOut{burnOutput}, 2500)
	if err != nil {
		t.Fatalf("unable to create burn tx: %v", err)
	}
	burnTXID := burnTX.TxHash()
	err = waitForMempoolTx(miner, &burnTXID)
	if err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}

	// Before we mine the next block, we'll ensure that the above
	// transaction shows up in the set of unconfirmed transactions returned
	// by ListTransactionDetails.
	err = waitForWalletSync(miner, alice)
	if err != nil {
		t.Fatalf("Couldn't sync Alice's wallet: %v", err)
	}

	// Query our wallet for transactions from the chain tip, including
	// unconfirmed transactions. The transaction above should be included
	// with a confirmation height of 0, indicating that it has not been
	// mined yet.
	txDetails, err = alice.ListTransactionDetails(
		chainTip, btcwallet.UnconfirmedHeight,
	)
	if err != nil {
		t.Fatalf("unable to fetch tx details: %v", err)
	}
	var mempoolTxFound bool
	for _, txDetail := range txDetails {
		if !bytes.Equal(txDetail.Hash[:], burnTXID[:]) {
			continue
		}

		// Now that we've found the transaction, ensure that it has a
		// negative number of confirmations to indicate that it's
		// unconfirmed.
		mempoolTxFound = true
		if txDetail.NumConfirmations != 0 {
			t.Fatalf("num confs incorrect, got %v expected %v",
				txDetail.NumConfirmations, 0)
		}

		// We test that each txDetail has destination addresses. This ensures
		// that even when we have 0 confirmation transactions, the destination
		// addresses are returned.
		var match bool
		for _, addr := range txDetail.DestAddresses {
			if addr.String() == minerAddr.String() {
				match = true
				break
			}
		}
		if !match {
			t.Fatalf("minerAddr: %v should have been a dest addr", minerAddr)
		}
	}
	if !mempoolTxFound {
		t.Fatalf("unable to find mempool tx in tx details!")
	}

	// Generate one block for our transaction to confirm in.
	var numBlocks int32 = 1
	burnBlock, err := miner.Node.Generate(uint32(numBlocks))
	if err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}

	// Progress our chain tip by the number of blocks we have just mined.
	chainTip += numBlocks

	// Fetch the transaction details again, the new transaction should be
	// shown as debiting from the wallet's balance. Start and end height
	// are inclusive, so we use chainTip for both parameters to get only
	// transactions from the last block.
	err = waitForWalletSync(miner, alice)
	if err != nil {
		t.Fatalf("Couldn't sync Alice's wallet: %v", err)
	}
	txDetails, err = alice.ListTransactionDetails(
		chainTip, chainTip,
	)
	if err != nil {
		t.Fatalf("unable to fetch tx details: %v", err)
	}
	var burnTxFound bool
	for _, txDetail := range txDetails {
		if !bytes.Equal(txDetail.Hash[:], burnTXID[:]) {
			continue
		}

		burnTxFound = true
		if txDetail.NumConfirmations != 1 {
			t.Fatalf("num confs incorrect, got %v expected %v",
				txDetail.NumConfirmations, 1)
		}

		// We assert that the value is greater than the amount we
		// attempted to send, as the wallet should have paid some amount
		// of network fees.
		if txDetail.Value >= -outputAmt {
			fmt.Println(spew.Sdump(txDetail))
			t.Fatalf("tx value incorrect, got %v expected %v",
				int64(txDetail.Value), -int64(outputAmt))
		}
		if !bytes.Equal(txDetail.BlockHash[:], burnBlock[0][:]) {
			t.Fatalf("block hash mismatch, got %v expected %v",
				txDetail.BlockHash, burnBlock[0])
		}
	}
	if !burnTxFound {
		t.Fatal("tx burning btc not found")
	}

	// Generate a block which has no wallet transactions in it.
	chainTip += numBlocks
	_, err = miner.Node.Generate(uint32(numBlocks))
	if err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}

	err = waitForWalletSync(miner, alice)
	if err != nil {
		t.Fatalf("Couldn't sync Alice's wallet: %v", err)
	}

	// Query for transactions only in the latest block. We do not expect
	// any transactions to be returned.
	txDetails, err = alice.ListTransactionDetails(
		chainTip, chainTip,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(txDetails) != 0 {
		t.Fatalf("expected 0 transactions, got: %v", len(txDetails))
	}
}

func testTransactionSubscriptions(miner *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	// First, check to see if this wallet meets the TransactionNotifier
	// interface, if not then we'll skip this test for this particular
	// implementation of the WalletController.
	txClient, err := alice.SubscribeTransactions()
	if err != nil {
		t.Skipf("unable to generate tx subscription: %v", err)
	}
	defer txClient.Cancel()

	const (
		outputAmt = btcutil.SatoshiPerBitcoin
		numTxns   = 3
	)
	errCh1 := make(chan error, 1)
	switch alice.BackEnd() {
	case "neutrino":
		// Neutrino doesn't listen for unconfirmed transactions.
	default:
		go func() {
			for i := 0; i < numTxns; i++ {
				txDetail := <-txClient.UnconfirmedTransactions()
				if txDetail.NumConfirmations != 0 {
					errCh1 <- fmt.Errorf("incorrect number of confs, "+
						"expected %v got %v", 0,
						txDetail.NumConfirmations)
					return
				}
				if txDetail.Value != outputAmt {
					errCh1 <- fmt.Errorf("incorrect output amt, "+
						"expected %v got %v", outputAmt,
						txDetail.Value)
					return
				}
				if txDetail.BlockHash != nil {
					errCh1 <- fmt.Errorf("block hash should be nil, "+
						"is instead %v",
						txDetail.BlockHash)
					return
				}
			}
			errCh1 <- nil
		}()
	}

	// Next, fetch a fresh address from the wallet, create 3 new outputs
	// with the pkScript.
	for i := 0; i < numTxns; i++ {
		addr, err := alice.NewAddress(lnwallet.WitnessPubKey, false)
		if err != nil {
			t.Fatalf("unable to create new address: %v", err)
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatalf("unable to create output script: %v", err)
		}

		output := &wire.TxOut{
			Value:    outputAmt,
			PkScript: script,
		}
		txid, err := miner.SendOutputs([]*wire.TxOut{output}, 2500)
		if err != nil {
			t.Fatalf("unable to send coinbase: %v", err)
		}
		err = waitForMempoolTx(miner, txid)
		if err != nil {
			t.Fatalf("tx not relayed to miner: %v", err)
		}
	}

	switch alice.BackEnd() {
	case "neutrino":
		// Neutrino doesn't listen for on unconfirmed transactions.
	default:
		// We should receive a notification for all three transactions
		// generated above.
		select {
		case <-time.After(time.Second * 10):
			t.Fatalf("transactions not received after 10 seconds")
		case err := <-errCh1:
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	errCh2 := make(chan error, 1)
	go func() {
		for i := 0; i < numTxns; i++ {
			txDetail := <-txClient.ConfirmedTransactions()
			if txDetail.NumConfirmations != 1 {
				errCh2 <- fmt.Errorf("incorrect number of confs for %s, expected %v got %v",
					txDetail.Hash, 1, txDetail.NumConfirmations)
				return
			}
			if txDetail.Value != outputAmt {
				errCh2 <- fmt.Errorf("incorrect output amt, expected %v got %v in txid %s",
					outputAmt, txDetail.Value, txDetail.Hash)
				return
			}
		}
		errCh2 <- nil
	}()

	// Next mine a single block, all the transactions generated above
	// should be included.
	if _, err := miner.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// We should receive a notification for all three transactions
	// since they should be mined in the next block.
	select {
	case <-time.After(time.Second * 5):
		t.Fatalf("transactions not received after 5 seconds")
	case err := <-errCh2:
		if err != nil {
			t.Fatal(err)
		}
	}

	// We'll also ensure that the client is able to send our new
	// notifications when we _create_ transactions ourselves that spend our
	// own outputs.
	b := txscript.NewScriptBuilder()
	b.AddOp(txscript.OP_RETURN)
	outputScript, err := b.Script()
	if err != nil {
		t.Fatalf("unable to make output script: %v", err)
	}
	burnOutput := wire.NewTxOut(outputAmt, outputScript)
	tx, err := alice.SendOutputs([]*wire.TxOut{burnOutput}, 2500)
	if err != nil {
		t.Fatalf("unable to create burn tx: %v", err)
	}
	txid := tx.TxHash()
	err = waitForMempoolTx(miner, &txid)
	if err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}

	// Before we mine the next block, we'll ensure that the above
	// transaction shows up in the set of unconfirmed transactions returned
	// by ListTransactionDetails.
	err = waitForWalletSync(miner, alice)
	if err != nil {
		t.Fatalf("Couldn't sync Alice's wallet: %v", err)
	}

	// As we just sent the transaction and it was landed in the mempool, we
	// should get a notification for a new unconfirmed transactions
	select {
	case <-time.After(time.Second * 10):
		t.Fatalf("transactions not received after 10 seconds")
	case unConfTx := <-txClient.UnconfirmedTransactions():
		if unConfTx.Hash != txid {
			t.Fatalf("wrong txn notified: expected %v got %v",
				txid, unConfTx.Hash)
		}
	}
}

// scriptFromKey creates a P2WKH script from the given pubkey.
func scriptFromKey(pubkey *btcec.PublicKey) ([]byte, error) {
	pubkeyHash := btcutil.Hash160(pubkey.SerializeCompressed())
	keyAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		pubkeyHash, &chaincfg.RegressionNetParams,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create addr: %v", err)
	}
	keyScript, err := txscript.PayToAddrScript(keyAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to generate script: %v", err)
	}

	return keyScript, nil
}

// mineAndAssert mines a block and ensures the passed TX is part of that block.
func mineAndAssert(r *rpctest.Harness, tx *wire.MsgTx) error {
	txid := tx.TxHash()
	err := waitForMempoolTx(r, &txid)
	if err != nil {
		return fmt.Errorf("tx not relayed to miner: %v", err)
	}

	blockHashes, err := r.Node.Generate(1)
	if err != nil {
		return fmt.Errorf("unable to generate block: %v", err)
	}

	block, err := r.Node.GetBlock(blockHashes[0])
	if err != nil {
		return fmt.Errorf("unable to find block: %v", err)
	}

	if len(block.Transactions) != 2 {
		return fmt.Errorf("expected 2 txs in block, got %d",
			len(block.Transactions))
	}

	blockTx := block.Transactions[1]
	if blockTx.TxHash() != tx.TxHash() {
		return fmt.Errorf("incorrect transaction was mined")
	}

	// Sleep for a second before returning, to make sure the block has
	// propagated.
	time.Sleep(1 * time.Second)
	return nil
}

// txFromOutput takes a tx paying to fromPubKey, and creates a new tx that
// spends the output from this tx, to an address derived from payToPubKey.
func txFromOutput(tx *wire.MsgTx, signer input.Signer, fromPubKey,
	payToPubKey *btcec.PublicKey, txFee btcutil.Amount,
	rbf bool) (*wire.MsgTx, error) {

	// Generate the script we want to spend from.
	keyScript, err := scriptFromKey(fromPubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate script: %v", err)
	}

	// We assume the output was paid to the keyScript made earlier.
	var outputIndex uint32
	if len(tx.TxOut) == 1 || bytes.Equal(tx.TxOut[0].PkScript, keyScript) {
		outputIndex = 0
	} else {
		outputIndex = 1
	}
	outputValue := tx.TxOut[outputIndex].Value

	// With the index located, we can create a transaction spending the
	// referenced output.
	tx1 := wire.NewMsgTx(2)

	// If we want to create a tx that signals replacement, set its
	// sequence number to the max one that signals replacement.
	// Otherwise we just use the standard max sequence.
	sequence := wire.MaxTxInSequenceNum
	if rbf {
		sequence = mempool.MaxRBFSequence
	}

	tx1.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: outputIndex,
		},
		Sequence: sequence,
	})

	// Create a script to pay to.
	payToScript, err := scriptFromKey(payToPubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate script: %v", err)
	}
	tx1.AddTxOut(&wire.TxOut{
		Value:    outputValue - int64(txFee),
		PkScript: payToScript,
	})

	// Now we can populate the sign descriptor which we'll use to generate
	// the signature.
	signDesc := &input.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			PubKey: fromPubKey,
		},
		WitnessScript: keyScript,
		Output:        tx.TxOut[outputIndex],
		HashType:      txscript.SigHashAll,
		SigHashes:     txscript.NewTxSigHashes(tx1),
		InputIndex:    0, // Has only one input.
	}

	// With the descriptor created, we use it to generate a signature, then
	// manually create a valid witness stack we'll use for signing.
	spendSig, err := signer.SignOutputRaw(tx1, signDesc)
	if err != nil {
		return nil, fmt.Errorf("unable to generate signature: %v", err)
	}
	witness := make([][]byte, 2)
	witness[0] = append(spendSig.Serialize(), byte(txscript.SigHashAll))
	witness[1] = fromPubKey.SerializeCompressed()
	tx1.TxIn[0].Witness = witness

	// Finally, attempt to validate the completed transaction. This should
	// succeed if the wallet was able to properly generate the proper
	// private key.
	vm, err := txscript.NewEngine(
		keyScript, tx1, 0, txscript.StandardVerifyFlags, nil,
		nil, outputValue,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create engine: %v", err)
	}
	if err := vm.Execute(); err != nil {
		return nil, fmt.Errorf("spend is invalid: %v", err)
	}

	return tx1, nil
}

// newTx sends coins from Alice's wallet, mines this transaction, and creates a
// new, unconfirmed tx that spends this output to pubKey.
func newTx(t *testing.T, r *rpctest.Harness, pubKey *btcec.PublicKey,
	alice *lnwallet.LightningWallet, rbf bool) *wire.MsgTx {
	t.Helper()

	keyScript, err := scriptFromKey(pubKey)
	if err != nil {
		t.Fatalf("unable to generate script: %v", err)
	}

	// Instruct the wallet to fund the output with a newly created
	// transaction.
	newOutput := &wire.TxOut{
		Value:    btcutil.SatoshiPerBitcoin,
		PkScript: keyScript,
	}
	tx, err := alice.SendOutputs([]*wire.TxOut{newOutput}, 2500)
	if err != nil {
		t.Fatalf("unable to create output: %v", err)
	}

	// Query for the transaction generated above so we can located the
	// index of our output.
	if err := mineAndAssert(r, tx); err != nil {
		t.Fatalf("unable to mine tx: %v", err)
	}

	// Create a new unconfirmed tx that spends this output.
	txFee := btcutil.Amount(0.001 * btcutil.SatoshiPerBitcoin)
	tx1, err := txFromOutput(
		tx, alice.Cfg.Signer, pubKey, pubKey, txFee, rbf,
	)
	if err != nil {
		t.Fatal(err)
	}

	return tx1
}

// testPublishTransaction checks that PublishTransaction returns the expected
// error types in case the transaction being published conflicts with the
// current mempool or chain.
func testPublishTransaction(r *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	// Generate a pubkey, and pay-to-addr script.
	keyDesc, err := alice.DeriveNextKey(keychain.KeyFamilyMultiSig)
	if err != nil {
		t.Fatalf("unable to obtain public key: %v", err)
	}

	// We will first check that publishing a transaction already in the
	// mempool does NOT return an error. Create the tx.
	tx1 := newTx(t, r, keyDesc.PubKey, alice, false)

	// Publish the transaction.
	if err := alice.PublishTransaction(tx1); err != nil {
		t.Fatalf("unable to publish: %v", err)
	}

	txid1 := tx1.TxHash()
	err = waitForMempoolTx(r, &txid1)
	if err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}

	// Publish the exact same transaction again. This should not return an
	// error, even though the transaction is already in the mempool.
	if err := alice.PublishTransaction(tx1); err != nil {
		t.Fatalf("unable to publish: %v", err)
	}

	// Mine the transaction.
	if _, err := r.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// We'll now test that we don't get an error if we try to publish a
	// transaction that is already mined.
	//
	// Create a new transaction. We must do this to properly test the
	// reject messages from our peers. They might only send us a reject
	// message for a given tx once, so we create a new to make sure it is
	// not just immediately rejected.
	tx2 := newTx(t, r, keyDesc.PubKey, alice, false)

	// Publish this tx.
	if err := alice.PublishTransaction(tx2); err != nil {
		t.Fatalf("unable to publish: %v", err)
	}

	// Mine the transaction.
	if err := mineAndAssert(r, tx2); err != nil {
		t.Fatalf("unable to mine tx: %v", err)
	}

	// Publish the transaction again. It is already mined, and we don't
	// expect this to return an error.
	if err := alice.PublishTransaction(tx2); err != nil {
		t.Fatalf("unable to publish: %v", err)
	}

	// We'll do the next mempool check on both RBF and non-RBF enabled
	// transactions.
	var (
		txFee         = btcutil.Amount(0.005 * btcutil.SatoshiPerBitcoin)
		tx3, tx3Spend *wire.MsgTx
	)

	for _, rbf := range []bool{false, true} {
		// Now we'll try to double spend an output with a different
		// transaction. Create a new tx and publish it. This is the
		// output we'll try to double spend.
		tx3 = newTx(t, r, keyDesc.PubKey, alice, false)
		if err := alice.PublishTransaction(tx3); err != nil {
			t.Fatalf("unable to publish: %v", err)
		}

		// Mine the transaction.
		if err := mineAndAssert(r, tx3); err != nil {
			t.Fatalf("unable to mine tx: %v", err)
		}

		// Now we create a transaction that spends the output from the
		// tx just mined.
		tx4, err := txFromOutput(
			tx3, alice.Cfg.Signer, keyDesc.PubKey,
			keyDesc.PubKey, txFee, rbf,
		)
		if err != nil {
			t.Fatal(err)
		}

		// This should be accepted into the mempool.
		if err := alice.PublishTransaction(tx4); err != nil {
			t.Fatalf("unable to publish: %v", err)
		}

		// Keep track of the last successfully published tx to spend
		// tx3.
		tx3Spend = tx4

		txid4 := tx4.TxHash()
		err = waitForMempoolTx(r, &txid4)
		if err != nil {
			t.Fatalf("tx not relayed to miner: %v", err)
		}

		// Create a new key we'll pay to, to ensure we create a unique
		// transaction.
		keyDesc2, err := alice.DeriveNextKey(
			keychain.KeyFamilyMultiSig,
		)
		if err != nil {
			t.Fatalf("unable to obtain public key: %v", err)
		}

		// Create a new transaction that spends the output from tx3,
		// and that pays to a different address. We expect this to be
		// rejected because it is a double spend.
		tx5, err := txFromOutput(
			tx3, alice.Cfg.Signer, keyDesc.PubKey,
			keyDesc2.PubKey, txFee, rbf,
		)
		if err != nil {
			t.Fatal(err)
		}

		err = alice.PublishTransaction(tx5)
		if err != lnwallet.ErrDoubleSpend {
			t.Fatalf("expected ErrDoubleSpend, got: %v", err)
		}

		// Create another transaction that spends the same output, but
		// has a higher fee. We expect also this tx to be rejected for
		// non-RBF enabled transactions, while it should succeed
		// otherwise.
		pubKey3, err := alice.DeriveNextKey(keychain.KeyFamilyMultiSig)
		if err != nil {
			t.Fatalf("unable to obtain public key: %v", err)
		}
		tx6, err := txFromOutput(
			tx3, alice.Cfg.Signer, keyDesc.PubKey,
			pubKey3.PubKey, 2*txFee, rbf,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Expect rejection in non-RBF case.
		expErr := lnwallet.ErrDoubleSpend
		if rbf {
			// Expect success in rbf case.
			expErr = nil
			tx3Spend = tx6
		}
		err = alice.PublishTransaction(tx6)
		if err != expErr {
			t.Fatalf("expected ErrDoubleSpend, got: %v", err)
		}

		// Mine the tx spending tx3.
		if err := mineAndAssert(r, tx3Spend); err != nil {
			t.Fatalf("unable to mine tx: %v", err)
		}
	}

	// At last we try to spend an output already spent by a confirmed
	// transaction.
	// TODO(halseth): we currently skip this test for neutrino, as the
	// backing btcd node will consider the tx being an orphan, and will
	// accept it. Should look into if this is the behavior also for
	// bitcoind, and update test accordingly.
	if alice.BackEnd() != "neutrino" {
		// Create another tx spending tx3.
		pubKey4, err := alice.DeriveNextKey(
			keychain.KeyFamilyMultiSig,
		)
		if err != nil {
			t.Fatalf("unable to obtain public key: %v", err)
		}
		tx7, err := txFromOutput(
			tx3, alice.Cfg.Signer, keyDesc.PubKey,
			pubKey4.PubKey, txFee, false,
		)

		if err != nil {
			t.Fatal(err)
		}

		// Expect rejection.
		err = alice.PublishTransaction(tx7)
		if err != lnwallet.ErrDoubleSpend {
			t.Fatalf("expected ErrDoubleSpend, got: %v", err)
		}
	}
}

func testSignOutputUsingTweaks(r *rpctest.Harness,
	alice, _ *lnwallet.LightningWallet, t *testing.T) {

	// We'd like to test the ability of the wallet's Signer implementation
	// to be able to sign with a private key derived from tweaking the
	// specific public key. This scenario exercises the case when the
	// wallet needs to sign for a sweep of a revoked output, or just claim
	// any output that pays to a tweaked key.

	// First, generate a new public key under the control of the wallet,
	// then generate a revocation key using it.
	pubKey, err := alice.DeriveNextKey(
		keychain.KeyFamilyMultiSig,
	)
	if err != nil {
		t.Fatalf("unable to obtain public key: %v", err)
	}

	// As we'd like to test both single tweak, and double tweak spends,
	// we'll generate a commitment pre-image, then derive a revocation key
	// and single tweak from that.
	commitPreimage := bytes.Repeat([]byte{2}, 32)
	commitSecret, commitPoint := btcec.PrivKeyFromBytes(btcec.S256(),
		commitPreimage)

	revocationKey := input.DeriveRevocationPubkey(pubKey.PubKey, commitPoint)
	commitTweak := input.SingleTweakBytes(commitPoint, pubKey.PubKey)

	tweakedPub := input.TweakPubKey(pubKey.PubKey, commitPoint)

	// As we'd like to test both single and double tweaks, we'll repeat
	// the same set up twice. The first will use a regular single tweak,
	// and the second will use a double tweak.
	baseKey := pubKey
	for i := 0; i < 2; i++ {
		var tweakedKey *btcec.PublicKey
		if i == 0 {
			tweakedKey = tweakedPub
		} else {
			tweakedKey = revocationKey
		}

		// Using the given key for the current iteration, we'll
		// generate a regular p2wkh from that.
		pubkeyHash := btcutil.Hash160(tweakedKey.SerializeCompressed())
		keyAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubkeyHash,
			&chaincfg.RegressionNetParams)
		if err != nil {
			t.Fatalf("unable to create addr: %v", err)
		}
		keyScript, err := txscript.PayToAddrScript(keyAddr)
		if err != nil {
			t.Fatalf("unable to generate script: %v", err)
		}

		// With the script fully assembled, instruct the wallet to fund
		// the output with a newly created transaction.
		newOutput := &wire.TxOut{
			Value:    btcutil.SatoshiPerBitcoin,
			PkScript: keyScript,
		}
		tx, err := alice.SendOutputs([]*wire.TxOut{newOutput}, 2500)
		if err != nil {
			t.Fatalf("unable to create output: %v", err)
		}
		txid := tx.TxHash()
		// Query for the transaction generated above so we can located
		// the index of our output.
		err = waitForMempoolTx(r, &txid)
		if err != nil {
			t.Fatalf("tx not relayed to miner: %v", err)
		}
		var outputIndex uint32
		if bytes.Equal(tx.TxOut[0].PkScript, keyScript) {
			outputIndex = 0
		} else {
			outputIndex = 1
		}

		// With the index located, we can create a transaction spending
		// the referenced output.
		sweepTx := wire.NewMsgTx(2)
		sweepTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  txid,
				Index: outputIndex,
			},
		})
		sweepTx.AddTxOut(&wire.TxOut{
			Value:    1000,
			PkScript: keyScript,
		})

		// Now we can populate the sign descriptor which we'll use to
		// generate the signature. Within the descriptor we set the
		// private tweak value as the key in the script is derived
		// based on this tweak value and the key we originally
		// generated above.
		signDesc := &input.SignDescriptor{
			KeyDesc: keychain.KeyDescriptor{
				PubKey: baseKey.PubKey,
			},
			WitnessScript: keyScript,
			Output:        newOutput,
			HashType:      txscript.SigHashAll,
			SigHashes:     txscript.NewTxSigHashes(sweepTx),
			InputIndex:    0,
		}

		// If this is the first, loop, we'll use the generated single
		// tweak, otherwise, we'll use the double tweak.
		if i == 0 {
			signDesc.SingleTweak = commitTweak
		} else {
			signDesc.DoubleTweak = commitSecret
		}

		// With the descriptor created, we use it to generate a
		// signature, then manually create a valid witness stack we'll
		// use for signing.
		spendSig, err := alice.Cfg.Signer.SignOutputRaw(sweepTx, signDesc)
		if err != nil {
			t.Fatalf("unable to generate signature: %v", err)
		}
		witness := make([][]byte, 2)
		witness[0] = append(spendSig.Serialize(), byte(txscript.SigHashAll))
		witness[1] = tweakedKey.SerializeCompressed()
		sweepTx.TxIn[0].Witness = witness

		// Finally, attempt to validate the completed transaction. This
		// should succeed if the wallet was able to properly generate
		// the proper private key.
		vm, err := txscript.NewEngine(keyScript,
			sweepTx, 0, txscript.StandardVerifyFlags, nil,
			nil, int64(btcutil.SatoshiPerBitcoin))
		if err != nil {
			t.Fatalf("unable to create engine: %v", err)
		}
		if err := vm.Execute(); err != nil {
			t.Fatalf("spend #%v is invalid: %v", i, err)
		}
	}
}

func testReorgWalletBalance(r *rpctest.Harness, w *lnwallet.LightningWallet,
	_ *lnwallet.LightningWallet, t *testing.T) {

	// We first mine a few blocks to ensure any transactions still in the
	// mempool confirm, and then get the original balance, before a
	// reorganization that doesn't invalidate any existing transactions or
	// create any new non-coinbase transactions. We'll then check if it's
	// the same after the empty reorg.
	_, err := r.Node.Generate(5)
	if err != nil {
		t.Fatalf("unable to generate blocks on passed node: %v", err)
	}

	// Give wallet time to catch up.
	err = waitForWalletSync(r, w)
	if err != nil {
		t.Fatalf("unable to sync wallet: %v", err)
	}

	// Send some money from the miner to the wallet
	err = loadTestCredits(r, w, 20, 4)
	if err != nil {
		t.Fatalf("unable to send money to lnwallet: %v", err)
	}

	// Send some money from the wallet back to the miner.
	// Grab a fresh address from the miner to house this output.
	minerAddr, err := r.NewAddress()
	if err != nil {
		t.Fatalf("unable to generate address for miner: %v", err)
	}
	script, err := txscript.PayToAddrScript(minerAddr)
	if err != nil {
		t.Fatalf("unable to create pay to addr script: %v", err)
	}
	output := &wire.TxOut{
		Value:    1e8,
		PkScript: script,
	}
	tx, err := w.SendOutputs([]*wire.TxOut{output}, 2500)
	if err != nil {
		t.Fatalf("unable to send outputs: %v", err)
	}
	txid := tx.TxHash()
	err = waitForMempoolTx(r, &txid)
	if err != nil {
		t.Fatalf("tx not relayed to miner: %v", err)
	}
	_, err = r.Node.Generate(50)
	if err != nil {
		t.Fatalf("unable to generate blocks on passed node: %v", err)
	}

	// Give wallet time to catch up.
	err = waitForWalletSync(r, w)
	if err != nil {
		t.Fatalf("unable to sync wallet: %v", err)
	}

	// Get the original balance.
	origBalance, err := w.ConfirmedBalance(1)
	if err != nil {
		t.Fatalf("unable to query for balance: %v", err)
	}

	// Now we cause a reorganization as follows.
	// Step 1: create a new miner and start it.
	r2, err := rpctest.New(r.ActiveNet, nil, []string{"--txindex"})
	if err != nil {
		t.Fatalf("unable to create mining node: %v", err)
	}
	err = r2.SetUp(false, 0)
	if err != nil {
		t.Fatalf("unable to set up mining node: %v", err)
	}
	defer r2.TearDown()
	newBalance, err := w.ConfirmedBalance(1)
	if err != nil {
		t.Fatalf("unable to query for balance: %v", err)
	}
	if origBalance != newBalance {
		t.Fatalf("wallet balance incorrect, should have %v, "+
			"instead have %v", origBalance, newBalance)
	}

	// Step 2: connect the miner to the passed miner and wait for
	// synchronization.
	err = r2.Node.AddNode(r.P2PAddress(), rpcclient.ANAdd)
	if err != nil {
		t.Fatalf("unable to connect mining nodes together: %v", err)
	}
	err = rpctest.JoinNodes([]*rpctest.Harness{r2, r}, rpctest.Blocks)
	if err != nil {
		t.Fatalf("unable to synchronize mining nodes: %v", err)
	}

	// Step 3: Do a set of reorgs by disconnecting the two miners, mining
	// one block on the passed miner and two on the created miner,
	// connecting them, and waiting for them to sync.
	for i := 0; i < 5; i++ {
		// Wait for disconnection
		timeout := time.After(30 * time.Second)
		stillConnected := true
		var peers []btcjson.GetPeerInfoResult
		for stillConnected {
			// Allow for timeout
			time.Sleep(100 * time.Millisecond)
			select {
			case <-timeout:
				t.Fatalf("timeout waiting for miner disconnect")
			default:
			}
			err = r2.Node.AddNode(r.P2PAddress(), rpcclient.ANRemove)
			if err != nil {
				t.Fatalf("unable to disconnect mining nodes: %v",
					err)
			}
			peers, err = r2.Node.GetPeerInfo()
			if err != nil {
				t.Fatalf("unable to get peer info: %v", err)
			}
			stillConnected = false
			for _, peer := range peers {
				if peer.Addr == r.P2PAddress() {
					stillConnected = true
					break
				}
			}
		}
		_, err = r.Node.Generate(2)
		if err != nil {
			t.Fatalf("unable to generate blocks on passed node: %v",
				err)
		}
		_, err = r2.Node.Generate(3)
		if err != nil {
			t.Fatalf("unable to generate blocks on created node: %v",
				err)
		}

		// Step 5: Reconnect the miners and wait for them to synchronize.
		err = r2.Node.AddNode(r.P2PAddress(), rpcclient.ANAdd)
		if err != nil {
			switch err := err.(type) {
			case *btcjson.RPCError:
				if err.Code != -8 {
					t.Fatalf("unable to connect mining "+
						"nodes together: %v", err)
				}
			default:
				t.Fatalf("unable to connect mining nodes "+
					"together: %v", err)
			}
		}
		err = rpctest.JoinNodes([]*rpctest.Harness{r2, r},
			rpctest.Blocks)
		if err != nil {
			t.Fatalf("unable to synchronize mining nodes: %v", err)
		}

		// Give wallet time to catch up.
		err = waitForWalletSync(r, w)
		if err != nil {
			t.Fatalf("unable to sync wallet: %v", err)
		}
	}

	// Now we check that the wallet balance stays the same.
	newBalance, err = w.ConfirmedBalance(1)
	if err != nil {
		t.Fatalf("unable to query for balance: %v", err)
	}
	if origBalance != newBalance {
		t.Fatalf("wallet balance incorrect, should have %v, "+
			"instead have %v", origBalance, newBalance)
	}
}

// testChangeOutputSpendConfirmation ensures that when we attempt to spend a
// change output created by the wallet, the wallet receives its confirmation
// once included in the chain.
func testChangeOutputSpendConfirmation(r *rpctest.Harness,
	alice, bob *lnwallet.LightningWallet, t *testing.T) {

	// In order to test that we see the confirmation of a transaction that
	// spends an output created by SendOutputs, we'll start by emptying
	// Alice's wallet so that no other UTXOs can be picked. To do so, we'll
	// generate an address for Bob, who will receive all the coins.
	// Assuming a balance of 80 BTC and a transaction fee of 2500 sat/kw,
	// we'll craft the following transaction so that Alice doesn't have any
	// UTXOs left.
	aliceBalance, err := alice.ConfirmedBalance(0)
	if err != nil {
		t.Fatalf("unable to retrieve alice's balance: %v", err)
	}
	bobPkScript := newPkScript(t, bob, lnwallet.WitnessPubKey)

	// We'll use a transaction fee of 13020 satoshis, which will allow us to
	// sweep all of Alice's balance in one transaction containing 1 input
	// and 1 output.
	//
	// TODO(wilmer): replace this once SendOutputs easily supports sending
	// all funds in one transaction.
	txFeeRate := chainfee.SatPerKWeight(2500)
	txFee := btcutil.Amount(14380)
	output := &wire.TxOut{
		Value:    int64(aliceBalance - txFee),
		PkScript: bobPkScript,
	}
	tx := sendCoins(t, r, alice, bob, output, txFeeRate)
	txHash := tx.TxHash()
	assertTxInWallet(t, alice, txHash, true)
	assertTxInWallet(t, bob, txHash, true)

	// With the transaction sent and confirmed, Alice's balance should now
	// be 0.
	aliceBalance, err = alice.ConfirmedBalance(0)
	if err != nil {
		t.Fatalf("unable to retrieve alice's balance: %v", err)
	}
	if aliceBalance != 0 {
		t.Fatalf("expected alice's balance to be 0 BTC, found %v",
			aliceBalance)
	}

	// Now, we'll send an output back to Alice from Bob of 1 BTC.
	alicePkScript := newPkScript(t, alice, lnwallet.WitnessPubKey)
	output = &wire.TxOut{
		Value:    btcutil.SatoshiPerBitcoin,
		PkScript: alicePkScript,
	}
	tx = sendCoins(t, r, bob, alice, output, txFeeRate)
	txHash = tx.TxHash()
	assertTxInWallet(t, alice, txHash, true)
	assertTxInWallet(t, bob, txHash, true)

	// Alice now has an available output to spend, but it was not a change
	// output, which is what the test expects. Therefore, we'll generate one
	// by sending Bob back some coins.
	output = &wire.TxOut{
		Value:    btcutil.SatoshiPerBitcent,
		PkScript: bobPkScript,
	}
	tx = sendCoins(t, r, alice, bob, output, txFeeRate)
	txHash = tx.TxHash()
	assertTxInWallet(t, alice, txHash, true)
	assertTxInWallet(t, bob, txHash, true)

	// Then, we'll spend the change output and ensure we see its
	// confirmation come in.
	tx = sendCoins(t, r, alice, bob, output, txFeeRate)
	txHash = tx.TxHash()
	assertTxInWallet(t, alice, txHash, true)
	assertTxInWallet(t, bob, txHash, true)

	// Finally, we'll replenish Alice's wallet with some more coins to
	// ensure she has enough for any following test cases.
	if err := loadTestCredits(r, alice, 20, 4); err != nil {
		t.Fatalf("unable to replenish alice's wallet: %v", err)
	}
}

// testLastUnusedAddr tests that the LastUnusedAddress returns the address if
// it isn't used, and also that once the address becomes used, then it's
// properly rotated.
func testLastUnusedAddr(miner *rpctest.Harness,
	alice, bob *lnwallet.LightningWallet, t *testing.T) {

	if _, err := miner.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// We'll repeat this test for each address type to ensure they're all
	// rotated properly.
	addrTypes := []lnwallet.AddressType{
		lnwallet.WitnessPubKey, lnwallet.NestedWitnessPubKey,
	}
	for _, addrType := range addrTypes {
		addr1, err := alice.LastUnusedAddress(addrType)
		if err != nil {
			t.Fatalf("unable to get addr: %v", err)
		}
		addr2, err := alice.LastUnusedAddress(addrType)
		if err != nil {
			t.Fatalf("unable to get addr: %v", err)
		}

		// If we generate two addresses back to back, then we should
		// get the same addr, as none of them have been used yet.
		if addr1.String() != addr2.String() {
			t.Fatalf("addresses changed w/o use: %v vs %v", addr1, addr2)
		}

		// Next, we'll have Bob pay to Alice's new address. This should
		// trigger address rotation at the backend wallet.
		addrScript, err := txscript.PayToAddrScript(addr1)
		if err != nil {
			t.Fatalf("unable to convert addr to script: %v", err)
		}
		feeRate := chainfee.SatPerKWeight(2500)
		output := &wire.TxOut{
			Value:    1000000,
			PkScript: addrScript,
		}
		sendCoins(t, miner, bob, alice, output, feeRate)

		// If we make a new address, then it should be brand new, as
		// the prior address has been used.
		addr3, err := alice.LastUnusedAddress(addrType)
		if err != nil {
			t.Fatalf("unable to get addr: %v", err)
		}
		if addr1.String() == addr3.String() {
			t.Fatalf("address should have changed but didn't")
		}
	}
}

// testCreateSimpleTx checks that a call to CreateSimpleTx will return a
// transaction that is equal to the one that is being created by SendOutputs in
// a subsequent call.
func testCreateSimpleTx(r *rpctest.Harness, w *lnwallet.LightningWallet,
	_ *lnwallet.LightningWallet, t *testing.T) {

	// Send some money from the miner to the wallet
	err := loadTestCredits(r, w, 20, 4)
	if err != nil {
		t.Fatalf("unable to send money to lnwallet: %v", err)
	}

	// The test cases we will run through for all backends.
	testCases := []struct {
		outVals []int64
		feeRate chainfee.SatPerKWeight
		valid   bool
	}{
		{
			outVals: []int64{},
			feeRate: 2500,
			valid:   false, // No outputs.
		},

		{
			outVals: []int64{200},
			feeRate: 2500,
			valid:   false, // Dust output.
		},

		{
			outVals: []int64{1e8},
			feeRate: 2500,
			valid:   true,
		},
		{
			outVals: []int64{1e8, 2e8, 1e8, 2e7, 3e5},
			feeRate: 2500,
			valid:   true,
		},
		{
			outVals: []int64{1e8, 2e8, 1e8, 2e7, 3e5},
			feeRate: 12500,
			valid:   true,
		},
		{
			outVals: []int64{1e8, 2e8, 1e8, 2e7, 3e5},
			feeRate: 50000,
			valid:   true,
		},
		{
			outVals: []int64{1e8, 2e8, 1e8, 2e7, 3e5, 1e8, 2e8,
				1e8, 2e7, 3e5},
			feeRate: 44250,
			valid:   true,
		},
	}

	for i, test := range testCases {
		feeRate := test.feeRate

		// Grab some fresh addresses from the miner that we will send
		// to.
		outputs := make([]*wire.TxOut, len(test.outVals))
		for i, outVal := range test.outVals {
			minerAddr, err := r.NewAddress()
			if err != nil {
				t.Fatalf("unable to generate address for "+
					"miner: %v", err)
			}
			script, err := txscript.PayToAddrScript(minerAddr)
			if err != nil {
				t.Fatalf("unable to create pay to addr "+
					"script: %v", err)
			}
			output := &wire.TxOut{
				Value:    outVal,
				PkScript: script,
			}

			outputs[i] = output
		}

		// Now try creating a tx spending to these outputs.
		createTx, createErr := w.CreateSimpleTx(
			outputs, feeRate, true,
		)
		switch {
		case test.valid && createErr != nil:
			fmt.Println(spew.Sdump(createTx.Tx))
			t.Fatalf("got unexpected error when creating tx: %v",
				createErr)

		case !test.valid && createErr == nil:
			t.Fatalf("test #%v should have failed on tx "+
				"creation", i)
		}

		// Also send to these outputs. This should result in a tx
		// _very_ similar to the one we just created being sent. The
		// only difference is that the dry run tx is not signed, and
		// that the change output position might be different.
		tx, sendErr := w.SendOutputs(outputs, feeRate)
		switch {
		case test.valid && sendErr != nil:
			t.Fatalf("got unexpected error when sending tx: %v",
				sendErr)

		case !test.valid && sendErr == nil:
			t.Fatalf("test #%v should fail for tx sending", i)
		}

		// We expected either both to not fail, or both to fail with
		// the same error.
		if createErr != sendErr {
			t.Fatalf("error creating tx (%v) different "+
				"from error sending outputs (%v)",
				createErr, sendErr)
		}

		// If we expected the creation to fail, then this test is over.
		if !test.valid {
			continue
		}

		txid := tx.TxHash()
		err = waitForMempoolTx(r, &txid)
		if err != nil {
			t.Fatalf("tx not relayed to miner: %v", err)
		}

		// Helper method to check that the two txs are similar.
		assertSimilarTx := func(a, b *wire.MsgTx) error {
			if a.Version != b.Version {
				return fmt.Errorf("different versions: "+
					"%v vs %v", a.Version, b.Version)
			}
			if a.LockTime != b.LockTime {
				return fmt.Errorf("different locktimes: "+
					"%v vs %v", a.LockTime, b.LockTime)
			}
			if len(a.TxIn) != len(b.TxIn) {
				return fmt.Errorf("different number of "+
					"inputs: %v vs %v", len(a.TxIn),
					len(b.TxIn))
			}
			if len(a.TxOut) != len(b.TxOut) {
				return fmt.Errorf("different number of "+
					"outputs: %v vs %v", len(a.TxOut),
					len(b.TxOut))
			}

			// They should be spending the same inputs.
			for i := range a.TxIn {
				prevA := a.TxIn[i].PreviousOutPoint
				prevB := b.TxIn[i].PreviousOutPoint
				if prevA != prevB {
					return fmt.Errorf("different inputs: "+
						"%v vs %v", spew.Sdump(prevA),
						spew.Sdump(prevB))
				}
			}

			// They should have the same outputs. Since the change
			// output position gets randomized, they are not
			// guaranteed to be in the same order.
			for _, outA := range a.TxOut {
				found := false
				for _, outB := range b.TxOut {
					if reflect.DeepEqual(outA, outB) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("did not find "+
						"output %v", spew.Sdump(outA))
				}
			}
			return nil
		}

		// Assert that our "template tx" was similar to the one that
		// ended up being sent.
		if err := assertSimilarTx(createTx.Tx, tx); err != nil {
			t.Fatalf("transactions not similar: %v", err)
		}
	}
}

// testSignOutputCreateAccount tests that we're able to properly sign for an
// output if the target account hasn't yet been created on disk. In this case,
// we'll create the account, then sign.
func testSignOutputCreateAccount(r *rpctest.Harness, w *lnwallet.LightningWallet,
	_ *lnwallet.LightningWallet, t *testing.T) {

	// First, we'll create a sign desc that references a non-default key
	// family. Under the hood, key families are actually accounts, so this
	// should force create of the account so we can sign with it.
	fakeTx := wire.NewMsgTx(2)
	fakeTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: 0,
		},
	})
	signDesc := &input.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: 99,
				Index:  1,
			},
		},
		WitnessScript: []byte{},
		Output: &wire.TxOut{
			Value: 1000,
		},
		HashType:   txscript.SigHashAll,
		SigHashes:  txscript.NewTxSigHashes(fakeTx),
		InputIndex: 0,
	}

	// We'll now sign and expect this to succeed, as even though the
	// account doesn't exist atm, it should be created in order to process
	// the inbound signing request.
	_, err := w.Cfg.Signer.SignOutputRaw(fakeTx, signDesc)
	if err != nil {
		t.Fatalf("unable to sign for output with non-existent "+
			"account: %v", err)
	}
}

type walletTestCase struct {
	name string
	test func(miner *rpctest.Harness, alice, bob *lnwallet.LightningWallet,
		test *testing.T)
}

var walletTests = []walletTestCase{
	{
		// TODO(wilmer): this test should remain first until the wallet
		// can properly craft a transaction that spends all of its
		// on-chain funds.
		name: "change output spend confirmation",
		test: testChangeOutputSpendConfirmation,
	},
	{
		name: "insane fee reject",
		test: testReservationInitiatorBalanceBelowDustCancel,
	},
	{
		name: "single funding workflow",
		test: func(miner *rpctest.Harness, alice,
			bob *lnwallet.LightningWallet, t *testing.T) {

			testSingleFunderReservationWorkflow(
				miner, alice, bob, t,
				lnwallet.CommitmentTypeLegacy, nil,
				nil, [32]byte{}, 0,
			)
		},
	},
	{
		name: "single funding workflow tweakless",
		test: func(miner *rpctest.Harness, alice,
			bob *lnwallet.LightningWallet, t *testing.T) {

			testSingleFunderReservationWorkflow(
				miner, alice, bob, t,
				lnwallet.CommitmentTypeTweakless, nil,
				nil, [32]byte{}, 0,
			)
		},
	},
	{
		name: "single funding workflow external funding tx",
		test: testSingleFunderExternalFundingTx,
	},
	{
		name: "dual funder workflow",
		test: testDualFundingReservationWorkflow,
	},
	{
		name: "output locking",
		test: testFundingTransactionLockedOutputs,
	},
	{
		name: "reservation insufficient funds",
		test: testFundingCancellationNotEnoughFunds,
	},
	{
		name: "transaction subscriptions",
		test: testTransactionSubscriptions,
	},
	{
		name: "transaction details",
		test: testListTransactionDetails,
	},
	{
		name: "publish transaction",
		test: testPublishTransaction,
	},
	{
		name: "signed with tweaked pubkeys",
		test: testSignOutputUsingTweaks,
	},
	{
		name: "test cancel non-existent reservation",
		test: testCancelNonExistentReservation,
	},
	{
		name: "last unused addr",
		test: testLastUnusedAddr,
	},
	{
		name: "reorg wallet balance",
		test: testReorgWalletBalance,
	},
	{
		name: "create simple tx",
		test: testCreateSimpleTx,
	},
	{
		name: "test sign create account",
		test: testSignOutputCreateAccount,
	},
}

func clearWalletStates(a, b *lnwallet.LightningWallet) error {
	a.ResetReservations()
	b.ResetReservations()

	if err := a.Cfg.Database.Wipe(); err != nil {
		return err
	}

	return b.Cfg.Database.Wipe()
}

func waitForMempoolTx(r *rpctest.Harness, txid *chainhash.Hash) error {
	var found bool
	var tx *btcutil.Tx
	var err error
	timeout := time.After(30 * time.Second)
	for !found {
		// Do a short wait
		select {
		case <-timeout:
			return fmt.Errorf("timeout after 10s")
		default:
		}
		time.Sleep(100 * time.Millisecond)

		// Check for the harness' knowledge of the txid
		tx, err = r.Node.GetRawTransaction(txid)
		if err != nil {
			switch e := err.(type) {
			case *btcjson.RPCError:
				if e.Code == btcjson.ErrRPCNoTxInfo {
					continue
				}
			default:
			}
			return err
		}
		if tx != nil && tx.MsgTx().TxHash() == *txid {
			found = true
		}
	}
	return nil
}

func waitForWalletSync(r *rpctest.Harness, w *lnwallet.LightningWallet) error {
	var (
		synced                  bool
		err                     error
		bestHash, knownHash     *chainhash.Hash
		bestHeight, knownHeight int32
	)
	timeout := time.After(10 * time.Second)
	for !synced {
		// Do a short wait
		select {
		case <-timeout:
			return fmt.Errorf("timeout after 30s")
		case <-time.Tick(100 * time.Millisecond):
		}

		// Check whether the chain source of the wallet is caught up to
		// the harness it's supposed to be catching up to.
		bestHash, bestHeight, err = r.Node.GetBestBlock()
		if err != nil {
			return err
		}
		knownHash, knownHeight, err = w.Cfg.ChainIO.GetBestBlock()
		if err != nil {
			return err
		}
		if knownHeight != bestHeight {
			continue
		}
		if *knownHash != *bestHash {
			return fmt.Errorf("hash at height %d doesn't match: "+
				"expected %s, got %s", bestHeight, bestHash,
				knownHash)
		}

		// Check for synchronization.
		synced, _, err = w.IsSynced()
		if err != nil {
			return err
		}
	}
	return nil
}

// testSingleFunderExternalFundingTx tests that the wallet is able to properly
// carry out a funding flow backed by a channel point that has been crafted
// outside the wallet.
func testSingleFunderExternalFundingTx(miner *rpctest.Harness,
	alice, bob *lnwallet.LightningWallet, t *testing.T) {

	// First, we'll obtain multi-sig keys from both Alice and Bob which
	// simulates them exchanging keys on a higher level.
	aliceFundingKey, err := alice.DeriveNextKey(keychain.KeyFamilyMultiSig)
	if err != nil {
		t.Fatalf("unable to obtain alice funding key: %v", err)
	}
	bobFundingKey, err := bob.DeriveNextKey(keychain.KeyFamilyMultiSig)
	if err != nil {
		t.Fatalf("unable to obtain bob funding key: %v", err)
	}

	// We'll now set up for them to open a 4 BTC channel, with 1 BTC pushed
	// to Bob's side.
	chanAmt := 4 * btcutil.SatoshiPerBitcoin

	// Simulating external funding negotiation, we'll now create the
	// funding transaction for both parties. Utilizing existing tools,
	// we'll create a new chanfunding.Assembler hacked by Alice's wallet.
	aliceChanFunder := chanfunding.NewWalletAssembler(chanfunding.WalletConfig{
		CoinSource:       lnwallet.NewCoinSource(alice),
		CoinSelectLocker: alice,
		CoinLocker:       alice,
		Signer:           alice.Cfg.Signer,
		DustLimit:        600,
	})

	// With the chan funder created, we'll now provision a funding intent,
	// bind the keys we obtained above, and finally obtain our funding
	// transaction and outpoint.
	fundingIntent, err := aliceChanFunder.ProvisionChannel(&chanfunding.Request{
		LocalAmt: btcutil.Amount(chanAmt),
		MinConfs: 1,
		FeeRate:  253,
		ChangeAddr: func() (btcutil.Address, error) {
			return alice.NewAddress(lnwallet.WitnessPubKey, true)
		},
	})
	if err != nil {
		t.Fatalf("unable to perform coin selection: %v", err)
	}

	// With our intent created, we'll instruct it to finalize the funding
	// transaction, and also hand us the outpoint so we can simulate
	// external crafting of the funding transaction.
	var (
		fundingTx *wire.MsgTx
		chanPoint *wire.OutPoint
	)
	if fullIntent, ok := fundingIntent.(*chanfunding.FullIntent); ok {
		fullIntent.BindKeys(&aliceFundingKey, bobFundingKey.PubKey)

		fundingTx, err = fullIntent.CompileFundingTx(nil, nil)
		if err != nil {
			t.Fatalf("unable to compile funding tx: %v", err)
		}
		chanPoint, err = fullIntent.ChanPoint()
		if err != nil {
			t.Fatalf("unable to obtain chan point: %v", err)
		}
	} else {
		t.Fatalf("expected full intent, instead got: %T", fullIntent)
	}

	// Now that we have the fully constructed funding transaction, we'll
	// create a new shim external funder out of it for Alice, and prep a
	// shim intent for Bob.
	thawHeight := uint32(200)
	aliceExternalFunder := chanfunding.NewCannedAssembler(
		thawHeight, *chanPoint, btcutil.Amount(chanAmt), &aliceFundingKey,
		bobFundingKey.PubKey, true,
	)
	bobShimIntent, err := chanfunding.NewCannedAssembler(
		thawHeight, *chanPoint, btcutil.Amount(chanAmt), &bobFundingKey,
		aliceFundingKey.PubKey, false,
	).ProvisionChannel(&chanfunding.Request{
		LocalAmt: btcutil.Amount(chanAmt),
		MinConfs: 1,
		FeeRate:  253,
		ChangeAddr: func() (btcutil.Address, error) {
			return bob.NewAddress(lnwallet.WitnessPubKey, true)
		},
	})
	if err != nil {
		t.Fatalf("unable to create shim intent for bob: %v", err)
	}

	// At this point, we have everything we need to carry out our test, so
	// we'll being the funding flow between Alice and Bob.
	//
	// However, before we do so, we'll register a new shim intent for Bob,
	// so he knows what keys to use when he receives the funding request
	// from Alice.
	pendingChanID := testHdSeed
	err = bob.RegisterFundingIntent(pendingChanID, bobShimIntent)
	if err != nil {
		t.Fatalf("unable to register intent: %v", err)
	}

	// Now we can carry out the single funding flow as normal, we'll
	// specify our external funder and funding transaction, as well as the
	// pending channel ID generated above to allow Alice and Bob to track
	// the funding flow externally.
	testSingleFunderReservationWorkflow(
		miner, alice, bob, t, lnwallet.CommitmentTypeTweakless,
		aliceExternalFunder, func() *wire.MsgTx {
			return fundingTx
		}, pendingChanID, thawHeight,
	)
}

// TestInterfaces tests all registered interfaces with a unified set of tests
// which exercise each of the required methods found within the WalletController
// interface.
//
// NOTE: In the future, when additional implementations of the WalletController
// interface have been implemented, in order to ensure the new concrete
// implementation is automatically tested, two steps must be undertaken. First,
// one needs add a "non-captured" (_) import from the new sub-package. This
// import should trigger an init() method within the package which registers
// the interface. Second, an additional case in the switch within the main loop
// below needs to be added which properly initializes the interface.
//
// TODO(roasbeef): purge bobNode in favor of dual lnwallet's
func TestLightningWallet(t *testing.T) {
	t.Parallel()

	// Initialize the harness around a btcd node which will serve as our
	// dedicated miner to generate blocks, cause re-orgs, etc. We'll set
	// up this node with a chain length of 125, so we have plenty of BTC
	// to play around with.
	miningNode, err := rpctest.New(netParams, nil, []string{"--txindex"})
	if err != nil {
		t.Fatalf("unable to create mining node: %v", err)
	}
	defer miningNode.TearDown()
	if err := miningNode.SetUp(true, 25); err != nil {
		t.Fatalf("unable to set up mining node: %v", err)
	}

	// Next mine enough blocks in order for segwit and the CSV package
	// soft-fork to activate on RegNet.
	numBlocks := netParams.MinerConfirmationWindow * 2
	if _, err := miningNode.Node.Generate(numBlocks); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	rpcConfig := miningNode.RPCConfig()

	tempDir, err := ioutil.TempDir("", "channeldb")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}
	db, err := channeldb.Open(tempDir)
	if err != nil {
		t.Fatalf("unable to create db: %v", err)
	}
	hintCache, err := chainntnfs.NewHeightHintCache(db)
	if err != nil {
		t.Fatalf("unable to create height hint cache: %v", err)
	}
	chainNotifier, err := btcdnotify.New(
		&rpcConfig, netParams, hintCache, hintCache,
	)
	if err != nil {
		t.Fatalf("unable to create notifier: %v", err)
	}
	if err := chainNotifier.Start(); err != nil {
		t.Fatalf("unable to start notifier: %v", err)
	}

	for _, walletDriver := range lnwallet.RegisteredWallets() {
		for _, backEnd := range walletDriver.BackEnds() {
			if !runTests(t, walletDriver, backEnd, miningNode,
				rpcConfig, chainNotifier) {
				return
			}
		}
	}
}

// runTests runs all of the tests for a single interface implementation and
// chain back-end combination. This makes it easier to use `defer` as well as
// factoring out the test logic from the loop which cycles through the
// interface implementations.
func runTests(t *testing.T, walletDriver *lnwallet.WalletDriver,
	backEnd string, miningNode *rpctest.Harness,
	rpcConfig rpcclient.ConnConfig,
	chainNotifier chainntnfs.ChainNotifier) bool {

	var (
		bio lnwallet.BlockChainIO

		aliceSigner input.Signer
		bobSigner   input.Signer

		aliceKeyRing keychain.SecretKeyRing
		bobKeyRing   keychain.SecretKeyRing

		aliceWalletController lnwallet.WalletController
		bobWalletController   lnwallet.WalletController
	)

	tempTestDirAlice, err := ioutil.TempDir("", "lnwallet")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempTestDirAlice)

	tempTestDirBob, err := ioutil.TempDir("", "lnwallet")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempTestDirBob)

	walletType := walletDriver.WalletType
	switch walletType {
	case "btcwallet":
		var aliceClient, bobClient chain.Interface
		switch backEnd {
		case "btcd":
			aliceClient, err = chain.NewRPCClient(netParams,
				rpcConfig.Host, rpcConfig.User, rpcConfig.Pass,
				rpcConfig.Certificates, false, 20)
			if err != nil {
				t.Fatalf("unable to make chain rpc: %v", err)
			}
			bobClient, err = chain.NewRPCClient(netParams,
				rpcConfig.Host, rpcConfig.User, rpcConfig.Pass,
				rpcConfig.Certificates, false, 20)
			if err != nil {
				t.Fatalf("unable to make chain rpc: %v", err)
			}

		case "neutrino":
			// Set some package-level variable to speed up
			// operation for tests.
			neutrino.BanDuration = time.Millisecond * 100
			neutrino.QueryTimeout = time.Millisecond * 500
			neutrino.QueryNumRetries = 1

			// Start Alice - open a database, start a neutrino
			// instance, and initialize a btcwallet driver for it.
			aliceDB, err := walletdb.Create(
				"bdb", tempTestDirAlice+"/neutrino.db",
				&bbolt.Options{
					NoFreelistSync: true,
				},
			)
			if err != nil {
				t.Fatalf("unable to create DB: %v", err)
			}
			defer aliceDB.Close()
			aliceChain, err := neutrino.NewChainService(
				neutrino.Config{
					DataDir:     tempTestDirAlice,
					Database:    aliceDB,
					ChainParams: *netParams,
					ConnectPeers: []string{
						miningNode.P2PAddress(),
					},
				},
			)
			if err != nil {
				t.Fatalf("unable to make neutrino: %v", err)
			}
			aliceChain.Start()
			defer aliceChain.Stop()
			aliceClient = chain.NewNeutrinoClient(
				netParams, aliceChain,
			)

			// Start Bob - open a database, start a neutrino
			// instance, and initialize a btcwallet driver for it.
			bobDB, err := walletdb.Create(
				"bdb", tempTestDirBob+"/neutrino.db",
				&bbolt.Options{
					NoFreelistSync: true,
				},
			)
			if err != nil {
				t.Fatalf("unable to create DB: %v", err)
			}
			defer bobDB.Close()
			bobChain, err := neutrino.NewChainService(
				neutrino.Config{
					DataDir:     tempTestDirBob,
					Database:    bobDB,
					ChainParams: *netParams,
					ConnectPeers: []string{
						miningNode.P2PAddress(),
					},
				},
			)
			if err != nil {
				t.Fatalf("unable to make neutrino: %v", err)
			}
			bobChain.Start()
			defer bobChain.Stop()
			bobClient = chain.NewNeutrinoClient(
				netParams, bobChain,
			)

		case "bitcoind":
			// Start a bitcoind instance.
			tempBitcoindDir, err := ioutil.TempDir("", "bitcoind")
			if err != nil {
				t.Fatalf("unable to create temp directory: %v", err)
			}
			zmqBlockHost := "ipc:///" + tempBitcoindDir + "/blocks.socket"
			zmqTxHost := "ipc:///" + tempBitcoindDir + "/tx.socket"
			defer os.RemoveAll(tempBitcoindDir)
			rpcPort := rand.Int()%(65536-1024) + 1024
			bitcoind := exec.Command(
				"bitcoind",
				"-datadir="+tempBitcoindDir,
				"-regtest",
				"-connect="+miningNode.P2PAddress(),
				"-txindex",
				"-rpcauth=weks:469e9bb14ab2360f8e226efed5ca6f"+
					"d$507c670e800a95284294edb5773b05544b"+
					"220110063096c221be9933c82d38e1",
				fmt.Sprintf("-rpcport=%d", rpcPort),
				"-disablewallet",
				"-zmqpubrawblock="+zmqBlockHost,
				"-zmqpubrawtx="+zmqTxHost,
			)
			err = bitcoind.Start()
			if err != nil {
				t.Fatalf("couldn't start bitcoind: %v", err)
			}
			defer bitcoind.Wait()
			defer bitcoind.Process.Kill()

			// Wait for the bitcoind instance to start up.

			host := fmt.Sprintf("127.0.0.1:%d", rpcPort)
			var chainConn *chain.BitcoindConn
			err = wait.NoError(func() error {
				chainConn, err = chain.NewBitcoindConn(
					netParams, host, "weks", "weks",
					zmqBlockHost, zmqTxHost,
					100*time.Millisecond,
				)
				if err != nil {
					return err
				}

				return chainConn.Start()
			}, 10*time.Second)
			if err != nil {
				t.Fatalf("unable to establish connection to "+
					"bitcoind: %v", err)
			}
			defer chainConn.Stop()

			// Create a btcwallet bitcoind client for both Alice and
			// Bob.
			aliceClient = chainConn.NewBitcoindClient()
			bobClient = chainConn.NewBitcoindClient()
		default:
			t.Fatalf("unknown chain driver: %v", backEnd)
		}

		aliceSeed := sha256.New()
		aliceSeed.Write([]byte(backEnd))
		aliceSeed.Write(aliceHDSeed[:])
		aliceSeedBytes := aliceSeed.Sum(nil)

		aliceWalletConfig := &btcwallet.Config{
			PrivatePass: []byte("alice-pass"),
			HdSeed:      aliceSeedBytes,
			DataDir:     tempTestDirAlice,
			NetParams:   netParams,
			ChainSource: aliceClient,
			CoinType:    keychain.CoinTypeTestnet,
		}
		aliceWalletController, err = walletDriver.New(aliceWalletConfig)
		if err != nil {
			t.Fatalf("unable to create btcwallet: %v", err)
		}
		aliceSigner = aliceWalletController.(*btcwallet.BtcWallet)
		aliceKeyRing = keychain.NewBtcWalletKeyRing(
			aliceWalletController.(*btcwallet.BtcWallet).InternalWallet(),
			keychain.CoinTypeTestnet,
		)

		bobSeed := sha256.New()
		bobSeed.Write([]byte(backEnd))
		bobSeed.Write(bobHDSeed[:])
		bobSeedBytes := bobSeed.Sum(nil)

		bobWalletConfig := &btcwallet.Config{
			PrivatePass: []byte("bob-pass"),
			HdSeed:      bobSeedBytes,
			DataDir:     tempTestDirBob,
			NetParams:   netParams,
			ChainSource: bobClient,
			CoinType:    keychain.CoinTypeTestnet,
		}
		bobWalletController, err = walletDriver.New(bobWalletConfig)
		if err != nil {
			t.Fatalf("unable to create btcwallet: %v", err)
		}
		bobSigner = bobWalletController.(*btcwallet.BtcWallet)
		bobKeyRing = keychain.NewBtcWalletKeyRing(
			bobWalletController.(*btcwallet.BtcWallet).InternalWallet(),
			keychain.CoinTypeTestnet,
		)
		bio = bobWalletController.(*btcwallet.BtcWallet)
	default:
		t.Fatalf("unknown wallet driver: %v", walletType)
	}

	// Funding via 20 outputs with 4BTC each.
	alice, err := createTestWallet(
		tempTestDirAlice, miningNode, netParams,
		chainNotifier, aliceWalletController, aliceKeyRing,
		aliceSigner, bio,
	)
	if err != nil {
		t.Fatalf("unable to create test ln wallet: %v", err)
	}
	defer alice.Shutdown()

	bob, err := createTestWallet(
		tempTestDirBob, miningNode, netParams,
		chainNotifier, bobWalletController, bobKeyRing, bobSigner, bio,
	)
	if err != nil {
		t.Fatalf("unable to create test ln wallet: %v", err)
	}
	defer bob.Shutdown()

	// Both wallets should now have 80BTC available for
	// spending.
	assertProperBalance(t, alice, 1, 80)
	assertProperBalance(t, bob, 1, 80)

	// Execute every test, clearing possibly mutated
	// wallet state after each step.
	for _, walletTest := range walletTests {

		walletTest := walletTest

		testName := fmt.Sprintf("%v/%v:%v", walletType, backEnd,
			walletTest.name)
		success := t.Run(testName, func(t *testing.T) {
			if backEnd == "neutrino" &&
				strings.Contains(walletTest.name, "dual funder") {
				t.Skip("skipping dual funder tests for neutrino")
			}

			walletTest.test(miningNode, alice, bob, t)
		})
		if !success {
			return false
		}

		// TODO(roasbeef): possible reset mining
		// node's chainstate to initial level, cleanly
		// wipe buckets
		if err := clearWalletStates(alice, bob); err !=
			nil && err != kvdb.ErrBucketNotFound {
			t.Fatalf("unable to wipe wallet state: %v", err)
		}
	}

	return true
}
