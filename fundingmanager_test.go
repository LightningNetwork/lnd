// +build !rpctest

package lnd

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/chanacceptor"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channelnotifier"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	// testPollNumTries is the number of times we attempt to query
	// for a certain expected database state before we give up and
	// consider the test failed. Since it sometimes can take a
	// while to update the database, we poll a certain amount of
	// times, until it gets into the state we expect, or we are out
	// of tries.
	testPollNumTries = 10

	// testPollSleepMs is the number of milliseconds to sleep between
	// each attempt to access the database to check its state.
	testPollSleepMs = 500

	// maxPending is the maximum number of channels we allow opening to the
	// same peer in the max pending channels test.
	maxPending = 4

	// A dummy value to use for the funding broadcast height.
	fundingBroadcastHeight = 123
)

var (
	// Use hard-coded keys for Alice and Bob, the two FundingManagers that
	// we will test the interaction between.
	alicePrivKeyBytes = [32]byte{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x88, 0xa3, 0xef, 0xb9,
		0x6a, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	alicePrivKey, alicePubKey = btcec.PrivKeyFromBytes(btcec.S256(),
		alicePrivKeyBytes[:])

	aliceTCPAddr, _ = net.ResolveTCPAddr("tcp", "10.0.0.2:9001")

	aliceAddr = &lnwire.NetAddress{
		IdentityKey: alicePubKey,
		Address:     aliceTCPAddr,
	}

	bobPrivKeyBytes = [32]byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}

	bobPrivKey, bobPubKey = btcec.PrivKeyFromBytes(btcec.S256(),
		bobPrivKeyBytes[:])

	bobTCPAddr, _ = net.ResolveTCPAddr("tcp", "10.0.0.2:9000")

	bobAddr = &lnwire.NetAddress{
		IdentityKey: bobPubKey,
		Address:     bobTCPAddr,
	}

	testSig = &btcec.Signature{
		R: new(big.Int),
		S: new(big.Int),
	}
	_, _ = testSig.R.SetString("63724406601629180062774974542967536251589935445068131219452686511677818569431", 10)
	_, _ = testSig.S.SetString("18801056069249825825291287104931333862866033135609736119018462340006816851118", 10)

	fundingNetParams = chainreg.BitcoinTestNetParams
)

type mockNotifier struct {
	oneConfChannel chan *chainntnfs.TxConfirmation
	sixConfChannel chan *chainntnfs.TxConfirmation
	epochChan      chan *chainntnfs.BlockEpoch
}

func (m *mockNotifier) RegisterConfirmationsNtfn(txid *chainhash.Hash,
	_ []byte, numConfs, heightHint uint32) (*chainntnfs.ConfirmationEvent, error) {

	if numConfs == 6 {
		return &chainntnfs.ConfirmationEvent{
			Confirmed: m.sixConfChannel,
		}, nil
	}
	return &chainntnfs.ConfirmationEvent{
		Confirmed: m.oneConfChannel,
	}, nil
}

func (m *mockNotifier) RegisterBlockEpochNtfn(
	bestBlock *chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {
	return &chainntnfs.BlockEpochEvent{
		Epochs: m.epochChan,
		Cancel: func() {},
	}, nil
}

func (m *mockNotifier) Start() error {
	return nil
}

func (m *mockNotifier) Started() bool {
	return true
}

func (m *mockNotifier) Stop() error {
	return nil
}

func (m *mockNotifier) RegisterSpendNtfn(outpoint *wire.OutPoint, _ []byte,
	heightHint uint32) (*chainntnfs.SpendEvent, error) {
	return &chainntnfs.SpendEvent{
		Spend:  make(chan *chainntnfs.SpendDetail),
		Cancel: func() {},
	}, nil
}

type mockChanEvent struct {
	openEvent        chan wire.OutPoint
	pendingOpenEvent chan channelnotifier.PendingOpenChannelEvent
}

func (m *mockChanEvent) NotifyOpenChannelEvent(outpoint wire.OutPoint) {
	m.openEvent <- outpoint
}

func (m *mockChanEvent) NotifyPendingOpenChannelEvent(outpoint wire.OutPoint,
	pendingChannel *channeldb.OpenChannel) {

	m.pendingOpenEvent <- channelnotifier.PendingOpenChannelEvent{
		ChannelPoint:   &outpoint,
		PendingChannel: pendingChannel,
	}
}

type newChannelMsg struct {
	channel *channeldb.OpenChannel
	err     chan error
}

type testNode struct {
	privKey         *btcec.PrivateKey
	addr            *lnwire.NetAddress
	msgChan         chan lnwire.Message
	announceChan    chan lnwire.Message
	publTxChan      chan *wire.MsgTx
	fundingMgr      *fundingManager
	newChannels     chan *newChannelMsg
	mockNotifier    *mockNotifier
	mockChanEvent   *mockChanEvent
	testDir         string
	shutdownChannel chan struct{}
	remoteFeatures  []lnwire.FeatureBit

	remotePeer  *testNode
	sendMessage func(lnwire.Message) error
}

var _ lnpeer.Peer = (*testNode)(nil)

func (n *testNode) IdentityKey() *btcec.PublicKey {
	return n.addr.IdentityKey
}

func (n *testNode) Address() net.Addr {
	return n.addr.Address
}

func (n *testNode) PubKey() [33]byte {
	return newSerializedKey(n.addr.IdentityKey)
}

func (n *testNode) SendMessage(_ bool, msg ...lnwire.Message) error {
	return n.sendMessage(msg[0])
}

func (n *testNode) SendMessageLazy(sync bool, msgs ...lnwire.Message) error {
	return n.SendMessage(sync, msgs...)
}

func (n *testNode) WipeChannel(_ *wire.OutPoint) {}

func (n *testNode) QuitSignal() <-chan struct{} {
	return n.shutdownChannel
}

func (n *testNode) LocalFeatures() *lnwire.FeatureVector {
	return lnwire.NewFeatureVector(nil, nil)
}

func (n *testNode) RemoteFeatures() *lnwire.FeatureVector {
	return lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(n.remoteFeatures...), nil,
	)
}

func (n *testNode) AddNewChannel(channel *channeldb.OpenChannel,
	quit <-chan struct{}) error {

	errChan := make(chan error)
	msg := &newChannelMsg{
		channel: channel,
		err:     errChan,
	}

	select {
	case n.newChannels <- msg:
	case <-quit:
		return ErrFundingManagerShuttingDown
	}

	select {
	case err := <-errChan:
		return err
	case <-quit:
		return ErrFundingManagerShuttingDown
	}
}

func createTestWallet(cdb *channeldb.DB, netParams *chaincfg.Params,
	notifier chainntnfs.ChainNotifier, wc lnwallet.WalletController,
	signer input.Signer, keyRing keychain.SecretKeyRing,
	bio lnwallet.BlockChainIO,
	estimator chainfee.Estimator) (*lnwallet.LightningWallet, error) {

	wallet, err := lnwallet.NewLightningWallet(lnwallet.Config{
		Database:           cdb,
		Notifier:           notifier,
		SecretKeyRing:      keyRing,
		WalletController:   wc,
		Signer:             signer,
		ChainIO:            bio,
		FeeEstimator:       estimator,
		NetParams:          *netParams,
		DefaultConstraints: chainreg.DefaultBtcChannelConstraints,
	})
	if err != nil {
		return nil, err
	}

	if err := wallet.Startup(); err != nil {
		return nil, err
	}

	return wallet, nil
}

func createTestFundingManager(t *testing.T, privKey *btcec.PrivateKey,
	addr *lnwire.NetAddress, tempTestDir string,
	options ...cfgOption) (*testNode, error) {

	netParams := fundingNetParams.Params
	estimator := chainfee.NewStaticEstimator(62500, 0)

	chainNotifier := &mockNotifier{
		oneConfChannel: make(chan *chainntnfs.TxConfirmation, 1),
		sixConfChannel: make(chan *chainntnfs.TxConfirmation, 1),
		epochChan:      make(chan *chainntnfs.BlockEpoch, 2),
	}

	sentMessages := make(chan lnwire.Message)
	sentAnnouncements := make(chan lnwire.Message)
	publTxChan := make(chan *wire.MsgTx, 1)
	shutdownChan := make(chan struct{})

	wc := &mock.WalletController{
		RootKey: alicePrivKey,
	}
	signer := &mock.SingleSigner{
		Privkey: alicePrivKey,
	}
	bio := &mock.ChainIO{
		BestHeight: fundingBroadcastHeight,
	}

	// The mock channel event notifier will receive events for each pending
	// open and open channel. Because some tests will create multiple
	// channels in a row before advancing to the next step, these channels
	// need to be buffered.
	evt := &mockChanEvent{
		openEvent: make(chan wire.OutPoint, maxPending),
		pendingOpenEvent: make(
			chan channelnotifier.PendingOpenChannelEvent, maxPending,
		),
	}

	dbDir := filepath.Join(tempTestDir, "cdb")
	cdb, err := channeldb.Open(dbDir)
	if err != nil {
		return nil, err
	}

	keyRing := &mock.SecretKeyRing{
		RootKey: alicePrivKey,
	}

	lnw, err := createTestWallet(
		cdb, netParams, chainNotifier, wc, signer, keyRing, bio,
		estimator,
	)
	if err != nil {
		t.Fatalf("unable to create test ln wallet: %v", err)
	}

	var chanIDSeed [32]byte

	chainedAcceptor := chanacceptor.NewChainedAcceptor()

	fundingCfg := fundingConfig{
		IDKey:        privKey.PubKey(),
		Wallet:       lnw,
		Notifier:     chainNotifier,
		FeeEstimator: estimator,
		SignMessage: func(pubKey *btcec.PublicKey,
			msg []byte) (input.Signature, error) {

			return testSig, nil
		},
		SendAnnouncement: func(msg lnwire.Message,
			_ ...discovery.OptionalMsgField) chan error {

			errChan := make(chan error, 1)
			select {
			case sentAnnouncements <- msg:
				errChan <- nil
			case <-shutdownChan:
				errChan <- fmt.Errorf("shutting down")
			}
			return errChan
		},
		CurrentNodeAnnouncement: func() (lnwire.NodeAnnouncement, error) {
			return lnwire.NodeAnnouncement{}, nil
		},
		TempChanIDSeed: chanIDSeed,
		FindChannel: func(chanID lnwire.ChannelID) (
			*channeldb.OpenChannel, error) {
			dbChannels, err := cdb.FetchAllChannels()
			if err != nil {
				return nil, err
			}

			for _, channel := range dbChannels {
				if chanID.IsChanPoint(&channel.FundingOutpoint) {
					return channel, nil
				}
			}

			return nil, fmt.Errorf("unable to find channel")
		},
		DefaultRoutingPolicy: htlcswitch.ForwardingPolicy{
			MinHTLCOut:    5,
			BaseFee:       100,
			FeeRate:       1000,
			TimeLockDelta: 10,
		},
		DefaultMinHtlcIn: 5,
		NumRequiredConfs: func(chanAmt btcutil.Amount,
			pushAmt lnwire.MilliSatoshi, allowZeroConfs bool) uint16 {
			return 3
		},
		RequiredRemoteDelay: func(amt btcutil.Amount) uint16 {
			return 4
		},
		RequiredRemoteChanReserve: func(chanAmt,
			dustLimit btcutil.Amount) btcutil.Amount {

			reserve := chanAmt / 100
			if reserve < dustLimit {
				reserve = dustLimit
			}

			return reserve
		},
		RequiredRemoteMaxValue: func(chanAmt btcutil.Amount) lnwire.MilliSatoshi {
			reserve := lnwire.NewMSatFromSatoshis(chanAmt / 100)
			return lnwire.NewMSatFromSatoshis(chanAmt) - reserve
		},
		RequiredRemoteMaxHTLCs: func(chanAmt btcutil.Amount) uint16 {
			return uint16(input.MaxHTLCNumber / 2)
		},
		WatchNewChannel: func(*channeldb.OpenChannel, *btcec.PublicKey) error {
			return nil
		},
		ReportShortChanID: func(wire.OutPoint) error {
			return nil
		},
		PublishTransaction: func(txn *wire.MsgTx, _ string) error {
			publTxChan <- txn
			return nil
		},
		UpdateLabel: func(chainhash.Hash, string) error {
			return nil
		},
		ZombieSweeperInterval:         1 * time.Hour,
		ReservationTimeout:            1 * time.Nanosecond,
		MaxChanSize:                   MaxFundingAmount,
		MaxPendingChannels:            lncfg.DefaultMaxPendingChannels,
		NotifyOpenChannelEvent:        evt.NotifyOpenChannelEvent,
		OpenChannelPredicate:          chainedAcceptor,
		NotifyPendingOpenChannelEvent: evt.NotifyPendingOpenChannelEvent,
		RegisteredChains:              chainreg.NewChainRegistry(),
	}

	for _, op := range options {
		op(&fundingCfg)
	}

	f, err := newFundingManager(fundingCfg)
	if err != nil {
		t.Fatalf("failed creating fundingManager: %v", err)
	}
	if err = f.Start(); err != nil {
		t.Fatalf("failed starting fundingManager: %v", err)
	}

	testNode := &testNode{
		privKey:         privKey,
		msgChan:         sentMessages,
		newChannels:     make(chan *newChannelMsg),
		announceChan:    sentAnnouncements,
		publTxChan:      publTxChan,
		fundingMgr:      f,
		mockNotifier:    chainNotifier,
		mockChanEvent:   evt,
		testDir:         tempTestDir,
		shutdownChannel: shutdownChan,
		addr:            addr,
	}

	f.cfg.NotifyWhenOnline = func(peer [33]byte,
		connectedChan chan<- lnpeer.Peer) {

		connectedChan <- testNode.remotePeer
	}

	return testNode, nil
}

func recreateAliceFundingManager(t *testing.T, alice *testNode) {
	// Stop the old fundingManager before creating a new one.
	close(alice.shutdownChannel)
	if err := alice.fundingMgr.Stop(); err != nil {
		t.Fatalf("unable to stop old fundingManager: %v", err)
	}

	aliceMsgChan := make(chan lnwire.Message)
	aliceAnnounceChan := make(chan lnwire.Message)
	shutdownChan := make(chan struct{})
	publishChan := make(chan *wire.MsgTx, 10)

	oldCfg := alice.fundingMgr.cfg

	chainedAcceptor := chanacceptor.NewChainedAcceptor()

	f, err := newFundingManager(fundingConfig{
		IDKey:        oldCfg.IDKey,
		Wallet:       oldCfg.Wallet,
		Notifier:     oldCfg.Notifier,
		FeeEstimator: oldCfg.FeeEstimator,
		SignMessage: func(pubKey *btcec.PublicKey,
			msg []byte) (input.Signature, error) {
			return testSig, nil
		},
		SendAnnouncement: func(msg lnwire.Message,
			_ ...discovery.OptionalMsgField) chan error {

			errChan := make(chan error, 1)
			select {
			case aliceAnnounceChan <- msg:
				errChan <- nil
			case <-shutdownChan:
				errChan <- fmt.Errorf("shutting down")
			}
			return errChan
		},
		CurrentNodeAnnouncement: func() (lnwire.NodeAnnouncement, error) {
			return lnwire.NodeAnnouncement{}, nil
		},
		NotifyWhenOnline: func(peer [33]byte,
			connectedChan chan<- lnpeer.Peer) {

			connectedChan <- alice.remotePeer
		},
		TempChanIDSeed: oldCfg.TempChanIDSeed,
		FindChannel:    oldCfg.FindChannel,
		DefaultRoutingPolicy: htlcswitch.ForwardingPolicy{
			MinHTLCOut:    5,
			BaseFee:       100,
			FeeRate:       1000,
			TimeLockDelta: 10,
		},
		DefaultMinHtlcIn:       5,
		RequiredRemoteMaxValue: oldCfg.RequiredRemoteMaxValue,
		PublishTransaction: func(txn *wire.MsgTx, _ string) error {
			publishChan <- txn
			return nil
		},
		UpdateLabel: func(chainhash.Hash, string) error {
			return nil
		},
		ZombieSweeperInterval: oldCfg.ZombieSweeperInterval,
		ReservationTimeout:    oldCfg.ReservationTimeout,
		OpenChannelPredicate:  chainedAcceptor,
	})
	if err != nil {
		t.Fatalf("failed recreating aliceFundingManager: %v", err)
	}

	alice.fundingMgr = f
	alice.msgChan = aliceMsgChan
	alice.announceChan = aliceAnnounceChan
	alice.publTxChan = publishChan
	alice.shutdownChannel = shutdownChan

	if err = f.Start(); err != nil {
		t.Fatalf("failed starting fundingManager: %v", err)
	}
}

type cfgOption func(*fundingConfig)

func setupFundingManagers(t *testing.T,
	options ...cfgOption) (*testNode, *testNode) {

	aliceTestDir, err := ioutil.TempDir("", "alicelnwallet")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}

	alice, err := createTestFundingManager(
		t, alicePrivKey, aliceAddr, aliceTestDir, options...,
	)
	if err != nil {
		t.Fatalf("failed creating fundingManager: %v", err)
	}

	bobTestDir, err := ioutil.TempDir("", "boblnwallet")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}

	bob, err := createTestFundingManager(
		t, bobPrivKey, bobAddr, bobTestDir, options...,
	)
	if err != nil {
		t.Fatalf("failed creating fundingManager: %v", err)
	}

	// With the funding manager's created, we'll now attempt to mimic a
	// connection pipe between them. In order to intercept the messages
	// within it, we'll redirect all messages back to the msgChan of the
	// sender. Since the fundingManager now has a reference to peers itself,
	// alice.sendMessage will be triggered when Bob's funding manager
	// attempts to send a message to Alice and vice versa.
	alice.remotePeer = bob
	alice.sendMessage = func(msg lnwire.Message) error {
		select {
		case alice.remotePeer.msgChan <- msg:
		case <-alice.shutdownChannel:
			return errors.New("shutting down")
		}
		return nil
	}

	bob.remotePeer = alice
	bob.sendMessage = func(msg lnwire.Message) error {
		select {
		case bob.remotePeer.msgChan <- msg:
		case <-bob.shutdownChannel:
			return errors.New("shutting down")
		}
		return nil
	}

	return alice, bob
}

func tearDownFundingManagers(t *testing.T, a, b *testNode) {
	close(a.shutdownChannel)
	close(b.shutdownChannel)

	if err := a.fundingMgr.Stop(); err != nil {
		t.Fatalf("unable to stop fundingManager: %v", err)
	}
	if err := b.fundingMgr.Stop(); err != nil {
		t.Fatalf("unable to stop fundingManager: %v", err)
	}
	os.RemoveAll(a.testDir)
	os.RemoveAll(b.testDir)
}

// openChannel takes the funding process to the point where the funding
// transaction is confirmed on-chain. Returns the funding out point.
func openChannel(t *testing.T, alice, bob *testNode, localFundingAmt,
	pushAmt btcutil.Amount, numConfs uint32,
	updateChan chan *lnrpc.OpenStatusUpdate, announceChan bool) (
	*wire.OutPoint, *wire.MsgTx) {

	publ := fundChannel(
		t, alice, bob, localFundingAmt, pushAmt, false, numConfs,
		updateChan, announceChan,
	)
	fundingOutPoint := &wire.OutPoint{
		Hash:  publ.TxHash(),
		Index: 0,
	}
	return fundingOutPoint, publ
}

// fundChannel takes the funding process to the point where the funding
// transaction is confirmed on-chain. Returns the funding tx.
func fundChannel(t *testing.T, alice, bob *testNode, localFundingAmt,
	pushAmt btcutil.Amount, subtractFees bool, numConfs uint32,
	updateChan chan *lnrpc.OpenStatusUpdate, announceChan bool) *wire.MsgTx {

	// Create a funding request and start the workflow.
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		subtractFees:    subtractFees,
		localFundingAmt: localFundingAmt,
		pushAmt:         lnwire.NewMSatFromSatoshis(pushAmt),
		fundingFeePerKw: 1000,
		private:         !announceChan,
		updates:         updateChan,
		err:             errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Let Bob handle the init message.
	bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

	// Bob should answer with an AcceptChannel message.
	acceptChannelResponse := assertFundingMsgSent(
		t, bob.msgChan, "AcceptChannel",
	).(*lnwire.AcceptChannel)

	// They now should both have pending reservations for this channel
	// active.
	assertNumPendingReservations(t, alice, bobPubKey, 1)
	assertNumPendingReservations(t, bob, alicePubKey, 1)

	// Forward the response to Alice.
	alice.fundingMgr.ProcessFundingMsg(acceptChannelResponse, bob)

	// Alice responds with a FundingCreated message.
	fundingCreated := assertFundingMsgSent(
		t, alice.msgChan, "FundingCreated",
	).(*lnwire.FundingCreated)

	// Give the message to Bob.
	bob.fundingMgr.ProcessFundingMsg(fundingCreated, alice)

	// Finally, Bob should send the FundingSigned message.
	fundingSigned := assertFundingMsgSent(
		t, bob.msgChan, "FundingSigned",
	).(*lnwire.FundingSigned)

	// Forward the signature to Alice.
	alice.fundingMgr.ProcessFundingMsg(fundingSigned, bob)

	// After Alice processes the singleFundingSignComplete message, she will
	// broadcast the funding transaction to the network. We expect to get a
	// channel update saying the channel is pending.
	var pendingUpdate *lnrpc.OpenStatusUpdate
	select {
	case pendingUpdate = <-updateChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenStatusUpdate_ChanPending")
	}

	_, ok = pendingUpdate.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	if !ok {
		t.Fatal("OpenStatusUpdate was not OpenStatusUpdate_ChanPending")
	}

	// Get and return the transaction Alice published to the network.
	var publ *wire.MsgTx
	select {
	case publ = <-alice.publTxChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not publish funding tx")
	}

	// Make sure the notification about the pending channel was sent out.
	select {
	case <-alice.mockChanEvent.pendingOpenEvent:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send pending channel event")
	}
	select {
	case <-bob.mockChanEvent.pendingOpenEvent:
	case <-time.After(time.Second * 5):
		t.Fatalf("bob did not send pending channel event")
	}

	// Finally, make sure neither have active reservation for the channel
	// now pending open in the database.
	assertNumPendingReservations(t, alice, bobPubKey, 0)
	assertNumPendingReservations(t, bob, alicePubKey, 0)

	return publ
}

func assertErrorNotSent(t *testing.T, msgChan chan lnwire.Message) {
	t.Helper()

	select {
	case <-msgChan:
		t.Fatalf("error sent unexpectedly")
	case <-time.After(100 * time.Millisecond):
		// Expected, return.
	}
}

func assertErrorSent(t *testing.T, msgChan chan lnwire.Message) {
	t.Helper()

	var msg lnwire.Message
	select {
	case msg = <-msgChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("node did not send Error message")
	}
	_, ok := msg.(*lnwire.Error)
	if !ok {
		t.Fatalf("expected Error to be sent from "+
			"node, instead got %T", msg)
	}
}

func assertFundingMsgSent(t *testing.T, msgChan chan lnwire.Message,
	msgType string) lnwire.Message {
	t.Helper()

	var msg lnwire.Message
	select {
	case msg = <-msgChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("peer did not send %s message", msgType)
	}

	var (
		sentMsg lnwire.Message
		ok      bool
	)
	switch msgType {
	case "AcceptChannel":
		sentMsg, ok = msg.(*lnwire.AcceptChannel)
	case "FundingCreated":
		sentMsg, ok = msg.(*lnwire.FundingCreated)
	case "FundingSigned":
		sentMsg, ok = msg.(*lnwire.FundingSigned)
	case "FundingLocked":
		sentMsg, ok = msg.(*lnwire.FundingLocked)
	case "Error":
		sentMsg, ok = msg.(*lnwire.Error)
	default:
		t.Fatalf("unknown message type: %s", msgType)
	}

	if !ok {
		errorMsg, gotError := msg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected %s to be sent, instead got error: %v",
				msgType, errorMsg.Error())
		}

		_, _, line, _ := runtime.Caller(1)
		t.Fatalf("expected %s to be sent, instead got %T at %v",
			msgType, msg, line)
	}

	return sentMsg
}

func assertNumPendingReservations(t *testing.T, node *testNode,
	peerPubKey *btcec.PublicKey, expectedNum int) {
	t.Helper()

	serializedPubKey := newSerializedKey(peerPubKey)
	actualNum := len(node.fundingMgr.activeReservations[serializedPubKey])
	if actualNum == expectedNum {
		// Success, return.
		return
	}

	t.Fatalf("Expected node to have %d pending reservations, had %v",
		expectedNum, actualNum)
}

func assertNumPendingChannelsBecomes(t *testing.T, node *testNode, expectedNum int) {
	t.Helper()

	var numPendingChans int
	for i := 0; i < testPollNumTries; i++ {
		// If this is not the first try, sleep before retrying.
		if i > 0 {
			time.Sleep(testPollSleepMs * time.Millisecond)
		}
		pendingChannels, err := node.fundingMgr.
			cfg.Wallet.Cfg.Database.FetchPendingChannels()
		if err != nil {
			t.Fatalf("unable to fetch pending channels: %v", err)
		}

		numPendingChans = len(pendingChannels)
		if numPendingChans == expectedNum {
			// Success, return.
			return
		}
	}

	t.Fatalf("Expected node to have %d pending channels, had %v",
		expectedNum, numPendingChans)
}

func assertNumPendingChannelsRemains(t *testing.T, node *testNode, expectedNum int) {
	t.Helper()

	var numPendingChans int
	for i := 0; i < 5; i++ {
		// If this is not the first try, sleep before retrying.
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		pendingChannels, err := node.fundingMgr.
			cfg.Wallet.Cfg.Database.FetchPendingChannels()
		if err != nil {
			t.Fatalf("unable to fetch pending channels: %v", err)
		}

		numPendingChans = len(pendingChannels)
		if numPendingChans != expectedNum {

			t.Fatalf("Expected node to have %d pending channels, had %v",
				expectedNum, numPendingChans)
		}
	}
}

func assertDatabaseState(t *testing.T, node *testNode,
	fundingOutPoint *wire.OutPoint, expectedState channelOpeningState) {
	t.Helper()

	var state channelOpeningState
	var err error
	for i := 0; i < testPollNumTries; i++ {
		// If this is not the first try, sleep before retrying.
		if i > 0 {
			time.Sleep(testPollSleepMs * time.Millisecond)
		}
		state, _, err = node.fundingMgr.getChannelOpeningState(
			fundingOutPoint)
		if err != nil && err != ErrChannelNotFound {
			t.Fatalf("unable to get channel state: %v", err)
		}

		// If we found the channel, check if it had the expected state.
		if err != ErrChannelNotFound && state == expectedState {
			// Got expected state, return with success.
			return
		}
	}

	// 10 tries without success.
	if err != nil {
		t.Fatalf("error getting channelOpeningState: %v", err)
	} else {
		t.Fatalf("expected state to be %v, was %v", expectedState,
			state)
	}
}

func assertMarkedOpen(t *testing.T, alice, bob *testNode,
	fundingOutPoint *wire.OutPoint) {
	t.Helper()

	// Make sure the notification about the pending channel was sent out.
	select {
	case <-alice.mockChanEvent.openEvent:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send open channel event")
	}
	select {
	case <-bob.mockChanEvent.openEvent:
	case <-time.After(time.Second * 5):
		t.Fatalf("bob did not send open channel event")
	}

	assertDatabaseState(t, alice, fundingOutPoint, markedOpen)
	assertDatabaseState(t, bob, fundingOutPoint, markedOpen)
}

func assertFundingLockedSent(t *testing.T, alice, bob *testNode,
	fundingOutPoint *wire.OutPoint) {
	t.Helper()

	assertDatabaseState(t, alice, fundingOutPoint, fundingLockedSent)
	assertDatabaseState(t, bob, fundingOutPoint, fundingLockedSent)
}

func assertAddedToRouterGraph(t *testing.T, alice, bob *testNode,
	fundingOutPoint *wire.OutPoint) {
	t.Helper()

	assertDatabaseState(t, alice, fundingOutPoint, addedToRouterGraph)
	assertDatabaseState(t, bob, fundingOutPoint, addedToRouterGraph)
}

// assertChannelAnnouncements checks that alice and bob both sends the expected
// announcements (ChannelAnnouncement, ChannelUpdate) after the funding tx has
// confirmed. The last arguments can be set if we expect the nodes to advertise
// custom min_htlc values as part of their ChannelUpdate. We expect Alice to
// advertise the value required by Bob and vice versa. If they are not set the
// advertised value will be checked against the other node's default min_htlc
// value.
func assertChannelAnnouncements(t *testing.T, alice, bob *testNode,
	capacity btcutil.Amount, customMinHtlc []lnwire.MilliSatoshi,
	customMaxHtlc []lnwire.MilliSatoshi) {
	t.Helper()

	// After the FundingLocked message is sent, Alice and Bob will each
	// send the following messages to their gossiper:
	//	1) ChannelAnnouncement
	//	2) ChannelUpdate
	// The ChannelAnnouncement is kept locally, while the ChannelUpdate
	// is sent directly to the other peer, so the edge policies are
	// known to both peers.
	nodes := []*testNode{alice, bob}
	for j, node := range nodes {
		announcements := make([]lnwire.Message, 2)
		for i := 0; i < len(announcements); i++ {
			select {
			case announcements[i] = <-node.announceChan:
			case <-time.After(time.Second * 5):
				t.Fatalf("node did not send announcement: %v", i)
			}
		}

		gotChannelAnnouncement := false
		gotChannelUpdate := false
		for _, msg := range announcements {
			switch m := msg.(type) {
			case *lnwire.ChannelAnnouncement:
				gotChannelAnnouncement = true
			case *lnwire.ChannelUpdate:

				// The channel update sent by the node should
				// advertise the MinHTLC value required by the
				// _other_ node.
				other := (j + 1) % 2
				minHtlc := nodes[other].fundingMgr.cfg.
					DefaultMinHtlcIn

				// We might expect a custom MinHTLC value.
				if len(customMinHtlc) > 0 {
					if len(customMinHtlc) != 2 {
						t.Fatalf("only 0 or 2 custom " +
							"min htlc values " +
							"currently supported")
					}

					minHtlc = customMinHtlc[j]
				}

				if m.HtlcMinimumMsat != minHtlc {
					t.Fatalf("expected ChannelUpdate to "+
						"advertise min HTLC %v, had %v",
						minHtlc, m.HtlcMinimumMsat)
				}

				maxHtlc := alice.fundingMgr.cfg.RequiredRemoteMaxValue(
					capacity,
				)
				// We might expect a custom MaxHltc value.
				if len(customMaxHtlc) > 0 {
					if len(customMaxHtlc) != 2 {
						t.Fatalf("only 0 or 2 custom " +
							"min htlc values " +
							"currently supported")
					}

					maxHtlc = customMaxHtlc[j]
				}
				if m.MessageFlags != 1 {
					t.Fatalf("expected message flags to "+
						"be 1, was %v", m.MessageFlags)
				}

				if maxHtlc != m.HtlcMaximumMsat {
					t.Fatalf("expected ChannelUpdate to "+
						"advertise max HTLC %v, had %v",
						maxHtlc,
						m.HtlcMaximumMsat)
				}

				gotChannelUpdate = true
			}
		}

		if !gotChannelAnnouncement {
			t.Fatalf("did not get ChannelAnnouncement from node %d",
				j)
		}
		if !gotChannelUpdate {
			t.Fatalf("did not get ChannelUpdate from node %d", j)
		}

		// Make sure no other message is sent.
		select {
		case <-node.announceChan:
			t.Fatalf("received unexpected announcement")
		case <-time.After(300 * time.Millisecond):
			// Expected
		}
	}
}

func assertAnnouncementSignatures(t *testing.T, alice, bob *testNode) {
	t.Helper()

	// After the FundingLocked message is sent and six confirmations have
	// been reached, the channel will be announced to the greater network
	// by having the nodes exchange announcement signatures.
	// Two distinct messages will be sent:
	//	1) AnnouncementSignatures
	//	2) NodeAnnouncement
	// These may arrive in no particular order.
	// Note that sending the NodeAnnouncement at this point is an
	// implementation detail, and not something required by the LN spec.
	for j, node := range []*testNode{alice, bob} {
		announcements := make([]lnwire.Message, 2)
		for i := 0; i < len(announcements); i++ {
			select {
			case announcements[i] = <-node.announceChan:
			case <-time.After(time.Second * 5):
				t.Fatalf("node did not send announcement %v", i)
			}
		}

		gotAnnounceSignatures := false
		gotNodeAnnouncement := false
		for _, msg := range announcements {
			switch msg.(type) {
			case *lnwire.AnnounceSignatures:
				gotAnnounceSignatures = true
			case *lnwire.NodeAnnouncement:
				gotNodeAnnouncement = true
			}
		}

		if !gotAnnounceSignatures {
			t.Fatalf("did not get AnnounceSignatures from node %d",
				j)
		}
		if !gotNodeAnnouncement {
			t.Fatalf("did not get NodeAnnouncement from node %d", j)
		}
	}
}

func waitForOpenUpdate(t *testing.T, updateChan chan *lnrpc.OpenStatusUpdate) {
	var openUpdate *lnrpc.OpenStatusUpdate
	select {
	case openUpdate = <-updateChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenStatusUpdate")
	}

	_, ok := openUpdate.Update.(*lnrpc.OpenStatusUpdate_ChanOpen)
	if !ok {
		t.Fatal("OpenStatusUpdate was not OpenStatusUpdate_ChanOpen")
	}
}

func assertNoChannelState(t *testing.T, alice, bob *testNode,
	fundingOutPoint *wire.OutPoint) {
	t.Helper()

	assertErrChannelNotFound(t, alice, fundingOutPoint)
	assertErrChannelNotFound(t, bob, fundingOutPoint)
}

func assertErrChannelNotFound(t *testing.T, node *testNode,
	fundingOutPoint *wire.OutPoint) {
	t.Helper()

	var state channelOpeningState
	var err error
	for i := 0; i < testPollNumTries; i++ {
		// If this is not the first try, sleep before retrying.
		if i > 0 {
			time.Sleep(testPollSleepMs * time.Millisecond)
		}
		state, _, err = node.fundingMgr.getChannelOpeningState(
			fundingOutPoint)
		if err == ErrChannelNotFound {
			// Got expected state, return with success.
			return
		} else if err != nil {
			t.Fatalf("unable to get channel state: %v", err)
		}
	}

	// 10 tries without success.
	t.Fatalf("expected to not find state, found state %v", state)
}

func assertHandleFundingLocked(t *testing.T, alice, bob *testNode) {
	t.Helper()

	// They should both send the new channel state to their peer.
	select {
	case c := <-alice.newChannels:
		close(c.err)
	case <-time.After(time.Second * 15):
		t.Fatalf("alice did not send new channel to peer")
	}

	select {
	case c := <-bob.newChannels:
		close(c.err)
	case <-time.After(time.Second * 15):
		t.Fatalf("bob did not send new channel to peer")
	}
}

func TestFundingManagerNormalWorkflow(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, true,
	)

	// Check that neither Alice nor Bob sent an error message.
	assertErrorNotSent(t, alice.msgChan)
	assertErrorNotSent(t, bob.msgChan)

	// Notify that transaction was mined.
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Check that the state machine is updated accordingly
	assertFundingLockedSent(t, alice, bob, fundingOutPoint)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Check that the state machine is updated accordingly
	assertAddedToRouterGraph(t, alice, bob, fundingOutPoint)

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)

	// Exchange the fundingLocked messages.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Make sure the fundingManagers exchange announcement signatures.
	assertAnnouncementSignatures(t, alice, bob)

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

func TestFundingManagerRestartBehavior(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	updateChan := make(chan *lnrpc.OpenStatusUpdate)
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, true,
	)

	// After the funding transaction gets mined, both nodes will send the
	// fundingLocked message to the other peer. If the funding node fails
	// before this message has been successfully sent, it should retry
	// sending it on restart. We mimic this behavior by letting the
	// SendToPeer method return an error, as if the message was not
	// successfully sent. We then recreate the fundingManager and make sure
	// it continues the process as expected. We'll save the current
	// implementation of sendMessage to restore the original behavior later
	// on.
	workingSendMessage := bob.sendMessage
	bob.sendMessage = func(msg lnwire.Message) error {
		return fmt.Errorf("intentional error in SendToPeer")
	}
	alice.fundingMgr.cfg.NotifyWhenOnline = func(peer [33]byte,
		con chan<- lnpeer.Peer) {
		// Intentionally empty.
	}

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction was mined, Bob should have successfully
	// sent the fundingLocked message, while Alice failed sending it. In
	// Alice's case this means that there should be no messages for Bob, and
	// the channel should still be in state 'markedOpen'
	select {
	case msg := <-alice.msgChan:
		t.Fatalf("did not expect any message from Alice: %v", msg)
	default:
		// Expected.
	}

	// Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Alice should still be markedOpen
	assertDatabaseState(t, alice, fundingOutPoint, markedOpen)

	// While Bob successfully sent fundingLocked.
	assertDatabaseState(t, bob, fundingOutPoint, fundingLockedSent)

	// We now recreate Alice's fundingManager with the correct sendMessage
	// implementation, and expect it to retry sending the fundingLocked
	// message. We'll explicitly shut down Alice's funding manager to
	// prevent a race when overriding the sendMessage implementation.
	if err := alice.fundingMgr.Stop(); err != nil {
		t.Fatalf("unable to stop alice's funding manager: %v", err)
	}
	bob.sendMessage = workingSendMessage
	recreateAliceFundingManager(t, alice)

	// Intentionally make the channel announcements fail
	alice.fundingMgr.cfg.SendAnnouncement = func(msg lnwire.Message,
		_ ...discovery.OptionalMsgField) chan error {

		errChan := make(chan error, 1)
		errChan <- fmt.Errorf("intentional error in SendAnnouncement")
		return errChan
	}

	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// The state should now be fundingLockedSent
	assertDatabaseState(t, alice, fundingOutPoint, fundingLockedSent)

	// Check that the channel announcements were never sent
	select {
	case ann := <-alice.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v",
			ann)
	default:
		// Expected
	}

	// Exchange the fundingLocked messages.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Next up, we check that Alice rebroadcasts the announcement
	// messages on restart. Bob should as expected send announcements.
	recreateAliceFundingManager(t, alice)
	time.Sleep(300 * time.Millisecond)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Check that the state machine is updated accordingly
	assertAddedToRouterGraph(t, alice, bob, fundingOutPoint)

	// Next, we check that Alice sends the announcement signatures
	// on restart after six confirmations. Bob should as expected send
	// them as well.
	recreateAliceFundingManager(t, alice)
	time.Sleep(300 * time.Millisecond)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Make sure the fundingManagers exchange announcement signatures.
	assertAnnouncementSignatures(t, alice, bob)

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerOfflinePeer checks that the fundingManager waits for the
// server to notify when the peer comes online, in case sending the
// fundingLocked message fails the first time.
func TestFundingManagerOfflinePeer(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	updateChan := make(chan *lnrpc.OpenStatusUpdate)
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, true,
	)

	// After the funding transaction gets mined, both nodes will send the
	// fundingLocked message to the other peer. If the funding node fails
	// to send the fundingLocked message to the peer, it should wait for
	// the server to notify it that the peer is back online, and try again.
	// We'll save the current implementation of sendMessage to restore the
	// original behavior later on.
	workingSendMessage := bob.sendMessage
	bob.sendMessage = func(msg lnwire.Message) error {
		return fmt.Errorf("intentional error in SendToPeer")
	}
	peerChan := make(chan [33]byte, 1)
	conChan := make(chan chan<- lnpeer.Peer, 1)
	alice.fundingMgr.cfg.NotifyWhenOnline = func(peer [33]byte,
		connected chan<- lnpeer.Peer) {

		peerChan <- peer
		conChan <- connected
	}

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction was mined, Bob should have successfully
	// sent the fundingLocked message, while Alice failed sending it. In
	// Alice's case this means that there should be no messages for Bob, and
	// the channel should still be in state 'markedOpen'
	select {
	case msg := <-alice.msgChan:
		t.Fatalf("did not expect any message from Alice: %v", msg)
	default:
		// Expected.
	}

	// Bob will send funding locked to Alice
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Alice should still be markedOpen
	assertDatabaseState(t, alice, fundingOutPoint, markedOpen)

	// While Bob successfully sent fundingLocked.
	assertDatabaseState(t, bob, fundingOutPoint, fundingLockedSent)

	// Alice should be waiting for the server to notify when Bob comes back
	// online.
	var peer [33]byte
	var con chan<- lnpeer.Peer
	select {
	case peer = <-peerChan:
		// Expected
	case <-time.After(time.Second * 3):
		t.Fatalf("alice did not register peer with server")
	}

	select {
	case con = <-conChan:
		// Expected
	case <-time.After(time.Second * 3):
		t.Fatalf("alice did not register connectedChan with server")
	}

	if !bytes.Equal(peer[:], bobPubKey.SerializeCompressed()) {
		t.Fatalf("expected to receive Bob's pubkey (%v), instead got %v",
			bobPubKey, peer)
	}

	// Restore the correct sendMessage implementation, and notify that Bob
	// is back online.
	bob.sendMessage = workingSendMessage
	con <- bob

	// This should make Alice send the fundingLocked.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// The state should now be fundingLockedSent
	assertDatabaseState(t, alice, fundingOutPoint, fundingLockedSent)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Check that the state machine is updated accordingly
	assertAddedToRouterGraph(t, alice, bob, fundingOutPoint)

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)

	// Exchange the fundingLocked messages.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Make sure both fundingManagers send the expected announcement
	// signatures.
	assertAnnouncementSignatures(t, alice, bob)

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerPeerTimeoutAfterInitFunding checks that the zombie sweeper
// will properly clean up a zombie reservation that times out after the
// initFundingMsg has been handled.
func TestFundingManagerPeerTimeoutAfterInitFunding(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Create a funding request and start the workflow.
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: 500000,
		pushAmt:         lnwire.NewMSatFromSatoshis(0),
		private:         false,
		updates:         updateChan,
		err:             errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	_, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Alice should have a new pending reservation.
	assertNumPendingReservations(t, alice, bobPubKey, 1)

	// Make sure Alice's reservation times out and then run her zombie sweeper.
	time.Sleep(1 * time.Millisecond)
	go alice.fundingMgr.pruneZombieReservations()

	// Alice should have sent an Error message to Bob.
	assertErrorSent(t, alice.msgChan)

	// Alice's zombie reservation should have been pruned.
	assertNumPendingReservations(t, alice, bobPubKey, 0)
}

// TestFundingManagerPeerTimeoutAfterFundingOpen checks that the zombie sweeper
// will properly clean up a zombie reservation that times out after the
// fundingOpenMsg has been handled.
func TestFundingManagerPeerTimeoutAfterFundingOpen(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Create a funding request and start the workflow.
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: 500000,
		pushAmt:         lnwire.NewMSatFromSatoshis(0),
		private:         false,
		updates:         updateChan,
		err:             errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Alice should have a new pending reservation.
	assertNumPendingReservations(t, alice, bobPubKey, 1)

	// Let Bob handle the init message.
	bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

	// Bob should answer with an AcceptChannel.
	assertFundingMsgSent(t, bob.msgChan, "AcceptChannel")

	// Bob should have a new pending reservation.
	assertNumPendingReservations(t, bob, alicePubKey, 1)

	// Make sure Bob's reservation times out and then run his zombie sweeper.
	time.Sleep(1 * time.Millisecond)
	go bob.fundingMgr.pruneZombieReservations()

	// Bob should have sent an Error message to Alice.
	assertErrorSent(t, bob.msgChan)

	// Bob's zombie reservation should have been pruned.
	assertNumPendingReservations(t, bob, alicePubKey, 0)
}

// TestFundingManagerPeerTimeoutAfterFundingAccept checks that the zombie sweeper
// will properly clean up a zombie reservation that times out after the
// fundingAcceptMsg has been handled.
func TestFundingManagerPeerTimeoutAfterFundingAccept(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Create a funding request and start the workflow.
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: 500000,
		pushAmt:         lnwire.NewMSatFromSatoshis(0),
		private:         false,
		updates:         updateChan,
		err:             errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Alice should have a new pending reservation.
	assertNumPendingReservations(t, alice, bobPubKey, 1)

	// Let Bob handle the init message.
	bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

	// Bob should answer with an AcceptChannel.
	acceptChannelResponse := assertFundingMsgSent(
		t, bob.msgChan, "AcceptChannel",
	).(*lnwire.AcceptChannel)

	// Bob should have a new pending reservation.
	assertNumPendingReservations(t, bob, alicePubKey, 1)

	// Forward the response to Alice.
	alice.fundingMgr.ProcessFundingMsg(acceptChannelResponse, bob)

	// Alice responds with a FundingCreated messages.
	assertFundingMsgSent(t, alice.msgChan, "FundingCreated")

	// Make sure Alice's reservation times out and then run her zombie sweeper.
	time.Sleep(1 * time.Millisecond)
	go alice.fundingMgr.pruneZombieReservations()

	// Alice should have sent an Error message to Bob.
	assertErrorSent(t, alice.msgChan)

	// Alice's zombie reservation should have been pruned.
	assertNumPendingReservations(t, alice, bobPubKey, 0)
}

func TestFundingManagerFundingTimeout(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	_, _ = openChannel(t, alice, bob, 500000, 0, 1, updateChan, true)

	// Bob will at this point be waiting for the funding transaction to be
	// confirmed, so the channel should be considered pending.
	pendingChannels, err := bob.fundingMgr.cfg.Wallet.Cfg.Database.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to fetch pending channels: %v", err)
	}
	if len(pendingChannels) != 1 {
		t.Fatalf("Expected Bob to have 1 pending channel, had  %v",
			len(pendingChannels))
	}

	// We expect Bob to forget the channel after 2016 blocks (2 weeks), so
	// mine 2016-1, and check that it is still pending.
	bob.mockNotifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: fundingBroadcastHeight + maxWaitNumBlocksFundingConf - 1,
	}

	// Bob should still be waiting for the channel to open.
	assertNumPendingChannelsRemains(t, bob, 1)

	bob.mockNotifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: fundingBroadcastHeight + maxWaitNumBlocksFundingConf,
	}

	// Bob should have sent an Error message to Alice.
	assertErrorSent(t, bob.msgChan)

	// Should not be pending anymore.
	assertNumPendingChannelsBecomes(t, bob, 0)
}

// TestFundingManagerFundingNotTimeoutInitiator checks that if the user was
// the channel initiator, that it does not timeout when the lnd restarts.
func TestFundingManagerFundingNotTimeoutInitiator(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	_, _ = openChannel(t, alice, bob, 500000, 0, 1, updateChan, true)

	// Alice will at this point be waiting for the funding transaction to be
	// confirmed, so the channel should be considered pending.
	pendingChannels, err := alice.fundingMgr.cfg.Wallet.Cfg.Database.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to fetch pending channels: %v", err)
	}
	if len(pendingChannels) != 1 {
		t.Fatalf("Expected Alice to have 1 pending channel, had  %v",
			len(pendingChannels))
	}

	recreateAliceFundingManager(t, alice)

	// We should receive the rebroadcasted funding txn.
	select {
	case <-alice.publTxChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not publish funding tx")
	}

	// Increase the height to 1 minus the maxWaitNumBlocksFundingConf height.
	alice.mockNotifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: fundingBroadcastHeight + maxWaitNumBlocksFundingConf - 1,
	}

	bob.mockNotifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: fundingBroadcastHeight + maxWaitNumBlocksFundingConf - 1,
	}

	// Assert both and Alice and Bob still have 1 pending channels.
	assertNumPendingChannelsRemains(t, alice, 1)

	assertNumPendingChannelsRemains(t, bob, 1)

	// Increase both Alice and Bob to maxWaitNumBlocksFundingConf height.
	alice.mockNotifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: fundingBroadcastHeight + maxWaitNumBlocksFundingConf,
	}

	bob.mockNotifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: fundingBroadcastHeight + maxWaitNumBlocksFundingConf,
	}

	// Since Alice was the initiator, the channel should not have timed out.
	assertNumPendingChannelsRemains(t, alice, 1)

	// Bob should have sent an Error message to Alice.
	assertErrorSent(t, bob.msgChan)

	// Since Bob was not the initiator, the channel should timeout.
	assertNumPendingChannelsBecomes(t, bob, 0)
}

// TestFundingManagerReceiveFundingLockedTwice checks that the fundingManager
// continues to operate as expected in case we receive a duplicate fundingLocked
// message.
func TestFundingManagerReceiveFundingLockedTwice(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, true,
	)

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Check that the state machine is updated accordingly
	assertFundingLockedSent(t, alice, bob, fundingOutPoint)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Check that the state machine is updated accordingly
	assertAddedToRouterGraph(t, alice, bob, fundingOutPoint)

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)

	// Send the fundingLocked message twice to Alice, and once to Bob.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Alice should not send the channel state the second time, as the
	// second funding locked should just be ignored.
	select {
	case <-alice.newChannels:
		t.Fatalf("alice sent new channel to peer a second time")
	case <-time.After(time.Millisecond * 300):
		// Expected
	}

	// Another fundingLocked should also be ignored, since Alice should
	// have updated her database at this point.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	select {
	case <-alice.newChannels:
		t.Fatalf("alice sent new channel to peer a second time")
	case <-time.After(time.Millisecond * 300):
		// Expected
	}

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Make sure the fundingManagers exchange announcement signatures.
	assertAnnouncementSignatures(t, alice, bob)

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerRestartAfterChanAnn checks that the fundingManager properly
// handles receiving a fundingLocked after the its own fundingLocked and channel
// announcement is sent and gets restarted.
func TestFundingManagerRestartAfterChanAnn(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, true,
	)

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Check that the state machine is updated accordingly
	assertFundingLockedSent(t, alice, bob, fundingOutPoint)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Check that the state machine is updated accordingly
	assertAddedToRouterGraph(t, alice, bob, fundingOutPoint)

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)

	// At this point we restart Alice's fundingManager, before she receives
	// the fundingLocked message. After restart, she will receive it, and
	// we expect her to be able to handle it correctly.
	recreateAliceFundingManager(t, alice)

	// Exchange the fundingLocked messages.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Make sure both fundingManagers send the expected channel announcements.
	assertAnnouncementSignatures(t, alice, bob)

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerRestartAfterReceivingFundingLocked checks that the
// fundingManager continues to operate as expected after it has received
// fundingLocked and then gets restarted.
func TestFundingManagerRestartAfterReceivingFundingLocked(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, true,
	)

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Check that the state machine is updated accordingly
	assertFundingLockedSent(t, alice, bob, fundingOutPoint)

	// Let Alice immediately get the fundingLocked message.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)

	// Also let Bob get the fundingLocked message.
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// At this point we restart Alice's fundingManager.
	recreateAliceFundingManager(t, alice)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Check that the state machine is updated accordingly
	assertAddedToRouterGraph(t, alice, bob, fundingOutPoint)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Make sure both fundingManagers send the expected channel announcements.
	assertAnnouncementSignatures(t, alice, bob)

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerPrivateChannel tests that if we open a private channel
// (a channel not supposed to be announced to the rest of the network),
// the announcementSignatures nor the nodeAnnouncement messages are sent.
func TestFundingManagerPrivateChannel(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, false,
	)

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Check that the state machine is updated accordingly
	assertFundingLockedSent(t, alice, bob, fundingOutPoint)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)

	// Exchange the fundingLocked messages.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Since this is a private channel, we shouldn't receive the
	// announcement signatures.
	select {
	case ann := <-alice.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	case <-time.After(300 * time.Millisecond):
		// Expected
	}

	select {
	case ann := <-bob.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	case <-time.After(300 * time.Millisecond):
		// Expected
	}

	// We should however receive each side's node announcement.
	select {
	case msg := <-alice.msgChan:
		if _, ok := msg.(*lnwire.NodeAnnouncement); !ok {
			t.Fatalf("expected to receive node announcement")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected to receive node announcement")
	}

	select {
	case msg := <-bob.msgChan:
		if _, ok := msg.(*lnwire.NodeAnnouncement); !ok {
			t.Fatalf("expected to receive node announcement")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected to receive node announcement")
	}

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerPrivateRestart tests that the privacy guarantees granted
// by the private channel persist even on restart. This means that the
// announcement signatures nor the node announcement messages are sent upon
// restart.
func TestFundingManagerPrivateRestart(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	localAmt := btcutil.Amount(500000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt
	fundingOutPoint, fundingTx := openChannel(
		t, alice, bob, localAmt, pushAmt, 1, updateChan, false,
	)

	// Notify that transaction was mined
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// The funding transaction was mined, so assert that both funding
	// managers now have the state of this channel 'markedOpen' in their
	// internal state machine.
	assertMarkedOpen(t, alice, bob, fundingOutPoint)

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	fundingLockedAlice := assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	fundingLockedBob := assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Check that the state machine is updated accordingly
	assertFundingLockedSent(t, alice, bob, fundingOutPoint)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	assertChannelAnnouncements(t, alice, bob, capacity, nil, nil)

	// Note: We don't check for the addedToRouterGraph state because in
	// the private channel mode, the state is quickly changed from
	// addedToRouterGraph to deleted from the database since the public
	// announcement phase is skipped.

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)

	// Exchange the fundingLocked messages.
	alice.fundingMgr.ProcessFundingMsg(fundingLockedBob, bob)
	bob.fundingMgr.ProcessFundingMsg(fundingLockedAlice, alice)

	// Check that they notify the breach arbiter and peer about the new
	// channel.
	assertHandleFundingLocked(t, alice, bob)

	// Notify that six confirmations has been reached on funding transaction.
	alice.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.sixConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// Since this is a private channel, we shouldn't receive the public
	// channel announcement messages.
	select {
	case ann := <-alice.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	case <-time.After(300 * time.Millisecond):
	}

	select {
	case ann := <-bob.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	case <-time.After(300 * time.Millisecond):
	}

	// We should however receive each side's node announcement.
	select {
	case msg := <-alice.msgChan:
		if _, ok := msg.(*lnwire.NodeAnnouncement); !ok {
			t.Fatalf("expected to receive node announcement")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected to receive node announcement")
	}

	select {
	case msg := <-bob.msgChan:
		if _, ok := msg.(*lnwire.NodeAnnouncement); !ok {
			t.Fatalf("expected to receive node announcement")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected to receive node announcement")
	}

	// Restart Alice's fundingManager so we can prove that the public
	// channel announcements are not sent upon restart and that the private
	// setting persists upon restart.
	recreateAliceFundingManager(t, alice)

	select {
	case ann := <-alice.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	case <-time.After(300 * time.Millisecond):
		// Expected
	}

	select {
	case ann := <-bob.announceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	case <-time.After(300 * time.Millisecond):
		// Expected
	}

	// The internal state-machine should now have deleted the channelStates
	// from the database, as the channel is announced.
	assertNoChannelState(t, alice, bob, fundingOutPoint)
}

// TestFundingManagerCustomChannelParameters checks that custom requirements we
// specify during the channel funding flow is preserved correcly on both sides.
func TestFundingManagerCustomChannelParameters(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// This is the custom parameters we'll use.
	const csvDelay = 67
	const minHtlcIn = 1234
	const maxValueInFlight = 50000
	const fundingAmt = 5000000

	// We will consume the channel updates as we go, so no buffering is
	// needed.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)

	localAmt := btcutil.Amount(5000000)
	pushAmt := btcutil.Amount(0)
	capacity := localAmt + pushAmt

	// Create a funding request with the custom parameters and start the
	// workflow.
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:     bob.privKey.PubKey(),
		chainHash:        *fundingNetParams.GenesisHash,
		localFundingAmt:  localAmt,
		pushAmt:          lnwire.NewMSatFromSatoshis(pushAmt),
		private:          false,
		maxValueInFlight: maxValueInFlight,
		minHtlcIn:        minHtlcIn,
		remoteCsvDelay:   csvDelay,
		updates:          updateChan,
		err:              errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Check that the custom CSV delay is sent as part of OpenChannel.
	if openChannelReq.CsvDelay != csvDelay {
		t.Fatalf("expected OpenChannel to have CSV delay %v, got %v",
			csvDelay, openChannelReq.CsvDelay)
	}

	// Check that the custom minHTLC value is sent.
	if openChannelReq.HtlcMinimum != minHtlcIn {
		t.Fatalf("expected OpenChannel to have minHtlc %v, got %v",
			minHtlcIn, openChannelReq.HtlcMinimum)
	}

	// Check that the max value in flight is sent as part of OpenChannel.
	if openChannelReq.MaxValueInFlight != maxValueInFlight {
		t.Fatalf("expected OpenChannel to have MaxValueInFlight %v, got %v",
			maxValueInFlight, openChannelReq.MaxValueInFlight)
	}

	chanID := openChannelReq.PendingChannelID

	// Let Bob handle the init message.
	bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

	// Bob should answer with an AcceptChannel message.
	acceptChannelResponse := assertFundingMsgSent(
		t, bob.msgChan, "AcceptChannel",
	).(*lnwire.AcceptChannel)

	// Bob should require the default delay of 4.
	if acceptChannelResponse.CsvDelay != 4 {
		t.Fatalf("expected AcceptChannel to have CSV delay %v, got %v",
			4, acceptChannelResponse.CsvDelay)
	}

	// And the default MinHTLC value of 5.
	if acceptChannelResponse.HtlcMinimum != 5 {
		t.Fatalf("expected AcceptChannel to have minHtlc %v, got %v",
			5, acceptChannelResponse.HtlcMinimum)
	}

	reserve := lnwire.NewMSatFromSatoshis(fundingAmt / 100)
	maxValueAcceptChannel := lnwire.NewMSatFromSatoshis(fundingAmt) - reserve

	if acceptChannelResponse.MaxValueInFlight != maxValueAcceptChannel {
		t.Fatalf("expected AcceptChannel to have MaxValueInFlight %v, got %v",
			maxValueAcceptChannel, acceptChannelResponse.MaxValueInFlight)
	}

	// Forward the response to Alice.
	alice.fundingMgr.ProcessFundingMsg(acceptChannelResponse, bob)

	// Alice responds with a FundingCreated message.
	fundingCreated := assertFundingMsgSent(
		t, alice.msgChan, "FundingCreated",
	).(*lnwire.FundingCreated)

	// Helper method for checking the CSV delay stored for a reservation.
	assertDelay := func(resCtx *reservationWithCtx,
		ourDelay, theirDelay uint16) error {

		ourCsvDelay := resCtx.reservation.OurContribution().CsvDelay
		if ourCsvDelay != ourDelay {
			return fmt.Errorf("expected our CSV delay to be %v, "+
				"was %v", ourDelay, ourCsvDelay)
		}

		theirCsvDelay := resCtx.reservation.TheirContribution().CsvDelay
		if theirCsvDelay != theirDelay {
			return fmt.Errorf("expected their CSV delay to be %v, "+
				"was %v", theirDelay, theirCsvDelay)
		}
		return nil
	}

	// Helper method for checking the MinHtlc value stored for a
	// reservation.
	assertMinHtlc := func(resCtx *reservationWithCtx,
		expOurMinHtlc, expTheirMinHtlc lnwire.MilliSatoshi) error {

		ourMinHtlc := resCtx.reservation.OurContribution().MinHTLC
		if ourMinHtlc != expOurMinHtlc {
			return fmt.Errorf("expected our minHtlc to be %v, "+
				"was %v", expOurMinHtlc, ourMinHtlc)
		}

		theirMinHtlc := resCtx.reservation.TheirContribution().MinHTLC
		if theirMinHtlc != expTheirMinHtlc {
			return fmt.Errorf("expected their minHtlc to be %v, "+
				"was %v", expTheirMinHtlc, theirMinHtlc)
		}
		return nil
	}

	// Helper method for checking the MaxValueInFlight stored for a
	// reservation.
	assertMaxHtlc := func(resCtx *reservationWithCtx,
		expOurMaxValue, expTheirMaxValue lnwire.MilliSatoshi) error {

		ourMaxValue :=
			resCtx.reservation.OurContribution().MaxPendingAmount
		if ourMaxValue != expOurMaxValue {
			return fmt.Errorf("expected our maxValue to be %v, "+
				"was %v", expOurMaxValue, ourMaxValue)
		}

		theirMaxValue :=
			resCtx.reservation.TheirContribution().MaxPendingAmount
		if theirMaxValue != expTheirMaxValue {
			return fmt.Errorf("expected their MaxPendingAmount to be %v, "+
				"was %v", expTheirMaxValue, theirMaxValue)
		}
		return nil
	}

	// Check that the custom channel parameters were properly set in the
	// channel reservation.
	resCtx, err := alice.fundingMgr.getReservationCtx(bobPubKey, chanID)
	if err != nil {
		t.Fatalf("unable to find ctx: %v", err)
	}

	// Alice's CSV delay should be 4 since Bob sent the default value, and
	// Bob's should be 67 since Alice sent the custom value.
	if err := assertDelay(resCtx, 4, csvDelay); err != nil {
		t.Fatal(err)
	}

	// The minimum HTLC value Alice can offer should be 5, and the minimum
	// Bob can offer should be 1234.
	if err := assertMinHtlc(resCtx, 5, minHtlcIn); err != nil {
		t.Fatal(err)
	}

	// The max value in flight Alice can have should be maxValueAcceptChannel,
	// which is the default value and the maxium Bob can offer should be
	// maxValueInFlight.
	if err := assertMaxHtlc(resCtx,
		maxValueAcceptChannel, maxValueInFlight); err != nil {
		t.Fatal(err)
	}

	// Also make sure the parameters are properly set on Bob's end.
	resCtx, err = bob.fundingMgr.getReservationCtx(alicePubKey, chanID)
	if err != nil {
		t.Fatalf("unable to find ctx: %v", err)
	}

	if err := assertDelay(resCtx, csvDelay, 4); err != nil {
		t.Fatal(err)
	}

	if err := assertMinHtlc(resCtx, minHtlcIn, 5); err != nil {
		t.Fatal(err)
	}

	if err := assertMaxHtlc(resCtx,
		maxValueInFlight, maxValueAcceptChannel); err != nil {
		t.Fatal(err)
	}
	// Give the message to Bob.
	bob.fundingMgr.ProcessFundingMsg(fundingCreated, alice)

	// Finally, Bob should send the FundingSigned message.
	fundingSigned := assertFundingMsgSent(
		t, bob.msgChan, "FundingSigned",
	).(*lnwire.FundingSigned)

	// Forward the signature to Alice.
	alice.fundingMgr.ProcessFundingMsg(fundingSigned, bob)

	// After Alice processes the singleFundingSignComplete message, she will
	// broadcast the funding transaction to the network. We expect to get a
	// channel update saying the channel is pending.
	var pendingUpdate *lnrpc.OpenStatusUpdate
	select {
	case pendingUpdate = <-updateChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenStatusUpdate_ChanPending")
	}

	_, ok = pendingUpdate.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	if !ok {
		t.Fatal("OpenStatusUpdate was not OpenStatusUpdate_ChanPending")
	}

	// Wait for Alice to published the funding tx to the network.
	var fundingTx *wire.MsgTx
	select {
	case fundingTx = <-alice.publTxChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not publish funding tx")
	}

	// Notify that transaction was mined.
	alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}
	bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
		Tx: fundingTx,
	}

	// After the funding transaction is mined, Alice will send
	// fundingLocked to Bob.
	_ = assertFundingMsgSent(
		t, alice.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// And similarly Bob will send funding locked to Alice.
	_ = assertFundingMsgSent(
		t, bob.msgChan, "FundingLocked",
	).(*lnwire.FundingLocked)

	// Make sure both fundingManagers send the expected channel
	// announcements.
	// Alice should advertise the default MinHTLC value of
	// 5, while bob should advertise the value minHtlc, since Alice
	// required him to use it.
	minHtlcArr := []lnwire.MilliSatoshi{5, minHtlcIn}

	// For maxHltc Alice should advertise the default MaxHtlc value of
	// maxValueAcceptChannel, while bob should advertise the value
	// maxValueInFlight since Alice required him to use it.
	maxHtlcArr := []lnwire.MilliSatoshi{maxValueAcceptChannel, maxValueInFlight}

	assertChannelAnnouncements(t, alice, bob, capacity, minHtlcArr, maxHtlcArr)

	// The funding transaction is now confirmed, wait for the
	// OpenStatusUpdate_ChanOpen update
	waitForOpenUpdate(t, updateChan)
}

// TestFundingManagerMaxPendingChannels checks that trying to open another
// channel with the same peer when MaxPending channels are pending fails.
func TestFundingManagerMaxPendingChannels(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(
		t, func(cfg *fundingConfig) {
			cfg.MaxPendingChannels = maxPending
		},
	)
	defer tearDownFundingManagers(t, alice, bob)

	// Create openChanReqs for maxPending+1 channels.
	var initReqs []*openChanReq
	for i := 0; i < maxPending+1; i++ {
		updateChan := make(chan *lnrpc.OpenStatusUpdate)
		errChan := make(chan error, 1)
		initReq := &openChanReq{
			targetPubkey:    bob.privKey.PubKey(),
			chainHash:       *fundingNetParams.GenesisHash,
			localFundingAmt: 5000000,
			pushAmt:         lnwire.NewMSatFromSatoshis(0),
			private:         false,
			updates:         updateChan,
			err:             errChan,
		}
		initReqs = append(initReqs, initReq)
	}

	// Kick of maxPending+1 funding workflows.
	var accepts []*lnwire.AcceptChannel
	var lastOpen *lnwire.OpenChannel
	for i, initReq := range initReqs {
		alice.fundingMgr.initFundingWorkflow(bob, initReq)

		// Alice should have sent the OpenChannel message to Bob.
		var aliceMsg lnwire.Message
		select {
		case aliceMsg = <-alice.msgChan:
		case err := <-initReq.err:
			t.Fatalf("error init funding workflow: %v", err)
		case <-time.After(time.Second * 5):
			t.Fatalf("alice did not send OpenChannel message")
		}

		openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
		if !ok {
			errorMsg, gotError := aliceMsg.(*lnwire.Error)
			if gotError {
				t.Fatalf("expected OpenChannel to be sent "+
					"from bob, instead got error: %v",
					errorMsg.Error())
			}
			t.Fatalf("expected OpenChannel to be sent from "+
				"alice, instead got %T", aliceMsg)
		}

		// Let Bob handle the init message.
		bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

		// Bob should answer with an AcceptChannel message for the
		// first maxPending channels.
		if i < maxPending {
			acceptChannelResponse := assertFundingMsgSent(
				t, bob.msgChan, "AcceptChannel",
			).(*lnwire.AcceptChannel)
			accepts = append(accepts, acceptChannelResponse)
			continue
		}

		// For the last channel, Bob should answer with an error.
		lastOpen = openChannelReq
		_ = assertFundingMsgSent(
			t, bob.msgChan, "Error",
		).(*lnwire.Error)

	}

	// Forward the responses to Alice.
	var signs []*lnwire.FundingSigned
	for _, accept := range accepts {
		alice.fundingMgr.ProcessFundingMsg(accept, bob)

		// Alice responds with a FundingCreated message.
		fundingCreated := assertFundingMsgSent(
			t, alice.msgChan, "FundingCreated",
		).(*lnwire.FundingCreated)

		// Give the message to Bob.
		bob.fundingMgr.ProcessFundingMsg(fundingCreated, alice)

		// Finally, Bob should send the FundingSigned message.
		fundingSigned := assertFundingMsgSent(
			t, bob.msgChan, "FundingSigned",
		).(*lnwire.FundingSigned)

		signs = append(signs, fundingSigned)
	}

	// Sending another init request from Alice should still make Bob
	// respond with an error.
	bob.fundingMgr.ProcessFundingMsg(lastOpen, alice)
	_ = assertFundingMsgSent(
		t, bob.msgChan, "Error",
	).(*lnwire.Error)

	// Give the FundingSigned messages to Alice.
	var txs []*wire.MsgTx
	for i, sign := range signs {
		alice.fundingMgr.ProcessFundingMsg(sign, bob)

		// Alice should send a status update for each channel, and
		// publish a funding tx to the network.
		var pendingUpdate *lnrpc.OpenStatusUpdate
		select {
		case pendingUpdate = <-initReqs[i].updates:
		case <-time.After(time.Second * 5):
			t.Fatalf("alice did not send OpenStatusUpdate_ChanPending")
		}

		_, ok := pendingUpdate.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
		if !ok {
			t.Fatal("OpenStatusUpdate was not OpenStatusUpdate_ChanPending")
		}

		select {
		case tx := <-alice.publTxChan:
			txs = append(txs, tx)
		case <-time.After(time.Second * 5):
			t.Fatalf("alice did not publish funding tx")
		}

	}

	// Sending another init request from Alice should still make Bob
	// respond with an error, since the funding transactions are not
	// confirmed yet,
	bob.fundingMgr.ProcessFundingMsg(lastOpen, alice)
	_ = assertFundingMsgSent(
		t, bob.msgChan, "Error",
	).(*lnwire.Error)

	// Notify that the transactions were mined.
	for i := 0; i < maxPending; i++ {
		alice.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
			Tx: txs[i],
		}
		bob.mockNotifier.oneConfChannel <- &chainntnfs.TxConfirmation{
			Tx: txs[i],
		}

		// Expect both to be sending FundingLocked.
		_ = assertFundingMsgSent(
			t, alice.msgChan, "FundingLocked",
		).(*lnwire.FundingLocked)

		_ = assertFundingMsgSent(
			t, bob.msgChan, "FundingLocked",
		).(*lnwire.FundingLocked)

	}

	// Now opening another channel should work.
	bob.fundingMgr.ProcessFundingMsg(lastOpen, alice)

	// Bob should answer with an AcceptChannel message.
	_ = assertFundingMsgSent(
		t, bob.msgChan, "AcceptChannel",
	).(*lnwire.AcceptChannel)
}

// TestFundingManagerRejectPush checks behaviour of 'rejectpush'
// option, namely that non-zero incoming push amounts are disabled.
func TestFundingManagerRejectPush(t *testing.T) {
	t.Parallel()

	// Enable 'rejectpush' option and initialize funding managers.
	alice, bob := setupFundingManagers(
		t, func(cfg *fundingConfig) {
			cfg.RejectPush = true
		},
	)
	defer tearDownFundingManagers(t, alice, bob)

	// Create a funding request and start the workflow.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: 500000,
		pushAmt:         lnwire.NewMSatFromSatoshis(10),
		private:         true,
		updates:         updateChan,
		err:             errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Let Bob handle the init message.
	bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

	// Assert Bob responded with an ErrNonZeroPushAmount error.
	err := assertFundingMsgSent(t, bob.msgChan, "Error").(*lnwire.Error)
	if !strings.Contains(err.Error(), "non-zero push amounts are disabled") {
		t.Fatalf("expected ErrNonZeroPushAmount error, got \"%v\"",
			err.Error())
	}
}

// TestFundingManagerMaxConfs ensures that we don't accept a funding proposal
// that proposes a MinAcceptDepth greater than the maximum number of
// confirmations we're willing to accept.
func TestFundingManagerMaxConfs(t *testing.T) {
	t.Parallel()

	alice, bob := setupFundingManagers(t)
	defer tearDownFundingManagers(t, alice, bob)

	// Create a funding request and start the workflow.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: 500000,
		pushAmt:         lnwire.NewMSatFromSatoshis(10),
		private:         false,
		updates:         updateChan,
		err:             errChan,
	}

	alice.fundingMgr.initFundingWorkflow(bob, initReq)

	// Alice should have sent the OpenChannel message to Bob.
	var aliceMsg lnwire.Message
	select {
	case aliceMsg = <-alice.msgChan:
	case err := <-initReq.err:
		t.Fatalf("error init funding workflow: %v", err)
	case <-time.After(time.Second * 5):
		t.Fatalf("alice did not send OpenChannel message")
	}

	openChannelReq, ok := aliceMsg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := aliceMsg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent from "+
			"alice, instead got %T", aliceMsg)
	}

	// Let Bob handle the init message.
	bob.fundingMgr.ProcessFundingMsg(openChannelReq, alice)

	// Bob should answer with an AcceptChannel message.
	acceptChannelResponse := assertFundingMsgSent(
		t, bob.msgChan, "AcceptChannel",
	).(*lnwire.AcceptChannel)

	// Modify the AcceptChannel message Bob is proposing to including a
	// MinAcceptDepth Alice won't be willing to accept.
	acceptChannelResponse.MinAcceptDepth = chainntnfs.MaxNumConfs + 1

	alice.fundingMgr.ProcessFundingMsg(acceptChannelResponse, bob)

	// Alice should respond back with an error indicating MinAcceptDepth is
	// too large.
	err := assertFundingMsgSent(t, alice.msgChan, "Error").(*lnwire.Error)
	if !strings.Contains(err.Error(), "minimum depth") {
		t.Fatalf("expected ErrNumConfsTooLarge, got \"%v\"",
			err.Error())
	}
}

// TestFundingManagerFundAll tests that we can initiate a funding request to
// use the funds remaining in the wallet. This should produce a funding tx with
// no change output.
func TestFundingManagerFundAll(t *testing.T) {
	t.Parallel()

	// We set up our mock wallet to control a list of UTXOs that sum to
	// less than the max channel size.
	allCoins := []*lnwallet.Utxo{
		{
			AddressType: lnwallet.WitnessPubKey,
			Value: btcutil.Amount(
				0.05 * btcutil.SatoshiPerBitcoin,
			),
			PkScript: mock.CoinPkScript,
			OutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
		},
		{
			AddressType: lnwallet.WitnessPubKey,
			Value: btcutil.Amount(
				0.06 * btcutil.SatoshiPerBitcoin,
			),
			PkScript: mock.CoinPkScript,
			OutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 1,
			},
		},
	}

	tests := []struct {
		spendAmt btcutil.Amount
		change   bool
	}{
		{
			// We will spend all the funds in the wallet, and
			// expects no change output.
			spendAmt: btcutil.Amount(
				0.11 * btcutil.SatoshiPerBitcoin,
			),
			change: false,
		},
		{
			// We spend a little less than the funds in the wallet,
			// so a change output should be created.
			spendAmt: btcutil.Amount(
				0.10 * btcutil.SatoshiPerBitcoin,
			),
			change: true,
		},
	}

	for _, test := range tests {
		alice, bob := setupFundingManagers(t)
		defer tearDownFundingManagers(t, alice, bob)

		alice.fundingMgr.cfg.Wallet.WalletController.(*mock.WalletController).Utxos = allCoins

		// We will consume the channel updates as we go, so no
		// buffering is needed.
		updateChan := make(chan *lnrpc.OpenStatusUpdate)

		// Initiate a fund channel, and inspect the funding tx.
		pushAmt := btcutil.Amount(0)
		fundingTx := fundChannel(
			t, alice, bob, test.spendAmt, pushAmt, true, 1,
			updateChan, true,
		)

		// Check whether the expected change output is present.
		if test.change && len(fundingTx.TxOut) != 2 {
			t.Fatalf("expected 2 outputs, had %v",
				len(fundingTx.TxOut))
		}

		if !test.change && len(fundingTx.TxOut) != 1 {
			t.Fatalf("expected 1 output, had %v",
				len(fundingTx.TxOut))
		}

		// Inputs should be all funds in the wallet.
		if len(fundingTx.TxIn) != len(allCoins) {
			t.Fatalf("Had %d inputs, expected %d",
				len(fundingTx.TxIn), len(allCoins))
		}

		for i, txIn := range fundingTx.TxIn {
			if txIn.PreviousOutPoint != allCoins[i].OutPoint {
				t.Fatalf("expected outpoint to be %v, was %v",
					allCoins[i].OutPoint,
					txIn.PreviousOutPoint)
			}
		}
	}
}

// TestGetUpfrontShutdown tests different combinations of inputs for getting a
// shutdown script. It varies whether the peer has the feature set, whether
// the user has provided a script and our local configuration to test that
// GetUpfrontShutdownScript returns the expected outcome.
func TestGetUpfrontShutdownScript(t *testing.T) {
	upfrontScript := []byte("upfront script")
	generatedScript := []byte("generated script")

	getScript := func() (lnwire.DeliveryAddress, error) {
		return generatedScript, nil
	}

	tests := []struct {
		name           string
		getScript      func() (lnwire.DeliveryAddress, error)
		upfrontScript  lnwire.DeliveryAddress
		peerEnabled    bool
		localEnabled   bool
		expectedScript lnwire.DeliveryAddress
		expectedErr    error
	}{
		{
			name:      "peer disabled, no shutdown",
			getScript: getScript,
		},
		{
			name:          "peer disabled, upfront provided",
			upfrontScript: upfrontScript,
			expectedErr:   errUpfrontShutdownScriptNotSupported,
		},
		{
			name:           "peer enabled, upfront provided",
			upfrontScript:  upfrontScript,
			peerEnabled:    true,
			expectedScript: upfrontScript,
		},
		{
			name:        "peer enabled, local disabled",
			peerEnabled: true,
		},
		{
			name:           "local enabled, no upfront script",
			getScript:      getScript,
			peerEnabled:    true,
			localEnabled:   true,
			expectedScript: generatedScript,
		},
		{
			name:           "local enabled, upfront script",
			peerEnabled:    true,
			upfrontScript:  upfrontScript,
			localEnabled:   true,
			expectedScript: upfrontScript,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			var mockPeer testNode

			// If the remote peer in the test should support upfront shutdown,
			// add the feature bit.
			if test.peerEnabled {
				mockPeer.remoteFeatures = []lnwire.FeatureBit{
					lnwire.UpfrontShutdownScriptOptional,
				}
			}

			addr, err := getUpfrontShutdownScript(
				test.localEnabled, &mockPeer, test.upfrontScript,
				test.getScript,
			)
			if err != test.expectedErr {
				t.Fatalf("got: %v, expected error: %v", err, test.expectedErr)
			}

			if !bytes.Equal(addr, test.expectedScript) {
				t.Fatalf("expected address: %x, got: %x",
					test.expectedScript, addr)
			}

		})
	}
}

func expectOpenChannelMsg(t *testing.T, msgChan chan lnwire.Message) *lnwire.OpenChannel {
	var msg lnwire.Message
	select {
	case msg = <-msgChan:
	case <-time.After(time.Second * 5):
		t.Fatalf("node did not send OpenChannel message")
	}

	openChannelReq, ok := msg.(*lnwire.OpenChannel)
	if !ok {
		errorMsg, gotError := msg.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected OpenChannel to be sent "+
				"from bob, instead got error: %v",
				errorMsg.Error())
		}
		t.Fatalf("expected OpenChannel to be sent, instead got %T",
			msg)
	}

	return openChannelReq
}

func TestMaxChannelSizeConfig(t *testing.T) {
	t.Parallel()

	// Create a set of funding managers that will reject wumbo
	// channels but set --maxchansize explicitly lower than soft-limit.
	// Verify that wumbo rejecting funding managers will respect --maxchansize
	// below 16777215 satoshi (MaxFundingAmount) limit.
	alice, bob := setupFundingManagers(t, func(cfg *fundingConfig) {
		cfg.NoWumboChans = true
		cfg.MaxChanSize = MaxFundingAmount - 1
	})

	// Attempt to create a channel above the limit
	// imposed by --maxchansize, which should be rejected.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: MaxFundingAmount,
		pushAmt:         lnwire.NewMSatFromSatoshis(0),
		private:         false,
		updates:         updateChan,
		err:             errChan,
	}

	// After processing the funding open message, bob should respond with
	// an error rejecting the channel that exceeds size limit.
	alice.fundingMgr.initFundingWorkflow(bob, initReq)
	openChanMsg := expectOpenChannelMsg(t, alice.msgChan)
	bob.fundingMgr.ProcessFundingMsg(openChanMsg, alice)
	assertErrorSent(t, bob.msgChan)

	// Create a set of funding managers that will reject wumbo
	// channels but set --maxchansize explicitly higher than soft-limit
	// A --maxchansize greater than this limit should have no effect.
	tearDownFundingManagers(t, alice, bob)
	alice, bob = setupFundingManagers(t, func(cfg *fundingConfig) {
		cfg.NoWumboChans = true
		cfg.MaxChanSize = MaxFundingAmount + 1
	})

	// We expect Bob to respond with an Accept channel message.
	alice.fundingMgr.initFundingWorkflow(bob, initReq)
	openChanMsg = expectOpenChannelMsg(t, alice.msgChan)
	bob.fundingMgr.ProcessFundingMsg(openChanMsg, alice)
	assertFundingMsgSent(t, bob.msgChan, "AcceptChannel")

	// Verify that wumbo accepting funding managers will respect --maxchansize
	// Create the funding managers, this time allowing
	// wumbo channels but setting --maxchansize explicitly.
	tearDownFundingManagers(t, alice, bob)
	alice, bob = setupFundingManagers(t, func(cfg *fundingConfig) {
		cfg.NoWumboChans = false
		cfg.MaxChanSize = btcutil.Amount(100000000)
	})

	// Attempt to create a channel above the limit
	// imposed by --maxchansize, which should be rejected.
	initReq.localFundingAmt = btcutil.SatoshiPerBitcoin + 1

	// After processing the funding open message, bob should respond with
	// an error rejecting the channel that exceeds size limit.
	alice.fundingMgr.initFundingWorkflow(bob, initReq)
	openChanMsg = expectOpenChannelMsg(t, alice.msgChan)
	bob.fundingMgr.ProcessFundingMsg(openChanMsg, alice)
	assertErrorSent(t, bob.msgChan)
}

// TestWumboChannelConfig tests that the funding manager will respect the wumbo
// channel config param when creating or accepting new channels.
func TestWumboChannelConfig(t *testing.T) {
	t.Parallel()

	// First we'll create a set of funding managers that will reject wumbo
	// channels.
	alice, bob := setupFundingManagers(t, func(cfg *fundingConfig) {
		cfg.NoWumboChans = true
	})

	// If we attempt to initiate a new funding open request to Alice,
	// that's below the wumbo channel mark, we should be able to start the
	// funding process w/o issue.
	updateChan := make(chan *lnrpc.OpenStatusUpdate)
	errChan := make(chan error, 1)
	initReq := &openChanReq{
		targetPubkey:    bob.privKey.PubKey(),
		chainHash:       *fundingNetParams.GenesisHash,
		localFundingAmt: MaxFundingAmount,
		pushAmt:         lnwire.NewMSatFromSatoshis(0),
		private:         false,
		updates:         updateChan,
		err:             errChan,
	}

	// We expect Bob to respond with an Accept channel message.
	alice.fundingMgr.initFundingWorkflow(bob, initReq)
	openChanMsg := expectOpenChannelMsg(t, alice.msgChan)
	bob.fundingMgr.ProcessFundingMsg(openChanMsg, alice)
	assertFundingMsgSent(t, bob.msgChan, "AcceptChannel")

	// We'll now attempt to create a channel above the wumbo mark, which
	// should be rejected.
	initReq.localFundingAmt = btcutil.SatoshiPerBitcoin

	// After processing the funding open message, bob should respond with
	// an error rejecting the channel.
	alice.fundingMgr.initFundingWorkflow(bob, initReq)
	openChanMsg = expectOpenChannelMsg(t, alice.msgChan)
	bob.fundingMgr.ProcessFundingMsg(openChanMsg, alice)
	assertErrorSent(t, bob.msgChan)

	// Next, we'll re-create the funding managers, but this time allowing
	// wumbo channels explicitly.
	tearDownFundingManagers(t, alice, bob)
	alice, bob = setupFundingManagers(t, func(cfg *fundingConfig) {
		cfg.NoWumboChans = false
		cfg.MaxChanSize = MaxBtcFundingAmountWumbo
	})

	// We should now be able to initiate a wumbo channel funding w/o any
	// issues.
	alice.fundingMgr.initFundingWorkflow(bob, initReq)
	openChanMsg = expectOpenChannelMsg(t, alice.msgChan)
	bob.fundingMgr.ProcessFundingMsg(openChanMsg, alice)
	assertFundingMsgSent(t, bob.msgChan, "AcceptChannel")
}
