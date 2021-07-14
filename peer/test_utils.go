package peer

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channelnotifier"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lntest/channels"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/pool"
	"github.com/lightningnetwork/lnd/queue"
	"github.com/lightningnetwork/lnd/shachain"
	"github.com/lightningnetwork/lnd/watchtower/wtmock"
	"github.com/stretchr/testify/require"
)

const (
	// timeout is a timeout value to use for tests which need to wait for
	// a return value on a channel.
	timeout = time.Second * 5
)

var (
	aliceAddr = &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 18555,
	}

	bobAddr = &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 18556,
	}

	// Just use some arbitrary bytes as delivery script.
	dummyDeliveryScript = channels.AlicesPrivKey

	errDummy = fmt.Errorf("dummy error")
)

type testContext struct {
	alicePriv *btcec.PrivateKey
	alicePub  *btcec.PublicKey
	aliceDb   *channeldb.DB

	bobPriv *btcec.PrivateKey
	bobPub  *btcec.PublicKey
	bobDb   *channeldb.DB

	aliceSigner *mock.SingleSigner
	alicePool   *lnwallet.SigPool

	bobSigner *mock.SingleSigner
	bobPool   *lnwallet.SigPool

	publTx chan *wire.MsgTx

	aliceConn *wtmock.MockPeer

	notifier *mock.ChainNotifier

	aliceCfg *Config

	bobInit *lnwire.Init

	cleanup func()
}

// createTestContext makes a test context.
func createTestContext(t *testing.T) *testContext {
	alicePriv, alicePub := btcec.PrivKeyFromBytes(
		btcec.S256(), channels.AlicesPrivKey,
	)

	alicePath, err := ioutil.TempDir("", "alicedb")
	require.NoError(t, err)

	aliceDb, err := channeldb.Open(alicePath)
	require.NoError(t, err)

	bobPriv, bobPub := btcec.PrivKeyFromBytes(
		btcec.S256(), channels.BobsPrivKey,
	)

	bobPath, err := ioutil.TempDir("", "bobdb")
	require.NoError(t, err)

	bobDb, err := channeldb.Open(bobPath)
	require.NoError(t, err)

	aliceSigner := &mock.SingleSigner{Privkey: alicePriv}
	alicePool := lnwallet.NewSigPool(1, aliceSigner)
	require.NoError(t, alicePool.Start())

	bobSigner := &mock.SingleSigner{Privkey: bobPriv}
	bobPool := lnwallet.NewSigPool(1, bobSigner)
	require.NoError(t, bobPool.Start())

	cleanup := func() {
		os.RemoveAll(alicePath)
		os.RemoveAll(bobPath)
		_ = alicePool.Stop()
		_ = bobPool.Stop()
	}

	publTx := make(chan *wire.MsgTx)

	aliceConn := wtmock.NewMockPeer(nil, nil, nil, 1)

	notifier := &mock.ChainNotifier{
		SpendChan: make(chan *chainntnfs.SpendDetail),
		EpochChan: make(chan *chainntnfs.BlockEpoch),
		ConfChan:  make(chan *chainntnfs.TxConfirmation),
	}

	aliceCfg, err := assembleConfig(
		alicePriv, alicePub, bobPub, aliceDb, aliceSigner, alicePool,
		publTx, aliceConn, notifier,
	)
	require.NoError(t, err)

	bobGlobalVec := lnwire.NewRawFeatureVector()
	bobFeatureVec := lnwire.NewRawFeatureVector(
		lnwire.DataLossProtectRequired,
	)
	bobInit := lnwire.NewInitMessage(bobGlobalVec, bobFeatureVec)

	return &testContext{
		alicePriv: alicePriv,
		alicePub:  alicePub,
		aliceDb:   aliceDb,

		bobPriv: bobPriv,
		bobPub:  bobPub,
		bobDb:   bobDb,

		aliceSigner: aliceSigner,
		alicePool:   alicePool,

		bobSigner: bobSigner,
		bobPool:   bobPool,

		publTx: publTx,

		aliceConn: aliceConn,

		notifier: notifier,

		aliceCfg: aliceCfg,

		bobInit: bobInit,

		cleanup: cleanup,
	}
}

// assembleConfig assembles a peer Config.
func assembleConfig(alicePriv *btcec.PrivateKey, alicePub,
	bobPub *btcec.PublicKey, aliceDb *channeldb.DB,
	aliceSigner input.Signer, alicePool *lnwallet.SigPool,
	publTx chan *wire.MsgTx, conn MessageConn,
	notifier chainntnfs.ChainNotifier) (*Config, error) {

	var aliceSerPub [33]byte
	copy(aliceSerPub[:], alicePub.SerializeCompressed())

	var bobSerPub [33]byte
	copy(bobSerPub[:], bobPub.SerializeCompressed())

	bobNetAddr := &lnwire.NetAddress{
		IdentityKey: bobPub,
		Address:     bobAddr,
		ChainNet:    wire.SimNet,
	}

	features := lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(lnwire.StaticRemoteKeyRequired),
		lnwire.Features,
	)
	legacy := lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(), lnwire.Features,
	)

	errBuffer, err := queue.NewCircularBuffer(ErrorBufferSize)
	if err != nil {
		return nil, err
	}

	writeBufferPool := pool.NewWriteBuffer(
		pool.DefaultWriteBufferGCInterval,
		pool.DefaultWriteBufferExpiryInterval,
	)
	writePool := pool.NewWrite(
		writeBufferPool, 1, timeout,
	)
	if err := writePool.Start(); err != nil {
		return nil, err
	}

	readBufferPool := pool.NewReadBuffer(
		pool.DefaultReadBufferGCInterval,
		pool.DefaultReadBufferExpiryInterval,
	)
	readPool := pool.NewRead(
		readBufferPool, 1, timeout,
	)
	if err := readPool.Start(); err != nil {
		return nil, err
	}

	chainIO := &mock.ChainIO{}

	estimator := chainfee.NewStaticEstimator(12500, 0)

	wallet := &lnwallet.LightningWallet{
		WalletController: &mock.WalletController{
			RootKey:               alicePriv,
			PublishedTransactions: publTx,
		},
	}

	chanNotifier := channelnotifier.New(aliceDb)
	if err := chanNotifier.Start(); err != nil {
		return nil, err
	}

	disconnect := func(_ *btcec.PublicKey) error { return nil }

	genAnn := func(_ bool, _ ...netann.NodeAnnModifier) (
		lnwire.NodeAnnouncement, error) {
		return lnwire.NodeAnnouncement{}, nil
	}

	prunePeer := func([33]byte) {}

	fetchUpdate := func(_ lnwire.ShortChannelID) (*lnwire.ChannelUpdate,
		error) {
		return &lnwire.ChannelUpdate{}, nil
	}

	interceptSwitch := htlcswitch.NewInterceptableSwitch(nil)

	cfg := &Config{
		Conn:                          conn,
		PubKeyBytes:                   bobSerPub,
		Addr:                          bobNetAddr,
		Features:                      features,
		LegacyFeatures:                legacy,
		ChanActiveTimeout:             time.Hour,
		ErrorBuffer:                   errBuffer,
		WritePool:                     writePool,
		ReadPool:                      readPool,
		Switch:                        newMockMessageSwitch(),
		InterceptSwitch:               interceptSwitch,
		ChannelDB:                     aliceDb,
		ChannelGraph:                  newMockChannelGraph(),
		ChainArb:                      newMockChainArb(),
		AuthGossiper:                  newMockGossiper(),
		ChanStatusMgr:                 newMockStatusMgr(),
		ChainIO:                       chainIO,
		FeeEstimator:                  estimator,
		Signer:                        aliceSigner,
		SigPool:                       alicePool,
		Wallet:                        wallet,
		ChainNotifier:                 notifier,
		RoutingPolicy:                 htlcswitch.ForwardingPolicy{},
		Sphinx:                        newMockSphinx(),
		ChannelNotifier:               chanNotifier,
		DisconnectPeer:                disconnect,
		GenNodeAnnouncement:           genAnn,
		PrunePersistentPeerConnection: prunePeer,
		FetchLastChanUpdate:           fetchUpdate,
		FundingManager:                newMockFunding(),
		Hodl:                          &hodl.Config{},
		ServerPubKey:                  aliceSerPub,
		Quit:                          make(chan struct{}),
	}

	return cfg, nil
}

// createTestChannels makes two test channels for alice, bob.
func createTestChannels(update func(a, b *channeldb.OpenChannel),
	alicePriv, bobPriv *btcec.PrivateKey, alicePub,
	bobPub *btcec.PublicKey, aliceDb, bobDb *channeldb.DB,
	estimator chainfee.Estimator, bobSigner input.Signer,
	bobSigPool *lnwallet.SigPool, tweak bool) (*channeldb.OpenChannel,
	*lnwallet.LightningChannel, error) {

	channelCapacity := btcutil.Amount(10 * 1e8)
	channelBal := channelCapacity / 2
	dustLimit := btcutil.Amount(1300)
	csvTimeout := uint32(5)

	prevOut := &wire.OutPoint{
		Hash:  channels.TestHdSeed,
		Index: 0,
	}
	fundingTxIn := wire.NewTxIn(prevOut, nil, nil)

	aliceCfg := channeldb.ChannelConfig{
		ChannelConstraints: channeldb.ChannelConstraints{
			DustLimit:        dustLimit,
			MaxPendingAmount: lnwire.MilliSatoshi(rand.Int63()),
			ChanReserve:      btcutil.Amount(rand.Int63()),
			MinHTLC:          lnwire.MilliSatoshi(rand.Int63()),
			MaxAcceptedHtlcs: uint16(rand.Int31()),
			CsvDelay:         uint16(csvTimeout),
		},
		MultiSigKey:         keychain.KeyDescriptor{PubKey: alicePub},
		RevocationBasePoint: keychain.KeyDescriptor{PubKey: alicePub},
		PaymentBasePoint:    keychain.KeyDescriptor{PubKey: alicePub},
		DelayBasePoint:      keychain.KeyDescriptor{PubKey: alicePub},
		HtlcBasePoint:       keychain.KeyDescriptor{PubKey: alicePub},
	}
	bobCfg := channeldb.ChannelConfig{
		ChannelConstraints: channeldb.ChannelConstraints{
			DustLimit:        dustLimit,
			MaxPendingAmount: lnwire.MilliSatoshi(rand.Int63()),
			ChanReserve:      btcutil.Amount(rand.Int63()),
			MinHTLC:          lnwire.MilliSatoshi(rand.Int63()),
			MaxAcceptedHtlcs: uint16(rand.Int31()),
			CsvDelay:         uint16(csvTimeout),
		},
		MultiSigKey:         keychain.KeyDescriptor{PubKey: bobPub},
		RevocationBasePoint: keychain.KeyDescriptor{PubKey: bobPub},
		PaymentBasePoint:    keychain.KeyDescriptor{PubKey: bobPub},
		DelayBasePoint:      keychain.KeyDescriptor{PubKey: bobPub},
		HtlcBasePoint:       keychain.KeyDescriptor{PubKey: bobPub},
	}

	aliceRoot, err := chainhash.NewHash(alicePriv.Serialize())
	if err != nil {
		return nil, nil, err
	}
	alicePreimageProducer := shachain.NewRevocationProducer(*aliceRoot)
	aliceFirstRevoke, err := alicePreimageProducer.AtIndex(0)
	if err != nil {
		return nil, nil, err
	}
	aliceCommitPoint := input.ComputeCommitmentPoint(aliceFirstRevoke[:])

	bobRoot, err := chainhash.NewHash(bobPriv.Serialize())
	if err != nil {
		return nil, nil, err
	}
	bobPreimageProducer := shachain.NewRevocationProducer(*bobRoot)
	bobFirstRevoke, err := bobPreimageProducer.AtIndex(0)
	if err != nil {
		return nil, nil, err
	}
	bobCommitPoint := input.ComputeCommitmentPoint(bobFirstRevoke[:])

	aliceCommitTx, bobCommitTx, err := lnwallet.CreateCommitmentTxns(
		channelBal, channelBal, &aliceCfg, &bobCfg, aliceCommitPoint,
		bobCommitPoint, *fundingTxIn,
		channeldb.SingleFunderTweaklessBit,
	)
	if err != nil {
		return nil, nil, err
	}

	feePerKw, err := estimator.EstimateFeePerKW(1)
	if err != nil {
		return nil, nil, err
	}

	aliceCommit := channeldb.ChannelCommitment{
		CommitHeight:  0,
		LocalBalance:  lnwire.NewMSatFromSatoshis(channelBal),
		RemoteBalance: lnwire.NewMSatFromSatoshis(channelBal),
		FeePerKw:      btcutil.Amount(feePerKw),
		CommitFee:     feePerKw.FeeForWeight(input.CommitWeight),
		CommitTx:      aliceCommitTx,
		CommitSig:     bytes.Repeat([]byte{1}, 71),
	}
	bobCommit := channeldb.ChannelCommitment{
		CommitHeight:  0,
		LocalBalance:  lnwire.NewMSatFromSatoshis(channelBal),
		RemoteBalance: lnwire.NewMSatFromSatoshis(channelBal),
		FeePerKw:      btcutil.Amount(feePerKw),
		CommitFee:     feePerKw.FeeForWeight(input.CommitWeight),
		CommitTx:      bobCommitTx,
		CommitSig:     bytes.Repeat([]byte{1}, 71),
	}

	var chanIDBytes [8]byte
	if _, err := io.ReadFull(crand.Reader, chanIDBytes[:]); err != nil {
		return nil, nil, err
	}

	shortChanID := lnwire.NewShortChanIDFromInt(
		binary.BigEndian.Uint64(chanIDBytes[:]),
	)

	chanType := channeldb.SingleFunderTweaklessBit
	if tweak {
		chanType = channeldb.SingleFunderBit
	}

	alicePackager := channeldb.NewChannelPackager(shortChanID)
	bobPackager := channeldb.NewChannelPackager(shortChanID)

	aliceChannelState := &channeldb.OpenChannel{
		LocalChanCfg:            aliceCfg,
		RemoteChanCfg:           bobCfg,
		IdentityPub:             bobPub,
		FundingOutpoint:         *prevOut,
		ShortChannelID:          shortChanID,
		ChanType:                chanType,
		IsInitiator:             true,
		Capacity:                channelCapacity,
		RemoteCurrentRevocation: bobCommitPoint,
		RevocationProducer:      alicePreimageProducer,
		RevocationStore:         shachain.NewRevocationStore(),
		LocalCommitment:         aliceCommit,
		RemoteCommitment:        bobCommit,
		Db:                      aliceDb,
		Packager:                alicePackager,
		FundingTxn:              channels.TestFundingTx,
	}
	bobChannelState := &channeldb.OpenChannel{
		LocalChanCfg:            bobCfg,
		RemoteChanCfg:           aliceCfg,
		IdentityPub:             alicePub,
		FundingOutpoint:         *prevOut,
		ChanType:                chanType,
		IsInitiator:             false,
		Capacity:                channelCapacity,
		RemoteCurrentRevocation: aliceCommitPoint,
		RevocationProducer:      bobPreimageProducer,
		RevocationStore:         shachain.NewRevocationStore(),
		LocalCommitment:         bobCommit,
		RemoteCommitment:        aliceCommit,
		Db:                      bobDb,
		Packager:                bobPackager,
	}

	update(aliceChannelState, bobChannelState)

	if err := aliceChannelState.SyncPending(aliceAddr, 0); err != nil {
		return nil, nil, err
	}

	if err := bobChannelState.SyncPending(bobAddr, 0); err != nil {
		return nil, nil, err
	}

	bobChannel, err := lnwallet.NewLightningChannel(
		bobSigner, bobChannelState, bobSigPool,
	)
	if err != nil {
		return nil, nil, err
	}

	return aliceChannelState, bobChannel, nil
}

// noUpdate is a function which can be used as a parameter in
// createTestChannels to call the setup code with no custom values on the
// channels set up.
var noUpdate = func(a, b *channeldb.OpenChannel) {}

type mockMessageLink struct {
	cid     lnwire.ChannelID
	cfg     htlcswitch.ChannelLinkConfig
	channel *lnwallet.LightningChannel
}

// newMockMessageLink makes a mockMessageLink from a ChannelID.
func newMockMessageLink(linkCfg htlcswitch.ChannelLinkConfig,
	lnChan *lnwallet.LightningChannel,
	cid lnwire.ChannelID) *mockMessageLink {

	messageLink := &mockMessageLink{
		cid:     cid,
		cfg:     linkCfg,
		channel: lnChan,
	}

	return messageLink
}

// ChanID returns the mockMessageLink's ChannelID.
func (l *mockMessageLink) ChanID() lnwire.ChannelID {
	return l.cid
}

// HandleChannelUpdate currently does nothing.
func (l *mockMessageLink) HandleChannelUpdate(msg lnwire.Message) {}

// start begins the message-processing part of the mockMessageLink.
func (l *mockMessageLink) start() {
	l.cfg.NotifyActiveLink(l.channel.State().FundingOutpoint)
}

type mockMessageSwitch struct {
	linkIndex map[lnwire.ChannelID]*mockMessageLink
}

// newMockMessageSwitch creates a new *mockMessageSwitch.
func newMockMessageSwitch() *mockMessageSwitch {
	messageSwitch := &mockMessageSwitch{
		linkIndex: make(map[lnwire.ChannelID]*mockMessageLink),
	}

	return messageSwitch
}

// BestHeight returns 0 since it is unused in testing.
func (s *mockMessageSwitch) BestHeight() uint32 {
	return 0
}

// CircuitModifier returns nil since it is unused in testing.
func (s *mockMessageSwitch) CircuitModifier() htlcswitch.CircuitModifier {
	return nil
}

// GetLink retrieves a *mockMessageLink from linkIndex given a ChannelID.
func (s *mockMessageSwitch) GetLink(cid lnwire.ChannelID) (MessageLink,
	error) {

	messageLink := s.linkIndex[cid]
	return messageLink, nil
}

// InitLink starts a *mockMessageLink and adds it to linkIndex.
func (s *mockMessageSwitch) InitLink(linkCfg htlcswitch.ChannelLinkConfig,
	lnChan *lnwallet.LightningChannel) error {

	cid := lnwire.NewChanIDFromOutPoint(&lnChan.State().FundingOutpoint)
	messageLink := newMockMessageLink(linkCfg, lnChan, cid)
	messageLink.start()
	s.linkIndex[cid] = messageLink
	return nil
}

// RemoveLink stops and removes a *mockMessageLink given its ChannelID.
func (s *mockMessageSwitch) RemoveLink(cid lnwire.ChannelID) {
	messageLink := s.linkIndex[cid]
	if messageLink == nil {
		return
	}

	delete(s.linkIndex, cid)
}

type mockChannelGraph struct{}

// newMockChannelGraph returns an instance of *mockChannelGraph.
func newMockChannelGraph() *mockChannelGraph { return &mockChannelGraph{} }

// FetchChannelEdgesByOutpoint currently returns nil for all values.
func (g *mockChannelGraph) FetchChannelEdgesByOutpoint(_ *wire.OutPoint) (
	*channeldb.ChannelEdgeInfo, *channeldb.ChannelEdgePolicy,
	*channeldb.ChannelEdgePolicy, error) {

	return nil, nil, nil, nil
}

type mockStatusMgr struct{}

// newMockStatusMgr returns an instance of *mockStatusMgr.
func newMockStatusMgr() *mockStatusMgr { return &mockStatusMgr{} }

// RequestEnable returns nil.
func (s *mockStatusMgr) RequestEnable(_ wire.OutPoint, _ bool) error {
	return nil
}

// RequestDisable returns nil.
func (s *mockStatusMgr) RequestDisable(_ wire.OutPoint, _ bool) error {
	return nil
}

type mockChainArb struct{}

// newMockChainArb returns an instance of *mockChainArb.
func newMockChainArb() *mockChainArb { return &mockChainArb{} }

// SubscribeChannelEvents returns nil values.
func (c *mockChainArb) SubscribeChannelEvents(_ wire.OutPoint) (
	*contractcourt.ChainEventSubscription, error) {

	return nil, nil
}

// UpdateContractSignals returns nil.
func (c *mockChainArb) UpdateContractSignals(_ wire.OutPoint,
	_ *contractcourt.ContractSignals) error {

	return nil
}

// ForceCloseContract currently returns an error.
func (c *mockChainArb) ForceCloseContract(_ wire.OutPoint) (*wire.MsgTx,
	error) {

	return nil, fmt.Errorf("could not force close channel")
}

type mockSphinx struct{}

// newMockSphinx returns an instance of *mockSphinx.
func newMockSphinx() *mockSphinx { return &mockSphinx{} }

// DecodeHopIterators returns nil values.
func (s *mockSphinx) DecodeHopIterators(_ []byte,
	_ []hop.DecodeHopIteratorRequest) ([]hop.DecodeHopIteratorResponse,
	error) {

	return nil, nil
}

// ExtractErrorEncrypter returns nil values.
func (s *mockSphinx) ExtractErrorEncrypter(_ *btcec.PublicKey) (
	hop.ErrorEncrypter, lnwire.FailCode) {

	return nil, 0
}

type mockGossiper struct{}

// newMockGossiper returns an instance of *mockGossiper.
func newMockGossiper() *mockGossiper { return &mockGossiper{} }

// InitSyncState currently does nothing.
func (g *mockGossiper) InitSyncState(_ lnpeer.Peer) {}

// ProcessRemoteAnnouncement currently does nothing.
func (g *mockGossiper) ProcessRemoteAnnouncement(_ lnwire.Message,
	_ lnpeer.Peer) chan error {

	return make(chan error)
}

type mockFunding struct{}

// newMockFunding returns an instance of *mockFunding.
func newMockFunding() *mockFunding { return &mockFunding{} }

// ProcessFundingMsg currently does nothing.
func (f *mockFunding) ProcessFundingMsg(_ lnwire.Message, _ lnpeer.Peer) {}

// IsPendingChannel currently returns false.
func (f *mockFunding) IsPendingChannel(_ [32]byte, _ lnpeer.Peer) bool {
	return false
}

// pushMessage pushes an lnwire.Message to the MockPeer.
func pushMessage(p *wtmock.MockPeer, msg lnwire.Message) error {
	var b bytes.Buffer
	if _, err := lnwire.WriteMessage(&b, msg, 0); err != nil {
		return err
	}

	select {
	case p.IncomingMsgs <- b.Bytes():
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("failed pushing message: %v", msg)
	}
}

// getMessage retrieves a message from the MockPeer.
func getMessage(p *wtmock.MockPeer) (lnwire.Message, error) {
	select {
	case msgBytes := <-p.OutgoingMsgs:
		r := bytes.NewReader(msgBytes)
		msg, err := lnwire.ReadMessage(r, 0)
		if err != nil {
			return nil, err
		}

		return msg, nil

	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting to retrieve message")
	}
}
