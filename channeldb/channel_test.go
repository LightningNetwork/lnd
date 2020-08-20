package channeldb

import (
	"bytes"
	"math/rand"
	"net"
	"reflect"
	"runtime"
	"testing"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
)

var (
	key = [chainhash.HashSize]byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x68, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x93, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xf9, 0x9e, 0xc5, 0x8c, 0xe9,
	}
	rev = [chainhash.HashSize]byte{
		0x51, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x48, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0x2d, 0xe7, 0x93, 0xe4,
	}
	testTx = &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte{0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62},
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 5000000000,
				PkScript: []byte{
					0x41, // OP_DATA_65
					0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
					0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
					0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
					0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
					0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
					0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
					0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
					0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
					0xa6, // 65-byte signature
					0xac, // OP_CHECKSIG
				},
			},
		},
		LockTime: 5,
	}
	privKey, pubKey = btcec.PrivKeyFromBytes(btcec.S256(), key[:])

	wireSig, _ = lnwire.NewSigFromSignature(testSig)

	testClock = clock.NewTestClock(testNow)

	// defaultPendingHeight is the default height at which we set
	// channels to pending.
	defaultPendingHeight = 100

	// defaultAddr is the default address that we mark test channels pending
	// with.
	defaultAddr = &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 18555,
	}
)

// testChannelParams is a struct which details the specifics of how a channel
// should be created.
type testChannelParams struct {
	// channel is the channel that will be written to disk.
	channel *OpenChannel

	// addr is the address that the channel will be synced pending with.
	addr *net.TCPAddr

	// pendingHeight is the height that the channel should be recorded as
	// pending.
	pendingHeight uint32

	// openChannel is set to true if the channel should be fully marked as
	// open if this is false, the channel will be left in pending state.
	openChannel bool
}

// testChannelOption is a functional option which can be used to alter the
// default channel that is creates for testing.
type testChannelOption func(params *testChannelParams)

// channelCommitmentOption is an option which allows overwriting of the default
// commitment height and balances. The local boolean can be used to set these
// balances on the local or remote commit.
func channelCommitmentOption(height uint64, localBalance,
	remoteBalance lnwire.MilliSatoshi, local bool) testChannelOption {

	return func(params *testChannelParams) {
		if local {
			params.channel.LocalCommitment.CommitHeight = height
			params.channel.LocalCommitment.LocalBalance = localBalance
			params.channel.LocalCommitment.RemoteBalance = remoteBalance
		} else {
			params.channel.RemoteCommitment.CommitHeight = height
			params.channel.RemoteCommitment.LocalBalance = localBalance
			params.channel.RemoteCommitment.RemoteBalance = remoteBalance
		}
	}
}

// pendingHeightOption is an option which can be used to set the height the
// channel is marked as pending at.
func pendingHeightOption(height uint32) testChannelOption {
	return func(params *testChannelParams) {
		params.pendingHeight = height
	}
}

// openChannelOption is an option which can be used to create a test channel
// that is open.
func openChannelOption() testChannelOption {
	return func(params *testChannelParams) {
		params.openChannel = true
	}
}

// localHtlcsOption is an option which allows setting of htlcs on the local
// commitment.
func localHtlcsOption(htlcs []HTLC) testChannelOption {
	return func(params *testChannelParams) {
		params.channel.LocalCommitment.Htlcs = htlcs
	}
}

// remoteHtlcsOption is an option which allows setting of htlcs on the remote
// commitment.
func remoteHtlcsOption(htlcs []HTLC) testChannelOption {
	return func(params *testChannelParams) {
		params.channel.RemoteCommitment.Htlcs = htlcs
	}
}

// localShutdownOption is an option which sets the local upfront shutdown
// script for the channel.
func localShutdownOption(addr lnwire.DeliveryAddress) testChannelOption {
	return func(params *testChannelParams) {
		params.channel.LocalShutdownScript = addr
	}
}

// remoteShutdownOption is an option which sets the remote upfront shutdown
// script for the channel.
func remoteShutdownOption(addr lnwire.DeliveryAddress) testChannelOption {
	return func(params *testChannelParams) {
		params.channel.RemoteShutdownScript = addr
	}
}

// fundingPointOption is an option which sets the funding outpoint of the
// channel.
func fundingPointOption(chanPoint wire.OutPoint) testChannelOption {
	return func(params *testChannelParams) {
		params.channel.FundingOutpoint = chanPoint
	}
}

// channelIDOption is an option which sets the short channel ID of the channel.
var channelIDOption = func(chanID lnwire.ShortChannelID) testChannelOption {
	return func(params *testChannelParams) {
		params.channel.ShortChannelID = chanID
	}
}

// createTestChannel writes a test channel to the database. It takes a set of
// functional options which can be used to overwrite the default of creating
// a pending channel that was broadcast at height 100.
func createTestChannel(t *testing.T, cdb *DB,
	opts ...testChannelOption) *OpenChannel {

	// Create a default set of parameters.
	params := &testChannelParams{
		channel:       createTestChannelState(t, cdb),
		addr:          defaultAddr,
		openChannel:   false,
		pendingHeight: uint32(defaultPendingHeight),
	}

	// Apply all functional options to the test channel params.
	for _, o := range opts {
		o(params)
	}

	// Mark the channel as pending.
	err := params.channel.SyncPending(params.addr, params.pendingHeight)
	if err != nil {
		t.Fatalf("unable to save and serialize channel "+
			"state: %v", err)
	}

	// If the parameters do not specify that we should open the channel
	// fully, we return the pending channel.
	if !params.openChannel {
		return params.channel
	}

	// Mark the channel as open with the short channel id provided.
	err = params.channel.MarkAsOpen(params.channel.ShortChannelID)
	if err != nil {
		t.Fatalf("unable to mark channel open: %v", err)
	}

	return params.channel
}

func createTestChannelState(t *testing.T, cdb *DB) *OpenChannel {
	// Simulate 1000 channel updates.
	producer, err := shachain.NewRevocationProducerFromBytes(key[:])
	if err != nil {
		t.Fatalf("could not get producer: %v", err)
	}
	store := shachain.NewRevocationStore()
	for i := 0; i < 1; i++ {
		preImage, err := producer.AtIndex(uint64(i))
		if err != nil {
			t.Fatalf("could not get "+
				"preimage: %v", err)
		}

		if err := store.AddNextEntry(preImage); err != nil {
			t.Fatalf("could not add entry: %v", err)
		}
	}

	localCfg := ChannelConfig{
		ChannelConstraints: ChannelConstraints{
			DustLimit:        btcutil.Amount(rand.Int63()),
			MaxPendingAmount: lnwire.MilliSatoshi(rand.Int63()),
			ChanReserve:      btcutil.Amount(rand.Int63()),
			MinHTLC:          lnwire.MilliSatoshi(rand.Int63()),
			MaxAcceptedHtlcs: uint16(rand.Int31()),
			CsvDelay:         uint16(rand.Int31()),
		},
		MultiSigKey: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
		},
		RevocationBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
		},
		PaymentBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
		},
		DelayBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
		},
		HtlcBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
		},
	}
	remoteCfg := ChannelConfig{
		ChannelConstraints: ChannelConstraints{
			DustLimit:        btcutil.Amount(rand.Int63()),
			MaxPendingAmount: lnwire.MilliSatoshi(rand.Int63()),
			ChanReserve:      btcutil.Amount(rand.Int63()),
			MinHTLC:          lnwire.MilliSatoshi(rand.Int63()),
			MaxAcceptedHtlcs: uint16(rand.Int31()),
			CsvDelay:         uint16(rand.Int31()),
		},
		MultiSigKey: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyMultiSig,
				Index:  9,
			},
		},
		RevocationBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyRevocationBase,
				Index:  8,
			},
		},
		PaymentBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyPaymentBase,
				Index:  7,
			},
		},
		DelayBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyDelayBase,
				Index:  6,
			},
		},
		HtlcBasePoint: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyHtlcBase,
				Index:  5,
			},
		},
	}

	shortChanID := lnwire.NewShortChanIDFromInt(uint64(rand.Int63()))
	fundingOutpoint := wire.OutPoint{Hash: key, Index: rand.Uint32()}
	chanID := lnwire.NewChanIDFromOutPoint(&fundingOutpoint)

	return &OpenChannel{
		ChanType:          SingleFunderBit | FrozenBit,
		ChainHash:         key,
		FundingOutpoint:   fundingOutpoint,
		ShortChannelID:    shortChanID,
		IsInitiator:       true,
		IsPending:         true,
		IdentityPub:       pubKey,
		Capacity:          btcutil.Amount(10000),
		LocalChanCfg:      localCfg,
		RemoteChanCfg:     remoteCfg,
		TotalMSatSent:     8,
		TotalMSatReceived: 2,
		LocalCommitment: ChannelCommitment{
			CommitHeight:  0,
			LocalBalance:  lnwire.MilliSatoshi(9000),
			RemoteBalance: lnwire.MilliSatoshi(3000),
			CommitFee:     btcutil.Amount(rand.Int63()),
			FeePerKw:      btcutil.Amount(5000),
			CommitTx:      testTx,
			CommitSig:     bytes.Repeat([]byte{1}, 71),
		},
		RemoteCommitment: ChannelCommitment{
			CommitHeight:  0,
			LocalBalance:  lnwire.MilliSatoshi(3000),
			RemoteBalance: lnwire.MilliSatoshi(9000),
			CommitFee:     btcutil.Amount(rand.Int63()),
			FeePerKw:      btcutil.Amount(5000),
			CommitTx:      testTx,
			CommitSig:     bytes.Repeat([]byte{1}, 71),
		},
		NumConfsRequired:        4,
		RemoteCurrentRevocation: privKey.PubKey(),
		RemoteNextRevocation:    privKey.PubKey(),
		RevocationProducer:      producer,
		RevocationStore:         store,
		Db:                      cdb,
		Packager:                NewChannelPackager(chanID),
		FundingTxn:              testTx,
		ThawHeight:              uint32(defaultPendingHeight),
	}
}

func TestOpenChannelPutGetDelete(t *testing.T) {
	t.Parallel()

	cdb, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v", err)
	}
	defer cleanUp()

	// Create the test channel state, with additional htlcs on the local
	// and remote commitment.
	localHtlcs := []HTLC{
		{Signature: testSig.Serialize(),
			Incoming:      true,
			Amt:           10,
			RHash:         key,
			RefundTimeout: 1,
			OnionBlob:     []byte("onionblob"),
		},
	}

	remoteHtlcs := []HTLC{
		{
			Signature:     testSig.Serialize(),
			Incoming:      false,
			Amt:           10,
			RHash:         key,
			RefundTimeout: 1,
			OnionBlob:     []byte("onionblob"),
		},
	}

	state := createTestChannel(
		t, cdb,
		remoteHtlcsOption(remoteHtlcs),
		localHtlcsOption(localHtlcs),
	)

	openChannels, err := cdb.FetchOpenChannels(state.IdentityPub)
	if err != nil {
		t.Fatalf("unable to fetch open channel: %v", err)
	}

	newState := openChannels[0]

	// The decoded channel state should be identical to what we stored
	// above.
	if !reflect.DeepEqual(state, newState) {
		t.Fatalf("channel state doesn't match:: %v vs %v",
			spew.Sdump(state), spew.Sdump(newState))
	}

	// We'll also test that the channel is properly able to hot swap the
	// next revocation for the state machine. This tests the initial
	// post-funding revocation exchange.
	nextRevKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("unable to create new private key: %v", err)
	}
	if err := state.InsertNextRevocation(nextRevKey.PubKey()); err != nil {
		t.Fatalf("unable to update revocation: %v", err)
	}

	openChannels, err = cdb.FetchOpenChannels(state.IdentityPub)
	if err != nil {
		t.Fatalf("unable to fetch open channel: %v", err)
	}
	updatedChan := openChannels[0]

	// Ensure that the revocation was set properly.
	if !nextRevKey.PubKey().IsEqual(updatedChan.RemoteNextRevocation) {
		t.Fatalf("next revocation wasn't updated")
	}

	// Finally to wrap up the test, delete the state of the channel within
	// the database. This involves "closing" the channel which removes all
	// written state, and creates a small "summary" elsewhere within the
	// database.
	closeSummary := &ChannelCloseSummary{
		ChanPoint:         state.FundingOutpoint,
		RemotePub:         state.IdentityPub,
		SettledBalance:    btcutil.Amount(500),
		TimeLockedBalance: btcutil.Amount(10000),
		IsPending:         false,
		CloseType:         CooperativeClose,
	}
	if err := state.CloseChannel(closeSummary); err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	// As the channel is now closed, attempting to fetch all open channels
	// for our fake node ID should return an empty slice.
	openChans, err := cdb.FetchOpenChannels(state.IdentityPub)
	if err != nil {
		t.Fatalf("unable to fetch open channels: %v", err)
	}
	if len(openChans) != 0 {
		t.Fatalf("all channels not deleted, found %v", len(openChans))
	}

	// Additionally, attempting to fetch all the open channels globally
	// should yield no results.
	openChans, err = cdb.FetchAllChannels()
	if err != nil {
		t.Fatal("unable to fetch all open chans")
	}
	if len(openChans) != 0 {
		t.Fatalf("all channels not deleted, found %v", len(openChans))
	}
}

// TestOptionalShutdown tests the reading and writing of channels with and
// without optional shutdown script fields.
func TestOptionalShutdown(t *testing.T) {
	local := lnwire.DeliveryAddress([]byte("local shutdown script"))
	remote := lnwire.DeliveryAddress([]byte("remote shutdown script"))

	if _, err := rand.Read(remote); err != nil {
		t.Fatalf("Could not create random script: %v", err)
	}

	tests := []struct {
		name           string
		localShutdown  lnwire.DeliveryAddress
		remoteShutdown lnwire.DeliveryAddress
	}{
		{
			name:           "no shutdown scripts",
			localShutdown:  nil,
			remoteShutdown: nil,
		},
		{
			name:           "local shutdown script",
			localShutdown:  local,
			remoteShutdown: nil,
		},
		{
			name:           "remote shutdown script",
			localShutdown:  nil,
			remoteShutdown: remote,
		},
		{
			name:           "both scripts set",
			localShutdown:  local,
			remoteShutdown: remote,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			cdb, cleanUp, err := MakeTestDB()
			if err != nil {
				t.Fatalf("unable to make test database: %v", err)
			}
			defer cleanUp()

			// Create a channel with upfront scripts set as
			// specified in the test.
			state := createTestChannel(
				t, cdb,
				localShutdownOption(test.localShutdown),
				remoteShutdownOption(test.remoteShutdown),
			)

			openChannels, err := cdb.FetchOpenChannels(
				state.IdentityPub,
			)
			if err != nil {
				t.Fatalf("unable to fetch open"+
					" channel: %v", err)
			}

			if len(openChannels) != 1 {
				t.Fatalf("Expected one channel open,"+
					" got: %v", len(openChannels))
			}

			if !bytes.Equal(openChannels[0].LocalShutdownScript,
				test.localShutdown) {

				t.Fatalf("Expected local: %x, got: %x",
					test.localShutdown,
					openChannels[0].LocalShutdownScript)
			}

			if !bytes.Equal(openChannels[0].RemoteShutdownScript,
				test.remoteShutdown) {

				t.Fatalf("Expected remote: %x, got: %x",
					test.remoteShutdown,
					openChannels[0].RemoteShutdownScript)
			}
		})
	}
}

func assertCommitmentEqual(t *testing.T, a, b *ChannelCommitment) {
	if !reflect.DeepEqual(a, b) {
		_, _, line, _ := runtime.Caller(1)
		t.Fatalf("line %v: commitments don't match: %v vs %v",
			line, spew.Sdump(a), spew.Sdump(b))
	}
}

func TestChannelStateTransition(t *testing.T) {
	t.Parallel()

	cdb, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v", err)
	}
	defer cleanUp()

	// First create a minimal channel, then perform a full sync in order to
	// persist the data.
	channel := createTestChannel(t, cdb)

	// Add some HTLCs which were added during this new state transition.
	// Half of the HTLCs are incoming, while the other half are outgoing.
	var (
		htlcs   []HTLC
		htlcAmt lnwire.MilliSatoshi
	)
	for i := uint32(0); i < 10; i++ {
		var incoming bool
		if i > 5 {
			incoming = true
		}
		htlc := HTLC{
			Signature:     testSig.Serialize(),
			Incoming:      incoming,
			Amt:           10,
			RHash:         key,
			RefundTimeout: i,
			OutputIndex:   int32(i * 3),
			LogIndex:      uint64(i * 2),
			HtlcIndex:     uint64(i),
		}
		htlc.OnionBlob = make([]byte, 10)
		copy(htlc.OnionBlob[:], bytes.Repeat([]byte{2}, 10))
		htlcs = append(htlcs, htlc)
		htlcAmt += htlc.Amt
	}

	// Create a new channel delta which includes the above HTLCs, some
	// balance updates, and an increment of the current commitment height.
	// Additionally, modify the signature and commitment transaction.
	newSequence := uint32(129498)
	newSig := bytes.Repeat([]byte{3}, 71)
	newTx := channel.LocalCommitment.CommitTx.Copy()
	newTx.TxIn[0].Sequence = newSequence
	commitment := ChannelCommitment{
		CommitHeight:    1,
		LocalLogIndex:   2,
		LocalHtlcIndex:  1,
		RemoteLogIndex:  2,
		RemoteHtlcIndex: 1,
		LocalBalance:    lnwire.MilliSatoshi(1e8),
		RemoteBalance:   lnwire.MilliSatoshi(1e8),
		CommitFee:       55,
		FeePerKw:        99,
		CommitTx:        newTx,
		CommitSig:       newSig,
		Htlcs:           htlcs,
	}

	// First update the local node's broadcastable state and also add a
	// CommitDiff remote node's as well in order to simulate a proper state
	// transition.
	unsignedAckedUpdates := []LogUpdate{
		{
			LogIndex: 2,
			UpdateMsg: &lnwire.UpdateAddHTLC{
				ChanID: lnwire.ChannelID{1, 2, 3},
			},
		},
	}

	err = channel.UpdateCommitment(&commitment, unsignedAckedUpdates)
	if err != nil {
		t.Fatalf("unable to update commitment: %v", err)
	}

	// Assert that update is correctly written to the database.
	dbUnsignedAckedUpdates, err := channel.UnsignedAckedUpdates()
	if err != nil {
		t.Fatalf("unable to fetch dangling remote updates: %v", err)
	}
	if len(dbUnsignedAckedUpdates) != 1 {
		t.Fatalf("unexpected number of dangling remote updates")
	}
	if !reflect.DeepEqual(
		dbUnsignedAckedUpdates[0], unsignedAckedUpdates[0],
	) {
		t.Fatalf("unexpected update")
	}

	// The balances, new update, the HTLCs and the changes to the fake
	// commitment transaction along with the modified signature should all
	// have been updated.
	updatedChannel, err := cdb.FetchOpenChannels(channel.IdentityPub)
	if err != nil {
		t.Fatalf("unable to fetch updated channel: %v", err)
	}
	assertCommitmentEqual(t, &commitment, &updatedChannel[0].LocalCommitment)
	numDiskUpdates, err := updatedChannel[0].CommitmentHeight()
	if err != nil {
		t.Fatalf("unable to read commitment height from disk: %v", err)
	}
	if numDiskUpdates != uint64(commitment.CommitHeight) {
		t.Fatalf("num disk updates doesn't match: %v vs %v",
			numDiskUpdates, commitment.CommitHeight)
	}

	// Attempting to query for a commitment diff should return
	// ErrNoPendingCommit as we haven't yet created a new state for them.
	_, err = channel.RemoteCommitChainTip()
	if err != ErrNoPendingCommit {
		t.Fatalf("expected ErrNoPendingCommit, instead got %v", err)
	}

	// To simulate us extending a new state to the remote party, we'll also
	// create a new commit diff for them.
	remoteCommit := commitment
	remoteCommit.LocalBalance = lnwire.MilliSatoshi(2e8)
	remoteCommit.RemoteBalance = lnwire.MilliSatoshi(3e8)
	remoteCommit.CommitHeight = 1
	commitDiff := &CommitDiff{
		Commitment: remoteCommit,
		CommitSig: &lnwire.CommitSig{
			ChanID:    lnwire.ChannelID(key),
			CommitSig: wireSig,
			HtlcSigs: []lnwire.Sig{
				wireSig,
				wireSig,
			},
		},
		LogUpdates: []LogUpdate{
			{
				LogIndex: 1,
				UpdateMsg: &lnwire.UpdateAddHTLC{
					ID:     1,
					Amount: lnwire.NewMSatFromSatoshis(100),
					Expiry: 25,
				},
			},
			{
				LogIndex: 2,
				UpdateMsg: &lnwire.UpdateAddHTLC{
					ID:     2,
					Amount: lnwire.NewMSatFromSatoshis(200),
					Expiry: 50,
				},
			},
		},
		OpenedCircuitKeys: []CircuitKey{},
		ClosedCircuitKeys: []CircuitKey{},
	}
	copy(commitDiff.LogUpdates[0].UpdateMsg.(*lnwire.UpdateAddHTLC).PaymentHash[:],
		bytes.Repeat([]byte{1}, 32))
	copy(commitDiff.LogUpdates[1].UpdateMsg.(*lnwire.UpdateAddHTLC).PaymentHash[:],
		bytes.Repeat([]byte{2}, 32))
	if err := channel.AppendRemoteCommitChain(commitDiff); err != nil {
		t.Fatalf("unable to add to commit chain: %v", err)
	}

	// The commitment tip should now match the commitment that we just
	// inserted.
	diskCommitDiff, err := channel.RemoteCommitChainTip()
	if err != nil {
		t.Fatalf("unable to fetch commit diff: %v", err)
	}
	if !reflect.DeepEqual(commitDiff, diskCommitDiff) {
		t.Fatalf("commit diffs don't match: %v vs %v", spew.Sdump(remoteCommit),
			spew.Sdump(diskCommitDiff))
	}

	// We'll save the old remote commitment as this will be added to the
	// revocation log shortly.
	oldRemoteCommit := channel.RemoteCommitment

	// Next, write to the log which tracks the necessary revocation state
	// needed to rectify any fishy behavior by the remote party. Modify the
	// current uncollapsed revocation state to simulate a state transition
	// by the remote party.
	channel.RemoteCurrentRevocation = channel.RemoteNextRevocation
	newPriv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	channel.RemoteNextRevocation = newPriv.PubKey()
	chanID := lnwire.NewChanIDFromOutPoint(&channel.FundingOutpoint)

	fwdPkg := NewFwdPkg(chanID, oldRemoteCommit.CommitHeight,
		diskCommitDiff.LogUpdates, nil)

	err = channel.AdvanceCommitChainTail(fwdPkg, nil)
	if err != nil {
		t.Fatalf("unable to append to revocation log: %v", err)
	}

	// At this point, the remote commit chain should be nil, and the posted
	// remote commitment should match the one we added as a diff above.
	if _, err := channel.RemoteCommitChainTip(); err != ErrNoPendingCommit {
		t.Fatalf("expected ErrNoPendingCommit, instead got %v", err)
	}

	// We should be able to fetch the channel delta created above by its
	// update number with all the state properly reconstructed.
	diskPrevCommit, err := channel.FindPreviousState(
		oldRemoteCommit.CommitHeight,
	)
	if err != nil {
		t.Fatalf("unable to fetch past delta: %v", err)
	}

	// The two deltas (the original vs the on-disk version) should
	// identical, and all HTLC data should properly be retained.
	assertCommitmentEqual(t, &oldRemoteCommit, diskPrevCommit)

	// The state number recovered from the tail of the revocation log
	// should be identical to this current state.
	logTail, err := channel.RevocationLogTail()
	if err != nil {
		t.Fatalf("unable to retrieve log: %v", err)
	}
	if logTail.CommitHeight != oldRemoteCommit.CommitHeight {
		t.Fatal("update number doesn't match")
	}

	oldRemoteCommit = channel.RemoteCommitment

	// Next modify the posted diff commitment slightly, then create a new
	// commitment diff and advance the tail.
	commitDiff.Commitment.CommitHeight = 2
	commitDiff.Commitment.LocalBalance -= htlcAmt
	commitDiff.Commitment.RemoteBalance += htlcAmt
	commitDiff.LogUpdates = []LogUpdate{}
	if err := channel.AppendRemoteCommitChain(commitDiff); err != nil {
		t.Fatalf("unable to add to commit chain: %v", err)
	}

	fwdPkg = NewFwdPkg(chanID, oldRemoteCommit.CommitHeight, nil, nil)

	err = channel.AdvanceCommitChainTail(fwdPkg, nil)
	if err != nil {
		t.Fatalf("unable to append to revocation log: %v", err)
	}

	// Once again, fetch the state and ensure it has been properly updated.
	prevCommit, err := channel.FindPreviousState(oldRemoteCommit.CommitHeight)
	if err != nil {
		t.Fatalf("unable to fetch past delta: %v", err)
	}
	assertCommitmentEqual(t, &oldRemoteCommit, prevCommit)

	// Once again, state number recovered from the tail of the revocation
	// log should be identical to this current state.
	logTail, err = channel.RevocationLogTail()
	if err != nil {
		t.Fatalf("unable to retrieve log: %v", err)
	}
	if logTail.CommitHeight != oldRemoteCommit.CommitHeight {
		t.Fatal("update number doesn't match")
	}

	// The revocation state stored on-disk should now also be identical.
	updatedChannel, err = cdb.FetchOpenChannels(channel.IdentityPub)
	if err != nil {
		t.Fatalf("unable to fetch updated channel: %v", err)
	}
	if !channel.RemoteCurrentRevocation.IsEqual(updatedChannel[0].RemoteCurrentRevocation) {
		t.Fatalf("revocation state was not synced")
	}
	if !channel.RemoteNextRevocation.IsEqual(updatedChannel[0].RemoteNextRevocation) {
		t.Fatalf("revocation state was not synced")
	}

	// Now attempt to delete the channel from the database.
	closeSummary := &ChannelCloseSummary{
		ChanPoint:         channel.FundingOutpoint,
		RemotePub:         channel.IdentityPub,
		SettledBalance:    btcutil.Amount(500),
		TimeLockedBalance: btcutil.Amount(10000),
		IsPending:         false,
		CloseType:         RemoteForceClose,
	}
	if err := updatedChannel[0].CloseChannel(closeSummary); err != nil {
		t.Fatalf("unable to delete updated channel: %v", err)
	}

	// If we attempt to fetch the target channel again, it shouldn't be
	// found.
	channels, err := cdb.FetchOpenChannels(channel.IdentityPub)
	if err != nil {
		t.Fatalf("unable to fetch updated channels: %v", err)
	}
	if len(channels) != 0 {
		t.Fatalf("%v channels, found, but none should be",
			len(channels))
	}

	// Attempting to find previous states on the channel should fail as the
	// revocation log has been deleted.
	_, err = updatedChannel[0].FindPreviousState(oldRemoteCommit.CommitHeight)
	if err == nil {
		t.Fatal("revocation log search should have failed")
	}
}

func TestFetchPendingChannels(t *testing.T) {
	t.Parallel()

	cdb, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v", err)
	}
	defer cleanUp()

	// Create a pending channel that was broadcast at height 99.
	const broadcastHeight = 99
	createTestChannel(t, cdb, pendingHeightOption(broadcastHeight))

	pendingChannels, err := cdb.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to list pending channels: %v", err)
	}

	if len(pendingChannels) != 1 {
		t.Fatalf("incorrect number of pending channels: expecting %v,"+
			"got %v", 1, len(pendingChannels))
	}

	// The broadcast height of the pending channel should have been set
	// properly.
	if pendingChannels[0].FundingBroadcastHeight != broadcastHeight {
		t.Fatalf("broadcast height mismatch: expected %v, got %v",
			pendingChannels[0].FundingBroadcastHeight,
			broadcastHeight)
	}

	chanOpenLoc := lnwire.ShortChannelID{
		BlockHeight: 5,
		TxIndex:     10,
		TxPosition:  15,
	}
	err = pendingChannels[0].MarkAsOpen(chanOpenLoc)
	if err != nil {
		t.Fatalf("unable to mark channel as open: %v", err)
	}

	if pendingChannels[0].IsPending {
		t.Fatalf("channel marked open should no longer be pending")
	}

	if pendingChannels[0].ShortChanID() != chanOpenLoc {
		t.Fatalf("channel opening height not updated: expected %v, "+
			"got %v", spew.Sdump(pendingChannels[0].ShortChanID()),
			chanOpenLoc)
	}

	// Next, we'll re-fetch the channel to ensure that the open height was
	// properly set.
	openChans, err := cdb.FetchAllChannels()
	if err != nil {
		t.Fatalf("unable to fetch channels: %v", err)
	}
	if openChans[0].ShortChanID() != chanOpenLoc {
		t.Fatalf("channel opening heights don't match: expected %v, "+
			"got %v", spew.Sdump(openChans[0].ShortChanID()),
			chanOpenLoc)
	}
	if openChans[0].FundingBroadcastHeight != broadcastHeight {
		t.Fatalf("broadcast height mismatch: expected %v, got %v",
			openChans[0].FundingBroadcastHeight,
			broadcastHeight)
	}

	pendingChannels, err = cdb.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to list pending channels: %v", err)
	}

	if len(pendingChannels) != 0 {
		t.Fatalf("incorrect number of pending channels: expecting %v,"+
			"got %v", 0, len(pendingChannels))
	}
}

func TestFetchClosedChannels(t *testing.T) {
	t.Parallel()

	cdb, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v", err)
	}
	defer cleanUp()

	// Create an open channel in the database.
	state := createTestChannel(t, cdb, openChannelOption())

	// Next, close the channel by including a close channel summary in the
	// database.
	summary := &ChannelCloseSummary{
		ChanPoint:         state.FundingOutpoint,
		ClosingTXID:       rev,
		RemotePub:         state.IdentityPub,
		Capacity:          state.Capacity,
		SettledBalance:    state.LocalCommitment.LocalBalance.ToSatoshis(),
		TimeLockedBalance: state.RemoteCommitment.LocalBalance.ToSatoshis() + 10000,
		CloseType:         RemoteForceClose,
		IsPending:         true,
		LocalChanConfig:   state.LocalChanCfg,
	}
	if err := state.CloseChannel(summary); err != nil {
		t.Fatalf("unable to close channel: %v", err)
	}

	// Query the database to ensure that the channel has now been properly
	// closed. We should get the same result whether querying for pending
	// channels only, or not.
	pendingClosed, err := cdb.FetchClosedChannels(true)
	if err != nil {
		t.Fatalf("failed fetching closed channels: %v", err)
	}
	if len(pendingClosed) != 1 {
		t.Fatalf("incorrect number of pending closed channels: expecting %v,"+
			"got %v", 1, len(pendingClosed))
	}
	if !reflect.DeepEqual(summary, pendingClosed[0]) {
		t.Fatalf("database summaries don't match: expected %v got %v",
			spew.Sdump(summary), spew.Sdump(pendingClosed[0]))
	}
	closed, err := cdb.FetchClosedChannels(false)
	if err != nil {
		t.Fatalf("failed fetching all closed channels: %v", err)
	}
	if len(closed) != 1 {
		t.Fatalf("incorrect number of closed channels: expecting %v, "+
			"got %v", 1, len(closed))
	}
	if !reflect.DeepEqual(summary, closed[0]) {
		t.Fatalf("database summaries don't match: expected %v got %v",
			spew.Sdump(summary), spew.Sdump(closed[0]))
	}

	// Mark the channel as fully closed.
	err = cdb.MarkChanFullyClosed(&state.FundingOutpoint)
	if err != nil {
		t.Fatalf("failed fully closing channel: %v", err)
	}

	// The channel should no longer be considered pending, but should still
	// be retrieved when fetching all the closed channels.
	closed, err = cdb.FetchClosedChannels(false)
	if err != nil {
		t.Fatalf("failed fetching closed channels: %v", err)
	}
	if len(closed) != 1 {
		t.Fatalf("incorrect number of closed channels: expecting %v, "+
			"got %v", 1, len(closed))
	}
	pendingClose, err := cdb.FetchClosedChannels(true)
	if err != nil {
		t.Fatalf("failed fetching channels pending close: %v", err)
	}
	if len(pendingClose) != 0 {
		t.Fatalf("incorrect number of closed channels: expecting %v, "+
			"got %v", 0, len(closed))
	}
}

// TestFetchWaitingCloseChannels ensures that the correct channels that are
// waiting to be closed are returned.
func TestFetchWaitingCloseChannels(t *testing.T) {
	t.Parallel()

	const numChannels = 2
	const broadcastHeight = 99

	// We'll start by creating two channels within our test database. One of
	// them will have their funding transaction confirmed on-chain, while
	// the other one will remain unconfirmed.
	db, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v", err)
	}
	defer cleanUp()

	channels := make([]*OpenChannel, numChannels)
	for i := 0; i < numChannels; i++ {
		// Create a pending channel in the database at the broadcast
		// height.
		channels[i] = createTestChannel(
			t, db, pendingHeightOption(broadcastHeight),
		)
	}

	// We'll only confirm the first one.
	channelConf := lnwire.ShortChannelID{
		BlockHeight: broadcastHeight + 1,
		TxIndex:     10,
		TxPosition:  15,
	}
	if err := channels[0].MarkAsOpen(channelConf); err != nil {
		t.Fatalf("unable to mark channel as open: %v", err)
	}

	// Then, we'll mark the channels as if their commitments were broadcast.
	// This would happen in the event of a force close and should make the
	// channels enter a state of waiting close.
	for _, channel := range channels {
		closeTx := wire.NewMsgTx(2)
		closeTx.AddTxIn(
			&wire.TxIn{
				PreviousOutPoint: channel.FundingOutpoint,
			},
		)

		if err := channel.MarkCommitmentBroadcasted(closeTx, true); err != nil {
			t.Fatalf("unable to mark commitment broadcast: %v", err)
		}

		// Now try to marking a coop close with a nil tx. This should
		// succeed, but it shouldn't exit when queried.
		if err = channel.MarkCoopBroadcasted(nil, true); err != nil {
			t.Fatalf("unable to mark nil coop broadcast: %v", err)
		}
		_, err := channel.BroadcastedCooperative()
		if err != ErrNoCloseTx {
			t.Fatalf("expected no closing tx error, got: %v", err)
		}

		// Finally, modify the close tx deterministically  and also mark
		// it as coop closed. Later we will test that distinct
		// transactions are returned for both coop and force closes.
		closeTx.TxIn[0].PreviousOutPoint.Index ^= 1
		if err := channel.MarkCoopBroadcasted(closeTx, true); err != nil {
			t.Fatalf("unable to mark coop broadcast: %v", err)
		}
	}

	// Now, we'll fetch all the channels waiting to be closed from the
	// database. We should expect to see both channels above, even if any of
	// them haven't had their funding transaction confirm on-chain.
	waitingCloseChannels, err := db.FetchWaitingCloseChannels()
	if err != nil {
		t.Fatalf("unable to fetch all waiting close channels: %v", err)
	}
	if len(waitingCloseChannels) != numChannels {
		t.Fatalf("expected %d channels waiting to be closed, got %d", 2,
			len(waitingCloseChannels))
	}
	expectedChannels := make(map[wire.OutPoint]struct{})
	for _, channel := range channels {
		expectedChannels[channel.FundingOutpoint] = struct{}{}
	}
	for _, channel := range waitingCloseChannels {
		if _, ok := expectedChannels[channel.FundingOutpoint]; !ok {
			t.Fatalf("expected channel %v to be waiting close",
				channel.FundingOutpoint)
		}

		chanPoint := channel.FundingOutpoint

		// Assert that the force close transaction is retrievable.
		forceCloseTx, err := channel.BroadcastedCommitment()
		if err != nil {
			t.Fatalf("Unable to retrieve commitment: %v", err)
		}

		if forceCloseTx.TxIn[0].PreviousOutPoint != chanPoint {
			t.Fatalf("expected outpoint %v, got %v",
				chanPoint,
				forceCloseTx.TxIn[0].PreviousOutPoint)
		}

		// Assert that the coop close transaction is retrievable.
		coopCloseTx, err := channel.BroadcastedCooperative()
		if err != nil {
			t.Fatalf("unable to retrieve coop close: %v", err)
		}

		chanPoint.Index ^= 1
		if coopCloseTx.TxIn[0].PreviousOutPoint != chanPoint {
			t.Fatalf("expected outpoint %v, got %v",
				chanPoint,
				coopCloseTx.TxIn[0].PreviousOutPoint)
		}
	}
}

// TestRefreshShortChanID asserts that RefreshShortChanID updates the in-memory
// state of another OpenChannel to reflect a preceding call to MarkOpen on a
// different OpenChannel.
func TestRefreshShortChanID(t *testing.T) {
	t.Parallel()

	cdb, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v", err)
	}
	defer cleanUp()

	// First create a test channel.
	state := createTestChannel(t, cdb)

	// Next, locate the pending channel with the database.
	pendingChannels, err := cdb.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to load pending channels; %v", err)
	}

	var pendingChannel *OpenChannel
	for _, channel := range pendingChannels {
		if channel.FundingOutpoint == state.FundingOutpoint {
			pendingChannel = channel
			break
		}
	}
	if pendingChannel == nil {
		t.Fatalf("unable to find pending channel with funding "+
			"outpoint=%v: %v", state.FundingOutpoint, err)
	}

	// Next, simulate the confirmation of the channel by marking it as
	// pending within the database.
	chanOpenLoc := lnwire.ShortChannelID{
		BlockHeight: 105,
		TxIndex:     10,
		TxPosition:  15,
	}

	err = state.MarkAsOpen(chanOpenLoc)
	if err != nil {
		t.Fatalf("unable to mark channel open: %v", err)
	}

	// The short_chan_id of the receiver to MarkAsOpen should reflect the
	// open location, but the other pending channel should remain unchanged.
	if state.ShortChanID() == pendingChannel.ShortChanID() {
		t.Fatalf("pending channel short_chan_ID should not have been " +
			"updated before refreshing short_chan_id")
	}

	// Now that the receiver's short channel id has been updated, check to
	// ensure that the channel packager's source has been updated as well.
	// This ensures that the packager will read and write to buckets
	// corresponding to the new short chan id, instead of the prior.
	chanID := lnwire.NewChanIDFromOutPoint(&state.FundingOutpoint)
	packagerSource := state.Packager.(*ChannelPackager).source[:]
	if !bytes.Equal(packagerSource, chanID[:]) {
		t.Fatalf("channel packager source was not updated: want %v, "+
			"got %v", chanOpenLoc,
			state.Packager.(*ChannelPackager).source)
	}

	// Now, refresh the short channel ID of the pending channel.
	err = pendingChannel.RefreshShortChanID()
	if err != nil {
		t.Fatalf("unable to refresh short_chan_id: %v", err)
	}

	// This should result in both OpenChannel's now having the same
	// ShortChanID.
	if state.ShortChanID() != pendingChannel.ShortChanID() {
		t.Fatalf("expected pending channel short_chan_id to be "+
			"refreshed: want %v, got %v", state.ShortChanID(),
			pendingChannel.ShortChanID())
	}

	// Check to ensure that this channel is no longer pending and this field
	// is up to date.
	if pendingChannel.IsPending {
		t.Fatalf("channel pending state wasn't updated: want false got true")
	}
}

// TestCloseInitiator tests the setting of close initiator statuses for
// cooperative closes and local force closes.
func TestCloseInitiator(t *testing.T) {
	tests := []struct {
		name string
		// updateChannel is called to update the channel as broadcast,
		// cooperatively or not, based on the test's requirements.
		updateChannel    func(c *OpenChannel) error
		expectedStatuses []ChannelStatus
	}{
		{
			name: "local coop close",
			// Mark the channel as cooperatively closed, initiated
			// by the local party.
			updateChannel: func(c *OpenChannel) error {
				return c.MarkCoopBroadcasted(
					&wire.MsgTx{}, true,
				)
			},
			expectedStatuses: []ChannelStatus{
				ChanStatusLocalCloseInitiator,
				ChanStatusCoopBroadcasted,
			},
		},
		{
			name: "remote coop close",
			// Mark the channel as cooperatively closed, initiated
			// by the remote party.
			updateChannel: func(c *OpenChannel) error {
				return c.MarkCoopBroadcasted(
					&wire.MsgTx{}, false,
				)
			},
			expectedStatuses: []ChannelStatus{
				ChanStatusRemoteCloseInitiator,
				ChanStatusCoopBroadcasted,
			},
		},
		{
			name: "local force close",
			// Mark the channel's commitment as broadcast with
			// local initiator.
			updateChannel: func(c *OpenChannel) error {
				return c.MarkCommitmentBroadcasted(
					&wire.MsgTx{}, true,
				)
			},
			expectedStatuses: []ChannelStatus{
				ChanStatusLocalCloseInitiator,
				ChanStatusCommitBroadcasted,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cdb, cleanUp, err := MakeTestDB()
			if err != nil {
				t.Fatalf("unable to make test database: %v",
					err)
			}
			defer cleanUp()

			// Create an open channel.
			channel := createTestChannel(
				t, cdb, openChannelOption(),
			)

			err = test.updateChannel(channel)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Lookup open channels in the database.
			dbChans, err := fetchChannels(
				cdb, pendingChannelFilter(false),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(dbChans) != 1 {
				t.Fatalf("expected 1 channel, got: %v",
					len(dbChans))
			}

			// Check that the statuses that we expect were written
			// to disk.
			for _, status := range test.expectedStatuses {
				if !dbChans[0].HasChanStatus(status) {
					t.Fatalf("expected channel to have "+
						"status: %v, has status: %v",
						status, dbChans[0].chanStatus)
				}
			}
		})
	}
}

// TestCloseChannelStatus tests setting of a channel status on the historical
// channel on channel close.
func TestCloseChannelStatus(t *testing.T) {
	cdb, cleanUp, err := MakeTestDB()
	if err != nil {
		t.Fatalf("unable to make test database: %v",
			err)
	}
	defer cleanUp()

	// Create an open channel.
	channel := createTestChannel(
		t, cdb, openChannelOption(),
	)

	if err := channel.CloseChannel(
		&ChannelCloseSummary{
			ChanPoint: channel.FundingOutpoint,
			RemotePub: channel.IdentityPub,
		}, ChanStatusRemoteCloseInitiator,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	histChan, err := channel.Db.FetchHistoricalChannel(
		&channel.FundingOutpoint,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !histChan.HasChanStatus(ChanStatusRemoteCloseInitiator) {
		t.Fatalf("channel should have status")
	}
}

// TestBalanceAtHeight tests lookup of our local and remote balance at a given
// height.
func TestBalanceAtHeight(t *testing.T) {
	const (
		// Values that will be set on our current local commit in
		// memory.
		localHeight        = 2
		localLocalBalance  = 1000
		localRemoteBalance = 1500

		// Values that will be set on our current remote commit in
		// memory.
		remoteHeight        = 3
		remoteLocalBalance  = 2000
		remoteRemoteBalance = 2500

		// Values that will be written to disk in the revocation log.
		oldHeight        = 0
		oldLocalBalance  = 200
		oldRemoteBalance = 300

		// Heights to test error cases.
		unknownHeight   = 1
		unreachedHeight = 4
	)

	// putRevokedState is a helper function used to put commitments is
	// the revocation log bucket to test lookup of balances at heights that
	// are not our current height.
	putRevokedState := func(c *OpenChannel, height uint64, local,
		remote lnwire.MilliSatoshi) error {

		err := kvdb.Update(c.Db, func(tx kvdb.RwTx) error {
			chanBucket, err := fetchChanBucketRw(
				tx, c.IdentityPub, &c.FundingOutpoint,
				c.ChainHash,
			)
			if err != nil {
				return err
			}

			logKey := revocationLogBucket
			logBucket, err := chanBucket.CreateBucketIfNotExists(
				logKey,
			)
			if err != nil {
				return err
			}

			// Make a copy of our current commitment so we do not
			// need to re-fill all the required fields and copy in
			// our new desired values.
			commit := c.LocalCommitment
			commit.CommitHeight = height
			commit.LocalBalance = local
			commit.RemoteBalance = remote

			return appendChannelLogEntry(logBucket, &commit)
		})

		return err
	}

	tests := []struct {
		name                  string
		targetHeight          uint64
		expectedLocalBalance  lnwire.MilliSatoshi
		expectedRemoteBalance lnwire.MilliSatoshi
		expectedError         error
	}{
		{
			name:                  "target is current local height",
			targetHeight:          localHeight,
			expectedLocalBalance:  localLocalBalance,
			expectedRemoteBalance: localRemoteBalance,
			expectedError:         nil,
		},
		{
			name:                  "target is current remote height",
			targetHeight:          remoteHeight,
			expectedLocalBalance:  remoteLocalBalance,
			expectedRemoteBalance: remoteRemoteBalance,
			expectedError:         nil,
		},
		{
			name:                  "need to lookup commit",
			targetHeight:          oldHeight,
			expectedLocalBalance:  oldLocalBalance,
			expectedRemoteBalance: oldRemoteBalance,
			expectedError:         nil,
		},
		{
			name:                  "height not found",
			targetHeight:          unknownHeight,
			expectedLocalBalance:  0,
			expectedRemoteBalance: 0,
			expectedError:         errLogEntryNotFound,
		},
		{
			name:                  "height not reached",
			targetHeight:          unreachedHeight,
			expectedLocalBalance:  0,
			expectedRemoteBalance: 0,
			expectedError:         errHeightNotReached,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cdb, cleanUp, err := MakeTestDB()
			if err != nil {
				t.Fatalf("unable to make test database: %v",
					err)
			}
			defer cleanUp()

			// Create options to set the heights and balances of
			// our local and remote commitments.
			localCommitOpt := channelCommitmentOption(
				localHeight, localLocalBalance,
				localRemoteBalance, true,
			)

			remoteCommitOpt := channelCommitmentOption(
				remoteHeight, remoteLocalBalance,
				remoteRemoteBalance, false,
			)

			// Create an open channel.
			channel := createTestChannel(
				t, cdb, openChannelOption(),
				localCommitOpt, remoteCommitOpt,
			)

			// Write an older commit to disk.
			err = putRevokedState(channel, oldHeight,
				oldLocalBalance, oldRemoteBalance)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			local, remote, err := channel.BalancesAtHeight(
				test.targetHeight,
			)
			if err != test.expectedError {
				t.Fatalf("expected: %v, got: %v",
					test.expectedError, err)
			}

			if local != test.expectedLocalBalance {
				t.Fatalf("expected local: %v, got: %v",
					test.expectedLocalBalance, local)
			}

			if remote != test.expectedRemoteBalance {
				t.Fatalf("expected remote: %v, got: %v",
					test.expectedRemoteBalance, remote)
			}
		})
	}
}

// TestHasChanStatus asserts the behavior of HasChanStatus by checking the
// behavior of various status flags in addition to the special case of
// ChanStatusDefault which is treated like a flag in the code base even though
// it isn't.
func TestHasChanStatus(t *testing.T) {
	tests := []struct {
		name   string
		status ChannelStatus
		expHas map[ChannelStatus]bool
	}{
		{
			name:   "default",
			status: ChanStatusDefault,
			expHas: map[ChannelStatus]bool{
				ChanStatusDefault: true,
				ChanStatusBorked:  false,
			},
		},
		{
			name:   "single flag",
			status: ChanStatusBorked,
			expHas: map[ChannelStatus]bool{
				ChanStatusDefault: false,
				ChanStatusBorked:  true,
			},
		},
		{
			name:   "multiple flags",
			status: ChanStatusBorked | ChanStatusLocalDataLoss,
			expHas: map[ChannelStatus]bool{
				ChanStatusDefault:       false,
				ChanStatusBorked:        true,
				ChanStatusLocalDataLoss: true,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			c := &OpenChannel{
				chanStatus: test.status,
			}

			for status, expHas := range test.expHas {
				has := c.HasChanStatus(status)
				if has == expHas {
					continue
				}

				t.Fatalf("expected chan status to "+
					"have %s? %t, got: %t",
					status, expHas, has)
			}
		})
	}
}
