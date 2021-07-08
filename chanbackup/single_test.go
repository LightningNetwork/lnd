package chanbackup

import (
	"bytes"
	"math"
	"math/rand"
	"net"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/channels"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
)

var (
	chainHash = chainhash.Hash{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x18, 0xa3, 0xef, 0xb9,
		0x64, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	op = wire.OutPoint{
		Hash:  chainHash,
		Index: 4,
	}

	addr1, _ = net.ResolveTCPAddr("tcp", "10.0.0.2:9000")
	addr2, _ = net.ResolveTCPAddr("tcp", "10.0.0.3:9000")

	privKeyBytes = channels.AlicesPrivKey

	privKey, _ = btcec.PrivKeyFromBytes(btcec.S256(),
		privKeyBytes)
)

func assertSingleEqual(t *testing.T, a, b Single) {
	t.Helper()

	if a.Version != b.Version {
		t.Fatalf("versions don't match: %v vs %v", a.Version,
			b.Version)
	}
	if a.IsInitiator != b.IsInitiator {
		t.Fatalf("initiators don't match: %v vs %v", a.IsInitiator,
			b.IsInitiator)
	}
	if a.ChainHash != b.ChainHash {
		t.Fatalf("chainhash doesn't match: %v vs %v", a.ChainHash,
			b.ChainHash)
	}
	if a.FundingOutpoint != b.FundingOutpoint {
		t.Fatalf("chan point doesn't match: %v vs %v",
			a.FundingOutpoint, b.FundingOutpoint)
	}
	if a.ShortChannelID != b.ShortChannelID {
		t.Fatalf("chan id doesn't match: %v vs %v",
			a.ShortChannelID, b.ShortChannelID)
	}
	if a.Capacity != b.Capacity {
		t.Fatalf("capacity doesn't match: %v vs %v",
			a.Capacity, b.Capacity)
	}
	if !a.RemoteNodePub.IsEqual(b.RemoteNodePub) {
		t.Fatalf("node pubs don't match %x vs %x",
			a.RemoteNodePub.SerializeCompressed(),
			b.RemoteNodePub.SerializeCompressed())
	}
	if !reflect.DeepEqual(a.LocalChanCfg, b.LocalChanCfg) {
		t.Fatalf("local chan config doesn't match: %v vs %v",
			spew.Sdump(a.LocalChanCfg),
			spew.Sdump(b.LocalChanCfg))
	}
	if !reflect.DeepEqual(a.RemoteChanCfg, b.RemoteChanCfg) {
		t.Fatalf("remote chan config doesn't match: %v vs %v",
			spew.Sdump(a.RemoteChanCfg),
			spew.Sdump(b.RemoteChanCfg))
	}
	if !reflect.DeepEqual(a.ShaChainRootDesc, b.ShaChainRootDesc) {
		t.Fatalf("sha chain point doesn't match: %v vs %v",
			spew.Sdump(a.ShaChainRootDesc),
			spew.Sdump(b.ShaChainRootDesc))
	}

	if len(a.Addresses) != len(b.Addresses) {
		t.Fatalf("expected %v addrs got %v", len(a.Addresses),
			len(b.Addresses))
	}
	for i := 0; i < len(a.Addresses); i++ {
		if a.Addresses[i].String() != b.Addresses[i].String() {
			t.Fatalf("addr mismatch: %v vs %v",
				a.Addresses[i], b.Addresses[i])
		}
	}
}

func genRandomOpenChannelShell() (*channeldb.OpenChannel, error) {
	var testPriv [32]byte
	if _, err := rand.Read(testPriv[:]); err != nil {
		return nil, err
	}

	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), testPriv[:])

	var chanPoint wire.OutPoint
	if _, err := rand.Read(chanPoint.Hash[:]); err != nil {
		return nil, err
	}

	pub.Curve = nil

	chanPoint.Index = uint32(rand.Intn(math.MaxUint16))

	var shaChainRoot [32]byte
	if _, err := rand.Read(shaChainRoot[:]); err != nil {
		return nil, err
	}

	shaChainProducer := shachain.NewRevocationProducer(shaChainRoot)

	var isInitiator bool
	if rand.Int63()%2 == 0 {
		isInitiator = true
	}

	chanType := channeldb.SingleFunderBit
	if rand.Int63()%2 == 0 {
		chanType = channeldb.SingleFunderTweaklessBit
	}

	return &channeldb.OpenChannel{
		ChainHash:       chainHash,
		ChanType:        chanType,
		IsInitiator:     isInitiator,
		FundingOutpoint: chanPoint,
		ShortChannelID: lnwire.NewShortChanIDFromInt(
			uint64(rand.Int63()),
		),
		IdentityPub: pub,
		LocalChanCfg: channeldb.ChannelConfig{
			ChannelConstraints: channeldb.ChannelConstraints{
				CsvDelay: uint16(rand.Int63()),
			},
			MultiSigKey: keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(rand.Int63()),
					Index:  uint32(rand.Int63()),
				},
			},
			RevocationBasePoint: keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(rand.Int63()),
					Index:  uint32(rand.Int63()),
				},
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(rand.Int63()),
					Index:  uint32(rand.Int63()),
				},
			},
			DelayBasePoint: keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(rand.Int63()),
					Index:  uint32(rand.Int63()),
				},
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(rand.Int63()),
					Index:  uint32(rand.Int63()),
				},
			},
		},
		RemoteChanCfg: channeldb.ChannelConfig{
			ChannelConstraints: channeldb.ChannelConstraints{
				CsvDelay: uint16(rand.Int63()),
			},
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: pub,
			},
			RevocationBasePoint: keychain.KeyDescriptor{
				PubKey: pub,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: pub,
			},
			DelayBasePoint: keychain.KeyDescriptor{
				PubKey: pub,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: pub,
			},
		},
		RevocationProducer: shaChainProducer,
	}, nil
}

// TestSinglePackUnpack tests that we're able to unpack a previously packed
// channel backup.
func TestSinglePackUnpack(t *testing.T) {
	t.Parallel()

	// Given our test pub key, we'll create an open channel shell that
	// contains all the information we need to create a static channel
	// backup.
	channel, err := genRandomOpenChannelShell()
	if err != nil {
		t.Fatalf("unable to gen open channel: %v", err)
	}

	singleChanBackup := NewSingle(channel, []net.Addr{addr1, addr2})
	singleChanBackup.RemoteNodePub.Curve = nil

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	versionTestCases := []struct {
		// version is the pack/unpack version that we should use to
		// decode/encode the final SCB.
		version SingleBackupVersion

		// valid tests us if this test case should pass or not.
		valid bool
	}{
		// The default version, should pack/unpack with no problem.
		{
			version: DefaultSingleVersion,
			valid:   true,
		},

		// The new tweakless version, should pack/unpack with no
		// problem.
		{
			version: TweaklessCommitVersion,
			valid:   true,
		},

		// The new anchor version, should pack/unpack with no
		// problem.
		{
			version: AnchorsCommitVersion,
			valid:   true,
		},

		// A non-default version, atm this should result in a failure.
		{
			version: 99,
			valid:   false,
		},
	}
	for i, versionCase := range versionTestCases {
		// First, we'll re-assign SCB version to what was indicated in
		// the test case.
		singleChanBackup.Version = versionCase.version

		var b bytes.Buffer

		err := singleChanBackup.PackToWriter(&b, keyRing)
		switch {
		// If this is a valid test case, and we failed, then we'll
		// return an error.
		case err != nil && versionCase.valid:
			t.Fatalf("#%v, unable to pack single: %v", i, err)

		// If this is an invalid test case, and we passed it, then
		// we'll return an error.
		case err == nil && !versionCase.valid:
			t.Fatalf("#%v got nil error for invalid pack: %v",
				i, err)
		}

		// If this is a valid test case, then we'll continue to ensure
		// we can unpack it, and also that if we mutate the packed
		// version, then we trigger an error.
		if versionCase.valid {
			var unpackedSingle Single
			err = unpackedSingle.UnpackFromReader(&b, keyRing)
			if err != nil {
				t.Fatalf("#%v unable to unpack single: %v",
					i, err)
			}
			unpackedSingle.RemoteNodePub.Curve = nil

			assertSingleEqual(t, singleChanBackup, unpackedSingle)

			// If this was a valid packing attempt, then we'll test
			// to ensure that if we mutate the version prepended to
			// the serialization, then unpacking will fail as well.
			var rawSingle bytes.Buffer
			err := unpackedSingle.Serialize(&rawSingle)
			if err != nil {
				t.Fatalf("unable to serialize single: %v", err)
			}

			rawBytes := rawSingle.Bytes()
			rawBytes[0] ^= 5

			newReader := bytes.NewReader(rawBytes)
			err = unpackedSingle.Deserialize(newReader)
			if err == nil {
				t.Fatalf("#%v unpack with unknown version "+
					"should have failed", i)
			}
		}
	}
}

// TestPackedSinglesUnpack tests that we're able to properly unpack a series of
// packed singles.
func TestPackedSinglesUnpack(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	// To start, we'll create 10 new singles, and them assemble their
	// packed forms into a slice.
	numSingles := 10
	packedSingles := make([][]byte, 0, numSingles)
	unpackedSingles := make([]Single, 0, numSingles)
	for i := 0; i < numSingles; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable to gen channel: %v", err)
		}

		single := NewSingle(channel, nil)

		var b bytes.Buffer
		if err := single.PackToWriter(&b, keyRing); err != nil {
			t.Fatalf("unable to pack single: %v", err)
		}

		packedSingles = append(packedSingles, b.Bytes())
		unpackedSingles = append(unpackedSingles, single)
	}

	// With all singles packed, we'll create the grouped type and attempt
	// to Unpack all of them in a single go.
	freshSingles, err := PackedSingles(packedSingles).Unpack(keyRing)
	if err != nil {
		t.Fatalf("unable to unpack singles: %v", err)
	}

	// The set of freshly unpacked singles should exactly match the initial
	// set of singles that we packed before.
	for i := 0; i < len(unpackedSingles); i++ {
		assertSingleEqual(t, unpackedSingles[i], freshSingles[i])
	}

	// If we mutate one of the packed singles, then the entire method
	// should fail.
	packedSingles[0][0] ^= 1
	_, err = PackedSingles(packedSingles).Unpack(keyRing)
	if err == nil {
		t.Fatalf("unpack attempt should fail")
	}
}

// TestSinglePackStaticChanBackups tests that we're able to batch pack a set of
// Singles, and then unpack them obtaining the same set of unpacked singles.
func TestSinglePackStaticChanBackups(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	// First, we'll create a set of random single, and along the way,
	// create a map that will let us look up each single by its chan point.
	numSingles := 10
	singleMap := make(map[wire.OutPoint]Single, numSingles)
	unpackedSingles := make([]Single, 0, numSingles)
	for i := 0; i < numSingles; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable to gen channel: %v", err)
		}

		single := NewSingle(channel, nil)

		singleMap[channel.FundingOutpoint] = single
		unpackedSingles = append(unpackedSingles, single)
	}

	// Now that we have all of our singles are created, we'll attempt to
	// pack them all in a single batch.
	packedSingleMap, err := PackStaticChanBackups(unpackedSingles, keyRing)
	if err != nil {
		t.Fatalf("unable to pack backups: %v", err)
	}

	// With our packed singles obtained, we'll ensure that each of them
	// match their unpacked counterparts after they themselves have been
	// unpacked.
	for chanPoint, single := range singleMap {
		packedSingles, ok := packedSingleMap[chanPoint]
		if !ok {
			t.Fatalf("unable to find single %v", chanPoint)
		}

		var freshSingle Single
		err := freshSingle.UnpackFromReader(
			bytes.NewReader(packedSingles), keyRing,
		)
		if err != nil {
			t.Fatalf("unable to unpack single: %v", err)
		}

		assertSingleEqual(t, single, freshSingle)
	}

	// If we attempt to pack again, but force the key ring to fail, then
	// the entire method should fail.
	keyRing.Fail = true
	_, err = PackStaticChanBackups(
		unpackedSingles, keyRing,
	)
	if err == nil {
		t.Fatalf("pack attempt should fail")
	}
}

// TestSingleUnconfirmedChannel tests that unconfirmed channels get serialized
// correctly by encoding the funding broadcast height as block height of the
// short channel ID.
func TestSingleUnconfirmedChannel(t *testing.T) {
	t.Parallel()

	var fundingBroadcastHeight = uint32(1234)

	// Let's create an open channel shell that contains all the information
	// we need to create a static channel backup but simulate an
	// unconfirmed channel by setting the block height to 0.
	channel, err := genRandomOpenChannelShell()
	if err != nil {
		t.Fatalf("unable to gen open channel: %v", err)
	}
	channel.ShortChannelID.BlockHeight = 0
	channel.FundingBroadcastHeight = fundingBroadcastHeight

	singleChanBackup := NewSingle(channel, []net.Addr{addr1, addr2})
	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}
	// Pack it and then unpack it again to make sure everything is written
	// correctly, then check that the block height of the unpacked
	// is the funding broadcast height we set before.
	var b bytes.Buffer
	if err := singleChanBackup.PackToWriter(&b, keyRing); err != nil {
		t.Fatalf("unable to pack single: %v", err)
	}
	var unpackedSingle Single
	err = unpackedSingle.UnpackFromReader(&b, keyRing)
	if err != nil {
		t.Fatalf("unable to unpack single: %v", err)
	}
	if unpackedSingle.ShortChannelID.BlockHeight != fundingBroadcastHeight {
		t.Fatalf("invalid block height. got %d expected %d.",
			unpackedSingle.ShortChannelID.BlockHeight,
			fundingBroadcastHeight)
	}
}

// TODO(roasbsef): fuzz parsing
