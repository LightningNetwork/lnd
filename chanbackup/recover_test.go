package chanbackup

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lntest/mock"
)

type mockChannelRestorer struct {
	fail bool

	callCount int
}

func (m *mockChannelRestorer) RestoreChansFromSingles(...Single) error {
	if m.fail {
		return fmt.Errorf("fail")
	}

	m.callCount++

	return nil
}

type mockPeerConnector struct {
	fail bool

	callCount int
}

func (m *mockPeerConnector) ConnectPeer(node *btcec.PublicKey,
	addrs []net.Addr) error {

	if m.fail {
		return fmt.Errorf("fail")
	}

	m.callCount++

	return nil
}

// TestUnpackAndRecoverSingles tests that we're able to properly unpack and
// recover a set of packed singles.
func TestUnpackAndRecoverSingles(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}
	// First, we'll create a number of single chan backups that we'll
	// shortly back to so we can begin our recovery attempt.
	numSingles := 10
	backups := make([]Single, 0, numSingles)
	var packedBackups PackedSingles
	for i := 0; i < numSingles; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable make channel: %v", err)
		}

		single := NewSingle(channel, nil)

		var b bytes.Buffer
		if err := single.PackToWriter(&b, keyRing); err != nil {
			t.Fatalf("unable to pack single: %v", err)
		}

		backups = append(backups, single)
		packedBackups = append(packedBackups, b.Bytes())
	}

	chanRestorer := mockChannelRestorer{}
	peerConnector := mockPeerConnector{}

	// Now that we have our backups (packed and unpacked), we'll attempt to
	// restore them all in a single batch.

	// If we make the channel restore fail, then the entire method should
	// as well
	chanRestorer.fail = true
	err := UnpackAndRecoverSingles(
		packedBackups, keyRing, &chanRestorer, &peerConnector,
	)
	if err == nil {
		t.Fatalf("restoration should have failed")
	}

	chanRestorer.fail = false

	// If we make the peer connector fail, then the entire method should as
	// well
	peerConnector.fail = true
	err = UnpackAndRecoverSingles(
		packedBackups, keyRing, &chanRestorer, &peerConnector,
	)
	if err == nil {
		t.Fatalf("restoration should have failed")
	}

	chanRestorer.callCount--
	peerConnector.fail = false

	// Next, we'll ensure that if all the interfaces function as expected,
	// then the channels will properly be unpacked and restored.
	err = UnpackAndRecoverSingles(
		packedBackups, keyRing, &chanRestorer, &peerConnector,
	)
	if err != nil {
		t.Fatalf("unable to recover chans: %v", err)
	}

	// Both the restorer, and connector should have been called 10 times,
	// once for each backup.
	if chanRestorer.callCount != numSingles {
		t.Fatalf("expected %v calls, instead got %v",
			numSingles, chanRestorer.callCount)
	}
	if peerConnector.callCount != numSingles {
		t.Fatalf("expected %v calls, instead got %v",
			numSingles, peerConnector.callCount)
	}

	// If we modify the keyRing, then unpacking should fail.
	keyRing.Fail = true
	err = UnpackAndRecoverSingles(
		packedBackups, keyRing, &chanRestorer, &peerConnector,
	)
	if err == nil {
		t.Fatalf("unpacking should have failed")
	}

	// TODO(roasbeef): verify proper call args
}

// TestUnpackAndRecoverMulti tests that we're able to properly unpack and
// recover a packed multi.
func TestUnpackAndRecoverMulti(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}
	// First, we'll create a number of single chan backups that we'll
	// shortly back to so we can begin our recovery attempt.
	numSingles := 10
	backups := make([]Single, 0, numSingles)
	for i := 0; i < numSingles; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable make channel: %v", err)
		}

		single := NewSingle(channel, nil)

		backups = append(backups, single)
	}

	multi := Multi{
		StaticBackups: backups,
	}

	var b bytes.Buffer
	if err := multi.PackToWriter(&b, keyRing); err != nil {
		t.Fatalf("unable to pack multi: %v", err)
	}

	// Next, we'll pack the set of singles into a packed multi, and also
	// create the set of interfaces we need to carry out the remainder of
	// the test.
	packedMulti := PackedMulti(b.Bytes())

	chanRestorer := mockChannelRestorer{}
	peerConnector := mockPeerConnector{}

	// If we make the channel restore fail, then the entire method should
	// as well
	chanRestorer.fail = true
	err := UnpackAndRecoverMulti(
		packedMulti, keyRing, &chanRestorer, &peerConnector,
	)
	if err == nil {
		t.Fatalf("restoration should have failed")
	}

	chanRestorer.fail = false

	// If we make the peer connector fail, then the entire method should as
	// well
	peerConnector.fail = true
	err = UnpackAndRecoverMulti(
		packedMulti, keyRing, &chanRestorer, &peerConnector,
	)
	if err == nil {
		t.Fatalf("restoration should have failed")
	}

	chanRestorer.callCount--
	peerConnector.fail = false

	// Next, we'll ensure that if all the interfaces function as expected,
	// then the channels will properly be unpacked and restored.
	err = UnpackAndRecoverMulti(
		packedMulti, keyRing, &chanRestorer, &peerConnector,
	)
	if err != nil {
		t.Fatalf("unable to recover chans: %v", err)
	}

	// Both the restorer, and connector should have been called 10 times,
	// once for each backup.
	if chanRestorer.callCount != numSingles {
		t.Fatalf("expected %v calls, instead got %v",
			numSingles, chanRestorer.callCount)
	}
	if peerConnector.callCount != numSingles {
		t.Fatalf("expected %v calls, instead got %v",
			numSingles, peerConnector.callCount)
	}

	// If we modify the keyRing, then unpacking should fail.
	keyRing.Fail = true
	err = UnpackAndRecoverMulti(
		packedMulti, keyRing, &chanRestorer, &peerConnector,
	)
	if err == nil {
		t.Fatalf("unpacking should have failed")
	}

	// TODO(roasbeef): verify proper call args
}
