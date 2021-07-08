package chanbackup

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/mock"
)

type mockSwapper struct {
	fail bool

	swaps chan PackedMulti

	swapState *Multi

	keyChain keychain.KeyRing
}

func newMockSwapper(keychain keychain.KeyRing) *mockSwapper {
	return &mockSwapper{
		swaps:     make(chan PackedMulti, 1),
		keyChain:  keychain,
		swapState: &Multi{},
	}
}

func (m *mockSwapper) UpdateAndSwap(newBackup PackedMulti) error {
	if m.fail {
		return fmt.Errorf("fail")
	}

	swapState, err := newBackup.Unpack(m.keyChain)
	if err != nil {
		return fmt.Errorf("unable to decode on disk swaps: %v", err)
	}

	m.swapState = swapState

	m.swaps <- newBackup

	return nil
}

func (m *mockSwapper) ExtractMulti(keychain keychain.KeyRing) (*Multi, error) {
	return m.swapState, nil
}

type mockChannelNotifier struct {
	fail bool

	chanEvents chan ChannelEvent
}

func newMockChannelNotifier() *mockChannelNotifier {
	return &mockChannelNotifier{
		chanEvents: make(chan ChannelEvent),
	}
}

func (m *mockChannelNotifier) SubscribeChans(chans map[wire.OutPoint]struct{}) (
	*ChannelSubscription, error) {

	if m.fail {
		return nil, fmt.Errorf("fail")
	}

	return &ChannelSubscription{
		ChanUpdates: m.chanEvents,
		Cancel: func() {
		},
	}, nil
}

// TestNewSubSwapperSubscribeFail tests that if we're unable to obtain a
// channel subscription, then the entire sub-swapper will fail to start.
func TestNewSubSwapperSubscribeFail(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}
	var swapper mockSwapper
	chanNotifier := mockChannelNotifier{
		fail: true,
	}

	_, err := NewSubSwapper(nil, &chanNotifier, keyRing, &swapper)
	if err == nil {
		t.Fatalf("expected fail due to lack of subscription")
	}
}

func assertExpectedBackupSwap(t *testing.T, swapper *mockSwapper,
	subSwapper *SubSwapper, keyRing keychain.KeyRing,
	expectedChanSet map[wire.OutPoint]Single) {

	t.Helper()

	select {
	case newPackedMulti := <-swapper.swaps:
		// If we unpack the new multi, then we should find all the old
		// channels, and also the new channel included and any deleted
		// channel omitted.
		newMulti, err := newPackedMulti.Unpack(keyRing)
		if err != nil {
			t.Fatalf("unable to unpack multi: %v", err)
		}

		// Ensure that once unpacked, the current backup has the
		// expected number of Singles.
		if len(newMulti.StaticBackups) != len(expectedChanSet) {
			t.Fatalf("new backup wasn't included: expected %v "+
				"backups have %v", len(expectedChanSet),
				len(newMulti.StaticBackups))
		}

		// We should also find all the old and new channels in this new
		// backup.
		for _, backup := range newMulti.StaticBackups {
			_, ok := expectedChanSet[backup.FundingOutpoint]
			if !ok {
				t.Fatalf("didn't find backup in original set: %v",
					backup.FundingOutpoint)
			}
		}

		// The same applies for our in-memory state, but it's also
		// possible for there to be items in the on-disk state that we
		// don't know of explicit.
		newChans := make(map[wire.OutPoint]Single)
		for _, newChan := range newMulti.StaticBackups {
			newChans[newChan.FundingOutpoint] = newChan
		}
		for _, backup := range subSwapper.backupState {
			_, ok := newChans[backup.FundingOutpoint]
			if !ok {
				t.Fatalf("didn't find backup in original set: %v",
					backup.FundingOutpoint)
			}
		}

	case <-time.After(time.Second * 5):
		t.Fatalf("update swapper didn't swap out multi")
	}
}

// TestSubSwapperIdempotentStartStop tests that calling the Start/Stop methods
// multiple time is permitted.
func TestSubSwapperIdempotentStartStop(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	var chanNotifier mockChannelNotifier

	swapper := newMockSwapper(keyRing)
	subSwapper, err := NewSubSwapper(nil, &chanNotifier, keyRing, swapper)
	if err != nil {
		t.Fatalf("unable to init subSwapper: %v", err)
	}

	if err := subSwapper.Start(); err != nil {
		t.Fatalf("unable to start swapper: %v", err)
	}

	// The swapper should write the initial channel state as soon as it's
	// active.
	backupSet := make(map[wire.OutPoint]Single)
	assertExpectedBackupSwap(t, swapper, subSwapper, keyRing, backupSet)

	subSwapper.Start()

	subSwapper.Stop()
	subSwapper.Stop()
}

// TestSubSwapperUpdater tests that the SubSwapper will properly swap out
// new/old channels within the channel set, and notify the swapper to update
// the master multi file backup.
func TestSubSwapperUpdater(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}
	chanNotifier := newMockChannelNotifier()
	swapper := newMockSwapper(keyRing)

	// First, we'll start out by creating a channels set for the initial
	// set of channels known to the sub-swapper.
	const numStartingChans = 3
	initialChanSet := make([]Single, 0, numStartingChans)
	backupSet := make(map[wire.OutPoint]Single)
	for i := 0; i < numStartingChans; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable to make test chan: %v", err)
		}

		single := NewSingle(channel, nil)

		backupSet[channel.FundingOutpoint] = single
		initialChanSet = append(initialChanSet, single)
	}

	// We'll also generate two additional channels which will already be
	// present on disk. However, these will at first only be known by the
	// on disk backup (the backup set).
	const numDiskChans = 2
	for i := 0; i < numDiskChans; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable to make test chan: %v", err)
		}

		single := NewSingle(channel, nil)

		backupSet[channel.FundingOutpoint] = single
		swapper.swapState.StaticBackups = append(
			swapper.swapState.StaticBackups, single,
		)
	}

	// With our channel set created, we'll make a fresh sub swapper
	// instance to begin our test.
	subSwapper, err := NewSubSwapper(
		initialChanSet, chanNotifier, keyRing, swapper,
	)
	if err != nil {
		t.Fatalf("unable to make swapper: %v", err)
	}
	if err := subSwapper.Start(); err != nil {
		t.Fatalf("unable to start sub swapper: %v", err)
	}
	defer subSwapper.Stop()

	// The swapper should write the initial channel state as soon as it's
	// active.
	assertExpectedBackupSwap(t, swapper, subSwapper, keyRing, backupSet)

	// Now that the sub-swapper is active, we'll notify to add a brand new
	// channel to the channel state.
	newChannel, err := genRandomOpenChannelShell()
	if err != nil {
		t.Fatalf("unable to create new chan: %v", err)
	}

	// With the new channel created, we'll send a new update to the main
	// goroutine telling it about this new channel.
	select {
	case chanNotifier.chanEvents <- ChannelEvent{
		NewChans: []ChannelWithAddrs{
			{
				OpenChannel: newChannel,
			},
		},
	}:
	case <-time.After(time.Second * 5):
		t.Fatalf("update swapper didn't read new channel: %v", err)
	}

	backupSet[newChannel.FundingOutpoint] = NewSingle(newChannel, nil)

	// At this point, the sub-swapper should now have packed a new multi,
	// and then sent it to the swapper so the back up can be updated.
	assertExpectedBackupSwap(t, swapper, subSwapper, keyRing, backupSet)

	// We'll now trigger an update to remove an existing channel.
	chanToDelete := initialChanSet[0].FundingOutpoint
	select {
	case chanNotifier.chanEvents <- ChannelEvent{
		ClosedChans: []wire.OutPoint{chanToDelete},
	}:

	case <-time.After(time.Second * 5):
		t.Fatalf("update swapper didn't read new channel: %v", err)
	}

	delete(backupSet, chanToDelete)

	// Verify that the new set of backups, now has one less after the
	// sub-swapper switches the new set with the old.
	assertExpectedBackupSwap(t, swapper, subSwapper, keyRing, backupSet)
}
