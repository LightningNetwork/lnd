package htlcswitch

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/ticker"
)

var zeroCircuit = channeldb.CircuitKey{}

func genPreimage() ([32]byte, error) {
	var preimage [32]byte
	if _, err := io.ReadFull(rand.Reader, preimage[:]); err != nil {
		return preimage, err
	}
	return preimage, nil
}

// TestSwitchAddDuplicateLink tests that the switch will reject duplicate links
// for both pending and live links. It also tests that we can successfully
// add a link after having removed it.
func TestSwitchAddDuplicateLink(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, _, aliceChanID, _ := genIDs()

	pendingChanID := lnwire.ShortChannelID{}

	aliceChannelLink := newMockChannelLink(
		s, chanID1, pendingChanID, alicePeer, false,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}

	// Alice should have a pending link, adding again should fail.
	if err := s.AddLink(aliceChannelLink); err == nil {
		t.Fatalf("adding duplicate link should have failed")
	}

	// Update the short chan id of the channel, so that the link goes live.
	aliceChannelLink.setLiveShortChanID(aliceChanID)
	err = s.UpdateShortChanID(chanID1)
	if err != nil {
		t.Fatalf("unable to update alice short_chan_id: %v", err)
	}

	// Alice should have a live link, adding again should fail.
	if err := s.AddLink(aliceChannelLink); err == nil {
		t.Fatalf("adding duplicate link should have failed")
	}

	// Remove the live link to ensure the indexes are cleared.
	s.RemoveLink(chanID1)

	// Alice has no links, adding should succeed.
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
}

// TestSwitchHasActiveLink tests the behavior of HasActiveLink, and asserts that
// it only returns true if a link's short channel id has confirmed (meaning the
// channel is no longer pending) and it's EligibleToForward method returns true,
// i.e. it has received FundingLocked from the remote peer.
func TestSwitchHasActiveLink(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, _, aliceChanID, _ := genIDs()

	pendingChanID := lnwire.ShortChannelID{}

	aliceChannelLink := newMockChannelLink(
		s, chanID1, pendingChanID, alicePeer, false,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}

	// The link has been added, but it's still pending. HasActiveLink should
	// return false since the link has not been added to the linkIndex
	// containing live links.
	if s.HasActiveLink(chanID1) {
		t.Fatalf("link should not be active yet, still pending")
	}

	// Update the short chan id of the channel, so that the link goes live.
	aliceChannelLink.setLiveShortChanID(aliceChanID)
	err = s.UpdateShortChanID(chanID1)
	if err != nil {
		t.Fatalf("unable to update alice short_chan_id: %v", err)
	}

	// UpdateShortChanID will cause the mock link to become eligible to
	// forward. However, we can simulate the event where the short chan id
	// is confirmed, but funding locked has yet to be received by resetting
	// the mock link's eligibility to false.
	aliceChannelLink.eligible = false

	// Now, even though the link has been added to the linkIndex because the
	// short channel id has confirmed, we should still see HasActiveLink
	// fail because EligibleToForward should return false.
	if s.HasActiveLink(chanID1) {
		t.Fatalf("link should not be active yet, still ineligible")
	}

	// Finally, simulate the link receiving funding locked by setting its
	// eligibility to true.
	aliceChannelLink.eligible = true

	// The link should now be reported as active, since EligibleToForward
	// returns true and the link is in the linkIndex.
	if !s.HasActiveLink(chanID1) {
		t.Fatalf("link should not be active now")
	}
}

// TestSwitchSendPending checks the inability of htlc switch to forward adds
// over pending links, and the UpdateShortChanID makes a pending link live.
func TestSwitchSendPending(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}

	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	pendingChanID := lnwire.ShortChannelID{}

	aliceChannelLink := newMockChannelLink(
		s, chanID1, pendingChanID, alicePeer, false,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}

	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should is being forwarded from Bob channel
	// link to Alice channel link.
	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	packet := &htlcPacket{
		incomingChanID: bobChanID,
		incomingHTLCID: 0,
		outgoingChanID: aliceChanID,
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	// Send the ADD packet, this should not be forwarded out to the link
	// since there are no eligible links.
	if err = s.ForwardPackets(nil, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-bobChannelLink.packets:
		if p.linkFailure != nil {
			err = p.linkFailure
		}
	case <-time.After(time.Second):
		t.Fatal("no timely reply from switch")
	}
	linkErr, ok := err.(*LinkError)
	if !ok {
		t.Fatalf("expected link error, got: %T", err)
	}
	if linkErr.WireMessage().Code() != lnwire.CodeUnknownNextPeer {
		t.Fatalf("expected fail unknown next peer, got: %T",
			linkErr.WireMessage().Code())
	}

	// No message should be sent, since the packet was failed.
	select {
	case <-aliceChannelLink.packets:
		t.Fatal("expected not to receive message")
	case <-time.After(time.Second):
	}

	// Since the packet should have been failed, there should be no active
	// circuits.
	if s.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}

	// Now, update Alice's link with her final short channel id. This should
	// move the link to the live state.
	aliceChannelLink.setLiveShortChanID(aliceChanID)
	err = s.UpdateShortChanID(chanID1)
	if err != nil {
		t.Fatalf("unable to update alice short_chan_id: %v", err)
	}

	// Increment the packet's HTLC index, so that it does not collide with
	// the prior attempt.
	packet.incomingHTLCID++

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, packet); err != nil {
		t.Fatalf("unexpected forward failure: %v", err)
	}

	// Since Alice's link is now active, this packet should succeed.
	select {
	case <-aliceChannelLink.packets:
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to alice")
	}
}

// TestSwitchForward checks the ability of htlc switch to forward add/settle
// requests.
func TestSwitchForward(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	packet := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, packet); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobChannelLink.packets:
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumOpen() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	if !s.IsForwardedHTLC(bobChannelLink.ShortChanID(), 0) {
		t.Fatal("htlc should be identified as forwarded")
	}

	// Create settle request pretending that bob link handled the add htlc
	// request and sent the htlc settle request back. This request should
	// be forwarder back to Alice link.
	packet = &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc: &lnwire.UpdateFulfillHTLC{
			PaymentPreimage: preimage,
		},
	}

	// Handle the request and checks that payment circuit works properly.
	if err := s.ForwardPackets(nil, packet); err != nil {
		t.Fatal(err)
	}

	select {
	case pkt := <-aliceChannelLink.packets:
		if err := aliceChannelLink.deleteCircuit(pkt); err != nil {
			t.Fatalf("unable to remove circuit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to channelPoint")
	}

	if s.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

func TestSwitchForwardFailAfterFullAdd(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	tempPath, err := ioutil.TempDir("", "circuitdb")
	if err != nil {
		t.Fatalf("unable to temporary path: %v", err)
	}

	cdb, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to open channeldb: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, cdb)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}

	// Even though we intend to Stop s later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s.Stop()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	ogPacket := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	if s.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Pull packet from bob's link, but do not perform a full add.
	select {
	case packet := <-bobChannelLink.packets:
		// Complete the payment circuit and assign the outgoing htlc id
		// before restarting.
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 1 {
		t.Fatalf("wrong amount of circuits")
	}

	// Now we will restart bob, leaving the forwarding decision for this
	// htlc is in the half-added state.
	if err := s.Stop(); err != nil {
		t.Fatalf(err.Error())
	}

	if err := cdb.Close(); err != nil {
		t.Fatalf(err.Error())
	}

	cdb2, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to reopen channeldb: %v", err)
	}

	s2, err := initSwitchWithDB(testStartingHeight, cdb2)
	if err != nil {
		t.Fatalf("unable reinit switch: %v", err)
	}
	if err := s2.Start(); err != nil {
		t.Fatalf("unable to restart switch: %v", err)
	}

	// Even though we intend to Stop s2 later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s2.Stop()

	aliceChannelLink = newMockChannelLink(
		s2, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink = newMockChannelLink(
		s2, chanID2, bobChanID, bobPeer, true,
	)
	if err := s2.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s2.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	if s2.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 1 {
		t.Fatalf("wrong amount of circuits")
	}

	// Craft a failure message from the remote peer.
	fail := &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc:           &lnwire.UpdateFailHTLC{},
	}

	// Send the fail packet from the remote peer through the switch.
	if err := s2.ForwardPackets(nil, fail); err != nil {
		t.Fatalf(err.Error())
	}

	// Pull packet from alice's link, as it should have gone through
	// successfully.
	select {
	case pkt := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(pkt); err != nil {
			t.Fatalf("unable to remove circuit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	// Circuit map should be empty now.
	if s2.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Send the fail packet from the remote peer through the switch.
	if err := s.ForwardPackets(nil, fail); err != nil {
		t.Fatal(err)
	}
	select {
	case <-aliceChannelLink.packets:
		t.Fatalf("expected duplicate fail to not arrive at the destination")
	case <-time.After(time.Second):
	}
}

func TestSwitchForwardSettleAfterFullAdd(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	tempPath, err := ioutil.TempDir("", "circuitdb")
	if err != nil {
		t.Fatalf("unable to temporary path: %v", err)
	}

	cdb, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to open channeldb: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, cdb)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}

	// Even though we intend to Stop s later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s.Stop()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	ogPacket := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	if s.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Pull packet from bob's link, but do not perform a full add.
	select {
	case packet := <-bobChannelLink.packets:
		// Complete the payment circuit and assign the outgoing htlc id
		// before restarting.
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 1 {
		t.Fatalf("wrong amount of circuits")
	}

	// Now we will restart bob, leaving the forwarding decision for this
	// htlc is in the half-added state.
	if err := s.Stop(); err != nil {
		t.Fatalf(err.Error())
	}

	if err := cdb.Close(); err != nil {
		t.Fatalf(err.Error())
	}

	cdb2, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to reopen channeldb: %v", err)
	}

	s2, err := initSwitchWithDB(testStartingHeight, cdb2)
	if err != nil {
		t.Fatalf("unable reinit switch: %v", err)
	}
	if err := s2.Start(); err != nil {
		t.Fatalf("unable to restart switch: %v", err)
	}

	// Even though we intend to Stop s2 later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s2.Stop()

	aliceChannelLink = newMockChannelLink(
		s2, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink = newMockChannelLink(
		s2, chanID2, bobChanID, bobPeer, true,
	)
	if err := s2.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s2.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	if s2.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 1 {
		t.Fatalf("wrong amount of circuits")
	}

	// Craft a settle message from the remote peer.
	settle := &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc: &lnwire.UpdateFulfillHTLC{
			PaymentPreimage: preimage,
		},
	}

	// Send the settle packet from the remote peer through the switch.
	if err := s2.ForwardPackets(nil, settle); err != nil {
		t.Fatalf(err.Error())
	}

	// Pull packet from alice's link, as it should have gone through
	// successfully.
	select {
	case packet := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete circuit with in key=%s: %v",
				packet.inKey(), err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	// Circuit map should be empty now.
	if s2.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Send the settle packet again, which not arrive at destination.
	if err := s2.ForwardPackets(nil, settle); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bobChannelLink.packets:
		t.Fatalf("expected duplicate fail to not arrive at the destination")
	case <-time.After(time.Second):
	}
}

func TestSwitchForwardDropAfterFullAdd(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	tempPath, err := ioutil.TempDir("", "circuitdb")
	if err != nil {
		t.Fatalf("unable to temporary path: %v", err)
	}

	cdb, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to open channeldb: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, cdb)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}

	// Even though we intend to Stop s later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s.Stop()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	ogPacket := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	if s.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}

	// Pull packet from bob's link, but do not perform a full add.
	select {
	case packet := <-bobChannelLink.packets:
		// Complete the payment circuit and assign the outgoing htlc id
		// before restarting.
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	// Now we will restart bob, leaving the forwarding decision for this
	// htlc is in the half-added state.
	if err := s.Stop(); err != nil {
		t.Fatalf(err.Error())
	}

	if err := cdb.Close(); err != nil {
		t.Fatalf(err.Error())
	}

	cdb2, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to reopen channeldb: %v", err)
	}

	s2, err := initSwitchWithDB(testStartingHeight, cdb2)
	if err != nil {
		t.Fatalf("unable reinit switch: %v", err)
	}
	if err := s2.Start(); err != nil {
		t.Fatalf("unable to restart switch: %v", err)
	}

	// Even though we intend to Stop s2 later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s2.Stop()

	aliceChannelLink = newMockChannelLink(
		s2, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink = newMockChannelLink(
		s2, chanID2, bobChanID, bobPeer, true,
	)
	if err := s2.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s2.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	if s2.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}

	// Resend the failed htlc. The packet will be dropped silently since the
	// switch will detect that it has been half added previously.
	if err := s2.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	// After detecting an incomplete forward, the fail packet should have
	// been returned to the sender.
	select {
	case <-aliceChannelLink.packets:
		t.Fatal("request should not have returned to source")
	case <-bobChannelLink.packets:
		t.Fatal("request should not have forwarded to destination")
	case <-time.After(time.Second):
	}
}

func TestSwitchForwardFailAfterHalfAdd(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	tempPath, err := ioutil.TempDir("", "circuitdb")
	if err != nil {
		t.Fatalf("unable to temporary path: %v", err)
	}

	cdb, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to open channeldb: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, cdb)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}

	// Even though we intend to Stop s later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s.Stop()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	ogPacket := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	if s.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}

	// Pull packet from bob's link, but do not perform a full add.
	select {
	case <-bobChannelLink.packets:
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	// Now we will restart bob, leaving the forwarding decision for this
	// htlc is in the half-added state.
	if err := s.Stop(); err != nil {
		t.Fatalf(err.Error())
	}

	if err := cdb.Close(); err != nil {
		t.Fatalf(err.Error())
	}

	cdb2, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to reopen channeldb: %v", err)
	}

	s2, err := initSwitchWithDB(testStartingHeight, cdb2)
	if err != nil {
		t.Fatalf("unable reinit switch: %v", err)
	}
	if err := s2.Start(); err != nil {
		t.Fatalf("unable to restart switch: %v", err)
	}

	// Even though we intend to Stop s2 later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s2.Stop()

	aliceChannelLink = newMockChannelLink(
		s2, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink = newMockChannelLink(
		s2, chanID2, bobChanID, bobPeer, true,
	)
	if err := s2.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s2.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	if s2.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}

	// Resend the failed htlc, it should be returned to alice since the
	// switch will detect that it has been half added previously.
	err = s2.ForwardPackets(nil, ogPacket)
	if err != nil {
		t.Fatal(err)
	}

	// After detecting an incomplete forward, the fail packet should have
	// been returned to the sender.
	select {
	case pkt := <-aliceChannelLink.packets:
		linkErr := pkt.linkFailure
		if linkErr.FailureDetail != OutgoingFailureIncompleteForward {
			t.Fatalf("expected incomplete forward, got: %v",
				linkErr.FailureDetail)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}
}

// TestSwitchForwardCircuitPersistence checks the ability of htlc switch to
// maintain the proper entries in the circuit map in the face of restarts.
func TestSwitchForwardCircuitPersistence(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	tempPath, err := ioutil.TempDir("", "circuitdb")
	if err != nil {
		t.Fatalf("unable to temporary path: %v", err)
	}

	cdb, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to open channeldb: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, cdb)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}

	// Even though we intend to Stop s later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s.Stop()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	ogPacket := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	if s.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}

	// Retrieve packet from outgoing link and cache until after restart.
	var packet *htlcPacket
	select {
	case packet = <-bobChannelLink.packets:
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if err := s.Stop(); err != nil {
		t.Fatalf(err.Error())
	}

	if err := cdb.Close(); err != nil {
		t.Fatalf(err.Error())
	}

	cdb2, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to reopen channeldb: %v", err)
	}

	s2, err := initSwitchWithDB(testStartingHeight, cdb2)
	if err != nil {
		t.Fatalf("unable reinit switch: %v", err)
	}
	if err := s2.Start(); err != nil {
		t.Fatalf("unable to restart switch: %v", err)
	}

	// Even though we intend to Stop s2 later in the test, it is safe to
	// defer this Stop since its execution it is protected by an atomic
	// guard, guaranteeing it executes at most once.
	defer s2.Stop()

	aliceChannelLink = newMockChannelLink(
		s2, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink = newMockChannelLink(
		s2, chanID2, bobChanID, bobPeer, true,
	)
	if err := s2.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s2.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	if s2.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}

	// Now that the switch has restarted, complete the payment circuit.
	if err := bobChannelLink.completeCircuit(packet); err != nil {
		t.Fatalf("unable to complete payment circuit: %v", err)
	}

	if s2.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s2.circuits.NumOpen() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob link handled the add htlc
	// request and sent the htlc settle request back. This request should
	// be forwarder back to Alice link.
	ogPacket = &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc: &lnwire.UpdateFulfillHTLC{
			PaymentPreimage: preimage,
		},
	}

	// Handle the request and checks that payment circuit works properly.
	if err := s2.ForwardPackets(nil, ogPacket); err != nil {
		t.Fatal(err)
	}

	select {
	case packet = <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete circuit with in key=%s: %v",
				packet.inKey(), err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to channelPoint")
	}

	if s2.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits, want 1, got %d",
			s2.circuits.NumPending())
	}
	if s2.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}

	if err := s2.Stop(); err != nil {
		t.Fatal(err)
	}

	if err := cdb2.Close(); err != nil {
		t.Fatalf(err.Error())
	}

	cdb3, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to reopen channeldb: %v", err)
	}

	s3, err := initSwitchWithDB(testStartingHeight, cdb3)
	if err != nil {
		t.Fatalf("unable reinit switch: %v", err)
	}
	if err := s3.Start(); err != nil {
		t.Fatalf("unable to restart switch: %v", err)
	}
	defer s3.Stop()

	aliceChannelLink = newMockChannelLink(
		s3, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink = newMockChannelLink(
		s3, chanID2, bobChanID, bobPeer, true,
	)
	if err := s3.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s3.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	if s3.circuits.NumPending() != 0 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s3.circuits.NumOpen() != 0 {
		t.Fatalf("wrong amount of circuits")
	}
}

type multiHopFwdTest struct {
	name                 string
	eligible1, eligible2 bool
	failure1, failure2   *LinkError
	expectedReply        lnwire.FailCode
}

// TestCircularForwards tests the allowing/disallowing of circular payments
// through the same channel in the case where the switch is configured to allow
// and disallow same channel circular forwards.
func TestCircularForwards(t *testing.T) {
	chanID1, aliceChanID := genID()
	preimage := [sha256.Size]byte{1}
	hash := sha256.Sum256(preimage[:])

	tests := []struct {
		name                 string
		allowCircularPayment bool
		expectedErr          error
	}{
		{
			name:                 "circular payment allowed",
			allowCircularPayment: true,
			expectedErr:          nil,
		},
		{
			name:                 "circular payment disallowed",
			allowCircularPayment: false,
			expectedErr: NewDetailedLinkError(
				lnwire.NewTemporaryChannelFailure(nil),
				OutgoingFailureCircularRoute,
			),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			alicePeer, err := newMockServer(
				t, "alice", testStartingHeight, nil,
				testDefaultDelta,
			)
			if err != nil {
				t.Fatalf("unable to create alice server: %v",
					err)
			}

			s, err := initSwitchWithDB(testStartingHeight, nil)
			if err != nil {
				t.Fatalf("unable to init switch: %v", err)
			}
			if err := s.Start(); err != nil {
				t.Fatalf("unable to start switch: %v", err)
			}
			defer func() { _ = s.Stop() }()

			// Set the switch to allow or disallow circular routes
			// according to the test's requirements.
			s.cfg.AllowCircularRoute = test.allowCircularPayment

			aliceChannelLink := newMockChannelLink(
				s, chanID1, aliceChanID, alicePeer, true,
			)

			if err := s.AddLink(aliceChannelLink); err != nil {
				t.Fatalf("unable to add alice link: %v", err)
			}

			// Create a new packet that loops through alice's link
			// in a circle.
			obfuscator := NewMockObfuscator()
			packet := &htlcPacket{
				incomingChanID: aliceChannelLink.ShortChanID(),
				outgoingChanID: aliceChannelLink.ShortChanID(),
				htlc: &lnwire.UpdateAddHTLC{
					PaymentHash: hash,
					Amount:      1,
				},
				obfuscator: obfuscator,
			}

			// Attempt to forward the packet and check for the expected
			// error.
			if err = s.ForwardPackets(nil, packet); err != nil {
				t.Fatal(err)
			}
			select {
			case p := <-aliceChannelLink.packets:
				if p.linkFailure != nil {
					err = p.linkFailure
				}
			case <-time.After(time.Second):
				t.Fatal("no timely reply from switch")
			}
			if !reflect.DeepEqual(err, test.expectedErr) {
				t.Fatalf("expected: %v, got: %v",
					test.expectedErr, err)
			}

			// Ensure that no circuits were opened.
			if s.circuits.NumOpen() > 0 {
				t.Fatal("do not expect any open circuits")
			}
		})
	}
}

// TestCheckCircularForward tests the error returned by checkCircularForward
// in cases where we allow and disallow same channel circular forwards.
func TestCheckCircularForward(t *testing.T) {
	tests := []struct {
		name string

		// allowCircular determines whether we should allow circular
		// forwards.
		allowCircular bool

		// incomingLink is the link that the htlc arrived on.
		incomingLink lnwire.ShortChannelID

		// outgoingLink is the link that the htlc forward
		// is destined to leave on.
		outgoingLink lnwire.ShortChannelID

		// expectedErr is the error we expect to be returned.
		expectedErr *LinkError
	}{
		{
			name:          "not circular, allowed in config",
			allowCircular: true,
			incomingLink:  lnwire.NewShortChanIDFromInt(123),
			outgoingLink:  lnwire.NewShortChanIDFromInt(321),
			expectedErr:   nil,
		},
		{
			name:          "not circular, not allowed in config",
			allowCircular: false,
			incomingLink:  lnwire.NewShortChanIDFromInt(123),
			outgoingLink:  lnwire.NewShortChanIDFromInt(321),
			expectedErr:   nil,
		},
		{
			name:          "circular, allowed in config",
			allowCircular: true,
			incomingLink:  lnwire.NewShortChanIDFromInt(123),
			outgoingLink:  lnwire.NewShortChanIDFromInt(123),
			expectedErr:   nil,
		},
		{
			name:          "circular, not allowed in config",
			allowCircular: false,
			incomingLink:  lnwire.NewShortChanIDFromInt(123),
			outgoingLink:  lnwire.NewShortChanIDFromInt(123),
			expectedErr: NewDetailedLinkError(
				lnwire.NewTemporaryChannelFailure(nil),
				OutgoingFailureCircularRoute,
			),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Check for a circular forward, the hash passed can
			// be nil because it is only used for logging.
			err := checkCircularForward(
				test.incomingLink, test.outgoingLink,
				test.allowCircular, lntypes.Hash{},
			)
			if !reflect.DeepEqual(err, test.expectedErr) {
				t.Fatalf("expected: %v, got: %v",
					test.expectedErr, err)
			}
		})
	}
}

// TestSkipIneligibleLinksMultiHopForward tests that if a multi-hop HTLC comes
// along, then we won't attempt to froward it down al ink that isn't yet able
// to forward any HTLC's.
func TestSkipIneligibleLinksMultiHopForward(t *testing.T) {
	tests := []multiHopFwdTest{
		// None of the channels is eligible.
		{
			name:          "not eligible",
			expectedReply: lnwire.CodeUnknownNextPeer,
		},

		// Channel one has a policy failure and the other channel isn't
		// available.
		{
			name:      "policy fail",
			eligible1: true,
			failure1: NewLinkError(
				lnwire.NewFinalIncorrectCltvExpiry(0),
			),
			expectedReply: lnwire.CodeFinalIncorrectCltvExpiry,
		},

		// The requested channel is not eligible, but the packet is
		// forwarded through the other channel.
		{
			name:          "non-strict success",
			eligible2:     true,
			expectedReply: lnwire.CodeNone,
		},

		// The requested channel has insufficient bandwidth and the
		// other channel's policy isn't satisfied.
		{
			name:      "non-strict policy fail",
			eligible1: true,
			failure1: NewDetailedLinkError(
				lnwire.NewTemporaryChannelFailure(nil),
				OutgoingFailureInsufficientBalance,
			),
			eligible2: true,
			failure2: NewLinkError(
				lnwire.NewFinalIncorrectCltvExpiry(0),
			),
			expectedReply: lnwire.CodeTemporaryChannelFailure,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			testSkipIneligibleLinksMultiHopForward(t, &test)
		})
	}
}

// testSkipIneligibleLinksMultiHopForward tests that if a multi-hop HTLC comes
// along, then we won't attempt to froward it down al ink that isn't yet able
// to forward any HTLC's.
func testSkipIneligibleLinksMultiHopForward(t *testing.T,
	testCase *multiHopFwdTest) {

	t.Parallel()

	var packet *htlcPacket

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, aliceChanID := genID()
	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)

	// We'll create a link for Bob, but mark the link as unable to forward
	// any new outgoing HTLC's.
	chanID2, bobChanID2 := genID()
	bobChannelLink1 := newMockChannelLink(
		s, chanID2, bobChanID2, bobPeer, testCase.eligible1,
	)
	bobChannelLink1.checkHtlcForwardResult = testCase.failure1

	chanID3, bobChanID3 := genID()
	bobChannelLink2 := newMockChannelLink(
		s, chanID3, bobChanID3, bobPeer, testCase.eligible2,
	)
	bobChannelLink2.checkHtlcForwardResult = testCase.failure2

	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink1); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}
	if err := s.AddLink(bobChannelLink2); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create a new packet that's destined for Bob as an incoming HTLC from
	// Alice.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	obfuscator := NewMockObfuscator()
	packet = &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink1.ShortChanID(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
		obfuscator: obfuscator,
	}

	// The request to forward should fail as
	if err := s.ForwardPackets(nil, packet); err != nil {
		t.Fatal(err)
	}

	// We select from all links and extract the error if exists.
	// The packet must be selected but we don't always expect a link error.
	var linkError *LinkError
	select {
	case p := <-aliceChannelLink.packets:
		linkError = p.linkFailure
	case p := <-bobChannelLink1.packets:
		linkError = p.linkFailure
	case p := <-bobChannelLink2.packets:
		linkError = p.linkFailure
	case <-time.After(time.Second):
		t.Fatal("no timely reply from switch")
	}
	failure := obfuscator.(*mockObfuscator).failure
	if testCase.expectedReply == lnwire.CodeNone {
		if linkError != nil {
			t.Fatalf("forwarding should have succeeded")
		}
		if failure != nil {
			t.Fatalf("unexpected failure %T", failure)
		}
	} else {
		if linkError == nil {
			t.Fatalf("forwarding should have failed due to " +
				"inactive link")
		}
		if failure.Code() != testCase.expectedReply {
			t.Fatalf("unexpected failure %T", failure)
		}
	}

	if s.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSkipIneligibleLinksLocalForward ensures that the switch will not attempt
// to forward any HTLC's down a link that isn't yet eligible for forwarding.
func TestSkipIneligibleLinksLocalForward(t *testing.T) {
	t.Parallel()

	testSkipLinkLocalForward(t, false, nil)
}

// TestSkipPolicyUnsatisfiedLinkLocalForward ensures that the switch will not
// attempt to send locally initiated HTLCs that would violate the channel policy
// down a link.
func TestSkipPolicyUnsatisfiedLinkLocalForward(t *testing.T) {
	t.Parallel()

	testSkipLinkLocalForward(t, true, lnwire.NewTemporaryChannelFailure(nil))
}

func testSkipLinkLocalForward(t *testing.T, eligible bool,
	policyResult lnwire.FailureMessage) {

	// We'll create a single link for this test, marking it as being unable
	// to forward form the get go.
	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, _, aliceChanID, _ := genIDs()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, eligible,
	)
	aliceChannelLink.checkHtlcTransitResult = NewLinkError(
		policyResult,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}

	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	addMsg := &lnwire.UpdateAddHTLC{
		PaymentHash: rhash,
		Amount:      1,
	}

	// We'll attempt to send out a new HTLC that has Alice as the first
	// outgoing link. This should fail as Alice isn't yet able to forward
	// any active HTLC's.
	err = s.SendHTLC(aliceChannelLink.ShortChanID(), 0, addMsg)
	if err == nil {
		t.Fatalf("local forward should fail due to inactive link")
	}

	if s.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSwitchCancel checks that if htlc was rejected we remove unused
// circuits.
func TestSwitchCancel(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarder from alice channel link
	// to bob channel link.
	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	request := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, request); err != nil {
		t.Fatal(err)
	}

	select {
	case packet := <-bobChannelLink.packets:
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumPending() != 1 {
		t.Fatalf("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob channel link handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice channel link.
	request = &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc:           &lnwire.UpdateFailHTLC{},
	}

	// Handle the request and checks that payment circuit works properly.
	if err := s.ForwardPackets(nil, request); err != nil {
		t.Fatal(err)
	}

	select {
	case pkt := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(pkt); err != nil {
			t.Fatalf("unable to remove circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to channelPoint")
	}

	if s.circuits.NumPending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
	if s.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSwitchAddSamePayment tests that we send the payment with the same
// payment hash.
func TestSwitchAddSamePayment(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarder from alice channel link
	// to bob channel link.
	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	request := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, request); err != nil {
		t.Fatal(err)
	}

	select {
	case packet := <-bobChannelLink.packets:
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumOpen() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	request = &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 1,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.ForwardPackets(nil, request); err != nil {
		t.Fatal(err)
	}

	select {
	case packet := <-bobChannelLink.packets:
		if err := bobChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumOpen() != 2 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob channel link handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice channel link.
	request = &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc:           &lnwire.UpdateFailHTLC{},
	}

	// Handle the request and checks that payment circuit works properly.
	if err := s.ForwardPackets(nil, request); err != nil {
		t.Fatal(err)
	}

	select {
	case pkt := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(pkt); err != nil {
			t.Fatalf("unable to remove circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to channelPoint")
	}

	if s.circuits.NumOpen() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	request = &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 1,
		amount:         1,
		htlc:           &lnwire.UpdateFailHTLC{},
	}

	// Handle the request and checks that payment circuit works properly.
	if err := s.ForwardPackets(nil, request); err != nil {
		t.Fatal(err)
	}

	select {
	case pkt := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(pkt); err != nil {
			t.Fatalf("unable to remove circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to channelPoint")
	}

	if s.circuits.NumOpen() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSwitchSendPayment tests ability of htlc switch to respond to the
// users when response is came back from channel link.
func TestSwitchSendPayment(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, _, aliceChanID, _ := genIDs()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add link: %v", err)
	}

	// Create request which should be forwarder from alice channel link
	// to bob channel link.
	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	update := &lnwire.UpdateAddHTLC{
		PaymentHash: rhash,
		Amount:      1,
	}
	paymentID := uint64(123)

	// First check that the switch will correctly respond that this payment
	// ID is unknown.
	_, err = s.GetPaymentResult(
		paymentID, rhash, newMockDeobfuscator(),
	)
	if err != ErrPaymentIDNotFound {
		t.Fatalf("expected ErrPaymentIDNotFound, got %v", err)
	}

	// Handle the request and checks that bob channel link received it.
	errChan := make(chan error)
	go func() {
		err := s.SendHTLC(
			aliceChannelLink.ShortChanID(), paymentID, update,
		)
		if err != nil {
			errChan <- err
			return
		}

		resultChan, err := s.GetPaymentResult(
			paymentID, rhash, newMockDeobfuscator(),
		)
		if err != nil {
			errChan <- err
			return
		}

		result, ok := <-resultChan
		if !ok {
			errChan <- fmt.Errorf("shutting down")
		}

		if result.Error != nil {
			errChan <- result.Error
			return
		}

		errChan <- nil
	}()

	select {
	case packet := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case err := <-errChan:
		if err != nil {
			t.Fatalf("unable to send payment: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	if s.circuits.NumOpen() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create fail request pretending that bob channel link handled
	// the add htlc request with error and sent the htlc fail request
	// back. This request should be forwarded back to alice channel link.
	obfuscator := NewMockObfuscator()
	failure := lnwire.NewFailIncorrectDetails(update.Amount, 100)
	reason, err := obfuscator.EncryptFirstHop(failure)
	if err != nil {
		t.Fatalf("unable obfuscate failure: %v", err)
	}

	if s.IsForwardedHTLC(aliceChannelLink.ShortChanID(), update.ID) {
		t.Fatal("htlc should be identified as not forwarded")
	}
	packet := &htlcPacket{
		outgoingChanID: aliceChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc: &lnwire.UpdateFailHTLC{
			Reason: reason,
		},
	}

	if err := s.ForwardPackets(nil, packet); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}

	select {
	case err := <-errChan:
		assertFailureCode(
			t, err, lnwire.CodeIncorrectOrUnknownPaymentDetails,
		)
	case <-time.After(time.Second):
		t.Fatal("err wasn't received")
	}
}

// TestLocalPaymentNoForwardingEvents tests that if we send a series of locally
// initiated payments, then they aren't reflected in the forwarding log.
func TestLocalPaymentNoForwardingEvents(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network. We'll only be
	// interacting with and asserting the state of the first end point for
	// this test.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}

	// We'll now craft and send a payment from Alice to Bob.
	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(
		amount, testStartingHeight, n.firstBobChannelLink,
	)

	// With the payment crafted, we'll send it from Alice to Bob. We'll
	// wait for Alice to receive the preimage for the payment before
	// proceeding.
	receiver := n.bobServer
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, receiver, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to make the payment: %v", err)
	}

	// At this point, we'll forcibly stop the three hop network. Doing
	// this will cause any pending forwarding events to be flushed by the
	// various switches in the network.
	n.stop()

	// With all the switches stopped, we'll fetch Alice's mock forwarding
	// event log.
	log, ok := n.aliceServer.htlcSwitch.cfg.FwdingLog.(*mockForwardingLog)
	if !ok {
		t.Fatalf("mockForwardingLog assertion failed")
	}
	log.Lock()
	defer log.Unlock()

	// If we examine the memory of the forwarding log, then it should be
	// blank.
	if len(log.events) != 0 {
		t.Fatalf("log should have no events, instead has: %v",
			spew.Sdump(log.events))
	}
}

// TestMultiHopPaymentForwardingEvents tests that if we send a series of
// multi-hop payments via Alice->Bob->Carol. Then Bob properly logs forwarding
// events, while Alice and Carol don't.
func TestMultiHopPaymentForwardingEvents(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}

	// We'll make now 10 payments, of 100k satoshis each from Alice to
	// Carol via Bob.
	const numPayments = 10
	paymentHashes := make(map[lntypes.Hash]bool)
	finalAmt := lnwire.NewMSatFromSatoshis(100000)
	htlcAmt, totalTimelock, hops := generateHops(
		finalAmt, testStartingHeight, n.firstBobChannelLink,
		n.carolChannelLink,
	)
	firstHop := n.firstBobChannelLink.ShortChanID()
	for i := 0; i < numPayments/2; i++ {
		paymentHash, err := makePayment(
			n.aliceServer, n.carolServer, firstHop, hops, finalAmt,
			htlcAmt, totalTimelock,
		).Wait(30 * time.Second)
		if err != nil {
			t.Fatalf("unable to send payment: %v", err)
		}
		paymentHashes[paymentHash] = true
	}

	bobLog, ok := n.bobServer.htlcSwitch.cfg.FwdingLog.(*mockForwardingLog)
	if !ok {
		t.Fatalf("mockForwardingLog assertion failed")
	}

	// After sending 5 of the payments, trigger the forwarding ticker, to
	// make sure the events are properly flushed.
	bobTicker, ok := n.bobServer.htlcSwitch.cfg.FwdEventTicker.(*ticker.Force)
	if !ok {
		t.Fatalf("mockTicker assertion failed")
	}

	// We'll trigger the ticker, and wait for the events to appear in Bob's
	// forwarding log.
	timeout := time.After(15 * time.Second)
	for {
		select {
		case bobTicker.Force <- time.Now():
		case <-time.After(1 * time.Second):
			t.Fatalf("unable to force tick")
		}

		// If all 5 events is found in Bob's log, we can break out and
		// continue the test.
		bobLog.Lock()
		if len(bobLog.events) == 5 {
			bobLog.Unlock()
			break
		}
		bobLog.Unlock()

		// Otherwise wait a little bit before checking again.
		select {
		case <-time.After(50 * time.Millisecond):
		case <-timeout:
			bobLog.Lock()
			defer bobLog.Unlock()
			t.Fatalf("expected 5 events in event log, instead "+
				"found: %v", spew.Sdump(bobLog.events))
		}
	}

	// Send the remaining payments.
	for i := numPayments / 2; i < numPayments; i++ {
		paymentHash, err := makePayment(
			n.aliceServer, n.carolServer, firstHop, hops, finalAmt,
			htlcAmt, totalTimelock,
		).Wait(30 * time.Second)
		if err != nil {
			t.Fatalf("unable to send payment: %v", err)
		}
		paymentHashes[paymentHash] = true
	}

	// With all 10 payments sent. We'll now manually stop each of the
	// switches so we can examine their end state.
	n.stop()

	// Alice and Carol shouldn't have any recorded forwarding events, as
	// they were the source and the sink for these payment flows.
	aliceLog, ok := n.aliceServer.htlcSwitch.cfg.FwdingLog.(*mockForwardingLog)
	if !ok {
		t.Fatalf("mockForwardingLog assertion failed")
	}
	aliceLog.Lock()
	defer aliceLog.Unlock()
	if len(aliceLog.events) != 0 {
		t.Fatalf("log should have no events, instead has: %v",
			spew.Sdump(aliceLog.events))
	}

	carolLog, ok := n.carolServer.htlcSwitch.cfg.FwdingLog.(*mockForwardingLog)
	if !ok {
		t.Fatalf("mockForwardingLog assertion failed")
	}
	carolLog.Lock()
	defer carolLog.Unlock()
	if len(carolLog.events) != 0 {
		t.Fatalf("log should have no events, instead has: %v",
			spew.Sdump(carolLog.events))
	}

	// Bob on the other hand, should have 10 events.
	bobLog.Lock()
	defer bobLog.Unlock()
	if len(bobLog.events) != 10 {
		t.Fatalf("log should have 10 events, instead has: %v",
			spew.Sdump(bobLog.events))
	}

	// Each of the 10 events should have had all fields set properly.
	for _, event := range bobLog.events {
		// The incoming and outgoing channels should properly be set for
		// the event.
		if event.IncomingChanID != n.aliceChannelLink.ShortChanID() {
			t.Fatalf("chan id mismatch: expected %v, got %v",
				event.IncomingChanID,
				n.aliceChannelLink.ShortChanID())
		}
		if event.OutgoingChanID != n.carolChannelLink.ShortChanID() {
			t.Fatalf("chan id mismatch: expected %v, got %v",
				event.OutgoingChanID,
				n.carolChannelLink.ShortChanID())
		}

		// Additionally, the incoming and outgoing amounts should also
		// be properly set.
		if event.AmtIn != htlcAmt {
			t.Fatalf("incoming amt mismatch: expected %v, got %v",
				event.AmtIn, htlcAmt)
		}
		if event.AmtOut != finalAmt {
			t.Fatalf("outgoing amt mismatch: expected %v, got %v",
				event.AmtOut, finalAmt)
		}

		// Finally, the payment hash should be matched. After the match
		// check, payment hash is deleted in case a duplicate payment
		// hash value causes a false positive.
		if found := paymentHashes[event.PaymentHash]; !found {
			t.Fatalf("paymentHash not found: got %v",
				event.PaymentHash)
		}
		delete(paymentHashes, event.PaymentHash)
	}
}

// TestUpdateFailMalformedHTLCErrorConversion tests that we're able to properly
// convert malformed HTLC errors that originate at the direct link, as well as
// during multi-hop HTLC forwarding.
func TestUpdateFailMalformedHTLCErrorConversion(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3, btcutil.SatoshiPerBitcoin*5,
	)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(
		t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight,
	)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}

	assertPaymentFailure := func(t *testing.T) {
		// With the decoder modified, we'll now attempt to send a
		// payment from Alice to carol.
		finalAmt := lnwire.NewMSatFromSatoshis(100000)
		htlcAmt, totalTimelock, hops := generateHops(
			finalAmt, testStartingHeight, n.firstBobChannelLink,
			n.carolChannelLink,
		)
		firstHop := n.firstBobChannelLink.ShortChanID()
		_, err = makePayment(
			n.aliceServer, n.carolServer, firstHop, hops, finalAmt,
			htlcAmt, totalTimelock,
		).Wait(30 * time.Second)

		// The payment should fail as Carol is unable to decode the
		// onion blob sent to her.
		if err == nil {
			t.Fatalf("unable to send payment: %v", err)
		}

		routingErr := err.(ClearTextError)
		failureMsg := routingErr.WireMessage()
		if _, ok := failureMsg.(*lnwire.FailInvalidOnionKey); !ok {
			t.Fatalf("expected onion failure instead got: %v",
				routingErr.WireMessage())
		}
	}

	t.Run("multi-hop error conversion", func(t *testing.T) {
		// Now that we have our network up, we'll modify the hop
		// iterator for the Bob <-> Carol channel to fail to decode in
		// order to simulate either a replay attack or an issue
		// decoding the onion.
		n.carolOnionDecoder.decodeFail = true

		assertPaymentFailure(t)
	})

	t.Run("direct channel error conversion", func(t *testing.T) {
		// Similar to the above test case, we'll now make the Alice <->
		// Bob link always fail to decode an onion. This differs from
		// the above test case in that there's no encryption on the
		// error at all since Alice will directly receive a
		// UpdateFailMalformedHTLC message.
		n.bobOnionDecoder.decodeFail = true

		assertPaymentFailure(t)
	})
}

// TestSwitchGetPaymentResult tests that the switch interacts as expected with
// the circuit map and network result store when looking up the result of a
// payment ID. This is important for not to lose results under concurrent
// lookup and receiving results.
func TestSwitchGetPaymentResult(t *testing.T) {
	t.Parallel()

	const paymentID = 123
	var preimg lntypes.Preimage
	preimg[0] = 3

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	lookup := make(chan *PaymentCircuit, 1)
	s.circuits = &mockCircuitMap{
		lookup: lookup,
	}

	// If the payment circuit is not found in the circuit map, the payment
	// result must be found in the store if available. Since we haven't
	// added anything to the store yet, ErrPaymentIDNotFound should be
	// returned.
	lookup <- nil
	_, err = s.GetPaymentResult(
		paymentID, lntypes.Hash{}, newMockDeobfuscator(),
	)
	if err != ErrPaymentIDNotFound {
		t.Fatalf("expected ErrPaymentIDNotFound, got %v", err)
	}

	// Next let the lookup find the circuit in the circuit map. It should
	// subscribe to payment results, and return the result when available.
	lookup <- &PaymentCircuit{}
	resultChan, err := s.GetPaymentResult(
		paymentID, lntypes.Hash{}, newMockDeobfuscator(),
	)
	if err != nil {
		t.Fatalf("unable to get payment result: %v", err)
	}

	// Add the result to the store.
	n := &networkResult{
		msg: &lnwire.UpdateFulfillHTLC{
			PaymentPreimage: preimg,
		},
		unencrypted:  true,
		isResolution: true,
	}

	err = s.networkResults.storeResult(paymentID, n)
	if err != nil {
		t.Fatalf("unable to store result: %v", err)
	}

	// The result should be availble.
	select {
	case res, ok := <-resultChan:
		if !ok {
			t.Fatalf("channel was closed")
		}

		if res.Error != nil {
			t.Fatalf("got unexpected error result")
		}

		if res.Preimage != preimg {
			t.Fatalf("expected preimg %v, got %v",
				preimg, res.Preimage)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("result not received")
	}

	// As a final test, try to get the result again. Now that is no longer
	// in the circuit map, it should be immediately available from the
	// store.
	lookup <- nil
	resultChan, err = s.GetPaymentResult(
		paymentID, lntypes.Hash{}, newMockDeobfuscator(),
	)
	if err != nil {
		t.Fatalf("unable to get payment result: %v", err)
	}

	select {
	case res, ok := <-resultChan:
		if !ok {
			t.Fatalf("channel was closed")
		}

		if res.Error != nil {
			t.Fatalf("got unexpected error result")
		}

		if res.Preimage != preimg {
			t.Fatalf("expected preimg %v, got %v",
				preimg, res.Preimage)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("result not received")
	}
}

// TestInvalidFailure tests that the switch returns an unreadable failure error
// if the failure cannot be decrypted.
func TestInvalidFailure(t *testing.T) {
	t.Parallel()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, nil)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}
	defer s.Stop()

	chanID1, _, aliceChanID, _ := genIDs()

	// Set up a mock channel link.
	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add link: %v", err)
	}

	// Create a request which should be forwarded to the mock channel link.
	preimage, err := genPreimage()
	if err != nil {
		t.Fatalf("unable to generate preimage: %v", err)
	}
	rhash := sha256.Sum256(preimage[:])
	update := &lnwire.UpdateAddHTLC{
		PaymentHash: rhash,
		Amount:      1,
	}

	paymentID := uint64(123)

	// Send the request.
	err = s.SendHTLC(
		aliceChannelLink.ShortChanID(), paymentID, update,
	)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// Catch the packet and complete the circuit so that the switch is ready
	// for a response.
	select {
	case packet := <-aliceChannelLink.packets:
		if err := aliceChannelLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("request was not propagated to destination")
	}

	// Send response packet with an unreadable failure message to the
	// switch. The reason failed is not relevant, because we mock the
	// decryption.
	packet := &htlcPacket{
		outgoingChanID: aliceChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc: &lnwire.UpdateFailHTLC{
			Reason: []byte{1, 2, 3},
		},
	}

	if err := s.ForwardPackets(nil, packet); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}

	// Get payment result from switch. We expect an unreadable failure
	// message error.
	deobfuscator := SphinxErrorDecrypter{
		OnionErrorDecrypter: &mockOnionErrorDecryptor{
			err: ErrUnreadableFailureMessage,
		},
	}

	resultChan, err := s.GetPaymentResult(
		paymentID, rhash, &deobfuscator,
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-resultChan:
		if result.Error != ErrUnreadableFailureMessage {
			t.Fatal("expected unreadable failure message")
		}

	case <-time.After(time.Second):
		t.Fatal("err wasn't received")
	}

	// Modify the decryption to simulate that decryption went alright, but
	// the failure cannot be decoded.
	deobfuscator = SphinxErrorDecrypter{
		OnionErrorDecrypter: &mockOnionErrorDecryptor{
			sourceIdx: 2,
			message:   []byte{200},
		},
	}

	resultChan, err = s.GetPaymentResult(
		paymentID, rhash, &deobfuscator,
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-resultChan:
		rtErr, ok := result.Error.(ClearTextError)
		if !ok {
			t.Fatal("expected ClearTextError")
		}
		source, ok := rtErr.(*ForwardingError)
		if !ok {
			t.Fatalf("expected forwarding error, got: %T", rtErr)
		}
		if source.FailureSourceIdx != 2 {
			t.Fatal("unexpected error source index")
		}
		if rtErr.WireMessage() != nil {
			t.Fatal("expected empty failure message")
		}

	case <-time.After(time.Second):
		t.Fatal("err wasn't received")
	}
}

// htlcNotifierEvents is a function that generates a set of expected htlc
// notifier evetns for each node in a three hop network with the dynamic
// values provided. These functions take dynamic values so that changes to
// external systems (such as our default timelock delta) do not break
// these tests.
type htlcNotifierEvents func(channels *clusterChannels, htlcID uint64,
	ts time.Time, htlc *lnwire.UpdateAddHTLC,
	hops []*hop.Payload) ([]interface{}, []interface{}, []interface{})

// TestHtlcNotifier tests the notifying of htlc events that are routed over a
// three hop network. It sets up an Alice -> Bob -> Carol network and routes
// payments from Alice -> Carol to test events from the perspective of a
// sending (Alice), forwarding (Bob) and receiving (Carol) node. Test cases
// are present for saduccessful and failed payments.
func TestHtlcNotifier(t *testing.T) {
	tests := []struct {
		name string

		// Options is a set of options to apply to the three hop
		// network's servers.
		options []serverOption

		// expectedEvents is a function which returns an expected set
		// of events for the test.
		expectedEvents htlcNotifierEvents

		// iterations is the number of times we will send a payment,
		// this is used to send more than one payment to force non-
		// zero htlc indexes to make sure we aren't just checking
		// default values.
		iterations int
	}{
		{
			name:    "successful three hop payment",
			options: nil,
			expectedEvents: func(channels *clusterChannels,
				htlcID uint64, ts time.Time,
				htlc *lnwire.UpdateAddHTLC,
				hops []*hop.Payload) ([]interface{},
				[]interface{}, []interface{}) {

				return getThreeHopEvents(
					channels, htlcID, ts, htlc, hops, nil,
				)
			},
			iterations: 2,
		},
		{
			name: "failed at forwarding link",
			// Set a functional option which disables bob as a
			// forwarding node to force a payment error.
			options: []serverOption{
				serverOptionRejectHtlc(false, true, false),
			},
			expectedEvents: func(channels *clusterChannels,
				htlcID uint64, ts time.Time,
				htlc *lnwire.UpdateAddHTLC,
				hops []*hop.Payload) ([]interface{},
				[]interface{}, []interface{}) {

				return getThreeHopEvents(
					channels, htlcID, ts, htlc, hops,
					&LinkError{
						msg:           &lnwire.FailChannelDisabled{},
						FailureDetail: OutgoingFailureForwardsDisabled,
					},
				)
			},
			iterations: 1,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			testHtcNotifier(
				t, test.options, test.iterations,
				test.expectedEvents,
			)
		})
	}
}

// testHtcNotifier runs a htlc notifier test.
func testHtcNotifier(t *testing.T, testOpts []serverOption, iterations int,
	getEvents htlcNotifierEvents) {

	t.Parallel()

	// First, we'll create our traditional three hop
	// network.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	// Mock time so that all events are reported with a static timestamp.
	now := time.Now()
	mockTime := func() time.Time {
		return now
	}

	// Create htlc notifiers for each server in the three hop network and
	// start them.
	aliceNotifier := NewHtlcNotifier(mockTime)
	if err := aliceNotifier.Start(); err != nil {
		t.Fatalf("could not start alice notifier")
	}
	defer aliceNotifier.Stop()

	bobNotifier := NewHtlcNotifier(mockTime)
	if err := bobNotifier.Start(); err != nil {
		t.Fatalf("could not start bob notifier")
	}
	defer bobNotifier.Stop()

	carolNotifier := NewHtlcNotifier(mockTime)
	if err := carolNotifier.Start(); err != nil {
		t.Fatalf("could not start carol notifier")
	}
	defer carolNotifier.Stop()

	// Create a notifier server option which will set our htlc notifiers
	// for the three hop network.
	notifierOption := serverOptionWithHtlcNotifier(
		aliceNotifier, bobNotifier, carolNotifier,
	)

	// Add the htlcNotifier option to any other options
	// set in the test.
	options := append(testOpts, notifierOption)

	n := newThreeHopNetwork(
		t, channels.aliceToBob,
		channels.bobToAlice, channels.bobToCarol,
		channels.carolToBob, testStartingHeight,
		options...,
	)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop "+
			"network: %v", err)
	}
	defer n.stop()

	// Before we forward anything, subscribe to htlc events
	// from each notifier.
	aliceEvents, err := aliceNotifier.SubscribeHtlcEvents()
	if err != nil {
		t.Fatalf("could not subscribe to alice's"+
			" events: %v", err)
	}
	defer aliceEvents.Cancel()

	bobEvents, err := bobNotifier.SubscribeHtlcEvents()
	if err != nil {
		t.Fatalf("could not subscribe to bob's"+
			" events: %v", err)
	}
	defer bobEvents.Cancel()

	carolEvents, err := carolNotifier.SubscribeHtlcEvents()
	if err != nil {
		t.Fatalf("could not subscribe to carol's"+
			" events: %v", err)
	}
	defer carolEvents.Cancel()

	// Send multiple payments, as specified by the test to test incrementing
	// of htlc ids.
	for i := 0; i < iterations; i++ {
		// We'll start off by making a payment from
		// Alice -> Bob -> Carol.
		htlc, hops := n.sendThreeHopPayment(t)

		alice, bob, carol := getEvents(
			channels, uint64(i), now, htlc, hops,
		)

		checkHtlcEvents(t, aliceEvents.Updates(), alice)
		checkHtlcEvents(t, bobEvents.Updates(), bob)
		checkHtlcEvents(t, carolEvents.Updates(), carol)

	}
}

// checkHtlcEvents checks that a subscription has the set of htlc events
// we expect it to have.
func checkHtlcEvents(t *testing.T, events <-chan interface{},
	expectedEvents []interface{}) {

	t.Helper()

	for _, expected := range expectedEvents {
		select {
		case event := <-events:
			if !reflect.DeepEqual(event, expected) {
				t.Fatalf("expected %v, got: %v", expected,
					event)
			}

		case <-time.After(5 * time.Second):
			t.Fatalf("expected event: %v", expected)
		}
	}
}

// sendThreeHopPayment is a helper function which sends a payment over
// Alice -> Bob -> Carol in a three hop network and returns Alice's first htlc
// and the remainder of the hops.
func (n *threeHopNetwork) sendThreeHopPayment(t *testing.T) (*lnwire.UpdateAddHTLC,
	[]*hop.Payload) {

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)
	blob, err := generateRoute(hops...)
	if err != nil {
		t.Fatal(err)
	}
	invoice, htlc, pid, err := generatePayment(
		amount, htlcAmt, totalTimelock, blob,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = n.carolServer.registry.AddInvoice(*invoice, htlc.PaymentHash)
	if err != nil {
		t.Fatalf("unable to add invoice in carol registry: %v", err)
	}

	if err := n.aliceServer.htlcSwitch.SendHTLC(
		n.firstBobChannelLink.ShortChanID(), pid, htlc,
	); err != nil {
		t.Fatalf("could not send htlc")
	}

	return htlc, hops
}

// getThreeHopEvents gets the set of htlc events that we expect for a payment
// from Alice -> Bob -> Carol. If a non-nil link error is provided, the set
// of events will fail on Bob's outgoing link.
func getThreeHopEvents(channels *clusterChannels, htlcID uint64,
	ts time.Time, htlc *lnwire.UpdateAddHTLC, hops []*hop.Payload,
	linkError *LinkError) ([]interface{}, []interface{}, []interface{}) {

	aliceKey := HtlcKey{
		IncomingCircuit: zeroCircuit,
		OutgoingCircuit: channeldb.CircuitKey{
			ChanID: channels.aliceToBob.ShortChanID(),
			HtlcID: htlcID,
		},
	}

	// Alice always needs a forwarding event because she initiates the
	// send.
	aliceEvents := []interface{}{
		&ForwardingEvent{
			HtlcKey: aliceKey,
			HtlcInfo: HtlcInfo{
				OutgoingTimeLock: htlc.Expiry,
				OutgoingAmt:      htlc.Amount,
			},
			HtlcEventType: HtlcEventTypeSend,
			Timestamp:     ts,
		},
	}

	bobKey := HtlcKey{
		IncomingCircuit: channeldb.CircuitKey{
			ChanID: channels.bobToAlice.ShortChanID(),
			HtlcID: htlcID,
		},
		OutgoingCircuit: channeldb.CircuitKey{
			ChanID: channels.bobToCarol.ShortChanID(),
			HtlcID: htlcID,
		},
	}

	bobInfo := HtlcInfo{
		IncomingTimeLock: htlc.Expiry,
		IncomingAmt:      htlc.Amount,
		OutgoingTimeLock: hops[1].FwdInfo.OutgoingCTLV,
		OutgoingAmt:      hops[1].FwdInfo.AmountToForward,
	}

	// If we expect the payment to fail, we add failures for alice and
	// bob, and no events for carol because the payment never reaches her.
	if linkError != nil {
		aliceEvents = append(aliceEvents,
			&ForwardingFailEvent{
				HtlcKey:       aliceKey,
				HtlcEventType: HtlcEventTypeSend,
				Timestamp:     ts,
			},
		)

		bobEvents := []interface{}{
			&LinkFailEvent{
				HtlcKey:       bobKey,
				HtlcInfo:      bobInfo,
				HtlcEventType: HtlcEventTypeForward,
				LinkError:     linkError,
				Incoming:      false,
				Timestamp:     ts,
			},
		}

		return aliceEvents, bobEvents, nil
	}

	// If we want to get events for a successful payment, we add a settle
	// for alice, a forward and settle for bob and a receive settle for
	// carol.
	aliceEvents = append(
		aliceEvents,
		&SettleEvent{
			HtlcKey:       aliceKey,
			HtlcEventType: HtlcEventTypeSend,
			Timestamp:     ts,
		},
	)

	bobEvents := []interface{}{
		&ForwardingEvent{
			HtlcKey:       bobKey,
			HtlcInfo:      bobInfo,
			HtlcEventType: HtlcEventTypeForward,
			Timestamp:     ts,
		},
		&SettleEvent{
			HtlcKey:       bobKey,
			HtlcEventType: HtlcEventTypeForward,
			Timestamp:     ts,
		},
	}

	carolEvents := []interface{}{
		&SettleEvent{
			HtlcKey: HtlcKey{
				IncomingCircuit: channeldb.CircuitKey{
					ChanID: channels.carolToBob.ShortChanID(),
					HtlcID: htlcID,
				},
				OutgoingCircuit: zeroCircuit,
			},
			HtlcEventType: HtlcEventTypeReceive,
			Timestamp:     ts,
		},
	}

	return aliceEvents, bobEvents, carolEvents
}

type mockForwardInterceptor struct {
	intercepted InterceptedForward
}

func (m *mockForwardInterceptor) InterceptForwardHtlc(intercepted InterceptedForward) bool {

	m.intercepted = intercepted
	return true
}

func (m *mockForwardInterceptor) settle(preimage lntypes.Preimage) error {
	return m.intercepted.Settle(preimage)
}

func (m *mockForwardInterceptor) fail() error {
	return m.intercepted.Fail()
}

func (m *mockForwardInterceptor) resume() error {
	return m.intercepted.Resume()
}

func assertNumCircuits(t *testing.T, s *Switch, pending, opened int) {
	if s.circuits.NumPending() != pending {
		t.Fatal("wrong amount of half circuits")
	}
	if s.circuits.NumOpen() != opened {
		t.Fatal("wrong amount of circuits")
	}
}

func assertOutgoingLinkReceive(t *testing.T, targetLink *mockChannelLink,
	expectReceive bool) {

	// Pull packet from targetLink link.
	select {
	case packet := <-targetLink.packets:
		if !expectReceive {
			t.Fatal("forward was intercepted, shouldn't land at bob link")
		} else if err := targetLink.completeCircuit(packet); err != nil {
			t.Fatalf("unable to complete payment circuit: %v", err)
		}

	case <-time.After(time.Second):
		if expectReceive {
			t.Fatal("request was not propagated to destination")
		}
	}
}

func TestSwitchHoldForward(t *testing.T) {
	t.Parallel()

	chanID1, chanID2, aliceChanID, bobChanID := genIDs()

	alicePeer, err := newMockServer(
		t, "alice", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create alice server: %v", err)
	}
	bobPeer, err := newMockServer(
		t, "bob", testStartingHeight, nil, testDefaultDelta,
	)
	if err != nil {
		t.Fatalf("unable to create bob server: %v", err)
	}

	tempPath, err := ioutil.TempDir("", "circuitdb")
	if err != nil {
		t.Fatalf("unable to temporary path: %v", err)
	}

	cdb, err := channeldb.Open(tempPath)
	if err != nil {
		t.Fatalf("unable to open channeldb: %v", err)
	}

	s, err := initSwitchWithDB(testStartingHeight, cdb)
	if err != nil {
		t.Fatalf("unable to init switch: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("unable to start switch: %v", err)
	}

	defer func() {
		if err := s.Stop(); err != nil {
			t.Fatalf(err.Error())
		}
	}()

	aliceChannelLink := newMockChannelLink(
		s, chanID1, aliceChanID, alicePeer, true,
	)
	bobChannelLink := newMockChannelLink(
		s, chanID2, bobChanID, bobPeer, true,
	)
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarded from Alice channel link to
	// bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := sha256.Sum256(preimage[:])
	ogPacket := &htlcPacket{
		incomingChanID: aliceChannelLink.ShortChanID(),
		incomingHTLCID: 0,
		outgoingChanID: bobChannelLink.ShortChanID(),
		obfuscator:     NewMockObfuscator(),
		htlc: &lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
			Amount:      1,
		},
	}

	forwardInterceptor := &mockForwardInterceptor{}
	switchForwardInterceptor := NewInterceptableSwitch(s)
	switchForwardInterceptor.SetInterceptor(forwardInterceptor.InterceptForwardHtlc)
	linkQuit := make(chan struct{})

	// Test resume a hold forward
	assertNumCircuits(t, s, 0, 0)
	if err := switchForwardInterceptor.ForwardPackets(linkQuit, ogPacket); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}
	assertNumCircuits(t, s, 0, 0)
	assertOutgoingLinkReceive(t, bobChannelLink, false)

	if err := forwardInterceptor.resume(); err != nil {
		t.Fatalf("failed to resume forward")
	}
	assertOutgoingLinkReceive(t, bobChannelLink, true)
	assertNumCircuits(t, s, 1, 1)

	// settling the htlc to close the circuit.
	settle := &htlcPacket{
		outgoingChanID: bobChannelLink.ShortChanID(),
		outgoingHTLCID: 0,
		amount:         1,
		htlc: &lnwire.UpdateFulfillHTLC{
			PaymentPreimage: preimage,
		},
	}
	if err := switchForwardInterceptor.ForwardPackets(linkQuit, settle); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}
	assertOutgoingLinkReceive(t, aliceChannelLink, true)
	assertNumCircuits(t, s, 0, 0)

	// Test failing a hold forward
	if err := switchForwardInterceptor.ForwardPackets(linkQuit, ogPacket); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}
	assertNumCircuits(t, s, 0, 0)
	assertOutgoingLinkReceive(t, bobChannelLink, false)

	if err := forwardInterceptor.fail(); err != nil {
		t.Fatalf("failed to cancel forward %v", err)
	}
	assertOutgoingLinkReceive(t, bobChannelLink, false)
	assertOutgoingLinkReceive(t, aliceChannelLink, true)
	assertNumCircuits(t, s, 0, 0)

	// Test settling a hold forward
	if err := switchForwardInterceptor.ForwardPackets(linkQuit, ogPacket); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}
	assertNumCircuits(t, s, 0, 0)
	assertOutgoingLinkReceive(t, bobChannelLink, false)

	if err := forwardInterceptor.settle(preimage); err != nil {
		t.Fatal("failed to cancel forward")
	}
	assertOutgoingLinkReceive(t, bobChannelLink, false)
	assertOutgoingLinkReceive(t, aliceChannelLink, true)
	assertNumCircuits(t, s, 0, 0)
}
