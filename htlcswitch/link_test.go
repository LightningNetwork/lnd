package htlcswitch

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/ticker"
	"github.com/stretchr/testify/require"
)

const (
	testStartingHeight = 100
	testDefaultDelta   = 6
)

// concurrentTester is a thread-safe wrapper around the Fatalf method of a
// *testing.T instance. With this wrapper multiple goroutines can safely
// attempt to fail a test concurrently.
type concurrentTester struct {
	mtx sync.Mutex
	*testing.T
}

func newConcurrentTester(t *testing.T) *concurrentTester {
	return &concurrentTester{
		T: t,
	}
}

func (c *concurrentTester) Fatalf(format string, args ...interface{}) {
	c.T.Helper()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.T.Fatalf(format, args...)
}

// messageToString is used to produce less spammy log messages in trace mode by
// setting the 'Curve" parameter to nil. Doing this avoids printing out each of
// the field elements in the curve parameters for secp256k1.
func messageToString(msg lnwire.Message) string {
	switch m := msg.(type) {
	case *lnwire.RevokeAndAck:
		m.NextRevocationKey.Curve = nil
	case *lnwire.AcceptChannel:
		m.FundingKey.Curve = nil
		m.RevocationPoint.Curve = nil
		m.PaymentPoint.Curve = nil
		m.DelayedPaymentPoint.Curve = nil
		m.FirstCommitmentPoint.Curve = nil
	case *lnwire.OpenChannel:
		m.FundingKey.Curve = nil
		m.RevocationPoint.Curve = nil
		m.PaymentPoint.Curve = nil
		m.DelayedPaymentPoint.Curve = nil
		m.FirstCommitmentPoint.Curve = nil
	case *lnwire.FundingLocked:
		m.NextPerCommitmentPoint.Curve = nil
	}

	return spew.Sdump(msg)
}

// expectedMessage struct holds the message which travels from one peer to
// another, and additional information like, should this message we skipped for
// handling.
type expectedMessage struct {
	from    string
	to      string
	message lnwire.Message
	skip    bool
}

// createLogFunc is a helper function which returns the function which will be
// used for logging message are received from another peer.
func createLogFunc(name string, channelID lnwire.ChannelID) messageInterceptor {
	return func(m lnwire.Message) (bool, error) {
		chanID, err := getChanID(m)
		if err != nil {
			return false, err
		}

		if chanID == channelID {
			fmt.Printf("---------------------- \n %v received: "+
				"%v", name, messageToString(m))
		}
		return false, nil
	}
}

// createInterceptorFunc creates the function by the given set of messages
// which, checks the order of the messages and skip the ones which were
// indicated to be intercepted.
func createInterceptorFunc(prefix, receiver string, messages []expectedMessage,
	chanID lnwire.ChannelID, debug bool) messageInterceptor {

	// Filter message which should be received with given peer name.
	var expectToReceive []expectedMessage
	for _, message := range messages {
		if message.to == receiver {
			expectToReceive = append(expectToReceive, message)
		}
	}

	// Return function which checks the message order and skip the
	// messages.
	return func(m lnwire.Message) (bool, error) {
		messageChanID, err := getChanID(m)
		if err != nil {
			return false, err
		}

		if messageChanID == chanID {
			if len(expectToReceive) == 0 {
				return false, errors.Errorf("%v received "+
					"unexpected message out of range: %v",
					receiver, m.MsgType())
			}

			expectedMessage := expectToReceive[0]
			expectToReceive = expectToReceive[1:]

			if expectedMessage.message.MsgType() != m.MsgType() {
				return false, errors.Errorf("%v received wrong message: \n"+
					"real: %v\nexpected: %v", receiver, m.MsgType(),
					expectedMessage.message.MsgType())
			}

			if debug {
				var postfix string
				if revocation, ok := m.(*lnwire.RevokeAndAck); ok {
					var zeroHash chainhash.Hash
					if bytes.Equal(zeroHash[:], revocation.Revocation[:]) {
						postfix = "- empty revocation"
					}
				}

				if expectedMessage.skip {
					fmt.Printf("skipped: %v: %v %v \n", prefix,
						m.MsgType(), postfix)
				} else {
					fmt.Printf("%v: %v %v \n", prefix, m.MsgType(), postfix)
				}
			}

			return expectedMessage.skip, nil
		}
		return false, nil
	}
}

// TestChannelLinkRevThenSig tests that if a link owes both a revocation and a
// signature to the counterparty (in this order), that they are sent as rev and
// then sig.
//
// Specifically, this tests the following scenario:
//
// A               B
//   <----add-----
//   -----add---->
//   <----sig-----
//   -----rev----x
//   -----sig----x
func TestChannelLinkRevThenSig(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTicker, start, cleanUp, restore, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	require.NoError(t, err)
	defer cleanUp()

	err = start()
	require.NoError(t, err)
	defer aliceLink.Stop()

	alice := newPersistentLinkHarness(
		t, aliceLink, batchTicker, restore,
	)

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	bobHtlc1 := generateHtlc(t, coreLink, 0)

	// <-----add-----
	// Send an htlc from Bob to Alice.
	ctx.sendHtlcBobToAlice(bobHtlc1)

	aliceHtlc1, _ := generateHtlcAndInvoice(t, 0)

	// ------add---->
	ctx.sendHtlcAliceToBob(0, aliceHtlc1)
	ctx.receiveHtlcAliceToBob()

	// <-----sig-----
	ctx.sendCommitSigBobToAlice(1)

	// ------rev----x
	var msg lnwire.Message
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	_, ok := msg.(*lnwire.RevokeAndAck)
	require.True(t, ok)

	// ------sig----x
	// Trigger a commitsig from Alice->Bob.
	select {
	case batchTicker <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatalf("could not force commit sig")
	}

	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	comSig, ok := msg.(*lnwire.CommitSig)
	require.True(t, ok)

	if len(comSig.HtlcSigs) != 2 {
		t.Fatalf("expected 2 htlc sigs, got %d", len(comSig.HtlcSigs))
	}

	// Restart Alice so she sends and accepts ChannelReestablish.
	cleanUp = alice.restart(false, true)
	defer cleanUp()

	ctx.aliceLink = alice.link
	ctx.aliceMsgs = alice.msgs

	// Restart Bob as well by calling NewLightningChannel.
	bobSigner := bobChannel.Signer
	bobPool := lnwallet.NewSigPool(runtime.NumCPU(), bobSigner)
	bobChannel, err = lnwallet.NewLightningChannel(
		bobSigner, bobChannel.State(), bobPool,
	)
	require.NoError(t, err)
	err = bobPool.Start()
	require.NoError(t, err)

	ctx.bobChannel = bobChannel

	// --reestablish->
	select {
	case msg = <-ctx.aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	_, ok = msg.(*lnwire.ChannelReestablish)
	require.True(t, ok)

	// <-reestablish--
	bobReest, err := bobChannel.State().ChanSyncMsg()
	require.NoError(t, err)
	ctx.aliceLink.HandleChannelUpdate(bobReest)

	// ------rev---->
	ctx.receiveRevAndAckAliceToBob()

	// ------add---->
	ctx.receiveHtlcAliceToBob()

	// ------sig---->
	ctx.receiveCommitSigAliceToBob(2)
}

// TestChannelLinkSigThenRev tests that if a link owes both a signature and a
// revocation to the counterparty (in this order), that they are sent as sig
// and then rev.
//
// Specifically, this tests the following scenario:
//
// A               B
//   <----add-----
//   -----add---->
//   -----sig----x
//   <----sig-----
//   -----rev----x
func TestChannelLinkSigThenRev(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTicker, start, cleanUp, restore, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	require.NoError(t, err)
	defer cleanUp()

	err = start()
	require.NoError(t, err)
	defer aliceLink.Stop()

	alice := newPersistentLinkHarness(
		t, aliceLink, batchTicker, restore,
	)

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	bobHtlc1 := generateHtlc(t, coreLink, 0)

	// <-----add-----
	// Send an htlc from Bob to Alice.
	ctx.sendHtlcBobToAlice(bobHtlc1)

	aliceHtlc1, _ := generateHtlcAndInvoice(t, 0)

	// ------add---->
	ctx.sendHtlcAliceToBob(0, aliceHtlc1)
	ctx.receiveHtlcAliceToBob()

	// ------sig----x
	// Trigger a commitsig from Alice->Bob.
	select {
	case batchTicker <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatalf("could not force commit sig")
	}

	var msg lnwire.Message
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	comSig, ok := msg.(*lnwire.CommitSig)
	require.True(t, ok)

	if len(comSig.HtlcSigs) != 1 {
		t.Fatalf("expected 1 htlc sig, got %d", len(comSig.HtlcSigs))
	}

	// <-----sig-----
	ctx.sendCommitSigBobToAlice(1)

	// ------rev----x
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	_, ok = msg.(*lnwire.RevokeAndAck)
	require.True(t, ok)

	// Restart Alice so she sends and accepts ChannelReestablish.
	cleanUp = alice.restart(false, true)
	defer cleanUp()

	ctx.aliceLink = alice.link
	ctx.aliceMsgs = alice.msgs

	// Restart Bob as well by calling NewLightningChannel.
	bobSigner := bobChannel.Signer
	bobPool := lnwallet.NewSigPool(runtime.NumCPU(), bobSigner)
	bobChannel, err = lnwallet.NewLightningChannel(
		bobSigner, bobChannel.State(), bobPool,
	)
	require.NoError(t, err)
	err = bobPool.Start()
	require.NoError(t, err)

	ctx.bobChannel = bobChannel

	// --reestablish->
	select {
	case msg = <-ctx.aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	_, ok = msg.(*lnwire.ChannelReestablish)
	require.True(t, ok)

	// <-reestablish--
	bobReest, err := bobChannel.State().ChanSyncMsg()
	require.NoError(t, err)
	ctx.aliceLink.HandleChannelUpdate(bobReest)

	// ------add---->
	ctx.receiveHtlcAliceToBob()

	// ------sig---->
	ctx.receiveCommitSigAliceToBob(1)

	// ------rev---->
	ctx.receiveRevAndAckAliceToBob()
}

// TestChannelLinkSingleHopPayment in this test we checks the interaction
// between Alice and Bob within scope of one channel.
func TestChannelLinkSingleHopPayment(t *testing.T) {
	t.Parallel()

	// Setup a alice-bob network.
	alice, bob, cleanUp, err := createTwoClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newTwoHopNetwork(
		t, alice.channel, bob.channel, testStartingHeight,
	)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()
	bobBandwidthBefore := n.bobChannelLink.Bandwidth()

	debug := false
	if debug {
		// Log message that alice receives.
		n.aliceServer.intersect(createLogFunc("alice",
			n.aliceChannelLink.ChanID()))

		// Log message that bob receives.
		n.bobServer.intersect(createLogFunc("bob",
			n.bobChannelLink.ChanID()))
	}

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.bobChannelLink)

	// Wait for:
	// * HTLC add request to be sent to bob.
	// * alice<->bob commitment state to be updated.
	// * settle request to be sent back from bob to alice.
	// * alice<->bob commitment state to be updated.
	// * user notification to be sent.
	receiver := n.bobServer
	firstHop := n.bobChannelLink.ShortChanID()
	rhash, err := makePayment(
		n.aliceServer, receiver, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to make the payment: %v", err)
	}

	// Wait for Alice to receive the revocation.
	//
	// TODO(roasbeef); replace with select over returned err chan
	time.Sleep(2 * time.Second)

	// Check that alice invoice was settled and bandwidth of HTLC
	// links was changed.
	invoice, err := receiver.registry.LookupInvoice(rhash)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State != channeldb.ContractSettled {
		t.Fatal("alice invoice wasn't settled")
	}

	if aliceBandwidthBefore-amount != n.aliceChannelLink.Bandwidth() {
		t.Fatal("alice bandwidth should have decrease on payment " +
			"amount")
	}

	if bobBandwidthBefore+amount != n.bobChannelLink.Bandwidth() {
		t.Fatalf("bob bandwidth isn't match: expected %v, got %v",
			bobBandwidthBefore+amount,
			n.bobChannelLink.Bandwidth())
	}
}

// TestChannelLinkMultiHopPayment checks the ability to send payment over two
// hops. In this test we send the payment from Carol to Alice over Bob peer.
// (Carol -> Bob -> Alice) and checking that HTLC was settled properly and
// balances were changed in two channels.
//
// The test is executed with two different OutgoingCltvRejectDelta values for
// bob. In addition to a normal positive value, we also test the zero case
// because this is currently the configured value in lnd
// (defaultOutgoingCltvRejectDelta).
func TestChannelLinkMultiHopPayment(t *testing.T) {
	t.Run(
		"bobOutgoingCltvRejectDelta 3",
		func(t *testing.T) {
			testChannelLinkMultiHopPayment(t, 3)
		},
	)
	t.Run(
		"bobOutgoingCltvRejectDelta 0",
		func(t *testing.T) {
			testChannelLinkMultiHopPayment(t, 0)
		},
	)
}

func testChannelLinkMultiHopPayment(t *testing.T,
	bobOutgoingCltvRejectDelta uint32) {

	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)

	n.firstBobChannelLink.cfg.OutgoingCltvRejectDelta =
		bobOutgoingCltvRejectDelta

	n.secondBobChannelLink.cfg.OutgoingCltvRejectDelta =
		bobOutgoingCltvRejectDelta

	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	debug := false
	if debug {
		// Log messages that alice receives from bob.
		n.aliceServer.intersect(createLogFunc("[alice]<-bob<-carol: ",
			n.aliceChannelLink.ChanID()))

		// Log messages that bob receives from alice.
		n.bobServer.intersect(createLogFunc("alice->[bob]->carol: ",
			n.firstBobChannelLink.ChanID()))

		// Log messages that bob receives from carol.
		n.bobServer.intersect(createLogFunc("alice<-[bob]<-carol: ",
			n.secondBobChannelLink.ChanID()))

		// Log messages that carol receives from bob.
		n.carolServer.intersect(createLogFunc("alice->bob->[carol]",
			n.carolChannelLink.ChanID()))
	}

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount,
		testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	// Wait for:
	// * HTLC add request to be sent from Alice to Bob.
	// * Alice<->Bob commitment states to be updated.
	// * HTLC add request to be propagated to Carol.
	// * Bob<->Carol commitment state to be updated.
	// * settle request to be sent back from Carol to Bob.
	// * Alice<->Bob commitment state to be updated.
	// * settle request to be sent back from Bob to Alice.
	// * Alice<->Bob commitment states to be updated.
	// * user notification to be sent.
	receiver := n.carolServer
	firstHop := n.firstBobChannelLink.ShortChanID()
	rhash, err := makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// Wait for Alice and Bob's second link to receive the revocation.
	time.Sleep(2 * time.Second)

	// Check that Carol invoice was settled and bandwidth of HTLC
	// links were changed.
	invoice, err := receiver.registry.LookupInvoice(rhash)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State != channeldb.ContractSettled {
		t.Fatal("carol invoice haven't been settled")
	}

	expectedAliceBandwidth := aliceBandwidthBefore - htlcAmt
	if expectedAliceBandwidth != n.aliceChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedAliceBandwidth, n.aliceChannelLink.Bandwidth())
	}

	expectedBobBandwidth1 := firstBobBandwidthBefore + htlcAmt
	if expectedBobBandwidth1 != n.firstBobChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedBobBandwidth1, n.firstBobChannelLink.Bandwidth())
	}

	expectedBobBandwidth2 := secondBobBandwidthBefore - amount
	if expectedBobBandwidth2 != n.secondBobChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedBobBandwidth2, n.secondBobChannelLink.Bandwidth())
	}

	expectedCarolBandwidth := carolBandwidthBefore + amount
	if expectedCarolBandwidth != n.carolChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedCarolBandwidth, n.carolChannelLink.Bandwidth())
	}
}

// TestChannelLinkCancelFullCommitment tests the ability for links to cancel
// forwarded HTLCs once all of their commitment slots are full.
func TestChannelLinkCancelFullCommitment(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newTwoHopNetwork(
		t, channels.aliceToBob, channels.bobToAlice, testStartingHeight,
	)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	// Fill up the commitment from Alice's side with 20 sat payments.
	count := (input.MaxHTLCNumber / 2)
	amt := lnwire.NewMSatFromSatoshis(20000)

	htlcAmt, totalTimelock, hopsForwards := generateHops(amt,
		testStartingHeight, n.bobChannelLink)

	firstHop := n.aliceChannelLink.ShortChanID()

	// Create channels to buffer the preimage and error channels used in
	// making the preliminary payments.
	preimages := make([]lntypes.Preimage, count)
	aliceErrChan := make(chan chan error, count)

	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		// Deterministically generate preimages. Avoid the all-zeroes
		// preimage because that will be rejected by the database.
		preimages[i] = lntypes.Preimage{byte(i >> 8), byte(i), 1}

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			errChan := n.makeHoldPayment(
				n.aliceServer, n.bobServer, firstHop,
				hopsForwards, amt, htlcAmt, totalTimelock,
				preimages[i],
			)
			aliceErrChan <- errChan
		}(i)
	}

	// Wait for Alice to finish filling her commitment.
	wg.Wait()
	close(aliceErrChan)

	// Now make an additional payment from Alice to Bob, this should be
	// canceled because the commitment in this direction is full.
	err = <-makePayment(
		n.aliceServer, n.bobServer, firstHop, hopsForwards, amt,
		htlcAmt, totalTimelock,
	).err
	if err == nil {
		t.Fatalf("overflow payment should have failed")
	}
	lerr, ok := err.(*LinkError)
	if !ok {
		t.Fatalf("expected LinkError, got: %T", err)
	}

	msg := lerr.WireMessage()
	if _, ok := msg.(*lnwire.FailTemporaryChannelFailure); !ok {
		t.Fatalf("expected TemporaryChannelFailure, got: %T", msg)
	}

	// Now, settle all htlcs held by bob and clear the commitment of htlcs.
	for _, preimage := range preimages {
		preimage := preimage

		// It's possible that the HTLCs have not been delivered to the
		// invoice registry at this point, so we poll until we are able
		// to settle.
		err = wait.NoError(func() error {
			return n.bobServer.registry.SettleHodlInvoice(preimage)
		}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that all of the payments sent by alice eventually succeed.
	for errChan := range aliceErrChan {
		err := <-errChan
		if err != nil {
			t.Fatalf("alice payment failed: %v", err)
		}
	}
}

// TestExitNodeTimelockPayloadMismatch tests that when an exit node receives an
// incoming HTLC, if the time lock encoded in the payload of the forwarded HTLC
// doesn't match the expected payment value, then the HTLC will be rejected
// with the appropriate error.
func TestExitNodeTimelockPayloadMismatch(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	const amount = btcutil.SatoshiPerBitcoin
	htlcAmt, htlcExpiry, hops := generateHops(amount,
		testStartingHeight, n.firstBobChannelLink)

	// In order to exercise this case, we'll now _manually_ modify the
	// per-hop payload for outgoing time lock to be the incorrect value.
	// The proper value of the outgoing CLTV should be the policy set by
	// the receiving node, instead we set it to be a random value.
	hops[0].FwdInfo.OutgoingCTLV = 500
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amount, htlcAmt,
		htlcExpiry,
	).Wait(30 * time.Second)
	if err == nil {
		t.Fatalf("payment should have failed but didn't")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T", err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailFinalIncorrectCltvExpiry:
	default:
		t.Fatalf("incorrect error, expected incorrect cltv expiry, "+
			"instead have: %v", err)
	}
}

// TestExitNodeAmountPayloadMismatch tests that when an exit node receives an
// incoming HTLC, if the amount encoded in the onion payload of the forwarded
// HTLC doesn't match the expected payment value, then the HTLC will be
// rejected.
func TestExitNodeAmountPayloadMismatch(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	const amount = btcutil.SatoshiPerBitcoin
	htlcAmt, htlcExpiry, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink)

	// In order to exercise this case, we'll now _manually_ modify the
	// per-hop payload for amount to be the incorrect value.  The proper
	// value of the amount to forward should be the amount that the
	// receiving node expects to receive.
	hops[0].FwdInfo.AmountToForward = 1
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amount, htlcAmt,
		htlcExpiry,
	).Wait(30 * time.Second)
	if err == nil {
		t.Fatalf("payment should have failed but didn't")
	}
	assertFailureCode(t, err, lnwire.CodeFinalIncorrectHtlcAmount)
}

// TestLinkForwardTimelockPolicyMismatch tests that if a node is an
// intermediate node in a multi-hop payment, and receives an HTLC which
// violates its specified multi-hop policy, then the HTLC is rejected.
func TestLinkForwardTimelockPolicyMismatch(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	// We'll be sending 1 BTC over a 2-hop (3 vertex) route.
	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	// Generate the route over two hops, ignoring the total time lock that
	// we'll need to use for the first HTLC in order to have a sufficient
	// time-lock value to account for the decrements over the entire route.
	htlcAmt, htlcExpiry, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)
	htlcExpiry -= 2

	// Next, we'll make the payment which'll send an HTLC with our
	// specified parameters to the first hop in the route.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount, htlcAmt,
		htlcExpiry,
	).Wait(30 * time.Second)

	// We should get an error, and that error should indicate that the HTLC
	// should be rejected due to a policy violation.
	if err == nil {
		t.Fatalf("payment should have failed but didn't")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T", err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailIncorrectCltvExpiry:
	default:
		t.Fatalf("incorrect error, expected incorrect cltv expiry, "+
			"instead have: %v", err)
	}
}

// TestLinkForwardFeePolicyMismatch tests that if a node is an intermediate
// node in a multi-hop payment and receives an HTLC that violates its current
// fee policy, then the HTLC is rejected with the proper error.
func TestLinkForwardFeePolicyMismatch(t *testing.T) {
	t.Parallel()

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
		t.Fatal(err)
	}
	defer n.stop()

	// We'll be sending 1 BTC over a 2-hop (3 vertex) route. Given the
	// current default fee of 1 SAT, if we just send a single BTC over in
	// an HTLC, it should be rejected.
	amountNoFee := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	// Generate the route over two hops, ignoring the amount we _should_
	// actually send in order to be able to cover fees.
	_, htlcExpiry, hops := generateHops(amountNoFee, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	// Next, we'll make the payment which'll send an HTLC with our
	// specified parameters to the first hop in the route.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amountNoFee,
		amountNoFee, htlcExpiry,
	).Wait(30 * time.Second)

	// We should get an error, and that error should indicate that the HTLC
	// should be rejected due to a policy violation.
	if err == nil {
		t.Fatalf("payment should have failed but didn't")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T", err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailFeeInsufficient:
	default:
		t.Fatalf("incorrect error, expected fee insufficient, "+
			"instead have: %T", err)
	}
}

// TestLinkForwardFeePolicyMismatch tests that if a node is an intermediate
// node and receives an HTLC which is _below_ its min HTLC policy, then the
// HTLC will be rejected.
func TestLinkForwardMinHTLCPolicyMismatch(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	// The current default global min HTLC policy set in the default config
	// for the three-hop-network is 5 SAT. So in order to trigger this
	// failure mode, we'll create an HTLC with 1 satoshi.
	amountNoFee := lnwire.NewMSatFromSatoshis(1)

	// With the amount set, we'll generate a route over 2 hops within the
	// network that attempts to pay out our specified amount.
	htlcAmt, htlcExpiry, hops := generateHops(amountNoFee, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	// Next, we'll make the payment which'll send an HTLC with our
	// specified parameters to the first hop in the route.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amountNoFee,
		htlcAmt, htlcExpiry,
	).Wait(30 * time.Second)

	// We should get an error, and that error should indicate that the HTLC
	// should be rejected due to a policy violation (below min HTLC).
	if err == nil {
		t.Fatalf("payment should have failed but didn't")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T", err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailAmountBelowMinimum:
	default:
		t.Fatalf("incorrect error, expected amount below minimum, "+
			"instead have: %v", err)
	}
}

// TestLinkForwardMaxHTLCPolicyMismatch tests that if a node is an intermediate
// node and receives an HTLC which is _above_ its max HTLC policy then the
// HTLC will be rejected.
func TestLinkForwardMaxHTLCPolicyMismatch(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5, btcutil.SatoshiPerBitcoin*5,
	)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(
		t, channels.aliceToBob, channels.bobToAlice, channels.bobToCarol,
		channels.carolToBob, testStartingHeight,
	)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	// In order to trigger this failure mode, we'll update our policy to have
	// a new max HTLC of 10 satoshis.
	maxHtlc := lnwire.NewMSatFromSatoshis(10)

	// First we'll generate a route over 2 hops within the network that
	// attempts to pay out an amount greater than the max HTLC we're about to
	// set.
	amountNoFee := maxHtlc + 1
	htlcAmt, htlcExpiry, hops := generateHops(
		amountNoFee, testStartingHeight, n.firstBobChannelLink,
		n.carolChannelLink,
	)

	// We'll now update Bob's policy to set the max HTLC we chose earlier.
	n.secondBobChannelLink.cfg.FwrdingPolicy.MaxHTLC = maxHtlc

	// Finally, we'll make the payment which'll send an HTLC with our
	// specified parameters.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amountNoFee,
		htlcAmt, htlcExpiry,
	).Wait(30 * time.Second)

	// We should get an error indicating a temporary channel failure, The
	// failure is temporary because this payment would be allowed if Bob
	// updated his policy to increase the max HTLC.
	if err == nil {
		t.Fatalf("payment should have failed but didn't")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T", err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailTemporaryChannelFailure:
	default:
		t.Fatalf("incorrect error, expected temporary channel failure, "+
			"instead have: %v", err)
	}
}

// TestUpdateForwardingPolicy tests that the forwarding policy for a link is
// able to be updated properly. We'll first create an HTLC that meets the
// specified policy, assert that it succeeds, update the policy (to invalidate
// the prior HTLC), and then ensure that the HTLC is rejected.
func TestUpdateForwardingPolicy(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	amountNoFee := lnwire.NewMSatFromSatoshis(10)
	htlcAmt, htlcExpiry, hops := generateHops(amountNoFee,
		testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	// First, send this 10 mSAT payment over the three hops, the payment
	// should succeed, and all balances should be updated accordingly.
	firstHop := n.firstBobChannelLink.ShortChanID()
	payResp, err := makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amountNoFee,
		htlcAmt, htlcExpiry,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// Carol's invoice should now be shown as settled as the payment
	// succeeded.
	invoice, err := n.carolServer.registry.LookupInvoice(payResp)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State != channeldb.ContractSettled {
		t.Fatal("carol invoice haven't been settled")
	}

	expectedAliceBandwidth := aliceBandwidthBefore - htlcAmt
	if expectedAliceBandwidth != n.aliceChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedAliceBandwidth, n.aliceChannelLink.Bandwidth())
	}
	expectedBobBandwidth1 := firstBobBandwidthBefore + htlcAmt
	if expectedBobBandwidth1 != n.firstBobChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedBobBandwidth1, n.firstBobChannelLink.Bandwidth())
	}
	expectedBobBandwidth2 := secondBobBandwidthBefore - amountNoFee
	if expectedBobBandwidth2 != n.secondBobChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedBobBandwidth2, n.secondBobChannelLink.Bandwidth())
	}
	expectedCarolBandwidth := carolBandwidthBefore + amountNoFee
	if expectedCarolBandwidth != n.carolChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedCarolBandwidth, n.carolChannelLink.Bandwidth())
	}

	// Now we'll update Bob's policy to jack up his free rate to an extent
	// that'll cause him to reject the same HTLC that we just sent.
	//
	// TODO(roasbeef): should implement grace period within link policy
	// update logic
	newPolicy := n.globalPolicy
	newPolicy.BaseFee = lnwire.NewMSatFromSatoshis(1000)
	n.secondBobChannelLink.UpdateForwardingPolicy(newPolicy)

	// Next, we'll send the payment again, using the exact same per-hop
	// payload for each node. This payment should fail as it won't factor
	// in Bob's new fee policy.
	_, err = makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amountNoFee,
		htlcAmt, htlcExpiry,
	).Wait(30 * time.Second)
	if err == nil {
		t.Fatalf("payment should've been rejected")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got (%T): %v", err, err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailFeeInsufficient:
	default:
		t.Fatalf("expected FailFeeInsufficient instead got: %v", err)
	}

	// Reset the policy so we can then test updating the max HTLC policy.
	n.secondBobChannelLink.UpdateForwardingPolicy(n.globalPolicy)

	// As a sanity check, ensure the original payment now succeeds again.
	_, err = makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amountNoFee,
		htlcAmt, htlcExpiry,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// Now we'll update Bob's policy to lower his max HTLC to an extent
	// that'll cause him to reject the same HTLC that we just sent.
	newPolicy = n.globalPolicy
	newPolicy.MaxHTLC = amountNoFee - 1
	n.secondBobChannelLink.UpdateForwardingPolicy(newPolicy)

	// Next, we'll send the payment again, using the exact same per-hop
	// payload for each node. This payment should fail as it won't factor
	// in Bob's new max HTLC policy.
	_, err = makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amountNoFee,
		htlcAmt, htlcExpiry,
	).Wait(30 * time.Second)
	if err == nil {
		t.Fatalf("payment should've been rejected")
	}

	rtErr, ok = err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got (%T): %v",
			err, err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailTemporaryChannelFailure:
	default:
		t.Fatalf("expected TemporaryChannelFailure, instead got: %v",
			err)
	}
}

// TestChannelLinkMultiHopInsufficientPayment checks that we receive error if
// bob<->alice channel has insufficient BTC capacity/bandwidth. In this test we
// send the payment from Carol to Alice over Bob peer. (Carol -> Bob -> Alice)
func TestChannelLinkMultiHopInsufficientPayment(t *testing.T) {
	t.Parallel()

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
	defer n.stop()

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	// We'll attempt to send 4 BTC although the alice-to-bob channel only
	// has 3 BTC total capacity. As a result, this payment should be
	// rejected.
	amount := lnwire.NewMSatFromSatoshis(4 * btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	// Wait for:
	// * HTLC add request to be sent to from Alice to Bob.
	// * Alice<->Bob commitment states to be updated.
	// * Bob trying to add HTLC add request in Bob<->Carol channel.
	// * Cancel HTLC request to be sent back from Bob to Alice.
	// * user notification to be sent.

	receiver := n.carolServer
	firstHop := n.firstBobChannelLink.ShortChanID()
	rhash, err := makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err == nil {
		t.Fatal("error haven't been received")
	}
	assertFailureCode(t, err, lnwire.CodeTemporaryChannelFailure)

	// Wait for Alice to receive the revocation.
	//
	// TODO(roasbeef): add in ntfn hook for state transition completion
	time.Sleep(100 * time.Millisecond)

	// Check that alice invoice wasn't settled and bandwidth of htlc
	// links hasn't been changed.
	invoice, err := receiver.registry.LookupInvoice(rhash)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State == channeldb.ContractSettled {
		t.Fatal("carol invoice have been settled")
	}

	if n.aliceChannelLink.Bandwidth() != aliceBandwidthBefore {
		t.Fatal("the bandwidth of alice channel link which handles " +
			"alice->bob channel should be the same")
	}

	if n.firstBobChannelLink.Bandwidth() != firstBobBandwidthBefore {
		t.Fatal("the bandwidth of bob channel link which handles " +
			"alice->bob channel should be the same")
	}

	if n.secondBobChannelLink.Bandwidth() != secondBobBandwidthBefore {
		t.Fatal("the bandwidth of bob channel link which handles " +
			"bob->carol channel should be the same")
	}

	if n.carolChannelLink.Bandwidth() != carolBandwidthBefore {
		t.Fatal("the bandwidth of carol channel link which handles " +
			"bob->carol channel should be the same")
	}
}

// TestChannelLinkMultiHopUnknownPaymentHash checks that we receive remote error
// from Alice if she received not suitable payment hash for htlc.
func TestChannelLinkMultiHopUnknownPaymentHash(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
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
	defer n.stop()

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)
	blob, err := generateRoute(hops...)
	if err != nil {
		t.Fatal(err)
	}

	// Generate payment invoice and htlc, but don't add this invoice to the
	// receiver registry. This should trigger an unknown payment hash
	// failure.
	_, htlc, pid, err := generatePayment(
		amount, htlcAmt, totalTimelock, blob,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Send payment and expose err channel.
	err = n.aliceServer.htlcSwitch.SendHTLC(
		n.firstBobChannelLink.ShortChanID(), pid, htlc,
	)
	if err != nil {
		t.Fatalf("unable to get send payment: %v", err)
	}

	resultChan, err := n.aliceServer.htlcSwitch.GetPaymentResult(
		pid, htlc.PaymentHash, newMockDeobfuscator(),
	)
	if err != nil {
		t.Fatalf("unable to get payment result: %v", err)
	}

	var result *PaymentResult
	var ok bool
	select {

	case result, ok = <-resultChan:
		if !ok {
			t.Fatalf("unexpected shutdown")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("no result arrive")
	}

	assertFailureCode(
		t, result.Error, lnwire.CodeIncorrectOrUnknownPaymentDetails,
	)

	// Wait for Alice to receive the revocation.
	require.Eventually(t, func() bool {
		if n.aliceChannelLink.Bandwidth() != aliceBandwidthBefore {
			return false
		}

		if n.firstBobChannelLink.Bandwidth() != firstBobBandwidthBefore {
			return false
		}

		if n.secondBobChannelLink.Bandwidth() != secondBobBandwidthBefore {
			return false
		}

		if n.carolChannelLink.Bandwidth() != carolBandwidthBefore {
			return false
		}

		return true
	}, 10*time.Second, 100*time.Millisecond)
}

// TestChannelLinkMultiHopUnknownNextHop construct the chain of hops
// Carol<->Bob<->Alice and checks that we receive remote error from Bob if he
// has no idea about next hop (hop might goes down and routing info not updated
// yet).
func TestChannelLinkMultiHopUnknownNextHop(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*5,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	// Remove bob's outgoing link with Carol. This will cause him to fail
	// back the payment to Alice since he is unaware of Carol when the
	// payment comes across.
	bobChanID := lnwire.NewChanIDFromOutPoint(
		&channels.bobToCarol.State().FundingOutpoint,
	)
	n.bobServer.htlcSwitch.RemoveLink(bobChanID)

	firstHop := n.firstBobChannelLink.ShortChanID()
	receiver := n.carolServer
	rhash, err := makePayment(
		n.aliceServer, receiver, firstHop, hops, amount, htlcAmt,
		totalTimelock).Wait(30 * time.Second)
	if err == nil {
		t.Fatal("error haven't been received")
	}
	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected ClearTextError")
	}

	if _, ok = rtErr.WireMessage().(*lnwire.FailUnknownNextPeer); !ok {
		t.Fatalf("wrong error has been received: %T",
			rtErr.WireMessage())
	}

	// Wait for Alice to receive the revocation.
	//
	// TODO(roasbeef): add in ntfn hook for state transition completion
	time.Sleep(100 * time.Millisecond)

	// Check that alice invoice wasn't settled and bandwidth of htlc
	// links hasn't been changed.
	invoice, err := receiver.registry.LookupInvoice(rhash)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State == channeldb.ContractSettled {
		t.Fatal("carol invoice have been settled")
	}

	if n.aliceChannelLink.Bandwidth() != aliceBandwidthBefore {
		t.Fatal("the bandwidth of alice channel link which handles " +
			"alice->bob channel should be the same")
	}

	if n.firstBobChannelLink.Bandwidth() != firstBobBandwidthBefore {
		t.Fatal("the bandwidth of bob channel link which handles " +
			"alice->bob channel should be the same")
	}

	if n.secondBobChannelLink.Bandwidth() != secondBobBandwidthBefore {
		t.Fatal("the bandwidth of bob channel link which handles " +
			"bob->carol channel should be the same")
	}

	if n.carolChannelLink.Bandwidth() != carolBandwidthBefore {
		t.Fatal("the bandwidth of carol channel link which handles " +
			"bob->carol channel should be the same")
	}

	// Load the forwarding packages for Bob's incoming link. The payment
	// should have been rejected by the switch, and the AddRef in this link
	// should be acked by the failed payment.
	bobInFwdPkgs, err := channels.bobToAlice.State().LoadFwdPkgs()
	if err != nil {
		t.Fatalf("unable to load bob's fwd pkgs: %v", err)
	}

	// There should be exactly two forward packages, as a full state
	// transition requires two commitment dances.
	if len(bobInFwdPkgs) != 2 {
		t.Fatalf("bob should have exactly 2 fwdpkgs, has %d",
			len(bobInFwdPkgs))
	}

	// Only one of the forwarding package should have an Add in it, the
	// other will be empty. Either way, both AckFilters should be fully
	// acked.
	for _, fwdPkg := range bobInFwdPkgs {
		if !fwdPkg.AckFilter.IsFull() {
			t.Fatalf("fwdpkg chanid=%v height=%d AckFilter is not "+
				"fully acked", fwdPkg.Source, fwdPkg.Height)
		}
	}
}

// TestChannelLinkMultiHopDecodeError checks that we send HTLC cancel if
// decoding of onion blob failed.
func TestChannelLinkMultiHopDecodeError(t *testing.T) {
	t.Parallel()

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
	defer n.stop()

	// Replace decode function with another which throws an error.
	n.carolChannelLink.cfg.ExtractErrorEncrypter = func(
		*btcec.PublicKey) (hop.ErrorEncrypter, lnwire.FailCode) {
		return nil, lnwire.CodeInvalidOnionVersion
	}

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink)

	receiver := n.carolServer
	firstHop := n.firstBobChannelLink.ShortChanID()
	rhash, err := makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err == nil {
		t.Fatal("error haven't been received")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T", err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailInvalidOnionVersion:
	default:
		t.Fatalf("wrong error have been received: %v", err)
	}

	// Wait for Bob to receive the revocation.
	time.Sleep(100 * time.Millisecond)

	// Check that alice invoice wasn't settled and bandwidth of htlc
	// links hasn't been changed.
	invoice, err := receiver.registry.LookupInvoice(rhash)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State == channeldb.ContractSettled {
		t.Fatal("carol invoice have been settled")
	}

	if n.aliceChannelLink.Bandwidth() != aliceBandwidthBefore {
		t.Fatal("the bandwidth of alice channel link which handles " +
			"alice->bob channel should be the same")
	}

	if n.firstBobChannelLink.Bandwidth() != firstBobBandwidthBefore {
		t.Fatal("the bandwidth of bob channel link which handles " +
			"alice->bob channel should be the same")
	}

	if n.secondBobChannelLink.Bandwidth() != secondBobBandwidthBefore {
		t.Fatal("the bandwidth of bob channel link which handles " +
			"bob->carol channel should be the same")
	}

	if n.carolChannelLink.Bandwidth() != carolBandwidthBefore {
		t.Fatal("the bandwidth of carol channel link which handles " +
			"bob->carol channel should be the same")
	}
}

// TestChannelLinkExpiryTooSoonExitNode tests that if we send an HTLC to a node
// with an expiry that is already expired, or too close to the current block
// height, then it will cancel the HTLC.
func TestChannelLinkExpiryTooSoonExitNode(t *testing.T) {
	t.Parallel()

	// The starting height for this test will be 200. So we'll base all
	// HTLC starting points off of that.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	const startingHeight = 200
	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, startingHeight)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}
	defer n.stop()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	// We'll craft an HTLC packet, but set the final hop CLTV to 5 blocks
	// after the current true height. This is less than the test invoice
	// cltv delta of 6, so we expect the incoming htlc to be failed by the
	// exit hop.
	htlcAmt, totalTimelock, hops := generateHops(amount,
		startingHeight-1, n.firstBobChannelLink)

	// Now we'll send out the payment from Alice to Bob.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)

	// The payment should've failed as the time lock value was in the
	// _past_.
	if err == nil {
		t.Fatalf("payment should have failed due to a too early " +
			"time lock value")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T %v",
			rtErr, err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailIncorrectDetails:
	default:
		t.Fatalf("expected incorrect_or_unknown_payment_details, "+
			"instead have: %v", err)
	}
}

// TestChannelLinkExpiryTooSoonExitNode tests that if we send a multi-hop HTLC,
// and the time lock is too early for an intermediate node, then they cancel
// the HTLC back to the sender.
func TestChannelLinkExpiryTooSoonMidNode(t *testing.T) {
	t.Parallel()

	// The starting height for this test will be 200. So we'll base all
	// HTLC starting points off of that.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	const startingHeight = 200
	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, startingHeight)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}
	defer n.stop()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	// We'll craft an HTLC packet, but set the starting height to 3 blocks
	// before the current true height. This means that the outgoing time
	// lock of the middle hop will be at starting height + 3 blocks (channel
	// policy time lock delta is 6 blocks). There is an expiry grace delta
	// of 3 blocks relative to the current height, meaning that htlc will
	// not be sent out by the middle hop.
	htlcAmt, totalTimelock, hops := generateHops(amount,
		startingHeight-3, n.firstBobChannelLink, n.carolChannelLink)

	// Now we'll send out the payment from Alice to Bob.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)

	// The payment should've failed as the time lock value was in the
	// _past_.
	if err == nil {
		t.Fatalf("payment should have failed due to a too early " +
			"time lock value")
	}

	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected a ClearTextError, instead got: %T: %v",
			rtErr, err)
	}

	switch rtErr.WireMessage().(type) {
	case *lnwire.FailExpiryTooSoon:
	default:
		t.Fatalf("incorrect error, expected final time lock too "+
			"early, instead have: %v", err)
	}
}

// TestChannelLinkSingleHopMessageOrdering test checks ordering of message which
// flying around between Alice and Bob are correct when Bob sends payments to
// Alice.
func TestChannelLinkSingleHopMessageOrdering(t *testing.T) {
	t.Parallel()

	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)

	chanID := n.aliceChannelLink.ChanID()

	messages := []expectedMessage{
		{"alice", "bob", &lnwire.ChannelReestablish{}, false},
		{"bob", "alice", &lnwire.ChannelReestablish{}, false},

		{"alice", "bob", &lnwire.FundingLocked{}, false},
		{"bob", "alice", &lnwire.FundingLocked{}, false},

		{"alice", "bob", &lnwire.UpdateAddHTLC{}, false},
		{"alice", "bob", &lnwire.CommitSig{}, false},
		{"bob", "alice", &lnwire.RevokeAndAck{}, false},
		{"bob", "alice", &lnwire.CommitSig{}, false},
		{"alice", "bob", &lnwire.RevokeAndAck{}, false},

		{"bob", "alice", &lnwire.UpdateFulfillHTLC{}, false},
		{"bob", "alice", &lnwire.CommitSig{}, false},
		{"alice", "bob", &lnwire.RevokeAndAck{}, false},
		{"alice", "bob", &lnwire.CommitSig{}, false},
		{"bob", "alice", &lnwire.RevokeAndAck{}, false},
	}

	debug := false
	if debug {
		// Log message that alice receives.
		n.aliceServer.intersect(createLogFunc("alice",
			n.aliceChannelLink.ChanID()))

		// Log message that bob receives.
		n.bobServer.intersect(createLogFunc("bob",
			n.firstBobChannelLink.ChanID()))
	}

	// Check that alice receives messages in right order.
	n.aliceServer.intersect(createInterceptorFunc("[alice] <-- [bob]",
		"alice", messages, chanID, false))

	// Check that bob receives messages in right order.
	n.bobServer.intersect(createInterceptorFunc("[alice] --> [bob]",
		"bob", messages, chanID, false))

	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}
	defer n.stop()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.firstBobChannelLink)

	// Wait for:
	// * HTLC add request to be sent to bob.
	// * alice<->bob commitment state to be updated.
	// * settle request to be sent back from bob to alice.
	// * alice<->bob commitment state to be updated.
	// * user notification to be sent.
	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to make the payment: %v", err)
	}
}

type mockPeer struct {
	sync.Mutex
	disconnected bool
	sentMsgs     chan lnwire.Message
	quit         chan struct{}
}

func (m *mockPeer) QuitSignal() <-chan struct{} {
	return m.quit
}

var _ lnpeer.Peer = (*mockPeer)(nil)

func (m *mockPeer) SendMessage(sync bool, msgs ...lnwire.Message) error {
	if m.disconnected {
		return fmt.Errorf("disconnected")
	}

	select {
	case m.sentMsgs <- msgs[0]:
	case <-m.quit:
		return fmt.Errorf("mockPeer shutting down")
	}
	return nil
}
func (m *mockPeer) SendMessageLazy(sync bool, msgs ...lnwire.Message) error {
	return m.SendMessage(sync, msgs...)
}
func (m *mockPeer) AddNewChannel(_ *channeldb.OpenChannel,
	_ <-chan struct{}) error {
	return nil
}
func (m *mockPeer) WipeChannel(*wire.OutPoint) {}
func (m *mockPeer) PubKey() [33]byte {
	return [33]byte{}
}
func (m *mockPeer) IdentityKey() *btcec.PublicKey {
	return nil
}
func (m *mockPeer) Address() net.Addr {
	return nil
}
func (m *mockPeer) LocalFeatures() *lnwire.FeatureVector {
	return nil
}
func (m *mockPeer) RemoteFeatures() *lnwire.FeatureVector {
	return nil
}

func newSingleLinkTestHarness(chanAmt, chanReserve btcutil.Amount) (
	ChannelLink, *lnwallet.LightningChannel, chan time.Time, func() error,
	func(), func() (*lnwallet.LightningChannel, error), error) {

	var chanIDBytes [8]byte
	if _, err := io.ReadFull(rand.Reader, chanIDBytes[:]); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	chanID := lnwire.NewShortChanIDFromInt(
		binary.BigEndian.Uint64(chanIDBytes[:]))

	aliceLc, bobLc, fCleanUp, err := createTestChannel(
		alicePrivKey, bobPrivKey, chanAmt, chanAmt,
		chanReserve, chanReserve, chanID,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	var (
		decoder    = newMockIteratorDecoder()
		obfuscator = NewMockObfuscator()
		alicePeer  = &mockPeer{
			sentMsgs: make(chan lnwire.Message, 2000),
			quit:     make(chan struct{}),
		}
		globalPolicy = ForwardingPolicy{
			MinHTLCOut:    lnwire.NewMSatFromSatoshis(5),
			MaxHTLC:       lnwire.NewMSatFromSatoshis(chanAmt),
			BaseFee:       lnwire.NewMSatFromSatoshis(1),
			TimeLockDelta: 6,
		}
		invoiceRegistry = newMockRegistry(globalPolicy.TimeLockDelta)
	)

	pCache := newMockPreimageCache()

	aliceDb := aliceLc.channel.State().Db
	aliceSwitch, err := initSwitchWithDB(testStartingHeight, aliceDb)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	// Instantiate with a long interval, so that we can precisely control
	// the firing via force feeding.
	bticker := ticker.NewForce(time.Hour)
	aliceCfg := ChannelLinkConfig{
		FwrdingPolicy:      globalPolicy,
		Peer:               alicePeer,
		Switch:             aliceSwitch,
		BestHeight:         aliceSwitch.BestHeight,
		Circuits:           aliceSwitch.CircuitModifier(),
		ForwardPackets:     aliceSwitch.ForwardPackets,
		DecodeHopIterators: decoder.DecodeHopIterators,
		ExtractErrorEncrypter: func(*btcec.PublicKey) (
			hop.ErrorEncrypter, lnwire.FailCode) {
			return obfuscator, lnwire.CodeNone
		},
		FetchLastChannelUpdate: mockGetChanUpdateMessage,
		PreimageCache:          pCache,
		OnChannelFailure: func(lnwire.ChannelID,
			lnwire.ShortChannelID, LinkFailureError) {
		},
		UpdateContractSignals: func(*contractcourt.ContractSignals) error {
			return nil
		},
		Registry:            invoiceRegistry,
		FeeEstimator:        newMockFeeEstimator(),
		ChainEvents:         &contractcourt.ChainEventSubscription{},
		BatchTicker:         bticker,
		FwdPkgGCTicker:      ticker.NewForce(15 * time.Second),
		PendingCommitTicker: ticker.New(time.Minute),
		// Make the BatchSize and Min/MaxFeeUpdateTimeout large enough
		// to not trigger commit updates automatically during tests.
		BatchSize:             10000,
		MinFeeUpdateTimeout:   30 * time.Minute,
		MaxFeeUpdateTimeout:   40 * time.Minute,
		MaxOutgoingCltvExpiry: DefaultMaxOutgoingCltvExpiry,
		MaxFeeAllocation:      DefaultMaxLinkFeeAllocation,
		NotifyActiveLink:      func(wire.OutPoint) {},
		NotifyActiveChannel:   func(wire.OutPoint) {},
		NotifyInactiveChannel: func(wire.OutPoint) {},
		HtlcNotifier:          aliceSwitch.cfg.HtlcNotifier,
	}

	aliceLink := NewChannelLink(aliceCfg, aliceLc.channel)
	start := func() error {
		return aliceSwitch.AddLink(aliceLink)
	}
	go func() {
		for {
			select {
			case <-aliceLink.(*channelLink).htlcUpdates:
			case <-aliceLink.(*channelLink).quit:
				return
			}
		}
	}()

	cleanUp := func() {
		close(alicePeer.quit)
		defer fCleanUp()
	}

	return aliceLink, bobLc.channel, bticker.Force, start, cleanUp,
		aliceLc.restore, nil
}

func assertLinkBandwidth(t *testing.T, link ChannelLink,
	expected lnwire.MilliSatoshi) {

	currentBandwidth := link.Bandwidth()
	_, _, line, _ := runtime.Caller(1)
	if currentBandwidth != expected {
		t.Fatalf("line %v: alice's link bandwidth is incorrect: "+
			"expected %v, got %v", line, expected, currentBandwidth)
	}
}

// handleStateUpdate handles the messages sent from the link after
// the batch ticker has triggered a state update.
func handleStateUpdate(link *channelLink,
	remoteChannel *lnwallet.LightningChannel) error {
	sentMsgs := link.cfg.Peer.(*mockPeer).sentMsgs
	var msg lnwire.Message
	select {
	case msg = <-sentMsgs:
	case <-time.After(60 * time.Second):
		return fmt.Errorf("did not receive CommitSig from Alice")
	}

	// The link should be sending a commit sig at this point.
	commitSig, ok := msg.(*lnwire.CommitSig)
	if !ok {
		return fmt.Errorf("expected CommitSig, got %T", msg)
	}

	// Let the remote channel receive the commit sig, and
	// respond with a revocation + commitsig.
	err := remoteChannel.ReceiveNewCommitment(
		commitSig.CommitSig, commitSig.HtlcSigs)
	if err != nil {
		return err
	}

	remoteRev, _, err := remoteChannel.RevokeCurrentCommitment()
	if err != nil {
		return err
	}
	link.HandleChannelUpdate(remoteRev)

	remoteSig, remoteHtlcSigs, _, err := remoteChannel.SignNextCommitment()
	if err != nil {
		return err
	}
	commitSig = &lnwire.CommitSig{
		CommitSig: remoteSig,
		HtlcSigs:  remoteHtlcSigs,
	}
	link.HandleChannelUpdate(commitSig)

	// This should make the link respond with a revocation.
	select {
	case msg = <-sentMsgs:
	case <-time.After(60 * time.Second):
		return fmt.Errorf("did not receive RevokeAndAck from Alice")
	}

	revoke, ok := msg.(*lnwire.RevokeAndAck)
	if !ok {
		return fmt.Errorf("expected RevokeAndAck got %T", msg)
	}
	_, _, _, _, err = remoteChannel.ReceiveRevocation(revoke)
	if err != nil {
		return fmt.Errorf("unable to receive "+
			"revocation: %v", err)
	}

	return nil
}

// updateState is used exchange the messages necessary to do a full state
// transition. If initiateUpdate=true, then this call will make the link
// trigger an update by sending on the batchTick channel, if not, it will
// make the remoteChannel initiate the state update.
func updateState(batchTick chan time.Time, link *channelLink,
	remoteChannel *lnwallet.LightningChannel,
	initiateUpdate bool) error {
	sentMsgs := link.cfg.Peer.(*mockPeer).sentMsgs

	if initiateUpdate {
		// Trigger update by ticking the batchTicker.
		select {
		case batchTick <- time.Now():
		case <-link.quit:
			return fmt.Errorf("link shutting down")
		}
		return handleStateUpdate(link, remoteChannel)
	}

	// The remote is triggering the state update, emulate this by
	// signing and sending CommitSig to the link.
	remoteSig, remoteHtlcSigs, _, err := remoteChannel.SignNextCommitment()
	if err != nil {
		return err
	}

	commitSig := &lnwire.CommitSig{
		CommitSig: remoteSig,
		HtlcSigs:  remoteHtlcSigs,
	}
	link.HandleChannelUpdate(commitSig)

	// The link should respond with a revocation + commit sig.
	var msg lnwire.Message
	select {
	case msg = <-sentMsgs:
	case <-time.After(60 * time.Second):
		return fmt.Errorf("did not receive RevokeAndAck from Alice")
	}

	revoke, ok := msg.(*lnwire.RevokeAndAck)
	if !ok {
		return fmt.Errorf("expected RevokeAndAck got %T",
			msg)
	}
	_, _, _, _, err = remoteChannel.ReceiveRevocation(revoke)
	if err != nil {
		return fmt.Errorf("unable to receive "+
			"revocation: %v", err)
	}
	select {
	case msg = <-sentMsgs:
	case <-time.After(60 * time.Second):
		return fmt.Errorf("did not receive CommitSig from Alice")
	}

	commitSig, ok = msg.(*lnwire.CommitSig)
	if !ok {
		return fmt.Errorf("expected CommitSig, got %T", msg)
	}

	err = remoteChannel.ReceiveNewCommitment(
		commitSig.CommitSig, commitSig.HtlcSigs)
	if err != nil {
		return err
	}

	// Lastly, send a revocation back to the link.
	remoteRev, _, err := remoteChannel.RevokeCurrentCommitment()
	if err != nil {
		return err
	}
	link.HandleChannelUpdate(remoteRev)

	// Sleep to make sure Alice has handled the remote revocation.
	time.Sleep(500 * time.Millisecond)

	return nil
}

// TestChannelLinkBandwidthConsistency ensures that the reported bandwidth of a
// given ChannelLink is properly updated in response to downstream messages
// from the switch, and upstream messages from its channel peer.
//
// TODO(roasbeef): add sync hook into packet processing so can eliminate all
// sleep in this test and the one below
func TestChannelLinkBandwidthConsistency(t *testing.T) {
	if !build.IsDevBuild() {
		t.Fatalf("htlcswitch tests must be run with '-tags debug")
	}
	t.Parallel()

	// TODO(roasbeef): replace manual bit twiddling with concept of
	// resource cost for packets?
	//  * or also able to consult link

	// We'll start the test by creating a single instance of
	const chanAmt = btcutil.SatoshiPerBitcoin * 5

	aliceLink, bobChannel, tmr, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		carolChanID            = lnwire.NewShortChanIDFromInt(3)
		mockBlob               [lnwire.OnionPacketSize]byte
		coreChan               = aliceLink.(*channelLink).channel
		coreLink               = aliceLink.(*channelLink)
		defaultCommitFee       = coreChan.StateSnapshot().CommitFee
		aliceStartingBandwidth = aliceLink.Bandwidth()
		aliceMsgs              = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	// We put Alice into hodl.ExitSettle mode, such that she won't settle
	// incoming HTLCs automatically.
	coreLink.cfg.HodlMask = hodl.MaskFromFlags(hodl.ExitSettle)

	estimator := chainfee.NewStaticEstimator(6000, 0)
	feePerKw, err := estimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}
	htlcFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(input.HTLCWeight),
	)

	// The starting bandwidth of the channel should be exactly the amount
	// that we created the channel between her and Bob, minus the
	// commitment fee and fee for adding an additional HTLC.
	expectedBandwidth := lnwire.NewMSatFromSatoshis(
		chanAmt-defaultCommitFee,
	) - htlcFee
	assertLinkBandwidth(t, aliceLink, expectedBandwidth)

	// Next, we'll create an HTLC worth 1 BTC, and send it into the link as
	// a switch initiated payment.  The resulting bandwidth should
	// now be decremented to reflect the new HTLC.
	htlcAmt := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	invoice, htlc, _, err := generatePayment(
		htlcAmt, htlcAmt, 5, mockBlob,
	)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}
	addPkt := htlcPacket{
		htlc:           htlc,
		incomingChanID: hop.Source,
		incomingHTLCID: 0,
		obfuscator:     NewMockObfuscator(),
	}

	circuit := makePaymentCircuit(&htlc.PaymentHash, &addPkt)
	_, err = coreLink.cfg.Switch.commitCircuits(&circuit)
	if err != nil {
		t.Fatalf("unable to commit circuit: %v", err)
	}

	addPkt.circuit = &circuit
	if err := aliceLink.HandleSwitchPacket(&addPkt); err != nil {
		t.Fatalf("unable to handle switch packet: %v", err)
	}
	time.Sleep(time.Millisecond * 500)

	// The resulting bandwidth should reflect that Alice is paying the
	// htlc amount in addition to the htlc fee.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)

	// Alice should send the HTLC to Bob.
	var msg lnwire.Message
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	addHtlc, ok := msg.(*lnwire.UpdateAddHTLC)
	if !ok {
		t.Fatalf("expected UpdateAddHTLC, got %T", msg)
	}

	bobIndex, err := bobChannel.ReceiveHTLC(addHtlc)
	if err != nil {
		t.Fatalf("bob failed receiving htlc: %v", err)
	}

	// Lock in the HTLC.
	if err := updateState(tmr, coreLink, bobChannel, true); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}
	// Locking in the HTLC should not change Alice's bandwidth.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)

	// If we now send in a valid HTLC settle for the prior HTLC we added,
	// then the bandwidth should remain unchanged as the remote party will
	// gain additional channel balance.
	err = bobChannel.SettleHTLC(*invoice.Terms.PaymentPreimage, bobIndex, nil, nil, nil)
	if err != nil {
		t.Fatalf("unable to settle htlc: %v", err)
	}
	htlcSettle := &lnwire.UpdateFulfillHTLC{
		ID:              0,
		PaymentPreimage: *invoice.Terms.PaymentPreimage,
	}
	aliceLink.HandleChannelUpdate(htlcSettle)
	time.Sleep(time.Millisecond * 500)

	// Since the settle is not locked in yet, Alice's bandwidth should still
	// reflect that she has to pay the fee.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)

	// Lock in the settle.
	if err := updateState(tmr, coreLink, bobChannel, false); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	// Now that it is settled, Alice should have gotten the htlc fee back.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt)

	// Next, we'll add another HTLC initiated by the switch (of the same
	// amount as the prior one).
	_, htlc, _, err = generatePayment(htlcAmt, htlcAmt, 5, mockBlob)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}
	addPkt = htlcPacket{
		htlc:           htlc,
		incomingChanID: hop.Source,
		incomingHTLCID: 1,
		obfuscator:     NewMockObfuscator(),
	}

	circuit = makePaymentCircuit(&htlc.PaymentHash, &addPkt)
	_, err = coreLink.cfg.Switch.commitCircuits(&circuit)
	if err != nil {
		t.Fatalf("unable to commit circuit: %v", err)
	}

	addPkt.circuit = &circuit
	if err := aliceLink.HandleSwitchPacket(&addPkt); err != nil {
		t.Fatalf("unable to handle switch packet: %v", err)
	}
	time.Sleep(time.Millisecond * 500)

	// Again, Alice's bandwidth decreases by htlcAmt+htlcFee.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-2*htlcAmt-htlcFee)

	// Alice will send the HTLC to Bob.
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	addHtlc, ok = msg.(*lnwire.UpdateAddHTLC)
	if !ok {
		t.Fatalf("expected UpdateAddHTLC, got %T", msg)
	}

	bobIndex, err = bobChannel.ReceiveHTLC(addHtlc)
	if err != nil {
		t.Fatalf("bob failed receiving htlc: %v", err)
	}

	// Lock in the HTLC, which should not affect the bandwidth.
	if err := updateState(tmr, coreLink, bobChannel, true); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt*2-htlcFee)

	// With that processed, we'll now generate an HTLC fail (sent by the
	// remote peer) to cancel the HTLC we just added. This should return us
	// back to the bandwidth of the link right before the HTLC was sent.
	err = bobChannel.FailHTLC(bobIndex, []byte("nop"), nil, nil, nil)
	if err != nil {
		t.Fatalf("unable to fail htlc: %v", err)
	}
	failMsg := &lnwire.UpdateFailHTLC{
		ID:     1,
		Reason: lnwire.OpaqueReason([]byte("nop")),
	}

	aliceLink.HandleChannelUpdate(failMsg)
	time.Sleep(time.Millisecond * 500)

	// Before the Fail gets locked in, the bandwidth should remain unchanged.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt*2-htlcFee)

	// Lock in the Fail.
	if err := updateState(tmr, coreLink, bobChannel, false); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	// Now the bandwidth should reflect the failed HTLC.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt)

	// Moving along, we'll now receive a new HTLC from the remote peer,
	// with an ID of 0 as this is their first HTLC. The bandwidth should
	// remain unchanged (but Alice will need to pay the fee for the extra
	// HTLC).
	htlcAmt, totalTimelock, hops := generateHops(htlcAmt, testStartingHeight,
		coreLink)
	blob, err := generateRoute(hops...)
	if err != nil {
		t.Fatalf("unable to gen route: %v", err)
	}
	invoice, htlc, _, err = generatePayment(
		htlcAmt, htlcAmt, totalTimelock, blob,
	)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}

	// We must add the invoice to the registry, such that Alice expects
	// this payment.
	err = coreLink.cfg.Registry.(*mockInvoiceRegistry).AddInvoice(
		*invoice, htlc.PaymentHash,
	)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}

	htlc.ID = 0
	_, err = bobChannel.AddHTLC(htlc, nil)
	if err != nil {
		t.Fatalf("unable to add htlc: %v", err)
	}
	aliceLink.HandleChannelUpdate(htlc)

	// Alice's balance remains unchanged until this HTLC is locked in.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt)

	// Lock in the HTLC.
	if err := updateState(tmr, coreLink, bobChannel, false); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	// Since Bob is adding this HTLC, Alice only needs to pay the fee.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)
	time.Sleep(time.Millisecond * 500)

	addPkt = htlcPacket{
		htlc:           htlc,
		incomingChanID: aliceLink.ShortChanID(),
		incomingHTLCID: 0,
		obfuscator:     NewMockObfuscator(),
	}

	circuit = makePaymentCircuit(&htlc.PaymentHash, &addPkt)
	_, err = coreLink.cfg.Switch.commitCircuits(&circuit)
	if err != nil {
		t.Fatalf("unable to commit circuit: %v", err)
	}

	addPkt.outgoingChanID = carolChanID
	addPkt.outgoingHTLCID = 0

	err = coreLink.cfg.Switch.openCircuits(addPkt.keystone())
	if err != nil {
		t.Fatalf("unable to set keystone: %v", err)
	}

	// Next, we'll settle the HTLC with our knowledge of the pre-image that
	// we eventually learn (simulating a multi-hop payment). The bandwidth
	// of the channel should now be re-balanced to the starting point.
	settlePkt := htlcPacket{
		incomingChanID: aliceLink.ShortChanID(),
		incomingHTLCID: 0,
		circuit:        &circuit,
		outgoingChanID: addPkt.outgoingChanID,
		outgoingHTLCID: addPkt.outgoingHTLCID,
		htlc: &lnwire.UpdateFulfillHTLC{
			ID:              0,
			PaymentPreimage: *invoice.Terms.PaymentPreimage,
		},
		obfuscator: NewMockObfuscator(),
	}

	if err := aliceLink.HandleSwitchPacket(&settlePkt); err != nil {
		t.Fatalf("unable to handle switch packet: %v", err)
	}
	time.Sleep(time.Millisecond * 500)

	// Settling this HTLC gives Alice all her original bandwidth back.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth)

	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	settleMsg, ok := msg.(*lnwire.UpdateFulfillHTLC)
	if !ok {
		t.Fatalf("expected UpdateFulfillHTLC, got %T", msg)
	}
	err = bobChannel.ReceiveHTLCSettle(settleMsg.PaymentPreimage, settleMsg.ID)
	if err != nil {
		t.Fatalf("failed receiving fail htlc: %v", err)
	}

	// After failing an HTLC, the link will automatically trigger
	// a state update.
	if err := handleStateUpdate(coreLink, bobChannel); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	// Finally, we'll test the scenario of failing an HTLC received by the
	// remote node. This should result in no perceived bandwidth changes.
	htlcAmt, totalTimelock, hops = generateHops(htlcAmt, testStartingHeight,
		coreLink)
	blob, err = generateRoute(hops...)
	if err != nil {
		t.Fatalf("unable to gen route: %v", err)
	}
	invoice, htlc, _, err = generatePayment(
		htlcAmt, htlcAmt, totalTimelock, blob,
	)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}
	err = coreLink.cfg.Registry.(*mockInvoiceRegistry).AddInvoice(
		*invoice, htlc.PaymentHash,
	)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}

	// Since we are not using the link to handle HTLC IDs for the
	// remote channel, we must set this manually. This is the second
	// HTLC we add, hence it should have an ID of 1 (Alice's channel
	// link will set this automatically for her side).
	htlc.ID = 1
	_, err = bobChannel.AddHTLC(htlc, nil)
	if err != nil {
		t.Fatalf("unable to add htlc: %v", err)
	}
	aliceLink.HandleChannelUpdate(htlc)
	time.Sleep(time.Millisecond * 500)

	// No changes before the HTLC is locked in.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth)
	if err := updateState(tmr, coreLink, bobChannel, false); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	// After lock-in, Alice will have to pay the htlc fee.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcFee)

	addPkt = htlcPacket{
		htlc:           htlc,
		incomingChanID: aliceLink.ShortChanID(),
		incomingHTLCID: 1,
		obfuscator:     NewMockObfuscator(),
	}

	circuit = makePaymentCircuit(&htlc.PaymentHash, &addPkt)
	_, err = coreLink.cfg.Switch.commitCircuits(&circuit)
	if err != nil {
		t.Fatalf("unable to commit circuit: %v", err)
	}

	addPkt.outgoingChanID = carolChanID
	addPkt.outgoingHTLCID = 1

	err = coreLink.cfg.Switch.openCircuits(addPkt.keystone())
	if err != nil {
		t.Fatalf("unable to set keystone: %v", err)
	}

	failPkt := htlcPacket{
		incomingChanID: aliceLink.ShortChanID(),
		incomingHTLCID: 1,
		circuit:        &circuit,
		outgoingChanID: addPkt.outgoingChanID,
		outgoingHTLCID: addPkt.outgoingHTLCID,
		htlc: &lnwire.UpdateFailHTLC{
			ID: 1,
		},
		obfuscator: NewMockObfuscator(),
	}

	if err := aliceLink.HandleSwitchPacket(&failPkt); err != nil {
		t.Fatalf("unable to handle switch packet: %v", err)
	}
	time.Sleep(time.Millisecond * 500)

	// Alice should get all her bandwidth back.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth)

	// Message should be sent to Bob.
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}
	failMsg, ok = msg.(*lnwire.UpdateFailHTLC)
	if !ok {
		t.Fatalf("expected UpdateFailHTLC, got %T", msg)
	}
	err = bobChannel.ReceiveFailHTLC(failMsg.ID, []byte("fail"))
	if err != nil {
		t.Fatalf("failed receiving fail htlc: %v", err)
	}

	// After failing an HTLC, the link will automatically trigger
	// a state update.
	if err := handleStateUpdate(coreLink, bobChannel); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth)
}

// genAddsAndCircuits creates `numHtlcs` sequential ADD packets and there
// corresponding circuits. The provided `htlc` is used in all test packets.
func genAddsAndCircuits(numHtlcs int, htlc *lnwire.UpdateAddHTLC) (
	[]*htlcPacket, []*PaymentCircuit) {

	addPkts := make([]*htlcPacket, 0, numHtlcs)
	circuits := make([]*PaymentCircuit, 0, numHtlcs)
	for i := 0; i < numHtlcs; i++ {
		addPkt := htlcPacket{
			htlc:           htlc,
			incomingChanID: hop.Source,
			incomingHTLCID: uint64(i),
			obfuscator:     NewMockObfuscator(),
		}

		circuit := makePaymentCircuit(&htlc.PaymentHash, &addPkt)
		addPkt.circuit = &circuit

		addPkts = append(addPkts, &addPkt)
		circuits = append(circuits, &circuit)
	}

	return addPkts, circuits
}

// TestChannelLinkTrimCircuitsPending checks that the switch and link properly
// trim circuits if there are open circuits corresponding to ADDs on a pending
// commmitment transaction.
func TestChannelLinkTrimCircuitsPending(t *testing.T) {
	t.Parallel()

	const (
		chanAmt   = btcutil.SatoshiPerBitcoin * 5
		numHtlcs  = 4
		halfHtlcs = numHtlcs / 2
	)

	// We'll start by creating a new link with our chanAmt (5 BTC). We will
	// only be testing Alice's behavior, so the reference to Bob's channel
	// state is unnecessary.
	aliceLink, _, batchTicker, start, cleanUp, restore, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	alice := newPersistentLinkHarness(
		t, aliceLink, batchTicker, restore,
	)

	// Compute the static fees that will be used to determine the
	// correctness of Alice's bandwidth when forwarding HTLCs.
	estimator := chainfee.NewStaticEstimator(6000, 0)
	feePerKw, err := estimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}

	defaultCommitFee := alice.channel.StateSnapshot().CommitFee
	htlcFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(input.HTLCWeight),
	)

	// The starting bandwidth of the channel should be exactly the amount
	// that we created the channel between her and Bob, minus the commitment
	// fee and fee of adding an HTLC.
	expectedBandwidth := lnwire.NewMSatFromSatoshis(
		chanAmt-defaultCommitFee,
	) - htlcFee
	assertLinkBandwidth(t, alice.link, expectedBandwidth)

	// Capture Alice's starting bandwidth to perform later, relative
	// bandwidth assertions.
	aliceStartingBandwidth := alice.link.Bandwidth()

	// Next, we'll create an HTLC worth 1 BTC that will be used as a dummy
	// message for the test.
	var mockBlob [lnwire.OnionPacketSize]byte
	htlcAmt := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	_, htlc, _, err := generatePayment(htlcAmt, htlcAmt, 5, mockBlob)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}

	// Create `numHtlc` htlcPackets and payment circuits that will be used
	// to drive the test. All of the packets will use the same dummy HTLC.
	addPkts, circuits := genAddsAndCircuits(numHtlcs, htlc)

	// To begin the test, start by committing the circuits belong to our
	// first two HTLCs.
	fwdActions := alice.commitCircuits(circuits[:halfHtlcs])

	// Both of these circuits should have successfully added, as this is the
	// first attempt to send them.
	if len(fwdActions.Adds) != halfHtlcs {
		t.Fatalf("expected %d circuits to be added", halfHtlcs)
	}
	alice.assertNumPendingNumOpenCircuits(2, 0)

	// Since both were committed successfully, we will now deliver them to
	// Alice's link.
	for _, addPkt := range addPkts[:halfHtlcs] {
		if err := alice.link.HandleSwitchPacket(addPkt); err != nil {
			t.Fatalf("unable to handle switch packet: %v", err)
		}
	}

	// Wait until Alice's link has sent both HTLCs via the peer.
	alice.checkSent(addPkts[:halfHtlcs])

	// The resulting bandwidth should reflect that Alice is paying both
	// htlc amounts, in addition to both htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)

	// Now, initiate a state transition by Alice so that the pending HTLCs
	// are locked in. This will *not* involve any participation by Bob,
	// which ensures the commitment will remain in a pending state.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(2, 2)

	// Restart Alice's link, which simulates a disconnection with the remote
	// peer.
	cleanUp = alice.restart(false, false)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(2, 2)

	// Make a second attempt to commit the first two circuits. This can
	// happen if the incoming link flaps, but also allows us to verify that
	// the circuits were trimmed properly.
	fwdActions = alice.commitCircuits(circuits[:halfHtlcs])

	// Since Alice has a pending commitment with the first two HTLCs, the
	// restart should not have trimmed them from the circuit map.
	// Therefore, we expect both of these circuits to be dropped by the
	// switch, as keystones should still be set.
	if len(fwdActions.Drops) != halfHtlcs {
		t.Fatalf("expected %d packets to be dropped", halfHtlcs)
	}

	// The resulting bandwidth should remain unchanged from before,
	// reflecting that Alice is paying both htlc amounts, in addition to
	// both htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)

	// Now, restart Alice's link *and* the entire switch. This will ensure
	// that entire circuit map is reloaded from disk, and we can now test
	// against the behavioral differences of committing circuits that
	// conflict with duplicate circuits after a restart.
	cleanUp = alice.restart(true, false)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(2, 2)

	// Alice should not send out any messages. Even though Alice has a
	// pending commitment transaction, channel reestablishment is not
	// enabled in this test.
	select {
	case <-alice.msgs:
		t.Fatalf("message should not have been sent by Alice")
	case <-time.After(time.Second):
	}

	// We will now try to commit the circuits for all of our HTLCs. The
	// first two are already on the pending commitment transaction, the
	// latter two are new HTLCs.
	fwdActions = alice.commitCircuits(circuits)

	// The first two circuits should have been dropped, as they are still on
	// the pending commitment transaction, and the restart should not have
	// trimmed the circuits for these valid HTLCs.
	if len(fwdActions.Drops) != halfHtlcs {
		t.Fatalf("expected %d packets to be dropped", halfHtlcs)
	}
	// The latter two circuits are unknown the circuit map, and should
	// report being added.
	if len(fwdActions.Adds) != halfHtlcs {
		t.Fatalf("expected %d packets to be added", halfHtlcs)
	}

	// Deliver the latter two HTLCs to Alice's links so that they can be
	// processed and added to the in-memory commitment state.
	for _, addPkt := range addPkts[halfHtlcs:] {
		if err := alice.link.HandleSwitchPacket(addPkt); err != nil {
			t.Fatalf("unable to handle switch packet: %v", err)
		}
	}

	// Wait for Alice to send the two latter HTLCs via the peer.
	alice.checkSent(addPkts[halfHtlcs:])

	// With two HTLCs on the pending commit, and two added to the in-memory
	// commitment state, the resulting bandwidth should reflect that Alice
	// is paying the all htlc amounts in addition to all htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-numHtlcs*(htlcAmt+htlcFee),
	)

	// We will try to initiate a state transition for Alice, which will
	// ensure the circuits for the two in-memory HTLCs are opened. However,
	// since we have a pending commitment, these HTLCs will not actually be
	// included in a commitment.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(4, 4)

	// Restart Alice's link to simulate a disconnect. Since the switch
	// remains up throughout, the two latter HTLCs will remain in the link's
	// mailbox, and will reprocessed upon being reattached to the link.
	cleanUp = alice.restart(false, false)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(4, 2)

	// Again, try to recommit all of our circuits.
	fwdActions = alice.commitCircuits(circuits)

	// It is expected that all of these will get dropped by the switch.
	// The first two circuits are still open as a result of being on the
	// commitment transaction. The latter two should have had their open
	// circuits trimmed, *but* since the HTLCs are still in Alice's mailbox,
	// the switch knows not to fail them as a result of the latter two
	// circuits never having been loaded from disk.
	if len(fwdActions.Drops) != numHtlcs {
		t.Fatalf("expected %d packets to be dropped", numHtlcs)
	}

	// Wait for the latter two htlcs to be pulled from the mailbox, added to
	// the in-memory channel state, and sent out via the peer.
	alice.checkSent(addPkts[halfHtlcs:])

	// This should result in reconstructing the same bandwidth as our last
	// assertion. There are two HTLCs on the pending commit, and two added
	// to the in-memory commitment state, the resulting bandwidth should
	// reflect that Alice is paying the all htlc amounts in addition to all
	// htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-numHtlcs*(htlcAmt+htlcFee),
	)

	// Again, we will try to initiate a state transition for Alice, which
	// will ensure the circuits for the two in-memory HTLCs are opened.
	// As before, these HTLCs will not actually be included in a commitment
	// since we have a pending commitment.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(4, 4)

	// As a final persistence check, we will restart the link and switch,
	// wiping the latter two HTLCs from memory, and forcing their circuits
	// to be reloaded from disk.
	cleanUp = alice.restart(true, false)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(4, 2)

	// Alice's mailbox will be empty after the restart, and no channel
	// reestablishment is configured, so no messages will be sent upon
	// restart.
	select {
	case <-alice.msgs:
		t.Fatalf("message should not have been sent by Alice")
	case <-time.After(time.Second):
	}

	// Finally, make one last attempt to commit all circuits.
	fwdActions = alice.commitCircuits(circuits)

	// The first two HTLCs should still be dropped by the htlcswitch. Their
	// existence on the pending commitment transaction should prevent their
	// open circuits from being trimmed.
	if len(fwdActions.Drops) != halfHtlcs {
		t.Fatalf("expected %d packets to be dropped", halfHtlcs)
	}
	// The latter two HTLCs should now be failed by the switch. These will
	// have been trimmed by the link or switch restarting, and since the
	// HTLCs are known to be lost from memory (since their circuits were
	// loaded from disk), it is safe fail them back as they won't ever be
	// delivered to the outgoing link.
	if len(fwdActions.Fails) != halfHtlcs {
		t.Fatalf("expected %d packets to be dropped", halfHtlcs)
	}

	// Since the latter two HTLCs have been completely dropped from memory,
	// only the first two HTLCs we added should still be reflected in the
	// channel bandwidth.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)
}

// TestChannelLinkTrimCircuitsNoCommit checks that the switch and link properly trim
// circuits if the ADDs corresponding to open circuits are never committed.
func TestChannelLinkTrimCircuitsNoCommit(t *testing.T) {
	if !build.IsDevBuild() {
		t.Fatalf("htlcswitch tests must be run with '-tags debug")
	}

	t.Parallel()

	const (
		chanAmt   = btcutil.SatoshiPerBitcoin * 5
		numHtlcs  = 4
		halfHtlcs = numHtlcs / 2
	)

	// We'll start by creating a new link with our chanAmt (5 BTC). We will
	// only be testing Alice's behavior, so the reference to Bob's channel
	// state is unnecessary.
	aliceLink, _, batchTicker, start, cleanUp, restore, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	alice := newPersistentLinkHarness(
		t, aliceLink, batchTicker, restore,
	)

	// We'll put Alice into hodl.Commit mode, such that the circuits for any
	// outgoing ADDs are opened, but the changes are not committed in the
	// channel state.
	alice.coreLink.cfg.HodlMask = hodl.Commit.Mask()

	// Compute the static fees that will be used to determine the
	// correctness of Alice's bandwidth when forwarding HTLCs.
	estimator := chainfee.NewStaticEstimator(6000, 0)
	feePerKw, err := estimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}

	defaultCommitFee := alice.channel.StateSnapshot().CommitFee
	htlcFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(input.HTLCWeight),
	)

	// The starting bandwidth of the channel should be exactly the amount
	// that we created the channel between her and Bob, minus the commitment
	// fee and fee for adding an additional HTLC.
	expectedBandwidth := lnwire.NewMSatFromSatoshis(
		chanAmt-defaultCommitFee,
	) - htlcFee
	assertLinkBandwidth(t, alice.link, expectedBandwidth)

	// Capture Alice's starting bandwidth to perform later, relative
	// bandwidth assertions.
	aliceStartingBandwidth := alice.link.Bandwidth()

	// Next, we'll create an HTLC worth 1 BTC that will be used as a dummy
	// message for the test.
	var mockBlob [lnwire.OnionPacketSize]byte
	htlcAmt := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	_, htlc, _, err := generatePayment(htlcAmt, htlcAmt, 5, mockBlob)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}

	// Create `numHtlc` htlcPackets and payment circuits that will be used
	// to drive the test. All of the packets will use the same dummy HTLC.
	addPkts, circuits := genAddsAndCircuits(numHtlcs, htlc)

	// To begin the test, start by committing the circuits belong to our
	// first two HTLCs.
	fwdActions := alice.commitCircuits(circuits[:halfHtlcs])

	// Both of these circuits should have successfully added, as this is the
	// first attempt to send them.
	if len(fwdActions.Adds) != halfHtlcs {
		t.Fatalf("expected %d circuits to be added", halfHtlcs)
	}

	// Since both were committed successfully, we will now deliver them to
	// Alice's link.
	for _, addPkt := range addPkts[:halfHtlcs] {
		if err := alice.link.HandleSwitchPacket(addPkt); err != nil {
			t.Fatalf("unable to handle switch packet: %v", err)
		}
	}

	// Wait until Alice's link has sent both HTLCs via the peer.
	alice.checkSent(addPkts[:halfHtlcs])

	// The resulting bandwidth should reflect that Alice is paying both
	// htlc amounts, in addition to both htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)

	alice.assertNumPendingNumOpenCircuits(2, 0)

	// Now, init a state transition by Alice to try and commit the HTLCs.
	// Since she is in hodl.Commit mode, this will fail, but the circuits
	// will be opened persistently.
	alice.trySignNextCommitment()

	alice.assertNumPendingNumOpenCircuits(2, 2)

	// Restart Alice's link, which simulates a disconnection with the remote
	// peer. Alice's link and switch should trim the circuits that were
	// opened but not committed.
	cleanUp = alice.restart(false, false, hodl.Commit)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(2, 0)

	// The first two HTLCs should have been reset in Alice's mailbox since
	// the switch was not shutdown. Knowing this the switch should drop the
	// two circuits, even if the circuits were trimmed.
	fwdActions = alice.commitCircuits(circuits[:halfHtlcs])
	if len(fwdActions.Drops) != halfHtlcs {
		t.Fatalf("expected %d packets to be dropped since "+
			"the switch has not been restarted", halfHtlcs)
	}

	// Wait for alice to process the first two HTLCs resend them via the
	// peer.
	alice.checkSent(addPkts[:halfHtlcs])

	// The resulting bandwidth should reflect that Alice is paying both htlc
	// amounts, in addition to both htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)

	// Again, initiate another state transition by Alice to try and commit
	// the HTLCs.  Since she is in hodl.Commit mode, this will fail, but the
	// circuits will be opened persistently.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(2, 2)

	// Now, we we will do a full restart of the link and switch, configuring
	// Alice again in hodl.Commit mode. Since none of the HTLCs were
	// actually committed, the previously opened circuits should be trimmed
	// by both the link and switch.
	cleanUp = alice.restart(true, false, hodl.Commit)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(2, 0)

	// Attempt another commit of our first two circuits. Both should fail,
	// as the opened circuits should have been trimmed, and circuit map
	// recognizes that these HTLCs were lost during the restart.
	fwdActions = alice.commitCircuits(circuits[:halfHtlcs])
	if len(fwdActions.Fails) != halfHtlcs {
		t.Fatalf("expected %d packets to be failed", halfHtlcs)
	}

	// Bob should not receive any HTLCs from Alice, since Alice's mailbox is
	// empty and there is no pending commitment.
	select {
	case <-alice.msgs:
		t.Fatalf("received unexpected message from Alice")
	case <-time.After(time.Second):
	}

	// Alice's bandwidth should have reverted back to her starting value.
	assertLinkBandwidth(t, alice.link, aliceStartingBandwidth)

	// Now, try to commit the last two payment circuits, which are unused
	// thus far. These should succeed without hesitation.
	fwdActions = alice.commitCircuits(circuits[halfHtlcs:])
	if len(fwdActions.Adds) != halfHtlcs {
		t.Fatalf("expected %d packets to be added", halfHtlcs)
	}

	// Deliver the last two HTLCs to the link via Alice's mailbox.
	for _, addPkt := range addPkts[halfHtlcs:] {
		if err := alice.link.HandleSwitchPacket(addPkt); err != nil {
			t.Fatalf("unable to handle switch packet: %v", err)
		}
	}

	// Verify that Alice processed and sent out the ADD packets via the
	// peer.
	alice.checkSent(addPkts[halfHtlcs:])

	// The resulting bandwidth should reflect that Alice is paying both htlc
	// amounts, in addition to both htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)

	// Now, initiate a state transition for Alice. Since we are hodl.Commit
	// mode, this will only open the circuits that were added to the
	// in-memory channel state.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(4, 2)

	// Restart Alice's link, and place her back in hodl.Commit mode. On
	// restart, all previously opened circuits should be trimmed by both the
	// link and the switch.
	cleanUp = alice.restart(false, false, hodl.Commit)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(4, 0)

	// Now, try to commit all of known circuits.
	fwdActions = alice.commitCircuits(circuits)

	// The first two HTLCs will fail to commit for the same reason as
	// before, the circuits have been trimmed.
	if len(fwdActions.Fails) != halfHtlcs {
		t.Fatalf("expected %d packet to be failed", halfHtlcs)
	}

	// The last two HTLCs will be dropped, as thought the circuits are
	// trimmed, the switch is aware that the HTLCs are still in Alice's
	// mailbox.
	if len(fwdActions.Drops) != halfHtlcs {
		t.Fatalf("expected %d packet to be dropped", halfHtlcs)
	}

	// Wait until Alice reprocesses the last two HTLCs and sends them via
	// the peer.
	alice.checkSent(addPkts[halfHtlcs:])

	// Her bandwidth should now reflect having sent only those two HTLCs.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-halfHtlcs*(htlcAmt+htlcFee),
	)

	// Now, initiate a state transition for Alice. Since we are hodl.Commit
	// mode, this will only open the circuits that were added to the
	// in-memory channel state.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(4, 2)

	// Finally, do one last restart of both the link and switch. This will
	// flush the HTLCs from the mailbox. The circuits should now be trimmed
	// for all of the HTLCs.
	cleanUp = alice.restart(true, false, hodl.Commit)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(4, 0)

	// Bob should not receive any HTLCs from Alice, as none of the HTLCs are
	// in Alice's mailbox, and channel reestablishment is disabled.
	select {
	case <-alice.msgs:
		t.Fatalf("received unexpected message from Alice")
	case <-time.After(time.Second):
	}

	// Attempt to commit the last two circuits, both should now fail since
	// though they were opened before shutting down, the circuits have been
	// properly trimmed.
	fwdActions = alice.commitCircuits(circuits[halfHtlcs:])
	if len(fwdActions.Fails) != halfHtlcs {
		t.Fatalf("expected %d packet to be failed", halfHtlcs)
	}

	// Alice balance should not have changed since the start.
	assertLinkBandwidth(t, alice.link, aliceStartingBandwidth)
}

// TestChannelLinkTrimCircuitsRemoteCommit checks that the switch and link
// don't trim circuits if the ADD is locked in on the remote commitment but
// not on our local commitment.
func TestChannelLinkTrimCircuitsRemoteCommit(t *testing.T) {
	t.Parallel()

	const (
		chanAmt  = btcutil.SatoshiPerBitcoin * 5
		numHtlcs = 2
	)

	// We'll start by creating a new link with our chanAmt (5 BTC).
	aliceLink, bobChan, batchTicker, start, cleanUp, restore, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}
	defer cleanUp()

	alice := newPersistentLinkHarness(
		t, aliceLink, batchTicker, restore,
	)

	// Compute the static fees that will be used to determine the
	// correctness of Alice's bandwidth when forwarding HTLCs.
	estimator := chainfee.NewStaticEstimator(6000, 0)
	feePerKw, err := estimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}

	defaultCommitFee := alice.channel.StateSnapshot().CommitFee
	htlcFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(input.HTLCWeight),
	)

	// The starting bandwidth of the channel should be exactly the amount
	// that we created the channel between her and Bob, minus the commitment
	// fee and fee of adding an HTLC.
	expectedBandwidth := lnwire.NewMSatFromSatoshis(
		chanAmt-defaultCommitFee,
	) - htlcFee
	assertLinkBandwidth(t, alice.link, expectedBandwidth)

	// Capture Alice's starting bandwidth to perform later, relative
	// bandwidth assertions.
	aliceStartingBandwidth := alice.link.Bandwidth()

	// Next, we'll create an HTLC worth 1 BTC that will be used as a dummy
	// message for the test.
	var mockBlob [lnwire.OnionPacketSize]byte
	htlcAmt := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	_, htlc, _, err := generatePayment(htlcAmt, htlcAmt, 5, mockBlob)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}

	// Create `numHtlc` htlcPackets and payment circuits that will be used
	// to drive the test. All of the packets will use the same dummy HTLC.
	addPkts, circuits := genAddsAndCircuits(numHtlcs, htlc)

	// To begin the test, start by committing the circuits for our first two
	// HTLCs.
	fwdActions := alice.commitCircuits(circuits)

	// Both of these circuits should have successfully added, as this is the
	// first attempt to send them.
	if len(fwdActions.Adds) != numHtlcs {
		t.Fatalf("expected %d circuits to be added", numHtlcs)
	}
	alice.assertNumPendingNumOpenCircuits(2, 0)

	// Since both were committed successfully, we will now deliver them to
	// Alice's link.
	for _, addPkt := range addPkts {
		if err := alice.link.HandleSwitchPacket(addPkt); err != nil {
			t.Fatalf("unable to handle switch packet: %v", err)
		}
	}

	// Wait until Alice's link has sent both HTLCs via the peer.
	alice.checkSent(addPkts)

	// Pass both of the htlcs to Bob.
	for i, addPkt := range addPkts {
		pkt, ok := addPkt.htlc.(*lnwire.UpdateAddHTLC)
		if !ok {
			t.Fatalf("unable to add packet")
		}

		pkt.ID = uint64(i)

		_, err := bobChan.ReceiveHTLC(pkt)
		if err != nil {
			t.Fatalf("unable to receive htlc: %v", err)
		}
	}

	// The resulting bandwidth should reflect that Alice is paying both
	// htlc amounts, in addition to both htlc fees.
	assertLinkBandwidth(t, alice.link,
		aliceStartingBandwidth-numHtlcs*(htlcAmt+htlcFee),
	)

	// Now, initiate a state transition by Alice so that the pending HTLCs
	// are locked in.
	alice.trySignNextCommitment()
	alice.assertNumPendingNumOpenCircuits(2, 2)

	select {
	case aliceMsg := <-alice.msgs:
		// Pass the commitment signature to Bob.
		sig, ok := aliceMsg.(*lnwire.CommitSig)
		if !ok {
			t.Fatalf("alice did not send commitment signature")
		}

		err := bobChan.ReceiveNewCommitment(sig.CommitSig, sig.HtlcSigs)
		if err != nil {
			t.Fatalf("unable to receive new commitment: %v", err)
		}
	case <-time.After(time.Second):
	}

	// Next, revoke Bob's current commitment and send it to Alice so that we
	// can test that Alice's circuits aren't trimmed.
	rev, _, err := bobChan.RevokeCurrentCommitment()
	if err != nil {
		t.Fatalf("unable to revoke current commitment: %v", err)
	}

	_, _, _, _, err = alice.channel.ReceiveRevocation(rev)
	if err != nil {
		t.Fatalf("unable to receive revocation: %v", err)
	}

	// Restart Alice's link, which simulates a disconnection with the remote
	// peer.
	cleanUp = alice.restart(false, false)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(2, 2)

	// Restart the link + switch and check that the number of open circuits
	// doesn't change.
	cleanUp = alice.restart(true, false)
	defer cleanUp()

	alice.assertNumPendingNumOpenCircuits(2, 2)
}

// TestChannelLinkBandwidthChanReserve checks that the bandwidth available
// on the channel link reflects the channel reserve that must be kept
// at all times.
func TestChannelLinkBandwidthChanReserve(t *testing.T) {
	t.Parallel()

	// First start a link that has a balance greater than it's
	// channel reserve.
	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTimer, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		mockBlob               [lnwire.OnionPacketSize]byte
		coreLink               = aliceLink.(*channelLink)
		coreChan               = coreLink.channel
		defaultCommitFee       = coreChan.StateSnapshot().CommitFee
		aliceStartingBandwidth = aliceLink.Bandwidth()
		aliceMsgs              = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	estimator := chainfee.NewStaticEstimator(6000, 0)
	feePerKw, err := estimator.EstimateFeePerKW(1)
	if err != nil {
		t.Fatalf("unable to query fee estimator: %v", err)
	}
	htlcFee := lnwire.NewMSatFromSatoshis(
		feePerKw.FeeForWeight(input.HTLCWeight),
	)

	// The starting bandwidth of the channel should be exactly the amount
	// that we created the channel between her and Bob, minus the channel
	// reserve, commitment fee and fee for adding an additional HTLC.
	expectedBandwidth := lnwire.NewMSatFromSatoshis(
		chanAmt-defaultCommitFee-chanReserve) - htlcFee
	assertLinkBandwidth(t, aliceLink, expectedBandwidth)

	// Next, we'll create an HTLC worth 3 BTC, and send it into the link as
	// a switch initiated payment.  The resulting bandwidth should
	// now be decremented to reflect the new HTLC.
	htlcAmt := lnwire.NewMSatFromSatoshis(3 * btcutil.SatoshiPerBitcoin)
	invoice, htlc, _, err := generatePayment(htlcAmt, htlcAmt, 5, mockBlob)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}

	addPkt := &htlcPacket{
		htlc:       htlc,
		obfuscator: NewMockObfuscator(),
	}
	circuit := makePaymentCircuit(&htlc.PaymentHash, addPkt)
	_, err = coreLink.cfg.Switch.commitCircuits(&circuit)
	if err != nil {
		t.Fatalf("unable to commit circuit: %v", err)
	}

	aliceLink.HandleSwitchPacket(addPkt)
	time.Sleep(time.Millisecond * 100)
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)

	// Alice should send the HTLC to Bob.
	var msg lnwire.Message
	select {
	case msg = <-aliceMsgs:
	case <-time.After(15 * time.Second):
		t.Fatalf("did not receive message")
	}

	addHtlc, ok := msg.(*lnwire.UpdateAddHTLC)
	if !ok {
		t.Fatalf("expected UpdateAddHTLC, got %T", msg)
	}

	bobIndex, err := bobChannel.ReceiveHTLC(addHtlc)
	if err != nil {
		t.Fatalf("bob failed receiving htlc: %v", err)
	}

	// Lock in the HTLC.
	if err := updateState(batchTimer, coreLink, bobChannel, true); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)

	// If we now send in a valid HTLC settle for the prior HTLC we added,
	// then the bandwidth should remain unchanged as the remote party will
	// gain additional channel balance.
	err = bobChannel.SettleHTLC(*invoice.Terms.PaymentPreimage, bobIndex, nil, nil, nil)
	if err != nil {
		t.Fatalf("unable to settle htlc: %v", err)
	}
	htlcSettle := &lnwire.UpdateFulfillHTLC{
		ID:              bobIndex,
		PaymentPreimage: *invoice.Terms.PaymentPreimage,
	}
	aliceLink.HandleChannelUpdate(htlcSettle)
	time.Sleep(time.Millisecond * 500)

	// Since the settle is not locked in yet, Alice's bandwidth should still
	// reflect that she has to pay the fee.
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt-htlcFee)

	// Lock in the settle.
	if err := updateState(batchTimer, coreLink, bobChannel, false); err != nil {
		t.Fatalf("unable to update state: %v", err)
	}

	time.Sleep(time.Millisecond * 100)
	assertLinkBandwidth(t, aliceLink, aliceStartingBandwidth-htlcAmt)

	// Now we create a channel that has a channel reserve that is
	// greater than it's balance. In these case only payments can
	// be received on this channel, not sent. The available bandwidth
	// should therefore be 0.
	const bobChanAmt = btcutil.SatoshiPerBitcoin * 1
	const bobChanReserve = btcutil.SatoshiPerBitcoin * 1.5
	bobLink, _, _, start, bobCleanUp, _, err :=
		newSingleLinkTestHarness(bobChanAmt, bobChanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer bobCleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	// Make sure bandwidth is reported as 0.
	assertLinkBandwidth(t, bobLink, 0)
}

// TestChannelRetransmission tests the ability of the channel links to
// synchronize theirs states after abrupt disconnect.
func TestChannelRetransmission(t *testing.T) {
	t.Parallel()

	retransmissionTests := []struct {
		name     string
		messages []expectedMessage
	}{
		{
			// Tests the ability of the channel links states to be
			// synchronized after remote node haven't receive
			// revoke and ack message.
			name: "intercept last alice revoke_and_ack",
			messages: []expectedMessage{
				// First initialization of the channel.
				{"alice", "bob", &lnwire.ChannelReestablish{}, false},
				{"bob", "alice", &lnwire.ChannelReestablish{}, false},

				{"alice", "bob", &lnwire.FundingLocked{}, false},
				{"bob", "alice", &lnwire.FundingLocked{}, false},

				// Send payment from Alice to Bob and intercept
				// the last revocation message, in this case
				// Bob should not proceed the payment farther.
				{"alice", "bob", &lnwire.UpdateAddHTLC{}, false},
				{"alice", "bob", &lnwire.CommitSig{}, false},
				{"bob", "alice", &lnwire.RevokeAndAck{}, false},
				{"bob", "alice", &lnwire.CommitSig{}, false},
				{"alice", "bob", &lnwire.RevokeAndAck{}, true},

				// Reestablish messages exchange on nodes restart.
				{"alice", "bob", &lnwire.ChannelReestablish{}, false},
				{"bob", "alice", &lnwire.ChannelReestablish{}, false},

				// Alice should resend the revoke_and_ack
				// message to Bob because Bob claimed it in the
				// re-establish message.
				{"alice", "bob", &lnwire.RevokeAndAck{}, false},

				// Proceed the payment farther by sending the
				// fulfilment message and trigger the state
				// update.
				{"bob", "alice", &lnwire.UpdateFulfillHTLC{}, false},
				{"bob", "alice", &lnwire.CommitSig{}, false},
				{"alice", "bob", &lnwire.RevokeAndAck{}, false},
				{"alice", "bob", &lnwire.CommitSig{}, false},
				{"bob", "alice", &lnwire.RevokeAndAck{}, false},
			},
		},
		{
			// Tests the ability of the channel links states to be
			// synchronized after remote node haven't receive
			// revoke and ack message.
			name: "intercept bob revoke_and_ack commit_sig messages",
			messages: []expectedMessage{
				{"alice", "bob", &lnwire.ChannelReestablish{}, false},
				{"bob", "alice", &lnwire.ChannelReestablish{}, false},

				{"alice", "bob", &lnwire.FundingLocked{}, false},
				{"bob", "alice", &lnwire.FundingLocked{}, false},

				// Send payment from Alice to Bob and intercept
				// the last revocation message, in this case
				// Bob should not proceed the payment farther.
				{"alice", "bob", &lnwire.UpdateAddHTLC{}, false},
				{"alice", "bob", &lnwire.CommitSig{}, false},

				// Intercept bob commit sig and revoke and ack
				// messages.
				{"bob", "alice", &lnwire.RevokeAndAck{}, true},
				{"bob", "alice", &lnwire.CommitSig{}, true},

				// Reestablish messages exchange on nodes restart.
				{"alice", "bob", &lnwire.ChannelReestablish{}, false},
				{"bob", "alice", &lnwire.ChannelReestablish{}, false},

				// Bob should resend previously intercepted messages.
				{"bob", "alice", &lnwire.RevokeAndAck{}, false},
				{"bob", "alice", &lnwire.CommitSig{}, false},

				// Proceed the payment farther by sending the
				// fulfilment message and trigger the state
				// update.
				{"alice", "bob", &lnwire.RevokeAndAck{}, false},
				{"bob", "alice", &lnwire.UpdateFulfillHTLC{}, false},
				{"bob", "alice", &lnwire.CommitSig{}, false},
				{"alice", "bob", &lnwire.RevokeAndAck{}, false},
				{"alice", "bob", &lnwire.CommitSig{}, false},
				{"bob", "alice", &lnwire.RevokeAndAck{}, false},
			},
		},
		{
			// Tests the ability of the channel links states to be
			// synchronized after remote node haven't receive
			// update and commit sig messages.
			name: "intercept update add htlc and commit sig messages",
			messages: []expectedMessage{
				{"alice", "bob", &lnwire.ChannelReestablish{}, false},
				{"bob", "alice", &lnwire.ChannelReestablish{}, false},

				{"alice", "bob", &lnwire.FundingLocked{}, false},
				{"bob", "alice", &lnwire.FundingLocked{}, false},

				// Attempt make a payment from Alice to Bob,
				// which is intercepted, emulating the Bob
				// server abrupt stop.
				{"alice", "bob", &lnwire.UpdateAddHTLC{}, true},
				{"alice", "bob", &lnwire.CommitSig{}, true},

				// Restart of the nodes, and after that nodes
				// should exchange the reestablish messages.
				{"alice", "bob", &lnwire.ChannelReestablish{}, false},
				{"bob", "alice", &lnwire.ChannelReestablish{}, false},

				{"alice", "bob", &lnwire.FundingLocked{}, false},
				{"bob", "alice", &lnwire.FundingLocked{}, false},

				// After Bob has notified Alice that he didn't
				// receive updates Alice should re-send them.
				{"alice", "bob", &lnwire.UpdateAddHTLC{}, false},
				{"alice", "bob", &lnwire.CommitSig{}, false},

				{"bob", "alice", &lnwire.RevokeAndAck{}, false},
				{"bob", "alice", &lnwire.CommitSig{}, false},
				{"alice", "bob", &lnwire.RevokeAndAck{}, false},

				{"bob", "alice", &lnwire.UpdateFulfillHTLC{}, false},
				{"bob", "alice", &lnwire.CommitSig{}, false},
				{"alice", "bob", &lnwire.RevokeAndAck{}, false},
				{"alice", "bob", &lnwire.CommitSig{}, false},
				{"bob", "alice", &lnwire.RevokeAndAck{}, false},
			},
		},
	}
	paymentWithRestart := func(t *testing.T, messages []expectedMessage) {
		channels, cleanUp, restoreChannelsFromDb, err := createClusterChannels(
			btcutil.SatoshiPerBitcoin*5,
			btcutil.SatoshiPerBitcoin*5)
		if err != nil {
			t.Fatalf("unable to create channel: %v", err)
		}
		defer cleanUp()

		chanID := lnwire.NewChanIDFromOutPoint(channels.aliceToBob.ChannelPoint())
		serverErr := make(chan error, 4)

		aliceInterceptor := createInterceptorFunc("[alice] <-- [bob]",
			"alice", messages, chanID, false)
		bobInterceptor := createInterceptorFunc("[alice] --> [bob]",
			"bob", messages, chanID, false)

		ct := newConcurrentTester(t)

		// Add interceptor to check the order of Bob and Alice
		// messages.
		n := newThreeHopNetwork(ct,
			channels.aliceToBob, channels.bobToAlice,
			channels.bobToCarol, channels.carolToBob,
			testStartingHeight,
		)
		n.aliceServer.intersect(aliceInterceptor)
		n.bobServer.intersect(bobInterceptor)
		if err := n.start(); err != nil {
			ct.Fatalf("unable to start three hop network: %v", err)
		}
		defer n.stop()

		bobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
		aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

		amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
		htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
			n.firstBobChannelLink)

		// Send payment which should fail because we intercept the
		// update and commit messages.
		//
		// TODO(roasbeef); increase timeout?
		receiver := n.bobServer
		firstHop := n.firstBobChannelLink.ShortChanID()
		rhash, err := makePayment(
			n.aliceServer, receiver, firstHop, hops, amount,
			htlcAmt, totalTimelock,
		).Wait(time.Second * 5)
		if err == nil {
			ct.Fatalf("payment shouldn't haven been finished")
		}

		// Stop network cluster and create new one, with the old
		// channels states. Also do the *hack* - save the payment
		// receiver to pass it in new channel link, otherwise payment
		// will be failed because of the unknown payment hash. Hack
		// will be removed with sphinx payment.
		bobRegistry := n.bobServer.registry
		n.stop()

		channels, err = restoreChannelsFromDb()
		if err != nil {
			ct.Fatalf("unable to restore channels from database: %v", err)
		}

		n = newThreeHopNetwork(ct, channels.aliceToBob, channels.bobToAlice,
			channels.bobToCarol, channels.carolToBob, testStartingHeight)
		n.firstBobChannelLink.cfg.Registry = bobRegistry
		n.aliceServer.intersect(aliceInterceptor)
		n.bobServer.intersect(bobInterceptor)

		if err := n.start(); err != nil {
			ct.Fatalf("unable to start three hop network: %v", err)
		}
		defer n.stop()

		// Wait for reestablishment to be proceeded and invoice to be settled.
		// TODO(andrew.shvv) Will be removed if we move the notification center
		// to the channel link itself.

		var invoice channeldb.Invoice
		for i := 0; i < 20; i++ {
			select {
			case <-time.After(time.Millisecond * 200):
			case serverErr := <-serverErr:
				ct.Fatalf("server error: %v", serverErr)
			}

			// Check that alice invoice wasn't settled and
			// bandwidth of htlc links hasn't been changed.
			invoice, err = receiver.registry.LookupInvoice(rhash)
			if err != nil {
				err = errors.Errorf("unable to get invoice: %v", err)
				continue
			}
			if invoice.State != channeldb.ContractSettled {
				err = errors.Errorf("alice invoice haven't been settled")
				continue
			}

			aliceExpectedBandwidth := aliceBandwidthBefore - htlcAmt
			if aliceExpectedBandwidth != n.aliceChannelLink.Bandwidth() {
				err = errors.Errorf("expected alice to have %v, instead has %v",
					aliceExpectedBandwidth, n.aliceChannelLink.Bandwidth())
				continue
			}

			bobExpectedBandwidth := bobBandwidthBefore + htlcAmt
			if bobExpectedBandwidth != n.firstBobChannelLink.Bandwidth() {
				err = errors.Errorf("expected bob to have %v, instead has %v",
					bobExpectedBandwidth, n.firstBobChannelLink.Bandwidth())
				continue
			}

			break
		}

		if err != nil {
			ct.Fatal(err)
		}
	}

	for _, test := range retransmissionTests {
		passed := t.Run(test.name, func(t *testing.T) {
			paymentWithRestart(t, test.messages)
		})

		if !passed {
			break
		}
	}

}

// TestShouldAdjustCommitFee tests the shouldAdjustCommitFee pivot function to
// ensure that ie behaves properly. We should only update the fee if it
// deviates from our current fee by more 10% or more.
func TestShouldAdjustCommitFee(t *testing.T) {
	tests := []struct {
		netFee       chainfee.SatPerKWeight
		chanFee      chainfee.SatPerKWeight
		shouldAdjust bool
	}{

		// The network fee is 3x lower than the current commitment
		// transaction. As a result, we should adjust our fee to match
		// it.
		{
			netFee:       100,
			chanFee:      3000,
			shouldAdjust: true,
		},

		// The network fee is lower than the current commitment fee,
		// but only slightly so, so we won't update the commitment fee.
		{
			netFee:       2999,
			chanFee:      3000,
			shouldAdjust: false,
		},

		// The network fee is lower than the commitment fee, but only
		// right before it crosses our current threshold.
		{
			netFee:       1000,
			chanFee:      1099,
			shouldAdjust: false,
		},

		// The network fee is lower than the commitment fee, and within
		// our range of adjustment, so we should adjust.
		{
			netFee:       1000,
			chanFee:      1100,
			shouldAdjust: true,
		},

		// The network fee is 2x higher than our commitment fee, so we
		// should adjust upwards.
		{
			netFee:       2000,
			chanFee:      1000,
			shouldAdjust: true,
		},

		// The network fee is higher than our commitment fee, but only
		// slightly so, so we won't update.
		{
			netFee:       1001,
			chanFee:      1000,
			shouldAdjust: false,
		},

		// The network fee is higher than our commitment fee, but
		// hasn't yet crossed our activation threshold.
		{
			netFee:       1100,
			chanFee:      1099,
			shouldAdjust: false,
		},

		// The network fee is higher than our commitment fee, and
		// within our activation threshold, so we should update our
		// fee.
		{
			netFee:       1100,
			chanFee:      1000,
			shouldAdjust: true,
		},

		// Our fees match exactly, so we shouldn't update it at all.
		{
			netFee:       1000,
			chanFee:      1000,
			shouldAdjust: false,
		},
	}

	for i, test := range tests {
		adjustedFee := shouldAdjustCommitFee(
			test.netFee, test.chanFee,
		)

		if adjustedFee && !test.shouldAdjust {
			t.Fatalf("test #%v failed: net_fee=%v, "+
				"chan_fee=%v, adjust_expect=%v, adjust_returned=%v",
				i, test.netFee, test.chanFee, test.shouldAdjust,
				adjustedFee)
		}
	}
}

// TestChannelLinkShutdownDuringForward asserts that a link can be fully
// stopped when it is trying to send synchronously through the switch. The
// specific case this can occur is when a link forwards incoming Adds. We test
// this by forcing the switch into a state where it will not accept new packets,
// and then killing the link, which can only succeed if forwarding can be
// canceled by a call to Stop.
func TestChannelLinkShutdownDuringForward(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network. We're
	// interested in testing the ability to stop the link when it is
	// synchronously forwarding to the switch, which happens when an
	// incoming link forwards Adds. Thus, the test will be performed
	// against Bob's first link.
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
		t.Fatal(err)
	}
	defer n.stop()
	defer n.feeEstimator.Stop()

	// Define a helper method that strobes the switch's log ticker, and
	// unblocks after nothing has been pulled for two seconds.
	waitForBobsSwitchToBlock := func() {
		bobSwitch := n.firstBobChannelLink.cfg.Switch
		ticker := bobSwitch.cfg.LogEventTicker.(*ticker.Force)
		timeout := time.After(15 * time.Second)
		for {
			time.Sleep(50 * time.Millisecond)
			select {
			case ticker.Force <- time.Now():

			case <-time.After(2 * time.Second):
				return

			case <-timeout:
				t.Fatalf("switch did not block")
			}
		}
	}

	// Define a helper method that strobes the link's batch ticker, and
	// unblocks after nothing has been pulled for two seconds.
	waitForBobsIncomingLinkToBlock := func() {
		ticker := n.firstBobChannelLink.cfg.BatchTicker.(*ticker.Force)
		timeout := time.After(15 * time.Second)
		for {
			time.Sleep(50 * time.Millisecond)
			select {
			case ticker.Force <- time.Now():

			case <-time.After(2 * time.Second):
				// We'll give a little extra time here, to
				// ensure that the packet is being pressed
				// against the htlcPlex.
				time.Sleep(50 * time.Millisecond)
				return

			case <-timeout:
				t.Fatalf("link did not block")
			}
		}
	}

	// To test that the cancellation is happening properly, we will set the
	// switch's htlcPlex to nil, so that calls to routeAsync block, and can
	// only exit if the link (or switch) is exiting. We will only be testing
	// the link here.
	//
	// In order to avoid data races, we need to ensure the switch isn't
	// selecting on that channel in the meantime. We'll prevent this by
	// first acquiring the index mutex and forcing a log event so that the
	// htlcForwarder is blocked inside the logTicker case, which also needs
	// the indexMtx.
	n.firstBobChannelLink.cfg.Switch.indexMtx.Lock()

	// Strobe the log ticker, and wait for switch to stop accepting any more
	// log ticks.
	waitForBobsSwitchToBlock()

	// While the htlcForwarder is blocked, swap out the htlcPlex with a nil
	// channel, and unlock the indexMtx to allow return to the
	// htlcForwarder's main select. After this, any attempt to forward
	// through the switch will block.
	n.firstBobChannelLink.cfg.Switch.htlcPlex = nil
	n.firstBobChannelLink.cfg.Switch.indexMtx.Unlock()

	// Now, make a payment from Alice to Carol, which should cause Bob's
	// incoming link to block when it tries to submit the packet to the nil
	// htlcPlex.
	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(
		amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink,
	)

	firstHop := n.firstBobChannelLink.ShortChanID()
	makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	)

	// Strobe the batch ticker of Bob's incoming link, waiting for it to
	// become fully blocked.
	waitForBobsIncomingLinkToBlock()

	// Finally, stop the link to test that it can exit while synchronously
	// forwarding Adds to the switch.
	done := make(chan struct{})
	go func() {
		n.firstBobChannelLink.Stop()
		close(done)
	}()

	select {
	case <-time.After(3 * time.Second):
		t.Fatalf("unable to shutdown link while fwding incoming Adds")
	case <-done:
	}
}

// TestChannelLinkUpdateCommitFee tests that when a new block comes in, the
// channel link properly checks to see if it should update the commitment fee.
func TestChannelLinkUpdateCommitFee(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network. We'll only be
	// interacting with and asserting the state of two of the end points
	// for this test.
	const aliceInitialBalance = btcutil.SatoshiPerBitcoin * 3
	channels, cleanUp, _, err := createClusterChannels(
		aliceInitialBalance, btcutil.SatoshiPerBitcoin*5,
	)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(t, channels.aliceToBob, channels.bobToAlice,
		channels.bobToCarol, channels.carolToBob, testStartingHeight)

	// First, we'll set up some message interceptors to ensure that the
	// proper messages are sent when updating fees.
	chanID := n.aliceChannelLink.ChanID()
	messages := []expectedMessage{
		{"alice", "bob", &lnwire.ChannelReestablish{}, false},
		{"bob", "alice", &lnwire.ChannelReestablish{}, false},

		{"alice", "bob", &lnwire.FundingLocked{}, false},
		{"bob", "alice", &lnwire.FundingLocked{}, false},

		// First fee update.
		{"alice", "bob", &lnwire.UpdateFee{}, false},
		{"alice", "bob", &lnwire.CommitSig{}, false},
		{"bob", "alice", &lnwire.RevokeAndAck{}, false},
		{"bob", "alice", &lnwire.CommitSig{}, false},
		{"alice", "bob", &lnwire.RevokeAndAck{}, false},

		// Second fee update.
		{"alice", "bob", &lnwire.UpdateFee{}, false},
		{"alice", "bob", &lnwire.CommitSig{}, false},
		{"bob", "alice", &lnwire.RevokeAndAck{}, false},
		{"bob", "alice", &lnwire.CommitSig{}, false},
		{"alice", "bob", &lnwire.RevokeAndAck{}, false},
	}
	n.aliceServer.intersect(createInterceptorFunc("[alice] <-- [bob]",
		"alice", messages, chanID, false))
	n.bobServer.intersect(createInterceptorFunc("[alice] --> [bob]",
		"bob", messages, chanID, false))

	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()
	defer n.feeEstimator.Stop()

	startingFeeRate := channels.aliceToBob.CommitFeeRate()

	// triggerFeeUpdate is a helper closure to determine whether a fee
	// update was triggered and completed properly.
	triggerFeeUpdate := func(feeEstimate, newFeeRate chainfee.SatPerKWeight,
		shouldUpdate bool) {

		t.Helper()

		// Record the fee rates before the links process the fee update
		// to test the case where a fee update isn't triggered.
		aliceBefore := channels.aliceToBob.CommitFeeRate()
		bobBefore := channels.bobToAlice.CommitFeeRate()

		// For the sake of this test, we'll reset the timer so that
		// Alice's link queries for a new network fee.
		n.aliceChannelLink.updateFeeTimer.Reset(time.Millisecond)

		// Next, we'll send the first fee rate response to Alice.
		select {
		case n.feeEstimator.byteFeeIn <- feeEstimate:
		case <-time.After(time.Second * 5):
			t.Fatalf("alice didn't query for the new network fee")
		}

		// Record the fee rates after the links have processed the fee
		// update and ensure they are correct based on whether a fee
		// update should have been triggered.
		require.Eventually(t, func() bool {
			aliceAfter := channels.aliceToBob.CommitFeeRate()
			bobAfter := channels.bobToAlice.CommitFeeRate()

			switch {
			case shouldUpdate && aliceAfter != newFeeRate:
				return false

			case shouldUpdate && bobAfter != newFeeRate:
				return false

			case !shouldUpdate && aliceAfter != aliceBefore:
				return false

			case !shouldUpdate && bobAfter != bobBefore:
				return false
			}

			return true
		}, 10*time.Second, time.Second)
	}

	// Triggering the link to update the fee of the channel with the same
	// fee rate should not send a fee update.
	triggerFeeUpdate(startingFeeRate, startingFeeRate, false)

	// Triggering the link to update the fee of the channel with a much
	// larger fee rate _should_ send a fee update.
	newFeeRate := startingFeeRate * 3
	triggerFeeUpdate(newFeeRate, newFeeRate, true)

	// Triggering the link to update the fee of the channel with a fee rate
	// that exceeds its maximum fee allocation should result in a fee rate
	// corresponding to the maximum fee allocation.
	const maxFeeRate chainfee.SatPerKWeight = 207182320
	triggerFeeUpdate(maxFeeRate+1, maxFeeRate, true)
}

// TestChannelLinkAcceptDuplicatePayment tests that if a link receives an
// incoming HTLC for a payment we have already settled, then it accepts the
// HTLC. We do this to simplify the processing of settles after restarts or
// failures, reducing ambiguity when a batch is only partially processed.
func TestChannelLinkAcceptDuplicatePayment(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network. We'll only be
	// interacting with and asserting the state of two of the end points
	// for this test.
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
	defer n.stop()

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	// We'll start off by making a payment from Alice to Carol. We'll
	// manually generate this request so we can control all the parameters.
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

	// With the invoice now added to Carol's registry, we'll send the
	// payment.
	err = n.aliceServer.htlcSwitch.SendHTLC(
		n.firstBobChannelLink.ShortChanID(), pid, htlc,
	)
	if err != nil {
		t.Fatalf("unable to send payment to carol: %v", err)
	}

	resultChan, err := n.aliceServer.htlcSwitch.GetPaymentResult(
		pid, htlc.PaymentHash, newMockDeobfuscator(),
	)
	if err != nil {
		t.Fatalf("unable to get payment result: %v", err)
	}

	// Now, if we attempt to send the payment *again* it should be rejected
	// as it's a duplicate request.
	err = n.aliceServer.htlcSwitch.SendHTLC(
		n.firstBobChannelLink.ShortChanID(), pid, htlc,
	)
	if err != ErrDuplicateAdd {
		t.Fatalf("ErrDuplicateAdd should have been "+
			"received got: %v", err)
	}

	select {
	case result, ok := <-resultChan:
		if !ok {
			t.Fatalf("unexpected shutdown")
		}

		if result.Error != nil {
			t.Fatalf("payment failed: %v", result.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("payment result did not arrive")
	}
}

// TestChannelLinkAcceptOverpay tests that if we create an invoice for sender,
// and the sender sends *more* than specified in the invoice, then we'll still
// accept it and settle as normal.
func TestChannelLinkAcceptOverpay(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network. We'll only be
	// interacting with and asserting the state of two of the end points
	// for this test.
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
	defer n.stop()

	carolBandwidthBefore := n.carolChannelLink.Bandwidth()
	firstBobBandwidthBefore := n.firstBobChannelLink.Bandwidth()
	secondBobBandwidthBefore := n.secondBobChannelLink.Bandwidth()
	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()

	// We'll request a route to send 10k satoshis via Alice -> Bob ->
	// Carol.
	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(
		amount, testStartingHeight,
		n.firstBobChannelLink, n.carolChannelLink,
	)

	// When we actually go to send the payment, we'll actually create an
	// invoice at Carol for only half of this amount.
	receiver := n.carolServer
	firstHop := n.firstBobChannelLink.ShortChanID()
	rhash, err := makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount/2, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}

	// Wait for Alice and Bob's second link to receive the revocation.
	time.Sleep(2 * time.Second)

	// Even though we sent 2x what was asked for, Carol should still have
	// accepted the payment and marked it as settled.
	invoice, err := receiver.registry.LookupInvoice(rhash)
	if err != nil {
		t.Fatalf("unable to get invoice: %v", err)
	}
	if invoice.State != channeldb.ContractSettled {
		t.Fatal("carol invoice haven't been settled")
	}

	expectedAliceBandwidth := aliceBandwidthBefore - htlcAmt
	if expectedAliceBandwidth != n.aliceChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedAliceBandwidth, n.aliceChannelLink.Bandwidth())
	}

	expectedBobBandwidth1 := firstBobBandwidthBefore + htlcAmt
	if expectedBobBandwidth1 != n.firstBobChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedBobBandwidth1, n.firstBobChannelLink.Bandwidth())
	}

	expectedBobBandwidth2 := secondBobBandwidthBefore - amount
	if expectedBobBandwidth2 != n.secondBobChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedBobBandwidth2, n.secondBobChannelLink.Bandwidth())
	}

	expectedCarolBandwidth := carolBandwidthBefore + amount
	if expectedCarolBandwidth != n.carolChannelLink.Bandwidth() {
		t.Fatalf("channel bandwidth incorrect: expected %v, got %v",
			expectedCarolBandwidth, n.carolChannelLink.Bandwidth())
	}

	// Finally, we'll ensure that the amount we paid is properly reflected
	// in the stored invoice.
	if invoice.AmtPaid != amount {
		t.Fatalf("expected amt paid to be %v, is instead %v", amount,
			invoice.AmtPaid)
	}
}

// persistentLinkHarness is used to control the lifecylce of a link and the
// switch that operates it. It supports the ability to restart either the link
// or both the link and the switch.
type persistentLinkHarness struct {
	t *testing.T

	link     ChannelLink
	coreLink *channelLink
	channel  *lnwallet.LightningChannel

	batchTicker chan time.Time
	msgs        chan lnwire.Message

	restoreChan func() (*lnwallet.LightningChannel, error)
}

// newPersistentLinkHarness initializes a new persistentLinkHarness and derives
// the supporting references from the active link.
func newPersistentLinkHarness(t *testing.T, link ChannelLink,
	batchTicker chan time.Time,
	restore func() (*lnwallet.LightningChannel,
		error)) *persistentLinkHarness {

	coreLink := link.(*channelLink)

	return &persistentLinkHarness{
		t:           t,
		link:        link,
		coreLink:    coreLink,
		channel:     coreLink.channel,
		batchTicker: batchTicker,
		msgs:        coreLink.cfg.Peer.(*mockPeer).sentMsgs,
		restoreChan: restore,
	}
}

// restart facilitates a shutdown and restart of the link maintained by the
// harness. The primary purpose of this method is to ensure the consistency of
// the supporting references is maintained across restarts.
//
// If `restartSwitch` is set, the entire switch will also be restarted,
// and will be reinitialized with the contents of the channeldb backing Alice's
// channel.
//
// Any number of hodl flags can be passed as additional arguments to this
// method. If none are provided, the mask will be extracted as hodl.MaskNone.
func (h *persistentLinkHarness) restart(restartSwitch, syncStates bool,
	hodlFlags ...hodl.Flag) func() {

	// First, remove the link from the switch.
	h.coreLink.cfg.Switch.RemoveLink(h.link.ChanID())

	if restartSwitch {
		// If a switch restart is requested, we will stop it. It will be
		// reinstantiated in restartLink.
		h.coreLink.cfg.Switch.Stop()
	}

	// Since our in-memory state may have diverged from our persistent
	// state, we will restore the persisted state to ensure we always start
	// the link in a consistent state.
	var err error
	h.channel, err = h.restoreChan()
	if err != nil {
		h.t.Fatalf("unable to restore channels: %v", err)
	}

	// Now, restart the link using the channel state. This will take care of
	// adding the link to an existing switch, or creating a new one using
	// the database owned by the link.
	var cleanUp func()
	h.link, h.batchTicker, cleanUp, err = h.restartLink(
		h.channel, restartSwitch, syncStates, hodlFlags,
	)
	if err != nil {
		h.t.Fatalf("unable to restart alicelink: %v", err)
	}

	// Repopulate the remaining fields in the harness.
	h.coreLink = h.link.(*channelLink)
	h.msgs = h.coreLink.cfg.Peer.(*mockPeer).sentMsgs

	return cleanUp
}

// checkSent reads the links message stream and verify that the messages are
// dequeued in the same order as provided by `pkts`.
func (h *persistentLinkHarness) checkSent(pkts []*htlcPacket) {
	for _, pkt := range pkts {
		var msg lnwire.Message
		select {
		case msg = <-h.msgs:
		case <-time.After(15 * time.Second):
			h.t.Fatalf("did not receive message")
		}

		if !reflect.DeepEqual(msg, pkt.htlc) {
			h.t.Fatalf("unexpected packet, want %v, got %v",
				pkt.htlc, msg)
		}
	}
}

// commitCircuits accepts a list of circuits and tries to commit them to the
// switch's circuit map. The forwarding actions are returned if there was no
// failure.
func (h *persistentLinkHarness) commitCircuits(circuits []*PaymentCircuit) *CircuitFwdActions {
	fwdActions, err := h.coreLink.cfg.Switch.commitCircuits(circuits...)
	if err != nil {
		h.t.Fatalf("unable to commit circuit: %v", err)
	}

	return fwdActions
}

func (h *persistentLinkHarness) assertNumPendingNumOpenCircuits(
	wantPending, wantOpen int) {

	_, _, line, _ := runtime.Caller(1)

	numPending := h.coreLink.cfg.Switch.circuits.NumPending()
	if numPending != wantPending {
		h.t.Fatalf("line: %d: wrong number of pending circuits: "+
			"want %d, got %d", line, wantPending, numPending)
	}
	numOpen := h.coreLink.cfg.Switch.circuits.NumOpen()
	if numOpen != wantOpen {
		h.t.Fatalf("line: %d: wrong number of open circuits: "+
			"want %d, got %d", line, wantOpen, numOpen)
	}
}

// trySignNextCommitment signals the batch ticker so that the link will try to
// update its commitment transaction.
func (h *persistentLinkHarness) trySignNextCommitment() {
	select {
	case h.batchTicker <- time.Now():
		// Give the link enough time to process the request.
		time.Sleep(time.Millisecond * 500)

	case <-time.After(15 * time.Second):
		h.t.Fatalf("did not initiate state transition")
	}
}

// restartLink creates a new channel link from the given channel state, and adds
// to an htlcswitch. If none is provided by the caller, a new one will be
// created using Alice's database.
func (h *persistentLinkHarness) restartLink(
	aliceChannel *lnwallet.LightningChannel, restartSwitch, syncStates bool,
	hodlFlags []hodl.Flag) (
	ChannelLink, chan time.Time, func(), error) {

	var (
		decoder    = newMockIteratorDecoder()
		obfuscator = NewMockObfuscator()
		alicePeer  = &mockPeer{
			sentMsgs: make(chan lnwire.Message, 2000),
			quit:     make(chan struct{}),
		}

		globalPolicy = ForwardingPolicy{
			MinHTLCOut:    lnwire.NewMSatFromSatoshis(5),
			BaseFee:       lnwire.NewMSatFromSatoshis(1),
			TimeLockDelta: 6,
		}

		pCache = newMockPreimageCache()
	)

	aliceDb := aliceChannel.State().Db
	aliceSwitch := h.coreLink.cfg.Switch
	if restartSwitch {
		var err error
		aliceSwitch, err = initSwitchWithDB(testStartingHeight, aliceDb)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Instantiate with a long interval, so that we can precisely control
	// the firing via force feeding.
	bticker := ticker.NewForce(time.Hour)
	aliceCfg := ChannelLinkConfig{
		FwrdingPolicy:      globalPolicy,
		Peer:               alicePeer,
		Switch:             aliceSwitch,
		BestHeight:         aliceSwitch.BestHeight,
		Circuits:           aliceSwitch.CircuitModifier(),
		ForwardPackets:     aliceSwitch.ForwardPackets,
		DecodeHopIterators: decoder.DecodeHopIterators,
		ExtractErrorEncrypter: func(*btcec.PublicKey) (
			hop.ErrorEncrypter, lnwire.FailCode) {
			return obfuscator, lnwire.CodeNone
		},
		FetchLastChannelUpdate: mockGetChanUpdateMessage,
		PreimageCache:          pCache,
		OnChannelFailure: func(lnwire.ChannelID,
			lnwire.ShortChannelID, LinkFailureError) {
		},
		UpdateContractSignals: func(*contractcourt.ContractSignals) error {
			return nil
		},
		Registry:            h.coreLink.cfg.Registry,
		FeeEstimator:        newMockFeeEstimator(),
		ChainEvents:         &contractcourt.ChainEventSubscription{},
		BatchTicker:         bticker,
		FwdPkgGCTicker:      ticker.New(5 * time.Second),
		PendingCommitTicker: ticker.New(time.Minute),
		// Make the BatchSize and Min/MaxFeeUpdateTimeout large enough
		// to not trigger commit updates automatically during tests.
		BatchSize:           10000,
		MinFeeUpdateTimeout: 30 * time.Minute,
		MaxFeeUpdateTimeout: 40 * time.Minute,
		// Set any hodl flags requested for the new link.
		HodlMask:              hodl.MaskFromFlags(hodlFlags...),
		MaxOutgoingCltvExpiry: DefaultMaxOutgoingCltvExpiry,
		MaxFeeAllocation:      DefaultMaxLinkFeeAllocation,
		NotifyActiveLink:      func(wire.OutPoint) {},
		NotifyActiveChannel:   func(wire.OutPoint) {},
		NotifyInactiveChannel: func(wire.OutPoint) {},
		HtlcNotifier:          aliceSwitch.cfg.HtlcNotifier,
		SyncStates:            syncStates,
	}

	aliceLink := NewChannelLink(aliceCfg, aliceChannel)
	if err := aliceSwitch.AddLink(aliceLink); err != nil {
		return nil, nil, nil, err
	}
	go func() {
		for {
			select {
			case <-aliceLink.(*channelLink).htlcUpdates:
			case <-aliceLink.(*channelLink).quit:
				return
			}
		}
	}()

	cleanUp := func() {
		close(alicePeer.quit)
		defer aliceLink.Stop()
	}

	return aliceLink, bticker.Force, cleanUp, nil
}

// gnerateHtlc generates a simple payment from Bob to Alice.
func generateHtlc(t *testing.T, coreLink *channelLink,
	id uint64) *lnwire.UpdateAddHTLC {

	t.Helper()

	htlc, invoice := generateHtlcAndInvoice(t, id)

	// We must add the invoice to the registry, such that Alice
	// expects this payment.
	err := coreLink.cfg.Registry.(*mockInvoiceRegistry).AddInvoice(
		*invoice, htlc.PaymentHash,
	)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}

	return htlc
}

// generateHtlcAndInvoice generates an invoice and a single hop htlc to send to
// the receiver.
func generateHtlcAndInvoice(t *testing.T,
	id uint64) (*lnwire.UpdateAddHTLC, *channeldb.Invoice) {

	t.Helper()

	htlcAmt := lnwire.NewMSatFromSatoshis(10000)
	htlcExpiry := testStartingHeight + testInvoiceCltvExpiry
	hops := []*hop.Payload{
		hop.NewLegacyPayload(&sphinx.HopData{
			Realm:         [1]byte{}, // hop.BitcoinNetwork
			NextAddress:   [8]byte{}, // hop.Exit,
			ForwardAmount: uint64(htlcAmt),
			OutgoingCltv:  uint32(htlcExpiry),
		}),
	}
	blob, err := generateRoute(hops...)
	if err != nil {
		t.Fatalf("unable to generate route: %v", err)
	}

	invoice, htlc, _, err := generatePayment(
		htlcAmt, htlcAmt, uint32(htlcExpiry), blob,
	)
	if err != nil {
		t.Fatalf("unable to create payment: %v", err)
	}

	htlc.ID = id

	return htlc, invoice
}

// TestChannelLinkNoMoreUpdates tests that we won't send a new commitment
// when there are no new updates to sign.
func TestChannelLinkNoMoreUpdates(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, _, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	// Add two HTLCs to Alice's registry, that Bob can pay.
	htlc1 := generateHtlc(t, coreLink, 0)
	htlc2 := generateHtlc(t, coreLink, 1)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	// We now play out the following scanario:
	//
	// (1) Alice receives htlc1 from Bob.
	// (2) Bob sends signature covering htlc1.
	// (3) Alice receives htlc2 from Bob.
	// (4) Since Bob has sent a new commitment signature, Alice should
	// first respond with a revocation.
	// (5) Alice should also send a commitment signature for the new state,
	// covering htlc1.
	// (6) Bob sends a new commitment signature, covering htlc2 that he sent
	// earlier. This signature should cover hltc1 + htlc2.
	// (7) Alice should revoke the old commitment. This ACKs htlc2.
	// (8) Bob can now revoke his old commitment in response to the
	// signature Alice sent covering htlc1.
	// (9) htlc1 is now locked in on Bob's commitment, and we expect Alice
	// to settle it.
	// (10) Alice should send a signature covering this settle to Bob. Only
	// htlc2 should now be covered by this signature.
	// (11) Bob can revoke his last state, which will also ACK the settle
	// of htlc1.
	// (12) Bob sends a new commitment signature. This signature should
	// cover htlc2.
	// (13) Alice will send a settle for htlc2.
	// (14) Alice will also send a signature covering the settle.
	// (15) Alice should send a revocation in response to the signature Bob
	// sent earlier.
	// (16) Bob will revoke his commitment in response to the commitment
	// Alice sent.
	// (17) Send a signature for the empty state. No HTLCs are left.
	// (18) Alice will revoke her previous state.
	//                                   Alice                Bob
	//                                     |                   |
	//                                     |        ...        |
	//                                     |                   | <--- idle (no htlc on either side)
	//                                     |                   |
	ctx.sendHtlcBobToAlice(htlc1)     //   |<----- add-1 ------| (1)
	ctx.sendCommitSigBobToAlice(1)    //   |<------ sig -------| (2)
	ctx.sendHtlcBobToAlice(htlc2)     //   |<----- add-2 ------| (3)
	ctx.receiveRevAndAckAliceToBob()  //   |------- rev ------>| (4) <--- Alice acks add-1
	ctx.receiveCommitSigAliceToBob(1) //   |------- sig ------>| (5) <--- Alice signs add-1
	ctx.sendCommitSigBobToAlice(2)    //   |<------ sig -------| (6)
	ctx.receiveRevAndAckAliceToBob()  //   |------- rev ------>| (7) <--- Alice acks add-2
	ctx.sendRevAndAckBobToAlice()     //   |<------ rev -------| (8)
	ctx.receiveSettleAliceToBob()     //   |------ ful-1 ----->| (9)
	ctx.receiveCommitSigAliceToBob(1) //   |------- sig ------>| (10) <--- Alice signs add-1 + add-2 + ful-1 = add-2
	ctx.sendRevAndAckBobToAlice()     //   |<------ rev -------| (11)
	ctx.sendCommitSigBobToAlice(1)    //   |<------ sig -------| (12)
	ctx.receiveSettleAliceToBob()     //   |------ ful-2 ----->| (13)
	ctx.receiveCommitSigAliceToBob(0) //   |------- sig ------>| (14) <--- Alice signs add-2 + ful-2 = no htlcs
	ctx.receiveRevAndAckAliceToBob()  //   |------- rev ------>| (15)
	ctx.sendRevAndAckBobToAlice()     //   |<------ rev -------| (16) <--- Bob acks that there are no more htlcs
	ctx.sendCommitSigBobToAlice(0)    //   |<------ sig -------| (17)
	ctx.receiveRevAndAckAliceToBob()  //   |------- rev ------>| (18) <--- Alice acks that there are no htlcs on Alice's side

	// No there are no more changes to ACK or sign, make sure Alice doesn't
	// attempt to send any more messages.
	var msg lnwire.Message
	select {
	case msg = <-aliceMsgs:
		t.Fatalf("did not expect message %T", msg)
	case <-time.After(100 * time.Millisecond):
	}
}

// checkHasPreimages inspects Alice's preimage cache, and asserts whether the
// preimages for the provided HTLCs are known and unknown, and that all of them
// match the expected status of expOk.
func checkHasPreimages(t *testing.T, coreLink *channelLink,
	htlcs []*lnwire.UpdateAddHTLC, expOk bool) {

	t.Helper()

	err := wait.NoError(func() error {
		for i := range htlcs {
			_, ok := coreLink.cfg.PreimageCache.LookupPreimage(
				htlcs[i].PaymentHash,
			)
			if ok == expOk {
				continue
			}

			return fmt.Errorf("expected to find witness: %v, "+
				"got %v for hash=%x", expOk, ok,
				htlcs[i].PaymentHash)
		}

		return nil
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("unable to find preimages: %v", err)
	}
}

// TestChannelLinkWaitForRevocation tests that we will keep accepting updates
// to our commitment transaction, even when we are waiting for a revocation
// from the remote node.
func TestChannelLinkWaitForRevocation(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, _, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	// We will send 10 HTLCs in total, from Bob to Alice.
	numHtlcs := 10
	var htlcs []*lnwire.UpdateAddHTLC
	for i := 0; i < numHtlcs; i++ {
		htlc := generateHtlc(t, coreLink, uint64(i))
		htlcs = append(htlcs, htlc)
	}

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	assertNoMsgFromAlice := func() {
		select {
		case <-aliceMsgs:
			t.Fatalf("did not expect message from Alice")
		case <-time.After(50 * time.Millisecond):
		}
	}

	// We play out the following scenario:
	//
	// (1) Add the first HTLC.
	// (2) Bob sends signature covering the htlc.
	// (3) Since Bob has sent a new commitment signature, Alice should first
	// respond with a revocation. This revocation will ACK the first htlc.
	// (4) Alice should also send a commitment signature for the new state,
	// locking in the HTLC on Bob's commitment. Note that we don't
	// immediately let Bob respond with a revocation in this case.
	// (5.i) Now we send the rest of the HTLCs from Bob to Alice.
	// (6.i) Bob sends a new commitment signature, covering all HTLCs up
	// to this point.
	// (7.i) Alice should respond to Bob's state updates with revocations,
	// but cannot send any new signatures for Bob's state because her
	// revocation window is exhausted.
	// (8) Now let Bob finally send his revocation.
	// (9) We expect Alice to settle her first HTLC, since it was already
	// locked in.
	// (10) Now Alice should send a signature covering this settle + lock
	// in the rest of the HTLCs on Bob's commitment.
	// (11) Bob receives the new signature for his commitment, and can
	// revoke his old state, ACKing the settle.
	// (12.i) Now Alice can settle all the HTLCs, since they are locked in
	// on both parties' commitments.
	// (13) Bob can send a signature covering the first settle Alice sent.
	// Bob's signature should cover all the remaining HTLCs as well, since
	// he hasn't ACKed the last settles yet. Alice receives the signature
	// from Bob. Alice's commitment now has the first HTLC settled, and all
	// the other HTLCs locked in.
	// (14) Alice will send a signature for all the settles she just sent.
	// (15) Bob can revoke his previous state, in response to Alice's
	// signature.
	// (16) In response to the signature Bob sent, Alice can
	// revoke her previous state.
	// (17) Bob still hasn't sent a commitment covering all settles, so do
	// that now. Since Bob ACKed all settles, no HTLCs should be left on
	// the commitment.
	// (18) Alice will revoke her previous state.
	//                                            Alice                Bob
	//                                              |                   |
	//                                              |        ...        |
	//                                              |                   | <--- idle (no htlc on either side)
	//                                              |                   |
	ctx.sendHtlcBobToAlice(htlcs[0])  //            |<----- add-1 ------| (1)
	ctx.sendCommitSigBobToAlice(1)    //            |<------ sig -------| (2)
	ctx.receiveRevAndAckAliceToBob()  //            |------- rev ------>| (3) <--- Alice acks add-1
	ctx.receiveCommitSigAliceToBob(1) //            |------- sig ------>| (4) <--- Alice signs add-1
	for i := 1; i < numHtlcs; i++ {   //            |                   |
		ctx.sendHtlcBobToAlice(htlcs[i])   //   |<----- add-i ------| (5.i)
		ctx.sendCommitSigBobToAlice(i + 1) //   |<------ sig -------| (6.i)
		ctx.receiveRevAndAckAliceToBob()   //   |------- rev ------>| (7.i) <--- Alice acks add-i
		assertNoMsgFromAlice()             //   |                   |
		//                                      |                   | Alice should not send a sig for
		//                                      |                   | Bob's last state, since she is
		//                                      |                   | still waiting for a revocation
		//                                      |                   | for the previous one.
	} //                                            |                   |
	ctx.sendRevAndAckBobToAlice()                // |<------ rev -------| (8) Finally let Bob send rev
	ctx.receiveSettleAliceToBob()                // |------ ful-1 ----->| (9)
	ctx.receiveCommitSigAliceToBob(numHtlcs - 1) // |------- sig ------>| (10) <--- Alice signs add-i
	ctx.sendRevAndAckBobToAlice()                // |<------ rev -------| (11)
	for i := 1; i < numHtlcs; i++ {              // |                   |
		ctx.receiveSettleAliceToBob() //        |------ ful-1 ----->| (12.i)
	} //                                            |                   |
	ctx.sendCommitSigBobToAlice(numHtlcs - 1) //    |<------ sig -------| (13)
	ctx.receiveCommitSigAliceToBob(0)         //    |------- sig ------>| (14)
	ctx.sendRevAndAckBobToAlice()             //    |<------ rev -------| (15)
	ctx.receiveRevAndAckAliceToBob()          //    |------- rev ------>| (16)
	ctx.sendCommitSigBobToAlice(0)            //    |<------ sig -------| (17)
	ctx.receiveRevAndAckAliceToBob()          //    |------- rev ------>| (18)

	// Both side's state is now updated, no more messages should be sent.
	assertNoMsgFromAlice()
}

// TestChannelLinkNoEmptySig asserts that no empty commit sig message is sent
// when the commitment txes are out of sync.
func TestChannelLinkNoEmptySig(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTicker, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}
	defer aliceLink.Stop()

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	// Send htlc 1 from Alice to Bob.
	htlc1, _ := generateHtlcAndInvoice(t, 0)
	ctx.sendHtlcAliceToBob(0, htlc1)
	ctx.receiveHtlcAliceToBob()

	// Tick the batch ticker to trigger a commitsig from Alice->Bob.
	select {
	case batchTicker <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatalf("could not force commit sig")
	}

	// Receive a CommitSig from Alice covering the Add from above.
	ctx.receiveCommitSigAliceToBob(1)

	// Bob revokes previous commitment tx.
	ctx.sendRevAndAckBobToAlice()

	// Alice sends htlc 2 to Bob.
	htlc2, _ := generateHtlcAndInvoice(t, 0)
	ctx.sendHtlcAliceToBob(1, htlc2)
	ctx.receiveHtlcAliceToBob()

	// Tick the batch ticker to trigger a commitsig from Alice->Bob.
	select {
	case batchTicker <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatalf("could not force commit sig")
	}

	// Get the commit sig from Alice, but don't send it to Bob yet.
	commitSigAlice := ctx.receiveCommitSigAlice(2)

	// Bob adds htlc 1 to its remote commit tx.
	ctx.sendCommitSigBobToAlice(1)

	// Now send Bob the signature from Alice covering both htlcs.
	err = bobChannel.ReceiveNewCommitment(
		commitSigAlice.CommitSig, commitSigAlice.HtlcSigs,
	)
	if err != nil {
		t.Fatalf("bob failed receiving commitment: %v", err)
	}

	// Both Alice and Bob revoke their previous commitment txes.
	ctx.receiveRevAndAckAliceToBob()
	ctx.sendRevAndAckBobToAlice()

	// The commit txes are not in sync, but it is Bob's turn to send a new
	// signature. We don't expect Alice to send out any message. This check
	// allows some time for the log commit ticker to trigger for Alice.
	ctx.assertNoMsgFromAlice(time.Second)
}

// TestChannelLinkBatchPreimageWrite asserts that a link will batch preimage
// writes when just as it receives a CommitSig to lock in any Settles, and also
// if the link is aware of any uncommitted preimages if the link is stopped,
// i.e. due to a disconnection or shutdown.
func TestChannelLinkBatchPreimageWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		disconnect bool
	}{
		{
			name:       "flush on commit sig",
			disconnect: false,
		},
		{
			name:       "flush on disconnect",
			disconnect: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testChannelLinkBatchPreimageWrite(t, test.disconnect)
		})
	}
}

func testChannelLinkBatchPreimageWrite(t *testing.T, disconnect bool) {
	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTicker, startUp, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := startUp(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	// We will send 10 HTLCs in total, from Bob to Alice.
	numHtlcs := 10
	var htlcs []*lnwire.UpdateAddHTLC
	var invoices []*channeldb.Invoice
	for i := 0; i < numHtlcs; i++ {
		htlc, invoice := generateHtlcAndInvoice(t, uint64(i))
		htlcs = append(htlcs, htlc)
		invoices = append(invoices, invoice)
	}

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	// First, send a batch of Adds from Alice to Bob.
	for i, htlc := range htlcs {
		ctx.sendHtlcAliceToBob(i, htlc)
		ctx.receiveHtlcAliceToBob()
	}

	// Assert that no preimages exist for these htlcs in Alice's cache.
	checkHasPreimages(t, coreLink, htlcs, false)

	// Force alice's link to sign a commitment covering the htlcs sent thus
	// far.
	select {
	case batchTicker <- time.Now():
	case <-time.After(15 * time.Second):
		t.Fatalf("could not force commit sig")
	}

	// Do a commitment dance to lock in the Adds, we expect numHtlcs htlcs
	// to be on each party's commitment transactions.
	ctx.receiveCommitSigAliceToBob(numHtlcs)
	ctx.sendRevAndAckBobToAlice()
	ctx.sendCommitSigBobToAlice(numHtlcs)
	ctx.receiveRevAndAckAliceToBob()

	// Check again that no preimages exist for these htlcs in Alice's cache.
	checkHasPreimages(t, coreLink, htlcs, false)

	// Now, have Bob settle the HTLCs back to Alice using the preimages in
	// the invoice corresponding to each of the HTLCs.
	for i, invoice := range invoices {
		ctx.sendSettleBobToAlice(
			uint64(i),
			*invoice.Terms.PaymentPreimage,
		)
	}

	// Assert that Alice has not yet written the preimages, even though she
	// has received them in the UpdateFulfillHTLC messages.
	checkHasPreimages(t, coreLink, htlcs, false)

	// If this is the disconnect run, we will having Bob send Alice his
	// CommitSig, and simply stop Alice's link. As she exits, we should
	// detect that she has uncommitted preimages and write them to disk.
	if disconnect {
		aliceLink.Stop()
		checkHasPreimages(t, coreLink, htlcs, true)
		return
	}

	// Otherwise, we are testing that Alice commits the preimages after
	// receiving a CommitSig from Bob. Bob's commitment should now have 0
	// HTLCs.
	ctx.sendCommitSigBobToAlice(0)

	// Since Alice will process the CommitSig asynchronously, we wait until
	// she replies with her RevokeAndAck to ensure the tests reliably
	// inspect her cache after advancing her state.
	select {

	// Received Alice's RevokeAndAck, assert that she has written all of the
	// uncommitted preimages learned in this commitment.
	case <-aliceMsgs:
		checkHasPreimages(t, coreLink, htlcs, true)

	// Alice didn't send her RevokeAndAck, something is wrong.
	case <-time.After(15 * time.Second):
		t.Fatalf("alice did not send her revocation")
	}
}

// TestChannelLinkCleanupSpuriousResponses tests that we properly cleanup
// references in the event that internal retransmission continues as a result of
// not properly cleaning up Add/SettleFailRefs.
func TestChannelLinkCleanupSpuriousResponses(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, _, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	// Settle Alice in hodl ExitSettle mode so that she won't respond
	// immediately to the htlc's meant for her. This allows us to control
	// the responses she gives back to Bob.
	coreLink.cfg.HodlMask = hodl.ExitSettle.Mask()

	// Add two HTLCs to Alice's registry, that Bob can pay.
	htlc1 := generateHtlc(t, coreLink, 0)
	htlc2 := generateHtlc(t, coreLink, 1)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	// We start with he following scenario: Bob sends Alice two HTLCs, and a
	// commitment dance ensures, leaving two HTLCs that Alice can respond
	// to. Since Alice is in ExitSettle mode, we will then take over and
	// provide targeted fail messages to test the link's ability to cleanup
	// spurious responses.
	//
	//  Bob               Alice
	//   |------ add-1 ----->|
	//   |------ add-2 ----->|
	//   |------  sig  ----->| commits add-1 + add-2
	//   |<-----  rev  ------|
	//   |<-----  sig  ------| commits add-1 + add-2
	//   |------  rev  ----->|
	ctx.sendHtlcBobToAlice(htlc1)
	ctx.sendHtlcBobToAlice(htlc2)
	ctx.sendCommitSigBobToAlice(2)
	ctx.receiveRevAndAckAliceToBob()
	ctx.receiveCommitSigAliceToBob(2)
	ctx.sendRevAndAckBobToAlice()

	// Give Alice to time to process the revocation.
	time.Sleep(time.Second)

	aliceFwdPkgs, err := coreLink.channel.LoadFwdPkgs()
	if err != nil {
		t.Fatalf("unable to load alice's fwdpkgs: %v", err)
	}

	// Alice should have exactly one forwarding package.
	if len(aliceFwdPkgs) != 1 {
		t.Fatalf("alice should have 1 fwd pkgs, has %d instead",
			len(aliceFwdPkgs))
	}

	// We'll stash the height of these AddRefs, so that we can reconstruct
	// the proper references later.
	addHeight := aliceFwdPkgs[0].Height

	// The first fwdpkg should have exactly 2 entries, one for each Add that
	// was added during the last dance.
	if aliceFwdPkgs[0].AckFilter.Count() != 2 {
		t.Fatalf("alice fwdpkg should have 2 Adds, has %d instead",
			aliceFwdPkgs[0].AckFilter.Count())
	}

	// Both of the entries in the FwdFilter should be unacked.
	for i := 0; i < 2; i++ {
		if aliceFwdPkgs[0].AckFilter.Contains(uint16(i)) {
			t.Fatalf("alice fwdpkg index %d should not "+
				"have ack", i)
		}
	}

	// Now, construct a Fail packet for Bob settling the first HTLC. This
	// packet will NOT include a sourceRef, meaning the AddRef on disk will
	// not be acked after committing this response.
	fail0 := &htlcPacket{
		incomingChanID: bobChannel.ShortChanID(),
		incomingHTLCID: 0,
		obfuscator:     NewMockObfuscator(),
		htlc:           &lnwire.UpdateFailHTLC{},
	}
	aliceLink.HandleSwitchPacket(fail0)

	//  Bob               Alice
	//   |<----- fal-1 ------|
	//   |<-----  sig  ------| commits fal-1
	ctx.receiveFailAliceToBob()
	ctx.receiveCommitSigAliceToBob(1)

	aliceFwdPkgs, err = coreLink.channel.LoadFwdPkgs()
	if err != nil {
		t.Fatalf("unable to load alice's fwdpkgs: %v", err)
	}

	// Alice should still only have one fwdpkg, as she hasn't yet received
	// another revocation from Bob.
	if len(aliceFwdPkgs) != 1 {
		t.Fatalf("alice should have 1 fwd pkgs, has %d instead",
			len(aliceFwdPkgs))
	}

	// Assert the fwdpkg still has 2 entries for the original Adds.
	if aliceFwdPkgs[0].AckFilter.Count() != 2 {
		t.Fatalf("alice fwdpkg should have 2 Adds, has %d instead",
			aliceFwdPkgs[0].AckFilter.Count())
	}

	// Since the fail packet was missing the AddRef, the forward filter for
	// either HTLC should not have been modified.
	for i := 0; i < 2; i++ {
		if aliceFwdPkgs[0].AckFilter.Contains(uint16(i)) {
			t.Fatalf("alice fwdpkg index %d should not "+
				"have ack", i)
		}
	}

	// Complete the rest of the commitment dance, now that the forwarding
	// packages have been verified.
	//
	//  Bob                Alice
	//   |------  rev  ----->|
	//   |------  sig  ----->|
	//   |<-----  rev  ------|
	ctx.sendRevAndAckBobToAlice()
	ctx.sendCommitSigBobToAlice(1)
	ctx.receiveRevAndAckAliceToBob()

	// Next, we'll construct a fail packet for add-2 (index 1), which we'll
	// send to Bob and lock in. Since the AddRef is set on this instance, we
	// should see the second HTLCs AddRef update the forward filter for the
	// first fwd pkg.
	fail1 := &htlcPacket{
		sourceRef: &channeldb.AddRef{
			Height: addHeight,
			Index:  1,
		},
		incomingChanID: bobChannel.ShortChanID(),
		incomingHTLCID: 1,
		obfuscator:     NewMockObfuscator(),
		htlc:           &lnwire.UpdateFailHTLC{},
	}
	aliceLink.HandleSwitchPacket(fail1)

	//  Bob               Alice
	//   |<----- fal-1 ------|
	//   |<-----  sig  ------| commits fal-1
	ctx.receiveFailAliceToBob()
	ctx.receiveCommitSigAliceToBob(0)

	aliceFwdPkgs, err = coreLink.channel.LoadFwdPkgs()
	if err != nil {
		t.Fatalf("unable to load alice's fwdpkgs: %v", err)
	}

	// Now that another commitment dance has completed, Alice should have 2
	// forwarding packages.
	if len(aliceFwdPkgs) != 2 {
		t.Fatalf("alice should have 2 fwd pkgs, has %d instead",
			len(aliceFwdPkgs))
	}

	// The most recent package should have no new HTLCs, so it should be
	// empty.
	if aliceFwdPkgs[1].AckFilter.Count() != 0 {
		t.Fatalf("alice fwdpkg height=%d should have 0 Adds, "+
			"has %d instead", aliceFwdPkgs[1].Height,
			aliceFwdPkgs[1].AckFilter.Count())
	}

	// The index for the first AddRef should still be unacked, as the
	// sourceRef was missing on the htlcPacket.
	if aliceFwdPkgs[0].AckFilter.Contains(0) {
		t.Fatalf("alice fwdpkg height=%d index=0 should not "+
			"have an ack", aliceFwdPkgs[0].Height)
	}

	// The index for the second AddRef should now be acked, as it was
	// properly constructed and committed in Alice's last commit sig.
	if !aliceFwdPkgs[0].AckFilter.Contains(1) {
		t.Fatalf("alice fwdpkg height=%d index=1 should have "+
			"an ack", aliceFwdPkgs[0].Height)
	}

	// Complete the rest of the commitment dance.
	//
	//  Bob                Alice
	//   |------  rev  ----->|
	//   |------  sig  ----->|
	//   |<-----  rev  ------|
	ctx.sendRevAndAckBobToAlice()
	ctx.sendCommitSigBobToAlice(0)
	ctx.receiveRevAndAckAliceToBob()

	// We'll do a quick sanity check, and blindly send the same fail packet
	// for the first HTLC. Since this HTLC index has already been settled,
	// this should trigger an attempt to cleanup the spurious response.
	// However, we expect it to result in a NOP since it is still missing
	// its sourceRef.
	aliceLink.HandleSwitchPacket(fail0)

	// Allow the link enough time to process and reject the duplicate
	// packet, we'll also check that this doesn't trigger Alice to send the
	// fail to Bob.
	select {
	case <-aliceMsgs:
		t.Fatalf("message sent for duplicate fail")
	case <-time.After(time.Second):
	}

	aliceFwdPkgs, err = coreLink.channel.LoadFwdPkgs()
	if err != nil {
		t.Fatalf("unable to load alice's fwdpkgs: %v", err)
	}

	// Alice should now have 3 forwarding packages, and the latest should be
	// empty.
	if len(aliceFwdPkgs) != 3 {
		t.Fatalf("alice should have 3 fwd pkgs, has %d instead",
			len(aliceFwdPkgs))
	}
	if aliceFwdPkgs[2].AckFilter.Count() != 0 {
		t.Fatalf("alice fwdpkg height=%d should have 0 Adds, "+
			"has %d instead", aliceFwdPkgs[2].Height,
			aliceFwdPkgs[2].AckFilter.Count())
	}

	// The state of the forwarding packages should be unmodified from the
	// prior assertion, since the duplicate Fail for index 0 should have
	// been ignored.
	if aliceFwdPkgs[0].AckFilter.Contains(0) {
		t.Fatalf("alice fwdpkg height=%d index=0 should not "+
			"have an ack", aliceFwdPkgs[0].Height)
	}
	if !aliceFwdPkgs[0].AckFilter.Contains(1) {
		t.Fatalf("alice fwdpkg height=%d index=1 should have "+
			"an ack", aliceFwdPkgs[0].Height)
	}

	// Finally, construct a new Fail packet for the first HTLC, this time
	// with the sourceRef properly constructed. When the link handles this
	// duplicate, it should clean up the remaining AddRef state maintained
	// in Alice's link, but it should not result in anything being sent to
	// Bob.
	fail0 = &htlcPacket{
		sourceRef: &channeldb.AddRef{
			Height: addHeight,
			Index:  0,
		},
		incomingChanID: bobChannel.ShortChanID(),
		incomingHTLCID: 0,
		obfuscator:     NewMockObfuscator(),
		htlc:           &lnwire.UpdateFailHTLC{},
	}
	aliceLink.HandleSwitchPacket(fail0)

	// Allow the link enough time to process and reject the duplicate
	// packet, we'll also check that this doesn't trigger Alice to send the
	// fail to Bob.
	select {
	case <-aliceMsgs:
		t.Fatalf("message sent for duplicate fail")
	case <-time.After(time.Second):
	}

	aliceFwdPkgs, err = coreLink.channel.LoadFwdPkgs()
	if err != nil {
		t.Fatalf("unable to load alice's fwdpkgs: %v", err)
	}

	// Since no state transitions have been performed for the duplicate
	// packets, Alice should still have the same 3 forwarding packages.
	if len(aliceFwdPkgs) != 3 {
		t.Fatalf("alice should have 3 fwd pkgs, has %d instead",
			len(aliceFwdPkgs))
	}

	// Assert that all indices in our original forwarded have now been acked
	// as a result of our spurious cleanup logic.
	for i := 0; i < 2; i++ {
		if !aliceFwdPkgs[0].AckFilter.Contains(uint16(i)) {
			t.Fatalf("alice fwdpkg height=%d index=%d "+
				"should have ack", aliceFwdPkgs[0].Height, i)
		}
	}
}

type mockPackager struct {
	failLoadFwdPkgs bool
}

func (*mockPackager) AddFwdPkg(tx kvdb.RwTx, fwdPkg *channeldb.FwdPkg) error {
	return nil
}

func (*mockPackager) SetFwdFilter(tx kvdb.RwTx, height uint64,
	fwdFilter *channeldb.PkgFilter) error {
	return nil
}

func (*mockPackager) AckAddHtlcs(tx kvdb.RwTx,
	addRefs ...channeldb.AddRef) error {
	return nil
}

func (m *mockPackager) LoadFwdPkgs(tx kvdb.RTx) ([]*channeldb.FwdPkg, error) {
	if m.failLoadFwdPkgs {
		return nil, fmt.Errorf("failing LoadFwdPkgs")
	}
	return nil, nil
}

func (*mockPackager) RemovePkg(tx kvdb.RwTx, height uint64) error {
	return nil
}

func (*mockPackager) AckSettleFails(tx kvdb.RwTx,
	settleFailRefs ...channeldb.SettleFailRef) error {
	return nil
}

// TestChannelLinkFail tests that we will fail the channel, and force close the
// channel in certain situations.
func TestChannelLinkFail(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		// options is used to set up mocks and configure the link
		// before it is started.
		options func(*channelLink)

		// link test is used to execute the given test on the channel
		// link after it is started.
		linkTest func(*testing.T, *channelLink, *lnwallet.LightningChannel)

		// shouldForceClose indicates whether we expect the link to
		// force close the channel in response to the actions performed
		// during the linkTest.
		shouldForceClose bool

		// permanentFailure indicates whether we expect the link to
		// consider the failure permanent in response to the actions
		// performed during the linkTest.
		permanentFailure bool
	}{
		{
			// Test that we don't force close if syncing states
			// fails at startup.
			func(c *channelLink) {
				c.cfg.SyncStates = true

				// Make the syncChanStateCall fail by making
				// the SendMessage call fail.
				c.cfg.Peer.(*mockPeer).disconnected = true
			},
			func(t *testing.T, c *channelLink, _ *lnwallet.LightningChannel) {
				// Should fail at startup.
			},
			false,
			false,
		},
		{
			// Test that we don't force closes the channel if
			// resolving forward packages fails at startup.
			func(c *channelLink) {
				// We make the call to resolveFwdPkgs fail by
				// making the underlying forwarder fail.
				pkg := &mockPackager{
					failLoadFwdPkgs: true,
				}
				c.channel.State().Packager = pkg
			},
			func(t *testing.T, c *channelLink, _ *lnwallet.LightningChannel) {
				// Should fail at startup.
			},
			false,
			false,
		},
		{
			// Test that we force close the channel if we receive
			// an invalid Settle message.
			func(c *channelLink) {
			},
			func(t *testing.T, c *channelLink, _ *lnwallet.LightningChannel) {
				// Recevive an htlc settle for an htlc that was
				// never added.
				htlcSettle := &lnwire.UpdateFulfillHTLC{
					ID:              0,
					PaymentPreimage: [32]byte{},
				}
				c.HandleChannelUpdate(htlcSettle)
			},
			true,
			false,
		},
		{
			// Test that we force close the channel if we receive
			// an invalid CommitSig, not containing enough HTLC
			// sigs.
			func(c *channelLink) {
			},
			func(t *testing.T, c *channelLink, remoteChannel *lnwallet.LightningChannel) {

				// Generate an HTLC and send to the link.
				htlc1 := generateHtlc(t, c, 0)
				ctx := linkTestContext{
					t:          t,
					aliceLink:  c,
					bobChannel: remoteChannel,
				}
				ctx.sendHtlcBobToAlice(htlc1)

				// Sign a commitment that will include
				// signature for the HTLC just sent.
				sig, htlcSigs, _, err :=
					remoteChannel.SignNextCommitment()
				if err != nil {
					t.Fatalf("error signing commitment: %v",
						err)
				}

				// Remove the HTLC sig, such that the commit
				// sig will be invalid.
				commitSig := &lnwire.CommitSig{
					CommitSig: sig,
					HtlcSigs:  htlcSigs[1:],
				}

				c.HandleChannelUpdate(commitSig)
			},
			true,
			false,
		},
		{
			// Test that we force close the channel if we receive
			// an invalid CommitSig, where the sig itself is
			// corrupted.
			func(c *channelLink) {
			},
			func(t *testing.T, c *channelLink, remoteChannel *lnwallet.LightningChannel) {

				// Generate an HTLC and send to the link.
				htlc1 := generateHtlc(t, c, 0)
				ctx := linkTestContext{
					t:          t,
					aliceLink:  c,
					bobChannel: remoteChannel,
				}

				ctx.sendHtlcBobToAlice(htlc1)

				// Sign a commitment that will include
				// signature for the HTLC just sent.
				sig, htlcSigs, _, err :=
					remoteChannel.SignNextCommitment()
				if err != nil {
					t.Fatalf("error signing commitment: %v",
						err)
				}

				// Flip a bit on the signature, rendering it
				// invalid.
				sig[19] ^= 1
				commitSig := &lnwire.CommitSig{
					CommitSig: sig,
					HtlcSigs:  htlcSigs,
				}

				c.HandleChannelUpdate(commitSig)
			},
			true,
			false,
		},
		{
			// Test that we consider the failure permanent if we
			// receive a link error from the remote.
			func(c *channelLink) {
			},
			func(t *testing.T, c *channelLink, remoteChannel *lnwallet.LightningChannel) {
				err := &lnwire.Error{}
				c.HandleChannelUpdate(err)
			},
			false,
			// TODO(halseth) For compatibility with CL we currently
			// don't treat Errors as permanent errors.
			false,
		},
	}

	const chanAmt = btcutil.SatoshiPerBitcoin * 5

	// Execute each test case.
	for i, test := range testCases {
		link, remoteChannel, _, start, cleanUp, _, err :=
			newSingleLinkTestHarness(chanAmt, 0)
		if err != nil {
			t.Fatalf("unable to create link: %v", err)
		}

		coreLink := link.(*channelLink)

		// Set up a channel used to check whether the link error
		// force closed the channel.
		linkErrors := make(chan LinkFailureError, 1)
		coreLink.cfg.OnChannelFailure = func(_ lnwire.ChannelID,
			_ lnwire.ShortChannelID, linkErr LinkFailureError) {
			linkErrors <- linkErr
		}

		// Set up the link before starting it.
		test.options(coreLink)
		if err := start(); err != nil {
			t.Fatalf("unable to start test harness: %v", err)
		}

		// Execute the test case.
		test.linkTest(t, coreLink, remoteChannel)

		// Currently we expect all test cases to lead to link error.
		var linkErr LinkFailureError
		select {
		case linkErr = <-linkErrors:
		case <-time.After(10 * time.Second):
			t.Fatalf("%d) Alice did not fail"+
				"channel", i)
		}

		// If we expect the link to force close the channel in this
		// case, check that it happens. If not, make sure it does not
		// happen.
		if test.shouldForceClose != linkErr.ForceClose {
			t.Fatalf("%d) Expected Alice to force close(%v), "+
				"instead got(%v)", i, test.shouldForceClose,
				linkErr.ForceClose)
		}

		if test.permanentFailure != linkErr.PermanentFailure {
			t.Fatalf("%d) Expected Alice set permanent failure(%v), "+
				"instead got(%v)", i, test.permanentFailure,
				linkErr.PermanentFailure)
		}

		// Clean up before starting next test case.
		cleanUp()
	}
}

// TestExpectedFee tests calculation of ExpectedFee returns expected fee, given
// a baseFee, a feeRate, and an htlc amount.
func TestExpectedFee(t *testing.T) {
	testCases := []struct {
		baseFee  lnwire.MilliSatoshi
		feeRate  lnwire.MilliSatoshi
		htlcAmt  lnwire.MilliSatoshi
		expected lnwire.MilliSatoshi
	}{
		{
			lnwire.MilliSatoshi(0),
			lnwire.MilliSatoshi(0),
			lnwire.MilliSatoshi(0),
			lnwire.MilliSatoshi(0),
		},
		{
			lnwire.MilliSatoshi(0),
			lnwire.MilliSatoshi(1),
			lnwire.MilliSatoshi(999999),
			lnwire.MilliSatoshi(0),
		},
		{
			lnwire.MilliSatoshi(0),
			lnwire.MilliSatoshi(1),
			lnwire.MilliSatoshi(1000000),
			lnwire.MilliSatoshi(1),
		},
		{
			lnwire.MilliSatoshi(0),
			lnwire.MilliSatoshi(1),
			lnwire.MilliSatoshi(1000001),
			lnwire.MilliSatoshi(1),
		},
		{
			lnwire.MilliSatoshi(1),
			lnwire.MilliSatoshi(1),
			lnwire.MilliSatoshi(1000000),
			lnwire.MilliSatoshi(2),
		},
	}

	for _, test := range testCases {
		f := ForwardingPolicy{
			BaseFee: test.baseFee,
			FeeRate: test.feeRate,
		}
		fee := ExpectedFee(f, test.htlcAmt)
		if fee != test.expected {
			t.Errorf("expected fee to be (%v), instead got (%v)", test.expected,
				fee)
		}
	}
}

// TestForwardingAsymmetricTimeLockPolicies tests that each link is able to
// properly handle forwarding HTLCs when their outgoing channels have
// asymmetric policies w.r.t what they require for time locks.
func TestForwardingAsymmetricTimeLockPolicies(t *testing.T) {
	t.Parallel()

	// First, we'll create our traditional three hop network. Bob
	// interacting with and asserting the state of two of the end points
	// for this test.
	channels, cleanUp, _, err := createClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5,
	)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newThreeHopNetwork(
		t, channels.aliceToBob, channels.bobToAlice, channels.bobToCarol,
		channels.carolToBob, testStartingHeight,
	)
	if err := n.start(); err != nil {
		t.Fatalf("unable to start three hop network: %v", err)
	}
	defer n.stop()

	// Now that each of the links are up, we'll modify the link from Alice
	// -> Bob to have a greater time lock delta than that of the link of
	// Bob -> Carol.
	newPolicy := n.firstBobChannelLink.cfg.FwrdingPolicy
	newPolicy.TimeLockDelta = 7
	n.firstBobChannelLink.UpdateForwardingPolicy(newPolicy)

	// Now that the Alice -> Bob link has been updated, we'll craft and
	// send a payment from Alice -> Carol. This should succeed as normal,
	// even though Bob has asymmetric time lock policies.
	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(
		amount, testStartingHeight, n.firstBobChannelLink,
		n.carolChannelLink,
	)

	firstHop := n.firstBobChannelLink.ShortChanID()
	_, err = makePayment(
		n.aliceServer, n.carolServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	).Wait(30 * time.Second)
	if err != nil {
		t.Fatalf("unable to send payment: %v", err)
	}
}

// TestCheckHtlcForward tests that a link is properly enforcing the HTLC
// forwarding policy.
func TestCheckHtlcForward(t *testing.T) {

	fetchLastChannelUpdate := func(lnwire.ShortChannelID) (
		*lnwire.ChannelUpdate, error) {

		return &lnwire.ChannelUpdate{}, nil
	}

	testChannel, _, fCleanUp, err := createTestChannel(
		alicePrivKey, bobPrivKey, 100000, 100000,
		1000, 1000, lnwire.ShortChannelID{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer fCleanUp()

	link := channelLink{
		cfg: ChannelLinkConfig{
			FwrdingPolicy: ForwardingPolicy{
				TimeLockDelta: 20,
				MinHTLCOut:    500,
				MaxHTLC:       1000,
				BaseFee:       10,
			},
			FetchLastChannelUpdate: fetchLastChannelUpdate,
			MaxOutgoingCltvExpiry:  DefaultMaxOutgoingCltvExpiry,
			HtlcNotifier:           &mockHTLCNotifier{},
		},
		log:     log,
		channel: testChannel.channel,
	}

	var hash [32]byte

	t.Run("satisfied", func(t *testing.T) {
		result := link.CheckHtlcForward(hash, 1500, 1000,
			200, 150, 0)
		if result != nil {
			t.Fatalf("expected policy to be satisfied")
		}
	})

	t.Run("below minhtlc", func(t *testing.T) {
		result := link.CheckHtlcForward(hash, 100, 50,
			200, 150, 0)
		if _, ok := result.WireMessage().(*lnwire.FailAmountBelowMinimum); !ok {
			t.Fatalf("expected FailAmountBelowMinimum failure code")
		}
	})

	t.Run("above maxhtlc", func(t *testing.T) {
		result := link.CheckHtlcForward(hash, 1500, 1200,
			200, 150, 0)
		if _, ok := result.WireMessage().(*lnwire.FailTemporaryChannelFailure); !ok {
			t.Fatalf("expected FailTemporaryChannelFailure failure code")
		}
	})

	t.Run("insufficient fee", func(t *testing.T) {
		result := link.CheckHtlcForward(hash, 1005, 1000,
			200, 150, 0)
		if _, ok := result.WireMessage().(*lnwire.FailFeeInsufficient); !ok {
			t.Fatalf("expected FailFeeInsufficient failure code")
		}
	})

	t.Run("expiry too soon", func(t *testing.T) {
		result := link.CheckHtlcForward(hash, 1500, 1000,
			200, 150, 190)
		if _, ok := result.WireMessage().(*lnwire.FailExpiryTooSoon); !ok {
			t.Fatalf("expected FailExpiryTooSoon failure code")
		}
	})

	t.Run("incorrect cltv expiry", func(t *testing.T) {
		result := link.CheckHtlcForward(hash, 1500, 1000,
			200, 190, 0)
		if _, ok := result.WireMessage().(*lnwire.FailIncorrectCltvExpiry); !ok {
			t.Fatalf("expected FailIncorrectCltvExpiry failure code")
		}

	})

	t.Run("cltv expiry too far in the future", func(t *testing.T) {
		// Check that expiry isn't too far in the future.
		result := link.CheckHtlcForward(hash, 1500, 1000,
			10200, 10100, 0)
		if _, ok := result.WireMessage().(*lnwire.FailExpiryTooFar); !ok {
			t.Fatalf("expected FailExpiryTooFar failure code")
		}
	})
}

// TestChannelLinkCanceledInvoice in this test checks the interaction
// between Alice and Bob for a canceled invoice.
func TestChannelLinkCanceledInvoice(t *testing.T) {
	t.Parallel()

	// Setup a alice-bob network.
	alice, bob, cleanUp, err := createTwoClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}
	defer cleanUp()

	n := newTwoHopNetwork(t, alice.channel, bob.channel, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}
	defer n.stop()

	// Prepare an alice -> bob payment.
	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(amount, testStartingHeight,
		n.bobChannelLink)

	firstHop := n.bobChannelLink.ShortChanID()

	invoice, payFunc, err := preparePayment(
		n.aliceServer, n.bobServer, firstHop, hops, amount, htlcAmt,
		totalTimelock,
	)
	if err != nil {
		t.Fatalf("unable to prepare the payment: %v", err)
	}

	// Cancel the invoice at bob's end.
	hash := invoice.Terms.PaymentPreimage.Hash()
	err = n.bobServer.registry.CancelInvoice(hash)
	if err != nil {
		t.Fatal(err)
	}

	// Have Alice fire the payment.
	err = waitForPayFuncResult(payFunc, 30*time.Second)

	// Because the invoice is canceled, we expect an unknown payment hash
	// result.
	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected ClearTextError, but got %v", err)
	}
	_, ok = rtErr.WireMessage().(*lnwire.FailIncorrectDetails)
	if !ok {
		t.Fatalf("expected unknown payment hash, but got %v", err)
	}
}

type hodlInvoiceTestCtx struct {
	n                   *twoHopNetwork
	startBandwidthAlice lnwire.MilliSatoshi
	startBandwidthBob   lnwire.MilliSatoshi
	hash                lntypes.Hash
	preimage            lntypes.Preimage
	amount              lnwire.MilliSatoshi
	errChan             chan error

	restoreBob func() (*lnwallet.LightningChannel, error)

	cleanUp func()
}

func newHodlInvoiceTestCtx(t *testing.T) (*hodlInvoiceTestCtx, error) {
	// Setup a alice-bob network.
	alice, bob, cleanUp, err := createTwoClusterChannels(
		btcutil.SatoshiPerBitcoin*3,
		btcutil.SatoshiPerBitcoin*5,
	)
	if err != nil {
		t.Fatalf("unable to create channel: %v", err)
	}

	n := newTwoHopNetwork(t, alice.channel, bob.channel, testStartingHeight)
	if err := n.start(); err != nil {
		t.Fatal(err)
	}

	aliceBandwidthBefore := n.aliceChannelLink.Bandwidth()
	bobBandwidthBefore := n.bobChannelLink.Bandwidth()

	debug := false
	if debug {
		// Log message that alice receives.
		n.aliceServer.intersect(
			createLogFunc("alice", n.aliceChannelLink.ChanID()),
		)

		// Log message that bob receives.
		n.bobServer.intersect(
			createLogFunc("bob", n.bobChannelLink.ChanID()),
		)
	}

	amount := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)
	htlcAmt, totalTimelock, hops := generateHops(
		amount, testStartingHeight, n.bobChannelLink,
	)

	// Generate hold invoice preimage.
	r, err := generateRandomBytes(sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := lntypes.MakePreimage(r)
	if err != nil {
		t.Fatal(err)
	}
	hash := preimage.Hash()

	// Have alice pay the hodl invoice, wait for bob's commitment state to
	// be updated and the invoice state to be updated.
	receiver := n.bobServer
	receiver.registry.settleChan = make(chan lntypes.Hash)
	firstHop := n.bobChannelLink.ShortChanID()
	errChan := n.makeHoldPayment(
		n.aliceServer, receiver, firstHop, hops, amount, htlcAmt,
		totalTimelock, preimage,
	)

	select {
	case err := <-errChan:
		t.Fatalf("no payment result expected: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	case h := <-receiver.registry.settleChan:
		if hash != h {
			t.Fatal("unexpect invoice settled")
		}
	}

	return &hodlInvoiceTestCtx{
		n:                   n,
		startBandwidthAlice: aliceBandwidthBefore,
		startBandwidthBob:   bobBandwidthBefore,
		preimage:            preimage,
		hash:                hash,
		amount:              amount,
		errChan:             errChan,
		restoreBob:          bob.restore,

		cleanUp: func() {
			cleanUp()
			n.stop()
		},
	}, nil
}

// TestChannelLinkHoldInvoiceSettle asserts that a hodl invoice can be settled.
func TestChannelLinkHoldInvoiceSettle(t *testing.T) {
	t.Parallel()

	defer timeout(t)()

	ctx, err := newHodlInvoiceTestCtx(t)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.cleanUp()

	err = ctx.n.bobServer.registry.SettleHodlInvoice(ctx.preimage)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for payment to succeed.
	err = <-ctx.errChan
	if err != nil {
		t.Fatal(err)
	}

	// Wait for Alice to receive the revocation. This is needed
	// because the settles are pipelined to the switch and otherwise
	// the bandwidth won't be updated by the time Alice receives a
	// response here.
	time.Sleep(2 * time.Second)

	if ctx.startBandwidthAlice-ctx.amount !=
		ctx.n.aliceChannelLink.Bandwidth() {

		t.Fatal("alice bandwidth should have decrease on payment " +
			"amount")
	}

	if ctx.startBandwidthBob+ctx.amount !=
		ctx.n.bobChannelLink.Bandwidth() {

		t.Fatalf("bob bandwidth isn't match: expected %v, got %v",
			ctx.startBandwidthBob+ctx.amount,
			ctx.n.bobChannelLink.Bandwidth())
	}
}

// TestChannelLinkHoldInvoiceSettle asserts that a hodl invoice can be canceled.
func TestChannelLinkHoldInvoiceCancel(t *testing.T) {
	t.Parallel()

	defer timeout(t)()

	ctx, err := newHodlInvoiceTestCtx(t)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.cleanUp()

	err = ctx.n.bobServer.registry.CancelInvoice(ctx.hash)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for payment to succeed.
	err = <-ctx.errChan
	assertFailureCode(t, err, lnwire.CodeIncorrectOrUnknownPaymentDetails)
}

// TestChannelLinkHoldInvoiceRestart asserts hodl htlcs are held after blocks
// are mined and the link is restarted. The initial expiry checks should not
// apply to hodl htlcs after restart.
func TestChannelLinkHoldInvoiceRestart(t *testing.T) {
	t.Parallel()

	defer timeout(t)()

	const (
		chanAmt = btcutil.SatoshiPerBitcoin * 5
	)

	// We'll start by creating a new link with our chanAmt (5 BTC). We will
	// only be testing Alice's behavior, so the reference to Bob's channel
	// state is unnecessary.
	aliceLink, bobChannel, _, start, cleanUp, restore, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	alice := newPersistentLinkHarness(
		t, aliceLink, nil, restore,
	)

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink = alice.coreLink
		registry = coreLink.cfg.Registry.(*mockInvoiceRegistry)
	)

	registry.settleChan = make(chan lntypes.Hash)

	htlc, invoice := generateHtlcAndInvoice(t, 0)

	// Convert into a hodl invoice and save the preimage for later.
	preimage := invoice.Terms.PaymentPreimage
	invoice.Terms.PaymentPreimage = nil
	invoice.HodlInvoice = true

	// We must add the invoice to the registry, such that Alice
	// expects this payment.
	err = registry.AddInvoice(
		*invoice, htlc.PaymentHash,
	)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}

	ctx := linkTestContext{
		t:          t,
		aliceLink:  alice.link,
		aliceMsgs:  alice.msgs,
		bobChannel: bobChannel,
	}

	// Lock in htlc paying the hodl invoice.
	ctx.sendHtlcBobToAlice(htlc)
	ctx.sendCommitSigBobToAlice(1)
	ctx.receiveRevAndAckAliceToBob()
	ctx.receiveCommitSigAliceToBob(1)
	ctx.sendRevAndAckBobToAlice()

	// We expect a call to the invoice registry to notify the arrival of the
	// htlc.
	<-registry.settleChan

	// Increase block height. This height will be retrieved by the link
	// after restart.
	coreLink.cfg.Switch.bestHeight++

	// Restart link.
	alice.restart(false, false)
	ctx.aliceLink = alice.link
	ctx.aliceMsgs = alice.msgs

	// Expect htlc to be reprocessed.
	<-registry.settleChan

	// Settle the invoice with the preimage.
	err = registry.SettleHodlInvoice(*preimage)
	if err != nil {
		t.Fatalf("settle hodl invoice: %v", err)
	}

	// Expect alice to send a settle and commitsig message to bob.
	ctx.receiveSettleAliceToBob()
	ctx.receiveCommitSigAliceToBob(0)

	// Stop the link
	alice.link.Stop()

	// Check that no unexpected messages were sent.
	select {
	case msg := <-alice.msgs:
		t.Fatalf("did not expect message %T", msg)
	default:
	}
}

// TestChannelLinkRevocationWindowRegular asserts that htlcs paying to a regular
// invoice are settled even if the revocation window gets exhausted.
func TestChannelLinkRevocationWindowRegular(t *testing.T) {
	t.Parallel()

	const (
		chanAmt = btcutil.SatoshiPerBitcoin * 5
	)

	// We'll start by creating a new link with our chanAmt (5 BTC). We will
	// only be testing Alice's behavior, so the reference to Bob's channel
	// state is unnecessary.
	aliceLink, bobChannel, _, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}
	defer aliceLink.Stop()

	var (
		coreLink  = aliceLink.(*channelLink)
		registry  = coreLink.cfg.Registry.(*mockInvoiceRegistry)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	registry.settleChan = make(chan lntypes.Hash)

	htlc1, invoice1 := generateHtlcAndInvoice(t, 0)
	htlc2, invoice2 := generateHtlcAndInvoice(t, 1)

	// We must add the invoice to the registry, such that Alice
	// expects this payment.
	err = registry.AddInvoice(*invoice1, htlc1.PaymentHash)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}
	err = registry.AddInvoice(*invoice2, htlc2.PaymentHash)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}

	// Lock in htlc 1 on both sides.
	ctx.sendHtlcBobToAlice(htlc1)
	ctx.sendCommitSigBobToAlice(1)
	ctx.receiveRevAndAckAliceToBob()
	ctx.receiveCommitSigAliceToBob(1)
	ctx.sendRevAndAckBobToAlice()

	// We expect a call to the invoice registry to notify the arrival of the
	// htlc.
	select {
	case <-registry.settleChan:
	case <-time.After(5 * time.Second):
		t.Fatal("expected invoice to be settled")
	}

	// Expect alice to send a settle and commitsig message to bob. Bob does
	// not yet send the revocation.
	ctx.receiveSettleAliceToBob()
	ctx.receiveCommitSigAliceToBob(0)

	// Pay invoice 2.
	ctx.sendHtlcBobToAlice(htlc2)
	ctx.sendCommitSigBobToAlice(2)
	ctx.receiveRevAndAckAliceToBob()

	// At this point, Alice cannot send a new commit sig to bob because the
	// revocation window is exhausted.

	// Bob sends revocation and signs commit with htlc1 settled.
	ctx.sendRevAndAckBobToAlice()

	// After the revocation, it is again possible for Alice to send a commit
	// sig with htlc2.
	ctx.receiveCommitSigAliceToBob(1)
}

// TestChannelLinkRevocationWindowHodl asserts that htlcs paying to a hodl
// invoice are settled even if the revocation window gets exhausted.
func TestChannelLinkRevocationWindowHodl(t *testing.T) {
	t.Parallel()

	const (
		chanAmt = btcutil.SatoshiPerBitcoin * 5
	)

	// We'll start by creating a new link with our chanAmt (5 BTC). We will
	// only be testing Alice's behavior, so the reference to Bob's channel
	// state is unnecessary.
	aliceLink, bobChannel, batchTicker, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, 0)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		registry  = coreLink.cfg.Registry.(*mockInvoiceRegistry)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	registry.settleChan = make(chan lntypes.Hash)

	// Generate two invoice-htlc pairs.
	htlc1, invoice1 := generateHtlcAndInvoice(t, 0)
	htlc2, invoice2 := generateHtlcAndInvoice(t, 1)

	// Convert into hodl invoices and save the preimages for later.
	preimage1 := invoice1.Terms.PaymentPreimage
	invoice1.Terms.PaymentPreimage = nil
	invoice1.HodlInvoice = true

	preimage2 := invoice2.Terms.PaymentPreimage
	invoice2.Terms.PaymentPreimage = nil
	invoice2.HodlInvoice = true

	// We must add the invoices to the registry, such that Alice
	// expects the payments.
	err = registry.AddInvoice(*invoice1, htlc1.PaymentHash)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}
	err = registry.AddInvoice(*invoice2, htlc2.PaymentHash)
	if err != nil {
		t.Fatalf("unable to add invoice to registry: %v", err)
	}

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	// Lock in htlc 1 on both sides.
	ctx.sendHtlcBobToAlice(htlc1)
	ctx.sendCommitSigBobToAlice(1)
	ctx.receiveRevAndAckAliceToBob()
	ctx.receiveCommitSigAliceToBob(1)
	ctx.sendRevAndAckBobToAlice()

	// We expect a call to the invoice registry to notify the arrival of
	// htlc 1.
	select {
	case <-registry.settleChan:
	case <-time.After(15 * time.Second):
		t.Fatal("exit hop notification not received")
	}

	// Lock in htlc 2 on both sides.
	ctx.sendHtlcBobToAlice(htlc2)
	ctx.sendCommitSigBobToAlice(2)
	ctx.receiveRevAndAckAliceToBob()
	ctx.receiveCommitSigAliceToBob(2)
	ctx.sendRevAndAckBobToAlice()

	select {
	case <-registry.settleChan:
	case <-time.After(15 * time.Second):
		t.Fatal("exit hop notification not received")
	}

	// Settle invoice 1 with the preimage.
	err = registry.SettleHodlInvoice(*preimage1)
	if err != nil {
		t.Fatalf("settle hodl invoice: %v", err)
	}

	// Expect alice to send a settle and commitsig message to bob. Bob does
	// not yet send the revocation.
	ctx.receiveSettleAliceToBob()
	ctx.receiveCommitSigAliceToBob(1)

	// Settle invoice 2 with the preimage.
	err = registry.SettleHodlInvoice(*preimage2)
	if err != nil {
		t.Fatalf("settle hodl invoice: %v", err)
	}

	// Expect alice to send a settle for htlc 2.
	ctx.receiveSettleAliceToBob()

	// At this point, Alice cannot send a new commit sig to bob because the
	// revocation window is exhausted.

	// Sleep to let timer(s) expire.
	time.Sleep(time.Second)

	// We don't expect a commitSig from Alice.
	select {
	case msg := <-aliceMsgs:
		t.Fatalf("did not expect message %T", msg)
	default:
	}

	// Bob sends revocation and signs commit with htlc 1 settled.
	ctx.sendRevAndAckBobToAlice()

	// Allow some time for it to be processed by the link.
	time.Sleep(time.Second)

	// Trigger the batch timer as this may trigger Alice to send a commit
	// sig.
	batchTicker <- time.Time{}

	// After the revocation, it is again possible for Alice to send a commit
	// sig no more htlcs. Bob acks the update.
	ctx.receiveCommitSigAliceToBob(0)
	ctx.sendRevAndAckBobToAlice()

	// Bob updates his remote commit tx.
	ctx.sendCommitSigBobToAlice(0)
	ctx.receiveRevAndAckAliceToBob()

	// Stop the link
	aliceLink.Stop()

	// Check that no unexpected messages were sent.
	select {
	case msg := <-aliceMsgs:
		t.Fatalf("did not expect message %T", msg)
	default:
	}
}

// TestChannelLinkReceiveEmptySig tests the response of the link to receiving an
// empty commit sig. This should be tolerated, but we shouldn't send out an
// empty sig ourselves.
func TestChannelLinkReceiveEmptySig(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTicker, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}
	defer cleanUp()

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		aliceMsgs:  aliceMsgs,
		bobChannel: bobChannel,
	}

	htlc, _ := generateHtlcAndInvoice(t, 0)

	// First, send an Add from Alice to Bob.
	ctx.sendHtlcAliceToBob(0, htlc)
	ctx.receiveHtlcAliceToBob()

	// Tick the batch ticker to trigger a commitsig from Alice->Bob.
	select {
	case batchTicker <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatalf("could not force commit sig")
	}

	// Make Bob send a CommitSig. Since Bob hasn't received Alice's sig, he
	// cannot add the htlc to his remote tx yet. The commit sig that we
	// force Bob to send will be empty. Note that this normally does not
	// happen, because the link (which is not present for Bob in this test)
	// check whether Bob actually owes a sig first.
	ctx.sendCommitSigBobToAlice(0)

	// Receive a CommitSig from Alice covering the htlc from above.
	ctx.receiveCommitSigAliceToBob(1)

	// Wait for RevokeAndAck Alice->Bob. Even though Bob sent an empty
	// commit sig, Alice still needs to revoke the previous commitment tx.
	ctx.receiveRevAndAckAliceToBob()

	// Send RevokeAndAck Bob->Alice to ack the added htlc.
	ctx.sendRevAndAckBobToAlice()

	// We received an empty commit sig, we accepted it, but there is nothing
	// new to sign for us.

	// No other messages are expected.
	ctx.assertNoMsgFromAlice(time.Second)

	// Stop the link
	aliceLink.Stop()
}

// TestPendingCommitTicker tests that a link will fail itself after a timeout if
// the commitment dance stalls out.
func TestPendingCommitTicker(t *testing.T) {
	t.Parallel()

	const chanAmt = btcutil.SatoshiPerBitcoin * 5
	const chanReserve = btcutil.SatoshiPerBitcoin * 1
	aliceLink, bobChannel, batchTicker, start, cleanUp, _, err :=
		newSingleLinkTestHarness(chanAmt, chanReserve)
	if err != nil {
		t.Fatalf("unable to create link: %v", err)
	}

	var (
		coreLink  = aliceLink.(*channelLink)
		aliceMsgs = coreLink.cfg.Peer.(*mockPeer).sentMsgs
	)

	coreLink.cfg.PendingCommitTicker = ticker.NewForce(time.Millisecond)

	linkErrs := make(chan LinkFailureError)
	coreLink.cfg.OnChannelFailure = func(_ lnwire.ChannelID,
		_ lnwire.ShortChannelID, linkErr LinkFailureError) {

		linkErrs <- linkErr
	}

	if err := start(); err != nil {
		t.Fatalf("unable to start test harness: %v", err)
	}
	defer cleanUp()

	ctx := linkTestContext{
		t:          t,
		aliceLink:  aliceLink,
		bobChannel: bobChannel,
		aliceMsgs:  aliceMsgs,
	}

	// Send an HTLC from Alice to Bob, and signal the batch ticker to signa
	// a commitment.
	htlc, _ := generateHtlcAndInvoice(t, 0)
	ctx.sendHtlcAliceToBob(0, htlc)
	ctx.receiveHtlcAliceToBob()
	batchTicker <- time.Now()

	select {
	case msg := <-aliceMsgs:
		if _, ok := msg.(*lnwire.CommitSig); !ok {
			t.Fatalf("expected CommitSig, got: %T", msg)
		}
	case <-time.After(time.Second):
		t.Fatalf("alice did not send commit sig")
	}

	// Check that Alice hasn't failed.
	select {
	case linkErr := <-linkErrs:
		t.Fatalf("link failed unexpectedly: %v", linkErr)
	case <-time.After(50 * time.Millisecond):
	}

	// Without completing the dance, send another HTLC from Alice to Bob.
	// Since the revocation window has been exhausted, we should see the
	// link fail itself immediately due to the low pending commit timeout.
	// In production this would be much longer, e.g. a minute.
	htlc, _ = generateHtlcAndInvoice(t, 1)
	ctx.sendHtlcAliceToBob(1, htlc)
	ctx.receiveHtlcAliceToBob()
	batchTicker <- time.Now()

	// Assert that we get the expected link failure from Alice.
	select {
	case linkErr := <-linkErrs:
		if linkErr.code != ErrRemoteUnresponsive {
			t.Fatalf("error code mismatch, "+
				"want: ErrRemoteUnresponsive, got: %v",
				linkErr.code)
		}

	case <-time.After(time.Second):
		t.Fatalf("did not receive failure")
	}
}

// assertFailureCode asserts that an error is of type ClearTextError and that
// the failure code is as expected.
func assertFailureCode(t *testing.T, err error, code lnwire.FailCode) {
	rtErr, ok := err.(ClearTextError)
	if !ok {
		t.Fatalf("expected ClearTextError but got %T", err)
	}

	if rtErr.WireMessage().Code() != code {
		t.Fatalf("expected %v but got %v",
			code, rtErr.WireMessage().Code())
	}
}
