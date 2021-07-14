package peer

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnwallet/chancloser"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

var (
	// p2SHAddress is a valid pay to script hash address.
	p2SHAddress = "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n"

	// p2wshAddress is a valid pay to witness script hash address.
	p2wshAddress = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
)

// TestPeerChannelClosureAcceptFeeResponder tests the shutdown responder's
// behavior if we can agree on the fee immediately.
func TestPeerChannelClosureAcceptFeeResponder(t *testing.T) {
	t.Parallel()

	ctx := createTestContext(t)
	defer ctx.cleanup()

	aliceConn := ctx.aliceConn

	// Send the Init message to Alice.
	err := pushMessage(aliceConn, ctx.bobInit)
	require.NoError(t, err)

	// Alice's Peer struct is created, representing a connection to Bob.
	alicePeer := NewBrontide(*ctx.aliceCfg)
	require.NoError(t, alicePeer.Start())

	// Cleanup Alice via Disconnect.
	defer func() {
		alicePeer.Disconnect(errDummy)
		alicePeer.WaitForDisconnect(make(chan struct{}))
	}()

	// Alice should reply with an Init message, we discard it.
	msg, err := getMessage(aliceConn)
	require.NoError(t, err)
	require.IsType(t, &lnwire.Init{}, msg)

	// Create a test channel between Alice and Bob.
	aliceChan, bobLnChan, err := createTestChannels(noUpdate,
		ctx.alicePriv, ctx.bobPriv, ctx.alicePub, ctx.bobPub,
		ctx.aliceDb, ctx.bobDb, ctx.aliceCfg.FeeEstimator,
		ctx.bobSigner, ctx.bobPool, false)
	require.NoError(t, err)

	err = alicePeer.AddNewChannel(aliceChan, make(chan struct{}))
	require.NoError(t, err)

	chanID := lnwire.NewChanIDFromOutPoint(bobLnChan.ChannelPoint())

	// We send a shutdown request to Alice. She will now be the responding
	// node in this shutdown procedure. We first expect Alice to answer
	// this shutdown request with a Shutdown message.
	bobShutdownMsg := lnwire.NewShutdown(chanID, dummyDeliveryScript)
	err = pushMessage(aliceConn, bobShutdownMsg)
	require.NoError(t, err)

	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceShutdownMsg, ok := msg.(*lnwire.Shutdown)
	require.True(t, ok)

	aliceDeliveryScript := aliceShutdownMsg.Address

	// Alice will then send a ClosingSigned message, indicating her
	// proposed closing transaction fee. Alice sends the ClosingSigned
	// message as she is the initiator of the channel.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	// We accept the fee, and send a ClosingSigned with the same fee back,
	// so she knows we agreed.
	aliceFee := aliceClosingSigned.FeeSatoshis
	bobSig, _, _, err := bobLnChan.CreateCloseProposal(
		aliceFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err := lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned := lnwire.NewClosingSigned(
		chanID, aliceFee, parsedSig,
	)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Alice should now see that we agreed on the fee, and should broadcast
	// the closing transaction.
	select {
	case <-ctx.publTx:
	case <-time.After(timeout):
		t.Fatalf("closing tx not broadcast")
	}

	// Alice will respond with a ClosingSigned.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)
	require.Equal(t, aliceClosingSigned.FeeSatoshis, aliceFee)

	// Alice should be waiting in a goroutine for a confirmation.
	ctx.notifier.ConfChan <- &chainntnfs.TxConfirmation{}
}

// TestPeerChannelClosureAcceptFeeInitiator tests the shutdown initiator's
// behavior if we can agree on the fee immediately.
func TestPeerChannelClosureAcceptFeeInitiator(t *testing.T) {
	t.Parallel()

	ctx := createTestContext(t)
	defer ctx.cleanup()

	aliceConn := ctx.aliceConn

	// Send the Init message to Alice.
	err := pushMessage(aliceConn, ctx.bobInit)
	require.NoError(t, err)

	// Alice's Peer struct is created, representing a connection to Bob.
	alicePeer := NewBrontide(*ctx.aliceCfg)
	require.NoError(t, alicePeer.Start())

	// Cleanup Alice via Disconnect.
	defer func() {
		alicePeer.Disconnect(errDummy)
		alicePeer.WaitForDisconnect(make(chan struct{}))
	}()

	// Alice should reply with an Init message, we discard it.
	msg, err := getMessage(aliceConn)
	require.NoError(t, err)
	require.IsType(t, &lnwire.Init{}, msg)

	// Create a test channel between Alice and Bob.
	aliceChan, bobLnChan, err := createTestChannels(noUpdate,
		ctx.alicePriv, ctx.bobPriv, ctx.alicePub, ctx.bobPub,
		ctx.aliceDb, ctx.bobDb, ctx.aliceCfg.FeeEstimator,
		ctx.bobSigner, ctx.bobPool, false)
	require.NoError(t, err)

	err = alicePeer.AddNewChannel(aliceChan, make(chan struct{}))
	require.NoError(t, err)

	// We make Alice send a shutdown request.
	closeCommand := &htlcswitch.ChanClose{
		CloseType:      htlcswitch.CloseRegular,
		ChanPoint:      bobLnChan.ChannelPoint(),
		Updates:        make(chan interface{}, 1),
		TargetFeePerKw: 12500,
		Err:            make(chan error, 1),
	}

	alicePeer.HandleLocalCloseChanReqs(closeCommand)

	// Alice should send a Shutdown message to Bob.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceShutdownMsg, ok := msg.(*lnwire.Shutdown)
	require.True(t, ok)

	aliceDeliveryScript := aliceShutdownMsg.Address

	// Bob will respond with his own Shutdown message.
	chanID := aliceShutdownMsg.ChannelID
	bobShutdownMsg := lnwire.NewShutdown(chanID, dummyDeliveryScript)
	err = pushMessage(aliceConn, bobShutdownMsg)
	require.NoError(t, err)

	// Alice will reply with a ClosingSigned here.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	// Bob should reply with the exact same fee in his next ClosingSigned
	// message.
	aliceFee := aliceClosingSigned.FeeSatoshis
	bobSig, _, _, err := bobLnChan.CreateCloseProposal(
		aliceFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err := lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned := lnwire.NewClosingSigned(
		chanID, aliceFee, parsedSig,
	)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Alice should accept Bob's fee, broadcast the cooperative close tx,
	// and send a ClosingSigned message back to Bob.

	// Alice should now broadcast the closing transaction.
	select {
	case <-ctx.publTx:
	case <-time.After(timeout):
		t.Fatalf("closing tx not broadcast")
	}

	// Alice should respond with the ClosingSigned they both agreed upon.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)
	require.Equal(t, aliceClosingSigned.FeeSatoshis, aliceFee)

	// Alice should be waiting on a single confirmation for the coop close
	// tx.
	ctx.notifier.ConfChan <- &chainntnfs.TxConfirmation{}
}

// TestPeerChannelClosureFeeNegotiationsResponder tests the shutdown
// responder's behavior in the case where we must do several rounds of fee
// negotiation before we agree on a fee.
func TestPeerChannelClosureFeeNegotiationsResponder(t *testing.T) {
	t.Parallel()

	ctx := createTestContext(t)
	defer ctx.cleanup()

	aliceConn := ctx.aliceConn

	// Send the Init message to Alice.
	err := pushMessage(aliceConn, ctx.bobInit)
	require.NoError(t, err)

	// Alice's Peer struct is created, representing a connection to Bob.
	alicePeer := NewBrontide(*ctx.aliceCfg)
	require.NoError(t, alicePeer.Start())

	// Cleanup Alice via Disconnect.
	defer func() {
		alicePeer.Disconnect(errDummy)
		alicePeer.WaitForDisconnect(make(chan struct{}))
	}()

	// Alice should reply with an Init message, we discard it.
	msg, err := getMessage(aliceConn)
	require.NoError(t, err)
	require.IsType(t, &lnwire.Init{}, msg)

	// Create a test channel between Alice and Bob.
	aliceChan, bobLnChan, err := createTestChannels(noUpdate,
		ctx.alicePriv, ctx.bobPriv, ctx.alicePub, ctx.bobPub,
		ctx.aliceDb, ctx.bobDb, ctx.aliceCfg.FeeEstimator,
		ctx.bobSigner, ctx.bobPool, false)
	require.NoError(t, err)

	err = alicePeer.AddNewChannel(aliceChan, make(chan struct{}))
	require.NoError(t, err)

	chanID := lnwire.NewChanIDFromOutPoint(bobLnChan.ChannelPoint())

	// Bob sends a shutdown request to Alice. She will now be the
	// responding node in this shutdown procedure. We first expect Alice to
	// answer this Shutdown request with a Shutdown message.
	bobShutdownMsg := lnwire.NewShutdown(chanID, dummyDeliveryScript)
	err = pushMessage(aliceConn, bobShutdownMsg)
	require.NoError(t, err)

	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceShutdownMsg, ok := msg.(*lnwire.Shutdown)
	require.True(t, ok)

	aliceDeliveryScript := aliceShutdownMsg.Address

	// As Alice is the channel initiator, she will send her ClosingSigned
	// message.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	// Bob doesn't agree with the fee and will send one back that's 2.5x.
	preferredRespFee := aliceClosingSigned.FeeSatoshis
	increasedFee := btcutil.Amount(float64(preferredRespFee) * 2.5)
	bobSig, _, _, err := bobLnChan.CreateCloseProposal(
		increasedFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err := lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned := lnwire.NewClosingSigned(
		chanID, increasedFee, parsedSig,
	)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Alice will now see the new fee we propose, but with current settings
	// it won't accept it immediately as it differs too much by its ideal
	// fee. We should get a new proposal back, which should have the
	// average fee rate proposed.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	// The fee sent by Alice should be less than the fee Bob just sent as
	// Alice should attempt to compromise.
	aliceFee := aliceClosingSigned.FeeSatoshis
	require.LessOrEqual(t, int64(aliceFee), int64(increasedFee))

	lastFeeResponder := aliceFee

	// We try negotiating a 2.1x fee, which should also be rejected.
	increasedFee = btcutil.Amount(float64(preferredRespFee) * 2.1)
	bobSig, _, _, err = bobLnChan.CreateCloseProposal(
		increasedFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err = lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned = lnwire.NewClosingSigned(
		chanID, increasedFee, parsedSig,
	)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Bob's latest proposal still won't be accepted and Alice should send
	// over a new ClosingSigned message. It should be the average of what
	// Bob and Alice each proposed last time.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	// Alice should inch towards Bob's fee, in order to compromise.
	// Additionally, this fee should be less than the fee Bob sent before.
	aliceFee = aliceClosingSigned.FeeSatoshis
	require.GreaterOrEqual(t, int64(aliceFee), int64(lastFeeResponder))
	require.LessOrEqual(t, int64(aliceFee), int64(increasedFee))

	// Finally, Bob will accept the fee by echoing back the same fee that
	// Alice just sent over.
	bobSig, _, _, err = bobLnChan.CreateCloseProposal(
		aliceFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err = lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned = lnwire.NewClosingSigned(chanID, aliceFee, parsedSig)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Alice will now see that Bob agreed on the fee, and broadcast the
	// coop close transaction.
	select {
	case <-ctx.publTx:
	case <-time.After(timeout):
		t.Fatalf("closing tx not broadcast")
	}

	// Alice should respond with the ClosingSigned they both agreed upon.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)
	require.Equal(t, aliceClosingSigned.FeeSatoshis, aliceFee)

	// Alice should be waiting on a single confirmation for the coop close
	// tx.
	ctx.notifier.ConfChan <- &chainntnfs.TxConfirmation{}
}

// TestPeerChannelClosureFeeNegotiationsInitiator tests the shutdown
// initiator's behavior in the case where we must do several rounds of fee
// negotiation before we agree on a fee.
func TestPeerChannelClosureFeeNegotiationsInitiator(t *testing.T) {
	t.Parallel()

	ctx := createTestContext(t)
	defer ctx.cleanup()

	aliceConn := ctx.aliceConn

	// Send the Init message to Alice.
	err := pushMessage(aliceConn, ctx.bobInit)
	require.NoError(t, err)

	// Alice's Peer struct is created, representing a connection to Bob.
	alicePeer := NewBrontide(*ctx.aliceCfg)
	require.NoError(t, alicePeer.Start())

	// Cleanup Alice via Disconnect.
	defer func() {
		alicePeer.Disconnect(errDummy)
		alicePeer.WaitForDisconnect(make(chan struct{}))
	}()

	// Alice should reply with an Init message, we discard it.
	msg, err := getMessage(aliceConn)
	require.NoError(t, err)
	require.IsType(t, &lnwire.Init{}, msg)

	// Create a test channel between Alice and Bob.
	aliceChan, bobLnChan, err := createTestChannels(noUpdate,
		ctx.alicePriv, ctx.bobPriv, ctx.alicePub, ctx.bobPub,
		ctx.aliceDb, ctx.bobDb, ctx.aliceCfg.FeeEstimator,
		ctx.bobSigner, ctx.bobPool, false)
	require.NoError(t, err)

	err = alicePeer.AddNewChannel(aliceChan, make(chan struct{}))
	require.NoError(t, err)

	// We make Alice send a shutdown request.
	closeCommand := &htlcswitch.ChanClose{
		CloseType:      htlcswitch.CloseRegular,
		ChanPoint:      bobLnChan.ChannelPoint(),
		Updates:        make(chan interface{}, 1),
		TargetFeePerKw: 12500,
		Err:            make(chan error, 1),
	}

	alicePeer.HandleLocalCloseChanReqs(closeCommand)

	// Alice should now send a Shutdown request to Bob.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceShutdownMsg, ok := msg.(*lnwire.Shutdown)
	require.True(t, ok)

	aliceDeliveryScript := aliceShutdownMsg.Address

	// Bob will answer the Shutdown message with his own Shutdown.
	chanID := aliceShutdownMsg.ChannelID
	bobShutdownMsg := lnwire.NewShutdown(chanID, dummyDeliveryScript)
	err = pushMessage(aliceConn, bobShutdownMsg)
	require.NoError(t, err)

	// Alice should now respond with a ClosingSigned message with her ideal
	// fee rate.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	idealFeeRate := aliceClosingSigned.FeeSatoshis
	lastReceivedFee := idealFeeRate

	increasedFee := btcutil.Amount(float64(idealFeeRate) * 2.1)
	lastSentFee := increasedFee

	bobSig, _, _, err := bobLnChan.CreateCloseProposal(
		increasedFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err := lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned := lnwire.NewClosingSigned(
		chanID, increasedFee, parsedSig,
	)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// It still won't be accepted, and we should get a new proposal, the
	// average of what we proposed, and what they proposed last time.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	aliceFee := aliceClosingSigned.FeeSatoshis
	require.GreaterOrEqual(t, int64(aliceFee), int64(lastReceivedFee))
	require.LessOrEqual(t, int64(aliceFee), int64(lastSentFee))

	lastReceivedFee = aliceFee

	// We'll try negotiating a 1.5x fee, which should also be rejected.
	increasedFee = btcutil.Amount(float64(idealFeeRate) * 1.5)
	lastSentFee = increasedFee

	bobSig, _, _, err = bobLnChan.CreateCloseProposal(
		increasedFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err = lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned = lnwire.NewClosingSigned(
		chanID, increasedFee, parsedSig,
	)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Alice won't accept Bob's new proposal, and Bob should receive a new
	// proposal which is the average of what Bob proposed and Alice
	// proposed last time.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)

	aliceFee = aliceClosingSigned.FeeSatoshis
	require.GreaterOrEqual(t, int64(aliceFee), int64(lastReceivedFee))
	require.LessOrEqual(t, int64(aliceFee), int64(lastSentFee))

	// Bob will now accept their fee by sending back a ClosingSigned
	// message with an identical fee.
	bobSig, _, _, err = bobLnChan.CreateCloseProposal(
		aliceFee, dummyDeliveryScript, aliceDeliveryScript,
	)
	require.NoError(t, err)

	parsedSig, err = lnwire.NewSigFromSignature(bobSig)
	require.NoError(t, err)

	bobClosingSigned = lnwire.NewClosingSigned(chanID, aliceFee, parsedSig)
	err = pushMessage(aliceConn, bobClosingSigned)
	require.NoError(t, err)

	// Wait for closing tx to be broadcasted.
	select {
	case <-ctx.publTx:
	case <-time.After(timeout):
		t.Fatalf("closing tx not broadcast")
	}

	// Alice should respond with the ClosingSigned they both agreed upon.
	msg, err = getMessage(aliceConn)
	require.NoError(t, err)
	aliceClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	require.True(t, ok)
	require.Equal(t, aliceClosingSigned.FeeSatoshis, aliceFee)

	// Alice should be waiting on a single confirmation for the coop close
	// tx.
	ctx.notifier.ConfChan <- &chainntnfs.TxConfirmation{}
}

// TestChooseDeliveryScript tests that chooseDeliveryScript correctly errors
// when upfront and user set scripts that do not match are provided, allows
// matching values and returns appropriate values in the case where one or none
// are set.
func TestChooseDeliveryScript(t *testing.T) {
	// generate non-zero scripts for testing.
	script1 := genScript(t, p2SHAddress)
	script2 := genScript(t, p2wshAddress)

	tests := []struct {
		name           string
		userScript     lnwire.DeliveryAddress
		shutdownScript lnwire.DeliveryAddress
		expectedScript lnwire.DeliveryAddress
		expectedError  error
	}{
		{
			name:           "Neither set",
			userScript:     nil,
			shutdownScript: nil,
			expectedScript: nil,
			expectedError:  nil,
		},
		{
			name:           "Both set and equal",
			userScript:     script1,
			shutdownScript: script1,
			expectedScript: script1,
			expectedError:  nil,
		},
		{
			name:           "Both set and not equal",
			userScript:     script1,
			shutdownScript: script2,
			expectedScript: nil,
			expectedError:  chancloser.ErrUpfrontShutdownScriptMismatch,
		},
		{
			name:           "Only upfront script",
			userScript:     nil,
			shutdownScript: script1,
			expectedScript: script1,
			expectedError:  nil,
		},
		{
			name:           "Only user script",
			userScript:     script2,
			shutdownScript: nil,
			expectedScript: script2,
			expectedError:  nil,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			script, err := chooseDeliveryScript(
				test.shutdownScript, test.userScript,
			)
			if err != test.expectedError {
				t.Fatalf("Expected: %v, got: %v", test.expectedError, err)
			}

			if !bytes.Equal(script, test.expectedScript) {
				t.Fatalf("Expected: %x, got: %x", test.expectedScript, script)
			}
		})
	}
}

// TestCustomShutdownScript tests that the delivery script of a shutdown
// message can be set to a specified address. It checks that setting a close
// script fails for channels which have an upfront shutdown script already set.
func TestCustomShutdownScript(t *testing.T) {
	script := genScript(t, p2SHAddress)

	// setShutdown is a function which sets the upfront shutdown address
	// for the local channel.
	setShutdown := func(a, b *channeldb.OpenChannel) {
		a.LocalShutdownScript = script
		b.RemoteShutdownScript = script
	}

	tests := []struct {
		name string

		// update is a function used to set values on the channel set
		// up for the test. It is used to set values for upfront
		// shutdown addresses.
		update func(a, b *channeldb.OpenChannel)

		// userCloseScript is the address specified by the user.
		userCloseScript lnwire.DeliveryAddress

		// expectedScript is the address we expect to be set on the
		// shutdown message.
		expectedScript lnwire.DeliveryAddress

		// expectedError is the error we expect, if any.
		expectedError error
	}{
		{
			name:            "User set script",
			update:          noUpdate,
			userCloseScript: script,
			expectedScript:  script,
		},
		{
			name:   "No user set script",
			update: noUpdate,
		},
		{
			name:           "Shutdown set, no user script",
			update:         setShutdown,
			expectedScript: script,
		},
		{
			name:            "Shutdown set, user script matches",
			update:          setShutdown,
			userCloseScript: script,
			expectedScript:  script,
		},
		{
			name:            "Shutdown set, user script different",
			update:          setShutdown,
			userCloseScript: []byte("different addr"),
			expectedError:   chancloser.ErrUpfrontShutdownScriptMismatch,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {

			ctx := createTestContext(t)
			defer ctx.cleanup()

			aliceConn := ctx.aliceConn

			// Send the Init message to Alice.
			err := pushMessage(aliceConn, ctx.bobInit)
			require.NoError(t, err)

			// Alice's Peer struct is created, representing a
			// connection to Bob.
			alicePeer := NewBrontide(*ctx.aliceCfg)
			require.NoError(t, alicePeer.Start())

			// Cleanup Alice via Disconnect.
			defer func() {
				alicePeer.Disconnect(errDummy)
				alicePeer.WaitForDisconnect(
					make(chan struct{}),
				)
			}()

			// Alice should reply with an Init message, we discard
			// it.
			msg, err := getMessage(aliceConn)
			require.NoError(t, err)
			require.IsType(t, &lnwire.Init{}, msg)

			// Create a test channel between Alice and Bob.
			aliceChan, bobLnChan, err := createTestChannels(
				test.update, ctx.alicePriv, ctx.bobPriv,
				ctx.alicePub, ctx.bobPub, ctx.aliceDb,
				ctx.bobDb, ctx.aliceCfg.FeeEstimator,
				ctx.bobSigner, ctx.bobPool, false)
			require.NoError(t, err)

			err = alicePeer.AddNewChannel(
				aliceChan, make(chan struct{}),
			)
			require.NoError(t, err)

			// Request initiator to cooperatively close the
			// channel, with a specified delivery address.
			errChan := make(chan error, 1)
			closeCommand := &htlcswitch.ChanClose{
				CloseType:      htlcswitch.CloseRegular,
				ChanPoint:      bobLnChan.ChannelPoint(),
				Updates:        make(chan interface{}, 1),
				TargetFeePerKw: 12500,
				DeliveryScript: test.userCloseScript,
				Err:            errChan,
			}

			// Send the close command for the correct channel and
			// check that a shutdown message is sent.
			alicePeer.HandleLocalCloseChanReqs(closeCommand)

			if test.expectedError != nil {
				select {
				case <-time.After(timeout):
					t.Fatalf("did not receive error")
				case err := <-errChan:
					// Fail if we do not expect this error.
					require.Equal(t, err, test.expectedError)

					// Terminate the test early if we have
					// received the expected error, no
					// further action is expected.
					return
				}
			}

			// Check that we have received a shutdown message.
			msg, err = getMessage(aliceConn)
			require.NoError(t, err)
			aliceShutdownMsg, ok := msg.(*lnwire.Shutdown)
			require.True(t, ok)

			// If the test has not specified an expected address,
			// do not check whether the shutdown address matches.
			// This covers the case where we expect shutdown to a
			// random address and cannot match it.
			if len(test.expectedScript) == 0 {
				return
			}

			// Check that the Shutdown message includes the
			// expected delivery script.
			if !bytes.Equal(
				test.expectedScript, aliceShutdownMsg.Address,
			) {
				t.Fatalf("expected delivery script: %x, got: %x",
					test.expectedScript, aliceShutdownMsg.Address)
			}
		})
	}
}

// TestStaticRemoteDowngrade tests that we downgrade our static remote feature
// bit to optional if we have legacy channels with a peer. This ensures that
// we can stay connected to peers that don't support the feature bit that we
// have channels with.
func TestStaticRemoteDowngrade(t *testing.T) {
	t.Parallel()

	var (
		// We set the same legacy feature bits for all tests, since
		// these are not relevant to our test scenario
		rawLegacy = lnwire.NewRawFeatureVector(
			lnwire.UpfrontShutdownScriptOptional,
		)
		legacy = lnwire.NewFeatureVector(rawLegacy, nil)

		legacyCombinedOptional = lnwire.NewRawFeatureVector(
			lnwire.UpfrontShutdownScriptOptional,
			lnwire.StaticRemoteKeyOptional,
		)

		rawFeatureOptional = lnwire.NewRawFeatureVector(
			lnwire.StaticRemoteKeyOptional,
		)

		featureOptional = lnwire.NewFeatureVector(
			rawFeatureOptional, nil,
		)

		rawFeatureRequired = lnwire.NewRawFeatureVector(
			lnwire.StaticRemoteKeyRequired,
		)

		featureRequired = lnwire.NewFeatureVector(
			rawFeatureRequired, nil,
		)
	)

	tests := []struct {
		name         string
		legacy       bool
		features     *lnwire.FeatureVector
		expectedInit *lnwire.Init
	}{
		{
			name:     "no legacy channel, static optional",
			legacy:   false,
			features: featureOptional,
			expectedInit: &lnwire.Init{
				GlobalFeatures: rawLegacy,
				Features:       rawFeatureOptional,
				ExtraData:      make([]byte, 0),
			},
		},
		{
			name:     "legacy channel, static optional",
			legacy:   true,
			features: featureOptional,
			expectedInit: &lnwire.Init{
				GlobalFeatures: rawLegacy,
				Features:       rawFeatureOptional,
				ExtraData:      make([]byte, 0),
			},
		},
		{
			name:     "no legacy channel, static required",
			legacy:   false,
			features: featureRequired,
			expectedInit: &lnwire.Init{
				GlobalFeatures: rawLegacy,
				Features:       rawFeatureRequired,
				ExtraData:      make([]byte, 0),
			},
		},

		// In this case we need to flip our required bit to optional,
		// this should also propagate to the legacy set of feature bits
		// so we have proper consistency: a bit isn't set to optional
		// in one field and required in the other.
		{
			name:     "legacy channel, static required",
			legacy:   true,
			features: featureRequired,
			expectedInit: &lnwire.Init{
				GlobalFeatures: legacyCombinedOptional,
				Features:       rawFeatureOptional,
				ExtraData:      make([]byte, 0),
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			ctx := createTestContext(t)
			defer ctx.cleanup()

			aliceConn := ctx.aliceConn

			ctx.aliceCfg.LegacyFeatures = legacy
			ctx.aliceCfg.Features = test.features

			// Create a test channel between Alice and Bob.
			_, _, err := createTestChannels(
				noUpdate, ctx.alicePriv, ctx.bobPriv,
				ctx.alicePub, ctx.bobPub, ctx.aliceDb,
				ctx.bobDb, ctx.aliceCfg.FeeEstimator,
				ctx.bobSigner, ctx.bobPool, test.legacy,
			)
			require.NoError(t, err)

			// Send the Init message to Alice.
			err = pushMessage(aliceConn, ctx.bobInit)
			require.NoError(t, err)

			// Alice's Peer struct is created, representing a
			// connection to Bob.
			alicePeer := NewBrontide(*ctx.aliceCfg)
			require.NoError(t, alicePeer.Start())

			// Cleanup Alice via Disconnect.
			defer func() {
				alicePeer.Disconnect(errDummy)
				alicePeer.WaitForDisconnect(
					make(chan struct{}),
				)
			}()

			// Alice should reply with an Init message, we discard
			// it during this test.
			msg, err := getMessage(aliceConn)
			require.NoError(t, err)
			aliceInitMsg, ok := msg.(*lnwire.Init)
			require.True(t, ok)

			require.Equal(t, aliceInitMsg, test.expectedInit)
		})
	}
}

// genScript creates a script paying out to the address provided, which must
// be a valid address.
func genScript(t *testing.T, address string) lnwire.DeliveryAddress {
	// Generate an address which can be used for testing.
	deliveryAddr, err := btcutil.DecodeAddress(
		address,
		&chaincfg.TestNet3Params,
	)
	if err != nil {
		t.Fatalf("invalid delivery address: %v", err)
	}

	script, err := txscript.PayToAddrScript(deliveryAddr)
	if err != nil {
		t.Fatalf("cannot create script: %v", err)
	}

	return script
}
