package contractcourt

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	outgoingContestHtlcExpiry = 110
)

// TestHtlcOutgoingResolverTimeout tests resolution of an offered htlc that
// timed out.
func TestHtlcOutgoingResolverTimeout(t *testing.T) {
	t.Parallel()
	defer timeout(t)()

	// Setup the resolver with our test resolution.
	ctx := newOutgoingResolverTestContext(t)

	// Start the resolution process in a goroutine.
	ctx.resolve(true)

	// Notify arrival of the block after which the timeout path of the htlc
	// unlocks.
	ctx.notifyEpoch(outgoingContestHtlcExpiry - 1)

	// Assert that the resolver finishes without error and transforms in a
	// timeout resolver.
	ctx.waitForResult(true)
}

// TestHtlcOutgoingResolverRemoteClaim tests resolution of an offered htlc that
// is claimed by the remote party.
func TestHtlcOutgoingResolverRemoteClaim(t *testing.T) {
	t.Parallel()
	defer timeout(t)()

	// Setup the resolver with our test resolution and start the resolution
	// process.
	ctx := newOutgoingResolverTestContext(t)
	ctx.resolve(true)

	// The remote party sweeps the htlc. Notify our resolver of this event.
	preimage := lntypes.Preimage{}
	ctx.notifier.spendChan <- &chainntnfs.SpendDetail{
		SpendingTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{
				{
					Witness: [][]byte{
						{0}, {1}, {2}, preimage[:], {4},
					},
				},
			},
		},
	}

	// We expect the extracted preimage to be added to the witness beacon.
	<-ctx.preimageDB.newPreimages

	// We also expect a resolution message to the incoming side of the
	// circuit.
	<-ctx.resolutionChan

	// Assert that the resolver finishes without error.
	ctx.waitForResult(false)
}

// TestHtlcOutgoingResolverRemoteClaim tests resolution of an offered htlc that
// is claimed by the remote party. Specifically, claiming by sending a
// retribution transaction is tested.
func TestHtlcOutgoingResolveWithFailure(t *testing.T) {
	t.Parallel()
	defer timeout(t)()

	tests := []struct {
		name         string
		isEarlySpend bool
	}{
		{
			name:         "output spent before resolver started",
			isEarlySpend: true,
		},
		{
			name:         "output spent after resolver started",
			isEarlySpend: false,
		},
	}

	for _, test := range tests {
		// Setup the resolver with our test resolution and start the
		// resolution process.
		ctx := newOutgoingResolverTestContext(t)

		// The remote party sweeps the HTLC by sending a retribution
		// transaction. Notify our resolver of this event.
		revokKey := bytes.Repeat([]byte{0x00}, 33)
		spendDetails := &chainntnfs.SpendDetail{
			SpendingTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{
					{
						Witness: [][]byte{
							{0}, revokKey},
					},
				},
			},
		}

		if test.isEarlySpend {
			// To simulate an early spend, we send spendDetails
			// before running the resolver. Also, the resolver
			// shouldn't expect for new block epochs.
			go func() {
				ctx.notifier.spendChan <- spendDetails
			}()
			ctx.resolve(!test.isEarlySpend)
		} else {
			// To simulate a late spend, we send spendDetails after
			// running the resolver. The resolver also receives a
			// new block epoch.
			ctx.resolve(test.isEarlySpend)
			ctx.notifier.spendChan <- spendDetails
		}

		// We expect a resolution message to the incoming side of the
		// circuit.
		resMsg := <-ctx.resolutionChan

		// We expect preImage to be nil because it wasn't revealed.
		if resMsg.PreImage != nil {
			t.Errorf("didn't expect a pre-image, got '%x'",
				*resMsg.PreImage)
		}

		// We expect the resolution message to contain a failure.
		_, ok := resMsg.Failure.(*lnwire.FailPermanentChannelFailure)
		if !ok {
			t.Errorf("expected resolution message to have a "+
				"failure of type "+
				"lnwire.FailPermanentChannelFailure, got %+v",
				resMsg.Failure)
		}

		// We expect the resolution message to contain a proper channel
		// ID.
		if resMsg.SourceChan.BlockHeight != 31337 ||
			resMsg.SourceChan.TxIndex != 13 ||
			resMsg.SourceChan.TxPosition != 1 {
			t.Errorf("expected resolution message to have channel "+
				"ID 31337:13:1, "+
				"got %+v", resMsg.SourceChan)
		}

		// Assert that the resolver finishes without error.
		ctx.waitForResult(false)
	}
}

type resolveResult struct {
	err          error
	nextResolver ContractResolver
}

type outgoingResolverTestContext struct {
	resolver           *htlcOutgoingContestResolver
	notifier           *mockNotifier
	preimageDB         *mockWitnessBeacon
	resolverResultChan chan resolveResult
	resolutionChan     chan ResolutionMsg
	t                  *testing.T
}

func newOutgoingResolverTestContext(t *testing.T) *outgoingResolverTestContext {
	notifier := &mockNotifier{
		epochChan: make(chan *chainntnfs.BlockEpoch),
		spendChan: make(chan *chainntnfs.SpendDetail),
		confChan:  make(chan *chainntnfs.TxConfirmation),
	}

	checkPointChan := make(chan struct{}, 1)
	resolutionChan := make(chan ResolutionMsg, 1)

	preimageDB := newMockWitnessBeacon()

	onionProcessor := &mockOnionProcessor{}

	chainCfg := ChannelArbitratorConfig{
		ChainArbitratorConfig: ChainArbitratorConfig{
			Notifier:   notifier,
			PreimageDB: preimageDB,
			DeliverResolutionMsg: func(msgs ...ResolutionMsg) error {
				if len(msgs) != 1 {
					return fmt.Errorf("expected 1 "+
						"resolution msg, instead got %v",
						len(msgs))
				}

				resolutionChan <- msgs[0]
				return nil
			},
			OnionProcessor: onionProcessor,
		},
		ShortChanID: lnwire.ShortChannelID{
			BlockHeight: 31337,
			TxIndex:     13,
			TxPosition:  1,
		},
	}

	outgoingRes := lnwallet.OutgoingHtlcResolution{
		Expiry: outgoingContestHtlcExpiry,
		SweepSignDesc: input.SignDescriptor{
			Output: &wire.TxOut{},
		},
	}

	cfg := ResolverConfig{
		ChannelArbitratorConfig: chainCfg,
		Checkpoint: func(_ ContractResolver) error {
			checkPointChan <- struct{}{}
			return nil
		},
	}

	resolver := &htlcOutgoingContestResolver{
		htlcTimeoutResolver: htlcTimeoutResolver{
			contractResolverKit: *newContractResolverKit(cfg),
			htlcResolution:      outgoingRes,
			htlc: channeldb.HTLC{
				RHash:     testResHash,
				OnionBlob: testOnionBlob,
			},
		},
	}

	return &outgoingResolverTestContext{
		resolver:       resolver,
		notifier:       notifier,
		preimageDB:     preimageDB,
		resolutionChan: resolutionChan,
		t:              t,
	}
}

func (i *outgoingResolverTestContext) resolve(notifyInitialBlockHeight bool) {
	// Start resolver.
	i.resolverResultChan = make(chan resolveResult, 1)
	go func() {
		nextResolver, err := i.resolver.Resolve()
		i.resolverResultChan <- resolveResult{
			nextResolver: nextResolver,
			err:          err,
		}
	}()

	// Notify initial block height. This is not needed when the output
	// has been spent before the resolver started.
	if notifyInitialBlockHeight {
		i.notifyEpoch(testInitialBlockHeight)
	}
}

func (i *outgoingResolverTestContext) notifyEpoch(height int32) {
	i.notifier.epochChan <- &chainntnfs.BlockEpoch{
		Height: height,
	}
}

func (i *outgoingResolverTestContext) waitForResult(expectTimeoutRes bool) {
	i.t.Helper()

	result := <-i.resolverResultChan
	if result.err != nil {
		i.t.Fatal(result.err)
	}

	if !expectTimeoutRes {
		if result.nextResolver != nil {
			i.t.Fatal("expected no next resolver")
		}
		return
	}

	_, ok := result.nextResolver.(*htlcTimeoutResolver)
	if !ok {
		i.t.Fatal("expected htlcTimeoutResolver")
	}
}
