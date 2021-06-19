package localchans

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/routing"
)

// TestManager tests that the local channel manager properly propagates fee
// updates to gossiper and links.
func TestManager(t *testing.T) {
	t.Parallel()

	var (
		chanPoint         = wire.OutPoint{Hash: chainhash.Hash{1}, Index: 2}
		chanCap           = btcutil.Amount(1000)
		chanPointInactive = wire.OutPoint{Hash: chainhash.Hash{2}, Index: 2}
		chanCapInactive   = btcutil.Amount(1000)
		chanPointMissing  = wire.OutPoint{Hash: chainhash.Hash{3}, Index: 2}
		maxPendingAmount  = lnwire.MilliSatoshi(999000)
		minHTLC           = lnwire.MilliSatoshi(2000)
	)

	newPolicy := routing.ChannelPolicy{
		FeeSchema: routing.FeeSchema{
			BaseFee: 100,
			FeeRate: 200,
		},
		TimeLockDelta: 80,
		MaxHTLC:       5000,
	}

	currentPolicy := channeldb.ChannelEdgePolicy{
		MinHTLC:      minHTLC,
		MessageFlags: lnwire.ChanUpdateOptionMaxHtlc,
	}

	updateForwardingPolicies := func(
		chanPolicies map[wire.OutPoint]htlcswitch.ForwardingPolicy) {

		if len(chanPolicies) != 1 {
			t.Fatal("unexpected number of policies to apply")
		}

		policy := chanPolicies[chanPoint]
		if policy.TimeLockDelta != newPolicy.TimeLockDelta {
			t.Fatal("unexpected time lock delta")
		}
		if policy.BaseFee != newPolicy.BaseFee {
			t.Fatal("unexpected base fee")
		}
		if uint32(policy.FeeRate) != newPolicy.FeeRate {
			t.Fatal("unexpected base fee")
		}
		if policy.MaxHTLC != newPolicy.MaxHTLC {
			t.Fatal("unexpected max htlc")
		}
	}

	propagateChanPolicyUpdate := func(
		edgesToUpdate []discovery.EdgeWithInfo) error {

		if len(edgesToUpdate) != 1 {
			t.Fatal("unexpected number of edges to update")
		}

		policy := edgesToUpdate[0].Edge
		if !policy.MessageFlags.HasMaxHtlc() {
			t.Fatal("expected max htlc flag")
		}
		if policy.TimeLockDelta != uint16(newPolicy.TimeLockDelta) {
			t.Fatal("unexpected time lock delta")
		}
		if policy.FeeBaseMSat != newPolicy.BaseFee {
			t.Fatal("unexpected base fee")
		}
		if uint32(policy.FeeProportionalMillionths) != newPolicy.FeeRate {
			t.Fatal("unexpected base fee")
		}
		if policy.MaxHTLC != newPolicy.MaxHTLC {
			t.Fatal("unexpected max htlc")
		}

		return nil
	}

	forAllOutgoingChannels := func(cb func(*channeldb.ChannelEdgeInfo,
		*channeldb.ChannelEdgePolicy) error) error {

		err := cb(
			&channeldb.ChannelEdgeInfo{
				Capacity:     chanCap,
				ChannelPoint: chanPoint,
			},
			&currentPolicy,
		)
		if err != nil {
			return err
		}
		return cb(
			&channeldb.ChannelEdgeInfo{
				Capacity:     chanCapInactive,
				ChannelPoint: chanPointInactive,
			},
			&currentPolicy,
		)
	}

	fetchChannel := func(chanPoint wire.OutPoint) (*channeldb.OpenChannel,
		error) {

		constraints := channeldb.ChannelConstraints{
			MaxPendingAmount: maxPendingAmount,
			MinHTLC:          minHTLC,
		}

		return &channeldb.OpenChannel{
			LocalChanCfg: channeldb.ChannelConfig{
				ChannelConstraints: constraints,
			},
		}, nil
	}

	hasActiveLink := func(chanID lnwire.ChannelID) bool {
		activeChannelID := lnwire.NewChanIDFromOutPoint(&chanPoint)
		return chanID == activeChannelID
	}

	manager := Manager{
		UpdateForwardingPolicies:  updateForwardingPolicies,
		PropagateChanPolicyUpdate: propagateChanPolicyUpdate,
		ForAllOutgoingChannels:    forAllOutgoingChannels,
		FetchChannel:              fetchChannel,
		HasActiveLink:             hasActiveLink,
	}

	// Policy with no max htlc value.
	MaxHTLCPolicy := currentPolicy
	MaxHTLCPolicy.MaxHTLC = newPolicy.MaxHTLC
	noMaxHtlcPolicy := newPolicy
	noMaxHtlcPolicy.MaxHTLC = 0

	var updatePolicyTestCases = []struct {
		currentPolicy channeldb.ChannelEdgePolicy
		newPolicy     routing.ChannelPolicy
		valid         bool
		chanPoints    []wire.OutPoint
		errMsg        string
	}{
		// Test updating a valid channel.
		{currentPolicy, newPolicy, true,
			[]wire.OutPoint{chanPoint},
			""},

		// Test updating an active and an inactive channels.
		{currentPolicy, newPolicy, false,
			[]wire.OutPoint{chanPoint, chanPointInactive},
			"an inactive channel should give an error message."},

		// Test updating a missing channel.
		{currentPolicy, newPolicy, false,
			[]wire.OutPoint{chanPointMissing},
			"a missing channel should give an error message."},

		// Test updating all channels. Since one of the channels are
		// inactive this should fail.
		{currentPolicy, newPolicy, false,
			[]wire.OutPoint{},
			"an inactive channel should give an error message."},

		// Here, no max htlc is specified, the max htlc value should be kept
		// unchanged.
		{MaxHTLCPolicy, noMaxHtlcPolicy, true,
			[]wire.OutPoint{chanPoint},
			""},
	}

	// Perform table driven tests.
	for _, upt := range updatePolicyTestCases {
		// Update the current polices.
		currentPolicy = upt.currentPolicy

		err := manager.UpdatePolicy(upt.newPolicy, upt.chanPoints...)
		if !upt.valid && err == nil {
			t.Fatalf(upt.errMsg)
		}
		if upt.valid && err != nil {
			t.Fatalf(err.Error())
		}
	}
}
