package routing

import (
	"testing"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// TestUnifiedPolicies tests the composition of unified policies for nodes that
// have multiple channels between them.
func TestUnifiedPolicies(t *testing.T) {
	source := route.Vertex{1}
	toNode := route.Vertex{2}
	fromNode := route.Vertex{3}

	bandwidthHints := &mockBandwidthHints{}

	u := newUnifiedPolicies(source, toNode, nil)

	// Add two channels between the pair of nodes.
	p1 := channeldb.ChannelEdgePolicy{
		FeeProportionalMillionths: 100000,
		FeeBaseMSat:               30,
		TimeLockDelta:             60,
		MessageFlags:              lnwire.ChanUpdateOptionMaxHtlc,
		MaxHTLC:                   500,
		MinHTLC:                   100,
	}
	p2 := channeldb.ChannelEdgePolicy{
		FeeProportionalMillionths: 190000,
		FeeBaseMSat:               10,
		TimeLockDelta:             40,
		MessageFlags:              lnwire.ChanUpdateOptionMaxHtlc,
		MaxHTLC:                   400,
		MinHTLC:                   100,
	}
	u.addPolicy(fromNode, &p1, 7)
	u.addPolicy(fromNode, &p2, 7)

	checkPolicy := func(policy *channeldb.ChannelEdgePolicy,
		feeBase lnwire.MilliSatoshi, feeRate lnwire.MilliSatoshi,
		timeLockDelta uint16) {

		t.Helper()

		if policy.FeeBaseMSat != feeBase {
			t.Fatalf("expected fee base %v, got %v",
				feeBase, policy.FeeBaseMSat)
		}

		if policy.TimeLockDelta != timeLockDelta {
			t.Fatalf("expected fee base %v, got %v",
				timeLockDelta, policy.TimeLockDelta)
		}

		if policy.FeeProportionalMillionths != feeRate {
			t.Fatalf("expected fee rate %v, got %v",
				feeRate, policy.FeeProportionalMillionths)
		}
	}

	policy := u.policies[fromNode].getPolicy(50, bandwidthHints)
	if policy != nil {
		t.Fatal("expected no policy for amt below min htlc")
	}

	policy = u.policies[fromNode].getPolicy(550, bandwidthHints)
	if policy != nil {
		t.Fatal("expected no policy for amt above max htlc")
	}

	// For 200 sat, p1 yields the highest fee. Use that policy to forward,
	// because it will also match p2 in case p1 does not have enough
	// balance.
	policy = u.policies[fromNode].getPolicy(200, bandwidthHints)
	checkPolicy(
		policy, p1.FeeBaseMSat, p1.FeeProportionalMillionths,
		p1.TimeLockDelta,
	)

	// For 400 sat, p2 yields the highest fee. Use that policy to forward,
	// because it will also match p1 in case p2 does not have enough
	// balance. In order to match p1, it needs to have p1's time lock delta.
	policy = u.policies[fromNode].getPolicy(400, bandwidthHints)
	checkPolicy(
		policy, p2.FeeBaseMSat, p2.FeeProportionalMillionths,
		p1.TimeLockDelta,
	)
}
