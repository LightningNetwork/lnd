package routing

import (
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/zpay32"
	"github.com/stretchr/testify/require"
)

func TestValidateCLTVLimit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		cltvLimit      uint32
		finalCltvDelta uint16
		includePadding bool
		expectError    bool
	}{
		{
			name:           "bad limit with padding",
			cltvLimit:      uint32(103),
			finalCltvDelta: uint16(100),
			includePadding: true,
			expectError:    true,
		},
		{
			name:           "good limit with padding",
			cltvLimit:      uint32(104),
			finalCltvDelta: uint16(100),
			includePadding: true,
			expectError:    false,
		},
		{
			name:           "bad limit no padding",
			cltvLimit:      uint32(100),
			finalCltvDelta: uint16(100),
			includePadding: false,
			expectError:    true,
		},
		{
			name:           "good limit no padding",
			cltvLimit:      uint32(101),
			finalCltvDelta: uint16(100),
			includePadding: false,
			expectError:    false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			err := ValidateCLTVLimit(
				testCase.cltvLimit, testCase.finalCltvDelta,
				testCase.includePadding,
			)

			if testCase.expectError {
				require.NotEmpty(t, err)
			} else {
				require.NoError(t, err)
			}
		})
		if !success {
			break
		}
	}
}

// TestUpdateAdditionalEdge checks that we can update the additional edges as
// expected.
func TestUpdateAdditionalEdge(t *testing.T) {

	var (
		testChannelID  = uint64(12345)
		oldFeeBaseMSat = uint32(1000)
		newFeeBaseMSat = uint32(1100)
		oldExpiryDelta = uint16(100)
		newExpiryDelta = uint16(120)

		payHash lntypes.Hash
	)

	// Create a minimal test node using the private key priv1.
	pub := priv1.PubKey().SerializeCompressed()
	testNode := &channeldb.LightningNode{}
	copy(testNode.PubKeyBytes[:], pub)

	nodeID, err := testNode.PubKey()
	require.NoError(t, err, "failed to get node id")

	// Create a payment with a route hint.
	payment := &LightningPayment{
		Target: testNode.PubKeyBytes,
		Amount: 1000,
		RouteHints: [][]zpay32.HopHint{{
			zpay32.HopHint{
				// The nodeID is actually the target itself. It
				// doesn't matter as we are not doing routing
				// in this test.
				NodeID:          nodeID,
				ChannelID:       testChannelID,
				FeeBaseMSat:     oldFeeBaseMSat,
				CLTVExpiryDelta: oldExpiryDelta,
			},
		}},
		paymentHash: &payHash,
	}

	// Create the paymentsession.
	session, err := newPaymentSession(
		payment,
		func() (bandwidthHints, error) {
			return &mockBandwidthHints{}, nil
		},
		func() (routingGraph, func(), error) {
			return &sessionGraph{}, func() {}, nil
		},
		&MissionControl{},
		PathFindingConfig{},
	)
	require.NoError(t, err, "failed to create payment session")

	// We should have 1 additional edge.
	require.Equal(t, 1, len(session.additionalEdges))

	// The edge should use nodeID as key, and its value should have 1 edge
	// policy.
	vertex := route.NewVertex(nodeID)
	policies, ok := session.additionalEdges[vertex]
	require.True(t, ok, "cannot find policy")
	require.Equal(t, 1, len(policies), "should have 1 edge policy")

	// Check that the policy has been created as expected.
	policy := policies[0]
	require.Equal(t, testChannelID, policy.ChannelID, "channel ID mismatch")
	require.Equal(t,
		oldExpiryDelta, policy.TimeLockDelta, "timelock delta mismatch",
	)
	require.Equal(t,
		lnwire.MilliSatoshi(oldFeeBaseMSat),
		policy.FeeBaseMSat, "fee base msat mismatch",
	)

	// Create the channel update message and sign.
	msg := &lnwire.ChannelUpdate{
		ShortChannelID: lnwire.NewShortChanIDFromInt(testChannelID),
		Timestamp:      uint32(time.Now().Unix()),
		BaseFee:        newFeeBaseMSat,
		TimeLockDelta:  newExpiryDelta,
	}
	signErrChanUpdate(t, priv1, msg)

	// Apply the update.
	require.True(t,
		session.UpdateAdditionalEdge(msg, nodeID, policy),
		"failed to update additional edge",
	)

	// Check that the policy has been updated as expected.
	require.Equal(t, testChannelID, policy.ChannelID, "channel ID mismatch")
	require.Equal(t,
		newExpiryDelta, policy.TimeLockDelta, "timelock delta mismatch",
	)
	require.Equal(t,
		lnwire.MilliSatoshi(newFeeBaseMSat),
		policy.FeeBaseMSat, "fee base msat mismatch",
	)
}

func TestRequestRoute(t *testing.T) {
	const (
		height = 10
	)

	cltvLimit := uint32(30)
	finalCltvDelta := uint16(8)

	payment := &LightningPayment{
		CltvLimit:      cltvLimit,
		FinalCLTVDelta: finalCltvDelta,
		Amount:         1000,
		FeeLimit:       1000,
	}

	var paymentHash [32]byte
	if err := payment.SetPaymentHash(paymentHash); err != nil {
		t.Fatal(err)
	}

	session, err := newPaymentSession(
		payment,
		func() (bandwidthHints, error) {
			return &mockBandwidthHints{}, nil
		},
		func() (routingGraph, func(), error) {
			return &sessionGraph{}, func() {}, nil
		},
		&MissionControl{},
		PathFindingConfig{},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Override pathfinder with a mock.
	session.pathFinder = func(
		g *graphParams, r *RestrictParams, cfg *PathFindingConfig,
		source, target route.Vertex, amt lnwire.MilliSatoshi,
		finalHtlcExpiry int32) ([]*channeldb.ChannelEdgePolicy, error) {

		// We expect find path to receive a cltv limit excluding the
		// final cltv delta (including the block padding).
		if r.CltvLimit != 22-uint32(BlockPadding) {
			t.Fatal("wrong cltv limit")
		}

		path := []*channeldb.ChannelEdgePolicy{
			{
				Node: &channeldb.LightningNode{
					Features: lnwire.NewFeatureVector(
						nil, nil,
					),
				},
			},
		}

		return path, nil
	}

	route, err := session.RequestRoute(
		payment.Amount, payment.FeeLimit, 0, height,
	)
	if err != nil {
		t.Fatal(err)
	}

	// We expect an absolute route lock value of height + finalCltvDelta
	// + BlockPadding.
	if route.TotalTimeLock != 18+uint32(BlockPadding) {
		t.Fatalf("unexpected total time lock of %v",
			route.TotalTimeLock)
	}
}

type sessionGraph struct {
	routingGraph
}

func (g *sessionGraph) sourceNode() route.Vertex {
	return route.Vertex{}
}
