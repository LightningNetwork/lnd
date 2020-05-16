package routing

import (
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"go.etcd.io/bbolt"
)

const (
	sourceNodeID = 1
	targetNodeID = 2
)

// integratedRoutingContext defines the context in which integrated routing
// tests run.
type integratedRoutingContext struct {
	graph *mockGraph
	t     *testing.T

	source *mockNode
	target *mockNode

	amt         lnwire.MilliSatoshi
	finalExpiry int32

	mcCfg          MissionControlConfig
	pathFindingCfg PathFindingConfig
}

// newIntegratedRoutingContext instantiates a new integrated routing test
// context with a source and a target node.
func newIntegratedRoutingContext(t *testing.T) *integratedRoutingContext {
	// Instantiate a mock graph.
	source := newMockNode(sourceNodeID)
	target := newMockNode(targetNodeID)

	graph := newMockGraph(t)
	graph.addNode(source)
	graph.addNode(target)
	graph.source = source

	// Initiate the test context with a set of default configuration values.
	// We don't use the lnd defaults here, because otherwise changing the
	// defaults would break the unit tests. The actual values picked aren't
	// critical to excite certain behavior, but do need to be aligned with
	// the test case assertions.
	ctx := integratedRoutingContext{
		t:           t,
		graph:       graph,
		amt:         100000,
		finalExpiry: 40,

		mcCfg: MissionControlConfig{
			PenaltyHalfLife:       30 * time.Minute,
			AprioriHopProbability: 0.6,
			AprioriWeight:         0.5,
			SelfNode:              source.pubkey,
		},

		pathFindingCfg: PathFindingConfig{
			PaymentAttemptPenalty: 1000,
			MinProbability:        0.01,
		},

		source: source,
		target: target,
	}

	return &ctx
}

// htlcAttempt records the route and outcome of an attempted htlc.
type htlcAttempt struct {
	route   *route.Route
	success bool
}

func (h htlcAttempt) String() string {
	return fmt.Sprintf("success=%v, route=%v", h.success, h.route)
}

// testPayment launches a test payment and asserts that it is completed after
// the expected number of attempts.
func (c *integratedRoutingContext) testPayment(maxParts uint32) ([]htlcAttempt,
	error) {

	var (
		nextPid  uint64
		attempts []htlcAttempt
	)

	// Create temporary database for mission control.
	file, err := ioutil.TempFile("", "*.db")
	if err != nil {
		c.t.Fatal(err)
	}

	dbPath := file.Name()
	defer os.Remove(dbPath)

	bboltOpts := &bbolt.Options{
		NoFreelistSync: true,
	}
	db, err := kvdb.Open(kvdb.BoltBackendName, dbPath, bboltOpts)
	if err != nil {
		c.t.Fatal(err)
	}
	defer db.Close()

	// Instantiate a new mission control with the current configuration
	// values.
	mc, err := NewMissionControl(db, &c.mcCfg)
	if err != nil {
		c.t.Fatal(err)
	}

	getBandwidthHints := func() (map[uint64]lnwire.MilliSatoshi, error) {
		// Create bandwidth hints based on local channel balances.
		bandwidthHints := map[uint64]lnwire.MilliSatoshi{}
		for _, ch := range c.graph.nodes[c.source.pubkey].channels {
			bandwidthHints[ch.id] = ch.balance
		}

		return bandwidthHints, nil
	}

	var paymentAddr [32]byte
	payment := LightningPayment{
		FinalCLTVDelta: uint16(c.finalExpiry),
		FeeLimit:       lnwire.MaxMilliSatoshi,
		Target:         c.target.pubkey,
		PaymentAddr:    &paymentAddr,
		DestFeatures:   lnwire.NewFeatureVector(mppFeatures, nil),
		Amount:         c.amt,
		CltvLimit:      math.MaxUint32,
		MaxParts:       maxParts,
	}

	session, err := newPaymentSession(
		&payment, getBandwidthHints,
		func() (routingGraph, func(), error) {
			return c.graph, func() {}, nil
		},
		mc, c.pathFindingCfg,
	)
	if err != nil {
		c.t.Fatal(err)
	}

	// Override default minimum shard amount.
	session.minShardAmt = lnwire.NewMSatFromSatoshis(5000)

	// Now the payment control loop starts. It will keep trying routes until
	// the payment succeeds.
	var (
		amtRemaining  = payment.Amount
		inFlightHtlcs uint32
	)
	for {
		// Create bandwidth hints based on local channel balances.
		bandwidthHints := map[uint64]lnwire.MilliSatoshi{}
		for _, ch := range c.graph.nodes[c.source.pubkey].channels {
			bandwidthHints[ch.id] = ch.balance
		}

		// Find a route.
		route, err := session.RequestRoute(
			amtRemaining, lnwire.MaxMilliSatoshi, inFlightHtlcs, 0,
		)
		if err != nil {
			return attempts, err
		}

		// Send out the htlc on the mock graph.
		pid := nextPid
		nextPid++
		htlcResult, err := c.graph.sendHtlc(route)
		if err != nil {
			c.t.Fatal(err)
		}

		success := htlcResult.failure == nil
		attempts = append(attempts, htlcAttempt{
			route:   route,
			success: success,
		})

		// Process the result. In normal Lightning operations, the
		// sender doesn't get an acknowledgement from the recipient that
		// the htlc arrived. In integrated routing tests, this
		// acknowledgement is available. It is a simplification of
		// reality that still allows certain classes of tests to be
		// performed.
		if success {
			inFlightHtlcs++

			err := mc.ReportPaymentSuccess(pid, route)
			if err != nil {
				c.t.Fatal(err)
			}

			amtRemaining -= route.ReceiverAmt()

			// If the full amount has been paid, the payment is
			// successful and the control loop can be terminated.
			if amtRemaining == 0 {
				break
			}

			// Otherwise try to send the remaining amount.
			continue
		}

		// Failure, update mission control and retry.
		finalResult, err := mc.ReportPaymentFail(
			pid, route,
			getNodeIndex(route, htlcResult.failureSource),
			htlcResult.failure,
		)
		if err != nil {
			c.t.Fatal(err)
		}

		if finalResult != nil {
			break
		}
	}

	return attempts, nil
}

// getNodeIndex returns the zero-based index of the given node in the route.
func getNodeIndex(route *route.Route, failureSource route.Vertex) *int {
	if failureSource == route.SourcePubKey {
		idx := 0
		return &idx
	}

	for i, h := range route.Hops {
		if h.PubKeyBytes == failureSource {
			idx := i + 1
			return &idx
		}
	}
	return nil
}
