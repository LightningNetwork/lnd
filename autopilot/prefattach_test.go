package autopilot

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	prand "math/rand"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
)

func TestConstrainedPrefAttachmentNeedMoreChan(t *testing.T) {
	t.Parallel()

	prand.Seed(time.Now().Unix())

	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)

		chanLimit = 3

		threshold = 0.5
	)

	randChanID := func() lnwire.ShortChannelID {
		return lnwire.NewShortChanIDFromInt(uint64(prand.Int63()))
	}

	testCases := []struct {
		channels  []Channel
		walletAmt btcutil.Amount

		needMore     bool
		amtAvailable btcutil.Amount
		numMore      uint32
	}{
		// Many available funds, but already have too many active open
		// channels.
		{
			[]Channel{
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(prand.Int31()),
				},
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(prand.Int31()),
				},
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(prand.Int31()),
				},
			},
			btcutil.Amount(btcutil.SatoshiPerBitcoin * 10),
			false,
			0,
			0,
		},

		// Ratio of funds in channels and total funds meets the
		// threshold.
		{
			[]Channel{
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin),
				},
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin),
				},
			},
			btcutil.Amount(btcutil.SatoshiPerBitcoin * 2),
			false,
			0,
			0,
		},

		// Ratio of funds in channels and total funds is below the
		// threshold. We have 10 BTC allocated amongst channels and
		// funds, atm. We're targeting 50%, so 5 BTC should be
		// allocated. Only 1 BTC is atm, so 4 BTC should be
		// recommended. We should also request 2 more channels as the
		// limit is 3.
		{
			[]Channel{
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin),
				},
			},
			btcutil.Amount(btcutil.SatoshiPerBitcoin * 9),
			true,
			btcutil.Amount(btcutil.SatoshiPerBitcoin * 4),
			2,
		},

		// Ratio of funds in channels and total funds is below the
		// threshold. We have 14 BTC total amongst the wallet's
		// balance, and our currently opened channels. Since we're
		// targeting a 50% allocation, we should commit 7 BTC. The
		// current channels commit 4 BTC, so we should expected 3 BTC
		// to be committed. We should only request a single additional
		// channel as the limit is 3.
		{
			[]Channel{
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin),
				},
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin * 3),
				},
			},
			btcutil.Amount(btcutil.SatoshiPerBitcoin * 10),
			true,
			btcutil.Amount(btcutil.SatoshiPerBitcoin * 3),
			1,
		},

		// Ratio of funds in channels and total funds is above the
		// threshold.
		{
			[]Channel{
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin),
				},
				{
					ChanID:   randChanID(),
					Capacity: btcutil.Amount(btcutil.SatoshiPerBitcoin),
				},
			},
			btcutil.Amount(btcutil.SatoshiPerBitcoin),
			false,
			0,
			0,
		},
	}

	prefAttach := NewConstrainedPrefAttachment(minChanSize, maxChanSize,
		chanLimit, threshold)

	for i, testCase := range testCases {
		amtToAllocate, numMore, needMore := prefAttach.NeedMoreChans(
			testCase.channels, testCase.walletAmt,
		)

		if amtToAllocate != testCase.amtAvailable {
			t.Fatalf("test #%v: expected %v, got %v",
				i, testCase.amtAvailable, amtToAllocate)
		}
		if needMore != testCase.needMore {
			t.Fatalf("test #%v: expected %v, got %v",
				i, testCase.needMore, needMore)
		}
		if numMore != testCase.numMore {
			t.Fatalf("test #%v: expected %v, got %v",
				i, testCase.numMore, numMore)
		}
	}
}

type genGraphFunc func() (testGraph, func(), error)

type testGraph interface {
	ChannelGraph

	addRandChannel(*btcec.PublicKey, *btcec.PublicKey,
		btcutil.Amount, bool) (*ChannelEdge, *ChannelEdge, error)
}

func newDiskChanGraph() (testGraph, func(), error) {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName, err := ioutil.TempDir("", "channeldb")
	if err != nil {
		return nil, nil, err
	}

	// Next, create channeldb for the first time.
	cdb, err := channeldb.Open(tempDirName)
	if err != nil {
		return nil, nil, err
	}

	cleanUp := func() {
		cdb.Close()
		os.RemoveAll(tempDirName)
	}

	return &databaseChannelGraph{
		db: cdb.ChannelGraph(),
	}, cleanUp, nil
}

var _ testGraph = (*databaseChannelGraph)(nil)

func newMemChanGraph() (testGraph, func(), error) {
	return newMemChannelGraph(), nil, nil
}

var _ testGraph = (*memChannelGraph)(nil)

var chanGraphs = []struct {
	name    string
	genFunc genGraphFunc
}{
	{
		name:    "disk_graph",
		genFunc: newDiskChanGraph,
	},
	{
		name:    "mem_graph",
		genFunc: newMemChanGraph,
	},
}

// TestConstrainedPrefAttachmentSelectEmptyGraph ensures that when passed en
// empty graph, the Select function always detects the state, and returns nil.
// Otherwise, it would be possible for the main Select loop to entire an
// infinite loop.
func TestConstrainedPrefAttachmentSelectEmptyGraph(t *testing.T) {
	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)
		chanLimit   = 3
		threshold   = 0.5
	)

	// First, we'll generate a random key that represents "us", and create
	// a new instance of the heuristic with our set parameters.
	self, err := randKey()
	if err != nil {
		t.Fatalf("unable to generate self key: %v", err)
	}
	prefAttach := NewConstrainedPrefAttachment(minChanSize, maxChanSize,
		chanLimit, threshold)

	skipNodes := make(map[NodeID]struct{})
	for _, graph := range chanGraphs {
		success := t.Run(graph.name, func(t1 *testing.T) {
			graph, cleanup, err := graph.genFunc()
			if err != nil {
				t1.Fatalf("unable to create graph: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			// With the necessary state initialized, we'll not
			// attempt to select a set of candidates channel for
			// creation given the current state of the graph.
			const walletFunds = btcutil.SatoshiPerBitcoin
			directives, err := prefAttach.Select(self, graph,
				walletFunds, 5, skipNodes)
			if err != nil {
				t1.Fatalf("unable to select attachment "+
					"directives: %v", err)
			}

			// We shouldn't have selected any new directives as we
			// started with an empty graph.
			if len(directives) != 0 {
				t1.Fatalf("zero attachment directives "+
					"should have been returned instead %v were",
					len(directives))
			}
		})
		if !success {
			break
		}
	}
}

// TestConstrainedPrefAttachmentSelectTwoVertexes ensures that when passed a
// graph with only two eligible vertexes, then both are selected (without any
// repeats), and the funds are appropriately allocated across each peer.
func TestConstrainedPrefAttachmentSelectTwoVertexes(t *testing.T) {
	t.Parallel()

	prand.Seed(time.Now().Unix())

	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)
		chanLimit   = 3
		threshold   = 0.5
	)

	skipNodes := make(map[NodeID]struct{})
	for _, graph := range chanGraphs {
		success := t.Run(graph.name, func(t1 *testing.T) {
			graph, cleanup, err := graph.genFunc()
			if err != nil {
				t1.Fatalf("unable to create graph: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			// First, we'll generate a random key that represents
			// "us", and create a new instance of the heuristic
			// with our set parameters.
			self, err := randKey()
			if err != nil {
				t1.Fatalf("unable to generate self key: %v", err)
			}
			prefAttach := NewConstrainedPrefAttachment(minChanSize, maxChanSize,
				chanLimit, threshold)

			// For this set, we'll load the memory graph with two
			// nodes, and a random channel connecting them.
			const chanCapacity = btcutil.SatoshiPerBitcoin
			edge1, edge2, err := graph.addRandChannel(
				nil, nil, chanCapacity, false,
			)
			if err != nil {
				t1.Fatalf("unable to generate channel: %v", err)
			}

			// With the necessary state initialized, we'll not
			// attempt to select a set of candidates channel for
			// creation given the current state of the graph.
			const walletFunds = btcutil.SatoshiPerBitcoin * 10
			directives, err := prefAttach.Select(self, graph,
				walletFunds, 2, skipNodes)
			if err != nil {
				t1.Fatalf("unable to select attachment directives: %v", err)
			}

			// Two new directives should have been selected, one
			// for each node already present within the graph.
			if len(directives) != 2 {
				t1.Fatalf("two attachment directives should have been "+
					"returned instead %v were", len(directives))
			}

			// The node attached to should be amongst the two edges
			// created above.
			for _, directive := range directives {
				switch {
				case directive.PeerKey.IsEqual(edge1.Peer.PubKey()):
				case directive.PeerKey.IsEqual(edge2.Peer.PubKey()):
				default:
					t1.Fatalf("attache to unknown node: %x",
						directive.PeerKey.SerializeCompressed())
				}

				// As the number of funds available exceed the
				// max channel size, both edges should consume
				// the maximum channel size.
				if directive.ChanAmt != maxChanSize {
					t1.Fatalf("max channel size should be allocated, "+
						"instead %v was: ", maxChanSize)
				}
			}
		})
		if !success {
			break
		}
	}
}

// TestConstrainedPrefAttachmentIgnoreDisabled asserts that the attachment
// heuristics will ignore nodes if their remote party reports them as being
// disabled.
func TestConstrainedPrefAttachmentIgnoreDisabled(t *testing.T) {
	t.Parallel()

	prand.Seed(time.Now().Unix())

	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)
		chanLimit   = 3
		threshold   = 0.5
	)

	skipNodes := make(map[NodeID]struct{})
	for _, graph := range chanGraphs {
		success := t.Run(graph.name, func(t1 *testing.T) {
			graph, cleanup, err := graph.genFunc()
			if err != nil {
				t1.Fatalf("unable to create graph: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			// First, we'll generate a random key that represents
			// "us", and create a new instance of the heuristic
			// with our set parameters.
			self, err := randKey()
			if err != nil {
				t1.Fatalf("unable to generate self key: %v", err)
			}
			prefAttach := NewConstrainedPrefAttachment(
				minChanSize, maxChanSize, chanLimit, threshold,
			)

			// For this set, we'll load the memory graph with two
			// nodes, and a random channel connecting them. We'll
			// mark each channel as disabled, to test that we ignore
			// them during selection.
			const chanCapacity = btcutil.SatoshiPerBitcoin
			_, _, err = graph.addRandChannel(
				nil, nil, chanCapacity, true,
			)
			if err != nil {
				t1.Fatalf("unable to generate channel: %v", err)
			}

			// Next, we'll attempt to select a set of candidates,
			// passing 10 BTC for the amount of wallet funds. This
			// should return an empty slice of directives, since
			// both nodes report the other as disabled.
			const walletFunds = btcutil.SatoshiPerBitcoin * 10
			directives, err := prefAttach.Select(
				self, graph, walletFunds, 2, skipNodes,
			)
			if err != nil {
				t1.Fatalf("unable to select attachment "+
					"directives: %v", err)
			}
			if len(directives) != 0 {
				t1.Fatalf("zero attachment directives "+
					"should have been returned instead %v were",
					len(directives))
			}
		})
		if !success {
			break
		}
	}
}

// TestConstrainedPrefAttachmentSelectInsufficientFunds ensures that if the
// balance of the backing wallet is below the set min channel size, then it
// never recommends candidates to attach to.
func TestConstrainedPrefAttachmentSelectInsufficientFunds(t *testing.T) {
	t.Parallel()

	prand.Seed(time.Now().Unix())

	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)
		chanLimit   = 3
		threshold   = 0.5
	)

	skipNodes := make(map[NodeID]struct{})
	for _, graph := range chanGraphs {
		success := t.Run(graph.name, func(t1 *testing.T) {
			graph, cleanup, err := graph.genFunc()
			if err != nil {
				t1.Fatalf("unable to create graph: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			// First, we'll generate a random key that represents
			// "us", and create a new instance of the heuristic
			// with our set parameters.
			self, err := randKey()
			if err != nil {
				t1.Fatalf("unable to generate self key: %v", err)
			}
			prefAttach := NewConstrainedPrefAttachment(
				minChanSize, maxChanSize, chanLimit, threshold,
			)

			// Next, we'll attempt to select a set of candidates,
			// passing zero for the amount of wallet funds. This
			// should return an empty slice of directives.
			directives, err := prefAttach.Select(self, graph, 0,
				0, skipNodes)
			if err != nil {
				t1.Fatalf("unable to select attachment "+
					"directives: %v", err)
			}
			if len(directives) != 0 {
				t1.Fatalf("zero attachment directives "+
					"should have been returned instead %v were",
					len(directives))
			}
		})
		if !success {
			break
		}
	}
}

// TestConstrainedPrefAttachmentSelectGreedyAllocation tests that if upon
// deciding a set of candidates, we're unable to evenly split our funds, then
// we attempt to greedily allocate all funds to each selected vertex (up to the
// max channel size).
func TestConstrainedPrefAttachmentSelectGreedyAllocation(t *testing.T) {
	t.Parallel()

	prand.Seed(time.Now().Unix())

	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)
		chanLimit   = 3
		threshold   = 0.5
	)

	skipNodes := make(map[NodeID]struct{})
	for _, graph := range chanGraphs {
		success := t.Run(graph.name, func(t1 *testing.T) {
			graph, cleanup, err := graph.genFunc()
			if err != nil {
				t1.Fatalf("unable to create graph: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			// First, we'll generate a random key that represents
			// "us", and create a new instance of the heuristic
			// with our set parameters.
			self, err := randKey()
			if err != nil {
				t1.Fatalf("unable to generate self key: %v", err)
			}
			prefAttach := NewConstrainedPrefAttachment(
				minChanSize, maxChanSize, chanLimit, threshold,
			)

			const chanCapacity = btcutil.SatoshiPerBitcoin

			// Next, we'll add 3 nodes to the graph, creating an
			// "open triangle topology".
			edge1, _, err := graph.addRandChannel(
				nil, nil, chanCapacity, false,
			)
			if err != nil {
				t1.Fatalf("unable to create channel: %v", err)
			}
			_, _, err = graph.addRandChannel(
				edge1.Peer.PubKey(), nil, chanCapacity, false,
			)
			if err != nil {
				t1.Fatalf("unable to create channel: %v", err)
			}

			// At this point, there should be three nodes in the
			// graph, with node node having two edges.
			numNodes := 0
			twoChans := false
			if err := graph.ForEachNode(func(n Node) error {
				numNodes++

				numChans := 0
				err := n.ForEachChannel(func(c ChannelEdge) error {
					numChans++
					return nil
				})
				if err != nil {
					return err
				}

				twoChans = twoChans || (numChans == 2)

				return nil
			}); err != nil {
				t1.Fatalf("unable to traverse graph: %v", err)
			}
			if numNodes != 3 {
				t1.Fatalf("expected 3 nodes, instead have: %v",
					numNodes)
			}
			if !twoChans {
				t1.Fatalf("expected node to have two channels")
			}

			// We'll now begin our test, modeling the available
			// wallet balance to be 5.5 BTC. We're shooting for a
			// 50/50 allocation, and have 3 BTC in channels. As a
			// result, the heuristic should try to greedily
			// allocate funds to channels.
			const availableBalance = btcutil.SatoshiPerBitcoin * 2.5
			directives, err := prefAttach.Select(self, graph,
				availableBalance, 5, skipNodes)
			if err != nil {
				t1.Fatalf("unable to select attachment "+
					"directives: %v", err)
			}

			// Three directives should have been returned.
			if len(directives) != 3 {
				t1.Fatalf("expected 3 directives, instead "+
					"got: %v", len(directives))
			}

			// The two directive should have the max channel amount
			// allocated.
			if directives[0].ChanAmt != maxChanSize {
				t1.Fatalf("expected recommendation of %v, "+
					"instead got %v", maxChanSize,
					directives[0].ChanAmt)
			}
			if directives[1].ChanAmt != maxChanSize {
				t1.Fatalf("expected recommendation of %v, "+
					"instead got %v", maxChanSize,
					directives[1].ChanAmt)
			}

			// The third channel should have been allocated the
			// remainder, or 0.5 BTC.
			if directives[2].ChanAmt != (btcutil.SatoshiPerBitcoin * 0.5) {
				t1.Fatalf("expected recommendation of %v, "+
					"instead got %v", maxChanSize,
					directives[2].ChanAmt)
			}
		})
		if !success {
			break
		}
	}
}

// TestConstrainedPrefAttachmentSelectSkipNodes ensures that if a node was
// already select for attachment, then that node is excluded from the set of
// candidate nodes.
func TestConstrainedPrefAttachmentSelectSkipNodes(t *testing.T) {
	t.Parallel()

	prand.Seed(time.Now().Unix())

	const (
		minChanSize = 0
		maxChanSize = btcutil.Amount(btcutil.SatoshiPerBitcoin)
		chanLimit   = 3
		threshold   = 0.5
	)

	for _, graph := range chanGraphs {
		success := t.Run(graph.name, func(t1 *testing.T) {
			skipNodes := make(map[NodeID]struct{})

			graph, cleanup, err := graph.genFunc()
			if err != nil {
				t1.Fatalf("unable to create graph: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			// First, we'll generate a random key that represents
			// "us", and create a new instance of the heuristic
			// with our set parameters.
			self, err := randKey()
			if err != nil {
				t1.Fatalf("unable to generate self key: %v", err)
			}
			prefAttach := NewConstrainedPrefAttachment(
				minChanSize, maxChanSize, chanLimit, threshold,
			)

			// Next, we'll create a simple topology of two nodes,
			// with a single channel connecting them.
			const chanCapacity = btcutil.SatoshiPerBitcoin
			_, _, err = graph.addRandChannel(
				nil, nil, chanCapacity, false,
			)
			if err != nil {
				t1.Fatalf("unable to create channel: %v", err)
			}

			// With our graph created, we'll now execute the Select
			// function to recommend potential attachment
			// candidates.
			const availableBalance = btcutil.SatoshiPerBitcoin * 2.5
			directives, err := prefAttach.Select(self, graph,
				availableBalance, 2, skipNodes)
			if err != nil {
				t1.Fatalf("unable to select attachment "+
					"directives: %v", err)
			}

			// As the channel limit is three, and two nodes are
			// present in the graph, both should be selected.
			if len(directives) != 2 {
				t1.Fatalf("expected two directives, instead "+
					"got %v", len(directives))
			}

			// We'll simulate a channel update by adding the nodes
			// we just establish channel with the to set of nodes
			// to be skipped.
			skipNodes[NewNodeID(directives[0].PeerKey)] = struct{}{}
			skipNodes[NewNodeID(directives[1].PeerKey)] = struct{}{}

			// If we attempt to make a call to the Select function,
			// without providing any new information, then we
			// should get no new directives as both nodes has
			// already been attached to.
			directives, err = prefAttach.Select(self, graph,
				availableBalance, 2, skipNodes)
			if err != nil {
				t1.Fatalf("unable to select attachment "+
					"directives: %v", err)
			}

			if len(directives) != 0 {
				t1.Fatalf("zero new directives should have been "+
					"selected, but %v were", len(directives))
			}
		})
		if !success {
			break
		}
	}
}
