package sweep

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

// TestTxInputSet tests adding various sized inputs to the set.
func TestTxInputSet(t *testing.T) {
	const (
		feeRate   = 1000
		relayFee  = 300
		maxInputs = 10
	)
	set := newTxInputSet(nil, feeRate, relayFee, maxInputs)

	if set.dustLimit != 537 {
		t.Fatalf("incorrect dust limit")
	}

	// Create a 300 sat input. The fee to sweep this input to a P2WKH output
	// is 439 sats. That means that this input yields -139 sats and we
	// expect it not to be added.
	if set.add(createP2WKHInput(300), nil, constraintsRegular) {
		t.Fatal("expected add of negatively yielding input to fail")
	}

	// A 700 sat input should be accepted into the set, because it yields
	// positively.
	if !set.add(createP2WKHInput(700), nil, constraintsRegular) {
		t.Fatal("expected add of positively yielding input to succeed")
	}

	fee := set.weightEstimate(true).fee()
	require.Equal(t, btcutil.Amount(439), fee)

	// The tx output should now be 700-439 = 261 sats. The dust limit isn't
	// reached yet.
	if set.totalOutput() != 261 {
		t.Fatal("unexpected output value")
	}
	if set.enoughInput() {
		t.Fatal("expected dust limit not yet to be reached")
	}

	// Add a 1000 sat input. This increases the tx fee to 712 sats. The tx
	// output should now be 1000+700 - 712 = 988 sats.
	if !set.add(createP2WKHInput(1000), nil, constraintsRegular) {
		t.Fatal("expected add of positively yielding input to succeed")
	}
	if set.totalOutput() != 988 {
		t.Fatal("unexpected output value")
	}
	if !set.enoughInput() {
		t.Fatal("expected dust limit to be reached")
	}
}

// TestTxInputSetFromWallet tests adding a wallet input to a TxInputSet to reach
// the dust limit.
func TestTxInputSetFromWallet(t *testing.T) {
	const (
		feeRate   = 500
		relayFee  = 300
		maxInputs = 10
	)

	wallet := &mockWallet{}
	set := newTxInputSet(wallet, feeRate, relayFee, maxInputs)

	// Add a 700 sat input to the set. It yields positively, but doesn't
	// reach the output dust limit.
	if !set.add(createP2WKHInput(700), nil, constraintsRegular) {
		t.Fatal("expected add of positively yielding input to succeed")
	}
	if set.enoughInput() {
		t.Fatal("expected dust limit not yet to be reached")
	}

	// Expect that adding a negative yield input fails.
	if set.add(createP2WKHInput(50), nil, constraintsRegular) {
		t.Fatal("expected negative yield input add to fail")
	}

	// Force add the negative yield input. It should succeed.
	if !set.add(createP2WKHInput(50), nil, constraintsForce) {
		t.Fatal("expected forced add to succeed")
	}

	err := set.tryAddWalletInputsIfNeeded(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !set.enoughInput() {
		t.Fatal("expected dust limit to be reached")
	}
}

// createP2WKHInput returns a P2WKH test input with the specified amount.
func createP2WKHInput(amt btcutil.Amount) input.Input {
	input := createTestInput(int64(amt), input.WitnessKeyHash)
	return &input
}

type mockWallet struct {
	Wallet
}

func (m *mockWallet) ListUnspentWitness(minconfirms, maxconfirms int32) (
	[]*lnwallet.Utxo, error) {

	return []*lnwallet.Utxo{
		{
			AddressType: lnwallet.WitnessPubKey,
			Value:       10000,
		},
	}, nil
}

type reqInput struct {
	input.Input

	txOut *wire.TxOut
}

func (r *reqInput) RequiredTxOut() *wire.TxOut {
	return r.txOut
}

// TestTxInputSetRequiredOutput tests that the tx input set behaves as expected
// when we add inputs that have required tx outs.
func TestTxInputSetRequiredOutput(t *testing.T) {
	const (
		feeRate   = 1000
		relayFee  = 300
		maxInputs = 10
	)
	set := newTxInputSet(nil, feeRate, relayFee, maxInputs)
	if set.dustLimit != 537 {
		t.Fatalf("incorrect dust limit")
	}

	// Attempt to add an input with a required txout below the dust limit.
	// This should fail since we cannot trim such outputs.
	inp := &reqInput{
		Input: createP2WKHInput(500),
		txOut: &wire.TxOut{
			Value:    500,
			PkScript: make([]byte, 33),
		},
	}
	require.False(t, set.add(inp, nil, constraintsRegular),
		"expected adding dust required tx out to fail")

	// Create a 1000 sat input that also has a required TxOut of 1000 sat.
	// The fee to sweep this input to a P2WKH output is 439 sats.
	inp = &reqInput{
		Input: createP2WKHInput(1000),
		txOut: &wire.TxOut{
			Value:    1000,
			PkScript: make([]byte, 22),
		},
	}
	require.True(t, set.add(inp, nil, constraintsRegular), "failed adding input")

	// The fee needed to pay for this input and output should be 439 sats.
	fee := set.weightEstimate(false).fee()
	require.Equal(t, btcutil.Amount(439), fee)

	// Since the tx set currently pays no fees, we expect the current
	// change to actually be negative, since this is what it would cost us
	// in fees to add a change output.
	feeWithChange := set.weightEstimate(true).fee()
	if set.changeOutput != -feeWithChange {
		t.Fatalf("expected negative change of %v, had %v",
			-feeWithChange, set.changeOutput)
	}

	// This should also be reflected by not having enough input.
	require.False(t, set.enoughInput())

	// Get a weight estimate without change output, and add an additional
	// input to it.
	dummyInput := createP2WKHInput(1000)
	weight := set.weightEstimate(false)
	require.NoError(t, weight.add(dummyInput))

	// Now we add a an input that is large enough to pay the fee for the
	// transaction without a change output, but not large enough to afford
	// adding a change output.
	extraInput1 := weight.fee() + 100
	require.True(t, set.add(createP2WKHInput(extraInput1), nil, constraintsRegular),
		"expected add of positively yielding input to succeed")

	// The change should be negative, since we would have to add a change
	// output, which we cannot yet afford.
	if set.changeOutput >= 0 {
		t.Fatal("expected change to be negaitve")
	}

	// Even though we cannot afford a change output, the tx set is valid,
	// since we can pay the fees without the change output.
	require.True(t, set.enoughInput())

	// Get another weight estimate, this time with a change output, and
	// figure out how much we must add to afford a change output.
	weight = set.weightEstimate(true)
	require.NoError(t, weight.add(dummyInput))

	// We add what is left to reach this value.
	extraInput2 := weight.fee() - extraInput1 + 100

	// Add this input, which should result in the change now being 100 sats.
	require.True(t, set.add(createP2WKHInput(extraInput2), nil, constraintsRegular))

	// The change should be 100, since this is what is left after paying
	// fees in case of a change output.
	change := set.changeOutput
	if change != 100 {
		t.Fatalf("expected change be 100, was %v", change)
	}

	// Even though the change output is dust, we have enough for fees, and
	// we have an output, so it should be considered enough to craft a
	// valid sweep transaction.
	require.True(t, set.enoughInput())

	// Finally we add an input that should push the change output above the
	// dust limit.
	weight = set.weightEstimate(true)
	require.NoError(t, weight.add(dummyInput))

	// We expect the change to everything that is left after paying the tx
	// fee.
	extraInput3 := weight.fee() - extraInput1 - extraInput2 + 1000
	require.True(t, set.add(createP2WKHInput(extraInput3), nil, constraintsRegular))

	change = set.changeOutput
	if change != 1000 {
		t.Fatalf("expected change to be %v, had %v", 1000, change)

	}
	require.True(t, set.enoughInput())
}
