package sweep

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// addConstraints defines the constraints to apply when adding an input.
type addConstraints uint8

const (
	// constraintsRegular is for regular input sweeps that should have a positive
	// yield.
	constraintsRegular addConstraints = iota

	// constraintsWallet is for wallet inputs that are only added to bring up the tx
	// output value.
	constraintsWallet

	// constraintsForce is for inputs that should be swept even with a negative
	// yield at the set fee rate.
	constraintsForce
)

type txInputSetState struct {
	// feeRate is the fee rate to use for the sweep transaction.
	feeRate chainfee.SatPerKWeight

	// inputTotal is the total value of all inputs.
	inputTotal btcutil.Amount

	// requiredOutput is the sum of the outputs committed to by the inputs.
	requiredOutput btcutil.Amount

	// changeOutput is the value of the change output. This will be what is
	// left over after subtracting the requiredOutput and the tx fee from
	// the inputTotal.
	//
	// NOTE: This might be below the dust limit, or even negative since it
	// is the change remaining in csse we pay the fee for a change output.
	changeOutput btcutil.Amount

	// inputs is the set of tx inputs.
	inputs []input.Input

	// walletInputTotal is the total value of inputs coming from the wallet.
	walletInputTotal btcutil.Amount

	// force indicates that this set must be swept even if the total yield
	// is negative.
	force bool

	// exclusiveGroups are all exlusive groups of the inputs added to this
	// set.
	exclusiveGroups map[uint64]struct{}

	// walletUtxos holds all the UTXOs we have chosen from the wallet to be
	// part of this set.
	walletUtxos []*lnwallet.Utxo
}

// weightEstimate is the (worst case) tx weight with the current set of
// inputs. It takes a parameter whether to add a change output or not.
func (t *txInputSetState) weightEstimate(change bool) *weightEstimator {
	weightEstimate := newWeightEstimator(t.feeRate)
	for _, i := range t.inputs {
		// Can ignore error, because it has already been checked when
		// calculating the yields.
		_ = weightEstimate.add(i)

		r := i.RequiredTxOut()
		if r != nil {
			weightEstimate.addOutput(r)
		}
	}

	// Add a change output to the weight estimate if requested.
	if change {
		weightEstimate.addP2WKHOutput()
	}

	return weightEstimate
}

// totalOutput is the total amount left for us after paying fees.
//
// NOTE: This might be dust.
func (t *txInputSetState) totalOutput() btcutil.Amount {
	return t.requiredOutput + t.changeOutput
}

func (t *txInputSetState) clone() txInputSetState {
	s := txInputSetState{
		feeRate:          t.feeRate,
		inputTotal:       t.inputTotal,
		changeOutput:     t.changeOutput,
		requiredOutput:   t.requiredOutput,
		walletInputTotal: t.walletInputTotal,
		force:            t.force,
		inputs:           make([]input.Input, len(t.inputs)),
		exclusiveGroups:  make(map[uint64]struct{}),
		walletUtxos:      make([]*lnwallet.Utxo, len(t.walletUtxos)),
	}
	for k := range t.exclusiveGroups {
		s.exclusiveGroups[k] = struct{}{}
	}
	copy(s.inputs, t.inputs)
	copy(s.walletUtxos, t.walletUtxos)

	return s
}

// txInputSet is an object that accumulates tx inputs and keeps running counters
// on various properties of the tx.
type txInputSet struct {
	txInputSetState

	// dustLimit is the minimum output value of the tx.
	dustLimit btcutil.Amount

	// maxInputs is the maximum number of inputs that will be accepted in
	// the set.
	maxInputs int

	// wallet contains wallet functionality required by the input set to
	// retrieve utxos.
	wallet Wallet
}

func dustLimit(relayFee chainfee.SatPerKWeight) btcutil.Amount {
	return txrules.GetDustThreshold(
		input.P2WPKHSize,
		btcutil.Amount(relayFee.FeePerKVByte()),
	)
}

// newTxInputSet constructs a new, empty input set.
func newTxInputSet(wallet Wallet, feePerKW,
	relayFee chainfee.SatPerKWeight, maxInputs int) *txInputSet {

	dustLimit := dustLimit(relayFee)

	state := txInputSetState{
		feeRate: feePerKW,
	}

	b := txInputSet{
		dustLimit:       dustLimit,
		maxInputs:       maxInputs,
		wallet:          wallet,
		txInputSetState: state,
	}

	return &b
}

// enoughInput returns true if we've accumulated enough inputs to pay the fees
// and have at least one output that meets the dust limit.
func (t *txInputSet) enoughInput() bool {
	// If we have a change output above dust, then we certainly have enough
	// inputs to the transaction.
	if t.changeOutput >= t.dustLimit {
		return true
	}

	// We did not have enough input for a change output. Check if we have
	// enough input to pay the fees for a transaction with no change
	// output.
	fee := t.weightEstimate(false).fee()
	if t.inputTotal < t.requiredOutput+fee {
		return false
	}

	// We could pay the fees, but we still need at least one output to be
	// above the dust limit for the tx to be valid (we assume that these
	// required outputs only get added if they are above dust)
	for _, inp := range t.inputs {
		if inp.RequiredTxOut() != nil {
			return true
		}
	}

	return false
}

// add adds a new input to the set. It returns a bool indicating whether the
// input was added to the set. An input is rejected if it decreases the tx
// output value after paying fees.
func (t *txInputSet) addToState(inp input.Input, exclusiveGroup *uint64,
	constraints addConstraints) *txInputSetState {

	// Stop if max inputs is reached. Do not count additional wallet inputs,
	// because we don't know in advance how many we may need.
	if constraints != constraintsWallet &&
		len(t.inputs) >= t.maxInputs {

		return nil
	}

	// If the input comes with a required tx out that is below dust, we
	// won't add it.
	reqOut := inp.RequiredTxOut()
	if reqOut != nil && btcutil.Amount(reqOut.Value) < t.dustLimit {
		return nil
	}

	// Clone the current set state.
	s := t.clone()

	// It this exclusive group was already part of the set, we cannot add
	// this input.
	if exclusiveGroup != nil {
		eg := *exclusiveGroup
		_, ok := s.exclusiveGroups[eg]
		if ok {
			return nil
		}

		s.exclusiveGroups[eg] = struct{}{}
	}

	// Add the new input.
	s.inputs = append(s.inputs, inp)

	// Add the value of the new input.
	value := btcutil.Amount(inp.SignDesc().Output.Value)
	s.inputTotal += value

	// Recalculate the tx fee.
	fee := s.weightEstimate(true).fee()

	// Calculate the new output value.
	if reqOut != nil {
		s.requiredOutput += btcutil.Amount(reqOut.Value)
	}
	s.changeOutput = s.inputTotal - s.requiredOutput - fee

	// Calculate the yield of this input from the change in total tx output
	// value.
	inputYield := s.totalOutput() - t.totalOutput()

	switch constraints {

	// Don't sweep inputs that cost us more to sweep than they give us.
	case constraintsRegular:
		if inputYield <= 0 {
			return nil
		}

	// For force adds, no further constraints apply.
	case constraintsForce:
		s.force = true

	// We are attaching a wallet input to raise the tx output value above
	// the dust limit.
	case constraintsWallet:
		// Skip this wallet input if adding it would lower the output
		// value.
		if inputYield <= 0 {
			return nil
		}

		// Calculate the total value that we spend in this tx from the
		// wallet if we'd add this wallet input.
		s.walletInputTotal += value

		// In any case, we don't want to lose money by sweeping. If we
		// don't get more out of the tx then we put in ourselves, do not
		// add this wallet input. If there is at least one force sweep
		// in the set, this does no longer apply.
		//
		// We should only add wallet inputs to get the tx output value
		// above the dust limit, otherwise we'd only burn into fees.
		// This is guarded by tryAddWalletInputsIfNeeded.
		//
		// TODO(joostjager): Possibly require a max ratio between the
		// value of the wallet input and what we get out of this
		// transaction. To prevent attaching and locking a big utxo for
		// very little benefit.
		if !s.force && s.walletInputTotal >= s.totalOutput() {
			log.Debugf("Rejecting wallet input of %v, because it "+
				"would make a negative yielding transaction "+
				"(%v)",
				value, s.totalOutput()-s.walletInputTotal)

			return nil
		}
	}

	return &s
}

// add adds a new input to the set. It returns a bool indicating whether the
// input was added to the set. An input is rejected if it decreases the tx
// output value after paying fees.
func (t *txInputSet) add(input input.Input, exclusiveGroup *uint64,
	constraints addConstraints) bool {

	newState := t.addToState(input, exclusiveGroup, constraints)
	if newState == nil {
		return false
	}

	t.txInputSetState = *newState

	return true
}

// addPositiveYieldInputs adds sweepableInputs that have a positive yield to the
// input set. This function assumes that the list of inputs is sorted descending
// by yield.
//
// TODO(roasbeef): Consider including some negative yield inputs too to clean
// up the utxo set even if it costs us some fees up front.  In the spirit of
// minimizing any negative externalities we cause for the Bitcoin system as a
// whole.
func (t *txInputSet) addPositiveYieldInputs(sweepableInputs []txInput) {
	for i, inp := range sweepableInputs {
		// Apply relaxed constraints for force sweeps.
		constraints := constraintsRegular
		if inp.parameters().Force {
			constraints = constraintsForce
		}

		// Try to add the input to the transaction. If that doesn't
		// succeed because it wouldn't increase the output value,
		// return. Assuming inputs are sorted by yield, any further
		// inputs wouldn't increase the output value either.
		if !t.add(inp, inp.parameters().ExclusiveGroup, constraints) {
			var rem []input.Input
			for j := i; j < len(sweepableInputs); j++ {
				rem = append(rem, sweepableInputs[j])
			}
			log.Debugf("%d negative yield inputs not added to "+
				"input set: %v", len(rem),
				inputTypeSummary(rem))
			return
		}

		log.Debugf("Added positive yield input %v to input set",
			inputTypeSummary([]input.Input{inp}))
	}

	// We managed to add all inputs to the set.
}

// tryAddWalletInputsIfNeeded retrieves utxos from the wallet and tries adding
// as many as required to bring the tx output value above the given minimum. It
// takes a list of preferred UTXOs that will be added first. This is used to
// re-use UTXOs that have been used in other sweeps having inputs with the same
// exclusive groups.
func (t *txInputSet) tryAddWalletInputsIfNeeded(
	preferredUtxos []*lnwallet.Utxo) error {

	// If we've already have enough to pay the transaction fees and have at
	// least one output materialize, no action is needed.
	if t.enoughInput() {
		return nil
	}

	// Retrieve wallet utxos. Only consider confirmed utxos to prevent
	// problems around RBF rules for unconfirmed inputs.
	newUtxos, err := t.wallet.ListUnspentWitness(1, math.MaxInt32)
	if err != nil {
		return err
	}

	// We merge the preferred and newly listed UTXOs, keeping the preferred
	// ones first in the list, and de-duping as we go.
	var (
		utxos []*lnwallet.Utxo
		added = make(map[wire.OutPoint]struct{})
	)

	addUtxo := func(utxo *lnwallet.Utxo) {
		if _, ok := added[utxo.OutPoint]; ok {
			return
		}
		utxos = append(utxos, utxo)
		added[utxo.OutPoint] = struct{}{}
	}

	for _, u := range preferredUtxos {
		addUtxo(u)
	}
	for _, u := range newUtxos {
		addUtxo(u)
	}

	for _, utxo := range utxos {
		input, err := createWalletTxInput(utxo)
		if err != nil {
			return err
		}

		// If the wallet input isn't positively-yielding at this fee
		// rate, skip it.
		if !t.add(input, nil, constraintsWallet) {
			continue
		}

		// The utxo was added, keep track of it.
		t.walletUtxos = append(t.walletUtxos, utxo)

		// Return if we've reached the minimum output amount.
		if t.enoughInput() {
			return nil
		}
	}

	// We were not able to reach the minimum output amount.
	return nil
}

// createWalletTxInput converts a wallet utxo into an object that can be added
// to the other inputs to sweep.
func createWalletTxInput(utxo *lnwallet.Utxo) (input.Input, error) {
	var witnessType input.WitnessType
	switch utxo.AddressType {
	case lnwallet.WitnessPubKey:
		witnessType = input.WitnessKeyHash
	case lnwallet.NestedWitnessPubKey:
		witnessType = input.NestedWitnessKeyHash
	default:
		return nil, fmt.Errorf("unknown address type %v",
			utxo.AddressType)
	}

	signDesc := &input.SignDescriptor{
		Output: &wire.TxOut{
			PkScript: utxo.PkScript,
			Value:    int64(utxo.Value),
		},
		HashType: txscript.SigHashAll,
	}

	// A height hint doesn't need to be set, because we don't monitor these
	// inputs for spend.
	heightHint := uint32(0)

	return input.NewBaseInput(
		&utxo.OutPoint, witnessType, signDesc, heightHint,
	), nil
}
