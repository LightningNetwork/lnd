package chanfunding

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
)

// FullIntent is an intent that is fully backed by the internal wallet. This
// intent differs from the ShimIntent, in that the funding transaction will be
// constructed internally, and will consist of only inputs we wholly control.
// This Intent implements a basic state machine that must be executed in order
// before CompileFundingTx can be called.
//
// Steps to final channel provisioning:
//  1. Call BindKeys to notify the intent which keys to use when constructing
//  the multi-sig output.
//  2. Call CompileFundingTx afterwards to obtain the funding transaction.
//
// If either of these steps fail, then the Cancel method MUST be called.
type FullIntent struct {
	ShimIntent

	// InputCoins are the set of coins selected as inputs to this funding
	// transaction.
	InputCoins []Coin

	// ChangeOutputs are the set of outputs that the Assembler will use as
	// change from the main funding transaction.
	ChangeOutputs []*wire.TxOut

	// coinLocker is the Assembler's instance of the OutpointLocker
	// interface.
	coinLocker OutpointLocker

	// coinSource is the Assembler's instance of the CoinSource interface.
	coinSource CoinSource

	// signer is the Assembler's instance of the Singer interface.
	signer input.Signer
}

// BindKeys is a method unique to the FullIntent variant. This allows the
// caller to decide precisely which keys are used in the final funding
// transaction. This is kept out of the main Assembler as these may may not
// necessarily be under full control of the wallet. Only after this method has
// been executed will CompileFundingTx succeed.
func (f *FullIntent) BindKeys(localKey *keychain.KeyDescriptor,
	remoteKey *btcec.PublicKey) {

	f.localKey = localKey
	f.remoteKey = remoteKey
}

// CompileFundingTx is to be called after BindKeys on the sub-intent has been
// called. This method will construct the final funding transaction, and fully
// sign all inputs that are known by the backing CoinSource. After this method
// returns, the Intent is assumed to be complete, as the output can be created
// at any point.
func (f *FullIntent) CompileFundingTx(extraInputs []*wire.TxIn,
	extraOutputs []*wire.TxOut) (*wire.MsgTx, error) {

	// Create a blank, fresh transaction. Soon to be a complete funding
	// transaction which will allow opening a lightning channel.
	fundingTx := wire.NewMsgTx(2)

	// Add all multi-party inputs and outputs to the transaction.
	for _, coin := range f.InputCoins {
		fundingTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: coin.OutPoint,
		})
	}
	for _, theirInput := range extraInputs {
		fundingTx.AddTxIn(theirInput)
	}
	for _, ourChangeOutput := range f.ChangeOutputs {
		fundingTx.AddTxOut(ourChangeOutput)
	}
	for _, theirChangeOutput := range extraOutputs {
		fundingTx.AddTxOut(theirChangeOutput)
	}

	_, fundingOutput, err := f.FundingOutput()
	if err != nil {
		return nil, err
	}

	// Sort the transaction. Since both side agree to a canonical ordering,
	// by sorting we no longer need to send the entire transaction. Only
	// signatures will be exchanged.
	fundingTx.AddTxOut(fundingOutput)
	txsort.InPlaceSort(fundingTx)

	// Now that the funding tx has been fully assembled, we'll locate the
	// index of the funding output so we can create our final channel
	// point.
	_, multiSigIndex := input.FindScriptOutputIndex(
		fundingTx, fundingOutput.PkScript,
	)

	// Next, sign all inputs that are ours, collecting the signatures in
	// order of the inputs.
	signDesc := input.SignDescriptor{
		HashType:  txscript.SigHashAll,
		SigHashes: txscript.NewTxSigHashes(fundingTx),
	}
	for i, txIn := range fundingTx.TxIn {
		// We can only sign this input if it's ours, so we'll ask the
		// coin source if it can map this outpoint into a coin we own.
		// If not, then we'll continue as it isn't our input.
		info, err := f.coinSource.CoinFromOutPoint(
			txIn.PreviousOutPoint,
		)
		if err != nil {
			continue
		}

		// Now that we know the input is ours, we'll populate the
		// signDesc with the per input unique information.
		signDesc.Output = &wire.TxOut{
			Value:    info.Value,
			PkScript: info.PkScript,
		}
		signDesc.InputIndex = i

		// Finally, we'll sign the input as is, and populate the input
		// with the witness and sigScript (if needed).
		inputScript, err := f.signer.ComputeInputScript(
			fundingTx, &signDesc,
		)
		if err != nil {
			return nil, err
		}

		txIn.SignatureScript = inputScript.SigScript
		txIn.Witness = inputScript.Witness
	}

	// Finally, we'll populate the chanPoint now that we've fully
	// constructed the funding transaction.
	f.chanPoint = &wire.OutPoint{
		Hash:  fundingTx.TxHash(),
		Index: multiSigIndex,
	}

	return fundingTx, nil
}

// Inputs returns all inputs to the final funding transaction that we
// know about. Since this funding transaction is created all from our wallet,
// it will be all inputs.
func (f *FullIntent) Inputs() []wire.OutPoint {
	var ins []wire.OutPoint
	for _, coin := range f.InputCoins {
		ins = append(ins, coin.OutPoint)
	}

	return ins
}

// Outputs returns all outputs of the final funding transaction that we
// know about. This will be the funding output and the change outputs going
// back to our wallet.
func (f *FullIntent) Outputs() []*wire.TxOut {
	outs := f.ShimIntent.Outputs()
	outs = append(outs, f.ChangeOutputs...)

	return outs
}

// Cancel allows the caller to cancel a funding Intent at any time.  This will
// return any resources such as coins back to the eligible pool to be used in
// order channel fundings.
//
// NOTE: Part of the chanfunding.Intent interface.
func (f *FullIntent) Cancel() {
	for _, coin := range f.InputCoins {
		f.coinLocker.UnlockOutpoint(coin.OutPoint)
	}

	f.ShimIntent.Cancel()
}

// A compile-time check to ensure FullIntent meets the Intent interface.
var _ Intent = (*FullIntent)(nil)

// WalletConfig is the main config of the WalletAssembler.
type WalletConfig struct {
	// CoinSource is what the WalletAssembler uses to list/locate coins.
	CoinSource CoinSource

	// CoinSelectionLocker allows the WalletAssembler to gain exclusive
	// access to the current set of coins returned by the CoinSource.
	CoinSelectLocker CoinSelectionLocker

	// CoinLocker is what the WalletAssembler uses to lock coins that may
	// be used as inputs for a new funding transaction.
	CoinLocker OutpointLocker

	// Signer allows the WalletAssembler to sign inputs on any potential
	// funding transactions.
	Signer input.Signer

	// DustLimit is the current dust limit. We'll use this to ensure that
	// we don't make dust outputs on the funding transaction.
	DustLimit btcutil.Amount
}

// WalletAssembler is an instance of the Assembler interface that is backed by
// a full wallet. This variant of the Assembler interface will produce the
// entirety of the funding transaction within the wallet. This implements the
// typical funding flow that is initiated either on the p2p level or using the
// CLi.
type WalletAssembler struct {
	cfg WalletConfig
}

// NewWalletAssembler creates a new instance of the WalletAssembler from a
// fully populated wallet config.
func NewWalletAssembler(cfg WalletConfig) *WalletAssembler {
	return &WalletAssembler{
		cfg: cfg,
	}
}

// ProvisionChannel is the main entry point to begin a funding workflow given a
// fully populated request. The internal WalletAssembler will perform coin
// selection in a goroutine safe manner, returning an Intent that will allow
// the caller to finalize the funding process.
//
// NOTE: To cancel the funding flow the Cancel() method on the returned Intent,
// MUST be called.
//
// NOTE: This is a part of the chanfunding.Assembler interface.
func (w *WalletAssembler) ProvisionChannel(r *Request) (Intent, error) {
	var intent Intent

	// We hold the coin select mutex while querying for outputs, and
	// performing coin selection in order to avoid inadvertent double
	// spends across funding transactions.
	err := w.cfg.CoinSelectLocker.WithCoinSelectLock(func() error {
		log.Infof("Performing funding tx coin selection using %v "+
			"sat/kw as fee rate", int64(r.FeeRate))

		// Find all unlocked unspent witness outputs that satisfy the
		// minimum number of confirmations required.
		coins, err := w.cfg.CoinSource.ListCoins(
			r.MinConfs, math.MaxInt32,
		)
		if err != nil {
			return err
		}

		var (
			selectedCoins        []Coin
			localContributionAmt btcutil.Amount
			changeAmt            btcutil.Amount
		)

		// Perform coin selection over our available, unlocked unspent
		// outputs in order to find enough coins to meet the funding
		// amount requirements.
		switch {
		// If there's no funding amount at all (receiving an inbound
		// single funder request), then we don't need to perform any
		// coin selection at all.
		case r.LocalAmt == 0:
			break

		// In case this request uses funding up to some maximum amount,
		// we will call the specialized method for that.
		case r.FundUpToMaxAmt != 0:
			dustLimit := w.cfg.DustLimit
			selectedCoins, localContributionAmt, changeAmt, err = CoinSelectUpToAmount(
				r.FeeRate, r.FundUpToMaxAmt, dustLimit, coins,
			)
			if err != nil {
				return err
			}

			// In case the selected amount is lower than the amount defined
			// as the minimum with LocalAmt, we must return an error.
			if localContributionAmt < r.LocalAmt {
				return fmt.Errorf("available funds(%v) below the "+
					"minimum amount(%v)", localContributionAmt, r.LocalAmt)
			}

		// In case this request want the fees subtracted from the local
		// amount, we'll call the specialized method for that. This
		// ensures that we won't deduct more that the specified balance
		// from our wallet.
		case r.SubtractFees:
			dustLimit := w.cfg.DustLimit
			selectedCoins, localContributionAmt, changeAmt, err = CoinSelectSubtractFees(
				r.FeeRate, r.LocalAmt, dustLimit, coins,
			)
			if err != nil {
				return err
			}

		// Otherwise do a normal coin selection where we target a given
		// funding amount.
		default:
			dustLimit := w.cfg.DustLimit
			localContributionAmt = r.LocalAmt
			selectedCoins, changeAmt, err = CoinSelect(
				r.FeeRate, r.LocalAmt, dustLimit, coins,
			)
			if err != nil {
				return err
			}
		}

		// Sanity check: The addition of the outputs should not lead to the
		// creation of dust.
		if changeAmt != 0 && changeAmt <= w.cfg.DustLimit {
			return fmt.Errorf("change amount(%v) after coin "+
				"select is below dust limit(%v)", changeAmt,
				w.cfg.DustLimit)
		}

		// Record any change output(s) generated as a result of the
		// coin selection.
		var changeOutput *wire.TxOut
		if changeAmt != 0 {
			changeAddr, err := r.ChangeAddr()
			if err != nil {
				return err
			}
			changeScript, err := txscript.PayToAddrScript(changeAddr)
			if err != nil {
				return err
			}

			changeOutput = &wire.TxOut{
				Value:    int64(changeAmt),
				PkScript: changeScript,
			}
		}

		// Lock the selected coins. These coins are now "reserved",
		// this prevents concurrent funding requests from referring to
		// and this double-spending the same set of coins.
		for _, coin := range selectedCoins {
			outpoint := coin.OutPoint

			w.cfg.CoinLocker.LockOutpoint(outpoint)
		}

		newIntent := &FullIntent{
			ShimIntent: ShimIntent{
				localFundingAmt:  localContributionAmt,
				remoteFundingAmt: r.RemoteAmt,
			},
			InputCoins: selectedCoins,
			coinLocker: w.cfg.CoinLocker,
			coinSource: w.cfg.CoinSource,
			signer:     w.cfg.Signer,
		}

		if changeOutput != nil {
			newIntent.ChangeOutputs = []*wire.TxOut{changeOutput}
		}

		intent = newIntent

		return nil
	})
	if err != nil {
		return nil, err
	}

	return intent, nil
}

// FundingTxAvailable is an empty method that an assembler can implement to
// signal to callers that its able to provide the funding transaction for the
// channel via the intent it returns.
//
// NOTE: This method is a part of the FundingTxAssembler interface.
func (w *WalletAssembler) FundingTxAvailable() {}

// A compile-time assertion to ensure the WalletAssembler meets the
// FundingTxAssembler interface.
var _ FundingTxAssembler = (*WalletAssembler)(nil)
