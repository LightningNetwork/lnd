package chanfunding

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	localPrivkey                  = []byte{1, 2, 3, 4, 5, 6}
	remotePrivkey                 = []byte{6, 5, 4, 3, 2, 1}
	chanCapacity   btcutil.Amount = 644000
	params                        = chaincfg.RegressionNetParams
	defaultTimeout                = 50 * time.Millisecond
)

// TestPsbtIntent tests the basic happy path of the PSBT assembler and intent.
func TestPsbtIntent(t *testing.T) {
	t.Parallel()

	// Create a simple assembler and ask it to provision a channel to get
	// the funding intent.
	a := NewPsbtAssembler(chanCapacity, nil, &params, true)
	intent, err := a.ProvisionChannel(&Request{LocalAmt: chanCapacity})
	if err != nil {
		t.Fatalf("error provisioning channel: %v", err)
	}
	psbtIntent, ok := intent.(*PsbtIntent)
	if !ok {
		t.Fatalf("intent was not a PsbtIntent")
	}
	if psbtIntent.State != PsbtShimRegistered {
		t.Fatalf("unexpected state. got %d wanted %d", psbtIntent.State,
			PsbtShimRegistered)
	}

	// The first step with the intent is that the funding manager starts
	// negotiating with the remote peer and they accept. By accepting, they
	// send over their multisig key that's going to be used for the funding
	// output. With that known, we can start crafting a PSBT.
	_, localPubkey := btcec.PrivKeyFromBytes(btcec.S256(), localPrivkey)
	_, remotePubkey := btcec.PrivKeyFromBytes(btcec.S256(), remotePrivkey)
	psbtIntent.BindKeys(
		&keychain.KeyDescriptor{PubKey: localPubkey}, remotePubkey,
	)
	if psbtIntent.State != PsbtOutputKnown {
		t.Fatalf("unexpected state. got %d wanted %d", psbtIntent.State,
			PsbtOutputKnown)
	}

	// Make sure the output script address is correct.
	script, _, err := input.GenFundingPkScript(
		localPubkey.SerializeCompressed(),
		remotePubkey.SerializeCompressed(), int64(chanCapacity),
	)
	if err != nil {
		t.Fatalf("error calculating script: %v", err)
	}
	witnessScriptHash := sha256.Sum256(script)
	addr, err := btcutil.NewAddressWitnessScriptHash(
		witnessScriptHash[:], &params,
	)
	if err != nil {
		t.Fatalf("unable to encode address: %v", err)
	}
	fundingAddr, amt, pendingPsbt, err := psbtIntent.FundingParams()
	if err != nil {
		t.Fatalf("unable to get funding params: %v", err)
	}
	if addr.EncodeAddress() != fundingAddr.EncodeAddress() {
		t.Fatalf("unexpected address. got %s wanted %s", fundingAddr,
			addr)
	}
	if amt != int64(chanCapacity) {
		t.Fatalf("unexpected amount. got %d wanted %d", amt,
			chanCapacity)
	}

	// Parse and check the returned PSBT packet.
	if pendingPsbt == nil {
		t.Fatalf("expected pending PSBT to be returned")
	}
	if len(pendingPsbt.UnsignedTx.TxOut) != 1 {
		t.Fatalf("unexpected number of outputs. got %d wanted %d",
			len(pendingPsbt.UnsignedTx.TxOut), 1)
	}
	txOut := pendingPsbt.UnsignedTx.TxOut[0]
	if !bytes.Equal(txOut.PkScript[2:], witnessScriptHash[:]) {
		t.Fatalf("unexpected PK script in output. got %x wanted %x",
			txOut.PkScript[2:], witnessScriptHash)
	}
	if txOut.Value != int64(chanCapacity) {
		t.Fatalf("unexpected value in output. got %d wanted %d",
			txOut.Value, chanCapacity)
	}

	// Add an input to the pending TX to simulate it being funded.
	pendingPsbt.UnsignedTx.TxIn = []*wire.TxIn{
		{PreviousOutPoint: wire.OutPoint{Index: 0}},
	}
	pendingPsbt.Inputs = []psbt.PInput{
		{WitnessUtxo: &wire.TxOut{Value: int64(chanCapacity + 1)}},
	}

	// Verify the dummy PSBT with the intent.
	err = psbtIntent.Verify(pendingPsbt, false)
	if err != nil {
		t.Fatalf("error verifying pending PSBT: %v", err)
	}
	if psbtIntent.State != PsbtVerified {
		t.Fatalf("unexpected state. got %d wanted %d", psbtIntent.State,
			PsbtVerified)
	}

	// Add some fake witness data to the transaction so it thinks it's
	// signed.
	pendingPsbt.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    int64(chanCapacity) * 2,
		PkScript: []byte{99, 99, 99},
	}
	pendingPsbt.Inputs[0].FinalScriptSig = []byte{88, 88, 88}
	pendingPsbt.Inputs[0].FinalScriptWitness = []byte{2, 0, 0}

	// If we call Finalize, the intent will signal to the funding manager
	// that it can continue with the funding flow. We want to make sure
	// the signal arrives.
	var wg sync.WaitGroup
	errChan := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case err := <-psbtIntent.PsbtReady:
			errChan <- err

		case <-time.After(defaultTimeout):
			errChan <- fmt.Errorf("timed out")
		}
	}()
	err = psbtIntent.Finalize(pendingPsbt)
	if err != nil {
		t.Fatalf("error finalizing pending PSBT: %v", err)
	}
	wg.Wait()

	// We should have a nil error in our channel now.
	err = <-errChan
	if err != nil {
		t.Fatalf("unexpected error after finalize: %v", err)
	}
	if psbtIntent.State != PsbtFinalized {
		t.Fatalf("unexpected state. got %d wanted %d", psbtIntent.State,
			PsbtFinalized)
	}

	// Make sure the funding transaction can be compiled.
	_, err = psbtIntent.CompileFundingTx()
	if err != nil {
		t.Fatalf("error compiling funding TX from PSBT: %v", err)
	}
	if psbtIntent.State != PsbtFundingTxCompiled {
		t.Fatalf("unexpected state. got %d wanted %d", psbtIntent.State,
			PsbtFundingTxCompiled)
	}
}

// TestPsbtIntentBasePsbt tests that a channel funding output can be appended to
// a given base PSBT in the funding flow.
func TestPsbtIntentBasePsbt(t *testing.T) {
	t.Parallel()

	// First create a dummy PSBT with a single output.
	pendingPsbt, err := psbt.New(
		[]*wire.OutPoint{{}}, []*wire.TxOut{
			{Value: 999, PkScript: []byte{99, 88, 77}},
		}, 2, 0, []uint32{0},
	)
	if err != nil {
		t.Fatalf("unable to create dummy PSBT")
	}

	// Generate the funding multisig keys and the address so we can compare
	// it to the output of the intent.
	_, localPubkey := btcec.PrivKeyFromBytes(btcec.S256(), localPrivkey)
	_, remotePubkey := btcec.PrivKeyFromBytes(btcec.S256(), remotePrivkey)
	// Make sure the output script address is correct.
	script, _, err := input.GenFundingPkScript(
		localPubkey.SerializeCompressed(),
		remotePubkey.SerializeCompressed(), int64(chanCapacity),
	)
	if err != nil {
		t.Fatalf("error calculating script: %v", err)
	}
	witnessScriptHash := sha256.Sum256(script)
	addr, err := btcutil.NewAddressWitnessScriptHash(
		witnessScriptHash[:], &params,
	)
	if err != nil {
		t.Fatalf("unable to encode address: %v", err)
	}

	// Now as the next step, create a new assembler/intent pair with a base
	// PSBT to see that we can add an additional output to it.
	a := NewPsbtAssembler(chanCapacity, pendingPsbt, &params, true)
	intent, err := a.ProvisionChannel(&Request{LocalAmt: chanCapacity})
	if err != nil {
		t.Fatalf("error provisioning channel: %v", err)
	}
	psbtIntent, ok := intent.(*PsbtIntent)
	if !ok {
		t.Fatalf("intent was not a PsbtIntent")
	}
	psbtIntent.BindKeys(
		&keychain.KeyDescriptor{PubKey: localPubkey}, remotePubkey,
	)
	newAddr, amt, twoOutPsbt, err := psbtIntent.FundingParams()
	if err != nil {
		t.Fatalf("unable to get funding params: %v", err)
	}
	if addr.EncodeAddress() != newAddr.EncodeAddress() {
		t.Fatalf("unexpected address. got %s wanted %s", newAddr,
			addr)
	}
	if amt != int64(chanCapacity) {
		t.Fatalf("unexpected amount. got %d wanted %d", amt,
			chanCapacity)
	}
	if len(twoOutPsbt.UnsignedTx.TxOut) != 2 {
		t.Fatalf("unexpected number of outputs. got %d wanted %d",
			len(twoOutPsbt.UnsignedTx.TxOut), 2)
	}
	if len(twoOutPsbt.UnsignedTx.TxIn) != 1 {
		t.Fatalf("unexpected number of inputs. got %d wanted %d",
			len(twoOutPsbt.UnsignedTx.TxIn), 1)
	}
	txOld := pendingPsbt.UnsignedTx
	txNew := twoOutPsbt.UnsignedTx
	prevoutEqual := reflect.DeepEqual(
		txOld.TxIn[0].PreviousOutPoint, txNew.TxIn[0].PreviousOutPoint,
	)
	if !prevoutEqual {
		t.Fatalf("inputs changed. got %s wanted %s",
			spew.Sdump(txOld.TxIn[0].PreviousOutPoint),
			spew.Sdump(txNew.TxIn[0].PreviousOutPoint))
	}
	if !reflect.DeepEqual(txOld.TxOut[0], txNew.TxOut[0]) {
		t.Fatalf("existing output changed. got %v wanted %v",
			txOld.TxOut[0], txNew.TxOut[0])
	}
}

// TestPsbtVerify tests the PSBT verification process more deeply than just
// the happy path.
func TestPsbtVerify(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		expectedErr   string
		shouldPublish bool
		doVerify      func(int64, *psbt.Packet, *PsbtIntent) error
	}{
		{
			name:          "nil packet",
			expectedErr:   "PSBT is nil",
			shouldPublish: true,
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				return i.Verify(nil, false)
			},
		},
		{
			name:          "wrong state",
			shouldPublish: true,
			expectedErr: "invalid state. got user_canceled " +
				"expected output_known",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				i.State = PsbtInitiatorCanceled
				return i.Verify(p, false)
			},
		},
		{
			name:          "output not found, value wrong",
			shouldPublish: true,
			expectedErr:   "funding output not found in PSBT",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				p.UnsignedTx.TxOut[0].Value = 123
				return i.Verify(p, false)
			},
		},
		{
			name:          "output not found, pk script wrong",
			shouldPublish: true,
			expectedErr:   "funding output not found in PSBT",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				p.UnsignedTx.TxOut[0].PkScript = []byte{1, 2, 3}
				return i.Verify(p, false)
			},
		},
		{
			name:          "no inputs",
			shouldPublish: true,
			expectedErr:   "PSBT has no inputs",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				return i.Verify(p, false)
			},
		},
		{
			name:          "input(s) too small",
			shouldPublish: true,
			expectedErr: "input amount sum must be larger than " +
				"output amount sum",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				p.UnsignedTx.TxIn = []*wire.TxIn{{}}
				p.Inputs = []psbt.PInput{{
					WitnessUtxo: &wire.TxOut{
						Value: int64(chanCapacity),
					},
				}}
				return i.Verify(p, false)
			},
		},
		{
			name:          "missing witness-utxo field",
			shouldPublish: true,
			expectedErr: "cannot use TX for channel funding, not " +
				"all inputs are SegWit spends, risk of " +
				"malleability: input 1 is non-SegWit spend " +
				"or missing redeem script",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				txOut := &wire.TxOut{
					Value: int64(chanCapacity/2) + 1,
				}
				p.UnsignedTx.TxIn = []*wire.TxIn{
					{},
					{
						PreviousOutPoint: wire.OutPoint{
							Index: 0,
						},
					},
				}
				p.Inputs = []psbt.PInput{
					{
						WitnessUtxo: txOut,
					},
					{
						NonWitnessUtxo: &wire.MsgTx{
							TxOut: []*wire.TxOut{
								txOut,
							},
						},
					},
				}
				return i.Verify(p, false)
			},
		},
		{
			name:          "skip verify",
			shouldPublish: false,
			expectedErr:   "",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				txOut := &wire.TxOut{
					Value: int64(chanCapacity/2) + 1,
				}
				p.UnsignedTx.TxIn = []*wire.TxIn{
					{},
					{
						PreviousOutPoint: wire.OutPoint{
							Index: 0,
						},
					},
				}
				p.Inputs = []psbt.PInput{
					{
						WitnessUtxo: txOut,
					},
					{
						WitnessUtxo: txOut,
					},
				}

				if err := i.Verify(p, true); err != nil {
					return err
				}

				if i.FinalTX != p.UnsignedTx {
					return fmt.Errorf("expected final TX " +
						"to be set")
				}
				if i.State != PsbtFinalized {
					return fmt.Errorf("expected state to " +
						"be finalized")
				}

				select {
				case <-i.PsbtReady:

				case <-time.After(50 * time.Millisecond):
					return fmt.Errorf("expected PSBT " +
						"ready to be signaled")
				}

				return nil
			},
		},
		{
			name:          "input correct",
			shouldPublish: true,
			expectedErr:   "",
			doVerify: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				txOut := &wire.TxOut{
					Value: int64(chanCapacity/2) + 1,
				}
				p.UnsignedTx.TxIn = []*wire.TxIn{
					{},
					{
						PreviousOutPoint: wire.OutPoint{
							Index: 0,
						},
					},
				}
				p.Inputs = []psbt.PInput{
					{
						WitnessUtxo: txOut,
					},
					{
						WitnessUtxo: txOut,
					}}
				return i.Verify(p, false)
			},
		},
	}

	// Create a simple assembler and ask it to provision a channel to get
	// the funding intent.
	a := NewPsbtAssembler(chanCapacity, nil, &params, true)
	intent, err := a.ProvisionChannel(&Request{LocalAmt: chanCapacity})
	if err != nil {
		t.Fatalf("error provisioning channel: %v", err)
	}
	psbtIntent := intent.(*PsbtIntent)

	// Bind our test keys to get the funding parameters.
	_, localPubkey := btcec.PrivKeyFromBytes(btcec.S256(), localPrivkey)
	_, remotePubkey := btcec.PrivKeyFromBytes(btcec.S256(), remotePrivkey)
	psbtIntent.BindKeys(
		&keychain.KeyDescriptor{PubKey: localPubkey}, remotePubkey,
	)

	// Loop through all our test cases.
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Reset the state from a previous test and create a new
			// pending PSBT that we can manipulate.
			psbtIntent.shouldPublish = tc.shouldPublish
			psbtIntent.State = PsbtOutputKnown
			_, amt, pendingPsbt, err := psbtIntent.FundingParams()
			if err != nil {
				t.Fatalf("unable to get funding params: %v", err)
			}

			err = tc.doVerify(amt, pendingPsbt, psbtIntent)
			if err != nil && tc.expectedErr == "" {
				t.Fatalf("unexpected error, got '%v' wanted "+
					"'%v'", err, tc.expectedErr)
			}
			if err != nil && err.Error() != tc.expectedErr {
				t.Fatalf("unexpected error, got '%v' wanted "+
					"'%v'", err, tc.expectedErr)
			}
		})
	}
}

// TestPsbtFinalize tests the PSBT finalization process more deeply than just
// the happy path.
func TestPsbtFinalize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		expectedErr string
		doFinalize  func(int64, *psbt.Packet, *PsbtIntent) error
	}{
		{
			name:        "nil packet",
			expectedErr: "PSBT is nil",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				return i.Finalize(nil)
			},
		},
		{
			name: "wrong state",
			expectedErr: "invalid state. got user_canceled " +
				"expected verified",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				i.State = PsbtInitiatorCanceled
				return i.Finalize(p)
			},
		},
		{
			name:        "not verified first",
			expectedErr: "PSBT was not verified first",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				i.State = PsbtVerified
				i.PendingPsbt = nil
				return i.Finalize(p)
			},
		},
		{
			name: "output value changed",
			expectedErr: "outputs differ from verified PSBT: " +
				"output 0 is different",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				p.UnsignedTx.TxOut[0].Value = 123
				return i.Finalize(p)
			},
		},
		{
			name: "output pk script changed",
			expectedErr: "outputs differ from verified PSBT: " +
				"output 0 is different",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				p.UnsignedTx.TxOut[0].PkScript = []byte{3, 2, 1}
				return i.Finalize(p)
			},
		},
		{
			name: "input previous outpoint index changed",
			expectedErr: "inputs differ from verified PSBT: " +
				"previous outpoint of input 0 is different",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 0
				return i.Finalize(p)
			},
		},
		{
			name: "input previous outpoint hash changed",
			expectedErr: "inputs differ from verified PSBT: " +
				"previous outpoint of input 0 is different",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				prevout := &p.UnsignedTx.TxIn[0].PreviousOutPoint
				prevout.Hash = chainhash.Hash{77, 88, 99, 11}
				return i.Finalize(p)
			},
		},
		{
			name:        "raw tx - nil transaction",
			expectedErr: "raw transaction is nil",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				return i.FinalizeRawTX(nil)
			},
		},
		{
			name: "raw tx - no witness data in raw tx",
			expectedErr: "inputs not signed: input 0 has no " +
				"signature data attached",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				rawTx, err := psbt.Extract(p)
				require.NoError(t, err)
				rawTx.TxIn[0].Witness = nil

				return i.FinalizeRawTX(rawTx)
			},
		},
		{
			name:        "happy path",
			expectedErr: "",
			doFinalize: func(amt int64, p *psbt.Packet,
				i *PsbtIntent) error {

				err := i.Finalize(p)
				require.NoError(t, err)

				require.Equal(t, PsbtFinalized, i.State)
				require.NotNil(t, i.FinalTX)

				return nil
			},
		},
	}

	// Create a simple assembler and ask it to provision a channel to get
	// the funding intent.
	a := NewPsbtAssembler(chanCapacity, nil, &params, true)
	intent, err := a.ProvisionChannel(&Request{LocalAmt: chanCapacity})
	if err != nil {
		t.Fatalf("error provisioning channel: %v", err)
	}
	psbtIntent := intent.(*PsbtIntent)

	// Bind our test keys to get the funding parameters.
	_, localPubkey := btcec.PrivKeyFromBytes(btcec.S256(), localPrivkey)
	_, remotePubkey := btcec.PrivKeyFromBytes(btcec.S256(), remotePrivkey)
	psbtIntent.BindKeys(
		&keychain.KeyDescriptor{PubKey: localPubkey}, remotePubkey,
	)

	// Loop through all our test cases.
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Reset the state from a previous test and create a new
			// pending PSBT that we can manipulate.
			psbtIntent.State = PsbtOutputKnown
			_, amt, pendingPsbt, err := psbtIntent.FundingParams()
			if err != nil {
				t.Fatalf("unable to get funding params: %v", err)
			}

			// We need to have a simulated transaction here that is
			// fully funded and signed.
			pendingPsbt.UnsignedTx.TxIn = []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Index: 1,
					Hash:  chainhash.Hash{1, 2, 3},
				},
			}}
			pendingPsbt.Inputs = []psbt.PInput{{
				WitnessUtxo: &wire.TxOut{
					Value:    int64(chanCapacity) + 1,
					PkScript: []byte{1, 2, 3},
				},
				FinalScriptWitness: []byte{0x01, 0x00},
			}}
			err = psbtIntent.Verify(pendingPsbt, false)
			if err != nil {
				t.Fatalf("error verifying PSBT: %v", err)
			}

			// Deep clone the PSBT so we don't modify the pending
			// one that was registered during Verify.
			pendingPsbt = clonePsbt(t, pendingPsbt)

			err = tc.doFinalize(amt, pendingPsbt, psbtIntent)
			if (err == nil && tc.expectedErr != "") ||
				(err != nil && err.Error() != tc.expectedErr) {

				t.Fatalf("unexpected error, got '%v' wanted "+
					"'%v'", err, tc.expectedErr)
			}
		})
	}
}

func TestVerifyAllInputsSegWit(t *testing.T) {
	testCases := []struct {
		name       string
		packet     string
		shouldFail bool
	}{{
		// Electrum takes the spec literally and does not include the
		// WitnessUtxo field in the PSBT.
		name: "Electrum np2wkh spend",
		packet: "cHNidP8BAFMCAAAAAcptbRo6Ez2R8WclfL4IAW+XEWIl8sNOHnw" +
			"eXfeU3dTwAQAAAAD9////Ab26GQAAAAAAF6kUf+wXsa7Z4ejieW" +
			"CSdKaGFwJmfbyHQyMeAAABAOACAAAAAAEBiS1A2NE4KW00wLQ1B" +
			"9R05jFMINs6egYFNL/5vLseeXMBAAAAAP7///8CNl1m1AEAAAAX" +
			"qRR/7Bexrtnh6OJ5YJJ0poYXAmZ9vIdDuxkAAAAAABepFMD8Ngx" +
			"k/Z7M5nJM2ltpszQZ4KGahwJHMEQCIAD4EIg16hjWEnEf2pilRF" +
			"UmWSk5UsMD7tTrR2FbFCurAiAiNvqpFQSr/FCCXknOV1HzeDVxe" +
			"B9gXeDZ62tmZv04/AEhAxGTJ9E/ImiOp2Ti3w/l/JFHa95RvXCB" +
			"UXFKifC/7f9dQyMeAAEEFgAU9pqV6WX0D/HEMfdw9yzU30MmkV4" +
			"iBgP4kZAAjhAKuixOLJczugvMmlS0xxPc2eD+4IJPHVOeRgxGbt" +
			"z0AAAAAAAAAAAAAA==",
	}, {
		name: "Electrum p2wkh spend",
		packet: "cHNidP8BAFMCAAAAASaMwGRzF7QWjHMX9WaGyUp7f3jznuNigHF" +
			"4l57hW0CgAAAAAAD9////AU+6GQAAAAAAF6kUf+wXsa7Z4ejieW" +
			"CSdKaGFwJmfbyHRSMeAAABANYCAAAAAAEBym1tGjoTPZHxZyV8v" +
			"ggBb5cRYiXyw04efB5d95Td1PABAAAAFxYAFPaalell9A/xxDH3" +
			"cPcs1N9DJpFe/f///wG+uhkAAAAAABYAFPaalell9A/xxDH3cPc" +
			"s1N9DJpFeAkcwRAIgRwfN0qpcM5DHR+YrgXFxhEi6F0qTf4dmQc" +
			"c1cu3TnnICIH5wc0kkMbHZ2mqZUFEITRUXExR7US3wohctQK1lf" +
			"q/oASED+JGQAI4QCrosTiyXM7oLzJpUtMcT3Nng/uCCTx1TnkZF" +
			"Ix4AIgYD+JGQAI4QCrosTiyXM7oLzJpUtMcT3Nng/uCCTx1TnkY" +
			"MRm7c9AAAAAAAAAAAAAA=",
	}, {
		name: "Bitcoind p2wkh spend",
		packet: "cHNidP8BAHICAAAAAeEw64k3k+YEk5EgNTytvkGlpiF6iMSsm0o" +
			"dCSm03dt7AAAAAAD+////AsSvp8oAAAAAFgAUzWRW/Ccwf/Cosy" +
			"dy0uYe5fa/Gb0A4fUFAAAAABepFMD8Ngxk/Z7M5nJM2ltpszQZ4" +
			"KGahwAAAAAAAQBxAgAAAAEtMrUZuqjRoaSEMU9sc7pS2zKlS8X3" +
			"/CUaENX1IHOICgEAAAAA/v///wLcm53QAAAAABYAFB1zJOaGOpk" +
			"NHVkIguiZ2Zh46dlmAGXNHQAAAAAWABTbjTIbrBMD+sWxE6mahK" +
			"tKGa//O1wAAAABAR/cm53QAAAAABYAFB1zJOaGOpkNHVkIguiZ2" +
			"Zh46dlmIgYDjVRSrQ7d5Rld1nDBTY/uA7Xp+SKUfaFpB0SQiM8O" +
			"3usQBp+HNQAAAIABAACADwAAgAAiAgJ9LOXb4MwHRoq31B9fQ2U" +
			"0K+Uj8BBJzy+MWc0OOOVuQxAGn4c1AAAAgAEAAIARAACAAAA=",
	}, {
		name: "Bitcoind p2pkh spend",
		packet: "cHNidP8BAHICAAAAAdp3QE/zv3Q7RhkAR0JyzBWLttUqRHJ" +
			"pAYmHLIqJzGXOAQAAAAD/////AoDw+gIAAAAAF6kUwPw2DGT9ns" +
			"zmckzaW2mzNBngoZqHUN/6AgAAAAAWABRLzlCRi8BozkTClLcIN" +
			"tnz8zYTtAAAAAAAAQB0AgAAAAHhMOuJN5PmBJORIDU8rb5BpaYh" +
			"eojErJtKHQkptN3bewAAAAAA/v///wKcr6fKAAAAABYAFOvePfh" +
			"lztKeDuQRgcGsHLS5BPhTAOH1BQAAAAAZdqkUt9QziR33rxhwcg" +
			"ipzwrDti93vTWIrAAAAAAiBgNKzHC4j7KaSKeH9RYx3Ur3dHL5w" +
			"YRjXpOAi3SI12WNFxAGn4c1AAAAgAAAAIAGAACAAAAiAgK8Fq3O" +
			"5nnASvhn9LJMIJOkGBMYQFd5DcbvOCbBCX/VBRAGn4c1AAAAgAE" +
			"AAIAVAACAAA==",
		shouldFail: true,
	}, {
		name: "Bitcoind p2sh multisig spend",
		packet: "cHNidP8BAHICAAAAAQvO6z5f4wghsQ2c5+Zcw2qdZ4FOYkyWBFe" +
			"U/jiIKcwdAAAAAAD/////AkTc+gIAAAAAFgAU2kWEYfMLfgwVQ0" +
			"2wJwFNsOmorBWA8PoCAAAAABepFMD8Ngxk/Z7M5nJM2ltpszQZ4" +
			"KGahwAAAAAAAQByAgAAAAHad0BP8790O0YZAEdCcswVi7bVKkRy" +
			"aQGJhyyKicxlzgAAAAAA/v///wIA4fUFAAAAABepFJdSg2Xdeo3" +
			"mYbTqbcZnZIH8oWbPh4TDscQAAAAAFgAUs5d3GhxrF5Zdi8fQHy" +
			"A05BSZr4t3AAAAAQRHUSEDdy41G190ATg/VnhXHE4dufESLLl53" +
			"RewoYB2ZYRJ/4AhA6MR4qMgHUkIyqhXW0jEECV8cHg/DCiuLgUk" +
			"YvQeub1zUq4AAAA=",
		shouldFail: true,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.packet)
			packet, err := psbt.NewFromRawBytes(r, true)
			require.NoError(t, err)

			txIns := packet.UnsignedTx.TxIn
			ins := packet.Inputs

			err = verifyAllInputsSegWit(txIns, ins)
			if tc.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// clonePsbt creates a clone of a PSBT packet by serializing then de-serializing
// it.
func clonePsbt(t *testing.T, p *psbt.Packet) *psbt.Packet {
	var buf bytes.Buffer
	err := p.Serialize(&buf)
	if err != nil {
		t.Fatalf("error serializing PSBT: %v", err)
	}
	newPacket, err := psbt.NewFromRawBytes(&buf, false)
	if err != nil {
		t.Fatalf("error unserializing PSBT: %v", err)
	}
	return newPacket
}
