package txscript

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"golang.org/x/crypto/ripemd160"
)

const (
	// minPubKeyHashSigScriptLen is the minimum length of a signature script
	// that spends a P2PKH output. The length is composed of the following:
	//   Signature length (1 byte)
	//   Signature (min 8 bytes)
	//   Signature hash type (1 byte)
	//   Public key length (1 byte)
	//   Public key (33 byte)
	minPubKeyHashSigScriptLen = 1 + btcec.MinSigLen + 1 + 1 + 33

	// maxPubKeyHashSigScriptLen is the maximum length of a signature script
	// that spends a P2PKH output. The length is composed of the following:
	//   Signature length (1 byte)
	//   Signature (max 72 bytes)
	//   Signature hash type (1 byte)
	//   Public key length (1 byte)
	//   Public key (33 byte)
	maxPubKeyHashSigScriptLen = 1 + 72 + 1 + 1 + 33

	// compressedPubKeyLen is the length in bytes of a compressed public
	// key.
	compressedPubKeyLen = 33

	// pubKeyHashLen is the length of a P2PKH script.
	pubKeyHashLen = 25

	// witnessV0PubKeyHashLen is the length of a P2WPKH script.
	witnessV0PubKeyHashLen = 22

	// scriptHashLen is the length of a P2SH script.
	scriptHashLen = 23

	// witnessV0ScriptHashLen is the length of a P2WSH script.
	witnessV0ScriptHashLen = 34

	// maxLen is the maximum script length supported by ParsePkScript.
	maxLen = witnessV0ScriptHashLen
)

var (
	// ErrUnsupportedScriptType is an error returned when we attempt to
	// parse/re-compute an output script into a PkScript struct.
	ErrUnsupportedScriptType = errors.New("unsupported script type")
)

// PkScript is a wrapper struct around a byte array, allowing it to be used
// as a map index.
type PkScript struct {
	// class is the type of the script encoded within the byte array. This
	// is used to determine the correct length of the script within the byte
	// array.
	class ScriptClass

	// script is the script contained within a byte array. If the script is
	// smaller than the length of the byte array, it will be padded with 0s
	// at the end.
	script [maxLen]byte
}

// ParsePkScript parses an output script into the PkScript struct.
// ErrUnsupportedScriptType is returned when attempting to parse an unsupported
// script type.
func ParsePkScript(pkScript []byte) (PkScript, error) {
	var outputScript PkScript
	scriptClass, _, _, err := ExtractPkScriptAddrs(
		pkScript, &chaincfg.MainNetParams,
	)
	if err != nil {
		return outputScript, fmt.Errorf("unable to parse script type: "+
			"%v", err)
	}

	if !isSupportedScriptType(scriptClass) {
		return outputScript, ErrUnsupportedScriptType
	}

	outputScript.class = scriptClass
	copy(outputScript.script[:], pkScript)

	return outputScript, nil
}

// isSupportedScriptType determines whether the script type is supported by the
// PkScript struct.
func isSupportedScriptType(class ScriptClass) bool {
	switch class {
	case PubKeyHashTy, WitnessV0PubKeyHashTy, ScriptHashTy,
		WitnessV0ScriptHashTy:
		return true
	default:
		return false
	}
}

// Class returns the script type.
func (s PkScript) Class() ScriptClass {
	return s.class
}

// Script returns the script as a byte slice without any padding.
func (s PkScript) Script() []byte {
	var script []byte

	switch s.class {
	case PubKeyHashTy:
		script = make([]byte, pubKeyHashLen)
		copy(script, s.script[:pubKeyHashLen])

	case WitnessV0PubKeyHashTy:
		script = make([]byte, witnessV0PubKeyHashLen)
		copy(script, s.script[:witnessV0PubKeyHashLen])

	case ScriptHashTy:
		script = make([]byte, scriptHashLen)
		copy(script, s.script[:scriptHashLen])

	case WitnessV0ScriptHashTy:
		script = make([]byte, witnessV0ScriptHashLen)
		copy(script, s.script[:witnessV0ScriptHashLen])

	default:
		// Unsupported script type.
		return nil
	}

	return script
}

// Address encodes the script into an address for the given chain.
func (s PkScript) Address(chainParams *chaincfg.Params) (btcutil.Address, error) {
	_, addrs, _, err := ExtractPkScriptAddrs(s.Script(), chainParams)
	if err != nil {
		return nil, fmt.Errorf("unable to parse address: %v", err)
	}

	return addrs[0], nil
}

// String returns a hex-encoded string representation of the script.
func (s PkScript) String() string {
	str, _ := DisasmString(s.Script())
	return str
}

// ComputePkScript computes the script of an output by looking at the spending
// input's signature script or witness.
//
// NOTE: Only P2PKH, P2SH, P2WSH, and P2WPKH redeem scripts are supported.
func ComputePkScript(sigScript []byte, witness wire.TxWitness) (PkScript, error) {
	switch {
	case len(sigScript) > 0:
		return computeNonWitnessPkScript(sigScript)
	case len(witness) > 0:
		return computeWitnessPkScript(witness)
	default:
		return PkScript{}, ErrUnsupportedScriptType
	}
}

// computeNonWitnessPkScript computes the script of an output by looking at the
// spending input's signature script.
func computeNonWitnessPkScript(sigScript []byte) (PkScript, error) {
	switch {
	// Since we only support P2PKH and P2SH scripts as the only non-witness
	// script types, we should expect to see a push only script.
	case !IsPushOnlyScript(sigScript):
		return PkScript{}, ErrUnsupportedScriptType

	// If a signature script is provided with a length long enough to
	// represent a P2PKH script, then we'll attempt to parse the compressed
	// public key from it.
	case len(sigScript) >= minPubKeyHashSigScriptLen &&
		len(sigScript) <= maxPubKeyHashSigScriptLen:

		// The public key should be found as the last part of the
		// signature script. We'll attempt to parse it to ensure this is
		// a P2PKH redeem script.
		pubKey := sigScript[len(sigScript)-compressedPubKeyLen:]
		if btcec.IsCompressedPubKey(pubKey) {
			pubKeyHash := hash160(pubKey)
			script, err := payToPubKeyHashScript(pubKeyHash)
			if err != nil {
				return PkScript{}, err
			}

			pkScript := PkScript{class: PubKeyHashTy}
			copy(pkScript.script[:], script)
			return pkScript, nil
		}

		fallthrough

	// If we failed to parse a compressed public key from the script in the
	// case above, or if the script length is not that of a P2PKH one, we
	// can assume it's a P2SH signature script.
	default:
		// The redeem script will always be the last data push of the
		// signature script, so we'll parse the script into opcodes to
		// obtain it.
		parsedOpcodes, err := parseScript(sigScript)
		if err != nil {
			return PkScript{}, err
		}
		redeemScript := parsedOpcodes[len(parsedOpcodes)-1].data

		scriptHash := hash160(redeemScript)
		script, err := payToScriptHashScript(scriptHash)
		if err != nil {
			return PkScript{}, err
		}

		pkScript := PkScript{class: ScriptHashTy}
		copy(pkScript.script[:], script)
		return pkScript, nil
	}
}

// computeWitnessPkScript computes the script of an output by looking at the
// spending input's witness.
func computeWitnessPkScript(witness wire.TxWitness) (PkScript, error) {
	// We'll use the last item of the witness stack to determine the proper
	// witness type.
	lastWitnessItem := witness[len(witness)-1]

	var pkScript PkScript
	switch {
	// If the witness stack has a size of 2 and its last item is a
	// compressed public key, then this is a P2WPKH witness.
	case len(witness) == 2 && len(lastWitnessItem) == compressedPubKeyLen:
		pubKeyHash := hash160(lastWitnessItem)
		script, err := payToWitnessPubKeyHashScript(pubKeyHash)
		if err != nil {
			return pkScript, err
		}

		pkScript.class = WitnessV0PubKeyHashTy
		copy(pkScript.script[:], script)

	// For any other witnesses, we'll assume it's a P2WSH witness.
	default:
		scriptHash := sha256.Sum256(lastWitnessItem)
		script, err := payToWitnessScriptHashScript(scriptHash[:])
		if err != nil {
			return pkScript, err
		}

		pkScript.class = WitnessV0ScriptHashTy
		copy(pkScript.script[:], script)
	}

	return pkScript, nil
}

// hash160 returns the RIPEMD160 hash of the SHA-256 HASH of the given data.
func hash160(data []byte) []byte {
	h := sha256.Sum256(data)
	return ripemd160h(h[:])
}

// ripemd160h returns the RIPEMD160 hash of the given data.
func ripemd160h(data []byte) []byte {
	h := ripemd160.New()
	h.Write(data)
	return h.Sum(nil)
}
