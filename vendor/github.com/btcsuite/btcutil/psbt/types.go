package psbt

// GlobalType is the set of types that are used at the global scope level
// within the PSBT.
type GlobalType uint8

const (
	// UnsignedTxType is the global scope key that houses the unsigned
	// transaction of the PSBT. The value is a transaction in network
	// serialization. The scriptSigs and witnesses for each input must be
	// empty. The transaction must be in the old serialization format
	// (without witnesses). A PSBT must have a transaction, otherwise it is
	// invalid.
	UnsignedTxType GlobalType = 0

	// XpubType houses a global xpub for the entire PSBT packet.
	//
	// The key ({0x01}|{xpub}) is he 78 byte serialized extended public key
	// as defined by BIP 32.  Extended public keys are those that can be
	// used to derive public keys used in the inputs and outputs of this
	// transaction. It should be the public key at the highest hardened
	// derivation index so that
	// the unhardened child keys used in the transaction can be derived.
	//
	// The value is the master key fingerprint as defined by BIP 32
	// concatenated with the derivation path of the public key. The
	// derivation path is represented as 32-bit little endian unsigned
	// integer indexes concatenated with each other. The number of 32 bit
	// unsigned integer indexes must match the depth provided in the
	// extended public key.
	XpubType GlobalType = 1

	// VersionType houses the global version number of this PSBT. There is
	// no key (only contains the byte type), then the value if omitted, is
	// assumed to be zero.
	VersionType GlobalType = 0xFB

	// ProprietaryGlobalType is used to house any proper chary global-scope
	// keys within the PSBT.
	//
	// The key is ({0xFC}|<prefix>|{subtype}|{key data}) a variable length
	// identifier prefix, followed by a subtype, followed by the key data
	// itself.
	//
	// The value is any data as defined by the proprietary type user.
	ProprietaryGlobalType = 0xFC
)

// InputType is the set of types that are defined for each input included
// within the PSBT.
type InputType uint32

const (
	// NonWitnessUtxoType has no key ({0x00}) and houses the transaction in
	// network serialization format the current input spends from. This
	// should only be present for inputs which spend non-segwit outputs.
	// However, if it is unknown whether an input spends a segwit output,
	// this type should be used. The entire input transaction is needed in
	// order to be able to verify the values of the input (pre-segwit they
	// aren't in the signature digest).
	NonWitnessUtxoType InputType = 0

	// WitnessUtxoType has no key ({0x01}), and houses the entire
	// transaction output in network serialization which the current input
	// spends from.  This should only be present for inputs which spend
	// segwit outputs, including P2SH embedded ones (value || script).
	WitnessUtxoType InputType = 1

	// PartialSigType is used to include a partial signature with key
	// ({0x02}|{public key}).
	//
	// The value is the signature as would be pushed to the stack from a
	// scriptSig or witness..
	PartialSigType InputType = 2

	// SighashType is an empty key ({0x03}).
	//
	// The value contains the 32-bit unsigned integer specifying the
	// sighash type to be used for this input. Signatures for this input
	// must use the sighash type, finalizers must fail to finalize inputs
	// which have signatures that do not match the specified sighash type.
	// Signers who cannot produce signatures with the sighash type must not
	// provide a signature.
	SighashType InputType = 3

	// RedeemScriptInputType is an empty key ({0x40}).
	//
	// The value is the redeem script of the input if present.
	RedeemScriptInputType InputType = 4

	// WitnessScriptInputType is an empty key ({0x05}).
	//
	// The value is the witness script of this input, if it has one.
	WitnessScriptInputType InputType = 5

	// Bip32DerivationInputType is a type that carries the pubkey along
	// with the key ({0x06}|{public key}).
	//
	// The value is master key fingerprint as defined by BIP 32
	// concatenated with the derivation path of the public key. The
	// derivation path is represented as 32 bit unsigned integer indexes
	// concatenated with each other. Public keys are those that will be
	// needed to sign this input.
	Bip32DerivationInputType InputType = 6

	// FinalScriptSigType is an empty key ({0x07}).
	//
	// The value contains a fully constructed scriptSig with signatures and
	// any other scripts necessary for the input to pass validation.
	FinalScriptSigType InputType = 7

	// FinalScriptWitnessType is an empty key ({0x08}). The value is a
	// fully constructed scriptWitness with signatures and any other
	// scripts necessary for the input to pass validation.
	FinalScriptWitnessType InputType = 8

	// ProprietaryInputType is a custom type for use by devs.
	//
	// The key ({0xFC}|<prefix>|{subtype}|{key data}), is a Variable length
	// identifier prefix, followed by a subtype, followed by the key data
	// itself.
	//
	// The value is any value data as defined by the proprietary type user.
	ProprietaryInputType InputType = 0xFC
)

// OutputType is the set of types defined per output within the PSBT.
type OutputType uint32

const (
	// RedeemScriptOutputType is an empty key ({0x00}>
	//
	// The value is the redeemScript for this output if it has one.
	RedeemScriptOutputType OutputType = 0

	// WitnessScriptOutputType is an empty key ({0x01}).
	//
	// The value is the witness script of this input, if it has one.
	WitnessScriptOutputType OutputType = 1

	j // Bip32DerivationOutputType is used to communicate derivation information
	// needed to spend this output. The key is ({0x02}|{public key}).
	//
	// The value is master key fingerprint concatenated with the derivation
	// path of the public key. The derivation path is represented as 32-bit
	// little endian unsigned integer indexes concatenated with each other.
	// Public keys are those needed to spend this output.
	Bip32DerivationOutputType OutputType = 2
)
