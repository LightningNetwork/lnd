package chanfunding

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// CoinSource is an interface that allows a caller to access a source of UTXOs
// to use when attempting to fund a new channel.
type CoinSource interface {
	// ListCoins returns all UTXOs from the source that have between
	// minConfs and maxConfs number of confirmations.
	ListCoins(minConfs, maxConfs int32) ([]Coin, error)

	// CoinFromOutPoint attempts to locate details pertaining to a coin
	// based on its outpoint. If the coin isn't under the control of the
	// backing CoinSource, then an error should be returned.
	CoinFromOutPoint(wire.OutPoint) (*Coin, error)
}

// CoinSelectionLocker is an interface that allows the caller to perform an
// operation, which is synchronized with all coin selection attempts. This can
// be used when an operation requires that all coin selection operations cease
// forward progress. Think of this as an exclusive lock on coin selection
// operations.
type CoinSelectionLocker interface {
	// WithCoinSelectLock will execute the passed function closure in a
	// synchronized manner preventing any coin selection operations from
	// proceeding while the closure is executing. This can be seen as the
	// ability to execute a function closure under an exclusive coin
	// selection lock.
	WithCoinSelectLock(func() error) error
}

// OutpointLocker allows a caller to lock/unlock an outpoint. When locked, the
// outpoints shouldn't be used for any sort of channel funding of coin
// selection. Locked outpoints are not expected to be persisted between
// restarts.
type OutpointLocker interface {
	// LockOutpoint locks a target outpoint, rendering it unusable for coin
	// selection.
	LockOutpoint(o wire.OutPoint)

	// UnlockOutpoint unlocks a target outpoint, allowing it to be used for
	// coin selection once again.
	UnlockOutpoint(o wire.OutPoint)
}

// Request is a new request for funding a channel. The items in the struct
// governs how the final channel point will be provisioned by the target
// Assembler.
type Request struct {
	// LocalAmt is the amount of coins we're placing into the funding
	// output.
	LocalAmt btcutil.Amount

	// RemoteAmt is the amount of coins the remote party is contributing to
	// the funding output.
	RemoteAmt btcutil.Amount

	// FundUpToMaxAmt should be set to a non-zero amount if the channel
	// funding should try to add as many funds to LocalAmt as possible
	// until at most that amount is reached.
	FundUpToMaxAmt btcutil.Amount

	// MinConfs controls how many confirmations a coin need to be eligible
	// to be used as an input to the funding transaction. If this value is
	// set to zero, then zero conf outputs may be spent.
	MinConfs int32

	// SubtractFees should be set if we intend to spend exactly LocalAmt
	// when opening the channel, subtracting the fees from the funding
	// output. This can be used for instance to use all our remaining funds
	// to open the channel, since it will take fees into
	// account.
	SubtractFees bool

	// FeeRate is the fee rate in sat/kw that the funding transaction
	// should carry.
	FeeRate chainfee.SatPerKWeight

	// ChangeAddr is a closure that will provide the Assembler with a
	// change address for the funding transaction if needed.
	ChangeAddr func() (btcutil.Address, error)
}

// Intent is returned by an Assembler and represents the base functionality the
// caller needs to proceed with channel funding on a higher level. If the
// Cancel method is called, then all resources assembled to fund the channel
// will be released back to the eligible pool.
type Intent interface {
	// FundingOutput returns the witness script, and the output that
	// creates the funding output.
	FundingOutput() ([]byte, *wire.TxOut, error)

	// ChanPoint returns the final outpoint that will create the funding
	// output described above.
	ChanPoint() (*wire.OutPoint, error)

	// RemoteFundingAmt is the amount the remote party put into the
	// channel.
	RemoteFundingAmt() btcutil.Amount

	// LocalFundingAmt is the amount we put into the channel. This may
	// differ from the local amount requested, as depending on coin
	// selection, we may bleed from of that LocalAmt into fees to minimize
	// change.
	LocalFundingAmt() btcutil.Amount

	// Inputs returns all inputs to the final funding transaction that we
	// know about. Note that there might be more, but we are not (yet)
	// aware of.
	Inputs() []wire.OutPoint

	// Outputs returns all outputs of the final funding transaction that we
	// know about. Note that there might be more, but we are not (yet)
	// aware of.
	Outputs() []*wire.TxOut

	// Cancel allows the caller to cancel a funding Intent at any time.
	// This will return any resources such as coins back to the eligible
	// pool to be used in order channel fundings.
	Cancel()
}

// Assembler is an abstract object that is capable of assembling everything
// needed to create a new funding output. As an example, this assembler may be
// our core backing wallet, an interactive PSBT based assembler, an assembler
// than can aggregate multiple intents into a single funding transaction, or an
// external protocol that creates a funding output out-of-band such as channel
// factories.
type Assembler interface {
	// ProvisionChannel returns a populated Intent that can be used to
	// further the channel funding workflow. Depending on the
	// implementation of Assembler, additional state machine (Intent)
	// actions may be required before the FundingOutput and ChanPoint are
	// made available to the caller.
	ProvisionChannel(*Request) (Intent, error)
}

// FundingTxAssembler is a super-set of the regular Assembler interface that's
// also able to provide a fully populated funding transaction via the intents
// that it produces.
type FundingTxAssembler interface {
	Assembler

	// FundingTxAvailable is an empty method that an assembler can
	// implement to signal to callers that its able to provide the funding
	// transaction for the channel via the intent it returns.
	FundingTxAvailable()
}

// ConditionalPublishAssembler is an assembler that can dynamically define if
// the funding transaction should be published after channel negotiations or
// not. Not publishing the transaction is only useful if the particular channel
// the assembler is in charge of is part of a batch of channels. In that case
// it is only safe to wait for all channel negotiations of the batch to complete
// before publishing the batch transaction.
type ConditionalPublishAssembler interface {
	Assembler

	// ShouldPublishFundingTx is a method of the assembler that signals if
	// the funding transaction should be published after the channel
	// negotiations are completed with the remote peer.
	ShouldPublishFundingTx() bool
}
