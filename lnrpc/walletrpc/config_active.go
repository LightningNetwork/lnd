// +build walletrpc

package walletrpc

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/sweep"
)

const (
	// SubServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize as the name of our
	SubServerName = "WalletKitRPC"
)

// Config is the primary configuration struct for the WalletKit RPC server. It
// contains all the items required for the signer rpc server to carry out its
// duties. The fields with struct tags are meant to be parsed as normal
// configuration options, while if able to be populated, the latter fields MUST
// also be specified.
type Config struct {
	// WalletKitMacPath is the path for the signer macaroon. If unspecified
	// then we assume that the macaroon will be found under the network
	// directory, named DefaultWalletKitMacFilename.
	WalletKitMacPath string `long:"walletkitmacaroonpath" description:"Path to the wallet kit macaroon"`

	// NetworkDir is the main network directory wherein the signer rpc
	// server will find the macaroon named DefaultWalletKitMacFilename.
	NetworkDir string

	// MacService is the main macaroon service that we'll use to handle
	// authentication for the signer rpc server.
	MacService *macaroons.Service

	// FeeEstimator is an instance of the primary fee estimator instance
	// the WalletKit will use to respond to fee estimation requests.
	FeeEstimator chainfee.Estimator

	// Wallet is the primary wallet that the WalletKit will use to proxy
	// any relevant requests to.
	Wallet lnwallet.WalletController

	// CoinSelectionLocker allows the caller to perform an operation, which
	// is synchronized with all coin selection attempts. This can be used
	// when an operation requires that all coin selection operations cease
	// forward progress. Think of this as an exclusive lock on coin
	// selection operations.
	CoinSelectionLocker sweep.CoinSelectionLocker

	// KeyRing is an interface that the WalletKit will use to derive any
	// keys due to incoming client requests.
	KeyRing keychain.KeyRing

	// Sweeper is the central batching engine of lnd. It is responsible for
	// sweeping inputs in batches back into the wallet.
	Sweeper *sweep.UtxoSweeper

	// Chain is an interface that the WalletKit will use to determine state
	// about the backing chain of the wallet.
	Chain lnwallet.BlockChainIO

	// ChainParams are the parameters of the wallet's backing chain.
	ChainParams *chaincfg.Params
}
