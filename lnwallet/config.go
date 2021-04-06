package lnwallet

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// Config is a struct which houses configuration parameters which modify the
// behaviour of LightningWallet.
//
// NOTE: The passed channeldb, and ChainNotifier should already be fully
// initialized/started before being passed as a function argument.
type Config struct {
	// Database is a wrapper around a namespace within boltdb reserved for
	// ln-based wallet metadata. See the 'channeldb' package for further
	// information.
	Database *channeldb.DB

	// Notifier is used by in order to obtain notifications about funding
	// transaction reaching a specified confirmation depth, and to catch
	// counterparty's broadcasting revoked commitment states.
	Notifier chainntnfs.ChainNotifier

	// SecretKeyRing is used by the wallet during the funding workflow
	// process to obtain keys to be used directly within contracts. Usage
	// of this interface ensures that all key derivation is itself fully
	// deterministic.
	SecretKeyRing keychain.SecretKeyRing

	// WalletController is the core wallet, all non Lightning Network
	// specific interaction is proxied to the internal wallet.
	WalletController WalletController

	// Signer is the wallet's current Signer implementation. This Signer is
	// used to generate signature for all inputs to potential funding
	// transactions, as well as for spends from the funding transaction to
	// update the commitment state.
	Signer input.Signer

	// FeeEstimator is the implementation that the wallet will use for the
	// calculation of on-chain transaction fees.
	FeeEstimator chainfee.Estimator

	// ChainIO is an instance of the BlockChainIO interface. ChainIO is
	// used to lookup the existence of outputs within the UTXO set.
	ChainIO BlockChainIO

	// DefaultConstraints is the set of default constraints that will be
	// used for any incoming or outgoing channel reservation requests.
	DefaultConstraints channeldb.ChannelConstraints

	// NetParams is the set of parameters that tells the wallet which chain
	// it will be operating on.
	NetParams chaincfg.Params

	// IsRoutingNode indicates whether the node is currently configured to
	// route payments. This is currently used to identify potentially unsafe
	// funding flows, e.g. when accepting anchor channels with no utxos
	// reserved for on-chain fees.
	IsRoutingNode bool
}
