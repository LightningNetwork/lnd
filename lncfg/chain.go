package lncfg

import "github.com/lightningnetwork/lnd/lnwire"

// Chain holds the configuration options for the daemon's chain settings.
type Chain struct {
	Active   bool   `long:"active" description:"If the chain should be active or not."`
	ChainDir string `long:"chaindir" description:"The directory to store the chain's data within."`

	Node string `long:"node" description:"The blockchain interface to use." choice:"btcd" choice:"bitcoind" choice:"neutrino" choice:"ltcd" choice:"litecoind"`

	MainNet  bool `long:"mainnet" description:"Use the main network"`
	TestNet3 bool `long:"testnet" description:"Use the test network"`
	SimNet   bool `long:"simnet" description:"Use the simulation test network"`
	RegTest  bool `long:"regtest" description:"Use the regression test network"`

	DefaultNumChanConfs     int                 `long:"defaultchanconfs" description:"The default number of confirmations a channel must have before it's considered open. If this is not set, we will scale the value according to the channel size."`
	SkipChannelConfirmation bool                `long:"skip-channel-confirmation" description:"Whether or not to wait for a channel to confirm on-chain before making it operational"`
	DefaultRemoteDelay      int                 `long:"defaultremotedelay" description:"The default number of blocks we will require our channel counterparty to wait before accessing its funds in case of unilateral close. If this is not set, we will scale the value according to the channel size."`
	MinHTLCIn               lnwire.MilliSatoshi `long:"minhtlc" description:"The smallest HTLC we are willing to accept on our channels, in millisatoshi"`
	MinHTLCOut              lnwire.MilliSatoshi `long:"minhtlcout" description:"The smallest HTLC we are willing to send out on our channels, in millisatoshi"`
	BaseFee                 lnwire.MilliSatoshi `long:"basefee" description:"The base fee in millisatoshi we will charge for forwarding payments on our channels"`
	FeeRate                 lnwire.MilliSatoshi `long:"feerate" description:"The fee rate used when forwarding payments on our channels. The total fee charged is basefee + (amount * feerate / 1000000), where amount is the forwarded amount."`
	TimeLockDelta           uint32              `long:"timelockdelta" description:"The CLTV delta we will subtract from a forwarded HTLC's timelock value"`
}
