package watchtower

import (
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/lightningnetwork/lnd/watchtower/lookout"
)

const (
	// DefaultPeerPort is the default server port to which clients can
	// connect.
	DefaultPeerPort = 9911

	// DefaultReadTimeout is the default timeout after which the tower will
	// hang up on a client if nothing is received.
	DefaultReadTimeout = 15 * time.Second

	// DefaultWriteTimeout is the default timeout after which the tower will
	// hang up on a client if it is unable to send a message.
	DefaultWriteTimeout = 15 * time.Second
)

var (
	// DefaultListenAddr is the default watchtower address listening on all
	// interfaces.
	DefaultListenAddr = fmt.Sprintf(":%d", DefaultPeerPort)
)

// Config defines the resources and parameters used to configure a Watchtower.
// All nil-able elements besides tor-related ones must be set in order for the
// Watchtower to function properly.
type Config struct {
	// ChainHash identifies the chain that the watchtower will be monitoring
	// for breaches and that will be advertised in the server's Init message
	// to inbound clients.
	ChainHash chainhash.Hash

	// BlockFetcher supports the ability to fetch blocks from the network by
	// hash.
	BlockFetcher lookout.BlockFetcher

	// DB provides access to persistent storage of sessions and state
	// updates uploaded by watchtower clients, and the ability to query for
	// breach hints when receiving new blocks.
	DB DB

	// EpochRegistrar supports the ability to register for events
	// corresponding to newly created blocks.
	EpochRegistrar lookout.EpochRegistrar

	// Net specifies the network type that the watchtower will use to listen
	// for client connections. Either a clear net or Tor are supported.
	Net tor.Net

	// NewAddress is used to generate reward addresses, where a cut of
	// successfully sent funds can be received.
	NewAddress func() (btcutil.Address, error)

	// NodeKeyECDH is the ECDH capable wrapper of the key to be used in
	// accepting new brontide connections.
	NodeKeyECDH keychain.SingleKeyECDH

	// PublishTx provides the ability to send a signed transaction to the
	// network.
	//
	// TODO(conner): replace with lnwallet.WalletController interface to
	// have stronger guarantees wrt. returned error types.
	PublishTx func(*wire.MsgTx, string) error

	// ListenAddrs specifies the listening addresses of the tower.
	ListenAddrs []net.Addr

	// ExternalIPs specifies the addresses to which clients may connect to
	// the tower.
	ExternalIPs []net.Addr

	// ReadTimeout specifies how long a client may go without sending a
	// message.
	ReadTimeout time.Duration

	// WriteTimeout specifies how long a client may go without reading a
	// message from the other end, if the connection has stopped buffering
	// the server's replies.
	WriteTimeout time.Duration

	// TorController allows the watchtower to optionally setup an onion hidden
	// service.
	TorController *tor.Controller

	// WatchtowerKeyPath allows the watchtower to specify where the private key
	// for a watchtower hidden service should be stored.
	WatchtowerKeyPath string

	// EncryptKey will encrypt the Tor private key on disk
	EncryptKey bool

	// KeyRing is the KeyRing to use when encrypting the Tor private key
	KeyRing keychain.KeyRing

	// Type specifies the hidden service type (V2 or V3) that the watchtower
	// will create.
	Type tor.OnionType
}
