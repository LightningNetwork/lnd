// +build chainrpc

package chainrpc

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// subServerName is the name of the RPC sub-server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize this as the name of the
	// config file that we need.
	subServerName = "ChainRPC"
)

var (
	// macaroonOps are the set of capabilities that our minted macaroon (if
	// it doesn't already exist) will have.
	macaroonOps = []bakery.Op{
		{
			Entity: "onchain",
			Action: "read",
		},
	}

	// macPermissions maps RPC calls to the permissions they require.
	macPermissions = map[string][]bakery.Op{
		"/chainrpc.ChainNotifier/RegisterConfirmationsNtfn": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/chainrpc.ChainNotifier/RegisterSpendNtfn": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/chainrpc.ChainNotifier/RegisterBlockEpochNtfn": {{
			Entity: "onchain",
			Action: "read",
		}},
	}

	// DefaultChainNotifierMacFilename is the default name of the chain
	// notifier macaroon that we expect to find via a file handle within the
	// main configuration file in this package.
	DefaultChainNotifierMacFilename = "chainnotifier.macaroon"

	// ErrChainNotifierServerShuttingDown is an error returned when we are
	// waiting for a notification to arrive but the chain notifier server
	// has been shut down.
	ErrChainNotifierServerShuttingDown = errors.New("chain notifier RPC " +
		"subserver shutting down")

	// ErrChainNotifierServerNotActive indicates that the chain notifier hasn't
	// finished the startup process.
	ErrChainNotifierServerNotActive = errors.New("chain notifier RPC is " +
		"still in the process of starting")
)

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	ChainNotifierServer
}

// Server is a sub-server of the main RPC server: the chain notifier RPC. This
// RPC sub-server allows external callers to access the full chain notifier
// capabilities of lnd. This allows callers to create custom protocols, external
// to lnd, even backed by multiple distinct lnd across independent failure
// domains.
type Server struct {
	started sync.Once
	stopped sync.Once

	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedChainNotifierServer

	cfg Config

	quit chan struct{}
}

// New returns a new instance of the chainrpc ChainNotifier sub-server. We also
// return the set of permissions for the macaroons that we may create within
// this method. If the macaroons we need aren't found in the filepath, then
// we'll create them on start up. If we're unable to locate, or create the
// macaroons we need, then we'll return with an error.
func New(cfg *Config) (*Server, lnrpc.MacaroonPerms, error) {
	// If the path of the chain notifier macaroon wasn't generated, then
	// we'll assume that it's found at the default network directory.
	if cfg.ChainNotifierMacPath == "" {
		cfg.ChainNotifierMacPath = filepath.Join(
			cfg.NetworkDir, DefaultChainNotifierMacFilename,
		)
	}

	// Now that we know the full path of the chain notifier macaroon, we can
	// check to see if we need to create it or not. If stateless_init is set
	// then we don't write the macaroons.
	macFilePath := cfg.ChainNotifierMacPath
	if cfg.MacService != nil && !cfg.MacService.StatelessInit &&
		!lnrpc.FileExists(macFilePath) {

		log.Infof("Baking macaroons for ChainNotifier RPC Server at: %v",
			macFilePath)

		// At this point, we know that the chain notifier macaroon
		// doesn't yet, exist, so we need to create it with the help of
		// the main macaroon service.
		chainNotifierMac, err := cfg.MacService.NewMacaroon(
			context.Background(), macaroons.DefaultRootKeyID,
			macaroonOps...,
		)
		if err != nil {
			return nil, nil, err
		}
		chainNotifierMacBytes, err := chainNotifierMac.M().MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		err = ioutil.WriteFile(macFilePath, chainNotifierMacBytes, 0644)
		if err != nil {
			_ = os.Remove(macFilePath)
			return nil, nil, err
		}
	}

	return &Server{
		cfg:  *cfg,
		quit: make(chan struct{}),
	}, macPermissions, nil
}

// Compile-time checks to ensure that Server fully implements the
// ChainNotifierServer gRPC service and lnrpc.SubServer interface.
var _ ChainNotifierServer = (*Server)(nil)
var _ lnrpc.SubServer = (*Server)(nil)

// Start launches any helper goroutines required for the server to function.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Start() error {
	s.started.Do(func() {})
	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Stop() error {
	s.stopped.Do(func() {
		close(s.quit)
	})
	return nil
}

// Name returns a unique string representation of the sub-server. This can be
// used to identify the sub-server and also de-duplicate them.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Name() string {
	return subServerName
}

// RegisterWithRootServer will be called by the root gRPC server to direct a RPC
// sub-server to register itself with the main gRPC root server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRootServer(grpcServer *grpc.Server) error {
	// We make sure that we register it with the main gRPC server to ensure
	// all our methods are routed properly.
	RegisterChainNotifierServer(grpcServer, r)

	log.Debug("ChainNotifier RPC server successfully register with root " +
		"gRPC server")

	return nil
}

// RegisterWithRestServer will be called by the root REST mux to direct a sub
// RPC server to register itself with the main REST mux server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRestServer(ctx context.Context,
	mux *runtime.ServeMux, dest string, opts []grpc.DialOption) error {

	// We make sure that we register it with the main REST server to ensure
	// all our methods are routed properly.
	err := RegisterChainNotifierHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register ChainNotifier REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("ChainNotifier REST server successfully registered with " +
		"root REST server")
	return nil
}

// CreateSubServer populates the subserver's dependencies using the passed
// SubServerConfigDispatcher. This method should fully initialize the
// sub-server instance, making it ready for action. It returns the macaroon
// permissions that the sub-server wishes to pass on to the root server for all
// methods routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) CreateSubServer(configRegistry lnrpc.SubServerConfigDispatcher) (
	lnrpc.SubServer, lnrpc.MacaroonPerms, error) {

	subServer, macPermissions, err := createNewSubServer(configRegistry)
	if err != nil {
		return nil, nil, err
	}

	r.ChainNotifierServer = subServer
	return subServer, macPermissions, nil
}

// RegisterConfirmationsNtfn is a synchronous response-streaming RPC that
// registers an intent for a client to be notified once a confirmation request
// has reached its required number of confirmations on-chain.
//
// A client can specify whether the confirmation request should be for a
// particular transaction by its hash or for an output script by specifying a
// zero hash.
//
// NOTE: This is part of the chainrpc.ChainNotifierService interface.
func (s *Server) RegisterConfirmationsNtfn(in *ConfRequest,
	confStream ChainNotifier_RegisterConfirmationsNtfnServer) error {

	if !s.cfg.ChainNotifier.Started() {
		return ErrChainNotifierServerNotActive
	}

	// We'll start by reconstructing the RPC request into what the
	// underlying ChainNotifier expects.
	var txid chainhash.Hash
	copy(txid[:], in.Txid)

	// We'll then register for the spend notification of the request.
	confEvent, err := s.cfg.ChainNotifier.RegisterConfirmationsNtfn(
		&txid, in.Script, in.NumConfs, in.HeightHint,
	)
	if err != nil {
		return err
	}
	defer confEvent.Cancel()

	// With the request registered, we'll wait for its spend notification to
	// be dispatched.
	for {
		select {
		// The transaction satisfying the request has confirmed on-chain
		// and reached its required number of confirmations. We'll
		// dispatch an event to the caller indicating so.
		case details, ok := <-confEvent.Confirmed:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			var rawTxBuf bytes.Buffer
			err := details.Tx.Serialize(&rawTxBuf)
			if err != nil {
				return err
			}

			rpcConfDetails := &ConfDetails{
				RawTx:       rawTxBuf.Bytes(),
				BlockHash:   details.BlockHash[:],
				BlockHeight: details.BlockHeight,
				TxIndex:     details.TxIndex,
			}

			conf := &ConfEvent{
				Event: &ConfEvent_Conf{
					Conf: rpcConfDetails,
				},
			}
			if err := confStream.Send(conf); err != nil {
				return err
			}

		// The transaction satisfying the request has been reorged out
		// of the chain, so we'll send an event describing so.
		case _, ok := <-confEvent.NegativeConf:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			reorg := &ConfEvent{
				Event: &ConfEvent_Reorg{Reorg: &Reorg{}},
			}
			if err := confStream.Send(reorg); err != nil {
				return err
			}

		// The transaction satisfying the request has confirmed and is
		// no longer under the risk of being reorged out of the chain,
		// so we can safely exit.
		case _, ok := <-confEvent.Done:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			return nil

		// The response stream's context for whatever reason has been
		// closed. We'll return the error indicated by the context
		// itself to the caller.
		case <-confStream.Context().Done():
			return confStream.Context().Err()

		// The server has been requested to shut down.
		case <-s.quit:
			return ErrChainNotifierServerShuttingDown
		}
	}
}

// RegisterSpendNtfn is a synchronous response-streaming RPC that registers an
// intent for a client to be notification once a spend request has been spent by
// a transaction that has confirmed on-chain.
//
// A client can specify whether the spend request should be for a particular
// outpoint  or for an output script by specifying a zero outpoint.
//
// NOTE: This is part of the chainrpc.ChainNotifierService interface.
func (s *Server) RegisterSpendNtfn(in *SpendRequest,
	spendStream ChainNotifier_RegisterSpendNtfnServer) error {

	if !s.cfg.ChainNotifier.Started() {
		return ErrChainNotifierServerNotActive
	}

	// We'll start by reconstructing the RPC request into what the
	// underlying ChainNotifier expects.
	var op *wire.OutPoint
	if in.Outpoint != nil {
		var txid chainhash.Hash
		copy(txid[:], in.Outpoint.Hash)
		op = &wire.OutPoint{Hash: txid, Index: in.Outpoint.Index}
	}

	// We'll then register for the spend notification of the request.
	spendEvent, err := s.cfg.ChainNotifier.RegisterSpendNtfn(
		op, in.Script, in.HeightHint,
	)
	if err != nil {
		return err
	}
	defer spendEvent.Cancel()

	// With the request registered, we'll wait for its spend notification to
	// be dispatched.
	for {
		select {
		// A transaction that spends the given has confirmed on-chain.
		// We'll return an event to the caller indicating so that
		// includes the details of the spending transaction.
		case details, ok := <-spendEvent.Spend:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			var rawSpendingTxBuf bytes.Buffer
			err := details.SpendingTx.Serialize(&rawSpendingTxBuf)
			if err != nil {
				return err
			}

			rpcSpendDetails := &SpendDetails{
				SpendingOutpoint: &Outpoint{
					Hash:  details.SpentOutPoint.Hash[:],
					Index: details.SpentOutPoint.Index,
				},
				RawSpendingTx:      rawSpendingTxBuf.Bytes(),
				SpendingTxHash:     details.SpenderTxHash[:],
				SpendingInputIndex: details.SpenderInputIndex,
				SpendingHeight:     uint32(details.SpendingHeight),
			}

			spend := &SpendEvent{
				Event: &SpendEvent_Spend{
					Spend: rpcSpendDetails,
				},
			}
			if err := spendStream.Send(spend); err != nil {
				return err
			}

		// The spending transaction of the request has been reorged of
		// the chain. We'll return an event to the caller indicating so.
		case _, ok := <-spendEvent.Reorg:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			reorg := &SpendEvent{
				Event: &SpendEvent_Reorg{Reorg: &Reorg{}},
			}
			if err := spendStream.Send(reorg); err != nil {
				return err
			}

		// The spending transaction of the requests has confirmed
		// on-chain and is no longer under the risk of being reorged out
		// of the chain, so we can safely exit.
		case _, ok := <-spendEvent.Done:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			return nil

		// The response stream's context for whatever reason has been
		// closed. We'll return the error indicated by the context
		// itself to the caller.
		case <-spendStream.Context().Done():
			return spendStream.Context().Err()

		// The server has been requested to shut down.
		case <-s.quit:
			return ErrChainNotifierServerShuttingDown
		}
	}
}

// RegisterBlockEpochNtfn is a synchronous response-streaming RPC that registers
// an intent for a client to be notified of blocks in the chain. The stream will
// return a hash and height tuple of a block for each new/stale block in the
// chain. It is the client's responsibility to determine whether the tuple
// returned is for a new or stale block in the chain.
//
// A client can also request a historical backlog of blocks from a particular
// point. This allows clients to be idempotent by ensuring that they do not
// missing processing a single block within the chain.
//
// NOTE: This is part of the chainrpc.ChainNotifierService interface.
func (s *Server) RegisterBlockEpochNtfn(in *BlockEpoch,
	epochStream ChainNotifier_RegisterBlockEpochNtfnServer) error {

	if !s.cfg.ChainNotifier.Started() {
		return ErrChainNotifierServerNotActive
	}

	// We'll start by reconstructing the RPC request into what the
	// underlying ChainNotifier expects.
	var hash chainhash.Hash
	copy(hash[:], in.Hash)

	// If the request isn't for a zero hash and a zero height, then we
	// should deliver a backlog of notifications from the given block
	// (hash/height tuple) until tip, and continue delivering epochs for
	// new blocks.
	var blockEpoch *chainntnfs.BlockEpoch
	if hash != chainntnfs.ZeroHash && in.Height != 0 {
		blockEpoch = &chainntnfs.BlockEpoch{
			Hash:   &hash,
			Height: int32(in.Height),
		}
	}

	epochEvent, err := s.cfg.ChainNotifier.RegisterBlockEpochNtfn(blockEpoch)
	if err != nil {
		return err
	}
	defer epochEvent.Cancel()

	for {
		select {
		// A notification for a block has been received. This block can
		// either be a new block or stale.
		case blockEpoch, ok := <-epochEvent.Epochs:
			if !ok {
				return chainntnfs.ErrChainNotifierShuttingDown
			}

			epoch := &BlockEpoch{
				Hash:   blockEpoch.Hash[:],
				Height: uint32(blockEpoch.Height),
			}
			if err := epochStream.Send(epoch); err != nil {
				return err
			}

		// The response stream's context for whatever reason has been
		// closed. We'll return the error indicated by the context
		// itself to the caller.
		case <-epochStream.Context().Done():
			return epochStream.Context().Err()

		// The server has been requested to shut down.
		case <-s.quit:
			return ErrChainNotifierServerShuttingDown
		}
	}
}
