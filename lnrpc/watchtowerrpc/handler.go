// +build watchtowerrpc

package watchtowerrpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/lnrpc"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// subServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognizes it as the name of our
	// RPC service.
	subServerName = "WatchtowerRPC"
)

var (
	// macPermissions maps RPC calls to the permissions they require.
	macPermissions = map[string][]bakery.Op{
		"/watchtowerrpc.Watchtower/GetInfo": {{
			Entity: "info",
			Action: "read",
		}},
	}

	// ErrTowerNotActive signals that RPC calls cannot be processed because
	// the watchtower is not active.
	ErrTowerNotActive = errors.New("watchtower not active")
)

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	WatchtowerServer
}

// Handler is the RPC server we'll use to interact with the backing active
// watchtower.
type Handler struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedWatchtowerServer

	cfg Config
}

// A compile time check to ensure that Handler fully implements the Handler gRPC
// service.
var _ WatchtowerServer = (*Handler)(nil)

// New returns a new instance of the Watchtower sub-server. We also return the
// set of permissions for the macaroons that we may create within this method.
// If the macaroons we need aren't found in the filepath, then we'll create them
// on start up. If we're unable to locate, or create the macaroons we need, then
// we'll return with an error.
func New(cfg *Config) (*Handler, lnrpc.MacaroonPerms, error) {
	return &Handler{cfg: *cfg}, macPermissions, nil
}

// Start launches any helper goroutines required for the Handler to function.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (c *Handler) Start() error {
	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (c *Handler) Stop() error {
	return nil
}

// Name returns a unique string representation of the sub-server. This can be
// used to identify the sub-server and also de-duplicate them.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (c *Handler) Name() string {
	return subServerName
}

// RegisterWithRootServer will be called by the root gRPC server to direct a sub
// RPC server to register itself with the main gRPC root server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRootServer(grpcServer *grpc.Server) error {
	// We make sure that we register it with the main gRPC server to ensure
	// all our methods are routed properly.
	RegisterWatchtowerServer(grpcServer, r)

	log.Debugf("Watchtower RPC server successfully register with root " +
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
	err := RegisterWatchtowerHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register Watchtower REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("Watchtower REST server successfully registered with " +
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

	r.WatchtowerServer = subServer
	return subServer, macPermissions, nil
}

// AddTower adds a new watchtower reachable at the given address and considers
// it for new sessions. If the watchtower already exists, then any new addresses
// included will be considered when dialing it for session negotiations and
// backups.
func (c *Handler) GetInfo(ctx context.Context,
	req *GetInfoRequest) (*GetInfoResponse, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	pubkey := c.cfg.Tower.PubKey().SerializeCompressed()

	var listeners []string
	for _, addr := range c.cfg.Tower.ListeningAddrs() {
		listeners = append(listeners, addr.String())
	}

	var uris []string
	for _, addr := range c.cfg.Tower.ExternalIPs() {
		uris = append(uris, fmt.Sprintf("%x@%v", pubkey, addr))
	}

	return &GetInfoResponse{
		Pubkey:    pubkey,
		Listeners: listeners,
		Uris:      uris,
	}, nil
}

// isActive returns nil if the tower backend is initialized, and the Handler can
// proccess RPC requests.
func (c *Handler) isActive() error {
	if c.cfg.Active {
		return nil
	}
	return ErrTowerNotActive
}
