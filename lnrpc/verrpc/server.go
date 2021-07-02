package verrpc

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/lnrpc"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const subServerName = "VersionRPC"

var macPermissions = map[string][]bakery.Op{
	"/verrpc.Versioner/GetVersion": {{
		Entity: "info",
		Action: "read",
	}},
}

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	VersionerServer
}

// Server is an rpc server that supports querying for information about the
// running binary.
type Server struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedVersionerServer
}

// Start launches any helper goroutines required for the rpcServer to function.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Start() error {
	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Stop() error {
	return nil
}

// Name returns a unique string representation of the sub-server. This can be
// used to identify the sub-server and also de-duplicate them.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Name() string {
	return subServerName
}

// RegisterWithRootServer will be called by the root gRPC server to direct a
// sub RPC server to register itself with the main gRPC root server. Until this
// is called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRootServer(grpcServer *grpc.Server) error {
	RegisterVersionerServer(grpcServer, r)

	log.Debugf("Versioner RPC server successfully registered with root " +
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
	err := RegisterVersionerHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register Versioner REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("Versioner REST server successfully registered with " +
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
func (r *ServerShell) CreateSubServer(_ lnrpc.SubServerConfigDispatcher) (
	lnrpc.SubServer, lnrpc.MacaroonPerms, error) {

	subServer := &Server{}
	r.VersionerServer = subServer
	return subServer, macPermissions, nil
}

// GetVersion returns information about the compiled binary.
func (s *Server) GetVersion(_ context.Context,
	_ *VersionRequest) (*Version, error) {

	return &Version{
		Commit:        build.Commit,
		CommitHash:    build.CommitHash,
		Version:       build.Version(),
		AppMajor:      uint32(build.AppMajor),
		AppMinor:      uint32(build.AppMinor),
		AppPatch:      uint32(build.AppPatch),
		AppPreRelease: build.AppPreRelease,
		BuildTags:     build.Tags(),
		GoVersion:     build.GoVersion,
	}, nil
}
