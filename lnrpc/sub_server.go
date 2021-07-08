package lnrpc

import (
	"context"
	"fmt"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// MacaroonPerms is a map from the FullMethod of an invoked gRPC command. It
// maps the set of operations that the macaroon presented with the command MUST
// satisfy. With this map, all sub-servers are able to communicate to the
// primary macaroon service what type of macaroon must be passed with each
// method present on the service of the sub-server.
type MacaroonPerms map[string][]bakery.Op

// SubServer is a child server of the main lnrpc gRPC server. Sub-servers allow
// lnd to expose discrete services that can be used with or independent of the
// main RPC server. The main rpcserver will create, start, stop, and manage
// each sub-server in a generalized manner.
type SubServer interface {
	// Start starts the sub-server and all goroutines it needs to operate.
	Start() error

	// Stop signals that the sub-server should wrap up any lingering
	// requests, and being a graceful shutdown.
	Stop() error

	// Name returns a unique string representation of the sub-server. This
	// can be used to identify the sub-server and also de-duplicate them.
	Name() string
}

// GrpcHandler is the interface that should be registered with the root gRPC
// server, and is the interface that implements the subserver's defined RPC.
// Before the actual sub server has been created, this will be an empty shell
// allowing us to start the gRPC server before we have all the dependencies
// needed to create the subserver itself.
type GrpcHandler interface {
	// RegisterWithRootServer will be called by the root gRPC server to
	// direct a sub RPC server to register itself with the main gRPC root
	// server. Until this is called, each sub-server won't be able to have
	// requests routed towards it.
	RegisterWithRootServer(*grpc.Server) error

	// RegisterWithRestServer will be called by the root REST mux to direct
	// a sub RPC server to register itself with the main REST mux server.
	// Until this is called, each sub-server won't be able to have requests
	// routed towards it.
	RegisterWithRestServer(context.Context, *runtime.ServeMux, string,
		[]grpc.DialOption) error

	// CreateSubServer populates the subserver's dependencies using the
	// passed SubServerConfigDispatcher. This method should fully
	// initialize the sub-server instance, making it ready for action. It
	// returns the macaroon permissions that the sub-server wishes to pass
	// on to the root server for all methods routed towards it.
	CreateSubServer(subCfgs SubServerConfigDispatcher) (SubServer,
		MacaroonPerms, error)
}

// SubServerConfigDispatcher is an interface that all sub-servers will use to
// dynamically locate their configuration files. This abstraction will allow
// the primary RPC sever to initialize all sub-servers in a generic manner
// without knowing of each individual sub server.
type SubServerConfigDispatcher interface {
	// FetchConfig attempts to locate an existing configuration file mapped
	// to the target sub-server. If we're unable to find a config file
	// matching the subServerName name, then false will be returned for the
	// second parameter.
	FetchConfig(subServerName string) (interface{}, bool)
}

// SubServerDriver is a template struct that allows the root server to create a
// sub-server gRPC handler with minimal knowledge.
type SubServerDriver struct {
	// SubServerName is the full name of a sub-sever.
	//
	// NOTE: This MUST be unique.
	SubServerName string

	// NewGrpcHandler creates a a new sub-server gRPC interface that can be
	// registered with the root gRPC server. It is not expected that the
	// SubServer is ready for operation before its CreateSubServer and
	// Start methods have been called.
	NewGrpcHandler func() GrpcHandler
}

var (
	// subServers is a package level global variable that houses all the
	// registered sub-servers.
	subServers = make(map[string]*SubServerDriver)

	// registerMtx is a mutex that protects access to the above subServer
	// map.
	registerMtx sync.Mutex
)

// RegisteredSubServers returns all registered sub-servers.
//
// NOTE: This function is safe for concurrent access.
func RegisteredSubServers() []*SubServerDriver {
	registerMtx.Lock()
	defer registerMtx.Unlock()

	drivers := make([]*SubServerDriver, 0, len(subServers))
	for _, driver := range subServers {
		drivers = append(drivers, driver)
	}

	return drivers
}

// RegisterSubServer should be called by a sub-server within its package's
// init() method to register its existence with the main sub-server map. Each
// sub-server, if active, is meant to register via this method in their init()
// method. This allows callers to easily initialize and register all
// sub-servers without knowing any details beyond that the fact that they
// satisfy the necessary interfaces.
//
// NOTE: This function is safe for concurrent access.
func RegisterSubServer(driver *SubServerDriver) error {
	registerMtx.Lock()
	defer registerMtx.Unlock()

	if _, ok := subServers[driver.SubServerName]; ok {
		return fmt.Errorf("subserver already registered")
	}

	subServers[driver.SubServerName] = driver

	return nil
}

// SupportedServers returns slice of the names of all registered sub-servers.
//
// NOTE: This function is safe for concurrent access.
func SupportedServers() []string {
	registerMtx.Lock()
	defer registerMtx.Unlock()

	supportedSubServers := make([]string, 0, len(subServers))
	for driverName := range subServers {
		supportedSubServers = append(supportedSubServers, driverName)
	}

	return supportedSubServers
}
