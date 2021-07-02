package rpcperms

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btclog"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/monitoring"
	"github.com/lightningnetwork/lnd/subscribe"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// rpcState is an enum that we use to keep track of the current RPC service
// state. This will transition as we go from startup to unlocking the wallet,
// and finally fully active.
type rpcState uint8

const (
	// waitingToStart indicates that we're at the beginning of the startup
	// process. In a cluster evironment this may mean that we're waiting to
	// become the leader in which case RPC calls will be disabled until
	// this instance has been elected as leader.
	waitingToStart rpcState = iota

	// walletNotCreated is the starting state if the RPC server is active,
	// but the wallet is not yet created. In this state we'll only allow
	// calls to the WalletUnlockerService.
	walletNotCreated

	// walletLocked indicates the RPC server is active, but the wallet is
	// locked. In this state we'll only allow calls to the
	// WalletUnlockerService.
	walletLocked

	// walletUnlocked means that the wallet has been unlocked, but the full
	// RPC server is not yeat ready.
	walletUnlocked

	// rpcActive means that the RPC server is ready to accept calls.
	rpcActive
)

var (
	// ErrWaitingToStart is returned if LND is still wating to start,
	// possibly blocked until elected as the leader.
	ErrWaitingToStart = fmt.Errorf("waiting to start, RPC services not " +
		"available")

	// ErrNoWallet is returned if the wallet does not exist.
	ErrNoWallet = fmt.Errorf("wallet not created, create one to enable " +
		"full RPC access")

	// ErrWalletLocked is returned if the wallet is locked and any service
	// other than the WalletUnlocker is called.
	ErrWalletLocked = fmt.Errorf("wallet locked, unlock it to enable " +
		"full RPC access")

	// ErrWalletUnlocked is returned if the WalletUnlocker service is
	// called when the wallet already has been unlocked.
	ErrWalletUnlocked = fmt.Errorf("wallet already unlocked, " +
		"WalletUnlocker service is no longer available")

	// ErrRPCStarting is returned if the wallet has been unlocked but the
	// RPC server is not yet ready to accept calls.
	ErrRPCStarting = fmt.Errorf("the RPC server is in the process of " +
		"starting up, but not yet ready to accept calls")

	// macaroonWhitelist defines methods that we don't require macaroons to
	// access.
	macaroonWhitelist = map[string]struct{}{
		// We allow all calls to the WalletUnlocker without macaroons.
		"/lnrpc.WalletUnlocker/GenSeed":        {},
		"/lnrpc.WalletUnlocker/InitWallet":     {},
		"/lnrpc.WalletUnlocker/UnlockWallet":   {},
		"/lnrpc.WalletUnlocker/ChangePassword": {},

		// The State service must be available at all times, even
		// before we can check macaroons, so we whitelist it.
		"/lnrpc.State/SubscribeState": {},
		"/lnrpc.State/GetState":       {},
	}
)

// InterceptorChain is a struct that can be added to the running GRPC server,
// intercepting API calls. This is useful for logging, enforcing permissions
// etc.
type InterceptorChain struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	lnrpc.UnimplementedStateServer

	started sync.Once
	stopped sync.Once

	// state is the current RPC state of our RPC server.
	state rpcState

	// ntfnServer is a subscription server we use to notify clients of the
	// State service when the state changes.
	ntfnServer *subscribe.Server

	// noMacaroons should be set true if we don't want to check macaroons.
	noMacaroons bool

	// svc is the macaroon service used to enforce permissions in case
	// macaroons are used.
	svc *macaroons.Service

	// permissionMap is the permissions to enforce if macaroons are used.
	permissionMap map[string][]bakery.Op

	// rpcsLog is the logger used to log calles to the RPCs intercepted.
	rpcsLog btclog.Logger

	quit chan struct{}
	sync.RWMutex
}

// A compile time check to ensure that InterceptorChain fully implements the
// StateServer gRPC service.
var _ lnrpc.StateServer = (*InterceptorChain)(nil)

// NewInterceptorChain creates a new InterceptorChain.
func NewInterceptorChain(log btclog.Logger, noMacaroons bool) *InterceptorChain {
	return &InterceptorChain{
		state:         waitingToStart,
		ntfnServer:    subscribe.NewServer(),
		noMacaroons:   noMacaroons,
		permissionMap: make(map[string][]bakery.Op),
		rpcsLog:       log,
		quit:          make(chan struct{}),
	}
}

// Start starts the InterceptorChain, which is needed to start the state
// subscription server it powers.
func (r *InterceptorChain) Start() error {
	var err error
	r.started.Do(func() {
		err = r.ntfnServer.Start()
	})

	return err
}

// Stop stops the InterceptorChain and its internal state subscription server.
func (r *InterceptorChain) Stop() error {
	var err error
	r.stopped.Do(func() {
		close(r.quit)
		err = r.ntfnServer.Stop()
	})

	return err
}

// SetWalletNotCreated moves the RPC state from either waitingToStart to
// walletNotCreated.
func (r *InterceptorChain) SetWalletNotCreated() {
	r.Lock()
	defer r.Unlock()

	r.state = walletNotCreated
	_ = r.ntfnServer.SendUpdate(r.state)
}

// SetWalletLocked moves the RPC state from either walletNotCreated to
// walletLocked.
func (r *InterceptorChain) SetWalletLocked() {
	r.Lock()
	defer r.Unlock()

	r.state = walletLocked
	_ = r.ntfnServer.SendUpdate(r.state)
}

// SetWalletUnlocked moves the RPC state from either walletNotCreated or
// walletLocked to walletUnlocked.
func (r *InterceptorChain) SetWalletUnlocked() {
	r.Lock()
	defer r.Unlock()

	r.state = walletUnlocked
	_ = r.ntfnServer.SendUpdate(r.state)
}

// SetRPCActive moves the RPC state from walletUnlocked to rpcActive.
func (r *InterceptorChain) SetRPCActive() {
	r.Lock()
	defer r.Unlock()

	r.state = rpcActive
	_ = r.ntfnServer.SendUpdate(r.state)
}

// rpcStateToWalletState converts rpcState to lnrpc.WalletState. Returns
// WAITING_TO_START and an error on conversion error.
func rpcStateToWalletState(state rpcState) (lnrpc.WalletState, error) {
	const defaultState = lnrpc.WalletState_WAITING_TO_START
	var walletState lnrpc.WalletState

	switch state {
	case waitingToStart:
		walletState = lnrpc.WalletState_WAITING_TO_START
	case walletNotCreated:
		walletState = lnrpc.WalletState_NON_EXISTING
	case walletLocked:
		walletState = lnrpc.WalletState_LOCKED
	case walletUnlocked:
		walletState = lnrpc.WalletState_UNLOCKED
	case rpcActive:
		walletState = lnrpc.WalletState_RPC_ACTIVE

	default:
		return defaultState, fmt.Errorf("unknown wallet state %v", state)
	}

	return walletState, nil
}

// SubscribeState subscribes to the state of the wallet. The current wallet
// state will always be delivered immediately.
//
// NOTE: Part of the StateService interface.
func (r *InterceptorChain) SubscribeState(req *lnrpc.SubscribeStateRequest,
	stream lnrpc.State_SubscribeStateServer) error {

	sendStateUpdate := func(state rpcState) error {
		walletState, err := rpcStateToWalletState(state)
		if err != nil {
			return err
		}

		return stream.Send(&lnrpc.SubscribeStateResponse{
			State: walletState,
		})
	}

	// Subscribe to state updates.
	client, err := r.ntfnServer.Subscribe()
	if err != nil {
		return err
	}
	defer client.Cancel()

	// Always start by sending the current state.
	r.RLock()
	state := r.state
	r.RUnlock()

	if err := sendStateUpdate(state); err != nil {
		return err
	}

	for {
		select {
		case e := <-client.Updates():
			newState := e.(rpcState)

			// Ignore already sent state.
			if newState == state {
				continue
			}

			state = newState
			err := sendStateUpdate(state)
			if err != nil {
				return err
			}

		case <-stream.Context().Done():
			return stream.Context().Err()

		case <-r.quit:
			return fmt.Errorf("server exiting")
		}
	}
}

// GetState returns he current wallet state.
func (r *InterceptorChain) GetState(_ context.Context,
	req *lnrpc.GetStateRequest) (*lnrpc.GetStateResponse, error) {

	r.RLock()
	state := r.state
	r.RUnlock()

	walletState, err := rpcStateToWalletState(state)
	if err != nil {
		return nil, err
	}

	return &lnrpc.GetStateResponse{
		State: walletState,
	}, nil
}

// AddMacaroonService adds a macaroon service to the interceptor. After this is
// done every RPC call made will have to pass a valid macaroon to be accepted.
func (r *InterceptorChain) AddMacaroonService(svc *macaroons.Service) {
	r.Lock()
	defer r.Unlock()

	r.svc = svc
}

// AddPermission adds a new macaroon rule for the given method.
func (r *InterceptorChain) AddPermission(method string, ops []bakery.Op) error {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.permissionMap[method]; ok {
		return fmt.Errorf("detected duplicate macaroon constraints "+
			"for path: %v", method)
	}

	r.permissionMap[method] = ops
	return nil
}

// Permissions returns the current set of macaroon permissions.
func (r *InterceptorChain) Permissions() map[string][]bakery.Op {
	r.RLock()
	defer r.RUnlock()

	// Make a copy under the read lock to avoid races.
	c := make(map[string][]bakery.Op)
	for k, v := range r.permissionMap {
		s := make([]bakery.Op, len(v))
		copy(s, v)
		c[k] = s
	}

	return c
}

// CreateServerOpts creates the GRPC server options that can be added to a GRPC
// server in order to add this InterceptorChain.
func (r *InterceptorChain) CreateServerOpts() []grpc.ServerOption {
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var strmInterceptors []grpc.StreamServerInterceptor

	// The first interceptors we'll add to the chain is our logging
	// interceptors, so we can automatically log all errors that happen
	// during RPC calls.
	unaryInterceptors = append(
		unaryInterceptors, errorLogUnaryServerInterceptor(r.rpcsLog),
	)
	strmInterceptors = append(
		strmInterceptors, errorLogStreamServerInterceptor(r.rpcsLog),
	)

	// Next we'll add our RPC state check interceptors, that will check
	// whether the attempted call is allowed in the current state.
	unaryInterceptors = append(
		unaryInterceptors, r.rpcStateUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, r.rpcStateStreamServerInterceptor(),
	)

	// We'll add the macaroon interceptors. If macaroons aren't disabled,
	// then these interceptors will enforce macaroon authentication.
	unaryInterceptors = append(
		unaryInterceptors, r.MacaroonUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, r.MacaroonStreamServerInterceptor(),
	)

	// Get interceptors for Prometheus to gather gRPC performance metrics.
	// If monitoring is disabled, GetPromInterceptors() will return empty
	// slices.
	promUnaryInterceptors, promStrmInterceptors :=
		monitoring.GetPromInterceptors()

	// Concatenate the slices of unary and stream interceptors respectively.
	unaryInterceptors = append(unaryInterceptors, promUnaryInterceptors...)
	strmInterceptors = append(strmInterceptors, promStrmInterceptors...)

	// Create server options from the interceptors we just set up.
	chainedUnary := grpc_middleware.WithUnaryServerChain(
		unaryInterceptors...,
	)
	chainedStream := grpc_middleware.WithStreamServerChain(
		strmInterceptors...,
	)
	serverOpts := []grpc.ServerOption{chainedUnary, chainedStream}

	return serverOpts
}

// errorLogUnaryServerInterceptor is a simple UnaryServerInterceptor that will
// automatically log any errors that occur when serving a client's unary
// request.
func errorLogUnaryServerInterceptor(logger btclog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		resp, err := handler(ctx, req)
		if err != nil {
			// TODO(roasbeef): also log request details?
			logger.Errorf("[%v]: %v", info.FullMethod, err)
		}

		return resp, err
	}
}

// errorLogStreamServerInterceptor is a simple StreamServerInterceptor that
// will log any errors that occur while processing a client or server streaming
// RPC.
func errorLogStreamServerInterceptor(logger btclog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		err := handler(srv, ss)
		if err != nil {
			logger.Errorf("[%v]: %v", info.FullMethod, err)
		}

		return err
	}
}

// checkMacaroon validates that the context contains the macaroon needed to
// invoke the given RPC method.
func (r *InterceptorChain) checkMacaroon(ctx context.Context,
	fullMethod string) error {

	// If noMacaroons is set, we'll always allow the call.
	if r.noMacaroons {
		return nil
	}

	// Check whether the method is whitelisted, if so we'll allow it
	// regardless of macaroons.
	_, ok := macaroonWhitelist[fullMethod]
	if ok {
		return nil
	}

	r.RLock()
	svc := r.svc
	r.RUnlock()

	// If the macaroon service is not yet active, we cannot allow
	// the call.
	if svc == nil {
		return fmt.Errorf("unable to determine macaroon permissions")
	}

	r.RLock()
	uriPermissions, ok := r.permissionMap[fullMethod]
	r.RUnlock()
	if !ok {
		return fmt.Errorf("%s: unknown permissions required for method",
			fullMethod)
	}

	// Find out if there is an external validator registered for
	// this method. Fall back to the internal one if there isn't.
	validator, ok := svc.ExternalValidators[fullMethod]
	if !ok {
		validator = svc
	}

	// Now that we know what validator to use, let it do its work.
	return validator.ValidateMacaroon(ctx, uriPermissions, fullMethod)
}

// MacaroonUnaryServerInterceptor is a GRPC interceptor that checks whether the
// request is authorized by the included macaroons.
func (r *InterceptorChain) MacaroonUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		// Check macaroons.
		if err := r.checkMacaroon(ctx, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// MacaroonStreamServerInterceptor is a GRPC interceptor that checks whether
// the request is authorized by the included macaroons.
func (r *InterceptorChain) MacaroonStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		// Check macaroons.
		err := r.checkMacaroon(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

// checkRPCState checks whether a call to the given server is allowed in the
// current RPC state.
func (r *InterceptorChain) checkRPCState(srv interface{}) error {
	// The StateService is being accessed, we allow the call regardless of
	// the current state.
	_, ok := srv.(lnrpc.StateServer)
	if ok {
		return nil
	}

	r.RLock()
	state := r.state
	r.RUnlock()

	switch state {

	// Do not accept any RPC calls (unless to the state service) until LND
	// has not started.
	case waitingToStart:
		return ErrWaitingToStart

	// If the wallet does not exists, only calls to the WalletUnlocker are
	// accepted.
	case walletNotCreated:
		_, ok := srv.(lnrpc.WalletUnlockerServer)
		if !ok {
			return ErrNoWallet
		}

	// If the wallet is locked, only calls to the WalletUnlocker are
	// accepted.
	case walletLocked:
		_, ok := srv.(lnrpc.WalletUnlockerServer)
		if !ok {
			return ErrWalletLocked
		}

	// If the wallet is unlocked, but the RPC not yet active, we reject.
	case walletUnlocked:
		_, ok := srv.(lnrpc.WalletUnlockerServer)
		if ok {
			return ErrWalletUnlocked
		}

		return ErrRPCStarting

	// If the RPC is active, we allow calls to any service except the
	// WalletUnlocker.
	case rpcActive:
		_, ok := srv.(lnrpc.WalletUnlockerServer)
		if ok {
			return ErrWalletUnlocked
		}

	default:
		return fmt.Errorf("unknown RPC state: %v", state)
	}

	return nil
}

// rpcStateUnaryServerInterceptor is a GRPC interceptor that checks whether
// calls to the given gGRPC server is allowed in the current rpc state.
func (r *InterceptorChain) rpcStateUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		if err := r.checkRPCState(info.Server); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// rpcStateStreamServerInterceptor is a GRPC interceptor that checks whether
// calls to the given gGRPC server is allowed in the current rpc state.
func (r *InterceptorChain) rpcStateStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		if err := r.checkRPCState(srv); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}
