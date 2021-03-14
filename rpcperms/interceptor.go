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
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// rpcState is an enum that we use to keep track of the current RPC service
// state. This will transition as we go from startup to unlocking the wallet,
// and finally fully active.
type rpcState uint8

const (
	// walletNotCreated is the starting state if the RPC server is active,
	// but the wallet is not yet created. In this state we'll only allow
	// calls to the WalletUnlockerService.
	walletNotCreated rpcState = iota

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
	}
)

// InterceptorChain is a struct that can be added to the running GRPC server,
// intercepting API calls. This is useful for logging, enforcing permissions,
// supporting middleware etc. The following diagram shows the order of each
// interceptor in the chain and when exactly requests/responses are intercepted
// and forwarded to external middleware for approval/modification. Middleware in
// general can only intercept gRPC requests/responses that are sent by the
// client with a macaroon that contains a custom caveat that is supported by one
// of the registered middlewares.
//
//        |
//        | gRPC request from client
//        |
//    +---v--------------------------------+
//    |   InterceptorChain                 |
//    +-+----------------------------------+
//      | Log Interceptor                  |
//      +----------------------------------+
//      | RPC State Interceptor            |
//      +----------------------------------+
//      | Macaroon Interceptor             |
//      +----------------------------------+--------> +---------------------+
//      | RPC Macaroon Middleware Handler  |<-------- | External Middleware |
//      +----------------------------------+          |   - approve request |
//      | Prometheus Interceptor           |          +---------------------+
//      +-+--------------------------------+
//        | validated gRPC request from client
//    +---v--------------------------------+
//    |   main gRPC server                 |
//    +---+--------------------------------+
//        |
//        | original gRPC request to client
//        |
//    +---v--------------------------------+--------> +---------------------+
//    |   RPC Macaroon Middleware Handler  |<-------- | External Middleware |
//    +---+--------------------------------+          |   - modify response |
//        |                                           +---------------------+
//        | edited gRPC request to client
//        v
type InterceptorChain struct {
	// state is the current RPC state of our RPC server.
	state rpcState

	// noMacaroons should be set true if we don't want to check macaroons.
	noMacaroons bool

	// svc is the macaroon service used to enforce permissions in case
	// macaroons are used.
	svc *macaroons.Service

	// permissionMap is the permissions to enforce if macaroons are used.
	permissionMap map[string][]bakery.Op

	// rpcsLog is the logger used to log calles to the RPCs intercepted.
	rpcsLog btclog.Logger

	// registeredMiddleware is a map of all macaroon permission based RPC
	// middleware clients that are currently registered. The map is keyed
	// by the middleware's custom caveat name that it is handling.
	registeredMiddleware map[string]*MiddlewareHandler

	sync.RWMutex
}

// NewInterceptorChain creates a new InterceptorChain.
func NewInterceptorChain(log btclog.Logger, noMacaroons,
	walletExists bool) *InterceptorChain {

	startState := walletNotCreated
	if walletExists {
		startState = walletLocked
	}

	return &InterceptorChain{
		state:                startState,
		noMacaroons:          noMacaroons,
		permissionMap:        make(map[string][]bakery.Op),
		rpcsLog:              log,
		registeredMiddleware: make(map[string]*MiddlewareHandler),
	}
}

// SetWalletUnlocked moves the RPC state from either walletNotCreated or
// walletLocked to walletUnlocked.
func (r *InterceptorChain) SetWalletUnlocked() {
	r.Lock()
	defer r.Unlock()

	r.state = walletUnlocked
}

// SetRPCActive moves the RPC state from walletUnlocked to rpcActive.
func (r *InterceptorChain) SetRPCActive() {
	r.Lock()
	defer r.Unlock()

	r.state = rpcActive
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

// RegisterMiddleware registers a new middleware that will handle request/
// response interception for all RPC messages that are initiated with a custom
// macaroon caveat. The name of the custom caveat a middleware is handling is
// also its unique identifier. Only one middleware can be registered for each
// custom caveat.
func (r *InterceptorChain) RegisterMiddleware(mw *MiddlewareHandler) error {
	r.Lock()
	defer r.Unlock()

	// For now we only want one middleware per custom caveat name. If we
	// allowed multiple middlewares handling the same caveat there would be
	// a need for extra call chaining logic and they could overwrite each
	// other's responses.
	registered, ok := r.registeredMiddleware[mw.customCaveatName]
	if ok {
		return fmt.Errorf("a middleware is already registered for the "+
			"custom caveat name '%s': %v", mw.customCaveatName,
			registered.middlewareName)
	}

	r.registeredMiddleware[mw.customCaveatName] = mw

	return nil
}

// RemoveMiddleware removes the middleware that handles the given custom caveat
// name.
func (r *InterceptorChain) RemoveMiddleware(customCaveatName string) {
	r.Lock()
	defer r.Unlock()

	delete(r.registeredMiddleware, customCaveatName)
}

// CustomCaveatSupported makes sure a middleware that handles the given custom
// caveat name is registered. If none is, an error is returned, signalling to
// the macaroon bakery and its validator to reject macaroons that have a custom
// caveat with that name.
//
// NOTE: This method is part of the macaroons.CustomCaveatAcceptor interface.
func (r *InterceptorChain) CustomCaveatSupported(customCaveatName string) error {
	r.RLock()
	defer r.RUnlock()

	// We only accept requests with a custom caveat if we also have a
	// middleware registered that handles that custom caveat. That is
	// crucial for security! Otherwise a request with an encumbered (=has
	// restricted permissions based upon the custom caveat condition)
	// macaroon would not be validated against the limitations that the
	// custom caveat implicate.
	for _, middleware := range r.registeredMiddleware {
		if middleware.customCaveatName == customCaveatName {
			return nil
		}
	}

	return fmt.Errorf("cannot accept macaroon with custom caveat '%s', "+
		"no middleware registered to handle it", customCaveatName)
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

	// Next, we'll add the interceptors for our custom macaroon caveat based
	// middleware.
	unaryInterceptors = append(
		unaryInterceptors, r.middlewareUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, r.middlewareStreamServerInterceptor(),
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
	r.RLock()
	state := r.state
	r.RUnlock()

	switch state {

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

// middlewareUnaryServerInterceptor is an unary gRPC interceptor that intercepts
// all requests and responses that are send with a macaroon containing a custom
// caveat condition that is handled by registered middleware.
func (r *InterceptorChain) middlewareUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		msg, err := NewMessageInterceptionRequest(
			ctx, TypeRequest, false, info.FullMethod, req,
		)
		if err != nil {
			return nil, err
		}

		err = r.acceptRequest(msg)
		if err != nil {
			return nil, err
		}

		resp, respErr := handler(ctx, req)
		if respErr != nil {
			return resp, respErr
		}

		return r.interceptResponse(ctx, false, info.FullMethod, resp)
	}
}

// middlewareStreamServerInterceptor is a streaming gRPC interceptor that
// intercepts all requests and responses that are send with a macaroon
// containing a custom caveat condition that is handled by registered
// middleware.
func (r *InterceptorChain) middlewareStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{},
		ss grpc.ServerStream, info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {

		// Don't intercept the interceptor itself which is a streaming
		// RPC too!
		if info.FullMethod == lnrpc.RegisterRPCMiddlewareURI {
			return handler(srv, ss)
		}

		// To give the middleware a chance to accept or reject the
		// establishment of the stream itself (and not only when the
		// first message is sent on the stream), we send an intercept
		// request for the stream auth now:
		msg, err := NewStreamAuthInterceptionRequest(
			ss.Context(), info.FullMethod,
		)
		if err != nil {
			return err
		}

		err = r.acceptRequest(msg)
		if err != nil {
			return err
		}

		wrappedSS := &serverStreamWrapper{
			baseServerStream: ss,
			fullMethod:       info.FullMethod,
			interceptor:      r,
		}

		return handler(srv, wrappedSS)
	}
}

func (r *InterceptorChain) acceptRequest(msg *InterceptionRequest) error {
	r.RLock()
	defer r.RUnlock()

	// TODO(guggero): Check if macaroon actually has any custom macaroons
	// and only forward to the middleware that handles those caveats.

	for _, middleware := range r.registeredMiddleware {
		resp, err := middleware.intercept(msg)

		// Error during interception itself.
		if err != nil {
			return err
		}

		// Error returned from middleware client.
		if resp.err != nil {
			return resp.err
		}
	}

	return nil
}

func (r *InterceptorChain) interceptResponse(ctx context.Context,
	isStream bool, fullMethod string, m interface{}) (interface{}, error) {

	msg, err := NewMessageInterceptionRequest(
		ctx, TypeResponse, isStream, fullMethod, m,
	)
	if err != nil {
		return nil, err
	}

	r.RLock()
	defer r.RUnlock()

	// TODO(guggero): Check if macaroon actually has any custom macaroons
	// and only forward to the middleware that handles those caveats.

	for _, middleware := range r.registeredMiddleware {
		resp, err := middleware.intercept(msg)

		// Error during interception itself.
		if err != nil {
			return nil, err
		}

		// Error returned from middleware client.
		if resp.err != nil {
			return nil, resp.err
		}

		if resp.replace {
			return resp.replacement, nil
		}
	}

	return m, nil
}

type serverStreamWrapper struct {
	baseServerStream grpc.ServerStream

	fullMethod string

	interceptor *InterceptorChain
}

func (w *serverStreamWrapper) SetHeader(md metadata.MD) error {
	return w.baseServerStream.SetHeader(md)
}

func (w *serverStreamWrapper) SendHeader(md metadata.MD) error {
	return w.baseServerStream.SendHeader(md)
}

func (w *serverStreamWrapper) SetTrailer(md metadata.MD) {
	w.baseServerStream.SetTrailer(md)
}

func (w *serverStreamWrapper) Context() context.Context {
	return w.baseServerStream.Context()
}

func (w *serverStreamWrapper) SendMsg(m interface{}) error {
	newMsg, err := w.interceptor.interceptResponse(
		w.baseServerStream.Context(), true, w.fullMethod, m,
	)
	if err != nil {
		return err
	}

	return w.baseServerStream.SendMsg(newMsg)
}

func (w *serverStreamWrapper) RecvMsg(m interface{}) error {
	err := w.baseServerStream.RecvMsg(m)
	if err != nil {
		return err
	}

	msg, err := NewMessageInterceptionRequest(
		w.baseServerStream.Context(), TypeRequest, true, w.fullMethod,
		m,
	)
	if err != nil {
		return err
	}

	return w.interceptor.acceptRequest(msg)
}
