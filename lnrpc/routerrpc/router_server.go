package routerrpc

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/routing/route"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// subServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize as the name of our
	subServerName = "RouterRPC"
)

var (
	errServerShuttingDown = errors.New("routerrpc server shutting down")

	// ErrInterceptorAlreadyExists is an error returned when the a new stream
	// is opened and there is already one active interceptor.
	// The user must disconnect prior to open another stream.
	ErrInterceptorAlreadyExists = errors.New("interceptor already exists")

	// macaroonOps are the set of capabilities that our minted macaroon (if
	// it doesn't already exist) will have.
	macaroonOps = []bakery.Op{
		{
			Entity: "offchain",
			Action: "read",
		},
		{
			Entity: "offchain",
			Action: "write",
		},
	}

	// macPermissions maps RPC calls to the permissions they require.
	macPermissions = map[string][]bakery.Op{
		"/routerrpc.Router/SendPaymentV2": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/SendToRouteV2": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/SendToRoute": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/TrackPaymentV2": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/EstimateRouteFee": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/QueryMissionControl": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/XImportMissionControl": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/GetMissionControlConfig": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/SetMissionControlConfig": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/QueryProbability": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/ResetMissionControl": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/BuildRoute": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/SubscribeHtlcEvents": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/SendPayment": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/TrackPayment": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/routerrpc.Router/HtlcInterceptor": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/routerrpc.Router/UpdateChanStatus": {{
			Entity: "offchain",
			Action: "write",
		}},
	}

	// DefaultRouterMacFilename is the default name of the router macaroon
	// that we expect to find via a file handle within the main
	// configuration file in this package.
	DefaultRouterMacFilename = "router.macaroon"
)

// ServerShell a is shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	RouterServer
}

// Server is a stand alone sub RPC server which exposes functionality that
// allows clients to route arbitrary payment through the Lightning Network.
type Server struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedRouterServer

	started                  int32 // To be used atomically.
	shutdown                 int32 // To be used atomically.
	forwardInterceptorActive int32 // To be used atomically.

	cfg *Config

	quit chan struct{}
}

// A compile time check to ensure that Server fully implements the RouterServer
// gRPC service.
var _ RouterServer = (*Server)(nil)

// New creates a new instance of the RouterServer given a configuration struct
// that contains all external dependencies. If the target macaroon exists, and
// we're unable to create it, then an error will be returned. We also return
// the set of permissions that we require as a server. At the time of writing
// of this documentation, this is the same macaroon as as the admin macaroon.
func New(cfg *Config) (*Server, lnrpc.MacaroonPerms, error) {
	// If the path of the router macaroon wasn't generated, then we'll
	// assume that it's found at the default network directory.
	if cfg.RouterMacPath == "" {
		cfg.RouterMacPath = filepath.Join(
			cfg.NetworkDir, DefaultRouterMacFilename,
		)
	}

	// Now that we know the full path of the router macaroon, we can check
	// to see if we need to create it or not. If stateless_init is set
	// then we don't write the macaroons.
	macFilePath := cfg.RouterMacPath
	if cfg.MacService != nil && !cfg.MacService.StatelessInit &&
		!lnrpc.FileExists(macFilePath) {

		log.Infof("Making macaroons for Router RPC Server at: %v",
			macFilePath)

		// At this point, we know that the router macaroon doesn't yet,
		// exist, so we need to create it with the help of the main
		// macaroon service.
		routerMac, err := cfg.MacService.NewMacaroon(
			context.Background(), macaroons.DefaultRootKeyID,
			macaroonOps...,
		)
		if err != nil {
			return nil, nil, err
		}
		routerMacBytes, err := routerMac.M().MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		err = ioutil.WriteFile(macFilePath, routerMacBytes, 0644)
		if err != nil {
			_ = os.Remove(macFilePath)
			return nil, nil, err
		}
	}

	routerServer := &Server{
		cfg:  cfg,
		quit: make(chan struct{}),
	}

	return routerServer, macPermissions, nil
}

// Start launches any helper goroutines required for the rpcServer to function.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Start() error {
	if atomic.AddInt32(&s.started, 1) != 1 {
		return nil
	}

	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Stop() error {
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		return nil
	}

	close(s.quit)
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
	// We make sure that we register it with the main gRPC server to ensure
	// all our methods are routed properly.
	RegisterRouterServer(grpcServer, r)

	log.Debugf("Router RPC server successfully register with root gRPC " +
		"server")

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
	err := RegisterRouterHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register Router REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("Router REST server successfully registered with " +
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

	r.RouterServer = subServer
	return subServer, macPermissions, nil
}

// SendPaymentV2 attempts to route a payment described by the passed
// PaymentRequest to the final destination. If we are unable to route the
// payment, or cannot find a route that satisfies the constraints in the
// PaymentRequest, then an error will be returned. Otherwise, the payment
// pre-image, along with the final route will be returned.
func (s *Server) SendPaymentV2(req *SendPaymentRequest,
	stream Router_SendPaymentV2Server) error {

	payment, err := s.cfg.RouterBackend.extractIntentFromSendRequest(req)
	if err != nil {
		return err
	}

	err = s.cfg.Router.SendPaymentAsync(payment)
	if err != nil {
		// Transform user errors to grpc code.
		if err == channeldb.ErrPaymentInFlight ||
			err == channeldb.ErrAlreadyPaid {

			log.Debugf("SendPayment async result for payment %x: %v",
				payment.Identifier(), err)

			return status.Error(
				codes.AlreadyExists, err.Error(),
			)
		}

		log.Errorf("SendPayment async error for payment %x: %v",
			payment.Identifier(), err)

		return err
	}

	return s.trackPayment(payment.Identifier(), stream, req.NoInflightUpdates)
}

// EstimateRouteFee allows callers to obtain a lower bound w.r.t how much it
// may cost to send an HTLC to the target end destination.
func (s *Server) EstimateRouteFee(ctx context.Context,
	req *RouteFeeRequest) (*RouteFeeResponse, error) {

	if len(req.Dest) != 33 {
		return nil, errors.New("invalid length destination key")
	}
	var destNode route.Vertex
	copy(destNode[:], req.Dest)

	// Next, we'll convert the amount in satoshis to mSAT, which are the
	// native unit of LN.
	amtMsat := lnwire.NewMSatFromSatoshis(btcutil.Amount(req.AmtSat))

	// Pick a fee limit
	//
	// TODO: Change this into behaviour that makes more sense.
	feeLimit := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin)

	// Finally, we'll query for a route to the destination that can carry
	// that target amount, we'll only request a single route. Set a
	// restriction for the default CLTV limit, otherwise we can find a route
	// that exceeds it and is useless to us.
	mc := s.cfg.RouterBackend.MissionControl
	route, err := s.cfg.Router.FindRoute(
		s.cfg.RouterBackend.SelfNode, destNode, amtMsat,
		&routing.RestrictParams{
			FeeLimit:          feeLimit,
			CltvLimit:         s.cfg.RouterBackend.MaxTotalTimelock,
			ProbabilitySource: mc.GetProbability,
		}, nil, nil, s.cfg.RouterBackend.DefaultFinalCltvDelta,
	)
	if err != nil {
		return nil, err
	}

	return &RouteFeeResponse{
		RoutingFeeMsat: int64(route.TotalFees()),
		TimeLockDelay:  int64(route.TotalTimeLock),
	}, nil
}

// SendToRouteV2 sends a payment through a predefined route. The response of this
// call contains structured error information.
func (s *Server) SendToRouteV2(ctx context.Context,
	req *SendToRouteRequest) (*lnrpc.HTLCAttempt, error) {

	if req.Route == nil {
		return nil, fmt.Errorf("unable to send, no routes provided")
	}

	route, err := s.cfg.RouterBackend.UnmarshallRoute(req.Route)
	if err != nil {
		return nil, err
	}

	hash, err := lntypes.MakeHash(req.PaymentHash)
	if err != nil {
		return nil, err
	}

	// Pass route to the router. This call returns the full htlc attempt
	// information as it is stored in the database. It is possible that both
	// the attempt return value and err are non-nil. This can happen when
	// the attempt was already initiated before the error happened. In that
	// case, we give precedence to the attempt information as stored in the
	// db.
	attempt, err := s.cfg.Router.SendToRoute(hash, route)
	if attempt != nil {
		rpcAttempt, err := s.cfg.RouterBackend.MarshalHTLCAttempt(
			*attempt,
		)
		if err != nil {
			return nil, err
		}
		return rpcAttempt, nil
	}

	// Transform user errors to grpc code.
	if err == channeldb.ErrPaymentInFlight ||
		err == channeldb.ErrAlreadyPaid {

		return nil, status.Error(codes.AlreadyExists, err.Error())
	}

	return nil, err
}

// ResetMissionControl clears all mission control state and starts with a clean
// slate.
func (s *Server) ResetMissionControl(ctx context.Context,
	req *ResetMissionControlRequest) (*ResetMissionControlResponse, error) {

	err := s.cfg.RouterBackend.MissionControl.ResetHistory()
	if err != nil {
		return nil, err
	}

	return &ResetMissionControlResponse{}, nil
}

// GetMissionControlConfig returns our current mission control config.
func (s *Server) GetMissionControlConfig(ctx context.Context,
	req *GetMissionControlConfigRequest) (*GetMissionControlConfigResponse,
	error) {

	cfg := s.cfg.RouterBackend.MissionControl.GetConfig()
	return &GetMissionControlConfigResponse{
		Config: &MissionControlConfig{
			HalfLifeSeconds:             uint64(cfg.PenaltyHalfLife.Seconds()),
			HopProbability:              float32(cfg.AprioriHopProbability),
			Weight:                      float32(cfg.AprioriWeight),
			MaximumPaymentResults:       uint32(cfg.MaxMcHistory),
			MinimumFailureRelaxInterval: uint64(cfg.MinFailureRelaxInterval.Seconds()),
		},
	}, nil
}

// SetMissionControlConfig returns our current mission control config.
func (s *Server) SetMissionControlConfig(ctx context.Context,
	req *SetMissionControlConfigRequest) (*SetMissionControlConfigResponse,
	error) {

	cfg := &routing.MissionControlConfig{
		ProbabilityEstimatorCfg: routing.ProbabilityEstimatorCfg{
			PenaltyHalfLife: time.Duration(
				req.Config.HalfLifeSeconds,
			) * time.Second,
			AprioriHopProbability: float64(req.Config.HopProbability),
			AprioriWeight:         float64(req.Config.Weight),
		},
		MaxMcHistory: int(req.Config.MaximumPaymentResults),
		MinFailureRelaxInterval: time.Duration(
			req.Config.MinimumFailureRelaxInterval,
		) * time.Second,
	}

	return &SetMissionControlConfigResponse{},
		s.cfg.RouterBackend.MissionControl.SetConfig(cfg)
}

// QueryMissionControl exposes the internal mission control state to callers. It
// is a development feature.
func (s *Server) QueryMissionControl(ctx context.Context,
	req *QueryMissionControlRequest) (*QueryMissionControlResponse, error) {

	snapshot := s.cfg.RouterBackend.MissionControl.GetHistorySnapshot()

	rpcPairs := make([]*PairHistory, 0, len(snapshot.Pairs))
	for _, p := range snapshot.Pairs {
		// Prevent binding to loop variable.
		pair := p

		rpcPair := PairHistory{
			NodeFrom: pair.Pair.From[:],
			NodeTo:   pair.Pair.To[:],
			History:  toRPCPairData(&pair.TimedPairResult),
		}

		rpcPairs = append(rpcPairs, &rpcPair)
	}

	response := QueryMissionControlResponse{
		Pairs: rpcPairs,
	}

	return &response, nil
}

// toRPCPairData marshalls mission control pair data to the rpc struct.
func toRPCPairData(data *routing.TimedPairResult) *PairData {
	rpcData := PairData{
		FailAmtSat:     int64(data.FailAmt.ToSatoshis()),
		FailAmtMsat:    int64(data.FailAmt),
		SuccessAmtSat:  int64(data.SuccessAmt.ToSatoshis()),
		SuccessAmtMsat: int64(data.SuccessAmt),
	}

	if !data.FailTime.IsZero() {
		rpcData.FailTime = data.FailTime.Unix()
	}

	if !data.SuccessTime.IsZero() {
		rpcData.SuccessTime = data.SuccessTime.Unix()
	}

	return &rpcData
}

// XImportMissionControl imports the state provided to our internal mission
// control. Only entries that are fresher than our existing state will be used.
func (s *Server) XImportMissionControl(ctx context.Context,
	req *XImportMissionControlRequest) (*XImportMissionControlResponse,
	error) {

	if len(req.Pairs) == 0 {
		return nil, errors.New("at least one pair required for import")
	}

	snapshot := &routing.MissionControlSnapshot{
		Pairs: make(
			[]routing.MissionControlPairSnapshot, len(req.Pairs),
		),
	}

	for i, pairResult := range req.Pairs {
		pairSnapshot, err := toPairSnapshot(pairResult)
		if err != nil {
			return nil, err
		}

		snapshot.Pairs[i] = *pairSnapshot
	}

	err := s.cfg.RouterBackend.MissionControl.ImportHistory(snapshot)
	if err != nil {
		return nil, err
	}

	return &XImportMissionControlResponse{}, nil
}

func toPairSnapshot(pairResult *PairHistory) (*routing.MissionControlPairSnapshot,
	error) {

	from, err := route.NewVertexFromBytes(pairResult.NodeFrom)
	if err != nil {
		return nil, err
	}

	to, err := route.NewVertexFromBytes(pairResult.NodeTo)
	if err != nil {
		return nil, err
	}

	pairPrefix := fmt.Sprintf("pair: %v -> %v:", from, to)

	if from == to {
		return nil, fmt.Errorf("%v source and destination node must "+
			"differ", pairPrefix)
	}

	failAmt, failTime, err := getPair(
		lnwire.MilliSatoshi(pairResult.History.FailAmtMsat),
		btcutil.Amount(pairResult.History.FailAmtSat),
		pairResult.History.FailTime,
	)
	if err != nil {
		return nil, fmt.Errorf("%v invalid failure: %v", pairPrefix,
			err)
	}

	successAmt, successTime, err := getPair(
		lnwire.MilliSatoshi(pairResult.History.SuccessAmtMsat),
		btcutil.Amount(pairResult.History.SuccessAmtSat),
		pairResult.History.SuccessTime,
	)
	if err != nil {
		return nil, fmt.Errorf("%v invalid success: %v", pairPrefix,
			err)
	}

	if successAmt == 0 && failAmt == 0 {
		return nil, fmt.Errorf("%v: either success or failure result "+
			"required", pairPrefix)
	}

	pair := routing.NewDirectedNodePair(from, to)

	result := &routing.TimedPairResult{
		FailAmt:     failAmt,
		FailTime:    failTime,
		SuccessAmt:  successAmt,
		SuccessTime: successTime,
	}

	return &routing.MissionControlPairSnapshot{
		Pair:            pair,
		TimedPairResult: *result,
	}, nil
}

// getPair validates the values provided for a mission control result and
// returns the msat amount and timestamp for it.
func getPair(amtMsat lnwire.MilliSatoshi, amtSat btcutil.Amount,
	timestamp int64) (lnwire.MilliSatoshi, time.Time, error) {

	amt, err := getMsatPairValue(amtMsat, amtSat)
	if err != nil {
		return 0, time.Time{}, err
	}

	var (
		timeSet   = timestamp != 0
		amountSet = amt != 0
	)

	switch {
	case timeSet && amountSet:
		return amt, time.Unix(timestamp, 0), nil

	case timeSet && !amountSet:
		return 0, time.Time{}, errors.New("non-zero timestamp " +
			"requires non-zero amount")

	case !timeSet && amountSet:
		return 0, time.Time{}, errors.New("non-zero amount requires " +
			"non-zero timestamp")

	default:
		return 0, time.Time{}, nil
	}
}

// getMsatPairValue checks the msat and sat values set for a pair and ensures
// that the values provided are either the same, or only a single value is set.
func getMsatPairValue(msatValue lnwire.MilliSatoshi,
	satValue btcutil.Amount) (lnwire.MilliSatoshi, error) {

	// If our msat value converted to sats equals our sat value, we just
	// return the msat value, since the values are the same.
	if msatValue.ToSatoshis() == satValue {
		return msatValue, nil
	}

	// If we have no msatValue, we can just return our sate value even if
	// it is zero, because it's impossible that we have mismatched values.
	if msatValue == 0 {
		return lnwire.MilliSatoshi(satValue * 1000), nil
	}

	// Likewise, we can just use msat value if we have no sat value set.
	if satValue == 0 {
		return msatValue, nil
	}

	// If our values are non-zero but not equal, we have invalid amounts
	// set, so we fail.
	return 0, fmt.Errorf("msat: %v and sat: %v values not equal", msatValue,
		satValue)
}

// QueryProbability returns the current success probability estimate for a
// given node pair and amount.
func (s *Server) QueryProbability(ctx context.Context,
	req *QueryProbabilityRequest) (*QueryProbabilityResponse, error) {

	fromNode, err := route.NewVertexFromBytes(req.FromNode)
	if err != nil {
		return nil, err
	}

	toNode, err := route.NewVertexFromBytes(req.ToNode)
	if err != nil {
		return nil, err
	}

	amt := lnwire.MilliSatoshi(req.AmtMsat)

	mc := s.cfg.RouterBackend.MissionControl
	prob := mc.GetProbability(fromNode, toNode, amt)
	history := mc.GetPairHistorySnapshot(fromNode, toNode)

	return &QueryProbabilityResponse{
		Probability: prob,
		History:     toRPCPairData(&history),
	}, nil
}

// TrackPaymentV2 returns a stream of payment state updates. The stream is
// closed when the payment completes.
func (s *Server) TrackPaymentV2(request *TrackPaymentRequest,
	stream Router_TrackPaymentV2Server) error {

	paymentHash, err := lntypes.MakeHash(request.PaymentHash)
	if err != nil {
		return err
	}

	log.Debugf("TrackPayment called for payment %v", paymentHash)

	return s.trackPayment(paymentHash, stream, request.NoInflightUpdates)
}

// trackPayment writes payment status updates to the provided stream.
func (s *Server) trackPayment(identifier lntypes.Hash,
	stream Router_TrackPaymentV2Server, noInflightUpdates bool) error {

	router := s.cfg.RouterBackend

	// Subscribe to the outcome of this payment.
	subscription, err := router.Tower.SubscribePayment(
		identifier,
	)
	switch {
	case err == channeldb.ErrPaymentNotInitiated:
		return status.Error(codes.NotFound, err.Error())
	case err != nil:
		return err
	}
	defer subscription.Close()

	// Stream updates back to the client. The first update is always the
	// current state of the payment.
	for {
		select {
		case item, ok := <-subscription.Updates:
			if !ok {
				// No more payment updates.
				return nil
			}
			result := item.(*channeldb.MPPayment)

			// Skip in-flight updates unless requested.
			if noInflightUpdates &&
				result.Status == channeldb.StatusInFlight {

				continue
			}

			rpcPayment, err := router.MarshallPayment(result)
			if err != nil {
				return err
			}

			// Send event to the client.
			err = stream.Send(rpcPayment)
			if err != nil {
				return err
			}

		case <-s.quit:
			return errServerShuttingDown

		case <-stream.Context().Done():
			log.Debugf("Payment status stream %v canceled", identifier)
			return stream.Context().Err()
		}
	}
}

// BuildRoute builds a route from a list of hop addresses.
func (s *Server) BuildRoute(ctx context.Context,
	req *BuildRouteRequest) (*BuildRouteResponse, error) {

	// Unmarshall hop list.
	hops := make([]route.Vertex, len(req.HopPubkeys))
	for i, pubkeyBytes := range req.HopPubkeys {
		pubkey, err := route.NewVertexFromBytes(pubkeyBytes)
		if err != nil {
			return nil, err
		}
		hops[i] = pubkey
	}

	// Prepare BuildRoute call parameters from rpc request.
	var amt *lnwire.MilliSatoshi
	if req.AmtMsat != 0 {
		rpcAmt := lnwire.MilliSatoshi(req.AmtMsat)
		amt = &rpcAmt
	}

	var outgoingChan *uint64
	if req.OutgoingChanId != 0 {
		outgoingChan = &req.OutgoingChanId
	}

	var payAddr *[32]byte
	if len(req.PaymentAddr) != 0 {
		var backingPayAddr [32]byte
		copy(backingPayAddr[:], req.PaymentAddr)

		payAddr = &backingPayAddr
	}

	// Build the route and return it to the caller.
	route, err := s.cfg.Router.BuildRoute(
		amt, hops, outgoingChan, req.FinalCltvDelta, payAddr,
	)
	if err != nil {
		return nil, err
	}

	rpcRoute, err := s.cfg.RouterBackend.MarshallRoute(route)
	if err != nil {
		return nil, err
	}

	routeResp := &BuildRouteResponse{
		Route: rpcRoute,
	}

	return routeResp, nil
}

// SubscribeHtlcEvents creates a uni-directional stream from the server to
// the client which delivers a stream of htlc events.
func (s *Server) SubscribeHtlcEvents(req *SubscribeHtlcEventsRequest,
	stream Router_SubscribeHtlcEventsServer) error {

	htlcClient, err := s.cfg.RouterBackend.SubscribeHtlcEvents()
	if err != nil {
		return err
	}
	defer htlcClient.Cancel()

	for {
		select {
		case event := <-htlcClient.Updates():
			rpcEvent, err := rpcHtlcEvent(event)
			if err != nil {
				return err
			}

			if err := stream.Send(rpcEvent); err != nil {
				return err
			}

		// If the stream's context is cancelled, return an error.
		case <-stream.Context().Done():
			log.Debugf("htlc event stream cancelled")
			return stream.Context().Err()

		// If the subscribe client terminates, exit with an error.
		case <-htlcClient.Quit():
			return errors.New("htlc event subscription terminated")

		// If the server has been signalled to shut down, exit.
		case <-s.quit:
			return errServerShuttingDown
		}
	}
}

// HtlcInterceptor is a bidirectional stream for streaming interception
// requests to the caller.
// Upon connection it does the following:
// 1. Check if there is already a live stream, if yes it rejects the request.
// 2. Regsitered a ForwardInterceptor
// 3. Delivers to the caller every √√ and detect his answer.
// It uses a local implementation of holdForwardsStore to keep all the hold
// forwards and find them when manual resolution is later needed.
func (s *Server) HtlcInterceptor(stream Router_HtlcInterceptorServer) error {
	// We ensure there is only one interceptor at a time.
	if !atomic.CompareAndSwapInt32(&s.forwardInterceptorActive, 0, 1) {
		return ErrInterceptorAlreadyExists
	}
	defer atomic.CompareAndSwapInt32(&s.forwardInterceptorActive, 1, 0)

	// run the forward interceptor.
	return newForwardInterceptor(s, stream).run()
}

func extractOutPoint(req *UpdateChanStatusRequest) (*wire.OutPoint, error) {
	chanPoint := req.GetChanPoint()
	txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
	if err != nil {
		return nil, err
	}
	index := chanPoint.OutputIndex
	return wire.NewOutPoint(txid, index), nil
}

// UpdateChanStatus allows channel state to be set manually.
func (s *Server) UpdateChanStatus(ctx context.Context,
	req *UpdateChanStatusRequest) (*UpdateChanStatusResponse, error) {

	outPoint, err := extractOutPoint(req)
	if err != nil {
		return nil, err
	}

	action := req.GetAction()

	log.Debugf("UpdateChanStatus called for channel(%v) with "+
		"action %v", outPoint, action)

	switch action {
	case ChanStatusAction_ENABLE:
		err = s.cfg.RouterBackend.SetChannelEnabled(*outPoint)
	case ChanStatusAction_DISABLE:
		err = s.cfg.RouterBackend.SetChannelDisabled(*outPoint)
	case ChanStatusAction_AUTO:
		err = s.cfg.RouterBackend.SetChannelAuto(*outPoint)
	default:
		err = fmt.Errorf("unrecognized ChannelStatusAction %v", action)
	}

	if err != nil {
		return nil, err
	}
	return &UpdateChanStatusResponse{}, nil
}
