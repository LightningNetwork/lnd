package wtclientrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/btcsuite/btcd/btcec"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower"
	"github.com/lightningnetwork/lnd/watchtower/wtclient"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// subServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognizes it as the name of our
	// RPC service.
	subServerName = "WatchtowerClientRPC"
)

var (
	// macPermissions maps RPC calls to the permissions they require.
	//
	// TODO(wilmer): create tower macaroon?
	macPermissions = map[string][]bakery.Op{
		"/wtclientrpc.WatchtowerClient/AddTower": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/wtclientrpc.WatchtowerClient/RemoveTower": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/wtclientrpc.WatchtowerClient/ListTowers": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/wtclientrpc.WatchtowerClient/GetTowerInfo": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/wtclientrpc.WatchtowerClient/Stats": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/wtclientrpc.WatchtowerClient/Policy": {{
			Entity: "offchain",
			Action: "read",
		}},
	}

	// ErrWtclientNotActive signals that RPC calls cannot be processed
	// because the watchtower client is not active.
	ErrWtclientNotActive = errors.New("watchtower client not active")
)

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	WatchtowerClientServer
}

// WatchtowerClient is the RPC server we'll use to interact with the backing
// active watchtower client.
//
// TODO(wilmer): better name?
type WatchtowerClient struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedWatchtowerClientServer

	cfg Config
}

// A compile time check to ensure that WatchtowerClient fully implements the
// WatchtowerClientWatchtowerClient gRPC service.
var _ WatchtowerClientServer = (*WatchtowerClient)(nil)

// New returns a new instance of the wtclientrpc WatchtowerClient sub-server.
// We also return the set of permissions for the macaroons that we may create
// within this method. If the macaroons we need aren't found in the filepath,
// then we'll create them on start up. If we're unable to locate, or create the
// macaroons we need, then we'll return with an error.
func New(cfg *Config) (*WatchtowerClient, lnrpc.MacaroonPerms, error) {
	return &WatchtowerClient{cfg: *cfg}, macPermissions, nil
}

// Start launches any helper goroutines required for the WatchtowerClient to
// function.
//
// NOTE: This is part of the lnrpc.SubWatchtowerClient interface.
func (c *WatchtowerClient) Start() error {
	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (c *WatchtowerClient) Stop() error {
	return nil
}

// Name returns a unique string representation of the sub-server. This can be
// used to identify the sub-server and also de-duplicate them.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (c *WatchtowerClient) Name() string {
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
	RegisterWatchtowerClientServer(grpcServer, r)

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
	err := RegisterWatchtowerClientHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		return err
	}

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

	r.WatchtowerClientServer = subServer
	return subServer, macPermissions, nil
}

// isActive returns nil if the watchtower client is initialized so that we can
// process RPC requests.
func (c *WatchtowerClient) isActive() error {
	if c.cfg.Active {
		return nil
	}
	return ErrWtclientNotActive
}

// AddTower adds a new watchtower reachable at the given address and considers
// it for new sessions. If the watchtower already exists, then any new addresses
// included will be considered when dialing it for session negotiations and
// backups.
func (c *WatchtowerClient) AddTower(ctx context.Context,
	req *AddTowerRequest) (*AddTowerResponse, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	pubKey, err := btcec.ParsePubKey(req.Pubkey, btcec.S256())
	if err != nil {
		return nil, err
	}
	addr, err := lncfg.ParseAddressString(
		req.Address, strconv.Itoa(watchtower.DefaultPeerPort),
		c.cfg.Resolver,
	)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", req.Address, err)
	}

	towerAddr := &lnwire.NetAddress{
		IdentityKey: pubKey,
		Address:     addr,
	}

	// TODO(conner): make atomic via multiplexed client
	if err := c.cfg.Client.AddTower(towerAddr); err != nil {
		return nil, err
	}
	if err := c.cfg.AnchorClient.AddTower(towerAddr); err != nil {
		return nil, err
	}

	return &AddTowerResponse{}, nil
}

// RemoveTower removes a watchtower from being considered for future session
// negotiations and from being used for any subsequent backups until it's added
// again. If an address is provided, then this RPC only serves as a way of
// removing the address from the watchtower instead.
func (c *WatchtowerClient) RemoveTower(ctx context.Context,
	req *RemoveTowerRequest) (*RemoveTowerResponse, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	pubKey, err := btcec.ParsePubKey(req.Pubkey, btcec.S256())
	if err != nil {
		return nil, err
	}

	var addr net.Addr
	if req.Address != "" {
		addr, err = lncfg.ParseAddressString(
			req.Address, strconv.Itoa(watchtower.DefaultPeerPort),
			c.cfg.Resolver,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse tower "+
				"address %v: %v", req.Address, err)
		}
	}

	// TODO(conner): make atomic via multiplexed client
	err = c.cfg.Client.RemoveTower(pubKey, addr)
	if err != nil {
		return nil, err
	}
	err = c.cfg.AnchorClient.RemoveTower(pubKey, addr)
	if err != nil {
		return nil, err
	}

	return &RemoveTowerResponse{}, nil
}

// ListTowers returns the list of watchtowers registered with the client.
func (c *WatchtowerClient) ListTowers(ctx context.Context,
	req *ListTowersRequest) (*ListTowersResponse, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	anchorTowers, err := c.cfg.AnchorClient.RegisteredTowers()
	if err != nil {
		return nil, err
	}

	legacyTowers, err := c.cfg.Client.RegisteredTowers()
	if err != nil {
		return nil, err
	}

	// Filter duplicates.
	towers := make(map[wtdb.TowerID]*wtclient.RegisteredTower)
	for _, tower := range anchorTowers {
		towers[tower.Tower.ID] = tower
	}
	for _, tower := range legacyTowers {
		towers[tower.Tower.ID] = tower
	}

	rpcTowers := make([]*Tower, 0, len(towers))
	for _, tower := range towers {
		rpcTower := marshallTower(tower, req.IncludeSessions)
		rpcTowers = append(rpcTowers, rpcTower)
	}

	return &ListTowersResponse{Towers: rpcTowers}, nil
}

// GetTowerInfo retrieves information for a registered watchtower.
func (c *WatchtowerClient) GetTowerInfo(ctx context.Context,
	req *GetTowerInfoRequest) (*Tower, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	pubKey, err := btcec.ParsePubKey(req.Pubkey, btcec.S256())
	if err != nil {
		return nil, err
	}

	var tower *wtclient.RegisteredTower
	tower, err = c.cfg.Client.LookupTower(pubKey)
	if err == wtdb.ErrTowerNotFound {
		tower, err = c.cfg.AnchorClient.LookupTower(pubKey)
	}
	if err != nil {
		return nil, err
	}

	return marshallTower(tower, req.IncludeSessions), nil
}

// Stats returns the in-memory statistics of the client since startup.
func (c *WatchtowerClient) Stats(ctx context.Context,
	req *StatsRequest) (*StatsResponse, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	clientStats := []wtclient.ClientStats{
		c.cfg.Client.Stats(),
		c.cfg.AnchorClient.Stats(),
	}

	var stats wtclient.ClientStats
	for i := range clientStats {
		// Grab a reference to the slice index rather than copying bc
		// ClientStats contains a lock which cannot be copied by value.
		stat := &clientStats[i]

		stats.NumTasksAccepted += stat.NumTasksAccepted
		stats.NumTasksIneligible += stat.NumTasksIneligible
		stats.NumTasksPending += stat.NumTasksPending
		stats.NumSessionsAcquired += stat.NumSessionsAcquired
		stats.NumSessionsExhausted += stat.NumSessionsExhausted
	}

	return &StatsResponse{
		NumBackups:           uint32(stats.NumTasksAccepted),
		NumFailedBackups:     uint32(stats.NumTasksIneligible),
		NumPendingBackups:    uint32(stats.NumTasksPending),
		NumSessionsAcquired:  uint32(stats.NumSessionsAcquired),
		NumSessionsExhausted: uint32(stats.NumSessionsExhausted),
	}, nil
}

// Policy returns the active watchtower client policy configuration.
func (c *WatchtowerClient) Policy(ctx context.Context,
	req *PolicyRequest) (*PolicyResponse, error) {

	if err := c.isActive(); err != nil {
		return nil, err
	}

	var policy wtpolicy.Policy
	switch req.PolicyType {
	case PolicyType_LEGACY:
		policy = c.cfg.Client.Policy()
	case PolicyType_ANCHOR:
		policy = c.cfg.AnchorClient.Policy()
	default:
		return nil, fmt.Errorf("unknown policy type: %v",
			req.PolicyType)
	}

	return &PolicyResponse{
		MaxUpdates: uint32(policy.MaxUpdates),
		SweepSatPerVbyte: uint32(
			policy.SweepFeeRate.FeePerKVByte() / 1000,
		),

		// Deprecated field.
		SweepSatPerByte: uint32(
			policy.SweepFeeRate.FeePerKVByte() / 1000,
		),
	}, nil
}

// marshallTower converts a client registered watchtower into its corresponding
// RPC type.
func marshallTower(tower *wtclient.RegisteredTower, includeSessions bool) *Tower {
	rpcAddrs := make([]string, 0, len(tower.Addresses))
	for _, addr := range tower.Addresses {
		rpcAddrs = append(rpcAddrs, addr.String())
	}

	var rpcSessions []*TowerSession
	if includeSessions {
		rpcSessions = make([]*TowerSession, 0, len(tower.Sessions))
		for _, session := range tower.Sessions {
			satPerVByte := session.Policy.SweepFeeRate.FeePerKVByte() / 1000
			rpcSessions = append(rpcSessions, &TowerSession{
				NumBackups:        uint32(len(session.AckedUpdates)),
				NumPendingBackups: uint32(len(session.CommittedUpdates)),
				MaxBackups:        uint32(session.Policy.MaxUpdates),
				SweepSatPerVbyte:  uint32(satPerVByte),

				// Deprecated field.
				SweepSatPerByte: uint32(satPerVByte),
			})
		}
	}

	return &Tower{
		Pubkey:                 tower.IdentityKey.SerializeCompressed(),
		Addresses:              rpcAddrs,
		ActiveSessionCandidate: tower.ActiveSessionCandidate,
		NumSessions:            uint32(len(tower.Sessions)),
		Sessions:               rpcSessions,
	}
}
