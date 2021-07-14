// +build invoicesrpc

package invoicesrpc

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/macaroons"
)

const (
	// subServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize it as the name of our
	// RPC service.
	subServerName = "InvoicesRPC"
)

var (
	// macaroonOps are the set of capabilities that our minted macaroon (if
	// it doesn't already exist) will have.
	macaroonOps = []bakery.Op{
		{
			Entity: "invoices",
			Action: "write",
		},
		{
			Entity: "invoices",
			Action: "read",
		},
	}

	// macPermissions maps RPC calls to the permissions they require.
	macPermissions = map[string][]bakery.Op{
		"/invoicesrpc.Invoices/SubscribeSingleInvoice": {{
			Entity: "invoices",
			Action: "read",
		}},
		"/invoicesrpc.Invoices/SettleInvoice": {{
			Entity: "invoices",
			Action: "write",
		}},
		"/invoicesrpc.Invoices/CancelInvoice": {{
			Entity: "invoices",
			Action: "write",
		}},
		"/invoicesrpc.Invoices/AddHoldInvoice": {{
			Entity: "invoices",
			Action: "write",
		}},
	}

	// DefaultInvoicesMacFilename is the default name of the invoices
	// macaroon that we expect to find via a file handle within the main
	// configuration file in this package.
	DefaultInvoicesMacFilename = "invoices.macaroon"
)

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	InvoicesServer
}

// Server is a sub-server of the main RPC server: the invoices RPC. This sub
// RPC server allows external callers to access the status of the invoices
// currently active within lnd, as well as configuring it at runtime.
type Server struct {
	quit chan struct{}

	cfg *Config
}

// A compile time check to ensure that Server fully implements the
// InvoicesServer gRPC service.
var _ InvoicesServer = (*Server)(nil)

// New returns a new instance of the invoicesrpc Invoices sub-server. We also
// return the set of permissions for the macaroons that we may create within
// this method. If the macaroons we need aren't found in the filepath, then
// we'll create them on start up. If we're unable to locate, or create the
// macaroons we need, then we'll return with an error.
func New(cfg *Config) (*Server, lnrpc.MacaroonPerms, error) {
	// If the path of the invoices macaroon wasn't specified, then we'll
	// assume that it's found at the default network directory.
	macFilePath := filepath.Join(
		cfg.NetworkDir, DefaultInvoicesMacFilename,
	)

	// Now that we know the full path of the invoices macaroon, we can
	// check to see if we need to create it or not. If stateless_init is set
	// then we don't write the macaroons.
	if cfg.MacService != nil && !cfg.MacService.StatelessInit &&
		!lnrpc.FileExists(macFilePath) {

		log.Infof("Baking macaroons for invoices RPC Server at: %v",
			macFilePath)

		// At this point, we know that the invoices macaroon doesn't
		// yet, exist, so we need to create it with the help of the
		// main macaroon service.
		invoicesMac, err := cfg.MacService.NewMacaroon(
			context.Background(), macaroons.DefaultRootKeyID,
			macaroonOps...,
		)
		if err != nil {
			return nil, nil, err
		}
		invoicesMacBytes, err := invoicesMac.M().MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		err = ioutil.WriteFile(macFilePath, invoicesMacBytes, 0644)
		if err != nil {
			_ = os.Remove(macFilePath)
			return nil, nil, err
		}
	}

	server := &Server{
		cfg:  cfg,
		quit: make(chan struct{}, 1),
	}

	return server, macPermissions, nil
}

// Start launches any helper goroutines required for the Server to function.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Start() error {
	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Stop() error {
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

// RegisterWithRootServer will be called by the root gRPC server to direct a sub
// RPC server to register itself with the main gRPC root server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRootServer(grpcServer *grpc.Server) error {
	// We make sure that we register it with the main gRPC server to ensure
	// all our methods are routed properly.
	RegisterInvoicesServer(grpcServer, r)

	log.Debugf("Invoices RPC server successfully registered with root " +
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
	err := RegisterInvoicesHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register Invoices REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("Invoices REST server successfully registered with " +
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

	r.InvoicesServer = subServer
	return subServer, macPermissions, nil
}

// SubscribeSingleInvoice returns a uni-directional stream (server -> client)
// for notifying the client of state changes for a specified invoice.
func (s *Server) SubscribeSingleInvoice(req *SubscribeSingleInvoiceRequest,
	updateStream Invoices_SubscribeSingleInvoiceServer) error {

	hash, err := lntypes.MakeHash(req.RHash)
	if err != nil {
		return err
	}

	invoiceClient, err := s.cfg.InvoiceRegistry.SubscribeSingleInvoice(hash)
	if err != nil {
		return err
	}
	defer invoiceClient.Cancel()

	for {
		select {
		case newInvoice := <-invoiceClient.Updates:
			rpcInvoice, err := CreateRPCInvoice(
				newInvoice, s.cfg.ChainParams,
			)
			if err != nil {
				return err
			}

			if err := updateStream.Send(rpcInvoice); err != nil {
				return err
			}

			// If we have reached a terminal state, close the
			// stream with no error.
			if newInvoice.State.IsFinal() {
				return nil
			}

		case <-updateStream.Context().Done():
			return updateStream.Context().Err()

		case <-s.quit:
			return nil
		}
	}
}

// SettleInvoice settles an accepted invoice. If the invoice is already settled,
// this call will succeed.
func (s *Server) SettleInvoice(ctx context.Context,
	in *SettleInvoiceMsg) (*SettleInvoiceResp, error) {

	preimage, err := lntypes.MakePreimage(in.Preimage)
	if err != nil {
		return nil, err
	}

	err = s.cfg.InvoiceRegistry.SettleHodlInvoice(preimage)
	if err != nil && err != channeldb.ErrInvoiceAlreadySettled {
		return nil, err
	}

	return &SettleInvoiceResp{}, nil
}

// CancelInvoice cancels a currently open invoice. If the invoice is already
// canceled, this call will succeed. If the invoice is already settled, it will
// fail.
func (s *Server) CancelInvoice(ctx context.Context,
	in *CancelInvoiceMsg) (*CancelInvoiceResp, error) {

	paymentHash, err := lntypes.MakeHash(in.PaymentHash)
	if err != nil {
		return nil, err
	}

	err = s.cfg.InvoiceRegistry.CancelInvoice(paymentHash)
	if err != nil {
		return nil, err
	}

	log.Infof("Canceled invoice %v", paymentHash)

	return &CancelInvoiceResp{}, nil
}

// AddHoldInvoice attempts to add a new hold invoice to the invoice database.
// Any duplicated invoices are rejected, therefore all invoices *must* have a
// unique payment hash.
func (s *Server) AddHoldInvoice(ctx context.Context,
	invoice *AddHoldInvoiceRequest) (*AddHoldInvoiceResp, error) {

	addInvoiceCfg := &AddInvoiceConfig{
		AddInvoice:            s.cfg.InvoiceRegistry.AddInvoice,
		IsChannelActive:       s.cfg.IsChannelActive,
		ChainParams:           s.cfg.ChainParams,
		NodeSigner:            s.cfg.NodeSigner,
		DefaultCLTVExpiry:     s.cfg.DefaultCLTVExpiry,
		ChanDB:                s.cfg.ChanStateDB,
		Graph:                 s.cfg.GraphDB,
		GenInvoiceFeatures:    s.cfg.GenInvoiceFeatures,
		GenAmpInvoiceFeatures: s.cfg.GenAmpInvoiceFeatures,
	}

	hash, err := lntypes.MakeHash(invoice.Hash)
	if err != nil {
		return nil, err
	}

	value, err := lnrpc.UnmarshallAmt(invoice.Value, invoice.ValueMsat)
	if err != nil {
		return nil, err
	}

	// Convert the passed routing hints to the required format.
	routeHints, err := CreateZpay32HopHints(invoice.RouteHints)
	if err != nil {
		return nil, err
	}
	addInvoiceData := &AddInvoiceData{
		Memo:            invoice.Memo,
		Hash:            &hash,
		Value:           value,
		DescriptionHash: invoice.DescriptionHash,
		Expiry:          invoice.Expiry,
		FallbackAddr:    invoice.FallbackAddr,
		CltvExpiry:      invoice.CltvExpiry,
		Private:         invoice.Private,
		HodlInvoice:     true,
		Preimage:        nil,
		RouteHints:      routeHints,
	}

	_, dbInvoice, err := AddInvoice(ctx, addInvoiceCfg, addInvoiceData)
	if err != nil {
		return nil, err
	}

	return &AddHoldInvoiceResp{
		PaymentRequest: string(dbInvoice.PaymentRequest),
	}, nil
}
