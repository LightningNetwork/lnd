package rpcperms

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/golang/protobuf/proto"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
)

var (
	// errShuttingDown is the error that's returned when the server is
	// shutting down and a request cannot be served anymore.
	errShuttingDown = errors.New("server shutting down")

	// errTimeoutReached is the error that's returned if any of the
	// middleware's tasks is not completed in the given time.
	errTimeoutReached = errors.New("intercept timeout reached")

	// errClientQuit is the error that's returned if the client closes the
	// middleware communication stream before a request was fully handled.
	errClientQuit = errors.New("interceptor RPC client quit")
)

// MiddlewareHandler is a type that communicates with a middleware over the
// established bi-directional RPC stream. It sends messages to the middleware
// whenever the custom business logic implemented there should give feedback to
// a request or response that's happening on the main gRPC server.
type MiddlewareHandler struct {
	// lastRequestID is the ID of the last request that was forwarded to the
	// middleware.
	//
	// NOTE: Must be used atomically!
	lastRequestID uint64

	middlewareName string

	customCaveatName string

	receive func() (*lnrpc.RPCMiddlewareResponse, error)

	send func(request *lnrpc.RPCMiddlewareRequest) error

	interceptRequests chan *interceptRequest

	timeout time.Duration

	// params are our current chain params.
	params *chaincfg.Params

	// done is closed when the rpc client terminates.
	done chan struct{}

	// quit is closed when lnd is shutting down.
	quit chan struct{}

	wg sync.WaitGroup
}

// NewMiddlewareHandler creates a new handler for the middleware with the given
// name and custom caveat name.
func NewMiddlewareHandler(name, customCaveatName string,
	receive func() (*lnrpc.RPCMiddlewareResponse, error),
	send func(request *lnrpc.RPCMiddlewareRequest) error,
	timeout time.Duration, params *chaincfg.Params,
	quit chan struct{}) *MiddlewareHandler {

	// We explicitly want to log this as a warning since intercepting any
	// gRPC messages can also be used for malicious purposes and the user
	// should be made aware of the risks.
	log.Warnf("A new gRPC middleware with the name '%s' was registered "+
		"for the custom macaroon caveat '%s'. Make sure you trust the "+
		"middleware author since that code will be able to intercept "+
		"and possibly modify and gRPC messages sent/received to/from "+
		"a client that has a macaroon with that custom caveat", name,
		customCaveatName)

	return &MiddlewareHandler{
		middlewareName:    name,
		customCaveatName:  customCaveatName,
		receive:           receive,
		send:              send,
		interceptRequests: make(chan *interceptRequest),
		timeout:           timeout,
		params:            params,
		done:              make(chan struct{}),
		quit:              quit,
	}
}

// intercept handles the full interception lifecycle of a single middleware
// event (stream authentication, request interception or response interception).
// The lifecycle consists of sending a message to the middleware, receiving a
// feedback on it and sending the feedback to the appropriate channel. All steps
// are guarded by the configured timeout to make sure a middleware cannot slow
// down requests too much.
func (h *MiddlewareHandler) intercept(
	req *InterceptionRequest) (*interceptResponse, error) {

	respChan := make(chan *interceptResponse, 1)

	newRequest := &interceptRequest{
		request:  req,
		response: respChan,
	}

	// timeout is the time after which intercept requests expire.
	timeout := time.After(h.timeout)

	// Send the request to the interceptRequests channel for the main
	// goroutine to be picked up.
	select {
	case h.interceptRequests <- newRequest:

	case <-timeout:
		log.Errorf("MiddlewareHandler returned error - reached "+
			"timeout of %v", h.timeout)

		return nil, errTimeoutReached

	case <-h.done:
		return nil, errClientQuit

	case <-h.quit:
		return nil, errShuttingDown
	}

	// Receive the response and return it. If no response has been received
	// in AcceptorTimeout, then return false.
	select {
	case resp := <-respChan:
		return resp, nil

	case <-timeout:
		log.Errorf("MiddlewareHandler returned error - reached "+
			"timeout of %v", h.timeout)
		return nil, errTimeoutReached

	case <-h.done:
		return nil, errClientQuit

	case <-h.quit:
		return nil, errShuttingDown
	}
}

// Run is the main loop for the middleware handler. This function will block
// until it receives the signal that lnd is shutting down, or the rpc stream is
// cancelled by the client.
func (h *MiddlewareHandler) Run() error {
	// Wait for our goroutines to exit before we return.
	defer h.wg.Wait()

	// Create a channel that responses from middlewares are sent into.
	responses := make(chan *lnrpc.RPCMiddlewareResponse)

	// errChan is used by the receive loop to signal any errors that occur
	// during reading from the stream. This is primarily used to shutdown
	// the send loop in the case of an RPC client disconnecting.
	errChan := make(chan error, 1)

	// Start a goroutine to receive responses from the channel acceptor.
	// We expect the receive function to block, so it must be run in a
	// goroutine (otherwise we could not send more than one channel accept
	// request to the client).
	h.wg.Add(1)
	go func() {
		h.receiveResponses(errChan, responses)
		h.wg.Done()
	}()

	return h.sendInterceptRequests(errChan, responses)
}

// receiveResponses receives responses for our channel accept requests and
// dispatches them into the responses channel provided, sending any errors that
// occur into the error channel provided.
func (h *MiddlewareHandler) receiveResponses(errChan chan error,
	responses chan *lnrpc.RPCMiddlewareResponse) {

	for {
		resp, err := h.receive()
		if err != nil {
			errChan <- err
			return
		}

		select {
		case responses <- resp:

		case <-h.done:
			return

		case <-h.quit:
			return
		}
	}
}

// sendInterceptRequests handles channel acceptor requests sent to us by our
// Accept() function, dispatching them to our acceptor stream and coordinating
// return of responses to their callers.
func (h *MiddlewareHandler) sendInterceptRequests(errChan chan error,
	responses chan *lnrpc.RPCMiddlewareResponse) error {

	// Close the done channel to indicate that the interceptor is no longer
	// listening and any in-progress requests should be terminated.
	defer close(h.done)

	interceptRequests := make(map[uint64]*interceptRequest)

	for {
		select {
		// Consume requests passed to us from our Accept() function and
		// send them into our stream.
		case newRequest := <-h.interceptRequests:
			id := atomic.AddUint64(&h.lastRequestID, 1)

			req := newRequest.request
			interceptRequests[id] = newRequest

			interceptReq, err := req.ToRPC(id)
			if err != nil {
				return err
			}

			if err := h.send(interceptReq); err != nil {
				return err
			}

		// Process newly received responses from our channel acceptor,
		// looking the original request up in our map of requests and
		// dispatching the response.
		case resp := <-responses:
			requestInfo, ok := interceptRequests[resp.RequestId]
			if !ok {
				continue
			}

			response := &interceptResponse{}
			switch msg := resp.GetMiddlewareMessage().(type) {
			case *lnrpc.RPCMiddlewareResponse_Feedback:
				t := msg.Feedback
				if t.Error != "" {
					response.err = fmt.Errorf("%s", t.Error)
					break
				}

				// For intercepted responses we also allow the
				// content itself to be overwritten.
				if requestInfo.request.Type == TypeResponse &&
					t.ReplaceResponse {

					response.replace = true
					protoMsg, err := parseProto(
						requestInfo.request.ProtoTypeName,
						t.ReplacementSerialized,
					)

					if err != nil {
						response.err = err

						break
					}

					response.replacement = protoMsg
				}

			default:
				return fmt.Errorf("unknown middleware "+
					"message: %v", msg)
			}

			select {
			case requestInfo.response <- response:
			case <-h.quit:
			}

			delete(interceptRequests, resp.RequestId)

		// If we failed to receive from our middleware, we exit.
		case err := <-errChan:
			log.Errorf("Received an error: %v, shutting down", err)
			return err

		// Exit if we are shutting down.
		case <-h.quit:
			return errShuttingDown
		}
	}
}

type InterceptType uint8

const (
	TypeStreamAuth InterceptType = 1

	TypeRequest InterceptType = 2

	TypeResponse InterceptType = 3
)

type InterceptionRequest struct {
	Type InterceptType

	StreamRPC bool

	RawMacaroon []byte

	CustomCaveatName string

	CustomCaveatCondition string

	FullURI string

	ProtoSerialized []byte

	ProtoTypeName string
}

func NewMessageInterceptionRequest(ctx context.Context,
	authType InterceptType, isStream bool, fullMethod string,
	m interface{}) (*InterceptionRequest, error) {

	mac, err := macaroons.MacaroonFromContext(ctx)
	if err != nil {
		return nil, err
	}

	rawMacaroon, err := mac.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rpcReq, ok := m.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("msg is not proto message: %v", m)
	}
	rawRequest, err := proto.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal proto msg: %v", err)
	}

	return &InterceptionRequest{
		Type:            authType,
		StreamRPC:       isStream,
		RawMacaroon:     rawMacaroon,
		FullURI:         fullMethod,
		ProtoSerialized: rawRequest,
		ProtoTypeName:   proto.MessageName(rpcReq),
	}, nil
}

func NewStreamAuthInterceptionRequest(ctx context.Context,
	fullMethod string) (*InterceptionRequest, error) {

	mac, err := macaroons.MacaroonFromContext(ctx)
	if err != nil {
		return nil, err
	}

	rawMacaroon, err := mac.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &InterceptionRequest{
		Type:        TypeStreamAuth,
		StreamRPC:   true,
		RawMacaroon: rawMacaroon,
		FullURI:     fullMethod,
	}, nil
}

func (r *InterceptionRequest) ToRPC(id uint64) (*lnrpc.RPCMiddlewareRequest,
	error) {

	rpcRequest := &lnrpc.RPCMiddlewareRequest{
		RequestId:             id,
		RawMacaroon:           r.RawMacaroon,
		CustomCaveatCondition: r.CustomCaveatCondition,
	}

	switch r.Type {
	case TypeStreamAuth:
		rpcRequest.InterceptType = &lnrpc.RPCMiddlewareRequest_StreamAuth{
			StreamAuth: &lnrpc.StreamAuth{
				MethodFullUri: r.FullURI,
			},
		}

	case TypeRequest:
		rpcRequest.InterceptType = &lnrpc.RPCMiddlewareRequest_Request{
			Request: &lnrpc.RPCMessage{
				MethodFullUri: r.FullURI,
				StreamRpc:     r.StreamRPC,
				TypeName:      r.ProtoTypeName,
				Serialized:    r.ProtoSerialized,
			},
		}

	case TypeResponse:
		rpcRequest.InterceptType = &lnrpc.RPCMiddlewareRequest_Response{
			Response: &lnrpc.RPCMessage{
				MethodFullUri: r.FullURI,
				StreamRpc:     r.StreamRPC,
				TypeName:      r.ProtoTypeName,
				Serialized:    r.ProtoSerialized,
			},
		}

	default:
		return nil, fmt.Errorf("unknown intercept type %v", r.Type)
	}

	return rpcRequest, nil
}

type interceptRequest struct {
	request  *InterceptionRequest
	response chan *interceptResponse
}

type interceptResponse struct {
	err         error
	replace     bool
	replacement interface{}
}

func parseProto(typeName string, serialized []byte) (proto.Message, error) {
	reflectType := proto.MessageType(typeName)
	msgValue := reflect.New(reflectType.Elem())
	msg := msgValue.Interface().(proto.Message)

	err := proto.Unmarshal(serialized, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}
