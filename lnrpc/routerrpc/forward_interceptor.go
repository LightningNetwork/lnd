package routerrpc

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// ErrFwdNotExists is an error returned when the caller tries to resolve
	// a forward that doesn't exist anymore.
	ErrFwdNotExists = errors.New("forward does not exist")

	// ErrMissingPreimage is an error returned when the caller tries to settle
	// a forward and doesn't provide a preimage.
	ErrMissingPreimage = errors.New("missing preimage")
)

// forwardInterceptor is a helper struct that handles the lifecycle of an rpc
// interceptor streaming session.
// It is created when the stream opens and disconnects when the stream closes.
type forwardInterceptor struct {
	// server is the Server reference
	server *Server

	// holdForwards is a map of current hold forwards and their corresponding
	// ForwardResolver.
	holdForwards map[channeldb.CircuitKey]htlcswitch.InterceptedForward

	// stream is the bidirectional RPC stream
	stream Router_HtlcInterceptorServer

	// quit is a channel that is closed when this forwardInterceptor is shutting
	// down.
	quit chan struct{}

	// intercepted is where we stream all intercepted packets coming from
	// the switch.
	intercepted chan htlcswitch.InterceptedForward

	wg sync.WaitGroup
}

// newForwardInterceptor creates a new forwardInterceptor.
func newForwardInterceptor(server *Server, stream Router_HtlcInterceptorServer) *forwardInterceptor {
	return &forwardInterceptor{
		server: server,
		stream: stream,
		holdForwards: make(
			map[channeldb.CircuitKey]htlcswitch.InterceptedForward),
		quit:        make(chan struct{}),
		intercepted: make(chan htlcswitch.InterceptedForward),
	}
}

// run sends the intercepted packets to the client and receives the
// corersponding responses. On one hand it regsitered itself as an interceptor
// that receives the switch packets and on the other hand launches a go routine
// to read from the client stream.
// To coordinate all this and make sure it is safe for concurrent access all
// packets are sent to the main where they are handled.
func (r *forwardInterceptor) run() error {
	// make sure we disconnect and resolves all remaining packets if any.
	defer r.onDisconnect()

	// Register our interceptor so we receive all forwarded packets.
	interceptableForwarder := r.server.cfg.RouterBackend.InterceptableForwarder
	interceptableForwarder.SetInterceptor(r.onIntercept)
	defer interceptableForwarder.SetInterceptor(nil)

	// start a go routine that reads client resolutions.
	errChan := make(chan error)
	resolutionRequests := make(chan *ForwardHtlcInterceptResponse)
	r.wg.Add(1)
	go r.readClientResponses(resolutionRequests, errChan)

	// run the main loop that synchronizes both sides input into one go routine.
	for {
		select {
		case intercepted := <-r.intercepted:
			log.Tracef("sending intercepted packet to client %v", intercepted)
			// in case we couldn't forward we exit the loop and drain the
			// current interceptor as this indicates on a connection problem.
			if err := r.holdAndForwardToClient(intercepted); err != nil {
				return err
			}
		case resolution := <-resolutionRequests:
			log.Tracef("resolving intercepted packet %v", resolution)
			// in case we couldn't resolve we just add a log line since this
			// does not indicate on any connection problem.
			if err := r.resolveFromClient(resolution); err != nil {
				log.Warnf("client resolution of intercepted "+
					"packet failed %v", err)
			}
		case err := <-errChan:
			return err
		case <-r.server.quit:
			return nil
		}
	}
}

// onIntercept is the function that is called by the switch for every forwarded
// packet. Our interceptor makes sure we hold the packet and then signal to the
// main loop to handle the packet. We only return true if we were able
// to deliver the packet to the main loop.
func (r *forwardInterceptor) onIntercept(p htlcswitch.InterceptedForward) bool {
	select {
	case r.intercepted <- p:
		return true
	case <-r.quit:
		return false
	case <-r.server.quit:
		return false
	}
}

func (r *forwardInterceptor) readClientResponses(
	resolutionChan chan *ForwardHtlcInterceptResponse, errChan chan error) {

	defer r.wg.Done()
	for {
		resp, err := r.stream.Recv()
		if err != nil {
			errChan <- err
			return
		}

		// Now that we have the response from the RPC client, send it to
		// the responses chan.
		select {
		case resolutionChan <- resp:
		case <-r.quit:
			return
		case <-r.server.quit:
			return
		}
	}
}

// holdAndForwardToClient forwards the intercepted htlc to the client.
func (r *forwardInterceptor) holdAndForwardToClient(
	forward htlcswitch.InterceptedForward) error {

	htlc := forward.Packet()
	inKey := htlc.IncomingCircuit

	// First hold the forward, then send to client.
	r.holdForwards[inKey] = forward
	interceptionRequest := &ForwardHtlcInterceptRequest{
		IncomingCircuitKey: &CircuitKey{
			ChanId: inKey.ChanID.ToUint64(),
			HtlcId: inKey.HtlcID,
		},
		OutgoingRequestedChanId: htlc.OutgoingChanID.ToUint64(),
		PaymentHash:             htlc.Hash[:],
		OutgoingAmountMsat:      uint64(htlc.OutgoingAmount),
		OutgoingExpiry:          htlc.OutgoingExpiry,
		IncomingAmountMsat:      uint64(htlc.IncomingAmount),
		IncomingExpiry:          htlc.IncomingExpiry,
		CustomRecords:           htlc.CustomRecords,
		OnionBlob:               htlc.OnionBlob[:],
	}

	return r.stream.Send(interceptionRequest)
}

// resolveFromClient handles a resolution arrived from the client.
func (r *forwardInterceptor) resolveFromClient(
	in *ForwardHtlcInterceptResponse) error {

	circuitKey := channeldb.CircuitKey{
		ChanID: lnwire.NewShortChanIDFromInt(in.IncomingCircuitKey.ChanId),
		HtlcID: in.IncomingCircuitKey.HtlcId,
	}
	var interceptedForward htlcswitch.InterceptedForward
	interceptedForward, ok := r.holdForwards[circuitKey]
	if !ok {
		return ErrFwdNotExists
	}
	delete(r.holdForwards, circuitKey)

	switch in.Action {
	case ResolveHoldForwardAction_RESUME:
		var onionBlob [lnwire.OnionPacketSize]byte
		copy(onionBlob[:], in.OnionBlob)
		return interceptedForward.Resume(lnwire.MilliSatoshi(in.OutgoingAmountMsat), lnwire.NewShortChanIDFromInt(in.OutgoingRequestedChanId), onionBlob)
	case ResolveHoldForwardAction_FAIL:
		var failureMessage lnwire.FailureMessage
		switch in.FailureCode {
		case ForwardHtlcInterceptResponse_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
			failureMessage = &lnwire.FailIncorrectDetails{}
		default:
			failureMessage = lnwire.NewTemporaryChannelFailure(nil)
		}
		return interceptedForward.Fail(failureMessage)
	case ResolveHoldForwardAction_SETTLE:
		if in.Preimage == nil {
			return ErrMissingPreimage
		}
		preimage, err := lntypes.MakePreimage(in.Preimage)
		if err != nil {
			return err
		}
		return interceptedForward.Settle(preimage)
	default:
		return fmt.Errorf("unrecognized resolve action %v", in.Action)
	}
}

// onDisconnect removes all previousely held forwards from
// the store. Before they are removed it ensure to resume as the default
// behavior.
func (r *forwardInterceptor) onDisconnect() {
	// Then close the channel so all go routine will exit.
	close(r.quit)

	log.Infof("RPC interceptor disconnected, resolving held packets")
	for key, forward := range r.holdForwards {
		if err := forward.Resume(forward.Packet().OutgoingAmount, forward.Packet().OutgoingChanID, forward.Packet().OnionBlob); err != nil {
			log.Errorf("failed to resume hold forward %v", err)
		}
		delete(r.holdForwards, key)
	}
	r.wg.Wait()
}
