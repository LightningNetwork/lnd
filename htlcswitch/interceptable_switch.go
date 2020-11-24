package htlcswitch

import (
	"fmt"
	"sync"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// ErrFwdNotExists is an error returned when the caller tries to resolve
	// a forward that doesn't exist anymore.
	ErrFwdNotExists = errors.New("forward does not exist")
)

// InterceptableSwitch is an implementation of ForwardingSwitch interface.
// This implementation is used like a proxy that wraps the switch and
// intercepts forward requests. A reference to the Switch is held in order
// to communicate back the interception result where the options are:
// Resume - forwards the original request to the switch as is.
// Settle - routes UpdateFulfillHTLC to the originating link.
// Fail - routes UpdateFailHTLC to the originating link.
type InterceptableSwitch struct {
	sync.RWMutex

	// htlcSwitch is the underline switch
	htlcSwitch *Switch

	// fwdInterceptor is the callback that is called for each forward of
	// an incoming htlc. It should return true if it is interested in handling
	// it.
	fwdInterceptor ForwardInterceptor
}

// NewInterceptableSwitch returns an instance of InterceptableSwitch.
func NewInterceptableSwitch(s *Switch) *InterceptableSwitch {
	return &InterceptableSwitch{htlcSwitch: s}
}

// SetInterceptor sets the ForwardInterceptor to be used.
func (s *InterceptableSwitch) SetInterceptor(
	interceptor ForwardInterceptor) {

	s.Lock()
	defer s.Unlock()
	s.fwdInterceptor = interceptor
}

// ForwardPackets attempts to forward the batch of htlcs through the
// switch, any failed packets will be returned to the provided
// ChannelLink. The link's quit signal should be provided to allow
// cancellation of forwarding during link shutdown.
func (s *InterceptableSwitch) ForwardPackets(linkQuit chan struct{},
	packets ...*htlcPacket) error {

	var interceptor ForwardInterceptor
	s.Lock()
	interceptor = s.fwdInterceptor
	s.Unlock()

	// Optimize for the case we don't have an interceptor.
	if interceptor == nil {
		return s.htlcSwitch.ForwardPackets(linkQuit, packets...)
	}

	var notIntercepted []*htlcPacket
	for _, p := range packets {
		if !s.interceptForward(p, interceptor, linkQuit) {
			notIntercepted = append(notIntercepted, p)
		}
	}
	return s.htlcSwitch.ForwardPackets(linkQuit, notIntercepted...)
}

// interceptForward checks if there is any external interceptor interested in
// this packet. Currently only htlc type of UpdateAddHTLC that are forwarded
// are being checked for interception. It can be extended in the future given
// the right use case.
func (s *InterceptableSwitch) interceptForward(packet *htlcPacket,
	interceptor ForwardInterceptor, linkQuit chan struct{}) bool {

	switch htlc := packet.htlc.(type) {
	case *lnwire.UpdateAddHTLC:
		// We are not interested in intercepting initated payments.
		if packet.incomingChanID == hop.Source {
			return false
		}

		intercepted := &interceptedForward{
			linkQuit:   linkQuit,
			htlc:       htlc,
			packet:     packet,
			htlcSwitch: s.htlcSwitch,
		}

		// If this htlc was intercepted, don't handle the forward.
		return interceptor(intercepted)
	default:
		return false
	}
}

// interceptedForward implements the InterceptedForward interface.
// It is passed from the switch to external interceptors that are interested
// in holding forwards and resolve them manually.
type interceptedForward struct {
	linkQuit   chan struct{}
	htlc       *lnwire.UpdateAddHTLC
	packet     *htlcPacket
	htlcSwitch *Switch
}

// Packet returns the intercepted htlc packet.
func (f *interceptedForward) Packet() InterceptedPacket {
	return InterceptedPacket{
		IncomingCircuit: channeldb.CircuitKey{
			ChanID: f.packet.incomingChanID,
			HtlcID: f.packet.incomingHTLCID,
		},
		OutgoingChanID: f.packet.outgoingChanID,
		Hash:           f.htlc.PaymentHash,
		OutgoingExpiry: f.htlc.Expiry,
		OutgoingAmount: f.htlc.Amount,
		IncomingAmount: f.packet.incomingAmount,
		IncomingExpiry: f.packet.incomingTimeout,
		CustomRecords:  f.packet.customRecords,
		OnionBlob:      f.htlc.OnionBlob,
	}
}

// Resume resumes the default behavior as if the packet was not intercepted.
func (f *interceptedForward) Resume(outgoingAmount lnwire.MilliSatoshi, outgoingChanID lnwire.ShortChannelID, onionBlob [lnwire.OnionPacketSize]byte) error {
	f.htlc.OnionBlob = onionBlob
	f.htlc.Amount = outgoingAmount
	f.packet.htlc = f.htlc
	f.packet.amount = outgoingAmount
	f.packet.outgoingChanID = outgoingChanID
	return f.htlcSwitch.ForwardPackets(f.linkQuit, f.packet)
}

// Fail forward a failed packet to the switch.
func (f *interceptedForward) Fail(failureMessage lnwire.FailureMessage) error {
	reason, err := f.packet.obfuscator.EncryptFirstHop(failureMessage)
	if err != nil {
		return fmt.Errorf("failed to encrypt failure reason %v", err)
	}
	return f.resolve(&lnwire.UpdateFailHTLC{
		Reason: reason,
	})
}

// Settle forwards a settled packet to the switch.
func (f *interceptedForward) Settle(preimage lntypes.Preimage) error {
	if !preimage.Matches(f.htlc.PaymentHash) {
		return errors.New("preimage does not match hash")
	}
	return f.resolve(&lnwire.UpdateFulfillHTLC{
		PaymentPreimage: preimage,
	})
}

// resolve is used for both Settle and Fail and forwards the message to the
// switch.
func (f *interceptedForward) resolve(message lnwire.Message) error {
	pkt := &htlcPacket{
		incomingChanID: f.packet.incomingChanID,
		incomingHTLCID: f.packet.incomingHTLCID,
		outgoingChanID: f.packet.outgoingChanID,
		outgoingHTLCID: f.packet.outgoingHTLCID,
		isResolution:   true,
		circuit:        f.packet.circuit,
		htlc:           message,
		obfuscator:     f.packet.obfuscator,
	}
	return f.htlcSwitch.mailOrchestrator.Deliver(pkt.incomingChanID, pkt)
}
