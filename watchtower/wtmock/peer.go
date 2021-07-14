package wtmock

import (
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
)

const (
	timeout = 5 * time.Second
)

// MockPeer emulates a single endpoint of brontide transport.
type MockPeer struct {
	remotePub  *btcec.PublicKey
	remoteAddr net.Addr
	localPub   *btcec.PublicKey
	localAddr  net.Addr

	IncomingMsgs chan []byte
	OutgoingMsgs chan []byte

	writeDeadline <-chan time.Time
	readDeadline  <-chan time.Time

	RemoteQuit chan struct{}
	Quit       chan struct{}
}

// NewMockPeer returns a fresh MockPeer.
func NewMockPeer(lpk, rpk *btcec.PublicKey, addr net.Addr,
	bufferSize int) *MockPeer {

	return &MockPeer{
		remotePub:  rpk,
		remoteAddr: addr,
		localAddr: &net.TCPAddr{
			IP:   net.IP{0x32, 0x31, 0x30, 0x29},
			Port: 36723,
		},
		localPub:     lpk,
		IncomingMsgs: make(chan []byte, bufferSize),
		OutgoingMsgs: make(chan []byte, bufferSize),
		Quit:         make(chan struct{}),
	}
}

// NewMockConn establishes a bidirectional connection between two MockPeers.
func NewMockConn(localPk, remotePk *btcec.PublicKey,
	localAddr, remoteAddr net.Addr,
	bufferSize int) (*MockPeer, *MockPeer) {

	localPeer := &MockPeer{
		remotePub:    remotePk,
		remoteAddr:   remoteAddr,
		localPub:     localPk,
		localAddr:    localAddr,
		IncomingMsgs: make(chan []byte, bufferSize),
		OutgoingMsgs: make(chan []byte, bufferSize),
		Quit:         make(chan struct{}),
	}

	remotePeer := &MockPeer{
		remotePub:    localPk,
		remoteAddr:   localAddr,
		localPub:     remotePk,
		localAddr:    remoteAddr,
		IncomingMsgs: localPeer.OutgoingMsgs,
		OutgoingMsgs: localPeer.IncomingMsgs,
		Quit:         make(chan struct{}),
	}

	localPeer.RemoteQuit = remotePeer.Quit
	remotePeer.RemoteQuit = localPeer.Quit

	return localPeer, remotePeer
}

// Write sends the raw bytes as the next full message read to the remote peer.
// The write will fail if either party closes the connection or the write
// deadline expires. The passed bytes slice is copied before sending, thus the
// bytes may be reused once the method returns.
func (p *MockPeer) Write(b []byte) (n int, err error) {
	bb := make([]byte, len(b))
	copy(bb, b)

	select {
	case p.OutgoingMsgs <- bb:
		return len(b), nil
	case <-p.writeDeadline:
		return 0, fmt.Errorf("write timeout expired")
	case <-p.RemoteQuit:
		return 0, fmt.Errorf("remote closed connected")
	case <-p.Quit:
		return 0, fmt.Errorf("connection closed")
	}
}

// Close tearsdown the connection, and fails any pending reads or writes.
func (p *MockPeer) Close() error {
	select {
	case <-p.Quit:
		return fmt.Errorf("connection already closed")
	default:
		close(p.Quit)
		return nil
	}
}

// ReadNextMessage returns the raw bytes of the next full message read from the
// remote peer. The read will fail if either party closes the connection or the
// read deadline expires.
func (p *MockPeer) ReadNextMessage() ([]byte, error) {
	select {
	case b := <-p.IncomingMsgs:
		return b, nil
	case <-p.readDeadline:
		return nil, fmt.Errorf("read timeout expired")
	case <-p.RemoteQuit:
		return nil, fmt.Errorf("remote closed connected")
	case <-p.Quit:
		return nil, fmt.Errorf("connection closed")
	}
}

// SetWriteDeadline initializes a timer that will cause any pending writes to
// fail at time t. If t is zero, the deadline is infinite.
func (p *MockPeer) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		p.writeDeadline = nil
		return nil
	}

	duration := time.Until(t)
	p.writeDeadline = time.After(duration)

	return nil
}

// SetReadDeadline initializes a timer that will cause any pending reads to fail
// at time t. If t is zero, the deadline is infinite.
func (p *MockPeer) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		p.readDeadline = nil
		return nil
	}

	duration := time.Until(t)
	p.readDeadline = time.After(duration)

	return nil
}

// RemotePub returns the public key of the remote peer.
func (p *MockPeer) RemotePub() *btcec.PublicKey {
	return p.remotePub
}

// RemoteAddr returns the net address of the remote peer.
func (p *MockPeer) RemoteAddr() net.Addr {
	return p.remoteAddr
}

// LocalAddr returns the local net address of the peer.
func (p *MockPeer) LocalAddr() net.Addr {
	return p.localAddr
}

// Read is not implemented.
func (p *MockPeer) Read(dst []byte) (int, error) {
	panic("not implemented")
}

// SetDeadline is not implemented.
func (p *MockPeer) SetDeadline(t time.Time) error {
	panic("not implemented")
}

// WriteMessage mocks sending the message.
func (p *MockPeer) WriteMessage(msg []byte) error {
	// Since we may be using a write pool, we copy the message
	// over before sending it through.
	msgLen := len(msg)
	msgCopy := make([]byte, msgLen)
	if msgLen != copy(msgCopy, msg) {
		return fmt.Errorf("failed to copy message: %v", msg)
	}

	select {
	case p.OutgoingMsgs <- msgCopy:
	case <-time.After(timeout):
		return fmt.Errorf("timeout sending message: %v", msg)
	}

	return nil
}

// Flush mocks flushing the message down the wire.
func (p *MockPeer) Flush() (int, error) {
	return 0, nil
}

// ReadNextHeader mocks reading the next header.
func (p *MockPeer) ReadNextHeader() (uint32, error) {
	return 0, nil
}

// ReadNextBody mocks reading the next body.
func (p *MockPeer) ReadNextBody(_ []byte) ([]byte, error) {
	select {
	case msg := <-p.IncomingMsgs:
		return msg, nil

	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout reading message")
	}
}

// Compile-time constraint ensuring the MockPeer implements the wserver.Peer
// interface.
var _ wtserver.Peer = (*MockPeer)(nil)

// Compile-time constraint ensuring the MockPeer implements the net.Conn
// interface.
var _ net.Conn = (*MockPeer)(nil)
