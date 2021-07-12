// Package gozmq provides a ZMQ pubsub client.
//
// It implements the protocol described here:
// http://rfc.zeromq.org/spec:23/ZMTP/
package gozmq

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// MaxBodySize is the maximum frame size we're willing to accept.
	// The maximum size of a Bitcoin message is 32MiB.
	MaxBodySize uint64 = 0x02000000
)

// reconnectError wraps any error with a timeout, which allows clients to keep
// attempting to read normally while the underlying socket attempts to
// reconnect.
type reconnectError struct {
	error
}

// Timeout implements the timeout interface from net and other packages.
func (e *reconnectError) Timeout() bool {
	return true
}

func connFromAddr(addr string) (net.Conn, error) {
	re, err := regexp.Compile(`((tcp|unix|ipc)://)?([^:]*):?(\d*)`)
	if err != nil {
		return nil, err
	}

	submatch := re.FindStringSubmatch(addr)

	if addrs, err := net.LookupIP(submatch[3]); (err == nil &&
		len(addrs) > 0) || submatch[2] == "tcp" ||
		net.ParseIP(submatch[3]) != nil || submatch[4] != "" {

		// We have a TCP address.
		return net.DialTimeout("tcp", strings.Replace(submatch[3], "*",
			"", 1)+":"+submatch[4], time.Minute)

	} else if _, err := os.Stat(submatch[3]); err == nil ||
		submatch[2] == "unix" || submatch[2] == "ipc" {

		// We have a UNIX socket.
		return net.DialTimeout("unix", submatch[3], time.Minute)
	}

	return nil, fmt.Errorf("couldn't resolve address %s", addr)
}

// Conn is a connection to a ZMQ server.
type Conn struct {
	conn    net.Conn
	topics  []string
	timeout time.Duration

	closeConn sync.Once
	quit      chan struct{}
}

func (c *Conn) writeAll(buf []byte) error {
	written := 0
	for written < len(buf) {
		n, err := c.conn.Write(buf[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

func (c *Conn) writeGreeting() error {
	signature := []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f}
	version := []byte{3, 0}
	mechanism := make([]byte, 20)
	for i, chr := range "NULL" {
		mechanism[i] = byte(chr)
	}
	server := []byte{0}

	var greeting []byte
	greeting = append(greeting, signature...)
	greeting = append(greeting, version...)
	greeting = append(greeting, mechanism...)
	greeting = append(greeting, server...)
	for len(greeting) < 64 {
		greeting = append(greeting, 0)
	}

	return c.writeAll(greeting)
}

func (c *Conn) readGreeting() error {
	greet := make([]byte, 64)
	if _, err := io.ReadFull(c.conn, greet); err != nil {
		return err
	}

	if greet[0] != 0xff || greet[9] != 0x7f {
		return errors.New("invalid signature")
	}
	if greet[10] < 3 {
		return errors.New("peer version is too old")
	}
	if string(greet[12:17]) != "NULL\x00" {
		return errors.New("unsupported security mechanism")
	}
	if greet[32] != 0 {
		return errors.New("as-server must be zero for NULL")
	}

	return nil
}

func (c *Conn) writeFrame(flag byte, buf []byte) error {
	if flag&0xf8 != 0 {
		return errors.New("invalid flag")
	}

	if flag&2 != 0 {
		return errors.New("caller must not specify long frame flag")
	}

	var header []byte

	if len(buf) > 255 {
		flag = flag | 2
		header = []byte{flag, 0, 0, 0, 0, 0, 0, 0, 0}
		size := len(buf)
		i := len(header) - 1
		for size > 0 {
			header[i] = byte(size & 0xff)
			size = size >> 8
			i--
		}
	} else {
		header = []byte{flag, byte(len(buf))}
	}

	if err := c.writeAll(header); err != nil {
		return err
	}
	return c.writeAll(buf)
}

func (c *Conn) writeCommand(name string, data []byte) error {
	size := len(name)
	if size > 255 {
		return errors.New("command name is too long")
	}
	body := append([]byte{byte(size)}, []byte(name)...)
	buf := append(body, data...)
	var flag byte = 4
	return c.writeFrame(flag, buf)
}

func (c *Conn) writeReady(socketType string) error {
	if len(socketType) > 255 {
		return errors.New("socket type too long")
	}
	const socketTypeName = "Socket-Type"
	metadata := []byte{byte(len(socketTypeName))}
	metadata = append(metadata, []byte(socketTypeName)...)
	metadata = append(metadata, []byte{0, 0, 0, byte(len(socketType))}...)
	metadata = append(metadata, []byte(socketType)...)
	return c.writeCommand(commandReady, metadata)
}

func (c *Conn) writeMessage(parts [][]byte) error {
	if len(parts) == 0 {
		return errors.New("empty message")
	}
	for _, msg := range parts[:len(parts)-1] {
		if err := c.writeFrame(1, msg); err != nil {
			return err
		}
	}
	return c.writeFrame(0, parts[len(parts)-1])
}

func (c *Conn) subscribe(prefix string) error {
	msg := append([]byte{1}, []byte(prefix)...)
	return c.writeMessage([][]byte{msg})
}

func (c *Conn) readCommand() (string, []byte, error) {
	var (
		flag byte
		buf  []byte
		err  error
	)
	flag, buf, err = c.readFrame(buf, true)
	if err != nil {
		return "", nil, err
	}
	if flag&4 != 4 {
		return "", nil, errors.New("expected command frame")
	}
	if len(buf) < 1 {
		return "", nil, errors.New("empty command buffer")
	}
	size := int(buf[0])
	buf = buf[1:]
	if size > len(buf) {
		return "", nil, errors.New("invalid command name size")
	}
	name := string(buf[:size])
	data := buf[size:]
	return name, data, nil
}

const commandReady = "READY"

func (c *Conn) readReady() error {
	name, metadata, err := c.readCommand()
	if err != nil {
		return err
	}
	if name != commandReady {
		return errors.New("expected ready command")
	}

	m := make(map[string]string)
	for len(metadata) > 0 {
		size := int(metadata[0])
		metadata = metadata[1:]
		if size > len(metadata) {
			return errors.New("invalid metadata")
		}
		name := metadata[:size]
		metadata = metadata[size:]

		if len(metadata) < 4 {
			return errors.New("invalid metadata")
		}
		var valueSize uint32
		for i := 0; i < 4; i++ {
			valueSize = valueSize<<8 + uint32(metadata[i])
		}
		metadata = metadata[4:]

		if int(valueSize) > len(metadata) {
			return errors.New("invalid metadata")
		}
		value := metadata[:valueSize]
		metadata = metadata[valueSize:]

		m[string(name)] = string(value)
	}

	return nil
}

// Read a frame from the socket, setting deadline before each read to prevent
// timeouts during or between frames. The initialFrame should be used to denote
// whether this is the first frame we'll read for a _new_ message. The frame
// will be read into the provided buffer, which should be large enough to fit
// the frame. If nil, then an appropriately sized one will be allocated instead.
//
// NOTE: This is a blocking call if there is nothing to read from the
// connection.
func (c *Conn) readFrame(buf []byte, initialFrame bool) (byte, []byte, error) {
	// We'll only set a read deadline if this is not the first frame of a
	// message. We do this to ensure we receive complete messages in a
	// timely manner.
	if !initialFrame {
		c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	}

	var flagBuf [1]byte
	if _, err := io.ReadFull(c.conn, flagBuf[:1]); err != nil {
		return 0, nil, err
	}

	flag := flagBuf[0]
	if flag&0xf8 != 0 {
		return 0, nil, errors.New("invalid flag")
	}

	var size uint64

	if flag&2 == 2 {
		// Long form
		var sizeBuf [8]byte
		c.conn.SetReadDeadline(time.Now().Add(c.timeout))
		if _, err := io.ReadFull(c.conn, sizeBuf[:8]); err != nil {
			return 0, nil, err
		}
		for _, b := range sizeBuf {
			size = (size << 8) | uint64(b)
		}
	} else {
		// Short form
		var sizeBuf [1]byte
		c.conn.SetReadDeadline(time.Now().Add(c.timeout))
		if _, err := io.ReadFull(c.conn, sizeBuf[:1]); err != nil {
			return 0, nil, err
		}
		size = uint64(sizeBuf[0])
	}

	if size > MaxBodySize {
		return 0, nil, errors.New("frame too large")
	}

	// Allocate a buffer large enough to fit the frame if one wasn't
	// provided.
	if buf == nil {
		buf = make([]byte, size)
	} else if uint64(len(buf)) < size {
		return 0, nil, fmt.Errorf("buffer of size %v is too small for "+
			"frame of size %v", len(buf), size)
	}

	// Prevent timeout during large data read in case of slow connection.
	c.conn.SetReadDeadline(time.Time{})
	if _, err := io.ReadFull(c.conn, buf[:size]); err != nil {
		return 0, nil, err
	}

	return flag, buf[:size], nil
}

// readMessage reads a new message from the connection. Messages can be composed
// of multiple sub-messages. They are read into the provided buffers. Each
// buffer should be of sufficient length to successfully read messages. If none
// are provided, then buffers will be allocated for each sub-message.
//
// NOTE: This is a blocking call if there is nothing to read from the
// connection.
func (c *Conn) readMessage(bufs [][]byte) ([][]byte, error) {
	// We'll only set read deadlines on the underlying connection when
	// reading messages of multiple frames after the first frame has been
	// read. This is done to ensure we receive all of the frames of a
	// message within a reasonable time frame. When reading the first frame,
	// we want to avoid setting them as we don't know when a new message
	// will be available for us to read.
	initialFrame := true

	// If any buffers were provided, we'll use them to read the message
	// into. If the message consumes more buffers than provided, we'll need
	// to allocate some more.
	bufIdx := 0
	numInitialBufs := len(bufs)

	for {
		// If we have a buffer available, use it. Otherwise, buf will be
		// nil and an appropriately sized buffer will be allocated
		// instead.
		var (
			flag byte
			buf  []byte
			err  error
		)
		if bufIdx < numInitialBufs {
			buf = bufs[bufIdx]
		}
		flag, buf, err = c.readFrame(buf, initialFrame)
		if err != nil {
			return nil, err
		}
		if flag&4 != 0 {
			return nil, errors.New("expected message frame")
		}

		// Include the buffer back in the response.
		if bufIdx < numInitialBufs {
			bufs[bufIdx] = buf
		} else {
			bufs = append(bufs, buf)
		}

		if flag&1 == 0 {
			break
		}

		if len(bufs) > 16 {
			return nil, errors.New("message has too many parts")
		}

		initialFrame = false
		bufIdx++
	}

	return bufs, nil
}

// Subscribe connects to a publisher server and subscribes to the given topics.
func Subscribe(addr string, topics []string, timeout time.Duration) (*Conn, error) {
	conn, err := connFromAddr(addr)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	c := &Conn{
		conn:    conn,
		topics:  topics,
		timeout: timeout,
		quit:    make(chan struct{}),
	}

	if err := c.writeGreeting(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.readGreeting(); err != nil {
		conn.Close()
		return nil, err
	}

	if err := c.writeReady("SUB"); err != nil {
		conn.Close()
		return nil, err
	}

	if err := c.readReady(); err != nil {
		conn.Close()
		return nil, err
	}

	for _, topic := range topics {
		if err := c.subscribe(topic); err != nil {
			conn.Close()
			return nil, err
		}
	}

	conn.SetDeadline(time.Time{})

	return c, nil
}

// Receive a message from the publisher. Messages can be composed of multiple
// sub-messages. They are read into the provided buffers. Each buffer should be
// of sufficient length to successfully read messages. If none are provided,
// then buffers will be allocated for each sub-message. It blocks until a new
// message is received. If the connection times out and it was not explicitly
// terminated, then a timeout error is returned. Otherwise, if it was explicitly
// terminated, then io.EOF is returned.
func (c *Conn) Receive(bufs [][]byte) ([][]byte, error) {
	// If the error is either nil or a non-EOF error, we return it as-is.
	var err error
	bufs, err = c.readMessage(bufs)
	if err != io.EOF {
		return bufs, err
	}

	// We got an EOF, so our socket is disconnected. If the connection was
	// explicitly terminated, we'll return the EOF error.
	select {
	case <-c.quit:
		return nil, io.EOF
	default:
	}

	// Otherwise, we'll attempt to reconnect. If successful, we'll replace
	// the existing connection with the new one. Either way, return a
	// timeout error.
	errTimeout := &net.OpError{
		Op:     "read",
		Net:    c.conn.LocalAddr().Network(),
		Source: c.conn.LocalAddr(),
		Addr:   c.conn.RemoteAddr(),
		Err:    &reconnectError{err},
	}
	newConn, err := Subscribe(
		c.conn.RemoteAddr().String(), c.topics, c.timeout,
	)
	if err != nil {
		// Prevent CPU overuse by refused reconnection attempts.
		time.Sleep(c.timeout)
	} else {
		c.conn.Close()
		c.conn = newConn.conn
	}
	return nil, errTimeout
}

// Close the underlying connection. Any further operations will fail.
func (c *Conn) Close() error {
	var err error
	c.closeConn.Do(func() {
		close(c.quit)
		err = c.conn.Close()
	})
	return err
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
