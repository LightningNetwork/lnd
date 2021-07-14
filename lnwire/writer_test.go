package lnwire

import (
	"bytes"
	"encoding/base32"
	"image/color"
	"math"
	"net"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/stretchr/testify/require"
)

func TestWriteBytes(t *testing.T) {
	buf := new(bytes.Buffer)
	data := []byte{1, 2, 3}

	err := WriteBytes(buf, data)

	require.NoError(t, err)
	require.Equal(t, data, buf.Bytes())
}

func TestWriteUint8(t *testing.T) {
	buf := new(bytes.Buffer)
	data := uint8(1)
	expectedBytes := []byte{1}

	err := WriteUint8(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteUint16(t *testing.T) {
	buf := new(bytes.Buffer)
	data := uint16(1)
	expectedBytes := []byte{0, 1}

	err := WriteUint16(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteUint32(t *testing.T) {
	buf := new(bytes.Buffer)
	data := uint32(1)
	expectedBytes := []byte{0, 0, 0, 1}

	err := WriteUint32(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteUint64(t *testing.T) {
	buf := new(bytes.Buffer)
	data := uint64(1)
	expectedBytes := []byte{0, 0, 0, 0, 0, 0, 0, 1}

	err := WriteUint64(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteSatoshi(t *testing.T) {
	buf := new(bytes.Buffer)
	data := btcutil.Amount(1)
	expectedBytes := []byte{0, 0, 0, 0, 0, 0, 0, 1}

	err := WriteSatoshi(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteMilliSatoshi(t *testing.T) {
	buf := new(bytes.Buffer)
	data := MilliSatoshi(1)
	expectedBytes := []byte{0, 0, 0, 0, 0, 0, 0, 1}

	err := WriteMilliSatoshi(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWritePublicKey(t *testing.T) {
	buf := new(bytes.Buffer)

	// Check that when nil pubkey is used, an error will return.
	err := WritePublicKey(buf, nil)
	require.Equal(t, ErrNilPublicKey, err)

	pub, err := randPubKey()
	require.NoError(t, err)
	expectedBytes := pub.SerializeCompressed()

	err = WritePublicKey(buf, pub)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteChannelID(t *testing.T) {
	buf := new(bytes.Buffer)
	data := ChannelID{1}
	expectedBytes := [32]byte{1}

	err := WriteChannelID(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes[:], buf.Bytes())
}

func TestWriteNodeAlias(t *testing.T) {
	buf := new(bytes.Buffer)
	data := NodeAlias{1}
	expectedBytes := [32]byte{1}

	err := WriteNodeAlias(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes[:], buf.Bytes())
}

func TestWriteShortChannelID(t *testing.T) {
	buf := new(bytes.Buffer)
	data := ShortChannelID{BlockHeight: 1, TxIndex: 2, TxPosition: 3}
	expectedBytes := []byte{
		0, 0, 1, // First three bytes encodes BlockHeight.
		0, 0, 2, // Second three bytes encodes TxIndex.
		0, 3, // Final two bytes encodes TxPosition.
	}

	err := WriteShortChannelID(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteSig(t *testing.T) {
	buf := new(bytes.Buffer)
	data := Sig{1, 2, 3}
	expectedBytes := [64]byte{1, 2, 3}

	err := WriteSig(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes[:], buf.Bytes())
}

func TestWriteSigs(t *testing.T) {
	buf := new(bytes.Buffer)
	sig1, sig2, sig3 := Sig{1}, Sig{2}, Sig{3}
	data := []Sig{sig1, sig2, sig3}

	// First two bytes encode the length of the slice.
	expectedBytes := []byte{0, 3}
	expectedBytes = append(expectedBytes, sig1[:]...)
	expectedBytes = append(expectedBytes, sig2[:]...)
	expectedBytes = append(expectedBytes, sig3[:]...)

	err := WriteSigs(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteFailCode(t *testing.T) {
	buf := new(bytes.Buffer)
	data := FailCode(1)
	expectedBytes := []byte{0, 1}

	err := WriteFailCode(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

// TODO(yy): expand the test to cover more encoding scenarios.
func TestWriteRawFeatureVector(t *testing.T) {
	buf := new(bytes.Buffer)

	// Check that when nil feature is used, an error will return.
	err := WriteRawFeatureVector(buf, nil)
	require.Equal(t, ErrNilFeatureVector, err)

	// Create a raw feature vector.
	feature := &RawFeatureVector{features: map[FeatureBit]bool{
		InitialRoutingSync: true, // FeatureBit 3.
	}}
	expectedBytes := []byte{
		0, 1, // First two bytes encode the length.
		8, // Last byte encodes the feature bit (1 << 3).
	}

	err = WriteRawFeatureVector(buf, feature)
	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteColorRGBA(t *testing.T) {
	buf := new(bytes.Buffer)
	data := color.RGBA{R: 1, G: 2, B: 3}
	expectedBytes := []byte{1, 2, 3}

	err := WriteColorRGBA(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteShortChanIDEncoding(t *testing.T) {
	buf := new(bytes.Buffer)
	data := ShortChanIDEncoding(1)
	expectedBytes := []byte{1}

	err := WriteShortChanIDEncoding(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteFundingFlag(t *testing.T) {
	buf := new(bytes.Buffer)
	data := FundingFlag(1)
	expectedBytes := []byte{1}

	err := WriteFundingFlag(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteChanUpdateMsgFlags(t *testing.T) {
	buf := new(bytes.Buffer)
	data := ChanUpdateMsgFlags(1)
	expectedBytes := []byte{1}

	err := WriteChanUpdateMsgFlags(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteChanUpdateChanFlags(t *testing.T) {
	buf := new(bytes.Buffer)
	data := ChanUpdateChanFlags(1)
	expectedBytes := []byte{1}

	err := WriteChanUpdateChanFlags(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteDeliveryAddress(t *testing.T) {
	buf := new(bytes.Buffer)
	data := DeliveryAddress{1, 1, 1}
	expectedBytes := []byte{
		0, 3, // First two bytes encode the length.
		1, 1, 1, // The actual data.
	}

	err := WriteDeliveryAddress(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWritePingPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	data := PingPayload{1, 1, 1}
	expectedBytes := []byte{
		0, 3, // First two bytes encode the length.
		1, 1, 1, // The actual data.
	}

	err := WritePingPayload(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWritePongPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	data := PongPayload{1, 1, 1}
	expectedBytes := []byte{
		0, 3, // First two bytes encode the length.
		1, 1, 1, // The actual data.
	}

	err := WritePongPayload(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteErrorData(t *testing.T) {
	buf := new(bytes.Buffer)
	data := ErrorData{1, 1, 1}
	expectedBytes := []byte{
		0, 3, // First two bytes encode the length.
		1, 1, 1, // The actual data.
	}

	err := WriteErrorData(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteOpaqueReason(t *testing.T) {
	buf := new(bytes.Buffer)
	data := OpaqueReason{1, 1, 1}
	expectedBytes := []byte{
		0, 3, // First two bytes encode the length.
		1, 1, 1, // The actual data.
	}

	err := WriteOpaqueReason(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteBool(t *testing.T) {
	buf := new(bytes.Buffer)

	// Test write true.
	data := true
	expectedBytes := []byte{1}

	err := WriteBool(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())

	// Test write false.
	data = false
	expectedBytes = append(expectedBytes, 0)

	err = WriteBool(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWritePkScript(t *testing.T) {
	buf := new(bytes.Buffer)

	// Write a very long script to check the error is returned as expected.
	script := PkScript{}
	zeros := [35]byte{}
	script = append(script, zeros[:]...)
	err := WritePkScript(buf, script)
	require.Equal(t, ErrPkScriptTooLong, err)

	data := PkScript{1, 1, 1}
	expectedBytes := []byte{
		3,       // First byte encodes the length.
		1, 1, 1, // The actual data.
	}

	err = WritePkScript(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteOutPoint(t *testing.T) {
	buf := new(bytes.Buffer)

	// Create an outpoint with very large index to check the error is
	// returned as expected.
	outpointWrong := wire.OutPoint{Index: math.MaxUint16 + 1}
	err := WriteOutPoint(buf, outpointWrong)
	require.Equal(t, ErrOutpointIndexTooBig(outpointWrong.Index), err)

	// Now check the normal write succeeds.
	hash := chainhash.Hash{1}
	data := wire.OutPoint{Index: 2, Hash: hash}
	expectedBytes := []byte{}
	expectedBytes = append(expectedBytes, hash[:]...)
	expectedBytes = append(expectedBytes, []byte{0, 2}...)

	err = WriteOutPoint(buf, data)

	require.NoError(t, err)
	require.Equal(t, expectedBytes, buf.Bytes())
}

func TestWriteTCPAddr(t *testing.T) {
	buf := new(bytes.Buffer)

	testCases := []struct {
		name string
		addr *net.TCPAddr

		expectedErr   error
		expectedBytes []byte
	}{
		{
			// Check that the error is returned when nil address is
			// used.
			name:          "nil address err",
			addr:          nil,
			expectedErr:   ErrNilTCPAddress,
			expectedBytes: nil,
		},
		{
			// Check write IPv4.
			name: "write ipv4",
			addr: &net.TCPAddr{
				IP:   net.IP{127, 0, 0, 1},
				Port: 8080,
			},
			expectedErr: nil,
			expectedBytes: []byte{
				0x1,                 // The addressType.
				0x7f, 0x0, 0x0, 0x1, // The IP.
				0x1f, 0x90, // The port (31 * 256 + 144).
			},
		},
		{
			// Check write IPv6.
			name: "write ipv6",
			addr: &net.TCPAddr{
				IP: net.IP{
					1, 1, 1, 1, 1, 1, 1, 1,
					1, 1, 1, 1, 1, 1, 1, 1,
				},
				Port: 8080,
			},
			expectedErr: nil,
			expectedBytes: []byte{
				0x2, // The addressType.
				// The IP.
				0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
				0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
				0x1f, 0x90, // The port (31 * 256 + 144).
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			oldLen := buf.Len()

			err := WriteTCPAddr(buf, tc.addr)
			require.Equal(t, tc.expectedErr, err)

			bytesWritten := buf.Bytes()[oldLen:buf.Len()]
			require.Equal(t, tc.expectedBytes, bytesWritten)
		})
	}
}

func TestWriteOnionAddr(t *testing.T) {
	buf := new(bytes.Buffer)

	testCases := []struct {
		name string
		addr *tor.OnionAddr

		expectedErr   error
		expectedBytes []byte
	}{
		{
			// Check that the error is returned when nil address is
			// used.
			name:          "nil address err",
			addr:          nil,
			expectedErr:   ErrNilOnionAddress,
			expectedBytes: nil,
		},
		{
			// Check the error is returned when an invalid onion
			// address is used.
			name:          "wrong onion service length",
			addr:          &tor.OnionAddr{OnionService: "wrong"},
			expectedErr:   ErrUnknownServiceLength,
			expectedBytes: nil,
		},
		{
			// Check when the address has invalid base32 encoding,
			// the error is returned.
			name: "invalid base32 encoding",
			addr: &tor.OnionAddr{
				OnionService: "1234567890123456.onion",
			},
			expectedErr:   base32.CorruptInputError(0),
			expectedBytes: nil,
		},
		{
			// Check write onion v2.
			name: "onion address v2",
			addr: &tor.OnionAddr{
				OnionService: "abcdefghijklmnop.onion",
				Port:         9065,
			},
			expectedErr: nil,
			expectedBytes: []byte{
				0x3,                         // The descriptor.
				0x0, 0x44, 0x32, 0x14, 0xc7, // The host.
				0x42, 0x54, 0xb6, 0x35, 0xcf,
				0x23, 0x69, // The port.
			},
		},
		{
			// Check write onion v3.
			name: "onion address v3",
			addr: &tor.OnionAddr{
				OnionService: "abcdefghij" +
					"abcdefghijabcdefghij" +
					"abcdefghijabcdefghij" +
					"234567.onion",
				Port: 9065,
			},
			expectedErr: nil,
			expectedBytes: []byte{
				0x4, // The descriptor.
				0x0, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x40,
				0x11, 0xc, 0x85, 0x31, 0xd0, 0x90, 0x4,
				0x43, 0x21, 0x4c, 0x74, 0x24, 0x1, 0x10,
				0xc8, 0x53, 0x1d, 0x9, 0x0, 0x44, 0x32,
				0x14, 0xc7, 0x42, 0x75, 0xbe, 0x77, 0xdf,
				0x23, 0x69, // The port.
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			oldLen := buf.Len()

			err := WriteOnionAddr(buf, tc.addr)
			require.Equal(t, tc.expectedErr, err)

			bytesWritten := buf.Bytes()[oldLen:buf.Len()]
			require.Equal(t, tc.expectedBytes, bytesWritten)
		})
	}
}

func TestWriteNetAddrs(t *testing.T) {
	buf := new(bytes.Buffer)
	tcpAddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: 8080,
	}
	onionAddr := &tor.OnionAddr{
		OnionService: "abcdefghijklmnop.onion",
		Port:         9065,
	}

	testCases := []struct {
		name string
		addr []net.Addr

		expectedErr   error
		expectedBytes []byte
	}{
		{
			// Check that the error is returned when nil address is
			// used.
			name:          "nil address err",
			addr:          []net.Addr{nil, tcpAddr, onionAddr},
			expectedErr:   ErrNilNetAddress,
			expectedBytes: nil,
		},
		{
			// Check empty address slice.
			name:        "empty address slice",
			addr:        []net.Addr{},
			expectedErr: nil,
			// Use two bytes to encode the address size.
			expectedBytes: []byte{0, 0},
		},
		{
			// Check a successful writes of a slice of addresses.
			name:        "two addresses",
			addr:        []net.Addr{tcpAddr, onionAddr},
			expectedErr: nil,
			expectedBytes: []byte{
				// 7 bytes for TCP and 13 bytes for onion.
				0x0, 0x14,
				// TCP address.
				0x1, 0x7f, 0x0, 0x0, 0x1, 0x1f, 0x90,
				// Onion address.
				0x3, 0x0, 0x44, 0x32, 0x14, 0xc7, 0x42,
				0x54, 0xb6, 0x35, 0xcf, 0x23, 0x69,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			oldLen := buf.Len()

			err := WriteNetAddrs(buf, tc.addr)
			require.Equal(t, tc.expectedErr, err)

			bytesWritten := buf.Bytes()[oldLen:buf.Len()]
			require.Equal(t, tc.expectedBytes, bytesWritten)
		})
	}
}
