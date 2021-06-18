package lnwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image/color"
	"math"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/tor"
)

var (
	// ErrNilFeatureVector is returned when the supplied feature is nil.
	ErrNilFeatureVector = errors.New("cannot write nil feature vector")

	// ErrPkScriptTooLong is returned when the length of the provided
	// script exceeds 34.
	ErrPkScriptTooLong = errors.New("'PkScript' too long")

	// ErrNilTCPAddress is returned when the supplied address is nil.
	ErrNilTCPAddress = errors.New("cannot write nil TCPAddr")

	// ErrNilOnionAddress is returned when the supplied address is nil.
	ErrNilOnionAddress = errors.New("cannot write nil onion address")

	// ErrNilNetAddress is returned when a nil value is used in []net.Addr.
	ErrNilNetAddress = errors.New("cannot write nil address")

	// ErrNilPublicKey is returned when a nil pubkey is used.
	ErrNilPublicKey = errors.New("cannot write nil pubkey")

	// ErrUnknownServiceLength is returned when the onion service length is
	// unknown.
	ErrUnknownServiceLength = errors.New("unknown onion service length")
)

// ErrOutpointIndexTooBig is used when the outpoint index exceeds the max value
// of uint16.
func ErrOutpointIndexTooBig(index uint32) error {
	return fmt.Errorf(
		"index for outpoint (%v) is greater than "+
			"max index of %v", index, math.MaxUint16,
	)
}

// WriteBytes appends the given bytes to the provided buffer.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func WriteBytes(buf *bytes.Buffer, b []byte) error { // nolint: interfacer
	_, err := buf.Write(b)
	return err
}

// WriteUint8 appends the uint8 to the provided buffer.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func WriteUint8(buf *bytes.Buffer, n uint8) error { // nolint: interfacer
	_, err := buf.Write([]byte{n})
	return err
}

// WriteUint16 appends the uint16 to the provided buffer. It encodes the
// integer using big endian byte order.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func WriteUint16(buf *bytes.Buffer, n uint16) error { // nolint: interfacer
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	_, err := buf.Write(b[:])
	return err
}

// WriteUint32 appends the uint32 to the provided buffer. It encodes the
// integer using big endian byte order.
func WriteUint32(buf *bytes.Buffer, n uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	_, err := buf.Write(b[:])
	return err
}

// WriteUint64 appends the uint64 to the provided buffer. It encodes the
// integer using big endian byte order.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func WriteUint64(buf *bytes.Buffer, n uint64) error { // nolint: interfacer
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	_, err := buf.Write(b[:])
	return err
}

// WriteSatoshi appends the Satoshi value to the provided buffer.
func WriteSatoshi(buf *bytes.Buffer, amount btcutil.Amount) error {
	return WriteUint64(buf, uint64(amount))
}

// WriteMilliSatoshi appends the MilliSatoshi value to the provided buffer.
func WriteMilliSatoshi(buf *bytes.Buffer, amount MilliSatoshi) error {
	return WriteUint64(buf, uint64(amount))
}

// WritePublicKey appends the compressed public key to the provided buffer.
func WritePublicKey(buf *bytes.Buffer, pub *btcec.PublicKey) error {
	if pub == nil {
		return ErrNilPublicKey
	}

	serializedPubkey := pub.SerializeCompressed()
	return WriteBytes(buf, serializedPubkey)

}

// WriteChannelID appends the ChannelID to the provided buffer.
func WriteChannelID(buf *bytes.Buffer, channelID ChannelID) error {
	return WriteBytes(buf, channelID[:])
}

// WriteNodeAlias appends the alias to the provided buffer.
func WriteNodeAlias(buf *bytes.Buffer, alias NodeAlias) error {
	return WriteBytes(buf, alias[:])
}

// WriteShortChannelID appends the ShortChannelID to the provided buffer. It
// encodes the BlockHeight and TxIndex each using 3 bytes with big endian byte
// order, and encodes txPosition using 2 bytes with big endian byte order.
func WriteShortChannelID(buf *bytes.Buffer, shortChanID ShortChannelID) error {
	// Check that field fit in 3 bytes and write the blockHeight
	if shortChanID.BlockHeight > ((1 << 24) - 1) {
		return errors.New("block height should fit in 3 bytes")
	}

	var blockHeight [4]byte
	binary.BigEndian.PutUint32(blockHeight[:], shortChanID.BlockHeight)

	if _, err := buf.Write(blockHeight[1:]); err != nil {
		return err
	}

	// Check that field fit in 3 bytes and write the txIndex
	if shortChanID.TxIndex > ((1 << 24) - 1) {
		return errors.New("tx index should fit in 3 bytes")
	}

	var txIndex [4]byte
	binary.BigEndian.PutUint32(txIndex[:], shortChanID.TxIndex)
	if _, err := buf.Write(txIndex[1:]); err != nil {
		return err
	}

	// Write the TxPosition
	return WriteUint16(buf, shortChanID.TxPosition)
}

// WriteSig appends the signature to the provided buffer.
func WriteSig(buf *bytes.Buffer, sig Sig) error {
	return WriteBytes(buf, sig[:])
}

// WriteSigs appends the slice of signatures to the provided buffer with its
// length.
func WriteSigs(buf *bytes.Buffer, sigs []Sig) error {
	// Write the length of the sigs.
	if err := WriteUint16(buf, uint16(len(sigs))); err != nil {
		return err
	}

	for _, sig := range sigs {
		if err := WriteSig(buf, sig); err != nil {
			return err
		}
	}
	return nil
}

// WriteFailCode appends the FailCode to the provided buffer.
func WriteFailCode(buf *bytes.Buffer, e FailCode) error {
	return WriteUint16(buf, uint16(e))
}

// WriteRawFeatureVector encodes the feature using the feature's Encode method
// and appends the data to the provided buffer. An error will return if the
// passed feature is nil.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func WriteRawFeatureVector(buf *bytes.Buffer, // nolint: interfacer
	feature *RawFeatureVector) error {

	if feature == nil {
		return ErrNilFeatureVector
	}

	return feature.Encode(buf)
}

// WriteColorRGBA appends the RGBA color using three bytes.
func WriteColorRGBA(buf *bytes.Buffer, e color.RGBA) error {
	// Write R
	if err := WriteUint8(buf, e.R); err != nil {
		return err
	}

	// Write G
	if err := WriteUint8(buf, e.G); err != nil {
		return err
	}

	// Write B
	return WriteUint8(buf, e.B)
}

// WriteShortChanIDEncoding appends the ShortChanIDEncoding to the provided
// buffer.
func WriteShortChanIDEncoding(buf *bytes.Buffer, e ShortChanIDEncoding) error {
	return WriteUint8(buf, uint8(e))
}

// WriteFundingFlag appends the FundingFlag to the provided buffer.
func WriteFundingFlag(buf *bytes.Buffer, flag FundingFlag) error {
	return WriteUint8(buf, uint8(flag))
}

// WriteChanUpdateMsgFlags appends the update flag to the provided buffer.
func WriteChanUpdateMsgFlags(buf *bytes.Buffer, f ChanUpdateMsgFlags) error {
	return WriteUint8(buf, uint8(f))
}

// WriteChanUpdateChanFlags appends the update flag to the provided buffer.
func WriteChanUpdateChanFlags(buf *bytes.Buffer, f ChanUpdateChanFlags) error {
	return WriteUint8(buf, uint8(f))
}

// WriteDeliveryAddress appends the address to the provided buffer.
func WriteDeliveryAddress(buf *bytes.Buffer, addr DeliveryAddress) error {
	return writeDataWithLength(buf, addr)
}

// WritePingPayload appends the payload to the provided buffer.
func WritePingPayload(buf *bytes.Buffer, payload PingPayload) error {
	return writeDataWithLength(buf, payload)
}

// WritePongPayload appends the payload to the provided buffer.
func WritePongPayload(buf *bytes.Buffer, payload PongPayload) error {
	return writeDataWithLength(buf, payload)
}

// WriteErrorData appends the data to the provided buffer.
func WriteErrorData(buf *bytes.Buffer, data ErrorData) error {
	return writeDataWithLength(buf, data)
}

// WriteOpaqueReason appends the reason to the provided buffer.
func WriteOpaqueReason(buf *bytes.Buffer, reason OpaqueReason) error {
	return writeDataWithLength(buf, reason)
}

// WriteBool appends the boolean to the provided buffer.
func WriteBool(buf *bytes.Buffer, b bool) error {
	if b {
		return WriteBytes(buf, []byte{1})
	}
	return WriteBytes(buf, []byte{0})
}

// WritePkScript appends the script to the provided buffer. Returns an error if
// the provided script exceeds 34 bytes.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func WritePkScript(buf *bytes.Buffer, s PkScript) error { // nolint: interfacer
	// The largest script we'll accept is a p2wsh which is exactly
	// 34 bytes long.
	scriptLength := len(s)
	if scriptLength > 34 {
		return ErrPkScriptTooLong
	}

	return wire.WriteVarBytes(buf, 0, s)
}

// WriteOutPoint appends the outpoint to the provided buffer.
func WriteOutPoint(buf *bytes.Buffer, p wire.OutPoint) error {
	// Before we write anything to the buffer, check the Index is sane.
	if p.Index > math.MaxUint16 {
		return ErrOutpointIndexTooBig(p.Index)
	}

	var h [32]byte
	copy(h[:], p.Hash[:])
	if _, err := buf.Write(h[:]); err != nil {
		return err
	}

	// Write the index using two bytes.
	return WriteUint16(buf, uint16(p.Index))
}

// WriteTCPAddr appends the TCP address to the provided buffer, either a IPv4
// or a IPv6.
func WriteTCPAddr(buf *bytes.Buffer, addr *net.TCPAddr) error {
	if addr == nil {
		return ErrNilTCPAddress
	}

	// Make a slice of bytes to hold the data of descriptor and ip. At
	// most, we need 17 bytes - 1 byte for the descriptor, 16 bytes for
	// IPv6.
	data := make([]byte, 0, 17)

	if addr.IP.To4() != nil {
		data = append(data, uint8(tcp4Addr))
		data = append(data, addr.IP.To4()...)
	} else {
		data = append(data, uint8(tcp6Addr))
		data = append(data, addr.IP.To16()...)
	}

	if _, err := buf.Write(data); err != nil {
		return err
	}

	return WriteUint16(buf, uint16(addr.Port))
}

// WriteOnionAddr appends the onion address to the provided buffer.
func WriteOnionAddr(buf *bytes.Buffer, addr *tor.OnionAddr) error {
	if addr == nil {
		return ErrNilOnionAddress
	}

	var (
		suffixIndex int
		descriptor  []byte
	)

	// Decide the suffixIndex and descriptor.
	switch len(addr.OnionService) {
	case tor.V2Len:
		descriptor = []byte{byte(v2OnionAddr)}
		suffixIndex = tor.V2Len - tor.OnionSuffixLen

	case tor.V3Len:
		descriptor = []byte{byte(v3OnionAddr)}
		suffixIndex = tor.V3Len - tor.OnionSuffixLen

	default:
		return ErrUnknownServiceLength
	}

	// Decode the address.
	host, err := tor.Base32Encoding.DecodeString(
		addr.OnionService[:suffixIndex],
	)
	if err != nil {
		return err
	}

	// Perform the actual write when the above checks passed.
	if _, err := buf.Write(descriptor); err != nil {
		return err
	}
	if _, err := buf.Write(host); err != nil {
		return err
	}

	return WriteUint16(buf, uint16(addr.Port))
}

// WriteNetAddrs appends a slice of addresses to the provided buffer with the
// length info.
func WriteNetAddrs(buf *bytes.Buffer, addresses []net.Addr) error {
	// First, we'll encode all the addresses into an intermediate
	// buffer. We need to do this in order to compute the total
	// length of the addresses.
	buffer := make([]byte, 0, MaxMsgBody)
	addrBuf := bytes.NewBuffer(buffer)

	for _, address := range addresses {
		switch a := address.(type) {
		case *net.TCPAddr:
			if err := WriteTCPAddr(addrBuf, a); err != nil {
				return err
			}
		case *tor.OnionAddr:
			if err := WriteOnionAddr(addrBuf, a); err != nil {
				return err
			}
		default:
			return ErrNilNetAddress
		}
	}

	// With the addresses fully encoded, we can now write out data.
	return writeDataWithLength(buf, addrBuf.Bytes())
}

// writeDataWithLength writes the data and its length to the buffer.
//
// Note: We intentionally skip the interfacer linter check here because we want
// to have concrete type (bytes.Buffer) rather than interface type (io.Write)
// due to performance concern.
func writeDataWithLength(buf *bytes.Buffer, // nolint: interfacer
	data []byte) error {

	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(data)))
	if _, err := buf.Write(l[:]); err != nil {
		return err
	}

	_, err := buf.Write(data)
	return err
}
