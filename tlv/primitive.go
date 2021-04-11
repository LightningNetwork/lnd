package tlv

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// ErrTypeForEncoding signals that an incorrect type was passed to an Encoder.
type ErrTypeForEncoding struct {
	val     interface{}
	expType string
}

// NewTypeForEncodingErr creates a new ErrTypeForEncoding given the incorrect
// val and the expected type.
func NewTypeForEncodingErr(val interface{}, expType string) ErrTypeForEncoding {
	return ErrTypeForEncoding{
		val:     val,
		expType: expType,
	}
}

// Error returns a human-readable description of the type mismatch.
func (e ErrTypeForEncoding) Error() string {
	return fmt.Sprintf("ErrTypeForEncoding want (type: *%s), "+
		"got (type: %T)", e.expType, e.val)
}

// ErrTypeForDecoding signals that an incorrect type was passed to a Decoder or
// that the expected length of the encoding is different from that required by
// the expected type.
type ErrTypeForDecoding struct {
	val       interface{}
	expType   string
	valLength uint64
	expLength uint64
}

// NewTypeForDecodingErr creates a new ErrTypeForDecoding given the incorrect
// val and expected type, or the mismatch in their expected lengths.
func NewTypeForDecodingErr(val interface{}, expType string,
	valLength, expLength uint64) ErrTypeForDecoding {

	return ErrTypeForDecoding{
		val:       val,
		expType:   expType,
		valLength: valLength,
		expLength: expLength,
	}
}

// Error returns a human-readable description of the type mismatch.
func (e ErrTypeForDecoding) Error() string {
	return fmt.Sprintf("ErrTypeForDecoding want (type: *%s, length: %v), "+
		"got (type: %T, length: %v)", e.expType, e.expLength, e.val,
		e.valLength)
}

var (
	byteOrder = binary.BigEndian
)

// EUint8 is an Encoder for uint8 values. An error is returned if val is not a
// *uint8.
func EUint8(w io.Writer, val interface{}, buf *[8]byte) error {
	if i, ok := val.(*uint8); ok {
		buf[0] = *i
		_, err := w.Write(buf[:1])
		return err
	}
	return NewTypeForEncodingErr(val, "uint8")
}

// EUint8T encodes a uint8 val to the provided io.Writer. This method is exposed
// so that encodings for custom uint8-like types can be created without
// incurring an extra heap allocation.
func EUint8T(w io.Writer, val uint8, buf *[8]byte) error {
	buf[0] = val
	_, err := w.Write(buf[:1])
	return err
}

// EUint16 is an Encoder for uint16 values. An error is returned if val is not a
// *uint16.
func EUint16(w io.Writer, val interface{}, buf *[8]byte) error {
	if i, ok := val.(*uint16); ok {
		byteOrder.PutUint16(buf[:2], *i)
		_, err := w.Write(buf[:2])
		return err
	}
	return NewTypeForEncodingErr(val, "uint16")
}

// EUint16T encodes a uint16 val to the provided io.Writer. This method is
// exposed so that encodings for custom uint16-like types can be created without
// incurring an extra heap allocation.
func EUint16T(w io.Writer, val uint16, buf *[8]byte) error {
	byteOrder.PutUint16(buf[:2], val)
	_, err := w.Write(buf[:2])
	return err
}

// EUint32 is an Encoder for uint32 values. An error is returned if val is not a
// *uint32.
func EUint32(w io.Writer, val interface{}, buf *[8]byte) error {
	if i, ok := val.(*uint32); ok {
		byteOrder.PutUint32(buf[:4], *i)
		_, err := w.Write(buf[:4])
		return err
	}
	return NewTypeForEncodingErr(val, "uint32")
}

// EUint32T encodes a uint32 val to the provided io.Writer. This method is
// exposed so that encodings for custom uint32-like types can be created without
// incurring an extra heap allocation.
func EUint32T(w io.Writer, val uint32, buf *[8]byte) error {
	byteOrder.PutUint32(buf[:4], val)
	_, err := w.Write(buf[:4])
	return err
}

// EUint64 is an Encoder for uint64 values. An error is returned if val is not a
// *uint64.
func EUint64(w io.Writer, val interface{}, buf *[8]byte) error {
	if i, ok := val.(*uint64); ok {
		byteOrder.PutUint64(buf[:], *i)
		_, err := w.Write(buf[:])
		return err
	}
	return NewTypeForEncodingErr(val, "uint64")
}

// EUint64T encodes a uint64 val to the provided io.Writer. This method is
// exposed so that encodings for custom uint64-like types can be created without
// incurring an extra heap allocation.
func EUint64T(w io.Writer, val uint64, buf *[8]byte) error {
	byteOrder.PutUint64(buf[:], val)
	_, err := w.Write(buf[:])
	return err
}

// DUint8 is a Decoder for uint8 values. An error is returned if val is not a
// *uint8.
func DUint8(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if i, ok := val.(*uint8); ok && l == 1 {
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return err
		}
		*i = buf[0]
		return nil
	}
	return NewTypeForDecodingErr(val, "uint8", l, 1)
}

// DUint16 is a Decoder for uint16 values. An error is returned if val is not a
// *uint16.
func DUint16(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if i, ok := val.(*uint16); ok && l == 2 {
		if _, err := io.ReadFull(r, buf[:2]); err != nil {
			return err
		}
		*i = byteOrder.Uint16(buf[:2])
		return nil
	}
	return NewTypeForDecodingErr(val, "uint16", l, 2)
}

// DUint32 is a Decoder for uint32 values. An error is returned if val is not a
// *uint32.
func DUint32(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if i, ok := val.(*uint32); ok && l == 4 {
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return err
		}
		*i = byteOrder.Uint32(buf[:4])
		return nil
	}
	return NewTypeForDecodingErr(val, "uint32", l, 4)
}

// DUint64 is a Decoder for uint64 values. An error is returned if val is not a
// *uint64.
func DUint64(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if i, ok := val.(*uint64); ok && l == 8 {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return err
		}
		*i = byteOrder.Uint64(buf[:])
		return nil
	}
	return NewTypeForDecodingErr(val, "uint64", l, 8)
}

// EBytes32 is an Encoder for 32-byte arrays. An error is returned if val is not
// a *[32]byte.
func EBytes32(w io.Writer, val interface{}, _ *[8]byte) error {
	if b, ok := val.(*[32]byte); ok {
		_, err := w.Write(b[:])
		return err
	}
	return NewTypeForEncodingErr(val, "[32]byte")
}

// DBytes32 is a Decoder for 32-byte arrays. An error is returned if val is not
// a *[32]byte.
func DBytes32(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	if b, ok := val.(*[32]byte); ok && l == 32 {
		_, err := io.ReadFull(r, b[:])
		return err
	}
	return NewTypeForDecodingErr(val, "[32]byte", l, 32)
}

// EBytes33 is an Encoder for 33-byte arrays. An error is returned if val is not
// a *[33]byte.
func EBytes33(w io.Writer, val interface{}, _ *[8]byte) error {
	if b, ok := val.(*[33]byte); ok {
		_, err := w.Write(b[:])
		return err
	}
	return NewTypeForEncodingErr(val, "[33]byte")
}

// DBytes33 is a Decoder for 33-byte arrays. An error is returned if val is not
// a *[33]byte.
func DBytes33(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	if b, ok := val.(*[33]byte); ok {
		_, err := io.ReadFull(r, b[:])
		return err
	}
	return NewTypeForDecodingErr(val, "[33]byte", l, 33)
}

// EBytes64 is an Encoder for 64-byte arrays. An error is returned if val is not
// a *[64]byte.
func EBytes64(w io.Writer, val interface{}, _ *[8]byte) error {
	if b, ok := val.(*[64]byte); ok {
		_, err := w.Write(b[:])
		return err
	}
	return NewTypeForEncodingErr(val, "[64]byte")
}

// DBytes64 is an Decoder for 64-byte arrays. An error is returned if val is not
// a *[64]byte.
func DBytes64(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	if b, ok := val.(*[64]byte); ok && l == 64 {
		_, err := io.ReadFull(r, b[:])
		return err
	}
	return NewTypeForDecodingErr(val, "[64]byte", l, 64)
}

// EPubKey is an Encoder for *btcec.PublicKey values. An error is returned if
// val is not a **btcec.PublicKey.
func EPubKey(w io.Writer, val interface{}, _ *[8]byte) error {
	if pk, ok := val.(**btcec.PublicKey); ok && *pk != nil {
		_, err := w.Write((*pk).SerializeCompressed())
		return err
	}
	return NewTypeForEncodingErr(val, "*btcec.PublicKey")
}

// DPubKey is a Decoder for *btcec.PublicKey values. An error is returned if val
// is not a **btcec.PublicKey.
func DPubKey(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	if pk, ok := val.(**btcec.PublicKey); ok && l == 33 {
		var b [33]byte
		_, err := io.ReadFull(r, b[:])
		if err != nil {
			return err
		}

		p, err := btcec.ParsePubKey(b[:], btcec.S256())
		if err != nil {
			return err
		}

		*pk = p

		return nil
	}
	return NewTypeForDecodingErr(val, "*btcec.PublicKey", l, 33)
}

// EVarBytes is an Encoder for variable byte slices. An error is returned if val
// is not *[]byte.
func EVarBytes(w io.Writer, val interface{}, _ *[8]byte) error {
	if b, ok := val.(*[]byte); ok {
		_, err := w.Write(*b)
		return err
	}
	return NewTypeForEncodingErr(val, "[]byte")
}

// DVarBytes is a Decoder for variable byte slices. An error is returned if val
// is not *[]byte.
func DVarBytes(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	if b, ok := val.(*[]byte); ok {
		*b = make([]byte, l)
		_, err := io.ReadFull(r, *b)
		return err
	}
	return NewTypeForDecodingErr(val, "[]byte", l, l)
}
