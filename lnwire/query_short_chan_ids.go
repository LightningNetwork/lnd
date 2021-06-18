package lnwire

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// ShortChanIDEncoding is an enum-like type that represents exactly how a set
// of short channel ID's is encoded on the wire. The set of encodings allows us
// to take advantage of the structure of a list of short channel ID's to
// achieving a high degree of compression.
type ShortChanIDEncoding uint8

const (
	// EncodingSortedPlain signals that the set of short channel ID's is
	// encoded using the regular encoding, in a sorted order.
	EncodingSortedPlain ShortChanIDEncoding = 0

	// EncodingSortedZlib signals that the set of short channel ID's is
	// encoded by first sorting the set of channel ID's, as then
	// compressing them using zlib.
	EncodingSortedZlib ShortChanIDEncoding = 1
)

const (
	// maxZlibBufSize is the max number of bytes that we'll accept from a
	// zlib decoding instance. We do this in order to limit the total
	// amount of memory allocated during a decoding instance.
	maxZlibBufSize = 67413630
)

// ErrUnsortedSIDs is returned when decoding a QueryShortChannelID request whose
// items were not sorted.
type ErrUnsortedSIDs struct {
	prevSID ShortChannelID
	curSID  ShortChannelID
}

// Error returns a human-readable description of the error.
func (e ErrUnsortedSIDs) Error() string {
	return fmt.Sprintf("current sid: %v isn't greater than last sid: %v",
		e.curSID, e.prevSID)
}

// zlibDecodeMtx is a package level mutex that we'll use in order to ensure
// that we'll only attempt a single zlib decoding instance at a time. This
// allows us to also further bound our memory usage.
var zlibDecodeMtx sync.Mutex

// ErrUnknownShortChanIDEncoding is a parametrized error that indicates that we
// came across an unknown short channel ID encoding, and therefore were unable
// to continue parsing.
func ErrUnknownShortChanIDEncoding(encoding ShortChanIDEncoding) error {
	return fmt.Errorf("unknown short chan id encoding: %v", encoding)
}

// QueryShortChanIDs is a message that allows the sender to query a set of
// channel announcement and channel update messages that correspond to the set
// of encoded short channel ID's. The encoding of the short channel ID's is
// detailed in the query message ensuring that the receiver knows how to
// properly decode each encode short channel ID which may be encoded using a
// compression format. The receiver should respond with a series of channel
// announcement and channel updates, finally sending a ReplyShortChanIDsEnd
// message.
type QueryShortChanIDs struct {
	// ChainHash denotes the target chain that we're querying for the
	// channel ID's of.
	ChainHash chainhash.Hash

	// EncodingType is a signal to the receiver of the message that
	// indicates exactly how the set of short channel ID's that follow have
	// been encoded.
	EncodingType ShortChanIDEncoding

	// ShortChanIDs is a slice of decoded short channel ID's.
	ShortChanIDs []ShortChannelID

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData

	// noSort indicates whether or not to sort the short channel ids before
	// writing them out.
	//
	// NOTE: This should only be used during testing.
	noSort bool
}

// NewQueryShortChanIDs creates a new QueryShortChanIDs message.
func NewQueryShortChanIDs(h chainhash.Hash, e ShortChanIDEncoding,
	s []ShortChannelID) *QueryShortChanIDs {

	return &QueryShortChanIDs{
		ChainHash:    h,
		EncodingType: e,
		ShortChanIDs: s,
	}
}

// A compile time check to ensure QueryShortChanIDs implements the
// lnwire.Message interface.
var _ Message = (*QueryShortChanIDs)(nil)

// Decode deserializes a serialized QueryShortChanIDs message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (q *QueryShortChanIDs) Decode(r io.Reader, pver uint32) error {
	err := ReadElements(r, q.ChainHash[:])
	if err != nil {
		return err
	}

	q.EncodingType, q.ShortChanIDs, err = decodeShortChanIDs(r)
	if err != nil {
		return err
	}

	return q.ExtraData.Decode(r)
}

// decodeShortChanIDs decodes a set of short channel ID's that have been
// encoded. The first byte of the body details how the short chan ID's were
// encoded. We'll use this type to govern exactly how we go about encoding the
// set of short channel ID's.
func decodeShortChanIDs(r io.Reader) (ShortChanIDEncoding, []ShortChannelID, error) {
	// First, we'll attempt to read the number of bytes in the body of the
	// set of encoded short channel ID's.
	var numBytesResp uint16
	err := ReadElements(r, &numBytesResp)
	if err != nil {
		return 0, nil, err
	}

	if numBytesResp == 0 {
		return 0, nil, nil
	}

	queryBody := make([]byte, numBytesResp)
	if _, err := io.ReadFull(r, queryBody); err != nil {
		return 0, nil, err
	}

	// The first byte is the encoding type, so we'll extract that so we can
	// continue our parsing.
	encodingType := ShortChanIDEncoding(queryBody[0])

	// Before continuing, we'll snip off the first byte of the query body
	// as that was just the encoding type.
	queryBody = queryBody[1:]

	// Otherwise, depending on the encoding type, we'll decode the encode
	// short channel ID's in a different manner.
	switch encodingType {

	// In this encoding, we'll simply read a sort array of encoded short
	// channel ID's from the buffer.
	case EncodingSortedPlain:
		// If after extracting the encoding type, the number of
		// remaining bytes is not a whole multiple of the size of an
		// encoded short channel ID (8 bytes), then we'll return a
		// parsing error.
		if len(queryBody)%8 != 0 {
			return 0, nil, fmt.Errorf("whole number of short "+
				"chan ID's cannot be encoded in len=%v",
				len(queryBody))
		}

		// As each short channel ID is encoded as 8 bytes, we can
		// compute the number of bytes encoded based on the size of the
		// query body.
		numShortChanIDs := len(queryBody) / 8
		if numShortChanIDs == 0 {
			return encodingType, nil, nil
		}

		// Finally, we'll read out the exact number of short channel
		// ID's to conclude our parsing.
		shortChanIDs := make([]ShortChannelID, numShortChanIDs)
		bodyReader := bytes.NewReader(queryBody)
		var lastChanID ShortChannelID
		for i := 0; i < numShortChanIDs; i++ {
			if err := ReadElements(bodyReader, &shortChanIDs[i]); err != nil {
				return 0, nil, fmt.Errorf("unable to parse "+
					"short chan ID: %v", err)
			}

			// We'll ensure that this short chan ID is greater than
			// the last one. This is a requirement within the
			// encoding, and if violated can aide us in detecting
			// malicious payloads. This can only be true starting
			// at the second chanID.
			cid := shortChanIDs[i]
			if i > 0 && cid.ToUint64() <= lastChanID.ToUint64() {
				return 0, nil, ErrUnsortedSIDs{lastChanID, cid}
			}
			lastChanID = cid
		}

		return encodingType, shortChanIDs, nil

	// In this encoding, we'll use zlib to decode the compressed payload.
	// However, we'll pay attention to ensure that we don't open our selves
	// up to a memory exhaustion attack.
	case EncodingSortedZlib:
		// We'll obtain an ultimately release the zlib decode mutex.
		// This guards us against allocating too much memory to decode
		// each instance from concurrent peers.
		zlibDecodeMtx.Lock()
		defer zlibDecodeMtx.Unlock()

		// At this point, if there's no body remaining, then only the encoding
		// type was specified, meaning that there're no further bytes to be
		// parsed.
		if len(queryBody) == 0 {
			return encodingType, nil, nil
		}

		// Before we start to decode, we'll create a limit reader over
		// the current reader. This will ensure that we can control how
		// much memory we're allocating during the decoding process.
		limitedDecompressor, err := zlib.NewReader(&io.LimitedReader{
			R: bytes.NewReader(queryBody),
			N: maxZlibBufSize,
		})
		if err != nil {
			return 0, nil, fmt.Errorf("unable to create zlib reader: %v", err)
		}

		var (
			shortChanIDs []ShortChannelID
			lastChanID   ShortChannelID
			i            int
		)
		for {
			// We'll now attempt to read the next short channel ID
			// encoded in the payload.
			var cid ShortChannelID
			err := ReadElements(limitedDecompressor, &cid)

			switch {
			// If we get an EOF error, then that either means we've
			// read all that's contained in the buffer, or have hit
			// our limit on the number of bytes we'll read. In
			// either case, we'll return what we have so far.
			case err == io.ErrUnexpectedEOF || err == io.EOF:
				return encodingType, shortChanIDs, nil

			// Otherwise, we hit some other sort of error, possibly
			// an invalid payload, so we'll exit early with the
			// error.
			case err != nil:
				return 0, nil, fmt.Errorf("unable to "+
					"deflate next short chan "+
					"ID: %v", err)
			}

			// We successfully read the next ID, so we'll collect
			// that in the set of final ID's to return.
			shortChanIDs = append(shortChanIDs, cid)

			// Finally, we'll ensure that this short chan ID is
			// greater than the last one. This is a requirement
			// within the encoding, and if violated can aide us in
			// detecting malicious payloads. This can only be true
			// starting at the second chanID.
			if i > 0 && cid.ToUint64() <= lastChanID.ToUint64() {
				return 0, nil, ErrUnsortedSIDs{lastChanID, cid}
			}

			lastChanID = cid
			i++
		}

	default:
		// If we've been sent an encoding type that we don't know of,
		// then we'll return a parsing error as we can't continue if
		// we're unable to encode them.
		return 0, nil, ErrUnknownShortChanIDEncoding(encodingType)
	}
}

// Encode serializes the target QueryShortChanIDs into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (q *QueryShortChanIDs) Encode(w *bytes.Buffer, pver uint32) error {
	// First, we'll write out the chain hash.
	if err := WriteBytes(w, q.ChainHash[:]); err != nil {
		return err
	}

	// Base on our encoding type, we'll write out the set of short channel
	// ID's.
	err := encodeShortChanIDs(w, q.EncodingType, q.ShortChanIDs, q.noSort)
	if err != nil {
		return err
	}

	return WriteBytes(w, q.ExtraData)
}

// encodeShortChanIDs encodes the passed short channel ID's into the passed
// io.Writer, respecting the specified encoding type.
func encodeShortChanIDs(w *bytes.Buffer, encodingType ShortChanIDEncoding,
	shortChanIDs []ShortChannelID, noSort bool) error {

	// For both of the current encoding types, the channel ID's are to be
	// sorted in place, so we'll do that now. The sorting is applied unless
	// we were specifically requested not to for testing purposes.
	if !noSort {
		sort.Slice(shortChanIDs, func(i, j int) bool {
			return shortChanIDs[i].ToUint64() <
				shortChanIDs[j].ToUint64()
		})
	}

	switch encodingType {

	// In this encoding, we'll simply write a sorted array of encoded short
	// channel ID's from the buffer.
	case EncodingSortedPlain:
		// First, we'll write out the number of bytes of the query
		// body. We add 1 as the response will have the encoding type
		// prepended to it.
		numBytesBody := uint16(len(shortChanIDs)*8) + 1
		if err := WriteUint16(w, numBytesBody); err != nil {
			return err
		}

		// We'll then write out the encoding that that follows the
		// actual encoded short channel ID's.
		err := WriteShortChanIDEncoding(w, encodingType)
		if err != nil {
			return err
		}

		// Now that we know they're sorted, we can write out each short
		// channel ID to the buffer.
		for _, chanID := range shortChanIDs {
			if err := WriteShortChannelID(w, chanID); err != nil {
				return fmt.Errorf("unable to write short chan "+
					"ID: %v", err)
			}
		}

		return nil

	// For this encoding we'll first write out a serialized version of all
	// the channel ID's into a buffer, then zlib encode that. The final
	// payload is what we'll write out to the passed io.Writer.
	//
	// TODO(roasbeef): assumes the caller knows the proper chunk size to
	// pass to avoid bin-packing here
	case EncodingSortedZlib:
		// If we don't have anything at all to write, then we'll write
		// an empty payload so we don't include things like the zlib
		// header when the remote party is expecting no actual short
		// channel IDs.
		var compressedPayload []byte
		if len(shortChanIDs) > 0 {
			// We'll make a new write buffer to hold the bytes of
			// shortChanIDs.
			var wb bytes.Buffer

			// Next, we'll write out all the channel ID's directly
			// into the zlib writer, which will do compressing on
			// the fly.
			for _, chanID := range shortChanIDs {
				err := WriteShortChannelID(&wb, chanID)
				if err != nil {
					return fmt.Errorf(
						"unable to write short chan "+
							"ID: %v", err,
					)
				}
			}

			// With shortChanIDs written into wb, we'll create a
			// zlib writer and write all the compressed bytes.
			var zlibBuffer bytes.Buffer
			zlibWriter := zlib.NewWriter(&zlibBuffer)

			if _, err := zlibWriter.Write(wb.Bytes()); err != nil {
				return fmt.Errorf(
					"unable to write compressed short chan"+
						"ID: %w", err)
			}

			// Now that we've written all the elements, we'll
			// ensure the compressed stream is written to the
			// underlying buffer.
			if err := zlibWriter.Close(); err != nil {
				return fmt.Errorf("unable to finalize "+
					"compression: %v", err)
			}

			compressedPayload = zlibBuffer.Bytes()
		}

		// Now that we have all the items compressed, we can compute
		// what the total payload size will be. We add one to account
		// for the byte to encode the type.
		//
		// If we don't have any actual bytes to write, then we'll end
		// up emitting one byte for the length, followed by the
		// encoding type, and nothing more. The spec isn't 100% clear
		// in this area, but we do this as this is what most of the
		// other implementations do.
		numBytesBody := len(compressedPayload) + 1

		// Finally, we can write out the number of bytes, the
		// compression type, and finally the buffer itself.
		if err := WriteUint16(w, uint16(numBytesBody)); err != nil {
			return err
		}
		err := WriteShortChanIDEncoding(w, encodingType)
		if err != nil {
			return err
		}

		return WriteBytes(w, compressedPayload)

	default:
		// If we're trying to encode with an encoding type that we
		// don't know of, then we'll return a parsing error as we can't
		// continue if we're unable to encode them.
		return ErrUnknownShortChanIDEncoding(encodingType)
	}
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (q *QueryShortChanIDs) MsgType() MessageType {
	return MsgQueryShortChanIDs
}
