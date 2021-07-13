package lnwire

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	// ErrFeaturePairExists signals an error in feature vector construction
	// where the opposing bit in a feature pair has already been set.
	ErrFeaturePairExists = errors.New("feature pair exists")
)

// FeatureBit represents a feature that can be enabled in either a local or
// global feature vector at a specific bit position. Feature bits follow the
// "it's OK to be odd" rule, where features at even bit positions must be known
// to a node receiving them from a peer while odd bits do not. In accordance,
// feature bits are usually assigned in pairs, first being assigned an odd bit
// position which may later be changed to the preceding even position once
// knowledge of the feature becomes required on the network.
type FeatureBit uint16

const (
	// DataLossProtectRequired is a feature bit that indicates that a peer
	// *requires* the other party know about the data-loss-protect optional
	// feature. If the remote peer does not know of such a feature, then
	// the sending peer SHOLUD disconnect them. The data-loss-protect
	// feature allows a peer that's lost partial data to recover their
	// settled funds of the latest commitment state.
	DataLossProtectRequired FeatureBit = 0

	// DataLossProtectOptional is an optional feature bit that indicates
	// that the sending peer knows of this new feature and can activate it
	// it. The data-loss-protect feature allows a peer that's lost partial
	// data to recover their settled funds of the latest commitment state.
	DataLossProtectOptional FeatureBit = 1

	// InitialRoutingSync is a local feature bit meaning that the receiving
	// node should send a complete dump of routing information when a new
	// connection is established.
	InitialRoutingSync FeatureBit = 3

	// UpfrontShutdownScriptRequired is a feature bit which indicates that a
	// peer *requires* that the remote peer accept an upfront shutdown script to
	// which payout is enforced on cooperative closes.
	UpfrontShutdownScriptRequired FeatureBit = 4

	// UpfrontShutdownScriptOptional is an optional feature bit which indicates
	// that the peer will accept an upfront shutdown script to which payout is
	// enforced on cooperative closes.
	UpfrontShutdownScriptOptional FeatureBit = 5

	// GossipQueriesRequired is a feature bit that indicates that the
	// receiving peer MUST know of the set of features that allows nodes to
	// more efficiently query the network view of peers on the network for
	// reconciliation purposes.
	GossipQueriesRequired FeatureBit = 6

	// GossipQueriesOptional is an optional feature bit that signals that
	// the setting peer knows of the set of features that allows more
	// efficient network view reconciliation.
	GossipQueriesOptional FeatureBit = 7

	// TLVOnionPayloadRequired is a feature bit that indicates a node is
	// able to decode the new TLV information included in the onion packet.
	TLVOnionPayloadRequired FeatureBit = 8

	// TLVOnionPayloadOptional is an optional feature bit that indicates a
	// node is able to decode the new TLV information included in the onion
	// packet.
	TLVOnionPayloadOptional FeatureBit = 9

	// StaticRemoteKeyRequired is a required feature bit that signals that
	// within one's commitment transaction, the key used for the remote
	// party's non-delay output should not be tweaked.
	StaticRemoteKeyRequired FeatureBit = 12

	// StaticRemoteKeyOptional is an optional feature bit that signals that
	// within one's commitment transaction, the key used for the remote
	// party's non-delay output should not be tweaked.
	StaticRemoteKeyOptional FeatureBit = 13

	// PaymentAddrRequired is a required feature bit that signals that a
	// node requires payment addresses, which are used to mitigate probing
	// attacks on the receiver of a payment.
	PaymentAddrRequired FeatureBit = 14

	// PaymentAddrOptional is an optional feature bit that signals that a
	// node supports payment addresses, which are used to mitigate probing
	// attacks on the receiver of a payment.
	PaymentAddrOptional FeatureBit = 15

	// MPPOptional is a required feature bit that signals that the receiver
	// of a payment requires settlement of an invoice with more than one
	// HTLC.
	MPPRequired FeatureBit = 16

	// MPPOptional is an optional feature bit that signals that the receiver
	// of a payment supports settlement of an invoice with more than one
	// HTLC.
	MPPOptional FeatureBit = 17

	// WumboChannelsRequired is a required feature bit that signals that a
	// node is willing to accept channels larger than 2^24 satoshis.
	WumboChannelsRequired FeatureBit = 18

	// WumboChannelsOptional is an optional feature bit that signals that a
	// node is willing to accept channels larger than 2^24 satoshis.
	WumboChannelsOptional FeatureBit = 19

	// AnchorsRequired is a required feature bit that signals that the node
	// requires channels to be made using commitments having anchor
	// outputs.
	AnchorsRequired FeatureBit = 20

	// AnchorsOptional is an optional feature bit that signals that the
	// node supports channels to be made using commitments having anchor
	// outputs.
	AnchorsOptional FeatureBit = 21

	// AnchorsZeroFeeHtlcTxRequired is a required feature bit that signals
	// that the node requires channels having zero-fee second-level HTLC
	// transactions, which also imply anchor commitments.
	AnchorsZeroFeeHtlcTxRequired FeatureBit = 22

	// AnchorsZeroFeeHtlcTxRequired is an optional feature bit that signals
	// that the node supports channels having zero-fee second-level HTLC
	// transactions, which also imply anchor commitments.
	AnchorsZeroFeeHtlcTxOptional FeatureBit = 23

	// AMPRequired is a required feature bit that signals that the receiver
	// of a payment supports accepts spontaneous payments, i.e.
	// sender-generated preimages according to BOLT XX.
	AMPRequired FeatureBit = 30

	// AMPOptional is an optional feature bit that signals that the receiver
	// of a payment supports accepts spontaneous payments, i.e.
	// sender-generated preimages according to BOLT XX.
	AMPOptional FeatureBit = 31

	// maxAllowedSize is a maximum allowed size of feature vector.
	//
	// NOTE: Within the protocol, the maximum allowed message size is 65535
	// bytes for all messages. Accounting for the overhead within the feature
	// message to signal the type of message, that leaves us with 65533 bytes
	// for the init message itself.  Next, we reserve 4 bytes to encode the
	// lengths of both the local and global feature vectors, so 65529 bytes
	// for the local and global features. Knocking off one byte for the sake
	// of the calculation, that leads us to 32764 bytes for each feature
	// vector, or 131056 different features.
	maxAllowedSize = 32764
)

// IsRequired returns true if the feature bit is even, and false otherwise.
func (b FeatureBit) IsRequired() bool {
	return b&0x01 == 0x00
}

// Features is a mapping of known feature bits to a descriptive name. All known
// feature bits must be assigned a name in this mapping, and feature bit pairs
// must be assigned together for correct behavior.
var Features = map[FeatureBit]string{
	DataLossProtectRequired:       "data-loss-protect",
	DataLossProtectOptional:       "data-loss-protect",
	InitialRoutingSync:            "initial-routing-sync",
	UpfrontShutdownScriptRequired: "upfront-shutdown-script",
	UpfrontShutdownScriptOptional: "upfront-shutdown-script",
	GossipQueriesRequired:         "gossip-queries",
	GossipQueriesOptional:         "gossip-queries",
	TLVOnionPayloadRequired:       "tlv-onion",
	TLVOnionPayloadOptional:       "tlv-onion",
	StaticRemoteKeyOptional:       "static-remote-key",
	StaticRemoteKeyRequired:       "static-remote-key",
	PaymentAddrOptional:           "payment-addr",
	PaymentAddrRequired:           "payment-addr",
	MPPOptional:                   "multi-path-payments",
	MPPRequired:                   "multi-path-payments",
	AnchorsRequired:               "anchor-commitments",
	AnchorsOptional:               "anchor-commitments",
	AnchorsZeroFeeHtlcTxRequired:  "anchors-zero-fee-htlc-tx",
	AnchorsZeroFeeHtlcTxOptional:  "anchors-zero-fee-htlc-tx",
	WumboChannelsRequired:         "wumbo-channels",
	WumboChannelsOptional:         "wumbo-channels",
	AMPRequired:                   "amp",
	AMPOptional:                   "amp",
}

// RawFeatureVector represents a set of feature bits as defined in BOLT-09.  A
// RawFeatureVector itself just stores a set of bit flags but can be used to
// construct a FeatureVector which binds meaning to each bit. Feature vectors
// can be serialized and deserialized to/from a byte representation that is
// transmitted in Lightning network messages.
type RawFeatureVector struct {
	features map[FeatureBit]bool
}

// NewRawFeatureVector creates a feature vector with all of the feature bits
// given as arguments enabled.
func NewRawFeatureVector(bits ...FeatureBit) *RawFeatureVector {
	fv := &RawFeatureVector{features: make(map[FeatureBit]bool)}
	for _, bit := range bits {
		fv.Set(bit)
	}
	return fv
}

// Merges sets all feature bits in other on the receiver's feature vector.
func (fv *RawFeatureVector) Merge(other *RawFeatureVector) error {
	for bit := range other.features {
		err := fv.SafeSet(bit)
		if err != nil {
			return err
		}
	}
	return nil
}

// Clone makes a copy of a feature vector.
func (fv *RawFeatureVector) Clone() *RawFeatureVector {
	newFeatures := NewRawFeatureVector()
	for bit := range fv.features {
		newFeatures.Set(bit)
	}
	return newFeatures
}

// IsSet returns whether a particular feature bit is enabled in the vector.
func (fv *RawFeatureVector) IsSet(feature FeatureBit) bool {
	return fv.features[feature]
}

// Set marks a feature as enabled in the vector.
func (fv *RawFeatureVector) Set(feature FeatureBit) {
	fv.features[feature] = true
}

// SafeSet sets the chosen feature bit in the feature vector, but returns an
// error if the opposing feature bit is already set. This ensures both that we
// are creating properly structured feature vectors, and in some cases, that
// peers are sending properly encoded ones, i.e. it can't be both optional and
// required.
func (fv *RawFeatureVector) SafeSet(feature FeatureBit) error {
	if _, ok := fv.features[feature^1]; ok {
		return ErrFeaturePairExists
	}

	fv.Set(feature)
	return nil
}

// Unset marks a feature as disabled in the vector.
func (fv *RawFeatureVector) Unset(feature FeatureBit) {
	delete(fv.features, feature)
}

// SerializeSize returns the number of bytes needed to represent feature vector
// in byte format.
func (fv *RawFeatureVector) SerializeSize() int {
	// We calculate byte-length via the largest bit index.
	return fv.serializeSize(8)
}

// SerializeSize32 returns the number of bytes needed to represent feature
// vector in base32 format.
func (fv *RawFeatureVector) SerializeSize32() int {
	// We calculate base32-length via the largest bit index.
	return fv.serializeSize(5)
}

// serializeSize returns the number of bytes required to encode the feature
// vector using at most width bits per encoded byte.
func (fv *RawFeatureVector) serializeSize(width int) int {
	// Find the largest feature bit index
	max := -1
	for feature := range fv.features {
		index := int(feature)
		if index > max {
			max = index
		}
	}
	if max == -1 {
		return 0
	}

	return max/width + 1
}

// Encode writes the feature vector in byte representation. Every feature
// encoded as a bit, and the bit vector is serialized using the least number of
// bytes. Since the bit vector length is variable, the first two bytes of the
// serialization represent the length.
func (fv *RawFeatureVector) Encode(w io.Writer) error {
	// Write length of feature vector.
	var l [2]byte
	length := fv.SerializeSize()
	binary.BigEndian.PutUint16(l[:], uint16(length))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}

	return fv.encode(w, length, 8)
}

// EncodeBase256 writes the feature vector in base256 representation. Every
// feature is encoded as a bit, and the bit vector is serialized using the least
// number of bytes.
func (fv *RawFeatureVector) EncodeBase256(w io.Writer) error {
	length := fv.SerializeSize()
	return fv.encode(w, length, 8)
}

// EncodeBase32 writes the feature vector in base32 representation. Every feature
// is encoded as a bit, and the bit vector is serialized using the least number of
// bytes.
func (fv *RawFeatureVector) EncodeBase32(w io.Writer) error {
	length := fv.SerializeSize32()
	return fv.encode(w, length, 5)
}

// encode writes the feature vector
func (fv *RawFeatureVector) encode(w io.Writer, length, width int) error {
	// Generate the data and write it.
	data := make([]byte, length)
	for feature := range fv.features {
		byteIndex := int(feature) / width
		bitIndex := int(feature) % width
		data[length-byteIndex-1] |= 1 << uint(bitIndex)
	}

	_, err := w.Write(data)
	return err
}

// Decode reads the feature vector from its byte representation. Every feature
// is encoded as a bit, and the bit vector is serialized using the least number
// of bytes. Since the bit vector length is variable, the first two bytes of the
// serialization represent the length.
func (fv *RawFeatureVector) Decode(r io.Reader) error {
	// Read the length of the feature vector.
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint16(l[:])

	return fv.decode(r, int(length), 8)
}

// DecodeBase256 reads the feature vector from its base256 representation. Every
// feature encoded as a bit, and the bit vector is serialized using the least
// number of bytes.
func (fv *RawFeatureVector) DecodeBase256(r io.Reader, length int) error {
	return fv.decode(r, length, 8)
}

// DecodeBase32 reads the feature vector from its base32 representation. Every
// feature encoded as a bit, and the bit vector is serialized using the least
// number of bytes.
func (fv *RawFeatureVector) DecodeBase32(r io.Reader, length int) error {
	return fv.decode(r, length, 5)
}

// decode reads a feature vector from the next length bytes of the io.Reader,
// assuming each byte has width feature bits encoded per byte.
func (fv *RawFeatureVector) decode(r io.Reader, length, width int) error {
	// Read the feature vector data.
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}

	// Set feature bits from parsed data.
	bitsNumber := len(data) * width
	for i := 0; i < bitsNumber; i++ {
		byteIndex := int(i / width)
		bitIndex := uint(i % width)
		if (data[length-byteIndex-1]>>bitIndex)&1 == 1 {
			fv.Set(FeatureBit(i))
		}
	}

	return nil
}

// FeatureVector represents a set of enabled features. The set stores
// information on enabled flags and metadata about the feature names. A feature
// vector is serializable to a compact byte representation that is included in
// Lightning network messages.
type FeatureVector struct {
	*RawFeatureVector
	featureNames map[FeatureBit]string
}

// NewFeatureVector constructs a new FeatureVector from a raw feature vector
// and mapping of feature definitions. If the feature vector argument is nil, a
// new one will be constructed with no enabled features.
func NewFeatureVector(featureVector *RawFeatureVector,
	featureNames map[FeatureBit]string) *FeatureVector {

	if featureVector == nil {
		featureVector = NewRawFeatureVector()
	}
	return &FeatureVector{
		RawFeatureVector: featureVector,
		featureNames:     featureNames,
	}
}

// EmptyFeatureVector returns a feature vector with no bits set.
func EmptyFeatureVector() *FeatureVector {
	return NewFeatureVector(nil, Features)
}

// HasFeature returns whether a particular feature is included in the set. The
// feature can be seen as set either if the bit is set directly OR the queried
// bit has the same meaning as its corresponding even/odd bit, which is set
// instead. The second case is because feature bits are generally assigned in
// pairs where both the even and odd position represent the same feature.
func (fv *FeatureVector) HasFeature(feature FeatureBit) bool {
	return fv.IsSet(feature) ||
		(fv.isFeatureBitPair(feature) && fv.IsSet(feature^1))
}

// RequiresFeature returns true if the referenced feature vector *requires*
// that the given required bit be set. This method can be used with both
// optional and required feature bits as a parameter.
func (fv *FeatureVector) RequiresFeature(feature FeatureBit) bool {
	// If we weren't passed a required feature bit, then we'll flip the
	// lowest bit to query for the required version of the feature. This
	// lets callers pass in both the optional and required bits.
	if !feature.IsRequired() {
		feature ^= 1
	}

	return fv.IsSet(feature)
}

// UnknownRequiredFeatures returns a list of feature bits set in the vector
// that are unknown and in an even bit position. Feature bits with an even
// index must be known to a node receiving the feature vector in a message.
func (fv *FeatureVector) UnknownRequiredFeatures() []FeatureBit {
	var unknown []FeatureBit
	for feature := range fv.features {
		if feature%2 == 0 && !fv.IsKnown(feature) {
			unknown = append(unknown, feature)
		}
	}
	return unknown
}

// Name returns a string identifier for the feature represented by this bit. If
// the bit does not represent a known feature, this returns a string indicating
// as such.
func (fv *FeatureVector) Name(bit FeatureBit) string {
	name, known := fv.featureNames[bit]
	if !known {
		return "unknown"
	}
	return name
}

// IsKnown returns whether this feature bit represents a known feature.
func (fv *FeatureVector) IsKnown(bit FeatureBit) bool {
	_, known := fv.featureNames[bit]
	return known
}

// isFeatureBitPair returns whether this feature bit and its corresponding
// even/odd bit both represent the same feature. This may often be the case as
// bits are generally assigned in pairs, first being assigned an odd bit
// position then being promoted to an even bit position once the network is
// ready.
func (fv *FeatureVector) isFeatureBitPair(bit FeatureBit) bool {
	name1, known1 := fv.featureNames[bit]
	name2, known2 := fv.featureNames[bit^1]
	return known1 && known2 && name1 == name2
}

// Features returns the set of raw features contained in the feature vector.
func (fv *FeatureVector) Features() map[FeatureBit]struct{} {
	fs := make(map[FeatureBit]struct{}, len(fv.RawFeatureVector.features))
	for b := range fv.RawFeatureVector.features {
		fs[b] = struct{}{}
	}
	return fs
}

// Clone copies a feature vector, carrying over its feature bits. The feature
// names are not copied.
func (fv *FeatureVector) Clone() *FeatureVector {
	var features *RawFeatureVector

	if fv.RawFeatureVector != nil {
		features = fv.RawFeatureVector.Clone()
	}
	return NewFeatureVector(features, fv.featureNames)
}
