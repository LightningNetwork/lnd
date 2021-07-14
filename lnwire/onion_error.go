package lnwire

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"bytes"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/tlv"
)

// FailureMessage represents the onion failure object identified by its unique
// failure code.
type FailureMessage interface {
	// Code returns a failure code describing the exact nature of the
	// error.
	Code() FailCode

	// Error returns a human readable string describing the error. With
	// this method, the FailureMessage interface meets the built-in error
	// interface.
	Error() string
}

// FailureMessageLength is the size of the failure message plus the size of
// padding. The FailureMessage message should always be EXACTLY this size.
const FailureMessageLength = 256

const (
	// FlagBadOnion error flag describes an unparsable, encrypted by
	// previous node.
	FlagBadOnion FailCode = 0x8000

	// FlagPerm error flag indicates a permanent failure.
	FlagPerm FailCode = 0x4000

	// FlagNode error flag indicates a node failure.
	FlagNode FailCode = 0x2000

	// FlagUpdate error flag indicates a new channel update is enclosed
	// within the error.
	FlagUpdate FailCode = 0x1000
)

// FailCode specifies the precise reason that an upstream HTLC was canceled.
// Each UpdateFailHTLC message carries a FailCode which is to be passed
// backwards, encrypted at each step back to the source of the HTLC within the
// route.
type FailCode uint16

// The currently defined onion failure types within this current version of the
// Lightning protocol.
const (
	CodeNone                             FailCode = 0
	CodeInvalidRealm                              = FlagBadOnion | 1
	CodeTemporaryNodeFailure                      = FlagNode | 2
	CodePermanentNodeFailure                      = FlagPerm | FlagNode | 2
	CodeRequiredNodeFeatureMissing                = FlagPerm | FlagNode | 3
	CodeInvalidOnionVersion                       = FlagBadOnion | FlagPerm | 4
	CodeInvalidOnionHmac                          = FlagBadOnion | FlagPerm | 5
	CodeInvalidOnionKey                           = FlagBadOnion | FlagPerm | 6
	CodeTemporaryChannelFailure                   = FlagUpdate | 7
	CodePermanentChannelFailure                   = FlagPerm | 8
	CodeRequiredChannelFeatureMissing             = FlagPerm | 9
	CodeUnknownNextPeer                           = FlagPerm | 10
	CodeAmountBelowMinimum                        = FlagUpdate | 11
	CodeFeeInsufficient                           = FlagUpdate | 12
	CodeIncorrectCltvExpiry                       = FlagUpdate | 13
	CodeExpiryTooSoon                             = FlagUpdate | 14
	CodeChannelDisabled                           = FlagUpdate | 20
	CodeIncorrectOrUnknownPaymentDetails          = FlagPerm | 15
	CodeIncorrectPaymentAmount                    = FlagPerm | 16
	CodeFinalExpiryTooSoon               FailCode = 17
	CodeFinalIncorrectCltvExpiry         FailCode = 18
	CodeFinalIncorrectHtlcAmount         FailCode = 19
	CodeExpiryTooFar                     FailCode = 21
	CodeInvalidOnionPayload                       = FlagPerm | 22
	CodeMPPTimeout                       FailCode = 23
)

// String returns the string representation of the failure code.
func (c FailCode) String() string {
	switch c {
	case CodeInvalidRealm:
		return "InvalidRealm"

	case CodeTemporaryNodeFailure:
		return "TemporaryNodeFailure"

	case CodePermanentNodeFailure:
		return "PermanentNodeFailure"

	case CodeRequiredNodeFeatureMissing:
		return "RequiredNodeFeatureMissing"

	case CodeInvalidOnionVersion:
		return "InvalidOnionVersion"

	case CodeInvalidOnionHmac:
		return "InvalidOnionHmac"

	case CodeInvalidOnionKey:
		return "InvalidOnionKey"

	case CodeTemporaryChannelFailure:
		return "TemporaryChannelFailure"

	case CodePermanentChannelFailure:
		return "PermanentChannelFailure"

	case CodeRequiredChannelFeatureMissing:
		return "RequiredChannelFeatureMissing"

	case CodeUnknownNextPeer:
		return "UnknownNextPeer"

	case CodeAmountBelowMinimum:
		return "AmountBelowMinimum"

	case CodeFeeInsufficient:
		return "FeeInsufficient"

	case CodeIncorrectCltvExpiry:
		return "IncorrectCltvExpiry"

	case CodeIncorrectPaymentAmount:
		return "IncorrectPaymentAmount"

	case CodeExpiryTooSoon:
		return "ExpiryTooSoon"

	case CodeChannelDisabled:
		return "ChannelDisabled"

	case CodeIncorrectOrUnknownPaymentDetails:
		return "IncorrectOrUnknownPaymentDetails"

	case CodeFinalExpiryTooSoon:
		return "FinalExpiryTooSoon"

	case CodeFinalIncorrectCltvExpiry:
		return "FinalIncorrectCltvExpiry"

	case CodeFinalIncorrectHtlcAmount:
		return "FinalIncorrectHtlcAmount"

	case CodeExpiryTooFar:
		return "ExpiryTooFar"

	case CodeInvalidOnionPayload:
		return "InvalidOnionPayload"

	case CodeMPPTimeout:
		return "MPPTimeout"

	default:
		return "<unknown>"
	}
}

// FailInvalidRealm is returned if the realm byte is unknown.
//
// NOTE: May be returned by any node in the payment route.
type FailInvalidRealm struct{}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailInvalidRealm) Error() string {
	return f.Code().String()
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailInvalidRealm) Code() FailCode {
	return CodeInvalidRealm
}

// FailTemporaryNodeFailure is returned if an otherwise unspecified transient
// error occurs for the entire node.
//
// NOTE: May be returned by any node in the payment route.
type FailTemporaryNodeFailure struct{}

// Code returns the failure unique code.
// NOTE: Part of the FailureMessage interface.
func (f *FailTemporaryNodeFailure) Code() FailCode {
	return CodeTemporaryNodeFailure
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailTemporaryNodeFailure) Error() string {
	return f.Code().String()
}

// FailPermanentNodeFailure is returned if an otherwise unspecified permanent
// error occurs for the entire node.
//
// NOTE: May be returned by any node in the payment route.
type FailPermanentNodeFailure struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailPermanentNodeFailure) Code() FailCode {
	return CodePermanentNodeFailure
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailPermanentNodeFailure) Error() string {
	return f.Code().String()
}

// FailRequiredNodeFeatureMissing is returned if a node has requirement
// advertised in its node_announcement features which were not present in the
// onion.
//
// NOTE: May be returned by any node in the payment route.
type FailRequiredNodeFeatureMissing struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailRequiredNodeFeatureMissing) Code() FailCode {
	return CodeRequiredNodeFeatureMissing
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailRequiredNodeFeatureMissing) Error() string {
	return f.Code().String()
}

// FailPermanentChannelFailure is return if an otherwise unspecified permanent
// error occurs for the outgoing channel (eg. channel (recently).
//
// NOTE: May be returned by any node in the payment route.
type FailPermanentChannelFailure struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailPermanentChannelFailure) Code() FailCode {
	return CodePermanentChannelFailure
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailPermanentChannelFailure) Error() string {
	return f.Code().String()
}

// FailRequiredChannelFeatureMissing is returned if the outgoing channel has a
// requirement advertised in its channel announcement features which were not
// present in the onion.
//
// NOTE: May only be returned by intermediate nodes.
type FailRequiredChannelFeatureMissing struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailRequiredChannelFeatureMissing) Code() FailCode {
	return CodeRequiredChannelFeatureMissing
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailRequiredChannelFeatureMissing) Error() string {
	return f.Code().String()
}

// FailUnknownNextPeer is returned if the next peer specified by the onion is
// not known.
//
// NOTE: May only be returned by intermediate nodes.
type FailUnknownNextPeer struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailUnknownNextPeer) Code() FailCode {
	return CodeUnknownNextPeer
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailUnknownNextPeer) Error() string {
	return f.Code().String()
}

// FailIncorrectPaymentAmount is returned if the amount paid is less than the
// amount expected, the final node MUST fail the HTLC. If the amount paid is
// more than twice the amount expected, the final node SHOULD fail the HTLC.
// This allows the sender to reduce information leakage by altering the amount,
// without allowing accidental gross overpayment.
//
// NOTE: May only be returned by the final node in the path.
type FailIncorrectPaymentAmount struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailIncorrectPaymentAmount) Code() FailCode {
	return CodeIncorrectPaymentAmount
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailIncorrectPaymentAmount) Error() string {
	return f.Code().String()
}

// FailIncorrectDetails is returned for two reasons:
//
// 1) if the payment hash has already been paid, the final node MAY treat the
// payment hash as unknown, or may succeed in accepting the HTLC. If the
// payment hash is unknown, the final node MUST fail the HTLC.
//
// 2) if the amount paid is less than the amount expected, the final node MUST
// fail the HTLC. If the amount paid is more than twice the amount expected,
// the final node SHOULD fail the HTLC. This allows the sender to reduce
// information leakage by altering the amount, without allowing accidental
// gross overpayment.
//
// NOTE: May only be returned by the final node in the path.
type FailIncorrectDetails struct {
	// amount is the value of the extended HTLC.
	amount MilliSatoshi

	// height is the block height when the htlc was received.
	height uint32
}

// NewFailIncorrectDetails makes a new instance of the FailIncorrectDetails
// error bound to the specified HTLC amount and acceptance height.
func NewFailIncorrectDetails(amt MilliSatoshi,
	height uint32) *FailIncorrectDetails {

	return &FailIncorrectDetails{
		amount: amt,
		height: height,
	}
}

// Amount is the value of the extended HTLC.
func (f *FailIncorrectDetails) Amount() MilliSatoshi {
	return f.amount
}

// Height is the block height when the htlc was received.
func (f *FailIncorrectDetails) Height() uint32 {
	return f.height
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailIncorrectDetails) Code() FailCode {
	return CodeIncorrectOrUnknownPaymentDetails
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailIncorrectDetails) Error() string {
	return fmt.Sprintf(
		"%v(amt=%v, height=%v)", CodeIncorrectOrUnknownPaymentDetails,
		f.amount, f.height,
	)
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailIncorrectDetails) Decode(r io.Reader, pver uint32) error {
	err := ReadElement(r, &f.amount)
	switch {
	// This is an optional tack on that was added later in the protocol. As
	// a result, older nodes may not include this value. We'll account for
	// this by checking for io.EOF here which means that no bytes were read
	// at all.
	case err == io.EOF:
		return nil

	case err != nil:
		return err
	}

	// At a later stage, the height field was also tacked on. We need to
	// check for io.EOF here as well.
	err = ReadElement(r, &f.height)
	switch {
	case err == io.EOF:
		return nil

	case err != nil:
		return err
	}

	return nil
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailIncorrectDetails) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteMilliSatoshi(w, f.amount); err != nil {
		return err
	}

	return WriteUint32(w, f.height)
}

// FailFinalExpiryTooSoon is returned if the cltv_expiry is too low, the final
// node MUST fail the HTLC.
//
// NOTE: May only be returned by the final node in the path.
type FailFinalExpiryTooSoon struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailFinalExpiryTooSoon) Code() FailCode {
	return CodeFinalExpiryTooSoon
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailFinalExpiryTooSoon) Error() string {
	return f.Code().String()
}

// NewFinalExpiryTooSoon creates new instance of the FailFinalExpiryTooSoon.
func NewFinalExpiryTooSoon() *FailFinalExpiryTooSoon {
	return &FailFinalExpiryTooSoon{}
}

// FailInvalidOnionVersion is returned if the onion version byte is unknown.
//
// NOTE: May be returned only by intermediate nodes.
type FailInvalidOnionVersion struct {
	// OnionSHA256 hash of the onion blob which haven't been proceeded.
	OnionSHA256 [sha256.Size]byte
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailInvalidOnionVersion) Error() string {
	return fmt.Sprintf("InvalidOnionVersion(onion_sha=%x)", f.OnionSHA256[:])
}

// NewInvalidOnionVersion creates new instance of the FailInvalidOnionVersion.
func NewInvalidOnionVersion(onion []byte) *FailInvalidOnionVersion {
	return &FailInvalidOnionVersion{OnionSHA256: sha256.Sum256(onion)}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailInvalidOnionVersion) Code() FailCode {
	return CodeInvalidOnionVersion
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailInvalidOnionVersion) Decode(r io.Reader, pver uint32) error {
	return ReadElement(r, f.OnionSHA256[:])
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailInvalidOnionVersion) Encode(w *bytes.Buffer, pver uint32) error {
	return WriteBytes(w, f.OnionSHA256[:])
}

// FailInvalidOnionHmac is return if the onion HMAC is incorrect.
//
// NOTE: May only be returned by intermediate nodes.
type FailInvalidOnionHmac struct {
	// OnionSHA256 hash of the onion blob which haven't been proceeded.
	OnionSHA256 [sha256.Size]byte
}

// NewInvalidOnionHmac creates new instance of the FailInvalidOnionHmac.
func NewInvalidOnionHmac(onion []byte) *FailInvalidOnionHmac {
	return &FailInvalidOnionHmac{OnionSHA256: sha256.Sum256(onion)}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailInvalidOnionHmac) Code() FailCode {
	return CodeInvalidOnionHmac
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailInvalidOnionHmac) Decode(r io.Reader, pver uint32) error {
	return ReadElement(r, f.OnionSHA256[:])
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailInvalidOnionHmac) Encode(w *bytes.Buffer, pver uint32) error {
	return WriteBytes(w, f.OnionSHA256[:])
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailInvalidOnionHmac) Error() string {
	return fmt.Sprintf("InvalidOnionHMAC(onion_sha=%x)", f.OnionSHA256[:])
}

// FailInvalidOnionKey is return if the ephemeral key in the onion is
// unparsable.
//
// NOTE: May only be returned by intermediate nodes.
type FailInvalidOnionKey struct {
	// OnionSHA256 hash of the onion blob which haven't been proceeded.
	OnionSHA256 [sha256.Size]byte
}

// NewInvalidOnionKey creates new instance of the FailInvalidOnionKey.
func NewInvalidOnionKey(onion []byte) *FailInvalidOnionKey {
	return &FailInvalidOnionKey{OnionSHA256: sha256.Sum256(onion)}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailInvalidOnionKey) Code() FailCode {
	return CodeInvalidOnionKey
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailInvalidOnionKey) Decode(r io.Reader, pver uint32) error {
	return ReadElement(r, f.OnionSHA256[:])
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailInvalidOnionKey) Encode(w *bytes.Buffer, pver uint32) error {
	return WriteBytes(w, f.OnionSHA256[:])
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailInvalidOnionKey) Error() string {
	return fmt.Sprintf("InvalidOnionKey(onion_sha=%x)", f.OnionSHA256[:])
}

// parseChannelUpdateCompatabilityMode will attempt to parse a channel updated
// encoded into an onion error payload in two ways. First, we'll try the
// compatibility oriented version wherein we'll _skip_ the length prefixing on
// the channel update message. Older versions of c-lighting do this so we'll
// attempt to parse these messages in order to retain compatibility. If we're
// unable to pull out a fully valid version, then we'll fall back to the
// regular parsing mechanism which includes the length prefix an NO type byte.
func parseChannelUpdateCompatabilityMode(r *bufio.Reader,
	chanUpdate *ChannelUpdate, pver uint32) error {

	// We'll peek out two bytes from the buffer without advancing the
	// buffer so we can decide how to parse the remainder of it.
	maybeTypeBytes, err := r.Peek(2)
	if err != nil {
		return err
	}

	// Some nodes well prefix an additional set of bytes in front of their
	// channel updates. These bytes will _almost_ always be 258 or the type
	// of the ChannelUpdate message.
	typeInt := binary.BigEndian.Uint16(maybeTypeBytes)
	if typeInt == MsgChannelUpdate {
		// At this point it's likely the case that this is a channel
		// update message with its type prefixed, so we'll snip off the
		// first two bytes and parse it as normal.
		var throwAwayTypeBytes [2]byte
		_, err := r.Read(throwAwayTypeBytes[:])
		if err != nil {
			return err
		}
	}

	// At this pint, we've either decided to keep the entire thing, or snip
	// off the first two bytes. In either case, we can just read it as
	// normal.
	return chanUpdate.Decode(r, pver)
}

// FailTemporaryChannelFailure is if an otherwise unspecified transient error
// occurs for the outgoing channel (eg. channel capacity reached, too many
// in-flight htlcs)
//
// NOTE: May only be returned by intermediate nodes.
type FailTemporaryChannelFailure struct {
	// Update is used to update information about state of the channel
	// which caused the failure.
	//
	// NOTE: This field is optional.
	Update *ChannelUpdate
}

// NewTemporaryChannelFailure creates new instance of the FailTemporaryChannelFailure.
func NewTemporaryChannelFailure(update *ChannelUpdate) *FailTemporaryChannelFailure {
	return &FailTemporaryChannelFailure{Update: update}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailTemporaryChannelFailure) Code() FailCode {
	return CodeTemporaryChannelFailure
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailTemporaryChannelFailure) Error() string {
	if f.Update == nil {
		return f.Code().String()
	}

	return fmt.Sprintf("TemporaryChannelFailure(update=%v)",
		spew.Sdump(f.Update))
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailTemporaryChannelFailure) Decode(r io.Reader, pver uint32) error {
	var length uint16
	err := ReadElement(r, &length)
	if err != nil {
		return err
	}

	if length != 0 {
		f.Update = &ChannelUpdate{}
		return parseChannelUpdateCompatabilityMode(
			bufio.NewReader(r), f.Update, pver,
		)
	}

	return nil
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailTemporaryChannelFailure) Encode(w *bytes.Buffer,
	pver uint32) error {

	var payload []byte
	if f.Update != nil {
		var bw bytes.Buffer
		if err := f.Update.Encode(&bw, pver); err != nil {
			return err
		}
		payload = bw.Bytes()
	}

	if err := WriteUint16(w, uint16(len(payload))); err != nil {
		return err
	}

	_, err := w.Write(payload)
	return err
}

// FailAmountBelowMinimum is returned if the HTLC does not reach the current
// minimum amount, we tell them the amount of the incoming HTLC and the current
// channel setting for the outgoing channel.
//
// NOTE: May only be returned by the intermediate nodes in the path.
type FailAmountBelowMinimum struct {
	// HtlcMsat is the wrong amount of the incoming HTLC.
	HtlcMsat MilliSatoshi

	// Update is used to update information about state of the channel
	// which caused the failure.
	Update ChannelUpdate
}

// NewAmountBelowMinimum creates new instance of the FailAmountBelowMinimum.
func NewAmountBelowMinimum(htlcMsat MilliSatoshi,
	update ChannelUpdate) *FailAmountBelowMinimum {

	return &FailAmountBelowMinimum{
		HtlcMsat: htlcMsat,
		Update:   update,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailAmountBelowMinimum) Code() FailCode {
	return CodeAmountBelowMinimum
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailAmountBelowMinimum) Error() string {
	return fmt.Sprintf("AmountBelowMinimum(amt=%v, update=%v", f.HtlcMsat,
		spew.Sdump(f.Update))
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailAmountBelowMinimum) Decode(r io.Reader, pver uint32) error {
	if err := ReadElement(r, &f.HtlcMsat); err != nil {
		return err
	}

	var length uint16
	if err := ReadElement(r, &length); err != nil {
		return err
	}

	f.Update = ChannelUpdate{}
	return parseChannelUpdateCompatabilityMode(
		bufio.NewReader(r), &f.Update, pver,
	)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailAmountBelowMinimum) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteMilliSatoshi(w, f.HtlcMsat); err != nil {
		return err
	}

	return writeOnionErrorChanUpdate(w, &f.Update, pver)
}

// FailFeeInsufficient is returned if the HTLC does not pay sufficient fee, we
// tell them the amount of the incoming HTLC and the current channel setting
// for the outgoing channel.
//
// NOTE: May only be returned by intermediate nodes.
type FailFeeInsufficient struct {
	// HtlcMsat is the wrong amount of the incoming HTLC.
	HtlcMsat MilliSatoshi

	// Update is used to update information about state of the channel
	// which caused the failure.
	Update ChannelUpdate
}

// NewFeeInsufficient creates new instance of the FailFeeInsufficient.
func NewFeeInsufficient(htlcMsat MilliSatoshi,
	update ChannelUpdate) *FailFeeInsufficient {
	return &FailFeeInsufficient{
		HtlcMsat: htlcMsat,
		Update:   update,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailFeeInsufficient) Code() FailCode {
	return CodeFeeInsufficient
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailFeeInsufficient) Error() string {
	return fmt.Sprintf("FeeInsufficient(htlc_amt==%v, update=%v", f.HtlcMsat,
		spew.Sdump(f.Update))
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailFeeInsufficient) Decode(r io.Reader, pver uint32) error {
	if err := ReadElement(r, &f.HtlcMsat); err != nil {
		return err
	}

	var length uint16
	if err := ReadElement(r, &length); err != nil {
		return err
	}

	f.Update = ChannelUpdate{}
	return parseChannelUpdateCompatabilityMode(
		bufio.NewReader(r), &f.Update, pver,
	)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailFeeInsufficient) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteMilliSatoshi(w, f.HtlcMsat); err != nil {
		return err
	}

	return writeOnionErrorChanUpdate(w, &f.Update, pver)
}

// FailIncorrectCltvExpiry is returned if outgoing cltv value does not match
// the update add htlc's cltv expiry minus cltv expiry delta for the outgoing
// channel, we tell them the cltv expiry and the current channel setting for
// the outgoing channel.
//
// NOTE: May only be returned by intermediate nodes.
type FailIncorrectCltvExpiry struct {
	// CltvExpiry is the wrong absolute timeout in blocks, after which
	// outgoing HTLC expires.
	CltvExpiry uint32

	// Update is used to update information about state of the channel
	// which caused the failure.
	Update ChannelUpdate
}

// NewIncorrectCltvExpiry creates new instance of the FailIncorrectCltvExpiry.
func NewIncorrectCltvExpiry(cltvExpiry uint32,
	update ChannelUpdate) *FailIncorrectCltvExpiry {

	return &FailIncorrectCltvExpiry{
		CltvExpiry: cltvExpiry,
		Update:     update,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailIncorrectCltvExpiry) Code() FailCode {
	return CodeIncorrectCltvExpiry
}

func (f *FailIncorrectCltvExpiry) Error() string {
	return fmt.Sprintf("IncorrectCltvExpiry(expiry=%v, update=%v",
		f.CltvExpiry, spew.Sdump(f.Update))
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailIncorrectCltvExpiry) Decode(r io.Reader, pver uint32) error {
	if err := ReadElement(r, &f.CltvExpiry); err != nil {
		return err
	}

	var length uint16
	if err := ReadElement(r, &length); err != nil {
		return err
	}

	f.Update = ChannelUpdate{}
	return parseChannelUpdateCompatabilityMode(
		bufio.NewReader(r), &f.Update, pver,
	)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailIncorrectCltvExpiry) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteUint32(w, f.CltvExpiry); err != nil {
		return err
	}

	return writeOnionErrorChanUpdate(w, &f.Update, pver)
}

// FailExpiryTooSoon is returned if the ctlv-expiry is too near, we tell them
// the current channel setting for the outgoing channel.
//
// NOTE: May only be returned by intermediate nodes.
type FailExpiryTooSoon struct {
	// Update is used to update information about state of the channel
	// which caused the failure.
	Update ChannelUpdate
}

// NewExpiryTooSoon creates new instance of the FailExpiryTooSoon.
func NewExpiryTooSoon(update ChannelUpdate) *FailExpiryTooSoon {
	return &FailExpiryTooSoon{
		Update: update,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailExpiryTooSoon) Code() FailCode {
	return CodeExpiryTooSoon
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailExpiryTooSoon) Error() string {
	return fmt.Sprintf("ExpiryTooSoon(update=%v", spew.Sdump(f.Update))
}

// Decode decodes the failure from l stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailExpiryTooSoon) Decode(r io.Reader, pver uint32) error {
	var length uint16
	if err := ReadElement(r, &length); err != nil {
		return err
	}

	f.Update = ChannelUpdate{}
	return parseChannelUpdateCompatabilityMode(
		bufio.NewReader(r), &f.Update, pver,
	)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailExpiryTooSoon) Encode(w *bytes.Buffer, pver uint32) error {
	return writeOnionErrorChanUpdate(w, &f.Update, pver)
}

// FailChannelDisabled is returned if the channel is disabled, we tell them the
// current channel setting for the outgoing channel.
//
// NOTE: May only be returned by intermediate nodes.
type FailChannelDisabled struct {
	// Flags least-significant bit must be set to 0 if the creating node
	// corresponds to the first node in the previously sent channel
	// announcement and 1 otherwise.
	Flags uint16

	// Update is used to update information about state of the channel
	// which caused the failure.
	Update ChannelUpdate
}

// NewChannelDisabled creates new instance of the FailChannelDisabled.
func NewChannelDisabled(flags uint16, update ChannelUpdate) *FailChannelDisabled {
	return &FailChannelDisabled{
		Flags:  flags,
		Update: update,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailChannelDisabled) Code() FailCode {
	return CodeChannelDisabled
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailChannelDisabled) Error() string {
	return fmt.Sprintf("ChannelDisabled(flags=%v, update=%v", f.Flags,
		spew.Sdump(f.Update))
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailChannelDisabled) Decode(r io.Reader, pver uint32) error {
	if err := ReadElement(r, &f.Flags); err != nil {
		return err
	}

	var length uint16
	if err := ReadElement(r, &length); err != nil {
		return err
	}

	f.Update = ChannelUpdate{}
	return parseChannelUpdateCompatabilityMode(
		bufio.NewReader(r), &f.Update, pver,
	)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailChannelDisabled) Encode(w *bytes.Buffer, pver uint32) error {
	if err := WriteUint16(w, f.Flags); err != nil {
		return err
	}

	return writeOnionErrorChanUpdate(w, &f.Update, pver)
}

// FailFinalIncorrectCltvExpiry is returned if the outgoing_cltv_value does not
// match the ctlv_expiry of the HTLC at the final hop.
//
// NOTE: might be returned by final node only.
type FailFinalIncorrectCltvExpiry struct {
	// CltvExpiry is the wrong absolute timeout in blocks, after which
	// outgoing HTLC expires.
	CltvExpiry uint32
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailFinalIncorrectCltvExpiry) Error() string {
	return fmt.Sprintf("FinalIncorrectCltvExpiry(expiry=%v)", f.CltvExpiry)
}

// NewFinalIncorrectCltvExpiry creates new instance of the
// FailFinalIncorrectCltvExpiry.
func NewFinalIncorrectCltvExpiry(cltvExpiry uint32) *FailFinalIncorrectCltvExpiry {
	return &FailFinalIncorrectCltvExpiry{
		CltvExpiry: cltvExpiry,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailFinalIncorrectCltvExpiry) Code() FailCode {
	return CodeFinalIncorrectCltvExpiry
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailFinalIncorrectCltvExpiry) Decode(r io.Reader, pver uint32) error {
	return ReadElement(r, &f.CltvExpiry)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailFinalIncorrectCltvExpiry) Encode(w *bytes.Buffer,
	pver uint32) error {

	return WriteUint32(w, f.CltvExpiry)
}

// FailFinalIncorrectHtlcAmount is returned if the amt_to_forward is higher
// than incoming_htlc_amt of the HTLC at the final hop.
//
// NOTE: May only be returned by the final node.
type FailFinalIncorrectHtlcAmount struct {
	// IncomingHTLCAmount is the wrong forwarded htlc amount.
	IncomingHTLCAmount MilliSatoshi
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailFinalIncorrectHtlcAmount) Error() string {
	return fmt.Sprintf("FinalIncorrectHtlcAmount(amt=%v)",
		f.IncomingHTLCAmount)
}

// NewFinalIncorrectHtlcAmount creates new instance of the
// FailFinalIncorrectHtlcAmount.
func NewFinalIncorrectHtlcAmount(amount MilliSatoshi) *FailFinalIncorrectHtlcAmount {
	return &FailFinalIncorrectHtlcAmount{
		IncomingHTLCAmount: amount,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailFinalIncorrectHtlcAmount) Code() FailCode {
	return CodeFinalIncorrectHtlcAmount
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailFinalIncorrectHtlcAmount) Decode(r io.Reader, pver uint32) error {
	return ReadElement(r, &f.IncomingHTLCAmount)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *FailFinalIncorrectHtlcAmount) Encode(w *bytes.Buffer,
	pver uint32) error {

	return WriteMilliSatoshi(w, f.IncomingHTLCAmount)
}

// FailExpiryTooFar is returned if the CLTV expiry in the HTLC is too far in the
// future.
//
// NOTE: May be returned by any node in the payment route.
type FailExpiryTooFar struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailExpiryTooFar) Code() FailCode {
	return CodeExpiryTooFar
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailExpiryTooFar) Error() string {
	return f.Code().String()
}

// InvalidOnionPayload is returned if the hop could not process the TLV payload
// enclosed in the onion.
type InvalidOnionPayload struct {
	// Type is the TLV type that caused the specific failure.
	Type uint64

	// Offset is the byte offset within the payload where the failure
	// occurred.
	Offset uint16
}

// NewInvalidOnionPayload initializes a new InvalidOnionPayload failure.
func NewInvalidOnionPayload(typ uint64, offset uint16) *InvalidOnionPayload {
	return &InvalidOnionPayload{
		Type:   typ,
		Offset: offset,
	}
}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *InvalidOnionPayload) Code() FailCode {
	return CodeInvalidOnionPayload
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *InvalidOnionPayload) Error() string {
	return fmt.Sprintf("%v(type=%v, offset=%d)",
		f.Code(), f.Type, f.Offset)
}

// Decode decodes the failure from bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *InvalidOnionPayload) Decode(r io.Reader, pver uint32) error {
	var buf [8]byte
	typ, err := tlv.ReadVarInt(r, &buf)
	if err != nil {
		return err
	}
	f.Type = typ

	return ReadElements(r, &f.Offset)
}

// Encode writes the failure in bytes stream.
//
// NOTE: Part of the Serializable interface.
func (f *InvalidOnionPayload) Encode(w *bytes.Buffer, pver uint32) error {
	var buf [8]byte
	if err := tlv.WriteVarInt(w, f.Type, &buf); err != nil {
		return err
	}

	return WriteUint16(w, f.Offset)
}

// FailMPPTimeout is returned if the complete amount for a multi part payment
// was not received within a reasonable time.
//
// NOTE: May only be returned by the final node in the path.
type FailMPPTimeout struct{}

// Code returns the failure unique code.
//
// NOTE: Part of the FailureMessage interface.
func (f *FailMPPTimeout) Code() FailCode {
	return CodeMPPTimeout
}

// Returns a human readable string describing the target FailureMessage.
//
// NOTE: Implements the error interface.
func (f *FailMPPTimeout) Error() string {
	return f.Code().String()
}

// DecodeFailure decodes, validates, and parses the lnwire onion failure, for
// the provided protocol version.
func DecodeFailure(r io.Reader, pver uint32) (FailureMessage, error) {
	// First, we'll parse out the encapsulated failure message itself. This
	// is a 2 byte length followed by the payload itself.
	var failureLength uint16
	if err := ReadElement(r, &failureLength); err != nil {
		return nil, fmt.Errorf("unable to read error len: %v", err)
	}
	if failureLength > FailureMessageLength {
		return nil, fmt.Errorf("failure message is too "+
			"long: %v", failureLength)
	}
	failureData := make([]byte, failureLength)
	if _, err := io.ReadFull(r, failureData); err != nil {
		return nil, fmt.Errorf("unable to full read payload of "+
			"%v: %v", failureLength, err)
	}

	dataReader := bytes.NewReader(failureData)

	return DecodeFailureMessage(dataReader, pver)
}

// DecodeFailureMessage decodes just the failure message, ignoring any padding
// that may be present at the end.
func DecodeFailureMessage(r io.Reader, pver uint32) (FailureMessage, error) {
	// Once we have the failure data, we can obtain the failure code from
	// the first two bytes of the buffer.
	var codeBytes [2]byte
	if _, err := io.ReadFull(r, codeBytes[:]); err != nil {
		return nil, fmt.Errorf("unable to read failure code: %v", err)
	}
	failCode := FailCode(binary.BigEndian.Uint16(codeBytes[:]))

	// Create the empty failure by given code and populate the failure with
	// additional data if needed.
	failure, err := makeEmptyOnionError(failCode)
	if err != nil {
		return nil, fmt.Errorf("unable to make empty error: %v", err)
	}

	// Finally, if this failure has a payload, then we'll read that now as
	// well.
	switch f := failure.(type) {
	case Serializable:
		if err := f.Decode(r, pver); err != nil {
			return nil, fmt.Errorf("unable to decode error "+
				"update (type=%T): %v", failure, err)
		}
	}

	return failure, nil
}

// EncodeFailure encodes, including the necessary onion failure header
// information.
func EncodeFailure(w *bytes.Buffer, failure FailureMessage, pver uint32) error {
	var failureMessageBuffer bytes.Buffer

	err := EncodeFailureMessage(&failureMessageBuffer, failure, pver)
	if err != nil {
		return err
	}

	// The combined size of this message must be below the max allowed
	// failure message length.
	failureMessage := failureMessageBuffer.Bytes()
	if len(failureMessage) > FailureMessageLength {
		return fmt.Errorf("failure message exceed max "+
			"available size: %v", len(failureMessage))
	}

	// Finally, we'll add some padding in order to ensure that all failure
	// messages are fixed size.
	pad := make([]byte, FailureMessageLength-len(failureMessage))

	if err := WriteUint16(w, uint16(len(failureMessage))); err != nil {
		return err
	}

	if err := WriteBytes(w, failureMessage); err != nil {
		return err
	}
	if err := WriteUint16(w, uint16(len(pad))); err != nil {
		return err
	}

	return WriteBytes(w, pad)
}

// EncodeFailureMessage encodes just the failure message without adding a length
// and padding the message for the onion protocol.
func EncodeFailureMessage(w *bytes.Buffer,
	failure FailureMessage, pver uint32) error {

	// First, we'll write out the error code itself into the failure
	// buffer.
	var codeBytes [2]byte
	code := uint16(failure.Code())
	binary.BigEndian.PutUint16(codeBytes[:], code)
	_, err := w.Write(codeBytes[:])
	if err != nil {
		return err
	}

	// Next, some message have an additional message payload, if this is
	// one of those types, then we'll also encode the error payload as
	// well.
	switch failure := failure.(type) {
	case Serializable:
		if err := failure.Encode(w, pver); err != nil {
			return err
		}
	}

	return nil
}

// makeEmptyOnionError creates a new empty onion error  of the proper concrete
// type based on the passed failure code.
func makeEmptyOnionError(code FailCode) (FailureMessage, error) {
	switch code {
	case CodeInvalidRealm:
		return &FailInvalidRealm{}, nil

	case CodeTemporaryNodeFailure:
		return &FailTemporaryNodeFailure{}, nil

	case CodePermanentNodeFailure:
		return &FailPermanentNodeFailure{}, nil

	case CodeRequiredNodeFeatureMissing:
		return &FailRequiredNodeFeatureMissing{}, nil

	case CodePermanentChannelFailure:
		return &FailPermanentChannelFailure{}, nil

	case CodeRequiredChannelFeatureMissing:
		return &FailRequiredChannelFeatureMissing{}, nil

	case CodeUnknownNextPeer:
		return &FailUnknownNextPeer{}, nil

	case CodeIncorrectOrUnknownPaymentDetails:
		return &FailIncorrectDetails{}, nil

	case CodeIncorrectPaymentAmount:
		return &FailIncorrectPaymentAmount{}, nil

	case CodeFinalExpiryTooSoon:
		return &FailFinalExpiryTooSoon{}, nil

	case CodeInvalidOnionVersion:
		return &FailInvalidOnionVersion{}, nil

	case CodeInvalidOnionHmac:
		return &FailInvalidOnionHmac{}, nil

	case CodeInvalidOnionKey:
		return &FailInvalidOnionKey{}, nil

	case CodeTemporaryChannelFailure:
		return &FailTemporaryChannelFailure{}, nil

	case CodeAmountBelowMinimum:
		return &FailAmountBelowMinimum{}, nil

	case CodeFeeInsufficient:
		return &FailFeeInsufficient{}, nil

	case CodeIncorrectCltvExpiry:
		return &FailIncorrectCltvExpiry{}, nil

	case CodeExpiryTooSoon:
		return &FailExpiryTooSoon{}, nil

	case CodeChannelDisabled:
		return &FailChannelDisabled{}, nil

	case CodeFinalIncorrectCltvExpiry:
		return &FailFinalIncorrectCltvExpiry{}, nil

	case CodeFinalIncorrectHtlcAmount:
		return &FailFinalIncorrectHtlcAmount{}, nil

	case CodeExpiryTooFar:
		return &FailExpiryTooFar{}, nil

	case CodeInvalidOnionPayload:
		return &InvalidOnionPayload{}, nil

	case CodeMPPTimeout:
		return &FailMPPTimeout{}, nil

	default:
		return nil, errors.Errorf("unknown error code: %v", code)
	}
}

// writeOnionErrorChanUpdate writes out a ChannelUpdate using the onion error
// format. The format is that we first write out the true serialized length of
// the channel update, followed by the serialized channel update itself.
func writeOnionErrorChanUpdate(w *bytes.Buffer, chanUpdate *ChannelUpdate,
	pver uint32) error {

	// First, we encode the channel update in a temporary buffer in order
	// to get the exact serialized size.
	var b bytes.Buffer
	if err := chanUpdate.Encode(&b, pver); err != nil {
		return err
	}

	// Now that we know the size, we can write the length out in the main
	// writer.
	updateLen := b.Len()
	if err := WriteUint16(w, uint16(updateLen)); err != nil {
		return err
	}

	// With the length written, we'll then write out the serialized channel
	// update.
	if _, err := w.Write(b.Bytes()); err != nil {
		return err
	}

	return nil
}
