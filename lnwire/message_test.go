package lnwire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image/color"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const deliveryAddressMaxSize = 34
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	testSig = &btcec.Signature{
		R: new(big.Int),
		S: new(big.Int),
	}
	testNodeSig, _ = lnwire.NewSigFromSignature(testSig)

	testNumExtraBytes = 1000
	testNumSigs       = 100
	testNumChanIDs    = 1000
	buffer            = make([]byte, 0, lnwire.MaxSliceLength)

	bufPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(buffer)
		},
	}
)

type mockMsg struct {
	mock.Mock
}

func (m *mockMsg) Decode(r io.Reader, pver uint32) error {
	args := m.Called(r, pver)
	return args.Error(0)
}

func (m *mockMsg) Encode(w *bytes.Buffer, pver uint32) error {
	args := m.Called(w, pver)
	return args.Error(0)
}

func (m *mockMsg) MsgType() lnwire.MessageType {
	args := m.Called()
	return lnwire.MessageType(args.Int(0))
}

// A compile time check to ensure mockMsg implements the lnwire.Message
// interface.
var _ lnwire.Message = (*mockMsg)(nil)

// TestWriteMessage tests the function lnwire.WriteMessage.
func TestWriteMessage(t *testing.T) {
	var (
		buf = new(bytes.Buffer)

		// encodeNormalSize specifies a message size that is normal.
		encodeNormalSize = 1000

		// encodeOversize specifies a message size that's too big.
		encodeOversize = lnwire.MaxMsgBody + 1

		// errDummy is returned by the msg.Encode when specified.
		errDummy = errors.New("test error")

		// oneByte is a dummy byte used to fill up the buffer.
		oneByte = [1]byte{}
	)

	testCases := []struct {
		name string

		// encodeSize controls how many bytes are written to the buffer
		// by the method msg.Encode(buf, pver).
		encodeSize int

		// encodeErr determines the return value of the method
		// msg.Encode(buf, pver).
		encodeErr error

		errorExpected error
	}{

		{
			name:          "successful write",
			encodeSize:    encodeNormalSize,
			encodeErr:     nil,
			errorExpected: nil,
		},
		{
			name:          "failed to encode payload",
			encodeSize:    encodeNormalSize,
			encodeErr:     errDummy,
			errorExpected: lnwire.ErrorEncodeMessage(errDummy),
		},
		{
			name:       "exceeds MaxMsgBody",
			encodeSize: encodeOversize,
			encodeErr:  nil,
			errorExpected: lnwire.ErrorPayloadTooLarge(
				encodeOversize,
			),
		},
	}

	for _, test := range testCases {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			// Start the test by creating a mock message and patch
			// the relevant methods.
			msg := &mockMsg{}

			// Use message type Ping here since all types are
			// encoded using 2 bytes, it won't affect anything
			// here.
			msg.On("MsgType").Return(lnwire.MsgPing)

			// Encode will return the specified error (could be
			// nil) and has the side effect of filling up the
			// buffer by repeating the oneByte encodeSize times.
			msg.On("Encode", mock.Anything, mock.Anything).Return(
				tc.encodeErr,
			).Run(func(_ mock.Arguments) {
				for i := 0; i < tc.encodeSize; i++ {
					_, err := buf.Write(oneByte[:])
					require.NoError(t, err)
				}
			})

			// Record the initial state of the buffer and write the
			// message.
			oldBytesSize := buf.Len()
			bytesWritten, err := lnwire.WriteMessage(
				buf, msg, 1,
			)

			// Check that the returned error is expected.
			require.Equal(
				t, tc.errorExpected, err, "unexpected err",
			)

			// If there's an error, no bytes should be written to
			// the buf.
			if tc.errorExpected != nil {
				require.Equal(
					t, 0, bytesWritten,
					"bytes written should be 0",
				)

				// We also check that the old buf was not
				// affected.
				require.Equal(
					t, oldBytesSize, buf.Len(),
					"original buffer should not change",
				)
			} else {
				expected := buf.Len() - oldBytesSize
				require.Equal(
					t, expected, bytesWritten,
					"bytes written not matched",
				)
			}

			// Finally, check the mocked methods are called as
			// expected.
			msg.AssertExpectations(t)
		})
	}
}

// BenchmarkWriteMessage benchmarks the performance of lnwire.WriteMessage. It
// generates a test message for each of the lnwire.Message, calls the
// WriteMessage method and benchmark it.
func BenchmarkWriteMessage(b *testing.B) {
	// Create testing messages. We will use a constant seed to make sure
	// the benchmark uses the same data every time.
	r := rand.New(rand.NewSource(42))

	msgAll := makeAllMessages(b, r)

	// Iterate all messages and write each once.
	for _, msg := range msgAll {
		m := msg
		// Run each message as a sub benchmark test.
		b.Run(msg.MsgType().String(), func(b *testing.B) {

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Fetch a buffer from the pool and reset it.
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()

				_, err := lnwire.WriteMessage(buf, m, 0)
				require.NoError(b, err, "unable to write msg")

				// Put the buffer back when done.
				bufPool.Put(buf)
			}
		})
	}
}

// BenchmarkReadMessage benchmarks the performance of lnwire.ReadMessage. It
// first creates a test message for each of the lnwire.Message, writes it to
// the buffer, then later reads it from the buffer.
func BenchmarkReadMessage(b *testing.B) {
	// Create testing messages. We will use a constant seed to make sure
	// the benchmark uses the same data every time.
	r := rand.New(rand.NewSource(42))
	msgAll := makeAllMessages(b, r)

	// Write all the messages to the buffer.
	for _, msg := range msgAll {
		// Fetch a buffer from the pool and reset it.
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()

		_, err := lnwire.WriteMessage(buf, msg, 0)
		require.NoError(b, err, "unable to write msg")

		// Run each message as a sub benchmark test.
		m := msg
		b.Run(m.MsgType().String(), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				r := bytes.NewBuffer(buf.Bytes())

				// Read the message from the buffer.
				_, err := lnwire.ReadMessage(r, 0)
				require.NoError(b, err, "unable to read msg")
			}
		})

		// Put the buffer back when done.
		bufPool.Put(buf)
	}
}

// makeAllMessages is used to create testing messages for each lnwire message
// type.
//
// TODO(yy): the following testing messages are created somewhat arbitrary. We
// should standardlize each of the testing messages so that a better baseline
// can be used.
func makeAllMessages(t testing.TB, r *rand.Rand) []lnwire.Message {
	msgAll := []lnwire.Message{}

	msgAll = append(msgAll, newMsgInit(t, r))
	msgAll = append(msgAll, newMsgError(t, r))
	msgAll = append(msgAll, newMsgPing(t, r))
	msgAll = append(msgAll, newMsgPong(t, r))
	msgAll = append(msgAll, newMsgOpenChannel(t, r))
	msgAll = append(msgAll, newMsgAcceptChannel(t, r))
	msgAll = append(msgAll, newMsgFundingCreated(t, r))
	msgAll = append(msgAll, newMsgFundingSigned(t, r))
	msgAll = append(msgAll, newMsgFundingLocked(t, r))
	msgAll = append(msgAll, newMsgShutdown(t, r))
	msgAll = append(msgAll, newMsgClosingSigned(t, r))
	msgAll = append(msgAll, newMsgUpdateAddHTLC(t, r))
	msgAll = append(msgAll, newMsgUpdateFulfillHTLC(t, r))
	msgAll = append(msgAll, newMsgUpdateFailHTLC(t, r))
	msgAll = append(msgAll, newMsgCommitSig(t, r))
	msgAll = append(msgAll, newMsgRevokeAndAck(t, r))
	msgAll = append(msgAll, newMsgUpdateFee(t, r))
	msgAll = append(msgAll, newMsgUpdateFailMalformedHTLC(t, r))
	msgAll = append(msgAll, newMsgChannelReestablish(t, r))
	msgAll = append(msgAll, newMsgChannelAnnouncement(t, r))
	msgAll = append(msgAll, newMsgNodeAnnouncement(t, r))
	msgAll = append(msgAll, newMsgChannelUpdate(t, r))
	msgAll = append(msgAll, newMsgAnnounceSignatures(t, r))
	msgAll = append(msgAll, newMsgQueryShortChanIDs(t, r))
	msgAll = append(msgAll, newMsgReplyShortChanIDsEnd(t, r))
	msgAll = append(msgAll, newMsgQueryChannelRange(t, r))
	msgAll = append(msgAll, newMsgReplyChannelRange(t, r))
	msgAll = append(msgAll, newMsgGossipTimestampRange(t, r))
	msgAll = append(msgAll, newMsgQueryShortChanIDsZlib(t, r))
	msgAll = append(msgAll, newMsgReplyChannelRangeZlib(t, r))

	return msgAll
}

func newMsgInit(t testing.TB, r io.Reader) *lnwire.Init {
	t.Helper()

	return &lnwire.Init{
		GlobalFeatures: rawFeatureVector(),
		Features:       rawFeatureVector(),
		ExtraData:      createExtraData(t, r),
	}
}

// newMsgOpenChannel creates a testing OpenChannel message.
func newMsgOpenChannel(t testing.TB, r *rand.Rand) *lnwire.OpenChannel {
	t.Helper()

	msg := &lnwire.OpenChannel{
		FundingAmount:        btcutil.Amount(r.Int63()),
		PushAmount:           lnwire.MilliSatoshi(r.Int63()),
		DustLimit:            btcutil.Amount(r.Int63()),
		MaxValueInFlight:     lnwire.MilliSatoshi(r.Int63()),
		ChannelReserve:       btcutil.Amount(r.Int63()),
		HtlcMinimum:          lnwire.MilliSatoshi(r.Int63()),
		FeePerKiloWeight:     uint32(r.Int31()),
		CsvDelay:             uint16(r.Intn(1 << 16)),
		MaxAcceptedHTLCs:     uint16(r.Intn(1 << 16)),
		ChannelFlags:         lnwire.FundingFlag(uint8(r.Intn(1 << 8))),
		FundingKey:           randPubKey(t),
		RevocationPoint:      randPubKey(t),
		PaymentPoint:         randPubKey(t),
		DelayedPaymentPoint:  randPubKey(t),
		HtlcPoint:            randPubKey(t),
		FirstCommitmentPoint: randPubKey(t),
		ExtraData:            createExtraData(t, r),
	}

	_, err := r.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read bytes for ChainHash")

	_, err = r.Read(msg.PendingChannelID[:])
	require.NoError(t, err, "unable to read bytes for PendingChannelID")

	return msg
}

func newMsgAcceptChannel(t testing.TB, r *rand.Rand) *lnwire.AcceptChannel {
	t.Helper()

	msg := &lnwire.AcceptChannel{
		DustLimit:             btcutil.Amount(r.Int63()),
		MaxValueInFlight:      lnwire.MilliSatoshi(r.Int63()),
		ChannelReserve:        btcutil.Amount(r.Int63()),
		MinAcceptDepth:        uint32(r.Int31()),
		HtlcMinimum:           lnwire.MilliSatoshi(r.Int63()),
		CsvDelay:              uint16(r.Intn(1 << 16)),
		MaxAcceptedHTLCs:      uint16(r.Intn(1 << 16)),
		FundingKey:            randPubKey(t),
		RevocationPoint:       randPubKey(t),
		PaymentPoint:          randPubKey(t),
		DelayedPaymentPoint:   randPubKey(t),
		HtlcPoint:             randPubKey(t),
		FirstCommitmentPoint:  randPubKey(t),
		UpfrontShutdownScript: randDeliveryAddress(t, r),
		ExtraData:             createExtraData(t, r),
	}
	_, err := r.Read(msg.PendingChannelID[:])
	require.NoError(t, err, "unable to generate pending chan id")

	return msg
}

func newMsgError(t testing.TB, r io.Reader) *lnwire.Error {
	t.Helper()

	msg := lnwire.NewError()

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	msg.Data = createExtraData(t, r)

	return msg
}

func newMsgPing(t testing.TB, r *rand.Rand) *lnwire.Ping {
	t.Helper()

	return &lnwire.Ping{
		NumPongBytes: uint16(r.Intn(1 << 16)),
		PaddingBytes: createExtraData(t, r),
	}
}

func newMsgPong(t testing.TB, r io.Reader) *lnwire.Pong {
	t.Helper()

	return &lnwire.Pong{
		PongBytes: createExtraData(t, r),
	}
}

func newMsgFundingCreated(t testing.TB, r *rand.Rand) *lnwire.FundingCreated {
	t.Helper()

	msg := &lnwire.FundingCreated{
		CommitSig: testNodeSig,
		ExtraData: createExtraData(t, r),
	}

	_, err := r.Read(msg.PendingChannelID[:])
	require.NoError(t, err, "unable to generate pending chan id")

	_, err = r.Read(msg.FundingPoint.Hash[:])
	require.NoError(t, err, "unable to generate hash")

	msg.FundingPoint.Index = uint32(r.Int31()) % math.MaxUint16

	return msg
}

func newMsgFundingSigned(t testing.TB, r io.Reader) *lnwire.FundingSigned {
	t.Helper()

	var c [32]byte

	_, err := r.Read(c[:])
	require.NoError(t, err, "unable to generate chan id")

	msg := &lnwire.FundingSigned{
		ChanID:    lnwire.ChannelID(c),
		CommitSig: testNodeSig,
		ExtraData: createExtraData(t, r),
	}

	return msg
}

func newMsgFundingLocked(t testing.TB, r io.Reader) *lnwire.FundingLocked {
	t.Helper()

	var c [32]byte

	_, err := r.Read(c[:])
	require.NoError(t, err, "unable to generate chan id")

	pubKey := randPubKey(t)

	msg := lnwire.NewFundingLocked(lnwire.ChannelID(c), pubKey)
	msg.ExtraData = createExtraData(t, r)

	return msg
}

func newMsgShutdown(t testing.TB, r *rand.Rand) *lnwire.Shutdown {
	t.Helper()

	msg := &lnwire.Shutdown{
		Address:   randDeliveryAddress(t, r),
		ExtraData: createExtraData(t, r),
	}

	_, err := r.Read(msg.ChannelID[:])
	require.NoError(t, err, "unable to generate channel id")

	return msg
}

func newMsgClosingSigned(t testing.TB, r *rand.Rand) *lnwire.ClosingSigned {
	t.Helper()

	msg := &lnwire.ClosingSigned{
		FeeSatoshis: btcutil.Amount(r.Int63()),
		Signature:   testNodeSig,
		ExtraData:   createExtraData(t, r),
	}

	_, err := r.Read(msg.ChannelID[:])
	require.NoError(t, err, "unable to generate chan id")

	return msg
}

func newMsgUpdateAddHTLC(t testing.TB, r *rand.Rand) *lnwire.UpdateAddHTLC {
	t.Helper()

	msg := &lnwire.UpdateAddHTLC{
		ID:        r.Uint64(),
		Amount:    lnwire.MilliSatoshi(r.Int63()),
		Expiry:    r.Uint32(),
		ExtraData: createExtraData(t, r),
	}

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	_, err = r.Read(msg.PaymentHash[:])
	require.NoError(t, err, "unable to generate paymenthash")

	_, err = r.Read(msg.OnionBlob[:])
	require.NoError(t, err, "unable to generate onion blob")

	return msg
}

func newMsgUpdateFulfillHTLC(t testing.TB,
	r *rand.Rand) *lnwire.UpdateFulfillHTLC {

	t.Helper()

	msg := &lnwire.UpdateFulfillHTLC{
		ID:        r.Uint64(),
		ExtraData: createExtraData(t, r),
	}

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	_, err = r.Read(msg.PaymentPreimage[:])
	require.NoError(t, err, "unable to generate payment preimage")

	return msg
}

func newMsgUpdateFailHTLC(t testing.TB, r *rand.Rand) *lnwire.UpdateFailHTLC {
	t.Helper()

	msg := &lnwire.UpdateFailHTLC{
		ID:        r.Uint64(),
		ExtraData: createExtraData(t, r),
	}

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	return msg
}

func newMsgCommitSig(t testing.TB, r io.Reader) *lnwire.CommitSig {
	t.Helper()

	msg := lnwire.NewCommitSig()

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	msg.CommitSig = testNodeSig
	msg.ExtraData = createExtraData(t, r)

	msg.HtlcSigs = make([]lnwire.Sig, testNumSigs)
	for i := 0; i < testNumSigs; i++ {
		msg.HtlcSigs[i] = testNodeSig
	}

	return msg
}

func newMsgRevokeAndAck(t testing.TB, r io.Reader) *lnwire.RevokeAndAck {
	t.Helper()

	msg := lnwire.NewRevokeAndAck()

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	_, err = r.Read(msg.Revocation[:])
	require.NoError(t, err, "unable to generate bytes")

	msg.NextRevocationKey = randPubKey(t)
	require.NoError(t, err, "unable to generate key")

	msg.ExtraData = createExtraData(t, r)

	return msg
}

func newMsgUpdateFee(t testing.TB, r *rand.Rand) *lnwire.UpdateFee {
	t.Helper()

	msg := &lnwire.UpdateFee{
		FeePerKw:  uint32(r.Int31()),
		ExtraData: createExtraData(t, r),
	}

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	return msg
}

func newMsgUpdateFailMalformedHTLC(t testing.TB,
	r *rand.Rand) *lnwire.UpdateFailMalformedHTLC {

	t.Helper()

	msg := &lnwire.UpdateFailMalformedHTLC{
		ID:          r.Uint64(),
		FailureCode: lnwire.FailCode(r.Intn(1 << 16)),
		ExtraData:   createExtraData(t, r),
	}

	_, err := r.Read(msg.ChanID[:])
	require.NoError(t, err, "unable to generate chan id")

	_, err = r.Read(msg.ShaOnionBlob[:])
	require.NoError(t, err, "unable to generate sha256 onion blob")

	return msg
}

func newMsgChannelReestablish(t testing.TB,
	r *rand.Rand) *lnwire.ChannelReestablish {

	t.Helper()

	msg := &lnwire.ChannelReestablish{
		NextLocalCommitHeight:     uint64(r.Int63()),
		RemoteCommitTailHeight:    uint64(r.Int63()),
		LocalUnrevokedCommitPoint: randPubKey(t),
		ExtraData:                 createExtraData(t, r),
	}

	_, err := r.Read(msg.LastRemoteCommitSecret[:])
	require.NoError(t, err, "unable to read commit secret")

	return msg
}

func newMsgChannelAnnouncement(t testing.TB,
	r *rand.Rand) *lnwire.ChannelAnnouncement {

	t.Helper()

	msg := &lnwire.ChannelAnnouncement{
		ShortChannelID:  lnwire.NewShortChanIDFromInt(uint64(r.Int63())),
		Features:        rawFeatureVector(),
		NodeID1:         randRawKey(t),
		NodeID2:         randRawKey(t),
		BitcoinKey1:     randRawKey(t),
		BitcoinKey2:     randRawKey(t),
		ExtraOpaqueData: createExtraData(t, r),
		NodeSig1:        testNodeSig,
		NodeSig2:        testNodeSig,
		BitcoinSig1:     testNodeSig,
		BitcoinSig2:     testNodeSig,
	}

	_, err := r.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to generate chain hash")

	return msg
}

func newMsgNodeAnnouncement(t testing.TB,
	r *rand.Rand) *lnwire.NodeAnnouncement {

	t.Helper()

	msg := &lnwire.NodeAnnouncement{
		Features:  rawFeatureVector(),
		Timestamp: uint32(r.Int31()),
		Alias:     randAlias(r),
		RGBColor: color.RGBA{
			R: uint8(r.Intn(1 << 8)),
			G: uint8(r.Intn(1 << 8)),
			B: uint8(r.Intn(1 << 8)),
		},
		NodeID:          randRawKey(t),
		Addresses:       randAddrs(t, r),
		ExtraOpaqueData: createExtraData(t, r),
		Signature:       testNodeSig,
	}

	return msg
}

func newMsgChannelUpdate(t testing.TB, r *rand.Rand) *lnwire.ChannelUpdate {
	t.Helper()

	msgFlags := lnwire.ChanUpdateMsgFlags(r.Int31())
	maxHtlc := lnwire.MilliSatoshi(r.Int63())

	// We make the max_htlc field zero if it is not flagged
	// as being part of the ChannelUpdate, to pass
	// serialization tests, as it will be ignored if the bit
	// is not set.
	if msgFlags&lnwire.ChanUpdateOptionMaxHtlc == 0 {
		maxHtlc = 0
	}

	msg := &lnwire.ChannelUpdate{
		ShortChannelID:  lnwire.NewShortChanIDFromInt(r.Uint64()),
		Timestamp:       uint32(r.Int31()),
		MessageFlags:    msgFlags,
		ChannelFlags:    lnwire.ChanUpdateChanFlags(r.Int31()),
		TimeLockDelta:   uint16(r.Int31()),
		HtlcMinimumMsat: lnwire.MilliSatoshi(r.Int63()),
		HtlcMaximumMsat: maxHtlc,
		BaseFee:         uint32(r.Int31()),
		FeeRate:         uint32(r.Int31()),
		ExtraOpaqueData: createExtraData(t, r),
		Signature:       testNodeSig,
	}

	_, err := r.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to generate chain hash")

	return msg
}

func newMsgAnnounceSignatures(t testing.TB,
	r *rand.Rand) *lnwire.AnnounceSignatures {

	t.Helper()

	msg := &lnwire.AnnounceSignatures{
		ShortChannelID: lnwire.NewShortChanIDFromInt(
			uint64(r.Int63()),
		),
		ExtraOpaqueData:  createExtraData(t, r),
		NodeSignature:    testNodeSig,
		BitcoinSignature: testNodeSig,
	}

	_, err := r.Read(msg.ChannelID[:])
	require.NoError(t, err, "unable to generate chan id")

	return msg
}

func newMsgQueryShortChanIDs(t testing.TB,
	r *rand.Rand) *lnwire.QueryShortChanIDs {

	t.Helper()

	msg := &lnwire.QueryShortChanIDs{
		EncodingType: lnwire.EncodingSortedPlain,
		ExtraData:    createExtraData(t, r),
	}

	_, err := rand.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	for i := 0; i < testNumChanIDs; i++ {
		msg.ShortChanIDs = append(msg.ShortChanIDs,
			lnwire.NewShortChanIDFromInt(uint64(r.Int63())))
	}

	return msg
}

func newMsgQueryShortChanIDsZlib(t testing.TB,
	r *rand.Rand) *lnwire.QueryShortChanIDs {

	t.Helper()

	msg := &lnwire.QueryShortChanIDs{
		EncodingType: lnwire.EncodingSortedZlib,
		ExtraData:    createExtraData(t, r),
	}

	_, err := rand.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	for i := 0; i < testNumChanIDs; i++ {
		msg.ShortChanIDs = append(msg.ShortChanIDs,
			lnwire.NewShortChanIDFromInt(uint64(r.Int63())))
	}

	return msg
}

func newMsgReplyShortChanIDsEnd(t testing.TB,
	r *rand.Rand) *lnwire.ReplyShortChanIDsEnd {

	t.Helper()

	msg := lnwire.NewReplyShortChanIDsEnd()

	_, err := rand.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	msg.Complete = uint8(r.Int31n(2))
	msg.ExtraData = createExtraData(t, r)

	return msg
}

func newMsgQueryChannelRange(t testing.TB,
	r *rand.Rand) *lnwire.QueryChannelRange {

	t.Helper()

	msg := lnwire.NewQueryChannelRange()

	_, err := rand.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	msg.FirstBlockHeight = r.Uint32()
	msg.NumBlocks = r.Uint32()
	msg.ExtraData = createExtraData(t, r)

	return msg
}

func newMsgReplyChannelRange(t testing.TB,
	r *rand.Rand) *lnwire.ReplyChannelRange {

	t.Helper()

	msg := &lnwire.ReplyChannelRange{
		EncodingType: lnwire.EncodingSortedPlain,
		ExtraData:    createExtraData(t, r),
	}

	_, err := rand.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	msg.Complete = uint8(r.Int31n(2))

	for i := 0; i < testNumChanIDs; i++ {
		msg.ShortChanIDs = append(msg.ShortChanIDs,
			lnwire.NewShortChanIDFromInt(uint64(r.Int63())))
	}

	return msg
}

func newMsgReplyChannelRangeZlib(t testing.TB,
	r *rand.Rand) *lnwire.ReplyChannelRange {

	t.Helper()

	msg := &lnwire.ReplyChannelRange{
		EncodingType: lnwire.EncodingSortedZlib,
		ExtraData:    createExtraData(t, r),
	}

	_, err := rand.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	msg.Complete = uint8(r.Int31n(2))

	for i := 0; i < testNumChanIDs; i++ {
		msg.ShortChanIDs = append(msg.ShortChanIDs,
			lnwire.NewShortChanIDFromInt(uint64(r.Int63())))
	}

	return msg
}

func newMsgGossipTimestampRange(t testing.TB,
	r *rand.Rand) *lnwire.GossipTimestampRange {

	t.Helper()

	msg := lnwire.NewGossipTimestampRange()
	msg.FirstTimestamp = r.Uint32()
	msg.TimestampRange = r.Uint32()
	msg.ExtraData = createExtraData(t, r)

	_, err := r.Read(msg.ChainHash[:])
	require.NoError(t, err, "unable to read chain hash")

	return msg
}

func randRawKey(t testing.TB) [33]byte {
	t.Helper()

	var n [33]byte

	priv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err, "failed to create privKey")

	copy(n[:], priv.PubKey().SerializeCompressed())

	return n
}

func randPubKey(t testing.TB) *btcec.PublicKey {
	t.Helper()

	priv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err, "failed to create pubkey")

	return priv.PubKey()
}

func rawFeatureVector() *lnwire.RawFeatureVector {
	// Get a slice of known feature bits.
	featureBits := make([]lnwire.FeatureBit, 0, len(lnwire.Features))
	for fb := range lnwire.Features {
		featureBits = append(featureBits, fb)
	}

	featureVec := lnwire.NewRawFeatureVector(featureBits...)

	return featureVec
}

func randDeliveryAddress(t testing.TB, r *rand.Rand) lnwire.DeliveryAddress {
	t.Helper()

	// Generate a max sized address.
	size := r.Intn(deliveryAddressMaxSize) + 1
	da := lnwire.DeliveryAddress(make([]byte, size))

	_, err := r.Read(da)
	require.NoError(t, err, "unable to read address")
	return da
}

func randTCP4Addr(t testing.TB, r *rand.Rand) *net.TCPAddr {
	t.Helper()

	var ip [4]byte
	_, err := r.Read(ip[:])
	require.NoError(t, err, "unable to read ip")

	var port [2]byte
	_, err = r.Read(port[:])
	require.NoError(t, err, "unable to read port")

	addrIP := net.IP(ip[:])
	addrPort := int(binary.BigEndian.Uint16(port[:]))

	return &net.TCPAddr{IP: addrIP, Port: addrPort}
}

func randTCP6Addr(t testing.TB, r *rand.Rand) *net.TCPAddr {
	t.Helper()

	var ip [16]byte

	_, err := r.Read(ip[:])
	require.NoError(t, err, "unable to read ip")

	var port [2]byte
	_, err = r.Read(port[:])
	require.NoError(t, err, "unable to read port")

	addrIP := net.IP(ip[:])
	addrPort := int(binary.BigEndian.Uint16(port[:]))

	return &net.TCPAddr{IP: addrIP, Port: addrPort}
}

func randV2OnionAddr(t testing.TB, r *rand.Rand) *tor.OnionAddr {
	t.Helper()

	var serviceID [tor.V2DecodedLen]byte
	_, err := r.Read(serviceID[:])
	require.NoError(t, err, "unable to read serviceID")

	var port [2]byte
	_, err = r.Read(port[:])
	require.NoError(t, err, "unable to read port")

	onionService := tor.Base32Encoding.EncodeToString(serviceID[:])
	onionService += tor.OnionSuffix
	addrPort := int(binary.BigEndian.Uint16(port[:]))

	return &tor.OnionAddr{OnionService: onionService, Port: addrPort}
}

func randV3OnionAddr(t testing.TB, r *rand.Rand) *tor.OnionAddr {
	t.Helper()

	var serviceID [tor.V3DecodedLen]byte
	_, err := r.Read(serviceID[:])
	require.NoError(t, err, "unable to read serviceID")

	var port [2]byte
	_, err = r.Read(port[:])
	require.NoError(t, err, "unable to read port")

	onionService := tor.Base32Encoding.EncodeToString(serviceID[:])
	onionService += tor.OnionSuffix
	addrPort := int(binary.BigEndian.Uint16(port[:]))

	return &tor.OnionAddr{OnionService: onionService, Port: addrPort}
}

func randAddrs(t testing.TB, r *rand.Rand) []net.Addr {
	tcp4Addr := randTCP4Addr(t, r)
	tcp6Addr := randTCP6Addr(t, r)
	v2OnionAddr := randV2OnionAddr(t, r)
	v3OnionAddr := randV3OnionAddr(t, r)

	return []net.Addr{tcp4Addr, tcp6Addr, v2OnionAddr, v3OnionAddr}
}

func randAlias(r *rand.Rand) lnwire.NodeAlias {
	var a lnwire.NodeAlias
	for i := range a {
		a[i] = letterBytes[r.Intn(len(letterBytes))]
	}

	return a
}

func createExtraData(t testing.TB, r io.Reader) []byte {
	t.Helper()

	// Read random bytes.
	extraData := make([]byte, testNumExtraBytes)
	_, err := r.Read(extraData)
	require.NoError(t, err, "unable to generate extra data")

	// Encode the data length.
	binary.BigEndian.PutUint16(extraData[:2], uint16(len(extraData[2:])))

	return extraData
}
