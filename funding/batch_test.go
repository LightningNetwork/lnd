package funding

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

var (
	errFundingFailed = errors.New("funding failed")

	testPubKey1Hex = "02e1ce77dfdda9fd1cf5e9d796faf57d1cedef9803aec84a6d7" +
		"f8487d32781341e"
	testPubKey1Bytes, _ = hex.DecodeString(testPubKey1Hex)

	testPubKey2Hex = "039ddfc912035417b24aefe8da155267d71c3cf9e35405fc390" +
		"df8357c5da7a5eb"
	testPubKey2Bytes, _ = hex.DecodeString(testPubKey2Hex)

	testOutPoint = wire.OutPoint{
		Hash:  [32]byte{1, 2, 3},
		Index: 2,
	}
)

type fundingIntent struct {
	chanIndex  uint32
	updateChan chan *lnrpc.OpenStatusUpdate
	errChan    chan error
}

type testHarness struct {
	t       *testing.T
	batcher *Batcher

	failUpdate1 bool
	failUpdate2 bool
	failPublish bool

	intentsCreated    map[[32]byte]*fundingIntent
	intentsCanceled   map[[32]byte]struct{}
	abandonedChannels map[wire.OutPoint]struct{}
	releasedUTXOs     map[wire.OutPoint]struct{}

	pendingPacket *psbt.Packet
	pendingTx     *wire.MsgTx

	txPublished bool
}

func newTestHarness(t *testing.T, failUpdate1, failUpdate2,
	failPublish bool) *testHarness {

	h := &testHarness{
		t:                 t,
		failUpdate1:       failUpdate1,
		failUpdate2:       failUpdate2,
		failPublish:       failPublish,
		intentsCreated:    make(map[[32]byte]*fundingIntent),
		intentsCanceled:   make(map[[32]byte]struct{}),
		abandonedChannels: make(map[wire.OutPoint]struct{}),
		releasedUTXOs:     make(map[wire.OutPoint]struct{}),
		pendingTx: &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				// Our one input that pays for everything.
				PreviousOutPoint: testOutPoint,
			}},
			TxOut: []*wire.TxOut{{
				// Our static change output.
				PkScript: []byte{1, 2, 3},
				Value:    99,
			}},
		},
	}
	h.batcher = NewBatcher(&BatchConfig{
		RequestParser:    h.parseRequest,
		ChannelOpener:    h.openChannel,
		ChannelAbandoner: h.abandonChannel,
		WalletKitServer:  h,
		Wallet:           h,
		Quit:             make(chan struct{}),
	})
	return h
}

func (h *testHarness) parseRequest(
	in *lnrpc.OpenChannelRequest) (*InitFundingMsg, error) {

	pubKey, err := btcec.ParsePubKey(in.NodePubkey, btcec.S256())
	if err != nil {
		return nil, err
	}

	return &InitFundingMsg{
		TargetPubkey:    pubKey,
		LocalFundingAmt: btcutil.Amount(in.LocalFundingAmount),
		PushAmt: lnwire.NewMSatFromSatoshis(
			btcutil.Amount(in.PushSat),
		),
		FundingFeePerKw: chainfee.SatPerKVByte(
			in.SatPerVbyte * 1000,
		).FeePerKWeight(),
		Private:        in.Private,
		RemoteCsvDelay: uint16(in.RemoteCsvDelay),
		MinConfs:       in.MinConfs,
		MaxLocalCsv:    uint16(in.MaxLocalCsv),
	}, nil
}

func (h *testHarness) openChannel(
	req *InitFundingMsg) (chan *lnrpc.OpenStatusUpdate, chan error) {

	updateChan := make(chan *lnrpc.OpenStatusUpdate, 2)
	errChan := make(chan error, 1)

	// The change output is always index 0.
	chanIndex := uint32(len(h.intentsCreated) + 1)

	h.intentsCreated[req.PendingChanID] = &fundingIntent{
		chanIndex:  chanIndex,
		updateChan: updateChan,
		errChan:    errChan,
	}
	h.pendingTx.TxOut = append(h.pendingTx.TxOut, &wire.TxOut{
		PkScript: []byte{1, 2, 3, byte(chanIndex)},
		Value:    int64(req.LocalFundingAmt),
	})

	if h.failUpdate1 {
		errChan <- errFundingFailed

		// Once we fail we don't send any more updates.
		return updateChan, errChan
	}

	updateChan <- &lnrpc.OpenStatusUpdate{
		PendingChanId: req.PendingChanID[:],
		Update: &lnrpc.OpenStatusUpdate_PsbtFund{
			PsbtFund: &lnrpc.ReadyForPsbtFunding{
				FundingAmount: int64(
					req.LocalFundingAmt,
				),
				FundingAddress: fmt.Sprintf("foo%d", chanIndex),
			},
		},
	}

	return updateChan, errChan
}

func (h *testHarness) abandonChannel(op *wire.OutPoint) error {
	h.abandonedChannels[*op] = struct{}{}

	return nil
}

func (h *testHarness) FundPsbt(context.Context,
	*walletrpc.FundPsbtRequest) (*walletrpc.FundPsbtResponse, error) {

	packet, err := psbt.NewFromUnsignedTx(h.pendingTx)
	if err != nil {
		return nil, err
	}
	h.pendingPacket = packet

	var buf bytes.Buffer
	if err := packet.Serialize(&buf); err != nil {
		return nil, err
	}

	return &walletrpc.FundPsbtResponse{
		FundedPsbt: buf.Bytes(),
		LockedUtxos: []*walletrpc.UtxoLease{{
			Id: []byte{1, 2, 3},
			Outpoint: &lnrpc.OutPoint{
				TxidBytes:   testOutPoint.Hash[:],
				OutputIndex: testOutPoint.Index,
			},
		}},
	}, nil
}

func (h *testHarness) FinalizePsbt(context.Context,
	*walletrpc.FinalizePsbtRequest) (*walletrpc.FinalizePsbtResponse,
	error) {

	var psbtBuf bytes.Buffer
	if err := h.pendingPacket.Serialize(&psbtBuf); err != nil {
		return nil, err
	}

	var txBuf bytes.Buffer
	if err := h.pendingTx.Serialize(&txBuf); err != nil {
		return nil, err
	}

	return &walletrpc.FinalizePsbtResponse{
		SignedPsbt: psbtBuf.Bytes(),
		RawFinalTx: txBuf.Bytes(),
	}, nil
}

func (h *testHarness) ReleaseOutput(_ context.Context,
	r *walletrpc.ReleaseOutputRequest) (*walletrpc.ReleaseOutputResponse,
	error) {

	hash, err := chainhash.NewHash(r.Outpoint.TxidBytes)
	if err != nil {
		return nil, err
	}
	op := wire.OutPoint{
		Hash:  *hash,
		Index: r.Outpoint.OutputIndex,
	}

	h.releasedUTXOs[op] = struct{}{}

	return &walletrpc.ReleaseOutputResponse{}, nil
}

func (h *testHarness) PsbtFundingVerify([32]byte, *psbt.Packet, bool) error {
	return nil
}

func (h *testHarness) PsbtFundingFinalize(pid [32]byte, _ *psbt.Packet,
	_ *wire.MsgTx) error {

	// During the finalize phase we can now prepare the next update to send.
	// For this we first need to find the intent that has the channels we
	// need to send on.
	intent, ok := h.intentsCreated[pid]
	if !ok {
		return fmt.Errorf("intent %x not found", pid)
	}

	// We should now also have the final TX, let's get its hash.
	hash := h.pendingTx.TxHash()

	// For the second update we fail on the second channel only so the first
	// is actually pending.
	if h.failUpdate2 && intent.chanIndex == 2 {
		intent.errChan <- errFundingFailed
	} else {
		intent.updateChan <- &lnrpc.OpenStatusUpdate{
			PendingChanId: pid[:],
			Update: &lnrpc.OpenStatusUpdate_ChanPending{
				ChanPending: &lnrpc.PendingUpdate{
					Txid:        hash[:],
					OutputIndex: intent.chanIndex,
				},
			},
		}
	}

	return nil
}

func (h *testHarness) PublishTransaction(*wire.MsgTx, string) error {
	if h.failPublish {
		return errFundingFailed
	}

	h.txPublished = true

	return nil
}

func (h *testHarness) CancelFundingIntent(pid [32]byte) error {
	h.intentsCanceled[pid] = struct{}{}

	return nil
}

// TestBatchFund tests different success and error scenarios of the atomic batch
// channel funding.
func TestBatchFund(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		failUpdate1 bool
		failUpdate2 bool
		failPublish bool
		channels    []*lnrpc.BatchOpenChannel
		expectedErr string
	}{{
		name: "happy path",
		channels: []*lnrpc.BatchOpenChannel{{
			NodePubkey:         testPubKey1Bytes,
			LocalFundingAmount: 1234,
		}, {
			NodePubkey:         testPubKey2Bytes,
			LocalFundingAmount: 4321,
		}},
	}, {
		name:        "initial negotiation failure",
		failUpdate1: true,
		channels: []*lnrpc.BatchOpenChannel{{
			NodePubkey:         testPubKey1Bytes,
			LocalFundingAmount: 1234,
		}, {
			NodePubkey:         testPubKey2Bytes,
			LocalFundingAmount: 4321,
		}},
		expectedErr: "initial negotiation failed",
	}, {
		name:        "final negotiation failure",
		failUpdate2: true,
		channels: []*lnrpc.BatchOpenChannel{{
			NodePubkey:         testPubKey1Bytes,
			LocalFundingAmount: 1234,
		}, {
			NodePubkey:         testPubKey2Bytes,
			LocalFundingAmount: 4321,
		}},
		expectedErr: "final negotiation failed",
	}, {
		name:        "publish failure",
		failPublish: true,
		channels: []*lnrpc.BatchOpenChannel{{
			NodePubkey:         testPubKey1Bytes,
			LocalFundingAmount: 1234,
		}, {
			NodePubkey:         testPubKey2Bytes,
			LocalFundingAmount: 4321,
		}},
		expectedErr: "error publishing final batch transaction",
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newTestHarness(
				t, tc.failUpdate1, tc.failUpdate2,
				tc.failPublish,
			)

			req := &lnrpc.BatchOpenChannelRequest{
				Channels:    tc.channels,
				SatPerVbyte: 5,
				MinConfs:    1,
			}
			updates, err := h.batcher.BatchFund(
				context.Background(), req,
			)

			if tc.failUpdate1 || tc.failUpdate2 || tc.failPublish {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
			} else {
				require.NoError(t, err)
				require.Len(t, updates, len(tc.channels))
			}

			if tc.failUpdate1 {
				require.Len(t, h.releasedUTXOs, 0)
				require.Len(t, h.intentsCreated, 2)
				for pid := range h.intentsCreated {
					require.Contains(
						t, h.intentsCanceled, pid,
					)
				}
			}

			hash := h.pendingTx.TxHash()
			if tc.failUpdate2 {
				require.Len(t, h.releasedUTXOs, 1)
				require.Len(t, h.intentsCreated, 2)

				// If we fail on update 2 we do so on the second
				// channel so one will be pending and one not
				// yet.
				require.Len(t, h.intentsCanceled, 1)
				require.Len(t, h.abandonedChannels, 1)
				require.Contains(
					t, h.abandonedChannels, wire.OutPoint{
						Hash:  hash,
						Index: 1,
					},
				)
			}

			if tc.failPublish {
				require.Len(t, h.releasedUTXOs, 1)
				require.Len(t, h.intentsCreated, 2)

				require.Len(t, h.intentsCanceled, 0)
				require.Len(t, h.abandonedChannels, 2)
				require.Contains(
					t, h.abandonedChannels, wire.OutPoint{
						Hash:  hash,
						Index: 1,
					},
				)
				require.Contains(
					t, h.abandonedChannels, wire.OutPoint{
						Hash:  hash,
						Index: 2,
					},
				)
			}
		})
	}
}
