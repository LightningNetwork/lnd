package funding

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/lightningnetwork/lnd/labels"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

var (
	// errShuttingDown is the error that is returned if a signal on the
	// quit channel is received which means the whole server is shutting
	// down.
	errShuttingDown = errors.New("shutting down")
)

// batchChannel is a struct that keeps track of a single channel's state within
// the batch funding process.
type batchChannel struct {
	fundingReq    *InitFundingMsg
	pendingChanID [32]byte
	updateChan    chan *lnrpc.OpenStatusUpdate
	errChan       chan error
	fundingAddr   string
	chanPoint     *wire.OutPoint
	isPending     bool
}

// processPsbtUpdate processes the first channel update message that is sent
// once the initial part of the negotiation has completed and the funding output
// (and therefore address) is known.
func (c *batchChannel) processPsbtUpdate(u *lnrpc.OpenStatusUpdate) error {
	psbtUpdate := u.GetPsbtFund()
	if psbtUpdate == nil {
		return fmt.Errorf("got unexpected channel update %v", u.Update)
	}

	if psbtUpdate.FundingAmount != int64(c.fundingReq.LocalFundingAmt) {
		return fmt.Errorf("got unexpected funding amount %d, wanted "+
			"%d", psbtUpdate.FundingAmount,
			c.fundingReq.LocalFundingAmt)
	}

	c.fundingAddr = psbtUpdate.FundingAddress

	return nil
}

// processPendingUpdate is the second channel update message that is sent once
// the negotiation with the peer has completed and the channel is now pending.
func (c *batchChannel) processPendingUpdate(u *lnrpc.OpenStatusUpdate) error {
	pendingUpd := u.GetChanPending()
	if pendingUpd == nil {
		return fmt.Errorf("got unexpected channel update %v", u.Update)
	}

	hash, err := chainhash.NewHash(pendingUpd.Txid)
	if err != nil {
		return fmt.Errorf("could not parse outpoint TX hash: %v", err)
	}

	c.chanPoint = &wire.OutPoint{
		Index: pendingUpd.OutputIndex,
		Hash:  *hash,
	}
	c.isPending = true

	return nil
}

// RequestParser is a function that parses an incoming RPC request into the
// internal funding initialization message.
type RequestParser func(*lnrpc.OpenChannelRequest) (*InitFundingMsg, error)

// ChannelOpener is a function that kicks off the initial channel open
// negotiation with the peer.
type ChannelOpener func(*InitFundingMsg) (chan *lnrpc.OpenStatusUpdate,
	chan error)

// ChannelAbandoner is a function that can abandon a channel in the local
// database, graph and arbitrator state.
type ChannelAbandoner func(*wire.OutPoint) error

// WalletKitServer is a local interface that abstracts away the methods we need
// from the wallet kit sub server instance.
type WalletKitServer interface {
	// FundPsbt creates a fully populated PSBT that contains enough inputs
	// to fund the outputs specified in the template.
	FundPsbt(context.Context,
		*walletrpc.FundPsbtRequest) (*walletrpc.FundPsbtResponse, error)

	// FinalizePsbt expects a partial transaction with all inputs and
	// outputs fully declared and tries to sign all inputs that belong to
	// the wallet.
	FinalizePsbt(context.Context,
		*walletrpc.FinalizePsbtRequest) (*walletrpc.FinalizePsbtResponse,
		error)

	// ReleaseOutput unlocks an output, allowing it to be available for coin
	// selection if it remains unspent. The ID should match the one used to
	// originally lock the output.
	ReleaseOutput(context.Context,
		*walletrpc.ReleaseOutputRequest) (*walletrpc.ReleaseOutputResponse,
		error)
}

// Wallet is a local interface that abstracts away the methods we need from the
// internal lightning wallet instance.
type Wallet interface {
	// PsbtFundingVerify looks up a previously registered funding intent by
	// its pending channel ID and tries to advance the state machine by
	// verifying the passed PSBT.
	PsbtFundingVerify([32]byte, *psbt.Packet) error

	// PsbtFundingFinalize looks up a previously registered funding intent
	// by its pending channel ID and tries to advance the state machine by
	// finalizing the passed PSBT.
	PsbtFundingFinalize([32]byte, *psbt.Packet, *wire.MsgTx) error

	// PublishTransaction performs cursory validation (dust checks, etc),
	// then finally broadcasts the passed transaction to the Bitcoin network.
	PublishTransaction(*wire.MsgTx, string) error

	// CancelFundingIntent allows a caller to cancel a previously registered
	// funding intent. If no intent was found, then an error will be
	// returned.
	CancelFundingIntent([32]byte) error
}

// BatchConfig is the configuration for executing a single batch transaction for
// opening multiple channels atomically.
type BatchConfig struct {
	// RequestParser is the function that parses an incoming RPC request
	// into the internal funding initialization message.
	RequestParser RequestParser

	// ChannelOpener is the function that kicks off the initial channel open
	// negotiation with the peer.
	ChannelOpener ChannelOpener

	// ChannelAbandoner is the function that can abandon a channel in the
	// local database, graph and arbitrator state.
	ChannelAbandoner ChannelAbandoner

	// WalletKitServer is an instance of the wallet kit sub server that can
	// handle PSBT funding and finalization.
	WalletKitServer WalletKitServer

	// Wallet is an instance of the internal lightning wallet.
	Wallet Wallet

	// NetParams contains the current bitcoin network parameters.
	NetParams *chaincfg.Params

	// Quit is the channel that is selected on to recognize if the main
	// server is shutting down.
	Quit chan struct{}
}

// Batcher is a type that can be used to perform an atomic funding of multiple
// channels within a single on-chain transaction.
type Batcher struct {
	cfg *BatchConfig

	channels    []*batchChannel
	lockedUTXOs []*walletrpc.UtxoLease

	didPublish bool

	wg           sync.WaitGroup
	negotiateErr error
}

// NewBatcher returns a new batch channel funding helper.
func NewBatcher(cfg *BatchConfig) *Batcher {
	return &Batcher{
		cfg: cfg,
	}
}

// BatchFund starts the atomic batch channel funding process.
//
// NOTE: This method should only be called once per instance.
func (b *Batcher) BatchFund(ctx context.Context,
	req *lnrpc.BatchOpenChannelRequest) ([]*lnrpc.PendingUpdate, error) {

	label, err := labels.ValidateAPI(req.Label)
	if err != nil {
		return nil, err
	}

	// Parse and validate each individual channel.
	b.channels = make([]*batchChannel, 0, len(req.Channels))
	for idx, rpcChannel := range req.Channels {
		var pendingChanID [32]byte
		if _, err := rand.Read(pendingChanID[:]); err != nil {
			return nil, fmt.Errorf("error making temp chan ID: %v",
				err)
		}

		fundingReq, err := b.cfg.RequestParser(&lnrpc.OpenChannelRequest{
			SatPerVbyte:        uint64(req.SatPerVbyte),
			NodePubkey:         rpcChannel.NodePubkey,
			LocalFundingAmount: rpcChannel.LocalFundingAmount,
			PushSat:            rpcChannel.PushSat,
			TargetConf:         req.TargetConf,
			Private:            rpcChannel.Private,
			MinHtlcMsat:        rpcChannel.MinHtlcMsat,
			RemoteCsvDelay:     rpcChannel.RemoteCsvDelay,
			MinConfs:           req.MinConfs,
			SpendUnconfirmed:   req.SpendUnconfirmed,
			CloseAddress:       rpcChannel.CloseAddress,
			FundingShim: &lnrpc.FundingShim{
				Shim: &lnrpc.FundingShim_PsbtShim{
					PsbtShim: &lnrpc.PsbtShim{
						PendingChanId: pendingChanID[:],
						NoPublish:     true,
					},
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("error parsing channel %d: %v",
				idx, err)
		}

		// Prepare the stuff that we'll need for the internal PSBT
		// funding.
		fundingReq.PendingChanID = pendingChanID
		fundingReq.ChanFunder = chanfunding.NewPsbtAssembler(
			btcutil.Amount(rpcChannel.LocalFundingAmount), nil,
			b.cfg.NetParams, false,
		)

		b.channels = append(b.channels, &batchChannel{
			pendingChanID: pendingChanID,
			fundingReq:    fundingReq,
		})
	}

	// From this point on we can fail for any of the channels and for any
	// number of reasons. This deferred function makes sure that the full
	// operation is actually atomic: We either succeed and publish a
	// transaction for the full batch or we clean up everything.
	defer b.cleanup(ctx)

	// Now that we know the user input is sane, we need to kick off the
	// channel funding negotiation with the peers. Because we specified a
	// PSBT assembler, we'll get a special response in the channel once the
	// funding output script is known (which we need to craft the TX).
	b.wg.Add(len(b.channels))
	b.negotiateErr = nil
	for _, channel := range b.channels {
		channel.updateChan, channel.errChan = b.cfg.ChannelOpener(
			channel.fundingReq,
		)

		// Launch a goroutine that waits for the initial response on
		// either the update or error chan.
		go b.waitForUpdate(channel, true)
	}

	// Wait for all goroutines to report back. Any error at this stage means
	// we need to abort.
	b.wg.Wait()
	if b.negotiateErr != nil {
		return nil, fmt.Errorf("error batch opening channel, initial "+
			"negotiation failed: %v", b.negotiateErr)
	}

	// We can now assemble all outputs that we're going to give to the PSBT
	// funding method of the wallet kit server.
	txTemplate := &walletrpc.TxTemplate{
		Outputs: make(map[string]uint64),
	}
	for _, channel := range b.channels {
		txTemplate.Outputs[channel.fundingAddr] = uint64(
			channel.fundingReq.LocalFundingAmt,
		)
	}

	// Great, we've now started the channel negotiation successfully with
	// all peers. This means we know the channel outputs for all channels
	// and can craft our PSBT now. We take the fee rate and min conf
	// settings from the first request as all of them should be equal
	// anyway.
	firstReq := b.channels[0].fundingReq
	feeRateSatPerKVByte := firstReq.FundingFeePerKw.FeePerKVByte()
	fundPsbtReq := &walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_Raw{
			Raw: txTemplate,
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: uint64(feeRateSatPerKVByte) / 1000,
		},
		MinConfs:         firstReq.MinConfs,
		SpendUnconfirmed: firstReq.MinConfs == 0,
	}
	fundPsbtResp, err := b.cfg.WalletKitServer.FundPsbt(ctx, fundPsbtReq)
	if err != nil {
		return nil, fmt.Errorf("error funding PSBT for batch channel "+
			"open: %v", err)
	}

	// Funding was successful. This means there are some UTXOs that are now
	// locked for us. We need to make sure we release them if we don't
	// complete the publish process.
	b.lockedUTXOs = fundPsbtResp.LockedUtxos

	// Parse and log the funded PSBT for debugging purposes.
	unsignedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(fundPsbtResp.FundedPsbt), false,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing funded PSBT for batch "+
			"channel open: %v", err)
	}
	log.Tracef("[batchopenchannel] funded PSBT: %s",
		base64.StdEncoding.EncodeToString(fundPsbtResp.FundedPsbt))

	// With the funded PSBT we can now advance the funding state machine of
	// each of the channels.
	for _, channel := range b.channels {
		err = b.cfg.Wallet.PsbtFundingVerify(
			channel.pendingChanID, unsignedPacket,
		)
		if err != nil {
			return nil, fmt.Errorf("error verifying PSBT: %v", err)
		}
	}

	// The funded PSBT was accepted by each of the assemblers, let's now
	// sign/finalize it.
	finalizePsbtResp, err := b.cfg.WalletKitServer.FinalizePsbt(
		ctx, &walletrpc.FinalizePsbtRequest{
			FundedPsbt: fundPsbtResp.FundedPsbt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error finalizing PSBT for batch "+
			"channel open: %v", err)
	}
	finalTx := &wire.MsgTx{}
	txReader := bytes.NewReader(finalizePsbtResp.RawFinalTx)
	if err := finalTx.Deserialize(txReader); err != nil {
		return nil, fmt.Errorf("error parsing signed raw TX: %v", err)
	}
	log.Tracef("[batchopenchannel] signed PSBT: %s",
		base64.StdEncoding.EncodeToString(finalizePsbtResp.SignedPsbt))

	// Advance the funding state machine of each of the channels a last time
	// to complete the negotiation with the now signed funding TX.
	for _, channel := range b.channels {
		err = b.cfg.Wallet.PsbtFundingFinalize(
			channel.pendingChanID, nil, finalTx,
		)
		if err != nil {
			return nil, fmt.Errorf("error finalizing PSBT: %v", err)
		}
	}

	// Now every channel should be ready for the funding transaction to be
	// broadcast. Let's wait for the updates that actually confirm this
	// state.
	b.wg.Add(len(b.channels))
	b.negotiateErr = nil
	for _, channel := range b.channels {
		// Launch another goroutine that waits for the channel pending
		// response on the update chan.
		go b.waitForUpdate(channel, false)
	}

	// Wait for all updates and make sure we're still good to proceed.
	b.wg.Wait()
	if b.negotiateErr != nil {
		return nil, fmt.Errorf("error batch opening channel, final "+
			"negotiation failed: %v", b.negotiateErr)
	}

	// Great, we're now finally ready to publish the transaction.
	err = b.cfg.Wallet.PublishTransaction(finalTx, label)
	if err != nil {
		return nil, fmt.Errorf("error publishing final batch "+
			"transaction: %v", err)
	}
	b.didPublish = true

	rpcPoints := make([]*lnrpc.PendingUpdate, len(b.channels))
	for idx, channel := range b.channels {
		rpcPoints[idx] = &lnrpc.PendingUpdate{
			Txid:        channel.chanPoint.Hash.CloneBytes(),
			OutputIndex: channel.chanPoint.Index,
		}
	}

	return rpcPoints, nil
}

// waitForUpdate waits for an incoming channel update (or error) for a single
// channel.
func (b *Batcher) waitForUpdate(channel *batchChannel, firstUpdate bool) {
	defer b.wg.Done()

	select {
	// If an error occurs then immediately return the error to the client.
	case err := <-channel.errChan:
		log.Errorf("unable to open channel to NodeKey(%x): %v",
			channel.fundingReq.TargetPubkey.SerializeCompressed(),
			err)
		b.negotiateErr = err

	// Otherwise, wait for the next channel update. The first update sent
	// must be the signal to start the PSBT funding in our case since we
	// specified a PSBT shim. The second update will be the signal that the
	// channel is now pending.
	case fundingUpdate := <-channel.updateChan:
		log.Tracef("[batchopenchannel] received update: %v",
			fundingUpdate)

		// Depending on what update we were waiting for the batch
		// channel knows what to do with it.
		var err error
		if firstUpdate {
			err = channel.processPsbtUpdate(fundingUpdate)
		} else {
			err = channel.processPendingUpdate(fundingUpdate)
		}
		if err != nil {
			b.negotiateErr = err
			return
		}

	case <-b.cfg.Quit:
		b.negotiateErr = errShuttingDown
	}
}

// cleanup tries to remove any pending state or UTXO locks in case we had to
// abort before finalizing and publishing the funding transaction.
func (b *Batcher) cleanup(ctx context.Context) {
	// Did we publish a transaction? Then there's nothing to clean up since
	// we succeeded.
	if b.didPublish {
		return
	}

	// Make sure the error message doesn't sound too scary. These might be
	// logged quite frequently depending on where exactly things were
	// aborted. We could just not log any cleanup errors though it might be
	// helpful to debug things if something doesn't go as expected.
	const errMsgTpl = "Attempted to clean up after failed batch channel " +
		"open but could not %s: %v"

	// If we failed, we clean up in reverse order. First, let's unlock the
	// leased outputs.
	for _, lockedUTXO := range b.lockedUTXOs {
		rpcOP := &lnrpc.OutPoint{
			OutputIndex: lockedUTXO.Outpoint.OutputIndex,
			TxidBytes:   lockedUTXO.Outpoint.TxidBytes,
		}
		_, err := b.cfg.WalletKitServer.ReleaseOutput(
			ctx, &walletrpc.ReleaseOutputRequest{
				Id:       lockedUTXO.Id,
				Outpoint: rpcOP,
			},
		)
		if err != nil {
			log.Debugf(errMsgTpl, "release locked output "+
				lockedUTXO.Outpoint.String(), err)
		}
	}

	// Then go through all channels that ever got into a pending state and
	// remove the pending channel by abandoning them.
	for _, channel := range b.channels {
		if !channel.isPending {
			continue
		}

		err := b.cfg.ChannelAbandoner(channel.chanPoint)
		if err != nil {
			log.Debugf(errMsgTpl, "abandon pending open channel",
				err)
		}
	}

	// And finally clean up the funding shim for each channel that didn't
	// make it into a pending state.
	for _, channel := range b.channels {
		if channel.isPending {
			continue
		}

		err := b.cfg.Wallet.CancelFundingIntent(channel.pendingChanID)
		if err != nil {
			log.Debugf(errMsgTpl, "cancel funding shim", err)
		}
	}
}
