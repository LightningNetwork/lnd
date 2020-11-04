package invoices

import (
	"errors"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
)

// invoiceUpdateCtx is an object that describes the context for the invoice
// update to be carried out.
type invoiceUpdateCtx struct {
	hash                 lntypes.Hash
	circuitKey           channeldb.CircuitKey
	amtPaid              lnwire.MilliSatoshi
	expiry               uint32
	currentHeight        int32
	finalCltvRejectDelta int32
	customRecords        record.CustomSet
	mpp                  *record.MPP
}

// invoiceRef returns an identifier that can be used to lookup or update the
// invoice this HTLC is targeting.
func (i *invoiceUpdateCtx) invoiceRef() channeldb.InvoiceRef {
	if i.mpp != nil {
		payAddr := i.mpp.PaymentAddr()
		return channeldb.InvoiceRefByHashAndAddr(i.hash, payAddr)
	}
	return channeldb.InvoiceRefByHash(i.hash)
}

// log logs a message specific to this update context.
func (i *invoiceUpdateCtx) log(s string) {
	log.Debugf("Invoice%v: %v, amt=%v, expiry=%v, circuit=%v, mpp=%v",
		i.invoiceRef, s, i.amtPaid, i.expiry, i.circuitKey, i.mpp)
}

// failRes is a helper function which creates a failure resolution with
// the information contained in the invoiceUpdateCtx and the fail resolution
// result provided.
func (i invoiceUpdateCtx) failRes(outcome FailResolutionResult) *HtlcFailResolution {
	return NewFailResolution(i.circuitKey, i.currentHeight, outcome)
}

// settleRes is a helper function which creates a settle resolution with
// the information contained in the invoiceUpdateCtx and the preimage and
// the settle resolution result provided.
func (i invoiceUpdateCtx) settleRes(preimage lntypes.Preimage,
	outcome SettleResolutionResult) *HtlcSettleResolution {

	return NewSettleResolution(
		preimage, i.circuitKey, i.currentHeight, outcome,
	)
}

// acceptRes is a helper function which creates an accept resolution with
// the information contained in the invoiceUpdateCtx and the accept resolution
// result provided.
func (i invoiceUpdateCtx) acceptRes(outcome acceptResolutionResult) *htlcAcceptResolution {
	return newAcceptResolution(i.circuitKey, outcome)
}

// updateInvoice is a callback for DB.UpdateInvoice that contains the invoice
// settlement logic. It returns a hltc resolution that indicates what the
// outcome of the update was.
func updateInvoice(ctx *invoiceUpdateCtx, inv *channeldb.Invoice) (
	*channeldb.InvoiceUpdateDesc, HtlcResolution, error) {

	// Don't update the invoice when this is a replayed htlc.
	htlc, ok := inv.Htlcs[ctx.circuitKey]
	if ok {
		switch htlc.State {
		case channeldb.HtlcStateCanceled:
			return nil, ctx.failRes(ResultReplayToCanceled), nil

		case channeldb.HtlcStateAccepted:
			return nil, ctx.acceptRes(resultReplayToAccepted), nil

		case channeldb.HtlcStateSettled:
			return nil, ctx.settleRes(
				*inv.Terms.PaymentPreimage,
				ResultReplayToSettled,
			), nil

		default:
			return nil, nil, errors.New("unknown htlc state")
		}
	}

	if ctx.mpp == nil {
		return updateLegacy(ctx, inv)
	}

	return updateMpp(ctx, inv)
}

// updateMpp is a callback for DB.UpdateInvoice that contains the invoice
// settlement logic for mpp payments.
func updateMpp(ctx *invoiceUpdateCtx,
	inv *channeldb.Invoice) (*channeldb.InvoiceUpdateDesc,
	HtlcResolution, error) {

	// Start building the accept descriptor.
	acceptDesc := &channeldb.HtlcAcceptDesc{
		Amt:           ctx.amtPaid,
		Expiry:        ctx.expiry,
		AcceptHeight:  ctx.currentHeight,
		MppTotalAmt:   ctx.mpp.TotalMsat(),
		CustomRecords: ctx.customRecords,
	}

	// Only accept payments to open invoices. This behaviour differs from
	// non-mpp payments that are accepted even after the invoice is settled.
	// Because non-mpp payments don't have a payment address, this is needed
	// to thwart probing.
	if inv.State != channeldb.ContractOpen {
		return nil, ctx.failRes(ResultInvoiceNotOpen), nil
	}

	// Check the payment address that authorizes the payment.
	if ctx.mpp.PaymentAddr() != inv.Terms.PaymentAddr {
		return nil, ctx.failRes(ResultAddressMismatch), nil
	}

	// Don't accept zero-valued sets.
	if ctx.mpp.TotalMsat() == 0 {
		return nil, ctx.failRes(ResultHtlcSetTotalTooLow), nil
	}

	// Check that the total amt of the htlc set is high enough. In case this
	// is a zero-valued invoice, it will always be enough.
	if ctx.mpp.TotalMsat() < inv.Terms.Value {
		return nil, ctx.failRes(ResultHtlcSetTotalTooLow), nil
	}

	hodlInvoice := inv.HodlInvoice || ctx.circuitKey.ChanID.IsFake()
	// Check whether total amt matches other htlcs in the set.
	var newSetTotal lnwire.MilliSatoshi
	for circuitKey, htlc := range inv.Htlcs {
		// Only consider accepted mpp htlcs. It is possible that there
		// are htlcs registered in the invoice database that previously
		// timed out and are in the canceled state now.
		if htlc.State != channeldb.HtlcStateAccepted {
			continue
		}

		if ctx.mpp.TotalMsat() != htlc.MppTotalAmt {
			return nil, ctx.failRes(ResultHtlcSetTotalMismatch), nil
		}

		if circuitKey.ChanID.IsFake() {
			hodlInvoice = true
		}
		newSetTotal += htlc.Amt
	}

	// Add amount of new htlc.
	newSetTotal += ctx.amtPaid

	// Make sure the communicated set total isn't overpaid.
	if newSetTotal > ctx.mpp.TotalMsat() {
		return nil, ctx.failRes(ResultHtlcSetOverpayment), nil
	}

	// The invoice is still open. Check the expiry.
	if ctx.expiry < uint32(ctx.currentHeight+ctx.finalCltvRejectDelta) {
		return nil, ctx.failRes(ResultExpiryTooSoon), nil
	}

	if ctx.expiry < uint32(ctx.currentHeight+inv.Terms.FinalCltvDelta) {
		return nil, ctx.failRes(ResultExpiryTooSoon), nil
	}

	// Record HTLC in the invoice database.
	newHtlcs := map[channeldb.CircuitKey]*channeldb.HtlcAcceptDesc{
		ctx.circuitKey: acceptDesc,
	}

	update := channeldb.InvoiceUpdateDesc{
		AddHtlcs: newHtlcs,
	}

	// If the invoice cannot be settled yet, only record the htlc.
	setComplete := newSetTotal == ctx.mpp.TotalMsat()
	if !setComplete {
		return &update, ctx.acceptRes(resultPartialAccepted), nil
	}

	// Check to see if we can settle or this is an hold invoice and
	// we need to wait for the preimage.
	if hodlInvoice {
		update.State = &channeldb.InvoiceStateUpdateDesc{
			NewState: channeldb.ContractAccepted,
		}
		return &update, ctx.acceptRes(resultAccepted), nil
	}

	update.State = &channeldb.InvoiceStateUpdateDesc{
		NewState: channeldb.ContractSettled,
		Preimage: inv.Terms.PaymentPreimage,
	}

	return &update, ctx.settleRes(
		*inv.Terms.PaymentPreimage, ResultSettled,
	), nil
}

// updateLegacy is a callback for DB.UpdateInvoice that contains the invoice
// settlement logic for legacy payments.
func updateLegacy(ctx *invoiceUpdateCtx,
	inv *channeldb.Invoice) (*channeldb.InvoiceUpdateDesc, HtlcResolution, error) {

	// If the invoice is already canceled, there is no further
	// checking to do.
	if inv.State == channeldb.ContractCanceled {
		return nil, ctx.failRes(ResultInvoiceAlreadyCanceled), nil
	}

	// If an invoice amount is specified, check that enough is paid. Also
	// check this for duplicate payments if the invoice is already settled
	// or accepted. In case this is a zero-valued invoice, it will always be
	// enough.
	if ctx.amtPaid < inv.Terms.Value {
		return nil, ctx.failRes(ResultAmountTooLow), nil
	}

	// TODO(joostjager): Check invoice mpp required feature
	// bit when feature becomes mandatory.

	// Don't allow settling the invoice with an old style
	// htlc if we are already in the process of gathering an
	// mpp set.
	for _, htlc := range inv.Htlcs {
		if htlc.State == channeldb.HtlcStateAccepted &&
			htlc.MppTotalAmt > 0 {

			return nil, ctx.failRes(ResultMppInProgress), nil
		}
	}

	// The invoice is still open. Check the expiry.
	if ctx.expiry < uint32(ctx.currentHeight+ctx.finalCltvRejectDelta) {
		return nil, ctx.failRes(ResultExpiryTooSoon), nil
	}

	if ctx.expiry < uint32(ctx.currentHeight+inv.Terms.FinalCltvDelta) {
		return nil, ctx.failRes(ResultExpiryTooSoon), nil
	}

	// Record HTLC in the invoice database.
	newHtlcs := map[channeldb.CircuitKey]*channeldb.HtlcAcceptDesc{
		ctx.circuitKey: {
			Amt:           ctx.amtPaid,
			Expiry:        ctx.expiry,
			AcceptHeight:  ctx.currentHeight,
			CustomRecords: ctx.customRecords,
		},
	}

	update := channeldb.InvoiceUpdateDesc{
		AddHtlcs: newHtlcs,
	}

	// Don't update invoice state if we are accepting a duplicate payment.
	// We do accept or settle the HTLC.
	switch inv.State {
	case channeldb.ContractAccepted:
		return &update, ctx.acceptRes(resultDuplicateToAccepted), nil

	case channeldb.ContractSettled:
		return &update, ctx.settleRes(
			*inv.Terms.PaymentPreimage, ResultDuplicateToSettled,
		), nil
	}

	// Check to see if we can settle or this is an hold invoice and we need
	// to wait for the preimage.
	if inv.HodlInvoice || ctx.circuitKey.ChanID.IsFake() {
		update.State = &channeldb.InvoiceStateUpdateDesc{
			NewState: channeldb.ContractAccepted,
		}

		return &update, ctx.acceptRes(resultAccepted), nil
	}

	update.State = &channeldb.InvoiceStateUpdateDesc{
		NewState: channeldb.ContractSettled,
		Preimage: inv.Terms.PaymentPreimage,
	}

	return &update, ctx.settleRes(
		*inv.Terms.PaymentPreimage, ResultSettled,
	), nil
}
