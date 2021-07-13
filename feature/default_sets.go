package feature

import "github.com/lightningnetwork/lnd/lnwire"

// setDesc describes which feature bits should be advertised in which feature
// sets.
type setDesc map[lnwire.FeatureBit]map[Set]struct{}

// defaultSetDesc are the default set descriptors for generating feature
// vectors. Each set is annotated with the corresponding identifier from BOLT 9
// indicating where it should be advertised.
var defaultSetDesc = setDesc{
	lnwire.DataLossProtectRequired: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
	lnwire.GossipQueriesOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
	lnwire.TLVOnionPayloadOptional: {
		SetInit:         {}, // I
		SetNodeAnn:      {}, // N
		SetInvoice:      {}, // 9
		SetInvoiceAmp:   {}, // 9A
		SetLegacyGlobal: {},
	},
	lnwire.StaticRemoteKeyRequired: {
		SetInit:         {}, // I
		SetNodeAnn:      {}, // N
		SetLegacyGlobal: {},
	},
	lnwire.UpfrontShutdownScriptOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
	lnwire.PaymentAddrRequired: {
		SetInit:       {}, // I
		SetNodeAnn:    {}, // N
		SetInvoice:    {}, // 9
		SetInvoiceAmp: {}, // 9A
	},
	lnwire.MPPOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
		SetInvoice: {}, // 9
	},
	lnwire.AnchorsZeroFeeHtlcTxOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
	lnwire.WumboChannelsOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
	lnwire.AMPOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
	lnwire.AMPRequired: {
		SetInvoiceAmp: {}, // 9A
	},
	lnwire.ExplicitChannelTypeOptional: {
		SetInit:    {}, // I
		SetNodeAnn: {}, // N
	},
}
