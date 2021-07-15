package invoicesrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/zpay32"
)

const (
	// DefaultInvoiceExpiry is the default invoice expiry for new MPP
	// invoices.
	DefaultInvoiceExpiry = 24 * time.Hour

	// DefaultAMPInvoiceExpiry is the default invoice expiry for new AMP
	// invoices.
	DefaultAMPInvoiceExpiry = 30 * 24 * time.Hour
)

// AddInvoiceConfig contains dependencies for invoice creation.
type AddInvoiceConfig struct {
	// AddInvoice is called to add the invoice to the registry.
	AddInvoice func(invoice *channeldb.Invoice, paymentHash lntypes.Hash) (
		uint64, error)

	// IsChannelActive is used to generate valid hop hints.
	IsChannelActive func(chanID lnwire.ChannelID) bool

	// ChainParams are required to properly decode invoice payment requests
	// that are marshalled over rpc.
	ChainParams *chaincfg.Params

	// NodeSigner is an implementation of the MessageSigner implementation
	// that's backed by the identity private key of the running lnd node.
	NodeSigner *netann.NodeSigner

	// DefaultCLTVExpiry is the default invoice expiry if no values is
	// specified.
	DefaultCLTVExpiry uint32

	// ChanDB is a global boltdb instance which is needed to access the
	// channel graph.
	ChanDB *channeldb.DB

	// Graph holds a reference to the ChannelGraph database.
	Graph *channeldb.ChannelGraph

	// GenInvoiceFeatures returns a feature containing feature bits that
	// should be advertised on freshly generated invoices.
	GenInvoiceFeatures func() *lnwire.FeatureVector

	// GenAmpInvoiceFeatures returns a feature containing feature bits that
	// should be advertised on freshly generated AMP invoices.
	GenAmpInvoiceFeatures func() *lnwire.FeatureVector
}

// AddInvoiceData contains the required data to create a new invoice.
type AddInvoiceData struct {
	// An optional memo to attach along with the invoice. Used for record
	// keeping purposes for the invoice's creator, and will also be set in
	// the description field of the encoded payment request if the
	// description_hash field is not being used.
	Memo string

	// The preimage which will allow settling an incoming HTLC payable to
	// this preimage. If Preimage is set, Hash should be nil. If both
	// Preimage and Hash are nil, a random preimage is generated.
	Preimage *lntypes.Preimage

	// The hash of the preimage. If Hash is set, Preimage should be nil.
	// This condition indicates that we have a 'hold invoice' for which the
	// htlc will be accepted and held until the preimage becomes known.
	Hash *lntypes.Hash

	// The value of this invoice in millisatoshis.
	Value lnwire.MilliSatoshi

	// Hash (SHA-256) of a description of the payment. Used if the
	// description of payment (memo) is too long to naturally fit within the
	// description field of an encoded payment request.
	DescriptionHash []byte

	// Payment request expiry time in seconds. Default is 3600 (1 hour).
	Expiry int64

	// Fallback on-chain address.
	FallbackAddr string

	// Delta to use for the time-lock of the CLTV extended to the final hop.
	CltvExpiry uint64

	// Whether this invoice should include routing hints for private
	// channels.
	Private bool

	// HodlInvoice signals that this invoice shouldn't be settled
	// immediately upon receiving the payment.
	HodlInvoice bool

	// Amp signals whether or not to create an AMP invoice.
	//
	// NOTE: Preimage should always be set to nil when this value is true.
	Amp bool

	// RouteHints are optional route hints that can each be individually used
	// to assist in reaching the invoice's destination.
	RouteHints [][]zpay32.HopHint
}

// paymentHashAndPreimage returns the payment hash and preimage for this invoice
// depending on the configuration.
//
// For AMP invoices (when Amp flag is true), this method always returns a nil
// preimage. The hash value can be set externally by the user using the Hash
// field, or one will be generated randomly. The payment hash here only serves
// as a unique identifier for insertion into the invoice index, as there is
// no universal preimage for an AMP payment.
//
// For MPP invoices (when Amp flag is false), this method may return nil
// preimage when create a hodl invoice, but otherwise will always return a
// non-nil preimage and the corresponding payment hash. The valid combinations
// are parsed as follows:
//   - Preimage == nil && Hash == nil -> (random preimage, H(random preimage))
//   - Preimage != nil && Hash == nil -> (Preimage, H(Preimage))
//   - Preimage == nil && Hash != nil -> (nil, Hash)
func (d *AddInvoiceData) paymentHashAndPreimage() (
	*lntypes.Preimage, lntypes.Hash, error) {

	if d.Amp {
		return d.ampPaymentHashAndPreimage()
	}

	return d.mppPaymentHashAndPreimage()
}

// ampPaymentHashAndPreimage returns the payment hash to use for an AMP invoice.
// The preimage will always be nil.
func (d *AddInvoiceData) ampPaymentHashAndPreimage() (*lntypes.Preimage, lntypes.Hash, error) {
	switch {

	// Preimages cannot be set on AMP invoice.
	case d.Preimage != nil:
		return nil, lntypes.Hash{},
			errors.New("preimage set on AMP invoice")

	// If a specific hash was requested, use that.
	case d.Hash != nil:
		return nil, *d.Hash, nil

	// Otherwise generate a random hash value, just needs to be unique to be
	// added to the invoice index.
	default:
		var paymentHash lntypes.Hash
		if _, err := rand.Read(paymentHash[:]); err != nil {
			return nil, lntypes.Hash{}, err
		}

		return nil, paymentHash, nil
	}
}

// mppPaymentHashAndPreimage returns the payment hash and preimage to use for an
// MPP invoice.
func (d *AddInvoiceData) mppPaymentHashAndPreimage() (*lntypes.Preimage, lntypes.Hash, error) {
	var (
		paymentPreimage *lntypes.Preimage
		paymentHash     lntypes.Hash
	)

	switch {

	// Only either preimage or hash can be set.
	case d.Preimage != nil && d.Hash != nil:
		return nil, lntypes.Hash{},
			errors.New("preimage and hash both set")

	// If no hash or preimage is given, generate a random preimage.
	case d.Preimage == nil && d.Hash == nil:
		paymentPreimage = &lntypes.Preimage{}
		if _, err := rand.Read(paymentPreimage[:]); err != nil {
			return nil, lntypes.Hash{}, err
		}
		paymentHash = paymentPreimage.Hash()

	// If just a hash is given, we create a hold invoice by setting the
	// preimage to unknown.
	case d.Preimage == nil && d.Hash != nil:
		paymentHash = *d.Hash

	// A specific preimage was supplied. Use that for the invoice.
	case d.Preimage != nil && d.Hash == nil:
		preimage := *d.Preimage
		paymentPreimage = &preimage
		paymentHash = d.Preimage.Hash()
	}

	return paymentPreimage, paymentHash, nil
}

// AddInvoice attempts to add a new invoice to the invoice database. Any
// duplicated invoices are rejected, therefore all invoices *must* have a
// unique payment preimage.
func AddInvoice(ctx context.Context, cfg *AddInvoiceConfig,
	invoice *AddInvoiceData) (*lntypes.Hash, *channeldb.Invoice, error) {

	paymentPreimage, paymentHash, err := invoice.paymentHashAndPreimage()
	if err != nil {
		return nil, nil, err
	}

	// The size of the memo, receipt and description hash attached must not
	// exceed the maximum values for either of the fields.
	if len(invoice.Memo) > channeldb.MaxMemoSize {
		return nil, nil, fmt.Errorf("memo too large: %v bytes "+
			"(maxsize=%v)", len(invoice.Memo), channeldb.MaxMemoSize)
	}
	if len(invoice.DescriptionHash) > 0 && len(invoice.DescriptionHash) != 32 {
		return nil, nil, fmt.Errorf("description hash is %v bytes, must be 32",
			len(invoice.DescriptionHash))
	}

	// We set the max invoice amount to 100k BTC, which itself is several
	// multiples off the current block reward.
	maxInvoiceAmt := btcutil.Amount(btcutil.SatoshiPerBitcoin * 100000)

	switch {
	// The value of the invoice must not be negative.
	case int64(invoice.Value) < 0:
		return nil, nil, fmt.Errorf("payments of negative value "+
			"are not allowed, value is %v", int64(invoice.Value))

	// Also ensure that the invoice is actually realistic, while preventing
	// any issues due to underflow.
	case invoice.Value.ToSatoshis() > maxInvoiceAmt:
		return nil, nil, fmt.Errorf("invoice amount %v is "+
			"too large, max is %v", invoice.Value.ToSatoshis(),
			maxInvoiceAmt)
	}

	amtMSat := invoice.Value

	// We also create an encoded payment request which allows the
	// caller to compactly send the invoice to the payer. We'll create a
	// list of options to be added to the encoded payment request. For now
	// we only support the required fields description/description_hash,
	// expiry, fallback address, and the amount field.
	var options []func(*zpay32.Invoice)

	// We only include the amount in the invoice if it is greater than 0.
	// By not including the amount, we enable the creation of invoices that
	// allow the payee to specify the amount of satoshis they wish to send.
	if amtMSat > 0 {
		options = append(options, zpay32.Amount(amtMSat))
	}

	// If specified, add a fallback address to the payment request.
	if len(invoice.FallbackAddr) > 0 {
		addr, err := btcutil.DecodeAddress(invoice.FallbackAddr,
			cfg.ChainParams)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid fallback address: %v",
				err)
		}
		options = append(options, zpay32.FallbackAddr(addr))
	}

	switch {

	// If expiry is set, specify it. If it is not provided, no expiry time
	// will be explicitly added to this payment request, which will imply
	// the default 3600 seconds.
	case invoice.Expiry > 0:

		// We'll ensure that the specified expiry is restricted to sane
		// number of seconds. As a result, we'll reject an invoice with
		// an expiry greater than 1 year.
		maxExpiry := time.Hour * 24 * 365
		expSeconds := invoice.Expiry

		if float64(expSeconds) > maxExpiry.Seconds() {
			return nil, nil, fmt.Errorf("expiry of %v seconds "+
				"greater than max expiry of %v seconds",
				float64(expSeconds), maxExpiry.Seconds())
		}

		expiry := time.Duration(invoice.Expiry) * time.Second
		options = append(options, zpay32.Expiry(expiry))

	// If no custom expiry is provided, use the default MPP expiry.
	case !invoice.Amp:
		options = append(options, zpay32.Expiry(DefaultInvoiceExpiry))

	// Otherwise, use the default AMP expiry.
	default:
		options = append(options, zpay32.Expiry(DefaultAMPInvoiceExpiry))

	}

	// If the description hash is set, then we add it do the list of options.
	// If not, use the memo field as the payment request description.
	if len(invoice.DescriptionHash) > 0 {
		var descHash [32]byte
		copy(descHash[:], invoice.DescriptionHash[:])
		options = append(options, zpay32.DescriptionHash(descHash))
	} else {
		// Use the memo field as the description. If this is not set
		// this will just be an empty string.
		options = append(options, zpay32.Description(invoice.Memo))
	}

	// We'll use our current default CLTV value unless one was specified as
	// an option on the command line when creating an invoice.
	switch {
	case invoice.CltvExpiry > math.MaxUint16:
		return nil, nil, fmt.Errorf("CLTV delta of %v is too large, max "+
			"accepted is: %v", invoice.CltvExpiry, math.MaxUint16)
	case invoice.CltvExpiry != 0:
		// Disallow user-chosen final CLTV deltas below the required
		// minimum.
		if invoice.CltvExpiry < routing.MinCLTVDelta {
			return nil, nil, fmt.Errorf("CLTV delta of %v must be "+
				"greater than minimum of %v",
				routing.MinCLTVDelta, invoice.CltvExpiry)
		}

		options = append(options,
			zpay32.CLTVExpiry(invoice.CltvExpiry))
	default:
		// TODO(roasbeef): assumes set delta between versions
		defaultDelta := cfg.DefaultCLTVExpiry
		options = append(options, zpay32.CLTVExpiry(uint64(defaultDelta)))
	}

	// We make sure that the given invoice routing hints number is within the
	// valid range
	if len(invoice.RouteHints) > 20 {
		return nil, nil, fmt.Errorf("number of routing hints must not exceed " +
			"maximum of 20")
	}

	// We continue by populating the requested routing hints indexing their
	// corresponding channels so we won't duplicate them.
	forcedHints := make(map[uint64]struct{})
	for _, h := range invoice.RouteHints {
		if len(h) == 0 {
			return nil, nil, fmt.Errorf("number of hop hint within a route must " +
				"be positive")
		}
		options = append(options, zpay32.RouteHint(h))

		// Only this first hop is our direct channel.
		forcedHints[h[0].ChannelID] = struct{}{}
	}

	// If we were requested to include routing hints in the invoice, then
	// we'll fetch all of our available private channels and create routing
	// hints for them.
	if invoice.Private {
		openChannels, err := cfg.ChanDB.FetchAllChannels()
		if err != nil {
			return nil, nil, fmt.Errorf("could not fetch all channels")
		}

		if len(openChannels) > 0 {
			// We filter the channels by excluding the ones that were specified by
			// the caller and were already added.
			var filteredChannels []*channeldb.OpenChannel
			for _, c := range openChannels {
				if _, ok := forcedHints[c.ShortChanID().ToUint64()]; ok {
					continue
				}
				filteredChannels = append(filteredChannels, c)
			}

			// We'll restrict the number of individual route hints
			// to 20 to avoid creating overly large invoices.
			numMaxHophints := 20 - len(forcedHints)
			hopHints := selectHopHints(
				amtMSat, cfg, filteredChannels, numMaxHophints,
			)

			options = append(options, hopHints...)
		}
	}

	// Set our desired invoice features and add them to our list of options.
	var invoiceFeatures *lnwire.FeatureVector
	if invoice.Amp {
		invoiceFeatures = cfg.GenAmpInvoiceFeatures()
	} else {
		invoiceFeatures = cfg.GenInvoiceFeatures()
	}
	options = append(options, zpay32.Features(invoiceFeatures))

	// Generate and set a random payment address for this invoice. If the
	// sender understands payment addresses, this can be used to avoid
	// intermediaries probing the receiver.
	var paymentAddr [32]byte
	if _, err := rand.Read(paymentAddr[:]); err != nil {
		return nil, nil, err
	}
	options = append(options, zpay32.PaymentAddr(paymentAddr))

	// Create and encode the payment request as a bech32 (zpay32) string.
	creationDate := time.Now()
	payReq, err := zpay32.NewInvoice(
		cfg.ChainParams, paymentHash, creationDate, options...,
	)
	if err != nil {
		return nil, nil, err
	}

	payReqString, err := payReq.Encode(
		zpay32.MessageSigner{
			SignCompact: func(msg []byte) ([]byte, error) {
				hash := chainhash.HashB(msg)
				return cfg.NodeSigner.SignDigestCompact(hash)
			},
		},
	)
	if err != nil {
		return nil, nil, err
	}

	newInvoice := &channeldb.Invoice{
		CreationDate:   creationDate,
		Memo:           []byte(invoice.Memo),
		PaymentRequest: []byte(payReqString),
		Terms: channeldb.ContractTerm{
			FinalCltvDelta:  int32(payReq.MinFinalCLTVExpiry()),
			Expiry:          payReq.Expiry(),
			Value:           amtMSat,
			PaymentPreimage: paymentPreimage,
			PaymentAddr:     paymentAddr,
			Features:        invoiceFeatures,
		},
		HodlInvoice: invoice.HodlInvoice,
	}

	log.Tracef("[addinvoice] adding new invoice %v",
		newLogClosure(func() string {
			return spew.Sdump(newInvoice)
		}),
	)

	// With all sanity checks passed, write the invoice to the database.
	_, err = cfg.AddInvoice(newInvoice, paymentHash)
	if err != nil {
		return nil, nil, err
	}

	return &paymentHash, newInvoice, nil
}

// chanCanBeHopHint returns true if the target channel is eligible to be a hop
// hint.
func chanCanBeHopHint(channel *channeldb.OpenChannel, cfg *AddInvoiceConfig) (
	*channeldb.ChannelEdgePolicy, bool) {

	// Since we're only interested in our private channels, we'll skip
	// public ones.
	isPublic := channel.ChannelFlags&lnwire.FFAnnounceChannel != 0
	if isPublic {
		return nil, false
	}

	// Make sure the channel is active.
	chanPoint := lnwire.NewChanIDFromOutPoint(
		&channel.FundingOutpoint,
	)
	if !cfg.IsChannelActive(chanPoint) {
		log.Debugf("Skipping channel %v due to not "+
			"being eligible to forward payments",
			chanPoint)
		return nil, false
	}

	// To ensure we don't leak unadvertised nodes, we'll make sure our
	// counterparty is publicly advertised within the network.  Otherwise,
	// we'll end up leaking information about nodes that intend to stay
	// unadvertised, like in the case of a node only having private
	// channels.
	var remotePub [33]byte
	copy(remotePub[:], channel.IdentityPub.SerializeCompressed())
	isRemoteNodePublic, err := cfg.Graph.IsPublicNode(remotePub)
	if err != nil {
		log.Errorf("Unable to determine if node %x "+
			"is advertised: %v", remotePub, err)
		return nil, false
	}

	if !isRemoteNodePublic {
		log.Debugf("Skipping channel %v due to "+
			"counterparty %x being unadvertised",
			chanPoint, remotePub)
		return nil, false
	}

	// Fetch the policies for each end of the channel.
	chanID := channel.ShortChanID().ToUint64()
	info, p1, p2, err := cfg.Graph.FetchChannelEdgesByID(chanID)
	if err != nil {
		log.Errorf("Unable to fetch the routing "+
			"policies for the edges of the channel "+
			"%v: %v", chanPoint, err)
		return nil, false
	}

	// Now, we'll need to determine which is the correct policy for HTLCs
	// being sent from the remote node.
	var remotePolicy *channeldb.ChannelEdgePolicy
	if bytes.Equal(remotePub[:], info.NodeKey1Bytes[:]) {
		remotePolicy = p1
	} else {
		remotePolicy = p2
	}

	return remotePolicy, true
}

// addHopHint creates a hop hint out of the passed channel and channel policy.
// The new hop hint is appended to the passed slice.
func addHopHint(hopHints *[]func(*zpay32.Invoice),
	channel *channeldb.OpenChannel, chanPolicy *channeldb.ChannelEdgePolicy) {

	hopHint := zpay32.HopHint{
		NodeID:      channel.IdentityPub,
		ChannelID:   channel.ShortChanID().ToUint64(),
		FeeBaseMSat: uint32(chanPolicy.FeeBaseMSat),
		FeeProportionalMillionths: uint32(
			chanPolicy.FeeProportionalMillionths,
		),
		CLTVExpiryDelta: chanPolicy.TimeLockDelta,
	}
	*hopHints = append(
		*hopHints, zpay32.RouteHint([]zpay32.HopHint{hopHint}),
	)
}

// selectHopHints will select up to numMaxHophints from the set of passed open
// channels. The set of hop hints will be returned as a slice of functional
// options that'll append the route hint to the set of all route hints.
//
// TODO(roasbeef): do proper sub-set sum max hints usually << numChans
func selectHopHints(amtMSat lnwire.MilliSatoshi, cfg *AddInvoiceConfig,
	openChannels []*channeldb.OpenChannel,
	numMaxHophints int) []func(*zpay32.Invoice) {

	// We'll add our hop hints in two passes, first we'll add all channels
	// that are eligible to be hop hints, and also have a remote balance
	// above the payment amount.
	var totalHintBandwidth lnwire.MilliSatoshi
	var hopHintPolicies policies = make(map[route.Vertex]hopHint)
	hopHintChans := make(map[wire.OutPoint]struct{})
	hopHints := make([]func(*zpay32.Invoice), 0, numMaxHophints)
	for _, channel := range openChannels {
		// If this channel can't be a hop hint, then skip it.
		edgePolicy, canBeHopHint := chanCanBeHopHint(channel, cfg)
		if edgePolicy == nil || !canBeHopHint {
			continue
		}

		// Similarly, in this first pass, we'll ignore all channels in
		// isolation can't satisfy this payment.
		if channel.LocalCommitment.RemoteBalance < amtMSat {
			continue
		}

		// Now that we know this channel is usable, add it to the
		// policies map and the indexes we'll use later.
		bandwidthDelta := hopHintPolicies.addPolicy(
			channel, edgePolicy, amtMSat,
		)

		hopHintChans[channel.FundingOutpoint] = struct{}{}
		totalHintBandwidth += bandwidthDelta
	}

	// If we have enough hop hints at this point, then we'll exit early.
	// Otherwise, we'll continue to add more that may help out mpp users.
	if len(hopHintPolicies) >= numMaxHophints {
		for _, p := range hopHintPolicies {
			addHopHint(&hopHints, p.channel, p.policy)
		}

		return hopHints
	}

	// In this second pass we'll add channels, and we'll either stop when
	// we have 20 hop hints, we've run through all the available channels,
	// or if the sum of available bandwidth in the routing hints exceeds 2x
	// the payment amount. We do 2x here to account for a margin of error
	// if some of the selected channels no longer become operable.
	hopHintFactor := lnwire.MilliSatoshi(2)
	for i := 0; i < len(openChannels); i++ {
		// If we hit either of our early termination conditions, then
		// we'll break the loop here.
		if totalHintBandwidth > amtMSat*hopHintFactor ||
			len(hopHints) >= numMaxHophints {

			break
		}

		channel := openChannels[i]

		// Skip the channel if we already selected it.
		if _, ok := hopHintChans[channel.FundingOutpoint]; ok {
			continue
		}

		// If the channel can't be a hop hint, then we'll skip it.
		// Otherwise, we'll use the policy information to populate the
		// hop hint.
		remotePolicy, canBeHopHint := chanCanBeHopHint(channel, cfg)
		if !canBeHopHint || remotePolicy == nil {
			continue
		}

		// Include the route hint in our map of policies that will be
		// used when create the hop hints that will be used for creating
		// the invoice.
		bandwidthDelta := hopHintPolicies.addPolicy(channel,
			remotePolicy, amtMSat,
		)

		// As we've just added a new hop hint, we'll accumulate it's
		// available balance now to update our tally.
		//
		// TODO(roasbeef): have a cut off based on min bandwidth?
		totalHintBandwidth += bandwidthDelta
	}

	for _, p := range hopHintPolicies {
		addHopHint(&hopHints, p.channel, p.policy)
	}

	return hopHints
}

// hopHints holds the data that will be used when adding a new
// hop hint to the payment request.
type hopHint struct {
	channel *channeldb.OpenChannel
	policy  *channeldb.ChannelEdgePolicy
}

// policies is a map of peer public keys to hop hint data for
// a channel with that peer.
type policies map[route.Vertex]hopHint

// addPolicy adds policy data to a policies map if it does not already
// contain a policy for the given channel peer. If it does, then the old
// policy will be replaced with an optimal policy to use for this connection
// given a specific amount to send. The goal is to use a policy that maximizes
// the probability of a successful forward in a non-strict forwarding context.
// The return value is the possible bandwidth increase that results after
// adding the new policy.
func (p policies) addPolicy(channel *channeldb.OpenChannel,
	newPolicy *channeldb.ChannelEdgePolicy,
	amtMSat lnwire.MilliSatoshi) lnwire.MilliSatoshi {

	// If the policies map does not already have a hopHint entry for this
	// peer, add the new hop hint details to the map.
	oldHint, ok := p[route.NewVertex(channel.IdentityPub)]
	if !ok {
		p[route.NewVertex(channel.IdentityPub)] = hopHint{
			channel: channel,
			policy:  newPolicy,
		}
		return channel.LocalCommitment.RemoteBalance
	}

	bestHopHint := oldHint
	maxTimelock := oldHint.policy.TimeLockDelta

	// Use the policy that results in the highest fee for this
	// specific amount.
	if oldHint.policy.ComputeFee(amtMSat) < newPolicy.ComputeFee(amtMSat) {
		bestHopHint = hopHint{
			channel: channel,
			policy:  newPolicy,
		}
	}

	// Track the maximum time lock of the two channels that are
	// candidates for non-strict forwarding at the routing node.
	if oldHint.policy.TimeLockDelta < newPolicy.TimeLockDelta {
		maxTimelock = newPolicy.TimeLockDelta
	}

	bestHopHint.policy.TimeLockDelta = maxTimelock

	p[route.NewVertex(channel.IdentityPub)] = bestHopHint

	// Determine if the new policy's channel has a remote bandwidth that is
	// larger than the old policy's channel and return the difference if
	// there is an increase.
	oldPolicyBandwidth := oldHint.channel.LocalCommitment.RemoteBalance
	newPolicyBandwidth := bestHopHint.channel.LocalCommitment.RemoteBalance

	if newPolicyBandwidth > oldPolicyBandwidth {
		return newPolicyBandwidth - oldPolicyBandwidth
	}

	return lnwire.MilliSatoshi(0)
}
