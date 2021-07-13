package funding

import (
	"errors"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// errUnsupportedExplicitNegotiation is an error returned when explicit
	// channel commitment negotiation is attempted but either peer of the
	// channel does not support it.
	errUnsupportedExplicitNegotiation = errors.New("explicit channel " +
		"type negotiation not supported")

	// errUnsupportedCommitmentType is an error returned when a specific
	// channel commitment type is being explicitly negotiated but either
	// peer of the channel does not support it.
	errUnsupportedChannelType = errors.New("requested channel type " +
		"not supported")
)

// negotiateCommitmentType negotiates the commitment type of a newly opened
// channel. If a channelType is provided, explicit negotiation for said type
// will be attempted if the set of both local and remote features support it.
// Otherwise, implicit negotiation will be attempted.
func negotiateCommitmentType(channelType *lnwire.ChannelType,
	local, remote *lnwire.FeatureVector) (lnwallet.CommitmentType, error) {

	if channelType != nil {
		if !hasFeatures(local, remote, lnwire.ExplicitChannelTypeOptional) {
			return 0, errUnsupportedExplicitNegotiation
		}
		return explicitNegotiateCommitmentType(
			*channelType, local, remote,
		)
	}

	return implicitNegotiateCommitmentType(local, remote), nil
}

// explicitNegotiateCommitmentType attempts to explicitly negotiate for a
// specific channel type. Since the channel type is comprised of a set of even
// feature bits, we also make sure each feature is supported by both peers. An
// error is returned if either peer does not support said channel type.
func explicitNegotiateCommitmentType(channelType lnwire.ChannelType,
	local, remote *lnwire.FeatureVector) (lnwallet.CommitmentType, error) {

	// No features, use legacy commitment type.
	channelFeatures := lnwire.RawFeatureVector(channelType)
	if channelFeatures.OnlyContains() {
		return lnwallet.CommitmentTypeLegacy, nil
	}

	// Anchors zero fee + static remote key features only.
	if channelFeatures.OnlyContains(
		lnwire.AnchorsZeroFeeHtlcTxRequired,
		lnwire.StaticRemoteKeyRequired,
	) {
		if !hasFeatures(
			local, remote,
			lnwire.AnchorsZeroFeeHtlcTxOptional,
			lnwire.StaticRemoteKeyOptional,
		) {
			return 0, errUnsupportedChannelType
		}
		return lnwallet.CommitmentTypeAnchorsZeroFeeHtlcTx, nil
	}

	// Static remote key feature only.
	if channelFeatures.OnlyContains(lnwire.StaticRemoteKeyRequired) {
		if !hasFeatures(local, remote, lnwire.StaticRemoteKeyOptional) {
			return 0, errUnsupportedChannelType
		}
		return lnwallet.CommitmentTypeTweakless, nil
	}

	return 0, errUnsupportedChannelType
}

// implicitNegotiateCommitmentType negotiates the commitment type of a channel
// implicitly by choosing the latest type supported by the local and remote
// fetures.
func implicitNegotiateCommitmentType(local,
	remote *lnwire.FeatureVector) lnwallet.CommitmentType {

	// If both peers are signalling support for anchor commitments with
	// zero-fee HTLC transactions, we'll use this type.
	if hasFeatures(local, remote, lnwire.AnchorsZeroFeeHtlcTxOptional) {
		return lnwallet.CommitmentTypeAnchorsZeroFeeHtlcTx
	}

	// Since we don't want to support the "legacy" anchor type, we will fall
	// back to static remote key if the nodes don't support the zero fee
	// HTLC tx anchor type.
	//
	// If both nodes are signaling the proper feature bit for tweakless
	// commitments, we'll use that.
	if hasFeatures(local, remote, lnwire.StaticRemoteKeyOptional) {
		return lnwallet.CommitmentTypeTweakless
	}

	// Otherwise we'll fall back to the legacy type.
	return lnwallet.CommitmentTypeLegacy
}

// hasFeatures determines whether a set of features is supported by both the set
// of local and remote features.
func hasFeatures(local, remote *lnwire.FeatureVector,
	features ...lnwire.FeatureBit) bool {

	for _, feature := range features {
		if !local.HasFeature(feature) || !remote.HasFeature(feature) {
			return false
		}
	}
	return true
}
