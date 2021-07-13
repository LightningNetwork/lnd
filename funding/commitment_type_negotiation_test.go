package funding

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestCommitmentTypeNegotiation tests all of the possible paths of a channel
// commitment type negotiation.
func TestCommitmentTypeNegotiation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		channelFeatures *lnwire.RawFeatureVector
		localFeatures   *lnwire.RawFeatureVector
		remoteFeatures  *lnwire.RawFeatureVector
		expectsRes      lnwallet.CommitmentType
		expectsErr      error
	}{
		{
			name: "explicit missing remote negotiation feature",
			channelFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyRequired,
				lnwire.AnchorsZeroFeeHtlcTxRequired,
			),
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
			),
			expectsErr: errUnsupportedExplicitNegotiation,
		},
		{
			name: "explicit missing remote commitment feature",
			channelFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyRequired,
				lnwire.AnchorsZeroFeeHtlcTxRequired,
			),
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			expectsErr: errUnsupportedChannelType,
		},
		{
			name: "explicit anchors",
			channelFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyRequired,
				lnwire.AnchorsZeroFeeHtlcTxRequired,
			),
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			expectsRes: lnwallet.CommitmentTypeAnchorsZeroFeeHtlcTx,
			expectsErr: nil,
		},
		{
			name: "explicit tweakless",
			channelFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyRequired,
			),
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			expectsRes: lnwallet.CommitmentTypeTweakless,
			expectsErr: nil,
		},
		{
			name:            "explicit legacy",
			channelFeatures: lnwire.NewRawFeatureVector(),
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			expectsRes: lnwallet.CommitmentTypeLegacy,
			expectsErr: nil,
		},
		{
			name:            "implicit anchors",
			channelFeatures: nil,
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
				lnwire.ExplicitChannelTypeOptional,
			),
			expectsRes: lnwallet.CommitmentTypeAnchorsZeroFeeHtlcTx,
			expectsErr: nil,
		},
		{
			name:            "implicit tweakless",
			channelFeatures: nil,
			localFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
			),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
			),
			expectsRes: lnwallet.CommitmentTypeTweakless,
			expectsErr: nil,
		},
		{
			name:            "implicit legacy",
			channelFeatures: nil,
			localFeatures:   lnwire.NewRawFeatureVector(),
			remoteFeatures: lnwire.NewRawFeatureVector(
				lnwire.StaticRemoteKeyOptional,
				lnwire.AnchorsZeroFeeHtlcTxOptional,
			),
			expectsRes: lnwallet.CommitmentTypeLegacy,
			expectsErr: nil,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		ok := t.Run(testCase.name, func(t *testing.T) {
			localFeatures := lnwire.NewFeatureVector(
				testCase.localFeatures, lnwire.Features,
			)
			remoteFeatures := lnwire.NewFeatureVector(
				testCase.remoteFeatures, lnwire.Features,
			)

			var channelType *lnwire.ChannelType
			if testCase.channelFeatures != nil {
				channelType = new(lnwire.ChannelType)
				*channelType = lnwire.ChannelType(
					*testCase.channelFeatures,
				)
			}
			localType, err := negotiateCommitmentType(
				channelType, localFeatures, remoteFeatures,
			)
			require.Equal(t, testCase.expectsErr, err)

			remoteType, err := negotiateCommitmentType(
				channelType, remoteFeatures, localFeatures,
			)
			require.Equal(t, testCase.expectsErr, err)

			if testCase.expectsErr != nil {
				return
			}

			require.Equal(t, testCase.expectsRes, localType)
			require.Equal(t, testCase.expectsRes, remoteType)
		})
		if !ok {
			return
		}
	}
}
