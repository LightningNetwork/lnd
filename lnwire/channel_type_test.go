package lnwire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestChannelTypeEncodeDecode tests that we're able to properly encode and
// decode channel types within TLV streams.
func TestChannelTypeEncodeDecode(t *testing.T) {
	t.Parallel()

	chanType := ChannelType(*NewRawFeatureVector(
		StaticRemoteKeyRequired,
		AnchorsZeroFeeHtlcTxRequired,
	))

	var extraData ExtraOpaqueData
	require.NoError(t, extraData.PackRecords(&chanType))

	var chanType2 ChannelType
	tlvs, err := extraData.ExtractRecords(&chanType2)
	require.NoError(t, err)

	require.Contains(t, tlvs, ChannelTypeRecordType)
	require.Equal(t, chanType, chanType2)
}
