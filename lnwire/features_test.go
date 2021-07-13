package lnwire

import (
	"bytes"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

var testFeatureNames = map[FeatureBit]string{
	0: "feature1",
	3: "feature2",
	4: "feature3",
	5: "feature3",
}

func TestFeatureVectorSetUnset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bits             []FeatureBit
		expectedFeatures []bool
	}{
		// No features are enabled if no bits are set.
		{
			bits:             nil,
			expectedFeatures: []bool{false, false, false, false, false, false, false, false},
		},
		// Test setting an even bit for an even-only bit feature. The
		// corresponding odd bit should not be seen as set.
		{
			bits:             []FeatureBit{0},
			expectedFeatures: []bool{true, false, false, false, false, false, false, false},
		},
		// Test setting an odd bit for an even-only bit feature. The
		// corresponding even bit should not be seen as set.
		{
			bits:             []FeatureBit{1},
			expectedFeatures: []bool{false, true, false, false, false, false, false, false},
		},
		// Test setting an even bit for an odd-only bit feature. The bit should
		// be seen as set and the odd bit should not.
		{
			bits:             []FeatureBit{2},
			expectedFeatures: []bool{false, false, true, false, false, false, false, false},
		},
		// Test setting an odd bit for an odd-only bit feature. The bit should
		// be seen as set and the even bit should not.
		{
			bits:             []FeatureBit{3},
			expectedFeatures: []bool{false, false, false, true, false, false, false, false},
		},
		// Test setting an even bit for even-odd pair feature. Both bits in the
		// pair should be seen as set.
		{
			bits:             []FeatureBit{4},
			expectedFeatures: []bool{false, false, false, false, true, true, false, false},
		},
		// Test setting an odd bit for even-odd pair feature. Both bits in the
		// pair should be seen as set.
		{
			bits:             []FeatureBit{5},
			expectedFeatures: []bool{false, false, false, false, true, true, false, false},
		},
		// Test setting an even bit for an unknown feature. The bit should be
		// seen as set and the odd bit should not.
		{
			bits:             []FeatureBit{6},
			expectedFeatures: []bool{false, false, false, false, false, false, true, false},
		},
		// Test setting an odd bit for an unknown feature. The bit should be
		// seen as set and the odd bit should not.
		{
			bits:             []FeatureBit{7},
			expectedFeatures: []bool{false, false, false, false, false, false, false, true},
		},
	}

	fv := NewFeatureVector(nil, testFeatureNames)
	for i, test := range tests {
		for _, bit := range test.bits {
			fv.Set(bit)
		}

		for j, expectedSet := range test.expectedFeatures {
			if fv.HasFeature(FeatureBit(j)) != expectedSet {
				t.Errorf("Expectation failed in case %d, bit %d", i, j)
				break
			}

		}

		for _, bit := range test.bits {
			fv.Unset(bit)
		}
	}
}

// TestFeatureVectorRequiresFeature tests that if a feature vector only
// includes a required feature bit (it's even), then the RequiresFeature method
// will return true for both that bit as well as it's optional counter party.
func TestFeatureVectorRequiresFeature(t *testing.T) {
	t.Parallel()

	// Create a new feature vector with the features above, and set only
	// the set of required bits. These will be all the even features
	// referenced above.
	fv := NewFeatureVector(nil, testFeatureNames)
	fv.Set(0)
	fv.Set(4)

	// Next we'll query for those exact bits, these should show up as being
	// required.
	require.True(t, fv.RequiresFeature(0))
	require.True(t, fv.RequiresFeature(4))

	// If we query for the odd (optional) counter party to each of the
	// features, the method should still return that the backing feature
	// vector requires the feature to be set.
	require.True(t, fv.RequiresFeature(1))
	require.True(t, fv.RequiresFeature(5))
}

func TestFeatureVectorEncodeDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bits            []FeatureBit
		expectedEncoded []byte
	}{
		{
			bits:            nil,
			expectedEncoded: []byte{0x00, 0x00},
		},
		{
			bits:            []FeatureBit{2, 3, 7},
			expectedEncoded: []byte{0x00, 0x01, 0x8C},
		},
		{
			bits:            []FeatureBit{2, 3, 8},
			expectedEncoded: []byte{0x00, 0x02, 0x01, 0x0C},
		},
	}

	for i, test := range tests {
		fv := NewRawFeatureVector(test.bits...)

		// Test that Encode produces the correct serialization.
		buffer := new(bytes.Buffer)
		err := fv.Encode(buffer)
		if err != nil {
			t.Errorf("Failed to encode feature vector in case %d: %v", i, err)
			continue
		}

		encoded := buffer.Bytes()
		if !bytes.Equal(encoded, test.expectedEncoded) {
			t.Errorf("Wrong encoding in case %d: got %v, expected %v",
				i, encoded, test.expectedEncoded)
			continue
		}

		// Test that decoding then re-encoding produces the same result.
		fv2 := NewRawFeatureVector()
		err = fv2.Decode(bytes.NewReader(encoded))
		if err != nil {
			t.Errorf("Failed to decode feature vector in case %d: %v", i, err)
			continue
		}

		buffer2 := new(bytes.Buffer)
		err = fv2.Encode(buffer2)
		if err != nil {
			t.Errorf("Failed to re-encode feature vector in case %d: %v",
				i, err)
			continue
		}

		reencoded := buffer2.Bytes()
		if !bytes.Equal(reencoded, test.expectedEncoded) {
			t.Errorf("Wrong re-encoding in case %d: got %v, expected %v",
				i, reencoded, test.expectedEncoded)
		}
	}
}

func TestFeatureVectorUnknownFeatures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bits            []FeatureBit
		expectedUnknown []FeatureBit
	}{
		{
			bits:            nil,
			expectedUnknown: nil,
		},
		// Since bits {0, 3, 4, 5} are known, and only even bits are considered
		// required (according to the "it's OK to be odd rule"), that leaves
		// {2, 6} as both unknown and required.
		{
			bits:            []FeatureBit{0, 1, 2, 3, 4, 5, 6, 7},
			expectedUnknown: []FeatureBit{2, 6},
		},
	}

	for i, test := range tests {
		rawVector := NewRawFeatureVector(test.bits...)
		fv := NewFeatureVector(rawVector, testFeatureNames)

		unknown := fv.UnknownRequiredFeatures()

		// Sort to make comparison independent of order
		sort.Slice(unknown, func(i, j int) bool {
			return unknown[i] < unknown[j]
		})
		if !reflect.DeepEqual(unknown, test.expectedUnknown) {
			t.Errorf("Wrong unknown features in case %d: got %v, expected %v",
				i, unknown, test.expectedUnknown)
		}
	}
}

func TestFeatureNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bit           FeatureBit
		expectedName  string
		expectedKnown bool
	}{
		{
			bit:           0,
			expectedName:  "feature1",
			expectedKnown: true,
		},
		{
			bit:           1,
			expectedName:  "unknown",
			expectedKnown: false,
		},
		{
			bit:           2,
			expectedName:  "unknown",
			expectedKnown: false,
		},
		{
			bit:           3,
			expectedName:  "feature2",
			expectedKnown: true,
		},
		{
			bit:           4,
			expectedName:  "feature3",
			expectedKnown: true,
		},
		{
			bit:           5,
			expectedName:  "feature3",
			expectedKnown: true,
		},
		{
			bit:           6,
			expectedName:  "unknown",
			expectedKnown: false,
		},
		{
			bit:           7,
			expectedName:  "unknown",
			expectedKnown: false,
		},
	}

	fv := NewFeatureVector(nil, testFeatureNames)
	for _, test := range tests {
		name := fv.Name(test.bit)
		if name != test.expectedName {
			t.Errorf("Name for feature bit %d is incorrect: "+
				"expected %s, got %s", test.bit, name, test.expectedName)
		}

		known := fv.IsKnown(test.bit)
		if known != test.expectedKnown {
			t.Errorf("IsKnown for feature bit %d is incorrect: "+
				"expected %v, got %v", test.bit, known, test.expectedKnown)
		}
	}
}

// TestIsRequired asserts that feature bits properly return their IsRequired
// status. We require that even features be required and odd features be
// optional.
func TestIsRequired(t *testing.T) {
	optional := FeatureBit(1)
	if optional.IsRequired() {
		t.Fatalf("optional feature should not be required")
	}

	required := FeatureBit(0)
	if !required.IsRequired() {
		t.Fatalf("required feature should be required")
	}
}

// TestFeatures asserts that the Features() method on a FeatureVector properly
// returns the set of feature bits it stores internally.
func TestFeatures(t *testing.T) {
	tests := []struct {
		name string
		exp  map[FeatureBit]struct{}
	}{
		{
			name: "empty",
			exp:  map[FeatureBit]struct{}{},
		},
		{
			name: "one",
			exp: map[FeatureBit]struct{}{
				5: {},
			},
		},
		{
			name: "several",
			exp: map[FeatureBit]struct{}{
				0:     {},
				5:     {},
				23948: {},
			},
		},
	}

	toRawFV := func(set map[FeatureBit]struct{}) *RawFeatureVector {
		var bits []FeatureBit
		for bit := range set {
			bits = append(bits, bit)
		}
		return NewRawFeatureVector(bits...)
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fv := NewFeatureVector(
				toRawFV(test.exp), Features,
			)

			if !reflect.DeepEqual(fv.Features(), test.exp) {
				t.Fatalf("feature mismatch, want: %v, got: %v",
					test.exp, fv.Features())
			}
		})
	}
}

func TestRawFeatureVectorOnlyContains(t *testing.T) {
	t.Parallel()

	features := []FeatureBit{
		StaticRemoteKeyOptional,
		AnchorsZeroFeeHtlcTxOptional,
		ExplicitChannelTypeRequired,
	}
	fv := NewRawFeatureVector(features...)
	require.True(t, fv.OnlyContains(features...))
	require.False(t, fv.OnlyContains(features[:1]...))
}

func TestEqualRawFeatureVectors(t *testing.T) {
	t.Parallel()

	a := NewRawFeatureVector(
		StaticRemoteKeyOptional,
		AnchorsZeroFeeHtlcTxOptional,
		ExplicitChannelTypeRequired,
	)
	b := a.Clone()
	require.True(t, a.Equals(b))

	b.Unset(ExplicitChannelTypeRequired)
	require.False(t, a.Equals(b))

	b.Set(ExplicitChannelTypeOptional)
	require.False(t, a.Equals(b))
}
