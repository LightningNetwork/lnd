package chainfee

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcutil"
)

type mockSparseConfFeeSource struct {
	url  string
	fees map[uint32]uint32
}

func (e mockSparseConfFeeSource) GenQueryURL() string {
	return e.url
}

func (e mockSparseConfFeeSource) ParseResponse(r io.Reader) (map[uint32]uint32, error) {
	return e.fees, nil
}

// TestFeeRateTypes checks that converting fee rates between the
// different types that represent fee rates and calculating fees
// work as expected.
func TestFeeRateTypes(t *testing.T) {
	t.Parallel()

	// We'll be calculating the transaction fees for the given measurements
	// using different fee rates and expecting them to match.
	const vsize = 300
	const weight = vsize * 4

	// Test the conversion from sat/kw to sat/kb.
	for feePerKw := SatPerKWeight(250); feePerKw < 10000; feePerKw += 50 {
		feePerKB := feePerKw.FeePerKVByte()
		if feePerKB != SatPerKVByte(feePerKw*4) {
			t.Fatalf("expected %d sat/kb, got %d sat/kb when "+
				"converting from %d sat/kw", feePerKw*4,
				feePerKB, feePerKw)
		}

		// The resulting transaction fee should be the same when using
		// both rates.
		expectedFee := btcutil.Amount(feePerKw * weight / 1000)
		fee1 := feePerKw.FeeForWeight(weight)
		if fee1 != expectedFee {
			t.Fatalf("expected fee of %d sats, got %d sats",
				expectedFee, fee1)
		}
		fee2 := feePerKB.FeeForVSize(vsize)
		if fee2 != expectedFee {
			t.Fatalf("expected fee of %d sats, got %d sats",
				expectedFee, fee2)
		}
	}

	// Test the conversion from sat/kb to sat/kw.
	for feePerKB := SatPerKVByte(1000); feePerKB < 40000; feePerKB += 1000 {
		feePerKw := feePerKB.FeePerKWeight()
		if feePerKw != SatPerKWeight(feePerKB/4) {
			t.Fatalf("expected %d sat/kw, got %d sat/kw when "+
				"converting from %d sat/kb", feePerKB/4,
				feePerKw, feePerKB)
		}

		// The resulting transaction fee should be the same when using
		// both rates.
		expectedFee := btcutil.Amount(feePerKB * vsize / 1000)
		fee1 := feePerKB.FeeForVSize(vsize)
		if fee1 != expectedFee {
			t.Fatalf("expected fee of %d sats, got %d sats",
				expectedFee, fee1)
		}
		fee2 := feePerKw.FeeForWeight(weight)
		if fee2 != expectedFee {
			t.Fatalf("expected fee of %d sats, got %d sats",
				expectedFee, fee2)
		}
	}
}

// TestStaticFeeEstimator checks that the StaticFeeEstimator returns the
// expected fee rate.
func TestStaticFeeEstimator(t *testing.T) {
	t.Parallel()

	const feePerKw = FeePerKwFloor

	feeEstimator := NewStaticEstimator(feePerKw, 0)
	if err := feeEstimator.Start(); err != nil {
		t.Fatalf("unable to start fee estimator: %v", err)
	}
	defer feeEstimator.Stop()

	feeRate, err := feeEstimator.EstimateFeePerKW(6)
	if err != nil {
		t.Fatalf("unable to get fee rate: %v", err)
	}

	if feeRate != feePerKw {
		t.Fatalf("expected fee rate %v, got %v", feePerKw, feeRate)
	}
}

// TestSparseConfFeeSource checks that SparseConfFeeSource generates URLs and
// parses API responses as expected.
func TestSparseConfFeeSource(t *testing.T) {
	t.Parallel()

	// Test that GenQueryURL returns the URL as is.
	url := "test"
	feeSource := SparseConfFeeSource{URL: url}
	queryURL := feeSource.GenQueryURL()
	if queryURL != url {
		t.Fatalf("expected query URL of %v, got %v", url, queryURL)
	}

	// Test parsing a properly formatted JSON API response.
	// First, create the response as a bytes.Reader.
	testFees := map[uint32]uint32{
		1: 12345,
		2: 42,
		3: 54321,
	}
	testJSON := map[string]map[uint32]uint32{"fee_by_block_target": testFees}
	jsonResp, err := json.Marshal(testJSON)
	if err != nil {
		t.Fatalf("unable to marshal JSON API response: %v", err)
	}
	reader := bytes.NewReader(jsonResp)

	// Finally, ensure the expected map is returned without error.
	fees, err := feeSource.ParseResponse(reader)
	if err != nil {
		t.Fatalf("unable to parse API response: %v", err)
	}
	if !reflect.DeepEqual(fees, testFees) {
		t.Fatalf("expected %v, got %v", testFees, fees)
	}

	// Test parsing an improperly formatted JSON API response.
	badFees := map[string]uint32{"hi": 12345, "hello": 42, "satoshi": 54321}
	badJSON := map[string]map[string]uint32{"fee_by_block_target": badFees}
	jsonResp, err = json.Marshal(badJSON)
	if err != nil {
		t.Fatalf("unable to marshal JSON API response: %v", err)
	}
	reader = bytes.NewReader(jsonResp)

	// Finally, ensure the improperly formatted fees error.
	_, err = feeSource.ParseResponse(reader)
	if err == nil {
		t.Fatalf("expected ParseResponse to fail")
	}
}

// TestWebAPIFeeEstimator checks that the WebAPIFeeEstimator returns fee rates
// as expected.
func TestWebAPIFeeEstimator(t *testing.T) {
	t.Parallel()

	feeFloor := uint32(FeePerKwFloor.FeePerKVByte())
	testCases := []struct {
		name   string
		target uint32
		apiEst uint32
		est    uint32
		err    string
	}{
		{"target_below_min", 0, 12345, 12345, "too low, minimum"},
		{"target_w_too-low_fee", 10, 42, feeFloor, ""},
		{"API-omitted_target", 2, 0, 0, "web API does not include"},
		{"valid_target", 20, 54321, 54321, ""},
		{"valid_target_extrapolated_fee", 25, 0, 54321, ""},
	}

	// Construct mock fee source for the Estimator to pull fees from.
	testFees := make(map[uint32]uint32)
	for _, tc := range testCases {
		if tc.apiEst != 0 {
			testFees[tc.target] = tc.apiEst
		}
	}

	feeSource := mockSparseConfFeeSource{
		url:  "https://www.github.com",
		fees: testFees,
	}

	estimator := NewWebAPIEstimator(feeSource, false)

	// Test that requesting a fee when no fees have been cached fails.
	_, err := estimator.EstimateFeePerKW(5)
	if err == nil ||
		!strings.Contains(err.Error(), "web API does not include") {

		t.Fatalf("expected fee estimation to fail, instead got: %v", err)
	}

	if err := estimator.Start(); err != nil {
		t.Fatalf("unable to start fee estimator, got: %v", err)
	}
	defer estimator.Stop()

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			est, err := estimator.EstimateFeePerKW(tc.target)
			if tc.err != "" {
				if err == nil ||
					!strings.Contains(err.Error(), tc.err) {

					t.Fatalf("expected fee estimation to "+
						"fail, instead got: %v", err)
				}
			} else {
				exp := SatPerKVByte(tc.est).FeePerKWeight()
				if err != nil {
					t.Fatalf("unable to estimate fee for "+
						"%v block target, got: %v",
						tc.target, err)
				}
				if est != exp {
					t.Fatalf("expected fee estimate of "+
						"%v, got %v", exp, est)
				}
			}
		})
	}
}

type mockChainBackend struct {
	minRelayFee SatPerKWeight
	callCount   int
}

func (m *mockChainBackend) fetchFee() (SatPerKWeight, error) {
	m.callCount++
	return m.minRelayFee, nil
}

// TestMinRelayFeeManager tests that the minRelayFeeManager works as expected.
func TestMinRelayFeeManager(t *testing.T) {
	chainBackend := &mockChainBackend{
		minRelayFee: SatPerKWeight(1000),
	}

	feeManager := &minRelayFeeManager{
		minUpdateInterval: 200 * time.Millisecond,
		fetchNewFee:       chainBackend.fetchFee,
	}

	// Init the min relay fee manager. This should call the chain backend
	// once.
	err := feeManager.initMinRelayFee()
	require.NoError(t, err)
	require.Equal(t, 1, chainBackend.callCount)

	// If the fee is requested again, the stored fee should be returned
	// and the chain backend should not be queried.
	chainBackend.minRelayFee = SatPerKWeight(2000)
	minRelayFee := feeManager.getFee()
	require.Equal(t, minRelayFee, SatPerKWeight(1000))
	require.Equal(t, 1, chainBackend.callCount)

	time.Sleep(500 * time.Millisecond)

	// If the fee is queried again after the backoff period has passed
	// then the chain backend should be queried again for the min relay
	// fee.
	minRelayFee = feeManager.getFee()
	require.Equal(t, minRelayFee, SatPerKWeight(2000))
	require.Equal(t, 2, chainBackend.callCount)
}
