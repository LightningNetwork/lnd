package lnwire

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

type unsortedSidTest struct {
	name    string
	encType ShortChanIDEncoding
	sids    []ShortChannelID
}

var (
	unsortedSids = []ShortChannelID{
		NewShortChanIDFromInt(4),
		NewShortChanIDFromInt(3),
	}

	duplicateSids = []ShortChannelID{
		NewShortChanIDFromInt(3),
		NewShortChanIDFromInt(3),
	}

	unsortedSidTests = []unsortedSidTest{
		{
			name:    "plain unsorted",
			encType: EncodingSortedPlain,
			sids:    unsortedSids,
		},
		{
			name:    "plain duplicate",
			encType: EncodingSortedPlain,
			sids:    duplicateSids,
		},
		{
			name:    "zlib unsorted",
			encType: EncodingSortedZlib,
			sids:    unsortedSids,
		},
		{
			name:    "zlib duplicate",
			encType: EncodingSortedZlib,
			sids:    duplicateSids,
		},
	}
)

// TestQueryShortChanIDsUnsorted tests that decoding a QueryShortChanID request
// that contains duplicate or unsorted ids returns an ErrUnsortedSIDs failure.
func TestQueryShortChanIDsUnsorted(t *testing.T) {
	for _, test := range unsortedSidTests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			req := &QueryShortChanIDs{
				EncodingType: test.encType,
				ShortChanIDs: test.sids,
				noSort:       true,
			}

			var b bytes.Buffer
			err := req.Encode(&b, 0)
			if err != nil {
				t.Fatalf("unable to encode req: %v", err)
			}

			var req2 QueryShortChanIDs
			err = req2.Decode(bytes.NewReader(b.Bytes()), 0)
			if _, ok := err.(ErrUnsortedSIDs); !ok {
				t.Fatalf("expected ErrUnsortedSIDs, got: %T",
					err)
			}
		})
	}
}

func TestQueryShortChanIDsEmpty(t *testing.T) {
	emptyChannelsTests := []struct {
		name     string
		encType  ShortChanIDEncoding
		expected string
	}{
		{
			name:     "plain",
			encType:  EncodingSortedPlain,
			expected: "0000000000000000000000000000000000000000000000000000000000000000000100",
		},
		{
			name:     "zlib",
			encType:  EncodingSortedZlib,
			expected: "0000000000000000000000000000000000000000000000000000000000000000000101",
		},
	}

	for _, test := range emptyChannelsTests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			req := QueryShortChanIDs{
				EncodingType: test.encType,
				ShortChanIDs: nil,
			}

			var b bytes.Buffer
			err := req.Encode(&b, 0)
			if err != nil {
				t.Fatalf("unable to encode req: %v", err)
			}
			if hex.EncodeToString(b.Bytes()) != test.expected {
				t.Fatalf("results don't match: expected %v got %v",
					test.expected, hex.EncodeToString(b.Bytes()))
			}

			var req2 QueryShortChanIDs
			err = req2.Decode(bytes.NewReader(b.Bytes()), 0)
			if err != nil {
				t.Fatalf("unable to decode req: %v", err)
			}
			if !reflect.DeepEqual(req, req2) {
				t.Fatalf("requests don't match: expected %v got %v",
					spew.Sdump(req), spew.Sdump(req2))
			}
		})
	}
}
