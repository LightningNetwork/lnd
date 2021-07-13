package lnwire

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/lightningnetwork/lnd/tlv"
)

// TestExtraOpaqueDataEncodeDecode tests that we're able to encode/decode
// arbitrary payloads.
func TestExtraOpaqueDataEncodeDecode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		// emptyBytes indicates if we should try to encode empty bytes
		// or not.
		emptyBytes bool

		// inputBytes if emptyBytes is false, then we'll read in this
		// set of bytes instead.
		inputBytes []byte
	}

	// We should be able to read in an arbitrary set of bytes as an
	// ExtraOpaqueData, then encode those new bytes into a new instance.
	// The final two instances should be identical.
	scenario := func(test testCase) bool {
		var (
			extraData ExtraOpaqueData
			b         bytes.Buffer
		)

		copy(extraData[:], test.inputBytes)

		if err := extraData.Encode(&b); err != nil {
			t.Fatalf("unable to encode extra data: %v", err)
			return false
		}

		var newBytes ExtraOpaqueData
		if err := newBytes.Decode(&b); err != nil {
			t.Fatalf("unable to decode extra bytes: %v", err)
			return false
		}

		if !bytes.Equal(extraData[:], newBytes[:]) {
			t.Fatalf("expected %x, got %x", extraData,
				newBytes)
			return false
		}

		return true
	}

	// We'll make a function to generate random test data. Half of the
	// time, we'll actually feed in blank bytes.
	quickCfg := &quick.Config{
		Values: func(v []reflect.Value, r *rand.Rand) {

			var newTestCase testCase
			if r.Int31()%2 == 0 {
				newTestCase.emptyBytes = true
			}

			if !newTestCase.emptyBytes {
				numBytes := r.Int31n(1000)
				newTestCase.inputBytes = make([]byte, numBytes)

				_, err := r.Read(newTestCase.inputBytes)
				if err != nil {
					t.Fatalf("unable to gen random bytes: %v", err)
					return
				}
			}

			v[0] = reflect.ValueOf(newTestCase)
		},
	}

	if err := quick.Check(scenario, quickCfg); err != nil {
		t.Fatalf("encode+decode test failed: %v", err)
	}
}

type recordProducer struct {
	record tlv.Record
}

func (r *recordProducer) Record() tlv.Record {
	return r.record
}

// TestExtraOpaqueDataPackUnpackRecords tests that we're able to pack a set of
// tlv.Records into a stream, and unpack them on the other side to obtain the
// same set of records.
func TestExtraOpaqueDataPackUnpackRecords(t *testing.T) {
	t.Parallel()

	var (
		type1 tlv.Type = 1
		type2 tlv.Type = 2

		channelType1 uint8 = 2
		channelType2 uint8

		hop1 uint32 = 99
		hop2 uint32
	)
	testRecordsProducers := []tlv.RecordProducer{
		&recordProducer{tlv.MakePrimitiveRecord(type1, &channelType1)},
		&recordProducer{tlv.MakePrimitiveRecord(type2, &hop1)},
	}

	// Now that we have our set of sample records and types, we'll encode
	// them into the passed ExtraOpaqueData instance.
	var extraBytes ExtraOpaqueData
	if err := extraBytes.PackRecords(testRecordsProducers...); err != nil {
		t.Fatalf("unable to pack records: %v", err)
	}

	// We'll now simulate decoding these types _back_ into records on the
	// other side.
	newRecords := []tlv.RecordProducer{
		&recordProducer{tlv.MakePrimitiveRecord(type1, &channelType2)},
		&recordProducer{tlv.MakePrimitiveRecord(type2, &hop2)},
	}
	typeMap, err := extraBytes.ExtractRecords(newRecords...)
	if err != nil {
		t.Fatalf("unable to extract record: %v", err)
	}

	// We should find that the new backing values have been populated with
	// the proper value.
	switch {
	case channelType1 != channelType2:
		t.Fatalf("wrong record for channel type: expected %v, got %v",
			channelType1, channelType2)

	case hop1 != hop2:
		t.Fatalf("wrong record for hop: expected %v, got %v", hop1,
			hop2)
	}

	// Both types we created above should be found in the type map.
	if _, ok := typeMap[type1]; !ok {
		t.Fatalf("type1 not found in typeMap")
	}
	if _, ok := typeMap[type2]; !ok {
		t.Fatalf("type2 not found in typeMap")
	}
}
