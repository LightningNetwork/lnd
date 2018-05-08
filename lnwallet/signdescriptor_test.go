package lnwallet

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lightningnetwork/lnd/keychain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
)

func TestSignDescriptorSerialization(t *testing.T) {
	keys := [][]byte{
		{0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
			0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
			0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
			0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
			0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
			0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
			0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
			0xb4, 0x12, 0xa3,
		},
		{0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
			0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
			0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
			0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
			0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
			0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
			0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
			0xb4, 0x12, 0xa3,
		},
	}

	signDescriptors := []SignDescriptor{
		{
			SingleTweak: []byte{
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x02, 0x02, 0x02, 0x02, 0x02,
			},
			WitnessScript: []byte{
				0x00, 0x14, 0xee, 0x91, 0x41, 0x7e, 0x85, 0x6c, 0xde,
				0x10, 0xa2, 0x91, 0x1e, 0xdc, 0xbd, 0xbd, 0x69, 0xe2,
				0xef, 0xb5, 0x71, 0x48,
			},
			Output: &wire.TxOut{
				Value: 5000000000,
				PkScript: []byte{
					0x41, // OP_DATA_65
					0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
					0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
					0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
					0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
					0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
					0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
					0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
					0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
					0xa6, // 65-byte signature
					0xac, // OP_CHECKSIG
				},
			},
			HashType: txscript.SigHashAll,
		},

		// Test serializing a SignDescriptor with a nil-valued PrivateTweak
		{
			SingleTweak: nil,
			WitnessScript: []byte{
				0x00, 0x14, 0xee, 0x91, 0x41, 0x7e, 0x85, 0x6c, 0xde,
				0x10, 0xa2, 0x91, 0x1e, 0xdc, 0xbd, 0xbd, 0x69, 0xe2,
				0xef, 0xb5, 0x71, 0x48,
			},
			Output: &wire.TxOut{
				Value: 5000000000,
				PkScript: []byte{
					0x41, // OP_DATA_65
					0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
					0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
					0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
					0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
					0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
					0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
					0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
					0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
					0xa6, // 65-byte signature
					0xac, // OP_CHECKSIG
				},
			},
			HashType: txscript.SigHashAll,
		},
	}

	for i := 0; i < len(signDescriptors); i++ {
		// Parse pubkeys for each sign descriptor.
		sd := &signDescriptors[i]
		pubkey, err := btcec.ParsePubKey(keys[i], btcec.S256())
		if err != nil {
			t.Fatalf("unable to parse pubkey: %v", err)
		}
		sd.KeyDesc = keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: 50,
				Index:  99,
			},
			PubKey: pubkey,
		}

		// Test that serialize -> deserialize yields same result as original.
		var buf bytes.Buffer
		if err := WriteSignDescriptor(&buf, sd); err != nil {
			t.Fatalf("unable to serialize sign descriptor[%v]: %v", i, sd)
		}

		desSd := &SignDescriptor{}
		if err := ReadSignDescriptor(&buf, desSd); err != nil {
			t.Fatalf("unable to deserialize sign descriptor[%v]: %v", i, sd)
		}

		if !reflect.DeepEqual(sd, desSd) {
			t.Fatalf("original and deserialized sign descriptors not equal:\n"+
				"original     : %+v\n"+
				"deserialized : %+v\n",
				sd, desSd)
		}
	}
}
