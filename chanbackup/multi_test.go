package chanbackup

import (
	"bytes"
	"net"
	"testing"

	"github.com/lightningnetwork/lnd/lnencrypt"
	"github.com/lightningnetwork/lnd/lntest/mock"
)

// TestMultiPackUnpack...
func TestMultiPackUnpack(t *testing.T) {
	t.Parallel()

	var multi Multi
	numSingles := 10
	originalSingles := make([]Single, 0, numSingles)
	for i := 0; i < numSingles; i++ {
		channel, err := genRandomOpenChannelShell()
		if err != nil {
			t.Fatalf("unable to gen channel: %v", err)
		}

		single := NewSingle(channel, []net.Addr{addr1, addr2})

		originalSingles = append(originalSingles, single)
		multi.StaticBackups = append(multi.StaticBackups, single)
	}

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	versionTestCases := []struct {
		// version is the pack/unpack version that we should use to
		// decode/encode the final SCB.
		version MultiBackupVersion

		// valid tests us if this test case should pass or not.
		valid bool
	}{
		// The default version, should pack/unpack with no problem.
		{
			version: DefaultSingleVersion,
			valid:   true,
		},

		// A non-default version, atm this should result in a failure.
		{
			version: 99,
			valid:   false,
		},
	}
	for i, versionCase := range versionTestCases {
		multi.Version = versionCase.version

		var b bytes.Buffer
		err := multi.PackToWriter(&b, keyRing)
		switch {
		// If this is a valid test case, and we failed, then we'll
		// return an error.
		case err != nil && versionCase.valid:
			t.Fatalf("#%v, unable to pack multi: %v", i, err)

		// If this is an invalid test case, and we passed it, then
		// we'll return an error.
		case err == nil && !versionCase.valid:
			t.Fatalf("#%v got nil error for invalid pack: %v",
				i, err)
		}

		// If this is a valid test case, then we'll continue to ensure
		// we can unpack it, and also that if we mutate the packed
		// version, then we trigger an error.
		if versionCase.valid {
			var unpackedMulti Multi
			err = unpackedMulti.UnpackFromReader(&b, keyRing)
			if err != nil {
				t.Fatalf("#%v unable to unpack multi: %v",
					i, err)
			}

			// First, we'll ensure that the unpacked version of the
			// packed multi is the same as the original set.
			if len(originalSingles) !=
				len(unpackedMulti.StaticBackups) {
				t.Fatalf("expected %v singles, got %v",
					len(originalSingles),
					len(unpackedMulti.StaticBackups))
			}
			for i := 0; i < numSingles; i++ {
				assertSingleEqual(
					t, originalSingles[i],
					unpackedMulti.StaticBackups[i],
				)
			}

			// Next, we'll make a fake packed multi, it'll have an
			// unknown version relative to what's implemented atm.
			var fakePackedMulti bytes.Buffer
			fakeRawMulti := bytes.NewBuffer(
				bytes.Repeat([]byte{99}, 20),
			)
			err := lnencrypt.EncryptPayloadToWriter(
				*fakeRawMulti, &fakePackedMulti, keyRing,
			)
			if err != nil {
				t.Fatalf("unable to pack fake multi; %v", err)
			}

			// We should reject this fake multi as it contains an
			// unknown version.
			err = unpackedMulti.UnpackFromReader(
				&fakePackedMulti, keyRing,
			)
			if err == nil {
				t.Fatalf("#%v unpack with unknown version "+
					"should have failed", i)
			}
		}
	}
}

// TestPackedMultiUnpack tests that we're able to properly unpack a typed
// packed multi.
func TestPackedMultiUnpack(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}
	// First, we'll make a new unpacked multi with a random channel.
	testChannel, err := genRandomOpenChannelShell()
	if err != nil {
		t.Fatalf("unable to gen random channel: %v", err)
	}
	var multi Multi
	multi.StaticBackups = append(
		multi.StaticBackups, NewSingle(testChannel, nil),
	)

	// Now that we have our multi, we'll pack it into a new buffer.
	var b bytes.Buffer
	if err := multi.PackToWriter(&b, keyRing); err != nil {
		t.Fatalf("unable to pack multi: %v", err)
	}

	// We should be able to properly unpack this typed packed multi.
	packedMulti := PackedMulti(b.Bytes())
	unpackedMulti, err := packedMulti.Unpack(keyRing)
	if err != nil {
		t.Fatalf("unable to unpack multi: %v", err)
	}

	// Finally, the versions should match, and the unpacked singles also
	// identical.
	if multi.Version != unpackedMulti.Version {
		t.Fatalf("version mismatch: expected %v got %v",
			multi.Version, unpackedMulti.Version)
	}
	assertSingleEqual(
		t, multi.StaticBackups[0], unpackedMulti.StaticBackups[0],
	)
}
