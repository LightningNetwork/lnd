package chanbackup

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/lightningnetwork/lnd/lntest/mock"
)

func makeFakePackedMulti() (PackedMulti, error) {
	newPackedMulti := make([]byte, 50)
	if _, err := rand.Read(newPackedMulti[:]); err != nil {
		return nil, fmt.Errorf("unable to make test backup: %v", err)
	}

	return PackedMulti(newPackedMulti), nil
}

func assertBackupMatches(t *testing.T, filePath string,
	currentBackup PackedMulti) {

	t.Helper()

	packedBackup, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("unable to test file: %v", err)
	}

	if !bytes.Equal(packedBackup, currentBackup) {
		t.Fatalf("backups don't match after first swap: "+
			"expected %x got %x", packedBackup[:],
			currentBackup)
	}
}

func assertFileDeleted(t *testing.T, filePath string) {
	t.Helper()

	_, err := os.Stat(filePath)
	if err == nil {
		t.Fatalf("file %v still exists: ", filePath)
	}
}

// TestUpdateAndSwap test that we're able to properly swap out old backups on
// disk with new ones. Additionally, after a swap operation succeeds, then each
// time we should only have the main backup file on disk, as the temporary file
// has been removed.
func TestUpdateAndSwap(t *testing.T) {
	t.Parallel()

	tempTestDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("unable to make temp dir: %v", err)
	}
	defer os.Remove(tempTestDir)

	testCases := []struct {
		fileName     string
		tempFileName string

		oldTempExists bool

		valid bool
	}{
		// Main file name is blank, should fail.
		{
			fileName: "",
			valid:    false,
		},

		// Old temporary file still exists, should be removed. Only one
		// file should remain.
		{
			fileName: filepath.Join(
				tempTestDir, DefaultBackupFileName,
			),
			tempFileName: filepath.Join(
				tempTestDir, DefaultTempBackupFileName,
			),
			oldTempExists: true,
			valid:         true,
		},

		// Old temp doesn't exist, should swap out file, only a single
		// file remains.
		{
			fileName: filepath.Join(
				tempTestDir, DefaultBackupFileName,
			),
			tempFileName: filepath.Join(
				tempTestDir, DefaultTempBackupFileName,
			),
			valid: true,
		},
	}
	for i, testCase := range testCases {
		// Ensure that all created files are removed at the end of the
		// test case.
		defer os.Remove(testCase.fileName)
		defer os.Remove(testCase.tempFileName)

		backupFile := NewMultiFile(testCase.fileName)

		// To start with, we'll make a random byte slice that'll pose
		// as our packed multi backup.
		newPackedMulti, err := makeFakePackedMulti()
		if err != nil {
			t.Fatalf("unable to make test backup: %v", err)
		}

		// If the old temporary file is meant to exist, then we'll
		// create it now as an empty file.
		if testCase.oldTempExists {
			_, err := os.Create(testCase.tempFileName)
			if err != nil {
				t.Fatalf("unable to create temp file: %v", err)
			}

			// TODO(roasbeef): mock out fs calls?
		}

		// With our backup created, we'll now attempt to swap out this
		// backup, for the old one.
		err = backupFile.UpdateAndSwap(PackedMulti(newPackedMulti))
		switch {
		// If this is a valid test case, and we failed, then we'll
		// return an error.
		case err != nil && testCase.valid:
			t.Fatalf("#%v, unable to swap file: %v", i, err)

		// If this is an invalid test case, and we passed it, then
		// we'll return an error.
		case err == nil && !testCase.valid:
			t.Fatalf("#%v file swap should have failed: %v", i, err)
		}

		if !testCase.valid {
			continue
		}

		// If we read out the file on disk, then it should match
		// exactly what we wrote. The temp backup file should also be
		// gone.
		assertBackupMatches(t, testCase.fileName, newPackedMulti)
		assertFileDeleted(t, testCase.tempFileName)

		// Now that we know this is a valid test case, we'll make a new
		// packed multi to swap out this current one.
		newPackedMulti2, err := makeFakePackedMulti()
		if err != nil {
			t.Fatalf("unable to make test backup: %v", err)
		}

		// We'll then attempt to swap the old version for this new one.
		err = backupFile.UpdateAndSwap(PackedMulti(newPackedMulti2))
		if err != nil {
			t.Fatalf("unable to swap file: %v", err)
		}

		// Once again, the file written on disk should have been
		// properly swapped out with the new instance.
		assertBackupMatches(t, testCase.fileName, newPackedMulti2)

		// Additionally, we shouldn't be able to find the temp backup
		// file on disk, as it should be deleted each time.
		assertFileDeleted(t, testCase.tempFileName)
	}
}

func assertMultiEqual(t *testing.T, a, b *Multi) {

	if len(a.StaticBackups) != len(b.StaticBackups) {
		t.Fatalf("expected %v backups, got %v", len(a.StaticBackups),
			len(b.StaticBackups))
	}

	for i := 0; i < len(a.StaticBackups); i++ {
		assertSingleEqual(t, a.StaticBackups[i], b.StaticBackups[i])
	}
}

// TestExtractMulti tests that given a valid packed multi file on disk, we're
// able to read it multiple times repeatedly.
func TestExtractMulti(t *testing.T) {
	t.Parallel()

	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	// First, as prep, we'll create a single chan backup, then pack that
	// fully into a multi backup.
	channel, err := genRandomOpenChannelShell()
	if err != nil {
		t.Fatalf("unable to gen chan: %v", err)
	}

	singleBackup := NewSingle(channel, nil)

	var b bytes.Buffer
	unpackedMulti := Multi{
		StaticBackups: []Single{singleBackup},
	}
	err = unpackedMulti.PackToWriter(&b, keyRing)
	if err != nil {
		t.Fatalf("unable to pack to writer: %v", err)
	}

	packedMulti := PackedMulti(b.Bytes())

	// Finally, we'll make a new temporary file, then write out the packed
	// multi directly to to it.
	tempFile, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("unable to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(packedMulti)
	if err != nil {
		t.Fatalf("unable to write temp file: %v", err)
	}
	if err := tempFile.Sync(); err != nil {
		t.Fatalf("unable to sync temp file: %v", err)
	}

	testCases := []struct {
		fileName string
		pass     bool
	}{
		// Main file not read, file name not present.
		{
			fileName: "",
			pass:     false,
		},

		// Main file not read, file name is there, but file doesn't
		// exist.
		{
			fileName: "kek",
			pass:     false,
		},

		// Main file not read, should be able to read multiple times.
		{
			fileName: tempFile.Name(),
			pass:     true,
		},
	}
	for i, testCase := range testCases {
		// First, we'll make our backup file with the specified name.
		backupFile := NewMultiFile(testCase.fileName)

		// With our file made, we'll now attempt to read out the
		// multi-file.
		freshUnpackedMulti, err := backupFile.ExtractMulti(keyRing)
		switch {
		// If this is a valid test case, and we failed, then we'll
		// return an error.
		case err != nil && testCase.pass:
			t.Fatalf("#%v, unable to extract file: %v", i, err)

			// If this is an invalid test case, and we passed it, then
			// we'll return an error.
		case err == nil && !testCase.pass:
			t.Fatalf("#%v file extraction should have "+
				"failed: %v", i, err)
		}

		if !testCase.pass {
			continue
		}

		// We'll now ensure that the unpacked multi we read is
		// identical to the one we wrote out above.
		assertMultiEqual(t, &unpackedMulti, freshUnpackedMulti)

		// We should also be able to read the file again, as we have an
		// existing handle to it.
		freshUnpackedMulti, err = backupFile.ExtractMulti(keyRing)
		if err != nil {
			t.Fatalf("unable to unpack multi: %v", err)
		}

		assertMultiEqual(t, &unpackedMulti, freshUnpackedMulti)
	}
}
