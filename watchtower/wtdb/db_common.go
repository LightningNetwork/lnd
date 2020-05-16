package wtdb

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"go.etcd.io/bbolt"
)

const (
	// dbFilePermission requests read+write access to the db file.
	dbFilePermission = 0600
)

var (
	// metadataBkt stores all the meta information concerning the state of
	// the database.
	metadataBkt = []byte("metadata-bucket")

	// dbVersionKey is a static key used to retrieve the database version
	// number from the metadataBkt.
	dbVersionKey = []byte("version")

	// ErrUninitializedDB signals that top-level buckets for the database
	// have not been initialized.
	ErrUninitializedDB = errors.New("db not initialized")

	// ErrNoDBVersion signals that the database contains no version info.
	ErrNoDBVersion = errors.New("db has no version")

	// byteOrder is the default endianness used when serializing integers.
	byteOrder = binary.BigEndian
)

// fileExists returns true if the file exists, and false otherwise.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// createDBIfNotExist opens the boltdb database at dbPath/name, creating one if
// one doesn't exist. The boolean returned indicates if the database did not
// exist before, or if it has been created but no version metadata exists within
// it.
func createDBIfNotExist(dbPath, name string) (kvdb.Backend, bool, error) {
	path := filepath.Join(dbPath, name)

	// If the database file doesn't exist, this indicates we much initialize
	// a fresh database with the latest version.
	firstInit := !fileExists(path)
	if firstInit {
		// Ensure all parent directories are initialized.
		err := os.MkdirAll(dbPath, 0700)
		if err != nil {
			return nil, false, err
		}
	}

	// Specify bbolt freelist options to reduce heap pressure in case the
	// freelist grows to be very large.
	bboltOpts := &bbolt.Options{
		NoFreelistSync: true,
	}
	bdb, err := kvdb.Create(kvdb.BoltBackendName, path, bboltOpts)
	if err != nil {
		return nil, false, err
	}

	// If the file existed previously, we'll now check to see that the
	// metadata bucket is properly initialized. It could be the case that
	// the database was created, but we failed to actually populate any
	// metadata. If the metadata bucket does not actually exist, we'll
	// set firstInit to true so that we can treat is initialize the bucket.
	if !firstInit {
		var metadataExists bool
		err = kvdb.View(bdb, func(tx kvdb.ReadTx) error {
			metadataExists = tx.ReadBucket(metadataBkt) != nil
			return nil
		})
		if err != nil {
			return nil, false, err
		}

		if !metadataExists {
			firstInit = true
		}
	}

	return bdb, firstInit, nil
}
