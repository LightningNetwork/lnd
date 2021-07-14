package wtdb

import (
	"encoding/binary"
	"errors"

	"github.com/lightningnetwork/lnd/kvdb"
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

// isFirstInit returns true if the given database has not yet been initialized,
// e.g. no metadata bucket is present yet.
func isFirstInit(db kvdb.Backend) (bool, error) {
	var metadataExists bool
	err := kvdb.View(db, func(tx kvdb.RTx) error {
		metadataExists = tx.ReadBucket(metadataBkt) != nil
		return nil
	}, func() {
		metadataExists = false
	})
	if err != nil {
		return false, err
	}

	return !metadataExists, nil
}
