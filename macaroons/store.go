package macaroons

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/boltdb/bolt"
)

const (
	// RootKeyLen is the length of a root key.
	RootKeyLen = 32
	// RootKeyIDLen is the length of a root key ID.
	RootKeyIDLen = 4
)

var (
	// rootKeyBucketName is the name of the root key store bucket.
	rootKeyBucketName = []byte("macrootkeys")

	// macaroonBucketName is the name of the macaroon store bucket.
	macaroonBucketName = []byte("macaroons")
)

// RootKeyStorage implements the bakery.RootKeyStorage interface.
type RootKeyStorage struct {
	*bolt.DB
}

// NewRootKeyStorage creates a RootKeyStorage instance.
// TODO(aakselrod): Add support for encryption of data with passphrase.
func NewRootKeyStorage(db *bolt.DB) (*RootKeyStorage, error) {
	// If the store's bucket doesn't exist, create it.
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(rootKeyBucketName)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Return the DB wrapped in a RootKeyStorage object.
	return &RootKeyStorage{db}, nil
}

// Get implements the Get method for the bakery.RootKeyStorage interface.
func (r *RootKeyStorage) Get(id string) ([]byte, error) {
	var rootKey []byte
	err := r.View(func(tx *bolt.Tx) error {
		idBytes, err := hex.DecodeString(id)
		if err != nil {
			return fmt.Errorf("unable to decode root key ID %s", id)
		}
		dbKey := tx.Bucket(rootKeyBucketName).Get(idBytes)
		if len(dbKey) == 0 {
			return fmt.Errorf("root key with id %s doesn't exist",
				id)
		}

		rootKey = make([]byte, len(dbKey))
		copy(rootKey[:], dbKey)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return rootKey, nil
}

// RootKey implements the RootKey method for the bakery.RootKeyStorage
// interface.
func (r *RootKeyStorage) RootKey() ([]byte, string, error) {
	var rootKey, id []byte
	err := r.Update(func(tx *bolt.Tx) error {
		// Create a RootKeyLen-byte root key.
		rootKey = make([]byte, RootKeyLen)
		if _, err := io.ReadFull(rand.Reader, rootKey[:]); err != nil {
			return err
		}
		id = make([]byte, RootKeyIDLen)
		if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
			return err
		}
		ns := tx.Bucket(rootKeyBucketName)
		return ns.Put(id, rootKey)
	})
	if err != nil {
		return nil, "", err
	}

	return rootKey, hex.EncodeToString(id), nil
}

// Storage implements the bakery.Storage interface.
type Storage struct {
	*bolt.DB
}

// NewStorage creates a Storage instance.
//
// TODO(aakselrod): Add support for encryption of data with passphrase.
func NewStorage(db *bolt.DB) (*Storage, error) {
	// If the store's bucket doesn't exist, create it.
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(macaroonBucketName)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Return the DB wrapped in a Storage object.
	return &Storage{db}, nil
}

// Put implements the Put method for the bakery.Storage interface.
func (s *Storage) Put(location string, item string) error {
	return s.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(macaroonBucketName).Put([]byte(location),
			[]byte(item))
	})
}

// Get implements the Get method for the bakery.Storage interface.
func (s *Storage) Get(location string) (string, error) {
	var item []byte
	err := s.View(func(tx *bolt.Tx) error {
		itemBytes := tx.Bucket(macaroonBucketName).Get([]byte(location))
		if len(itemBytes) == 0 {
			return fmt.Errorf("couldn't get item for location %s",
				location)
		}

		item = make([]byte, len(itemBytes))
		copy(item, itemBytes)
		return nil
	})
	if err != nil {
		return "", err
	}

	return string(item), nil
}

// Del implements the Del method for the bakery.Storage interface.
func (s *Storage) Del(location string) error {
	return s.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(macaroonBucketName).Delete([]byte(location))
	})
}
