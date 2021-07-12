package banman

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// byteOrder is the preferred byte order in which we should write things
	// to disk.
	byteOrder = binary.BigEndian

	// banStoreBucket is the top level bucket of the Store that will contain
	// all relevant sub-buckets.
	banStoreBucket = []byte("ban-store")

	// banBucket is the main index in which we keep track of IP networks and
	// their absolute expiration time.
	//
	// The key is the IP network host and the value is the absolute
	// expiration time.
	banBucket = []byte("ban-index")

	// reasonBucket is an index in which we keep track of why an IP network
	// was banned.
	//
	// The key is the IP network and the value is the Reason.
	reasonBucket = []byte("reason-index")

	// ErrCorruptedStore is an error returned when we attempt to locate any
	// of the ban-related buckets in the database but are unable to.
	ErrCorruptedStore = errors.New("corrupted ban store")

	// ErrUnsupportedIP is an error returned when we attempt to parse an
	// unsupported IP address type.
	ErrUnsupportedIP = errors.New("unsupported IP type")
)

// Status gathers all of the details regarding an IP network's ban status.
type Status struct {
	// Banned determines whether the IP network is currently banned.
	Banned bool

	// Reason is the reason for which the IP network was banned.
	Reason Reason

	// Expiration is the absolute time in which the ban will expire.
	Expiration time.Time
}

// Store is the store responsible for maintaining records of banned IP networks.
// It uses IP networks, rather than single IP addresses, in order to coalesce
// multiple IP addresses that are likely to be correlated.
type Store interface {
	// BanIPNet creates a ban record for the IP network within the store for
	// the given duration. A reason can also be provided to note why the IP
	// network is being banned. The record will exist until a call to Status
	// is made after the ban expiration.
	BanIPNet(*net.IPNet, Reason, time.Duration) error

	// Status returns the ban status for a given IP network.
	Status(*net.IPNet) (Status, error)
}

// NewStore returns a Store backed by a database.
func NewStore(db walletdb.DB) (Store, error) {
	return newBanStore(db)
}

// banStore is a concrete implementation of the Store interface backed by a
// database.
type banStore struct {
	db walletdb.DB
}

// A compile-time constraint to ensure banStore satisfies the Store interface.
var _ Store = (*banStore)(nil)

// newBanStore creates a concrete implementation of the Store interface backed
// by a database.
func newBanStore(db walletdb.DB) (*banStore, error) {
	s := &banStore{db: db}

	// We'll ensure the expected buckets are created upon initialization.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		banStore, err := tx.CreateTopLevelBucket(banStoreBucket)
		if err != nil {
			return err
		}
		_, err = banStore.CreateBucketIfNotExists(banBucket)
		if err != nil {
			return err
		}
		_, err = banStore.CreateBucketIfNotExists(reasonBucket)
		return err
	})
	if err != nil && err != walletdb.ErrBucketExists {
		return nil, err
	}

	return s, nil
}

// BanIPNet creates a ban record for the IP network within the store for the
// given duration. A reason can also be provided to note why the IP network is
// being banned. The record will exist until a call to Status is made after the
// ban expiration.
func (s *banStore) BanIPNet(ipNet *net.IPNet, reason Reason, duration time.Duration) error {
	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		banStore := tx.ReadWriteBucket(banStoreBucket)
		if banStore == nil {
			return ErrCorruptedStore
		}
		banIndex := banStore.NestedReadWriteBucket(banBucket)
		if banIndex == nil {
			return ErrCorruptedStore
		}
		reasonIndex := banStore.NestedReadWriteBucket(reasonBucket)
		if reasonIndex == nil {
			return ErrCorruptedStore
		}

		var ipNetBuf bytes.Buffer
		if err := encodeIPNet(&ipNetBuf, ipNet); err != nil {
			return fmt.Errorf("unable to encode %v: %v", ipNet, err)
		}
		k := ipNetBuf.Bytes()

		return addBannedIPNet(banIndex, reasonIndex, k, reason, duration)
	})
}

// addBannedIPNet adds an entry to the ban store for the given IP network.
func addBannedIPNet(banIndex, reasonIndex walletdb.ReadWriteBucket,
	ipNetKey []byte, reason Reason, duration time.Duration) error {

	var v [8]byte
	banExpiration := time.Now().Add(duration)
	byteOrder.PutUint64(v[:], uint64(banExpiration.Unix()))

	if err := banIndex.Put(ipNetKey, v[:]); err != nil {
		return err
	}
	return reasonIndex.Put(ipNetKey, []byte{byte(reason)})
}

// Status returns the ban status for a given IP network.
func (s *banStore) Status(ipNet *net.IPNet) (Status, error) {
	var banStatus Status
	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		banStore := tx.ReadWriteBucket(banStoreBucket)
		if banStore == nil {
			return ErrCorruptedStore
		}
		banIndex := banStore.NestedReadWriteBucket(banBucket)
		if banIndex == nil {
			return ErrCorruptedStore
		}
		reasonIndex := banStore.NestedReadWriteBucket(reasonBucket)
		if reasonIndex == nil {
			return ErrCorruptedStore
		}

		var ipNetBuf bytes.Buffer
		if err := encodeIPNet(&ipNetBuf, ipNet); err != nil {
			return fmt.Errorf("unable to encode %v: %v", ipNet, err)
		}
		k := ipNetBuf.Bytes()

		status := fetchStatus(banIndex, reasonIndex, k)

		// If the IP network's ban duration has expired, we can remove
		// its entry from the store.
		if !time.Now().Before(status.Expiration) {
			return removeBannedIPNet(banIndex, reasonIndex, k)
		}

		banStatus = status
		return nil
	})
	if err != nil {
		return Status{}, err
	}

	return banStatus, nil
}

// fetchStatus retrieves the ban status of the given IP network.
func fetchStatus(banIndex, reasonIndex walletdb.ReadWriteBucket,
	ipNetKey []byte) Status {

	v := banIndex.Get(ipNetKey)
	if v == nil {
		return Status{}
	}
	reason := Reason(reasonIndex.Get(ipNetKey)[0])
	banExpiration := time.Unix(int64(byteOrder.Uint64(v)), 0)

	return Status{
		Banned:     true,
		Reason:     reason,
		Expiration: banExpiration,
	}
}

// removeBannedIPNet removes all references to a banned IP network within the
// ban store.
func removeBannedIPNet(banIndex, reasonIndex walletdb.ReadWriteBucket,
	ipNetKey []byte) error {

	if err := banIndex.Delete(ipNetKey); err != nil {
		return err
	}
	return reasonIndex.Delete(ipNetKey)
}
