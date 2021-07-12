package bakery

import (
	"sync"

	"golang.org/x/net/context"
)

// RootKeyStore defines store for macaroon root keys.
type RootKeyStore interface {
	// Get returns the root key for the given id.
	// If the item is not there, it returns ErrNotFound.
	Get(ctx context.Context, id []byte) ([]byte, error)

	// RootKey returns the root key to be used for making a new
	// macaroon, and an id that can be used to look it up later with
	// the Get method.
	//
	// Note that the root keys should remain available for as long
	// as the macaroons using them are valid.
	//
	// Note that there is no need for it to return a new root key
	// for every call - keys may be reused, although some key
	// cycling is over time is advisable.
	RootKey(ctx context.Context) (rootKey []byte, id []byte, err error)
}

// NewMemRootKeyStore returns an implementation of
// Store that generates a single key and always
// returns that from RootKey. The same id ("0") is always
// used.
func NewMemRootKeyStore() RootKeyStore {
	return new(memRootKeyStore)
}

type memRootKeyStore struct {
	mu  sync.Mutex
	key []byte
}

// Get implements Store.Get.
func (s *memRootKeyStore) Get(_ context.Context, id []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(id) != 1 || id[0] != '0' || s.key == nil {
		return nil, ErrNotFound
	}
	return s.key, nil
}

// RootKey implements Store.RootKey by always returning the same root
// key.
func (s *memRootKeyStore) RootKey(context.Context) (rootKey, id []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		newKey, err := randomBytes(24)
		if err != nil {
			return nil, nil, err
		}
		s.key = newKey
	}
	return s.key, []byte("0"), nil
}
