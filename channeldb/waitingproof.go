package channeldb

import (
	"encoding/binary"
	"fmt"
	"sync"

	"io"

	"bytes"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// waitingProofsBucketKey byte string name of the waiting proofs store.
	waitingProofsBucketKey = []byte("waitingproofs")

	// ErrWaitingProofNotFound is returned if waiting proofs haven't been
	// found by db.
	ErrWaitingProofNotFound = errors.New("waiting proofs haven't been " +
		"found")

	// ErrWaitingProofAlreadyExist is returned if waiting proofs haven't been
	// found by db.
	ErrWaitingProofAlreadyExist = errors.New("waiting proof with such " +
		"key already exist")
)

// WaitingProofStore is the bold db map-like storage for half announcement
// signatures. The one responsibility of this storage is to be able to
// retrieve waiting proofs after client restart.
type WaitingProofStore struct {
	// cache is used in order to reduce the number of redundant get
	// calls, when object isn't stored in it.
	cache map[WaitingProofKey]struct{}
	db    *DB
	mu    sync.RWMutex
}

// NewWaitingProofStore creates new instance of proofs storage.
func NewWaitingProofStore(db *DB) (*WaitingProofStore, error) {
	s := &WaitingProofStore{
		db: db,
	}

	if err := s.ForAll(func(proof *WaitingProof) error {
		s.cache[proof.Key()] = struct{}{}
		return nil
	}, func() {
		s.cache = make(map[WaitingProofKey]struct{})
	}); err != nil && err != ErrWaitingProofNotFound {
		return nil, err
	}

	return s, nil
}

// Add adds new waiting proof in the storage.
func (s *WaitingProofStore) Add(proof *WaitingProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := kvdb.Update(s.db, func(tx kvdb.RwTx) error {
		var err error
		var b bytes.Buffer

		// Get or create the bucket.
		bucket, err := tx.CreateTopLevelBucket(waitingProofsBucketKey)
		if err != nil {
			return err
		}

		// Encode the objects and place it in the bucket.
		if err := proof.Encode(&b); err != nil {
			return err
		}

		key := proof.Key()

		return bucket.Put(key[:], b.Bytes())
	}, func() {})
	if err != nil {
		return err
	}

	// Knowing that the write succeeded, we can now update the in-memory
	// cache with the proof's key.
	s.cache[proof.Key()] = struct{}{}

	return nil
}

// Remove removes the proof from storage by its key.
func (s *WaitingProofStore) Remove(key WaitingProofKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cache[key]; !ok {
		return ErrWaitingProofNotFound
	}

	err := kvdb.Update(s.db, func(tx kvdb.RwTx) error {
		// Get or create the top bucket.
		bucket := tx.ReadWriteBucket(waitingProofsBucketKey)
		if bucket == nil {
			return ErrWaitingProofNotFound
		}

		return bucket.Delete(key[:])
	}, func() {})
	if err != nil {
		return err
	}

	// Since the proof was successfully deleted from the store, we can now
	// remove it from the in-memory cache.
	delete(s.cache, key)

	return nil
}

// ForAll iterates thought all waiting proofs and passing the waiting proof
// in the given callback.
func (s *WaitingProofStore) ForAll(cb func(*WaitingProof) error,
	reset func()) error {

	return kvdb.View(s.db, func(tx kvdb.RTx) error {
		bucket := tx.ReadBucket(waitingProofsBucketKey)
		if bucket == nil {
			return ErrWaitingProofNotFound
		}

		// Iterate over objects buckets.
		return bucket.ForEach(func(k, v []byte) error {
			// Skip buckets fields.
			if v == nil {
				return nil
			}

			r := bytes.NewReader(v)
			proof := &WaitingProof{}
			if err := proof.Decode(r); err != nil {
				return err
			}

			return cb(proof)
		})
	}, reset)
}

// Get returns the object which corresponds to the given index.
func (s *WaitingProofStore) Get(key WaitingProofKey) (*WaitingProof, error) {
	var proof *WaitingProof

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.cache[key]; !ok {
		return nil, ErrWaitingProofNotFound
	}

	err := kvdb.View(s.db, func(tx kvdb.RTx) error {
		bucket := tx.ReadBucket(waitingProofsBucketKey)
		if bucket == nil {
			return ErrWaitingProofNotFound
		}

		// Iterate over objects buckets.
		v := bucket.Get(key[:])
		if v == nil {
			return ErrWaitingProofNotFound
		}

		r := bytes.NewReader(v)
		return proof.Decode(r)
	}, func() {
		proof = &WaitingProof{}
	})

	return proof, err
}

// WaitingProofKey is the proof key which uniquely identifies the waiting
// proof object. The goal of this key is distinguish the local and remote
// proof for the same channel id.
type WaitingProofKey [9]byte

// WaitingProof is the storable object, which encapsulate the half proof and
// the information about from which side this proof came. This structure is
// needed to make channel proof exchange persistent, so that after client
// restart we may receive remote/local half proof and process it.
type WaitingProof struct {
	*lnwire.AnnounceSignatures
	isRemote bool
}

// NewWaitingProof constructs a new waiting prof instance.
func NewWaitingProof(isRemote bool, proof *lnwire.AnnounceSignatures) *WaitingProof {
	return &WaitingProof{
		AnnounceSignatures: proof,
		isRemote:           isRemote,
	}
}

// OppositeKey returns the key which uniquely identifies opposite waiting proof.
func (p *WaitingProof) OppositeKey() WaitingProofKey {
	var key [9]byte
	binary.BigEndian.PutUint64(key[:8], p.ShortChannelID.ToUint64())

	if !p.isRemote {
		key[8] = 1
	}
	return key
}

// Key returns the key which uniquely identifies waiting proof.
func (p *WaitingProof) Key() WaitingProofKey {
	var key [9]byte
	binary.BigEndian.PutUint64(key[:8], p.ShortChannelID.ToUint64())

	if p.isRemote {
		key[8] = 1
	}
	return key
}

// Encode writes the internal representation of waiting proof in byte stream.
func (p *WaitingProof) Encode(w io.Writer) error {
	if err := binary.Write(w, byteOrder, p.isRemote); err != nil {
		return err
	}

	// TODO(yy): remove the type assertion when we finished refactoring db
	// into using write buffer.
	buf, ok := w.(*bytes.Buffer)
	if !ok {
		return fmt.Errorf("expect io.Writer to be *bytes.Buffer")
	}

	if err := p.AnnounceSignatures.Encode(buf, 0); err != nil {
		return err
	}

	return nil
}

// Decode reads the data from the byte stream and initializes the
// waiting proof object with it.
func (p *WaitingProof) Decode(r io.Reader) error {
	if err := binary.Read(r, byteOrder, &p.isRemote); err != nil {
		return err
	}

	msg := &lnwire.AnnounceSignatures{}
	if err := msg.Decode(r, 0); err != nil {
		return err
	}

	(*p).AnnounceSignatures = msg
	return nil
}
