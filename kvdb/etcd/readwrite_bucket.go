// +build kvdb_etcd

package etcd

import (
	"strconv"

	"github.com/btcsuite/btcwallet/walletdb"
)

// readWriteBucket stores the bucket id and the buckets transaction.
type readWriteBucket struct {
	// id is used to identify the bucket and is created by
	// hashing the parent id with the bucket key. For each key/value,
	// sub-bucket or the bucket sequence the bucket id is used with the
	// appropriate prefix to prefix the key.
	id []byte

	// tx holds the parent transaction.
	tx *readWriteTx
}

// newReadWriteBucket creates a new rw bucket with the passed transaction
// and bucket id.
func newReadWriteBucket(tx *readWriteTx, key, id []byte) *readWriteBucket {
	return &readWriteBucket{
		id: id,
		tx: tx,
	}
}

// NestedReadBucket retrieves a nested read bucket with the given key.
// Returns nil if the bucket does not exist.
func (b *readWriteBucket) NestedReadBucket(key []byte) walletdb.ReadBucket {
	return b.NestedReadWriteBucket(key)
}

// ForEach invokes the passed function with every key/value pair in
// the bucket. This includes nested buckets, in which case the value
// is nil, but it does not include the key/value pairs within those
// nested buckets.
func (b *readWriteBucket) ForEach(cb func(k, v []byte) error) error {
	prefix := string(b.id)

	// Get the first matching key that is in the bucket.
	kv, err := b.tx.stm.First(prefix)
	if err != nil {
		return err
	}

	for kv != nil {
		key, val := getKeyVal(kv)

		if err := cb(key, val); err != nil {
			return err
		}

		// Step to the next key.
		kv, err = b.tx.stm.Next(prefix, kv.key)
		if err != nil {
			return err
		}
	}

	return nil
}

// Get returns the value for the given key. Returns nil if the key does
// not exist in this bucket.
func (b *readWriteBucket) Get(key []byte) []byte {
	// Return nil if the key is empty.
	if len(key) == 0 {
		return nil
	}

	// Fetch the associated value.
	val, err := b.tx.stm.Get(string(makeValueKey(b.id, key)))
	if err != nil {
		// TODO: we should return the error once the
		// kvdb inteface is extended.
		return nil
	}

	if val == nil {
		return nil
	}

	return val
}

func (b *readWriteBucket) ReadCursor() walletdb.ReadCursor {
	return newReadWriteCursor(b)
}

// NestedReadWriteBucket retrieves a nested bucket with the given key.
// Returns nil if the bucket does not exist.
func (b *readWriteBucket) NestedReadWriteBucket(key []byte) walletdb.ReadWriteBucket {
	if len(key) == 0 {
		return nil
	}

	// Get the bucket id (and return nil if bucket doesn't exist).
	bucketKey := makeBucketKey(b.id, key)
	bucketVal, err := b.tx.stm.Get(string(bucketKey))
	if err != nil {
		// TODO: we should return the error once the
		// kvdb inteface is extended.
		return nil
	}

	if !isValidBucketID(bucketVal) {
		return nil
	}

	// Return the bucket with the fetched bucket id.
	return newReadWriteBucket(b.tx, bucketKey, bucketVal)
}

// CreateBucket creates and returns a new nested bucket with the given
// key. Returns ErrBucketExists if the bucket already exists,
// ErrBucketNameRequired if the key is empty, or ErrIncompatibleValue
// if the key value is otherwise invalid for the particular database
// implementation.  Other errors are possible depending on the
// implementation.
func (b *readWriteBucket) CreateBucket(key []byte) (
	walletdb.ReadWriteBucket, error) {

	if len(key) == 0 {
		return nil, walletdb.ErrBucketNameRequired
	}

	// Check if the bucket already exists.
	bucketKey := makeBucketKey(b.id, key)

	bucketVal, err := b.tx.stm.Get(string(bucketKey))
	if err != nil {
		return nil, err
	}

	if isValidBucketID(bucketVal) {
		return nil, walletdb.ErrBucketExists
	}

	// Create a deterministic bucket id from the bucket key.
	newID := makeBucketID(bucketKey)

	// Create the bucket.
	b.tx.stm.Put(string(bucketKey), string(newID[:]))

	return newReadWriteBucket(b.tx, bucketKey, newID[:]), nil
}

// CreateBucketIfNotExists creates and returns a new nested bucket with
// the given key if it does not already exist.  Returns
// ErrBucketNameRequired if the key is empty or ErrIncompatibleValue
// if the key value is otherwise invalid for the particular database
// backend.  Other errors are possible depending on the implementation.
func (b *readWriteBucket) CreateBucketIfNotExists(key []byte) (
	walletdb.ReadWriteBucket, error) {

	if len(key) == 0 {
		return nil, walletdb.ErrBucketNameRequired
	}

	// Check for the bucket and create if it doesn't exist.
	bucketKey := makeBucketKey(b.id, key)

	bucketVal, err := b.tx.stm.Get(string(bucketKey))
	if err != nil {
		return nil, err
	}

	if !isValidBucketID(bucketVal) {
		newID := makeBucketID(bucketKey)
		b.tx.stm.Put(string(bucketKey), string(newID[:]))

		return newReadWriteBucket(b.tx, bucketKey, newID[:]), nil
	}

	// Otherwise return the bucket with the fetched bucket id.
	return newReadWriteBucket(b.tx, bucketKey, bucketVal), nil
}

// DeleteNestedBucket deletes the nested bucket and its sub-buckets
// pointed to by the passed key. All values in the bucket and sub-buckets
// will be deleted as well.
func (b *readWriteBucket) DeleteNestedBucket(key []byte) error {
	// TODO shouldn't empty key return ErrBucketNameRequired ?
	if len(key) == 0 {
		return walletdb.ErrIncompatibleValue
	}

	// Get the bucket first.
	bucketKey := string(makeBucketKey(b.id, key))

	bucketVal, err := b.tx.stm.Get(bucketKey)
	if err != nil {
		return err
	}

	if !isValidBucketID(bucketVal) {
		return walletdb.ErrBucketNotFound
	}

	// Enqueue the top level bucket id.
	queue := [][]byte{bucketVal}

	// Traverse the buckets breadth first.
	for len(queue) != 0 {
		if !isValidBucketID(queue[0]) {
			return walletdb.ErrBucketNotFound
		}

		id := queue[0]
		queue = queue[1:]

		kv, err := b.tx.stm.First(string(id))
		if err != nil {
			return err
		}

		for kv != nil {
			b.tx.stm.Del(kv.key)

			if isBucketKey(kv.key) {
				queue = append(queue, []byte(kv.val))
			}

			kv, err = b.tx.stm.Next(string(id), kv.key)
			if err != nil {
				return err
			}
		}

		// Finally delete the sequence key for the bucket.
		b.tx.stm.Del(string(makeSequenceKey(id)))
	}

	// Delete the top level bucket and sequence key.
	b.tx.stm.Del(bucketKey)
	b.tx.stm.Del(string(makeSequenceKey(bucketVal)))

	return nil
}

// Put updates the value for the passed key.
// Returns ErrKeyRequred if te passed key is empty.
func (b *readWriteBucket) Put(key, value []byte) error {
	if len(key) == 0 {
		return walletdb.ErrKeyRequired
	}

	// Update the transaction with the new value.
	b.tx.stm.Put(string(makeValueKey(b.id, key)), string(value))

	return nil
}

// Delete deletes the key/value pointed to by the passed key.
// Returns ErrKeyRequred if the passed key is empty.
func (b *readWriteBucket) Delete(key []byte) error {
	if key == nil {
		return nil
	}
	if len(key) == 0 {
		return walletdb.ErrKeyRequired
	}

	// Update the transaction to delete the key/value.
	b.tx.stm.Del(string(makeValueKey(b.id, key)))

	return nil
}

// ReadWriteCursor returns a new read-write cursor for this bucket.
func (b *readWriteBucket) ReadWriteCursor() walletdb.ReadWriteCursor {
	return newReadWriteCursor(b)
}

// Tx returns the buckets transaction.
func (b *readWriteBucket) Tx() walletdb.ReadWriteTx {
	return b.tx
}

// NextSequence returns an autoincrementing sequence number for this bucket.
// Note that this is not a thread safe function and as such it must not be used
// for synchronization.
func (b *readWriteBucket) NextSequence() (uint64, error) {
	seq := b.Sequence() + 1

	return seq, b.SetSequence(seq)
}

// SetSequence updates the sequence number for the bucket.
func (b *readWriteBucket) SetSequence(v uint64) error {
	// Convert the number to string.
	val := strconv.FormatUint(v, 10)

	// Update the transaction with the new value for the sequence key.
	b.tx.stm.Put(string(makeSequenceKey(b.id)), val)

	return nil
}

// Sequence returns the current sequence number for this bucket without
// incrementing it.
func (b *readWriteBucket) Sequence() uint64 {
	val, err := b.tx.stm.Get(string(makeSequenceKey(b.id)))
	if err != nil {
		// TODO: This update kvdb interface such that error
		// may be returned here.
		return 0
	}

	if val == nil {
		// If the sequence number is not yet
		// stored, then take the default value.
		return 0
	}

	// Otherwise try to parse a 64 bit unsigned integer from the value.
	num, _ := strconv.ParseUint(string(val), 10, 64)

	return num
}
