// +build kvdb_etcd

package etcd

import (
	"crypto/sha256"
)

const (
	bucketIDLength = 32
)

var (
	valuePostfix   = []byte{0x00}
	bucketPostfix  = []byte{0xFF}
	sequencePrefix = []byte("$seq$")
)

// makeBucketID returns a deterministic key for the passed byte slice.
// Currently it returns the sha256 hash of the slice.
func makeBucketID(key []byte) [bucketIDLength]byte {
	return sha256.Sum256(key)
}

// isValidBucketID checks if the passed slice is the required length to be a
// valid bucket id.
func isValidBucketID(s []byte) bool {
	return len(s) == bucketIDLength
}

// makeKey concatenates parent, key and postfix into one byte slice.
// The postfix indicates the use of this key (whether bucket or value), while
// parent refers to the parent bucket.
func makeKey(parent, key, postfix []byte) []byte {
	keyBuf := make([]byte, len(parent)+len(key)+len(postfix))
	copy(keyBuf, parent)
	copy(keyBuf[len(parent):], key)
	copy(keyBuf[len(parent)+len(key):], postfix)

	return keyBuf
}

// makeBucketKey returns a bucket key from the passed parent bucket id and
// the key.
func makeBucketKey(parent []byte, key []byte) []byte {
	return makeKey(parent, key, bucketPostfix)
}

// makeValueKey returns a value key from the passed parent bucket id and
// the key.
func makeValueKey(parent []byte, key []byte) []byte {
	return makeKey(parent, key, valuePostfix)
}

// makeSequenceKey returns a sequence key of the passed parent bucket id.
func makeSequenceKey(parent []byte) []byte {
	keyBuf := make([]byte, len(sequencePrefix)+len(parent))
	copy(keyBuf, sequencePrefix)
	copy(keyBuf[len(sequencePrefix):], parent)
	return keyBuf
}

// isBucketKey returns true if the passed key is a bucket key, meaning it
// keys a bucket name.
func isBucketKey(key string) bool {
	if len(key) < bucketIDLength+1 {
		return false
	}

	return key[len(key)-1] == bucketPostfix[0]
}

// getKey chops out the key from the raw key (by removing the bucket id
// prefixing the key and the postfix indicating whether it is a bucket or
// a value key)
func getKey(rawKey string) []byte {
	return []byte(rawKey[bucketIDLength : len(rawKey)-1])
}

// getKeyVal chops out the key from the raw key (by removing the bucket id
// prefixing the key and the postfix indicating whether it is a bucket or
// a value key) and also returns the appropriate value for the key, which is
// nil in case of buckets (or the set value otherwise).
func getKeyVal(kv *KV) ([]byte, []byte) {
	var val []byte

	if !isBucketKey(kv.key) {
		val = []byte(kv.val)
	}

	return getKey(kv.key), val
}

// BucketKey is a helper functon used in tests to create a bucket key from
// passed bucket list.
func BucketKey(buckets ...string) string {
	var bucketKey []byte

	rootID := makeBucketID([]byte(etcdDefaultRootBucketId))
	parent := rootID[:]

	for _, bucketName := range buckets {
		bucketKey = makeBucketKey(parent, []byte(bucketName))
		id := makeBucketID(bucketKey)
		parent = id[:]
	}

	return string(bucketKey)
}

// BucketVal is a helper function used in tests to create a bucket value (the
// value for a bucket key) from the passed bucket list.
func BucketVal(buckets ...string) string {
	id := makeBucketID([]byte(BucketKey(buckets...)))
	return string(id[:])
}

// ValueKey is a helper function used in tests to create a value key from the
// passed key and bucket list.
func ValueKey(key string, buckets ...string) string {
	rootID := makeBucketID([]byte(etcdDefaultRootBucketId))
	bucket := rootID[:]

	for _, bucketName := range buckets {
		bucketKey := makeBucketKey(bucket, []byte(bucketName))
		id := makeBucketID(bucketKey)
		bucket = id[:]
	}

	return string(makeValueKey(bucket, []byte(key)))
}
