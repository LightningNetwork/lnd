// +build kvdb_etcd

package etcd

// bval is a helper function used in tests to create a bucket value (the value
// for a bucket key) from the passed bucket list.
func bval(buckets ...string) string {
	id := makeBucketID([]byte(bkey(buckets...)))
	return string(id[:])
}
