// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletdbtest

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/btcsuite/btcwallet/walletdb"
)

// errSubTestFail is used to signal that a sub test returned false.
var errSubTestFail = fmt.Errorf("sub test failure")

// testContext is used to store context information about a running test which
// is passed into helper functions.
type testContext struct {
	t           Tester
	db          walletdb.DB
	bucketDepth int
	isWritable  bool
}

// rollbackValues returns a copy of the provided map with all values set to an
// empty string.  This is used to test that values are properly rolled back.
func rollbackValues(values map[string]string) map[string]string {
	retMap := make(map[string]string, len(values))
	for k := range values {
		retMap[k] = ""
	}
	return retMap
}

// testGetValues checks that all of the provided key/value pairs can be
// retrieved from the database and the retrieved values match the provided
// values.
func testGetValues(tc *testContext, bucket walletdb.ReadBucket, values map[string]string) bool {
	for k, v := range values {
		var vBytes []byte
		if v != "" {
			vBytes = []byte(v)
		}

		gotValue := bucket.Get([]byte(k))
		if !reflect.DeepEqual(gotValue, vBytes) {
			tc.t.Errorf("Get: unexpected value - got %s, want %s",
				gotValue, vBytes)
			return false
		}
	}

	return true
}

// testPutValues stores all of the provided key/value pairs in the provided
// bucket while checking for errors.
func testPutValues(tc *testContext, bucket walletdb.ReadWriteBucket, values map[string]string) bool {
	for k, v := range values {
		var vBytes []byte
		if v != "" {
			vBytes = []byte(v)
		}
		if err := bucket.Put([]byte(k), vBytes); err != nil {
			tc.t.Errorf("Put: unexpected error: %v", err)
			return false
		}
	}

	return true
}

// testDeleteValues removes all of the provided key/value pairs from the
// provided bucket.
func testDeleteValues(tc *testContext, bucket walletdb.ReadWriteBucket, values map[string]string) bool {
	for k := range values {
		if err := bucket.Delete([]byte(k)); err != nil {
			tc.t.Errorf("Delete: unexpected error: %v", err)
			return false
		}
	}

	return true
}

// testNestedReadWriteBucket reruns the testBucketInterface against a nested bucket along
// with a counter to only test a couple of level deep.
func testNestedReadWriteBucket(tc *testContext, testBucket walletdb.ReadWriteBucket) bool {
	// Don't go more than 2 nested level deep.
	if tc.bucketDepth > 1 {
		return true
	}

	tc.bucketDepth++
	defer func() {
		tc.bucketDepth--
	}()
	if !testReadWriteBucketInterface(tc, testBucket) {
		return false
	}

	return true
}

// testSequence tests that the sequence related methods work as expected.
func testSequence(tc *testContext, testBucket walletdb.ReadWriteBucket) bool {
	// Obtaining the current sequence twice should give us the same value.
	seqNo1 := testBucket.Sequence()
	seqNo2 := testBucket.Sequence()
	if seqNo1 != seqNo2 {
		tc.t.Errorf("Sequence: seq has incremented")
		return false
	}

	// Incrementing to the next sequence should give us a value one larger
	// than the prior number.
	seqNo3, err := testBucket.NextSequence()
	if err != nil {
		tc.t.Errorf("Sequence: unexpected error: %v", err)
		return false
	}
	if seqNo3 != seqNo2+1 {
		tc.t.Errorf("Sequence: expected seq no of %v, instead got %v",
			seqNo2+1, seqNo3)
		return false
	}

	// We should be able to modify the sequence base number.
	newBase := uint64(100)
	if err := testBucket.SetSequence(newBase); err != nil {
		tc.t.Errorf("Sequence: unexpected error: %v", err)
		return false
	}

	// Any offset from this new sequence should now be properly reflected.
	seqNo4, err := testBucket.NextSequence()
	if err != nil {
		tc.t.Errorf("Sequence: unexpected error: %v", err)
		return false
	}
	if seqNo4 != newBase+1 {
		tc.t.Errorf("Sequence: expected seq no of %v, instead got %v",
			newBase+1, seqNo4)
		return false
	}

	return true
}

// testReadWriteBucketInterface ensures the bucket interface is working properly by
// exercising all of its functions.
func testReadWriteBucketInterface(tc *testContext, bucket walletdb.ReadWriteBucket) bool {
	// keyValues holds the keys and values to use when putting
	// values into the bucket.
	var keyValues = map[string]string{
		"bucketkey1": "foo1",
		"bucketkey2": "foo2",
		"bucketkey3": "foo3",
	}
	if !testPutValues(tc, bucket, keyValues) {
		return false
	}

	if !testGetValues(tc, bucket, keyValues) {
		return false
	}

	// Iterate all of the keys using ForEach while making sure the
	// stored values are the expected values.
	keysFound := make(map[string]struct{}, len(keyValues))
	err := bucket.ForEach(func(k, v []byte) error {
		ks := string(k)
		wantV, ok := keyValues[ks]
		if !ok {
			return fmt.Errorf("ForEach: key '%s' should "+
				"exist", ks)
		}

		if !reflect.DeepEqual(v, []byte(wantV)) {
			return fmt.Errorf("ForEach: value for key '%s' "+
				"does not match - got %s, want %s",
				ks, v, wantV)
		}

		keysFound[ks] = struct{}{}
		return nil
	})
	if err != nil {
		tc.t.Errorf("%v", err)
		return false
	}

	// Ensure all keys were iterated.
	for k := range keyValues {
		if _, ok := keysFound[k]; !ok {
			tc.t.Errorf("ForEach: key '%s' was not iterated "+
				"when it should have been", k)
			return false
		}
	}

	// Delete the keys and ensure they were deleted.
	if !testDeleteValues(tc, bucket, keyValues) {
		return false
	}
	if !testGetValues(tc, bucket, rollbackValues(keyValues)) {
		return false
	}

	// Test that the sequence methods work as expected.
	if !testSequence(tc, bucket) {
		return false
	}

	// Ensure creating a new bucket works as expected.
	testBucketName := []byte("testbucket")
	testBucket, err := bucket.CreateBucket(testBucketName)
	if err != nil {
		tc.t.Errorf("CreateBucket: unexpected error: %v", err)
		return false
	}
	if !testNestedReadWriteBucket(tc, testBucket) {
		return false
	}

	// Ensure creating a bucket that already exists fails with the
	// expected error.
	wantErr := walletdb.ErrBucketExists
	if _, err := bucket.CreateBucket(testBucketName); err != wantErr {
		tc.t.Errorf("CreateBucket: unexpected error - got %v, "+
			"want %v", err, wantErr)
		return false
	}

	// Ensure CreateBucketIfNotExists returns an existing bucket.
	testBucket, err = bucket.CreateBucketIfNotExists(testBucketName)
	if err != nil {
		tc.t.Errorf("CreateBucketIfNotExists: unexpected "+
			"error: %v", err)
		return false
	}
	if !testNestedReadWriteBucket(tc, testBucket) {
		return false
	}

	// Ensure retrieving and existing bucket works as expected.
	testBucket = bucket.NestedReadWriteBucket(testBucketName)
	if !testNestedReadWriteBucket(tc, testBucket) {
		return false
	}

	// Ensure deleting a bucket works as intended.
	if err := bucket.DeleteNestedBucket(testBucketName); err != nil {
		tc.t.Errorf("DeleteNestedBucket: unexpected error: %v", err)
		return false
	}
	if b := bucket.NestedReadWriteBucket(testBucketName); b != nil {
		tc.t.Errorf("DeleteNestedBucket: bucket '%s' still exists",
			testBucketName)
		return false
	}

	// Ensure deleting a bucket that doesn't exist returns the
	// expected error.
	wantErr = walletdb.ErrBucketNotFound
	if err := bucket.DeleteNestedBucket(testBucketName); err != wantErr {
		tc.t.Errorf("DeleteNestedBucket: unexpected error - got %v, "+
			"want %v", err, wantErr)
		return false
	}

	// Ensure CreateBucketIfNotExists creates a new bucket when
	// it doesn't already exist.
	testBucket, err = bucket.CreateBucketIfNotExists(testBucketName)
	if err != nil {
		tc.t.Errorf("CreateBucketIfNotExists: unexpected "+
			"error: %v", err)
		return false
	}
	if !testNestedReadWriteBucket(tc, testBucket) {
		return false
	}

	// Delete the test bucket to avoid leaving it around for future
	// calls.
	if err := bucket.DeleteNestedBucket(testBucketName); err != nil {
		tc.t.Errorf("DeleteNestedBucket: unexpected error: %v", err)
		return false
	}
	if b := bucket.NestedReadWriteBucket(testBucketName); b != nil {
		tc.t.Errorf("DeleteNestedBucket: bucket '%s' still exists",
			testBucketName)
		return false
	}
	return true
}

// testManualTxInterface ensures that manual transactions work as expected.
func testManualTxInterface(tc *testContext, bucketKey []byte) bool {
	db := tc.db

	// populateValues tests that populating values works as expected.
	//
	// When the writable flag is false, a read-only tranasction is created,
	// standard bucket tests for read-only transactions are performed, and
	// the Commit function is checked to ensure it fails as expected.
	//
	// Otherwise, a read-write transaction is created, the values are
	// written, standard bucket tests for read-write transactions are
	// performed, and then the transaction is either commited or rolled
	// back depending on the flag.
	populateValues := func(writable, rollback bool, putValues map[string]string) bool {
		var dbtx walletdb.ReadTx
		var rootBucket walletdb.ReadBucket
		var err error
		if writable {
			dbtx, err = db.BeginReadWriteTx()
			if err != nil {
				tc.t.Errorf("BeginReadWriteTx: unexpected error %v", err)
				return false
			}
			rootBucket = dbtx.(walletdb.ReadWriteTx).ReadWriteBucket(bucketKey)
		} else {
			dbtx, err = db.BeginReadTx()
			if err != nil {
				tc.t.Errorf("BeginReadTx: unexpected error %v", err)
				return false
			}
			rootBucket = dbtx.ReadBucket(bucketKey)
		}
		if rootBucket == nil {
			tc.t.Errorf("ReadWriteBucket/ReadBucket: unexpected nil root bucket")
			_ = dbtx.Rollback()
			return false
		}

		if writable {
			tc.isWritable = writable
			if !testReadWriteBucketInterface(tc, rootBucket.(walletdb.ReadWriteBucket)) {
				_ = dbtx.Rollback()
				return false
			}
		}

		if !writable {
			// Rollback the transaction.
			if err := dbtx.Rollback(); err != nil {
				tc.t.Errorf("Commit: unexpected error %v", err)
				return false
			}
		} else {
			rootBucket := rootBucket.(walletdb.ReadWriteBucket)
			if !testPutValues(tc, rootBucket, putValues) {
				return false
			}

			if rollback {
				// Rollback the transaction.
				if err := dbtx.Rollback(); err != nil {
					tc.t.Errorf("Rollback: unexpected "+
						"error %v", err)
					return false
				}
			} else {
				// The commit should succeed.
				if err := dbtx.(walletdb.ReadWriteTx).Commit(); err != nil {
					tc.t.Errorf("Commit: unexpected error "+
						"%v", err)
					return false
				}
			}
		}

		return true
	}

	// checkValues starts a read-only transaction and checks that all of
	// the key/value pairs specified in the expectedValues parameter match
	// what's in the database.
	checkValues := func(expectedValues map[string]string) bool {
		// Begin another read-only transaction to ensure...
		dbtx, err := db.BeginReadTx()
		if err != nil {
			tc.t.Errorf("BeginReadTx: unexpected error %v", err)
			return false
		}

		rootBucket := dbtx.ReadBucket(bucketKey)
		if rootBucket == nil {
			tc.t.Errorf("ReadBucket: unexpected nil root bucket")
			_ = dbtx.Rollback()
			return false
		}

		if !testGetValues(tc, rootBucket, expectedValues) {
			_ = dbtx.Rollback()
			return false
		}

		// Rollback the read-only transaction.
		if err := dbtx.Rollback(); err != nil {
			tc.t.Errorf("Commit: unexpected error %v", err)
			return false
		}

		return true
	}

	// deleteValues starts a read-write transaction and deletes the keys
	// in the passed key/value pairs.
	deleteValues := func(values map[string]string) bool {
		dbtx, err := db.BeginReadWriteTx()
		if err != nil {
			tc.t.Errorf("BeginReadWriteTx: unexpected error %v", err)
			_ = dbtx.Rollback()
			return false
		}

		rootBucket := dbtx.ReadWriteBucket(bucketKey)
		if rootBucket == nil {
			tc.t.Errorf("RootBucket: unexpected nil root bucket")
			_ = dbtx.Rollback()
			return false
		}

		// Delete the keys and ensure they were deleted.
		if !testDeleteValues(tc, rootBucket, values) {
			_ = dbtx.Rollback()
			return false
		}
		if !testGetValues(tc, rootBucket, rollbackValues(values)) {
			_ = dbtx.Rollback()
			return false
		}

		// Commit the changes and ensure it was successful.
		if err := dbtx.Commit(); err != nil {
			tc.t.Errorf("Commit: unexpected error %v", err)
			return false
		}

		return true
	}

	// keyValues holds the keys and values to use when putting values
	// into a bucket.
	var keyValues = map[string]string{
		"umtxkey1": "foo1",
		"umtxkey2": "foo2",
		"umtxkey3": "foo3",
	}

	// Ensure that attempting populating the values using a read-only
	// transaction fails as expected.
	if !populateValues(false, true, keyValues) {
		return false
	}
	if !checkValues(rollbackValues(keyValues)) {
		return false
	}

	// Ensure that attempting populating the values using a read-write
	// transaction and then rolling it back yields the expected values.
	if !populateValues(true, true, keyValues) {
		return false
	}
	if !checkValues(rollbackValues(keyValues)) {
		return false
	}

	// Ensure that attempting populating the values using a read-write
	// transaction and then committing it stores the expected values.
	if !populateValues(true, false, keyValues) {
		return false
	}
	if !checkValues(keyValues) {
		return false
	}

	// Clean up the keys.
	if !deleteValues(keyValues) {
		return false
	}

	return true
}

// testNamespaceAndTxInterfaces creates a namespace using the provided key and
// tests all facets of it interface as well as  transaction and bucket
// interfaces under it.
func testNamespaceAndTxInterfaces(tc *testContext, namespaceKey string) bool {
	namespaceKeyBytes := []byte(namespaceKey)
	err := walletdb.Update(tc.db, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(namespaceKeyBytes)
		return err
	})
	if err != nil {
		tc.t.Errorf("CreateTopLevelBucket: unexpected error: %v", err)
		return false
	}
	defer func() {
		// Remove the namespace now that the tests are done for it.
		err := walletdb.Update(tc.db, func(tx walletdb.ReadWriteTx) error {
			return tx.DeleteTopLevelBucket(namespaceKeyBytes)
		})
		if err != nil {
			tc.t.Errorf("DeleteTopLevelBucket: unexpected error: %v", err)
			return
		}
	}()

	if !testManualTxInterface(tc, namespaceKeyBytes) {
		return false
	}

	// keyValues holds the keys and values to use when putting values
	// into a bucket.
	var keyValues = map[string]string{
		"mtxkey1": "foo1",
		"mtxkey2": "foo2",
		"mtxkey3": "foo3",
	}

	// Test the bucket interface via a managed read-only transaction.
	err = walletdb.View(tc.db, func(tx walletdb.ReadTx) error {
		rootBucket := tx.ReadBucket(namespaceKeyBytes)
		if rootBucket == nil {
			return fmt.Errorf("ReadBucket: unexpected nil root bucket")
		}

		return nil
	})
	if err != nil {
		if err != errSubTestFail {
			tc.t.Errorf("%v", err)
		}
		return false
	}

	// Test the bucket interface via a managed read-write transaction.
	// Also, put a series of values and force a rollback so the following
	// code can ensure the values were not stored.
	forceRollbackError := fmt.Errorf("force rollback")
	err = walletdb.Update(tc.db, func(tx walletdb.ReadWriteTx) error {
		rootBucket := tx.ReadWriteBucket(namespaceKeyBytes)
		if rootBucket == nil {
			return fmt.Errorf("ReadWriteBucket: unexpected nil root bucket")
		}

		tc.isWritable = true
		if !testReadWriteBucketInterface(tc, rootBucket) {
			return errSubTestFail
		}

		if !testPutValues(tc, rootBucket, keyValues) {
			return errSubTestFail
		}

		// Return an error to force a rollback.
		return forceRollbackError
	})
	if err != forceRollbackError {
		if err == errSubTestFail {
			return false
		}

		tc.t.Errorf("Update: inner function error not returned - got "+
			"%v, want %v", err, forceRollbackError)
		return false
	}

	// Ensure the values that should have not been stored due to the forced
	// rollback above were not actually stored.
	err = walletdb.View(tc.db, func(tx walletdb.ReadTx) error {
		rootBucket := tx.ReadBucket(namespaceKeyBytes)
		if rootBucket == nil {
			return fmt.Errorf("ReadBucket: unexpected nil root bucket")
		}

		if !testGetValues(tc, rootBucket, rollbackValues(keyValues)) {
			return errSubTestFail
		}

		return nil
	})
	if err != nil {
		if err != errSubTestFail {
			tc.t.Errorf("%v", err)
		}
		return false
	}

	// Store a series of values via a managed read-write transaction.
	err = walletdb.Update(tc.db, func(tx walletdb.ReadWriteTx) error {
		rootBucket := tx.ReadWriteBucket(namespaceKeyBytes)
		if rootBucket == nil {
			return fmt.Errorf("ReadWriteBucket: unexpected nil root bucket")
		}

		if !testPutValues(tc, rootBucket, keyValues) {
			return errSubTestFail
		}

		return nil
	})
	if err != nil {
		if err != errSubTestFail {
			tc.t.Errorf("%v", err)
		}
		return false
	}

	// Ensure the values stored above were committed as expected.
	err = walletdb.View(tc.db, func(tx walletdb.ReadTx) error {
		rootBucket := tx.ReadBucket(namespaceKeyBytes)
		if rootBucket == nil {
			return fmt.Errorf("ReadBucket: unexpected nil root bucket")
		}

		if !testGetValues(tc, rootBucket, keyValues) {
			return errSubTestFail
		}

		return nil
	})
	if err != nil {
		if err != errSubTestFail {
			tc.t.Errorf("%v", err)
		}
		return false
	}

	// Clean up the values stored above in a managed read-write transaction.
	err = walletdb.Update(tc.db, func(tx walletdb.ReadWriteTx) error {
		rootBucket := tx.ReadWriteBucket(namespaceKeyBytes)
		if rootBucket == nil {
			return fmt.Errorf("ReadWriteBucket: unexpected nil root bucket")
		}

		if !testDeleteValues(tc, rootBucket, keyValues) {
			return errSubTestFail
		}

		return nil
	})
	if err != nil {
		if err != errSubTestFail {
			tc.t.Errorf("%v", err)
		}
		return false
	}

	return true
}

// testAdditionalErrors performs some tests for error cases not covered
// elsewhere in the tests and therefore improves negative test coverage.
func testAdditionalErrors(tc *testContext) bool {
	ns3Key := []byte("ns3")

	err := walletdb.Update(tc.db, func(tx walletdb.ReadWriteTx) error {
		// Create a new namespace
		rootBucket, err := tx.CreateTopLevelBucket(ns3Key)
		if err != nil {
			return fmt.Errorf("CreateTopLevelBucket: unexpected error: %v", err)
		}

		// Ensure CreateBucket returns the expected error when no bucket
		// key is specified.
		wantErr := walletdb.ErrBucketNameRequired
		if _, err := rootBucket.CreateBucket(nil); err != wantErr {
			return fmt.Errorf("CreateBucket: unexpected error - "+
				"got %v, want %v", err, wantErr)
		}

		// Ensure DeleteNestedBucket returns the expected error when no bucket
		// key is specified.
		wantErr = walletdb.ErrIncompatibleValue
		if err := rootBucket.DeleteNestedBucket(nil); err != wantErr {
			return fmt.Errorf("DeleteNestedBucket: unexpected error - "+
				"got %v, want %v", err, wantErr)
		}

		// Ensure Put returns the expected error when no key is
		// specified.
		wantErr = walletdb.ErrKeyRequired
		if err := rootBucket.Put(nil, nil); err != wantErr {
			return fmt.Errorf("Put: unexpected error - got %v, "+
				"want %v", err, wantErr)
		}

		return nil
	})
	if err != nil {
		if err != errSubTestFail {
			tc.t.Errorf("%v", err)
		}
		return false
	}

	// Ensure that attempting to rollback or commit a transaction that is
	// already closed returns the expected error.
	tx, err := tc.db.BeginReadWriteTx()
	if err != nil {
		tc.t.Errorf("Begin: unexpected error: %v", err)
		return false
	}
	if err := tx.Rollback(); err != nil {
		tc.t.Errorf("Rollback: unexpected error: %v", err)
		return false
	}
	wantErr := walletdb.ErrTxClosed
	if err := tx.Rollback(); err != wantErr {
		tc.t.Errorf("Rollback: unexpected error - got %v, want %v", err,
			wantErr)
		return false
	}
	if err := tx.Commit(); err != wantErr {
		tc.t.Errorf("Commit: unexpected error - got %v, want %v", err,
			wantErr)
		return false
	}

	return true
}

// testBatchInterface tests that if the target database implements the batch
// method, then the method functions as expected.
func testBatchInterface(tc *testContext) bool {
	// If the database doesn't support the batch super-set of the
	// interface, then we're done here.
	batchDB, ok := tc.db.(walletdb.BatchDB)
	if !ok {
		return true
	}

	const numGoroutines = 5
	errChan := make(chan error, numGoroutines)

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := walletdb.Batch(batchDB, func(tx walletdb.ReadWriteTx) error {
				b, err := tx.CreateTopLevelBucket([]byte("test"))
				if err != nil {
					return err
				}

				byteI := []byte{byte(i)}
				return b.Put(byteI, byteI)
			})
			errChan <- err
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			tc.t.Errorf("Batch: unexpected error: %v", err)
			return false
		}
	}

	err := walletdb.View(batchDB, func(tx walletdb.ReadTx) error {
		b := tx.ReadBucket([]byte("test"))

		for i := 0; i < numGoroutines; i++ {
			byteI := []byte{byte(i)}
			if v := b.Get(byteI); v == nil {
				return fmt.Errorf("key %v not present", byteI)
			} else if !bytes.Equal(v, byteI) {
				return fmt.Errorf("key %v not equal to value: "+
					"%v", byteI, v)
			}
		}

		return nil
	})
	if err != nil {
		tc.t.Errorf("Batch: unexpected error: %v", err)
		return false
	}

	return true
}

// TestInterface performs all interfaces tests for this database driver.
func TestInterface(t Tester, dbType string, args ...interface{}) {
	db, err := walletdb.Create(dbType, args...)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer db.Close()

	// Run all of the interface tests against the database.
	// Create a test context to pass around.
	context := testContext{t: t, db: db}

	// Create a namespace and test the interface for it.
	if !testNamespaceAndTxInterfaces(&context, "ns1") {
		return
	}

	// Create a second namespace and test the interface for it.
	if !testNamespaceAndTxInterfaces(&context, "ns2") {
		return
	}

	// Check a few more error conditions not covered elsewhere.
	if !testAdditionalErrors(&context) {
		return
	}

	// If applicable, also test the behavior of the Batch call.
	if !testBatchInterface(&context) {
		return
	}
}
