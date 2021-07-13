package postgres

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/walletdb"
)

// readWriteBucket stores the bucket id and the buckets transaction.
type readWriteBucket struct {
	// id is used to identify the bucket. If id is null, it refers to the
	// root bucket.
	id *int64

	// tx holds the parent transaction.
	tx *readWriteTx

	table string
}

// newReadWriteBucket creates a new rw bucket with the passed transaction
// and bucket id.
func newReadWriteBucket(tx *readWriteTx, table string,
	id *int64) *readWriteBucket {

	return &readWriteBucket{
		id:    id,
		tx:    tx,
		table: table,
	}
}

// NestedReadBucket retrieves a nested read bucket with the given key.
// Returns nil if the bucket does not exist.
func (b *readWriteBucket) NestedReadBucket(key []byte) walletdb.ReadBucket {
	return b.NestedReadWriteBucket(key)
}

func parentSelector(id *int64) string {
	if id == nil {
		return "parent_id IS NULL"
	}
	return fmt.Sprintf("parent_id=%v", *id)
}

// ForEach invokes the passed function with every key/value pair in
// the bucket. This includes nested buckets, in which case the value
// is nil, but it does not include the key/value pairs within those
// nested buckets.
func (b *readWriteBucket) ForEach(cb func(k, v []byte) error) error {
	cursor := b.ReadWriteCursor()

	k, v := cursor.First()
	for k != nil {
		err := cb(k, v)
		if err != nil {
			return err
		}

		k, v = cursor.Next()
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

	var value *[]byte
	err := b.tx.tx.QueryRowContext(
		b.tx.db.ctx,
		"SELECT value FROM "+b.table+" WHERE "+parentSelector(b.id)+
			" AND key=$1",
		key,
	).Scan(&value)

	switch {
	case err == sql.ErrNoRows:
		return nil

	case err != nil:
		panic(err)
	}

	return *value
}

func (b *readWriteBucket) ReadCursor() walletdb.ReadCursor {
	return newReadWriteCursor(b)
}

// NestedReadWriteBucket retrieves a nested bucket with the given key.
// Returns nil if the bucket does not exist.
func (b *readWriteBucket) NestedReadWriteBucket(
	key []byte) walletdb.ReadWriteBucket {

	if len(key) == 0 {
		return nil
	}

	var id int64
	err := b.tx.tx.QueryRowContext(
		b.tx.db.ctx,
		"SELECT id FROM "+b.table+" WHERE "+parentSelector(b.id)+
			" AND key=$1 AND value IS NULL",
		key,
	).Scan(&id)

	switch {
	case err == sql.ErrNoRows:
		return nil

	case err != nil:
		panic(err)
	}

	return newReadWriteBucket(b.tx, b.table, &id)
}

// CreateBucket creates and returns a new nested bucket with the given key.
// Returns ErrBucketExists if the bucket already exists, ErrBucketNameRequired
// if the key is empty, or ErrIncompatibleValue if the key value is otherwise
// invalid for the particular database implementation.  Other errors are
// possible depending on the implementation.
func (b *readWriteBucket) CreateBucket(key []byte) (
	walletdb.ReadWriteBucket, error) {

	if len(key) == 0 {
		return nil, walletdb.ErrBucketNameRequired
	}

	// Check to see if the bucket already exists.
	var (
		value *[]byte
		id    int64
	)
	err := b.tx.tx.QueryRowContext(
		b.tx.db.ctx,
		"SELECT id,value FROM "+b.table+" WHERE "+parentSelector(b.id)+
			" AND key=$1",
		key).Scan(&id, &value)

	switch {
	case err == sql.ErrNoRows:

	case err == nil && value == nil:
		return nil, walletdb.ErrBucketExists

	case err == nil && value != nil:
		return nil, walletdb.ErrIncompatibleValue

	case err != nil:
		return nil, err
	}

	// Bucket does not yet exist, so create it. Postgres will generate a
	// bucket id for the new bucket.
	err = b.tx.tx.QueryRowContext(
		b.tx.db.ctx,
		"INSERT INTO "+b.table+" (parent_id, key) "+
			"VALUES($1, $2) RETURNING id",
		b.id, key,
	).Scan(&id)
	if err != nil {
		return nil, err
	}

	return newReadWriteBucket(b.tx, b.table, &id), nil
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

	// Check to see if the bucket already exists.
	var (
		value *[]byte
		id    int64
	)
	err := b.tx.tx.QueryRowContext(
		b.tx.db.ctx,
		"SELECT id,value FROM "+b.table+" WHERE "+parentSelector(b.id)+
			" AND key=$1",
		key).Scan(&id, &value)

	switch {
	// Bucket does not yet exist, so create it now. Postgres will generate a
	// bucket id for the new bucket.
	case err == sql.ErrNoRows:
		err = b.tx.tx.QueryRowContext(
			b.tx.db.ctx,
			"INSERT INTO "+b.table+" (parent_id, key) "+
				"VALUES($1, $2) RETURNING id",
			b.id, key,
		).Scan(&id)
		if err != nil {
			return nil, err
		}

	case err == nil && value != nil:
		return nil, walletdb.ErrIncompatibleValue

	case err != nil:
		return nil, err
	}

	return newReadWriteBucket(b.tx, b.table, &id), nil
}

// DeleteNestedBucket deletes the nested bucket and its sub-buckets
// pointed to by the passed key. All values in the bucket and sub-buckets
// will be deleted as well.
func (b *readWriteBucket) DeleteNestedBucket(key []byte) error {
	// TODO shouldn't empty key return ErrBucketNameRequired ?
	if len(key) == 0 {
		return walletdb.ErrIncompatibleValue
	}

	result, err := b.tx.tx.ExecContext(
		b.tx.db.ctx,
		"DELETE FROM "+b.table+" WHERE "+parentSelector(b.id)+
			" AND key=$1 AND value IS NULL",
		key,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return walletdb.ErrBucketNotFound
	}

	return nil
}

// Put updates the value for the passed key.
// Returns ErrKeyRequred if te passed key is empty.
func (b *readWriteBucket) Put(key, value []byte) error {
	if len(key) == 0 {
		return walletdb.ErrKeyRequired
	}

	// Prevent NULL being written for an empty value slice.
	if value == nil {
		value = []byte{}
	}

	var (
		result sql.Result
		err    error
	)
	// We are putting a value in a bucket in this table. Try to insert the
	// key first. If the key already exists (ON CONFLICT), update the key.
	// Do not update a NULL value, because this indicates that the key
	// contains a sub-bucket. This case will be caught via RowsAffected
	// below.
	if b.id == nil {
		// ON CONFLICT requires the WHERE parent_id IS NULL hint to let
		// Postgres find the NULL-parent_id unique index (<table>_unp).
		result, err = b.tx.tx.ExecContext(
			b.tx.db.ctx,
			"INSERT INTO "+b.table+" (key, value) VALUES($1, $2) "+
				"ON CONFLICT (key) WHERE parent_id IS NULL "+
				"DO UPDATE SET value=$2 "+
				"WHERE "+b.table+".value IS NOT NULL",
			key, value,
		)
	} else {
		// ON CONFLICT requires the WHERE parent_id NOT IS NULL hint to
		// let Postgres find the non-NULL-parent_id unique index
		// (<table>_up).
		result, err = b.tx.tx.ExecContext(
			b.tx.db.ctx,
			"INSERT INTO "+b.table+" (key, value, parent_id) "+
				"VALUES($1, $2, $3) "+
				"ON CONFLICT (key, parent_id) "+
				"WHERE parent_id IS NOT NULL "+
				"DO UPDATE SET value=$2 "+
				"WHERE "+b.table+".value IS NOT NULL",
			key, value, b.id,
		)
	}
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return walletdb.ErrIncompatibleValue
	}

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

	_, err := b.tx.tx.ExecContext(
		b.tx.db.ctx,
		"DELETE FROM "+b.table+" WHERE key=$1 AND "+
			parentSelector(b.id)+" AND value IS NOT NULL",
		key,
	)
	if err != nil {
		return err
	}

	// TODO: Check is key points to bucket if no rows affected?
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
	var (
		query     string
		queryArgs []interface{}
	)

	if b.id == nil {
		// There is no parent row to point to, so set the sequence
		// number in the system table.
		query = "INSERT INTO " + b.tx.db.sequenceTableName +
			" (table_name, sequence) VALUES($1, $2) " +
			"ON CONFLICT (table_name) DO UPDATE SET sequence=$2"
		queryArgs = []interface{}{b.table, int64(v)}
	} else {
		// Update the sequence field on the parent row.
		query = "UPDATE " + b.table + " SET sequence=$2 WHERE id=$1"
		queryArgs = []interface{}{b.id, int64(v)}
	}

	result, err := b.tx.tx.ExecContext(
		b.tx.db.ctx,
		query, queryArgs...,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("cannot set sequence")
	}

	return nil
}

// Sequence returns the current sequence number for this bucket without
// incrementing it.
func (b *readWriteBucket) Sequence() uint64 {
	var (
		query     string
		queryArgs []interface{}
	)

	if b.id == nil {
		query = "SELECT sequence FROM " + b.tx.db.sequenceTableName +
			" WHERE table_name=$1 AND sequence IS NOT NULL"
		queryArgs = []interface{}{b.table}
	} else {
		query = "SELECT sequence FROM " + b.table + " WHERE id=$1 " +
			"AND sequence IS NOT NULL"
		queryArgs = []interface{}{b.id}
	}

	var seq int64
	err := b.tx.tx.QueryRowContext(
		b.tx.db.ctx,
		query, queryArgs...,
	).Scan(&seq)

	switch {
	case err == sql.ErrNoRows:
		return 0

	case err != nil:
		panic(err)
	}

	return uint64(seq)
}
