package postgres

import (
	"database/sql"

	"github.com/btcsuite/btcwallet/walletdb"
)

// readWriteCursor holds a reference to the cursors bucket, the value
// prefix and the current key used while iterating.
type readWriteCursor struct {
	bucket *readWriteBucket

	// currKey holds the current key of the cursor.
	currKey []byte
}

func newReadWriteCursor(b *readWriteBucket) *readWriteCursor {
	return &readWriteCursor{
		bucket: b,
	}
}

// First positions the cursor at the first key/value pair and returns
// the pair.
func (c *readWriteCursor) First() ([]byte, []byte) {
	var (
		key   []byte
		value []byte
	)
	err := c.bucket.tx.tx.QueryRowContext(
		c.bucket.tx.db.ctx,
		"SELECT key, value FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" ORDER BY key LIMIT 1",
	).Scan(&key, &value)

	switch {
	case err == sql.ErrNoRows:
		return nil, nil

	case err != nil:
		panic(err)
	}

	// Copy current key to prevent modification by the caller.
	c.currKey = make([]byte, len(key))
	copy(c.currKey, key)

	return key, value
}

// Last positions the cursor at the last key/value pair and returns the
// pair.
func (c *readWriteCursor) Last() ([]byte, []byte) {
	var (
		key   []byte
		value []byte
	)
	err := c.bucket.tx.tx.QueryRowContext(
		c.bucket.tx.db.ctx,
		"SELECT key, value FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" ORDER BY key DESC LIMIT 1",
	).Scan(&key, &value)

	switch {
	case err == sql.ErrNoRows:
		return nil, nil

	case err != nil:
		panic(err)
	}

	// Copy current key to prevent modification by the caller.
	c.currKey = make([]byte, len(key))
	copy(c.currKey, key)

	return key, value
}

// Next moves the cursor one key/value pair forward and returns the new
// pair.
func (c *readWriteCursor) Next() ([]byte, []byte) {
	var (
		key   []byte
		value []byte
	)
	err := c.bucket.tx.tx.QueryRowContext(
		c.bucket.tx.db.ctx,
		"SELECT key, value FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" AND key>$1 ORDER BY key LIMIT 1",
		c.currKey,
	).Scan(&key, &value)

	switch {
	case err == sql.ErrNoRows:
		return nil, nil

	case err != nil:
		panic(err)
	}

	// Copy current key to prevent modification by the caller.
	c.currKey = make([]byte, len(key))
	copy(c.currKey, key)

	return key, value
}

// Prev moves the cursor one key/value pair backward and returns the new
// pair.
func (c *readWriteCursor) Prev() ([]byte, []byte) {
	var (
		key   []byte
		value []byte
	)
	err := c.bucket.tx.tx.QueryRowContext(
		c.bucket.tx.db.ctx,
		"SELECT key, value FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" AND key<$1 ORDER BY key DESC LIMIT 1",
		c.currKey,
	).Scan(&key, &value)

	switch {
	case err == sql.ErrNoRows:
		return nil, nil

	case err != nil:
		panic(err)
	}

	// Copy current key to prevent modification by the caller.
	c.currKey = make([]byte, len(key))
	copy(c.currKey, key)

	return key, value
}

// Seek positions the cursor at the passed seek key.  If the key does
// not exist, the cursor is moved to the next key after seek.  Returns
// the new pair.
func (c *readWriteCursor) Seek(seek []byte) ([]byte, []byte) {
	// Convert nil to empty slice, otherwise sql mapping won't be correct
	// and no keys are found.
	if seek == nil {
		seek = []byte{}
	}

	var (
		key   []byte
		value []byte
	)
	err := c.bucket.tx.tx.QueryRowContext(
		c.bucket.tx.db.ctx,
		"SELECT key, value FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" AND key>=$1 ORDER BY key LIMIT 1",
		seek,
	).Scan(&key, &value)

	switch {
	case err == sql.ErrNoRows:
		return nil, nil

	case err != nil:
		panic(err)
	}

	// Copy current key to prevent modification by the caller.
	c.currKey = make([]byte, len(key))
	copy(c.currKey, key)

	return key, value
}

// Delete removes the current key/value pair the cursor is at without
// invalidating the cursor.  Returns ErrIncompatibleValue if attempted
// when the cursor points to a nested bucket.
func (c *readWriteCursor) Delete() error {
	// Get first record at or after cursor.
	var key []byte
	err := c.bucket.tx.tx.QueryRowContext(
		c.bucket.tx.db.ctx,
		"SELECT key FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" AND key>=$1 ORDER BY key LIMIT 1",
		c.currKey,
	).Scan(&key)

	switch {
	case err == sql.ErrNoRows:
		return nil

	case err != nil:
		panic(err)
	}

	// Delete record.
	result, err := c.bucket.tx.tx.ExecContext(
		c.bucket.tx.db.ctx,
		"DELETE FROM "+c.bucket.table+" WHERE "+
			parentSelector(c.bucket.id)+
			" AND key=$1 AND value IS NOT NULL",
		key,
	)
	if err != nil {
		panic(err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	// The key exists but nothing has been deleted. This means that the key
	// must have been a bucket key.
	if rows != 1 {
		return walletdb.ErrIncompatibleValue
	}

	return err
}
