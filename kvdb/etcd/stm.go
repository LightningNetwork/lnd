// +build kvdb_etcd

package etcd

import (
	"context"
	"fmt"
	"math"
	"strings"

	v3 "go.etcd.io/etcd/client/v3"
)

type CommitStats struct {
	Rset    int
	Wset    int
	Retries int
}

// KV stores a key/value pair.
type KV struct {
	key string
	val string
}

// STM is an interface for software transactional memory.
// All calls that return error will do so only if STM is manually handled and
// abort the apply closure otherwise. In both case the returned error is a
// DatabaseError.
type STM interface {
	// Get returns the value for a key and inserts the key in the txn's read
	// set. Returns nil if there's no matching key, or the key is empty.
	Get(key string) ([]byte, error)

	// Put adds a value for a key to the txn's write set.
	Put(key, val string)

	// Del adds a delete operation for the key to the txn's write set.
	Del(key string)

	// First returns the first k/v that begins with prefix or nil if there's
	// no such k/v pair. If the key is found it is inserted to the txn's
	// read set. Returns nil if there's no match.
	First(prefix string) (*KV, error)

	// Last returns the last k/v that begins with prefix or nil if there's
	// no such k/v pair. If the key is found it is inserted to the txn's
	// read set. Returns nil if there's no match.
	Last(prefix string) (*KV, error)

	// Prev returns the previous k/v before key that begins with prefix or
	// nil if there's no such k/v. If the key is found it is inserted to the
	// read set. Returns nil if there's no match.
	Prev(prefix, key string) (*KV, error)

	// Next returns the next k/v after key that begins with prefix or nil
	// if there's no such k/v. If the key is found it is inserted to the
	// txn's read set. Returns nil if there's no match.
	Next(prefix, key string) (*KV, error)

	// Seek will return k/v at key beginning with prefix. If the key doesn't
	// exists Seek will return the next k/v after key beginning with prefix.
	// If a matching k/v is found it is inserted to the txn's read set. Returns
	// nil if there's no match.
	Seek(prefix, key string) (*KV, error)

	// OnCommit calls the passed callback func upon commit.
	OnCommit(func())

	// Commit attempts to apply the txn's changes to the server.
	// Commit may return CommitError if transaction is outdated and needs retry.
	Commit() error

	// Rollback emties the read and write sets such that a subsequent commit
	// won't alter the database.
	Rollback()
}

// CommitError is used to check if there was an error
// due to stale data in the transaction.
type CommitError struct{}

// Error returns a static string for CommitError for
// debugging/logging purposes.
func (e CommitError) Error() string {
	return "commit failed"
}

// DatabaseError is used to wrap errors that are not
// related to stale data in the transaction.
type DatabaseError struct {
	msg string
	err error
}

// Unwrap returns the wrapped error in a DatabaseError.
func (e *DatabaseError) Unwrap() error {
	return e.err
}

// Error simply converts DatabaseError to a string that
// includes both the message and the wrapped error.
func (e DatabaseError) Error() string {
	return fmt.Sprintf("etcd error: %v - %v", e.msg, e.err)
}

// stmGet is the result of a read operation,
// a value and the mod revision of the key/value.
type stmGet struct {
	val string
	rev int64
}

// readSet stores all reads done in an STM.
type readSet map[string]stmGet

// stmPut stores a value and an operation (put/delete).
type stmPut struct {
	val string
	op  v3.Op
}

// writeSet stroes all writes done in an STM.
type writeSet map[string]stmPut

// stm implements repeatable-read software transactional memory
// over etcd.
type stm struct {
	// client is an etcd client handling all RPC communications
	// to the etcd instance/cluster.
	client *v3.Client

	// manual is set to true for manual transactions which don't
	// execute in the STM run loop.
	manual bool

	// txQueue is lightweight contention manager, which is used to detect
	// transaction conflicts and reduce retries.
	txQueue *commitQueue

	// options stores optional settings passed by the user.
	options *STMOptions

	// prefetch hold prefetched key values and revisions.
	prefetch readSet

	// rset holds read key values and revisions.
	rset readSet

	// wset holds overwritten keys and their values.
	wset writeSet

	// getOpts are the opts used for gets.
	getOpts []v3.OpOption

	// revision stores the snapshot revision after first read.
	revision int64

	// onCommit gets called upon commit.
	onCommit func()
}

// STMOptions can be used to pass optional settings
// when an STM is created.
type STMOptions struct {
	// ctx holds an externally provided abort context.
	ctx                 context.Context
	commitStatsCallback func(bool, CommitStats)
}

// STMOptionFunc is a function that updates the passed STMOptions.
type STMOptionFunc func(*STMOptions)

// WithAbortContext specifies the context for permanently
// aborting the transaction.
func WithAbortContext(ctx context.Context) STMOptionFunc {
	return func(so *STMOptions) {
		so.ctx = ctx
	}
}

func WithCommitStatsCallback(cb func(bool, CommitStats)) STMOptionFunc {
	return func(so *STMOptions) {
		so.commitStatsCallback = cb
	}
}

// RunSTM runs the apply function by creating an STM using serializable snapshot
// isolation, passing it to the apply and handling commit errors and retries.
func RunSTM(cli *v3.Client, apply func(STM) error, txQueue *commitQueue,
	so ...STMOptionFunc) error {

	return runSTM(makeSTM(cli, false, txQueue, so...), apply)
}

// NewSTM creates a new STM instance, using serializable snapshot isolation.
func NewSTM(cli *v3.Client, txQueue *commitQueue, so ...STMOptionFunc) STM {
	return makeSTM(cli, true, txQueue, so...)
}

// makeSTM is the actual constructor of the stm. It first apply all passed
// options then creates the stm object and resets it before returning.
func makeSTM(cli *v3.Client, manual bool, txQueue *commitQueue,
	so ...STMOptionFunc) *stm {

	opts := &STMOptions{
		ctx: cli.Ctx(),
	}

	// Apply all functional options.
	for _, fo := range so {
		fo(opts)
	}

	s := &stm{
		client:   cli,
		manual:   manual,
		txQueue:  txQueue,
		options:  opts,
		prefetch: make(map[string]stmGet),
	}

	// Reset read and write set.
	s.Rollback()

	return s
}

// runSTM implements the run loop of the STM, running the apply func, catching
// errors and handling commit. The loop will quit on every error except
// CommitError which is used to indicate a necessary retry.
func runSTM(s *stm, apply func(STM) error) error {
	var (
		retries    int
		stats      CommitStats
		executeErr error
	)

	done := make(chan struct{})

	execute := func() {
		defer close(done)

		for {
			select {
			// Check if the STM is aborted and break the retry loop
			// if it is.
			case <-s.options.ctx.Done():
				executeErr = fmt.Errorf("aborted")
				return

			default:
			}

			stats, executeErr = s.commit()

			// Re-apply only upon commit error (meaning the
			// keys were changed).
			if _, ok := executeErr.(CommitError); !ok {
				// Anything that's not a CommitError
				// aborts the transaction.
				return
			}

			// Rollback before trying to re-apply.
			s.Rollback()
			retries++

			// Re-apply the transaction closure.
			if executeErr = apply(s); executeErr != nil {
				return
			}
		}
	}

	// Run the tx closure to construct the read and write sets.
	// Also we expect that if there are no conflicting transactions
	// in the queue, then we only run apply once.
	if preApplyErr := apply(s); preApplyErr != nil {
		return preApplyErr
	}

	// Queue up the transaction for execution.
	s.txQueue.Add(execute, s.rset, s.wset)

	// Wait for the transaction to execute, or break if aborted.
	select {
	case <-done:
	case <-s.options.ctx.Done():
	}

	s.txQueue.Done(s.rset, s.wset)

	if s.options.commitStatsCallback != nil {
		stats.Retries = retries
		s.options.commitStatsCallback(executeErr == nil, stats)
	}

	return executeErr
}

// add inserts a txn response to the read set. This is useful when the txn
// fails due to conflict where the txn response can be used to prefetch
// key/values.
func (rs readSet) add(txnResp *v3.TxnResponse) {
	for _, resp := range txnResp.Responses {
		getResp := (*v3.GetResponse)(resp.GetResponseRange())
		for _, kv := range getResp.Kvs {
			rs[string(kv.Key)] = stmGet{
				val: string(kv.Value),
				rev: kv.ModRevision,
			}
		}
	}
}

// gets is a helper to create an op slice for transaction
// construction.
func (rs readSet) gets() []v3.Op {
	ops := make([]v3.Op, 0, len(rs))

	for k := range rs {
		ops = append(ops, v3.OpGet(k))
	}

	return ops
}

// cmps returns a compare list which will serve as a precondition testing that
// the values in the read set didn't change.
func (rs readSet) cmps() []v3.Cmp {
	cmps := make([]v3.Cmp, 0, len(rs))
	for key, getValue := range rs {
		cmps = append(cmps, v3.Compare(
			v3.ModRevision(key), "=", getValue.rev,
		))
	}

	return cmps
}

// cmps returns a cmp list testing no writes have happened past rev.
func (ws writeSet) cmps(rev int64) []v3.Cmp {
	cmps := make([]v3.Cmp, 0, len(ws))
	for key := range ws {
		cmps = append(cmps, v3.Compare(v3.ModRevision(key), "<", rev))
	}

	return cmps
}

// puts is the list of ops for all pending writes.
func (ws writeSet) puts() []v3.Op {
	puts := make([]v3.Op, 0, len(ws))
	for _, v := range ws {
		puts = append(puts, v.op)
	}

	return puts
}

// fetch is a helper to fetch key/value given options. If a value is returned
// then fetch will try to fix the STM's snapshot revision (if not already set).
// We'll also cache the returned key/value in the read set.
func (s *stm) fetch(key string, opts ...v3.OpOption) ([]KV, error) {
	resp, err := s.client.Get(
		s.options.ctx, key, append(opts, s.getOpts...)...,
	)
	if err != nil {
		return nil, DatabaseError{
			msg: "stm.fetch() failed",
			err: err,
		}
	}

	// Set revison and serializable options upon first fetch
	// for any subsequent fetches.
	if s.getOpts == nil {
		s.revision = resp.Header.Revision
		s.getOpts = []v3.OpOption{
			v3.WithRev(s.revision),
			v3.WithSerializable(),
		}
	}

	if len(resp.Kvs) == 0 {
		// Add assertion to the read set which will extend our commit
		// constraint such that the commit will fail if the key is
		// present in the database.
		s.rset[key] = stmGet{
			rev: 0,
		}
	}

	var result []KV

	// Fill the read set with key/values returned.
	for _, kv := range resp.Kvs {
		// Remove from prefetch.
		key := string(kv.Key)
		val := string(kv.Value)

		delete(s.prefetch, key)

		// Add to read set.
		s.rset[key] = stmGet{
			val: val,
			rev: kv.ModRevision,
		}

		result = append(result, KV{key, val})
	}

	return result, nil
}

// Get returns the value for key. If there's no such
// key/value in the database or the passed key is empty
// Get will return nil.
func (s *stm) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, nil
	}

	// Return freshly written value if present.
	if put, ok := s.wset[key]; ok {
		if put.op.IsDelete() {
			return nil, nil
		}

		return []byte(put.val), nil
	}

	// Populate read set if key is present in
	// the prefetch set.
	if getValue, ok := s.prefetch[key]; ok {
		delete(s.prefetch, key)

		// Use the prefetched value only if it is for
		// an existing key.
		if getValue.rev != 0 {
			s.rset[key] = getValue
		}
	}

	// Return value if alread in read set.
	if getValue, ok := s.rset[key]; ok {
		// Return the value if the rset contains an existing key.
		if getValue.rev != 0 {
			return []byte(getValue.val), nil
		} else {
			return nil, nil
		}
	}

	// Fetch and return value.
	kvs, err := s.fetch(key)
	if err != nil {
		return nil, err
	}

	if len(kvs) > 0 {
		return []byte(kvs[0].val), nil
	}

	// Return empty result if key not in DB.
	return nil, nil
}

// First returns the first key/value matching prefix. If there's no key starting
// with prefix, Last will return nil.
func (s *stm) First(prefix string) (*KV, error) {
	return s.next(prefix, prefix, true)
}

// Last returns the last key/value with prefix. If there's no key starting with
// prefix, Last will return nil.
func (s *stm) Last(prefix string) (*KV, error) {
	// As we don't know the full range, fetch the last
	// key/value with this prefix first.
	resp, err := s.fetch(prefix, v3.WithLastKey()...)
	if err != nil {
		return nil, err
	}

	var (
		kv    KV
		found bool
	)

	if len(resp) > 0 {
		kv = resp[0]
		found = true
	}

	// Now make sure there's nothing in the write set
	// that is a better match, meaning it has the same
	// prefix but is greater or equal than the current
	// best candidate. Note that this is not efficient
	// when the write set is large!
	for k, put := range s.wset {
		if put.op.IsDelete() {
			continue
		}

		if strings.HasPrefix(k, prefix) && k >= kv.key {
			kv.key = k
			kv.val = put.val
			found = true
		}
	}

	if found {
		return &kv, nil
	}

	return nil, nil
}

// Prev returns the prior key/value before key (with prefix). If there's no such
// key Next will return nil.
func (s *stm) Prev(prefix, startKey string) (*KV, error) {
	var result KV

	fetchKey := startKey
	matchFound := false

	for {
		// Ask etcd to retrieve one key that is a
		// match in descending order from the passed key.
		opts := []v3.OpOption{
			v3.WithRange(fetchKey),
			v3.WithSort(v3.SortByKey, v3.SortDescend),
			v3.WithLimit(1),
		}

		kvs, err := s.fetch(prefix, opts...)
		if err != nil {
			return nil, err
		}

		if len(kvs) == 0 {
			break
		}

		kv := &kvs[0]

		// WithRange and WithPrefix can't be used
		// together, so check prefix here. If the
		// returned key no longer has the prefix,
		// then break out.
		if !strings.HasPrefix(kv.key, prefix) {
			break
		}

		// Fetch the prior key if this is deleted.
		if put, ok := s.wset[kv.key]; ok && put.op.IsDelete() {
			fetchKey = kv.key
			continue
		}

		result = *kv
		matchFound = true

		break
	}

	// Closre holding all checks to find a possibly
	// better match.
	matches := func(key string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}

		if !matchFound {
			return key < startKey
		}

		// matchFound == true
		return result.key <= key && key < startKey
	}

	// Now go trough the write set and check
	// if there's an even better match.
	for k, put := range s.wset {
		if !put.op.IsDelete() && matches(k) {
			result.key = k
			result.val = put.val
			matchFound = true
		}
	}

	if !matchFound {
		return nil, nil
	}

	return &result, nil
}

// Next returns the next key/value after key (with prefix). If there's no such
// key Next will return nil.
func (s *stm) Next(prefix string, key string) (*KV, error) {
	return s.next(prefix, key, false)
}

// Seek "seeks" to the key (with prefix). If the key doesn't exists it'll get
// the next key with the same prefix. If no key fills this criteria, Seek will
// return nil.
func (s *stm) Seek(prefix, key string) (*KV, error) {
	return s.next(prefix, key, true)
}

// next will try to retrieve the next match that has prefix and starts with the
// passed startKey. If includeStartKey is set to true, it'll return the value
// of startKey (essentially implementing seek).
func (s *stm) next(prefix, startKey string, includeStartKey bool) (*KV, error) {
	var result KV

	fetchKey := startKey
	firstFetch := true
	matchFound := false

	for {
		// Ask etcd to retrieve one key that is a
		// match in ascending order from the passed key.
		opts := []v3.OpOption{
			v3.WithFromKey(),
			v3.WithSort(v3.SortByKey, v3.SortAscend),
			v3.WithLimit(1),
		}

		// By default we include the start key too
		// if it is a full match.
		if includeStartKey && firstFetch {
			firstFetch = false
		} else {
			// If we'd like to retrieve the first key
			// after the start key.
			fetchKey += "\x00"
		}

		kvs, err := s.fetch(fetchKey, opts...)
		if err != nil {
			return nil, err
		}

		if len(kvs) == 0 {
			break
		}

		kv := &kvs[0]
		// WithRange and WithPrefix can't be used
		// together, so check prefix here. If the
		// returned key no longer has the prefix,
		// then break the fetch loop.
		if !strings.HasPrefix(kv.key, prefix) {
			break
		}

		// Move on to fetch starting with the next
		// key if this one is marked deleted.
		if put, ok := s.wset[kv.key]; ok && put.op.IsDelete() {
			fetchKey = kv.key
			continue
		}

		result = *kv
		matchFound = true

		break
	}

	// Closure holding all checks to find a possibly
	// better match.
	matches := func(k string) bool {
		if !strings.HasPrefix(k, prefix) {
			return false
		}

		if includeStartKey && !matchFound {
			return startKey <= k
		}

		if !includeStartKey && !matchFound {
			return startKey < k
		}

		if includeStartKey && matchFound {
			return startKey <= k && k <= result.key
		}

		// !includeStartKey && matchFound.
		return startKey < k && k <= result.key
	}

	// Now go trough the write set and check
	// if there's an even better match.
	for k, put := range s.wset {
		if !put.op.IsDelete() && matches(k) {
			result.key = k
			result.val = put.val
			matchFound = true
		}
	}

	if !matchFound {
		return nil, nil
	}

	return &result, nil
}

// Put sets the value of the passed key. The actual put will happen upon commit.
func (s *stm) Put(key, val string) {
	s.wset[key] = stmPut{
		val: val,
		op:  v3.OpPut(key, val),
	}
}

// Del marks a key as deleted. The actual delete will happen upon commit.
func (s *stm) Del(key string) {
	s.wset[key] = stmPut{
		val: "",
		op:  v3.OpDelete(key),
	}
}

// OnCommit sets the callback that is called upon committing the STM
// transaction.
func (s *stm) OnCommit(cb func()) {
	s.onCommit = cb
}

// commit builds the final transaction and tries to execute it. If commit fails
// because the keys have changed return a CommitError, otherwise return a
// DatabaseError.
func (s *stm) commit() (CommitStats, error) {
	rset := s.rset.cmps()
	wset := s.wset.cmps(s.revision + 1)

	stats := CommitStats{
		Rset: len(rset),
		Wset: len(wset),
	}

	// Create the compare set.
	cmps := append(rset, wset...)
	// Create a transaction with the optional abort context.
	txn := s.client.Txn(s.options.ctx)

	// If the compare set holds, try executing the puts.
	txn = txn.If(cmps...)
	txn = txn.Then(s.wset.puts()...)

	// Prefetch keys in case of conflict to save
	// a round trip to etcd.
	txn = txn.Else(s.rset.gets()...)

	txnresp, err := txn.Commit()
	if err != nil {
		return stats, DatabaseError{
			msg: "stm.Commit() failed",
			err: err,
		}
	}

	// Call the commit callback if the transaction
	// was successful.
	if txnresp.Succeeded {
		if s.onCommit != nil {
			s.onCommit()
		}

		return stats, nil
	}

	// Load prefetch before if commit failed.
	s.rset.add(txnresp)
	s.prefetch = s.rset

	// Return CommitError indicating that the transaction
	// can be retried.
	return stats, CommitError{}
}

// Commit simply calls commit and the commit stats callback if set.
func (s *stm) Commit() error {
	stats, err := s.commit()

	if s.options.commitStatsCallback != nil {
		s.options.commitStatsCallback(err == nil, stats)
	}

	return err
}

// Rollback resets the STM. This is useful for uncommitted transaction rollback
// and also used in the STM main loop to reset state if commit fails.
func (s *stm) Rollback() {
	s.rset = make(map[string]stmGet)
	s.wset = make(map[string]stmPut)
	s.getOpts = nil
	s.revision = math.MaxInt64 - 1
}
