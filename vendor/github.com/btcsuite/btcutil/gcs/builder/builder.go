// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2017 The Lightning Network Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"crypto/rand"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
)

const (
	// DefaultP is the default collision probability (2^-19)
	DefaultP = 19

	// DefaultM is the default value used for the hash range.
	DefaultM uint64 = 784931
)

// GCSBuilder is a utility class that makes building GCS filters convenient.
type GCSBuilder struct {
	p uint8

	m uint64

	key [gcs.KeySize]byte

	// data is a set of entries represented as strings. This is done to
	// deduplicate items as they are added.
	data map[string]struct{}
	err  error
}

// RandomKey is a utility function that returns a cryptographically random
// [gcs.KeySize]byte usable as a key for a GCS filter.
func RandomKey() ([gcs.KeySize]byte, error) {
	var key [gcs.KeySize]byte

	// Read a byte slice from rand.Reader.
	randKey := make([]byte, gcs.KeySize)
	_, err := rand.Read(randKey)

	// This shouldn't happen unless the user is on a system that doesn't
	// have a system CSPRNG. OK to panic in this case.
	if err != nil {
		return key, err
	}

	// Copy the byte slice to a [gcs.KeySize]byte array and return it.
	copy(key[:], randKey[:])
	return key, nil
}

// DeriveKey is a utility function that derives a key from a chainhash.Hash by
// truncating the bytes of the hash to the appopriate key size.
func DeriveKey(keyHash *chainhash.Hash) [gcs.KeySize]byte {
	var key [gcs.KeySize]byte
	copy(key[:], keyHash.CloneBytes()[:])
	return key
}

// Key retrieves the key with which the builder will build a filter. This is
// useful if the builder is created with a random initial key.
func (b *GCSBuilder) Key() ([gcs.KeySize]byte, error) {
	// Do nothing if the builder's errored out.
	if b.err != nil {
		return [gcs.KeySize]byte{}, b.err
	}

	return b.key, nil
}

// SetKey sets the key with which the builder will build a filter to the passed
// [gcs.KeySize]byte.
func (b *GCSBuilder) SetKey(key [gcs.KeySize]byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	copy(b.key[:], key[:])
	return b
}

// SetKeyFromHash sets the key with which the builder will build a filter to a
// key derived from the passed chainhash.Hash using DeriveKey().
func (b *GCSBuilder) SetKeyFromHash(keyHash *chainhash.Hash) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	return b.SetKey(DeriveKey(keyHash))
}

// SetP sets the filter's probability after calling Builder().
func (b *GCSBuilder) SetP(p uint8) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	// Basic sanity check.
	if p > 32 {
		b.err = gcs.ErrPTooBig
		return b
	}

	b.p = p
	return b
}

// SetM sets the filter's modulous value after calling Builder().
func (b *GCSBuilder) SetM(m uint64) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	// Basic sanity check.
	if m > uint64(math.MaxUint32) {
		b.err = gcs.ErrPTooBig
		return b
	}

	b.m = m
	return b
}

// Preallocate sets the estimated filter size after calling Builder() to reduce
// the probability of memory reallocations. If the builder has already had data
// added to it, Preallocate has no effect.
func (b *GCSBuilder) Preallocate(n uint32) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	if b.data == nil {
		b.data = make(map[string]struct{}, n)
	}

	return b
}

// AddEntry adds a []byte to the list of entries to be included in the GCS
// filter when it's built.
func (b *GCSBuilder) AddEntry(data []byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	b.data[string(data)] = struct{}{}
	return b
}

// AddEntries adds all the []byte entries in a [][]byte to the list of entries
// to be included in the GCS filter when it's built.
func (b *GCSBuilder) AddEntries(data [][]byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	for _, entry := range data {
		b.AddEntry(entry)
	}
	return b
}

// AddHash adds a chainhash.Hash to the list of entries to be included in the
// GCS filter when it's built.
func (b *GCSBuilder) AddHash(hash *chainhash.Hash) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	return b.AddEntry(hash.CloneBytes())
}

// AddWitness adds each item of the passed filter stack to the filter, and then
// adds each item as a script.
func (b *GCSBuilder) AddWitness(witness wire.TxWitness) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	return b.AddEntries(witness)
}

// Build returns a function which builds a GCS filter with the given parameters
// and data.
func (b *GCSBuilder) Build() (*gcs.Filter, error) {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return nil, b.err
	}

	// We'll ensure that all the parmaters we need to actually build the
	// filter properly are set.
	if b.p == 0 {
		return nil, fmt.Errorf("p value is not set, cannot build")
	}
	if b.m == 0 {
		return nil, fmt.Errorf("m value is not set, cannot build")
	}

	dataSlice := make([][]byte, 0, len(b.data))
	for item := range b.data {
		dataSlice = append(dataSlice, []byte(item))
	}

	return gcs.BuildGCSFilter(b.p, b.m, b.key, dataSlice)
}

// WithKeyPNM creates a GCSBuilder with specified key and the passed
// probability, modulus and estimated filter size.
func WithKeyPNM(key [gcs.KeySize]byte, p uint8, n uint32, m uint64) *GCSBuilder {
	b := GCSBuilder{}
	return b.SetKey(key).SetP(p).SetM(m).Preallocate(n)
}

// WithKeyPM creates a GCSBuilder with specified key and the passed
// probability.  Estimated filter size is set to zero, which means more
// reallocations are done when building the filter.
func WithKeyPM(key [gcs.KeySize]byte, p uint8, m uint64) *GCSBuilder {
	return WithKeyPNM(key, p, 0, m)
}

// WithKey creates a GCSBuilder with specified key. Probability is set to 19
// (2^-19 collision probability). Estimated filter size is set to zero, which
// means more reallocations are done when building the filter.
func WithKey(key [gcs.KeySize]byte) *GCSBuilder {
	return WithKeyPNM(key, DefaultP, 0, DefaultM)
}

// WithKeyHashPNM creates a GCSBuilder with key derived from the specified
// chainhash.Hash and the passed probability and estimated filter size.
func WithKeyHashPNM(keyHash *chainhash.Hash, p uint8, n uint32,
	m uint64) *GCSBuilder {

	return WithKeyPNM(DeriveKey(keyHash), p, n, m)
}

// WithKeyHashPM creates a GCSBuilder with key derived from the specified
// chainhash.Hash and the passed probability. Estimated filter size is set to
// zero, which means more reallocations are done when building the filter.
func WithKeyHashPM(keyHash *chainhash.Hash, p uint8, m uint64) *GCSBuilder {
	return WithKeyHashPNM(keyHash, p, 0, m)
}

// WithKeyHash creates a GCSBuilder with key derived from the specified
// chainhash.Hash. Probability is set to 20 (2^-20 collision probability).
// Estimated filter size is set to zero, which means more reallocations are
// done when building the filter.
func WithKeyHash(keyHash *chainhash.Hash) *GCSBuilder {
	return WithKeyHashPNM(keyHash, DefaultP, 0, DefaultM)
}

// WithRandomKeyPNM creates a GCSBuilder with a cryptographically random key and
// the passed probability and estimated filter size.
func WithRandomKeyPNM(p uint8, n uint32, m uint64) *GCSBuilder {
	key, err := RandomKey()
	if err != nil {
		b := GCSBuilder{err: err}
		return &b
	}
	return WithKeyPNM(key, p, n, m)
}

// WithRandomKeyPM creates a GCSBuilder with a cryptographically random key and
// the passed probability. Estimated filter size is set to zero, which means
// more reallocations are done when building the filter.
func WithRandomKeyPM(p uint8, m uint64) *GCSBuilder {
	return WithRandomKeyPNM(p, 0, m)
}

// WithRandomKey creates a GCSBuilder with a cryptographically random key.
// Probability is set to 20 (2^-20 collision probability). Estimated filter
// size is set to zero, which means more reallocations are done when
// building the filter.
func WithRandomKey() *GCSBuilder {
	return WithRandomKeyPNM(DefaultP, 0, DefaultM)
}

// BuildBasicFilter builds a basic GCS filter from a block. A basic GCS filter
// will contain all the previous output scripts spent by inputs within a block,
// as well as the data pushes within all the outputs created within a block.
func BuildBasicFilter(block *wire.MsgBlock, prevOutScripts [][]byte) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := WithKeyHash(&blockHash)

	// If the filter had an issue with the specified key, then we force it
	// to bubble up here by calling the Key() function.
	_, err := b.Key()
	if err != nil {
		return nil, err
	}

	// In order to build a basic filter, we'll range over the entire block,
	// adding each whole script itself.
	for _, tx := range block.Transactions {
		// For each output in a transaction, we'll add each of the
		// individual data pushes within the script.
		for _, txOut := range tx.TxOut {
			if len(txOut.PkScript) == 0 {
				continue
			}

			// In order to allow the filters to later be committed
			// to within an OP_RETURN output, we ignore all
			// OP_RETURNs to avoid a circular dependency.
			if txOut.PkScript[0] == txscript.OP_RETURN {
				continue
			}

			b.AddEntry(txOut.PkScript)
		}
	}

	// In the second pass, we'll also add all the prevOutScripts
	// individually as elements.
	for _, prevScript := range prevOutScripts {
		if len(prevScript) == 0 {
			continue
		}

		b.AddEntry(prevScript)
	}

	return b.Build()
}

// GetFilterHash returns the double-SHA256 of the filter.
func GetFilterHash(filter *gcs.Filter) (chainhash.Hash, error) {
	filterData, err := filter.NBytes()
	if err != nil {
		return chainhash.Hash{}, err
	}

	return chainhash.DoubleHashH(filterData), nil
}

// MakeHeaderForFilter makes a filter chain header for a filter, given the
// filter and the previous filter chain header.
func MakeHeaderForFilter(filter *gcs.Filter, prevHeader chainhash.Hash) (chainhash.Hash, error) {
	filterTip := make([]byte, 2*chainhash.HashSize)
	filterHash, err := GetFilterHash(filter)
	if err != nil {
		return chainhash.Hash{}, err
	}

	// In the buffer we created above we'll compute hash || prevHash as an
	// intermediate value.
	copy(filterTip, filterHash[:])
	copy(filterTip[chainhash.HashSize:], prevHeader[:])

	// The final filter hash is the double-sha256 of the hash computed
	// above.
	return chainhash.DoubleHashH(filterTip), nil
}
