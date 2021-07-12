package neutrino

import (
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/neutrino/headerfs"
)

// mockBlockHeaderStore is an implementation of the BlockHeaderStore backed by
// a simple map.
type mockBlockHeaderStore struct {
	headers map[chainhash.Hash]wire.BlockHeader
	heights map[uint32]wire.BlockHeader
}

// A compile-time check to ensure the mockBlockHeaderStore adheres to the
// BlockHeaderStore interface.
var _ headerfs.BlockHeaderStore = (*mockBlockHeaderStore)(nil)

// NewMockBlockHeaderStore returns a version of the BlockHeaderStore that's
// backed by an in-memory map. This instance is meant to be used by callers
// outside the package to unit test components that require a BlockHeaderStore
// interface.
func newMockBlockHeaderStore() *mockBlockHeaderStore {
	return &mockBlockHeaderStore{
		headers: make(map[chainhash.Hash]wire.BlockHeader),
		heights: make(map[uint32]wire.BlockHeader),
	}
}

func (m *mockBlockHeaderStore) ChainTip() (*wire.BlockHeader,
	uint32, error) {
	return nil, 0, nil

}
func (m *mockBlockHeaderStore) LatestBlockLocator() (
	blockchain.BlockLocator, error) {
	return nil, nil
}

func (m *mockBlockHeaderStore) FetchHeaderByHeight(height uint32) (
	*wire.BlockHeader, error) {

	if header, ok := m.heights[height]; ok {
		return &header, nil
	}

	return nil, headerfs.ErrHeightNotFound
}

func (m *mockBlockHeaderStore) FetchHeaderAncestors(uint32,
	*chainhash.Hash) ([]wire.BlockHeader, uint32, error) {

	return nil, 0, nil
}
func (m *mockBlockHeaderStore) HeightFromHash(*chainhash.Hash) (uint32, error) {
	return 0, nil

}
func (m *mockBlockHeaderStore) RollbackLastBlock() (*headerfs.BlockStamp,
	error) {
	return nil, nil
}

func (m *mockBlockHeaderStore) FetchHeader(h *chainhash.Hash) (
	*wire.BlockHeader, uint32, error) {
	if header, ok := m.headers[*h]; ok {
		return &header, 0, nil
	}
	return nil, 0, fmt.Errorf("not found")
}

func (m *mockBlockHeaderStore) WriteHeaders(headers ...headerfs.BlockHeader) error {
	for _, h := range headers {
		m.headers[h.BlockHash()] = *h.BlockHeader
	}

	return nil
}
