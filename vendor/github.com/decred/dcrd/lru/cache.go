// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package lru

import (
	"container/list"
	"sync"
)

// Cache provides a concurrency safe least-recently-used cache with nearly O(1)
// lookups, inserts, and deletions.  The cache is limited to a maximum number of
// items with eviction for the oldest entry when the limit is exceeded.
//
// The NewCache function must be used to create a usable cache since the zero
// value of this struct is not valid.
type Cache struct {
	mtx   sync.Mutex
	cache map[interface{}]*list.Element // nearly O(1) lookups
	list  *list.List                    // O(1) insert, update, delete
	limit uint
}

// Contains returns whether or not the passed item is a member of the cache.
//
// This function is safe for concurrent access.
func (m *Cache) Contains(item interface{}) bool {
	m.mtx.Lock()
	node, exists := m.cache[item]
	if exists {
		m.list.MoveToFront(node)
	}
	m.mtx.Unlock()

	return exists
}

// Add adds the passed item to the cache and handles eviction of the oldest item
// if adding the new item would exceed the max limit.  Adding an existing item
// makes it the most recently used item.
//
// This function is safe for concurrent access.
func (m *Cache) Add(item interface{}) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// When the limit is zero, nothing can be added to the cache, so just
	// return.
	if m.limit == 0 {
		return
	}

	// When the entry already exists move it to the front of the list thereby
	// marking it most recently used.
	if node, exists := m.cache[item]; exists {
		m.list.MoveToFront(node)
		return
	}

	// Evict the least recently used entry (back of the list) if the the new
	// entry would exceed the size limit for the cache.  Also reuse the list
	// node so a new one doesn't have to be allocated.
	if uint(len(m.cache))+1 > m.limit {
		node := m.list.Back()
		lru := node.Value

		// Evict least recently used item.
		delete(m.cache, lru)

		// Reuse the list node of the item that was just evicted for the new
		// item.
		node.Value = item
		m.list.MoveToFront(node)
		m.cache[item] = node
		return
	}

	// The limit hasn't been reached yet, so just add the new item.
	node := m.list.PushFront(item)
	m.cache[item] = node
}

// Delete deletes the passed item from the cache (if it exists).
//
// This function is safe for concurrent access.
func (m *Cache) Delete(item interface{}) {
	m.mtx.Lock()
	if node, exists := m.cache[item]; exists {
		m.list.Remove(node)
		delete(m.cache, item)
	}
	m.mtx.Unlock()
}

// Cache returns an initialized and empty LRU cache.  See the documentation for
// Cache for more details.
func NewCache(limit uint) Cache {
	return Cache{
		cache: make(map[interface{}]*list.Element),
		list:  list.New(),
		limit: limit,
	}
}
