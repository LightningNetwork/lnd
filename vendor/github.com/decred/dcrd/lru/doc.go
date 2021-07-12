// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package lru implements a generic least-recently-used cache with near O(1) perf.

LRU Cache

A least-recently-used (LRU) cache is a cache that holds a limited number of
items with an eviction policy such that when the capacity of the cache is
exceeded, the least-recently-used item is automatically removed when inserting a
new item.  The meaining of used in this implementation is either accessing the
item via a lookup or adding the item into the cache, including when the item
already exists.

External Use

This package has intentionally been designed so it can be used as a standalone
package for any projects needing to make use of a well-test least-recently-used
cache with near O(1) performance characteristics for lookups, inserts, and
deletions.
*/
package lru
