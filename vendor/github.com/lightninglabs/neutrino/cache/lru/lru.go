package lru

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/lightninglabs/neutrino/cache"
)

// elementMap is an alias for a map from a generic interface to a list.Element.
type elementMap map[interface{}]*list.Element

// entry represents a (key,value) pair entry in the Cache. The Cache's list
// stores entries which let us get the cache key when an entry is evicted.
type entry struct {
	key   interface{}
	value cache.Value
}

// Cache provides a generic thread-safe lru cache that can be used for
// storing filters, blocks, etc.
type Cache struct {
	// capacity represents how much this cache can hold. It could be number
	// of elements or a number of bytes, decided by the cache.Value's Size.
	capacity uint64

	// size represents the size of all the elements currenty in the cache.
	size uint64

	// ll is a doubly linked list which keeps track of recency of used
	// elements by moving them to the front.
	ll *list.List

	// cache is a generic cache which allows us to find an elements position
	// in the ll list from a given key.
	cache elementMap

	// mtx is used to make sure the Cache is thread-safe.
	mtx sync.RWMutex
}

// NewCache return a cache with specified capacity, the cache's size can't
// exceed that given capacity.
func NewCache(capacity uint64) *Cache {
	return &Cache{
		capacity: capacity,
		ll:       list.New(),
		cache:    make(elementMap),
	}
}

// evict will evict as many elements as necessary to make enough space for a new
// element with size needed to be inserted.
func (c *Cache) evict(needed uint64) (bool, error) {
	if needed > c.capacity {
		return false, fmt.Errorf("can't evict %v elements in size, "+
			"since capacity is %v", needed, c.capacity)
	}

	evicted := false
	for c.capacity-c.size < needed {
		// We still need to evict some more elements.
		if c.ll.Len() == 0 {
			// We should never reach here.
			return false, fmt.Errorf("all elements got evicted, "+
				"yet still need to evict %v, likelihood of "+
				"error during size calculation",
				needed-(c.capacity-c.size))
		}

		// Find the least recently used item.
		if elr := c.ll.Back(); elr != nil {
			// Determine lru item's size.
			ce := elr.Value.(*entry)
			es, err := ce.value.Size()
			if err != nil {
				return false, fmt.Errorf("couldn't determine "+
					"size of existing cache value %v", err)
			}

			// Account for that element's removal in evicted and
			// cache size.
			c.size -= es

			// Remove the element from the cache.
			c.ll.Remove(elr)
			delete(c.cache, ce.key)
			evicted = true
		}
	}

	return evicted, nil
}

// Put inserts a given (key,value) pair into the cache, if the key already
// exists, it will replace value and update it to be most recent item in cache.
// The return value indicates whether items had to be evicted to make room for
// the new element.
func (c *Cache) Put(key interface{}, value cache.Value) (bool, error) {
	vs, err := value.Size()
	if err != nil {
		return false, fmt.Errorf("couldn't determine size of cache "+
			"value: %v", err)
	}

	if vs > c.capacity {
		return false, fmt.Errorf("can't insert entry of size %v into "+
			"cache with capacity %v", vs, c.capacity)
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// If the element already exists, remove it and decrease cache's size.
	el, ok := c.cache[key]
	if ok {
		es, err := el.Value.(*entry).value.Size()
		if err != nil {
			return false, fmt.Errorf("couldn't determine size of "+
				"existing cache value %v", err)
		}
		c.ll.Remove(el)
		c.size -= es
	}

	// Then we need to make sure we have enough space for the element, evict
	// elements if we need more space.
	evicted, err := c.evict(vs)
	if err != nil {
		return false, err
	}

	// We have made enough space in the cache, so just insert it.
	el = c.ll.PushFront(&entry{key, value})
	c.cache[key] = el
	c.size += vs

	return evicted, nil
}

// Get will return value for a given key, making the element the most recently
// accessed item in the process. Will return nil if the key isn't found.
func (c *Cache) Get(key interface{}) (cache.Value, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	el, ok := c.cache[key]
	if !ok {
		// Element not found in the cache.
		return nil, cache.ErrElementNotFound
	}

	// When the cache needs to evict a element to make space for another
	// one, it starts eviction from the back, so by moving this element to
	// the front, it's eviction is delayed because it's recently accessed.
	c.ll.MoveToFront(el)
	return el.Value.(*entry).value, nil
}

// Len returns number of elements in the cache.
func (c *Cache) Len() int {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.ll.Len()
}
