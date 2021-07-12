package queue

import (
	"errors"
)

// errInvalidSize is returned when an invalid size for a buffer is provided.
var errInvalidSize = errors.New("buffer size must be > 0")

// CircularBuffer is a buffer which retains a set of values in memory, and
// overwrites the oldest item in the buffer when a new item needs to be
// written.
type CircularBuffer struct {
	// total is the total number of items that have been added to the
	// buffer.
	total int

	// items is the set of buffered items.
	items []interface{}
}

// NewCircularBuffer returns a new circular buffer with the size provided. It
// will fail if a zero or negative size parameter is provided.
func NewCircularBuffer(size int) (*CircularBuffer, error) {
	if size <= 0 {
		return nil, errInvalidSize
	}

	return &CircularBuffer{
		total: 0,

		// Create a slice with length and capacity equal to the size of
		// the buffer so that we do not need to resize the underlying
		// array when we add items.
		items: make([]interface{}, size),
	}, nil
}

// index returns the index that should be written to next.
func (c *CircularBuffer) index() int {
	return c.total % len(c.items)
}

// Add adds an item to the buffer, overwriting the oldest item if the buffer
// is full.
func (c *CircularBuffer) Add(item interface{}) {
	// Set the item in the next free index in the items array.
	c.items[c.index()] = item

	// Increment the total number of items that we have stored.
	c.total++
}

// List returns a copy of the items in the buffer ordered from the oldest to
// newest item.
func (c *CircularBuffer) List() []interface{} {
	size := cap(c.items)
	index := c.index()

	switch {
	// If no items have been stored yet, we can just return a nil list.
	case c.total == 0:
		return nil

	// If we have added fewer items than the buffer size, we can simply
	// return the total number of items from the beginning of the list
	// to the index. This special case is added because the oldest item
	// is at the beginning of the underlying array, not at the index when
	// we have not filled the array yet.
	case c.total < size:
		resp := make([]interface{}, c.total)
		copy(resp, c.items[:c.index()])
		return resp
	}

	resp := make([]interface{}, size)

	// Get the items in the underlying array from index to end, the first
	// item in this slice will be the oldest item in the list.
	firstHalf := c.items[index:]

	// Copy the first set into our response slice from index 0, so that
	// the response returned is from oldest to newest.
	copy(resp, firstHalf)

	// Get the items in the underlying array from beginning until the write
	// index, the last item in this slice will be the newest item in the
	// list.
	secondHalf := c.items[:index]

	// Copy the second set of items into the response slice offset by the
	// length of the first set of items so that we return a response which
	// is ordered from oldest to newest entry.
	copy(resp[len(firstHalf):], secondHalf)

	return resp
}

// Total returns the total number of items that have been added to the buffer.
func (c *CircularBuffer) Total() int {
	return c.total
}

// Latest returns the item that was most recently added to the buffer.
func (c *CircularBuffer) Latest() interface{} {
	// If no items have been added yet, return nil.
	if c.total == 0 {
		return nil
	}

	// The latest item is one before our total, mod by length.
	latest := (c.total - 1) % len(c.items)

	// Return the latest item added.
	return c.items[latest]
}
