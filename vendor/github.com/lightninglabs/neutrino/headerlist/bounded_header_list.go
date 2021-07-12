package headerlist

// BoundedMemoryChain is an implemetnation of the headerlist.Chain interface
// which has a bounded size. The chain will be stored purely in memory. This is
// useful for enforcing that only the past N headers are stored in memory, or
// even as the primary header store. If an element inserted to the end of the
// chain exceeds the size limit, then the head of the chain will be moved
// forward removing a single entry from the head of the chain.
type BoundedMemoryChain struct {
	// headPtr points to the "front" of the chain. If the tailPtr is less
	// than this value, then we've wrapped around once. This value can
	// never exceed the maxSize value.
	headPtr int32

	// tailPtr points to the "tail" of the chain. This indexes into the
	// main chain slice which stores each node. This value can never exceed
	// the maxSize value.
	tailPtr int32

	// len is the length of the chain. This will be incremented for each
	// item inserted. This value can never exceed the maxSize value.
	len int32

	// maxSize is the max number of elements that should be kept int the
	// BoundedMemoryChain. Once we exceed this size, we'll start to wrap
	// the chain around.
	maxSize int32

	// chain is the primary store of the chain.
	chain []Node
}

// NewBoundedMemoryChain returns a new instance of the BoundedMemoryChain with
// a target max number of nodes.
func NewBoundedMemoryChain(maxNodes uint32) *BoundedMemoryChain {
	return &BoundedMemoryChain{
		headPtr: -1,
		tailPtr: -1,
		maxSize: int32(maxNodes),
		chain:   make([]Node, maxNodes),
	}
}

// A compile time constant to ensure that BoundedMemoryChain meets the Chain
// interface.
var _ Chain = (*BoundedMemoryChain)(nil)

// ResetHeaderState resets the state of all nodes. After this method, it will
// be as if the chain was just newly created.
//
// NOTE: Part of the Chain interface.
func (b *BoundedMemoryChain) ResetHeaderState(n Node) {
	b.headPtr = -1
	b.tailPtr = -1
	b.len = 0

	b.PushBack(n)
}

// Back returns the end of the chain. If the chain is empty, then this return a
// pointer to a nil node.
//
// NOTE: Part of the Chain interface.
func (b *BoundedMemoryChain) Back() *Node {
	if b.tailPtr == -1 && b.headPtr == -1 {
		return nil
	}

	return &b.chain[b.tailPtr]
}

// Front returns the head of the chain. If the chain is empty, then this
// returns a  pointer to a nil node.
//
// NOTE: Part of the Chain interface.
func (b *BoundedMemoryChain) Front() *Node {
	if b.tailPtr == -1 && b.headPtr == -1 {
		return nil
	}

	return &b.chain[b.headPtr]
}

// PushBack will push a new entry to the end of the chain. The entry added to
// the chain is also returned in place. As the chain is bounded, if the length
// of the chain is exceeded, then the front of the chain will be walked forward
// one element.
//
// NOTE: Part of the Chain interface.
func (b *BoundedMemoryChain) PushBack(n Node) *Node {
	// Before we do any insertion, we'll fetch the prior element to be able
	// to easily set the prev pointer of the new entry.
	var prevElem *Node
	if b.tailPtr != -1 {
		prevElem = &b.chain[b.tailPtr]
	}

	// As we're adding to the chain, we'll increment the tail pointer and
	// clamp it down to the max size.
	b.tailPtr++
	b.tailPtr %= b.maxSize

	// If we've wrapped around, or this is the first insertion, then we'll
	// increment the head pointer as well so it tracks the "start" of the
	// queue properly.
	if b.tailPtr <= b.headPtr || b.headPtr == -1 {
		b.headPtr++
		b.headPtr %= b.maxSize

		// As this is the new head of the chain, we'll set its prev
		// pointer to nil.
		b.chain[b.headPtr].prev = nil
	}

	// Now that we've updated the header and tail pointer, we can add the
	// new element to our backing slice, and also update its index within
	// the current chain.
	chainIndex := b.tailPtr
	b.chain[chainIndex] = n

	// If this isn't the very fist element we're inserting, then we'll set
	// its prev pointer to the prior node.

	// Now that we've inserted this new element, we'll set the prev pointer
	// to the prior element. If this is the first element, then we'll just
	// set the nil value again.
	b.chain[chainIndex].prev = prevElem

	// Finally, we'll increment the length of the chain, and clamp down the
	// size if needed to the max possible length.
	b.len++
	if b.len > b.maxSize {
		b.len = b.maxSize
	}

	return &b.chain[chainIndex]
}
