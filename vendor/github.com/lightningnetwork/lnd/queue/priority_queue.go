package queue

import (
	"container/heap"
)

// PriorityQueueItem is an interface that represents items in a PriorityQueue.
// Users of PriorityQueue will need to define a Less function such that
// PriorityQueue will be able to use that to build and restore an underlying
// heap.
type PriorityQueueItem interface {
	// Less must return true if this item is ordered before other and false
	// otherwise.
	Less(other PriorityQueueItem) bool
}

type priorityQueue []PriorityQueueItem

// Len returns the length of the priorityQueue.
func (pq priorityQueue) Len() int { return len(pq) }

// Less is used to order PriorityQueueItem items in the queue.
func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].Less(pq[j])
}

// Swap swaps two items in the priorityQueue. Swap is used by heap.Interface.
func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

// Push adds a new item the the priorityQueue.
func (pq *priorityQueue) Push(x interface{}) {
	item := x.(PriorityQueueItem)
	*pq = append(*pq, item)
}

// Pop removes the top item from the priorityQueue.
func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*pq = old[0 : n-1]
	return item
}

// PriorityQueue wraps a standard heap into a self contained class.
type PriorityQueue struct {
	queue priorityQueue
}

// Len returns the length of the queue.
func (pq *PriorityQueue) Len() int {
	return len(pq.queue)
}

// Empty returns true if the queue is empty.
func (pq *PriorityQueue) Empty() bool {
	return len(pq.queue) == 0
}

// Push adds an item to the priority queue.
func (pq *PriorityQueue) Push(item PriorityQueueItem) {
	heap.Push(&pq.queue, item)
}

// Pop removes the top most item from the queue.
func (pq *PriorityQueue) Pop() PriorityQueueItem {
	return heap.Pop(&pq.queue).(PriorityQueueItem)
}

// Top returns the top most item from the queue without removing it.
func (pq *PriorityQueue) Top() PriorityQueueItem {
	return pq.queue[0]
}
