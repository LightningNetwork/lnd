package query

// Task is an interface that has a method for returning their index in the
// work queue.
type Task interface {
	// Index returns this Task's index in the work queue.
	Index() uint64
}

// workQueue is struct implementing the heap interface, and is used to keep a
// list of remaining queryTasks in order.
type workQueue struct {
	tasks []Task
}

// Len returns the number of nodes in the priority queue.
//
// NOTE: This is part of the heap.Interface implementation.
func (w *workQueue) Len() int { return len(w.tasks) }

// Less returns whether the item in the priority queue with index i should sort
// before the item with index j.
//
// NOTE: This is part of the heap.Interface implementation.
func (w *workQueue) Less(i, j int) bool {
	return w.tasks[i].Index() < w.tasks[j].Index()
}

// Swap swaps the nodes at the passed indices in the priority queue.
//
// NOTE: This is part of the heap.Interface implementation.
func (w *workQueue) Swap(i, j int) {
	w.tasks[i], w.tasks[j] = w.tasks[j], w.tasks[i]
}

// Push add x as elemement Len().
//
// NOTE: This is part of the heap.Interface implementation.
func (w *workQueue) Push(x interface{}) {
	w.tasks = append(w.tasks, x.(Task))
}

// Pop removes and returns element Len()-1.
//
// NOTE: This is part of the heap.Interface implementation.
func (w *workQueue) Pop() interface{} {
	n := len(w.tasks)
	x := w.tasks[n-1]
	w.tasks[n-1] = nil
	w.tasks = w.tasks[0 : n-1]
	return x
}

// Peek returns the first item in the queue.
func (w *workQueue) Peek() interface{} {
	return w.tasks[0]
}
