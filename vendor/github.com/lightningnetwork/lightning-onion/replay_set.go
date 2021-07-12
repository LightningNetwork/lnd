package sphinx

import (
	"encoding/binary"
	"io"
)

// ReplaySet is a data structure used to efficiently record the occurrence of
// replays, identified by sequence number, when processing a Batch. Its primary
// functionality includes set construction, membership queries, and merging of
// replay sets.
type ReplaySet struct {
	replays map[uint16]struct{}
}

// NewReplaySet initializes an empty replay set.
func NewReplaySet() *ReplaySet {
	return &ReplaySet{
		replays: make(map[uint16]struct{}),
	}
}

// Size returns the number of elements in the replay set.
func (rs *ReplaySet) Size() int {
	return len(rs.replays)
}

// Add inserts the provided index into the replay set.
func (rs *ReplaySet) Add(idx uint16) {
	rs.replays[idx] = struct{}{}
}

// Contains queries the contents of the replay set for membership of a
// particular index.
func (rs *ReplaySet) Contains(idx uint16) bool {
	_, ok := rs.replays[idx]
	return ok
}

// Merge adds the contents of the provided replay set to the receiver's set.
func (rs *ReplaySet) Merge(rs2 *ReplaySet) {
	for seqNum := range rs2.replays {
		rs.Add(seqNum)
	}
}

// Encode serializes the replay set into an io.Writer suitable for storage. The
// replay set can be recovered using Decode.
func (rs *ReplaySet) Encode(w io.Writer) error {
	for seqNum := range rs.replays {
		err := binary.Write(w, binary.BigEndian, seqNum)
		if err != nil {
			return err
		}
	}

	return nil
}

// Decode reconstructs a replay set given a io.Reader. The byte
// slice is assumed to be even in length, otherwise resulting in failure.
func (rs *ReplaySet) Decode(r io.Reader) error {
	for {
		// seqNum provides to buffer to read the next uint16 index.
		var seqNum uint16

		err := binary.Read(r, binary.BigEndian, &seqNum)
		switch err {
		case nil:
			// Successful read, proceed.
		case io.EOF:
			return nil
		default:
			// Can return ErrShortBuffer or ErrUnexpectedEOF.
			return err
		}

		// Add this decoded sequence number to the set.
		rs.Add(seqNum)
	}
}
