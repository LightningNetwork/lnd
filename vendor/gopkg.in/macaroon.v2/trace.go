package macaroon

import (
	"fmt"
)

// Trace holds all toperations involved in verifying a macaroon,
// and the root key used as the initial verification key.
// This can be useful for debugging macaroon implementations.
type Trace struct {
	RootKey []byte
	Ops     []TraceOp
}

// Results returns the output from all operations in the Trace.
// The result from ts.Ops[i] will be in the i'th element of the
// returned slice.
// When a trace has resulted in a failure, the
// last element will be nil.
func (t Trace) Results() [][]byte {
	r := make([][]byte, len(t.Ops))
	input := t.RootKey
	for i, op := range t.Ops {
		input = op.Result(input)
		r[i] = input
	}
	return r
}

// TraceOp holds one possible operation when verifying a macaroon.
type TraceOp struct {
	Kind  TraceOpKind `json:"kind"`
	Data1 []byte      `json:"data1,omitempty"`
	Data2 []byte      `json:"data2,omitempty"`
}

// Result returns the result of computing the given
// operation with the given input data.
// If op is TraceFail, it returns nil.
func (op TraceOp) Result(input []byte) []byte {
	switch op.Kind {
	case TraceMakeKey:
		return makeKey(input)[:]
	case TraceHash:
		if len(op.Data2) == 0 {
			return keyedHash(bytesToKey(input), op.Data1)[:]
		}
		return keyedHash2(bytesToKey(input), op.Data1, op.Data2)[:]
	case TraceBind:
		return bindForRequest(op.Data1, bytesToKey(input))[:]
	case TraceFail:
		return nil
	default:
		panic(fmt.Errorf("unknown trace operation kind %d", op.Kind))
	}
}

func bytesToKey(data []byte) *[keyLen]byte {
	var key [keyLen]byte
	if len(data) != keyLen {
		panic(fmt.Errorf("unexpected input key length; got %d want %d", len(data), keyLen))
	}
	copy(key[:], data)
	return &key
}

// TraceOpKind represents the kind of a macaroon verification operation.
type TraceOpKind int

const (
	TraceInvalid = TraceOpKind(iota)

	// TraceMakeKey represents the operation of calculating a
	// fixed length root key from the variable length input key.
	TraceMakeKey

	// TraceHash represents a keyed hash operation with one
	// or two values. If there is only one value, it will be in Data1.
	TraceHash

	// TraceBind represents the operation of binding a discharge macaroon
	// to its primary macaroon. Data1 holds the signature of the primary
	// macaroon.
	TraceBind

	// TraceFail represents a verification failure. If present, this will always
	// be the last operation in a trace.
	TraceFail
)

var traceOps = []string{
	TraceInvalid: "invalid",
	TraceMakeKey: "makekey",
	TraceHash:    "hash",
	TraceBind:    "bind",
	TraceFail:    "fail",
}

// String returns a string representation of the operation.
func (k TraceOpKind) String() string {
	return traceOps[k]
}
