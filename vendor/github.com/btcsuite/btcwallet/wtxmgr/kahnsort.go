// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type graphNode struct {
	value    *wire.MsgTx
	outEdges []*chainhash.Hash
	inDegree int
}

type hashGraph map[chainhash.Hash]graphNode

func makeGraph(set map[chainhash.Hash]*wire.MsgTx) hashGraph {
	graph := make(hashGraph)

	for _, tx := range set {
		// Add a node for every transaction. The output edges and input
		// degree are set by iterating over each transaction's inputs
		// below.
		txHash := tx.TxHash()
		if _, ok := graph[txHash]; !ok {
			graph[txHash] = graphNode{value: tx}
		}

	inputLoop:
		for _, input := range tx.TxIn {
			// Transaction inputs that reference transactions not
			// included in the set do not create any (local) graph
			// edges.
			if _, ok := set[input.PreviousOutPoint.Hash]; !ok {
				continue
			}

			inputNode := graph[input.PreviousOutPoint.Hash]

			// Skip duplicate edges.
			for _, outEdge := range inputNode.outEdges {
				if *outEdge == input.PreviousOutPoint.Hash {
					continue inputLoop
				}
			}

			// Mark a directed edge from the previous transaction
			// hash to this transaction and increase the input
			// degree for this transaction's node.
			inputTx := inputNode.value
			if inputTx == nil {
				inputTx = set[input.PreviousOutPoint.Hash]
			}
			graph[input.PreviousOutPoint.Hash] = graphNode{
				value:    inputTx,
				outEdges: append(inputNode.outEdges, &txHash),
				inDegree: inputNode.inDegree,
			}
			node := graph[txHash]
			graph[txHash] = graphNode{
				value:    tx,
				outEdges: node.outEdges,
				inDegree: node.inDegree + 1,
			}
		}
	}

	return graph
}

// graphRoots returns the roots of the graph.  That is, it returns the node's
// values for all nodes which contain an input degree of 0.
func graphRoots(graph hashGraph) []*wire.MsgTx {
	roots := make([]*wire.MsgTx, 0, len(graph))
	for _, node := range graph {
		if node.inDegree == 0 {
			roots = append(roots, node.value)
		}
	}
	return roots
}

// DependencySort topologically sorts a set of transactions by their dependency
// order. It is implemented using Kahn's algorithm.
func DependencySort(txs map[chainhash.Hash]*wire.MsgTx) []*wire.MsgTx {
	graph := makeGraph(txs)
	s := graphRoots(graph)

	// If there are no edges (no transactions from the map reference each
	// other), then Kahn's algorithm is unnecessary.
	if len(s) == len(txs) {
		return s
	}

	sorted := make([]*wire.MsgTx, 0, len(txs))
	for len(s) != 0 {
		tx := s[0]
		s = s[1:]
		sorted = append(sorted, tx)

		n := graph[tx.TxHash()]
		for _, mHash := range n.outEdges {
			m := graph[*mHash]
			if m.inDegree != 0 {
				m.inDegree--
				graph[*mHash] = m
				if m.inDegree == 0 {
					s = append(s, m.value)
				}
			}
		}
	}
	return sorted
}
