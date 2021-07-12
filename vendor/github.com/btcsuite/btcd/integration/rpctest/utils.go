// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpctest

import (
	"reflect"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

// JoinType is an enum representing a particular type of "node join". A node
// join is a synchronization tool used to wait until a subset of nodes have a
// consistent state with respect to an attribute.
type JoinType uint8

const (
	// Blocks is a JoinType which waits until all nodes share the same
	// block height.
	Blocks JoinType = iota

	// Mempools is a JoinType which blocks until all nodes have identical
	// mempool.
	Mempools
)

// JoinNodes is a synchronization tool used to block until all passed nodes are
// fully synced with respect to an attribute. This function will block for a
// period of time, finally returning once all nodes are synced according to the
// passed JoinType. This function be used to to ensure all active test
// harnesses are at a consistent state before proceeding to an assertion or
// check within rpc tests.
func JoinNodes(nodes []*Harness, joinType JoinType) error {
	switch joinType {
	case Blocks:
		return syncBlocks(nodes)
	case Mempools:
		return syncMempools(nodes)
	}
	return nil
}

// syncMempools blocks until all nodes have identical mempools.
func syncMempools(nodes []*Harness) error {
	poolsMatch := false

retry:
	for !poolsMatch {
		firstPool, err := nodes[0].Node.GetRawMempool()
		if err != nil {
			return err
		}

		// If all nodes have an identical mempool with respect to the
		// first node, then we're done. Otherwise, drop back to the top
		// of the loop and retry after a short wait period.
		for _, node := range nodes[1:] {
			nodePool, err := node.Node.GetRawMempool()
			if err != nil {
				return err
			}

			if !reflect.DeepEqual(firstPool, nodePool) {
				time.Sleep(time.Millisecond * 100)
				continue retry
			}
		}

		poolsMatch = true
	}

	return nil
}

// syncBlocks blocks until all nodes report the same best chain.
func syncBlocks(nodes []*Harness) error {
	blocksMatch := false

retry:
	for !blocksMatch {
		var prevHash *chainhash.Hash
		var prevHeight int32
		for _, node := range nodes {
			blockHash, blockHeight, err := node.Node.GetBestBlock()
			if err != nil {
				return err
			}
			if prevHash != nil && (*blockHash != *prevHash ||
				blockHeight != prevHeight) {

				time.Sleep(time.Millisecond * 100)
				continue retry
			}
			prevHash, prevHeight = blockHash, blockHeight
		}

		blocksMatch = true
	}

	return nil
}

// ConnectNode establishes a new peer-to-peer connection between the "from"
// harness and the "to" harness.  The connection made is flagged as persistent,
// therefore in the case of disconnects, "from" will attempt to reestablish a
// connection to the "to" harness.
func ConnectNode(from *Harness, to *Harness) error {
	peerInfo, err := from.Node.GetPeerInfo()
	if err != nil {
		return err
	}
	numPeers := len(peerInfo)

	targetAddr := to.node.config.listen
	if err := from.Node.AddNode(targetAddr, rpcclient.ANAdd); err != nil {
		return err
	}

	// Block until a new connection has been established.
	peerInfo, err = from.Node.GetPeerInfo()
	if err != nil {
		return err
	}
	for len(peerInfo) <= numPeers {
		peerInfo, err = from.Node.GetPeerInfo()
		if err != nil {
			return err
		}
	}

	return nil
}

// TearDownAll tears down all active test harnesses.
func TearDownAll() error {
	harnessStateMtx.Lock()
	defer harnessStateMtx.Unlock()

	for _, harness := range testInstances {
		if err := harness.tearDown(); err != nil {
			return err
		}
	}

	return nil
}

// ActiveHarnesses returns a slice of all currently active test harnesses. A
// test harness if considered "active" if it has been created, but not yet torn
// down.
func ActiveHarnesses() []*Harness {
	harnessStateMtx.RLock()
	defer harnessStateMtx.RUnlock()

	activeNodes := make([]*Harness, 0, len(testInstances))
	for _, harness := range testInstances {
		activeNodes = append(activeNodes, harness)
	}

	return activeNodes
}
