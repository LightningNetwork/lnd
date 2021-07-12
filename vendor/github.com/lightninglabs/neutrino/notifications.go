// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: THIS API IS UNSTABLE RIGHT NOW.

package neutrino

import (
	"errors"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/lightninglabs/neutrino/query"
)

type getConnCountMsg struct {
	reply chan int32
}

type subConnPeersReply struct {
	peerChan   chan query.Peer
	cancelChan chan struct{}
}
type subConnPeersMsg struct {
	reply chan subConnPeersReply
}

type getPeersMsg struct {
	reply chan []*ServerPeer
}

type getOutboundGroup struct {
	key   string
	reply chan int
}

type getAddedNodesMsg struct {
	reply chan []*ServerPeer
}

type disconnectNodeMsg struct {
	cmp   func(*ServerPeer) bool
	reply chan error
}

type connectNodeMsg struct {
	addr      string
	permanent bool
	reply     chan error
}

type removeNodeMsg struct {
	cmp   func(*ServerPeer) bool
	reply chan error
}

type forAllPeersMsg struct {
	closure func(*ServerPeer)
}

// TODO: General - abstract out more of blockmanager into queries. It'll make
// this way more maintainable and usable.

// handleQuery is the central handler for all queries and commands from other
// goroutines related to peer state.
func (s *ChainService) handleQuery(state *peerState, querymsg interface{}) {
	switch msg := querymsg.(type) {

	case getConnCountMsg:
		nconnected := int32(0)
		state.forAllPeers(func(sp *ServerPeer) {
			if sp.Connected() {
				nconnected++
			}
		})
		msg.reply <- nconnected

	case getPeersMsg:
		peers := make([]*ServerPeer, 0, state.Count())
		state.forAllPeers(func(sp *ServerPeer) {
			if !sp.Connected() {
				return
			}
			peers = append(peers, sp)
		})
		msg.reply <- peers

	// Subscription for connected peers requested.
	case subConnPeersMsg:
		// Create a channel and fill it with the current set of
		// connected peers.
		cancelChan := make(chan struct{})
		peerChan := make(chan query.Peer, state.Count())
		state.forAllPeers(func(sp *ServerPeer) {
			if !sp.Connected() {
				return
			}
			peerChan <- sp
		})

		s.peerSubscribers = append(s.peerSubscribers, &peerSubscription{
			peers:  peerChan,
			cancel: cancelChan,
		})
		msg.reply <- subConnPeersReply{
			peerChan:   peerChan,
			cancelChan: cancelChan,
		}

	case connectNodeMsg:
		// TODO: duplicate oneshots?
		// Limit max number of total peers.
		if state.Count() >= MaxPeers {
			msg.reply <- errors.New("max peers reached")
			return
		}
		for _, peer := range state.persistentPeers {
			if peer.Addr() == msg.addr {
				if msg.permanent {
					msg.reply <- errors.New("peer already connected")
				} else {
					msg.reply <- errors.New("peer exists as a permanent peer")
				}
				return
			}
		}

		netAddr, err := s.addrStringToNetAddr(msg.addr)
		if err != nil {
			msg.reply <- err
			return
		}

		// TODO: if too many, nuke a non-perm peer.
		go s.connManager.Connect(&connmgr.ConnReq{
			Addr:      netAddr,
			Permanent: msg.permanent,
		})
		msg.reply <- nil

	case removeNodeMsg:
		found := disconnectPeer(state.persistentPeers, msg.cmp, func(sp *ServerPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		})

		if found {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("peer not found")
		}

	case getOutboundGroup:
		count, ok := state.outboundGroups[msg.key]
		if ok {
			msg.reply <- count
		} else {
			msg.reply <- 0
		}

	// Request a list of the persistent (added) peers.
	case getAddedNodesMsg:
		// Respond with a slice of the relavent peers.
		peers := make([]*ServerPeer, 0, len(state.persistentPeers))
		for _, sp := range state.persistentPeers {
			peers = append(peers, sp)
		}
		msg.reply <- peers

	case disconnectNodeMsg:
		// Check outbound peers.
		found := disconnectPeer(state.outboundPeers, msg.cmp, func(sp *ServerPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		})
		if found {
			// If there are multiple outbound connections to the same
			// ip:port, continue disconnecting them all until no such
			// peers are found.
			for found {
				found = disconnectPeer(state.outboundPeers, msg.cmp, func(sp *ServerPeer) {
					state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
				})
			}
			msg.reply <- nil
			return
		}

		msg.reply <- errors.New("peer not found")

	case forAllPeersMsg:
		// TODO: Remove this when it's unnecessary due to wider use of
		// queryPeers.
		// Run the closure on all peers in the passed state.
		state.forAllPeers(msg.closure)
		// Even though this is a query, there's no reply channel as the
		// forAllPeers method doesn't return anything. An error might be
		// useful in the future.
	}
}

// ConnectedCount returns the number of currently connected peers.
func (s *ChainService) ConnectedCount() int32 {
	replyChan := make(chan int32)

	select {
	case s.query <- getConnCountMsg{reply: replyChan}:
		return <-replyChan
	case <-s.quit:
		return 0
	}
}

// ConnectedPeers is a function that returns a channel where all connected
// peers will be sent. It is assumed that all current peers will be sent
// imemdiately, and new peers as they connect.
func (s *ChainService) ConnectedPeers() (<-chan query.Peer, func(), error) {
	replyChan := make(chan subConnPeersReply, 1)

	select {
	case s.query <- subConnPeersMsg{
		reply: replyChan,
	}:
	case <-s.quit:
		return nil, nil, ErrShuttingDown
	}

	select {
	case reply := <-replyChan:
		return reply.peerChan, func() {
			close(reply.cancelChan)
		}, nil

	case <-s.quit:
		return nil, nil, ErrShuttingDown
	}
}

// OutboundGroupCount returns the number of peers connected to the given
// outbound group key.
func (s *ChainService) OutboundGroupCount(key string) int {
	replyChan := make(chan int)

	select {
	case s.query <- getOutboundGroup{key: key, reply: replyChan}:
		return <-replyChan
	case <-s.quit:
		return 0
	}
}

// AddedNodeInfo returns an array of btcjson.GetAddedNodeInfoResult structures
// describing the persistent (added) nodes.
func (s *ChainService) AddedNodeInfo() []*ServerPeer {
	replyChan := make(chan []*ServerPeer)

	select {
	case s.query <- getAddedNodesMsg{reply: replyChan}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// Peers returns an array of all connected peers.
func (s *ChainService) Peers() []*ServerPeer {
	replyChan := make(chan []*ServerPeer)

	select {
	case s.query <- getPeersMsg{reply: replyChan}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// DisconnectNodeByAddr disconnects a peer by target address. Both outbound and
// inbound nodes will be searched for the target node. An error message will
// be returned if the peer was not found.
func (s *ChainService) DisconnectNodeByAddr(addr string) error {
	replyChan := make(chan error)

	select {
	case s.query <- disconnectNodeMsg{
		cmp:   func(sp *ServerPeer) bool { return sp.Addr() == addr },
		reply: replyChan,
	}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// DisconnectNodeByID disconnects a peer by target node id. Both outbound and
// inbound nodes will be searched for the target node. An error message will be
// returned if the peer was not found.
func (s *ChainService) DisconnectNodeByID(id int32) error {
	replyChan := make(chan error)

	select {
	case s.query <- disconnectNodeMsg{
		cmp:   func(sp *ServerPeer) bool { return sp.ID() == id },
		reply: replyChan,
	}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// RemoveNodeByAddr removes a peer from the list of persistent peers if
// present. An error will be returned if the peer was not found.
func (s *ChainService) RemoveNodeByAddr(addr string) error {
	replyChan := make(chan error)

	select {
	case s.query <- removeNodeMsg{
		cmp:   func(sp *ServerPeer) bool { return sp.Addr() == addr },
		reply: replyChan,
	}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// RemoveNodeByID removes a peer by node ID from the list of persistent peers
// if present. An error will be returned if the peer was not found.
func (s *ChainService) RemoveNodeByID(id int32) error {
	replyChan := make(chan error)

	select {
	case s.query <- removeNodeMsg{
		cmp:   func(sp *ServerPeer) bool { return sp.ID() == id },
		reply: replyChan,
	}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// ConnectNode adds `addr' as a new outbound peer. If permanent is true then the
// peer will be persistent and reconnect if the connection is lost.
// It is an error to call this with an already existing peer.
func (s *ChainService) ConnectNode(addr string, permanent bool) error {
	replyChan := make(chan error)

	select {
	case s.query <- connectNodeMsg{
		addr:      addr,
		permanent: permanent,
		reply:     replyChan,
	}:
		return <-replyChan
	case <-s.quit:
		return nil
	}
}

// ForAllPeers runs a closure over all peers (outbound and persistent) to which
// the ChainService is connected. Nothing is returned because the peerState's
// ForAllPeers method doesn't return anything as the closure passed to it
// doesn't return anything.
func (s *ChainService) ForAllPeers(closure func(sp *ServerPeer)) {
	select {
	case s.query <- forAllPeersMsg{closure: closure}:
	case <-s.quit:
	}
}
