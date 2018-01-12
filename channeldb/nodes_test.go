package channeldb

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/wire"
)

func TestLinkNodeEncodeDecode(t *testing.T) {
	t.Parallel()

	cdb, cleanUp, err := makeTestDB()
	if err != nil {
		t.Fatalf("uanble to make test database: %v", err)
	}
	defer cleanUp()

	// First we'll create some initial data to use for populating our test
	// LinkNode instances.
	_, pub1 := btcec.PrivKeyFromBytes(btcec.S256(), key[:])
	_, pub2 := btcec.PrivKeyFromBytes(btcec.S256(), rev[:])
	addr1, err := net.ResolveTCPAddr("tcp", "10.0.0.1:9000")
	if err != nil {
		t.Fatalf("unable to create test addr: %v", err)
	}
	addr2, err := net.ResolveTCPAddr("tcp", "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("unable to create test addr: %v", err)
	}

	// Create two fresh link node instances with the above dummy data, then
	// fully sync both instances to disk.
	node1 := cdb.NewLinkNode(wire.MainNet, pub1, addr1)
	node2 := cdb.NewLinkNode(wire.TestNet3, pub2, addr2)
	if err := node1.Sync(); err != nil {
		t.Fatalf("unable to sync node: %v", err)
	}
	if err := node2.Sync(); err != nil {
		t.Fatalf("unable to sync node: %v", err)
	}

	// Fetch all current link nodes from the database, they should exactly
	// match the two created above.
	originalNodes := []*LinkNode{node2, node1}
	linkNodes, err := cdb.FetchAllLinkNodes()
	if err != nil {
		t.Fatalf("unable to fetch nodes: %v", err)
	}
	for i, node := range linkNodes {
		if originalNodes[i].Network != node.Network {
			t.Fatalf("node networks don't match: expected %v, got %v",
				originalNodes[i].Network, node.Network)
		}

		originalPubkey := originalNodes[i].IdentityPub.SerializeCompressed()
		dbPubkey := node.IdentityPub.SerializeCompressed()
		if !bytes.Equal(originalPubkey, dbPubkey) {
			t.Fatalf("node pubkeys don't match: expected %x, got %x",
				originalPubkey, dbPubkey)
		}
		if originalNodes[i].LastSeen.Unix() != node.LastSeen.Unix() {
			t.Fatalf("last seen timestamps don't match: expected %v got %v",
				originalNodes[i].LastSeen.Unix(), node.LastSeen.Unix())
		}
		if !reflect.DeepEqual(originalNodes[i].Addresses,
			node.Addresses) {
			t.Fatalf("addresses don't match: expected %v, got %v",
				originalNodes[i].Addresses, node.Addresses)
		}
	}

	// Next, we'll exercise the methods to append additionall IP
	// addresses, and also to update the last seen time.
	if err := node1.UpdateLastSeen(time.Now()); err != nil {
		t.Fatalf("unable to update last seen: %v", err)
	}
	if err := node1.AddAddress(addr2); err != nil {
		t.Fatalf("unable to update addr: %v", err)
	}

	// Fetch the same node from the databse according to its public key.
	node1DB, err := cdb.FetchLinkNode(pub1)
	if err != nil {
		t.Fatalf("unable to find node: %v", err)
	}

	// Both the last seen timestamp and the list of reachable addresses for
	// the node should be updated.
	if node1DB.LastSeen.Unix() != node1.LastSeen.Unix() {
		t.Fatalf("last seen timestamps don't match: expected %v got %v",
			node1.LastSeen.Unix(), node1DB.LastSeen.Unix())
	}
	if len(node1DB.Addresses) != 2 {
		t.Fatalf("wrong length for node1 addrsses: expected %v, got %v",
			2, len(node1DB.Addresses))
	}
	if node1DB.Addresses[0].String() != addr1.String() {
		t.Fatalf("wrong address for node: expected %v, got %v",
			addr1.String(), node1DB.Addresses[0].String())
	}
	if node1DB.Addresses[1].String() != addr2.String() {
		t.Fatalf("wrong address for node: expected %v, got %v",
			addr2.String(), node1DB.Addresses[1].String())
	}
}
