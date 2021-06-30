// +build dev

package neutrinonotify

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// UnsafeStart starts the notifier with a specified best height and optional
// best hash. Its bestHeight, txNotifier and neutrino node are initialized with
// bestHeight. The parameter generateBlocks is necessary for the bitcoind
// notifier to ensure we drain all notifications up to syncHeight, since if they
// are generated ahead of UnsafeStart the chainConn may start up with an
// outdated best block and miss sending ntfns. Used for testing.
func (n *NeutrinoNotifier) UnsafeStart(bestHeight int32,
	bestHash *chainhash.Hash, syncHeight int32,
	generateBlocks func() error) error {

	// We'll obtain the latest block height of the p2p node. We'll
	// start the auto-rescan from this point. Once a caller actually wishes
	// to register a chain view, the rescan state will be rewound
	// accordingly.
	startingPoint, err := n.p2pNode.BestBlock()
	if err != nil {
		return err
	}

	// Next, we'll create our set of rescan options. Currently it's
	// required that a user MUST set an addr/outpoint/txid when creating a
	// rescan. To get around this, we'll add a "zero" outpoint, that won't
	// actually be matched.
	var zeroInput neutrino.InputWithScript
	rescanOptions := []neutrino.RescanOption{
		neutrino.StartBlock(startingPoint),
		neutrino.QuitChan(n.quit),
		neutrino.NotificationHandlers(
			rpcclient.NotificationHandlers{
				OnFilteredBlockConnected:    n.onFilteredBlockConnected,
				OnFilteredBlockDisconnected: n.onFilteredBlockDisconnected,
			},
		),
		neutrino.WatchInputs(zeroInput),
	}

	n.txNotifier = chainntnfs.NewTxNotifier(
		uint32(bestHeight), chainntnfs.ReorgSafetyLimit,
		n.confirmHintCache, n.spendHintCache,
	)

	// Finally, we'll create our rescan struct, start it, and launch all
	// the goroutines we need to operate this ChainNotifier instance.
	n.chainView = neutrino.NewRescan(
		&neutrino.RescanChainSource{
			ChainService: n.p2pNode,
		},
		rescanOptions...,
	)
	n.rescanErr = n.chainView.Start()

	n.txUpdates.Start()

	if generateBlocks != nil {
		// Ensure no block notifications are pending when we start the
		// notification dispatcher goroutine.

		// First generate the blocks, then drain the notifications
		// for the generated blocks.
		if err := generateBlocks(); err != nil {
			return err
		}

		timeout := time.After(60 * time.Second)
	loop:
		for {
			select {
			case ntfn := <-n.chainUpdates:
				lastReceivedNtfn := ntfn
				if lastReceivedNtfn.height >= uint32(syncHeight) {
					break loop
				}
			case <-timeout:
				return fmt.Errorf("unable to catch up to height %d",
					syncHeight)
			}
		}
	}

	// Run notificationDispatcher after setting the notifier's best height
	// to avoid a race condition.
	n.bestBlock.Hash = bestHash
	n.bestBlock.Height = bestHeight

	n.wg.Add(1)
	go n.notificationDispatcher()

	return nil
}
