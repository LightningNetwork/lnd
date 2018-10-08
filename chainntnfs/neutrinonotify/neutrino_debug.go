// +build debug

package neutrinonotify

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// UnsafeStart starts the notifier with a specified best height and optional
// best hash. Its bestHeight, txConfNotifier and neutrino node are initialized
// with bestHeight. The parameter generateBlocks is necessary for the
// bitcoind notifier to ensure we drain all notifications up to syncHeight,
// since if they are generated ahead of UnsafeStart the chainConn may start
// up with an outdated best block and miss sending ntfns. Used for testing.
func (n *NeutrinoNotifier) UnsafeStart(bestHeight int32, bestHash *chainhash.Hash,
	syncHeight int32, generateBlocks func() error) error {

	if err := n.hintCache.Start(); err != nil {
		return err
	}

	// We'll obtain the latest block height of the p2p node. We'll
	// start the auto-rescan from this point. Once a caller actually wishes
	// to register a chain view, the rescan state will be rewound
	// accordingly.
	header, height, err := n.p2pNode.BlockHeaders.ChainTip()
	if err != nil {
		return err
	}
	startingPoint := &waddrmgr.BlockStamp{
		Height: int32(height),
		Hash:   header.BlockHash(),
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

	n.txConfNotifier = chainntnfs.NewTxConfNotifier(
		uint32(bestHeight), reorgSafetyLimit, n.hintCache,
	)

	n.chainConn = &NeutrinoChainConn{n.p2pNode}

	// Finally, we'll create our rescan struct, start it, and launch all
	// the goroutines we need to operate this ChainNotifier instance.
	n.chainView = n.p2pNode.NewRescan(rescanOptions...)
	n.rescanErr = n.chainView.Start()

	n.chainUpdates.Start()

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
			case ntfn := <-n.chainUpdates.ChanOut():
				lastReceivedNtfn := ntfn.(*filteredBlock)
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
	n.bestHeight = uint32(bestHeight)

	n.wg.Add(1)
	go n.notificationDispatcher()

	return nil
}
