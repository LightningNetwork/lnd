package itest

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testChannelBackupRestore tests that we're able to recover from, and initiate
// the DLP protocol via: the RPC restore command, restoring on unlock, and
// restoring from initial wallet creation. We'll also alternate between
// restoring form the on disk file, and restoring from the exported RPC command
// as well.
func testChannelBackupRestore(net *lntest.NetworkHarness, t *harnessTest) {
	password := []byte("El Psy Kongroo")

	ctxb := context.Background()

	var testCases = []chanRestoreTestCase{
		// Restore from backups obtained via the RPC interface. Dave
		// was the initiator, of the non-advertised channel.
		{
			name:            "restore from RPC backup",
			channelsUpdated: false,
			initiator:       true,
			private:         false,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// For this restoration method, we'll grab the
				// current multi-channel backup from the old
				// node, and use it to restore a new node
				// within the closure.
				req := &lnrpc.ChanBackupExportRequest{}
				chanBackup, err := oldNode.ExportAllChannelBackups(
					ctxb, req,
				)
				if err != nil {
					return nil, fmt.Errorf("unable to obtain "+
						"channel backup: %v", err)
				}

				multi := chanBackup.MultiChanBackup.MultiChanBackup

				// In our nodeRestorer function, we'll restore
				// the node from seed, then manually recover
				// the channel backup.
				return chanRestoreViaRPC(
					net, password, mnemonic, multi, oldNode,
				)
			},
		},

		// Restore the backup from the on-disk file, using the RPC
		// interface.
		{
			name:      "restore from backup file",
			initiator: true,
			private:   false,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// Read the entire Multi backup stored within
				// this node's channels.backup file.
				multi, err := ioutil.ReadFile(backupFilePath)
				if err != nil {
					return nil, err
				}

				// Now that we have Dave's backup file, we'll
				// create a new nodeRestorer that will restore
				// using the on-disk channels.backup.
				return chanRestoreViaRPC(
					net, password, mnemonic, multi, oldNode,
				)
			},
		},

		// Restore the backup as part of node initialization with the
		// prior mnemonic and new backup seed.
		{
			name:      "restore during creation",
			initiator: true,
			private:   false,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// First, fetch the current backup state as is,
				// to obtain our latest Multi.
				chanBackup, err := oldNode.ExportAllChannelBackups(
					ctxb, &lnrpc.ChanBackupExportRequest{},
				)
				if err != nil {
					return nil, fmt.Errorf("unable to obtain "+
						"channel backup: %v", err)
				}
				backupSnapshot := &lnrpc.ChanBackupSnapshot{
					MultiChanBackup: chanBackup.MultiChanBackup,
				}

				// Create a new nodeRestorer that will restore
				// the node using the Multi backup we just
				// obtained above.
				return func() (*lntest.HarnessNode, error) {
					return net.RestoreNodeWithSeed(
						"dave", nil, password,
						mnemonic, 1000, backupSnapshot,
						copyPorts(oldNode),
					)
				}, nil
			},
		},

		// Restore the backup once the node has already been
		// re-created, using the Unlock call.
		{
			name:      "restore during unlock",
			initiator: true,
			private:   false,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// First, fetch the current backup state as is,
				// to obtain our latest Multi.
				chanBackup, err := oldNode.ExportAllChannelBackups(
					ctxb, &lnrpc.ChanBackupExportRequest{},
				)
				if err != nil {
					return nil, fmt.Errorf("unable to obtain "+
						"channel backup: %v", err)
				}
				backupSnapshot := &lnrpc.ChanBackupSnapshot{
					MultiChanBackup: chanBackup.MultiChanBackup,
				}

				// Create a new nodeRestorer that will restore
				// the node with its seed, but no channel
				// backup, shutdown this initialized node, then
				// restart it again using Unlock.
				return func() (*lntest.HarnessNode, error) {
					newNode, err := net.RestoreNodeWithSeed(
						"dave", nil, password,
						mnemonic, 1000, nil,
						copyPorts(oldNode),
					)
					if err != nil {
						return nil, err
					}

					err = net.RestartNode(
						newNode, nil, backupSnapshot,
					)
					if err != nil {
						return nil, err
					}

					return newNode, nil
				}, nil
			},
		},

		// Restore the backup from the on-disk file a second time to
		// make sure imports can be canceled and later resumed.
		{
			name:      "restore from backup file twice",
			initiator: true,
			private:   false,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// Read the entire Multi backup stored within
				// this node's channels.backup file.
				multi, err := ioutil.ReadFile(backupFilePath)
				if err != nil {
					return nil, err
				}

				// Now that we have Dave's backup file, we'll
				// create a new nodeRestorer that will restore
				// using the on-disk channels.backup.
				backup := &lnrpc.RestoreChanBackupRequest_MultiChanBackup{
					MultiChanBackup: multi,
				}

				ctxb := context.Background()

				return func() (*lntest.HarnessNode, error) {
					newNode, err := net.RestoreNodeWithSeed(
						"dave", nil, password, mnemonic,
						1000, nil, copyPorts(oldNode),
					)
					if err != nil {
						return nil, fmt.Errorf("unable to "+
							"restore node: %v", err)
					}

					_, err = newNode.RestoreChannelBackups(
						ctxb,
						&lnrpc.RestoreChanBackupRequest{
							Backup: backup,
						},
					)
					if err != nil {
						return nil, fmt.Errorf("unable "+
							"to restore backups: %v",
							err)
					}

					_, err = newNode.RestoreChannelBackups(
						ctxb,
						&lnrpc.RestoreChanBackupRequest{
							Backup: backup,
						},
					)
					if err != nil {
						return nil, fmt.Errorf("unable "+
							"to restore backups the"+
							"second time: %v",
							err)
					}

					return newNode, nil
				}, nil
			},
		},

		// Use the channel backup file that contains an unconfirmed
		// channel and make sure recovery works as well.
		{
			name:            "restore unconfirmed channel file",
			channelsUpdated: false,
			initiator:       true,
			private:         false,
			unconfirmed:     true,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// Read the entire Multi backup stored within
				// this node's channels.backup file.
				multi, err := ioutil.ReadFile(backupFilePath)
				if err != nil {
					return nil, err
				}

				// Let's assume time passes, the channel
				// confirms in the meantime but for some reason
				// the backup we made while it was still
				// unconfirmed is the only backup we have. We
				// should still be able to restore it. To
				// simulate time passing, we mine some blocks
				// to get the channel confirmed _after_ we saved
				// the backup.
				mineBlocks(t, net, 6, 1)

				// In our nodeRestorer function, we'll restore
				// the node from seed, then manually recover
				// the channel backup.
				return chanRestoreViaRPC(
					net, password, mnemonic, multi, oldNode,
				)
			},
		},

		// Create a backup using RPC that contains an unconfirmed
		// channel and make sure recovery works as well.
		{
			name:            "restore unconfirmed channel RPC",
			channelsUpdated: false,
			initiator:       true,
			private:         false,
			unconfirmed:     true,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// For this restoration method, we'll grab the
				// current multi-channel backup from the old
				// node. The channel should be included, even if
				// it is not confirmed yet.
				req := &lnrpc.ChanBackupExportRequest{}
				chanBackup, err := oldNode.ExportAllChannelBackups(
					ctxb, req,
				)
				if err != nil {
					return nil, fmt.Errorf("unable to obtain "+
						"channel backup: %v", err)
				}
				chanPoints := chanBackup.MultiChanBackup.ChanPoints
				if len(chanPoints) == 0 {
					return nil, fmt.Errorf("unconfirmed " +
						"channel not included in backup")
				}

				// Let's assume time passes, the channel
				// confirms in the meantime but for some reason
				// the backup we made while it was still
				// unconfirmed is the only backup we have. We
				// should still be able to restore it. To
				// simulate time passing, we mine some blocks
				// to get the channel confirmed _after_ we saved
				// the backup.
				mineBlocks(t, net, 6, 1)

				// In our nodeRestorer function, we'll restore
				// the node from seed, then manually recover
				// the channel backup.
				multi := chanBackup.MultiChanBackup.MultiChanBackup
				return chanRestoreViaRPC(
					net, password, mnemonic, multi, oldNode,
				)
			},
		},

		// Restore the backup from the on-disk file, using the RPC
		// interface, for anchor commitment channels.
		{
			name:         "restore from backup file anchors",
			initiator:    true,
			private:      false,
			anchorCommit: true,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// Read the entire Multi backup stored within
				// this node's channels.backup file.
				multi, err := ioutil.ReadFile(backupFilePath)
				if err != nil {
					return nil, err
				}

				// Now that we have Dave's backup file, we'll
				// create a new nodeRestorer that will restore
				// using the on-disk channels.backup.
				return chanRestoreViaRPC(
					net, password, mnemonic, multi, oldNode,
				)
			},
		},

		// Restore by also creating a channel with the legacy revocation
		// producer format to make sure old SCBs can still be recovered.
		{
			name:             "old revocation producer format",
			initiator:        true,
			legacyRevocation: true,
			restoreMethod: func(oldNode *lntest.HarnessNode,
				backupFilePath string,
				mnemonic []string) (nodeRestorer, error) {

				// For this restoration method, we'll grab the
				// current multi-channel backup from the old
				// node, and use it to restore a new node
				// within the closure.
				req := &lnrpc.ChanBackupExportRequest{}
				chanBackup, err := oldNode.ExportAllChannelBackups(
					ctxb, req,
				)
				require.NoError(t.t, err)

				multi := chanBackup.MultiChanBackup.MultiChanBackup

				// In our nodeRestorer function, we'll restore
				// the node from seed, then manually recover the
				// channel backup.
				return chanRestoreViaRPC(
					net, password, mnemonic, multi, oldNode,
				)
			},
		},
	}

	// TODO(roasbeef): online vs offline close?

	// TODO(roasbeef): need to re-trigger the on-disk file once the node
	// ann is updated?

	for _, testCase := range testCases {
		testCase := testCase
		success := t.t.Run(testCase.name, func(t *testing.T) {
			h := newHarnessTest(t, net)

			// Start each test with the default static fee estimate.
			net.SetFeeEstimate(12500)

			testChanRestoreScenario(h, net, &testCase, password)
		})
		if !success {
			break
		}
	}
}

// testChannelBackupUpdates tests that both the streaming channel update RPC,
// and the on-disk channels.backup are updated each time a channel is
// opened/closed.
func testChannelBackupUpdates(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, we'll make a temp directory that we'll use to store our
	// backup file, so we can check in on it during the test easily.
	backupDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("unable to create backup dir: %v", err)
	}
	defer os.RemoveAll(backupDir)

	// First, we'll create a new node, Carol. We'll also create a temporary
	// file that Carol will use to store her channel backups.
	backupFilePath := filepath.Join(
		backupDir, chanbackup.DefaultBackupFileName,
	)
	carolArgs := fmt.Sprintf("--backupfilepath=%v", backupFilePath)
	carol := net.NewNode(t.t, "carol", []string{carolArgs})
	defer shutdownAndAssert(net, t, carol)

	// Next, we'll register for streaming notifications for changes to the
	// backup file.
	backupStream, err := carol.SubscribeChannelBackups(
		ctxb, &lnrpc.ChannelBackupSubscription{},
	)
	if err != nil {
		t.Fatalf("unable to create backup stream: %v", err)
	}

	// We'll use this goroutine to proxy any updates to a channel we can
	// easily use below.
	var wg sync.WaitGroup
	backupUpdates := make(chan *lnrpc.ChanBackupSnapshot)
	streamErr := make(chan error)
	streamQuit := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			snapshot, err := backupStream.Recv()
			if err != nil {
				select {
				case streamErr <- err:
				case <-streamQuit:
					return
				}
			}

			select {
			case backupUpdates <- snapshot:
			case <-streamQuit:
				return
			}
		}
	}()
	defer close(streamQuit)

	// With Carol up, we'll now connect her to Alice, and open a channel
	// between them.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Alice)

	// Next, we'll open two channels between Alice and Carol back to back.
	var chanPoints []*lnrpc.ChannelPoint
	numChans := 2
	chanAmt := btcutil.Amount(1000000)
	for i := 0; i < numChans; i++ {
		ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
		chanPoint := openChannelAndAssert(
			ctxt, t, net, net.Alice, carol,
			lntest.OpenChannelParams{
				Amt: chanAmt,
			},
		)

		chanPoints = append(chanPoints, chanPoint)
	}

	// Using this helper function, we'll maintain a pointer to the latest
	// channel backup so we can compare it to the on disk state.
	var currentBackup *lnrpc.ChanBackupSnapshot
	assertBackupNtfns := func(numNtfns int) {
		for i := 0; i < numNtfns; i++ {
			select {
			case err := <-streamErr:
				t.Fatalf("error with backup stream: %v", err)

			case currentBackup = <-backupUpdates:

			case <-time.After(time.Second * 5):
				t.Fatalf("didn't receive channel backup "+
					"notification %v", i+1)
			}
		}
	}

	// assertBackupFileState is a helper function that we'll use to compare
	// the on disk back up file to our currentBackup pointer above.
	assertBackupFileState := func() {
		err := wait.NoError(func() error {
			packedBackup, err := ioutil.ReadFile(backupFilePath)
			if err != nil {
				return fmt.Errorf("unable to read backup "+
					"file: %v", err)
			}

			// As each back up file will be encrypted with a fresh
			// nonce, we can't compare them directly, so instead
			// we'll compare the length which is a proxy for the
			// number of channels that the multi-backup contains.
			rawBackup := currentBackup.MultiChanBackup.MultiChanBackup
			if len(rawBackup) != len(packedBackup) {
				return fmt.Errorf("backup files don't match: "+
					"expected %x got %x", rawBackup, packedBackup)
			}

			// Additionally, we'll assert that both backups up
			// returned are valid.
			for i, backup := range [][]byte{rawBackup, packedBackup} {
				snapshot := &lnrpc.ChanBackupSnapshot{
					MultiChanBackup: &lnrpc.MultiChanBackup{
						MultiChanBackup: backup,
					},
				}
				_, err := carol.VerifyChanBackup(ctxb, snapshot)
				if err != nil {
					return fmt.Errorf("unable to verify "+
						"backup #%d: %v", i, err)
				}
			}

			return nil
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("backup state invalid: %v", err)
		}
	}

	// As these two channels were just opened, we should've got two times
	// the pending and open notifications for channel backups.
	assertBackupNtfns(2 * 2)

	// The on disk file should also exactly match the latest backup that we
	// have.
	assertBackupFileState()

	// Next, we'll close the channels one by one. After each channel
	// closure, we should get a notification, and the on-disk state should
	// match this state as well.
	for i := 0; i < numChans; i++ {
		// To ensure force closes also trigger an update, we'll force
		// close half of the channels.
		forceClose := i%2 == 0

		chanPoint := chanPoints[i]

		ctxt, _ := context.WithTimeout(ctxb, channelCloseTimeout)
		closeChannelAndAssert(
			ctxt, t, net, net.Alice, chanPoint, forceClose,
		)

		// We should get a single notification after closing, and the
		// on-disk state should match this latest notifications.
		assertBackupNtfns(1)
		assertBackupFileState()

		// If we force closed the channel, then we'll mine enough
		// blocks to ensure all outputs have been swept.
		if forceClose {
			cleanupForceClose(t, net, net.Alice, chanPoint)
		}
	}
}

// testExportChannelBackup tests that we're able to properly export either a
// targeted channel's backup, or export backups of all the currents open
// channels.
func testExportChannelBackup(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	// First, we'll create our primary test node: Carol. We'll use Carol to
	// open channels and also export backups that we'll examine throughout
	// the test.
	carol := net.NewNode(t.t, "carol", nil)
	defer shutdownAndAssert(net, t, carol)

	// With Carol up, we'll now connect her to Alice, and open a channel
	// between them.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.ConnectNodes(ctxt, t.t, carol, net.Alice)

	// Next, we'll open two channels between Alice and Carol back to back.
	var chanPoints []*lnrpc.ChannelPoint
	numChans := 2
	chanAmt := btcutil.Amount(1000000)
	for i := 0; i < numChans; i++ {
		ctxt, _ := context.WithTimeout(ctxb, channelOpenTimeout)
		chanPoint := openChannelAndAssert(
			ctxt, t, net, net.Alice, carol,
			lntest.OpenChannelParams{
				Amt: chanAmt,
			},
		)

		chanPoints = append(chanPoints, chanPoint)
	}

	// Now that the channels are open, we should be able to fetch the
	// backups of each of the channels.
	for _, chanPoint := range chanPoints {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		req := &lnrpc.ExportChannelBackupRequest{
			ChanPoint: chanPoint,
		}
		chanBackup, err := carol.ExportChannelBackup(ctxt, req)
		if err != nil {
			t.Fatalf("unable to fetch backup for channel %v: %v",
				chanPoint, err)
		}

		// The returned backup should be full populated. Since it's
		// encrypted, we can't assert any more than that atm.
		if len(chanBackup.ChanBackup) == 0 {
			t.Fatalf("obtained empty backup for channel: %v", chanPoint)
		}

		// The specified chanPoint in the response should match our
		// requested chanPoint.
		if chanBackup.ChanPoint.String() != chanPoint.String() {
			t.Fatalf("chanPoint mismatched: expected %v, got %v",
				chanPoint.String(),
				chanBackup.ChanPoint.String())
		}
	}

	// Before we proceed, we'll make two utility methods we'll use below
	// for our primary assertions.
	assertNumSingleBackups := func(numSingles int) {
		err := wait.NoError(func() error {
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			req := &lnrpc.ChanBackupExportRequest{}
			chanSnapshot, err := carol.ExportAllChannelBackups(
				ctxt, req,
			)
			if err != nil {
				return fmt.Errorf("unable to export channel "+
					"backup: %v", err)
			}

			if chanSnapshot.SingleChanBackups == nil {
				return fmt.Errorf("single chan backups not " +
					"populated")
			}

			backups := chanSnapshot.SingleChanBackups.ChanBackups
			if len(backups) != numSingles {
				return fmt.Errorf("expected %v singles, "+
					"got %v", len(backups), numSingles)
			}

			return nil
		}, defaultTimeout)
		if err != nil {
			t.Fatalf(err.Error())
		}
	}
	assertMultiBackupFound := func() func(bool, map[wire.OutPoint]struct{}) {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		req := &lnrpc.ChanBackupExportRequest{}
		chanSnapshot, err := carol.ExportAllChannelBackups(ctxt, req)
		if err != nil {
			t.Fatalf("unable to export channel backup: %v", err)
		}

		return func(found bool, chanPoints map[wire.OutPoint]struct{}) {
			switch {
			case found && chanSnapshot.MultiChanBackup == nil:
				t.Fatalf("multi-backup not present")

			case !found && chanSnapshot.MultiChanBackup != nil &&
				(len(chanSnapshot.MultiChanBackup.MultiChanBackup) !=
					chanbackup.NilMultiSizePacked):

				t.Fatalf("found multi-backup when non should " +
					"be found")
			}

			if !found {
				return
			}

			backedUpChans := chanSnapshot.MultiChanBackup.ChanPoints
			if len(chanPoints) != len(backedUpChans) {
				t.Fatalf("expected %v chans got %v", len(chanPoints),
					len(backedUpChans))
			}

			for _, chanPoint := range backedUpChans {
				wirePoint := rpcPointToWirePoint(t, chanPoint)
				if _, ok := chanPoints[wirePoint]; !ok {
					t.Fatalf("unexpected backup: %v", wirePoint)
				}
			}
		}
	}

	chans := make(map[wire.OutPoint]struct{})
	for _, chanPoint := range chanPoints {
		chans[rpcPointToWirePoint(t, chanPoint)] = struct{}{}
	}

	// We should have exactly two single channel backups contained, and we
	// should also have a multi-channel backup.
	assertNumSingleBackups(2)
	assertMultiBackupFound()(true, chans)

	// We'll now close each channel on by one. After we close a channel, we
	// shouldn't be able to find that channel as a backup still. We should
	// also have one less single written to disk.
	for i, chanPoint := range chanPoints {
		ctxt, _ = context.WithTimeout(ctxb, channelCloseTimeout)
		closeChannelAndAssert(
			ctxt, t, net, net.Alice, chanPoint, false,
		)

		assertNumSingleBackups(len(chanPoints) - i - 1)

		delete(chans, rpcPointToWirePoint(t, chanPoint))
		assertMultiBackupFound()(true, chans)
	}

	// At this point we shouldn't have any single or multi-chan backups at
	// all.
	assertNumSingleBackups(0)
	assertMultiBackupFound()(false, nil)
}

// nodeRestorer is a function closure that allows each chanRestoreTestCase to
// control exactly *how* the prior node is restored. This might be using an
// backup obtained over RPC, or the file system, etc.
type nodeRestorer func() (*lntest.HarnessNode, error)

// chanRestoreTestCase describes a test case for an end to end SCB restoration
// work flow. One node will start from scratch using an existing SCB. At the
// end of the est, both nodes should be made whole via the DLP protocol.
type chanRestoreTestCase struct {
	// name is the name of the target test case.
	name string

	// channelsUpdated is false then this means that no updates
	// have taken place within the channel before restore.
	// Otherwise, HTLCs will be settled between the two parties
	// before restoration modifying the balance beyond the initial
	// allocation.
	channelsUpdated bool

	// initiator signals if Dave should be the one that opens the
	// channel to Alice, or if it should be the other way around.
	initiator bool

	// private signals if the channel from Dave to Carol should be
	// private or not.
	private bool

	// unconfirmed signals if the channel from Dave to Carol should be
	// confirmed or not.
	unconfirmed bool

	// anchorCommit is true, then the new anchor commitment type will be
	// used for the channels created in the test.
	anchorCommit bool

	// legacyRevocation signals if a channel with the legacy revocation
	// producer format should also be created before restoring.
	legacyRevocation bool

	// restoreMethod takes an old node, then returns a function
	// closure that'll return the same node, but with its state
	// restored via a custom method. We use this to abstract away
	// _how_ a node is restored from our assertions once the node
	// has been fully restored itself.
	restoreMethod func(oldNode *lntest.HarnessNode,
		backupFilePath string,
		mnemonic []string) (nodeRestorer, error)
}

// testChanRestoreScenario executes a chanRestoreTestCase from end to end,
// ensuring that after Dave restores his channel state according to the
// testCase, the DLP protocol is executed properly and both nodes are made
// whole.
func testChanRestoreScenario(t *harnessTest, net *lntest.NetworkHarness,
	testCase *chanRestoreTestCase, password []byte) {

	const (
		chanAmt = btcutil.Amount(10000000)
		pushAmt = btcutil.Amount(5000000)
	)

	ctxb := context.Background()

	nodeArgs := []string{
		"--minbackoff=50ms",
		"--maxbackoff=1s",
	}
	if testCase.anchorCommit {
		anchorNodeArgs := nodeArgsForCommitType(
			lnrpc.CommitmentType_ANCHORS,
		)
		nodeArgs = append(nodeArgs, anchorNodeArgs...)
	}

	// First, we'll create a brand new node we'll use within the test. If
	// we have a custom backup file specified, then we'll also create that
	// for use.
	dave, mnemonic, _, err := net.NewNodeWithSeed(
		"dave", nodeArgs, password, false,
	)
	if err != nil {
		t.Fatalf("unable to create new node: %v", err)
	}
	// Defer to a closure instead of to shutdownAndAssert due to the value
	// of 'dave' changing throughout the test.
	defer func() {
		shutdownAndAssert(net, t, dave)
	}()
	carol := net.NewNode(t.t, "carol", nodeArgs)
	defer shutdownAndAssert(net, t, carol)

	// Now that our new nodes are created, we'll give them some coins for
	// channel opening and anchor sweeping.
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, carol)

	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.SendCoins(ctxt, t.t, btcutil.SatoshiPerBitcoin, dave)

	var from, to *lntest.HarnessNode
	if testCase.initiator {
		from, to = dave, carol
	} else {
		from, to = carol, dave
	}

	// Next, we'll connect Dave to Carol, and open a new channel to her
	// with a portion pushed.
	net.ConnectNodes(ctxt, t.t, dave, carol)

	// We will either open a confirmed or unconfirmed channel, depending on
	// the requirements of the test case.
	switch {
	case testCase.unconfirmed:
		ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
		_, err := net.OpenPendingChannel(
			ctxt, from, to, chanAmt, pushAmt,
		)
		if err != nil {
			t.Fatalf("couldn't open pending channel: %v", err)
		}

		// Give the pubsub some time to update the channel backup.
		err = wait.NoError(func() error {
			fi, err := os.Stat(dave.ChanBackupPath())
			if err != nil {
				return err
			}
			if fi.Size() <= chanbackup.NilMultiSizePacked {
				return fmt.Errorf("backup file empty")
			}
			return nil
		}, defaultTimeout)
		if err != nil {
			t.Fatalf("channel backup not updated in time: %v", err)
		}

	// Also create channels with the legacy revocation producer format if
	// requested.
	case testCase.legacyRevocation:
		createLegacyRevocationChannel(
			net, t, chanAmt, pushAmt, from, to,
		)

	default:
		ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
		chanPoint := openChannelAndAssert(
			ctxt, t, net, from, to,
			lntest.OpenChannelParams{
				Amt:     chanAmt,
				PushAmt: pushAmt,
				Private: testCase.private,
			},
		)

		// Wait for both sides to see the opened channel.
		ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
		err = dave.WaitForNetworkChannelOpen(ctxt, chanPoint)
		if err != nil {
			t.Fatalf("dave didn't report channel: %v", err)
		}
		err = carol.WaitForNetworkChannelOpen(ctxt, chanPoint)
		if err != nil {
			t.Fatalf("carol didn't report channel: %v", err)
		}
	}

	// If both parties should start with existing channel updates, then
	// we'll send+settle an HTLC between 'from' and 'to' now.
	if testCase.channelsUpdated {
		invoice := &lnrpc.Invoice{
			Memo:  "testing",
			Value: 100000,
		}
		invoiceResp, err := to.AddInvoice(ctxt, invoice)
		if err != nil {
			t.Fatalf("unable to add invoice: %v", err)
		}

		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		err = completePaymentRequests(
			ctxt, from, from.RouterClient,
			[]string{invoiceResp.PaymentRequest}, true,
		)
		if err != nil {
			t.Fatalf("unable to complete payments: %v", err)
		}
	}

	// Before we start the recovery, we'll record the balances of both
	// Carol and Dave to ensure they both sweep their coins at the end.
	balReq := &lnrpc.WalletBalanceRequest{}
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	carolBalResp, err := carol.WalletBalance(ctxt, balReq)
	if err != nil {
		t.Fatalf("unable to get carol's balance: %v", err)
	}
	carolStartingBalance := carolBalResp.ConfirmedBalance

	daveBalance, err := dave.WalletBalance(ctxt, balReq)
	if err != nil {
		t.Fatalf("unable to get carol's balance: %v", err)
	}
	daveStartingBalance := daveBalance.ConfirmedBalance

	// At this point, we'll now execute the restore method to give us the
	// new node we should attempt our assertions against.
	backupFilePath := dave.ChanBackupPath()
	restoredNodeFunc, err := testCase.restoreMethod(
		dave, backupFilePath, mnemonic,
	)
	if err != nil {
		t.Fatalf("unable to prep node restoration: %v", err)
	}

	// Now that we're able to make our restored now, we'll shutdown the old
	// Dave node as we'll be storing it shortly below.
	shutdownAndAssert(net, t, dave)

	// To make sure the channel state is advanced correctly if the channel
	// peer is not online at first, we also shutdown Carol.
	restartCarol, err := net.SuspendNode(carol)
	require.NoError(t.t, err)

	// Next, we'll make a new Dave and start the bulk of our recovery
	// workflow.
	dave, err = restoredNodeFunc()
	if err != nil {
		t.Fatalf("unable to restore node: %v", err)
	}

	// First ensure that the on-chain balance is restored.
	err = wait.NoError(func() error {
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		balReq := &lnrpc.WalletBalanceRequest{}
		daveBalResp, err := dave.WalletBalance(ctxt, balReq)
		if err != nil {
			return err
		}

		daveBal := daveBalResp.ConfirmedBalance
		if daveBal <= 0 {
			return fmt.Errorf("expected positive balance, had %v",
				daveBal)
		}

		return nil
	}, defaultTimeout)
	if err != nil {
		t.Fatalf("On-chain balance not restored: %v", err)
	}

	// We now check that the restored channel is in the proper state. It
	// should not yet be force closing as no connection with the remote
	// peer was established yet. We should also not be able to close the
	// channel.
	assertNumPendingChannels(t, dave, 1, 0)
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	pendingChanResp, err := dave.PendingChannels(
		ctxt, &lnrpc.PendingChannelsRequest{},
	)
	require.NoError(t.t, err)

	// We now need to make sure the server is fully started before we can
	// actually close the channel. This is the first check in CloseChannel
	// so we can try with a nil channel point until we get the correct error
	// to find out if Dave is fully started.
	err = wait.Predicate(func() bool {
		const expectedErr = "must specify channel point"
		ctxc, cancel := context.WithCancel(ctxt)
		defer cancel()

		resp, err := dave.CloseChannel(
			ctxc, &lnrpc.CloseChannelRequest{},
		)
		if err != nil {
			return false
		}

		defer func() { _ = resp.CloseSend() }()

		_, err = resp.Recv()
		if err != nil && strings.Contains(err.Error(), expectedErr) {
			return true
		}

		return false
	}, defaultTimeout)
	require.NoError(t.t, err)

	// We also want to make sure we cannot force close in this state. That
	// would get the state machine in a weird state.
	chanPointParts := strings.Split(
		pendingChanResp.WaitingCloseChannels[0].Channel.ChannelPoint,
		":",
	)
	chanPointIndex, _ := strconv.ParseUint(chanPointParts[1], 10, 32)
	resp, err := dave.CloseChannel(ctxt, &lnrpc.CloseChannelRequest{
		ChannelPoint: &lnrpc.ChannelPoint{
			FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
				FundingTxidStr: chanPointParts[0],
			},
			OutputIndex: uint32(chanPointIndex),
		},
		Force: true,
	})

	// We don't get an error directly but only when reading the first
	// message of the stream.
	require.NoError(t.t, err)
	_, err = resp.Recv()
	require.Error(t.t, err)
	require.Contains(t.t, err.Error(), "cannot close channel with state: ")
	require.Contains(t.t, err.Error(), "ChanStatusRestored")

	// Increase the fee estimate so that the following force close tx will
	// be cpfp'ed in case of anchor commitments.
	net.SetFeeEstimate(30000)

	// Now that we have ensured that the channels restored by the backup are
	// in the correct state even without the remote peer telling us so,
	// let's start up Carol again.
	err = restartCarol()
	require.NoError(t.t, err)

	// Now that we have our new node up, we expect that it'll re-connect to
	// Carol automatically based on the restored backup.
	ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)
	net.EnsureConnected(ctxt, t.t, dave, carol)

	// TODO(roasbeef): move dave restarts?

	// Now we'll assert that both sides properly execute the DLP protocol.
	// We grab their balances now to ensure that they're made whole at the
	// end of the protocol.
	assertDLPExecuted(
		net, t, carol, carolStartingBalance, dave, daveStartingBalance,
		testCase.anchorCommit,
	)
}

// createLegacyRevocationChannel creates a single channel using the legacy
// revocation producer format by using PSBT to signal a special pending channel
// ID.
func createLegacyRevocationChannel(net *lntest.NetworkHarness, t *harnessTest,
	chanAmt, pushAmt btcutil.Amount, from, to *lntest.HarnessNode) {

	ctxb := context.Background()

	// We'll signal to the wallet that we also want to create a channel with
	// the legacy revocation producer format that relies on deriving a
	// private key from the key ring. This is only available during itests
	// to make sure we don't hard depend on the DerivePrivKey method of the
	// key ring. We can signal the wallet by setting a custom pending
	// channel ID. To be able to do that, we need to set a funding shim
	// which is easiest by using PSBT funding. The ID is the hex
	// representation of the string "legacy-revocation".
	itestLegacyFormatChanID := [32]byte{
		0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2d, 0x72, 0x65, 0x76,
		0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	}
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	openChannelReq := lntest.OpenChannelParams{
		Amt:     chanAmt,
		PushAmt: pushAmt,
		FundingShim: &lnrpc.FundingShim{
			Shim: &lnrpc.FundingShim_PsbtShim{
				PsbtShim: &lnrpc.PsbtShim{
					PendingChanId: itestLegacyFormatChanID[:],
				},
			},
		},
	}
	chanUpdates, tempPsbt, err := openChannelPsbt(
		ctxt, from, to, openChannelReq,
	)
	require.NoError(t.t, err)

	// Fund the PSBT by using the source node's wallet.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	fundReq := &walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_Psbt{
			Psbt: tempPsbt,
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
	}
	fundResp, err := from.WalletKitClient.FundPsbt(ctxt, fundReq)
	require.NoError(t.t, err)

	// We have a PSBT that has no witness data yet, which is exactly what we
	// need for the next step of verifying the PSBT with the funding intents.
	_, err = from.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtVerify{
			PsbtVerify: &lnrpc.FundingPsbtVerify{
				PendingChanId: itestLegacyFormatChanID[:],
				FundedPsbt:    fundResp.FundedPsbt,
			},
		},
	})
	require.NoError(t.t, err)

	// Now we'll ask the source node's wallet to sign the PSBT so we can
	// finish the funding flow.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	finalizeReq := &walletrpc.FinalizePsbtRequest{
		FundedPsbt: fundResp.FundedPsbt,
	}
	finalizeRes, err := from.WalletKitClient.FinalizePsbt(
		ctxt, finalizeReq,
	)
	require.NoError(t.t, err)

	// We've signed our PSBT now, let's pass it to the intent again.
	_, err = from.FundingStateStep(ctxb, &lnrpc.FundingTransitionMsg{
		Trigger: &lnrpc.FundingTransitionMsg_PsbtFinalize{
			PsbtFinalize: &lnrpc.FundingPsbtFinalize{
				PendingChanId: itestLegacyFormatChanID[:],
				SignedPsbt:    finalizeRes.SignedPsbt,
			},
		},
	})
	require.NoError(t.t, err)

	// Consume the "channel pending" update. This waits until the funding
	// transaction was fully compiled.
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	updateResp, err := receiveChanUpdate(ctxt, chanUpdates)
	require.NoError(t.t, err)
	upd, ok := updateResp.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	require.True(t.t, ok)
	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: upd.ChanPending.Txid,
		},
		OutputIndex: upd.ChanPending.OutputIndex,
	}

	_ = mineBlocks(t, net, 6, 1)
	ctxt, cancel = context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()
	err = from.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err)
	err = to.WaitForNetworkChannelOpen(ctxt, chanPoint)
	require.NoError(t.t, err)
}

// chanRestoreViaRPC is a helper test method that returns a nodeRestorer
// instance which will restore the target node from a password+seed, then
// trigger a SCB restore using the RPC interface.
func chanRestoreViaRPC(net *lntest.NetworkHarness, password []byte,
	mnemonic []string, multi []byte,
	oldNode *lntest.HarnessNode) (nodeRestorer, error) {

	backup := &lnrpc.RestoreChanBackupRequest_MultiChanBackup{
		MultiChanBackup: multi,
	}

	ctxb := context.Background()

	return func() (*lntest.HarnessNode, error) {
		newNode, err := net.RestoreNodeWithSeed(
			"dave", nil, password, mnemonic, 1000, nil,
			copyPorts(oldNode),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to "+
				"restore node: %v", err)
		}

		_, err = newNode.RestoreChannelBackups(
			ctxb, &lnrpc.RestoreChanBackupRequest{
				Backup: backup,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable "+
				"to restore backups: %v", err)
		}

		return newNode, nil
	}, nil
}

// copyPorts returns a node option function that copies the ports of an existing
// node over to the newly created one.
func copyPorts(oldNode *lntest.HarnessNode) lntest.NodeOption {
	return func(cfg *lntest.NodeConfig) {
		cfg.P2PPort = oldNode.Cfg.P2PPort
		cfg.RPCPort = oldNode.Cfg.RPCPort
		cfg.RESTPort = oldNode.Cfg.RESTPort
		cfg.ProfilePort = oldNode.Cfg.ProfilePort
	}
}
