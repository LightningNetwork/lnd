// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// RescanProgressMsg reports the current progress made by a rescan for a
// set of wallet addresses.
type RescanProgressMsg struct {
	Addresses    []btcutil.Address
	Notification *chain.RescanProgress
}

// RescanFinishedMsg reports the addresses that were rescanned when a
// rescanfinished message was received rescanning a batch of addresses.
type RescanFinishedMsg struct {
	Addresses    []btcutil.Address
	Notification *chain.RescanFinished
}

// RescanJob is a job to be processed by the RescanManager.  The job includes
// a set of wallet addresses, a starting height to begin the rescan, and
// outpoints spendable by the addresses thought to be unspent.  After the
// rescan completes, the error result of the rescan RPC is sent on the Err
// channel.
type RescanJob struct {
	InitialSync bool
	Addrs       []btcutil.Address
	OutPoints   map[wire.OutPoint]btcutil.Address
	BlockStamp  waddrmgr.BlockStamp
	err         chan error
}

// rescanBatch is a collection of one or more RescanJobs that were merged
// together before a rescan is performed.
type rescanBatch struct {
	initialSync bool
	addrs       []btcutil.Address
	outpoints   map[wire.OutPoint]btcutil.Address
	bs          waddrmgr.BlockStamp
	errChans    []chan error
}

// SubmitRescan submits a RescanJob to the RescanManager.  A channel is
// returned with the final error of the rescan.  The channel is buffered
// and does not need to be read to prevent a deadlock.
func (w *Wallet) SubmitRescan(job *RescanJob) <-chan error {
	errChan := make(chan error, 1)
	job.err = errChan
	select {
	case w.rescanAddJob <- job:
	case <-w.quitChan():
		errChan <- ErrWalletShuttingDown
	}
	return errChan
}

// batch creates the rescanBatch for a single rescan job.
func (job *RescanJob) batch() *rescanBatch {
	return &rescanBatch{
		initialSync: job.InitialSync,
		addrs:       job.Addrs,
		outpoints:   job.OutPoints,
		bs:          job.BlockStamp,
		errChans:    []chan error{job.err},
	}
}

// merge merges the work from k into j, setting the starting height to
// the minimum of the two jobs.  This method does not check for
// duplicate addresses or outpoints.
func (b *rescanBatch) merge(job *RescanJob) {
	if job.InitialSync {
		b.initialSync = true
	}
	b.addrs = append(b.addrs, job.Addrs...)

	for op, addr := range job.OutPoints {
		b.outpoints[op] = addr
	}

	if job.BlockStamp.Height < b.bs.Height {
		b.bs = job.BlockStamp
	}
	b.errChans = append(b.errChans, job.err)
}

// done iterates through all error channels, duplicating sending the error
// to inform callers that the rescan finished (or could not complete due
// to an error).
func (b *rescanBatch) done(err error) {
	for _, c := range b.errChans {
		c <- err
	}
}

// rescanBatchHandler handles incoming rescan request, serializing rescan
// submissions, and possibly batching many waiting requests together so they
// can be handled by a single rescan after the current one completes.
func (w *Wallet) rescanBatchHandler() {
	defer w.wg.Done()

	var curBatch, nextBatch *rescanBatch
	quit := w.quitChan()

	for {
		select {
		case job := <-w.rescanAddJob:
			if curBatch == nil {
				// Set current batch as this job and send
				// request.
				curBatch = job.batch()
				select {
				case w.rescanBatch <- curBatch:
				case <-quit:
					job.err <- ErrWalletShuttingDown
					return
				}
			} else {
				// Create next batch if it doesn't exist, or
				// merge the job.
				if nextBatch == nil {
					nextBatch = job.batch()
				} else {
					nextBatch.merge(job)
				}
			}

		case n := <-w.rescanNotifications:
			switch n := n.(type) {
			case *chain.RescanProgress:
				if curBatch == nil {
					log.Warnf("Received rescan progress " +
						"notification but no rescan " +
						"currently running")
					continue
				}
				select {
				case w.rescanProgress <- &RescanProgressMsg{
					Addresses:    curBatch.addrs,
					Notification: n,
				}:
				case <-quit:
					for _, errChan := range curBatch.errChans {
						errChan <- ErrWalletShuttingDown
					}
					return
				}

			case *chain.RescanFinished:
				if curBatch == nil {
					log.Warnf("Received rescan finished " +
						"notification but no rescan " +
						"currently running")
					continue
				}
				select {
				case w.rescanFinished <- &RescanFinishedMsg{
					Addresses:    curBatch.addrs,
					Notification: n,
				}:
				case <-quit:
					for _, errChan := range curBatch.errChans {
						errChan <- ErrWalletShuttingDown
					}
					return
				}

				curBatch, nextBatch = nextBatch, nil

				if curBatch != nil {
					select {
					case w.rescanBatch <- curBatch:
					case <-quit:
						for _, errChan := range curBatch.errChans {
							errChan <- ErrWalletShuttingDown
						}
						return
					}
				}

			default:
				// Unexpected message
				panic(n)
			}

		case <-quit:
			return
		}
	}
}

// rescanProgressHandler handles notifications for partially and fully completed
// rescans by marking each rescanned address as partially or fully synced.
func (w *Wallet) rescanProgressHandler() {
	quit := w.quitChan()
out:
	for {
		// These can't be processed out of order since both chans are
		// unbuffured and are sent from same context (the batch
		// handler).
		select {
		case msg := <-w.rescanProgress:
			n := msg.Notification
			log.Infof("Rescanned through block %v (height %d)",
				n.Hash, n.Height)

		case msg := <-w.rescanFinished:
			n := msg.Notification
			addrs := msg.Addresses
			noun := pickNoun(len(addrs), "address", "addresses")
			log.Infof("Finished rescan for %d %s (synced to block "+
				"%s, height %d)", len(addrs), noun, n.Hash,
				n.Height)

			go w.resendUnminedTxs()

		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// rescanRPCHandler reads batch jobs sent by rescanBatchHandler and sends the
// RPC requests to perform a rescan.  New jobs are not read until a rescan
// finishes.
func (w *Wallet) rescanRPCHandler() {
	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("rescanRPCHandler called without an RPC client")
		w.wg.Done()
		return
	}

	quit := w.quitChan()

out:
	for {
		select {
		case batch := <-w.rescanBatch:
			// Log the newly-started rescan.
			numAddrs := len(batch.addrs)
			noun := pickNoun(numAddrs, "address", "addresses")
			log.Infof("Started rescan from block %v (height %d) for %d %s",
				batch.bs.Hash, batch.bs.Height, numAddrs, noun)

			err := chainClient.Rescan(&batch.bs.Hash, batch.addrs,
				batch.outpoints)
			if err != nil {
				log.Errorf("Rescan for %d %s failed: %v", numAddrs,
					noun, err)
			}
			batch.done(err)
		case <-quit:
			break out
		}
	}

	w.wg.Done()
}

// Rescan begins a rescan for all active addresses and unspent outputs of
// a wallet.  This is intended to be used to sync a wallet back up to the
// current best block in the main chain, and is considered an initial sync
// rescan.
func (w *Wallet) Rescan(addrs []btcutil.Address, unspent []wtxmgr.Credit) error {
	return w.rescanWithTarget(addrs, unspent, nil)
}

// rescanWithTarget performs a rescan starting at the optional startStamp. If
// none is provided, the rescan will begin from the manager's sync tip.
func (w *Wallet) rescanWithTarget(addrs []btcutil.Address,
	unspent []wtxmgr.Credit, startStamp *waddrmgr.BlockStamp) error {

	outpoints := make(map[wire.OutPoint]btcutil.Address, len(unspent))
	for _, output := range unspent {
		_, outputAddrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if err != nil {
			return err
		}

		outpoints[output.OutPoint] = outputAddrs[0]
	}

	// If a start block stamp was provided, we will use that as the initial
	// starting point for the rescan.
	if startStamp == nil {
		startStamp = &waddrmgr.BlockStamp{}
		*startStamp = w.Manager.SyncedTo()
	}

	job := &RescanJob{
		InitialSync: true,
		Addrs:       addrs,
		OutPoints:   outpoints,
		BlockStamp:  *startStamp,
	}

	// Submit merged job and block until rescan completes.
	select {
	case err := <-w.SubmitRescan(job):
		return err
	case <-w.quitChan():
		return ErrWalletShuttingDown
	}
}
