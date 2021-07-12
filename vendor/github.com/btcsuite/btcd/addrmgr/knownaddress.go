// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"time"

	"github.com/btcsuite/btcd/wire"
)

// KnownAddress tracks information about a known network address that is used
// to determine how viable an address is.
type KnownAddress struct {
	na          *wire.NetAddress
	srcAddr     *wire.NetAddress
	attempts    int
	lastattempt time.Time
	lastsuccess time.Time
	tried       bool
	refs        int // reference count of new buckets
}

// NetAddress returns the underlying wire.NetAddress associated with the
// known address.
func (ka *KnownAddress) NetAddress() *wire.NetAddress {
	return ka.na
}

// LastAttempt returns the last time the known address was attempted.
func (ka *KnownAddress) LastAttempt() time.Time {
	return ka.lastattempt
}

// Services returns the services supported by the peer with the known address.
func (ka *KnownAddress) Services() wire.ServiceFlag {
	return ka.na.Services
}

// chance returns the selection probability for a known address.  The priority
// depends upon how recently the address has been seen, how recently it was last
// attempted and how often attempts to connect to it have failed.
func (ka *KnownAddress) chance() float64 {
	now := time.Now()
	lastAttempt := now.Sub(ka.lastattempt)

	if lastAttempt < 0 {
		lastAttempt = 0
	}

	c := 1.0

	// Very recent attempts are less likely to be retried.
	if lastAttempt < 10*time.Minute {
		c *= 0.01
	}

	// Failed attempts deprioritise.
	for i := ka.attempts; i > 0; i-- {
		c /= 1.5
	}

	return c
}

// isBad returns true if the address in question has not been tried in the last
// minute and meets one of the following criteria:
// 1) It claims to be from the future
// 2) It hasn't been seen in over a month
// 3) It has failed at least three times and never succeeded
// 4) It has failed ten times in the last week
// All addresses that meet these criteria are assumed to be worthless and not
// worth keeping hold of.
func (ka *KnownAddress) isBad() bool {
	if ka.lastattempt.After(time.Now().Add(-1 * time.Minute)) {
		return false
	}

	// From the future?
	if ka.na.Timestamp.After(time.Now().Add(10 * time.Minute)) {
		return true
	}

	// Over a month old?
	if ka.na.Timestamp.Before(time.Now().Add(-1 * numMissingDays * time.Hour * 24)) {
		return true
	}

	// Never succeeded?
	if ka.lastsuccess.IsZero() && ka.attempts >= numRetries {
		return true
	}

	// Hasn't succeeded in too long?
	if !ka.lastsuccess.After(time.Now().Add(-1*minBadDays*time.Hour*24)) &&
		ka.attempts >= maxFailures {
		return true
	}

	return false
}
