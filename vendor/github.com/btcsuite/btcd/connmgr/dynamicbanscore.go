// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import (
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	// Halflife defines the time (in seconds) by which the transient part
	// of the ban score decays to one half of it's original value.
	Halflife = 60

	// lambda is the decaying constant.
	lambda = math.Ln2 / Halflife

	// Lifetime defines the maximum age of the transient part of the ban
	// score to be considered a non-zero score (in seconds).
	Lifetime = 1800

	// precomputedLen defines the amount of decay factors (one per second) that
	// should be precomputed at initialization.
	precomputedLen = 64
)

// precomputedFactor stores precomputed exponential decay factors for the first
// 'precomputedLen' seconds starting from t == 0.
var precomputedFactor [precomputedLen]float64

// init precomputes decay factors.
func init() {
	for i := range precomputedFactor {
		precomputedFactor[i] = math.Exp(-1.0 * float64(i) * lambda)
	}
}

// decayFactor returns the decay factor at t seconds, using precalculated values
// if available, or calculating the factor if needed.
func decayFactor(t int64) float64 {
	if t < precomputedLen {
		return precomputedFactor[t]
	}
	return math.Exp(-1.0 * float64(t) * lambda)
}

// DynamicBanScore provides dynamic ban scores consisting of a persistent and a
// decaying component. The persistent score could be utilized to create simple
// additive banning policies similar to those found in other bitcoin node
// implementations.
//
// The decaying score enables the creation of evasive logic which handles
// misbehaving peers (especially application layer DoS attacks) gracefully
// by disconnecting and banning peers attempting various kinds of flooding.
// DynamicBanScore allows these two approaches to be used in tandem.
//
// Zero value: Values of type DynamicBanScore are immediately ready for use upon
// declaration.
type DynamicBanScore struct {
	lastUnix   int64
	transient  float64
	persistent uint32
	mtx        sync.Mutex
}

// String returns the ban score as a human-readable string.
func (s *DynamicBanScore) String() string {
	s.mtx.Lock()
	r := fmt.Sprintf("persistent %v + transient %v at %v = %v as of now",
		s.persistent, s.transient, s.lastUnix, s.int(time.Now()))
	s.mtx.Unlock()
	return r
}

// Int returns the current ban score, the sum of the persistent and decaying
// scores.
//
// This function is safe for concurrent access.
func (s *DynamicBanScore) Int() uint32 {
	s.mtx.Lock()
	r := s.int(time.Now())
	s.mtx.Unlock()
	return r
}

// Increase increases both the persistent and decaying scores by the values
// passed as parameters. The resulting score is returned.
//
// This function is safe for concurrent access.
func (s *DynamicBanScore) Increase(persistent, transient uint32) uint32 {
	s.mtx.Lock()
	r := s.increase(persistent, transient, time.Now())
	s.mtx.Unlock()
	return r
}

// Reset set both persistent and decaying scores to zero.
//
// This function is safe for concurrent access.
func (s *DynamicBanScore) Reset() {
	s.mtx.Lock()
	s.persistent = 0
	s.transient = 0
	s.lastUnix = 0
	s.mtx.Unlock()
}

// int returns the ban score, the sum of the persistent and decaying scores at a
// given point in time.
//
// This function is not safe for concurrent access. It is intended to be used
// internally and during testing.
func (s *DynamicBanScore) int(t time.Time) uint32 {
	dt := t.Unix() - s.lastUnix
	if s.transient < 1 || dt < 0 || Lifetime < dt {
		return s.persistent
	}
	return s.persistent + uint32(s.transient*decayFactor(dt))
}

// increase increases the persistent, the decaying or both scores by the values
// passed as parameters. The resulting score is calculated as if the action was
// carried out at the point time represented by the third parameter. The
// resulting score is returned.
//
// This function is not safe for concurrent access.
func (s *DynamicBanScore) increase(persistent, transient uint32, t time.Time) uint32 {
	s.persistent += persistent
	tu := t.Unix()
	dt := tu - s.lastUnix

	if transient > 0 {
		if Lifetime < dt {
			s.transient = 0
		} else if s.transient > 1 && dt > 0 {
			s.transient *= decayFactor(dt)
		}
		s.transient += float64(transient)
		s.lastUnix = tu
	}
	return s.persistent + uint32(s.transient)
}
