// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"sync"
)

// cprng is a cryptographically random-seeded math/rand prng.  It is seeded
// during package init.  Any initialization errors result in panics.  It is safe
// for concurrent access.
var cprng = cprngType{}

type cprngType struct {
	r  *mrand.Rand
	mu sync.Mutex
}

func init() {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic("Failed to seed prng: " + err.Error())
	}

	seed := int64(binary.LittleEndian.Uint64(buf))
	cprng.r = mrand.New(mrand.NewSource(seed))
}

func (c *cprngType) Int31n(n int32) int32 {
	defer c.mu.Unlock() // Int31n may panic
	c.mu.Lock()
	return c.r.Int31n(n)
}
