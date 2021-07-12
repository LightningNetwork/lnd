// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package txsort provides the transaction sorting according to BIP 69.

Overview

BIP 69 defines a standard lexicographical sort order of transaction inputs and
outputs.  This is useful to standardize transactions for faster multi-party
agreement as well as preventing information leaks in a single-party use case.

The BIP goes into more detail, but for a quick and simplistic overview, the
order for inputs is defined as first sorting on the previous output hash and
then on the index as a tie breaker.  The order for outputs is defined as first
sorting on the amount and then on the raw public key script bytes as a tie
breaker.
*/
package txsort
