// Copyright (c) 2016-2017 The btcsuite developers
// Copyright (c) 2016-2017 The Lightning Network Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package gcs provides an API for building and using a Golomb-coded set filter.

Golomb-Coded Set

A Golomb-coded set is a probabilistic data structure used similarly to a Bloom
filter. A filter uses constant-size overhead plus on average n+2 bits per
item added to the filter, where 2^-n is the desired false positive (collision)
probability.

GCS use in Bitcoin

GCS filters are a proposed mechanism for storing and transmitting per-block
filters in Bitcoin. The usage is intended to be the inverse of Bloom filters:
a full node would send an SPV node the GCS filter for a block, which the SPV
node would check against its list of relevant items. The suggested collision
probability for Bitcoin use is 2^-20.
*/
package gcs
