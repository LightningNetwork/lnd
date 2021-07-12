// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package hdkeychain provides an API for bitcoin hierarchical deterministic
extended keys (BIP0032).

Overview

The ability to implement hierarchical deterministic wallets depends on the
ability to create and derive hierarchical deterministic extended keys.

At a high level, this package provides support for those hierarchical
deterministic extended keys by providing an ExtendedKey type and supporting
functions.  Each extended key can either be a private or public extended key
which itself is capable of deriving a child extended key.

Determining the Extended Key Type

Whether an extended key is a private or public extended key can be determined
with the IsPrivate function.

Transaction Signing Keys and Payment Addresses

In order to create and sign transactions, or provide others with addresses to
send funds to, the underlying key and address material must be accessible.  This
package provides the ECPubKey, ECPrivKey, and Address functions for this
purpose.

The Master Node

As previously mentioned, the extended keys are hierarchical meaning they are
used to form a tree.  The root of that tree is called the master node and this
package provides the NewMaster function to create it from a cryptographically
random seed.  The GenerateSeed function is provided as a convenient way to
create a random seed for use with the NewMaster function.

Deriving Children

Once you have created a tree root (or have deserialized an extended key as
discussed later), the child extended keys can be derived by using the Child
function.  The Child function supports deriving both normal (non-hardened) and
hardened child extended keys.  In order to derive a hardened extended key, use
the HardenedKeyStart constant + the hardened key number as the index to the
Child function.  This provides the ability to cascade the keys into a tree and
hence generate the hierarchical deterministic key chains.

Normal vs Hardened Child Extended Keys

A private extended key can be used to derive both hardened and non-hardened
(normal) child private and public extended keys.  A public extended key can only
be used to derive non-hardened child public extended keys.  As enumerated in
BIP0032 "knowledge of the extended public key plus any non-hardened private key
descending from it is equivalent to knowing the extended private key (and thus
every private and public key descending from it).  This means that extended
public keys must be treated more carefully than regular public keys. It is also
the reason for the existence of hardened keys, and why they are used for the
account level in the tree. This way, a leak of an account-specific (or below)
private key never risks compromising the master or other accounts."

Neutering a Private Extended Key

A private extended key can be converted to a new instance of the corresponding
public extended key with the Neuter function.  The original extended key is not
modified.  A public extended key is still capable of deriving non-hardened child
public extended keys.

Serializing and Deserializing Extended Keys

Extended keys are serialized and deserialized with the String and
NewKeyFromString functions.  The serialized key is a Base58-encoded string which
looks like the following:
	public key:   xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw
	private key:  xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7

Network

Extended keys are much like normal Bitcoin addresses in that they have version
bytes which tie them to a specific network.  The SetNet and IsForNet functions
are provided to set and determinine which network an extended key is associated
with.
*/
package hdkeychain
