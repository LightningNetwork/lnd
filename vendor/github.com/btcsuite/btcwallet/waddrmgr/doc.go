// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package waddrmgr provides a secure hierarchical deterministic wallet address
manager.

Overview

One of the fundamental jobs of a wallet is to manage addresses, private keys,
and script data associated with them.  At a high level, this package provides
the facilities to perform this task with a focus on security and also allows
recovery through the use of hierarchical deterministic keys (BIP0032) generated
from a caller provided seed.  The specific structure used is as described in
BIP0044.  This setup means as long as the user writes the seed down (even better
is to use a mnemonic for the seed), all their addresses and private keys can be
regenerated from the seed.

There are two master keys which are protected by two independent passphrases.
One is intended for public facing data, while the other is intended for private
data.  The public password can be hardcoded for callers who don't want the
additional public data protection or the same password can be used if a single
password is desired.  These choices provide a usability versus security
tradeoff.  However, keep in mind that extended hd keys, as called out in BIP0032
need to be handled more carefully than normal EC public keys because they can be
used to generate all future addresses.  While this is part of what makes them
attractive, it also means an attacker getting access to your extended public key
for an account will allow them to know all derived addresses you will use and
hence reduces privacy.  For this reason, it is highly recommended that you do
not hard code a password which allows any attacker who gets a copy of your
address manager database to access your effectively plain text extended public
keys.

Each master key in turn protects the three real encryption keys (called crypto
keys) for public, private, and script data.  Some examples include payment
addresses, extended hd keys, and scripts associated with pay-to-script-hash
addresses.  This scheme makes changing passphrases more efficient since only the
crypto keys need to be re-encrypted versus every single piece of information
(which is what is needed for *rekeying*).  This results in a fully encrypted
database where access to it does not compromise address, key, or script privacy.
This differs from the handling by other wallets at the time of this writing in
that they divulge your addresses, and worse, some even expose the chain code
which can be used by the attacker to know all future addresses that will be
used.

The address manager is also hardened against memory scrapers.  This is
accomplished by typically having the address manager locked meaning no private
keys or scripts are in memory.  Unlocking the address manager causes the crypto
private and script keys to be decrypted and loaded in memory which in turn are
used to decrypt private keys and scripts on demand.  Relocking the address
manager actively zeros all private material from memory.  In addition, temp
private key material used internally is zeroed as soon as it's used.

Locking and Unlocking

As previously mentioned, this package provide facilities for locking and
unlocking the address manager to protect access to private material and remove
it from memory when locked.  The Lock, Unlock, and IsLocked functions are used
for this purpose.

Creating a New Address Manager

A new address manager is created via the Create function.  This function accepts
a wallet database namespace, passphrases, network, and perhaps most importantly,
a cryptographically random seed which is used to generate the master node of the
hierarchical deterministic keychain which allows all addresses and private keys
to be recovered with only the seed.  The GenerateSeed function in the hdkeychain
package can be used as a convenient way to create a random seed for use with
this function.  The address manager is locked immediately upon being created.

Opening an Existing Address Manager

An existing address manager is opened via the Open function.  This function
accepts an existing wallet database namespace, the public passphrase, and
network.  The address manager is opened locked as expected since the open
function does not take the private passphrase to unlock it.

Closing the Address Manager

The Close method should be called on the address manager when the caller is done
with it.  While it is not required, it is recommended because it sanely shuts
down the database and ensures all private and public key material is purged from
memory.

Managed Addresses

Each address returned by the address manager satisifies the ManagedAddress
interface as well as either the ManagedPubKeyAddress or ManagedScriptAddress
interfaces.  These interfaces provide the means to obtain relevant information
about the addresses such as their private keys and scripts.

Chained Addresses

Most callers will make use of the chained addresses for normal operations.
Internal addresses are intended for internal wallet uses such as change outputs,
while external addresses are intended for uses such payment addresses that are
shared.  The NextInternalAddresses and NextExternalAddresses functions provide
the means to acquire one or more of the next addresses that have not already
been provided.  In addition, the LastInternalAddress and LastExternalAddress
functions can be used to get the most recently provided internal and external
address, respectively.

Requesting Existing Addresses

In addition to generating new addresses, access to old addresses is often
required.  Most notably, to sign transactions in order to redeem them.  The
Address function provides this capability and returns a ManagedAddress.

Importing Addresses

While the recommended approach is to use the chained addresses discussed above
because they can be deterministically regenerated to avoid losing funds as long
as the user has the master seed, there are many addresses that already exist,
and as a result, this package provides the ability to import existing private
keys in Wallet Import Format (WIF) and hence the associated public key and
address.

Importing Scripts

In order to support pay-to-script-hash transactions, the script must be securely
stored as it is needed to redeem the transaction.  This can be useful for a
variety of scenarios, however the most common use is currently multi-signature
transactions.

Syncing

The address manager also supports storing and retrieving a block hash and height
which the manager is known to have all addresses synced through.  The manager
itself does not have any notion of which addresses are synced or not.  It only
provides the storage as a convenience for the caller.

Network

The address manager must be associated with a given network in order to provide
appropriate addresses and reject imported addresses and scripts which don't
apply to the associated network.

Errors

All errors returned from this package are of type ManagerError.  This allows the
caller to programmatically ascertain the specific reasons for failure by
examining the ErrorCode field of the type asserted ManagerError.  For certain
error codes, as documented by the specific error codes, the underlying error
will be contained in the Err field.

Bitcoin Improvement Proposals

This package includes concepts outlined by the following BIPs:

		BIP0032 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
		BIP0043 (https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki)
		BIP0044 (https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
*/
package waddrmgr
