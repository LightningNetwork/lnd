# lnd Operational Safety Guidelines

## Table of Contents

* [Overview](#overview)
  - [aezeed](#aezeed)
  - [Wallet password](#wallet-password)
  - [TLS](#tls)
  - [Macaroons](#macaroons)
  - [Static Channel Backups (SCBs)](#static-channel-backups-scbs)
  - [Static remote keys](#static-remote-keys)
* [Best practices](#best-practices)
  - [aezeed storage](#aezeed-storage)
  - [File based backups](#file-based-backups)
  - [Keeping Static Channel Backups (SCBs) safe](#keeping-static-channel-backups-scb-safe)
  - [Keep `lnd` updated](#keep-lnd-updated)
  - [Zombie channels](#zombie-channels)
  - [Migrating a node to a new device](#migrating-a-node-to-a-new-device)
  - [Migrating a node from clearnet to Tor](#migrating-a-node-from-clearnet-to-tor)
  - [Prevent data corruption](#prevent-data-corruption)
  - [Don't interrupt `lncli` commands](#dont-interrupt-lncli-commands)
  - [Regular accounting/monitoring](#regular-accountingmonitoring)
  - [Pruned bitcoind node](#pruned-bitcoind-node)
  - [The `--noseedbackup` flag](#the---noseedbackup-flag)
  
## Overview

This chapter describes the security/safety mechanisms that are implemented in
`lnd`. We encourage every person that is planning on putting mainnet funds into
a Lightning Network channel using `lnd` to read this guide carefully.   
As of this writing, `lnd` is still in beta and it is considered `#reckless` to
put any life altering amounts of BTC into the network.   
That said, we constantly put in a lot of effort to make `lnd` safer to use and
more secure. We will update this documentation with each safety mechanism that
we implement.

The first part of this document describes the security elements that are used in
`lnd` and how they work on a high level.   
The second part is a list of best practices that has crystallized from bug
reports, developer recommendations and experiences from a lot of individuals
running mainnet `lnd` nodes during the last 18 months and counting.

### aezeed

This is what all the on-chain private keys are derived from. `aezeed` is similar
to BIP39 as it uses the same word list to encode the seed as a mnemonic phrase.
But this is where the similarities end, because `aezeed` is _not_ compatible
with BIP39. The 24 words of `aezeed` encode a 128 bit entropy (the seed itself),
a wallet birthday (days since BTC genesis block) and a version.   
This data is _encrypted_ with a password using the AEZ cipher suite (hence the
name). Encrypting the content instead of using the password to derive the HD
extended root key has the advantage that the password can actually be checked
for correctness and can also be changed without affecting any of the derived
keys.  
A BIP for the `aezeed` scheme is being written and should be published soon.

Important to know:
* As with any bitcoin seed phrase, never reveal this to any person and store
  the 24 words (and the password) in a safe place.
* You should never run two different `lnd` nodes with the same seed! Even if
  they aren't running at the same time. This will lead to strange/unpredictable
  behavior or even loss of funds. To migrate an `lnd` node to a new device,
  please see the [node migration section](#migrating-a-node-to-a-new-device).
* For more technical information [see the aezeed README](../aezeed/README.md).

### Wallet password

The wallet password is one of the first things that has to be entered if a new
wallet is created using `lnd`. It is completely independent from the `aezeed`
cipher seed passphrase (which is optional). The wallet password is used to
encrypt the sensitive parts of `lnd`'s databases, currently some parts of
`wallet.db` and `macaroons.db`. Loss of this password does not necessarily
mean loss of funds, as long as the `aezeed` passphrase is still available.
But the node will need to be restored using the
[SCB restore procedure](recovery.md).

### TLS

By default the two API connections `lnd` offers (gRPC on port 10009 and REST on
port 8080) use TLS with a self-signed certificate for transport level security.
Specifying the certificate on the client side (for example `lncli`) is only a
protection against man-in-the-middle attacks and does not provide any
authentication. In fact, `lnd` will never even see the certificate that is
supplied to `lncli` with the `--tlscertpath` argument. `lncli` only uses that
certificate to verify it is talking to the correct gRPC server.   
If the key/certificate pair (`tls.cert` and `tls.key` in the main `lnd` data
directory) is missing on startup, a new self-signed key/certificate pair is
generated. Clients connecting to `lnd` then have to use the new certificate
to verify they are talking to the correct server.

#### TLS Key Encryption

By default, LND writes the TLS key to disk in plaintext. If you run in an
untrusted environment you may want to encrypt the TLS key so no one could
snoop on your API traffic. This can be accomplished with the `--tlsencryptkey`
flag in LND. When this is set, LND encrypts the TLS key using the wallet's
seed and writes the encrypted blob to disk.

Because the key is encrypted to the wallet's seed, that means we can only use
the TLS pair when the wallet is unlocked. This would leave the
`WalletUnlocker` service without TLS. To circumvent this problem, LND uses a
temporary TLS pair for the `WalletUnlocker` service. To avoid writing the
temporary key to disk, it is held in memory until the wallet is unlocked. The
temporary TLS cert is written to disk using the same value as `tlscertpath`
with `.tmp` appended to the end. Once the wallet is unlocked, the temporary
TLS cert is deleted from disk and the TLS key is removed from memory. Then
LND uses the main TLS cert and key after it's decrypted.

This requires a slight change in behavior when connecting to LND's APIs.
When `--tlsencryptkey` is set on LND, you will need to access the temporary
TLS cert for the initialize, unlock, and change password API calls. You can
do this in `lncli` by simply pointing the `--tlscertpath` flag at the temporary
TLS cert for the `create`, `unlock`, and `changepassword` commands. If you
aren't able to run `lncli` on the host `lnd` is running on, then you'll need
to copy the temporary certificate from the host onto whatever device you're
using. Ignoring TLS certificate verification is considered insecure and not
recommended.

_Important Considerations:_

- Once you set `--tlsencryptkey` when starting LND, you'll always need to use
the flag. If you don't want to encrypt the TLS key anymore you'll have to
delete the TLS cert and key so LND generates a new one in plaintext.

- The temporary TLS cert still contains the same information as the persistent
certificates

- The temporary TLS cert is only valid for 24 hours while the persistent certs
are valid for more than a year.


### Macaroons

Macaroons are used as the main authentication method in `lnd`. A macaroon is a
cryptographically verifiable token, comparable to a [JWT](https://jwt.io/)
or other form of API access token. In `lnd` this token consists of a _list of
permissions_ (what operations does the user of the token have access to) and a
set of _restrictions_ (e.g. token expiration timestamp, IP address restriction).
`lnd` does not keep track of the individual macaroons issued, only the key that
was used to create (and later verify) them. That means, individual tokens cannot
currently be invalidated, only all of them at once.   
See the [high-level macaroons documentation](macaroons.md) or the [technical
README](../macaroons/README.md) for more information.

Important to know:
* Deleting the `*.macaroon` files in the `<lnd-dir>/data/chain/bitcoin/mainnet/`
  folder will trigger `lnd` to recreate the default macaroons. But this does
  **NOT** invalidate clients that use an old macaroon. To make sure all
  previously generated macaroons are invalidated, the `macaroons.db` has to be
  deleted as well as all `*.macaroon`.

### Static Channel Backups (SCBs)

A Static Channel Backup is a piece of data that contains all _static_
information about a channel, like funding transaction, capacity, key derivation
paths, remote node public key, remote node last known network addresses and
some static settings like CSV timeout and min HTLC setting.   
Such a backup can either be obtained as a file containing entries for multiple
channels or by calling RPC methods to get individual (or all) channel data.
See the section on [keeping SCBs safe](#keeping-static-channel-backups-scb-safe)
for more information.

What the SCB does **not** contain is the current channel balance (or the
associated commitment transaction). So how can a channel be restored using
SCBs?   
That's the important part: _A channel cannot be restored using SCBs_, but the
funds that are in the channel can be claimed. The restore procedure relies on
the Data Loss Prevention (DLP) protocol which works by connecting to the remote
node and asking them to **force close** the channel and hand over the needed
information to sweep the on-chain funds that belong to the local node.   
Because of this, [restoring a node from SCB](recovery.md) should be seen as an
emergency measure as all channels will be closed and on-chain fees incur to the
party that opened the channel initially.   
To migrate an existing, working node to a new device, SCBs are _not_ the way to
do it. See the section about
[migrating a node](#migrating-a-node-to-a-new-device) on how to do it correctly.

Important to know:
* [Restoring a node from SCB](recovery.md) will force-close all channels
  contained in that file.
* Restoring a node from SCB relies on the remote node of each channel to be
  online and respond to the DLP protocol. That's why it's important to
  [get rid of zombie channels](#zombie-channels) because they cannot be
  recovered using SCBs.
* The SCB data is encrypted with a key from the seed the node was created with.
  A node can therefore only be restored from SCB if the seed is also known.

### Static remote keys

Since version `v0.8.0-beta`, `lnd` supports the `option_static_remote_key` (also
known as "safu commitments"). All new channels will be opened with this option
enabled by default, if the other node also supports it.  
In essence, this change makes it possible for a node to sweep their channel
funds if the remote node force-closes, without any further communication between
the nodes. Previous to this change, your node needed to get a random channel
secret (called the `per_commit_point`) from the remote node even if they
force-closed the channel, which could make recovery very difficult.

## Best practices

### aezeed storage

When creating a new wallet, `lnd` will print out 24 words to write down, which
is the wallet's seed (in the [aezeed](#aezeed) format). That seed is optionally
encrypted with a passphrase, also called the _cipher seed passphrase_.   
It is absolutely important to write both the seed and, if set, the password down
and store it in a safe place as **there is no way of exporting the seed from an
lnd wallet**. When creating the wallet, after printing the seed to the command
line, it is hashed and only the hash (or to be more exact, the BIP32 extended
root key) is stored in the `wallet.db` file.   
There is
[a tool being worked on](https://github.com/lightningnetwork/lnd/pull/2373)
that can extract the BIP32 extended root key but currently you cannot restore
lnd with only this root key.

Important to know:
* Setting a password/passphrase for the aezeed is meant to protect it from
  an attacker that finds the paper/storage device. Writing down the password
  alongside the 24 seed words does not enhance the security in any way.
  Therefore the password should be stored in a separate place.

### File based backups

There is a lot of confusion and also some myths about how to best backup the
off-chain funds of an `lnd` node. Making a mistake here is also still the single
biggest risk of losing off-chain funds, even though we do everything to mitigate
those risks.

**What files can/should I regularly backup?**   
The single most important file that needs to be backed up whenever it changes
is the `<lnddir>/data/chain/bitcoin/mainnet/channel.backup` file which holds
the Static Channel Backups (SCBs). This file is only updated every time `lnd`
starts, a channel is opened or a channel is closed.

Most consumer Lightning wallet apps upload the file to the cloud automatically.

See the [SCB chapter](#static-channel-backups-scbs) for more
information on how to use the file to restore channels.

**What files should never be backed up to avoid problems?**   
This is a bit of a trick question, as making the backup is not the problem.
Restoring/using an old version of a specific file called
`<lnddir>/data/graph/mainnet/channel.db` is what is very risky and should
_never_ be done!   
This requires some explanation:    
The way LN channels are currently set up (until `eltoo` is implemented) is that
both parties agree on a current balance. To make sure none of the two peers in
a channel ever try to publish an old state of that balance, they both hand over
their keys to the other peer that gives them the means to take _all_ funds (not
just their agreed upon part) from a channel, if an _old_ state is ever
published. Therefore, having an old state of a channel basically means
forfeiting the balance to the other party.   

As payments in `lnd` can be made multiple times a second, it's very hard to
make a backup of the channel database every time it is updated. And even if it
can be technically done, the confidence that a particular state is certainly the
most up-to-date can never be very high. That's why the focus should be on
[making sure the channel database is not corrupted](#prevent-data-corruption),
[closing out the zombie channels](#zombie-channels) and keeping your SCBs safe.

### Keeping Static Channel Backups (SCB) safe

As mentioned in the previous chapter, there is a file where `lnd` stores and
updates a backup of all channels whenever the node is restarted, a new channel
is opened or a channel is closed:
`<lnddir>/data/chain/bitcoin/mainnet/channel.backup`

One straight-forward way of backing that file up is to create a file watcher and
react whenever the file is changed. Here is an example script that
[automatically makes a copy of the file whenever it changes](https://gist.github.com/alexbosworth/2c5e185aedbdac45a03655b709e255a3).

Other ways of obtaining SCBs for a node's channels are
[described in the recovery documentation](recovery.md#obtaining-scbs).

Because the backup file is encrypted with a key from the seed the node was
created with, it can safely be stored on a cloud storage or any other storage
medium. Many consumer focused wallet smartphone apps automatically store a
backup file to the cloud, if the phone is set up to allow it.

### Keep `lnd` updated

With every larger update of `lnd`, new security features are added. Users are
always encouraged to update their nodes as soon as possible. This also helps the
network in general as new safety features that require compatibility among nodes
can be used sooner.

### Zombie channels

Zombie channels are channels that are most likely dead but are still around.
This can happen if one of the channel peers has gone offline for good (possibly
due to a failure of some sort) and didn't close its channels. The other, still
online node doesn't necessarily know that its partner will never come back
online.

Funds that are in such channels are at great risk, as is described quite
dramatically in
[this article](https://medium.com/@gcomxx/get-rid-of-those-zombie-channels-1267d5a2a708?)
.

The TL;DR of the article is that if you have funds in a zombie channel and you
need to recover your node after a failure, SCBs won't be able to recover those
funds. Because SCB restore
[relies on the remote node cooperating](#static-channel-backups-scbs).

That's why it's important to **close channels with peers that have been
offline** for a length of time as a precautionary measure.

Of course this might not be good advice for a routing node operator that wants
to support mobile users and route for them. Nodes running on a mobile device
tend to be offline for long periods of time. It would be bad for those users if
they needed to open a new channel every time they want to use the wallet.
Most mobile wallets only open private channels as they do not intend to route
payments through them. A routing node operator should therefore take into
account if a channel is public or private when thinking about closing it.

### Migrating a node to a new device

As mentioned in the chapters [aezeed](#aezeed) and
[SCB](#static-channel-backups-scbs) you should never use the same seed on two
different nodes and restoring from SCB is not a migration but an emergency
procedure.   
What is the correct way to migrate an existing node to a new device? There is
an easy way that should work for most people and there's the harder/costlier
fallback way to do it.

**Option 1: Move the whole data directory to the new device**   
This option works very well if the new device runs the same operating system on
the same architecture. If that is the case, the whole `/home/<user>/.lnd`
directory in Linux (or `$HOME/Library/Application Support/lnd` in MacOS,
`%LOCALAPPDATA%\lnd` in Windows) can be moved to the new device and `lnd`
started there. It is important to shut down `lnd` on the old device before
moving the directory!   
**Not supported/untested** is moving the data directory between different
operating systems (for example `MacOS` -> `Linux`) or different system
architectures (for example `32bit` -> `64bit` or `ARM` -> `amd64`). Data
corruption or unexpected behavior can be the result. Users switching between
operating systems or architectures should always use Option 2!

**Option 2: Start from scratch**   
If option 1 does not work or is too risky, the safest course of action is to
initialize the existing node again from scratch. Unfortunately this incurs some
on-chain fee costs as all channels will need to be closed. Using the same seed
means restoring the same network node identity as before. If a new identity
should be created, a new seed needs to be created.   
Follow these steps to create the **same node (with the same seed)** from
scratch:   
1. On the old device, close all channels (`lncli closeallchannels`). The
   command can take up to several minutes depending on the number of channels.
   **Do not interrupt the command!**
1. Wait for all channels to be fully closed. If some nodes don't respond to the
   close request it can be that `lnd` will go ahead and force close those
   channels. This means that the local balance will be time locked for up to
   two weeks (depending on the channel size). Check `lncli pendingchannels` to
   see if any channels are still in the process of being force closed.
1. After all channels are fully closed (and `lncli pendingchannels` lists zero
   channels), `lnd` can be shut down on the old device.
1. Start `lnd` on the new device and create a new wallet with the existing seed
   that was used on the old device (answer "yes" when asked if an existing seed
   should be used).
1. Wait for the wallet to rescan the blockchain. This can take up to several
   hours depending on the age of the seed and the speed of the chain backend.
1. After the chain is fully synced (`lncli getinfo` shows
   `"synced_to_chain": true`) the on-chain funds from the previous device should
   now be visible on the new device as well and new channels can be opened.

**What to do after the move**   
If things don't work as expected on the moved or re-created node, consider this
list things that possibly need to be changed to work on a new device:
* In case the new device has a different hostname and TLS connection problems
  occur, delete the `tls.key` and `tls.cert` files in the data directory and
  restart `lnd` to recreate them.
* If an external IP is set (either with `--externalip` or `--tlsextraip`) these
  might need to be changed if the new machine has a different address. Changing
  the `--tlsextraip` setting also means regenerating the certificate pair. See
  point 1.
* If port `9735` (or `10009` for gRPC) was forwarded on the router, these
  forwarded ports need to point to the new device. The same applies to firewall
  rules.
* It might take more than 24 hours for a new IP address to be visible on
  network explorers.
* If channels show as offline after several hours, try to manually connect to
  the remote peer. They might still try to reach `lnd` on the old address.

### Migrating a node from clearnet to Tor

If an `lnd` node has already been connected to the internet with an IPv4 or IPv6
(clearnet) address and has any non-private channels, this connection between
channels and IP address is known to the network and cannot be deleted.   
Starting the same node with the same identity and channels using Tor is trivial
to link back to any previously used clearnet IP address and does therefore not
provide any privacy benefits.   
The following steps are recommended to cut all links between the old clearnet
node and the new Tor node:
1. Close all channels on the old node and wait for them to fully close.
1. Send all on-chain funds of the old node through a Coin Join service (like
   Wasabi or Samurai/Whirlpool) until a sufficiently high anonymity set is
   reached.
1. Create a new `lnd` node with a **new seed** that is only connected to Tor
   and generate an on-chain address on the new node.
1. Send the mixed/coinjoined coins to the address of the new node.
1. Start opening channels.
1. Check an online network explorer that no IPv4 or IPv6 address is associated
   with the new node's identity.

### Prevent data corruption

Many problems while running an `lnd` node can be prevented by avoiding data
corruption in the channel database (`<lnddir>/data/graph/mainnet/channel.db`).

The following (non-exhaustive) list of things can lead to data corruption:
* A spinning hard drive gets a physical shock.
* `lnd`'s main data directory being written on an SD card or USB thumb drive
  (SD cards and USB thumb drives _must_ be considered unsafe for critical files
  that are written to very often, as the channel DB is).
* `lnd`'s main data directory being written to a network drive without
  `fsync` support.
* Unclean shutdown of `lnd`.
* Aborting channel operation commands (see next chapter).
* Not enough disk space for a growing channel DB file.
* Moving `lnd`'s main data directory between different operating systems/
  architectures.

To avoid most of these factors, it is recommended to store `lnd`'s main data
directory on an Solid State Drive (SSD) of a reliable manufacturer.
An alternative or extension to that is to use a replicated disk setup. Making
sure a power failure does not interrupt the node by running a UPS (
uninterruptible power supply) might also make sense depending on the reliability
of the local power grid and the amount of funds at stake.

### Don't interrupt `lncli` commands

Things can start to take a while to execute if a node has more than 50 to 100
channels. It is extremely important to **never interrupt an `lncli` command**
if it is manipulating the channel database, which is true for the following
commands:
 - `openchannel`
 - `closechannel` and `closeallchannels`
 - `abandonchannel`
 - `updatechanpolicy`
 - `restorechanbackup`

Interrupting any of those commands can lead to an inconsistent state of the
channel database and unpredictable behavior. If it is uncertain if a command
is really stuck or if the node is still working on it, a look at the log file
can help to get an idea.

### Regular accounting/monitoring

Regular monitoring of a node and keeping track of the movement of funds can help
prevent problems. Tools like [`lndmon`](https://github.com/lightninglabs/lndmon)
can assist with these tasks.

### Pruned bitcoind node

Running `lnd` connected to a `bitcoind` node that is running in prune mode is
not supported! `lnd` needs to verify the funding transaction of every channel
in the network and be able to retrieve that information from `bitcoind` which
it cannot deliver when that information is pruned away.

In theory pruning away all blocks _before_ the SegWit activation would work
as LN channels rely on SegWit. But this has neither been tested nor would it
be recommended/supported.

In addition to not running a pruned node, it is recommended to run `bitcoind`
with the `-txindex` flag for performance reasons, though this is not strictly
required.

Multiple `lnd` nodes can run off of a single `bitcoind` instance. There will be
connection/thread/performance limits at some number of `lnd` nodes but in
practice running 2 or 3 `lnd` instances per `bitcoind` node didn't show any
problems.

### The `--noseedbackup` flag

This is a flag that is only used for integration tests and should **never** be
used on mainnet! Turning this flag on means that the 24 word seed will not be
shown when creating a wallet. The seed is required to restore a node in case
of data corruption and without it all funds (on-chain and off-chain) are
being put at risk.
