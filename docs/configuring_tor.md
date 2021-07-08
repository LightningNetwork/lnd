# Table of Contents
1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Tor Stream Isolation](#tor-stream-isolation)
4. [Authentication](#authentication)
5. [Listening for Inbound Connections](#listening-for-inbound-connections)

## Overview

`lnd` currently has complete support for using Lightning over
[Tor](https://www.torproject.org/). Usage of Lightning over Tor is valuable as
routing nodes no longer need to potentially expose their location via their
advertised IP address. Additionally, leaf nodes can also protect their location
by using Tor for anonymous networking to establish connections.

With widespread usage of Onion Services within the network, concerns about the
difficulty of proper NAT traversal are alleviated, as usage of onion services
allows nodes to accept inbound connections even if they're behind a NAT. At the
time of writing this documentation, `lnd` supports both types of onion services:
v2 and v3.

Before following the remainder of this documentation, you should ensure that you
already have Tor installed locally. **If you want to run v3 Onion Services, make
sure that you run at least version 0.3.3.6.**
Official instructions to install the latest release of Tor can be found
[here](https://www.torproject.org/docs/tor-doc-unix.html.en).

**NOTE**: This documentation covers how to ensure that `lnd`'s _Lightning
protocol traffic_ is tunneled over Tor. Users must ensure that when also running
a Bitcoin full-node, that it is also proxying all traffic over Tor. If using the
`neutrino` backend for `lnd`, then it will automatically also default to Tor
usage if active within `lnd`.

## Getting Started

First, you'll want to run `tor` locally before starting up `lnd`. Depending on
how you installed Tor, you'll find the configuration file at
`/usr/local/etc/tor/torrc`. Here's an example configuration file that we'll be
using for the remainder of the tutorial:
```text
SOCKSPort 9050
Log notice stdout
ControlPort 9051
CookieAuthentication 1
```

With the configuration file created, you'll then want to start the Tor daemon:
```shell
⛰  tor
Feb 05 17:02:06.501 [notice] Tor 0.3.1.8 (git-ad5027f7dc790624) running on Darwin with Libevent 2.1.8-stable, OpenSSL 1.0.2l, Zlib 1.2.8, Liblzma N/A, and Libzstd N/A.
Feb 05 17:02:06.502 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://www.torproject.org/download/download#warning
Feb 05 17:02:06.502 [notice] Read configuration file "/usr/local/etc/tor/torrc".
Feb 05 17:02:06.506 [notice] Opening Socks listener on 127.0.0.1:9050
Feb 05 17:02:06.506 [notice] Opening Control listener on 127.0.0.1:9051
```

Once the `tor` daemon has started and it has finished bootstrapping, you'll see this in the logs:
```text
Feb 05 17:02:06.000 [notice] Bootstrapped 0%: Starting
Feb 05 17:02:07.000 [notice] Starting with guard context "default"
Feb 05 17:02:07.000 [notice] Bootstrapped 80%: Connecting to the Tor network
Feb 05 17:02:07.000 [notice] Bootstrapped 85%: Finishing handshake with first hop
Feb 05 17:02:08.000 [notice] Bootstrapped 90%: Establishing a Tor circuit
Feb 05 17:02:11.000 [notice] Tor has successfully opened a circuit. Looks like client functionality is working.
Feb 05 17:02:11.000 [notice] Bootstrapped 100%: Done
```

This indicates the daemon is fully bootstrapped and ready to proxy connections.
At this point, we can now start `lnd` with the relevant arguments:

```shell
⛰  ./lnd -h

<snip>

Tor:
      --tor.active                                            Allow outbound and inbound connections to be routed through Tor
      --tor.socks=                                            The host:port that Tor's exposed SOCKS5 proxy is listening on (default: localhost:9050)
      --tor.dns=                                              The DNS server as host:port that Tor will use for SRV queries - NOTE must have TCP resolution enabled (default: soa.nodes.lightning.directory:53)
      --tor.streamisolation                                   Enable Tor stream isolation by randomizing user credentials for each connection.
      --tor.control=                                          The host:port that Tor is listening on for Tor control connections (default: localhost:9051)
      --tor.targetipaddress=                                  IP address that Tor should use as the target of the hidden service
      --tor.password=                                         The password used to arrive at the HashedControlPassword for the control port. If provided, the HASHEDPASSWORD authentication method will be used instead of the SAFECOOKIE one.
      --tor.v2                                                Automatically set up a v2 onion service to listen for inbound connections
      --tor.v3                                                Automatically set up a v3 onion service to listen for inbound connections
      --tor.privatekeypath=                                   The path to the private key of the onion service being created
```

There are a couple things here, so let's dissect them. The `--tor.active` flag
allows `lnd` to route all outbound and inbound connections through Tor.

Outbound connections are possible with the use of the `--tor.socks` and
`--tor.dns` arguments. The `--tor.socks` argument should point to the interface
that the `Tor` daemon is listening on to proxy connections. The `--tor.dns` flag
is required in order to be able to properly automatically bootstrap a set of
peer connections. The `tor` daemon doesn't currently support proxying `SRV`
queries over Tor. So instead, we need to connect directly to the authoritative
DNS server over TCP, in order query for `SRV` records that we can use to
bootstrap our connections.

Inbound connections are possible due to `lnd` automatically creating an onion
service. A path to save the onion service's private key can be specified with
the `--tor.privatekeypath` flag.

Most of these arguments have defaults, so as long as they apply to you, routing
all outbound and inbound connections through Tor can simply be done with either
v2 or v3 onion services:
```shell
⛰  ./lnd --tor.active --tor.v2
```
```shell
⛰  ./lnd --tor.active --tor.v3
```
See [Listening for Inbound Connections](#listening-for-inbound-connections) for
more info about allowing inbound connections via Tor.

Outbound support only can also be used with:
```shell
⛰  ./lnd --tor.active
```

This will allow you to make all outgoing connections over Tor. Listening is
disabled to prevent inadvertent leaks.

## Tor Stream Isolation

Our support for Tor also has an additional privacy enhancing modified: stream
isolation. Usage of this mode means that Tor will always use  _new circuit_ for
each connection. This added features means that it's harder to correlate
connections. As otherwise, several applications using Tor might share the same
circuit.

Activating stream isolation is very straightforward, we only require the
specification of an additional argument:
```shell
⛰  ./lnd --tor.active --tor.streamisolation
```

## Authentication

In order for `lnd` to communicate with the Tor daemon securely, it must first
establish an authenticated connection. `lnd` supports the following Tor control
authentication methods (arguably, from most to least secure):

* `SAFECOOKIE`: This authentication method relies on a cookie created and
  stored by the Tor daemon and is the default assuming the Tor daemon supports
  it by specifying `CookieAuthentication 1` in its configuration file.
* `HASHEDPASSWORD`: This authentication method is stateless as it relies on a
  password hash scheme and may be useful if the Tor daemon is operating under a
  separate host from the `lnd` node. The password hash can be obtained through
  the Tor daemon with `tor --hash-password PASSWORD`, which should then be
  specified in Tor's configuration file with `HashedControlPassword
  PASSWORD_HASH`. Finally, to use it within `lnd`, the `--tor.password` flag
  should be provided with the corresponding password.
* `NULL`: To bypass any authentication at all, this scheme can be used instead.
  It doesn't require any additional flags to `lnd` or configuration options to
  the Tor daemon.

## Listening for Inbound Connections

In order to listen for inbound connections through Tor, an onion service must be
created. There are two types of onion services: v2 and v3. v3 onion services
are the latest generation of onion services and they provide a number of
advantages over the legacy v2 onion services. To learn more about these
benefits, see [Intro to Next Gen Onion Services](https://trac.torproject.org/projects/tor/wiki/doc/NextGenOnions).

Both types can be created and used automatically by `lnd`. Specifying which type
should be used can easily be done by either using the `tor.v2` or `tor.v3` flag.
To prevent unintentional leaking of identifying information, it is also necessary
to add the flag `listen=localhost`.  

For example, v3 onion services can be used with the following flags:
```shell
⛰  ./lnd --tor.active --tor.v3 --listen=localhost
```

This will automatically create a hidden service for your node to use to listen
for inbound connections and advertise itself to the network. The onion service's
private key is saved to a file named `v2_onion_private_key` or
`v3_onion_private_key` depending on the type of onion service used in `lnd`'s
base directory. This will allow `lnd` to recreate the same hidden service upon
restart. If you wish to generate a new onion service, you can simply delete this
file. The path to this private key file can also be modified with the
`--tor.privatekeypath` argument.

You can optionally encrypt the Tor private key by using the `--tor.encryptkey` 
flag. This will still write to the same private key files. However instead of 
writing the plaintext private key, `lnd` encrypts the private key using the 
wallet's seed and writes the encrypted blob to the file.