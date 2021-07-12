# lightning-onion
This repository houses an implementation of the [Lightning
Network's](lightning.network) onion routing protocol. The Lightning Network
uses onion routing to securely, and privately route HTLC's
(Hash-Time-Locked-Contracts, basically a conditional payment) within the
network.  (A full specification of the protocol can be found amongst the
lighting-rfc repository, specifically within
[BOLT#04](https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md).

The Lightning Network is composed of a series of "payment channels" which are
essentially tubes of money whose balances can instantaneous be reallocated
between two participants. By linking these payment channels in a pair-wise
manner, a network of connect payment channels are created. 

Within the Lightning Network,
[source-routing](https://en.wikipedia.org/wiki/Source_routing) is utilized in
order to give nodes _full_ control over the route their payment follows within
the network. This level of control is highly desirable as with it, senders are
able to fully specify: the total number of hops in their routes, the total
cumulative fee they'll pay to send the payment, and finally the total
worst-case time-lock period enforced by the conditional payment contract.

In line with Bitcoin's spirit of decentralization and censorship resistance, we
employ an onion routing scheme within the [Lightning
protocol](https://github.com/lightningnetwork/lightning-rfc) to prevent the
ability of participants on the network to easily censor payments, as the
participants are not aware of the final destination of any given payment.
Additionally, by encoding payment routes within a mix-net like packet, we are
able to achieve the following security and privacy features: 

  * Participants in a route don't know their exact position within the route
  * Participants within a route don't know the source of the payment, nor the
    ultimate destination of the payment
  * Participants within a route aren't aware _exactly_ how many other
    participants were involved in the payment route
  * Each new payment route is computationally indistinguishable from any other
    payment route

Our current onion routing protocol utilizes a message format derived from
[Sphinx](http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf). In order
to cater Sphinx's mix-format to our specification application, we've made the
following modifications: 

  * We've added a MAC over the entire mix-header as we have no use for SURB's
    (single-use-reply-blocks) in our protocol.
  * Additionally, the end-to-end payload to the destination has been removed in
    order to cut down on the packet-size, and also as we don't currently have a
    use for a large message from payment sender to recipient.
  * We've dropped usage of LIONESS (as we don't need SURB's), and instead
    utilize chacha20 uniformly throughout as a stream cipher.
  * Finally, the mix-header has been extended with a per-hop-payload which
    provides each hops with exact instructions as to how and where to forward
    the payment. This includes the amount to forward, the destination chain,
    and the time-lock value to attach to the outgoing HTLC.


For further information see these resources: 

  * [Olaoluwa's original post to the lightning-dev mailing
    list](http://lists.linuxfoundation.org/pipermail/lightning-dev/2015-December/000384.html). 
  * [Privacy Preserving Decentralized Micropayments](https://scalingbitcoin.org/milan2016/presentations/D1%20-%206%20-%20Olaoluwa%20Osuntokun.pdf) -- presented at Scaling Bitcoin Hong Kong.


In the near future, this repository will be extended to also includes a
application specific version of
[HORNET](https://www.scion-architecture.net/pdf/2015-HORNET.pdf).  
