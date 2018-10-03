package feature

// Conf houses the command-line configuration options for controlling
// advertisement of feature bits.
type Conf struct {
	// SupportGossipQueries configures our advertised support for the gossip
	// queries feature.
	SupportGossipQueries NegotiationLevel `long:"support-gossip-queries" description:"Negotiates support for gossip queries feature with peers at requested level -- 1:optional, 2:required (default: 1)"`

	// SupportDataLossProtection configures our advertised support for the
	// data loss protection feature.
	SupportDataLossProtection NegotiationLevel `long:"support-data-loss-protection" description:"Negotiates support for data loss protection feature with peers at requested level -- 1:optional, 2:required (default: 1)"`
}
