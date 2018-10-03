package feature

// NegotiationLevel specifies our advertised support for a feature when
// connection to remote peers.
type NegotiationLevel int

const (
	// NegotiationOff signals that we will not advertise a feature.
	NegotiationOff NegotiationLevel = 0

	// NegotiationOptional signals that we will not advertise optional
	// support for a feature.
	NegotiationOptional = 1

	// NegotiationRequired signals that we will not advertise required
	// support for a feature.
	NegotiationRequired = 2
)

// IsOff returns true if the negotiation level is off.
func (l NegotiationLevel) IsOff() bool {
	return l == NegotiationOff
}

// IsOptional returns true if the negotiation level is optional.
func (l NegotiationLevel) IsOptional() bool {
	return l == NegotiationOptional
}

// IsRequired returns true if the negotiation level is required.
func (l NegotiationLevel) IsRequired() bool {
	return l == NegotiationRequired
}
