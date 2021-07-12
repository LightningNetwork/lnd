package banman

// Reason includes the different possible reasons which caused us to ban a peer.
type Reason uint8

// We prevent using `iota` to ensure the order does not have the value since
// these are serialized within the database.
const (
	// ExcedeedBanThreshold signals that a peer exceeded its ban threshold.
	ExceededBanThreshold Reason = 1

	// NoCompactFilters signals that a peer was unable to serve us compact
	// filters.
	NoCompactFilters Reason = 2

	// InvalidFilterHeader signals that a peer served us an invalid filter
	// header.
	InvalidFilterHeader Reason = 3

	// InvalidFilterHeaderCheckpoint signals that a peer served us an
	// invalid filter header checkpoint.
	InvalidFilterHeaderCheckpoint Reason = 4
)

// String returns a human-readable description for the reason a peer was banned.
func (r Reason) String() string {
	switch r {
	case ExceededBanThreshold:
		return "peer exceeded ban threshold"

	case NoCompactFilters:
		return "peer was unable to serve compact filters"

	case InvalidFilterHeader:
		return "peer served invalid filter header"

	case InvalidFilterHeaderCheckpoint:
		return "peer served invalid filter header checkpoint"

	default:
		return "unknown reason"
	}
}
