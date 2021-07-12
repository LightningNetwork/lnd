package bakery

import "gopkg.in/macaroon.v2"

// Version represents a version of the bakery protocol.
type Version int

const (
	// In version 0, discharge-required errors use status 407
	Version0 Version = 0
	// In version 1,  discharge-required errors use status 401.
	Version1 Version = 1
	// In version 2, binary macaroons and caveat ids are supported.
	Version2 Version = 2
	// In version 3, we support operations associated with macaroons
	// and external third party caveats.
	Version3      Version = 3
	LatestVersion         = Version3
)

// MacaroonVersion returns the macaroon version that should
// be used with the given bakery Version.
func MacaroonVersion(v Version) macaroon.Version {
	switch v {
	case Version0, Version1:
		return macaroon.V1
	default:
		return macaroon.V2
	}
}
