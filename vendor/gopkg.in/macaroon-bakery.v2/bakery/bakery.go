package bakery

import (
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

// Bakery is a convenience type that contains both an Oven
// and a Checker.
type Bakery struct {
	Oven    *Oven
	Checker *Checker
}

// BakeryParams holds a selection of parameters for the Oven
// and the Checker created by New.
//
// For more fine-grained control of parameters, create the
// Oven or Checker directly.
//
// The zero value is OK to use, but won't allow any authentication
// or third party caveats to be added.
type BakeryParams struct {
	// Logger is used to send log messages. If it is nil,
	// DefaultLogger("bakery") will be used.
	// github.com/juju/loggo will be used for logging.
	Logger Logger

	// Checker holds the checker used to check first party caveats.
	// If this is nil, New will use checkers.New(nil).
	Checker FirstPartyCaveatChecker

	// RootKeyStore holds the root key store to use. If you need to
	// use a different root key store for different operations,
	// you'll need to pass a RootKeyStoreForOps value to NewOven
	// directly.
	//
	// If this is nil, New will use NewMemRootKeyStore().
	// Note that that is almost certain insufficient for production services
	// that are spread across multiple instances or that need
	// to persist keys across restarts.
	RootKeyStore RootKeyStore

	// Locator is used to find out information on third parties when
	// adding third party caveats. If this is nil, no non-local third
	// party caveats can be added.
	Locator ThirdPartyLocator

	// Key holds the private key of the oven. If this is nil,
	// no third party caveats may be added.
	Key *KeyPair

	// OpsAuthorizer is used to check whether operations are authorized
	// by some other already-authorized operation. If it is nil,
	// NewChecker will assume no operation is authorized by any
	// operation except itself.
	OpsAuthorizer OpsAuthorizer

	// Location holds the location to use when creating new macaroons.
	Location string

	// LegacyMacaroonOp holds the operation to associate with old
	// macaroons that don't have associated operations.
	// If this is empty, legacy macaroons will not be associated
	// with any operations.
	LegacyMacaroonOp Op
}

// New returns a new Bakery instance which combines an Oven with a
// Checker for the convenience of callers that wish to use both
// together.
func New(p BakeryParams) *Bakery {
	if p.Checker == nil {
		p.Checker = checkers.New(nil)
	}
	ovenParams := OvenParams{
		Key:              p.Key,
		Namespace:        p.Checker.Namespace(),
		Location:         p.Location,
		Locator:          p.Locator,
		LegacyMacaroonOp: p.LegacyMacaroonOp,
	}
	if p.RootKeyStore != nil {
		ovenParams.RootKeyStoreForOps = func(ops []Op) RootKeyStore {
			return p.RootKeyStore
		}
	}
	oven := NewOven(ovenParams)

	checker := NewChecker(CheckerParams{
		Checker:          p.Checker,
		MacaroonVerifier: oven,
		OpsAuthorizer:    p.OpsAuthorizer,
	})
	return &Bakery{
		Oven:    oven,
		Checker: checker,
	}
}
