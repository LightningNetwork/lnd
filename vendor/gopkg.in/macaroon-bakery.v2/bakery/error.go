package bakery

import (
	"fmt"

	errgo "gopkg.in/errgo.v1"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

var (
	// ErrNotFound is returned by Store.Get implementations
	// to signal that an id has not been found.
	ErrNotFound = errgo.New("not found")

	// ErrPermissionDenied is returned from AuthChecker when
	// permission has been denied.
	ErrPermissionDenied = errgo.New("permission denied")
)

// DischargeRequiredError is returned when authorization has failed and a
// discharged macaroon might fix it.
//
// A caller should grant the user the ability to authorize by minting a
// macaroon associated with Ops (see MacaroonStore.MacaroonIdInfo for
// how the associated operations are retrieved) and adding Caveats. If
// the user succeeds in discharging the caveats, the authorization will
// be granted.
type DischargeRequiredError struct {
	// Message holds some reason why the authorization was denied.
	// TODO this is insufficient (and maybe unnecessary) because we
	// can have multiple errors.
	Message string

	// Ops holds all the operations that were not authorized.
	// If Ops contains a single LoginOp member, the macaroon
	// should be treated as an login token. Login tokens (also
	// known as authentication macaroons) usually have a longer
	// life span than other macaroons.
	Ops []Op

	// Caveats holds the caveats that must be added
	// to macaroons that authorize the above operations.
	Caveats []checkers.Caveat

	// ForAuthentication holds whether the macaroon holding
	// the discharges will be used for authentication, and hence
	// should have wider scope and longer lifetime.
	// The bakery package never sets this field, but bakery/identchecker
	// uses it.
	ForAuthentication bool
}

func (e *DischargeRequiredError) Error() string {
	return "macaroon discharge required: " + e.Message
}

func IsDischargeRequiredError(err error) bool {
	_, ok := err.(*DischargeRequiredError)
	return ok
}

// VerificationError is used to signify that an error is because
// of a verification failure rather than because verification
// could not be done.
type VerificationError struct {
	Reason error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("verification failed: %v", e.Reason)
}

func isVerificationError(err error) bool {
	_, ok := errgo.Cause(err).(*VerificationError)
	return ok
}
