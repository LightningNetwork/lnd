package bakery

import (
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v2"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

// DischargeAll gathers discharge macaroons for all the third party
// caveats in m (and any subsequent caveats required by those) using
// getDischarge to acquire each discharge macaroon. It returns a slice
// with m as the first element, followed by all the discharge macaroons.
// All the discharge macaroons will be bound to the primary macaroon.
//
// The getDischarge function is passed the caveat to be discharged;
// encryptedCaveat will be passed the external caveat payload found
// in m, if any.
func DischargeAll(
	ctx context.Context,
	m *Macaroon,
	getDischarge func(ctx context.Context, cav macaroon.Caveat, encryptedCaveat []byte) (*Macaroon, error),
) (macaroon.Slice, error) {
	return DischargeAllWithKey(ctx, m, getDischarge, nil)
}

// DischargeAllWithKey is like DischargeAll except that the localKey
// parameter may optionally hold the key of the client, in which case it
// will be used to discharge any third party caveats with the special
// location "local". In this case, the caveat itself must be "true". This
// can be used be a server to ask a client to prove ownership of the
// private key.
//
// When localKey is nil, DischargeAllWithKey is exactly the same as
// DischargeAll.
func DischargeAllWithKey(
	ctx context.Context,
	m *Macaroon,
	getDischarge func(ctx context.Context, cav macaroon.Caveat, encodedCaveat []byte) (*Macaroon, error),
	localKey *KeyPair,
) (macaroon.Slice, error) {
	discharges, err := Slice{m}.DischargeAll(ctx, getDischarge, localKey)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return discharges.Bind(), nil
}

var localDischargeChecker = ThirdPartyCaveatCheckerFunc(func(_ context.Context, info *ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	if string(info.Condition) != "true" {
		return nil, checkers.ErrCaveatNotRecognized
	}
	return nil, nil
})
