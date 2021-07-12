package bakery

import (
	"fmt"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	macaroon "gopkg.in/macaroon.v2"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

// Slice holds a slice of unbound macaroons.
type Slice []*Macaroon

// Bind prepares the macaroon slice for use in a request. This must be
// done before presenting the macaroons to a service for use as
// authorization tokens. The result will only be valid
// if s contains discharge macaroons for all third party
// caveats.
//
// All the macaroons in the returned slice will be copies
// of this in s, not references.
func (s Slice) Bind() macaroon.Slice {
	if len(s) == 0 {
		return nil
	}
	ms := make(macaroon.Slice, len(s))
	ms[0] = s[0].M().Clone()
	rootSig := ms[0].Signature()
	for i, m := range s[1:] {
		m1 := m.M().Clone()
		m1.Bind(rootSig)
		ms[i+1] = m1
	}
	return ms
}

// Purge returns a new slice holding all macaroons in s
// that expire after the given time.
func (ms Slice) Purge(t time.Time) Slice {
	ms1 := make(Slice, 0, len(ms))
	for i, m := range ms {
		et, ok := checkers.ExpiryTime(m.Namespace(), m.M().Caveats())
		if !ok || et.After(t) {
			ms1 = append(ms1, m)
		} else if i == 0 {
			// The primary macaroon has expired, so all its discharges
			// have expired too.
			// TODO purge all discharge macaroons when the macaroon
			// containing their third-party caveat expires.
			return nil
		}
	}
	return ms1
}

// DischargeAll discharges all the third party caveats in the slice for
// which discharge macaroons are not already present, using getDischarge
// to acquire the discharge macaroons. It always returns the slice with
// any acquired discharge macaroons added, even on error. It returns an
// error if all the discharges could not be acquired.
//
// Note that this differs from DischargeAll in that it can be given several existing
// discharges, and that the resulting discharges are not bound to the primary,
// so it's still possible to add caveats and reacquire expired discharges
// without reacquiring the primary macaroon.
func (ms Slice) DischargeAll(ctx context.Context, getDischarge func(ctx context.Context, cav macaroon.Caveat, encryptedCaveat []byte) (*Macaroon, error), localKey *KeyPair) (Slice, error) {
	if len(ms) == 0 {
		return nil, errgo.Newf("no macaroons to discharge")
	}
	ms1 := make(Slice, len(ms))
	copy(ms1, ms)
	// have holds the keys of all the macaroon ids in the slice.
	type needCaveat struct {
		// cav holds the caveat that needs discharge.
		cav macaroon.Caveat
		// encryptedCaveat holds encrypted caveat
		// if it was held externally.
		encryptedCaveat []byte
	}
	var need []needCaveat
	have := make(map[string]bool)
	for _, m := range ms[1:] {
		have[string(m.M().Id())] = true
	}
	// addCaveats adds any required third party caveats to the need slice
	// that aren't already present .
	addCaveats := func(m *Macaroon) {
		for _, cav := range m.M().Caveats() {
			if len(cav.VerificationId) == 0 || have[string(cav.Id)] {
				continue
			}
			need = append(need, needCaveat{
				cav:             cav,
				encryptedCaveat: m.caveatData[string(cav.Id)],
			})
		}
	}
	for _, m := range ms {
		addCaveats(m)
	}
	var errs []error
	for len(need) > 0 {
		cav := need[0]
		need = need[1:]
		var dm *Macaroon
		var err error
		if localKey != nil && cav.cav.Location == "local" {
			// TODO use a small caveat id.
			dm, err = Discharge(ctx, DischargeParams{
				Key:     localKey,
				Checker: localDischargeChecker,
				Caveat:  cav.encryptedCaveat,
				Id:      cav.cav.Id,
				Locator: emptyLocator{},
			})
		} else {
			dm, err = getDischarge(ctx, cav.cav, cav.encryptedCaveat)
		}
		if err != nil {
			errs = append(errs, errgo.NoteMask(err, fmt.Sprintf("cannot get discharge from %q", cav.cav.Location), errgo.Any))
			continue
		}
		ms1 = append(ms1, dm)
		addCaveats(dm)
	}
	if errs != nil {
		// TODO log other errors? Return them all?
		return ms1, errgo.Mask(errs[0], errgo.Any)
	}
	return ms1, nil
}
