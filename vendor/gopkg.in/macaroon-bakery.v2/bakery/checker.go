package bakery

import (
	"sort"
	"sync"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	macaroon "gopkg.in/macaroon.v2"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

// Op holds an entity and action to be authorized on that entity.
type Op struct {
	// Entity holds the name of the entity to be authorized.
	// Entity names should not contain spaces and should
	// not start with the prefix "login" or "multi-" (conventionally,
	// entity names will be prefixed with the entity type followed
	// by a hyphen.
	Entity string

	// Action holds the action to perform on the entity, such as "read"
	// or "delete". It is up to the service using a checker to define
	// a set of operations and keep them consistent over time.
	Action string
}

// NoOp holds the empty operation, signifying no authorized
// operation. This is always considered to be authorized.
// See OpsAuthorizer for one place that it's used.
var NoOp = Op{}

// CheckerParams holds parameters for NewChecker.
type CheckerParams struct {
	// Checker is used to check first party caveats when authorizing.
	// If this is nil NewChecker will use checkers.New(nil).
	Checker FirstPartyCaveatChecker

	// OpsAuthorizer is used to check whether operations are authorized
	// by some other already-authorized operation. If it is nil,
	// NewChecker will assume no operation is authorized by any
	// operation except itself.
	OpsAuthorizer OpsAuthorizer

	// MacaroonVerifier is used to verify macaroons.
	MacaroonVerifier MacaroonVerifier

	// Logger is used to log checker operations. If it is nil,
	// DefaultLogger("bakery") will be used.
	Logger Logger
}

// OpsAuthorizer is used to check whether an operation authorizes some other
// operation. For example, a macaroon with an operation allowing general access to a service
// might also grant access to a more specific operation.
type OpsAuthorizer interface {
	// AuthorizeOp reports which elements of queryOps are authorized by
	// authorizedOp. On return, each element of the slice should represent
	// whether the respective element in queryOps has been authorized.
	// An empty returned slice indicates that no operations are authorized.
	// AuthorizeOps may also return third party caveats that apply to
	// the authorized operations. Access will only be authorized when
	// those caveats are discharged by the client.
	//
	// When not all operations can be authorized with the macaroons
	// supplied to Checker.Auth, the checker will call AuthorizeOps
	// with NoOp, because some operations might be authorized
	// regardless of authority. NoOp will always be the last
	// operation queried within any given Allow call.
	//
	// AuthorizeOps should only return an error if authorization cannot be checked
	// (for example because of a database access failure), not because
	// authorization was denied.
	AuthorizeOps(ctx context.Context, authorizedOp Op, queryOps []Op) ([]bool, []checkers.Caveat, error)
}

// AuthInfo information about an authorization decision.
type AuthInfo struct {
	// Macaroons holds all the macaroons that were
	// passed to Auth.
	Macaroons []macaroon.Slice

	// Used records which macaroons were used in the
	// authorization decision. It holds one element for
	// each element of Macaroons. Macaroons that
	// were invalid or unnecessary will have a false entry.
	Used []bool

	// OpIndexes holds the index of each macaroon
	// that was used to authorize an operation.
	OpIndexes map[Op]int
}

// Conditions returns the first party caveat caveat conditions hat apply to
// the given AuthInfo. This can be used to apply appropriate caveats
// to capability macaroons granted via a Checker.Allow call.
func (a *AuthInfo) Conditions() []string {
	var squasher caveatSquasher
	for i, ms := range a.Macaroons {
		if !a.Used[i] {
			continue
		}
		for _, m := range ms {
			for _, cav := range m.Caveats() {
				if len(cav.VerificationId) > 0 {
					continue
				}
				squasher.add(string(cav.Id))
			}
		}
	}
	return squasher.final()
}

// Checker wraps a FirstPartyCaveatChecker and adds authentication and authorization checks.
//
// It uses macaroons as authorization tokens but it is not itself responsible for
// creating the macaroons - see the Oven type (TODO) for one way of doing that.
type Checker struct {
	FirstPartyCaveatChecker
	p CheckerParams
}

// NewChecker returns a new Checker using the given parameters.
func NewChecker(p CheckerParams) *Checker {
	if p.Checker == nil {
		p.Checker = checkers.New(nil)
	}
	if p.Logger == nil {
		p.Logger = DefaultLogger("bakery")
	}
	return &Checker{
		FirstPartyCaveatChecker: p.Checker,
		p: p,
	}
}

// Auth makes a new AuthChecker instance using the
// given macaroons to inform authorization decisions.
func (c *Checker) Auth(mss ...macaroon.Slice) *AuthChecker {
	return &AuthChecker{
		Checker:   c,
		macaroons: mss,
	}
}

// AuthChecker authorizes operations with respect to a user's request.
type AuthChecker struct {
	// Checker is used to check first party caveats.
	*Checker
	macaroons []macaroon.Slice
	// conditions holds the first party caveat conditions
	// that apply to each of the above macaroons.
	conditions [][]string
	initOnce   sync.Once
	initError  error
	initErrors []error
	// authIndexes holds for each potentially authorized operation
	// the indexes of the macaroons that authorize it.
	authIndexes map[Op][]int
}

func (a *AuthChecker) init(ctx context.Context) error {
	a.initOnce.Do(func() {
		a.initError = a.initOnceFunc(ctx)
	})
	return a.initError
}

func (a *AuthChecker) initOnceFunc(ctx context.Context) error {
	a.authIndexes = make(map[Op][]int)
	a.conditions = make([][]string, len(a.macaroons))
	for i, ms := range a.macaroons {
		ops, conditions, err := a.p.MacaroonVerifier.VerifyMacaroon(ctx, ms)
		if err != nil {
			if !isVerificationError(err) {
				return errgo.Notef(err, "cannot retrieve macaroon")
			}
			a.initErrors = append(a.initErrors, errgo.Mask(err))
			continue
		}
		a.p.Logger.Debugf(ctx, "macaroon %d has valid sig; ops %q, conditions %q", i, ops, conditions)
		// It's a valid macaroon (in principle - we haven't checked first party caveats).
		a.conditions[i] = conditions
		for _, op := range ops {
			a.authIndexes[op] = append(a.authIndexes[op], i)
		}
	}
	return nil
}

// Allowed returns an AuthInfo that provides information on all
// operations directly authorized by the macaroons provided
// to Checker.Auth. Note that this does not include operations that would be indirectly
// allowed via the OpAuthorizer.
//
// Allowed returns an error only when there is an underlying storage failure,
// not when operations are not authorized.
func (a *AuthChecker) Allowed(ctx context.Context) (*AuthInfo, error) {
	actx, err := a.newAllowContext(ctx, nil)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	for op, mindexes := range a.authIndexes {
		for _, mindex := range mindexes {
			if actx.status[mindex]&statusOK != 0 {
				actx.status[mindex] |= statusUsed
				actx.opIndexes[op] = mindex
				break
			}
		}
	}
	return actx.newAuthInfo(), nil
}

func (a *allowContext) newAuthInfo() *AuthInfo {
	info := &AuthInfo{
		Macaroons: a.checker.macaroons,
		Used:      make([]bool, len(a.checker.macaroons)),
		OpIndexes: a.opIndexes,
	}
	for i, status := range a.status {
		if status&statusUsed != 0 {
			info.Used[i] = true
		}
	}
	return info
}

// allowContext holds temporary state used by AuthChecker.allowAny.
type allowContext struct {
	checker *AuthChecker

	// status holds used and authorized status of all the
	// request macaroons.
	status []macaroonStatus

	// opIndex holds an entry for each authorized operation
	// that refers to the macaroon that authorized that operation.
	opIndexes map[Op]int

	// authed holds which of the requested operations have
	// been authorized so far.
	authed []bool

	// need holds all of the requested operations that
	// are remaining to be authorized. needIndex holds the
	// index of each of these operations in the original operations slice
	need      []Op
	needIndex []int

	// errors holds any errors encountered during authorization.
	errors []error
}

type macaroonStatus uint8

const (
	statusOK = 1 << iota
	statusUsed
)

func (a *AuthChecker) newAllowContext(ctx context.Context, ops []Op) (*allowContext, error) {
	actx := &allowContext{
		checker:   a,
		status:    make([]macaroonStatus, len(a.macaroons)),
		authed:    make([]bool, len(ops)),
		need:      append([]Op(nil), ops...),
		needIndex: make([]int, len(ops)),
		opIndexes: make(map[Op]int),
	}
	for i := range actx.needIndex {
		actx.needIndex[i] = i
	}
	if err := a.init(ctx); err != nil {
		return actx, errgo.Mask(err)
	}
	// Check all the macaroons with respect to the current context.
	// Technically this is more than we need to do, because some
	// of the macaroons might not authorize the specific operations
	// we're interested in, but that's an optimisation that could happen
	// later if performance becomes an issue with respect to that.
outer:
	for i, ms := range a.macaroons {
		ctx := checkers.ContextWithMacaroons(ctx, a.Namespace(), ms)
		for _, cond := range a.conditions[i] {
			if err := a.CheckFirstPartyCaveat(ctx, cond); err != nil {
				actx.addError(err)
				continue outer
			}
		}
		actx.status[i] = statusOK
	}
	return actx, nil
}

// Macaroons returns the macaroons that were passed
// to Checker.Auth when creating the AuthChecker.
func (a *AuthChecker) Macaroons() []macaroon.Slice {
	return a.macaroons
}

// Allow checks that the authorizer's request is authorized to
// perform all the given operations.
//
// If all the operations are allowed, an AuthInfo is returned holding
// details of the decision.
//
// If an operation was not allowed, an error will be returned which may
// be *DischargeRequiredError holding the operations that remain to
// be authorized in order to allow authorization to
// proceed.
func (a *AuthChecker) Allow(ctx context.Context, ops ...Op) (*AuthInfo, error) {
	actx, err := a.newAllowContext(ctx, ops)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	actx.checkDirect(ctx)
	if len(actx.need) == 0 {
		return actx.newAuthInfo(), nil
	}
	caveats, err := actx.checkIndirect(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if len(actx.need) == 0 && len(caveats) == 0 {
		// No more ops need to be authenticated and no caveats to be discharged.
		return actx.newAuthInfo(), nil
	}
	a.p.Logger.Debugf(ctx, "operations still needed after auth check: %#v", actx.need)
	if len(caveats) == 0 || len(actx.need) > 0 {
		allErrors := make([]error, 0, len(a.initErrors)+len(actx.errors))
		allErrors = append(allErrors, a.initErrors...)
		allErrors = append(allErrors, actx.errors...)
		var err error
		if len(allErrors) > 0 {
			// TODO return all errors?
			a.p.Logger.Infof(ctx, "all auth errors: %q", allErrors)
			err = allErrors[0]
		}
		return nil, errgo.WithCausef(err, ErrPermissionDenied, "")
	}
	return nil, &DischargeRequiredError{
		Message: "some operations have extra caveats",
		Ops:     ops,
		Caveats: caveats,
	}
}

// checkDirect checks which operations are directly authorized by
// the macaroon operations.
func (a *allowContext) checkDirect(ctx context.Context) {
	defer a.updateNeed()
	for i, op := range a.need {
		if op == NoOp {
			// NoOp is always authorized.
			a.authed[a.needIndex[i]] = true
			continue
		}
		for _, mindex := range a.checker.authIndexes[op] {
			if a.status[mindex]&statusOK != 0 {
				a.authed[a.needIndex[i]] = true
				a.status[mindex] |= statusUsed
				a.opIndexes[op] = mindex
				break
			}
		}
	}
}

// checkIndirect checks to see if any of the remaining operations are authorized
// indirectly with the already-authorized operations.
func (a *allowContext) checkIndirect(ctx context.Context) ([]checkers.Caveat, error) {
	if a.checker.p.OpsAuthorizer == nil {
		return nil, nil
	}
	var allCaveats []checkers.Caveat
	for op, mindexes := range a.checker.authIndexes {
		if len(a.need) == 0 {
			break
		}
		for _, mindex := range mindexes {
			if a.status[mindex]&statusOK == 0 {
				continue
			}
			ctx := checkers.ContextWithMacaroons(ctx, a.checker.Namespace(), a.checker.macaroons[mindex])
			authedOK, caveats, err := a.checker.p.OpsAuthorizer.AuthorizeOps(ctx, op, a.need)
			if err != nil {
				return nil, errgo.Mask(err)
			}
			// TODO we could perhaps combine identical third party caveats here.
			allCaveats = append(allCaveats, caveats...)
			for i, ok := range authedOK {
				if !ok {
					continue
				}
				// Operation is authorized. Mark the appropriate macaroon as used,
				// and remove the operation from the needed list so that we don't
				// bother AuthorizeOps with it again.
				a.status[mindex] |= statusUsed
				a.authed[a.needIndex[i]] = true
				a.opIndexes[a.need[i]] = mindex
			}
		}
		a.updateNeed()
	}
	if len(a.need) == 0 {
		return allCaveats, nil
	}
	// We've still got at least one operation unauthorized.
	// Try to see if it can be authorized with no operation at all.
	authedOK, caveats, err := a.checker.p.OpsAuthorizer.AuthorizeOps(ctx, NoOp, a.need)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	allCaveats = append(allCaveats, caveats...)
	for i, ok := range authedOK {
		if ok {
			a.authed[a.needIndex[i]] = true
		}
	}
	a.updateNeed()
	return allCaveats, nil
}

// updateNeed removes all authorized operations from a.need
// and updates a.needIndex appropriately too.
func (a *allowContext) updateNeed() {
	j := 0
	for i, opIndex := range a.needIndex {
		if a.authed[opIndex] {
			continue
		}
		if i != j {
			a.need[j], a.needIndex[j] = a.need[i], a.needIndex[i]
		}
		j++
	}
	a.need, a.needIndex = a.need[0:j], a.needIndex[0:j]
}

func (a *allowContext) addError(err error) {
	a.errors = append(a.errors, err)
}

// caveatSquasher rationalizes first party caveats created for a capability
// by:
//	- including only the earliest time-before caveat.
//	- removing duplicates.
type caveatSquasher struct {
	expiry time.Time
	conds  []string
}

func (c *caveatSquasher) add(cond string) {
	if c.add0(cond) {
		c.conds = append(c.conds, cond)
	}
}

func (c *caveatSquasher) add0(cond string) bool {
	cond, args, err := checkers.ParseCaveat(cond)
	if err != nil {
		// Be safe - if we can't parse the caveat, just leave it there.
		return true
	}
	if cond != checkers.CondTimeBefore {
		return true
	}
	et, err := time.Parse(time.RFC3339Nano, args)
	if err != nil || et.IsZero() {
		// Again, if it doesn't seem valid, leave it alone.
		return true
	}
	if c.expiry.IsZero() || et.Before(c.expiry) {
		c.expiry = et
	}
	return false
}

func (c *caveatSquasher) final() []string {
	if !c.expiry.IsZero() {
		c.conds = append(c.conds, checkers.TimeBeforeCaveat(c.expiry).Condition)
	}
	if len(c.conds) == 0 {
		return nil
	}
	// Make deterministic and eliminate duplicates.
	sort.Strings(c.conds)
	prev := c.conds[0]
	j := 1
	for _, cond := range c.conds[1:] {
		if cond != prev {
			c.conds[j] = cond
			prev = cond
			j++
		}
	}
	c.conds = c.conds[:j]
	return c.conds
}
