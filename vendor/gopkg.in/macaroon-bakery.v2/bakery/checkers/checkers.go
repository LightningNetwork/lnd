// The checkers package provides some standard first-party
// caveat checkers and some primitives for combining them.
package checkers

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
)

// StdNamespace holds the URI of the standard checkers schema.
const StdNamespace = "std"

// Constants for all the standard caveat conditions.
// First and third party caveat conditions are both defined here,
// even though notionally they exist in separate name spaces.
const (
	CondDeclared   = "declared"
	CondTimeBefore = "time-before"
	CondError      = "error"
)

const (
	CondNeedDeclared = "need-declared"
)

// Func is the type of a function used by Checker to check a caveat. The
// cond parameter will hold the caveat condition including any namespace
// prefix; the arg parameter will hold any additional caveat argument
// text.
type Func func(ctx context.Context, cond, arg string) error

// CheckerInfo holds information on a registered checker.
type CheckerInfo struct {
	// Check holds the actual checker function.
	Check Func
	// Prefix holds the prefix for the checker condition.
	Prefix string
	// Name holds the name of the checker condition.
	Name string
	// Namespace holds the namespace URI for the checker's
	// schema.
	Namespace string
}

var allCheckers = map[string]Func{
	CondTimeBefore: checkTimeBefore,
	CondDeclared:   checkDeclared,
	CondError:      checkError,
}

// NewEmpty returns a checker using the given namespace
// that has no registered checkers.
// If ns is nil, a new one will be created.
func NewEmpty(ns *Namespace) *Checker {
	if ns == nil {
		ns = NewNamespace(nil)
	}
	return &Checker{
		namespace: ns,
		checkers:  make(map[string]CheckerInfo),
	}
}

// RegisterStd registers all the standard checkers in the given checker.
// If not present already, the standard checkers schema (StdNamespace) is
// added to the checker's namespace with an empty prefix.
func RegisterStd(c *Checker) {
	c.namespace.Register(StdNamespace, "")
	for cond, check := range allCheckers {
		c.Register(cond, StdNamespace, check)
	}
}

// New returns a checker with all the standard caveats checkers registered.
// If ns is nil, a new one will be created.
// The standard namespace is also added to ns if not present.
func New(ns *Namespace) *Checker {
	c := NewEmpty(ns)
	RegisterStd(c)
	return c
}

// Checker holds a set of checkers for first party caveats.
// It implements bakery.CheckFirstParty caveat.
type Checker struct {
	namespace *Namespace
	checkers  map[string]CheckerInfo
}

// Register registers the given condition in the given namespace URI
// to be checked with the given check function.
// It will panic if the namespace is not registered or
// if the condition has already been registered.
func (c *Checker) Register(cond, uri string, check Func) {
	if check == nil {
		panic(fmt.Errorf("nil check function registered for namespace %q when registering condition %q", uri, cond))
	}
	prefix, ok := c.namespace.Resolve(uri)
	if !ok {
		panic(fmt.Errorf("no prefix registered for namespace %q when registering condition %q", uri, cond))
	}
	if prefix == "" && strings.Contains(cond, ":") {
		panic(fmt.Errorf("caveat condition %q in namespace %q contains a colon but its prefix is empty", cond, uri))
	}
	fullCond := ConditionWithPrefix(prefix, cond)
	if info, ok := c.checkers[fullCond]; ok {
		panic(fmt.Errorf("checker for %q (namespace %q) already registered in namespace %q", fullCond, uri, info.Namespace))
	}
	c.checkers[fullCond] = CheckerInfo{
		Check:     check,
		Namespace: uri,
		Name:      cond,
		Prefix:    prefix,
	}
}

// Info returns information on all the registered checkers, sorted by namespace
// and then name.
func (c *Checker) Info() []CheckerInfo {
	checkers := make([]CheckerInfo, 0, len(c.checkers))
	for _, c := range c.checkers {
		checkers = append(checkers, c)
	}
	sort.Sort(checkerInfoByName(checkers))
	return checkers
}

// Namespace returns the namespace associated with the
// checker. It implements bakery.FirstPartyCaveatChecker.Namespace.
func (c *Checker) Namespace() *Namespace {
	return c.namespace
}

// CheckFirstPartyCaveat implements bakery.FirstPartyCaveatChecker
// by checking the caveat against all registered caveats conditions.
func (c *Checker) CheckFirstPartyCaveat(ctx context.Context, cav string) error {
	cond, arg, err := ParseCaveat(cav)
	if err != nil {
		// If we can't parse it, perhaps it's in some other format,
		// return a not-recognised error.
		return errgo.WithCausef(err, ErrCaveatNotRecognized, "cannot parse caveat %q", cav)
	}
	cf, ok := c.checkers[cond]
	if !ok {
		return errgo.NoteMask(ErrCaveatNotRecognized, fmt.Sprintf("caveat %q not satisfied", cav), errgo.Any)
	}
	if err := cf.Check(ctx, cond, arg); err != nil {
		return errgo.NoteMask(err, fmt.Sprintf("caveat %q not satisfied", cav), errgo.Any)
	}
	return nil
}

var errBadCaveat = errgo.New("bad caveat")

func checkError(ctx context.Context, _, arg string) error {
	return errBadCaveat
}

// ErrCaveatNotRecognized is the cause of errors returned
// from caveat checkers when the caveat was not
// recognized.
var ErrCaveatNotRecognized = errgo.New("caveat not recognized")

// Caveat represents a condition that must be true for a check to
// complete successfully. If Location is non-empty, the caveat must be
// discharged by a third party at the given location.
// The Namespace field holds the namespace URI of the
// condition - if it is non-empty, it will be converted to
// a namespace prefix before adding to the macaroon.
type Caveat struct {
	Condition string
	Namespace string
	Location  string
}

// Condition builds a caveat condition from the given name and argument.
func Condition(name, arg string) string {
	if arg == "" {
		return name
	}
	return name + " " + arg
}

func firstParty(name, arg string) Caveat {
	return Caveat{
		Condition: Condition(name, arg),
		Namespace: StdNamespace,
	}
}

// ParseCaveat parses a caveat into an identifier, identifying the
// checker that should be used, and the argument to the checker (the
// rest of the string).
//
// The identifier is taken from all the characters before the first
// space character.
func ParseCaveat(cav string) (cond, arg string, err error) {
	if cav == "" {
		return "", "", fmt.Errorf("empty caveat")
	}
	i := strings.IndexByte(cav, ' ')
	if i < 0 {
		return cav, "", nil
	}
	if i == 0 {
		return "", "", fmt.Errorf("caveat starts with space character")
	}
	return cav[0:i], cav[i+1:], nil
}

// ErrorCaveatf returns a caveat that will never be satisfied, holding
// the given fmt.Sprintf formatted text as the text of the caveat.
//
// This should only be used for highly unusual conditions that are never
// expected to happen in practice, such as a malformed key that is
// conventionally passed as a constant. It's not a panic but you should
// only use it in cases where a panic might possibly be appropriate.
//
// This mechanism means that caveats can be created without error
// checking and a later systematic check at a higher level (in the
// bakery package) can produce an error instead.
func ErrorCaveatf(f string, a ...interface{}) Caveat {
	return firstParty(CondError, fmt.Sprintf(f, a...))
}

type checkerInfoByName []CheckerInfo

func (c checkerInfoByName) Less(i, j int) bool {
	info0, info1 := &c[i], &c[j]
	if info0.Namespace != info1.Namespace {
		return info0.Namespace < info1.Namespace
	}
	return info0.Name < info1.Name
}

func (c checkerInfoByName) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c checkerInfoByName) Len() int {
	return len(c)
}
