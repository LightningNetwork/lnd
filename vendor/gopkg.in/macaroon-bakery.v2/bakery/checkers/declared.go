package checkers

import (
	"strings"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v2"
)

type macaroonsKey struct{}

type macaroonsValue struct {
	ns *Namespace
	ms macaroon.Slice
}

// ContextWithMacaroons returns the given context associated with a
// macaroon slice and the name space to use to interpret caveats in
// the macaroons.
func ContextWithMacaroons(ctx context.Context, ns *Namespace, ms macaroon.Slice) context.Context {
	return context.WithValue(ctx, macaroonsKey{}, macaroonsValue{
		ns: ns,
		ms: ms,
	})
}

// MacaroonsFromContext returns the namespace and macaroons associated
// with the context by ContextWithMacaroons. This can be used to
// implement "structural" first-party caveats that are predicated on
// the macaroons being validated.
func MacaroonsFromContext(ctx context.Context) (*Namespace, macaroon.Slice) {
	v, _ := ctx.Value(macaroonsKey{}).(macaroonsValue)
	return v.ns, v.ms
}

// DeclaredCaveat returns a "declared" caveat asserting that the given key is
// set to the given value. If a macaroon has exactly one first party
// caveat asserting the value of a particular key, then InferDeclared
// will be able to infer the value, and then DeclaredChecker will allow
// the declared value if it has the value specified here.
//
// If the key is empty or contains a space, DeclaredCaveat
// will return an error caveat.
func DeclaredCaveat(key string, value string) Caveat {
	if strings.Contains(key, " ") || key == "" {
		return ErrorCaveatf("invalid caveat 'declared' key %q", key)
	}
	return firstParty(CondDeclared, key+" "+value)
}

// NeedDeclaredCaveat returns a third party caveat that
// wraps the provided third party caveat and requires
// that the third party must add "declared" caveats for
// all the named keys.
// TODO(rog) namespaces in third party caveats?
func NeedDeclaredCaveat(cav Caveat, keys ...string) Caveat {
	if cav.Location == "" {
		return ErrorCaveatf("need-declared caveat is not third-party")
	}
	return Caveat{
		Location:  cav.Location,
		Condition: CondNeedDeclared + " " + strings.Join(keys, ",") + " " + cav.Condition,
	}
}

func checkDeclared(ctx context.Context, _, arg string) error {
	parts := strings.SplitN(arg, " ", 2)
	if len(parts) != 2 {
		return errgo.Newf("declared caveat has no value")
	}
	ns, ms := MacaroonsFromContext(ctx)
	attrs := InferDeclared(ns, ms)
	val, ok := attrs[parts[0]]
	if !ok {
		return errgo.Newf("got %s=null, expected %q", parts[0], parts[1])
	}
	if val != parts[1] {
		return errgo.Newf("got %s=%q, expected %q", parts[0], val, parts[1])
	}
	return nil
}

// InferDeclared retrieves any declared information from
// the given macaroons and returns it as a key-value map.
//
// Information is declared with a first party caveat as created
// by DeclaredCaveat.
//
// If there are two caveats that declare the same key with
// different values, the information is omitted from the map.
// When the caveats are later checked, this will cause the
// check to fail.
func InferDeclared(ns *Namespace, ms macaroon.Slice) map[string]string {
	var conditions []string
	for _, m := range ms {
		for _, cav := range m.Caveats() {
			if cav.Location == "" {
				conditions = append(conditions, string(cav.Id))
			}
		}
	}
	return InferDeclaredFromConditions(ns, conditions)
}

// InferDeclaredFromConditions is like InferDeclared except that
// it is passed a set of first party caveat conditions rather than a set of macaroons.
func InferDeclaredFromConditions(ns *Namespace, conds []string) map[string]string {
	var conflicts []string
	// If we can't resolve that standard namespace, then we'll look for
	// just bare "declared" caveats which will work OK for legacy
	// macaroons with no namespace.
	prefix, _ := ns.Resolve(StdNamespace)
	declaredCond := prefix + CondDeclared

	info := make(map[string]string)
	for _, cond := range conds {
		name, rest, _ := ParseCaveat(cond)
		if name != declaredCond {
			continue
		}
		parts := strings.SplitN(rest, " ", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if oldVal, ok := info[key]; ok && oldVal != val {
			conflicts = append(conflicts, key)
			continue
		}
		info[key] = val
	}
	for _, key := range conflicts {
		delete(info, key)
	}
	return info
}
