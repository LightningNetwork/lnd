package checkers

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	errgo "gopkg.in/errgo.v1"
)

// Namespace holds maps from schema URIs to the
// prefixes that are used to encode them in first party
// caveats. Several different URIs may map to the same
// prefix - this is usual when several different backwardly
// compatible schema versions are registered.
type Namespace struct {
	uriToPrefix map[string]string
}

// NewNamespace returns a new namespace with the
// given initial contents. It will panic if any of the
// URI keys or their associated prefix are invalid
// (see IsValidSchemaURI and IsValidPrefix).
func NewNamespace(uriToPrefix map[string]string) *Namespace {
	ns := &Namespace{
		uriToPrefix: make(map[string]string),
	}
	for uri, prefix := range uriToPrefix {
		ns.Register(uri, prefix)
	}
	return ns
}

// String returns the namespace representation as returned by
// ns.MarshalText.
func (ns *Namespace) String() string {
	data, _ := ns.MarshalText()
	return string(data)
}

// MarshalText implements encoding.TextMarshaler by
// returning all the elements in the namespace sorted by
// URI, joined to the associated prefix with a colon and
// separated with spaces.
func (ns *Namespace) MarshalText() ([]byte, error) {
	if ns == nil || len(ns.uriToPrefix) == 0 {
		return nil, nil
	}
	uris := make([]string, 0, len(ns.uriToPrefix))
	dataLen := 0
	for uri, prefix := range ns.uriToPrefix {
		uris = append(uris, uri)
		dataLen += len(uri) + 1 + len(prefix) + 1
	}
	sort.Strings(uris)
	data := make([]byte, 0, dataLen)
	for i, uri := range uris {
		if i > 0 {
			data = append(data, ' ')
		}
		data = append(data, uri...)
		data = append(data, ':')
		data = append(data, ns.uriToPrefix[uri]...)
	}
	return data, nil
}

func (ns *Namespace) UnmarshalText(data []byte) error {
	uriToPrefix := make(map[string]string)
	elems := strings.Fields(string(data))
	for _, elem := range elems {
		i := strings.LastIndex(elem, ":")
		if i == -1 {
			return errgo.Newf("no colon in namespace field %q", elem)
		}
		uri, prefix := elem[0:i], elem[i+1:]
		if !IsValidSchemaURI(uri) {
			// Currently this can't happen because the only invalid URIs
			// are those which contain a space
			return errgo.Newf("invalid URI %q in namespace field %q", uri, elem)
		}
		if !IsValidPrefix(prefix) {
			return errgo.Newf("invalid prefix %q in namespace field %q", prefix, elem)
		}
		if _, ok := uriToPrefix[uri]; ok {
			return errgo.Newf("duplicate URI %q in namespace %q", uri, data)
		}
		uriToPrefix[uri] = prefix
	}
	ns.uriToPrefix = uriToPrefix
	return nil
}

// EnsureResolved tries to resolve the given schema URI to a prefix and
// returns the prefix and whether the resolution was successful. If the
// URI hasn't been registered but a compatible version has, the
// given URI is registered with the same prefix.
func (ns *Namespace) EnsureResolved(uri string) (string, bool) {
	// TODO(rog) compatibility
	return ns.Resolve(uri)
}

// Resolve resolves the given schema URI to its registered prefix and
// returns the prefix and whether the resolution was successful.
//
// If ns is nil, it is treated as if it were empty.
//
// Resolve does not mutate ns and may be called concurrently
// with other non-mutating Namespace methods.
func (ns *Namespace) Resolve(uri string) (string, bool) {
	if ns == nil {
		return "", false
	}
	prefix, ok := ns.uriToPrefix[uri]
	return prefix, ok
}

// ResolveCaveat resolves the given caveat by using
// Resolve to map from its schema namespace to the appropriate prefix using
// Resolve. If there is no registered prefix for the namespace,
// it returns an error caveat.
//
// If ns.Namespace is empty or ns.Location is non-empty, it returns cav unchanged.
//
// If ns is nil, it is treated as if it were empty.
//
// ResolveCaveat does not mutate ns and may be called concurrently
// with other non-mutating Namespace methods.
func (ns *Namespace) ResolveCaveat(cav Caveat) Caveat {
	// TODO(rog) If a namespace isn't registered, try to resolve it by
	// resolving it to the latest compatible version that is
	// registered.
	if cav.Namespace == "" || cav.Location != "" {
		return cav
	}
	prefix, ok := ns.Resolve(cav.Namespace)
	if !ok {
		errCav := ErrorCaveatf("caveat %q in unregistered namespace %q", cav.Condition, cav.Namespace)
		if errCav.Namespace != cav.Namespace {
			prefix, _ = ns.Resolve(errCav.Namespace)
		}
		cav = errCav
	}
	if prefix != "" {
		cav.Condition = ConditionWithPrefix(prefix, cav.Condition)
	}
	cav.Namespace = ""
	return cav
}

// ConditionWithPrefix returns the given string prefixed by the
// given prefix. If the prefix is non-empty, a colon
// is used to separate them.
func ConditionWithPrefix(prefix, condition string) string {
	if prefix == "" {
		return condition
	}
	return prefix + ":" + condition
}

// Register registers the given URI and associates it
// with the given prefix. If the URI has already been registered,
// this is a no-op.
func (ns *Namespace) Register(uri, prefix string) {
	if !IsValidSchemaURI(uri) {
		panic(errgo.Newf("cannot register invalid URI %q (prefix %q)", uri, prefix))
	}
	if !IsValidPrefix(prefix) {
		panic(errgo.Newf("cannot register invalid prefix %q for URI %q", prefix, uri))
	}
	if _, ok := ns.uriToPrefix[uri]; !ok {
		ns.uriToPrefix[uri] = prefix
	}
}

func invalidSchemaRune(r rune) bool {
	return unicode.IsSpace(r)
}

// IsValidSchemaURI reports whether the given argument is suitable for
// use as a namespace schema URI. It must be non-empty, a valid UTF-8
// string and it must not contain white space.
func IsValidSchemaURI(uri string) bool {
	// TODO more stringent requirements?
	return len(uri) > 0 &&
		utf8.ValidString(uri) &&
		strings.IndexFunc(uri, invalidSchemaRune) == -1
}

func invalidPrefixRune(r rune) bool {
	return r == ' ' || r == ':' || unicode.IsSpace(r)
}

func IsValidPrefix(prefix string) bool {
	return utf8.ValidString(prefix) && strings.IndexFunc(prefix, invalidPrefixRune) == -1
}
