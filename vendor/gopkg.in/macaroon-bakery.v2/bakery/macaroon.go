package bakery

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v2"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

// legacyNamespace holds the standard namespace as used by
// pre-version3 macaroons.
func legacyNamespace() *checkers.Namespace {
	ns := checkers.NewNamespace(nil)
	ns.Register(checkers.StdNamespace, "")
	return ns
}

// Macaroon represents an undischarged macaroon along with its first
// party caveat namespace and associated third party caveat information
// which should be passed to the third party when discharging a caveat.
type Macaroon struct {
	// m holds the underlying macaroon.
	m *macaroon.Macaroon

	// version holds the version of the macaroon.
	version Version

	// caveatData maps from a third party caveat id to its
	// associated information, usually public-key encrypted with the
	// third party's public key.
	//
	// If version is less than Version3, this will always be nil,
	// because clients prior to that version do not support
	// macaroon-external caveat ids.
	caveatData map[string][]byte

	// namespace holds the first-party caveat namespace of the macaroon.
	namespace *checkers.Namespace

	// caveatIdPrefix holds the prefix to use for the ids of any third
	// party caveats created. This can be set when Discharge creates a
	// discharge macaroon.
	caveatIdPrefix []byte
}

// NewLegacyMacaroon returns a new macaroon holding m.
// This should only be used when there's no alternative
// (for example when m has been unmarshaled
// from some alternative format).
func NewLegacyMacaroon(m *macaroon.Macaroon) (*Macaroon, error) {
	v, err := bakeryVersion(m.Version())
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &Macaroon{
		m:         m,
		version:   v,
		namespace: legacyNamespace(),
	}, nil
}

type macaroonJSON struct {
	Macaroon *macaroon.Macaroon `json:"m"`
	Version  Version            `json:"v"`
	// Note: CaveatData is encoded using URL-base64-encoded keys
	// because JSON cannot deal with arbitrary byte sequences
	// in its strings, and URL-base64 values to match the
	// standard macaroon encoding.
	CaveatData map[string]string   `json:"cdata,omitempty"`
	Namespace  *checkers.Namespace `json:"ns"`
}

// Clone returns a copy of the macaroon. Note that the the new
// macaroon's namespace still points to the same underlying Namespace -
// copying the macaroon does not make a copy of the namespace.
func (m *Macaroon) Clone() *Macaroon {
	m1 := *m
	m1.m = m1.m.Clone()
	m1.caveatData = make(map[string][]byte)
	for id, data := range m.caveatData {
		m1.caveatData[id] = data
	}
	return &m1
}

// MarshalJSON implements json.Marshaler by marshaling
// the macaroon into the original macaroon format if the
// version is earlier than Version3.
func (m *Macaroon) MarshalJSON() ([]byte, error) {
	if m.version < Version3 {
		if len(m.caveatData) > 0 {
			return nil, errgo.Newf("cannot marshal pre-version3 macaroon with external caveat data")
		}
		return m.m.MarshalJSON()
	}
	caveatData := make(map[string]string)
	for id, data := range m.caveatData {
		caveatData[base64.RawURLEncoding.EncodeToString([]byte(id))] = base64.RawURLEncoding.EncodeToString(data)
	}
	return json.Marshal(macaroonJSON{
		Macaroon:   m.m,
		Version:    m.version,
		CaveatData: caveatData,
		Namespace:  m.namespace,
	})
}

// UnmarshalJSON implements json.Unmarshaler by unmarshaling in a
// backwardly compatible way - if provided with a previous macaroon
// version, it will unmarshal that too.
func (m *Macaroon) UnmarshalJSON(data []byte) error {
	// First try with new data format.
	var m1 macaroonJSON
	if err := json.Unmarshal(data, &m1); err != nil {
		// If we get an unmarshal error, we won't be able
		// to unmarshal into the old format either, as extra fields
		// are ignored.
		return errgo.Mask(err)
	}
	if m1.Macaroon == nil {
		return m.unmarshalJSONOldFormat(data)
	}
	// We've got macaroon field - it's the new format.
	if m1.Version < Version3 || m1.Version > LatestVersion {
		return errgo.Newf("unexpected bakery macaroon version; got %d want %d", m1.Version, Version3)
	}
	if got, want := m1.Macaroon.Version(), MacaroonVersion(m1.Version); got != want {
		return errgo.Newf("underlying macaroon has inconsistent version; got %d want %d", got, want)
	}
	caveatData := make(map[string][]byte)
	for id64, data64 := range m1.CaveatData {
		id, err := macaroon.Base64Decode([]byte(id64))
		if err != nil {
			return errgo.Notef(err, "cannot decode caveat id")
		}
		data, err := macaroon.Base64Decode([]byte(data64))
		if err != nil {
			return errgo.Notef(err, "cannot decode caveat")
		}
		caveatData[string(id)] = data
	}
	m.caveatData = caveatData
	m.m = m1.Macaroon
	m.namespace = m1.Namespace
	// TODO should we allow version > LatestVersion here?
	m.version = m1.Version
	return nil
}

// unmarshalJSONOldFormat unmarshals the data from an old format
// macaroon (without any external caveats or namespace).
func (m *Macaroon) unmarshalJSONOldFormat(data []byte) error {
	// Try to unmarshal from the original format.
	var m1 *macaroon.Macaroon
	if err := json.Unmarshal(data, &m1); err != nil {
		return errgo.Mask(err)
	}
	m2, err := NewLegacyMacaroon(m1)
	if err != nil {
		return errgo.Mask(err)
	}
	*m = *m2
	return nil
}

// bakeryVersion returns a bakery version that corresponds to
// the macaroon version v. It is necessarily approximate because
// several bakery versions can correspond to a single macaroon
// version, so it's only of use when decoding legacy formats
// (in Macaroon.UnmarshalJSON).
//
// It will return an error if it doesn't recognize the version.
func bakeryVersion(v macaroon.Version) (Version, error) {
	switch v {
	case macaroon.V1:
		// Use version 1 because we don't know of any existing
		// version 0 clients.
		return Version1, nil
	case macaroon.V2:
		// Note that this could also correspond to Version3, but
		// this logic is explicitly for legacy versions.
		return Version2, nil
	default:
		return 0, errgo.Newf("unknown macaroon version when legacy-unmarshaling bakery macaroon; got %d", v)
	}
}

// NewMacaroon creates and returns a new macaroon with the given root
// key, id and location. If the version is more than the latest known
// version, the latest known version will be used. The namespace is that
// of the service creating it.
func NewMacaroon(rootKey, id []byte, location string, version Version, ns *checkers.Namespace) (*Macaroon, error) {
	if version > LatestVersion {
		version = LatestVersion
	}
	m, err := macaroon.New(rootKey, id, location, MacaroonVersion(version))
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon")
	}
	return &Macaroon{
		m:         m,
		version:   version,
		namespace: ns,
	}, nil
}

// M returns the underlying macaroon held within m.
func (m *Macaroon) M() *macaroon.Macaroon {
	return m.m
}

// Version returns the bakery version of the first party
// that created the macaroon.
func (m *Macaroon) Version() Version {
	return m.version
}

// Namespace returns the first party caveat namespace of the macaroon.
func (m *Macaroon) Namespace() *checkers.Namespace {
	return m.namespace
}

// AddCaveats is a convenienced method that calls m.AddCaveat for each
// caveat in cavs.
func (m *Macaroon) AddCaveats(ctx context.Context, cavs []checkers.Caveat, key *KeyPair, loc ThirdPartyLocator) error {
	for _, cav := range cavs {
		if err := m.AddCaveat(ctx, cav, key, loc); err != nil {
			return errgo.Notef(err, "cannot add caveat %#v", cav)
		}
	}
	return nil
}

// AddCaveat adds a caveat to the given macaroon.
//
// If it's a third-party caveat, it encrypts it using the given key pair
// and by looking up the location using the given locator. If it's a
// first party cavat, key and loc are unused.
//
// As a special case, if the caveat's Location field has the prefix
// "local " the caveat is added as a client self-discharge caveat using
// the public key base64-encoded in the rest of the location. In this
// case, the Condition field must be empty. The resulting third-party
// caveat will encode the condition "true" encrypted with that public
// key. See LocalThirdPartyCaveat for a way of creating such caveats.
func (m *Macaroon) AddCaveat(ctx context.Context, cav checkers.Caveat, key *KeyPair, loc ThirdPartyLocator) error {
	if cav.Location == "" {
		if err := m.m.AddFirstPartyCaveat([]byte(m.namespace.ResolveCaveat(cav).Condition)); err != nil {
			return errgo.Mask(err)
		}
		return nil
	}
	if key == nil {
		return errgo.Newf("no private key to encrypt third party caveat")
	}
	var info ThirdPartyInfo
	if localInfo, ok := parseLocalLocation(cav.Location); ok {
		info = localInfo
		cav.Location = "local"
		if cav.Condition != "" {
			return errgo.New("cannot specify caveat condition in local third-party caveat")
		}
		cav.Condition = "true"
	} else {
		if loc == nil {
			return errgo.Newf("no locator when adding third party caveat")
		}
		var err error
		info, err = loc.ThirdPartyInfo(ctx, cav.Location)
		if err != nil {
			return errgo.Notef(err, "cannot find public key for location %q", cav.Location)
		}
	}
	rootKey, err := randomBytes(24)
	if err != nil {
		return errgo.Notef(err, "cannot generate third party secret")
	}
	// Use the least supported version to encode the caveat.
	if m.version < info.Version {
		info.Version = m.version
	}
	caveatInfo, err := encodeCaveat(cav.Condition, rootKey, info, key, m.namespace)
	if err != nil {
		return errgo.Notef(err, "cannot create third party caveat at %q", cav.Location)
	}
	var id []byte
	if info.Version < Version3 {
		// We're encoding for an earlier client or third party which does
		// not understand bundled caveat info, so use the encoded
		// caveat information as the caveat id.
		id = caveatInfo
	} else {
		id = m.newCaveatId(m.caveatIdPrefix)
		if m.caveatData == nil {
			m.caveatData = make(map[string][]byte)
		}
		m.caveatData[string(id)] = caveatInfo
	}
	if err := m.m.AddThirdPartyCaveat(rootKey, id, cav.Location); err != nil {
		return errgo.Notef(err, "cannot add third party caveat")
	}
	return nil
}

// newCaveatId returns a third party caveat id that
// does not duplicate any third party caveat ids already inside m.
//
// If base is non-empty, it is used as the id prefix.
func (m *Macaroon) newCaveatId(base []byte) []byte {
	var id []byte
	if len(base) > 0 {
		id = make([]byte, len(base), len(base)+binary.MaxVarintLen64)
		copy(id, base)
	} else {
		id = make([]byte, 0, 1+binary.MaxVarintLen32)
		// Add a version byte to the caveat id. Technically
		// this is unnecessary as the caveat-decoding logic
		// that looks at versions should never see this id,
		// but if the caveat payload isn't provided with the
		// payload, having this version gives a strong indication
		// that the payload has been omitted so we can produce
		// a better error for the user.
		id = append(id, byte(Version3))
	}

	// Iterate through integers looking for one that isn't already used,
	// starting from n so that if everyone is using this same algorithm,
	// we'll only perform one iteration.
	//
	// Note that although this looks like an infinite loop,
	// there's no way that it can run for more iterations
	// than the total number of existing third party caveats,
	// whatever their ids.
	caveats := m.m.Caveats()
again:
	for i := len(m.caveatData); ; i++ {
		// We append a varint to the end of the id and assume that
		// any client that's created the id that we're using as a base
		// is using similar conventions - in the worst case they might
		// end up with a duplicate third party caveat id and thus create
		// a macaroon that cannot be discharged.
		id1 := appendUvarint(id, uint64(i))
		for _, cav := range caveats {
			if cav.VerificationId != nil && bytes.Equal(cav.Id, id1) {
				continue again
			}
		}
		return id1
	}
}
