package bakery

import (
	"bytes"
	"encoding/base64"
	"sort"

	"github.com/rogpeppe/fastuuid"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v2"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/internal/macaroonpb"
)

// MacaroonVerifier verifies macaroons and returns the operations and
// caveats they're associated with.
type MacaroonVerifier interface {
	// VerifyMacaroon verifies the signature of the given macaroon and returns
	// information on its associated operations, and all the first party
	// caveat conditions that need to be checked.
	//
	// This method should not check first party caveats itself.
	//
	// It should return a *VerificationError if the error occurred
	// because the macaroon signature failed or the root key
	// was not found - any other error will be treated as fatal
	// by Checker and cause authorization to terminate.
	VerifyMacaroon(ctx context.Context, ms macaroon.Slice) ([]Op, []string, error)
}

var uuidGen = fastuuid.MustNewGenerator()

// Oven bakes macaroons. They emerge sweet and delicious
// and ready for use in a Checker.
//
// All macaroons are associated with one or more operations (see
// the Op type) which define the capabilities of the macaroon.
//
// There is one special operation, "login" (defined by LoginOp)
// which grants the capability to speak for a particular user.
// The login capability will never be mixed with other capabilities.
//
// It is up to the caller to decide on semantics for other operations.
type Oven struct {
	p OvenParams
}

type OvenParams struct {
	// Namespace holds the namespace to use when adding first party caveats.
	// If this is nil, checkers.New(nil).Namespace will be used.
	Namespace *checkers.Namespace

	// RootKeyStoreForEntity returns the macaroon storage to be
	// used for root keys associated with macaroons created
	// wth NewMacaroon.
	//
	// If this is nil, NewMemRootKeyStore will be used to create
	// a new store to be used for all entities.
	RootKeyStoreForOps func(ops []Op) RootKeyStore

	// Key holds the private key pair used to encrypt third party caveats.
	// If it is nil, no third party caveats can be created.
	Key *KeyPair

	// Location holds the location that will be associated with new macaroons
	// (as returned by Macaroon.Location).
	Location string

	// Locator is used to find out information on third parties when
	// adding third party caveats. If this is nil, no non-local third
	// party caveats can be added.
	Locator ThirdPartyLocator

	// LegacyMacaroonOp holds the operation to associate with old
	// macaroons that don't have associated operations.
	// If this is empty, legacy macaroons will not be associated
	// with any operations.
	LegacyMacaroonOp Op

	// TODO max macaroon or macaroon id size?
}

// NewOven returns a new oven using the given parameters.
func NewOven(p OvenParams) *Oven {
	if p.Locator == nil {
		p.Locator = emptyLocator{}
	}
	if p.RootKeyStoreForOps == nil {
		store := NewMemRootKeyStore()
		p.RootKeyStoreForOps = func(ops []Op) RootKeyStore {
			return store
		}
	}
	if p.Namespace == nil {
		p.Namespace = checkers.New(nil).Namespace()
	}
	return &Oven{
		p: p,
	}
}

// VerifyMacaroon implements MacaroonVerifier.VerifyMacaroon, making Oven
// an instance of MacaroonVerifier.
//
// For macaroons minted with previous bakery versions, it always
// returns a single LoginOp operation.
func (o *Oven) VerifyMacaroon(ctx context.Context, ms macaroon.Slice) (ops []Op, conditions []string, err error) {
	if len(ms) == 0 {
		return nil, nil, errgo.Newf("no macaroons in slice")
	}
	storageId, ops, err := o.decodeMacaroonId(ms[0].Id())
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	rootKey, err := o.p.RootKeyStoreForOps(ops).Get(ctx, storageId)
	if err != nil {
		if errgo.Cause(err) != ErrNotFound {
			return nil, nil, errgo.Notef(err, "cannot get macaroon")
		}
		// If the macaroon was not found, it is probably
		// because it's been removed after time-expiry,
		// so return a verification error.
		return nil, nil, &VerificationError{
			Reason: errgo.Newf("macaroon not found in storage"),
		}
	}
	conditions, err = ms[0].VerifySignature(rootKey, ms[1:])
	if err != nil {
		return nil, nil, &VerificationError{
			Reason: errgo.Mask(err),
		}
	}
	return ops, conditions, nil
}

func (o *Oven) decodeMacaroonId(id []byte) (storageId []byte, ops []Op, err error) {
	base64Decoded := false
	if id[0] == 'A' {
		// The first byte is not a version number and it's 'A', which is the
		// base64 encoding of the top 6 bits (all zero) of the version number 2 or 3,
		// so we assume that it's the base64 encoding of a new-style
		// macaroon id, so we base64 decode it.
		//
		// Note that old-style ids always start with an ASCII character >= 4
		// (> 32 in fact) so this logic won't be triggered for those.
		dec := make([]byte, base64.RawURLEncoding.DecodedLen(len(id)))
		n, err := base64.RawURLEncoding.Decode(dec, id)
		if err == nil {
			// Set the id only on success - if it's a bad encoding, we'll get a not-found error
			// which is fine because "not found" is a correct description of the issue - we
			// can't find the root key for the given id.
			id = dec[0:n]
			base64Decoded = true
		}
	}
	// Trim any extraneous information from the id before retrieving
	// it from storage, including the UUID that's added when
	// creating macaroons to make all macaroons unique even if
	// they're using the same root key.
	switch id[0] {
	case byte(Version2):
		// Skip the UUID at the start of the id.
		storageId = id[1+16:]
	case byte(Version3):
		var id1 macaroonpb.MacaroonId
		if err := id1.UnmarshalBinary(id[1:]); err != nil {
			return nil, nil, errgo.Notef(err, "cannot unmarshal macaroon id")
		}
		if len(id1.Ops) == 0 || len(id1.Ops[0].Actions) == 0 {
			return nil, nil, errgo.Newf("no operations found in macaroon")
		}
		ops = make([]Op, 0, len(id1.Ops))
		for _, op := range id1.Ops {
			for _, action := range op.Actions {
				ops = append(ops, Op{
					Entity: op.Entity,
					Action: action,
				})
			}
		}
		return id1.StorageId, ops, nil
	}
	if !base64Decoded && isLowerCaseHexChar(id[0]) {
		// It's an old-style id, probably with a hyphenated UUID.
		// so trim that off.
		if i := bytes.LastIndexByte(id, '-'); i >= 0 {
			storageId = id[0:i]
		}
	}
	if op := o.p.LegacyMacaroonOp; op != (Op{}) {
		ops = []Op{op}
	}
	return storageId, ops, nil
}

// NewMacaroon takes a macaroon with the given version from the oven, associates it with the given operations
// and attaches the given caveats. There must be at least one operation specified.
func (o *Oven) NewMacaroon(ctx context.Context, version Version, caveats []checkers.Caveat, ops ...Op) (*Macaroon, error) {
	if len(ops) == 0 {
		return nil, errgo.Newf("cannot mint a macaroon associated with no operations")
	}
	ops = CanonicalOps(ops)
	rootKey, storageId, err := o.p.RootKeyStoreForOps(ops).RootKey(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	id, err := o.newMacaroonId(ctx, ops, storageId)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	idBytesNoVersion, err := id.MarshalBinary()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	idBytes := make([]byte, len(idBytesNoVersion)+1)
	idBytes[0] = byte(LatestVersion)
	// TODO We could use a proto.Buffer to avoid this copy.
	copy(idBytes[1:], idBytesNoVersion)

	if MacaroonVersion(version) < macaroon.V2 {
		// The old macaroon format required valid text for the macaroon id,
		// so base64-encode it.
		b64data := make([]byte, base64.RawURLEncoding.EncodedLen(len(idBytes)))
		base64.RawURLEncoding.Encode(b64data, idBytes)
		idBytes = b64data
	}
	m, err := NewMacaroon(rootKey, idBytes, o.p.Location, version, o.p.Namespace)
	if err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon with version %v", version)
	}
	if err := o.AddCaveats(ctx, m, caveats); err != nil {
		return nil, errgo.Mask(err)
	}
	return m, nil
}

// AddCaveat adds a caveat to the given macaroon.
func (o *Oven) AddCaveat(ctx context.Context, m *Macaroon, cav checkers.Caveat) error {
	return m.AddCaveat(ctx, cav, o.p.Key, o.p.Locator)
}

// AddCaveats adds all the caveats to the given macaroon.
func (o *Oven) AddCaveats(ctx context.Context, m *Macaroon, caveats []checkers.Caveat) error {
	return m.AddCaveats(ctx, caveats, o.p.Key, o.p.Locator)
}

// Key returns the oven's private/public key par.
func (o *Oven) Key() *KeyPair {
	return o.p.Key
}

// Locator returns the third party locator that the
// oven was created with.
func (o *Oven) Locator() ThirdPartyLocator {
	return o.p.Locator
}

// CanonicalOps returns the given operations slice sorted
// with duplicates removed.
func CanonicalOps(ops []Op) []Op {
	canonOps := opsByValue(ops)
	needNewSlice := false
	for i := 1; i < len(ops); i++ {
		if !canonOps.Less(i-1, i) {
			needNewSlice = true
			break
		}
	}
	if !needNewSlice {
		return ops
	}
	canonOps = make([]Op, len(ops))
	copy(canonOps, ops)
	sort.Sort(canonOps)

	// Note we know that there's at least one operation here
	// because we'd have returned earlier if the slice was empty.
	j := 0
	for _, op := range canonOps[1:] {
		if op != canonOps[j] {
			j++
			canonOps[j] = op
		}
	}
	return canonOps[0 : j+1]
}

func (o *Oven) newMacaroonId(ctx context.Context, ops []Op, storageId []byte) (*macaroonpb.MacaroonId, error) {
	uuid := uuidGen.Next()
	nonce := uuid[0:16]
	return &macaroonpb.MacaroonId{
		Nonce:     nonce,
		StorageId: storageId,
		Ops:       macaroonIdOps(ops),
	}, nil
}

// macaroonIdOps returns operations suitable for serializing
// as part of an *macaroonpb.MacaroonId. It assumes that
// ops has been canonicalized and that there's at least
// one operation.
func macaroonIdOps(ops []Op) []*macaroonpb.Op {
	idOps := make([]macaroonpb.Op, 0, len(ops))
	idOps = append(idOps, macaroonpb.Op{
		Entity:  ops[0].Entity,
		Actions: []string{ops[0].Action},
	})
	i := 0
	idOp := &idOps[0]
	for _, op := range ops[1:] {
		if op.Entity != idOp.Entity {
			idOps = append(idOps, macaroonpb.Op{
				Entity:  op.Entity,
				Actions: []string{op.Action},
			})
			i++
			idOp = &idOps[i]
			continue
		}
		if op.Action != idOp.Actions[len(idOp.Actions)-1] {
			idOp.Actions = append(idOp.Actions, op.Action)
		}
	}
	idOpPtrs := make([]*macaroonpb.Op, len(idOps))
	for i := range idOps {
		idOpPtrs[i] = &idOps[i]
	}
	return idOpPtrs
}

type opsByValue []Op

func (o opsByValue) Less(i, j int) bool {
	o0, o1 := o[i], o[j]
	if o0.Entity != o1.Entity {
		return o0.Entity < o1.Entity
	}
	return o0.Action < o1.Action
}

func (o opsByValue) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

func (o opsByValue) Len() int {
	return len(o)
}

func isLowerCaseHexChar(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	}
	return false
}
