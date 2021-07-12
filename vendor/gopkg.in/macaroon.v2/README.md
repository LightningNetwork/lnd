# macaroon
--
    import "gopkg.in/macaroon.v1"

The macaroon package implements macaroons as described in the paper "Macaroons:
Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"
(http://theory.stanford.edu/~ataly/Papers/macaroons.pdf)

See the macaroon bakery packages at http://godoc.org/gopkg.in/macaroon-bakery.v0
for higher level services and operations that use macaroons.

## Usage

#### type Caveat

```go
type Caveat struct {
	Id       string
	Location string
}
```


#### type Macaroon

```go
type Macaroon struct {
}
```

Macaroon holds a macaroon. See Fig. 7 of
http://theory.stanford.edu/~ataly/Papers/macaroons.pdf for a description of the
data contained within. Macaroons are mutable objects - use Clone as appropriate
to avoid unwanted mutation.

#### func  New

```go
func New(rootKey []byte, id, loc string) (*Macaroon, error)
```
New returns a new macaroon with the given root key, identifier and location.

#### func (*Macaroon) AddFirstPartyCaveat

```go
func (m *Macaroon) AddFirstPartyCaveat(caveatId string) error
```
AddFirstPartyCaveat adds a caveat that will be verified by the target service.

#### func (*Macaroon) AddThirdPartyCaveat

```go
func (m *Macaroon) AddThirdPartyCaveat(rootKey []byte, caveatId string, loc string) error
```
AddThirdPartyCaveat adds a third-party caveat to the macaroon, using the given
shared root key, caveat id and location hint. The caveat id should encode the
root key in some way, either by encrypting it with a key known to the third
party or by holding a reference to it stored in the third party's storage.

#### func (*Macaroon) Bind

```go
func (m *Macaroon) Bind(sig []byte)
```
Bind prepares the macaroon for being used to discharge the macaroon with the
given signature sig. This must be used before it is used in the discharges
argument to Verify.

#### func (*Macaroon) Caveats

```go
func (m *Macaroon) Caveats() []Caveat
```
Caveats returns the macaroon's caveats. This method will probably change, and
it's important not to change the returned caveat.

#### func (*Macaroon) Clone

```go
func (m *Macaroon) Clone() *Macaroon
```
Clone returns a copy of the receiving macaroon.

#### func (*Macaroon) Id

```go
func (m *Macaroon) Id() string
```
Id returns the id of the macaroon. This can hold arbitrary information.

#### func (*Macaroon) Location

```go
func (m *Macaroon) Location() string
```
Location returns the macaroon's location hint. This is not verified as part of
the macaroon.

#### func (*Macaroon) MarshalBinary

```go
func (m *Macaroon) MarshalBinary() ([]byte, error)
```
MarshalBinary implements encoding.BinaryMarshaler.

#### func (*Macaroon) MarshalJSON

```go
func (m *Macaroon) MarshalJSON() ([]byte, error)
```
MarshalJSON implements json.Marshaler.

#### func (*Macaroon) Signature

```go
func (m *Macaroon) Signature() []byte
```
Signature returns the macaroon's signature.

#### func (*Macaroon) UnmarshalBinary

```go
func (m *Macaroon) UnmarshalBinary(data []byte) error
```
UnmarshalBinary implements encoding.BinaryUnmarshaler.

#### func (*Macaroon) UnmarshalJSON

```go
func (m *Macaroon) UnmarshalJSON(jsonData []byte) error
```
UnmarshalJSON implements json.Unmarshaler.

#### func (*Macaroon) Verify

```go
func (m *Macaroon) Verify(rootKey []byte, check func(caveat string) error, discharges []*Macaroon) error
```
Verify verifies that the receiving macaroon is valid. The root key must be the
same that the macaroon was originally minted with. The check function is called
to verify each first-party caveat - it should return an error if the condition
is not met.

The discharge macaroons should be provided in discharges.

Verify returns true if the verification succeeds; if returns (false, nil) if the
verification fails, and (false, err) if the verification cannot be asserted (but
may not be false).

TODO(rog) is there a possible DOS attack that can cause this function to
infinitely recurse?

#### type Verifier

```go
type Verifier interface {
	Verify(m *Macaroon, rootKey []byte) (bool, error)
}
```
