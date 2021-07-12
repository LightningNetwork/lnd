# errgo
--
    import "gopkg.in/errgo.v1"

The errgo package provides a way to create and diagnose errors. It is compatible
with the usual Go error idioms but adds a way to wrap errors so that they record
source location information while retaining a consistent way for code to inspect
errors to find out particular problems.

## Usage

#### func  Any

```go
func Any(error) bool
```
Any returns true. It can be used as an argument to Mask to allow any diagnosis
to pass through to the wrapped error.

#### func  Cause

```go
func Cause(err error) error
```
Cause returns the cause of the given error. If err does not implement Causer or
its Cause method returns nil, it returns err itself.

Cause is the usual way to diagnose errors that may have been wrapped by Mask or
NoteMask.

#### func  Details

```go
func Details(err error) string
```
Details returns information about the stack of underlying errors wrapped by err,
in the format:

    [{filename:99: error one} {otherfile:55: cause of error one}]

The details are found by type-asserting the error to the Locationer, Causer and
Wrapper interfaces. Details of the underlying stack are found by recursively
calling Underlying when the underlying error implements Wrapper.

#### func  Is

```go
func Is(err error) func(error) bool
```
Is returns a function that returns whether the an error is equal to the given
error. It is intended to be used as a "pass" argument to Mask and friends; for
example:

    return errgo.Mask(err, errgo.Is(http.ErrNoCookie))

would return an error with an http.ErrNoCookie cause only if that was err's
diagnosis; otherwise the diagnosis would be itself.

#### func  Mask

```go
func Mask(underlying error, pass ...func(error) bool) error
```
Mask returns an Err that wraps the given underyling error. The error message is
unchanged, but the error location records the caller of Mask.

If err is nil, Mask returns nil.

By default Mask conceals the cause of the wrapped error, but if pass(Cause(err))
returns true for any of the provided pass functions, the cause of the returned
error will be Cause(err).

For example, the following code will return an error whose cause is the error
from the os.Open call when (and only when) the file does not exist.

    f, err := os.Open("non-existent-file")
    if err != nil {
        return errgo.Mask(err, os.IsNotExist)
    }

In order to add context to returned errors, it is conventional to call Mask when
returning any error received from elsewhere.

#### func  MaskFunc

```go
func MaskFunc(allow ...func(error) bool) func(error, ...func(error) bool) error
```
MaskFunc returns an equivalent of Mask that always allows the specified causes
in addition to any causes specified when the returned function is called.

It is defined for convenience, for example when all calls to Mask in a given
package wish to allow the same set of causes to be returned.

#### func  New

```go
func New(s string) error
```
New returns a new error with the given error message and no cause. It is a
drop-in replacement for errors.New from the standard library.

#### func  Newf

```go
func Newf(f string, a ...interface{}) error
```
Newf returns a new error with the given printf-formatted error message and no
cause.

#### func  NoteMask

```go
func NoteMask(underlying error, msg string, pass ...func(error) bool) error
```
NoteMask returns an Err that has the given underlying error, with the given
message added as context, and allowing the cause of the underlying error to pass
through into the result if allowed by the specific pass functions (see Mask for
an explanation of the pass parameter).

#### func  Notef

```go
func Notef(underlying error, f string, a ...interface{}) error
```
Notef returns an Error that wraps the given underlying error and adds the given
formatted context message. The returned error has no cause (use NoteMask or
WithCausef to add a message while retaining a cause).

#### func  WithCausef

```go
func WithCausef(underlying, cause error, f string, a ...interface{}) error
```
WithCausef returns a new Error that wraps the given (possibly nil) underlying
error and associates it with the given cause. The given formatted message
context will also be added.

#### type Causer

```go
type Causer interface {
	Cause() error
}
```

Causer is the type of an error that may provide an error cause for error
diagnosis. Cause may return nil if there is no cause (for example because the
cause has been masked).

#### type Err

```go
type Err struct {
	// Message_ holds the text of the error message. It may be empty
	// if Underlying is set.
	Message_ string

	// Cause_ holds the cause of the error as returned
	// by the Cause method.
	Cause_ error

	// Underlying_ holds the underlying error, if any.
	Underlying_ error

	// File and Line identify the source code location where the error was
	// created.
	File string
	Line int
}
```

Err holds a description of an error along with information about where the error
was created.

It may be embedded in custom error types to add extra information that this
errors package can understand.

#### func (*Err) Cause

```go
func (e *Err) Cause() error
```
Cause implements Causer.

#### func (*Err) Error

```go
func (e *Err) Error() string
```
Error implements error.Error.

#### func (*Err) GoString

```go
func (e *Err) GoString() string
```
GoString returns the details of the receiving error message, so that printing an
error with %#v will produce useful information.

#### func (*Err) Location

```go
func (e *Err) Location() (file string, line int)
```
Location implements Locationer.

#### func (*Err) Message

```go
func (e *Err) Message() string
```
Message returns the top level error message.

#### func (*Err) SetLocation

```go
func (e *Err) SetLocation(callDepth int)
```
Locate records the source location of the error by setting e.Location, at
callDepth stack frames above the call.

#### func (*Err) Underlying

```go
func (e *Err) Underlying() error
```
Underlying returns the underlying error if any.

#### type Locationer

```go
type Locationer interface {
	// Location returns the name of the file and the line
	// number associated with an error.
	Location() (file string, line int)
}
```

Locationer can be implemented by any error type that wants to expose the source
location of an error.

#### type Wrapper

```go
type Wrapper interface {
	// Message returns the top level error message,
	// not including the message from the underlying
	// error.
	Message() string

	// Underlying returns the underlying error, or nil
	// if there is none.
	Underlying() error
}
```

Wrapper is the type of an error that wraps another error. It is exposed so that
external types may implement it, but should in general not be used otherwise.
