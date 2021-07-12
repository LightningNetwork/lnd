// Copyright 2014 Roger Peppe.
// See LICENCE file for details.

// Package errgo provides a way to create
// and diagnose errors. It is compatible with
// the usual Go error idioms but adds a way to wrap errors
// so that they record source location information
// while retaining a consistent way for code to
// inspect errors to find out particular problems.
//
package errgo

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
)

const debug = false

// Err holds a description of an error along with information about
// where the error was created.
//
// It may be embedded  in custom error types to add
// extra information that this errors package can
// understand.
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

// Location implements Locationer.
func (e *Err) Location() (file string, line int) {
	return e.File, e.Line
}

// Underlying returns the underlying error if any.
func (e *Err) Underlying() error {
	return e.Underlying_
}

// Cause implements Causer.
func (e *Err) Cause() error {
	return e.Cause_
}

// Message returns the top level error message.
func (e *Err) Message() string {
	return e.Message_
}

// Error implements error.Error.
func (e *Err) Error() string {
	switch {
	case e.Message_ == "" && e.Underlying_ == nil:
		return "<no error>"
	case e.Message_ == "":
		return e.Underlying_.Error()
	case e.Underlying_ == nil:
		return e.Message_
	}
	return fmt.Sprintf("%s: %v", e.Message_, e.Underlying_)
}

// GoString returns the details of the receiving error
// message, so that printing an error with %#v will
// produce useful information.
func (e *Err) GoString() string {
	return Details(e)
}

// Causer is the type of an error that may provide
// an error cause for error diagnosis. Cause may return
// nil if there is no cause (for example because the
// cause has been masked).
type Causer interface {
	Cause() error
}

// Wrapper is the type of an error that wraps another error. It is
// exposed so that external types may implement it, but should in
// general not be used otherwise.
type Wrapper interface {
	// Message returns the top level error message,
	// not including the message from the underlying
	// error.
	Message() string

	// Underlying returns the underlying error, or nil
	// if there is none.
	Underlying() error
}

// Locationer can be implemented by any error type
// that wants to expose the source location of an error.
type Locationer interface {
	// Location returns the name of the file and the line
	// number associated with an error.
	Location() (file string, line int)
}

// Details returns information about the stack of
// underlying errors wrapped by err, in the format:
//
//	[{filename:99: error one} {otherfile:55: cause of error one}]
//
// The details are found by type-asserting the error to
// the Locationer, Causer and Wrapper interfaces.
// Details of the underlying stack are found by
// recursively calling Underlying when the
// underlying error implements Wrapper.
func Details(err error) string {
	if err == nil {
		return "[]"
	}
	var s []byte
	s = append(s, '[')
	for {
		s = append(s, '{')
		if err, ok := err.(Locationer); ok {
			file, line := err.Location()
			if file != "" {
				s = append(s, fmt.Sprintf("%s:%d", file, line)...)
				s = append(s, ": "...)
			}
		}
		if cerr, ok := err.(Wrapper); ok {
			s = append(s, cerr.Message()...)
			err = cerr.Underlying()
		} else {
			s = append(s, err.Error()...)
			err = nil
		}
		if debug {
			if err, ok := err.(Causer); ok {
				if cause := err.Cause(); cause != nil {
					s = append(s, fmt.Sprintf("=%T", cause)...)
					s = append(s, Details(cause)...)
				}
			}
		}
		s = append(s, '}')
		if err == nil {
			break
		}
		s = append(s, ' ')
	}
	s = append(s, ']')
	return string(s)
}

// SetLocation records the source location of the error by setting
// e.Location, at callDepth stack frames above the call.
func (e *Err) SetLocation(callDepth int) {
	_, file, line, _ := runtime.Caller(callDepth + 1)
	e.File, e.Line = file, line
}

func setLocation(err error, callDepth int) {
	if e, _ := err.(*Err); e != nil {
		e.SetLocation(callDepth + 1)
	}
}

// New returns a new error with the given error message and no cause. It
// is a drop-in replacement for errors.New from the standard library.
func New(s string) error {
	err := &Err{Message_: s}
	err.SetLocation(1)
	return err
}

// Newf returns a new error with the given printf-formatted error
// message and no cause.
func Newf(f string, a ...interface{}) error {
	err := &Err{Message_: fmt.Sprintf(f, a...)}
	err.SetLocation(1)
	return err
}

// match returns whether any of the given
// functions returns true when called with err as an
// argument.
func match(err error, pass ...func(error) bool) bool {
	for _, f := range pass {
		if f(err) {
			return true
		}
	}
	return false
}

// Is returns a function that returns whether the
// an error is equal to the given error.
// It is intended to be used as a "pass" argument
// to Mask and friends; for example:
//
//	return errgo.Mask(err, errgo.Is(http.ErrNoCookie))
//
// would return an error with an http.ErrNoCookie cause
// only if that was err's diagnosis; otherwise the diagnosis
// would be itself.
func Is(err error) func(error) bool {
	return func(err1 error) bool {
		return err == err1
	}
}

// Any returns true. It can be used as an argument to Mask
// to allow any diagnosis to pass through to the wrapped
// error.
func Any(error) bool {
	return true
}

// NoteMask returns an Err that has the given underlying error,
// with the given message added as context, and allowing
// the cause of the underlying error to pass through into
// the result if allowed by the specific pass functions
// (see Mask for an explanation of the pass parameter).
func NoteMask(underlying error, msg string, pass ...func(error) bool) error {
	err := noteMask(underlying, msg, pass...)
	setLocation(err, 1)
	return err
}

// noteMask is exactly like NoteMask except it doesn't set the location
// of the returned error, so that we can avoid setting it twice
// when it's used in other functions.
func noteMask(underlying error, msg string, pass ...func(error) bool) error {
	newErr := &Err{
		Underlying_: underlying,
		Message_:    msg,
	}
	if len(pass) > 0 {
		if cause := Cause(underlying); match(cause, pass...) {
			newErr.Cause_ = cause
		}
	}
	if debug {
		if newd, oldd := newErr.Cause_, Cause(underlying); newd != oldd {
			log.Printf("Mask cause %[1]T(%[1]v)->%[2]T(%[2]v)", oldd, newd)
			log.Printf("call stack: %s", callers(0, 20))
			log.Printf("len(allow) == %d", len(pass))
			log.Printf("old error %#v", underlying)
			log.Printf("new error %#v", newErr)
		}
	}
	newErr.SetLocation(1)
	return newErr
}

// Mask returns an Err that wraps the given underyling error. The error
// message is unchanged, but the error location records the caller of
// Mask.
//
// If err is nil, Mask returns nil.
//
// By default Mask conceals the cause of the wrapped error, but if
// pass(Cause(err)) returns true for any of the provided pass functions,
// the cause of the returned error will be Cause(err).
//
// For example, the following code will return an error whose cause is
// the error from the os.Open call when (and only when) the file does
// not exist.
//
//	f, err := os.Open("non-existent-file")
//	if err != nil {
//		return errgo.Mask(err, os.IsNotExist)
//	}
//
// In order to add context to returned errors, it
// is conventional to call Mask when returning any
// error received from elsewhere.
//
func Mask(underlying error, pass ...func(error) bool) error {
	if underlying == nil {
		return nil
	}
	err := noteMask(underlying, "", pass...)
	setLocation(err, 1)
	return err
}

// Notef returns an Error that wraps the given underlying
// error and adds the given formatted context message.
// The returned error has no cause (use NoteMask
// or WithCausef to add a message while retaining a cause).
func Notef(underlying error, f string, a ...interface{}) error {
	err := noteMask(underlying, fmt.Sprintf(f, a...))
	setLocation(err, 1)
	return err
}

// MaskFunc returns an equivalent of Mask that always allows the
// specified causes in addition to any causes specified when the
// returned function is called.
//
// It is defined for convenience, for example when all calls to Mask in
// a given package wish to allow the same set of causes to be returned.
func MaskFunc(allow ...func(error) bool) func(error, ...func(error) bool) error {
	return func(err error, allow1 ...func(error) bool) error {
		var allowEither []func(error) bool
		if len(allow1) > 0 {
			// This is more efficient than using a function literal,
			// because the compiler knows that it doesn't escape.
			allowEither = make([]func(error) bool, len(allow)+len(allow1))
			copy(allowEither, allow)
			copy(allowEither[len(allow):], allow1)
		} else {
			allowEither = allow
		}
		err = Mask(err, allowEither...)
		setLocation(err, 1)
		return err
	}
}

// WithCausef returns a new Error that wraps the given
// (possibly nil) underlying error and associates it with
// the given cause. The given formatted message context
// will also be added. If underlying is nil and f is empty and has no arguments,
// the message will be the same as the cause.
func WithCausef(underlying, cause error, f string, a ...interface{}) error {
	var msg string
	if underlying == nil && f == "" && len(a) == 0 && cause != nil {
		msg = cause.Error()
	} else {
		msg = fmt.Sprintf(f, a...)
	}
	err := &Err{
		Underlying_: underlying,
		Cause_:      cause,
		Message_:    msg,
	}
	err.SetLocation(1)
	return err
}

// Cause returns the cause of the given error.  If err does not
// implement Causer or its Cause method returns nil, it returns err itself.
//
// Cause is the usual way to diagnose errors that may have
// been wrapped by Mask or NoteMask.
func Cause(err error) error {
	var diag error
	if err, ok := err.(Causer); ok {
		diag = err.Cause()
	}
	if diag != nil {
		return diag
	}
	return err
}

// callers returns the stack trace of the goroutine that called it,
// starting n entries above the caller of callers, as a space-separated list
// of filename:line-number pairs with no new lines.
func callers(n, max int) []byte {
	var b bytes.Buffer
	prev := false
	for i := 0; i < max; i++ {
		_, file, line, ok := runtime.Caller(n + 1)
		if !ok {
			return b.Bytes()
		}
		if prev {
			fmt.Fprintf(&b, " ")
		}
		fmt.Fprintf(&b, "%s:%d", file, line)
		n++
		prev = true
	}
	return b.Bytes()
}
