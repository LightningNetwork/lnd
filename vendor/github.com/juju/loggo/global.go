// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package loggo

var (
	defaultContext = newDefaultContxt()
)

func newDefaultContxt() *Context {
	ctx := NewContext(WARNING)
	ctx.AddWriter(DefaultWriterName, defaultWriter())
	return ctx
}

// DefaultContext returns the global default logging context.
func DefaultContext() *Context {
	return defaultContext
}

// LoggerInfo returns information about the configured loggers and their
// logging levels. The information is returned in the format expected by
// ConfigureLoggers. Loggers with UNSPECIFIED level will not
// be included.
func LoggerInfo() string {
	return defaultContext.Config().String()
}

// GetLogger returns a Logger for the given module name,
// creating it and its parents if necessary.
func GetLogger(name string) Logger {
	return defaultContext.GetLogger(name)
}

// ResetLogging iterates through the known modules and sets the levels of all
// to UNSPECIFIED, except for <root> which is set to WARNING. The call also
// removes all writers in the DefaultContext and puts the original default
// writer back as the only writer.
func ResetLogging() {
	defaultContext.ResetLoggerLevels()
	defaultContext.ResetWriters()
}

// ResetWriters puts the list of writers back into the initial state.
func ResetWriters() {
	defaultContext.ResetWriters()
}

// ReplaceDefaultWriter is a convenience method that does the equivalent of
// RemoveWriter and then RegisterWriter with the name "default".  The previous
// default writer, if any is returned.
func ReplaceDefaultWriter(writer Writer) (Writer, error) {
	return defaultContext.ReplaceWriter(DefaultWriterName, writer)
}

// RegisterWriter adds the writer to the list of writers in the DefaultContext
// that get notified when logging.  If there is already a registered writer
// with that name, an error is returned.
func RegisterWriter(name string, writer Writer) error {
	return defaultContext.AddWriter(name, writer)
}

// RemoveWriter removes the Writer identified by 'name' and returns it.
// If the Writer is not found, an error is returned.
func RemoveWriter(name string) (Writer, error) {
	return defaultContext.RemoveWriter(name)
}

// ConfigureLoggers configures loggers on the default context according to the
// given string specification, which specifies a set of modules and their
// associated logging levels.  Loggers are colon- or semicolon-separated; each
// module is specified as <modulename>=<level>.  White space outside of module
// names and levels is ignored.  The root module is specified with the name
// "<root>".
//
// An example specification:
//  `<root>=ERROR; foo.bar=WARNING`
func ConfigureLoggers(specification string) error {
	return defaultContext.ConfigureLoggers(specification)
}
