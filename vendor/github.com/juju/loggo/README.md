
# loggo
    import "github.com/juju/loggo"

[![GoDoc](https://godoc.org/github.com/juju/loggo?status.svg)](https://godoc.org/github.com/juju/loggo)

### Module level logging for Go
This package provides an alternative to the standard library log package.

The actual logging functions never return errors.  If you are logging
something, you really don't want to be worried about the logging
having trouble.

Modules have names that are defined by dotted strings.


	"first.second.third"

There is a root module that has the name `""`.  Each module
(except the root module) has a parent, identified by the part of
the name without the last dotted value.
* the parent of "first.second.third" is "first.second"
* the parent of "first.second" is "first"
* the parent of "first" is "" (the root module)

Each module can specify its own severity level.  Logging calls that are of
a lower severity than the module's effective severity level are not written
out.

Loggers are created through their Context. There is a default global context
that is used if you just want simple use. Contexts are used where you may want
different sets of writers for different loggers. Most use cases are fine with
just using the default global context.

Loggers are created using the GetLogger function.


	logger := loggo.GetLogger("foo.bar")

The default global context has one writer registered, which will write to Stderr,
and the root module, which will only emit warnings and above.
If you want to continue using the default
logger, but have it emit all logging levels you need to do the following.


	writer, err := loggo.RemoveWriter("default")
	// err is non-nil if and only if the name isn't found.
	loggo.RegisterWriter("default", writer)

To make loggo produce colored output, you can do the following,
having imported github.com/juju/loggo/loggocolor:


	loggo.ReplaceDefaultWriter(loggocolor.NewWriter(os.Stderr))




## Constants
``` go
const DefaultWriterName = "default"
```
DefaultWriterName is the name of the default writer for
a Context.


## Variables
``` go
var TimeFormat = initTimeFormat()
```
TimeFormat is the time format used for the default writer.
This can be set with the environment variable LOGGO_TIME_FORMAT.


## func ConfigureLoggers
``` go
func ConfigureLoggers(specification string) error
```
ConfigureLoggers configures loggers according to the given string
specification, which specifies a set of modules and their associated
logging levels.  Loggers are colon- or semicolon-separated; each
module is specified as <modulename>=<level>.  White space outside of
module names and levels is ignored.  The root module is specified
with the name "<root>".

An example specification:


	`<root>=ERROR; foo.bar=WARNING`


## func DefaultFormatter
``` go
func DefaultFormatter(entry Entry) string
```
DefaultFormatter returns the parameters separated by spaces except for
filename and line which are separated by a colon.  The timestamp is shown
to second resolution in UTC. For example:


	2016-07-02 15:04:05


## func LoggerInfo
``` go
func LoggerInfo() string
```
LoggerInfo returns information about the configured loggers and their
logging levels. The information is returned in the format expected by
ConfigureLoggers. Loggers with UNSPECIFIED level will not
be included.


## func RegisterWriter
``` go
func RegisterWriter(name string, writer Writer) error
```
RegisterWriter adds the writer to the list of writers in the DefaultContext
that get notified when logging.  If there is already a registered writer
with that name, an error is returned.


## func ResetLogging
``` go
func ResetLogging()
```
ResetLogging iterates through the known modules and sets the levels of all
to UNSPECIFIED, except for <root> which is set to WARNING. The call also
removes all writers in the DefaultContext and puts the original default
writer back as the only writer.


## func ResetWriters
``` go
func ResetWriters()
```
ResetWriters puts the list of writers back into the initial state.



## type Config
``` go
type Config map[string]Level
```
Config is a mapping of logger module names to logging severity levels.









### func ParseConfigString
``` go
func ParseConfigString(specification string) (Config, error)
```
ParseConfigString parses a logger configuration string into a map of logger
names and their associated log level. This method is provided to allow
other programs to pre-validate a configuration string rather than just
calling ConfigureLoggers.

Logging modules are colon- or semicolon-separated; each module is specified
as <modulename>=<level>.  White space outside of module names and levels is
ignored.  The root module is specified with the name "<root>".

As a special case, a log level may be specified on its own.
This is equivalent to specifying the level of the root module,
so "DEBUG" is equivalent to `<root>=DEBUG`

An example specification:


	`<root>=ERROR; foo.bar=WARNING`




### func (Config) String
``` go
func (c Config) String() string
```
String returns a logger configuration string that may be parsed
using ParseConfigurationString.



## type Context
``` go
type Context struct {
    // contains filtered or unexported fields
}
```
Context produces loggers for a hierarchy of modules. The context holds
a collection of hierarchical loggers and their writers.









### func DefaultContext
``` go
func DefaultContext() *Context
```
DefaultContext returns the global default logging context.


### func NewContext
``` go
func NewContext(rootLevel Level) *Context
```
NewLoggers returns a new Context with no writers set.
If the root level is UNSPECIFIED, WARNING is used.




### func (\*Context) AddWriter
``` go
func (c *Context) AddWriter(name string, writer Writer) error
```
AddWriter adds a writer to the list to be called for each logging call.
The name cannot be empty, and the writer cannot be nil. If an existing
writer exists with the specified name, an error is returned.



### func (\*Context) ApplyConfig
``` go
func (c *Context) ApplyConfig(config Config)
```
ApplyConfig configures the logging modules according to the provided config.



### func (\*Context) CompleteConfig
``` go
func (c *Context) CompleteConfig() Config
```
CompleteConfig returns all the loggers and their defined levels,
even if that level is UNSPECIFIED.



### func (\*Context) Config
``` go
func (c *Context) Config() Config
```
Config returns the current configuration of the Loggers. Loggers
with UNSPECIFIED level will not be included.



### func (\*Context) GetLogger
``` go
func (c *Context) GetLogger(name string) Logger
```
GetLogger returns a Logger for the given module name, creating it and
its parents if necessary.



### func (\*Context) RemoveWriter
``` go
func (c *Context) RemoveWriter(name string) (Writer, error)
```
RemoveWriter remotes the specified writer. If a writer is not found with
the specified name an error is returned. The writer that was removed is also
returned.



### func (\*Context) ReplaceWriter
``` go
func (c *Context) ReplaceWriter(name string, writer Writer) (Writer, error)
```
ReplaceWriter is a convenience method that does the equivalent of RemoveWriter
followed by AddWriter with the same name. The replaced writer is returned.



### func (\*Context) ResetLoggerLevels
``` go
func (c *Context) ResetLoggerLevels()
```
ResetLoggerLevels iterates through the known logging modules and sets the
levels of all to UNSPECIFIED, except for <root> which is set to WARNING.



### func (\*Context) ResetWriters
``` go
func (c *Context) ResetWriters()
```
ResetWriters is generally only used in testing and removes all the writers.



### func (\*Context) Writer
``` go
func (c *Context) Writer(name string) Writer
```
Writer returns the named writer if one exists.
If there is not a writer with the specified name, nil is returned.



## type Entry
``` go
type Entry struct {
    // Level is the severity of the log message.
    Level Level
    // Module is the dotted module name from the logger.
    Module string
    // Filename is the full path the file that logged the message.
    Filename string
    // Line is the line number of the Filename.
    Line int
    // Timestamp is when the log message was created
    Timestamp time.Time
    // Message is the formatted string from teh log call.
    Message string
}
```
Entry represents a single log message.











## type Level
``` go
type Level uint32
```
Level holds a severity level.



``` go
const (
    UNSPECIFIED Level = iota
    TRACE
    DEBUG
    INFO
    WARNING
    ERROR
    CRITICAL
)
```
The severity levels. Higher values are more considered more
important.







### func ParseLevel
``` go
func ParseLevel(level string) (Level, bool)
```
ParseLevel converts a string representation of a logging level to a
Level. It returns the level and whether it was valid or not.




### func (Level) Short
``` go
func (level Level) Short() string
```
Short returns a five character string to use in
aligned logging output.



### func (Level) String
``` go
func (level Level) String() string
```
String implements Stringer.



## type Logger
``` go
type Logger struct {
    // contains filtered or unexported fields
}
```
A Logger represents a logging module. It has an associated logging
level which can be changed; messages of lesser severity will
be dropped. Loggers have a hierarchical relationship - see
the package documentation.

The zero Logger value is usable - any messages logged
to it will be sent to the root Logger.









### func GetLogger
``` go
func GetLogger(name string) Logger
```
GetLogger returns a Logger for the given module name,
creating it and its parents if necessary.




### func (Logger) Child
``` go
func (logger Logger) Child(name string) Logger
```
Child returns the Logger whose module name is the composed of this
Logger's name and the specified name.



### func (Logger) Criticalf
``` go
func (logger Logger) Criticalf(message string, args ...interface{})
```
Criticalf logs the printf-formatted message at critical level.



### func (Logger) Debugf
``` go
func (logger Logger) Debugf(message string, args ...interface{})
```
Debugf logs the printf-formatted message at debug level.



### func (Logger) EffectiveLogLevel
``` go
func (logger Logger) EffectiveLogLevel() Level
```
EffectiveLogLevel returns the effective min log level of
the receiver - that is, messages with a lesser severity
level will be discarded.

If the log level of the receiver is unspecified,
it will be taken from the effective log level of its
parent.



### func (Logger) Errorf
``` go
func (logger Logger) Errorf(message string, args ...interface{})
```
Errorf logs the printf-formatted message at error level.



### func (Logger) Infof
``` go
func (logger Logger) Infof(message string, args ...interface{})
```
Infof logs the printf-formatted message at info level.



### func (Logger) IsDebugEnabled
``` go
func (logger Logger) IsDebugEnabled() bool
```
IsDebugEnabled returns whether debugging is enabled
at debug level.



### func (Logger) IsErrorEnabled
``` go
func (logger Logger) IsErrorEnabled() bool
```
IsErrorEnabled returns whether debugging is enabled
at error level.



### func (Logger) IsInfoEnabled
``` go
func (logger Logger) IsInfoEnabled() bool
```
IsInfoEnabled returns whether debugging is enabled
at info level.



### func (Logger) IsLevelEnabled
``` go
func (logger Logger) IsLevelEnabled(level Level) bool
```
IsLevelEnabled returns whether debugging is enabled
for the given log level.



### func (Logger) IsTraceEnabled
``` go
func (logger Logger) IsTraceEnabled() bool
```
IsTraceEnabled returns whether debugging is enabled
at trace level.



### func (Logger) IsWarningEnabled
``` go
func (logger Logger) IsWarningEnabled() bool
```
IsWarningEnabled returns whether debugging is enabled
at warning level.



### func (Logger) LogCallf
``` go
func (logger Logger) LogCallf(calldepth int, level Level, message string, args ...interface{})
```
LogCallf logs a printf-formatted message at the given level.
The location of the call is indicated by the calldepth argument.
A calldepth of 1 means the function that called this function.
A message will be discarded if level is less than the
the effective log level of the logger.
Note that the writers may also filter out messages that
are less than their registered minimum severity level.



### func (Logger) LogLevel
``` go
func (logger Logger) LogLevel() Level
```
LogLevel returns the configured min log level of the logger.



### func (Logger) Logf
``` go
func (logger Logger) Logf(level Level, message string, args ...interface{})
```
Logf logs a printf-formatted message at the given level.
A message will be discarded if level is less than the
the effective log level of the logger.
Note that the writers may also filter out messages that
are less than their registered minimum severity level.



### func (Logger) Name
``` go
func (logger Logger) Name() string
```
Name returns the logger's module name.



### func (Logger) Parent
``` go
func (logger Logger) Parent() Logger
```
Parent returns the Logger whose module name is the same
as this logger without the last period and suffix.
For example the parent of the logger that has the module
"a.b.c" is "a.b".
The Parent of the root logger is still the root logger.



### func (Logger) SetLogLevel
``` go
func (logger Logger) SetLogLevel(level Level)
```
SetLogLevel sets the severity level of the given logger.
The root logger cannot be set to UNSPECIFIED level.
See EffectiveLogLevel for how this affects the
actual messages logged.



### func (Logger) Tracef
``` go
func (logger Logger) Tracef(message string, args ...interface{})
```
Tracef logs the printf-formatted message at trace level.



### func (Logger) Warningf
``` go
func (logger Logger) Warningf(message string, args ...interface{})
```
Warningf logs the printf-formatted message at warning level.



## type TestWriter
``` go
type TestWriter struct {
    // contains filtered or unexported fields
}
```
TestWriter is a useful Writer for testing purposes.  Each component of the
logging message is stored in the Log array.











### func (\*TestWriter) Clear
``` go
func (writer *TestWriter) Clear()
```
Clear removes any saved log messages.



### func (\*TestWriter) Log
``` go
func (writer *TestWriter) Log() []Entry
```
Log returns a copy of the current logged values.



### func (\*TestWriter) Write
``` go
func (writer *TestWriter) Write(entry Entry)
```
Write saves the params as members in the TestLogValues struct appended to the Log array.



## type Writer
``` go
type Writer interface {
    // Write writes a message to the Writer with the given level and module
    // name. The filename and line hold the file name and line number of the
    // code that is generating the log message; the time stamp holds the time
    // the log message was generated, and message holds the log message
    // itself.
    Write(entry Entry)
}
```
Writer is implemented by any recipient of log messages.









### func NewMinimumLevelWriter
``` go
func NewMinimumLevelWriter(writer Writer, minLevel Level) Writer
```
NewMinLevelWriter returns a Writer that will only pass on the Write calls
to the provided writer if the log level is at or above the specified
minimum level.


### func NewSimpleWriter
``` go
func NewSimpleWriter(writer io.Writer, formatter func(entry Entry) string) Writer
```
NewSimpleWriter returns a new writer that writes log messages to the given
io.Writer formatting the messages with the given formatter.


### func RemoveWriter
``` go
func RemoveWriter(name string) (Writer, error)
```
RemoveWriter removes the Writer identified by 'name' and returns it.
If the Writer is not found, an error is returned.


### func ReplaceDefaultWriter
``` go
func ReplaceDefaultWriter(writer Writer) (Writer, error)
```
ReplaceDefaultWriter is a convenience method that does the equivalent of
RemoveWriter and then RegisterWriter with the name "default".  The previous
default writer, if any is returned.










- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)