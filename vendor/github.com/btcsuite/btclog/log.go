// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// Copyright (c) 2009 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package btclog

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultFlags specifies changes to the default logger behavior.  It is set
// during package init and configured using the LOGFLAGS environment variable.
// New logger backends can override these default flags using WithFlags.
var defaultFlags uint32

// Flags to modify Backend's behavior.
const (
	// Llongfile modifies the logger output to include full path and line number
	// of the logging callsite, e.g. /a/b/c/main.go:123.
	Llongfile uint32 = 1 << iota

	// Lshortfile modifies the logger output to include filename and line number
	// of the logging callsite, e.g. main.go:123.  Overrides Llongfile.
	Lshortfile
)

// Read logger flags from the LOGFLAGS environment variable.  Multiple flags can
// be set at once, separated by commas.
func init() {
	for _, f := range strings.Split(os.Getenv("LOGFLAGS"), ",") {
		switch f {
		case "longfile":
			defaultFlags |= Llongfile
		case "shortfile":
			defaultFlags |= Lshortfile
		}
	}
}

// Level is the level at which a logger is configured.  All messages sent
// to a level which is below the current level are filtered.
type Level uint32

// Level constants.
const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelCritical
	LevelOff
)

// levelStrs defines the human-readable names for each logging level.
var levelStrs = [...]string{"TRC", "DBG", "INF", "WRN", "ERR", "CRT", "OFF"}

// LevelFromString returns a level based on the input string s.  If the input
// can't be interpreted as a valid log level, the info level and false is
// returned.
func LevelFromString(s string) (l Level, ok bool) {
	switch strings.ToLower(s) {
	case "trace", "trc":
		return LevelTrace, true
	case "debug", "dbg":
		return LevelDebug, true
	case "info", "inf":
		return LevelInfo, true
	case "warn", "wrn":
		return LevelWarn, true
	case "error", "err":
		return LevelError, true
	case "critical", "crt":
		return LevelCritical, true
	case "off":
		return LevelOff, true
	default:
		return LevelInfo, false
	}
}

// String returns the tag of the logger used in log messages, or "OFF" if
// the level will not produce any log output.
func (l Level) String() string {
	if l >= LevelOff {
		return "OFF"
	}
	return levelStrs[l]
}

// NewBackend creates a logger backend from a Writer.
func NewBackend(w io.Writer, opts ...BackendOption) *Backend {
	b := &Backend{w: w, flag: defaultFlags}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Backend is a logging backend.  Subsystems created from the backend write to
// the backend's Writer.  Backend provides atomic writes to the Writer from all
// subsystems.
type Backend struct {
	w    io.Writer
	mu   sync.Mutex // ensures atomic writes
	flag uint32
}

// BackendOption is a function used to modify the behavior of a Backend.
type BackendOption func(b *Backend)

// WithFlags configures a Backend to use the specified flags rather than using
// the package's defaults as determined through the LOGFLAGS environment
// variable.
func WithFlags(flags uint32) BackendOption {
	return func(b *Backend) {
		b.flag = flags
	}
}

// bufferPool defines a concurrent safe free list of byte slices used to provide
// temporary buffers for formatting log messages prior to outputting them.
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 120)
		return &b // pointer to slice to avoid boxing alloc
	},
}

// buffer returns a byte slice from the free list.  A new buffer is allocated if
// there are not any available on the free list.  The returned byte slice should
// be returned to the fee list by using the recycleBuffer function when the
// caller is done with it.
func buffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// recycleBuffer puts the provided byte slice, which should have been obtain via
// the buffer function, back on the free list.
func recycleBuffer(b *[]byte) {
	*b = (*b)[:0]
	bufferPool.Put(b)
}

// From stdlib log package.
// Cheap integer to fixed-width decimal ASCII.  Give a negative width to avoid
// zero-padding.
func itoa(buf *[]byte, i int, wid int) {
	// Assemble decimal in reverse order.
	var b [20]byte
	bp := len(b) - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		b[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	b[bp] = byte('0' + i)
	*buf = append(*buf, b[bp:]...)
}

// Appends a header in the default format 'YYYY-MM-DD hh:mm:ss.sss [LVL] TAG: '.
// If either of the Lshortfile or Llongfile flags are specified, the file named
// and line number are included after the tag and before the final colon.
func formatHeader(buf *[]byte, t time.Time, lvl, tag string, file string, line int) {
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	ms := t.Nanosecond() / 1e6

	itoa(buf, year, 4)
	*buf = append(*buf, '-')
	itoa(buf, int(month), 2)
	*buf = append(*buf, '-')
	itoa(buf, day, 2)
	*buf = append(*buf, ' ')
	itoa(buf, hour, 2)
	*buf = append(*buf, ':')
	itoa(buf, min, 2)
	*buf = append(*buf, ':')
	itoa(buf, sec, 2)
	*buf = append(*buf, '.')
	itoa(buf, ms, 3)
	*buf = append(*buf, " ["...)
	*buf = append(*buf, lvl...)
	*buf = append(*buf, "] "...)
	*buf = append(*buf, tag...)
	if file != "" {
		*buf = append(*buf, ' ')
		*buf = append(*buf, file...)
		*buf = append(*buf, ':')
		itoa(buf, line, -1)
	}
	*buf = append(*buf, ": "...)
}

// calldepth is the call depth of the callsite function relative to the
// caller of the subsystem logger.  It is used to recover the filename and line
// number of the logging call if either the short or long file flags are
// specified.
const calldepth = 3

// callsite returns the file name and line number of the callsite to the
// subsystem logger.
func callsite(flag uint32) (string, int) {
	_, file, line, ok := runtime.Caller(calldepth)
	if !ok {
		return "???", 0
	}
	if flag&Lshortfile != 0 {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if os.IsPathSeparator(file[i]) {
				short = file[i+1:]
				break
			}
		}
		file = short
	}
	return file, line
}

// print outputs a log message to the writer associated with the backend after
// creating a prefix for the given level and tag according to the formatHeader
// function and formatting the provided arguments using the default formatting
// rules.
func (b *Backend) print(lvl, tag string, args ...interface{}) {
	t := time.Now() // get as early as possible

	bytebuf := buffer()

	var file string
	var line int
	if b.flag&(Lshortfile|Llongfile) != 0 {
		file, line = callsite(b.flag)
	}

	formatHeader(bytebuf, t, lvl, tag, file, line)
	buf := bytes.NewBuffer(*bytebuf)
	fmt.Fprintln(buf, args...)
	*bytebuf = buf.Bytes()

	b.mu.Lock()
	b.w.Write(*bytebuf)
	b.mu.Unlock()

	recycleBuffer(bytebuf)
}

// printf outputs a log message to the writer associated with the backend after
// creating a prefix for the given level and tag according to the formatHeader
// function and formatting the provided arguments according to the given format
// specifier.
func (b *Backend) printf(lvl, tag string, format string, args ...interface{}) {
	t := time.Now() // get as early as possible

	bytebuf := buffer()

	var file string
	var line int
	if b.flag&(Lshortfile|Llongfile) != 0 {
		file, line = callsite(b.flag)
	}

	formatHeader(bytebuf, t, lvl, tag, file, line)
	buf := bytes.NewBuffer(*bytebuf)
	fmt.Fprintf(buf, format, args...)
	*bytebuf = append(buf.Bytes(), '\n')

	b.mu.Lock()
	b.w.Write(*bytebuf)
	b.mu.Unlock()

	recycleBuffer(bytebuf)
}

// Logger returns a new logger for a particular subsystem that writes to the
// Backend b.  A tag describes the subsystem and is included in all log
// messages.  The logger uses the info verbosity level by default.
func (b *Backend) Logger(subsystemTag string) Logger {
	return &slog{LevelInfo, subsystemTag, b}
}

// slog is a subsystem logger for a Backend.  Implements the Logger interface.
type slog struct {
	lvl Level // atomic
	tag string
	b   *Backend
}

// Trace formats message using the default formats for its operands, prepends
// the prefix as necessary, and writes to log with LevelTrace.
//
// This is part of the Logger interface implementation.
func (l *slog) Trace(args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelTrace {
		l.b.print("TRC", l.tag, args...)
	}
}

// Tracef formats message according to format specifier, prepends the prefix as
// necessary, and writes to log with LevelTrace.
//
// This is part of the Logger interface implementation.
func (l *slog) Tracef(format string, args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelTrace {
		l.b.printf("TRC", l.tag, format, args...)
	}
}

// Debug formats message using the default formats for its operands, prepends
// the prefix as necessary, and writes to log with LevelDebug.
//
// This is part of the Logger interface implementation.
func (l *slog) Debug(args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelDebug {
		l.b.print("DBG", l.tag, args...)
	}
}

// Debugf formats message according to format specifier, prepends the prefix as
// necessary, and writes to log with LevelDebug.
//
// This is part of the Logger interface implementation.
func (l *slog) Debugf(format string, args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelDebug {
		l.b.printf("DBG", l.tag, format, args...)
	}
}

// Info formats message using the default formats for its operands, prepends
// the prefix as necessary, and writes to log with LevelInfo.
//
// This is part of the Logger interface implementation.
func (l *slog) Info(args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelInfo {
		l.b.print("INF", l.tag, args...)
	}
}

// Infof formats message according to format specifier, prepends the prefix as
// necessary, and writes to log with LevelInfo.
//
// This is part of the Logger interface implementation.
func (l *slog) Infof(format string, args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelInfo {
		l.b.printf("INF", l.tag, format, args...)
	}
}

// Warn formats message using the default formats for its operands, prepends
// the prefix as necessary, and writes to log with LevelWarn.
//
// This is part of the Logger interface implementation.
func (l *slog) Warn(args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelWarn {
		l.b.print("WRN", l.tag, args...)
	}
}

// Warnf formats message according to format specifier, prepends the prefix as
// necessary, and writes to log with LevelWarn.
//
// This is part of the Logger interface implementation.
func (l *slog) Warnf(format string, args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelWarn {
		l.b.printf("WRN", l.tag, format, args...)
	}
}

// Error formats message using the default formats for its operands, prepends
// the prefix as necessary, and writes to log with LevelError.
//
// This is part of the Logger interface implementation.
func (l *slog) Error(args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelError {
		l.b.print("ERR", l.tag, args...)
	}
}

// Errorf formats message according to format specifier, prepends the prefix as
// necessary, and writes to log with LevelError.
//
// This is part of the Logger interface implementation.
func (l *slog) Errorf(format string, args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelError {
		l.b.printf("ERR", l.tag, format, args...)
	}
}

// Critical formats message using the default formats for its operands, prepends
// the prefix as necessary, and writes to log with LevelCritical.
//
// This is part of the Logger interface implementation.
func (l *slog) Critical(args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelCritical {
		l.b.print("CRT", l.tag, args...)
	}
}

// Criticalf formats message according to format specifier, prepends the prefix
// as necessary, and writes to log with LevelCritical.
//
// This is part of the Logger interface implementation.
func (l *slog) Criticalf(format string, args ...interface{}) {
	lvl := l.Level()
	if lvl <= LevelCritical {
		l.b.printf("CRT", l.tag, format, args...)
	}
}

// Level returns the current logging level
//
// This is part of the Logger interface implementation.
func (l *slog) Level() Level {
	return Level(atomic.LoadUint32((*uint32)(&l.lvl)))
}

// SetLevel changes the logging level to the passed level.
//
// This is part of the Logger interface implementation.
func (l *slog) SetLevel(level Level) {
	atomic.StoreUint32((*uint32)(&l.lvl), uint32(level))
}

// Disabled is a Logger that will never output anything.
var Disabled Logger

func init() {
	Disabled = &slog{lvl: LevelOff, b: NewBackend(ioutil.Discard)}
}
