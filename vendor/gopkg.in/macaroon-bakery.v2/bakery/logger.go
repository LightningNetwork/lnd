package bakery

import (
	"github.com/juju/loggo"
	"golang.org/x/net/context"
)

// Logger is used by the bakery to log informational messages
// about bakery operations.
type Logger interface {
	Infof(ctx context.Context, f string, args ...interface{})
	Debugf(ctx context.Context, f string, args ...interface{})
}

// DefaultLogger returns a Logger instance that uses
// github.com/juju/loggo to log messages using the
// given logger name.
func DefaultLogger(name string) Logger {
	return loggoLogger{loggo.GetLogger(name)}
}

type loggoLogger struct {
	logger loggo.Logger
}

// Debugf implements Logger.Debugf.
func (l loggoLogger) Debugf(_ context.Context, f string, args ...interface{}) {
	l.logger.Debugf(f, args...)
}

// Debugf implements Logger.Infof.
func (l loggoLogger) Infof(_ context.Context, f string, args ...interface{}) {
	l.logger.Infof(f, args...)
}
