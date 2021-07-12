// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package loggo

import (
	"strings"
	"sync/atomic"
)

// The severity levels. Higher values are more considered more
// important.
const (
	UNSPECIFIED Level = iota
	TRACE
	DEBUG
	INFO
	WARNING
	ERROR
	CRITICAL
)

// Level holds a severity level.
type Level uint32

// ParseLevel converts a string representation of a logging level to a
// Level. It returns the level and whether it was valid or not.
func ParseLevel(level string) (Level, bool) {
	level = strings.ToUpper(level)
	switch level {
	case "UNSPECIFIED":
		return UNSPECIFIED, true
	case "TRACE":
		return TRACE, true
	case "DEBUG":
		return DEBUG, true
	case "INFO":
		return INFO, true
	case "WARN", "WARNING":
		return WARNING, true
	case "ERROR":
		return ERROR, true
	case "CRITICAL":
		return CRITICAL, true
	default:
		return UNSPECIFIED, false
	}
}

// String implements Stringer.
func (level Level) String() string {
	switch level {
	case UNSPECIFIED:
		return "UNSPECIFIED"
	case TRACE:
		return "TRACE"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "<unknown>"
	}
}

// Short returns a five character string to use in
// aligned logging output.
func (level Level) Short() string {
	switch level {
	case TRACE:
		return "TRACE"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO "
	case WARNING:
		return "WARN "
	case ERROR:
		return "ERROR"
	case CRITICAL:
		return "CRITC"
	default:
		return "     "
	}
}

// get atomically gets the value of the given level.
func (level *Level) get() Level {
	return Level(atomic.LoadUint32((*uint32)(level)))
}

// set atomically sets the value of the receiver
// to the given level.
func (level *Level) set(newLevel Level) {
	atomic.StoreUint32((*uint32)(level), uint32(newLevel))
}
