// Copyright 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package loggo

import (
	"path"
	"sync"
)

// TestWriter is a useful Writer for testing purposes.  Each component of the
// logging message is stored in the Log array.
type TestWriter struct {
	mu  sync.Mutex
	log []Entry
}

// Write saves the params as members in the TestLogValues struct appended to the Log array.
func (writer *TestWriter) Write(entry Entry) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	entry.Filename = path.Base(entry.Filename)
	writer.log = append(writer.log, entry)
}

// Clear removes any saved log messages.
func (writer *TestWriter) Clear() {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.log = nil
}

// Log returns a copy of the current logged values.
func (writer *TestWriter) Log() []Entry {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	v := make([]Entry, len(writer.log))
	copy(v, writer.log)
	return v
}
