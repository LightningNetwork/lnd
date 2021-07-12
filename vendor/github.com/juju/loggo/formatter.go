// Copyright 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package loggo

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultFormatter returns the parameters separated by spaces except for
// filename and line which are separated by a colon.  The timestamp is shown
// to second resolution in UTC. For example:
//   2016-07-02 15:04:05
func DefaultFormatter(entry Entry) string {
	ts := entry.Timestamp.In(time.UTC).Format("2006-01-02 15:04:05")
	// Just get the basename from the filename
	filename := filepath.Base(entry.Filename)
	return fmt.Sprintf("%s %s %s %s:%d %s", ts, entry.Level, entry.Module, filename, entry.Line, entry.Message)
}

// TimeFormat is the time format used for the default writer.
// This can be set with the environment variable LOGGO_TIME_FORMAT.
var TimeFormat = initTimeFormat()

func initTimeFormat() string {
	format := os.Getenv("LOGGO_TIME_FORMAT")
	if format != "" {
		return format
	}
	return "15:04:05"
}

func formatTime(ts time.Time) string {
	return ts.Format(TimeFormat)
}
