package main

import (
	"fmt"
	"os"
	"time"
)

type logger func(format string, args ...interface{})

func stderrLogger(format string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(format, args...)
	now := time.Now().Format("2006-01-02 15:04:05.000")
	_, _ = fmt.Fprintf(
		os.Stderr, "%s LNDINIT: %s\n", now, formattedMsg,
	)
}

func noopLogger(_ string, _ ...interface{}) {}
