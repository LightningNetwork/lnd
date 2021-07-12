package clock

import (
	"time"
)

// Clock is an interface that provides a time functions for LND packages.
// This is useful during testing when a concrete time reference is needed.
type Clock interface {
	// Now returns the current local time (as defined by the Clock).
	Now() time.Time

	// TickAfter returns a channel that will receive a tick after the specified
	// duration has passed.
	TickAfter(duration time.Duration) <-chan time.Time
}
