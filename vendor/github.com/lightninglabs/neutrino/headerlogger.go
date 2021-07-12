package neutrino

import (
	"sync"
	"time"

	"github.com/btcsuite/btclog"
)

// headerProgressLogger provides periodic logging for other services in order
// to show users progress of certain "actions" involving some or all current
// blocks. Ex: syncing to best chain, indexing all blocks, etc.
type headerProgressLogger struct {
	receivedLogBlocks int64
	lastBlockLogTime  time.Time

	entityType string

	subsystemLogger btclog.Logger
	progressAction  string
	sync.Mutex
}

// newBlockProgressLogger returns a new block progress logger.
// The progress message is templated as follows:
//  {progressAction} {numProcessed} {blocks|block} in the last {timePeriod}
//  ({numTxs}, height {lastBlockHeight}, {lastBlockTimeStamp})
func newBlockProgressLogger(progressMessage string,
	entityType string, logger btclog.Logger) *headerProgressLogger {

	return &headerProgressLogger{
		entityType:       entityType,
		lastBlockLogTime: time.Now(),
		progressAction:   progressMessage,
		subsystemLogger:  logger,
	}
}

// LogBlockHeight logs a new block height as an information message to show
// progress to the user. In order to prevent spam, it limits logging to one
// message every 10 seconds with duration and totals included.
func (b *headerProgressLogger) LogBlockHeight(timestamp time.Time, height int32) {
	b.Lock()
	defer b.Unlock()

	b.receivedLogBlocks++

	// TODO(roasbeef): have diff logger for fetching blocks to can eye ball
	// false positive

	now := time.Now()
	duration := now.Sub(b.lastBlockLogTime)
	if duration < time.Second*10 {
		return
	}

	// Truncate the duration to 10s of milliseconds.
	durationMillis := int64(duration / time.Millisecond)
	tDuration := 10 * time.Millisecond * time.Duration(durationMillis/10)

	// Log information about new block height.
	entityStr := b.entityType
	if b.receivedLogBlocks > 1 {
		entityStr += "s"
	}
	b.subsystemLogger.Infof("%s %d %s in the last %s (height %d, %s)",
		b.progressAction, b.receivedLogBlocks, entityStr, tDuration,
		height, timestamp)

	b.receivedLogBlocks = 0
	b.lastBlockLogTime = now
}

func (b *headerProgressLogger) SetLastLogTime(time time.Time) {
	b.lastBlockLogTime = time
}
