package neutrinonotify

import (
	"errors"
	"fmt"

	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// createNewNotifier creates a new instance of the ChainNotifier interface
// implemented by NeutrinoNotifier.
func createNewNotifier(args ...interface{}) (chainntnfs.ChainNotifier, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("incorrect number of arguments to "+
			".New(...), expected 2, instead passed %v", len(args))
	}

	config, ok := args[0].(*neutrino.ChainService)
	if !ok {
		return nil, errors.New("first argument to neutrinonotify.New " +
			"is incorrect, expected a *neutrino.ChainService")
	}

	hintCache, ok := args[1].(chainntnfs.HintCache)
	if !ok {
		return nil, errors.New("second argument to neutrinonotify.New " +
			"is incorrect, expected a chainntfs.HintCache")
	}

	return New(config, hintCache)
}

// init registers a driver for the NeutrinoNotify concrete implementation of
// the chainntnfs.ChainNotifier interface.
func init() {
	// Register the driver.
	notifier := &chainntnfs.NotifierDriver{
		NotifierType: notifierType,
		New:          createNewNotifier,
	}

	if err := chainntnfs.RegisterNotifier(notifier); err != nil {
		panic(fmt.Sprintf("failed to register notifier driver '%s': %v",
			notifierType, err))
	}
}
