package btcdnotify

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// createNewNotifier creates a new instance of the ChainNotifier interface
// implemented by BtcdNotifier.
func createNewNotifier(args ...interface{}) (chainntnfs.ChainNotifier, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("incorrect number of arguments to "+
			".New(...), expected 2, instead passed %v", len(args))
	}

	config, ok := args[0].(*rpcclient.ConnConfig)
	if !ok {
		return nil, errors.New("first argument to btcdnotifier.New " +
			"is incorrect, expected a *rpcclient.ConnConfig")
	}

	hintCache, ok := args[1].(chainntnfs.HintCache)
	if !ok {
		return nil, errors.New("second argument to btcdnotifier.New " +
			"is incorrect, expected a chainntnfs.HintCache")
	}

	return New(config, hintCache)
}

// init registers a driver for the BtcdNotifier concrete implementation of the
// chainntnfs.ChainNotifier interface.
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
