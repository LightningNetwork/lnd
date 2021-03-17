package lnd

import (
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/neutrino"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/autopilot"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/chanacceptor"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/chanfitness"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channelnotifier"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/healthcheck"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/lnrpc/autopilotrpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/verrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chancloser"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
	"github.com/lightningnetwork/lnd/monitoring"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/peer"
	"github.com/lightningnetwork/lnd/peernotifier"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/routing/localchans"
	"github.com/lightningnetwork/lnd/rpcperms"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/lightningnetwork/lnd/watchtower"
	"github.com/lightningnetwork/lnd/watchtower/wtclient"
)

// replaceableLogger is a thin wrapper around a logger that is used so the
// logger can be replaced easily without some black pointer magic.
type replaceableLogger struct {
	btclog.Logger
	subsystem string
}

// Loggers can not be used before the log rotator has been initialized with a
// log file. This must be performed early during application startup by
// calling InitLogRotator() on the main log writer instance in the config.
var (
	// lndPkgLoggers is a list of all lnd package level loggers that are
	// registered. They are tracked here so they can be replaced once the
	// SetupLoggers function is called with the final root logger.
	lndPkgLoggers []*replaceableLogger

	// addLndPkgLogger is a helper function that creates a new replaceable
	// main lnd package level logger and adds it to the list of loggers that
	// are replaced again later, once the final root logger is ready.
	addLndPkgLogger = func(subsystem string) *replaceableLogger {
		l := &replaceableLogger{
			Logger:    build.NewSubLogger(subsystem, nil),
			subsystem: subsystem,
		}
		lndPkgLoggers = append(lndPkgLoggers, l)
		return l
	}

	// Loggers that need to be accessible from the lnd package can be placed
	// here. Loggers that are only used in sub modules can be added directly
	// by using the addSubLogger method. We declare all loggers so we never
	// run into a nil reference if they are used early. But the SetupLoggers
	// function should always be called as soon as possible to finish
	// setting them up properly with a root logger.
	ltndLog = addLndPkgLogger("LTND")
	rpcsLog = addLndPkgLogger("RPCS")
	srvrLog = addLndPkgLogger("SRVR")
	utxnLog = addLndPkgLogger("UTXN")
	brarLog = addLndPkgLogger("BRAR")
	atplLog = addLndPkgLogger("ATPL")
)

// SetupLoggers initializes all package-global logger variables.
func SetupLoggers(root *build.RotatingLogWriter) {
	// Now that we have the proper root logger, we can replace the
	// placeholder lnd package loggers.
	for _, l := range lndPkgLoggers {
		l.Logger = build.NewSubLogger(l.subsystem, root.GenSubLogger)
		SetSubLogger(root, l.subsystem, l.Logger)
	}

	// Some of the loggers declared in the main lnd package are also used
	// in sub packages.
	signal.UseLogger(ltndLog)
	autopilot.UseLogger(atplLog)

	AddSubLogger(root, "LNWL", lnwallet.UseLogger)
	AddSubLogger(root, "DISC", discovery.UseLogger)
	AddSubLogger(root, "NTFN", chainntnfs.UseLogger)
	AddSubLogger(root, "CHDB", channeldb.UseLogger)
	AddSubLogger(root, "HSWC", htlcswitch.UseLogger)
	AddSubLogger(root, "CMGR", connmgr.UseLogger)
	AddSubLogger(root, "BTCN", neutrino.UseLogger)
	AddSubLogger(root, "CNCT", contractcourt.UseLogger)
	AddSubLogger(root, "SPHX", sphinx.UseLogger)
	AddSubLogger(root, "SWPR", sweep.UseLogger)
	AddSubLogger(root, "SGNR", signrpc.UseLogger)
	AddSubLogger(root, "WLKT", walletrpc.UseLogger)
	AddSubLogger(root, "ARPC", autopilotrpc.UseLogger)
	AddSubLogger(root, "INVC", invoices.UseLogger)
	AddSubLogger(root, "NANN", netann.UseLogger)
	AddSubLogger(root, "WTWR", watchtower.UseLogger)
	AddSubLogger(root, "NTFR", chainrpc.UseLogger)
	AddSubLogger(root, "IRPC", invoicesrpc.UseLogger)
	AddSubLogger(root, "CHNF", channelnotifier.UseLogger)
	AddSubLogger(root, "CHBU", chanbackup.UseLogger)
	AddSubLogger(root, "PROM", monitoring.UseLogger)
	AddSubLogger(root, "WTCL", wtclient.UseLogger)
	AddSubLogger(root, "PRNF", peernotifier.UseLogger)
	AddSubLogger(root, "CHFD", chanfunding.UseLogger)
	AddSubLogger(root, "PEER", peer.UseLogger)
	AddSubLogger(root, "CHCL", chancloser.UseLogger)

	AddSubLogger(root, routing.Subsystem, routing.UseLogger, localchans.UseLogger)
	AddSubLogger(root, routerrpc.Subsystem, routerrpc.UseLogger)
	AddSubLogger(root, chanfitness.Subsystem, chanfitness.UseLogger)
	AddSubLogger(root, verrpc.Subsystem, verrpc.UseLogger)
	AddSubLogger(root, healthcheck.Subsystem, healthcheck.UseLogger)
	AddSubLogger(root, chainreg.Subsystem, chainreg.UseLogger)
	AddSubLogger(root, chanacceptor.Subsystem, chanacceptor.UseLogger)
	AddSubLogger(root, funding.Subsystem, funding.UseLogger)
	AddSubLogger(root, rpcperms.Subsystem, rpcperms.UseLogger)
}

// AddSubLogger is a helper method to conveniently create and register the
// logger of one or more sub systems.
func AddSubLogger(root *build.RotatingLogWriter, subsystem string,
	useLoggers ...func(btclog.Logger)) {

	// Create and register just a single logger to prevent them from
	// overwriting each other internally.
	logger := build.NewSubLogger(subsystem, root.GenSubLogger)
	SetSubLogger(root, subsystem, logger, useLoggers...)
}

// SetSubLogger is a helper method to conveniently register the logger of a sub
// system.
func SetSubLogger(root *build.RotatingLogWriter, subsystem string,
	logger btclog.Logger, useLoggers ...func(btclog.Logger)) {

	root.RegisterSubLogger(subsystem, logger)
	for _, useLogger := range useLoggers {
		useLogger(logger)
	}
}

// logClosure is used to provide a closure over expensive logging operations so
// don't have to be performed when the logging level doesn't warrant it.
type logClosure func() string

// String invokes the underlying function and returns the result.
func (c logClosure) String() string {
	return c()
}

// newLogClosure returns a new closure over a function that returns a string
// which itself provides a Stringer interface so that it can be used with the
// logging system.
func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}
