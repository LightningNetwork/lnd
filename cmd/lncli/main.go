// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	macaroon "gopkg.in/macaroon.v2"

	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/urfave/cli"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultDataDir          = "data"
	defaultChainSubDir      = "chain"
	defaultTLSCertFilename  = "tls.cert"
	defaultMacaroonFilename = "admin.macaroon"
	defaultRPCPort          = "10009"
	defaultRPCHostPort      = "localhost:" + defaultRPCPort
)

var (
	defaultLndDir      = btcutil.AppDataDir("lnd", false)
	defaultTLSCertPath = filepath.Join(defaultLndDir, defaultTLSCertFilename)

	// maxMsgRecvSize is the largest message our client will receive. We
	// set this to 200MiB atm.
	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200)
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[lncli] %v\n", err)
	os.Exit(1)
}

func getWalletUnlockerClient(ctx *cli.Context) (lnrpc.WalletUnlockerClient, func()) {
	conn := getClientConn(ctx, true)

	cleanUp := func() {
		conn.Close()
	}

	return lnrpc.NewWalletUnlockerClient(conn), cleanUp
}

func getClient(ctx *cli.Context) (lnrpc.LightningClient, func()) {
	conn := getClientConn(ctx, false)

	cleanUp := func() {
		conn.Close()
	}

	return lnrpc.NewLightningClient(conn), cleanUp
}

func getClientConn(ctx *cli.Context, skipMacaroons bool) *grpc.ClientConn {
	// First, we'll parse the args from the command.
	tlsCertPath, macPath, err := extractPathArgs(ctx)
	if err != nil {
		fatal(err)
	}

	// Load the specified TLS certificate and build transport credentials
	// with it.
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		fatal(err)
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	// Only process macaroon credentials if --no-macaroons isn't set and
	// if we're not skipping macaroon processing.
	if !ctx.GlobalBool("no-macaroons") && !skipMacaroons {
		// Load the specified macaroon file.
		macBytes, err := ioutil.ReadFile(macPath)
		if err != nil {
			fatal(fmt.Errorf("unable to read macaroon path (check "+
				"the network setting!): %v", err))
		}

		mac := &macaroon.Macaroon{}
		if err = mac.UnmarshalBinary(macBytes); err != nil {
			fatal(fmt.Errorf("unable to decode macaroon: %v", err))
		}

		macConstraints := []macaroons.Constraint{
			// We add a time-based constraint to prevent replay of the
			// macaroon. It's good for 60 seconds by default to make up for
			// any discrepancy between client and server clocks, but leaking
			// the macaroon before it becomes invalid makes it possible for
			// an attacker to reuse the macaroon. In addition, the validity
			// time of the macaroon is extended by the time the server clock
			// is behind the client clock, or shortened by the time the
			// server clock is ahead of the client clock (or invalid
			// altogether if, in the latter case, this time is more than 60
			// seconds).
			// TODO(aakselrod): add better anti-replay protection.
			macaroons.TimeoutConstraint(ctx.GlobalInt64("macaroontimeout")),

			// Lock macaroon down to a specific IP address.
			macaroons.IPLockConstraint(ctx.GlobalString("macaroonip")),

			// ... Add more constraints if needed.
		}

		// Apply constraints to the macaroon.
		constrainedMac, err := macaroons.AddConstraints(mac, macConstraints...)
		if err != nil {
			fatal(err)
		}

		// Now we append the macaroon credentials to the dial options.
		cred := macaroons.NewMacaroonCredential(constrainedMac)
		opts = append(opts, grpc.WithPerRPCCredentials(cred))
	}

	// We need to use a custom dialer so we can also connect to unix sockets
	// and not just TCP addresses.
	genericDialer := lncfg.ClientAddressDialer(defaultRPCPort)
	opts = append(opts, grpc.WithContextDialer(genericDialer))
	opts = append(opts, grpc.WithDefaultCallOptions(maxMsgRecvSize))

	conn, err := grpc.Dial(ctx.GlobalString("rpcserver"), opts...)
	if err != nil {
		fatal(fmt.Errorf("unable to connect to RPC server: %v", err))
	}

	return conn
}

// extractPathArgs parses the TLS certificate and macaroon paths from the
// command.
func extractPathArgs(ctx *cli.Context) (string, string, error) {
	// We'll start off by parsing the active chain and network. These are
	// needed to determine the correct path to the macaroon when not
	// specified.
	chain := strings.ToLower(ctx.GlobalString("chain"))
	switch chain {
	case "bitcoin", "litecoin":
	default:
		return "", "", fmt.Errorf("unknown chain: %v", chain)
	}

	network := strings.ToLower(ctx.GlobalString("network"))
	switch network {
	case "mainnet", "testnet", "regtest", "simnet":
	default:
		return "", "", fmt.Errorf("unknown network: %v", network)
	}

	// We'll now fetch the lnddir so we can make a decision  on how to
	// properly read the macaroons (if needed) and also the cert. This will
	// either be the default, or will have been overwritten by the end
	// user.
	lndDir := cleanAndExpandPath(ctx.GlobalString("lnddir"))

	// If the macaroon path as been manually provided, then we'll only
	// target the specified file.
	var macPath string
	if ctx.GlobalString("macaroonpath") != "" {
		macPath = cleanAndExpandPath(ctx.GlobalString("macaroonpath"))
	} else {
		// Otherwise, we'll go into the path:
		// lnddir/data/chain/<chain>/<network> in order to fetch the
		// macaroon that we need.
		macPath = filepath.Join(
			lndDir, defaultDataDir, defaultChainSubDir, chain,
			network, defaultMacaroonFilename,
		)
	}

	tlsCertPath := cleanAndExpandPath(ctx.GlobalString("tlscertpath"))

	// If a custom lnd directory was set, we'll also check if custom paths
	// for the TLS cert and macaroon file were set as well. If not, we'll
	// override their paths so they can be found within the custom lnd
	// directory set. This allows us to set a custom lnd directory, along
	// with custom paths to the TLS cert and macaroon file.
	if lndDir != defaultLndDir {
		tlsCertPath = filepath.Join(lndDir, defaultTLSCertFilename)
	}

	return tlsCertPath, macPath, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "lncli"
	app.Version = build.Version() + " commit=" + build.Commit
	app.Usage = "control plane for your Lightning Network Daemon (lnd)"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "rpcserver",
			Value: defaultRPCHostPort,
			Usage: "host:port of ln daemon",
		},
		cli.StringFlag{
			Name:      "lnddir",
			Value:     defaultLndDir,
			Usage:     "path to lnd's base directory",
			TakesFile: true,
		},
		cli.StringFlag{
			Name:      "tlscertpath",
			Value:     defaultTLSCertPath,
			Usage:     "path to TLS certificate",
			TakesFile: true,
		},
		cli.StringFlag{
			Name:  "chain, c",
			Usage: "the chain lnd is running on e.g. bitcoin",
			Value: "bitcoin",
		},
		cli.StringFlag{
			Name: "network, n",
			Usage: "the network lnd is running on e.g. mainnet, " +
				"testnet, etc.",
			Value: "mainnet",
		},
		cli.BoolFlag{
			Name:  "no-macaroons",
			Usage: "disable macaroon authentication",
		},
		cli.StringFlag{
			Name:      "macaroonpath",
			Usage:     "path to macaroon file",
			TakesFile: true,
		},
		cli.Int64Flag{
			Name:  "macaroontimeout",
			Value: 60,
			Usage: "anti-replay macaroon validity time in seconds",
		},
		cli.StringFlag{
			Name:  "macaroonip",
			Usage: "if set, lock macaroon to specific IP address",
		},
	}
	app.Commands = []cli.Command{
		createCommand,
		unlockCommand,
		changePasswordCommand,
		newAddressCommand,
		estimateFeeCommand,
		sendManyCommand,
		sendCoinsCommand,
		listUnspentCommand,
		connectCommand,
		disconnectCommand,
		openChannelCommand,
		closeChannelCommand,
		closeAllChannelsCommand,
		abandonChannelCommand,
		listPeersCommand,
		walletBalanceCommand,
		channelBalanceCommand,
		getInfoCommand,
		pendingChannelsCommand,
		sendPaymentCommand,
		payInvoiceCommand,
		sendToRouteCommand,
		addInvoiceCommand,
		lookupInvoiceCommand,
		listInvoicesCommand,
		listChannelsCommand,
		closedChannelsCommand,
		listPaymentsCommand,
		describeGraphCommand,
		getNodeMetricsCommand,
		getChanInfoCommand,
		getNodeInfoCommand,
		queryRoutesCommand,
		getNetworkInfoCommand,
		debugLevelCommand,
		decodePayReqCommand,
		listChainTxnsCommand,
		stopCommand,
		signMessageCommand,
		verifyMessageCommand,
		feeReportCommand,
		updateChannelPolicyCommand,
		forwardingHistoryCommand,
		exportChanBackupCommand,
		verifyChanBackupCommand,
		restoreChanBackupCommand,
		bakeMacaroonCommand,
		trackPaymentCommand,
		versionCommand,
		fishCompletionCommand,
	}

	// Add any extra commands determined by build flags.
	app.Commands = append(app.Commands, autopilotCommands()...)
	app.Commands = append(app.Commands, invoicesCommands()...)
	app.Commands = append(app.Commands, routerCommands()...)
	app.Commands = append(app.Commands, walletCommands()...)
	app.Commands = append(app.Commands, watchtowerCommands()...)
	app.Commands = append(app.Commands, wtclientCommands()...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		user, err := user.Current()
		if err == nil {
			homeDir = user.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}
