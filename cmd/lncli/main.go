// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/urfave/cli"

	"golang.org/x/crypto/ssh/terminal"
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

func getStateServiceClient(ctx *cli.Context) (lnrpc.StateClient, func()) {
	conn := getClientConn(ctx, true)

	cleanUp := func() {
		conn.Close()
	}

	return lnrpc.NewStateClient(conn), cleanUp
}

func getClient(ctx *cli.Context) (lnrpc.LightningClient, func()) {
	conn := getClientConn(ctx, false)

	cleanUp := func() {
		conn.Close()
	}

	return lnrpc.NewLightningClient(conn), cleanUp
}

func getClientConn(ctx *cli.Context, skipMacaroons bool) *grpc.ClientConn {
	// First, we'll get the selected stored profile or an ephemeral one
	// created from the global options in the CLI context.
	profile, err := getGlobalOptions(ctx, skipMacaroons)
	if err != nil {
		fatal(fmt.Errorf("could not load global options: %v", err))
	}

	// Load the specified TLS certificate.
	certPool, err := profile.cert()
	if err != nil {
		fatal(fmt.Errorf("could not create cert pool: %v", err))
	}

	// Build transport credentials from the certificate pool. If there is no
	// certificate pool, we expect the server to use a non-self-signed
	// certificate such as a certificate obtained from Let's Encrypt.
	var creds credentials.TransportCredentials
	if certPool != nil {
		creds = credentials.NewClientTLSFromCert(certPool, "")
	} else {
		// Fallback to the system pool. Using an empty tls config is an
		// alternative to x509.SystemCertPool(). That call is not
		// supported on Windows.
		creds = credentials.NewTLS(&tls.Config{})
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	// Only process macaroon credentials if --no-macaroons isn't set and
	// if we're not skipping macaroon processing.
	if !profile.NoMacaroons && !skipMacaroons {
		// Find out which macaroon to load.
		macName := profile.Macaroons.Default
		if ctx.GlobalIsSet("macfromjar") {
			macName = ctx.GlobalString("macfromjar")
		}
		var macEntry *macaroonEntry
		for _, entry := range profile.Macaroons.Jar {
			if entry.Name == macName {
				macEntry = entry
				break
			}
		}
		if macEntry == nil {
			fatal(fmt.Errorf("macaroon with name '%s' not found "+
				"in profile", macName))
		}

		// Get and possibly decrypt the specified macaroon.
		//
		// TODO(guggero): Make it possible to cache the password so we
		// don't need to ask for it every time.
		mac, err := macEntry.loadMacaroon(readPassword)
		if err != nil {
			fatal(fmt.Errorf("could not load macaroon: %v", err))
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
			macaroons.TimeoutConstraint(profile.Macaroons.Timeout),

			// Lock macaroon down to a specific IP address.
			macaroons.IPLockConstraint(profile.Macaroons.IP),

			// ... Add more constraints if needed.
		}

		// Apply constraints to the macaroon.
		constrainedMac, err := macaroons.AddConstraints(
			mac, macConstraints...,
		)
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

	conn, err := grpc.Dial(profile.RPCServer, opts...)
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
	case "mainnet", "testnet", "regtest", "simnet", "signet":
	default:
		return "", "", fmt.Errorf("unknown network: %v", network)
	}

	// We'll now fetch the lnddir so we can make a decision  on how to
	// properly read the macaroons (if needed) and also the cert. This will
	// either be the default, or will have been overwritten by the end
	// user.
	lndDir := lncfg.CleanAndExpandPath(ctx.GlobalString("lnddir"))

	// If the macaroon path as been manually provided, then we'll only
	// target the specified file.
	var macPath string
	if ctx.GlobalString("macaroonpath") != "" {
		macPath = lncfg.CleanAndExpandPath(ctx.GlobalString("macaroonpath"))
	} else {
		// Otherwise, we'll go into the path:
		// lnddir/data/chain/<chain>/<network> in order to fetch the
		// macaroon that we need.
		macPath = filepath.Join(
			lndDir, defaultDataDir, defaultChainSubDir, chain,
			network, defaultMacaroonFilename,
		)
	}

	tlsCertPath := lncfg.CleanAndExpandPath(ctx.GlobalString("tlscertpath"))

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

// checkNotBothSet accepts two flag names, a and b, and checks that only flag a
// or flag b can be set, but not both. It returns the name of the flag or an
// error.
func checkNotBothSet(ctx *cli.Context, a, b string) (string, error) {
	if ctx.IsSet(a) && ctx.IsSet(b) {
		return "", fmt.Errorf(
			"either %s or %s should be set, but not both", a, b,
		)
	}

	if ctx.IsSet(a) {
		return a, nil
	}

	return b, nil
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
			Usage: "The host:port of LN daemon.",
		},
		cli.StringFlag{
			Name:  "lnddir",
			Value: defaultLndDir,
			Usage: "The path to lnd's base directory.",
		},
		cli.StringFlag{
			Name:  "tlscertpath",
			Value: defaultTLSCertPath,
			Usage: "The path to lnd's TLS certificate.",
		},
		cli.StringFlag{
			Name:  "chain, c",
			Usage: "The chain lnd is running on, e.g. bitcoin.",
			Value: "bitcoin",
		},
		cli.StringFlag{
			Name: "network, n",
			Usage: "The network lnd is running on, e.g. mainnet, " +
				"testnet, etc.",
			Value: "mainnet",
		},
		cli.BoolFlag{
			Name:  "no-macaroons",
			Usage: "Disable macaroon authentication.",
		},
		cli.StringFlag{
			Name:  "macaroonpath",
			Usage: "The path to macaroon file.",
		},
		cli.Int64Flag{
			Name:  "macaroontimeout",
			Value: 60,
			Usage: "Anti-replay macaroon validity time in seconds.",
		},
		cli.StringFlag{
			Name:  "macaroonip",
			Usage: "If set, lock macaroon to specific IP address.",
		},
		cli.StringFlag{
			Name: "profile, p",
			Usage: "Instead of reading settings from command " +
				"line parameters or using the default " +
				"profile, use a specific profile. If " +
				"a default profile is set, this flag can be " +
				"set to an empty string to disable reading " +
				"values from the profiles file.",
		},
		cli.StringFlag{
			Name: "macfromjar",
			Usage: "Use this macaroon from the profile's " +
				"macaroon jar instead of the default one. " +
				"Can only be used if profiles are defined.",
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
		getRecoveryInfoCommand,
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
		listMacaroonIDsCommand,
		deleteMacaroonIDCommand,
		listPermissionsCommand,
		printMacaroonCommand,
		trackPaymentCommand,
		versionCommand,
		profileSubCommand,
		getStateCommand,
		sendCustomCommand,
		subscribeCustomCommand,
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

// readPassword reads a password from the terminal. This requires there to be an
// actual TTY so passing in a password from stdin won't work.
func readPassword(text string) ([]byte, error) {
	fmt.Print(text)

	// The variable syscall.Stdin is of a different type in the Windows API
	// that's why we need the explicit cast. And of course the linter
	// doesn't like it either.
	pw, err := terminal.ReadPassword(int(syscall.Stdin)) // nolint:unconvert
	fmt.Println()
	return pw, err
}
