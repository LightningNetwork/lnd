package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/signal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultRPCPort   = "10009"
	defaultRPCServer = "localhost:" + defaultRPCPort
)

var (
	connectionRetryInterval = time.Second * 5
)

type waitReadyCommand struct {
	RPCServer string        `long:"rpcserver" description:"The host:port of lnd's RPC listener"`
	Timeout   time.Duration `long:"timeout" description:"The maximum time we'll wait for lnd to become ready; 0 means wait forever"`
}

func newWaitReadyCommand() *waitReadyCommand {
	return &waitReadyCommand{
		RPCServer: defaultRPCServer,
	}
}

func (x *waitReadyCommand) Register(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"wait-ready",
		"Wait for lnd to be fully ready",
		"Wait for lnd to be fully started, unlocked and ready to "+
			"serve RPC requests; will wait and block forever "+
			"until either lnd reports its status as ready or the "+
			"given timeout is reached; the RPC connection to lnd "+
			"is re-tried indefinitely and errors are ignored (or "+
			"logged in verbose mode) until success or timeout; "+
			"requires lnd v0.13.0-beta or later to work",
		x,
	)
	return err
}

func (x *waitReadyCommand) Execute(_ []string) error {
	// Since this will potentially run forever, make sure we catch any
	// interrupt signals.
	shutdown, err := signal.Intercept()
	if err != nil {
		return fmt.Errorf("error intercepting signals: %v", err)
	}

	log("Waiting for lnd to become ready")

	started := time.Now()
	timeout := time.Duration(math.MaxInt64)
	if x.Timeout > 0 {
		timeout = x.Timeout
		log("Will time out in %v (%s)", timeout, started.Add(timeout))
	}

	connectionRetryTicker := time.NewTicker(connectionRetryInterval)
	timeoutChan := time.After(timeout)

connectionLoop:
	for {
		conn, err := getStatusConnection(x.RPCServer)
		if err != nil {
			log("Connection to lnd not successful: %v", err)

			select {
			case <-connectionRetryTicker.C:
			case <-timeoutChan:
				return fmt.Errorf("timeout reached")
			case <-shutdown.ShutdownChannel():
				return nil
			}

			continue
		}

		statusStream, err := conn.SubscribeState(
			context.Background(), &lnrpc.SubscribeStateRequest{},
		)
		if err != nil {
			log("Status subscription for lnd not successful: %v",
				err)

			select {
			case <-connectionRetryTicker.C:
			case <-timeoutChan:
				return fmt.Errorf("timeout reached")
			case <-shutdown.ShutdownChannel():
				return nil
			}

			continue
		}

		for {
			// Have we reached the global timeout yet?
			select {
			case <-timeoutChan:
				return fmt.Errorf("timeout reached")
			case <-shutdown.ShutdownChannel():
				return nil
			default:
			}

			msg, err := statusStream.Recv()
			if err != nil {
				log("Error receiving status update: %v", err)

				select {
				case <-connectionRetryTicker.C:
				case <-timeoutChan:
					return fmt.Errorf("timeout reached")
				case <-shutdown.ShutdownChannel():
					return nil
				}

				// Something went wrong, perhaps lnd shut down
				// before becoming active. Let's retry the whole
				// connection again.
				continue connectionLoop
			}

			log("Received update from lnd, wallet status is now: "+
				"%v", msg.State.String())

			// We've arrived at the final state!
			if msg.State == lnrpc.WalletState_RPC_ACTIVE {
				return nil
			}

			// Let's wait for another another status message to
			// arrive.
		}
	}
}

func getStatusConnection(rpcServer string) (lnrpc.StateClient, error) {
	// Don't bother with checking the cert, we're not sending any macaroons
	// to the server anyway.
	creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})

	// We need to use a custom dialer so we can also connect to unix sockets
	// and not just TCP addresses.
	genericDialer := lncfg.ClientAddressDialer(defaultRPCPort)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(genericDialer),
	}

	conn, err := grpc.Dial(rpcServer, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC server: %v",
			err)
	}

	return lnrpc.NewStateClient(conn), nil
}
