package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/urfave/cli"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"
)

var bakeMacaroonCommand = cli.Command{
	Name:     "bakemacaroon",
	Category: "Macaroons",
	Usage: "Bakes a new macaroon with the provided list of permissions " +
		"and restrictions.",
	ArgsUsage: "[--save_to=] [--timeout=] [--ip_address=] [--allow_external_permissions] permissions...",
	Description: `
	Bake a new macaroon that grants the provided permissions and
	optionally adds restrictions (timeout, IP address) to it.

	The new macaroon can either be shown on command line in hex serialized
	format or it can be saved directly to a file using the --save_to
	argument.

	A permission is a tuple of an entity and an action, separated by a
	colon. Multiple operations can be added as arguments, for example:

	lncli bakemacaroon info:read invoices:write foo:bar

	For even more fine-grained permission control, it is also possible to
	specify single RPC method URIs that are allowed to be accessed by a
	macaroon. This can be achieved by specifying "uri:<methodURI>" pairs,
	for example:

	lncli bakemacaroon uri:/lnrpc.Lightning/GetInfo uri:/verrpc.Versioner/GetVersion

	The macaroon created by this command would only be allowed to use the
	"lncli getinfo" and "lncli version" commands.

	To get a list of all available URIs and permissions, use the
	"lncli listpermissions" command.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "save_to",
			Usage: "save the created macaroon to this file " +
				"using the default binary format",
		},
		cli.Uint64Flag{
			Name: "timeout",
			Usage: "the number of seconds the macaroon will be " +
				"valid before it times out",
		},
		cli.StringFlag{
			Name:  "ip_address",
			Usage: "the IP address the macaroon will be bound to",
		},
		cli.Uint64Flag{
			Name:  "root_key_id",
			Usage: "the numerical root key ID used to create the macaroon",
		},
		cli.BoolFlag{
			Name:  "allow_external_permissions",
			Usage: "whether permissions lnd is not familiar with are allowed",
		},
	},
	Action: actionDecorator(bakeMacaroon),
}

func bakeMacaroon(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	// Show command help if no arguments.
	if ctx.NArg() == 0 {
		return cli.ShowCommandHelp(ctx, "bakemacaroon")
	}
	args := ctx.Args()

	var (
		savePath          string
		timeout           int64
		ipAddress         net.IP
		rootKeyID         uint64
		parsedPermissions []*lnrpc.MacaroonPermission
		err               error
	)

	if ctx.String("save_to") != "" {
		savePath = lncfg.CleanAndExpandPath(ctx.String("save_to"))
	}

	if ctx.IsSet("timeout") {
		timeout = ctx.Int64("timeout")
		if timeout <= 0 {
			return fmt.Errorf("timeout must be greater than 0")
		}
	}

	if ctx.IsSet("ip_address") {
		ipAddress = net.ParseIP(ctx.String("ip_address"))
		if ipAddress == nil {
			return fmt.Errorf("unable to parse ip_address: %s",
				ctx.String("ip_address"))
		}
	}

	if ctx.IsSet("root_key_id") {
		rootKeyID = ctx.Uint64("root_key_id")
	}

	// A command line argument can't be an empty string. So we'll check each
	// entry if it's a valid entity:action tuple. The content itself is
	// validated server side. We just make sure we can parse it correctly.
	for _, permission := range args {
		tuple := strings.Split(permission, ":")
		if len(tuple) != 2 {
			return fmt.Errorf("unable to parse "+
				"permission tuple: %s", permission)
		}
		entity, action := tuple[0], tuple[1]
		if entity == "" {
			return fmt.Errorf("invalid permission [%s]. entity "+
				"cannot be empty", permission)
		}
		if action == "" {
			return fmt.Errorf("invalid permission [%s]. action "+
				"cannot be empty", permission)
		}

		// No we can assume that we have a formally valid entity:action
		// tuple. The rest of the validation happens server side.
		parsedPermissions = append(
			parsedPermissions, &lnrpc.MacaroonPermission{
				Entity: entity,
				Action: action,
			},
		)
	}

	// Now we have gathered all the input we need and can do the actual
	// RPC call.
	req := &lnrpc.BakeMacaroonRequest{
		Permissions:              parsedPermissions,
		RootKeyId:                rootKeyID,
		AllowExternalPermissions: ctx.Bool("allow_external_permissions"),
	}
	resp, err := client.BakeMacaroon(ctxc, req)
	if err != nil {
		return err
	}

	// Now we should have gotten a valid macaroon. Unmarshal it so we can
	// add first-party caveats (if necessary) to it.
	macBytes, err := hex.DecodeString(resp.Macaroon)
	if err != nil {
		return err
	}
	unmarshalMac := &macaroon.Macaroon{}
	if err = unmarshalMac.UnmarshalBinary(macBytes); err != nil {
		return err
	}

	// Now apply the desired constraints to the macaroon. This will always
	// create a new macaroon object, even if no constraints are added.
	macConstraints := make([]macaroons.Constraint, 0)
	if timeout > 0 {
		macConstraints = append(
			macConstraints, macaroons.TimeoutConstraint(timeout),
		)
	}
	if ipAddress != nil {
		macConstraints = append(
			macConstraints,
			macaroons.IPLockConstraint(ipAddress.String()),
		)
	}
	constrainedMac, err := macaroons.AddConstraints(
		unmarshalMac, macConstraints...,
	)
	if err != nil {
		return err
	}
	macBytes, err = constrainedMac.MarshalBinary()
	if err != nil {
		return err
	}

	// Now we can output the result. We either write it binary serialized to
	// a file or write to the standard output using hex encoding.
	switch {
	case savePath != "":
		err = ioutil.WriteFile(savePath, macBytes, 0644)
		if err != nil {
			return err
		}
		fmt.Printf("Macaroon saved to %s\n", savePath)

	default:
		fmt.Printf("%s\n", hex.EncodeToString(macBytes))
	}

	return nil
}

var listMacaroonIDsCommand = cli.Command{
	Name:     "listmacaroonids",
	Category: "Macaroons",
	Usage:    "List all macaroons root key IDs in use.",
	Action:   actionDecorator(listMacaroonIDs),
}

func listMacaroonIDs(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	req := &lnrpc.ListMacaroonIDsRequest{}
	resp, err := client.ListMacaroonIDs(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var deleteMacaroonIDCommand = cli.Command{
	Name:      "deletemacaroonid",
	Category:  "Macaroons",
	Usage:     "Delete a specific macaroon ID.",
	ArgsUsage: "root_key_id",
	Description: `
	Remove a macaroon ID using the specified root key ID. For example:

	lncli deletemacaroonid 1

	WARNING
	When the ID is deleted, all macaroons created from that root key will
	be invalidated.

	Note that the default root key ID 0 cannot be deleted.
	`,
	Action: actionDecorator(deleteMacaroonID),
}

func deleteMacaroonID(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	// Validate args length. Only one argument is allowed.
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "deletemacaroonid")
	}

	rootKeyIDString := ctx.Args().First()

	// Convert string into uint64.
	rootKeyID, err := strconv.ParseUint(rootKeyIDString, 10, 64)
	if err != nil {
		return fmt.Errorf("root key ID must be a positive integer")
	}

	// Check that the value is not equal to DefaultRootKeyID. Note that the
	// server also validates the root key ID when removing it. However, we check
	// it here too so that we can give users a nice warning.
	if bytes.Equal([]byte(rootKeyIDString), macaroons.DefaultRootKeyID) {
		return fmt.Errorf("deleting the default root key ID 0 is not allowed")
	}

	// Make the actual RPC call.
	req := &lnrpc.DeleteMacaroonIDRequest{
		RootKeyId: rootKeyID,
	}
	resp, err := client.DeleteMacaroonID(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var listPermissionsCommand = cli.Command{
	Name:     "listpermissions",
	Category: "Macaroons",
	Usage: "Lists all RPC method URIs and the macaroon permissions they " +
		"require to be invoked.",
	Action: actionDecorator(listPermissions),
}

func listPermissions(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	request := &lnrpc.ListPermissionsRequest{}
	response, err := client.ListPermissions(ctxc, request)
	if err != nil {
		return err
	}

	printRespJSON(response)

	return nil
}

type macaroonContent struct {
	Version     uint16   `json:"version"`
	Location    string   `json:"location"`
	RootKeyID   string   `json:"root_key_id"`
	Permissions []string `json:"permissions"`
	Caveats     []string `json:"caveats"`
}

var printMacaroonCommand = cli.Command{
	Name:      "printmacaroon",
	Category:  "Macaroons",
	Usage:     "Print the content of a macaroon in a human readable format.",
	ArgsUsage: "[macaroon_content_hex]",
	Description: `
	Decode a macaroon and show its content in a more human readable format.
	The macaroon can either be passed as a hex encoded positional parameter
	or loaded from a file.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "macaroon_file",
			Usage: "load the macaroon from a file instead of the " +
				"command line directly",
		},
	},
	Action: actionDecorator(printMacaroon),
}

func printMacaroon(ctx *cli.Context) error {
	// Show command help if no arguments or flags are set.
	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		return cli.ShowCommandHelp(ctx, "printmacaroon")
	}

	var (
		macBytes []byte
		err      error
		args     = ctx.Args()
	)
	switch {
	case ctx.IsSet("macaroon_file"):
		macPath := lncfg.CleanAndExpandPath(ctx.String("macaroon_file"))

		// Load the specified macaroon file.
		macBytes, err = ioutil.ReadFile(macPath)
		if err != nil {
			return fmt.Errorf("unable to read macaroon path %v: %v",
				macPath, err)
		}

	case args.Present():
		macBytes, err = hex.DecodeString(args.First())
		if err != nil {
			return fmt.Errorf("unable to hex decode macaroon: %v",
				err)
		}

	default:
		return fmt.Errorf("macaroon parameter missing")
	}

	// Decode the macaroon and its protobuf encoded internal identifier.
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return fmt.Errorf("unable to decode macaroon: %v", err)
	}
	rawID := mac.Id()
	if rawID[0] != byte(bakery.LatestVersion) {
		return fmt.Errorf("invalid macaroon version: %x", rawID)
	}
	decodedID := &lnrpc.MacaroonId{}
	idProto := rawID[1:]
	err = proto.Unmarshal(idProto, decodedID)
	if err != nil {
		return fmt.Errorf("unable to decode macaroon version: %v", err)
	}

	// Prepare everything to be printed in a more human readable format.
	content := &macaroonContent{
		Version:     uint16(mac.Version()),
		Location:    mac.Location(),
		RootKeyID:   string(decodedID.StorageId),
		Permissions: nil,
		Caveats:     nil,
	}

	for _, caveat := range mac.Caveats() {
		content.Caveats = append(content.Caveats, string(caveat.Id))
	}
	for _, op := range decodedID.Ops {
		for _, action := range op.Actions {
			permission := fmt.Sprintf("%s:%s", op.Entity, action)
			content.Permissions = append(
				content.Permissions, permission,
			)
		}
	}

	printJSON(content)

	return nil
}
