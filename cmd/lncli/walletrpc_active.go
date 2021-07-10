// +build walletrpc

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/urfave/cli"
)

var (
	// psbtCommand is a wallet subcommand that is responsible for PSBT
	// operations.
	psbtCommand = cli.Command{
		Name: "psbt",
		Usage: "Interact with partially signed bitcoin transactions " +
			"(PSBTs).",
		Subcommands: []cli.Command{
			fundPsbtCommand,
			finalizePsbtCommand,
		},
	}

	// accountsCommand is a wallet subcommand that is responsible for
	// account management operations.
	accountsCommand = cli.Command{
		Name:  "accounts",
		Usage: "Interact with wallet accounts.",
		Subcommands: []cli.Command{
			listAccountsCommand,
			importAccountCommand,
			importPubKeyCommand,
		},
	}
)

// walletCommands will return the set of commands to enable for walletrpc
// builds.
func walletCommands() []cli.Command {
	return []cli.Command{
		{
			Name:        "wallet",
			Category:    "Wallet",
			Usage:       "Interact with the wallet.",
			Description: "",
			Subcommands: []cli.Command{
				pendingSweepsCommand,
				bumpFeeCommand,
				bumpCloseFeeCommand,
				listSweepsCommand,
				labelTxCommand,
				publishTxCommand,
				releaseOutputCommand,
				listLeasesCommand,
				psbtCommand,
				accountsCommand,
			},
		},
	}
}

func parseAddrType(addrTypeStr string) (walletrpc.AddressType, error) {
	switch addrTypeStr {
	case "":
		return walletrpc.AddressType_UNKNOWN, nil
	case "p2wkh":
		return walletrpc.AddressType_WITNESS_PUBKEY_HASH, nil
	case "np2wkh":
		return walletrpc.AddressType_NESTED_WITNESS_PUBKEY_HASH, nil
	case "np2wkh-p2wkh":
		return walletrpc.AddressType_HYBRID_NESTED_WITNESS_PUBKEY_HASH, nil
	default:
		return 0, errors.New("invalid address type, supported address " +
			"types are: p2wkh, np2wkh, and np2wkh-p2wkh")
	}
}

func getWalletClient(ctx *cli.Context) (walletrpc.WalletKitClient, func()) {
	conn := getClientConn(ctx, false)
	cleanUp := func() {
		conn.Close()
	}
	return walletrpc.NewWalletKitClient(conn), cleanUp
}

var pendingSweepsCommand = cli.Command{
	Name:      "pendingsweeps",
	Usage:     "List all outputs that are pending to be swept within lnd.",
	ArgsUsage: "",
	Description: `
	List all on-chain outputs that lnd is currently attempting to sweep
	within its central batching engine. Outputs with similar fee rates are
	batched together in order to sweep them within a single transaction.
	`,
	Flags:  []cli.Flag{},
	Action: actionDecorator(pendingSweeps),
}

func pendingSweeps(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	req := &walletrpc.PendingSweepsRequest{}
	resp, err := client.PendingSweeps(ctxc, req)
	if err != nil {
		return err
	}

	// Sort them in ascending fee rate order for display purposes.
	sort.Slice(resp.PendingSweeps, func(i, j int) bool {
		return resp.PendingSweeps[i].SatPerVbyte <
			resp.PendingSweeps[j].SatPerVbyte
	})

	var pendingSweepsResp = struct {
		PendingSweeps []*PendingSweep `json:"pending_sweeps"`
	}{
		PendingSweeps: make([]*PendingSweep, 0, len(resp.PendingSweeps)),
	}

	for _, protoPendingSweep := range resp.PendingSweeps {
		pendingSweep := NewPendingSweepFromProto(protoPendingSweep)
		pendingSweepsResp.PendingSweeps = append(
			pendingSweepsResp.PendingSweeps, pendingSweep,
		)
	}

	printJSON(pendingSweepsResp)

	return nil
}

var bumpFeeCommand = cli.Command{
	Name:      "bumpfee",
	Usage:     "Bumps the fee of an arbitrary input/transaction.",
	ArgsUsage: "outpoint",
	Description: `
	This command takes a different approach than bitcoind's bumpfee command.
	lnd has a central batching engine in which inputs with similar fee rates
	are batched together to save on transaction fees. Due to this, we cannot
	rely on bumping the fee on a specific transaction, since transactions
	can change at any point with the addition of new inputs. The list of
	inputs that currently exist within lnd's central batching engine can be
	retrieved through lncli pendingsweeps.

	When bumping the fee of an input that currently exists within lnd's
	central batching engine, a higher fee transaction will be created that
	replaces the lower fee transaction through the Replace-By-Fee (RBF)
	policy.

	This command also serves useful when wanting to perform a
	Child-Pays-For-Parent (CPFP), where the child transaction pays for its
	parent's fee. This can be done by specifying an outpoint within the low
	fee transaction that is under the control of the wallet.

	A fee preference must be provided, either through the conf_target or
	sat_per_vbyte parameters.

	Note that this command currently doesn't perform any validation checks
	on the fee preference being provided. For now, the responsibility of
	ensuring that the new fee preference is sufficient is delegated to the
	user.

	The force flag enables sweeping of inputs that are negatively yielding.
	Normally it does not make sense to lose money on sweeping, unless a
	parent transaction needs to get confirmed and there is only a small
	output available to attach the child transaction to.
	`,
	Flags: []cli.Flag{
		cli.Uint64Flag{
			Name: "conf_target",
			Usage: "the number of blocks that the output should " +
				"be swept on-chain within",
		},
		cli.Uint64Flag{
			Name:   "sat_per_byte",
			Usage:  "Deprecated, use sat_per_vbyte instead.",
			Hidden: true,
		},
		cli.Uint64Flag{
			Name: "sat_per_vbyte",
			Usage: "a manual fee expressed in sat/vbyte that " +
				"should be used when sweeping the output",
		},
		cli.BoolFlag{
			Name:  "force",
			Usage: "sweep even if the yield is negative",
		},
	},
	Action: actionDecorator(bumpFee),
}

func bumpFee(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "bumpfee")
	}

	// Check that only the field sat_per_vbyte or the deprecated field
	// sat_per_byte is used.
	feeRateFlag, err := checkNotBothSet(
		ctx, "sat_per_vbyte", "sat_per_byte",
	)
	if err != nil {
		return err
	}

	// Validate and parse the relevant arguments/flags.
	protoOutPoint, err := NewProtoOutPoint(ctx.Args().Get(0))
	if err != nil {
		return err
	}

	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.BumpFee(ctxc, &walletrpc.BumpFeeRequest{
		Outpoint:    protoOutPoint,
		TargetConf:  uint32(ctx.Uint64("conf_target")),
		SatPerVbyte: ctx.Uint64(feeRateFlag),
		Force:       ctx.Bool("force"),
	})
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

var bumpCloseFeeCommand = cli.Command{
	Name:      "bumpclosefee",
	Usage:     "Bumps the fee of a channel closing transaction.",
	ArgsUsage: "channel_point",
	Description: `
	This command allows the fee of a channel closing transaction to be
	increased by using the child-pays-for-parent mechanism. It will instruct
	the sweeper to sweep the anchor outputs of transactions in the set
	of valid commitments for the specified channel at the requested fee
	rate or confirmation target.
	`,
	Flags: []cli.Flag{
		cli.Uint64Flag{
			Name: "conf_target",
			Usage: "the number of blocks that the output should " +
				"be swept on-chain within",
		},
		cli.Uint64Flag{
			Name:   "sat_per_byte",
			Usage:  "Deprecated, use sat_per_vbyte instead.",
			Hidden: true,
		},
		cli.Uint64Flag{
			Name: "sat_per_vbyte",
			Usage: "a manual fee expressed in sat/vbyte that " +
				"should be used when sweeping the output",
		},
	},
	Action: actionDecorator(bumpCloseFee),
}

func bumpCloseFee(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "bumpclosefee")
	}

	// Check that only the field sat_per_vbyte or the deprecated field
	// sat_per_byte is used.
	feeRateFlag, err := checkNotBothSet(
		ctx, "sat_per_vbyte", "sat_per_byte",
	)
	if err != nil {
		return err
	}

	// Validate the channel point.
	channelPoint := ctx.Args().Get(0)
	_, err = NewProtoOutPoint(channelPoint)
	if err != nil {
		return err
	}

	// Fetch all waiting close channels.
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	// Fetch waiting close channel commitments.
	commitments, err := getWaitingCloseCommitments(client, channelPoint)
	if err != nil {
		return err
	}

	// Retrieve pending sweeps.
	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	sweeps, err := walletClient.PendingSweeps(
		ctxc, &walletrpc.PendingSweepsRequest{},
	)
	if err != nil {
		return err
	}

	// Match pending sweeps with commitments of the channel for which a bump
	// is requested and bump their fees.
	commitSet := map[string]struct{}{
		commitments.LocalTxid:  {},
		commitments.RemoteTxid: {},
	}
	if commitments.RemotePendingTxid != "" {
		commitSet[commitments.RemotePendingTxid] = struct{}{}
	}

	for _, sweep := range sweeps.PendingSweeps {
		// Only bump anchor sweeps.
		if sweep.WitnessType != walletrpc.WitnessType_COMMITMENT_ANCHOR {
			continue
		}

		// Skip unrelated sweeps.
		sweepTxID, err := chainhash.NewHash(sweep.Outpoint.TxidBytes)
		if err != nil {
			return err
		}
		if _, match := commitSet[sweepTxID.String()]; !match {
			continue
		}

		// Bump fee of the anchor sweep.
		fmt.Printf("Bumping fee of %v:%v\n",
			sweepTxID, sweep.Outpoint.OutputIndex)

		_, err = walletClient.BumpFee(ctxc, &walletrpc.BumpFeeRequest{
			Outpoint:    sweep.Outpoint,
			TargetConf:  uint32(ctx.Uint64("conf_target")),
			SatPerVbyte: ctx.Uint64(feeRateFlag),
			Force:       true,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func getWaitingCloseCommitments(client lnrpc.LightningClient,
	channelPoint string) (*lnrpc.PendingChannelsResponse_Commitments,
	error) {

	ctxc := getContext()

	req := &lnrpc.PendingChannelsRequest{}
	resp, err := client.PendingChannels(ctxc, req)
	if err != nil {
		return nil, err
	}

	// Lookup the channel commit tx hashes.
	for _, channel := range resp.WaitingCloseChannels {
		if channel.Channel.ChannelPoint == channelPoint {
			return channel.Commitments, nil
		}
	}

	return nil, errors.New("channel not found")
}

var listSweepsCommand = cli.Command{
	Name:  "listsweeps",
	Usage: "Lists all sweeps that have been published by our node.",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "lookup full transaction",
		},
	},
	Description: `
	Get a list of the hex-encoded transaction ids of every sweep that our
	node has published. Note that these sweeps may not be confirmed on chain
	yet, as we store them on transaction broadcast, not confirmation.

	If the verbose flag is set, the full set of transactions will be 
	returned, otherwise only the sweep transaction ids will be returned. 
	`,
	Action: actionDecorator(listSweeps),
}

func listSweeps(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.ListSweeps(
		ctxc, &walletrpc.ListSweepsRequest{
			Verbose: ctx.IsSet("verbose"),
		},
	)
	if err != nil {
		return err
	}

	printJSON(resp)

	return nil
}

var labelTxCommand = cli.Command{
	Name:      "labeltx",
	Usage:     "Adds a label to a transaction.",
	ArgsUsage: "txid label",
	Description: `
	Add a label to a transaction. If the transaction already has a label, 
	this call will fail unless the overwrite option is set. The label is 
	limited to 500 characters. Note that multi word labels must be contained
	in quotation marks ("").
	`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "overwrite",
			Usage: "set to overwrite existing labels",
		},
	},
	Action: actionDecorator(labelTransaction),
}

func labelTransaction(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 2 {
		return cli.ShowCommandHelp(ctx, "labeltx")
	}

	// Get the transaction id and check that it is a valid hash.
	txid := ctx.Args().Get(0)
	hash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return err
	}

	label := ctx.Args().Get(1)

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	_, err = walletClient.LabelTransaction(
		ctxc, &walletrpc.LabelTransactionRequest{
			Txid:      hash[:],
			Label:     label,
			Overwrite: ctx.Bool("overwrite"),
		},
	)
	if err != nil {
		return err
	}

	fmt.Printf("Transaction: %v labelled with: %v\n", txid, label)

	return nil
}

var publishTxCommand = cli.Command{
	Name:      "publishtx",
	Usage:     "Attempts to publish the passed transaction to the network.",
	ArgsUsage: "tx_hex",
	Description: `
	Publish a hex-encoded raw transaction to the on-chain network. The 
	wallet will continually attempt to re-broadcast the transaction on start up, until it 
	enters the chain. The label parameter is optional and limited to 500 characters. Note 
	that multi word labels must be contained in quotation marks ("").
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "label",
			Usage: "(optional) transaction label",
		},
	},
	Action: actionDecorator(publishTransaction),
}

func publishTransaction(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 || ctx.NumFlags() > 1 {
		return cli.ShowCommandHelp(ctx, "publishtx")
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	tx, err := hex.DecodeString(ctx.Args().First())
	if err != nil {
		return err
	}

	// Deserialize the transaction to get the transaction hash.
	msgTx := &wire.MsgTx{}
	txReader := bytes.NewReader(tx)
	if err := msgTx.Deserialize(txReader); err != nil {
		return err
	}

	req := &walletrpc.Transaction{
		TxHex: tx,
		Label: ctx.String("label"),
	}

	_, err = walletClient.PublishTransaction(ctxc, req)
	if err != nil {
		return err
	}

	printJSON(&struct {
		TXID string `json:"txid"`
	}{
		TXID: msgTx.TxHash().String(),
	})

	return nil
}

// utxoLease contains JSON annotations for a lease on an unspent output.
type utxoLease struct {
	ID         string   `json:"id"`
	OutPoint   OutPoint `json:"outpoint"`
	Expiration uint64   `json:"expiration"`
}

// fundPsbtResponse is a struct that contains JSON annotations for nice result
// serialization.
type fundPsbtResponse struct {
	Psbt              string       `json:"psbt"`
	ChangeOutputIndex int32        `json:"change_output_index"`
	Locks             []*utxoLease `json:"locks"`
}

var fundPsbtCommand = cli.Command{
	Name:  "fund",
	Usage: "Fund a Partially Signed Bitcoin Transaction (PSBT).",
	ArgsUsage: "[--template_psbt=T | [--outputs=O [--inputs=I]]] " +
		"[--conf_target=C | --sat_per_vbyte=S]",
	Description: `
	The fund command creates a fully populated PSBT that contains enough
	inputs to fund the outputs specified in either the PSBT or the
	--outputs flag.

	If there are no inputs specified in the template (or --inputs flag),
	coin selection is performed automatically. If inputs are specified, the
	wallet assumes that full coin selection happened externally and it will
	not add any additional inputs to the PSBT. If the specified inputs
	aren't enough to fund the outputs with the given fee rate, an error is
	returned.

	After either selecting or verifying the inputs, all input UTXOs are
	locked with an internal app ID.

	The 'outputs' flag decodes addresses and the amount to send respectively
	in the following JSON format:

	    --outputs='{"ExampleAddr": NumCoinsInSatoshis, "SecondAddr": Sats}'

	The optional 'inputs' flag decodes a JSON list of UTXO outpoints as
	returned by the listunspent command for example:

	    --inputs='["<txid1>:<output-index1>","<txid2>:<output-index2>",...]'
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "template_psbt",
			Usage: "the outputs to fund and optional inputs to " +
				"spend provided in the base64 PSBT format",
		},
		cli.StringFlag{
			Name: "outputs",
			Usage: "a JSON compatible map of destination " +
				"addresses to amounts to send, must not " +
				"include a change address as that will be " +
				"added automatically by the wallet",
		},
		cli.StringFlag{
			Name: "inputs",
			Usage: "an optional JSON compatible list of UTXO " +
				"outpoints to use as the PSBT's inputs",
		},
		cli.Uint64Flag{
			Name: "conf_target",
			Usage: "the number of blocks that the transaction " +
				"should be confirmed on-chain within",
			Value: 6,
		},
		cli.Uint64Flag{
			Name: "sat_per_vbyte",
			Usage: "a manual fee expressed in sat/vbyte that " +
				"should be used when creating the transaction",
		},
		cli.StringFlag{
			Name: "account",
			Usage: "(optional) the name of the account to use to " +
				"create/fund the PSBT",
		},
	},
	Action: actionDecorator(fundPsbt),
}

func fundPsbt(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if there aren't any flags
	// specified.
	if ctx.NumFlags() == 0 {
		return cli.ShowCommandHelp(ctx, "fund")
	}

	req := &walletrpc.FundPsbtRequest{
		Account: ctx.String("account"),
	}

	// Parse template flags.
	switch {
	// The PSBT flag is mutally exclusive with the outputs/inputs flags.
	case ctx.IsSet("template_psbt") &&
		(ctx.IsSet("inputs") || ctx.IsSet("outputs")):

		return fmt.Errorf("cannot set template_psbt and inputs/" +
			"outputs flags at the same time")

	// Use a pre-existing PSBT as the transaction template.
	case len(ctx.String("template_psbt")) > 0:
		psbtBase64 := ctx.String("template_psbt")
		psbtBytes, err := base64.StdEncoding.DecodeString(psbtBase64)
		if err != nil {
			return err
		}

		req.Template = &walletrpc.FundPsbtRequest_Psbt{
			Psbt: psbtBytes,
		}

	// The user manually specified outputs and optional inputs in JSON
	// format.
	case len(ctx.String("outputs")) > 0:
		var (
			tpl          = &walletrpc.TxTemplate{}
			amountToAddr map[string]uint64
		)

		// Parse the address to amount map as JSON now. At least one
		// entry must be present.
		jsonMap := []byte(ctx.String("outputs"))
		if err := json.Unmarshal(jsonMap, &amountToAddr); err != nil {
			return fmt.Errorf("error parsing outputs JSON: %v",
				err)
		}
		if len(amountToAddr) == 0 {
			return fmt.Errorf("at least one output must be " +
				"specified")
		}
		tpl.Outputs = amountToAddr

		// Inputs are optional.
		if len(ctx.String("inputs")) > 0 {
			var inputs []string

			jsonList := []byte(ctx.String("inputs"))
			if err := json.Unmarshal(jsonList, &inputs); err != nil {
				return fmt.Errorf("error parsing inputs JSON: "+
					"%v", err)
			}

			for idx, input := range inputs {
				op, err := NewProtoOutPoint(input)
				if err != nil {
					return fmt.Errorf("error parsing "+
						"UTXO outpoint %d: %v", idx,
						err)
				}
				tpl.Inputs = append(tpl.Inputs, op)
			}
		}

		req.Template = &walletrpc.FundPsbtRequest_Raw{
			Raw: tpl,
		}

	default:
		return fmt.Errorf("must specify either template_psbt or " +
			"outputs flag")
	}

	// Parse fee flags.
	switch {
	case ctx.IsSet("conf_target") && ctx.IsSet("sat_per_vbyte"):
		return fmt.Errorf("cannot set conf_target and sat_per_vbyte " +
			"at the same time")

	case ctx.Uint64("sat_per_vbyte") > 0:
		req.Fees = &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: ctx.Uint64("sat_per_vbyte"),
		}

	// Check conf_target last because it has a default value.
	case ctx.Uint64("conf_target") > 0:
		req.Fees = &walletrpc.FundPsbtRequest_TargetConf{
			TargetConf: uint32(ctx.Uint64("conf_target")),
		}
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	response, err := walletClient.FundPsbt(ctxc, req)
	if err != nil {
		return err
	}

	jsonLocks := marshallLocks(response.LockedUtxos)

	printJSON(&fundPsbtResponse{
		Psbt: base64.StdEncoding.EncodeToString(
			response.FundedPsbt,
		),
		ChangeOutputIndex: response.ChangeOutputIndex,
		Locks:             jsonLocks,
	})

	return nil
}

// marshallLocks converts the rpc lease information to a more json-friendly
// format.
func marshallLocks(lockedUtxos []*walletrpc.UtxoLease) []*utxoLease {
	jsonLocks := make([]*utxoLease, len(lockedUtxos))
	for idx, lock := range lockedUtxos {
		jsonLocks[idx] = &utxoLease{
			ID:         hex.EncodeToString(lock.Id),
			OutPoint:   NewOutPointFromProto(lock.Outpoint),
			Expiration: lock.Expiration,
		}
	}

	return jsonLocks
}

// finalizePsbtResponse is a struct that contains JSON annotations for nice
// result serialization.
type finalizePsbtResponse struct {
	Psbt    string `json:"psbt"`
	FinalTx string `json:"final_tx"`
}

var finalizePsbtCommand = cli.Command{
	Name:      "finalize",
	Usage:     "Finalize a Partially Signed Bitcoin Transaction (PSBT).",
	ArgsUsage: "funded_psbt",
	Description: `
	The finalize command expects a partial transaction with all inputs
	and outputs fully declared and tries to sign all inputs that belong to
	the wallet. Lnd must be the last signer of the transaction. That means,
	if there are any unsigned non-witness inputs or inputs without UTXO
	information attached or inputs without witness data that do not belong
	to lnd's wallet, this method will fail. If no error is returned, the
	PSBT is ready to be extracted and the final TX within to be broadcast.

	This method does NOT publish the transaction after it's been finalized
	successfully.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "funded_psbt",
			Usage: "the base64 encoded PSBT to finalize",
		},
		cli.StringFlag{
			Name: "account",
			Usage: "(optional) the name of the account to " +
				"finalize the PSBT with",
		},
	},
	Action: actionDecorator(finalizePsbt),
}

func finalizePsbt(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() > 1 || ctx.NumFlags() > 2 {
		return cli.ShowCommandHelp(ctx, "finalize")
	}

	var (
		args       = ctx.Args()
		psbtBase64 string
	)
	switch {
	case ctx.IsSet("funded_psbt"):
		psbtBase64 = ctx.String("funded_psbt")
	case args.Present():
		psbtBase64 = args.First()
	default:
		return fmt.Errorf("funded_psbt argument missing")
	}

	psbtBytes, err := base64.StdEncoding.DecodeString(psbtBase64)
	if err != nil {
		return err
	}
	req := &walletrpc.FinalizePsbtRequest{
		FundedPsbt: psbtBytes,
		Account:    ctx.String("account"),
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	response, err := walletClient.FinalizePsbt(ctxc, req)
	if err != nil {
		return err
	}

	printJSON(&finalizePsbtResponse{
		Psbt:    base64.StdEncoding.EncodeToString(response.SignedPsbt),
		FinalTx: hex.EncodeToString(response.RawFinalTx),
	})

	return nil
}

var releaseOutputCommand = cli.Command{
	Name:      "releaseoutput",
	Usage:     "Release an output previously locked by lnd.",
	ArgsUsage: "outpoint",
	Description: `
	The releaseoutput command unlocks an output, allowing it to be available
	for coin selection if it remains unspent.

	The internal lnd app lock ID is used when releasing the output.
	Therefore only UTXOs locked by the fundpsbt command can currently be
	released with this command.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "outpoint",
			Usage: "the output to unlock",
		},
	},
	Action: actionDecorator(releaseOutput),
}

func releaseOutput(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 && ctx.NumFlags() != 1 {
		return cli.ShowCommandHelp(ctx, "releaseoutput")
	}

	var (
		args        = ctx.Args()
		outpointStr string
	)
	switch {
	case ctx.IsSet("outpoint"):
		outpointStr = ctx.String("outpoint")
	case args.Present():
		outpointStr = args.First()
	default:
		return fmt.Errorf("outpoint argument missing")
	}

	outpoint, err := NewProtoOutPoint(outpointStr)
	if err != nil {
		return fmt.Errorf("error parsing outpoint: %v", err)
	}
	req := &walletrpc.ReleaseOutputRequest{
		Outpoint: outpoint,
		Id:       walletrpc.LndInternalLockID[:],
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	response, err := walletClient.ReleaseOutput(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(response)

	return nil
}

var listLeasesCommand = cli.Command{
	Name:   "listleases",
	Usage:  "Return a list of currently held leases.",
	Action: actionDecorator(listLeases),
}

func listLeases(ctx *cli.Context) error {
	ctxc := getContext()

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	req := &walletrpc.ListLeasesRequest{}
	response, err := walletClient.ListLeases(ctxc, req)
	if err != nil {
		return err
	}

	printJSON(marshallLocks(response.LockedUtxos))
	return nil
}

var listAccountsCommand = cli.Command{
	Name:  "list",
	Usage: "Retrieve information of existing on-chain wallet accounts.",
	Description: `
	Retrieves all accounts belonging to the wallet by default. A name and
	key scope filter can be provided to filter through all of the wallet
	accounts and return only those matching.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "name",
			Usage: "(optional) only accounts matching this name " +
				"are returned",
		},
		cli.StringFlag{
			Name: "address_type",
			Usage: "(optional) only accounts matching this " +
				"address type are returned",
		},
	},
	Action: actionDecorator(listAccounts),
}

func listAccounts(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() > 0 || ctx.NumFlags() > 2 {
		return cli.ShowCommandHelp(ctx, "list")
	}

	addrType, err := parseAddrType(ctx.String("address_type"))
	if err != nil {
		return err
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	req := &walletrpc.ListAccountsRequest{
		Name:        ctx.String("name"),
		AddressType: addrType,
	}
	resp, err := walletClient.ListAccounts(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

var importAccountCommand = cli.Command{
	Name: "import",
	Usage: "Import an on-chain account into the wallet through its " +
		"extended public key.",
	ArgsUsage: "extended_public_key name",
	Description: `
	Imports an account backed by an account extended public key. The master
	key fingerprint denotes the fingerprint of the root key corresponding to
	the account public key (also known as the key with derivation path m/).
	This may be required by some hardware wallets for proper identification
	and signing.

	The address type can usually be inferred from the key's version, but may
	be required for certain keys to map them into the proper scope.

	For BIP-0044 keys, an address type must be specified as we intend to not
	support importing BIP-0044 keys into the wallet using the legacy
	pay-to-pubkey-hash (P2PKH) scheme. A nested witness address type will
	force the standard BIP-0049 derivation scheme, while a witness address
	type will force the standard BIP-0084 derivation scheme.

	For BIP-0049 keys, an address type must also be specified to make a
	distinction between the standard BIP-0049 address schema (nested witness
	pubkeys everywhere) and our own BIP-0049Plus address schema (nested
	pubkeys externally, witness pubkeys internally).

	NOTE: Events (deposits/spends) for keys derived from an account will
	only be detected by lnd if they happen after the import. Rescans to
	detect past events will be supported later on.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "address_type",
			Usage: "(optional) specify the type of addresses the " +
				"imported account should generate",
		},
		cli.StringFlag{
			Name: "master_key_fingerprint",
			Usage: "(optional) the fingerprint of the root key " +
				"(derivation path m/) corresponding to the " +
				"account public key",
		},
		cli.BoolFlag{
			Name:  "dry_run",
			Usage: "(optional) perform a dry run",
		},
	},
	Action: actionDecorator(importAccount),
}

func importAccount(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 2 || ctx.NumFlags() > 3 {
		return cli.ShowCommandHelp(ctx, "import")
	}

	addrType, err := parseAddrType(ctx.String("address_type"))
	if err != nil {
		return err
	}

	var mkfpBytes []byte
	if ctx.IsSet("master_key_fingerprint") {
		mkfpBytes, err = hex.DecodeString(
			ctx.String("master_key_fingerprint"),
		)
		if err != nil {
			return fmt.Errorf("invalid master key fingerprint: %v", err)
		}
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	dryRun := ctx.Bool("dry_run")
	req := &walletrpc.ImportAccountRequest{
		Name:                 ctx.Args().Get(1),
		ExtendedPublicKey:    ctx.Args().Get(0),
		MasterKeyFingerprint: mkfpBytes,
		AddressType:          addrType,
		DryRun:               dryRun,
	}
	resp, err := walletClient.ImportAccount(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var importPubKeyCommand = cli.Command{
	Name:      "import-pubkey",
	Usage:     "Import a public key as watch-only into the wallet.",
	ArgsUsage: "public_key address_type",
	Description: `
	Imports a public key represented in hex as watch-only into the wallet.
	The address type must be one of the following: np2wkh, p2wkh.

	NOTE: Events (deposits/spends) for a key will only be detected by lnd if
	they happen after the import. Rescans to detect past events will be
	supported later on.
	`,
	Action: actionDecorator(importPubKey),
}

func importPubKey(ctx *cli.Context) error {
	ctxc := getContext()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 2 || ctx.NumFlags() > 0 {
		return cli.ShowCommandHelp(ctx, "import-pubkey")
	}

	pubKeyBytes, err := hex.DecodeString(ctx.Args().Get(0))
	if err != nil {
		return err
	}
	addrType, err := parseAddrType(ctx.Args().Get(1))
	if err != nil {
		return err
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	req := &walletrpc.ImportPublicKeyRequest{
		PublicKey:   pubKeyBytes,
		AddressType: addrType,
	}
	resp, err := walletClient.ImportPublicKey(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}
