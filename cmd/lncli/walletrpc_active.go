// +build walletrpc

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
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
				releaseOutputCommand,
				psbtCommand,
				listWalletAddrsCmd,
			},
		},
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
	ctxb := context.Background()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	req := &walletrpc.PendingSweepsRequest{}
	resp, err := client.PendingSweeps(ctxb, req)
	if err != nil {
		return err
	}

	// Sort them in ascending fee rate order for display purposes.
	sort.Slice(resp.PendingSweeps, func(i, j int) bool {
		return resp.PendingSweeps[i].SatPerByte <
			resp.PendingSweeps[j].SatPerByte
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
	sat_per_byte parameters.

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
			Name: "sat_per_byte",
			Usage: "a manual fee expressed in sat/byte that " +
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
	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "bumpfee")
	}

	// Validate and parse the relevant arguments/flags.
	protoOutPoint, err := NewProtoOutPoint(ctx.Args().Get(0))
	if err != nil {
		return err
	}

	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.BumpFee(context.Background(), &walletrpc.BumpFeeRequest{
		Outpoint:   protoOutPoint,
		TargetConf: uint32(ctx.Uint64("conf_target")),
		SatPerByte: uint32(ctx.Uint64("sat_per_byte")),
		Force:      ctx.Bool("force"),
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
			Name: "sat_per_byte",
			Usage: "a manual fee expressed in sat/byte that " +
				"should be used when sweeping the output",
		},
	},
	Action: actionDecorator(bumpCloseFee),
}

func bumpCloseFee(ctx *cli.Context) error {
	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "bumpclosefee")
	}

	// Validate the channel point.
	channelPoint := ctx.Args().Get(0)
	_, err := NewProtoOutPoint(channelPoint)
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

	ctxb := context.Background()
	sweeps, err := walletClient.PendingSweeps(
		ctxb, &walletrpc.PendingSweepsRequest{},
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

		_, err = walletClient.BumpFee(ctxb, &walletrpc.BumpFeeRequest{
			Outpoint:   sweep.Outpoint,
			TargetConf: uint32(ctx.Uint64("conf_target")),
			SatPerByte: uint32(ctx.Uint64("sat_per_byte")),
			Force:      true,
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

	ctxb := context.Background()

	req := &lnrpc.PendingChannelsRequest{}
	resp, err := client.PendingChannels(ctxb, req)
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
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.ListSweeps(
		context.Background(), &walletrpc.ListSweepsRequest{
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
	Usage:     "adds a label to a transaction",
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

	ctxb := context.Background()
	_, err = walletClient.LabelTransaction(
		ctxb, &walletrpc.LabelTransactionRequest{
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
	},
	Action: actionDecorator(fundPsbt),
}

func fundPsbt(ctx *cli.Context) error {
	// Display the command's help message if there aren't any flags
	// specified.
	if ctx.NumFlags() == 0 {
		return cli.ShowCommandHelp(ctx, "fund")
	}

	req := &walletrpc.FundPsbtRequest{}

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

	case ctx.Uint64("conf_target") > 0:
		req.Fees = &walletrpc.FundPsbtRequest_TargetConf{
			TargetConf: uint32(ctx.Uint64("conf_target")),
		}

	case ctx.Uint64("sat_per_vbyte") > 0:
		req.Fees = &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: uint32(ctx.Uint64("sat_per_vbyte")),
		}
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	response, err := walletClient.FundPsbt(context.Background(), req)
	if err != nil {
		return err
	}

	jsonLocks := make([]*utxoLease, len(response.LockedUtxos))
	for idx, lock := range response.LockedUtxos {
		jsonLocks[idx] = &utxoLease{
			ID:         hex.EncodeToString(lock.Id),
			OutPoint:   NewOutPointFromProto(lock.Outpoint),
			Expiration: lock.Expiration,
		}
	}

	printJSON(&fundPsbtResponse{
		Psbt: base64.StdEncoding.EncodeToString(
			response.FundedPsbt,
		),
		ChangeOutputIndex: response.ChangeOutputIndex,
		Locks:             jsonLocks,
	})

	return nil
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
	},
	Action: actionDecorator(finalizePsbt),
}

func finalizePsbt(ctx *cli.Context) error {
	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg() != 1 && ctx.NumFlags() != 1 {
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
	}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	response, err := walletClient.FinalizePsbt(context.Background(), req)
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

	response, err := walletClient.ReleaseOutput(context.Background(), req)
	if err != nil {
		return err
	}

	printRespJSON(response)

	return nil
}

var listWalletAddrsCmd = cli.Command{
	Name:  "listaddresses",
	Usage: "Lists all addresses known to the wallet.",
	Description: `
	The listaddresses command returns all Pay-To-Witness-PubkeyHash
	addresses known to be in use/have been used by the underlying wallet.
	`,
	Action: actionDecorator(listWalletAddrs),
}

func listWalletAddrs(ctx *cli.Context) error {
	req := &walletrpc.AddrRequest{}

	walletClient, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	response, err := walletClient.ListWalletAddresses(context.Background(), req)
	if err != nil {
		return err
	}

	printRespJSON(response)

	return nil
}
