package lnrpc

import (
	"encoding/hex"
	"errors"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/lnwallet"
)

const (
	// RegisterRPCMiddlewareURI is the full RPC method URI for the
	// middleware registration call. This is declared here rather than where
	// it's mainly used to avoid circular package dependencies.
	RegisterRPCMiddlewareURI = "/lnrpc.Lightning/RegisterRPCMiddleware"
)

// RPCTransactionDetails returns a set of rpc transaction details.
func RPCTransactionDetails(txns []*lnwallet.TransactionDetail) *TransactionDetails {
	txDetails := &TransactionDetails{
		Transactions: make([]*Transaction, len(txns)),
	}

	for i, tx := range txns {
		var destAddresses []string
		for _, destAddress := range tx.DestAddresses {
			destAddresses = append(destAddresses, destAddress.EncodeAddress())
		}

		// We also get unconfirmed transactions, so BlockHash can be
		// nil.
		blockHash := ""
		if tx.BlockHash != nil {
			blockHash = tx.BlockHash.String()
		}

		txDetails.Transactions[i] = &Transaction{
			TxHash:           tx.Hash.String(),
			Amount:           int64(tx.Value),
			NumConfirmations: tx.NumConfirmations,
			BlockHash:        blockHash,
			BlockHeight:      tx.BlockHeight,
			TimeStamp:        tx.Timestamp,
			TotalFees:        tx.TotalFees,
			DestAddresses:    destAddresses,
			RawTxHex:         hex.EncodeToString(tx.RawTx),
			Label:            tx.Label,
		}
	}

	// Sort transactions by number of confirmations rather than height so
	// that unconfirmed transactions (height =0; confirmations =-1) will
	// follow the most recently set of confirmed transactions. If we sort
	// by height, unconfirmed transactions will follow our oldest
	// transactions, because they have lower block heights.
	sort.Slice(txDetails.Transactions, func(i, j int) bool {
		return txDetails.Transactions[i].NumConfirmations <
			txDetails.Transactions[j].NumConfirmations
	})

	return txDetails
}

// ExtractMinConfs extracts the minimum number of confirmations that each
// output used to fund a transaction should satisfy.
func ExtractMinConfs(minConfs int32, spendUnconfirmed bool) (int32, error) {
	switch {
	// Ensure that the MinConfs parameter is non-negative.
	case minConfs < 0:
		return 0, errors.New("minimum number of confirmations must " +
			"be a non-negative number")

	// The transaction should not be funded with unconfirmed outputs
	// unless explicitly specified by SpendUnconfirmed. We do this to
	// provide sane defaults to the OpenChannel RPC, as otherwise, if the
	// MinConfs field isn't explicitly set by the caller, we'll use
	// unconfirmed outputs without the caller being aware.
	case minConfs == 0 && !spendUnconfirmed:
		return 1, nil

	// In the event that the caller set MinConfs > 0 and SpendUnconfirmed to
	// true, we'll return an error to indicate the conflict.
	case minConfs > 0 && spendUnconfirmed:
		return 0, errors.New("SpendUnconfirmed set to true with " +
			"MinConfs > 0")

	// The funding transaction of the new channel to be created can be
	// funded with unconfirmed outputs.
	case spendUnconfirmed:
		return 0, nil

	// If none of the above cases matched, we'll return the value set
	// explicitly by the caller.
	default:
		return minConfs, nil
	}
}

// GetChanPointFundingTxid returns the given channel point's funding txid in
// raw bytes.
func GetChanPointFundingTxid(chanPoint *ChannelPoint) (*chainhash.Hash, error) {
	var txid []byte

	// A channel point's funding txid can be get/set as a byte slice or a
	// string. In the case it is a string, decode it.
	switch chanPoint.GetFundingTxid().(type) {
	case *ChannelPoint_FundingTxidBytes:
		txid = chanPoint.GetFundingTxidBytes()
	case *ChannelPoint_FundingTxidStr:
		s := chanPoint.GetFundingTxidStr()
		h, err := chainhash.NewHashFromStr(s)
		if err != nil {
			return nil, err
		}

		txid = h[:]
	}

	return chainhash.NewHash(txid)
}
