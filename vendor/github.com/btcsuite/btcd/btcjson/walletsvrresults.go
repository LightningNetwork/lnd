// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

// GetTransactionDetailsResult models the details data from the gettransaction command.
//
// This models the "short" version of the ListTransactionsResult type, which
// excludes fields common to the transaction.  These common fields are instead
// part of the GetTransactionResult.
type GetTransactionDetailsResult struct {
	Account           string   `json:"account"`
	Address           string   `json:"address,omitempty"`
	Amount            float64  `json:"amount"`
	Category          string   `json:"category"`
	InvolvesWatchOnly bool     `json:"involveswatchonly,omitempty"`
	Fee               *float64 `json:"fee,omitempty"`
	Vout              uint32   `json:"vout"`
}

// GetTransactionResult models the data from the gettransaction command.
type GetTransactionResult struct {
	Amount          float64                       `json:"amount"`
	Fee             float64                       `json:"fee,omitempty"`
	Confirmations   int64                         `json:"confirmations"`
	BlockHash       string                        `json:"blockhash"`
	BlockIndex      int64                         `json:"blockindex"`
	BlockTime       int64                         `json:"blocktime"`
	TxID            string                        `json:"txid"`
	WalletConflicts []string                      `json:"walletconflicts"`
	Time            int64                         `json:"time"`
	TimeReceived    int64                         `json:"timereceived"`
	Details         []GetTransactionDetailsResult `json:"details"`
	Hex             string                        `json:"hex"`
}

// InfoWalletResult models the data returned by the wallet server getinfo
// command.
type InfoWalletResult struct {
	Version         int32   `json:"version"`
	ProtocolVersion int32   `json:"protocolversion"`
	WalletVersion   int32   `json:"walletversion"`
	Balance         float64 `json:"balance"`
	Blocks          int32   `json:"blocks"`
	TimeOffset      int64   `json:"timeoffset"`
	Connections     int32   `json:"connections"`
	Proxy           string  `json:"proxy"`
	Difficulty      float64 `json:"difficulty"`
	TestNet         bool    `json:"testnet"`
	KeypoolOldest   int64   `json:"keypoololdest"`
	KeypoolSize     int32   `json:"keypoolsize"`
	UnlockedUntil   int64   `json:"unlocked_until"`
	PaytxFee        float64 `json:"paytxfee"`
	RelayFee        float64 `json:"relayfee"`
	Errors          string  `json:"errors"`
}

// ListTransactionsResult models the data from the listtransactions command.
type ListTransactionsResult struct {
	Abandoned         bool     `json:"abandoned"`
	Account           string   `json:"account"`
	Address           string   `json:"address,omitempty"`
	Amount            float64  `json:"amount"`
	BIP125Replaceable string   `json:"bip125-replaceable,omitempty"`
	BlockHash         string   `json:"blockhash,omitempty"`
	BlockIndex        *int64   `json:"blockindex,omitempty"`
	BlockTime         int64    `json:"blocktime,omitempty"`
	Category          string   `json:"category"`
	Confirmations     int64    `json:"confirmations"`
	Fee               *float64 `json:"fee,omitempty"`
	Generated         bool     `json:"generated,omitempty"`
	InvolvesWatchOnly bool     `json:"involveswatchonly,omitempty"`
	Time              int64    `json:"time"`
	TimeReceived      int64    `json:"timereceived"`
	Trusted           bool     `json:"trusted"`
	TxID              string   `json:"txid"`
	Vout              uint32   `json:"vout"`
	WalletConflicts   []string `json:"walletconflicts"`
	Comment           string   `json:"comment,omitempty"`
	OtherAccount      string   `json:"otheraccount,omitempty"`
}

// ListReceivedByAccountResult models the data from the listreceivedbyaccount
// command.
type ListReceivedByAccountResult struct {
	Account       string  `json:"account"`
	Amount        float64 `json:"amount"`
	Confirmations uint64  `json:"confirmations"`
}

// ListReceivedByAddressResult models the data from the listreceivedbyaddress
// command.
type ListReceivedByAddressResult struct {
	Account           string   `json:"account"`
	Address           string   `json:"address"`
	Amount            float64  `json:"amount"`
	Confirmations     uint64   `json:"confirmations"`
	TxIDs             []string `json:"txids,omitempty"`
	InvolvesWatchonly bool     `json:"involvesWatchonly,omitempty"`
}

// ListSinceBlockResult models the data from the listsinceblock command.
type ListSinceBlockResult struct {
	Transactions []ListTransactionsResult `json:"transactions"`
	LastBlock    string                   `json:"lastblock"`
}

// ListUnspentResult models a successful response from the listunspent request.
type ListUnspentResult struct {
	TxID          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	Address       string  `json:"address"`
	Account       string  `json:"account"`
	ScriptPubKey  string  `json:"scriptPubKey"`
	RedeemScript  string  `json:"redeemScript,omitempty"`
	Amount        float64 `json:"amount"`
	Confirmations int64   `json:"confirmations"`
	Spendable     bool    `json:"spendable"`
}

// SignRawTransactionError models the data that contains script verification
// errors from the signrawtransaction request.
type SignRawTransactionError struct {
	TxID      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	ScriptSig string `json:"scriptSig"`
	Sequence  uint32 `json:"sequence"`
	Error     string `json:"error"`
}

// SignRawTransactionResult models the data from the signrawtransaction
// command.
type SignRawTransactionResult struct {
	Hex      string                    `json:"hex"`
	Complete bool                      `json:"complete"`
	Errors   []SignRawTransactionError `json:"errors,omitempty"`
}

// ValidateAddressWalletResult models the data returned by the wallet server
// validateaddress command.
type ValidateAddressWalletResult struct {
	IsValid      bool     `json:"isvalid"`
	Address      string   `json:"address,omitempty"`
	IsMine       bool     `json:"ismine,omitempty"`
	IsWatchOnly  bool     `json:"iswatchonly,omitempty"`
	IsScript     bool     `json:"isscript,omitempty"`
	PubKey       string   `json:"pubkey,omitempty"`
	IsCompressed bool     `json:"iscompressed,omitempty"`
	Account      string   `json:"account,omitempty"`
	Addresses    []string `json:"addresses,omitempty"`
	Hex          string   `json:"hex,omitempty"`
	Script       string   `json:"script,omitempty"`
	SigsRequired int32    `json:"sigsrequired,omitempty"`
}

// GetBestBlockResult models the data from the getbestblock command.
type GetBestBlockResult struct {
	Hash   string `json:"hash"`
	Height int32  `json:"height"`
}

// BalanceDetailsResult models the details data from the `getbalances` command.
type BalanceDetailsResult struct {
	Trusted          float64  `json:"trusted"`
	UntrustedPending float64  `json:"untrusted_pending"`
	Immature         float64  `json:"immature"`
	Used             *float64 `json:"used"`
}

// GetBalancesResult models the data returned from the getbalances command.
type GetBalancesResult struct {
	Mine      BalanceDetailsResult  `json:"mine"`
	WatchOnly *BalanceDetailsResult `json:"watchonly"`
}
