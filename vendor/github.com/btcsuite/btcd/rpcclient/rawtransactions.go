// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// defaultMaxFeeRate is the default maximum fee rate in sat/KB enforced
	// by bitcoind v0.19.0 or after for transaction broadcast.
	defaultMaxFeeRate = btcutil.SatoshiPerBitcoin / 10
)

// SigHashType enumerates the available signature hashing types that the
// SignRawTransaction function accepts.
type SigHashType string

// Constants used to indicate the signature hash type for SignRawTransaction.
const (
	// SigHashAll indicates ALL of the outputs should be signed.
	SigHashAll SigHashType = "ALL"

	// SigHashNone indicates NONE of the outputs should be signed.  This
	// can be thought of as specifying the signer does not care where the
	// bitcoins go.
	SigHashNone SigHashType = "NONE"

	// SigHashSingle indicates that a SINGLE output should be signed.  This
	// can be thought of specifying the signer only cares about where ONE of
	// the outputs goes, but not any of the others.
	SigHashSingle SigHashType = "SINGLE"

	// SigHashAllAnyoneCanPay indicates that signer does not care where the
	// other inputs to the transaction come from, so it allows other people
	// to add inputs.  In addition, it uses the SigHashAll signing method
	// for outputs.
	SigHashAllAnyoneCanPay SigHashType = "ALL|ANYONECANPAY"

	// SigHashNoneAnyoneCanPay indicates that signer does not care where the
	// other inputs to the transaction come from, so it allows other people
	// to add inputs.  In addition, it uses the SigHashNone signing method
	// for outputs.
	SigHashNoneAnyoneCanPay SigHashType = "NONE|ANYONECANPAY"

	// SigHashSingleAnyoneCanPay indicates that signer does not care where
	// the other inputs to the transaction come from, so it allows other
	// people to add inputs.  In addition, it uses the SigHashSingle signing
	// method for outputs.
	SigHashSingleAnyoneCanPay SigHashType = "SINGLE|ANYONECANPAY"
)

// String returns the SighHashType in human-readable form.
func (s SigHashType) String() string {
	return string(s)
}

// FutureGetRawTransactionResult is a future promise to deliver the result of a
// GetRawTransactionAsync RPC invocation (or an applicable error).
type FutureGetRawTransactionResult chan *response

// Receive waits for the response promised by the future and returns a
// transaction given its hash.
func (r FutureGetRawTransactionResult) Receive() (*btcutil.Tx, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var txHex string
	err = json.Unmarshal(res, &txHex)
	if err != nil {
		return nil, err
	}

	// Decode the serialized transaction hex to raw bytes.
	serializedTx, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}

	// Deserialize the transaction and return it.
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(serializedTx)); err != nil {
		return nil, err
	}
	return btcutil.NewTx(&msgTx), nil
}

// GetRawTransactionAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetRawTransaction for the blocking version and more details.
func (c *Client) GetRawTransactionAsync(txHash *chainhash.Hash) FutureGetRawTransactionResult {
	hash := ""
	if txHash != nil {
		hash = txHash.String()
	}

	cmd := btcjson.NewGetRawTransactionCmd(hash, btcjson.Int(0))
	return c.sendCmd(cmd)
}

// GetRawTransaction returns a transaction given its hash.
//
// See GetRawTransactionVerbose to obtain additional information about the
// transaction.
func (c *Client) GetRawTransaction(txHash *chainhash.Hash) (*btcutil.Tx, error) {
	return c.GetRawTransactionAsync(txHash).Receive()
}

// FutureGetRawTransactionVerboseResult is a future promise to deliver the
// result of a GetRawTransactionVerboseAsync RPC invocation (or an applicable
// error).
type FutureGetRawTransactionVerboseResult chan *response

// Receive waits for the response promised by the future and returns information
// about a transaction given its hash.
func (r FutureGetRawTransactionVerboseResult) Receive() (*btcjson.TxRawResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a gettrawtransaction result object.
	var rawTxResult btcjson.TxRawResult
	err = json.Unmarshal(res, &rawTxResult)
	if err != nil {
		return nil, err
	}

	return &rawTxResult, nil
}

// GetRawTransactionVerboseAsync returns an instance of a type that can be used
// to get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See GetRawTransactionVerbose for the blocking version and more details.
func (c *Client) GetRawTransactionVerboseAsync(txHash *chainhash.Hash) FutureGetRawTransactionVerboseResult {
	hash := ""
	if txHash != nil {
		hash = txHash.String()
	}

	cmd := btcjson.NewGetRawTransactionCmd(hash, btcjson.Int(1))
	return c.sendCmd(cmd)
}

// GetRawTransactionVerbose returns information about a transaction given
// its hash.
//
// See GetRawTransaction to obtain only the transaction already deserialized.
func (c *Client) GetRawTransactionVerbose(txHash *chainhash.Hash) (*btcjson.TxRawResult, error) {
	return c.GetRawTransactionVerboseAsync(txHash).Receive()
}

// FutureDecodeRawTransactionResult is a future promise to deliver the result
// of a DecodeRawTransactionAsync RPC invocation (or an applicable error).
type FutureDecodeRawTransactionResult chan *response

// Receive waits for the response promised by the future and returns information
// about a transaction given its serialized bytes.
func (r FutureDecodeRawTransactionResult) Receive() (*btcjson.TxRawResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a decoderawtransaction result object.
	var rawTxResult btcjson.TxRawResult
	err = json.Unmarshal(res, &rawTxResult)
	if err != nil {
		return nil, err
	}

	return &rawTxResult, nil
}

// DecodeRawTransactionAsync returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See DecodeRawTransaction for the blocking version and more details.
func (c *Client) DecodeRawTransactionAsync(serializedTx []byte) FutureDecodeRawTransactionResult {
	txHex := hex.EncodeToString(serializedTx)
	cmd := btcjson.NewDecodeRawTransactionCmd(txHex)
	return c.sendCmd(cmd)
}

// DecodeRawTransaction returns information about a transaction given its
// serialized bytes.
func (c *Client) DecodeRawTransaction(serializedTx []byte) (*btcjson.TxRawResult, error) {
	return c.DecodeRawTransactionAsync(serializedTx).Receive()
}

// FutureFundRawTransactionResult is a future promise to deliver the result
// of a FutureFundRawTransactionAsync RPC invocation (or an applicable error).
type FutureFundRawTransactionResult chan *response

// Receive waits for the response promised by the future and returns information
// about a funding attempt
func (r FutureFundRawTransactionResult) Receive() (*btcjson.FundRawTransactionResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	var marshalled btcjson.FundRawTransactionResult
	if err := json.Unmarshal(res, &marshalled); err != nil {
		return nil, err
	}

	return &marshalled, nil
}

// FundRawTransactionAsync returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See FundRawTransaction for the blocking version and more details.
func (c *Client) FundRawTransactionAsync(tx *wire.MsgTx, opts btcjson.FundRawTransactionOpts, isWitness *bool) FutureFundRawTransactionResult {
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		return newFutureError(err)
	}

	cmd := btcjson.NewFundRawTransactionCmd(txBuf.Bytes(), opts, isWitness)
	return c.sendCmd(cmd)
}

// FundRawTransaction returns the result of trying to fund the given transaction with
// funds from the node wallet
func (c *Client) FundRawTransaction(tx *wire.MsgTx, opts btcjson.FundRawTransactionOpts, isWitness *bool) (*btcjson.FundRawTransactionResult, error) {
	return c.FundRawTransactionAsync(tx, opts, isWitness).Receive()
}

// FutureCreateRawTransactionResult is a future promise to deliver the result
// of a CreateRawTransactionAsync RPC invocation (or an applicable error).
type FutureCreateRawTransactionResult chan *response

// Receive waits for the response promised by the future and returns a new
// transaction spending the provided inputs and sending to the provided
// addresses.
func (r FutureCreateRawTransactionResult) Receive() (*wire.MsgTx, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var txHex string
	err = json.Unmarshal(res, &txHex)
	if err != nil {
		return nil, err
	}

	// Decode the serialized transaction hex to raw bytes.
	serializedTx, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}

	// Deserialize the transaction and return it.
	var msgTx wire.MsgTx
	// we try both the new and old encoding format
	witnessErr := msgTx.Deserialize(bytes.NewReader(serializedTx))
	if witnessErr != nil {
		legacyErr := msgTx.DeserializeNoWitness(bytes.NewReader(serializedTx))
		if legacyErr != nil {
			return nil, legacyErr
		}
	}
	return &msgTx, nil
}

// CreateRawTransactionAsync returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See CreateRawTransaction for the blocking version and more details.
func (c *Client) CreateRawTransactionAsync(inputs []btcjson.TransactionInput,
	amounts map[btcutil.Address]btcutil.Amount, lockTime *int64) FutureCreateRawTransactionResult {

	convertedAmts := make(map[string]float64, len(amounts))
	for addr, amount := range amounts {
		convertedAmts[addr.String()] = amount.ToBTC()
	}
	cmd := btcjson.NewCreateRawTransactionCmd(inputs, convertedAmts, lockTime)
	return c.sendCmd(cmd)
}

// CreateRawTransaction returns a new transaction spending the provided inputs
// and sending to the provided addresses. If the inputs are either nil or an
// empty slice, it is interpreted as an empty slice.
func (c *Client) CreateRawTransaction(inputs []btcjson.TransactionInput,
	amounts map[btcutil.Address]btcutil.Amount, lockTime *int64) (*wire.MsgTx, error) {

	return c.CreateRawTransactionAsync(inputs, amounts, lockTime).Receive()
}

// FutureSendRawTransactionResult is a future promise to deliver the result
// of a SendRawTransactionAsync RPC invocation (or an applicable error).
type FutureSendRawTransactionResult chan *response

// Receive waits for the response promised by the future and returns the result
// of submitting the encoded transaction to the server which then relays it to
// the network.
func (r FutureSendRawTransactionResult) Receive() (*chainhash.Hash, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var txHashStr string
	err = json.Unmarshal(res, &txHashStr)
	if err != nil {
		return nil, err
	}

	return chainhash.NewHashFromStr(txHashStr)
}

// SendRawTransactionAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See SendRawTransaction for the blocking version and more details.
func (c *Client) SendRawTransactionAsync(tx *wire.MsgTx, allowHighFees bool) FutureSendRawTransactionResult {
	txHex := ""
	if tx != nil {
		// Serialize the transaction and convert to hex string.
		buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(buf); err != nil {
			return newFutureError(err)
		}
		txHex = hex.EncodeToString(buf.Bytes())
	}

	// Due to differences in the sendrawtransaction API for different
	// backends, we'll need to inspect our version and construct the
	// appropriate request.
	version, err := c.BackendVersion()
	if err != nil {
		return newFutureError(err)
	}

	var cmd *btcjson.SendRawTransactionCmd
	switch version {
	// Starting from bitcoind v0.19.0, the MaxFeeRate field should be used.
	case BitcoindPost19:
		// Using a 0 MaxFeeRate is interpreted as a maximum fee rate not
		// being enforced by bitcoind.
		var maxFeeRate int32
		if !allowHighFees {
			maxFeeRate = defaultMaxFeeRate
		}
		cmd = btcjson.NewBitcoindSendRawTransactionCmd(txHex, maxFeeRate)

	// Otherwise, use the AllowHighFees field.
	default:
		cmd = btcjson.NewSendRawTransactionCmd(txHex, &allowHighFees)
	}

	return c.sendCmd(cmd)
}

// SendRawTransaction submits the encoded transaction to the server which will
// then relay it to the network.
func (c *Client) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error) {
	return c.SendRawTransactionAsync(tx, allowHighFees).Receive()
}

// FutureSignRawTransactionResult is a future promise to deliver the result
// of one of the SignRawTransactionAsync family of RPC invocations (or an
// applicable error).
type FutureSignRawTransactionResult chan *response

// Receive waits for the response promised by the future and returns the
// signed transaction as well as whether or not all inputs are now signed.
func (r FutureSignRawTransactionResult) Receive() (*wire.MsgTx, bool, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, false, err
	}

	// Unmarshal as a signrawtransaction result.
	var signRawTxResult btcjson.SignRawTransactionResult
	err = json.Unmarshal(res, &signRawTxResult)
	if err != nil {
		return nil, false, err
	}

	// Decode the serialized transaction hex to raw bytes.
	serializedTx, err := hex.DecodeString(signRawTxResult.Hex)
	if err != nil {
		return nil, false, err
	}

	// Deserialize the transaction and return it.
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(serializedTx)); err != nil {
		return nil, false, err
	}

	return &msgTx, signRawTxResult.Complete, nil
}

// SignRawTransactionAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See SignRawTransaction for the blocking version and more details.
func (c *Client) SignRawTransactionAsync(tx *wire.MsgTx) FutureSignRawTransactionResult {
	txHex := ""
	if tx != nil {
		// Serialize the transaction and convert to hex string.
		buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(buf); err != nil {
			return newFutureError(err)
		}
		txHex = hex.EncodeToString(buf.Bytes())
	}

	cmd := btcjson.NewSignRawTransactionCmd(txHex, nil, nil, nil)
	return c.sendCmd(cmd)
}

// SignRawTransaction signs inputs for the passed transaction and returns the
// signed transaction as well as whether or not all inputs are now signed.
//
// This function assumes the RPC server already knows the input transactions and
// private keys for the passed transaction which needs to be signed and uses the
// default signature hash type.  Use one of the SignRawTransaction# variants to
// specify that information if needed.
func (c *Client) SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error) {
	return c.SignRawTransactionAsync(tx).Receive()
}

// SignRawTransaction2Async returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See SignRawTransaction2 for the blocking version and more details.
func (c *Client) SignRawTransaction2Async(tx *wire.MsgTx, inputs []btcjson.RawTxInput) FutureSignRawTransactionResult {
	txHex := ""
	if tx != nil {
		// Serialize the transaction and convert to hex string.
		buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(buf); err != nil {
			return newFutureError(err)
		}
		txHex = hex.EncodeToString(buf.Bytes())
	}

	cmd := btcjson.NewSignRawTransactionCmd(txHex, &inputs, nil, nil)
	return c.sendCmd(cmd)
}

// SignRawTransaction2 signs inputs for the passed transaction given the list
// of information about the input transactions needed to perform the signing
// process.
//
// This only input transactions that need to be specified are ones the
// RPC server does not already know.  Already known input transactions will be
// merged with the specified transactions.
//
// See SignRawTransaction if the RPC server already knows the input
// transactions.
func (c *Client) SignRawTransaction2(tx *wire.MsgTx, inputs []btcjson.RawTxInput) (*wire.MsgTx, bool, error) {
	return c.SignRawTransaction2Async(tx, inputs).Receive()
}

// SignRawTransaction3Async returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See SignRawTransaction3 for the blocking version and more details.
func (c *Client) SignRawTransaction3Async(tx *wire.MsgTx,
	inputs []btcjson.RawTxInput,
	privKeysWIF []string) FutureSignRawTransactionResult {

	txHex := ""
	if tx != nil {
		// Serialize the transaction and convert to hex string.
		buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(buf); err != nil {
			return newFutureError(err)
		}
		txHex = hex.EncodeToString(buf.Bytes())
	}

	cmd := btcjson.NewSignRawTransactionCmd(txHex, &inputs, &privKeysWIF,
		nil)
	return c.sendCmd(cmd)
}

// SignRawTransaction3 signs inputs for the passed transaction given the list
// of information about extra input transactions and a list of private keys
// needed to perform the signing process.  The private keys must be in wallet
// import format (WIF).
//
// This only input transactions that need to be specified are ones the
// RPC server does not already know.  Already known input transactions will be
// merged with the specified transactions.  This means the list of transaction
// inputs can be nil if the RPC server already knows them all.
//
// NOTE: Unlike the merging functionality of the input transactions, ONLY the
// specified private keys will be used, so even if the server already knows some
// of the private keys, they will NOT be used.
//
// See SignRawTransaction if the RPC server already knows the input
// transactions and private keys or SignRawTransaction2 if it already knows the
// private keys.
func (c *Client) SignRawTransaction3(tx *wire.MsgTx,
	inputs []btcjson.RawTxInput,
	privKeysWIF []string) (*wire.MsgTx, bool, error) {

	return c.SignRawTransaction3Async(tx, inputs, privKeysWIF).Receive()
}

// SignRawTransaction4Async returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See SignRawTransaction4 for the blocking version and more details.
func (c *Client) SignRawTransaction4Async(tx *wire.MsgTx,
	inputs []btcjson.RawTxInput, privKeysWIF []string,
	hashType SigHashType) FutureSignRawTransactionResult {

	txHex := ""
	if tx != nil {
		// Serialize the transaction and convert to hex string.
		buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(buf); err != nil {
			return newFutureError(err)
		}
		txHex = hex.EncodeToString(buf.Bytes())
	}

	cmd := btcjson.NewSignRawTransactionCmd(txHex, &inputs, &privKeysWIF,
		btcjson.String(string(hashType)))
	return c.sendCmd(cmd)
}

// SignRawTransaction4 signs inputs for the passed transaction using the
// the specified signature hash type given the list of information about extra
// input transactions and a potential list of private keys needed to perform
// the signing process.  The private keys, if specified, must be in wallet
// import format (WIF).
//
// The only input transactions that need to be specified are ones the RPC server
// does not already know.  This means the list of transaction inputs can be nil
// if the RPC server already knows them all.
//
// NOTE: Unlike the merging functionality of the input transactions, ONLY the
// specified private keys will be used, so even if the server already knows some
// of the private keys, they will NOT be used.  The list of private keys can be
// nil in which case any private keys the RPC server knows will be used.
//
// This function should only used if a non-default signature hash type is
// desired.  Otherwise, see SignRawTransaction if the RPC server already knows
// the input transactions and private keys, SignRawTransaction2 if it already
// knows the private keys, or SignRawTransaction3 if it does not know both.
func (c *Client) SignRawTransaction4(tx *wire.MsgTx,
	inputs []btcjson.RawTxInput, privKeysWIF []string,
	hashType SigHashType) (*wire.MsgTx, bool, error) {

	return c.SignRawTransaction4Async(tx, inputs, privKeysWIF,
		hashType).Receive()
}

// FutureSearchRawTransactionsResult is a future promise to deliver the result
// of the SearchRawTransactionsAsync RPC invocation (or an applicable error).
type FutureSearchRawTransactionsResult chan *response

// Receive waits for the response promised by the future and returns the
// found raw transactions.
func (r FutureSearchRawTransactionsResult) Receive() ([]*wire.MsgTx, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal as an array of strings.
	var searchRawTxnsResult []string
	err = json.Unmarshal(res, &searchRawTxnsResult)
	if err != nil {
		return nil, err
	}

	// Decode and deserialize each transaction.
	msgTxns := make([]*wire.MsgTx, 0, len(searchRawTxnsResult))
	for _, hexTx := range searchRawTxnsResult {
		// Decode the serialized transaction hex to raw bytes.
		serializedTx, err := hex.DecodeString(hexTx)
		if err != nil {
			return nil, err
		}

		// Deserialize the transaction and add it to the result slice.
		var msgTx wire.MsgTx
		err = msgTx.Deserialize(bytes.NewReader(serializedTx))
		if err != nil {
			return nil, err
		}
		msgTxns = append(msgTxns, &msgTx)
	}

	return msgTxns, nil
}

// SearchRawTransactionsAsync returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See SearchRawTransactions for the blocking version and more details.
func (c *Client) SearchRawTransactionsAsync(address btcutil.Address, skip, count int, reverse bool, filterAddrs []string) FutureSearchRawTransactionsResult {
	addr := address.EncodeAddress()
	verbose := btcjson.Int(0)
	cmd := btcjson.NewSearchRawTransactionsCmd(addr, verbose, &skip, &count,
		nil, &reverse, &filterAddrs)
	return c.sendCmd(cmd)
}

// SearchRawTransactions returns transactions that involve the passed address.
//
// NOTE: Chain servers do not typically provide this capability unless it has
// specifically been enabled.
//
// See SearchRawTransactionsVerbose to retrieve a list of data structures with
// information about the transactions instead of the transactions themselves.
func (c *Client) SearchRawTransactions(address btcutil.Address, skip, count int, reverse bool, filterAddrs []string) ([]*wire.MsgTx, error) {
	return c.SearchRawTransactionsAsync(address, skip, count, reverse, filterAddrs).Receive()
}

// FutureSearchRawTransactionsVerboseResult is a future promise to deliver the
// result of the SearchRawTransactionsVerboseAsync RPC invocation (or an
// applicable error).
type FutureSearchRawTransactionsVerboseResult chan *response

// Receive waits for the response promised by the future and returns the
// found raw transactions.
func (r FutureSearchRawTransactionsVerboseResult) Receive() ([]*btcjson.SearchRawTransactionsResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal as an array of raw transaction results.
	var result []*btcjson.SearchRawTransactionsResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// SearchRawTransactionsVerboseAsync returns an instance of a type that can be
// used to get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See SearchRawTransactionsVerbose for the blocking version and more details.
func (c *Client) SearchRawTransactionsVerboseAsync(address btcutil.Address, skip,
	count int, includePrevOut, reverse bool, filterAddrs *[]string) FutureSearchRawTransactionsVerboseResult {

	addr := address.EncodeAddress()
	verbose := btcjson.Int(1)
	var prevOut *int
	if includePrevOut {
		prevOut = btcjson.Int(1)
	}
	cmd := btcjson.NewSearchRawTransactionsCmd(addr, verbose, &skip, &count,
		prevOut, &reverse, filterAddrs)
	return c.sendCmd(cmd)
}

// SearchRawTransactionsVerbose returns a list of data structures that describe
// transactions which involve the passed address.
//
// NOTE: Chain servers do not typically provide this capability unless it has
// specifically been enabled.
//
// See SearchRawTransactions to retrieve a list of raw transactions instead.
func (c *Client) SearchRawTransactionsVerbose(address btcutil.Address, skip,
	count int, includePrevOut, reverse bool, filterAddrs []string) ([]*btcjson.SearchRawTransactionsResult, error) {

	return c.SearchRawTransactionsVerboseAsync(address, skip, count,
		includePrevOut, reverse, &filterAddrs).Receive()
}

// FutureDecodeScriptResult is a future promise to deliver the result
// of a DecodeScriptAsync RPC invocation (or an applicable error).
type FutureDecodeScriptResult chan *response

// Receive waits for the response promised by the future and returns information
// about a script given its serialized bytes.
func (r FutureDecodeScriptResult) Receive() (*btcjson.DecodeScriptResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a decodescript result object.
	var decodeScriptResult btcjson.DecodeScriptResult
	err = json.Unmarshal(res, &decodeScriptResult)
	if err != nil {
		return nil, err
	}

	return &decodeScriptResult, nil
}

// DecodeScriptAsync returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See DecodeScript for the blocking version and more details.
func (c *Client) DecodeScriptAsync(serializedScript []byte) FutureDecodeScriptResult {
	scriptHex := hex.EncodeToString(serializedScript)
	cmd := btcjson.NewDecodeScriptCmd(scriptHex)
	return c.sendCmd(cmd)
}

// DecodeScript returns information about a script given its serialized bytes.
func (c *Client) DecodeScript(serializedScript []byte) (*btcjson.DecodeScriptResult, error) {
	return c.DecodeScriptAsync(serializedScript).Receive()
}
