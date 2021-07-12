// Copyright (c) 2014-2017 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
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
)

// FutureGetBestBlockHashResult is a future promise to deliver the result of a
// GetBestBlockAsync RPC invocation (or an applicable error).
type FutureGetBestBlockHashResult chan *response

// Receive waits for the response promised by the future and returns the hash of
// the best block in the longest block chain.
func (r FutureGetBestBlockHashResult) Receive() (*chainhash.Hash, error) {
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

// GetBestBlockHashAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetBestBlockHash for the blocking version and more details.
func (c *Client) GetBestBlockHashAsync() FutureGetBestBlockHashResult {
	cmd := btcjson.NewGetBestBlockHashCmd()
	return c.sendCmd(cmd)
}

// GetBestBlockHash returns the hash of the best block in the longest block
// chain.
func (c *Client) GetBestBlockHash() (*chainhash.Hash, error) {
	return c.GetBestBlockHashAsync().Receive()
}

// legacyGetBlockRequest constructs and sends a legacy getblock request which
// contains two separate bools to denote verbosity, in contract to a single int
// parameter.
func (c *Client) legacyGetBlockRequest(hash string, verbose,
	verboseTx bool) ([]byte, error) {

	hashJSON, err := json.Marshal(hash)
	if err != nil {
		return nil, err
	}
	verboseJSON, err := json.Marshal(btcjson.Bool(verbose))
	if err != nil {
		return nil, err
	}
	verboseTxJSON, err := json.Marshal(btcjson.Bool(verboseTx))
	if err != nil {
		return nil, err
	}
	return c.RawRequest("getblock", []json.RawMessage{
		hashJSON, verboseJSON, verboseTxJSON,
	})
}

// waitForGetBlockRes waits for the response of a getblock request. If the
// response indicates an invalid parameter was provided, a legacy style of the
// request is resent and its response is returned instead.
func (c *Client) waitForGetBlockRes(respChan chan *response, hash string,
	verbose, verboseTx bool) ([]byte, error) {

	res, err := receiveFuture(respChan)

	// If we receive an invalid parameter error, then we may be
	// communicating with a btcd node which only understands the legacy
	// request, so we'll try that.
	if err, ok := err.(*btcjson.RPCError); ok &&
		err.Code == btcjson.ErrRPCInvalidParams.Code {
		return c.legacyGetBlockRequest(hash, verbose, verboseTx)
	}

	// Otherwise, we can return the response as is.
	return res, err
}

// FutureGetBlockResult is a future promise to deliver the result of a
// GetBlockAsync RPC invocation (or an applicable error).
type FutureGetBlockResult struct {
	client   *Client
	hash     string
	Response chan *response
}

// Receive waits for the response promised by the future and returns the raw
// block requested from the server given its hash.
func (r FutureGetBlockResult) Receive() (*wire.MsgBlock, error) {
	res, err := r.client.waitForGetBlockRes(r.Response, r.hash, false, false)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var blockHex string
	err = json.Unmarshal(res, &blockHex)
	if err != nil {
		return nil, err
	}

	// Decode the serialized block hex to raw bytes.
	serializedBlock, err := hex.DecodeString(blockHex)
	if err != nil {
		return nil, err
	}

	// Deserialize the block and return it.
	var msgBlock wire.MsgBlock
	err = msgBlock.Deserialize(bytes.NewReader(serializedBlock))
	if err != nil {
		return nil, err
	}
	return &msgBlock, nil
}

// GetBlockAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetBlock for the blocking version and more details.
func (c *Client) GetBlockAsync(blockHash *chainhash.Hash) FutureGetBlockResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetBlockCmd(hash, btcjson.Int(0))
	return FutureGetBlockResult{
		client:   c,
		hash:     hash,
		Response: c.sendCmd(cmd),
	}
}

// GetBlock returns a raw block from the server given its hash.
//
// See GetBlockVerbose to retrieve a data structure with information about the
// block instead.
func (c *Client) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	return c.GetBlockAsync(blockHash).Receive()
}

// FutureGetBlockVerboseResult is a future promise to deliver the result of a
// GetBlockVerboseAsync RPC invocation (or an applicable error).
type FutureGetBlockVerboseResult struct {
	client   *Client
	hash     string
	Response chan *response
}

// Receive waits for the response promised by the future and returns the data
// structure from the server with information about the requested block.
func (r FutureGetBlockVerboseResult) Receive() (*btcjson.GetBlockVerboseResult, error) {
	res, err := r.client.waitForGetBlockRes(r.Response, r.hash, true, false)
	if err != nil {
		return nil, err
	}

	// Unmarshal the raw result into a BlockResult.
	var blockResult btcjson.GetBlockVerboseResult
	err = json.Unmarshal(res, &blockResult)
	if err != nil {
		return nil, err
	}
	return &blockResult, nil
}

// GetBlockVerboseAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetBlockVerbose for the blocking version and more details.
func (c *Client) GetBlockVerboseAsync(blockHash *chainhash.Hash) FutureGetBlockVerboseResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}
	// From the bitcoin-cli getblock documentation:
	// "If verbosity is 1, returns an Object with information about block ."
	cmd := btcjson.NewGetBlockCmd(hash, btcjson.Int(1))
	return FutureGetBlockVerboseResult{
		client:   c,
		hash:     hash,
		Response: c.sendCmd(cmd),
	}
}

// GetBlockVerbose returns a data structure from the server with information
// about a block given its hash.
//
// See GetBlockVerboseTx to retrieve transaction data structures as well.
// See GetBlock to retrieve a raw block instead.
func (c *Client) GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error) {
	return c.GetBlockVerboseAsync(blockHash).Receive()
}

// FutureGetBlockVerboseTxResult is a future promise to deliver the result of a
// GetBlockVerboseTxResult RPC invocation (or an applicable error).
type FutureGetBlockVerboseTxResult struct {
	client   *Client
	hash     string
	Response chan *response
}

// Receive waits for the response promised by the future and returns a verbose
// version of the block including detailed information about its transactions.
func (r FutureGetBlockVerboseTxResult) Receive() (*btcjson.GetBlockVerboseTxResult, error) {
	res, err := r.client.waitForGetBlockRes(r.Response, r.hash, true, true)
	if err != nil {
		return nil, err
	}

	var blockResult btcjson.GetBlockVerboseTxResult
	err = json.Unmarshal(res, &blockResult)
	if err != nil {
		return nil, err
	}

	return &blockResult, nil
}

// GetBlockVerboseTxAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetBlockVerboseTx or the blocking version and more details.
func (c *Client) GetBlockVerboseTxAsync(blockHash *chainhash.Hash) FutureGetBlockVerboseTxResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	// From the bitcoin-cli getblock documentation:
	//
	// If verbosity is 2, returns an Object with information about block
	// and information about each transaction.
	cmd := btcjson.NewGetBlockCmd(hash, btcjson.Int(2))
	return FutureGetBlockVerboseTxResult{
		client:   c,
		hash:     hash,
		Response: c.sendCmd(cmd),
	}
}

// GetBlockVerboseTx returns a data structure from the server with information
// about a block and its transactions given its hash.
//
// See GetBlockVerbose if only transaction hashes are preferred.
// See GetBlock to retrieve a raw block instead.
func (c *Client) GetBlockVerboseTx(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseTxResult, error) {
	return c.GetBlockVerboseTxAsync(blockHash).Receive()
}

// FutureGetBlockCountResult is a future promise to deliver the result of a
// GetBlockCountAsync RPC invocation (or an applicable error).
type FutureGetBlockCountResult chan *response

// Receive waits for the response promised by the future and returns the number
// of blocks in the longest block chain.
func (r FutureGetBlockCountResult) Receive() (int64, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return 0, err
	}

	// Unmarshal the result as an int64.
	var count int64
	err = json.Unmarshal(res, &count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetBlockCountAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetBlockCount for the blocking version and more details.
func (c *Client) GetBlockCountAsync() FutureGetBlockCountResult {
	cmd := btcjson.NewGetBlockCountCmd()
	return c.sendCmd(cmd)
}

// GetBlockCount returns the number of blocks in the longest block chain.
func (c *Client) GetBlockCount() (int64, error) {
	return c.GetBlockCountAsync().Receive()
}

// FutureGetChainTxStatsResult is a future promise to deliver the result of a
// GetChainTxStatsAsync RPC invocation (or an applicable error).
type FutureGetChainTxStatsResult chan *response

// Receive waits for the response promised by the future and returns transaction statistics
func (r FutureGetChainTxStatsResult) Receive() (*btcjson.GetChainTxStatsResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	var chainTxStats btcjson.GetChainTxStatsResult
	err = json.Unmarshal(res, &chainTxStats)
	if err != nil {
		return nil, err
	}

	return &chainTxStats, nil
}

// GetChainTxStatsAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetChainTxStats for the blocking version and more details.
func (c *Client) GetChainTxStatsAsync() FutureGetChainTxStatsResult {
	cmd := btcjson.NewGetChainTxStatsCmd(nil, nil)
	return c.sendCmd(cmd)
}

// GetChainTxStatsNBlocksAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetChainTxStatsNBlocks for the blocking version and more details.
func (c *Client) GetChainTxStatsNBlocksAsync(nBlocks int32) FutureGetChainTxStatsResult {
	cmd := btcjson.NewGetChainTxStatsCmd(&nBlocks, nil)
	return c.sendCmd(cmd)
}

// GetChainTxStatsNBlocksBlockHashAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetChainTxStatsNBlocksBlockHash for the blocking version and more details.
func (c *Client) GetChainTxStatsNBlocksBlockHashAsync(nBlocks int32, blockHash chainhash.Hash) FutureGetChainTxStatsResult {
	hash := blockHash.String()
	cmd := btcjson.NewGetChainTxStatsCmd(&nBlocks, &hash)
	return c.sendCmd(cmd)
}

// GetChainTxStats returns statistics about the total number and rate of transactions in the chain.
//
// Size of the window is one month and it ends at chain tip.
func (c *Client) GetChainTxStats() (*btcjson.GetChainTxStatsResult, error) {
	return c.GetChainTxStatsAsync().Receive()
}

// GetChainTxStatsNBlocks returns statistics about the total number and rate of transactions in the chain.
//
// The argument specifies size of the window in number of blocks. The window ends at chain tip.
func (c *Client) GetChainTxStatsNBlocks(nBlocks int32) (*btcjson.GetChainTxStatsResult, error) {
	return c.GetChainTxStatsNBlocksAsync(nBlocks).Receive()
}

// GetChainTxStatsNBlocksBlockHash returns statistics about the total number and rate of transactions in the chain.
//
// First argument specifies size of the window in number of blocks.
// Second argument is the hash of the block that ends the window.
func (c *Client) GetChainTxStatsNBlocksBlockHash(nBlocks int32, blockHash chainhash.Hash) (*btcjson.GetChainTxStatsResult, error) {
	return c.GetChainTxStatsNBlocksBlockHashAsync(nBlocks, blockHash).Receive()
}

// FutureGetDifficultyResult is a future promise to deliver the result of a
// GetDifficultyAsync RPC invocation (or an applicable error).
type FutureGetDifficultyResult chan *response

// Receive waits for the response promised by the future and returns the
// proof-of-work difficulty as a multiple of the minimum difficulty.
func (r FutureGetDifficultyResult) Receive() (float64, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return 0, err
	}

	// Unmarshal the result as a float64.
	var difficulty float64
	err = json.Unmarshal(res, &difficulty)
	if err != nil {
		return 0, err
	}
	return difficulty, nil
}

// GetDifficultyAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetDifficulty for the blocking version and more details.
func (c *Client) GetDifficultyAsync() FutureGetDifficultyResult {
	cmd := btcjson.NewGetDifficultyCmd()
	return c.sendCmd(cmd)
}

// GetDifficulty returns the proof-of-work difficulty as a multiple of the
// minimum difficulty.
func (c *Client) GetDifficulty() (float64, error) {
	return c.GetDifficultyAsync().Receive()
}

// FutureGetBlockChainInfoResult is a promise to deliver the result of a
// GetBlockChainInfoAsync RPC invocation (or an applicable error).
type FutureGetBlockChainInfoResult struct {
	client   *Client
	Response chan *response
}

// unmarshalPartialGetBlockChainInfoResult unmarshals the response into an
// instance of GetBlockChainInfoResult without populating the SoftForks and
// UnifiedSoftForks fields.
func unmarshalPartialGetBlockChainInfoResult(res []byte) (*btcjson.GetBlockChainInfoResult, error) {
	var chainInfo btcjson.GetBlockChainInfoResult
	if err := json.Unmarshal(res, &chainInfo); err != nil {
		return nil, err
	}
	return &chainInfo, nil
}

// unmarshalGetBlockChainInfoResultSoftForks properly unmarshals the softforks
// related fields into the GetBlockChainInfoResult instance.
func unmarshalGetBlockChainInfoResultSoftForks(chainInfo *btcjson.GetBlockChainInfoResult,
	version BackendVersion, res []byte) error {

	switch version {
	// Versions of bitcoind on or after v0.19.0 use the unified format.
	case BitcoindPost19:
		var softForks btcjson.UnifiedSoftForks
		if err := json.Unmarshal(res, &softForks); err != nil {
			return err
		}
		chainInfo.UnifiedSoftForks = &softForks

	// All other versions use the original format.
	default:
		var softForks btcjson.SoftForks
		if err := json.Unmarshal(res, &softForks); err != nil {
			return err
		}
		chainInfo.SoftForks = &softForks
	}

	return nil
}

// Receive waits for the response promised by the future and returns chain info
// result provided by the server.
func (r FutureGetBlockChainInfoResult) Receive() (*btcjson.GetBlockChainInfoResult, error) {
	res, err := receiveFuture(r.Response)
	if err != nil {
		return nil, err
	}
	chainInfo, err := unmarshalPartialGetBlockChainInfoResult(res)
	if err != nil {
		return nil, err
	}

	// Inspect the version to determine how we'll need to parse the
	// softforks from the response.
	version, err := r.client.BackendVersion()
	if err != nil {
		return nil, err
	}

	err = unmarshalGetBlockChainInfoResultSoftForks(chainInfo, version, res)
	if err != nil {
		return nil, err
	}

	return chainInfo, nil
}

// GetBlockChainInfoAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function
// on the returned instance.
//
// See GetBlockChainInfo for the blocking version and more details.
func (c *Client) GetBlockChainInfoAsync() FutureGetBlockChainInfoResult {
	cmd := btcjson.NewGetBlockChainInfoCmd()
	return FutureGetBlockChainInfoResult{
		client:   c,
		Response: c.sendCmd(cmd),
	}
}

// GetBlockChainInfo returns information related to the processing state of
// various chain-specific details such as the current difficulty from the tip
// of the main chain.
func (c *Client) GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error) {
	return c.GetBlockChainInfoAsync().Receive()
}

// FutureGetBlockHashResult is a future promise to deliver the result of a
// GetBlockHashAsync RPC invocation (or an applicable error).
type FutureGetBlockHashResult chan *response

// Receive waits for the response promised by the future and returns the hash of
// the block in the best block chain at the given height.
func (r FutureGetBlockHashResult) Receive() (*chainhash.Hash, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal the result as a string-encoded sha.
	var txHashStr string
	err = json.Unmarshal(res, &txHashStr)
	if err != nil {
		return nil, err
	}
	return chainhash.NewHashFromStr(txHashStr)
}

// GetBlockHashAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetBlockHash for the blocking version and more details.
func (c *Client) GetBlockHashAsync(blockHeight int64) FutureGetBlockHashResult {
	cmd := btcjson.NewGetBlockHashCmd(blockHeight)
	return c.sendCmd(cmd)
}

// GetBlockHash returns the hash of the block in the best block chain at the
// given height.
func (c *Client) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	return c.GetBlockHashAsync(blockHeight).Receive()
}

// FutureGetBlockHeaderResult is a future promise to deliver the result of a
// GetBlockHeaderAsync RPC invocation (or an applicable error).
type FutureGetBlockHeaderResult chan *response

// Receive waits for the response promised by the future and returns the
// blockheader requested from the server given its hash.
func (r FutureGetBlockHeaderResult) Receive() (*wire.BlockHeader, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var bhHex string
	err = json.Unmarshal(res, &bhHex)
	if err != nil {
		return nil, err
	}

	serializedBH, err := hex.DecodeString(bhHex)
	if err != nil {
		return nil, err
	}

	// Deserialize the blockheader and return it.
	var bh wire.BlockHeader
	err = bh.Deserialize(bytes.NewReader(serializedBH))
	if err != nil {
		return nil, err
	}

	return &bh, err
}

// GetBlockHeaderAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetBlockHeader for the blocking version and more details.
func (c *Client) GetBlockHeaderAsync(blockHash *chainhash.Hash) FutureGetBlockHeaderResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetBlockHeaderCmd(hash, btcjson.Bool(false))
	return c.sendCmd(cmd)
}

// GetBlockHeader returns the blockheader from the server given its hash.
//
// See GetBlockHeaderVerbose to retrieve a data structure with information about the
// block instead.
func (c *Client) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	return c.GetBlockHeaderAsync(blockHash).Receive()
}

// FutureGetBlockHeaderVerboseResult is a future promise to deliver the result of a
// GetBlockAsync RPC invocation (or an applicable error).
type FutureGetBlockHeaderVerboseResult chan *response

// Receive waits for the response promised by the future and returns the
// data structure of the blockheader requested from the server given its hash.
func (r FutureGetBlockHeaderVerboseResult) Receive() (*btcjson.GetBlockHeaderVerboseResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var bh btcjson.GetBlockHeaderVerboseResult
	err = json.Unmarshal(res, &bh)
	if err != nil {
		return nil, err
	}

	return &bh, nil
}

// GetBlockHeaderVerboseAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetBlockHeader for the blocking version and more details.
func (c *Client) GetBlockHeaderVerboseAsync(blockHash *chainhash.Hash) FutureGetBlockHeaderVerboseResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetBlockHeaderCmd(hash, btcjson.Bool(true))
	return c.sendCmd(cmd)
}

// GetBlockHeaderVerbose returns a data structure with information about the
// blockheader from the server given its hash.
//
// See GetBlockHeader to retrieve a blockheader instead.
func (c *Client) GetBlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {
	return c.GetBlockHeaderVerboseAsync(blockHash).Receive()
}

// FutureGetMempoolEntryResult is a future promise to deliver the result of a
// GetMempoolEntryAsync RPC invocation (or an applicable error).
type FutureGetMempoolEntryResult chan *response

// Receive waits for the response promised by the future and returns a data
// structure with information about the transaction in the memory pool given
// its hash.
func (r FutureGetMempoolEntryResult) Receive() (*btcjson.GetMempoolEntryResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal the result as an array of strings.
	var mempoolEntryResult btcjson.GetMempoolEntryResult
	err = json.Unmarshal(res, &mempoolEntryResult)
	if err != nil {
		return nil, err
	}

	return &mempoolEntryResult, nil
}

// GetMempoolEntryAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetMempoolEntry for the blocking version and more details.
func (c *Client) GetMempoolEntryAsync(txHash string) FutureGetMempoolEntryResult {
	cmd := btcjson.NewGetMempoolEntryCmd(txHash)
	return c.sendCmd(cmd)
}

// GetMempoolEntry returns a data structure with information about the
// transaction in the memory pool given its hash.
func (c *Client) GetMempoolEntry(txHash string) (*btcjson.GetMempoolEntryResult, error) {
	return c.GetMempoolEntryAsync(txHash).Receive()
}

// FutureGetRawMempoolResult is a future promise to deliver the result of a
// GetRawMempoolAsync RPC invocation (or an applicable error).
type FutureGetRawMempoolResult chan *response

// Receive waits for the response promised by the future and returns the hashes
// of all transactions in the memory pool.
func (r FutureGetRawMempoolResult) Receive() ([]*chainhash.Hash, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal the result as an array of strings.
	var txHashStrs []string
	err = json.Unmarshal(res, &txHashStrs)
	if err != nil {
		return nil, err
	}

	// Create a slice of ShaHash arrays from the string slice.
	txHashes := make([]*chainhash.Hash, 0, len(txHashStrs))
	for _, hashStr := range txHashStrs {
		txHash, err := chainhash.NewHashFromStr(hashStr)
		if err != nil {
			return nil, err
		}
		txHashes = append(txHashes, txHash)
	}

	return txHashes, nil
}

// GetRawMempoolAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetRawMempool for the blocking version and more details.
func (c *Client) GetRawMempoolAsync() FutureGetRawMempoolResult {
	cmd := btcjson.NewGetRawMempoolCmd(btcjson.Bool(false))
	return c.sendCmd(cmd)
}

// GetRawMempool returns the hashes of all transactions in the memory pool.
//
// See GetRawMempoolVerbose to retrieve data structures with information about
// the transactions instead.
func (c *Client) GetRawMempool() ([]*chainhash.Hash, error) {
	return c.GetRawMempoolAsync().Receive()
}

// FutureGetRawMempoolVerboseResult is a future promise to deliver the result of
// a GetRawMempoolVerboseAsync RPC invocation (or an applicable error).
type FutureGetRawMempoolVerboseResult chan *response

// Receive waits for the response promised by the future and returns a map of
// transaction hashes to an associated data structure with information about the
// transaction for all transactions in the memory pool.
func (r FutureGetRawMempoolVerboseResult) Receive() (map[string]btcjson.GetRawMempoolVerboseResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal the result as a map of strings (tx shas) to their detailed
	// results.
	var mempoolItems map[string]btcjson.GetRawMempoolVerboseResult
	err = json.Unmarshal(res, &mempoolItems)
	if err != nil {
		return nil, err
	}
	return mempoolItems, nil
}

// GetRawMempoolVerboseAsync returns an instance of a type that can be used to
// get the result of the RPC at some future time by invoking the Receive
// function on the returned instance.
//
// See GetRawMempoolVerbose for the blocking version and more details.
func (c *Client) GetRawMempoolVerboseAsync() FutureGetRawMempoolVerboseResult {
	cmd := btcjson.NewGetRawMempoolCmd(btcjson.Bool(true))
	return c.sendCmd(cmd)
}

// GetRawMempoolVerbose returns a map of transaction hashes to an associated
// data structure with information about the transaction for all transactions in
// the memory pool.
//
// See GetRawMempool to retrieve only the transaction hashes instead.
func (c *Client) GetRawMempoolVerbose() (map[string]btcjson.GetRawMempoolVerboseResult, error) {
	return c.GetRawMempoolVerboseAsync().Receive()
}

// FutureEstimateFeeResult is a future promise to deliver the result of a
// EstimateFeeAsync RPC invocation (or an applicable error).
type FutureEstimateFeeResult chan *response

// Receive waits for the response promised by the future and returns the info
// provided by the server.
func (r FutureEstimateFeeResult) Receive() (float64, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return -1, err
	}

	// Unmarshal result as a getinfo result object.
	var fee float64
	err = json.Unmarshal(res, &fee)
	if err != nil {
		return -1, err
	}

	return fee, nil
}

// EstimateFeeAsync returns an instance of a type that can be used to get the result
// of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See EstimateFee for the blocking version and more details.
func (c *Client) EstimateFeeAsync(numBlocks int64) FutureEstimateFeeResult {
	cmd := btcjson.NewEstimateFeeCmd(numBlocks)
	return c.sendCmd(cmd)
}

// EstimateFee provides an estimated fee  in bitcoins per kilobyte.
func (c *Client) EstimateFee(numBlocks int64) (float64, error) {
	return c.EstimateFeeAsync(numBlocks).Receive()
}

// FutureEstimateFeeResult is a future promise to deliver the result of a
// EstimateSmartFeeAsync RPC invocation (or an applicable error).
type FutureEstimateSmartFeeResult chan *response

// Receive waits for the response promised by the future and returns the
// estimated fee.
func (r FutureEstimateSmartFeeResult) Receive() (*btcjson.EstimateSmartFeeResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	var verified btcjson.EstimateSmartFeeResult
	err = json.Unmarshal(res, &verified)
	if err != nil {
		return nil, err
	}
	return &verified, nil
}

// EstimateSmartFeeAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See EstimateSmartFee for the blocking version and more details.
func (c *Client) EstimateSmartFeeAsync(confTarget int64, mode *btcjson.EstimateSmartFeeMode) FutureEstimateSmartFeeResult {
	cmd := btcjson.NewEstimateSmartFeeCmd(confTarget, mode)
	return c.sendCmd(cmd)
}

// EstimateSmartFee requests the server to estimate a fee level based on the given parameters.
func (c *Client) EstimateSmartFee(confTarget int64, mode *btcjson.EstimateSmartFeeMode) (*btcjson.EstimateSmartFeeResult, error) {
	return c.EstimateSmartFeeAsync(confTarget, mode).Receive()
}

// FutureVerifyChainResult is a future promise to deliver the result of a
// VerifyChainAsync, VerifyChainLevelAsyncRPC, or VerifyChainBlocksAsync
// invocation (or an applicable error).
type FutureVerifyChainResult chan *response

// Receive waits for the response promised by the future and returns whether
// or not the chain verified based on the check level and number of blocks
// to verify specified in the original call.
func (r FutureVerifyChainResult) Receive() (bool, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return false, err
	}

	// Unmarshal the result as a boolean.
	var verified bool
	err = json.Unmarshal(res, &verified)
	if err != nil {
		return false, err
	}
	return verified, nil
}

// VerifyChainAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See VerifyChain for the blocking version and more details.
func (c *Client) VerifyChainAsync() FutureVerifyChainResult {
	cmd := btcjson.NewVerifyChainCmd(nil, nil)
	return c.sendCmd(cmd)
}

// VerifyChain requests the server to verify the block chain database using
// the default check level and number of blocks to verify.
//
// See VerifyChainLevel and VerifyChainBlocks to override the defaults.
func (c *Client) VerifyChain() (bool, error) {
	return c.VerifyChainAsync().Receive()
}

// VerifyChainLevelAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See VerifyChainLevel for the blocking version and more details.
func (c *Client) VerifyChainLevelAsync(checkLevel int32) FutureVerifyChainResult {
	cmd := btcjson.NewVerifyChainCmd(&checkLevel, nil)
	return c.sendCmd(cmd)
}

// VerifyChainLevel requests the server to verify the block chain database using
// the passed check level and default number of blocks to verify.
//
// The check level controls how thorough the verification is with higher numbers
// increasing the amount of checks done as consequently how long the
// verification takes.
//
// See VerifyChain to use the default check level and VerifyChainBlocks to
// override the number of blocks to verify.
func (c *Client) VerifyChainLevel(checkLevel int32) (bool, error) {
	return c.VerifyChainLevelAsync(checkLevel).Receive()
}

// VerifyChainBlocksAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See VerifyChainBlocks for the blocking version and more details.
func (c *Client) VerifyChainBlocksAsync(checkLevel, numBlocks int32) FutureVerifyChainResult {
	cmd := btcjson.NewVerifyChainCmd(&checkLevel, &numBlocks)
	return c.sendCmd(cmd)
}

// VerifyChainBlocks requests the server to verify the block chain database
// using the passed check level and number of blocks to verify.
//
// The check level controls how thorough the verification is with higher numbers
// increasing the amount of checks done as consequently how long the
// verification takes.
//
// The number of blocks refers to the number of blocks from the end of the
// current longest chain.
//
// See VerifyChain and VerifyChainLevel to use defaults.
func (c *Client) VerifyChainBlocks(checkLevel, numBlocks int32) (bool, error) {
	return c.VerifyChainBlocksAsync(checkLevel, numBlocks).Receive()
}

// FutureGetTxOutResult is a future promise to deliver the result of a
// GetTxOutAsync RPC invocation (or an applicable error).
type FutureGetTxOutResult chan *response

// Receive waits for the response promised by the future and returns a
// transaction given its hash.
func (r FutureGetTxOutResult) Receive() (*btcjson.GetTxOutResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// take care of the special case where the output has been spent already
	// it should return the string "null"
	if string(res) == "null" {
		return nil, nil
	}

	// Unmarshal result as an gettxout result object.
	var txOutInfo *btcjson.GetTxOutResult
	err = json.Unmarshal(res, &txOutInfo)
	if err != nil {
		return nil, err
	}

	return txOutInfo, nil
}

// GetTxOutAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetTxOut for the blocking version and more details.
func (c *Client) GetTxOutAsync(txHash *chainhash.Hash, index uint32, mempool bool) FutureGetTxOutResult {
	hash := ""
	if txHash != nil {
		hash = txHash.String()
	}

	cmd := btcjson.NewGetTxOutCmd(hash, index, &mempool)
	return c.sendCmd(cmd)
}

// GetTxOut returns the transaction output info if it's unspent and
// nil, otherwise.
func (c *Client) GetTxOut(txHash *chainhash.Hash, index uint32, mempool bool) (*btcjson.GetTxOutResult, error) {
	return c.GetTxOutAsync(txHash, index, mempool).Receive()
}

// FutureRescanBlocksResult is a future promise to deliver the result of a
// RescanBlocksAsync RPC invocation (or an applicable error).
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrrpcclient.
type FutureRescanBlocksResult chan *response

// Receive waits for the response promised by the future and returns the
// discovered rescanblocks data.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrrpcclient.
func (r FutureRescanBlocksResult) Receive() ([]btcjson.RescannedBlock, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	var rescanBlocksResult []btcjson.RescannedBlock
	err = json.Unmarshal(res, &rescanBlocksResult)
	if err != nil {
		return nil, err
	}

	return rescanBlocksResult, nil
}

// RescanBlocksAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See RescanBlocks for the blocking version and more details.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrrpcclient.
func (c *Client) RescanBlocksAsync(blockHashes []chainhash.Hash) FutureRescanBlocksResult {
	strBlockHashes := make([]string, len(blockHashes))
	for i := range blockHashes {
		strBlockHashes[i] = blockHashes[i].String()
	}

	cmd := btcjson.NewRescanBlocksCmd(strBlockHashes)
	return c.sendCmd(cmd)
}

// RescanBlocks rescans the blocks identified by blockHashes, in order, using
// the client's loaded transaction filter.  The blocks do not need to be on the
// main chain, but they do need to be adjacent to each other.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrrpcclient.
func (c *Client) RescanBlocks(blockHashes []chainhash.Hash) ([]btcjson.RescannedBlock, error) {
	return c.RescanBlocksAsync(blockHashes).Receive()
}

// FutureInvalidateBlockResult is a future promise to deliver the result of a
// InvalidateBlockAsync RPC invocation (or an applicable error).
type FutureInvalidateBlockResult chan *response

// Receive waits for the response promised by the future and returns the raw
// block requested from the server given its hash.
func (r FutureInvalidateBlockResult) Receive() error {
	_, err := receiveFuture(r)

	return err
}

// InvalidateBlockAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See InvalidateBlock for the blocking version and more details.
func (c *Client) InvalidateBlockAsync(blockHash *chainhash.Hash) FutureInvalidateBlockResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewInvalidateBlockCmd(hash)
	return c.sendCmd(cmd)
}

// InvalidateBlock invalidates a specific block.
func (c *Client) InvalidateBlock(blockHash *chainhash.Hash) error {
	return c.InvalidateBlockAsync(blockHash).Receive()
}

// FutureGetCFilterResult is a future promise to deliver the result of a
// GetCFilterAsync RPC invocation (or an applicable error).
type FutureGetCFilterResult chan *response

// Receive waits for the response promised by the future and returns the raw
// filter requested from the server given its block hash.
func (r FutureGetCFilterResult) Receive() (*wire.MsgCFilter, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var filterHex string
	err = json.Unmarshal(res, &filterHex)
	if err != nil {
		return nil, err
	}

	// Decode the serialized cf hex to raw bytes.
	serializedFilter, err := hex.DecodeString(filterHex)
	if err != nil {
		return nil, err
	}

	// Assign the filter bytes to the correct field of the wire message.
	// We aren't going to set the block hash or extended flag, since we
	// don't actually get that back in the RPC response.
	var msgCFilter wire.MsgCFilter
	msgCFilter.Data = serializedFilter
	return &msgCFilter, nil
}

// GetCFilterAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetCFilter for the blocking version and more details.
func (c *Client) GetCFilterAsync(blockHash *chainhash.Hash,
	filterType wire.FilterType) FutureGetCFilterResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetCFilterCmd(hash, filterType)
	return c.sendCmd(cmd)
}

// GetCFilter returns a raw filter from the server given its block hash.
func (c *Client) GetCFilter(blockHash *chainhash.Hash,
	filterType wire.FilterType) (*wire.MsgCFilter, error) {
	return c.GetCFilterAsync(blockHash, filterType).Receive()
}

// FutureGetCFilterHeaderResult is a future promise to deliver the result of a
// GetCFilterHeaderAsync RPC invocation (or an applicable error).
type FutureGetCFilterHeaderResult chan *response

// Receive waits for the response promised by the future and returns the raw
// filter header requested from the server given its block hash.
func (r FutureGetCFilterHeaderResult) Receive() (*wire.MsgCFHeaders, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var headerHex string
	err = json.Unmarshal(res, &headerHex)
	if err != nil {
		return nil, err
	}

	// Assign the decoded header into a hash
	headerHash, err := chainhash.NewHashFromStr(headerHex)
	if err != nil {
		return nil, err
	}

	// Assign the hash to a headers message and return it.
	msgCFHeaders := wire.MsgCFHeaders{PrevFilterHeader: *headerHash}
	return &msgCFHeaders, nil

}

// GetCFilterHeaderAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function
// on the returned instance.
//
// See GetCFilterHeader for the blocking version and more details.
func (c *Client) GetCFilterHeaderAsync(blockHash *chainhash.Hash,
	filterType wire.FilterType) FutureGetCFilterHeaderResult {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetCFilterHeaderCmd(hash, filterType)
	return c.sendCmd(cmd)
}

// GetCFilterHeader returns a raw filter header from the server given its block
// hash.
func (c *Client) GetCFilterHeader(blockHash *chainhash.Hash,
	filterType wire.FilterType) (*wire.MsgCFHeaders, error) {
	return c.GetCFilterHeaderAsync(blockHash, filterType).Receive()
}

// FutureGetBlockStatsResult is a future promise to deliver the result of a
// GetBlockStatsAsync RPC invocation (or an applicable error).
type FutureGetBlockStatsResult chan *response

// Receive waits for the response promised by the future and returns statistics
// of a block at a certain height.
func (r FutureGetBlockStatsResult) Receive() (*btcjson.GetBlockStatsResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	var blockStats btcjson.GetBlockStatsResult
	err = json.Unmarshal(res, &blockStats)
	if err != nil {
		return nil, err
	}

	return &blockStats, nil
}

// GetBlockStatsAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetBlockStats or the blocking version and more details.
func (c *Client) GetBlockStatsAsync(hashOrHeight interface{}, stats *[]string) FutureGetBlockStatsResult {
	if hash, ok := hashOrHeight.(*chainhash.Hash); ok {
		hashOrHeight = hash.String()
	}

	cmd := btcjson.NewGetBlockStatsCmd(btcjson.HashOrHeight{Value: hashOrHeight}, stats)
	return c.sendCmd(cmd)
}

// GetBlockStats returns block statistics. First argument specifies height or hash of the target block.
// Second argument allows to select certain stats to return.
func (c *Client) GetBlockStats(hashOrHeight interface{}, stats *[]string) (*btcjson.GetBlockStatsResult, error) {
	return c.GetBlockStatsAsync(hashOrHeight, stats).Receive()
}
