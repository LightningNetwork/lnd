// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// GetBlockHeaderVerboseResult models the data from the getblockheader command when
// the verbose flag is set.  When the verbose flag is not set, getblockheader
// returns a hex-encoded string.
type GetBlockHeaderVerboseResult struct {
	Hash          string  `json:"hash"`
	Confirmations int64   `json:"confirmations"`
	Height        int32   `json:"height"`
	Version       int32   `json:"version"`
	VersionHex    string  `json:"versionHex"`
	MerkleRoot    string  `json:"merkleroot"`
	Time          int64   `json:"time"`
	Nonce         uint64  `json:"nonce"`
	Bits          string  `json:"bits"`
	Difficulty    float64 `json:"difficulty"`
	PreviousHash  string  `json:"previousblockhash,omitempty"`
	NextHash      string  `json:"nextblockhash,omitempty"`
}

// GetBlockStatsResult models the data from the getblockstats command.
type GetBlockStatsResult struct {
	AverageFee         int64   `json:"avgfee"`
	AverageFeeRate     int64   `json:"avgfeerate"`
	AverageTxSize      int64   `json:"avgtxsize"`
	FeeratePercentiles []int64 `json:"feerate_percentiles"`
	Hash               string  `json:"blockhash"`
	Height             int64   `json:"height"`
	Ins                int64   `json:"ins"`
	MaxFee             int64   `json:"maxfee"`
	MaxFeeRate         int64   `json:"maxfeerate"`
	MaxTxSize          int64   `json:"maxtxsize"`
	MedianFee          int64   `json:"medianfee"`
	MedianTime         int64   `json:"mediantime"`
	MedianTxSize       int64   `json:"mediantxsize"`
	MinFee             int64   `json:"minfee"`
	MinFeeRate         int64   `json:"minfeerate"`
	MinTxSize          int64   `json:"mintxsize"`
	Outs               int64   `json:"outs"`
	SegWitTotalSize    int64   `json:"swtotal_size"`
	SegWitTotalWeight  int64   `json:"swtotal_weight"`
	SegWitTxs          int64   `json:"swtxs"`
	Subsidy            int64   `json:"subsidy"`
	Time               int64   `json:"time"`
	TotalOut           int64   `json:"total_out"`
	TotalSize          int64   `json:"total_size"`
	TotalWeight        int64   `json:"total_weight"`
	Txs                int64   `json:"txs"`
	UTXOIncrease       int64   `json:"utxo_increase"`
	UTXOSizeIncrease   int64   `json:"utxo_size_inc"`
}

// GetBlockVerboseResult models the data from the getblock command when the
// verbose flag is set to 1.  When the verbose flag is set to 0, getblock returns a
// hex-encoded string. When the verbose flag is set to 1, getblock returns an object
// whose tx field is an array of transaction hashes. When the verbose flag is set to 2,
// getblock returns an object whose tx field is an array of raw transactions.
// Use GetBlockVerboseTxResult to unmarshal data received from passing verbose=2 to getblock.
type GetBlockVerboseResult struct {
	Hash          string        `json:"hash"`
	Confirmations int64         `json:"confirmations"`
	StrippedSize  int32         `json:"strippedsize"`
	Size          int32         `json:"size"`
	Weight        int32         `json:"weight"`
	Height        int64         `json:"height"`
	Version       int32         `json:"version"`
	VersionHex    string        `json:"versionHex"`
	MerkleRoot    string        `json:"merkleroot"`
	Tx            []string      `json:"tx,omitempty"`
	RawTx         []TxRawResult `json:"rawtx,omitempty"` // Note: this field is always empty when verbose != 2.
	Time          int64         `json:"time"`
	Nonce         uint32        `json:"nonce"`
	Bits          string        `json:"bits"`
	Difficulty    float64       `json:"difficulty"`
	PreviousHash  string        `json:"previousblockhash"`
	NextHash      string        `json:"nextblockhash,omitempty"`
}

// GetBlockVerboseTxResult models the data from the getblock command when the
// verbose flag is set to 2.  When the verbose flag is set to 0, getblock returns a
// hex-encoded string. When the verbose flag is set to 1, getblock returns an object
// whose tx field is an array of transaction hashes. When the verbose flag is set to 2,
// getblock returns an object whose tx field is an array of raw transactions.
// Use GetBlockVerboseResult to unmarshal data received from passing verbose=1 to getblock.
type GetBlockVerboseTxResult struct {
	Hash          string        `json:"hash"`
	Confirmations int64         `json:"confirmations"`
	StrippedSize  int32         `json:"strippedsize"`
	Size          int32         `json:"size"`
	Weight        int32         `json:"weight"`
	Height        int64         `json:"height"`
	Version       int32         `json:"version"`
	VersionHex    string        `json:"versionHex"`
	MerkleRoot    string        `json:"merkleroot"`
	Tx            []TxRawResult `json:"tx,omitempty"`
	Time          int64         `json:"time"`
	Nonce         uint32        `json:"nonce"`
	Bits          string        `json:"bits"`
	Difficulty    float64       `json:"difficulty"`
	PreviousHash  string        `json:"previousblockhash"`
	NextHash      string        `json:"nextblockhash,omitempty"`
}

// GetChainTxStatsResult models the data from the getchaintxstats command.
type GetChainTxStatsResult struct {
	Time                   int64   `json:"time"`
	TxCount                int64   `json:"txcount"`
	WindowFinalBlockHash   string  `json:"window_final_block_hash"`
	WindowFinalBlockHeight int32   `json:"window_final_block_height"`
	WindowBlockCount       int32   `json:"window_block_count"`
	WindowTxCount          int32   `json:"window_tx_count"`
	WindowInterval         int32   `json:"window_interval"`
	TxRate                 float64 `json:"txrate"`
}

// CreateMultiSigResult models the data returned from the createmultisig
// command.
type CreateMultiSigResult struct {
	Address      string `json:"address"`
	RedeemScript string `json:"redeemScript"`
}

// DecodeScriptResult models the data returned from the decodescript command.
type DecodeScriptResult struct {
	Asm       string   `json:"asm"`
	ReqSigs   int32    `json:"reqSigs,omitempty"`
	Type      string   `json:"type"`
	Addresses []string `json:"addresses,omitempty"`
	P2sh      string   `json:"p2sh,omitempty"`
}

// GetAddedNodeInfoResultAddr models the data of the addresses portion of the
// getaddednodeinfo command.
type GetAddedNodeInfoResultAddr struct {
	Address   string `json:"address"`
	Connected string `json:"connected"`
}

// GetAddedNodeInfoResult models the data from the getaddednodeinfo command.
type GetAddedNodeInfoResult struct {
	AddedNode string                        `json:"addednode"`
	Connected *bool                         `json:"connected,omitempty"`
	Addresses *[]GetAddedNodeInfoResultAddr `json:"addresses,omitempty"`
}

// SoftForkDescription describes the current state of a soft-fork which was
// deployed using a super-majority block signalling.
type SoftForkDescription struct {
	ID      string `json:"id"`
	Version uint32 `json:"version"`
	Reject  struct {
		Status bool `json:"status"`
	} `json:"reject"`
}

// Bip9SoftForkDescription describes the current state of a defined BIP0009
// version bits soft-fork.
type Bip9SoftForkDescription struct {
	Status     string `json:"status"`
	Bit        uint8  `json:"bit"`
	StartTime1 int64  `json:"startTime"`
	StartTime2 int64  `json:"start_time"`
	Timeout    int64  `json:"timeout"`
	Since      int32  `json:"since"`
}

// StartTime returns the starting time of the softfork as a Unix epoch.
func (d *Bip9SoftForkDescription) StartTime() int64 {
	if d.StartTime1 != 0 {
		return d.StartTime1
	}
	return d.StartTime2
}

// SoftForks describes the current softforks enabled by the backend. Softforks
// activated through BIP9 are grouped together separate from any other softforks
// with different activation types.
type SoftForks struct {
	SoftForks     []*SoftForkDescription              `json:"softforks"`
	Bip9SoftForks map[string]*Bip9SoftForkDescription `json:"bip9_softforks"`
}

// UnifiedSoftForks describes a softforks in a general manner, irrespective of
// its activation type. This was a format introduced by bitcoind v0.19.0
type UnifiedSoftFork struct {
	Type                    string                   `json:"type"`
	BIP9SoftForkDescription *Bip9SoftForkDescription `json:"bip9"`
	Height                  int32                    `json:"height"`
	Active                  bool                     `json:"active"`
}

// UnifiedSoftForks describes the current softforks enabled the by the backend
// in a unified manner, i.e, softforks with different activation types are
// grouped together. This was a format introduced by bitcoind v0.19.0
type UnifiedSoftForks struct {
	SoftForks map[string]*UnifiedSoftFork `json:"softforks"`
}

// GetBlockChainInfoResult models the data returned from the getblockchaininfo
// command.
type GetBlockChainInfoResult struct {
	Chain                string  `json:"chain"`
	Blocks               int32   `json:"blocks"`
	Headers              int32   `json:"headers"`
	BestBlockHash        string  `json:"bestblockhash"`
	Difficulty           float64 `json:"difficulty"`
	MedianTime           int64   `json:"mediantime"`
	VerificationProgress float64 `json:"verificationprogress,omitempty"`
	Pruned               bool    `json:"pruned"`
	PruneHeight          int32   `json:"pruneheight,omitempty"`
	ChainWork            string  `json:"chainwork,omitempty"`
	*SoftForks
	*UnifiedSoftForks
}

// GetBlockTemplateResultTx models the transactions field of the
// getblocktemplate command.
type GetBlockTemplateResultTx struct {
	Data    string  `json:"data"`
	Hash    string  `json:"hash"`
	Depends []int64 `json:"depends"`
	Fee     int64   `json:"fee"`
	SigOps  int64   `json:"sigops"`
	Weight  int64   `json:"weight"`
}

// GetBlockTemplateResultAux models the coinbaseaux field of the
// getblocktemplate command.
type GetBlockTemplateResultAux struct {
	Flags string `json:"flags"`
}

// GetBlockTemplateResult models the data returned from the getblocktemplate
// command.
type GetBlockTemplateResult struct {
	// Base fields from BIP 0022.  CoinbaseAux is optional.  One of
	// CoinbaseTxn or CoinbaseValue must be specified, but not both.
	Bits          string                     `json:"bits"`
	CurTime       int64                      `json:"curtime"`
	Height        int64                      `json:"height"`
	PreviousHash  string                     `json:"previousblockhash"`
	SigOpLimit    int64                      `json:"sigoplimit,omitempty"`
	SizeLimit     int64                      `json:"sizelimit,omitempty"`
	WeightLimit   int64                      `json:"weightlimit,omitempty"`
	Transactions  []GetBlockTemplateResultTx `json:"transactions"`
	Version       int32                      `json:"version"`
	CoinbaseAux   *GetBlockTemplateResultAux `json:"coinbaseaux,omitempty"`
	CoinbaseTxn   *GetBlockTemplateResultTx  `json:"coinbasetxn,omitempty"`
	CoinbaseValue *int64                     `json:"coinbasevalue,omitempty"`
	WorkID        string                     `json:"workid,omitempty"`

	// Witness commitment defined in BIP 0141.
	DefaultWitnessCommitment string `json:"default_witness_commitment,omitempty"`

	// Optional long polling from BIP 0022.
	LongPollID  string `json:"longpollid,omitempty"`
	LongPollURI string `json:"longpolluri,omitempty"`
	SubmitOld   *bool  `json:"submitold,omitempty"`

	// Basic pool extension from BIP 0023.
	Target  string `json:"target,omitempty"`
	Expires int64  `json:"expires,omitempty"`

	// Mutations from BIP 0023.
	MaxTime    int64    `json:"maxtime,omitempty"`
	MinTime    int64    `json:"mintime,omitempty"`
	Mutable    []string `json:"mutable,omitempty"`
	NonceRange string   `json:"noncerange,omitempty"`

	// Block proposal from BIP 0023.
	Capabilities  []string `json:"capabilities,omitempty"`
	RejectReasion string   `json:"reject-reason,omitempty"`
}

// GetMempoolEntryResult models the data returned from the getmempoolentry's
// fee field

type MempoolFees struct {
	Base       float64 `json:"base"`
	Modified   float64 `json:"modified"`
	Ancestor   float64 `json:"ancestor"`
	Descendant float64 `json:"descendant"`
}

// GetMempoolEntryResult models the data returned from the getmempoolentry
// command.
type GetMempoolEntryResult struct {
	VSize           int32       `json:"vsize"`
	Size            int32       `json:"size"`
	Weight          int64       `json:"weight"`
	Fee             float64     `json:"fee"`
	ModifiedFee     float64     `json:"modifiedfee"`
	Time            int64       `json:"time"`
	Height          int64       `json:"height"`
	DescendantCount int64       `json:"descendantcount"`
	DescendantSize  int64       `json:"descendantsize"`
	DescendantFees  float64     `json:"descendantfees"`
	AncestorCount   int64       `json:"ancestorcount"`
	AncestorSize    int64       `json:"ancestorsize"`
	AncestorFees    float64     `json:"ancestorfees"`
	WTxId           string      `json:"wtxid"`
	Fees            MempoolFees `json:"fees"`
	Depends         []string    `json:"depends"`
}

// GetMempoolInfoResult models the data returned from the getmempoolinfo
// command.
type GetMempoolInfoResult struct {
	Size  int64 `json:"size"`
	Bytes int64 `json:"bytes"`
}

// NetworksResult models the networks data from the getnetworkinfo command.
type NetworksResult struct {
	Name                      string `json:"name"`
	Limited                   bool   `json:"limited"`
	Reachable                 bool   `json:"reachable"`
	Proxy                     string `json:"proxy"`
	ProxyRandomizeCredentials bool   `json:"proxy_randomize_credentials"`
}

// LocalAddressesResult models the localaddresses data from the getnetworkinfo
// command.
type LocalAddressesResult struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Score   int32  `json:"score"`
}

// GetNetworkInfoResult models the data returned from the getnetworkinfo
// command.
type GetNetworkInfoResult struct {
	Version         int32                  `json:"version"`
	SubVersion      string                 `json:"subversion"`
	ProtocolVersion int32                  `json:"protocolversion"`
	LocalServices   string                 `json:"localservices"`
	LocalRelay      bool                   `json:"localrelay"`
	TimeOffset      int64                  `json:"timeoffset"`
	Connections     int32                  `json:"connections"`
	NetworkActive   bool                   `json:"networkactive"`
	Networks        []NetworksResult       `json:"networks"`
	RelayFee        float64                `json:"relayfee"`
	IncrementalFee  float64                `json:"incrementalfee"`
	LocalAddresses  []LocalAddressesResult `json:"localaddresses"`
	Warnings        string                 `json:"warnings"`
}

// GetPeerInfoResult models the data returned from the getpeerinfo command.
type GetPeerInfoResult struct {
	ID             int32   `json:"id"`
	Addr           string  `json:"addr"`
	AddrLocal      string  `json:"addrlocal,omitempty"`
	Services       string  `json:"services"`
	RelayTxes      bool    `json:"relaytxes"`
	LastSend       int64   `json:"lastsend"`
	LastRecv       int64   `json:"lastrecv"`
	BytesSent      uint64  `json:"bytessent"`
	BytesRecv      uint64  `json:"bytesrecv"`
	ConnTime       int64   `json:"conntime"`
	TimeOffset     int64   `json:"timeoffset"`
	PingTime       float64 `json:"pingtime"`
	PingWait       float64 `json:"pingwait,omitempty"`
	Version        uint32  `json:"version"`
	SubVer         string  `json:"subver"`
	Inbound        bool    `json:"inbound"`
	StartingHeight int32   `json:"startingheight"`
	CurrentHeight  int32   `json:"currentheight,omitempty"`
	BanScore       int32   `json:"banscore"`
	FeeFilter      int64   `json:"feefilter"`
	SyncNode       bool    `json:"syncnode"`
}

// GetRawMempoolVerboseResult models the data returned from the getrawmempool
// command when the verbose flag is set.  When the verbose flag is not set,
// getrawmempool returns an array of transaction hashes.
type GetRawMempoolVerboseResult struct {
	Size             int32    `json:"size"`
	Vsize            int32    `json:"vsize"`
	Weight           int32    `json:"weight"`
	Fee              float64  `json:"fee"`
	Time             int64    `json:"time"`
	Height           int64    `json:"height"`
	StartingPriority float64  `json:"startingpriority"`
	CurrentPriority  float64  `json:"currentpriority"`
	Depends          []string `json:"depends"`
}

// ScriptPubKeyResult models the scriptPubKey data of a tx script.  It is
// defined separately since it is used by multiple commands.
type ScriptPubKeyResult struct {
	Asm       string   `json:"asm"`
	Hex       string   `json:"hex,omitempty"`
	ReqSigs   int32    `json:"reqSigs,omitempty"`
	Type      string   `json:"type"`
	Addresses []string `json:"addresses,omitempty"`
}

// GetTxOutResult models the data from the gettxout command.
type GetTxOutResult struct {
	BestBlock     string             `json:"bestblock"`
	Confirmations int64              `json:"confirmations"`
	Value         float64            `json:"value"`
	ScriptPubKey  ScriptPubKeyResult `json:"scriptPubKey"`
	Coinbase      bool               `json:"coinbase"`
}

// GetNetTotalsResult models the data returned from the getnettotals command.
type GetNetTotalsResult struct {
	TotalBytesRecv uint64 `json:"totalbytesrecv"`
	TotalBytesSent uint64 `json:"totalbytessent"`
	TimeMillis     int64  `json:"timemillis"`
}

// ScriptSig models a signature script.  It is defined separately since it only
// applies to non-coinbase.  Therefore the field in the Vin structure needs
// to be a pointer.
type ScriptSig struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

// Vin models parts of the tx data.  It is defined separately since
// getrawtransaction, decoderawtransaction, and searchrawtransaction use the
// same structure.
type Vin struct {
	Coinbase  string     `json:"coinbase"`
	Txid      string     `json:"txid"`
	Vout      uint32     `json:"vout"`
	ScriptSig *ScriptSig `json:"scriptSig"`
	Sequence  uint32     `json:"sequence"`
	Witness   []string   `json:"txinwitness"`
}

// IsCoinBase returns a bool to show if a Vin is a Coinbase one or not.
func (v *Vin) IsCoinBase() bool {
	return len(v.Coinbase) > 0
}

// HasWitness returns a bool to show if a Vin has any witness data associated
// with it or not.
func (v *Vin) HasWitness() bool {
	return len(v.Witness) > 0
}

// MarshalJSON provides a custom Marshal method for Vin.
func (v *Vin) MarshalJSON() ([]byte, error) {
	if v.IsCoinBase() {
		coinbaseStruct := struct {
			Coinbase string   `json:"coinbase"`
			Sequence uint32   `json:"sequence"`
			Witness  []string `json:"witness,omitempty"`
		}{
			Coinbase: v.Coinbase,
			Sequence: v.Sequence,
			Witness:  v.Witness,
		}
		return json.Marshal(coinbaseStruct)
	}

	if v.HasWitness() {
		txStruct := struct {
			Txid      string     `json:"txid"`
			Vout      uint32     `json:"vout"`
			ScriptSig *ScriptSig `json:"scriptSig"`
			Witness   []string   `json:"txinwitness"`
			Sequence  uint32     `json:"sequence"`
		}{
			Txid:      v.Txid,
			Vout:      v.Vout,
			ScriptSig: v.ScriptSig,
			Witness:   v.Witness,
			Sequence:  v.Sequence,
		}
		return json.Marshal(txStruct)
	}

	txStruct := struct {
		Txid      string     `json:"txid"`
		Vout      uint32     `json:"vout"`
		ScriptSig *ScriptSig `json:"scriptSig"`
		Sequence  uint32     `json:"sequence"`
	}{
		Txid:      v.Txid,
		Vout:      v.Vout,
		ScriptSig: v.ScriptSig,
		Sequence:  v.Sequence,
	}
	return json.Marshal(txStruct)
}

// PrevOut represents previous output for an input Vin.
type PrevOut struct {
	Addresses []string `json:"addresses,omitempty"`
	Value     float64  `json:"value"`
}

// VinPrevOut is like Vin except it includes PrevOut.  It is used by searchrawtransaction
type VinPrevOut struct {
	Coinbase  string     `json:"coinbase"`
	Txid      string     `json:"txid"`
	Vout      uint32     `json:"vout"`
	ScriptSig *ScriptSig `json:"scriptSig"`
	Witness   []string   `json:"txinwitness"`
	PrevOut   *PrevOut   `json:"prevOut"`
	Sequence  uint32     `json:"sequence"`
}

// IsCoinBase returns a bool to show if a Vin is a Coinbase one or not.
func (v *VinPrevOut) IsCoinBase() bool {
	return len(v.Coinbase) > 0
}

// HasWitness returns a bool to show if a Vin has any witness data associated
// with it or not.
func (v *VinPrevOut) HasWitness() bool {
	return len(v.Witness) > 0
}

// MarshalJSON provides a custom Marshal method for VinPrevOut.
func (v *VinPrevOut) MarshalJSON() ([]byte, error) {
	if v.IsCoinBase() {
		coinbaseStruct := struct {
			Coinbase string `json:"coinbase"`
			Sequence uint32 `json:"sequence"`
		}{
			Coinbase: v.Coinbase,
			Sequence: v.Sequence,
		}
		return json.Marshal(coinbaseStruct)
	}

	if v.HasWitness() {
		txStruct := struct {
			Txid      string     `json:"txid"`
			Vout      uint32     `json:"vout"`
			ScriptSig *ScriptSig `json:"scriptSig"`
			Witness   []string   `json:"txinwitness"`
			PrevOut   *PrevOut   `json:"prevOut,omitempty"`
			Sequence  uint32     `json:"sequence"`
		}{
			Txid:      v.Txid,
			Vout:      v.Vout,
			ScriptSig: v.ScriptSig,
			Witness:   v.Witness,
			PrevOut:   v.PrevOut,
			Sequence:  v.Sequence,
		}
		return json.Marshal(txStruct)
	}

	txStruct := struct {
		Txid      string     `json:"txid"`
		Vout      uint32     `json:"vout"`
		ScriptSig *ScriptSig `json:"scriptSig"`
		PrevOut   *PrevOut   `json:"prevOut,omitempty"`
		Sequence  uint32     `json:"sequence"`
	}{
		Txid:      v.Txid,
		Vout:      v.Vout,
		ScriptSig: v.ScriptSig,
		PrevOut:   v.PrevOut,
		Sequence:  v.Sequence,
	}
	return json.Marshal(txStruct)
}

// Vout models parts of the tx data.  It is defined separately since both
// getrawtransaction and decoderawtransaction use the same structure.
type Vout struct {
	Value        float64            `json:"value"`
	N            uint32             `json:"n"`
	ScriptPubKey ScriptPubKeyResult `json:"scriptPubKey"`
}

// GetMiningInfoResult models the data from the getmininginfo command.
type GetMiningInfoResult struct {
	Blocks             int64   `json:"blocks"`
	CurrentBlockSize   uint64  `json:"currentblocksize"`
	CurrentBlockWeight uint64  `json:"currentblockweight"`
	CurrentBlockTx     uint64  `json:"currentblocktx"`
	Difficulty         float64 `json:"difficulty"`
	Errors             string  `json:"errors"`
	Generate           bool    `json:"generate"`
	GenProcLimit       int32   `json:"genproclimit"`
	HashesPerSec       int64   `json:"hashespersec"`
	NetworkHashPS      int64   `json:"networkhashps"`
	PooledTx           uint64  `json:"pooledtx"`
	TestNet            bool    `json:"testnet"`
}

// GetWorkResult models the data from the getwork command.
type GetWorkResult struct {
	Data     string `json:"data"`
	Hash1    string `json:"hash1"`
	Midstate string `json:"midstate"`
	Target   string `json:"target"`
}

// InfoChainResult models the data returned by the chain server getinfo command.
type InfoChainResult struct {
	Version         int32   `json:"version"`
	ProtocolVersion int32   `json:"protocolversion"`
	Blocks          int32   `json:"blocks"`
	TimeOffset      int64   `json:"timeoffset"`
	Connections     int32   `json:"connections"`
	Proxy           string  `json:"proxy"`
	Difficulty      float64 `json:"difficulty"`
	TestNet         bool    `json:"testnet"`
	RelayFee        float64 `json:"relayfee"`
	Errors          string  `json:"errors"`
}

// TxRawResult models the data from the getrawtransaction command.
type TxRawResult struct {
	Hex           string `json:"hex"`
	Txid          string `json:"txid"`
	Hash          string `json:"hash,omitempty"`
	Size          int32  `json:"size,omitempty"`
	Vsize         int32  `json:"vsize,omitempty"`
	Weight        int32  `json:"weight,omitempty"`
	Version       int32  `json:"version"`
	LockTime      uint32 `json:"locktime"`
	Vin           []Vin  `json:"vin"`
	Vout          []Vout `json:"vout"`
	BlockHash     string `json:"blockhash,omitempty"`
	Confirmations uint64 `json:"confirmations,omitempty"`
	Time          int64  `json:"time,omitempty"`
	Blocktime     int64  `json:"blocktime,omitempty"`
}

// SearchRawTransactionsResult models the data from the searchrawtransaction
// command.
type SearchRawTransactionsResult struct {
	Hex           string       `json:"hex,omitempty"`
	Txid          string       `json:"txid"`
	Hash          string       `json:"hash"`
	Size          string       `json:"size"`
	Vsize         string       `json:"vsize"`
	Weight        string       `json:"weight"`
	Version       int32        `json:"version"`
	LockTime      uint32       `json:"locktime"`
	Vin           []VinPrevOut `json:"vin"`
	Vout          []Vout       `json:"vout"`
	BlockHash     string       `json:"blockhash,omitempty"`
	Confirmations uint64       `json:"confirmations,omitempty"`
	Time          int64        `json:"time,omitempty"`
	Blocktime     int64        `json:"blocktime,omitempty"`
}

// TxRawDecodeResult models the data from the decoderawtransaction command.
type TxRawDecodeResult struct {
	Txid     string `json:"txid"`
	Version  int32  `json:"version"`
	Locktime uint32 `json:"locktime"`
	Vin      []Vin  `json:"vin"`
	Vout     []Vout `json:"vout"`
}

// ValidateAddressChainResult models the data returned by the chain server
// validateaddress command.
type ValidateAddressChainResult struct {
	IsValid bool   `json:"isvalid"`
	Address string `json:"address,omitempty"`
}

// EstimateSmartFeeResult models the data returned buy the chain server
// estimatesmartfee command
type EstimateSmartFeeResult struct {
	FeeRate *float64 `json:"feerate,omitempty"`
	Errors  []string `json:"errors,omitempty"`
	Blocks  int64    `json:"blocks"`
}

var _ json.Unmarshaler = &FundRawTransactionResult{}

type rawFundRawTransactionResult struct {
	Transaction    string  `json:"hex"`
	Fee            float64 `json:"fee"`
	ChangePosition int     `json:"changepos"`
}

// FundRawTransactionResult is the result of the fundrawtransaction JSON-RPC call
type FundRawTransactionResult struct {
	Transaction    *wire.MsgTx
	Fee            btcutil.Amount
	ChangePosition int // the position of the added change output, or -1
}

// UnmarshalJSON unmarshals the result of the fundrawtransaction JSON-RPC call
func (f *FundRawTransactionResult) UnmarshalJSON(data []byte) error {
	var rawRes rawFundRawTransactionResult
	if err := json.Unmarshal(data, &rawRes); err != nil {
		return err
	}

	txBytes, err := hex.DecodeString(rawRes.Transaction)
	if err != nil {
		return err
	}

	var msgTx wire.MsgTx
	witnessErr := msgTx.Deserialize(bytes.NewReader(txBytes))
	if witnessErr != nil {
		legacyErr := msgTx.DeserializeNoWitness(bytes.NewReader(txBytes))
		if legacyErr != nil {
			return legacyErr
		}
	}

	fee, err := btcutil.NewAmount(rawRes.Fee)
	if err != nil {
		return err
	}

	f.Transaction = &msgTx
	f.Fee = fee
	f.ChangePosition = rawRes.ChangePosition
	return nil
}
