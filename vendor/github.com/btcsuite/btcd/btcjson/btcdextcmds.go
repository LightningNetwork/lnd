// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: This file is intended to house the RPC commands that are supported by
// a chain server with btcd extensions.

package btcjson

// NodeSubCmd defines the type used in the addnode JSON-RPC command for the
// sub command field.
type NodeSubCmd string

const (
	// NConnect indicates the specified host that should be connected to.
	NConnect NodeSubCmd = "connect"

	// NRemove indicates the specified peer that should be removed as a
	// persistent peer.
	NRemove NodeSubCmd = "remove"

	// NDisconnect indicates the specified peer should be disonnected.
	NDisconnect NodeSubCmd = "disconnect"
)

// NodeCmd defines the dropnode JSON-RPC command.
type NodeCmd struct {
	SubCmd        NodeSubCmd `jsonrpcusage:"\"connect|remove|disconnect\""`
	Target        string
	ConnectSubCmd *string `jsonrpcusage:"\"perm|temp\""`
}

// NewNodeCmd returns a new instance which can be used to issue a `node`
// JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewNodeCmd(subCmd NodeSubCmd, target string, connectSubCmd *string) *NodeCmd {
	return &NodeCmd{
		SubCmd:        subCmd,
		Target:        target,
		ConnectSubCmd: connectSubCmd,
	}
}

// DebugLevelCmd defines the debuglevel JSON-RPC command.  This command is not a
// standard Bitcoin command.  It is an extension for btcd.
type DebugLevelCmd struct {
	LevelSpec string
}

// NewDebugLevelCmd returns a new DebugLevelCmd which can be used to issue a
// debuglevel JSON-RPC command.  This command is not a standard Bitcoin command.
// It is an extension for btcd.
func NewDebugLevelCmd(levelSpec string) *DebugLevelCmd {
	return &DebugLevelCmd{
		LevelSpec: levelSpec,
	}
}

// GenerateToAddressCmd defines the generatetoaddress JSON-RPC command.
type GenerateToAddressCmd struct {
	NumBlocks int64
	Address   string
	MaxTries  *int64 `jsonrpcdefault:"1000000"`
}

// NewGenerateToAddressCmd returns a new instance which can be used to issue a
// generatetoaddress JSON-RPC command.
func NewGenerateToAddressCmd(numBlocks int64, address string, maxTries *int64) *GenerateToAddressCmd {
	return &GenerateToAddressCmd{
		NumBlocks: numBlocks,
		Address:   address,
		MaxTries:  maxTries,
	}
}

// GenerateCmd defines the generate JSON-RPC command.
type GenerateCmd struct {
	NumBlocks uint32
}

// NewGenerateCmd returns a new instance which can be used to issue a generate
// JSON-RPC command.
func NewGenerateCmd(numBlocks uint32) *GenerateCmd {
	return &GenerateCmd{
		NumBlocks: numBlocks,
	}
}

// GetBestBlockCmd defines the getbestblock JSON-RPC command.
type GetBestBlockCmd struct{}

// NewGetBestBlockCmd returns a new instance which can be used to issue a
// getbestblock JSON-RPC command.
func NewGetBestBlockCmd() *GetBestBlockCmd {
	return &GetBestBlockCmd{}
}

// GetCurrentNetCmd defines the getcurrentnet JSON-RPC command.
type GetCurrentNetCmd struct{}

// NewGetCurrentNetCmd returns a new instance which can be used to issue a
// getcurrentnet JSON-RPC command.
func NewGetCurrentNetCmd() *GetCurrentNetCmd {
	return &GetCurrentNetCmd{}
}

// GetHeadersCmd defines the getheaders JSON-RPC command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
type GetHeadersCmd struct {
	BlockLocators []string `json:"blocklocators"`
	HashStop      string   `json:"hashstop"`
}

// NewGetHeadersCmd returns a new instance which can be used to issue a
// getheaders JSON-RPC command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
func NewGetHeadersCmd(blockLocators []string, hashStop string) *GetHeadersCmd {
	return &GetHeadersCmd{
		BlockLocators: blockLocators,
		HashStop:      hashStop,
	}
}

// VersionCmd defines the version JSON-RPC command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
type VersionCmd struct{}

// NewVersionCmd returns a new instance which can be used to issue a JSON-RPC
// version command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
func NewVersionCmd() *VersionCmd { return new(VersionCmd) }

func init() {
	// No special flags for commands in this file.
	flags := UsageFlag(0)

	MustRegisterCmd("debuglevel", (*DebugLevelCmd)(nil), flags)
	MustRegisterCmd("node", (*NodeCmd)(nil), flags)
	MustRegisterCmd("generate", (*GenerateCmd)(nil), flags)
	MustRegisterCmd("generatetoaddress", (*GenerateToAddressCmd)(nil), flags)
	MustRegisterCmd("getbestblock", (*GetBestBlockCmd)(nil), flags)
	MustRegisterCmd("getcurrentnet", (*GetCurrentNetCmd)(nil), flags)
	MustRegisterCmd("getheaders", (*GetHeadersCmd)(nil), flags)
	MustRegisterCmd("version", (*VersionCmd)(nil), flags)
}
