// Copyright (c) 2014-2017 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: This file is intended to house the RPC commands that are supported by
// a chain server, but are only available via websockets.

package btcjson

// AuthenticateCmd defines the authenticate JSON-RPC command.
type AuthenticateCmd struct {
	Username   string
	Passphrase string
}

// NewAuthenticateCmd returns a new instance which can be used to issue an
// authenticate JSON-RPC command.
func NewAuthenticateCmd(username, passphrase string) *AuthenticateCmd {
	return &AuthenticateCmd{
		Username:   username,
		Passphrase: passphrase,
	}
}

// NotifyBlocksCmd defines the notifyblocks JSON-RPC command.
type NotifyBlocksCmd struct{}

// NewNotifyBlocksCmd returns a new instance which can be used to issue a
// notifyblocks JSON-RPC command.
func NewNotifyBlocksCmd() *NotifyBlocksCmd {
	return &NotifyBlocksCmd{}
}

// StopNotifyBlocksCmd defines the stopnotifyblocks JSON-RPC command.
type StopNotifyBlocksCmd struct{}

// NewStopNotifyBlocksCmd returns a new instance which can be used to issue a
// stopnotifyblocks JSON-RPC command.
func NewStopNotifyBlocksCmd() *StopNotifyBlocksCmd {
	return &StopNotifyBlocksCmd{}
}

// NotifyNewTransactionsCmd defines the notifynewtransactions JSON-RPC command.
type NotifyNewTransactionsCmd struct {
	Verbose *bool `jsonrpcdefault:"false"`
}

// NewNotifyNewTransactionsCmd returns a new instance which can be used to issue
// a notifynewtransactions JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewNotifyNewTransactionsCmd(verbose *bool) *NotifyNewTransactionsCmd {
	return &NotifyNewTransactionsCmd{
		Verbose: verbose,
	}
}

// SessionCmd defines the session JSON-RPC command.
type SessionCmd struct{}

// NewSessionCmd returns a new instance which can be used to issue a session
// JSON-RPC command.
func NewSessionCmd() *SessionCmd {
	return &SessionCmd{}
}

// StopNotifyNewTransactionsCmd defines the stopnotifynewtransactions JSON-RPC command.
type StopNotifyNewTransactionsCmd struct{}

// NewStopNotifyNewTransactionsCmd returns a new instance which can be used to issue
// a stopnotifynewtransactions JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewStopNotifyNewTransactionsCmd() *StopNotifyNewTransactionsCmd {
	return &StopNotifyNewTransactionsCmd{}
}

// NotifyReceivedCmd defines the notifyreceived JSON-RPC command.
//
// Deprecated: Use LoadTxFilterCmd instead.
type NotifyReceivedCmd struct {
	Addresses []string
}

// NewNotifyReceivedCmd returns a new instance which can be used to issue a
// notifyreceived JSON-RPC command.
//
// Deprecated: Use NewLoadTxFilterCmd instead.
func NewNotifyReceivedCmd(addresses []string) *NotifyReceivedCmd {
	return &NotifyReceivedCmd{
		Addresses: addresses,
	}
}

// OutPoint describes a transaction outpoint that will be marshalled to and
// from JSON.
type OutPoint struct {
	Hash  string `json:"hash"`
	Index uint32 `json:"index"`
}

// LoadTxFilterCmd defines the loadtxfilter request parameters to load or
// reload a transaction filter.
//
// NOTE: This is a btcd extension ported from github.com/decred/dcrd/dcrjson
// and requires a websocket connection.
type LoadTxFilterCmd struct {
	Reload    bool
	Addresses []string
	OutPoints []OutPoint
}

// NewLoadTxFilterCmd returns a new instance which can be used to issue a
// loadtxfilter JSON-RPC command.
//
// NOTE: This is a btcd extension ported from github.com/decred/dcrd/dcrjson
// and requires a websocket connection.
func NewLoadTxFilterCmd(reload bool, addresses []string, outPoints []OutPoint) *LoadTxFilterCmd {
	return &LoadTxFilterCmd{
		Reload:    reload,
		Addresses: addresses,
		OutPoints: outPoints,
	}
}

// NotifySpentCmd defines the notifyspent JSON-RPC command.
//
// Deprecated: Use LoadTxFilterCmd instead.
type NotifySpentCmd struct {
	OutPoints []OutPoint
}

// NewNotifySpentCmd returns a new instance which can be used to issue a
// notifyspent JSON-RPC command.
//
// Deprecated: Use NewLoadTxFilterCmd instead.
func NewNotifySpentCmd(outPoints []OutPoint) *NotifySpentCmd {
	return &NotifySpentCmd{
		OutPoints: outPoints,
	}
}

// StopNotifyReceivedCmd defines the stopnotifyreceived JSON-RPC command.
//
// Deprecated: Use LoadTxFilterCmd instead.
type StopNotifyReceivedCmd struct {
	Addresses []string
}

// NewStopNotifyReceivedCmd returns a new instance which can be used to issue a
// stopnotifyreceived JSON-RPC command.
//
// Deprecated: Use NewLoadTxFilterCmd instead.
func NewStopNotifyReceivedCmd(addresses []string) *StopNotifyReceivedCmd {
	return &StopNotifyReceivedCmd{
		Addresses: addresses,
	}
}

// StopNotifySpentCmd defines the stopnotifyspent JSON-RPC command.
//
// Deprecated: Use LoadTxFilterCmd instead.
type StopNotifySpentCmd struct {
	OutPoints []OutPoint
}

// NewStopNotifySpentCmd returns a new instance which can be used to issue a
// stopnotifyspent JSON-RPC command.
//
// Deprecated: Use NewLoadTxFilterCmd instead.
func NewStopNotifySpentCmd(outPoints []OutPoint) *StopNotifySpentCmd {
	return &StopNotifySpentCmd{
		OutPoints: outPoints,
	}
}

// RescanCmd defines the rescan JSON-RPC command.
//
// Deprecated: Use RescanBlocksCmd instead.
type RescanCmd struct {
	BeginBlock string
	Addresses  []string
	OutPoints  []OutPoint
	EndBlock   *string
}

// NewRescanCmd returns a new instance which can be used to issue a rescan
// JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
//
// Deprecated: Use NewRescanBlocksCmd instead.
func NewRescanCmd(beginBlock string, addresses []string, outPoints []OutPoint, endBlock *string) *RescanCmd {
	return &RescanCmd{
		BeginBlock: beginBlock,
		Addresses:  addresses,
		OutPoints:  outPoints,
		EndBlock:   endBlock,
	}
}

// RescanBlocksCmd defines the rescan JSON-RPC command.
//
// NOTE: This is a btcd extension ported from github.com/decred/dcrd/dcrjson
// and requires a websocket connection.
type RescanBlocksCmd struct {
	// Block hashes as a string array.
	BlockHashes []string
}

// NewRescanBlocksCmd returns a new instance which can be used to issue a rescan
// JSON-RPC command.
//
// NOTE: This is a btcd extension ported from github.com/decred/dcrd/dcrjson
// and requires a websocket connection.
func NewRescanBlocksCmd(blockHashes []string) *RescanBlocksCmd {
	return &RescanBlocksCmd{BlockHashes: blockHashes}
}

func init() {
	// The commands in this file are only usable by websockets.
	flags := UFWebsocketOnly

	MustRegisterCmd("authenticate", (*AuthenticateCmd)(nil), flags)
	MustRegisterCmd("loadtxfilter", (*LoadTxFilterCmd)(nil), flags)
	MustRegisterCmd("notifyblocks", (*NotifyBlocksCmd)(nil), flags)
	MustRegisterCmd("notifynewtransactions", (*NotifyNewTransactionsCmd)(nil), flags)
	MustRegisterCmd("notifyreceived", (*NotifyReceivedCmd)(nil), flags)
	MustRegisterCmd("notifyspent", (*NotifySpentCmd)(nil), flags)
	MustRegisterCmd("session", (*SessionCmd)(nil), flags)
	MustRegisterCmd("stopnotifyblocks", (*StopNotifyBlocksCmd)(nil), flags)
	MustRegisterCmd("stopnotifynewtransactions", (*StopNotifyNewTransactionsCmd)(nil), flags)
	MustRegisterCmd("stopnotifyspent", (*StopNotifySpentCmd)(nil), flags)
	MustRegisterCmd("stopnotifyreceived", (*StopNotifyReceivedCmd)(nil), flags)
	MustRegisterCmd("rescan", (*RescanCmd)(nil), flags)
	MustRegisterCmd("rescanblocks", (*RescanBlocksCmd)(nil), flags)
}
