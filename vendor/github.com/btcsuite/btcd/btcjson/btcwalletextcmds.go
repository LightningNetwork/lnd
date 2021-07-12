// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: This file is intended to house the RPC commands that are supported by
// a wallet server with btcwallet extensions.

package btcjson

// CreateNewAccountCmd defines the createnewaccount JSON-RPC command.
type CreateNewAccountCmd struct {
	Account string
}

// NewCreateNewAccountCmd returns a new instance which can be used to issue a
// createnewaccount JSON-RPC command.
func NewCreateNewAccountCmd(account string) *CreateNewAccountCmd {
	return &CreateNewAccountCmd{
		Account: account,
	}
}

// DumpWalletCmd defines the dumpwallet JSON-RPC command.
type DumpWalletCmd struct {
	Filename string
}

// NewDumpWalletCmd returns a new instance which can be used to issue a
// dumpwallet JSON-RPC command.
func NewDumpWalletCmd(filename string) *DumpWalletCmd {
	return &DumpWalletCmd{
		Filename: filename,
	}
}

// ImportAddressCmd defines the importaddress JSON-RPC command.
type ImportAddressCmd struct {
	Address string
	Account string
	Rescan  *bool `jsonrpcdefault:"true"`
}

// NewImportAddressCmd returns a new instance which can be used to issue an
// importaddress JSON-RPC command.
func NewImportAddressCmd(address string, account string, rescan *bool) *ImportAddressCmd {
	return &ImportAddressCmd{
		Address: address,
		Account: account,
		Rescan:  rescan,
	}
}

// ImportPubKeyCmd defines the importpubkey JSON-RPC command.
type ImportPubKeyCmd struct {
	PubKey string
	Rescan *bool `jsonrpcdefault:"true"`
}

// NewImportPubKeyCmd returns a new instance which can be used to issue an
// importpubkey JSON-RPC command.
func NewImportPubKeyCmd(pubKey string, rescan *bool) *ImportPubKeyCmd {
	return &ImportPubKeyCmd{
		PubKey: pubKey,
		Rescan: rescan,
	}
}

// ImportWalletCmd defines the importwallet JSON-RPC command.
type ImportWalletCmd struct {
	Filename string
}

// NewImportWalletCmd returns a new instance which can be used to issue a
// importwallet JSON-RPC command.
func NewImportWalletCmd(filename string) *ImportWalletCmd {
	return &ImportWalletCmd{
		Filename: filename,
	}
}

// RenameAccountCmd defines the renameaccount JSON-RPC command.
type RenameAccountCmd struct {
	OldAccount string
	NewAccount string
}

// NewRenameAccountCmd returns a new instance which can be used to issue a
// renameaccount JSON-RPC command.
func NewRenameAccountCmd(oldAccount, newAccount string) *RenameAccountCmd {
	return &RenameAccountCmd{
		OldAccount: oldAccount,
		NewAccount: newAccount,
	}
}

func init() {
	// The commands in this file are only usable with a wallet server.
	flags := UFWalletOnly

	MustRegisterCmd("createnewaccount", (*CreateNewAccountCmd)(nil), flags)
	MustRegisterCmd("dumpwallet", (*DumpWalletCmd)(nil), flags)
	MustRegisterCmd("importaddress", (*ImportAddressCmd)(nil), flags)
	MustRegisterCmd("importpubkey", (*ImportPubKeyCmd)(nil), flags)
	MustRegisterCmd("importwallet", (*ImportWalletCmd)(nil), flags)
	MustRegisterCmd("renameaccount", (*RenameAccountCmd)(nil), flags)
}
