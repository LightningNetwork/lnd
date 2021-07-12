// Copyright (c) 2016 The Decred developers
// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// Note: The following common types should never reference the Wallet type.
// Long term goal is to move these to their own package so that the database
// access APIs can create them directly for the wallet to return.

// BlockIdentity identifies a block, or the lack of one (used to describe an
// unmined transaction).
type BlockIdentity struct {
	Hash   chainhash.Hash
	Height int32
}

// None returns whether there is no block described by the instance.  When
// associated with a transaction, this indicates the transaction is unmined.
func (b *BlockIdentity) None() bool {
	// BUG: Because dcrwallet uses both 0 and -1 in various places to refer
	// to an unmined transaction this must check against both and may not
	// ever be usable to represent the genesis block.
	return *b == BlockIdentity{Height: -1} || *b == BlockIdentity{}
}

// OutputKind describes a kind of transaction output.  This is used to
// differentiate between coinbase, stakebase, and normal outputs.
type OutputKind byte

// Defined OutputKind constants
const (
	OutputKindNormal OutputKind = iota
	OutputKindCoinbase
)

// TransactionOutput describes an output that was or is at least partially
// controlled by the wallet.  Depending on context, this could refer to an
// unspent output, or a spent one.
type TransactionOutput struct {
	OutPoint   wire.OutPoint
	Output     wire.TxOut
	OutputKind OutputKind
	// These should be added later when the DB can return them more
	// efficiently:
	//TxLockTime      uint32
	//TxExpiry        uint32
	ContainingBlock BlockIdentity
	ReceiveTime     time.Time
}

// OutputRedeemer identifies the transaction input which redeems an output.
type OutputRedeemer struct {
	TxHash     chainhash.Hash
	InputIndex uint32
}

// P2SHMultiSigOutput describes a transaction output with a pay-to-script-hash
// output script and an imported redemption script.  Along with common details
// of the output, this structure also includes the P2SH address the script was
// created from and the number of signatures required to redeem it.
//
// TODO: Could be useful to return how many of the required signatures can be
// created by this wallet.
type P2SHMultiSigOutput struct {
	// TODO: Add a TransactionOutput member to this struct and remove these
	// fields which are duplicated by it.  This improves consistency.  Only
	// not done now because wtxmgr APIs don't support an efficient way of
	// fetching other Transactionoutput data together with the rest of the
	// multisig info.
	OutPoint        wire.OutPoint
	OutputAmount    btcutil.Amount
	ContainingBlock BlockIdentity

	P2SHAddress  *btcutil.AddressScriptHash
	RedeemScript []byte
	M, N         uint8           // M of N signatures required to redeem
	Redeemer     *OutputRedeemer // nil unless spent
}
