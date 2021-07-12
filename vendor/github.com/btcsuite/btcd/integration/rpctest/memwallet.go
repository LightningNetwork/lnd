// Copyright (c) 2016-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpctest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
)

var (
	// hdSeed is the BIP 32 seed used by the memWallet to initialize it's
	// HD root key. This value is hard coded in order to ensure
	// deterministic behavior across test runs.
	hdSeed = [chainhash.HashSize]byte{
		0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1,
		0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e, 0xc7, 0xc8,
		0x75, 0x63, 0x2e, 0x75, 0xf1, 0xdf, 0x9c, 0x3f,
		0xa6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

// utxo represents an unspent output spendable by the memWallet. The maturity
// height of the transaction is recorded in order to properly observe the
// maturity period of direct coinbase outputs.
type utxo struct {
	pkScript       []byte
	value          btcutil.Amount
	keyIndex       uint32
	maturityHeight int32
	isLocked       bool
}

// isMature returns true if the target utxo is considered "mature" at the
// passed block height. Otherwise, false is returned.
func (u *utxo) isMature(height int32) bool {
	return height >= u.maturityHeight
}

// chainUpdate encapsulates an update to the current main chain. This struct is
// used to sync up the memWallet each time a new block is connected to the main
// chain.
type chainUpdate struct {
	blockHeight  int32
	filteredTxns []*btcutil.Tx
	isConnect    bool // True if connect, false if disconnect
}

// undoEntry is functionally the opposite of a chainUpdate. An undoEntry is
// created for each new block received, then stored in a log in order to
// properly handle block re-orgs.
type undoEntry struct {
	utxosDestroyed map[wire.OutPoint]*utxo
	utxosCreated   []wire.OutPoint
}

// memWallet is a simple in-memory wallet whose purpose is to provide basic
// wallet functionality to the harness. The wallet uses a hard-coded HD key
// hierarchy which promotes reproducibility between harness test runs.
type memWallet struct {
	coinbaseKey  *btcec.PrivateKey
	coinbaseAddr btcutil.Address

	// hdRoot is the root master private key for the wallet.
	hdRoot *hdkeychain.ExtendedKey

	// hdIndex is the next available key index offset from the hdRoot.
	hdIndex uint32

	// currentHeight is the latest height the wallet is known to be synced
	// to.
	currentHeight int32

	// addrs tracks all addresses belonging to the wallet. The addresses
	// are indexed by their keypath from the hdRoot.
	addrs map[uint32]btcutil.Address

	// utxos is the set of utxos spendable by the wallet.
	utxos map[wire.OutPoint]*utxo

	// reorgJournal is a map storing an undo entry for each new block
	// received. Once a block is disconnected, the undo entry for the
	// particular height is evaluated, thereby rewinding the effect of the
	// disconnected block on the wallet's set of spendable utxos.
	reorgJournal map[int32]*undoEntry

	chainUpdates      []*chainUpdate
	chainUpdateSignal chan struct{}
	chainMtx          sync.Mutex

	net *chaincfg.Params

	rpc *rpcclient.Client

	sync.RWMutex
}

// newMemWallet creates and returns a fully initialized instance of the
// memWallet given a particular blockchain's parameters.
func newMemWallet(net *chaincfg.Params, harnessID uint32) (*memWallet, error) {
	// The wallet's final HD seed is: hdSeed || harnessID. This method
	// ensures that each harness instance uses a deterministic root seed
	// based on its harness ID.
	var harnessHDSeed [chainhash.HashSize + 4]byte
	copy(harnessHDSeed[:], hdSeed[:])
	binary.BigEndian.PutUint32(harnessHDSeed[:chainhash.HashSize], harnessID)

	hdRoot, err := hdkeychain.NewMaster(harnessHDSeed[:], net)
	if err != nil {
		return nil, nil
	}

	// The first child key from the hd root is reserved as the coinbase
	// generation address.
	coinbaseChild, err := hdRoot.Child(0)
	if err != nil {
		return nil, err
	}
	coinbaseKey, err := coinbaseChild.ECPrivKey()
	if err != nil {
		return nil, err
	}
	coinbaseAddr, err := keyToAddr(coinbaseKey, net)
	if err != nil {
		return nil, err
	}

	// Track the coinbase generation address to ensure we properly track
	// newly generated bitcoin we can spend.
	addrs := make(map[uint32]btcutil.Address)
	addrs[0] = coinbaseAddr

	return &memWallet{
		net:               net,
		coinbaseKey:       coinbaseKey,
		coinbaseAddr:      coinbaseAddr,
		hdIndex:           1,
		hdRoot:            hdRoot,
		addrs:             addrs,
		utxos:             make(map[wire.OutPoint]*utxo),
		chainUpdateSignal: make(chan struct{}),
		reorgJournal:      make(map[int32]*undoEntry),
	}, nil
}

// Start launches all goroutines required for the wallet to function properly.
func (m *memWallet) Start() {
	go m.chainSyncer()
}

// SyncedHeight returns the height the wallet is known to be synced to.
//
// This function is safe for concurrent access.
func (m *memWallet) SyncedHeight() int32 {
	m.RLock()
	defer m.RUnlock()
	return m.currentHeight
}

// SetRPCClient saves the passed rpc connection to btcd as the wallet's
// personal rpc connection.
func (m *memWallet) SetRPCClient(rpcClient *rpcclient.Client) {
	m.rpc = rpcClient
}

// IngestBlock is a call-back which is to be triggered each time a new block is
// connected to the main chain. It queues the update for the chain syncer,
// calling the private version in sequential order.
func (m *memWallet) IngestBlock(height int32, header *wire.BlockHeader, filteredTxns []*btcutil.Tx) {
	// Append this new chain update to the end of the queue of new chain
	// updates.
	m.chainMtx.Lock()
	m.chainUpdates = append(m.chainUpdates, &chainUpdate{height,
		filteredTxns, true})
	m.chainMtx.Unlock()

	// Launch a goroutine to signal the chainSyncer that a new update is
	// available. We do this in a new goroutine in order to avoid blocking
	// the main loop of the rpc client.
	go func() {
		m.chainUpdateSignal <- struct{}{}
	}()
}

// ingestBlock updates the wallet's internal utxo state based on the outputs
// created and destroyed within each block.
func (m *memWallet) ingestBlock(update *chainUpdate) {
	// Update the latest synced height, then process each filtered
	// transaction in the block creating and destroying utxos within
	// the wallet as a result.
	m.currentHeight = update.blockHeight
	undo := &undoEntry{
		utxosDestroyed: make(map[wire.OutPoint]*utxo),
	}
	for _, tx := range update.filteredTxns {
		mtx := tx.MsgTx()
		isCoinbase := blockchain.IsCoinBaseTx(mtx)
		txHash := mtx.TxHash()
		m.evalOutputs(mtx.TxOut, &txHash, isCoinbase, undo)
		m.evalInputs(mtx.TxIn, undo)
	}

	// Finally, record the undo entry for this block so we can
	// properly update our internal state in response to the block
	// being re-org'd from the main chain.
	m.reorgJournal[update.blockHeight] = undo
}

// chainSyncer is a goroutine dedicated to processing new blocks in order to
// keep the wallet's utxo state up to date.
//
// NOTE: This MUST be run as a goroutine.
func (m *memWallet) chainSyncer() {
	var update *chainUpdate

	for range m.chainUpdateSignal {
		// A new update is available, so pop the new chain update from
		// the front of the update queue.
		m.chainMtx.Lock()
		update = m.chainUpdates[0]
		m.chainUpdates[0] = nil // Set to nil to prevent GC leak.
		m.chainUpdates = m.chainUpdates[1:]
		m.chainMtx.Unlock()

		m.Lock()
		if update.isConnect {
			m.ingestBlock(update)
		} else {
			m.unwindBlock(update)
		}
		m.Unlock()
	}
}

// evalOutputs evaluates each of the passed outputs, creating a new matching
// utxo within the wallet if we're able to spend the output.
func (m *memWallet) evalOutputs(outputs []*wire.TxOut, txHash *chainhash.Hash,
	isCoinbase bool, undo *undoEntry) {

	for i, output := range outputs {
		pkScript := output.PkScript

		// Scan all the addresses we currently control to see if the
		// output is paying to us.
		for keyIndex, addr := range m.addrs {
			pkHash := addr.ScriptAddress()
			if !bytes.Contains(pkScript, pkHash) {
				continue
			}

			// If this is a coinbase output, then we mark the
			// maturity height at the proper block height in the
			// future.
			var maturityHeight int32
			if isCoinbase {
				maturityHeight = m.currentHeight + int32(m.net.CoinbaseMaturity)
			}

			op := wire.OutPoint{Hash: *txHash, Index: uint32(i)}
			m.utxos[op] = &utxo{
				value:          btcutil.Amount(output.Value),
				keyIndex:       keyIndex,
				maturityHeight: maturityHeight,
				pkScript:       pkScript,
			}
			undo.utxosCreated = append(undo.utxosCreated, op)
		}
	}
}

// evalInputs scans all the passed inputs, destroying any utxos within the
// wallet which are spent by an input.
func (m *memWallet) evalInputs(inputs []*wire.TxIn, undo *undoEntry) {
	for _, txIn := range inputs {
		op := txIn.PreviousOutPoint
		oldUtxo, ok := m.utxos[op]
		if !ok {
			continue
		}

		undo.utxosDestroyed[op] = oldUtxo
		delete(m.utxos, op)
	}
}

// UnwindBlock is a call-back which is to be executed each time a block is
// disconnected from the main chain. It queues the update for the chain syncer,
// calling the private version in sequential order.
func (m *memWallet) UnwindBlock(height int32, header *wire.BlockHeader) {
	// Append this new chain update to the end of the queue of new chain
	// updates.
	m.chainMtx.Lock()
	m.chainUpdates = append(m.chainUpdates, &chainUpdate{height,
		nil, false})
	m.chainMtx.Unlock()

	// Launch a goroutine to signal the chainSyncer that a new update is
	// available. We do this in a new goroutine in order to avoid blocking
	// the main loop of the rpc client.
	go func() {
		m.chainUpdateSignal <- struct{}{}
	}()
}

// unwindBlock undoes the effect that a particular block had on the wallet's
// internal utxo state.
func (m *memWallet) unwindBlock(update *chainUpdate) {
	undo := m.reorgJournal[update.blockHeight]

	for _, utxo := range undo.utxosCreated {
		delete(m.utxos, utxo)
	}

	for outPoint, utxo := range undo.utxosDestroyed {
		m.utxos[outPoint] = utxo
	}

	delete(m.reorgJournal, update.blockHeight)
}

// newAddress returns a new address from the wallet's hd key chain.  It also
// loads the address into the RPC client's transaction filter to ensure any
// transactions that involve it are delivered via the notifications.
func (m *memWallet) newAddress() (btcutil.Address, error) {
	index := m.hdIndex

	childKey, err := m.hdRoot.Child(index)
	if err != nil {
		return nil, err
	}
	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	addr, err := keyToAddr(privKey, m.net)
	if err != nil {
		return nil, err
	}

	err = m.rpc.LoadTxFilter(false, []btcutil.Address{addr}, nil)
	if err != nil {
		return nil, err
	}

	m.addrs[index] = addr

	m.hdIndex++

	return addr, nil
}

// NewAddress returns a fresh address spendable by the wallet.
//
// This function is safe for concurrent access.
func (m *memWallet) NewAddress() (btcutil.Address, error) {
	m.Lock()
	defer m.Unlock()

	return m.newAddress()
}

// fundTx attempts to fund a transaction sending amt bitcoin. The coins are
// selected such that the final amount spent pays enough fees as dictated by the
// passed fee rate. The passed fee rate should be expressed in
// satoshis-per-byte. The transaction being funded can optionally include a
// change output indicated by the change boolean.
//
// NOTE: The memWallet's mutex must be held when this function is called.
func (m *memWallet) fundTx(tx *wire.MsgTx, amt btcutil.Amount,
	feeRate btcutil.Amount, change bool) error {

	const (
		// spendSize is the largest number of bytes of a sigScript
		// which spends a p2pkh output: OP_DATA_73 <sig> OP_DATA_33 <pubkey>
		spendSize = 1 + 73 + 1 + 33
	)

	var (
		amtSelected btcutil.Amount
		txSize      int
	)

	for outPoint, utxo := range m.utxos {
		// Skip any outputs that are still currently immature or are
		// currently locked.
		if !utxo.isMature(m.currentHeight) || utxo.isLocked {
			continue
		}

		amtSelected += utxo.value

		// Add the selected output to the transaction, updating the
		// current tx size while accounting for the size of the future
		// sigScript.
		tx.AddTxIn(wire.NewTxIn(&outPoint, nil, nil))
		txSize = tx.SerializeSize() + spendSize*len(tx.TxIn)

		// Calculate the fee required for the txn at this point
		// observing the specified fee rate. If we don't have enough
		// coins from he current amount selected to pay the fee, then
		// continue to grab more coins.
		reqFee := btcutil.Amount(txSize * int(feeRate))
		if amtSelected-reqFee < amt {
			continue
		}

		// If we have any change left over and we should create a change
		// output, then add an additional output to the transaction
		// reserved for it.
		changeVal := amtSelected - amt - reqFee
		if changeVal > 0 && change {
			addr, err := m.newAddress()
			if err != nil {
				return err
			}
			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return err
			}
			changeOutput := &wire.TxOut{
				Value:    int64(changeVal),
				PkScript: pkScript,
			}
			tx.AddTxOut(changeOutput)
		}

		return nil
	}

	// If we've reached this point, then coin selection failed due to an
	// insufficient amount of coins.
	return fmt.Errorf("not enough funds for coin selection")
}

// SendOutputs creates, then sends a transaction paying to the specified output
// while observing the passed fee rate. The passed fee rate should be expressed
// in satoshis-per-byte.
func (m *memWallet) SendOutputs(outputs []*wire.TxOut,
	feeRate btcutil.Amount) (*chainhash.Hash, error) {

	tx, err := m.CreateTransaction(outputs, feeRate, true)
	if err != nil {
		return nil, err
	}

	return m.rpc.SendRawTransaction(tx, true)
}

// SendOutputsWithoutChange creates and sends a transaction that pays to the
// specified outputs while observing the passed fee rate and ignoring a change
// output. The passed fee rate should be expressed in sat/b.
func (m *memWallet) SendOutputsWithoutChange(outputs []*wire.TxOut,
	feeRate btcutil.Amount) (*chainhash.Hash, error) {

	tx, err := m.CreateTransaction(outputs, feeRate, false)
	if err != nil {
		return nil, err
	}

	return m.rpc.SendRawTransaction(tx, true)
}

// CreateTransaction returns a fully signed transaction paying to the specified
// outputs while observing the desired fee rate. The passed fee rate should be
// expressed in satoshis-per-byte. The transaction being created can optionally
// include a change output indicated by the change boolean.
//
// This function is safe for concurrent access.
func (m *memWallet) CreateTransaction(outputs []*wire.TxOut,
	feeRate btcutil.Amount, change bool) (*wire.MsgTx, error) {

	m.Lock()
	defer m.Unlock()

	tx := wire.NewMsgTx(wire.TxVersion)

	// Tally up the total amount to be sent in order to perform coin
	// selection shortly below.
	var outputAmt btcutil.Amount
	for _, output := range outputs {
		outputAmt += btcutil.Amount(output.Value)
		tx.AddTxOut(output)
	}

	// Attempt to fund the transaction with spendable utxos.
	if err := m.fundTx(tx, outputAmt, feeRate, change); err != nil {
		return nil, err
	}

	// Populate all the selected inputs with valid sigScript for spending.
	// Along the way record all outputs being spent in order to avoid a
	// potential double spend.
	spentOutputs := make([]*utxo, 0, len(tx.TxIn))
	for i, txIn := range tx.TxIn {
		outPoint := txIn.PreviousOutPoint
		utxo := m.utxos[outPoint]

		extendedKey, err := m.hdRoot.Child(utxo.keyIndex)
		if err != nil {
			return nil, err
		}

		privKey, err := extendedKey.ECPrivKey()
		if err != nil {
			return nil, err
		}

		sigScript, err := txscript.SignatureScript(tx, i, utxo.pkScript,
			txscript.SigHashAll, privKey, true)
		if err != nil {
			return nil, err
		}

		txIn.SignatureScript = sigScript

		spentOutputs = append(spentOutputs, utxo)
	}

	// As these outputs are now being spent by this newly created
	// transaction, mark the outputs are "locked". This action ensures
	// these outputs won't be double spent by any subsequent transactions.
	// These locked outputs can be freed via a call to UnlockOutputs.
	for _, utxo := range spentOutputs {
		utxo.isLocked = true
	}

	return tx, nil
}

// UnlockOutputs unlocks any outputs which were previously locked due to
// being selected to fund a transaction via the CreateTransaction method.
//
// This function is safe for concurrent access.
func (m *memWallet) UnlockOutputs(inputs []*wire.TxIn) {
	m.Lock()
	defer m.Unlock()

	for _, input := range inputs {
		utxo, ok := m.utxos[input.PreviousOutPoint]
		if !ok {
			continue
		}

		utxo.isLocked = false
	}
}

// ConfirmedBalance returns the confirmed balance of the wallet.
//
// This function is safe for concurrent access.
func (m *memWallet) ConfirmedBalance() btcutil.Amount {
	m.RLock()
	defer m.RUnlock()

	var balance btcutil.Amount
	for _, utxo := range m.utxos {
		// Prevent any immature or locked outputs from contributing to
		// the wallet's total confirmed balance.
		if !utxo.isMature(m.currentHeight) || utxo.isLocked {
			continue
		}

		balance += utxo.value
	}

	return balance
}

// keyToAddr maps the passed private to corresponding p2pkh address.
func keyToAddr(key *btcec.PrivateKey, net *chaincfg.Params) (btcutil.Address, error) {
	serializedKey := key.PubKey().SerializeCompressed()
	pubKeyAddr, err := btcutil.NewAddressPubKey(serializedKey, net)
	if err != nil {
		return nil, err
	}
	return pubKeyAddr.AddressPubKeyHash(), nil
}
