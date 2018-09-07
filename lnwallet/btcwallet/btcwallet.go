package btcwallet

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	base "github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
)

const (
	defaultAccount = uint32(waddrmgr.DefaultAccountNum)
)

var (
	// waddrmgrNamespaceKey is the namespace key that the waddrmgr state is
	// stored within the top-level waleltdb buckets of btcwallet.
	waddrmgrNamespaceKey = []byte("waddrmgr")

	// lightningAddrSchema is the scope addr schema for all keys that we
	// derive. We'll treat them all as p2wkh addresses, as atm we must
	// specify a particular type.
	lightningAddrSchema = waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	}
)

// BtcWallet is an implementation of the lnwallet.WalletController interface
// backed by an active instance of btcwallet. At the time of the writing of
// this documentation, this implementation requires a full btcd node to
// operate.
type BtcWallet struct {
	// wallet is an active instance of btcwallet.
	wallet *base.Wallet

	chain chain.Interface

	db walletdb.DB

	cfg *Config

	netParams *chaincfg.Params

	chainKeyScope waddrmgr.KeyScope

	// utxoCache is a cache used to speed up repeated calls to
	// FetchInputInfo.
	utxoCache map[wire.OutPoint]*wire.TxOut
	cacheMtx  sync.RWMutex
}

// A compile time check to ensure that BtcWallet implements the
// WalletController interface.
var _ lnwallet.WalletController = (*BtcWallet)(nil)

// New returns a new fully initialized instance of BtcWallet given a valid
// configuration struct.
func New(cfg Config) (*BtcWallet, error) {
	// Ensure the wallet exists or create it when the create flag is set.
	netDir := NetworkDir(cfg.DataDir, cfg.NetParams)

	// Create the key scope for the coin type being managed by this wallet.
	chainKeyScope := waddrmgr.KeyScope{
		Purpose: keychain.BIP0043Purpose,
		Coin:    cfg.CoinType,
	}

	// Maybe the wallet has already been opened and unlocked by the
	// WalletUnlocker. So if we get a non-nil value from the config,
	// we assume everything is in order.
	var wallet = cfg.Wallet
	if wallet == nil {
		// No ready wallet was passed, so try to open an existing one.
		var pubPass []byte
		if cfg.PublicPass == nil {
			pubPass = defaultPubPassphrase
		} else {
			pubPass = cfg.PublicPass
		}
		loader := base.NewLoader(cfg.NetParams, netDir,
			cfg.RecoveryWindow)
		walletExists, err := loader.WalletExists()
		if err != nil {
			return nil, err
		}

		if !walletExists {
			// Wallet has never been created, perform initial
			// set up.
			wallet, err = loader.CreateNewWallet(
				pubPass, cfg.PrivatePass, cfg.HdSeed,
				cfg.Birthday,
			)
			if err != nil {
				return nil, err
			}
		} else {
			// Wallet has been created and been initialized at
			// this point, open it along with all the required DB
			// namespaces, and the DB itself.
			wallet, err = loader.OpenExistingWallet(pubPass, false)
			if err != nil {
				return nil, err
			}
		}
	}

	return &BtcWallet{
		cfg:           &cfg,
		wallet:        wallet,
		db:            wallet.Database(),
		chain:         cfg.ChainSource,
		netParams:     cfg.NetParams,
		chainKeyScope: chainKeyScope,
		utxoCache:     make(map[wire.OutPoint]*wire.TxOut),
	}, nil
}

// BackEnd returns the underlying ChainService's name as a string.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) BackEnd() string {
	if b.chain != nil {
		return b.chain.BackEnd()
	}

	return ""
}

// InternalWallet returns a pointer to the internal base wallet which is the
// core of btcwallet.
func (b *BtcWallet) InternalWallet() *base.Wallet {
	return b.wallet
}

// Start initializes the underlying rpc connection, the wallet itself, and
// begins syncing to the current available blockchain state.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) Start() error {
	// Establish an RPC connection in addition to starting the goroutines
	// in the underlying wallet.
	if err := b.chain.Start(); err != nil {
		return err
	}

	// Start the underlying btcwallet core.
	b.wallet.Start()

	// Pass the rpc client into the wallet so it can sync up to the
	// current main chain.
	b.wallet.SynchronizeRPC(b.chain)

	if err := b.wallet.Unlock(b.cfg.PrivatePass, nil); err != nil {
		return err
	}

	// We'll now ensure that the KeyScope: (1017, 1) exists within the
	// internal waddrmgr. We'll need this in order to properly generate the
	// keys required for signing various contracts.
	_, err := b.wallet.Manager.FetchScopedKeyManager(b.chainKeyScope)
	if err != nil {
		// If the scope hasn't yet been created (it wouldn't been
		// loaded by default if it was), then we'll manually create the
		// scope for the first time ourselves.
		err := walletdb.Update(b.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			_, err := b.wallet.Manager.NewScopedKeyManager(
				addrmgrNs, b.chainKeyScope, lightningAddrSchema,
			)
			return err
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// Stop signals the wallet for shutdown. Shutdown may entail closing
// any active sockets, database handles, stopping goroutines, etc.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) Stop() error {
	b.wallet.Stop()

	b.wallet.WaitForShutdown()

	b.chain.Stop()

	return nil
}

// ConfirmedBalance returns the sum of all the wallet's unspent outputs that
// have at least confs confirmations. If confs is set to zero, then all unspent
// outputs, including those currently in the mempool will be included in the
// final sum.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) ConfirmedBalance(confs int32) (btcutil.Amount, error) {
	var balance btcutil.Amount

	witnessOutputs, err := b.ListUnspentWitness(confs)
	if err != nil {
		return 0, err
	}

	for _, witnessOutput := range witnessOutputs {
		balance += witnessOutput.Value
	}

	return balance, nil
}

// NewAddress returns the next external or internal address for the wallet
// dictated by the value of the `change` parameter. If change is true, then an
// internal address will be returned, otherwise an external address should be
// returned.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) NewAddress(t lnwallet.AddressType, change bool) (btcutil.Address, error) {
	var keyScope waddrmgr.KeyScope

	switch t {
	case lnwallet.WitnessPubKey:
		keyScope = waddrmgr.KeyScopeBIP0084
	case lnwallet.NestedWitnessPubKey:
		keyScope = waddrmgr.KeyScopeBIP0049Plus
	default:
		return nil, fmt.Errorf("unknown address type")
	}

	if change {
		return b.wallet.NewChangeAddress(defaultAccount, keyScope)
	}

	return b.wallet.NewAddress(defaultAccount, keyScope)
}

// GetPrivKey retrieves the underlying private key associated with the passed
// address. If the we're unable to locate the proper private key, then a
// non-nil error will be returned.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) GetPrivKey(a btcutil.Address) (*btcec.PrivateKey, error) {
	// Using the ID address, request the private key corresponding to the
	// address from the wallet's address manager.
	return b.wallet.PrivKeyForAddress(a)
}

// SendOutputs funds, signs, and broadcasts a Bitcoin transaction paying out to
// the specified outputs. In the case the wallet has insufficient funds, or the
// outputs are non-standard, a non-nil error will be returned.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) SendOutputs(outputs []*wire.TxOut,
	feeRate lnwallet.SatPerKWeight) (*chainhash.Hash, error) {

	// Convert our fee rate from sat/kw to sat/kb since it's required by
	// SendOutputs.
	feeSatPerKB := btcutil.Amount(feeRate.FeePerKVByte())

	return b.wallet.SendOutputs(outputs, defaultAccount, 1, feeSatPerKB)
}

// LockOutpoint marks an outpoint as locked meaning it will no longer be deemed
// as eligible for coin selection. Locking outputs are utilized in order to
// avoid race conditions when selecting inputs for usage when funding a
// channel.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) LockOutpoint(o wire.OutPoint) {
	b.wallet.LockOutpoint(o)
}

// UnlockOutpoint unlocks a previously locked output, marking it eligible for
// coin selection.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) UnlockOutpoint(o wire.OutPoint) {
	b.wallet.UnlockOutpoint(o)
}

// ListUnspentWitness returns a slice of all the unspent outputs the wallet
// controls which pay to witness programs either directly or indirectly.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) ListUnspentWitness(minConfs int32) ([]*lnwallet.Utxo, error) {
	// First, grab all the unfiltered currently unspent outputs.
	maxConfs := int32(math.MaxInt32)
	unspentOutputs, err := b.wallet.ListUnspent(minConfs, maxConfs, nil)
	if err != nil {
		return nil, err
	}

	// Next, we'll run through all the regular outputs, only saving those
	// which are p2wkh outputs or a p2wsh output nested within a p2sh output.
	witnessOutputs := make([]*lnwallet.Utxo, 0, len(unspentOutputs))
	for _, output := range unspentOutputs {
		pkScript, err := hex.DecodeString(output.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		var addressType lnwallet.AddressType
		if txscript.IsPayToWitnessPubKeyHash(pkScript) {
			addressType = lnwallet.WitnessPubKey
		} else if txscript.IsPayToScriptHash(pkScript) {
			// TODO(roasbeef): This assumes all p2sh outputs returned by the
			// wallet are nested p2pkh. We can't check the redeem script because
			// the btcwallet service does not include it.
			addressType = lnwallet.NestedWitnessPubKey
		}

		if addressType == lnwallet.WitnessPubKey ||
			addressType == lnwallet.NestedWitnessPubKey {

			txid, err := chainhash.NewHashFromStr(output.TxID)
			if err != nil {
				return nil, err
			}

			// We'll ensure we properly convert the amount given in
			// BTC to satoshis.
			amt, err := btcutil.NewAmount(output.Amount)
			if err != nil {
				return nil, err
			}

			utxo := &lnwallet.Utxo{
				AddressType: addressType,
				Value:       amt,
				PkScript:    pkScript,
				OutPoint: wire.OutPoint{
					Hash:  *txid,
					Index: output.Vout,
				},
			}
			witnessOutputs = append(witnessOutputs, utxo)
		}

	}

	return witnessOutputs, nil
}

// PublishTransaction performs cursory validation (dust checks, etc), then
// finally broadcasts the passed transaction to the Bitcoin network. If
// publishing the transaction fails, an error describing the reason is
// returned (currently ErrDoubleSpend). If the transaction is already
// published to the network (either in the mempool or chain) no error
// will be returned.
func (b *BtcWallet) PublishTransaction(tx *wire.MsgTx) error {
	if err := b.wallet.PublishTransaction(tx); err != nil {
		switch b.chain.(type) {
		case *chain.RPCClient:
			if strings.Contains(err.Error(), "already have") {
				// Transaction was already in the mempool, do
				// not treat as an error. We do this to mimic
				// the behaviour of bitcoind, which will not
				// return an error if a transaction in the
				// mempool is sent again using the
				// sendrawtransaction RPC call.
				return nil
			}
			if strings.Contains(err.Error(), "already exists") {
				// Transaction was already mined, we don't
				// consider this an error.
				return nil
			}
			if strings.Contains(err.Error(), "already spent") {
				// Output was already spent.
				return lnwallet.ErrDoubleSpend
			}
			if strings.Contains(err.Error(), "already been spent") {
				// Output was already spent.
				return lnwallet.ErrDoubleSpend
			}
			if strings.Contains(err.Error(), "orphan transaction") {
				// Transaction is spending either output that
				// is missing or already spent.
				return lnwallet.ErrDoubleSpend
			}

		case *chain.BitcoindClient:
			if strings.Contains(err.Error(), "txn-already-in-mempool") {
				// Transaction in mempool, treat as non-error.
				return nil
			}
			if strings.Contains(err.Error(), "txn-already-known") {
				// Transaction in mempool, treat as non-error.
				return nil
			}
			if strings.Contains(err.Error(), "already in block") {
				// Transaction was already mined, we don't
				// consider this an error.
				return nil
			}
			if strings.Contains(err.Error(), "txn-mempool-conflict") {
				// Output was spent by other transaction
				// already in the mempool.
				return lnwallet.ErrDoubleSpend
			}
			if strings.Contains(err.Error(), "insufficient fee") {
				// RBF enabled transaction did not have enough fee.
				return lnwallet.ErrDoubleSpend
			}
			if strings.Contains(err.Error(), "Missing inputs") {
				// Transaction is spending either output that
				// is missing or already spent.
				return lnwallet.ErrDoubleSpend
			}

		case *chain.NeutrinoClient:
			if strings.Contains(err.Error(), "already have") {
				// Transaction was already in the mempool, do
				// not treat as an error.
				return nil
			}
			if strings.Contains(err.Error(), "already exists") {
				// Transaction was already mined, we don't
				// consider this an error.
				return nil
			}
			if strings.Contains(err.Error(), "already spent") {
				// Output was already spent.
				return lnwallet.ErrDoubleSpend
			}

		default:
		}
		return err
	}
	return nil
}

// extractBalanceDelta extracts the net balance delta from the PoV of the
// wallet given a TransactionSummary.
func extractBalanceDelta(
	txSummary base.TransactionSummary,
	tx *wire.MsgTx,
) (btcutil.Amount, error) {
	// For each input we debit the wallet's outflow for this transaction,
	// and for each output we credit the wallet's inflow for this
	// transaction.
	var balanceDelta btcutil.Amount
	for _, input := range txSummary.MyInputs {
		balanceDelta -= input.PreviousAmount
	}
	for _, output := range txSummary.MyOutputs {
		balanceDelta += btcutil.Amount(tx.TxOut[output.Index].Value)
	}

	return balanceDelta, nil
}

// minedTransactionsToDetails is a helper function which converts a summary
// information about mined transactions to a TransactionDetail.
func minedTransactionsToDetails(
	currentHeight int32,
	block base.Block,
	chainParams *chaincfg.Params,
) ([]*lnwallet.TransactionDetail, error) {

	details := make([]*lnwallet.TransactionDetail, 0, len(block.Transactions))
	for _, tx := range block.Transactions {
		wireTx := &wire.MsgTx{}
		txReader := bytes.NewReader(tx.Transaction)

		if err := wireTx.Deserialize(txReader); err != nil {
			return nil, err
		}

		var destAddresses []btcutil.Address
		for _, txOut := range wireTx.TxOut {
			_, outAddresses, _, err :=
				txscript.ExtractPkScriptAddrs(txOut.PkScript, chainParams)
			if err != nil {
				return nil, err
			}

			destAddresses = append(destAddresses, outAddresses...)
		}

		txDetail := &lnwallet.TransactionDetail{
			Hash:             *tx.Hash,
			NumConfirmations: currentHeight - block.Height + 1,
			BlockHash:        block.Hash,
			BlockHeight:      block.Height,
			Timestamp:        block.Timestamp,
			TotalFees:        int64(tx.Fee),
			DestAddresses:    destAddresses,
		}

		balanceDelta, err := extractBalanceDelta(tx, wireTx)
		if err != nil {
			return nil, err
		}
		txDetail.Value = balanceDelta

		details = append(details, txDetail)
	}

	return details, nil
}

// unminedTransactionsToDetail is a helper function which converts a summary
// for an unconfirmed transaction to a transaction detail.
func unminedTransactionsToDetail(
	summary base.TransactionSummary,
) (*lnwallet.TransactionDetail, error) {
	wireTx := &wire.MsgTx{}
	txReader := bytes.NewReader(summary.Transaction)

	if err := wireTx.Deserialize(txReader); err != nil {
		return nil, err
	}

	txDetail := &lnwallet.TransactionDetail{
		Hash:      *summary.Hash,
		TotalFees: int64(summary.Fee),
		Timestamp: summary.Timestamp,
	}

	balanceDelta, err := extractBalanceDelta(summary, wireTx)
	if err != nil {
		return nil, err
	}
	txDetail.Value = balanceDelta

	return txDetail, nil
}

// ListTransactionDetails returns a list of all transactions which are
// relevant to the wallet.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) ListTransactionDetails(offset int32, limit int32) ([]*lnwallet.TransactionDetail, error) {
	// Grab the best block the wallet knows of, we'll use this to calculate
	// # of confirmations shortly below.
	bestBlock := b.wallet.Manager.SyncedTo()
	currentHeight := bestBlock.Height

	// TODO(roasbeef): can replace with start "wallet birthday"
	start := base.NewBlockIdentifierFromHeight(0)
	stop := base.NewBlockIdentifierFromHeight(bestBlock.Height)
	txns, err := b.wallet.GetTransactions(start, stop, nil)
	if err != nil {
		return nil, err
	}

	txDetails := make([]*lnwallet.TransactionDetail, 0,
		len(txns.MinedTransactions)+len(txns.UnminedTransactions))

	// For both confirmed and unconfirmed transactions, create a
	// TransactionDetail which re-packages the data returned by the base
	// wallet.
	for _, blockPackage := range txns.MinedTransactions {
		details, err := minedTransactionsToDetails(currentHeight, blockPackage, b.netParams)
		if err != nil {
			return nil, err
		}

		txDetails = append(txDetails, details...)
	}
	for _, tx := range txns.UnminedTransactions {
		detail, err := unminedTransactionsToDetail(tx)
		if err != nil {
			return nil, err
		}

		txDetails = append(txDetails, detail)
	}

	// Return empty transaction list, if offset is more than all transactions.
	if offset > int32(len(txDetails)) {
		return make([]*lnwallet.TransactionDetail, 0), nil
	}

	// Sort transactions by timestamp descending.
	sort.Slice(txDetails, func(i, j int) bool {
		return txDetails[i].Timestamp > txDetails[j].Timestamp
	})
	end := offset + limit
	if end > int32(len(txDetails)) {
		end = int32(len(txDetails))
	}

	// Slice transactions from offset to end.
	return txDetails[offset:end], nil
}

// txSubscriptionClient encapsulates the transaction notification client from
// the base wallet. Notifications received from the client will be proxied over
// two distinct channels.
type txSubscriptionClient struct {
	txClient base.TransactionNotificationsClient

	confirmed   chan *lnwallet.TransactionDetail
	unconfirmed chan *lnwallet.TransactionDetail

	w *base.Wallet

	wg   sync.WaitGroup
	quit chan struct{}
}

// ConfirmedTransactions returns a channel which will be sent on as new
// relevant transactions are confirmed.
//
// This is part of the TransactionSubscription interface.
func (t *txSubscriptionClient) ConfirmedTransactions() chan *lnwallet.TransactionDetail {
	return t.confirmed
}

// UnconfirmedTransactions returns a channel which will be sent on as
// new relevant transactions are seen within the network.
//
// This is part of the TransactionSubscription interface.
func (t *txSubscriptionClient) UnconfirmedTransactions() chan *lnwallet.TransactionDetail {
	return t.unconfirmed
}

// Cancel finalizes the subscription, cleaning up any resources allocated.
//
// This is part of the TransactionSubscription interface.
func (t *txSubscriptionClient) Cancel() {
	close(t.quit)
	t.wg.Wait()

	t.txClient.Done()
}

// notificationProxier proxies the notifications received by the underlying
// wallet's notification client to a higher-level TransactionSubscription
// client.
func (t *txSubscriptionClient) notificationProxier() {
out:
	for {
		select {
		case txNtfn := <-t.txClient.C:
			// TODO(roasbeef): handle detached blocks
			currentHeight := t.w.Manager.SyncedTo().Height

			// Launch a goroutine to re-package and send
			// notifications for any newly confirmed transactions.
			go func() {
				for _, block := range txNtfn.AttachedBlocks {
					details, err := minedTransactionsToDetails(currentHeight, block, t.w.ChainParams())
					if err != nil {
						continue
					}

					for _, d := range details {
						select {
						case t.confirmed <- d:
						case <-t.quit:
							return
						}
					}
				}

			}()

			// Launch a goroutine to re-package and send
			// notifications for any newly unconfirmed transactions.
			go func() {
				for _, tx := range txNtfn.UnminedTransactions {
					detail, err := unminedTransactionsToDetail(tx)
					if err != nil {
						continue
					}

					select {
					case t.unconfirmed <- detail:
					case <-t.quit:
						return
					}
				}
			}()
		case <-t.quit:
			break out
		}
	}

	t.wg.Done()
}

// SubscribeTransactions returns a TransactionSubscription client which
// is capable of receiving async notifications as new transactions
// related to the wallet are seen within the network, or found in
// blocks.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) SubscribeTransactions() (lnwallet.TransactionSubscription, error) {
	walletClient := b.wallet.NtfnServer.TransactionNotifications()

	txClient := &txSubscriptionClient{
		txClient:    walletClient,
		confirmed:   make(chan *lnwallet.TransactionDetail),
		unconfirmed: make(chan *lnwallet.TransactionDetail),
		w:           b.wallet,
		quit:        make(chan struct{}),
	}
	txClient.wg.Add(1)
	go txClient.notificationProxier()

	return txClient, nil
}

// IsSynced returns a boolean indicating if from the PoV of the wallet,
// it has fully synced to the current best block in the main chain.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) IsSynced() (bool, int64, error) {
	// Grab the best chain state the wallet is currently aware of.
	syncState := b.wallet.Manager.SyncedTo()

	// We'll also extract the current best wallet timestamp so the caller
	// can get an idea of where we are in the sync timeline.
	bestTimestamp := syncState.Timestamp.Unix()

	// Next, query the chain backend to grab the info about the tip of the
	// main chain.
	bestHash, bestHeight, err := b.cfg.ChainSource.GetBestBlock()
	if err != nil {
		return false, 0, err
	}

	// If the wallet hasn't yet fully synced to the node's best chain tip,
	// then we're not yet fully synced.
	if syncState.Height < bestHeight {
		return false, bestTimestamp, nil
	}

	// If the wallet is on par with the current best chain tip, then we
	// still may not yet be synced as the chain backend may still be
	// catching up to the main chain. So we'll grab the block header in
	// order to make a guess based on the current time stamp.
	blockHeader, err := b.cfg.ChainSource.GetBlockHeader(bestHash)
	if err != nil {
		return false, 0, err
	}

	// If the timestamp on the best header is more than 2 hours in the
	// past, then we're not yet synced.
	minus24Hours := time.Now().Add(-2 * time.Hour)
	if blockHeader.Timestamp.Before(minus24Hours) {
		return false, bestTimestamp, nil
	}

	// If this is neutrino, then we'll also want to wait until the set of
	// filter headers also match
	if neutrinoNode, ok := b.chain.(*chain.NeutrinoClient); ok {
		filterDB := neutrinoNode.CS.RegFilterHeaders
		_, filterHeaderTip, err := filterDB.ChainTip()
		if err != nil {
			return false, 0, err
		}

		return filterHeaderTip == uint32(bestHeight), bestTimestamp, nil
	}

	return true, bestTimestamp, nil
}
