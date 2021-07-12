// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// TODO: It would be good to send errors during notification creation to the rpc
// server instead of just logging them here so the client is aware that wallet
// isn't working correctly and notifications are missing.

// TODO: Anything dealing with accounts here is expensive because the database
// is not organized correctly for true account support, but do the slow thing
// instead of the easy thing since the db can be fixed later, and we want the
// api correct now.

// NotificationServer is a server that interested clients may hook into to
// receive notifications of changes in a wallet.  A client is created for each
// registered notification.  Clients are guaranteed to receive messages in the
// order wallet created them, but there is no guaranteed synchronization between
// different clients.
type NotificationServer struct {
	transactions   []chan *TransactionNotifications
	currentTxNtfn  *TransactionNotifications // coalesce this since wallet does not add mined txs together
	spentness      map[uint32][]chan *SpentnessNotifications
	accountClients []chan *AccountNotification
	mu             sync.Mutex // Only protects registered client channels
	wallet         *Wallet    // smells like hacks
}

func newNotificationServer(wallet *Wallet) *NotificationServer {
	return &NotificationServer{
		spentness: make(map[uint32][]chan *SpentnessNotifications),
		wallet:    wallet,
	}
}

func lookupInputAccount(dbtx walletdb.ReadTx, w *Wallet, details *wtxmgr.TxDetails, deb wtxmgr.DebitRecord) uint32 {
	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	// TODO: Debits should record which account(s?) they
	// debit from so this doesn't need to be looked up.
	prevOP := &details.MsgTx.TxIn[deb.Index].PreviousOutPoint
	prev, err := w.TxStore.TxDetails(txmgrNs, &prevOP.Hash)
	if err != nil {
		log.Errorf("Cannot query previous transaction details for %v: %v", prevOP.Hash, err)
		return 0
	}
	if prev == nil {
		log.Errorf("Missing previous transaction %v", prevOP.Hash)
		return 0
	}
	prevOut := prev.MsgTx.TxOut[prevOP.Index]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(prevOut.PkScript, w.chainParams)
	var inputAcct uint32
	if err == nil && len(addrs) > 0 {
		_, inputAcct, err = w.Manager.AddrAccount(addrmgrNs, addrs[0])
	}
	if err != nil {
		log.Errorf("Cannot fetch account for previous output %v: %v", prevOP, err)
		inputAcct = 0
	}
	return inputAcct
}

func lookupOutputChain(dbtx walletdb.ReadTx, w *Wallet, details *wtxmgr.TxDetails,
	cred wtxmgr.CreditRecord) (account uint32, internal bool) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)

	output := details.MsgTx.TxOut[cred.Index]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, w.chainParams)
	var ma waddrmgr.ManagedAddress
	if err == nil && len(addrs) > 0 {
		ma, err = w.Manager.Address(addrmgrNs, addrs[0])
	}
	if err != nil {
		log.Errorf("Cannot fetch account for wallet output: %v", err)
	} else {
		account = ma.Account()
		internal = ma.Internal()
	}
	return
}

func makeTxSummary(dbtx walletdb.ReadTx, w *Wallet, details *wtxmgr.TxDetails) TransactionSummary {
	serializedTx := details.SerializedTx
	if serializedTx == nil {
		var buf bytes.Buffer
		err := details.MsgTx.Serialize(&buf)
		if err != nil {
			log.Errorf("Transaction serialization: %v", err)
		}
		serializedTx = buf.Bytes()
	}
	var fee btcutil.Amount
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		for _, deb := range details.Debits {
			fee += deb.Amount
		}
		for _, txOut := range details.MsgTx.TxOut {
			fee -= btcutil.Amount(txOut.Value)
		}
	}
	var inputs []TransactionSummaryInput
	if len(details.Debits) != 0 {
		inputs = make([]TransactionSummaryInput, len(details.Debits))
		for i, d := range details.Debits {
			inputs[i] = TransactionSummaryInput{
				Index:           d.Index,
				PreviousAccount: lookupInputAccount(dbtx, w, details, d),
				PreviousAmount:  d.Amount,
			}
		}
	}
	outputs := make([]TransactionSummaryOutput, 0, len(details.MsgTx.TxOut))
	for i := range details.MsgTx.TxOut {
		credIndex := len(outputs)
		mine := len(details.Credits) > credIndex && details.Credits[credIndex].Index == uint32(i)
		if !mine {
			continue
		}
		acct, internal := lookupOutputChain(dbtx, w, details, details.Credits[credIndex])
		output := TransactionSummaryOutput{
			Index:    uint32(i),
			Account:  acct,
			Internal: internal,
		}
		outputs = append(outputs, output)
	}
	return TransactionSummary{
		Hash:        &details.Hash,
		Transaction: serializedTx,
		MyInputs:    inputs,
		MyOutputs:   outputs,
		Fee:         fee,
		Timestamp:   details.Received.Unix(),
		Label:       details.Label,
	}
}

func totalBalances(dbtx walletdb.ReadTx, w *Wallet, m map[uint32]btcutil.Amount) error {
	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	unspent, err := w.TxStore.UnspentOutputs(dbtx.ReadBucket(wtxmgrNamespaceKey))
	if err != nil {
		return err
	}
	for i := range unspent {
		output := &unspent[i]
		var outputAcct uint32
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err == nil && len(addrs) > 0 {
			_, outputAcct, err = w.Manager.AddrAccount(addrmgrNs, addrs[0])
		}
		if err == nil {
			_, ok := m[outputAcct]
			if ok {
				m[outputAcct] += output.Amount
			}
		}
	}
	return nil
}

func flattenBalanceMap(m map[uint32]btcutil.Amount) []AccountBalance {
	s := make([]AccountBalance, 0, len(m))
	for k, v := range m {
		s = append(s, AccountBalance{Account: k, TotalBalance: v})
	}
	return s
}

func relevantAccounts(w *Wallet, m map[uint32]btcutil.Amount, txs []TransactionSummary) {
	for _, tx := range txs {
		for _, d := range tx.MyInputs {
			m[d.PreviousAccount] = 0
		}
		for _, c := range tx.MyOutputs {
			m[c.Account] = 0
		}
	}
}

func (s *NotificationServer) notifyUnminedTransaction(dbtx walletdb.ReadTx, details *wtxmgr.TxDetails) {
	// Sanity check: should not be currently coalescing a notification for
	// mined transactions at the same time that an unmined tx is notified.
	if s.currentTxNtfn != nil {
		log.Errorf("Notifying unmined tx notification (%s) while creating notification for blocks",
			details.Hash)
	}

	defer s.mu.Unlock()
	s.mu.Lock()
	clients := s.transactions
	if len(clients) == 0 {
		return
	}

	unminedTxs := []TransactionSummary{makeTxSummary(dbtx, s.wallet, details)}
	unminedHashes, err := s.wallet.TxStore.UnminedTxHashes(dbtx.ReadBucket(wtxmgrNamespaceKey))
	if err != nil {
		log.Errorf("Cannot fetch unmined transaction hashes: %v", err)
		return
	}
	bals := make(map[uint32]btcutil.Amount)
	relevantAccounts(s.wallet, bals, unminedTxs)
	err = totalBalances(dbtx, s.wallet, bals)
	if err != nil {
		log.Errorf("Cannot determine balances for relevant accounts: %v", err)
		return
	}
	n := &TransactionNotifications{
		UnminedTransactions:      unminedTxs,
		UnminedTransactionHashes: unminedHashes,
		NewBalances:              flattenBalanceMap(bals),
	}
	for _, c := range clients {
		c <- n
	}
}

func (s *NotificationServer) notifyDetachedBlock(hash *chainhash.Hash) {
	if s.currentTxNtfn == nil {
		s.currentTxNtfn = &TransactionNotifications{}
	}
	s.currentTxNtfn.DetachedBlocks = append(s.currentTxNtfn.DetachedBlocks, hash)
}

func (s *NotificationServer) notifyMinedTransaction(dbtx walletdb.ReadTx, details *wtxmgr.TxDetails, block *wtxmgr.BlockMeta) {
	if s.currentTxNtfn == nil {
		s.currentTxNtfn = &TransactionNotifications{}
	}
	n := len(s.currentTxNtfn.AttachedBlocks)
	if n == 0 || *s.currentTxNtfn.AttachedBlocks[n-1].Hash != block.Hash {
		s.currentTxNtfn.AttachedBlocks = append(s.currentTxNtfn.AttachedBlocks, Block{
			Hash:      &block.Hash,
			Height:    block.Height,
			Timestamp: block.Time.Unix(),
		})
		n++
	}
	txs := s.currentTxNtfn.AttachedBlocks[n-1].Transactions
	s.currentTxNtfn.AttachedBlocks[n-1].Transactions =
		append(txs, makeTxSummary(dbtx, s.wallet, details))
}

func (s *NotificationServer) notifyAttachedBlock(dbtx walletdb.ReadTx, block *wtxmgr.BlockMeta) {
	if s.currentTxNtfn == nil {
		s.currentTxNtfn = &TransactionNotifications{}
	}

	// Add block details if it wasn't already included for previously
	// notified mined transactions.
	n := len(s.currentTxNtfn.AttachedBlocks)
	if n == 0 || *s.currentTxNtfn.AttachedBlocks[n-1].Hash != block.Hash {
		s.currentTxNtfn.AttachedBlocks = append(s.currentTxNtfn.AttachedBlocks, Block{
			Hash:      &block.Hash,
			Height:    block.Height,
			Timestamp: block.Time.Unix(),
		})
	}

	// For now (until notification coalescing isn't necessary) just use
	// chain length to determine if this is the new best block.
	if s.wallet.ChainSynced() {
		if len(s.currentTxNtfn.DetachedBlocks) >= len(s.currentTxNtfn.AttachedBlocks) {
			return
		}
	}

	defer s.mu.Unlock()
	s.mu.Lock()
	clients := s.transactions
	if len(clients) == 0 {
		s.currentTxNtfn = nil
		return
	}

	// The UnminedTransactions field is intentionally not set.  Since the
	// hashes of all detached blocks are reported, and all transactions
	// moved from a mined block back to unconfirmed are either in the
	// UnminedTransactionHashes slice or don't exist due to conflicting with
	// a mined transaction in the new best chain, there is no possiblity of
	// a new, previously unseen transaction appearing in unconfirmed.

	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
	unminedHashes, err := s.wallet.TxStore.UnminedTxHashes(txmgrNs)
	if err != nil {
		log.Errorf("Cannot fetch unmined transaction hashes: %v", err)
		return
	}
	s.currentTxNtfn.UnminedTransactionHashes = unminedHashes

	bals := make(map[uint32]btcutil.Amount)
	for _, b := range s.currentTxNtfn.AttachedBlocks {
		relevantAccounts(s.wallet, bals, b.Transactions)
	}
	err = totalBalances(dbtx, s.wallet, bals)
	if err != nil {
		log.Errorf("Cannot determine balances for relevant accounts: %v", err)
		return
	}
	s.currentTxNtfn.NewBalances = flattenBalanceMap(bals)

	for _, c := range clients {
		c <- s.currentTxNtfn
	}
	s.currentTxNtfn = nil
}

// TransactionNotifications is a notification of changes to the wallet's
// transaction set and the current chain tip that wallet is considered to be
// synced with.  All transactions added to the blockchain are organized by the
// block they were mined in.
//
// During a chain switch, all removed block hashes are included.  Detached
// blocks are sorted in the reverse order they were mined.  Attached blocks are
// sorted in the order mined.
//
// All newly added unmined transactions are included.  Removed unmined
// transactions are not explicitly included.  Instead, the hashes of all
// transactions still unmined are included.
//
// If any transactions were involved, each affected account's new total balance
// is included.
//
// TODO: Because this includes stuff about blocks and can be fired without any
// changes to transactions, it needs a better name.
type TransactionNotifications struct {
	AttachedBlocks           []Block
	DetachedBlocks           []*chainhash.Hash
	UnminedTransactions      []TransactionSummary
	UnminedTransactionHashes []*chainhash.Hash
	NewBalances              []AccountBalance
}

// Block contains the properties and all relevant transactions of an attached
// block.
type Block struct {
	Hash         *chainhash.Hash
	Height       int32
	Timestamp    int64
	Transactions []TransactionSummary
}

// TransactionSummary contains a transaction relevant to the wallet and marks
// which inputs and outputs were relevant.
type TransactionSummary struct {
	Hash        *chainhash.Hash
	Transaction []byte
	MyInputs    []TransactionSummaryInput
	MyOutputs   []TransactionSummaryOutput
	Fee         btcutil.Amount
	Timestamp   int64
	Label       string
}

// TransactionSummaryInput describes a transaction input that is relevant to the
// wallet.  The Index field marks the transaction input index of the transaction
// (not included here).  The PreviousAccount and PreviousAmount fields describe
// how much this input debits from a wallet account.
type TransactionSummaryInput struct {
	Index           uint32
	PreviousAccount uint32
	PreviousAmount  btcutil.Amount
}

// TransactionSummaryOutput describes wallet properties of a transaction output
// controlled by the wallet.  The Index field marks the transaction output index
// of the transaction (not included here).
type TransactionSummaryOutput struct {
	Index    uint32
	Account  uint32
	Internal bool
}

// AccountBalance associates a total (zero confirmation) balance with an
// account.  Balances for other minimum confirmation counts require more
// expensive logic and it is not clear which minimums a client is interested in,
// so they are not included.
type AccountBalance struct {
	Account      uint32
	TotalBalance btcutil.Amount
}

// TransactionNotificationsClient receives TransactionNotifications from the
// NotificationServer over the channel C.
type TransactionNotificationsClient struct {
	C      <-chan *TransactionNotifications
	server *NotificationServer
}

// TransactionNotifications returns a client for receiving
// TransactionNotifiations notifications over a channel.  The channel is
// unbuffered.
//
// When finished, the Done method should be called on the client to disassociate
// it from the server.
func (s *NotificationServer) TransactionNotifications() TransactionNotificationsClient {
	c := make(chan *TransactionNotifications)
	s.mu.Lock()
	s.transactions = append(s.transactions, c)
	s.mu.Unlock()
	return TransactionNotificationsClient{
		C:      c,
		server: s,
	}
}

// Done deregisters the client from the server and drains any remaining
// messages.  It must be called exactly once when the client is finished
// receiving notifications.
func (c *TransactionNotificationsClient) Done() {
	go func() {
		// Drain notifications until the client channel is removed from
		// the server and closed.
		for range c.C {
		}
	}()
	go func() {
		s := c.server
		s.mu.Lock()
		clients := s.transactions
		for i, ch := range clients {
			if c.C == ch {
				clients[i] = clients[len(clients)-1]
				s.transactions = clients[:len(clients)-1]
				close(ch)
				break
			}
		}
		s.mu.Unlock()
	}()
}

// SpentnessNotifications is a notification that is fired for transaction
// outputs controlled by some account's keys.  The notification may be about a
// newly added unspent transaction output or that a previously unspent output is
// now spent.  When spent, the notification includes the spending transaction's
// hash and input index.
type SpentnessNotifications struct {
	hash         *chainhash.Hash
	spenderHash  *chainhash.Hash
	index        uint32
	spenderIndex uint32
}

// Hash returns the transaction hash of the spent output.
func (n *SpentnessNotifications) Hash() *chainhash.Hash {
	return n.hash
}

// Index returns the transaction output index of the spent output.
func (n *SpentnessNotifications) Index() uint32 {
	return n.index
}

// Spender returns the spending transction's hash and input index, if any.  If
// the output is unspent, the final bool return is false.
func (n *SpentnessNotifications) Spender() (*chainhash.Hash, uint32, bool) {
	return n.spenderHash, n.spenderIndex, n.spenderHash != nil
}

// notifyUnspentOutput notifies registered clients of a new unspent output that
// is controlled by the wallet.
func (s *NotificationServer) notifyUnspentOutput(account uint32, hash *chainhash.Hash, index uint32) {
	defer s.mu.Unlock()
	s.mu.Lock()
	clients := s.spentness[account]
	if len(clients) == 0 {
		return
	}
	n := &SpentnessNotifications{
		hash:  hash,
		index: index,
	}
	for _, c := range clients {
		c <- n
	}
}

// notifySpentOutput notifies registered clients that a previously-unspent
// output is now spent, and includes the spender hash and input index in the
// notification.
func (s *NotificationServer) notifySpentOutput(account uint32, op *wire.OutPoint, spenderHash *chainhash.Hash, spenderIndex uint32) {
	defer s.mu.Unlock()
	s.mu.Lock()
	clients := s.spentness[account]
	if len(clients) == 0 {
		return
	}
	n := &SpentnessNotifications{
		hash:         &op.Hash,
		index:        op.Index,
		spenderHash:  spenderHash,
		spenderIndex: spenderIndex,
	}
	for _, c := range clients {
		c <- n
	}
}

// SpentnessNotificationsClient receives SpentnessNotifications from the
// NotificationServer over the channel C.
type SpentnessNotificationsClient struct {
	C       <-chan *SpentnessNotifications
	account uint32
	server  *NotificationServer
}

// AccountSpentnessNotifications registers a client for spentness changes of
// outputs controlled by the account.
func (s *NotificationServer) AccountSpentnessNotifications(account uint32) SpentnessNotificationsClient {
	c := make(chan *SpentnessNotifications)
	s.mu.Lock()
	s.spentness[account] = append(s.spentness[account], c)
	s.mu.Unlock()
	return SpentnessNotificationsClient{
		C:       c,
		account: account,
		server:  s,
	}
}

// Done deregisters the client from the server and drains any remaining
// messages.  It must be called exactly once when the client is finished
// receiving notifications.
func (c *SpentnessNotificationsClient) Done() {
	go func() {
		// Drain notifications until the client channel is removed from
		// the server and closed.
		for range c.C {
		}
	}()
	go func() {
		s := c.server
		s.mu.Lock()
		clients := s.spentness[c.account]
		for i, ch := range clients {
			if c.C == ch {
				clients[i] = clients[len(clients)-1]
				s.spentness[c.account] = clients[:len(clients)-1]
				close(ch)
				break
			}
		}
		s.mu.Unlock()
	}()
}

// AccountNotification contains properties regarding an account, such as its
// name and the number of derived and imported keys.  When any of these
// properties change, the notification is fired.
type AccountNotification struct {
	AccountNumber    uint32
	AccountName      string
	ExternalKeyCount uint32
	InternalKeyCount uint32
	ImportedKeyCount uint32
}

func (s *NotificationServer) notifyAccountProperties(props *waddrmgr.AccountProperties) {
	defer s.mu.Unlock()
	s.mu.Lock()
	clients := s.accountClients
	if len(clients) == 0 {
		return
	}
	n := &AccountNotification{
		AccountNumber:    props.AccountNumber,
		AccountName:      props.AccountName,
		ExternalKeyCount: props.ExternalKeyCount,
		InternalKeyCount: props.InternalKeyCount,
		ImportedKeyCount: props.ImportedKeyCount,
	}
	for _, c := range clients {
		c <- n
	}
}

// AccountNotificationsClient receives AccountNotifications over the channel C.
type AccountNotificationsClient struct {
	C      chan *AccountNotification
	server *NotificationServer
}

// AccountNotifications returns a client for receiving AccountNotifications over
// a channel.  The channel is unbuffered.  When finished, the client's Done
// method should be called to disassociate the client from the server.
func (s *NotificationServer) AccountNotifications() AccountNotificationsClient {
	c := make(chan *AccountNotification)
	s.mu.Lock()
	s.accountClients = append(s.accountClients, c)
	s.mu.Unlock()
	return AccountNotificationsClient{
		C:      c,
		server: s,
	}
}

// Done deregisters the client from the server and drains any remaining
// messages.  It must be called exactly once when the client is finished
// receiving notifications.
func (c *AccountNotificationsClient) Done() {
	go func() {
		for range c.C {
		}
	}()
	go func() {
		s := c.server
		s.mu.Lock()
		clients := s.accountClients
		for i, ch := range clients {
			if c.C == ch {
				clients[i] = clients[len(clients)-1]
				s.accountClients = clients[:len(clients)-1]
				close(ch)
				break
			}
		}
		s.mu.Unlock()
	}()
}
