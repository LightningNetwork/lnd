package waddrmgr

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/walletdb"
)

// DerivationPath represents a derivation path from a particular key manager's
// scope.  Each ScopedKeyManager starts key derivation from the end of their
// cointype hardened key: m/purpose'/cointype'. The fields in this struct allow
// further derivation to the next three child levels after the coin type key.
// This restriction is in the spriti of BIP0044 type derivation. We maintain a
// degree of coherency with the standard, but allow arbitrary derivations
// beyond the cointype key. The key derived using this path will be exactly:
// m/purpose'/cointype'/account/branch/index, where purpose' and cointype' are
// bound by the scope of a particular manager.
type DerivationPath struct {
	// Account is the account, or the first immediate child from the scoped
	// manager's hardened coin type key.
	Account uint32

	// Branch is the branch to be derived from the account index above. For
	// BIP0044-like derivation, this is either 0 (external) or 1
	// (internal). However, we allow this value to vary arbitrarily within
	// its size range.
	Branch uint32

	// Index is the final child in the derivation path. This denotes the
	// key index within as a child of the account and branch.
	Index uint32
}

// KeyScope represents a restricted key scope from the primary root key within
// the HD chain. From the root manager (m/) we can create a nearly arbitrary
// number of ScopedKeyManagers of key derivation path: m/purpose'/cointype'.
// These scoped managers can then me managed indecently, as they house the
// encrypted cointype key and can derive any child keys from there on.
type KeyScope struct {
	// Purpose is the purpose of this key scope. This is the first child of
	// the master HD key.
	Purpose uint32

	// Coin is a value that represents the particular coin which is the
	// child of the purpose key. With this key, any accounts, or other
	// children can be derived at all.
	Coin uint32
}

// ScopedIndex is a tuple of KeyScope and child Index. This is used to compactly
// identify a particular child key, when the account and branch can be inferred
// from context.
type ScopedIndex struct {
	// Scope is the BIP44 account' used to derive the child key.
	Scope KeyScope

	// Index is the BIP44 address_index used to derive the child key.
	Index uint32
}

// String returns a human readable version describing the keypath encapsulated
// by the target key scope.
func (k *KeyScope) String() string {
	return fmt.Sprintf("m/%v'/%v'", k.Purpose, k.Coin)
}

// ScopeAddrSchema is the address schema of a particular KeyScope. This will be
// persisted within the database, and will be consulted when deriving any keys
// for a particular scope to know how to encode the public keys as addresses.
type ScopeAddrSchema struct {
	// ExternalAddrType is the address type for all keys within branch 0.
	ExternalAddrType AddressType

	// InternalAddrType is the address type for all keys within branch 1
	// (change addresses).
	InternalAddrType AddressType
}

var (
	// KeyScopeBIP0049Plus is the key scope of our modified BIP0049
	// derivation. We say this is BIP0049 "plus", as we'll actually use
	// p2wkh change all change addresses.
	KeyScopeBIP0049Plus = KeyScope{
		Purpose: 49,
		Coin:    0,
	}

	// KeyScopeBIP0084 is the key scope for BIP0084 derivation. BIP0084
	// will be used to derive all p2wkh addresses.
	KeyScopeBIP0084 = KeyScope{
		Purpose: 84,
		Coin:    0,
	}

	// KeyScopeBIP0044 is the key scope for BIP0044 derivation. Legacy
	// wallets will only be able to use this key scope, and no keys beyond
	// it.
	KeyScopeBIP0044 = KeyScope{
		Purpose: 44,
		Coin:    0,
	}

	// DefaultKeyScopes is the set of default key scopes that will be
	// created by the root manager upon initial creation.
	DefaultKeyScopes = []KeyScope{
		KeyScopeBIP0049Plus,
		KeyScopeBIP0084,
		KeyScopeBIP0044,
	}

	// ScopeAddrMap is a map from the default key scopes to the scope
	// address schema for each scope type. This will be consulted during
	// the initial creation of the root key manager.
	ScopeAddrMap = map[KeyScope]ScopeAddrSchema{
		KeyScopeBIP0049Plus: {
			ExternalAddrType: NestedWitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
		KeyScopeBIP0084: {
			ExternalAddrType: WitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
		KeyScopeBIP0044: {
			InternalAddrType: PubKeyHash,
			ExternalAddrType: PubKeyHash,
		},
	}
)

// ScopedKeyManager is a sub key manager under the main root key manager. The
// root key manager will handle the root HD key (m/), while each sub scoped key
// manager will handle the cointype key for a particular key scope
// (m/purpose'/cointype'). This abstraction allows higher-level applications
// built upon the root key manager to perform their own arbitrary key
// derivation, while still being protected under the encryption of the root key
// manager.
type ScopedKeyManager struct {
	// scope is the scope of this key manager. We can only generate keys
	// that are direct children of this scope.
	scope KeyScope

	// addrSchema is the address schema for this sub manager. This will be
	// consulted when encoding addresses from derived keys.
	addrSchema ScopeAddrSchema

	// rootManager is a pointer to the root key manager. We'll maintain
	// this as we need access to the crypto encryption keys before we can
	// derive any new accounts of child keys of accounts.
	rootManager *Manager

	// addrs is a cached map of all the addresses that we currently
	// manager.
	addrs map[addrKey]ManagedAddress

	// acctInfo houses information about accounts including what is needed
	// to generate deterministic chained keys for each created account.
	acctInfo map[uint32]*accountInfo

	// deriveOnUnlock is a list of private keys which needs to be derived
	// on the next unlock.  This occurs when a public address is derived
	// while the address manager is locked since it does not have access to
	// the private extended key (hence nor the underlying private key) in
	// order to encrypt it.
	deriveOnUnlock []*unlockDeriveInfo

	mtx sync.RWMutex
}

// Scope returns the exact KeyScope of this scoped key manager.
func (s *ScopedKeyManager) Scope() KeyScope {
	return s.scope
}

// AddrSchema returns the set address schema for the target ScopedKeyManager.
func (s *ScopedKeyManager) AddrSchema() ScopeAddrSchema {
	return s.addrSchema
}

// zeroSensitivePublicData performs a best try effort to remove and zero all
// sensitive public data associated with the address manager such as
// hierarchical deterministic extended public keys and the crypto public keys.
func (s *ScopedKeyManager) zeroSensitivePublicData() {
	// Clear all of the account private keys.
	for _, acctInfo := range s.acctInfo {
		acctInfo.acctKeyPub.Zero()
		acctInfo.acctKeyPub = nil
	}
}

// Close cleanly shuts down the manager.  It makes a best try effort to remove
// and zero all private key and sensitive public key material associated with
// the address manager from memory.
func (s *ScopedKeyManager) Close() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Attempt to clear sensitive public key material from memory too.
	s.zeroSensitivePublicData()
	return
}

// keyToManaged returns a new managed address for the provided derived key and
// its derivation path which consists of the account, branch, and index.
//
// The passed derivedKey is zeroed after the new address is created.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) keyToManaged(derivedKey *hdkeychain.ExtendedKey,
	account, branch, index uint32) (ManagedAddress, error) {

	var addrType AddressType
	if branch == InternalBranch {
		addrType = s.addrSchema.InternalAddrType
	} else {
		addrType = s.addrSchema.ExternalAddrType
	}

	derivationPath := DerivationPath{
		Account: account,
		Branch:  branch,
		Index:   index,
	}

	// Create a new managed address based on the public or private key
	// depending on whether the passed key is private.  Also, zero the key
	// after creating the managed address from it.
	ma, err := newManagedAddressFromExtKey(
		s, derivationPath, derivedKey, addrType,
	)
	defer derivedKey.Zero()
	if err != nil {
		return nil, err
	}

	if !derivedKey.IsPrivate() {
		// Add the managed address to the list of addresses that need
		// their private keys derived when the address manager is next
		// unlocked.
		info := unlockDeriveInfo{
			managedAddr: ma,
			branch:      branch,
			index:       index,
		}
		s.deriveOnUnlock = append(s.deriveOnUnlock, &info)
	}

	if branch == InternalBranch {
		ma.internal = true
	}

	return ma, nil
}

// deriveKey returns either a public or private derived extended key based on
// the private flag for the given an account info, branch, and index.
func (s *ScopedKeyManager) deriveKey(acctInfo *accountInfo, branch,
	index uint32, private bool) (*hdkeychain.ExtendedKey, error) {

	// Choose the public or private extended key based on whether or not
	// the private flag was specified.  This, in turn, allows for public or
	// private child derivation.
	acctKey := acctInfo.acctKeyPub
	if private {
		acctKey = acctInfo.acctKeyPriv
	}

	// Derive and return the key.
	branchKey, err := acctKey.Child(branch)
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branch)
		return nil, managerError(ErrKeyChain, str, err)
	}

	addressKey, err := branchKey.Child(index)
	branchKey.Zero() // Zero branch key after it's used.
	if err != nil {
		str := fmt.Sprintf("failed to derive child extended key -- "+
			"branch %d, child %d",
			branch, index)
		return nil, managerError(ErrKeyChain, str, err)
	}

	return addressKey, nil
}

// loadAccountInfo attempts to load and cache information about the given
// account from the database.   This includes what is necessary to derive new
// keys for it and track the state of the internal and external branches.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) loadAccountInfo(ns walletdb.ReadBucket,
	account uint32) (*accountInfo, error) {

	// Return the account info from cache if it's available.
	if acctInfo, ok := s.acctInfo[account]; ok {
		return acctInfo, nil
	}

	// The account is either invalid or just wasn't cached, so attempt to
	// load the information from the database.
	rowInterface, err := fetchAccountInfo(ns, &s.scope, account)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Ensure the account type is a default account.
	row, ok := rowInterface.(*dbDefaultAccountRow)
	if !ok {
		str := fmt.Sprintf("unsupported account type %T", row)
		return nil, managerError(ErrDatabase, str, nil)
	}

	// Use the crypto public key to decrypt the account public extended
	// key.
	serializedKeyPub, err := s.rootManager.cryptoKeyPub.Decrypt(row.pubKeyEncrypted)
	if err != nil {
		str := fmt.Sprintf("failed to decrypt public key for account %d",
			account)
		return nil, managerError(ErrCrypto, str, err)
	}
	acctKeyPub, err := hdkeychain.NewKeyFromString(string(serializedKeyPub))
	if err != nil {
		str := fmt.Sprintf("failed to create extended public key for "+
			"account %d", account)
		return nil, managerError(ErrKeyChain, str, err)
	}

	// Create the new account info with the known information.  The rest of
	// the fields are filled out below.
	acctInfo := &accountInfo{
		acctName:          row.name,
		acctKeyEncrypted:  row.privKeyEncrypted,
		acctKeyPub:        acctKeyPub,
		nextExternalIndex: row.nextExternalIndex,
		nextInternalIndex: row.nextInternalIndex,
	}

	if !s.rootManager.isLocked() {
		// Use the crypto private key to decrypt the account private
		// extended keys.
		decrypted, err := s.rootManager.cryptoKeyPriv.Decrypt(acctInfo.acctKeyEncrypted)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt private key for "+
				"account %d", account)
			return nil, managerError(ErrCrypto, str, err)
		}

		acctKeyPriv, err := hdkeychain.NewKeyFromString(string(decrypted))
		if err != nil {
			str := fmt.Sprintf("failed to create extended private "+
				"key for account %d", account)
			return nil, managerError(ErrKeyChain, str, err)
		}
		acctInfo.acctKeyPriv = acctKeyPriv
	}

	// Derive and cache the managed address for the last external address.
	branch, index := ExternalBranch, row.nextExternalIndex
	if index > 0 {
		index--
	}
	lastExtKey, err := s.deriveKey(
		acctInfo, branch, index, !s.rootManager.isLocked(),
	)
	if err != nil {
		return nil, err
	}
	lastExtAddr, err := s.keyToManaged(lastExtKey, account, branch, index)
	if err != nil {
		return nil, err
	}
	acctInfo.lastExternalAddr = lastExtAddr

	// Derive and cache the managed address for the last internal address.
	branch, index = InternalBranch, row.nextInternalIndex
	if index > 0 {
		index--
	}
	lastIntKey, err := s.deriveKey(
		acctInfo, branch, index, !s.rootManager.isLocked(),
	)
	if err != nil {
		return nil, err
	}
	lastIntAddr, err := s.keyToManaged(lastIntKey, account, branch, index)
	if err != nil {
		return nil, err
	}
	acctInfo.lastInternalAddr = lastIntAddr

	// Add it to the cache and return it when everything is successful.
	s.acctInfo[account] = acctInfo
	return acctInfo, nil
}

// AccountProperties returns properties associated with the account, such as
// the account number, name, and the number of derived and imported keys.
func (s *ScopedKeyManager) AccountProperties(ns walletdb.ReadBucket,
	account uint32) (*AccountProperties, error) {

	defer s.mtx.RUnlock()
	s.mtx.RLock()

	props := &AccountProperties{AccountNumber: account}

	// Until keys can be imported into any account, special handling is
	// required for the imported account.
	//
	// loadAccountInfo errors when using it on the imported account since
	// the accountInfo struct is filled with a BIP0044 account's extended
	// keys, and the imported accounts has none.
	//
	// Since only the imported account allows imports currently, the number
	// of imported keys for any other account is zero, and since the
	// imported account cannot contain non-imported keys, the external and
	// internal key counts for it are zero.
	if account != ImportedAddrAccount {
		acctInfo, err := s.loadAccountInfo(ns, account)
		if err != nil {
			return nil, err
		}
		props.AccountName = acctInfo.acctName
		props.ExternalKeyCount = acctInfo.nextExternalIndex
		props.InternalKeyCount = acctInfo.nextInternalIndex
	} else {
		props.AccountName = ImportedAddrAccountName // reserved, nonchangable

		// Could be more efficient if this was tracked by the db.
		var importedKeyCount uint32
		count := func(interface{}) error {
			importedKeyCount++
			return nil
		}
		err := forEachAccountAddress(ns, &s.scope, ImportedAddrAccount, count)
		if err != nil {
			return nil, err
		}
		props.ImportedKeyCount = importedKeyCount
	}

	return props, nil
}

// DeriveFromKeyPath attempts to derive a maximal child key (under the BIP0044
// scheme) from a given key path. If key derivation isn't possible, then an
// error will be returned.
func (s *ScopedKeyManager) DeriveFromKeyPath(ns walletdb.ReadBucket,
	kp DerivationPath) (ManagedAddress, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	extKey, err := s.deriveKeyFromPath(
		ns, kp.Account, kp.Branch, kp.Index, !s.rootManager.IsLocked(),
	)
	if err != nil {
		return nil, err
	}

	return s.keyToManaged(extKey, kp.Account, kp.Branch, kp.Index)
}

// deriveKeyFromPath returns either a public or private derived extended key
// based on the private flag for the given an account, branch, and index.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) deriveKeyFromPath(ns walletdb.ReadBucket, account, branch,
	index uint32, private bool) (*hdkeychain.ExtendedKey, error) {

	// Look up the account key information.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	return s.deriveKey(acctInfo, branch, index, private)
}

// chainAddressRowToManaged returns a new managed address based on chained
// address data loaded from the database.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) chainAddressRowToManaged(ns walletdb.ReadBucket,
	row *dbChainAddressRow) (ManagedAddress, error) {

	// Since the manger's mutex is assumed to held when invoking this
	// function, we use the internal isLocked to avoid a deadlock.
	isLocked := s.rootManager.isLocked()

	addressKey, err := s.deriveKeyFromPath(
		ns, row.account, row.branch, row.index, !isLocked,
	)
	if err != nil {
		return nil, err
	}

	return s.keyToManaged(addressKey, row.account, row.branch, row.index)
}

// importedAddressRowToManaged returns a new managed address based on imported
// address data loaded from the database.
func (s *ScopedKeyManager) importedAddressRowToManaged(row *dbImportedAddressRow) (ManagedAddress, error) {

	// Use the crypto public key to decrypt the imported public key.
	pubBytes, err := s.rootManager.cryptoKeyPub.Decrypt(row.encryptedPubKey)
	if err != nil {
		str := "failed to decrypt public key for imported address"
		return nil, managerError(ErrCrypto, str, err)
	}

	pubKey, err := btcec.ParsePubKey(pubBytes, btcec.S256())
	if err != nil {
		str := "invalid public key for imported address"
		return nil, managerError(ErrCrypto, str, err)
	}

	// Since this is an imported address, we won't populate the full
	// derivation path, as we don't have enough information to do so.
	derivationPath := DerivationPath{
		Account: row.account,
	}

	compressed := len(pubBytes) == btcec.PubKeyBytesLenCompressed
	ma, err := newManagedAddressWithoutPrivKey(
		s, derivationPath, pubKey, compressed,
		s.addrSchema.ExternalAddrType,
	)
	if err != nil {
		return nil, err
	}
	ma.privKeyEncrypted = row.encryptedPrivKey
	ma.imported = true

	return ma, nil
}

// scriptAddressRowToManaged returns a new managed address based on script
// address data loaded from the database.
func (s *ScopedKeyManager) scriptAddressRowToManaged(row *dbScriptAddressRow) (ManagedAddress, error) {
	// Use the crypto public key to decrypt the imported script hash.
	scriptHash, err := s.rootManager.cryptoKeyPub.Decrypt(row.encryptedHash)
	if err != nil {
		str := "failed to decrypt imported script hash"
		return nil, managerError(ErrCrypto, str, err)
	}

	return newScriptAddress(s, row.account, scriptHash, row.encryptedScript)
}

// rowInterfaceToManaged returns a new managed address based on the given
// address data loaded from the database.  It will automatically select the
// appropriate type.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) rowInterfaceToManaged(ns walletdb.ReadBucket,
	rowInterface interface{}) (ManagedAddress, error) {

	switch row := rowInterface.(type) {
	case *dbChainAddressRow:
		return s.chainAddressRowToManaged(ns, row)

	case *dbImportedAddressRow:
		return s.importedAddressRowToManaged(row)

	case *dbScriptAddressRow:
		return s.scriptAddressRowToManaged(row)
	}

	str := fmt.Sprintf("unsupported address type %T", rowInterface)
	return nil, managerError(ErrDatabase, str, nil)
}

// loadAndCacheAddress attempts to load the passed address from the database
// and caches the associated managed address.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) loadAndCacheAddress(ns walletdb.ReadBucket,
	address btcutil.Address) (ManagedAddress, error) {

	// Attempt to load the raw address information from the database.
	rowInterface, err := fetchAddress(ns, &s.scope, address.ScriptAddress())
	if err != nil {
		if merr, ok := err.(*ManagerError); ok {
			desc := fmt.Sprintf("failed to fetch address '%s': %v",
				address.ScriptAddress(), merr.Description)
			merr.Description = desc
			return nil, merr
		}
		return nil, maybeConvertDbError(err)
	}

	// Create a new managed address for the specific type of address based
	// on type.
	managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
	if err != nil {
		return nil, err
	}

	// Cache and return the new managed address.
	s.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr

	return managedAddr, nil
}

// existsAddress returns whether or not the passed address is known to the
// address manager.
//
// This function MUST be called with the manager lock held for reads.
func (s *ScopedKeyManager) existsAddress(ns walletdb.ReadBucket, addressID []byte) bool {
	// Check the in-memory map first since it's faster than a db access.
	if _, ok := s.addrs[addrKey(addressID)]; ok {
		return true
	}

	// Check the database if not already found above.
	return existsAddress(ns, &s.scope, addressID)
}

// Address returns a managed address given the passed address if it is known to
// the address manager.  A managed address differs from the passed address in
// that it also potentially contains extra information needed to sign
// transactions such as the associated private key for pay-to-pubkey and
// pay-to-pubkey-hash addresses and the script associated with
// pay-to-script-hash addresses.
func (s *ScopedKeyManager) Address(ns walletdb.ReadBucket,
	address btcutil.Address) (ManagedAddress, error) {

	// ScriptAddress will only return a script hash if we're accessing an
	// address that is either PKH or SH. In the event we're passed a PK
	// address, convert the PK to PKH address so that we can access it from
	// the addrs map and database.
	if pka, ok := address.(*btcutil.AddressPubKey); ok {
		address = pka.AddressPubKeyHash()
	}

	// Return the address from cache if it's available.
	//
	// NOTE: Not using a defer on the lock here since a write lock is
	// needed if the lookup fails.
	s.mtx.RLock()
	if ma, ok := s.addrs[addrKey(address.ScriptAddress())]; ok {
		s.mtx.RUnlock()
		return ma, nil
	}
	s.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Attempt to load the address from the database.
	return s.loadAndCacheAddress(ns, address)
}

// AddrAccount returns the account to which the given address belongs.
func (s *ScopedKeyManager) AddrAccount(ns walletdb.ReadBucket,
	address btcutil.Address) (uint32, error) {

	account, err := fetchAddrAccount(ns, &s.scope, address.ScriptAddress())
	if err != nil {
		return 0, maybeConvertDbError(err)
	}

	return account, nil
}

// nextAddresses returns the specified number of next chained address from the
// branch indicated by the internal flag.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) nextAddresses(ns walletdb.ReadWriteBucket,
	account uint32, numAddresses uint32, internal bool) ([]ManagedAddress, error) {

	// The next address can only be generated for accounts that have
	// already been created.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	// Choose the account key to used based on whether the address manager
	// is locked.
	acctKey := acctInfo.acctKeyPub
	if !s.rootManager.IsLocked() {
		acctKey = acctInfo.acctKeyPriv
	}

	// Choose the branch key and index depending on whether or not this is
	// an internal address.
	branchNum, nextIndex := ExternalBranch, acctInfo.nextExternalIndex
	if internal {
		branchNum = InternalBranch
		nextIndex = acctInfo.nextInternalIndex
	}

	addrType := s.addrSchema.ExternalAddrType
	if internal {
		addrType = s.addrSchema.InternalAddrType
	}

	// Ensure the requested number of addresses doesn't exceed the maximum
	// allowed for this account.
	if numAddresses > MaxAddressesPerAccount || nextIndex+numAddresses >
		MaxAddressesPerAccount {
		str := fmt.Sprintf("%d new addresses would exceed the maximum "+
			"allowed number of addresses per account of %d",
			numAddresses, MaxAddressesPerAccount)
		return nil, managerError(ErrTooManyAddresses, str, nil)
	}

	// Derive the appropriate branch key and ensure it is zeroed when done.
	branchKey, err := acctKey.Child(branchNum)
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branchNum)
		return nil, managerError(ErrKeyChain, str, err)
	}
	defer branchKey.Zero() // Ensure branch key is zeroed when done.

	// Create the requested number of addresses and keep track of the index
	// with each one.
	addressInfo := make([]*unlockDeriveInfo, 0, numAddresses)
	for i := uint32(0); i < numAddresses; i++ {
		// There is an extremely small chance that a particular child is
		// invalid, so use a loop to derive the next valid child.
		var nextKey *hdkeychain.ExtendedKey
		for {
			// Derive the next child in the external chain branch.
			key, err := branchKey.Child(nextIndex)
			if err != nil {
				// When this particular child is invalid, skip to the
				// next index.
				if err == hdkeychain.ErrInvalidChild {
					nextIndex++
					continue
				}

				str := fmt.Sprintf("failed to generate child %d",
					nextIndex)
				return nil, managerError(ErrKeyChain, str, err)
			}
			key.SetNet(s.rootManager.chainParams)

			nextIndex++
			nextKey = key
			break
		}

		// Now that we know this key can be used, we'll create the
		// proper derivation path so this information can be available
		// to callers.
		derivationPath := DerivationPath{
			Account: account,
			Branch:  branchNum,
			Index:   nextIndex - 1,
		}

		// Create a new managed address based on the public or private
		// key depending on whether the generated key is private.
		// Also, zero the next key after creating the managed address
		// from it.
		addr, err := newManagedAddressFromExtKey(
			s, derivationPath, nextKey, addrType,
		)
		if err != nil {
			return nil, err
		}
		if internal {
			addr.internal = true
		}
		managedAddr := addr
		nextKey.Zero()

		info := unlockDeriveInfo{
			managedAddr: managedAddr,
			branch:      branchNum,
			index:       nextIndex - 1,
		}
		addressInfo = append(addressInfo, &info)
	}

	// Now that all addresses have been successfully generated, update the
	// database in a single transaction.
	for _, info := range addressInfo {
		ma := info.managedAddr
		addressID := ma.Address().ScriptAddress()

		switch a := ma.(type) {
		case *managedAddress:
			err := putChainedAddress(
				ns, &s.scope, addressID, account, ssFull,
				info.branch, info.index, adtChain,
			)
			if err != nil {
				return nil, maybeConvertDbError(err)
			}
		case *scriptAddress:
			encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(a.AddrHash())
			if err != nil {
				str := fmt.Sprintf("failed to encrypt script hash %x",
					a.AddrHash())
				return nil, managerError(ErrCrypto, str, err)
			}

			err = putScriptAddress(
				ns, &s.scope, a.AddrHash(), ImportedAddrAccount,
				ssNone, encryptedHash, a.scriptEncrypted,
			)
			if err != nil {
				return nil, maybeConvertDbError(err)
			}
		}
	}

	managedAddresses := make([]ManagedAddress, 0, len(addressInfo))
	for _, info := range addressInfo {
		ma := info.managedAddr
		managedAddresses = append(managedAddresses, ma)
	}

	// Finally, create a closure that will update the next address tracking
	// and add the addresses to the cache after the newly generated
	// addresses have been successfully committed to the db.
	onCommit := func() {
		// Since this closure will be called when the DB transaction
		// gets committed, we won't longer be holding the manager's
		// mutex at that point. We must therefore re-acquire it before
		// continuing.
		s.mtx.Lock()
		defer s.mtx.Unlock()

		for _, info := range addressInfo {
			ma := info.managedAddr
			s.addrs[addrKey(ma.Address().ScriptAddress())] = ma

			// Add the new managed address to the list of addresses
			// that need their private keys derived when the
			// address manager is next unlocked.
			if s.rootManager.isLocked() && !s.rootManager.watchOnly() {
				s.deriveOnUnlock = append(s.deriveOnUnlock, info)
			}
		}

		// Set the last address and next address for tracking.
		ma := addressInfo[len(addressInfo)-1].managedAddr
		if internal {
			acctInfo.nextInternalIndex = nextIndex
			acctInfo.lastInternalAddr = ma
		} else {
			acctInfo.nextExternalIndex = nextIndex
			acctInfo.lastExternalAddr = ma
		}
	}
	ns.Tx().OnCommit(onCommit)

	return managedAddresses, nil
}

// extendAddresses ensures that all addresses up to and including the lastIndex
// are derived for either an internal or external branch. If the child at
// lastIndex is invalid, this method will proceed until the next valid child is
// found. An error is returned if method failed to properly extend addresses
// up to the requested index.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) extendAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32, internal bool) error {

	// The next address can only be generated for accounts that have
	// already been created.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return err
	}

	// Choose the account key to used based on whether the address manager
	// is locked.
	acctKey := acctInfo.acctKeyPub
	if !s.rootManager.IsLocked() {
		acctKey = acctInfo.acctKeyPriv
	}

	// Choose the branch key and index depending on whether or not this is
	// an internal address.
	branchNum, nextIndex := ExternalBranch, acctInfo.nextExternalIndex
	if internal {
		branchNum = InternalBranch
		nextIndex = acctInfo.nextInternalIndex
	}

	addrType := s.addrSchema.ExternalAddrType
	if internal {
		addrType = s.addrSchema.InternalAddrType
	}

	// If the last index requested is already lower than the next index, we
	// can return early.
	if lastIndex < nextIndex {
		return nil
	}

	// Ensure the requested number of addresses doesn't exceed the maximum
	// allowed for this account.
	if lastIndex > MaxAddressesPerAccount {
		str := fmt.Sprintf("last index %d would exceed the maximum "+
			"allowed number of addresses per account of %d",
			lastIndex, MaxAddressesPerAccount)
		return managerError(ErrTooManyAddresses, str, nil)
	}

	// Derive the appropriate branch key and ensure it is zeroed when done.
	branchKey, err := acctKey.Child(branchNum)
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branchNum)
		return managerError(ErrKeyChain, str, err)
	}
	defer branchKey.Zero() // Ensure branch key is zeroed when done.

	// Starting from this branch's nextIndex, derive all child indexes up to
	// and including the requested lastIndex. If a invalid child is
	// detected, this loop will continue deriving until it finds the next
	// subsequent index.
	addressInfo := make([]*unlockDeriveInfo, 0, lastIndex-nextIndex)
	for nextIndex <= lastIndex {
		// There is an extremely small chance that a particular child is
		// invalid, so use a loop to derive the next valid child.
		var nextKey *hdkeychain.ExtendedKey
		for {
			// Derive the next child in the external chain branch.
			key, err := branchKey.Child(nextIndex)
			if err != nil {
				// When this particular child is invalid, skip to the
				// next index.
				if err == hdkeychain.ErrInvalidChild {
					nextIndex++
					continue
				}

				str := fmt.Sprintf("failed to generate child %d",
					nextIndex)
				return managerError(ErrKeyChain, str, err)
			}
			key.SetNet(s.rootManager.chainParams)

			nextIndex++
			nextKey = key
			break
		}

		// Now that we know this key can be used, we'll create the
		// proper derivation path so this information can be available
		// to callers.
		derivationPath := DerivationPath{
			Account: account,
			Branch:  branchNum,
			Index:   nextIndex - 1,
		}

		// Create a new managed address based on the public or private
		// key depending on whether the generated key is private.
		// Also, zero the next key after creating the managed address
		// from it.
		addr, err := newManagedAddressFromExtKey(
			s, derivationPath, nextKey, addrType,
		)
		if err != nil {
			return err
		}
		if internal {
			addr.internal = true
		}
		managedAddr := addr
		nextKey.Zero()

		info := unlockDeriveInfo{
			managedAddr: managedAddr,
			branch:      branchNum,
			index:       nextIndex - 1,
		}
		addressInfo = append(addressInfo, &info)
	}

	// Now that all addresses have been successfully generated, update the
	// database in a single transaction.
	for _, info := range addressInfo {
		ma := info.managedAddr
		addressID := ma.Address().ScriptAddress()

		switch a := ma.(type) {
		case *managedAddress:
			err := putChainedAddress(
				ns, &s.scope, addressID, account, ssFull,
				info.branch, info.index, adtChain,
			)
			if err != nil {
				return maybeConvertDbError(err)
			}
		case *scriptAddress:
			encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(a.AddrHash())
			if err != nil {
				str := fmt.Sprintf("failed to encrypt script hash %x",
					a.AddrHash())
				return managerError(ErrCrypto, str, err)
			}

			err = putScriptAddress(
				ns, &s.scope, a.AddrHash(), ImportedAddrAccount,
				ssNone, encryptedHash, a.scriptEncrypted,
			)
			if err != nil {
				return maybeConvertDbError(err)
			}
		}
	}

	// Finally update the next address tracking and add the addresses to
	// the cache after the newly generated addresses have been successfully
	// added to the db.
	for _, info := range addressInfo {
		ma := info.managedAddr
		s.addrs[addrKey(ma.Address().ScriptAddress())] = ma

		// Add the new managed address to the list of addresses that
		// need their private keys derived when the address manager is
		// next unlocked.
		if s.rootManager.IsLocked() && !s.rootManager.WatchOnly() {
			s.deriveOnUnlock = append(s.deriveOnUnlock, info)
		}
	}

	// Set the last address and next address for tracking.
	ma := addressInfo[len(addressInfo)-1].managedAddr
	if internal {
		acctInfo.nextInternalIndex = nextIndex
		acctInfo.lastInternalAddr = ma
	} else {
		acctInfo.nextExternalIndex = nextIndex
		acctInfo.lastExternalAddr = ma
	}

	return nil
}

// NextExternalAddresses returns the specified number of next chained addresses
// that are intended for external use from the address manager.
func (s *ScopedKeyManager) NextExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, numAddresses uint32) ([]ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.nextAddresses(ns, account, numAddresses, false)
}

// NextInternalAddresses returns the specified number of next chained addresses
// that are intended for internal use such as change from the address manager.
func (s *ScopedKeyManager) NextInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, numAddresses uint32) ([]ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.nextAddresses(ns, account, numAddresses, true)
}

// ExtendExternalAddresses ensures that all valid external keys through
// lastIndex are derived and stored in the wallet. This is used to ensure that
// wallet's persistent state catches up to a external child that was found
// during recovery.
func (s *ScopedKeyManager) ExtendExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32) error {

	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.extendAddresses(ns, account, lastIndex, false)
}

// ExtendInternalAddresses ensures that all valid internal keys through
// lastIndex are derived and stored in the wallet. This is used to ensure that
// wallet's persistent state catches up to an internal child that was found
// during recovery.
func (s *ScopedKeyManager) ExtendInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32) error {

	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.extendAddresses(ns, account, lastIndex, true)
}

// LastExternalAddress returns the most recently requested chained external
// address from calling NextExternalAddress for the given account.  The first
// external address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.
func (s *ScopedKeyManager) LastExternalAddress(ns walletdb.ReadBucket,
	account uint32) (ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Load account information for the passed account.  It is typically
	// cached, but if not it will be loaded from the database.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	if acctInfo.nextExternalIndex > 0 {
		return acctInfo.lastExternalAddr, nil
	}

	return nil, managerError(ErrAddressNotFound, "no previous external address", nil)
}

// LastInternalAddress returns the most recently requested chained internal
// address from calling NextInternalAddress for the given account.  The first
// internal address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.
func (s *ScopedKeyManager) LastInternalAddress(ns walletdb.ReadBucket,
	account uint32) (ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Load account information for the passed account.  It is typically
	// cached, but if not it will be loaded from the database.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	if acctInfo.nextInternalIndex > 0 {
		return acctInfo.lastInternalAddr, nil
	}

	return nil, managerError(ErrAddressNotFound, "no previous internal address", nil)
}

// NewRawAccount creates a new account for the scoped manager. This method
// differs from the NewAccount method in that this method takes the account
// number *directly*, rather than taking a string name for the account, then
// mapping that to the next highest account number.
func (s *ScopedKeyManager) NewRawAccount(ns walletdb.ReadWriteBucket, number uint32) error {
	if s.rootManager.WatchOnly() {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.rootManager.IsLocked() {
		return managerError(ErrLocked, errLocked, nil)
	}

	// As this is an ad hoc account that may not follow our normal linear
	// derivation, we'll create a new name for this account based off of
	// the account number.
	name := fmt.Sprintf("act:%v", number)
	return s.newAccount(ns, number, name)
}

// NewRawAccountWatchingOnly creates a new watching only account for
// the scoped manager.  This method differs from the
// NewAccountWatchingOnly method in that this method takes the account
// number *directly*, rather than taking a string name for the
// account, then mapping that to the next highest account number.
func (s *ScopedKeyManager) NewRawAccountWatchingOnly(
	ns walletdb.ReadWriteBucket, number uint32,
	pubKey *hdkeychain.ExtendedKey) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// As this is an ad hoc account that may not follow our normal linear
	// derivation, we'll create a new name for this account based off of
	// the account number.
	name := fmt.Sprintf("act:%v", number)
	return s.newAccountWatchingOnly(ns, number, name, pubKey)
}

// NewAccount creates and returns a new account stored in the manager based on
// the given account name.  If an account with the same name already exists,
// ErrDuplicateAccount will be returned.  Since creating a new account requires
// access to the cointype keys (from which extended account keys are derived),
// it requires the manager to be unlocked.
func (s *ScopedKeyManager) NewAccount(ns walletdb.ReadWriteBucket, name string) (uint32, error) {
	if s.rootManager.WatchOnly() {
		return 0, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.rootManager.IsLocked() {
		return 0, managerError(ErrLocked, errLocked, nil)
	}

	// Fetch latest account, and create a new account in the same
	// transaction Fetch the latest account number to generate the next
	// account number
	account, err := fetchLastAccount(ns, &s.scope)
	if err != nil {
		return 0, err
	}
	account++

	// With the name validated, we'll create a new account for the new
	// contiguous account.
	if err := s.newAccount(ns, account, name); err != nil {
		return 0, err
	}

	return account, nil
}

// newAccount is a helper function that derives a new precise account number,
// and creates a mapping from the passed name to the account number in the
// database.
//
// NOTE: This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) newAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {

	// Validate the account name.
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	// Check that account with the same name does not exist
	_, err := s.lookupAccount(ns, name)
	if err == nil {
		str := fmt.Sprintf("account with the same name already exists")
		return managerError(ErrDuplicateAccount, str, err)
	}

	// Fetch the cointype key which will be used to derive the next account
	// extended keys
	_, coinTypePrivEnc, err := fetchCoinTypeKeys(ns, &s.scope)
	if err != nil {
		return err
	}

	// Decrypt the cointype key.
	serializedKeyPriv, err := s.rootManager.cryptoKeyPriv.Decrypt(coinTypePrivEnc)
	if err != nil {
		str := fmt.Sprintf("failed to decrypt cointype serialized private key")
		return managerError(ErrLocked, str, err)
	}
	coinTypeKeyPriv, err := hdkeychain.NewKeyFromString(string(serializedKeyPriv))
	zero.Bytes(serializedKeyPriv)
	if err != nil {
		str := fmt.Sprintf("failed to create cointype extended private key")
		return managerError(ErrKeyChain, str, err)
	}

	// Derive the account key using the cointype key
	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, account)
	coinTypeKeyPriv.Zero()
	if err != nil {
		str := "failed to convert private key for account"
		return managerError(ErrKeyChain, str, err)
	}
	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		str := "failed to convert public key for account"
		return managerError(ErrKeyChain, str, err)
	}

	// Encrypt the default account keys with the associated crypto keys.
	acctPubEnc, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(acctKeyPub.String()),
	)
	if err != nil {
		str := "failed to  encrypt public key for account"
		return managerError(ErrCrypto, str, err)
	}
	acctPrivEnc, err := s.rootManager.cryptoKeyPriv.Encrypt(
		[]byte(acctKeyPriv.String()),
	)
	if err != nil {
		str := "failed to encrypt private key for account"
		return managerError(ErrCrypto, str, err)
	}

	// We have the encrypted account extended keys, so save them to the
	// database
	err = putAccountInfo(
		ns, &s.scope, account, acctPubEnc, acctPrivEnc, 0, 0, name,
	)
	if err != nil {
		return err
	}

	// Save last account metadata
	return putLastAccount(ns, &s.scope, account)
}

// NewAccountWatchingOnly is similar to NewAccount, but for watch-only wallets.
func (s *ScopedKeyManager) NewAccountWatchingOnly(ns walletdb.ReadWriteBucket, name string,
	pubKey *hdkeychain.ExtendedKey) (uint32, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Fetch latest account, and create a new account in the same
	// transaction Fetch the latest account number to generate the next
	// account number
	account, err := fetchLastAccount(ns, &s.scope)
	if err != nil {
		return 0, err
	}
	account++

	// With the name validated, we'll create a new account for the new
	// contiguous account.
	if err := s.newAccountWatchingOnly(ns, account, name, pubKey); err != nil {
		return 0, err
	}

	return account, nil
}

// newAccountWatchingOnly is similar to newAccount, but for watching-only wallets.
//
// NOTE: This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) newAccountWatchingOnly(ns walletdb.ReadWriteBucket, account uint32, name string,
	pubKey *hdkeychain.ExtendedKey) error {

	// Validate the account name.
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	// Check that account with the same name does not exist
	_, err := s.lookupAccount(ns, name)
	if err == nil {
		str := fmt.Sprintf("account with the same name already exists")
		return managerError(ErrDuplicateAccount, str, err)
	}

	// Encrypt the default account keys with the associated crypto keys.
	acctPubEnc, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(pubKey.String()),
	)
	if err != nil {
		str := "failed to  encrypt public key for account"
		return managerError(ErrCrypto, str, err)
	}

	// We have the encrypted account extended keys, so save them to the
	// database
	err = putAccountInfo(
		ns, &s.scope, account, acctPubEnc, nil, 0, 0, name,
	)
	if err != nil {
		return err
	}

	// Save last account metadata
	return putLastAccount(ns, &s.scope, account)
}

// RenameAccount renames an account stored in the manager based on the given
// account number with the given name.  If an account with the same name
// already exists, ErrDuplicateAccount will be returned.
func (s *ScopedKeyManager) RenameAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Ensure that a reserved account is not being renamed.
	if isReservedAccountNum(account) {
		str := "reserved account cannot be renamed"
		return managerError(ErrInvalidAccount, str, nil)
	}

	// Check that account with the new name does not exist
	_, err := s.lookupAccount(ns, name)
	if err == nil {
		str := fmt.Sprintf("account with the same name already exists")
		return managerError(ErrDuplicateAccount, str, err)
	}

	// Validate account name
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	rowInterface, err := fetchAccountInfo(ns, &s.scope, account)
	if err != nil {
		return err
	}

	// Ensure the account type is a default account.
	row, ok := rowInterface.(*dbDefaultAccountRow)
	if !ok {
		str := fmt.Sprintf("unsupported account type %T", row)
		err = managerError(ErrDatabase, str, nil)
	}

	// Remove the old name key from the account id index.
	if err = deleteAccountIDIndex(ns, &s.scope, account); err != nil {
		return err
	}

	// Remove the old name key from the account name index.
	if err = deleteAccountNameIndex(ns, &s.scope, row.name); err != nil {
		return err
	}
	err = putAccountInfo(
		ns, &s.scope, account, row.pubKeyEncrypted,
		row.privKeyEncrypted, row.nextExternalIndex,
		row.nextInternalIndex, name,
	)
	if err != nil {
		return err
	}

	// Update in-memory account info with new name if cached and the db
	// write was successful.
	if err == nil {
		if acctInfo, ok := s.acctInfo[account]; ok {
			acctInfo.acctName = name
		}
	}

	return err
}

// ImportPrivateKey imports a WIF private key into the address manager.  The
// imported address is created using either a compressed or uncompressed
// serialized public key, depending on the CompressPubKey bool of the WIF.
//
// All imported addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// NOTE: When the address manager is watching-only, the private key itself will
// not be stored or available since it is private data.  Instead, only the
// public key will be stored.  This means it is paramount the private key is
// kept elsewhere as the watching-only address manager will NOT ever have access
// to it.
//
// This function will return an error if the address manager is locked and not
// watching-only, or not for the same network as the key trying to be imported.
// It will also return an error if the address already exists.  Any other
// errors returned are generally unexpected.
func (s *ScopedKeyManager) ImportPrivateKey(ns walletdb.ReadWriteBucket,
	wif *btcutil.WIF, bs *BlockStamp) (ManagedPubKeyAddress, error) {

	// Ensure the address is intended for network the address manager is
	// associated with.
	if !wif.IsForNet(s.rootManager.chainParams) {
		str := fmt.Sprintf("private key is not for the same network the "+
			"address manager is configured for (%s)",
			s.rootManager.chainParams.Name)
		return nil, managerError(ErrWrongNet, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// The manager must be unlocked to encrypt the imported private key.
	if s.rootManager.IsLocked() && !s.rootManager.WatchOnly() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Prevent duplicates.
	serializedPubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(serializedPubKey)
	alreadyExists := s.existsAddress(ns, pubKeyHash)
	if alreadyExists {
		str := fmt.Sprintf("address for public key %x already exists",
			serializedPubKey)
		return nil, managerError(ErrDuplicateAddress, str, nil)
	}

	// Encrypt public key.
	encryptedPubKey, err := s.rootManager.cryptoKeyPub.Encrypt(
		serializedPubKey,
	)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt public key for %x",
			serializedPubKey)
		return nil, managerError(ErrCrypto, str, err)
	}

	// Encrypt the private key when not a watching-only address manager.
	var encryptedPrivKey []byte
	if !s.rootManager.WatchOnly() {
		privKeyBytes := wif.PrivKey.Serialize()
		encryptedPrivKey, err = s.rootManager.cryptoKeyPriv.Encrypt(privKeyBytes)
		zero.Bytes(privKeyBytes)
		if err != nil {
			str := fmt.Sprintf("failed to encrypt private key for %x",
				serializedPubKey)
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	// The start block needs to be updated when the newly imported address
	// is before the current one.
	s.rootManager.mtx.Lock()
	updateStartBlock := bs.Height < s.rootManager.syncState.startBlock.Height
	s.rootManager.mtx.Unlock()

	// Save the new imported address to the db and update start block (if
	// needed) in a single transaction.
	err = putImportedAddress(
		ns, &s.scope, pubKeyHash, ImportedAddrAccount, ssNone,
		encryptedPubKey, encryptedPrivKey,
	)
	if err != nil {
		return nil, err
	}

	if updateStartBlock {
		err := putStartBlock(ns, bs)
		if err != nil {
			return nil, err
		}
	}

	// Now that the database has been updated, update the start block in
	// memory too if needed.
	if updateStartBlock {
		s.rootManager.mtx.Lock()
		s.rootManager.syncState.startBlock = *bs
		s.rootManager.mtx.Unlock()
	}

	// The full derivation path for an imported key is incomplete as we
	// don't know exactly how it was derived.
	importedDerivationPath := DerivationPath{
		Account: ImportedAddrAccount,
	}

	// Create a new managed address based on the imported address.
	var managedAddr *managedAddress
	if !s.rootManager.WatchOnly() {
		managedAddr, err = newManagedAddress(
			s, importedDerivationPath, wif.PrivKey,
			wif.CompressPubKey, s.addrSchema.ExternalAddrType,
		)
	} else {
		pubKey := (*btcec.PublicKey)(&wif.PrivKey.PublicKey)
		managedAddr, err = newManagedAddressWithoutPrivKey(
			s, importedDerivationPath, pubKey, wif.CompressPubKey,
			s.addrSchema.ExternalAddrType,
		)
	}
	if err != nil {
		return nil, err
	}
	managedAddr.imported = true

	// Add the new managed address to the cache of recent addresses and
	// return it.
	s.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr
	return managedAddr, nil
}

// ImportScript imports a user-provided script into the address manager.  The
// imported script will act as a pay-to-script-hash address.
//
// All imported script addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// When the address manager is watching-only, the script itself will not be
// stored or available since it is considered private data.
//
// This function will return an error if the address manager is locked and not
// watching-only, or the address already exists.  Any other errors returned are
// generally unexpected.
func (s *ScopedKeyManager) ImportScript(ns walletdb.ReadWriteBucket,
	script []byte, bs *BlockStamp) (ManagedScriptAddress, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// The manager must be unlocked to encrypt the imported script.
	if s.rootManager.IsLocked() && !s.rootManager.WatchOnly() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Prevent duplicates.
	scriptHash := btcutil.Hash160(script)
	alreadyExists := s.existsAddress(ns, scriptHash)
	if alreadyExists {
		str := fmt.Sprintf("address for script hash %x already exists",
			scriptHash)
		return nil, managerError(ErrDuplicateAddress, str, nil)
	}

	// Encrypt the script hash using the crypto public key so it is
	// accessible when the address manager is locked or watching-only.
	encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(scriptHash)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt script hash %x",
			scriptHash)
		return nil, managerError(ErrCrypto, str, err)
	}

	// Encrypt the script for storage in database using the crypto script
	// key when not a watching-only address manager.
	var encryptedScript []byte
	if !s.rootManager.WatchOnly() {
		encryptedScript, err = s.rootManager.cryptoKeyScript.Encrypt(
			script,
		)
		if err != nil {
			str := fmt.Sprintf("failed to encrypt script for %x",
				scriptHash)
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	// The start block needs to be updated when the newly imported address
	// is before the current one.
	updateStartBlock := false
	s.rootManager.mtx.Lock()
	if bs.Height < s.rootManager.syncState.startBlock.Height {
		updateStartBlock = true
	}
	s.rootManager.mtx.Unlock()

	// Save the new imported address to the db and update start block (if
	// needed) in a single transaction.
	err = putScriptAddress(
		ns, &s.scope, scriptHash, ImportedAddrAccount, ssNone,
		encryptedHash, encryptedScript,
	)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	if updateStartBlock {
		err := putStartBlock(ns, bs)
		if err != nil {
			return nil, maybeConvertDbError(err)
		}
	}

	// Now that the database has been updated, update the start block in
	// memory too if needed.
	if updateStartBlock {
		s.rootManager.mtx.Lock()
		s.rootManager.syncState.startBlock = *bs
		s.rootManager.mtx.Unlock()
	}

	// Create a new managed address based on the imported script.  Also,
	// when not a watching-only address manager, make a copy of the script
	// since it will be cleared on lock and the script the caller passed
	// should not be cleared out from under the caller.
	scriptAddr, err := newScriptAddress(
		s, ImportedAddrAccount, scriptHash, encryptedScript,
	)
	if err != nil {
		return nil, err
	}
	if !s.rootManager.WatchOnly() {
		scriptAddr.scriptCT = make([]byte, len(script))
		copy(scriptAddr.scriptCT, script)
	}

	// Add the new managed address to the cache of recent addresses and
	// return it.
	s.addrs[addrKey(scriptHash)] = scriptAddr
	return scriptAddr, nil
}

// lookupAccount loads account number stored in the manager for the given
// account name
//
// This function MUST be called with the manager lock held for reads.
func (s *ScopedKeyManager) lookupAccount(ns walletdb.ReadBucket, name string) (uint32, error) {
	return fetchAccountByName(ns, &s.scope, name)
}

// LookupAccount loads account number stored in the manager for the given
// account name
func (s *ScopedKeyManager) LookupAccount(ns walletdb.ReadBucket, name string) (uint32, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	return s.lookupAccount(ns, name)
}

// fetchUsed returns true if the provided address id was flagged used.
func (s *ScopedKeyManager) fetchUsed(ns walletdb.ReadBucket,
	addressID []byte) bool {

	return fetchAddressUsed(ns, &s.scope, addressID)
}

// MarkUsed updates the used flag for the provided address.
func (s *ScopedKeyManager) MarkUsed(ns walletdb.ReadWriteBucket,
	address btcutil.Address) error {

	addressID := address.ScriptAddress()
	err := markAddressUsed(ns, &s.scope, addressID)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Clear caches which might have stale entries for used addresses
	s.mtx.Lock()
	delete(s.addrs, addrKey(addressID))
	s.mtx.Unlock()
	return nil
}

// ChainParams returns the chain parameters for this address manager.
func (s *ScopedKeyManager) ChainParams() *chaincfg.Params {
	// NOTE: No need for mutex here since the net field does not change
	// after the manager instance is created.

	return s.rootManager.chainParams
}

// AccountName returns the account name for the given account number stored in
// the manager.
func (s *ScopedKeyManager) AccountName(ns walletdb.ReadBucket, account uint32) (string, error) {
	return fetchAccountName(ns, &s.scope, account)
}

// ForEachAccount calls the given function with each account stored in the
// manager, breaking early on error.
func (s *ScopedKeyManager) ForEachAccount(ns walletdb.ReadBucket,
	fn func(account uint32) error) error {

	return forEachAccount(ns, &s.scope, fn)
}

// LastAccount returns the last account stored in the manager.
// If no accounts, returns twos-complement representation of -1
func (s *ScopedKeyManager) LastAccount(ns walletdb.ReadBucket) (uint32, error) {
	return fetchLastAccount(ns, &s.scope)
}

// ForEachAccountAddress calls the given function with each address of the
// given account stored in the manager, breaking early on error.
func (s *ScopedKeyManager) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr ManagedAddress) error) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
		if err != nil {
			return err
		}
		return fn(managedAddr)
	}
	err := forEachAccountAddress(ns, &s.scope, account, addrFn)
	if err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}

// ForEachActiveAccountAddress calls the given function with each active
// address of the given account stored in the manager, breaking early on error.
//
// TODO(tuxcanfly): actually return only active addresses
func (s *ScopedKeyManager) ForEachActiveAccountAddress(ns walletdb.ReadBucket, account uint32,
	fn func(maddr ManagedAddress) error) error {

	return s.ForEachAccountAddress(ns, account, fn)
}

// ForEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.
func (s *ScopedKeyManager) ForEachActiveAddress(ns walletdb.ReadBucket,
	fn func(addr btcutil.Address) error) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
		if err != nil {
			return err
		}
		return fn(managedAddr.Address())
	}

	err := forEachActiveAddress(ns, &s.scope, addrFn)
	if err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}

// ForEachInternalActiveAddress invokes the given closure on each _internal_
// active address belonging to the scoped key manager, breaking early on error.
func (s *ScopedKeyManager) ForEachInternalActiveAddress(ns walletdb.ReadBucket,
	fn func(addr btcutil.Address) error) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
		if err != nil {
			return err
		}
		// Skip any non-internal branch addresses.
		if !managedAddr.Internal() {
			return nil
		}
		return fn(managedAddr.Address())
	}

	if err := forEachActiveAddress(ns, &s.scope, addrFn); err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}
