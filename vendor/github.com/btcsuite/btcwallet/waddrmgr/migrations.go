package waddrmgr

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
)

// versions is a list of the different database versions. The last entry should
// reflect the latest database state. If the database happens to be at a version
// number lower than the latest, migrations will be performed in order to catch
// it up.
var versions = []migration.Version{
	{
		Number:    2,
		Migration: upgradeToVersion2,
	},
	{
		Number:    5,
		Migration: upgradeToVersion5,
	},
	{
		Number:    6,
		Migration: populateBirthdayBlock,
	},
	{
		Number:    7,
		Migration: resetSyncedBlockToBirthday,
	},
	{
		Number:    8,
		Migration: storeMaxReorgDepth,
	},
}

// getLatestVersion returns the version number of the latest database version.
func getLatestVersion() uint32 {
	return versions[len(versions)-1].Number
}

// MigrationManager is an implementation of the migration.Manager interface that
// will be used to handle migrations for the address manager. It exposes the
// necessary parameters required to successfully perform migrations.
type MigrationManager struct {
	ns walletdb.ReadWriteBucket
}

// A compile-time assertion to ensure that MigrationManager implements the
// migration.Manager interface.
var _ migration.Manager = (*MigrationManager)(nil)

// NewMigrationManager creates a new migration manager for the address manager.
// The given bucket should reflect the top-level bucket in which all of the
// address manager's data is contained within.
func NewMigrationManager(ns walletdb.ReadWriteBucket) *MigrationManager {
	return &MigrationManager{ns: ns}
}

// Name returns the name of the service we'll be attempting to upgrade.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Name() string {
	return "wallet address manager"
}

// Namespace returns the top-level bucket of the service.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Namespace() walletdb.ReadWriteBucket {
	return m.ns
}

// CurrentVersion returns the current version of the service's database.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) CurrentVersion(ns walletdb.ReadBucket) (uint32, error) {
	if ns == nil {
		ns = m.ns
	}
	return fetchManagerVersion(ns)
}

// SetVersion sets the version of the service's database.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) SetVersion(ns walletdb.ReadWriteBucket,
	version uint32) error {

	if ns == nil {
		ns = m.ns
	}
	return putManagerVersion(m.ns, version)
}

// Versions returns all of the available database versions of the service.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Versions() []migration.Version {
	return versions
}

// upgradeToVersion2 upgrades the database from version 1 to version 2
// 'usedAddrBucketName' a bucket for storing addrs flagged as marked is
// initialized and it will be updated on the next rescan.
func upgradeToVersion2(ns walletdb.ReadWriteBucket) error {
	currentMgrVersion := uint32(2)

	_, err := ns.CreateBucketIfNotExists(usedAddrBucketName)
	if err != nil {
		str := "failed to create used addresses bucket"
		return managerError(ErrDatabase, str, err)
	}

	return putManagerVersion(ns, currentMgrVersion)
}

// upgradeToVersion5 upgrades the database from version 4 to version 5. After
// this update, the new ScopedKeyManager features cannot be used. This is due
// to the fact that in version 5, we now store the encrypted master private
// keys on disk. However, using the BIP0044 key scope, users will still be able
// to create old p2pkh addresses.
func upgradeToVersion5(ns walletdb.ReadWriteBucket) error {
	// First, we'll check if there are any existing segwit addresses, which
	// can't be upgraded to the new version. If so, we abort and warn the
	// user.
	err := ns.NestedReadBucket(addrBucketName).ForEach(
		func(k []byte, v []byte) error {
			row, err := deserializeAddressRow(v)
			if err != nil {
				return err
			}
			if row.addrType > adtScript {
				return fmt.Errorf("segwit address exists in " +
					"wallet, can't upgrade from v4 to " +
					"v5: well, we tried  ¯\\_(ツ)_/¯")
			}
			return nil
		})
	if err != nil {
		return err
	}

	// Next, we'll write out the new database version.
	if err := putManagerVersion(ns, 5); err != nil {
		return err
	}

	// First, we'll need to create the new buckets that are used in the new
	// database version.
	scopeBucket, err := ns.CreateBucket(scopeBucketName)
	if err != nil {
		str := "failed to create scope bucket"
		return managerError(ErrDatabase, str, err)
	}
	scopeSchemas, err := ns.CreateBucket(scopeSchemaBucketName)
	if err != nil {
		str := "failed to create scope schema bucket"
		return managerError(ErrDatabase, str, err)
	}

	// With the buckets created, we can now create the default BIP0044
	// scope which will be the only scope usable in the database after this
	// update.
	scopeKey := scopeToBytes(&KeyScopeBIP0044)
	scopeSchema := ScopeAddrMap[KeyScopeBIP0044]
	schemaBytes := scopeSchemaToBytes(&scopeSchema)
	if err := scopeSchemas.Put(scopeKey[:], schemaBytes); err != nil {
		return err
	}
	if err := createScopedManagerNS(scopeBucket, &KeyScopeBIP0044); err != nil {
		return err
	}

	bip44Bucket := scopeBucket.NestedReadWriteBucket(scopeKey[:])

	// With the buckets created, we now need to port over *each* item in
	// the prior main bucket, into the new default scope.
	mainBucket := ns.NestedReadWriteBucket(mainBucketName)

	// First, we'll move over the encrypted coin type private and public
	// keys to the new sub-bucket.
	encCoinPrivKeys := mainBucket.Get(coinTypePrivKeyName)
	encCoinPubKeys := mainBucket.Get(coinTypePubKeyName)

	err = bip44Bucket.Put(coinTypePrivKeyName, encCoinPrivKeys)
	if err != nil {
		return err
	}
	err = bip44Bucket.Put(coinTypePubKeyName, encCoinPubKeys)
	if err != nil {
		return err
	}

	if err := mainBucket.Delete(coinTypePrivKeyName); err != nil {
		return err
	}
	if err := mainBucket.Delete(coinTypePubKeyName); err != nil {
		return err
	}

	// Next, we'll move over everything that was in the meta bucket to the
	// meta bucket within the new scope.
	metaBucket := ns.NestedReadWriteBucket(metaBucketName)
	lastAccount := metaBucket.Get(lastAccountName)
	if err := metaBucket.Delete(lastAccountName); err != nil {
		return err
	}

	scopedMetaBucket := bip44Bucket.NestedReadWriteBucket(metaBucketName)
	err = scopedMetaBucket.Put(lastAccountName, lastAccount)
	if err != nil {
		return err
	}

	// Finally, we'll recursively move over a set of keys which were
	// formerly under the main bucket, into the new scoped buckets. We'll
	// do so by obtaining a slice of all the keys that we need to modify
	// and then recursing through each of them, moving both nested buckets
	// and key/value pairs.
	keysToMigrate := [][]byte{
		acctBucketName, addrBucketName, usedAddrBucketName,
		addrAcctIdxBucketName, acctNameIdxBucketName, acctIDIdxBucketName,
	}

	// Migrate each bucket recursively.
	for _, bucketKey := range keysToMigrate {
		err := migrateRecursively(ns, bip44Bucket, bucketKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// migrateRecursively moves a nested bucket from one bucket to another,
// recursing into nested buckets as required.
func migrateRecursively(src, dst walletdb.ReadWriteBucket,
	bucketKey []byte) error {
	// Within this bucket key, we'll migrate over, then delete each key.
	bucketToMigrate := src.NestedReadWriteBucket(bucketKey)
	newBucket, err := dst.CreateBucketIfNotExists(bucketKey)
	if err != nil {
		return err
	}
	err = bucketToMigrate.ForEach(func(k, v []byte) error {
		if nestedBucket := bucketToMigrate.
			NestedReadBucket(k); nestedBucket != nil {
			// We have a nested bucket, so recurse into it.
			return migrateRecursively(bucketToMigrate, newBucket, k)
		}

		if err := newBucket.Put(k, v); err != nil {
			return err
		}

		return bucketToMigrate.Delete(k)
	})
	if err != nil {
		return err
	}
	// Finally, we'll delete the bucket itself.
	if err := src.DeleteNestedBucket(bucketKey); err != nil {
		return err
	}
	return nil
}

// populateBirthdayBlock is a migration that attempts to populate the birthday
// block of the wallet. This is needed so that in the event that we need to
// perform a rescan of the wallet, we can do so starting from this block, rather
// than from the genesis block.
//
// NOTE: This migration cannot guarantee the correctness of the birthday block
// being set as we do not store block timestamps, so a sanity check must be done
// upon starting the wallet to ensure we do not potentially miss any relevant
// events when rescanning.
func populateBirthdayBlock(ns walletdb.ReadWriteBucket) error {
	// We'll need to jump through some hoops in order to determine the
	// corresponding block height for our birthday timestamp. Since we do
	// not store block timestamps, we'll need to estimate our height by
	// looking at the genesis timestamp and assuming a block occurs every 10
	// minutes. This can be unsafe, and cause us to actually miss on-chain
	// events, so a sanity check is done before the wallet attempts to sync
	// itself.
	//
	// We'll start by fetching our birthday timestamp.
	birthdayTimestamp, err := fetchBirthday(ns)
	if err != nil {
		return fmt.Errorf("unable to fetch birthday timestamp: %v", err)
	}

	log.Infof("Setting the wallet's birthday block from timestamp=%v",
		birthdayTimestamp)

	// Now, we'll need to determine the timestamp of the genesis block for
	// the corresponding chain.
	genesisHash, err := fetchBlockHash(ns, 0)
	if err != nil {
		return fmt.Errorf("unable to fetch genesis block hash: %v", err)
	}

	var genesisTimestamp time.Time
	switch *genesisHash {
	case *chaincfg.MainNetParams.GenesisHash:
		genesisTimestamp =
			chaincfg.MainNetParams.GenesisBlock.Header.Timestamp

	case *chaincfg.TestNet3Params.GenesisHash:
		genesisTimestamp =
			chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp

	case *chaincfg.RegressionNetParams.GenesisHash:
		genesisTimestamp =
			chaincfg.RegressionNetParams.GenesisBlock.Header.Timestamp

	case *chaincfg.SimNetParams.GenesisHash:
		genesisTimestamp =
			chaincfg.SimNetParams.GenesisBlock.Header.Timestamp

	default:
		return fmt.Errorf("unknown genesis hash %v", genesisHash)
	}

	// With the timestamps retrieved, we can estimate a block height by
	// taking the difference between them and dividing by the average block
	// time (10 minutes).
	birthdayHeight := int32((birthdayTimestamp.Sub(genesisTimestamp).Seconds() / 600))

	// Now that we have the height estimate, we can fetch the corresponding
	// block and set it as our birthday block.
	birthdayHash, err := fetchBlockHash(ns, birthdayHeight)

	// To ensure we record a height that is known to us from the chain,
	// we'll make sure this height estimate can be found. Otherwise, we'll
	// continue subtracting a day worth of blocks until we can find one.
	for IsError(err, ErrBlockNotFound) {
		birthdayHeight -= 144
		if birthdayHeight < 0 {
			birthdayHeight = 0
		}
		birthdayHash, err = fetchBlockHash(ns, birthdayHeight)
	}
	if err != nil {
		return err
	}

	log.Infof("Estimated birthday block from timestamp=%v: height=%d, "+
		"hash=%v", birthdayTimestamp, birthdayHeight, birthdayHash)

	// NOTE: The timestamp of the birthday block isn't set since we do not
	// store each block's timestamp.
	return PutBirthdayBlock(ns, BlockStamp{
		Height: birthdayHeight,
		Hash:   *birthdayHash,
	})
}

// resetSyncedBlockToBirthday is a migration that resets the wallet's currently
// synced block to its birthday block. This essentially serves as a migration to
// force a rescan of the wallet.
func resetSyncedBlockToBirthday(ns walletdb.ReadWriteBucket) error {
	syncBucket := ns.NestedReadWriteBucket(syncBucketName)
	if syncBucket == nil {
		return errors.New("sync bucket does not exist")
	}

	birthdayBlock, err := FetchBirthdayBlock(ns)
	if err != nil {
		return err
	}

	return PutSyncedTo(ns, &birthdayBlock)
}

// storeMaxReorgDepth is a migration responsible for allowing the wallet to only
// maintain MaxReorgDepth block hashes stored in order to recover from long
// reorgs.
func storeMaxReorgDepth(ns walletdb.ReadWriteBucket) error {
	// Retrieve the current tip of the wallet. We'll use this to determine
	// the highest stale height we currently have stored within it.
	syncedTo, err := fetchSyncedTo(ns)
	if err != nil {
		return err
	}
	maxStaleHeight := staleHeight(syncedTo.Height)

	// It's possible for this height to be non-sensical if we have less than
	// MaxReorgDepth blocks stored, so we can end the migration now.
	if maxStaleHeight < 1 {
		return nil
	}

	log.Infof("Removing block hash entries beyond maximum reorg depth of "+
		"%v from current tip %v", MaxReorgDepth, syncedTo.Height)

	// Otherwise, since we currently store all block hashes of the chain
	// before this migration, we'll remove all stale block hash entries
	// above the genesis block. This would leave us with only MaxReorgDepth
	// blocks stored.
	for height := maxStaleHeight; height > 0; height-- {
		if err := deleteBlockHash(ns, height); err != nil {
			return err
		}
	}

	return nil
}
