package migration

import (
	"errors"
	"sort"

	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrReversion is an error returned when an attempt to revert to a
	// previous version is detected. This is done to provide safety to users
	// as some upgrades may not be backwards-compatible.
	ErrReversion = errors.New("reverting to a previous version is not " +
		"supported")
)

// Version denotes the version number of the database. A migration can be used
// to bring a previous version of the database to a later one.
type Version struct {
	// Number represents the number of this version.
	Number uint32

	// Migration represents a migration function that modifies the database
	// state. Care must be taken so that consequent migrations build off of
	// the previous one in order to ensure the consistency of the database.
	Migration func(walletdb.ReadWriteBucket) error
}

// Manager is an interface that exposes the necessary methods needed in order to
// migrate/upgrade a service. Each service (i.e., an implementation of this
// interface) can then use the Upgrade function to perform any required database
// migrations.
type Manager interface {
	// Name returns the name of the service we'll be attempting to upgrade.
	Name() string

	// Namespace returns the top-level bucket of the service.
	Namespace() walletdb.ReadWriteBucket

	// CurrentVersion returns the current version of the service's database.
	CurrentVersion(walletdb.ReadBucket) (uint32, error)

	// SetVersion sets the version of the service's database.
	SetVersion(walletdb.ReadWriteBucket, uint32) error

	// Versions returns all of the available database versions of the
	// service.
	Versions() []Version
}

// GetLatestVersion returns the latest version available from the given slice.
func GetLatestVersion(versions []Version) uint32 {
	if len(versions) == 0 {
		return 0
	}

	// Before determining the latest version number, we'll sort the slice to
	// ensure it reflects the last element.
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Number < versions[j].Number
	})

	return versions[len(versions)-1].Number
}

// VersionsToApply determines which versions should be applied as migrations
// based on the current version.
func VersionsToApply(currentVersion uint32, versions []Version) []Version {
	// Assuming the migration versions are in increasing order, we'll apply
	// any migrations that have a version number lower than our current one.
	var upgradeVersions []Version
	for _, version := range versions {
		if version.Number > currentVersion {
			upgradeVersions = append(upgradeVersions, version)
		}
	}

	// Before returning, we'll sort the slice by its version number to
	// ensure the migrations are applied in their intended order.
	sort.Slice(upgradeVersions, func(i, j int) bool {
		return upgradeVersions[i].Number < upgradeVersions[j].Number
	})

	return upgradeVersions
}

// Upgrade attempts to upgrade a group of services exposed through the Manager
// interface. Each service will go through its available versions and determine
// whether it needs to apply any.
//
// NOTE: In order to guarantee fault-tolerance, each service upgrade should
// happen within the same database transaction.
func Upgrade(mgrs ...Manager) error {
	for _, mgr := range mgrs {
		if err := upgrade(mgr); err != nil {
			return err
		}
	}

	return nil
}

// upgrade attempts to upgrade a service expose through its implementation of
// the Manager interface. This function will determine whether any new versions
// need to be applied based on the service's current version and latest
// available one.
func upgrade(mgr Manager) error {
	// We'll start by fetching the service's current and latest version.
	ns := mgr.Namespace()
	currentVersion, err := mgr.CurrentVersion(ns)
	if err != nil {
		return err
	}
	versions := mgr.Versions()
	latestVersion := GetLatestVersion(versions)

	switch {
	// If the current version is greater than the latest, then the service
	// is attempting to revert to a previous version that's possibly
	// backwards-incompatible. To prevent this, we'll return an error
	// indicating so.
	case currentVersion > latestVersion:
		return ErrReversion

	// If the current version is behind the latest version, we'll need to
	// apply all of the newer versions in order to catch up to the latest.
	case currentVersion < latestVersion:
		versions := VersionsToApply(currentVersion, versions)
		mgrName := mgr.Name()
		ns := mgr.Namespace()

		for _, version := range versions {
			log.Infof("Applying %v migration #%d", mgrName,
				version.Number)

			// We'll only run a migration if there is one available
			// for this version.
			if version.Migration != nil {
				err := version.Migration(ns)
				if err != nil {
					log.Errorf("Unable to apply %v "+
						"migration #%d: %v", mgrName,
						version.Number, err)
					return err
				}
			}
		}

		// With all of the versions applied, we can now reflect the
		// latest version upon the service.
		if err := mgr.SetVersion(ns, latestVersion); err != nil {
			return err
		}

	// If the current version matches the latest one, there's no upgrade
	// needed and we can safely exit.
	case currentVersion == latestVersion:
	}

	return nil
}
