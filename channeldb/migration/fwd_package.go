package migration

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
)

var (
	fwdPackagesKey    = []byte("fwd-packages")
	openChannelBucket = []byte("open-chan-bucket")
	chanInfoKey       = []byte("chan-info-key")
	byteOrder         = binary.BigEndian
)

// MigrateFwdPackageKeys converts existing packages keys from
// lnwire.ShortChannelID to lnwire.ChannelID.
func MigrateFwdPackageKeys(tx kvdb.RwTx) error {
	log.Infof("Migrating forward packages keys...")

	openChanBkt := tx.ReadBucket(openChannelBucket)
	if openChanBkt == nil {
		return fmt.Errorf("%v bucket does not exist", string(openChannelBucket))
	}

	// First we create a mapping between ShortChannelID to ChannelID.
	shortIDToChanID := make(map[uint64][32]byte)

	// Iterating all nodes inside open channels bucket.
	err := openChanBkt.ForEach(func(k, v []byte) error {
		if v != nil {
			return nil
		}
		nodeChanBucket := openChanBkt.NestedReadBucket(k)
		if nodeChanBucket == nil {
			return fmt.Errorf("node channels bucket doesn't exist")
		}

		// Iterating all chains.
		return nodeChanBucket.ForEach(func(chainHash, v []byte) error {
			if v != nil {
				return nil
			}

			chainBucket := nodeChanBucket.NestedReadBucket(chainHash)
			if chainBucket == nil {
				return nil
			}

			// Iterating all channel points.
			return chainBucket.ForEach(func(chanPoint, v []byte) error {
				chanBucket := chainBucket.NestedReadBucket(chanPoint)
				chanID := channelIDFromSerializedOutpoint(chanPoint)

				infoBytes := chanBucket.Get(chanInfoKey)
				if infoBytes == nil {
					return fmt.Errorf("failed go get channel info")
				}

				// We are interested in the short channel id from the serialized channel info.
				r := bytes.NewReader(infoBytes)

				// Skip ChanType(1 bytes), ChainHash(32 bytes), FundingOutpoint(36 bytes)
				_, err := r.Seek(1+32+36, io.SeekStart)
				if err != nil {
					return err
				}

				// read short channel id
				var shortID uint64
				if err := binary.Read(r, byteOrder, &shortID); err != nil {
					return err
				}
				log.Infof("Mapping %v, to %x", shortID, chanID)
				shortIDToChanID[shortID] = chanID
				return nil

			})
		})
	})

	if err != nil {
		return err
	}

	// Now that we have the mapping we rename the packager buckets keys to the new format.
	fwdPkgBkt := tx.ReadWriteBucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return fmt.Errorf("%v bucket doesn't exist", string(fwdPackagesKey))
	}

	// First getting a list of keys to rename.
	var existingShortIDs []uint64
	err = fwdPkgBkt.ForEach(func(k, v []byte) error {
		existingShortIDs = append(existingShortIDs, byteOrder.Uint64(k))
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to iterate %v bucket", string(fwdPackagesKey))
	}

	for _, shortID := range existingShortIDs {
		chanID, ok := shortIDToChanID[shortID]
		if !ok {
			// TODO: Should we return error here?
			log.Infof("Couldn't find channel point for %v", shortID)
			continue
		}
		var oldKey [8]byte
		byteOrder.PutUint64(oldKey[:], shortID)
		log.Infof("Migrating bucket from %v to %x", shortID, chanID)

		// Unfortunately the db doesn't support rename so we need to
		// copy all bucket content.
		if err := copyBucket(fwdPkgBkt, fwdPkgBkt, oldKey[:], chanID[:]); err != nil {
			return err
		}

		// Now we can delete the old bucket.
		return fwdPkgBkt.DeleteNestedBucket(oldKey[:])
	}

	return nil
}

func channelIDFromSerializedOutpoint(chanPoint []byte) [32]byte {
	var cid [32]byte
	copy(cid[:], chanPoint[:32])
	cid[30] ^= chanPoint[33]
	cid[31] ^= chanPoint[34]
	return cid
}

func copyBucket(oldParent, newParent walletdb.ReadWriteBucket, oldkey, newkey []byte) error {
	oldBuck := oldParent.NestedReadWriteBucket(oldkey)
	newBuck, err := newParent.CreateBucket(newkey)
	if err != nil {
		return err
	}

	err = oldBuck.ForEach(func(k, v []byte) error {
		if v == nil {
			return copyBucket(oldBuck, newBuck, k, k)
		}
		return newBuck.Put(k, v)
	})
	return err
}
