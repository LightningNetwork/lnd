package feature

import (
	"fmt"

	"github.com/lightningnetwork/lnd/lnwire"
)

// Config houses any runtime modifications to the default set descriptors. For
// our purposes, this typically means disabling certain features to test legacy
// protocol interoperability or functionality.
type Config struct {
	// NoTLVOnion unsets any optional or required TLVOnionPaylod bits from
	// all feature sets.
	NoTLVOnion bool

	// NoStaticRemoteKey unsets any optional or required StaticRemoteKey
	// bits from all feature sets.
	NoStaticRemoteKey bool

	// NoAnchors unsets any bits signaling support for anchor outputs.
	NoAnchors bool

	// NoWumbo unsets any bits signalling support for wumbo channels.
	NoWumbo bool

	// NoZeroConfChannels signals that this peer doesn't accept zero conf
	// and will fail accept_channel response that contains minimum_depth
	// as zero.
	NoZeroConfChannels bool
}

// Manager is responsible for generating feature vectors for different requested
// feature sets.
type Manager struct {
	// fsets is a static map of feature set to raw feature vectors. Requests
	// are fulfilled by cloning these interal feature vectors.
	fsets map[Set]*lnwire.RawFeatureVector
}

// NewManager creates a new feature Manager, applying any custom modifications
// to its feature sets before returning.
func NewManager(cfg Config) (*Manager, error) {
	return newManager(cfg, defaultSetDesc)
}

// newManager creates a new feature Manager, applying any custom modifications
// to its feature sets before returning. This method accepts the setDesc as its
// own parameter so that it can be unit tested.
func newManager(cfg Config, desc setDesc) (*Manager, error) {
	// First build the default feature vector for all known sets.
	fsets := make(map[Set]*lnwire.RawFeatureVector)
	for bit, sets := range desc {
		for set := range sets {
			// Fetch the feature vector for this set, allocating a
			// new one if it doesn't exist.
			fv, ok := fsets[set]
			if !ok {
				fv = lnwire.NewRawFeatureVector()
			}

			// Set the configured bit on the feature vector,
			// ensuring that we don't set two feature bits for the
			// same pair.
			err := fv.SafeSet(bit)
			if err != nil {
				return nil, fmt.Errorf("unable to set "+
					"%v in %v: %v", bit, set, err)
			}

			// Write the updated feature vector under its set.
			fsets[set] = fv
		}
	}

	// Now, remove any features as directed by the config.
	for set, raw := range fsets {
		if cfg.NoTLVOnion {
			raw.Unset(lnwire.TLVOnionPayloadOptional)
			raw.Unset(lnwire.TLVOnionPayloadRequired)
			raw.Unset(lnwire.PaymentAddrOptional)
			raw.Unset(lnwire.PaymentAddrRequired)
			raw.Unset(lnwire.MPPOptional)
			raw.Unset(lnwire.MPPRequired)
		}
		if cfg.NoStaticRemoteKey {
			raw.Unset(lnwire.StaticRemoteKeyOptional)
			raw.Unset(lnwire.StaticRemoteKeyRequired)
		}
		if cfg.NoAnchors {
			raw.Unset(lnwire.AnchorsOptional)
			raw.Unset(lnwire.AnchorsRequired)
		}
		if cfg.NoWumbo {
			raw.Unset(lnwire.WumboChannelsOptional)
			raw.Unset(lnwire.WumboChannelsRequired)
		}
		if cfg.NoZeroConfChannels {
			raw.Unset(lnwire.SkipFundingConfirmationOptional)
			raw.Unset(lnwire.SkipFundingConfirmationRequired)
		}

		// Ensure that all of our feature sets properly set any
		// dependent features.
		fv := lnwire.NewFeatureVector(raw, lnwire.Features)
		err := ValidateDeps(fv)
		if err != nil {
			return nil, fmt.Errorf("invalid feature set %v: %v",
				set, err)
		}
	}

	return &Manager{
		fsets: fsets,
	}, nil
}

// GetRaw returns a raw feature vector for the passed set. If no set is known,
// an empty raw feature vector is returned.
func (m *Manager) GetRaw(set Set) *lnwire.RawFeatureVector {
	if fv, ok := m.fsets[set]; ok {
		return fv.Clone()
	}

	return lnwire.NewRawFeatureVector()
}

// Get returns a feature vector for the passed set. If no set is known, an empty
// feature vector is returned.
func (m *Manager) Get(set Set) *lnwire.FeatureVector {
	raw := m.GetRaw(set)
	return lnwire.NewFeatureVector(raw, lnwire.Features)
}

// ListSets returns a list of the feature sets that our node supports.
func (m *Manager) ListSets() []Set {
	var sets []Set

	for set := range m.fsets {
		sets = append(sets, set)
	}

	return sets
}
