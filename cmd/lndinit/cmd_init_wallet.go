package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
)

const (
	defaultNoFreelistSync = true

	defaultDirPermissions os.FileMode = 0700

	defaultBitcoinNetwork = "mainnet"
)

var (
	defaultWalletDBTimeout = 2 * time.Second
)

type secretSourceFile struct {
	Seed           string `long:"seed" description:"The full path to the file that contains the seed; if the file does not exist, lndinit will exit with code EXIT_CODE_INPUT_MISSING (129)"`
	SeedPassphrase string `long:"seed-passphrase" description:"The full path to the file that contains the seed passphrase; if not set, no passphrase will be used; if set but the file does not exist, lndinit will exit with code EXIT_CODE_INPUT_MISSING (129)"`
	WalletPassword string `long:"wallet-password" description:"The full path to the file that contains the wallet password; if the file does not exist, lndinit will exit with code EXIT_CODE_INPUT_MISSING (129)"`
}

type secretSourceK8s struct {
	Namespace               string `long:"namespace" description:"The Kubernetes namespace the secret is located in"`
	SecretName              string `long:"secret-name" description:"The name of the Kubernetes secret"`
	SeedEntryName           string `long:"seed-entry-name" description:"The name of the entry within the secret that contains the seed"`
	SeedPassphraseEntryName string `long:"seed-passphrase-entry-name" description:"The name of the entry within the secret that contains the seed passphrase"`
	WalletPasswordEntryName string `long:"wallet-password-entry-name" description:"The name of the entry within the secret that contains the wallet password"`
}

type initWalletCommand struct {
	Network          string            `long:"network" description:"The Bitcoin network to initialize the wallet for, required for wallet internals" choice:"mainnet" choice:"testnet" choice:"testnet3" choice:"regtest" choice:"simnet"`
	SecretSource     string            `long:"secret-source" description:"Where to read the secrets from to initialize the wallet with" choice:"file" choice:"k8s"`
	File             *secretSourceFile `group:"Flags for reading the secrets from files (use when --secret-source=file)" namespace:"file"`
	K8s              *secretSourceK8s  `group:"Flags for reading the secrets from Kubernetes (use when --secret-source=k8s)" namespace:"k8s"`
	OutputWalletDir  string            `long:"output-wallet-dir" description:"The directory in which the wallet.db file should be initialized"`
	ValidatePassword bool              `long:"validate-password" description:"If a wallet file already exists in the output wallet directory, validate that it can be unlocked with the given password; this will try to decrypt the wallet and will take several seconds to complete"`
}

func newInitWalletCommand() *initWalletCommand {
	return &initWalletCommand{
		Network:      defaultBitcoinNetwork,
		SecretSource: storageFile,
		File:         &secretSourceFile{},
		K8s: &secretSourceK8s{
			Namespace: defaultK8sNamespace,
		},
	}
}

func (x *initWalletCommand) Register(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"init-wallet",
		"Initialize an lnd wallet database",
		"Create an lnd wallet.db database file initialized with the "+
			"given wallet seed and password",
		x,
	)
	return err
}

func (x *initWalletCommand) Execute(_ []string) error {
	// First find out where we want to read the secrets from.
	var (
		seed           string
		seedPassPhrase string
		walletPassword string
		err            error
	)
	switch x.SecretSource {
	// Read all secrets from individual files.
	case storageFile:
		log("Reading seed from file")
		seed, err = readFile(x.File.Seed)
		if err != nil {
			return err
		}

		// The seed passphrase is optional.
		if x.File.SeedPassphrase != "" {
			log("Reading seed passphrase from file")
			seedPassPhrase, err = readFile(x.File.SeedPassphrase)
			if err != nil {
				return err
			}
		}

		log("Reading wallet password from file")
		walletPassword, err = readFile(x.File.WalletPassword)
		if err != nil {
			return err
		}

	// Read passphrase from Kubernetes secret.
	case storageK8s:
		k8sSecret := &k8sSecretOptions{
			Namespace:  x.K8s.Namespace,
			SecretName: x.K8s.SecretName,
		}
		k8sSecret.SecretEntryName = x.K8s.SeedEntryName

		log("Reading seed from k8s secret %s (namespace %s)",
			x.K8s.SecretName, x.K8s.Namespace)
		seed, _, err = readK8s(k8sSecret)
		if err != nil {
			return err
		}

		// The seed passphrase is optional.
		if x.K8s.SeedPassphraseEntryName != "" {
			log("Reading seed passphrase from k8s secret %s "+
				"(namespace %s)", x.K8s.SecretName,
				x.K8s.Namespace)
			k8sSecret.SecretEntryName = x.K8s.SeedPassphraseEntryName
			seedPassPhrase, _, err = readK8s(k8sSecret)
			if err != nil {
				return err
			}
		}

		log("Reading wallet password from k8s secret %s (namespace %s)",
			x.K8s.SecretName, x.K8s.Namespace)
		k8sSecret.SecretEntryName = x.K8s.WalletPasswordEntryName
		walletPassword, _, err = readK8s(k8sSecret)
		if err != nil {
			return err
		}

	}

	// Decrypt the seed now to make sure we got valid data before we
	// check anything else.
	seedWords := strings.Split(seed, " ")
	if len(seedWords) != aezeed.NumMnemonicWords {
		return fmt.Errorf("invalid seed, expected %d words but got %d",
			aezeed.NumMnemonicWords, len(seedWords))
	}
	var seedMnemonic aezeed.Mnemonic
	copy(seedMnemonic[:], seedWords)
	cipherSeed, err := seedMnemonic.ToCipherSeed([]byte(seedPassPhrase))
	if err != nil {
		return fmt.Errorf("error decrypting seed with passphrase: %v",
			err)
	}

	// The output directory must be specified explicitly. We don't want to
	// assume any defaults here!
	walletDir := lncfg.CleanAndExpandPath(x.OutputWalletDir)
	if walletDir == "" {
		return fmt.Errorf("must specify output wallet directory")
	}
	if strings.HasSuffix(walletDir, ".db") {
		return fmt.Errorf("output wallet directory must not be a file")
	}

	// The wallet directory must either not exist yet or be a directory.
	stat, err := os.Stat(walletDir)
	switch {
	case os.IsNotExist(err):
		err = os.MkdirAll(walletDir, defaultDirPermissions)
		if err != nil {
			return fmt.Errorf("error creating directory %s: %v",
				walletDir, err)
		}

	case !stat.IsDir():
		return fmt.Errorf("output wallet directory must not be a file")
	}

	// We should now be able to properly determine if a wallet already
	// exists or not. Depending on the flags, we either create or validate
	// the wallet now.
	walletFile := filepath.Join(walletDir, wallet.WalletDBName)
	switch {
	case lnrpc.FileExists(walletFile) && !x.ValidatePassword:
		return fmt.Errorf("wallet file %s exists: %v", walletFile,
			errTargetExists)

	case !lnrpc.FileExists(walletFile):
		return createWallet(
			walletDir, cipherSeed, []byte(walletPassword),
			x.Network,
		)

	default:
		return validateWallet(
			walletDir, []byte(walletPassword), x.Network,
		)
	}
}

func createWallet(walletDir string, cipherSeed *aezeed.CipherSeed,
	walletPassword []byte, network string) error {

	log("Creating new wallet in %s", walletDir)

	// The network parameters are needed for some wallet internal things
	// like the chain genesis hash and timestamp.
	netParams, err := getNetworkParams(network)
	if err != nil {
		return err
	}

	// Create the wallet now.
	loader := wallet.NewLoader(
		netParams, walletDir, defaultNoFreelistSync,
		defaultWalletDBTimeout, 0,
	)

	_, err = loader.CreateNewWallet(
		walletPassword, walletPassword, cipherSeed.Entropy[:],
		cipherSeed.BirthdayTime(),
	)
	if err != nil {
		return fmt.Errorf("error creating wallet from seed: %v", err)
	}

	// Close the wallet properly to release the file lock on the DB.
	if err := loader.UnloadWallet(); err != nil {
		return fmt.Errorf("error unloading wallet after creation: %v",
			err)
	}

	log("Wallet created successfully in %s", walletDir)

	return nil
}

func validateWallet(walletDir string, walletPassword []byte,
	network string) error {

	log("Validating password for wallet in %s", walletDir)

	// The network parameters are needed for some wallet internal things
	// like the chain genesis hash and timestamp.
	netParams, err := getNetworkParams(network)
	if err != nil {
		return err
	}

	// Try to load the wallet now. This will fail if the wallet is already
	// loaded by another process or does not exist yet.
	loader := wallet.NewLoader(
		netParams, walletDir, defaultNoFreelistSync,
		defaultWalletDBTimeout, 0,
	)
	_, err = loader.OpenExistingWallet(walletPassword, false)
	if err != nil {
		return fmt.Errorf("error validating wallet password: %v", err)
	}

	if err := loader.UnloadWallet(); err != nil {
		return fmt.Errorf("error unloading wallet after validation: %v",
			err)
	}

	log("Wallet password validated successfully")

	return nil
}

func getNetworkParams(network string) (*chaincfg.Params, error) {
	switch strings.ToLower(network) {
	case "mainnet":
		return &chaincfg.MainNetParams, nil

	case "testnet", "testnet3":
		return &chaincfg.TestNet3Params, nil

	case "regtest":
		return &chaincfg.RegressionNetParams, nil

	case "simnet":
		return &chaincfg.SimNetParams, nil

	default:
		return nil, fmt.Errorf("unknown network: %v", network)
	}
}
