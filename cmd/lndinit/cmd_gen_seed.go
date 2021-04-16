package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/aezeed"
)

const (
	defaultEntropyBytes = 16
)

type jsonSeed struct {
	Seed     string `json:"seed"`
	Birthday int64  `json:"birthday_timestamp"`
}

type genSeedCommand struct {
	EntropySourceFile string            `long:"entropy-source-file" description:"The file descriptor to read the seed entropy from; if set lndinit will read exactly 16 bytes from the file, otherwise the default crypto/rand source will be used"`
	PassphraseFile    string            `long:"passphrase-file" description:"The file to read the seed passphrase from; if not set, no seed passphrase will be used, unless --passhprase-k8s is used"`
	PassphraseK8s     *k8sSecretOptions `group:"Flags for reading seed passphrase from Kubernetes" namespace:"passphrase-k8s"`
	Output            string            `long:"output" short:"o" description:"Output format" choice:"raw" choice:"json"`
}

func newGenSeedCommand() *genSeedCommand {
	return &genSeedCommand{
		Output: outputFormatRaw,
		PassphraseK8s: &k8sSecretOptions{
			Namespace: defaultK8sNamespace,
		},
	}
}

func (x *genSeedCommand) Register(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"gen-seed",
		"Generate an lnd wallet seed",
		"Generate a fresh lnd wallet seed (aezeed) with 16 bytes of "+
			"entropy read from the given entropy file or the "+
			"system's default cryptographic entropy source; the "+
			"seed is printed to stdout, either as raw text or "+
			"formatted as JSON",
		x,
	)
	return err
}

func (x *genSeedCommand) Execute(_ []string) error {
	// First find out if we want to set a seed passphrase.
	var (
		passPhrase string
		err        error
	)
	switch {
	// Both file and Kubernetes input set.
	case x.PassphraseFile != "" && x.PassphraseK8s.AnySet():
		return fmt.Errorf("invalid passphrase input, either use file " +
			"or k8s but not both")

	// Read passphrase from file.
	case x.PassphraseFile != "":
		passPhrase, err = readFile(x.PassphraseFile)

	// Read passphrase from Kubernetes secret.
	case x.PassphraseK8s.AnySet():
		passPhrase, _, err = readK8s(x.PassphraseK8s)

	}
	if err != nil {
		return err
	}

	// Next read our entropy either from the given source or the default
	// crypto/rand source.
	var entropy [defaultEntropyBytes]byte
	if x.EntropySourceFile != "" {
		file, err := os.Open(x.EntropySourceFile)
		if err != nil {
			return fmt.Errorf("unable to open entropy source file "+
				"%s: %v", x.EntropySourceFile, err)
		}

		// Try to read exactly the number of bytes we require and make
		// sure we've actually also read that many.
		numRead, err := file.Read(entropy[:])
		if err != nil {
			return fmt.Errorf("unable to read from entropy source "+
				"file %s: %v", x.EntropySourceFile, err)
		}
		if numRead != defaultEntropyBytes {
			return fmt.Errorf("unable to read %d bytes from "+
				"entropy source, only got %d",
				defaultEntropyBytes, numRead)
		}

	} else {
		if _, err := rand.Read(entropy[:]); err != nil {
			return fmt.Errorf("unable get seed entropy: %v", err)
		}
	}

	// We now have everything we need for creating the cipher seed.
	seed, err := aezeed.New(aezeed.CipherSeedVersion, &entropy, time.Now())
	if err != nil {
		return fmt.Errorf("error creating cipher seed: %v", err)
	}
	mnemonic, err := seed.ToMnemonic([]byte(passPhrase))
	if err != nil {
		return fmt.Errorf("error encrypting cipher seed: %v", err)
	}

	seedWords := strings.Join(mnemonic[:], " ")
	if x.Output == outputFormatJSON {
		seedWords, err = asJSON(&jsonSeed{
			Seed:     seedWords,
			Birthday: seed.BirthdayTime().Unix(),
		})
	}

	fmt.Printf("%s\n", seedWords)

	return nil
}
