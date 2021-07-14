package main

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/kkdai/bstream"
	"github.com/lightningnetwork/lnd/aezeed"
)

const (
	defaultNumMnemonicWords     = 8
	defaultPasswordEntropyBits  = aezeed.BitsPerWord * defaultNumMnemonicWords
	defaultPasswordEntropyBytes = defaultPasswordEntropyBits / 8
)

type jsonPassword struct {
	Password string `json:"password"`
}

type genPasswordCommand struct {
	Output string `long:"output" short:"o" description:"Output format" choice:"raw" choice:"json"`
}

func newGenPasswordCommand() *genPasswordCommand {
	return &genPasswordCommand{
		Output: outputFormatRaw,
	}
}

func (x *genPasswordCommand) Register(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"gen-password",
		"Generate a strong password",
		"Generate a strong password with 11 bytes of entropy and "+
			"print it to stdout, either as raw text or "+
			"formatted as JSON",
		x,
	)
	return err
}

func (x *genPasswordCommand) Execute(_ []string) error {
	// Read a few bytes of random entropy.
	var password [defaultPasswordEntropyBytes]byte
	if _, err := rand.Read(password[:]); err != nil {
		return fmt.Errorf("unable get password entropy: %v", err)
	}

	// Then turn the password bytes into a human readable password by using
	// the aezeed default mnemonic wordlist.
	cipherBits := bstream.NewBStreamReader(password[:])
	passwordWords := make([]string, defaultNumMnemonicWords)
	for i := 0; i < defaultNumMnemonicWords; i++ {
		index, err := cipherBits.ReadBits(aezeed.BitsPerWord)
		if err != nil {
			return err
		}

		passwordWords[i] = aezeed.DefaultWordList[index]
	}

	passwordString := strings.Join(passwordWords, "-")
	if x.Output == outputFormatJSON {
		var err error
		passwordString, err = asJSON(&jsonPassword{
			Password: passwordString,
		})
		if err != nil {
			return err
		}
	}

	fmt.Printf("%s\n", passwordString)

	return nil
}
