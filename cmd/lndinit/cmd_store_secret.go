package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jessevdk/go-flags"
)

type targetK8s struct {
	k8sSecretOptions

	Helm *helmOptions `group:"Flags for configuring the Helm annotations (use when --target=k8s)" namespace:"helm"`
}

type secretEntry struct {
	name  string
	value string
}

type storeSecretCommand struct {
	Batch     bool       `long:"batch" description:"Instead of reading one secret from stdin, read all files of the argument list and store them as entries in the secret"`
	Overwrite bool       `long:"overwrite" description:"Overwrite existing secret entries instead of aborting"`
	Target    string     `long:"target" short:"t" description:"Secret storage target" choice:"k8s"`
	K8s       *targetK8s `group:"Flags for storing the secret as a value inside a Kubernetes Secret (use when --target=k8s)" namespace:"k8s"`
}

func newStoreSecretCommand() *storeSecretCommand {
	return &storeSecretCommand{
		Target: storageK8s,
		K8s: &targetK8s{
			k8sSecretOptions: k8sSecretOptions{
				Namespace: defaultK8sNamespace,
			},
			Helm: &helmOptions{
				ResourcePolicy: defaultK8sResourcePolicy,
			},
		},
	}
}

func (x *storeSecretCommand) Register(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"store-secret",
		"Store secret(s) to an external secrets storage",
		"Read a one line secret from stdin and store it to the "+
			"external secrets storage indicated by the --target "+
			"flag; if the --batch flag is used, instead of "+
			"reading a single secret from stdin, each command "+
			"line argument is treated as a file and each file's "+
			"content is added to the secret with the file's name "+
			"as the secret's entry name",
		x,
	)
	return err
}

func (x *storeSecretCommand) Execute(args []string) error {
	var entries []*secretEntry

	switch {
	case x.Batch && len(args) == 0:
		return fmt.Errorf("at least one command line argument is " +
			"required when using --batch flag")

	case x.Batch:
		for _, file := range args {
			log("Reading secret from file %s", file)
			content, err := readFile(file)
			if err != nil {
				return fmt.Errorf("cannot read file %s: %v",
					file, err)
			}

			entries = append(entries, &secretEntry{
				name:  filepath.Base(file),
				value: content,
			})
		}

	default:
		log("Reading secret from stdin")
		secret, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading secret from stdin: %v",
				err)
		}
		entries = append(entries, &secretEntry{value: secret})
	}

	switch x.Target {
	case storageK8s:
		// Take the actual entry name from the options if we aren't in
		// batch mode.
		if len(entries) == 1 && entries[0].name == "" {
			entries[0].name = x.K8s.SecretEntryName
		}

		return storeSecretsK8s(entries, x.K8s, x.Overwrite)

	default:
		return fmt.Errorf("invalid secret storage target %s", x.Target)
	}
}

func storeSecretsK8s(entries []*secretEntry, opts *targetK8s,
	overwrite bool) error {

	if opts.SecretName == "" {
		return fmt.Errorf("secret name is required")
	}

	for _, entry := range entries {
		if entry.name == "" {
			return fmt.Errorf("secret entry name is required")
		}

		entryOpts := &k8sSecretOptions{
			Namespace:       opts.Namespace,
			SecretName:      opts.SecretName,
			SecretEntryName: entry.name,
		}

		log("Storing entry with name %s to secret %s in namespace %s",
			entryOpts.SecretEntryName, entryOpts.SecretName,
			entryOpts.Namespace)
		err := saveK8s(entry.value, entryOpts, overwrite, opts.Helm)
		if err != nil {
			return fmt.Errorf("error storing secret %s entry %s: "+
				"%v", opts.SecretName, entry.name, err)
		}
	}

	return nil
}
