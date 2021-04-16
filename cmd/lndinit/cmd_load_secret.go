package main

import (
	"fmt"

	"github.com/jessevdk/go-flags"
)

type loadSecretCommand struct {
	Source string              `long:"source" short:"s" description:"Secret storage source" choice:"k8s" choice:"vault"`
	K8s    *k8sSecretOptions   `group:"Flags for looking up the secret as a value inside a Kubernetes Secret (use when --source=k8s)" namespace:"k8s"`
	Vault  *vaultSecretOptions `group:"Flags for looking up the secret as a value inside a HashiCorp Vault (use when --source=vault)" namespace:"vault"`
	Output string              `long:"output" short:"o" description:"Output format" choice:"raw" choice:"json"`
}

func newLoadSecretCommand() *loadSecretCommand {
	return &loadSecretCommand{
		Source: storageK8s,
		K8s: &k8sSecretOptions{
			Namespace: defaultK8sNamespace,
		},
		Vault: &vaultSecretOptions{
			AuthTokenPath: defaultK8sServiceAccountTokenPath,
		},
		Output: outputFormatRaw,
	}
}

func (x *loadSecretCommand) Register(parser *flags.Parser) error {
	_, err := parser.AddCommand(
		"load-secret",
		"Load a secret from external secrets storage",
		"Load a secret from the selected external secrets storage and "+
			"print it to stdout, either as raw text or formatted "+
			"as JSON",
		x,
	)
	return err
}

func (x *loadSecretCommand) Execute(_ []string) error {
	switch x.Source {
	case storageK8s:
		content, secret, err := readK8s(x.K8s)
		if err != nil {
			return fmt.Errorf("error reading secret %s in "+
				"namespace %s: %v", x.K8s.SecretName,
				x.K8s.Namespace, err)
		}

		if x.Output == outputFormatJSON {
			content, err = asJSON(&struct {
				*jsonK8sObject `json:",inline"`
				Value          string `json:"value"`
			}{
				jsonK8sObject: secret,
				Value:         content,
			})
		}

		fmt.Printf("%s\n", content)

		return nil

	case storageVault:
		content, secret, err := readVault(x.Vault)
		if err != nil {
			return fmt.Errorf("error reading secret %s from "+
				"vault: %v", x.Vault.SecretName, err)
		}

		if x.Output == outputFormatJSON {
			content, err = asJSON(&struct {
				*jsonVaultObject `json:",inline"`
				Value            string `json:"value"`
			}{
				jsonVaultObject: secret,
				Value:           content,
			})
		}

		fmt.Printf("%s\n", content)

		return nil

	default:
		return fmt.Errorf("invalid secret storage source %s", x.Source)
	}
}
