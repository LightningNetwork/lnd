package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

const (
	defaultK8sServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/" +
		"serviceaccount/token"

	vaultApiPathK8sAuth = "/v1/auth/kubernetes/login"
)

type jsonAuthResponse struct {
	Auth struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		LeaseDuration int      `json:"lease_duration"`
		Renewable     bool     `json:"renewable"`
		Metadata      struct {
			Role                     string `json:"role"`
			ServiceAccountName       string `json:"service_account_name"`
			ServiceAccountNamespace  string `json:"service_account_namespace"`
			ServiceAccountSecretName string `json:"service_account_secret_name"`
			ServiceAccountUID        string `json:"service_account_uid"`
		} `json:"metadata"`
	} `json:"auth"`
}

type jsonK8sAuthConfig struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

type vaultSecretOptions struct {
	AuthTokenPath   string `long:"auth-token-path" description:"The full path to the token file that should be used to authenticate against HashiCorp Vault"`
	AuthRole        string `long:"auth-role" description:"The role to acquire when logging into HashiCorp Vault"`
	SecretName      string `long:"secret-name" description:"The name of the Vault secret"`
	SecretEntryName string `long:"secret-entry-name" description:"The name of the entry within the secret"`
}

type jsonVaultObject struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

func saveVault(content string, opts *vaultSecretOptions, overwrite bool) error {
	client, err := getClientVault(opts)
	if err != nil {
		return err
	}

	secret, exists, err := getSecretVault(client, opts.SecretName)
	if err != nil {
		return err
	}

	secretData := make(map[string]interface{})
	if exists {
		secretData = secret.Data
	}

	return storeSecretVault(client, secretData, opts, overwrite, content)
}

func readVault(opts *vaultSecretOptions) (string, *jsonVaultObject, error) {
	client, err := getClientVault(opts)
	if err != nil {
		return "", nil, err
	}

	secret, exists, err := getSecretVault(client, opts.SecretName)
	if err != nil {
		return "", nil, err
	}

	if !exists {
		return "", nil, fmt.Errorf("secret %s does not exist in vault",
			opts.SecretName)
	}

	if len(secret.Data) == 0 {
		return "", nil, fmt.Errorf("secret %s exists but contains no "+
			"data", opts.SecretName)
	}

	entry := secret.Data[opts.SecretEntryName]
	stringEntry, isString := entry.(string)
	if entry == nil || (isString && len(stringEntry) == 0) {
		return "", nil, fmt.Errorf("secret %s exists but does not "+
			"contain the entry %s", opts.SecretName,
			opts.SecretEntryName)
	}

	// Remove any newlines at the end of the file. We won't ever write a
	// newline ourselves but maybe the file was provisioned by another
	// process or user.
	content := strings.TrimRight(stringEntry, "\r\n")

	return content, &jsonVaultObject{
		RequestID:     secret.RequestID,
		LeaseID:       secret.LeaseID,
		LeaseDuration: secret.LeaseDuration,
		Renewable:     secret.Renewable,
	}, nil
}

func getClientVault(opts *vaultSecretOptions) (*api.Client, error) {
	log("Creating vault config from environment")
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("error reading vault config from env: "+
			"%v", cfg.Error)
	}

	log("Creating vault client")
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating vault client: %v", err)
	}

	log("Reading auth token %s", opts.AuthTokenPath)
	token, err := readFile(opts.AuthTokenPath)
	if err != nil {
		return nil, fmt.Errorf("error reading auth token %s: %v",
			opts.AuthTokenPath, err)
	}

	if len(token) == 0 {
		return nil, fmt.Errorf("token %s is empty", opts.AuthTokenPath)
	}
	if len(opts.AuthRole) == 0 {
		return nil, fmt.Errorf("the --auth-role flag must be set")
	}

	log("Authenticating with auth token")
	conf := &jsonK8sAuthConfig{
		JWT:  token,
		Role: opts.AuthRole,
	}
	req := client.NewRequest("POST", vaultApiPathK8sAuth)
	if err := req.SetJSONBody(conf); err != nil {
		return nil, fmt.Errorf("error marshalling auth config: %v", err)
	}

	res, err := client.RawRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error sending auth request: %v", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error response from vault server: "+
			"%d - %s", res.StatusCode, res.Status)
	}

	authResponse := &jsonAuthResponse{}
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}
	if err = json.Unmarshal(respBody, authResponse); err != nil {
		return nil, fmt.Errorf("error parsing auth response: %v", err)
	}

	log("Authenticated successfully with vault server, acquired policies "+
		"%v", authResponse.Auth.Policies)
	client.SetToken(authResponse.Auth.ClientToken)

	log("Vault client created successfully")
	return client, nil
}

func getSecretVault(client *api.Client, name string) (*api.Secret, bool, error) {
	log("Attempting to load secret %s from vault", name)
	secret, err := client.Logical().Read(name)

	switch {
	case err == nil && secret != nil:
		log("Secret %s loaded successfully", name)
		return secret, true, nil

	case secret == nil:
		log("Secret %s not found in vault, got error %v", name, err)
		return nil, false, nil

	default:
		return nil, false, fmt.Errorf("error querying secret "+
			"existence: %v", err)
	}
}

func storeSecretVault(client *api.Client, secretData map[string]interface{},
	opts *vaultSecretOptions, overwrite bool, content string) error {

	if secretData[opts.SecretEntryName] != nil && !overwrite {
		return fmt.Errorf("entry %s in secret %s already exists: %v",
			opts.SecretEntryName, opts.SecretName,
			errTargetExists)
	}

	secretData[opts.SecretEntryName] = content

	log("Attempting to update entry %s of secret %s in vault",
		opts.SecretEntryName, opts.SecretName)

	_, err := client.Logical().Write(opts.SecretName, secretData)
	if err != nil {
		return fmt.Errorf("error updating secret %s in vault: %v",
			opts.SecretName, err)
	}
	
	log("Updated secret %s", opts.SecretName)

	return nil
}
