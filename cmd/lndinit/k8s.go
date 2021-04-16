package main

import (
	"context"
	"fmt"
	"strings"

	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	defaultK8sNamespace      = "default"
	defaultK8sResourcePolicy = "keep"
)

type k8sSecretOptions struct {
	Namespace       string `long:"namespace" description:"The Kubernetes namespace the secret is located in"`
	SecretName      string `long:"secret-name" description:"The name of the Kubernetes secret"`
	SecretEntryName string `long:"secret-entry-name" description:"The name of the entry within the secret"`
}

func (s *k8sSecretOptions) AnySet() bool {
	return s.Namespace != defaultK8sNamespace || s.SecretName != "" ||
		s.SecretEntryName != ""
}

type helmOptions struct {
	Annotate       bool   `long:"annotate" description:"Whether Helm annotations should be added to the created secret"`
	ReleaseName    string `long:"release-name" description:"The value for the meta.helm.sh/release-name annotation"`
	ResourcePolicy string `long:"resource-policy" description:"The value for the helm.sh/resource-policy annotation"`
}

type jsonK8sObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

func saveK8s(content string, opts *k8sSecretOptions, overwrite bool,
	helm *helmOptions) error {

	client, err := getClientK8s()
	if err != nil {
		return err
	}

	secret, exists, err := getSecretK8s(
		client, opts.Namespace, opts.SecretName,
	)
	if err != nil {
		return err
	}

	if exists {
		return updateSecretValueK8s(
			client, secret, opts, overwrite, content,
		)
	}

	return createSecretK8s(client, opts, helm, content)
}

func readK8s(opts *k8sSecretOptions) (string, *jsonK8sObject, error) {
	client, err := getClientK8s()
	if err != nil {
		return "", nil, err
	}

	secret, exists, err := getSecretK8s(
		client, opts.Namespace, opts.SecretName,
	)
	if err != nil {
		return "", nil, err
	}

	if !exists {
		return "", nil, fmt.Errorf("secret %s does not exist in "+
			"namespace %s", opts.SecretName, opts.Namespace)
	}

	if len(secret.Data) == 0 {
		return "", nil, fmt.Errorf("secret %s exists but contains no "+
			"data", opts.SecretName)
	}

	if len(secret.Data[opts.SecretEntryName]) == 0 {
		return "", nil, fmt.Errorf("secret %s exists but does not "+
			"contain the entry %s", opts.SecretName,
			opts.SecretEntryName)
	}

	// Remove any newlines at the end of the file. We won't ever write a
	// newline ourselves but maybe the file was provisioned by another
	// process or user.
	content := strings.TrimRight(
		string(secret.Data[opts.SecretEntryName]), "\r\n",
	)

	return content, &jsonK8sObject{
		TypeMeta:   secret.TypeMeta,
		ObjectMeta: secret.ObjectMeta,
	}, nil
}

func getClientK8s() (*kubernetes.Clientset, error) {
	log("Creating k8s cluster config")
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to grab cluster config: %v", err)
	}

	log("Creating k8s cluster client")
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating cluster config: %v", err)
	}

	log("Cluster client created successfully")
	return client, nil
}

func getSecretK8s(client *kubernetes.Clientset, namespace,
	name string) (*api.Secret, bool, error) {

	log("Attempting to load secret %s from namespace %s", name, namespace)
	secret, err := client.CoreV1().Secrets(namespace).Get(
		context.Background(), name, metav1.GetOptions{},
	)

	switch {
	case err == nil:
		log("Secret %s loaded successfully", name)
		return secret, true, nil

	case errors.IsNotFound(err):
		log("Secret %s not found in namespace %s", name, namespace)
		return nil, false, nil

	default:
		return nil, false, fmt.Errorf("error querying secret "+
			"existence: %v", err)
	}
}

func updateSecretValueK8s(client *kubernetes.Clientset, secret *api.Secret,
	opts *k8sSecretOptions, overwrite bool, content string) error {

	if len(secret.Data) == 0 {
		log("Data of secret %s is empty, initializing", opts.SecretName)
		secret.Data = make(map[string][]byte)
	}

	if len(secret.Data[opts.SecretEntryName]) > 0 && !overwrite {
		return fmt.Errorf("entry %s in secret %s already exists: %v",
			opts.SecretEntryName, opts.SecretName,
			errTargetExists)
	}

	secret.Data[opts.SecretEntryName] = []byte(content)

	log("Attempting to update entry %s of secret %s in namespace %s",
		opts.SecretEntryName, opts.SecretName, opts.Namespace)
	updatedSecret, err := client.CoreV1().Secrets(opts.Namespace).Update(
		context.Background(), secret, metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("error updating secret %s in namespace %s: "+
			"%v", opts.SecretName, opts.Namespace, err)
	}

	jsonSecret, _ := asJSON(jsonK8sObject{
		TypeMeta:   updatedSecret.TypeMeta,
		ObjectMeta: updatedSecret.ObjectMeta,
	})
	log("Updated secret: %s", jsonSecret)

	return nil
}

func createSecretK8s(client *kubernetes.Clientset, opts *k8sSecretOptions,
	helm *helmOptions, content string) error {

	meta := metav1.ObjectMeta{
		Name: opts.SecretName,
	}

	if helm != nil && helm.Annotate {
		meta.Labels = map[string]string{
			"app.kubernetes.io/managed-by": "Helm",
		}
		meta.Annotations = map[string]string{
			"helm.sh/resource-policy":        helm.ResourcePolicy,
			"meta.helm.sh/release-name":      helm.ReleaseName,
			"meta.helm.sh/release-namespace": opts.Namespace,
		}
	}

	newSecret := &api.Secret{
		Type:       api.SecretTypeOpaque,
		ObjectMeta: meta,
		Data: map[string][]byte{
			opts.SecretEntryName: []byte(content),
		},
	}

	updatedSecret, err := client.CoreV1().Secrets(opts.Namespace).Update(
		context.Background(), newSecret, metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("error creating secret %s in namespace %s: "+
			"%v", opts.SecretName, opts.Namespace, err)
	}

	jsonSecret, _ := asJSON(jsonK8sObject{
		TypeMeta:   updatedSecret.TypeMeta,
		ObjectMeta: updatedSecret.ObjectMeta,
	})
	log("Created secret: %s", jsonSecret)

	return nil
}
