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
	defaultK8sNamespace = "default"
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

type jsonK8sObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

func readK8s(cfg *k8sSecretOptions) (string, *jsonK8sObject, error) {
	client, err := clusterClient()
	if err != nil {
		return "", nil, err
	}

	secret, exists, err := getSecret(client, cfg.Namespace, cfg.SecretName)
	if err != nil {
		return "", nil, err
	}

	if !exists {
		return "", nil, fmt.Errorf("secret %s does not exist in "+
			"namespace %s", cfg.SecretName, cfg.Namespace)
	}

	if len(secret.Data) == 0 {
		return "", nil, fmt.Errorf("secret %s exists but contains no "+
			"data", cfg.SecretName)
	}

	if len(secret.Data[cfg.SecretEntryName]) == 0 {
		return "", nil, fmt.Errorf("secret %s exists but does not "+
			"contain the entry %s", cfg.SecretName,
			cfg.SecretEntryName)
	}

	// Remove any newlines at the end of the file. We won't ever write a
	// newline ourselves but maybe the file was provisioned by another
	// process or user.
	content := strings.TrimRight(
		string(secret.Data[cfg.SecretEntryName]), "\r\n",
	)

	return content, &jsonK8sObject{
		TypeMeta:   secret.TypeMeta,
		ObjectMeta: secret.ObjectMeta,
	}, nil
}

func clusterClient() (*kubernetes.Clientset, error) {
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

func getSecret(client *kubernetes.Clientset, namespace,
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
