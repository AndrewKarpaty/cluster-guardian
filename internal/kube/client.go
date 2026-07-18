// Package kube reads cluster state into a point-in-time Snapshot that the
// checks consume.
package kube

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client bundles the typed and dynamic Kubernetes clients.
type Client struct {
	Clientset kubernetes.Interface
	Dynamic   dynamic.Interface
	Context   string
}

// NewClient builds clients from --kubeconfig/--context, falling back to
// in-cluster config when no kubeconfig is reachable.
func NewClient(kubeconfig, context string) (*Client, error) {
	cfg, usedContext, err := buildConfig(kubeconfig, context)
	if err != nil {
		return nil, err
	}
	cfg.QPS = 50
	cfg.Burst = 100

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	return &Client{Clientset: clientset, Dynamic: dyn, Context: usedContext}, nil
}

// NewClientForCluster builds clients for a remote cluster from explicit
// connection details, as stored in fleet cluster secrets.
func NewClientForCluster(name, server, bearerToken string, caData []byte, insecure bool) (*Client, error) {
	cfg := &rest.Config{
		Host:            server,
		BearerToken:     bearerToken,
		TLSClientConfig: rest.TLSClientConfig{Insecure: insecure, CAData: caData},
	}
	cfg.QPS = 50
	cfg.Burst = 100
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating clientset for %s: %w", name, err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client for %s: %w", name, err)
	}
	return &Client{Clientset: clientset, Dynamic: dyn, Context: name}, nil
}

func buildConfig(kubeconfig, context string) (*rest.Config, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	if rules.ExplicitPath == "" && os.Getenv("KUBECONFIG") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			def := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(def); os.IsNotExist(err) {
				// No kubeconfig on disk — try in-cluster credentials.
				if cfg, err := rest.InClusterConfig(); err == nil {
					return cfg, "in-cluster", nil
				}
			}
		}
	}

	overrides := &clientcmd.ConfigOverrides{CurrentContext: context}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	raw, err := loader.RawConfig()
	if err != nil {
		return nil, "", fmt.Errorf("loading kubeconfig: %w", err)
	}
	usedContext := context
	if usedContext == "" {
		usedContext = raw.CurrentContext
	}
	cfg, err := loader.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("building client config: %w", err)
	}
	return cfg, usedContext, nil
}
