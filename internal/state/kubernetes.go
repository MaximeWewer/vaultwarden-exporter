package state

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// In-cluster service account files
const (
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount"
	stateKey    = "state.json"
	maxBodySize = 4 << 20
)

// Kubernetes stores the state in a ConfigMap, through the API server with the
// pod service account. The ConfigMap is created on the first save (it is not
// part of the Helm release, so upgrades and GitOps syncs never reset it).
// RBAC: create configmaps, get/patch on that name.
type Kubernetes struct {
	ConfigMap string
	Namespace string
	Labels    map[string]string

	baseURL   string
	tokenPath string
	client    *http.Client
}

// NewKubernetes configures the in-cluster client (KUBERNETES_SERVICE_HOST/PORT,
// service account token and CA). An empty namespace is read from the service
// account.
func NewKubernetes(configMap, namespace string, labels map[string]string) (*Kubernetes, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running in Kubernetes: KUBERNETES_SERVICE_HOST/PORT are not set")
	}
	if namespace == "" {
		data, err := os.ReadFile(saDir + "/namespace")
		if err != nil {
			return nil, fmt.Errorf("read service account namespace: %w", err)
		}
		namespace = strings.TrimSpace(string(data))
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid service account CA")
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	return newKubernetesWith("https://"+net.JoinHostPort(host, port), saDir+"/token", configMap, namespace, labels, client), nil
}

// newKubernetesWith builds a client against any API server (tests)
func newKubernetesWith(baseURL, tokenPath, configMap, namespace string, labels map[string]string, client *http.Client) *Kubernetes {
	return &Kubernetes{ConfigMap: configMap, Namespace: namespace, Labels: labels,
		baseURL: strings.TrimSuffix(baseURL, "/"), tokenPath: tokenPath, client: client}
}

// Name implements Store
func (k *Kubernetes) Name() string { return "kubernetes:configmap/" + k.Namespace + "/" + k.ConfigMap }

func (k *Kubernetes) collection() string {
	return k.baseURL + "/api/v1/namespaces/" + k.Namespace + "/configmaps"
}

// do sends an authenticated request. The token is read on every call: the
// kubelet rotates projected service account tokens.
func (k *Kubernetes) do(ctx context.Context, method, url, contentType string, body []byte) (int, []byte, error) {
	token, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return 0, nil, fmt.Errorf("read service account token: %w", err)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

type configMap struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   cmMetadata        `json:"metadata"`
	Data       map[string]string `json:"data"`
}

type cmMetadata struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Load implements Store
func (k *Kubernetes) Load(ctx context.Context) (*State, bool, error) {
	code, body, err := k.do(ctx, http.MethodGet, k.collection()+"/"+k.ConfigMap, "", nil)
	if err != nil {
		return nil, false, fmt.Errorf("get configmap %s: %w", k.ConfigMap, err)
	}
	switch code {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("get configmap %s: HTTP %d: %s", k.ConfigMap, code, truncate(body))
	}
	var cm configMap
	if err := json.Unmarshal(body, &cm); err != nil {
		return nil, false, fmt.Errorf("decode configmap %s: %w", k.ConfigMap, err)
	}
	raw := cm.Data[stateKey]
	if raw == "" {
		return nil, false, nil
	}
	st, err := Unmarshal([]byte(raw))
	if err != nil {
		return nil, false, err
	}
	return st, true, nil
}

// Save implements Store: merge-patch the ConfigMap, create it when missing
func (k *Kubernetes) Save(ctx context.Context, st *State) error {
	data, err := st.Marshal()
	if err != nil {
		return err
	}
	patch, err := json.Marshal(map[string]any{"data": map[string]string{stateKey: string(data)}})
	if err != nil {
		return err
	}
	code, body, err := k.do(ctx, http.MethodPatch, k.collection()+"/"+k.ConfigMap, "application/merge-patch+json", patch)
	if err != nil {
		return fmt.Errorf("patch configmap %s: %w", k.ConfigMap, err)
	}
	switch code {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return k.create(ctx, string(data))
	default:
		return fmt.Errorf("patch configmap %s: HTTP %d: %s", k.ConfigMap, code, truncate(body))
	}
}

func (k *Kubernetes) create(ctx context.Context, data string) error {
	body, err := json.Marshal(configMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: cmMetadata{Name: k.ConfigMap, Labels: k.Labels},
		Data:     map[string]string{stateKey: data},
	})
	if err != nil {
		return err
	}
	code, resp, err := k.do(ctx, http.MethodPost, k.collection(), "application/json", body)
	if err != nil {
		return fmt.Errorf("create configmap %s: %w", k.ConfigMap, err)
	}
	if code != http.StatusCreated {
		return fmt.Errorf("create configmap %s: HTTP %d: %s", k.ConfigMap, code, truncate(resp))
	}
	return nil
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
