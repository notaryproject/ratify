/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/sirupsen/logrus"
)

const (
	EnvIdentityBindingSNIName = "AZURE_ACR_IDENTITY_BINDING_SNI_NAME"

	EnvIdentityBindingAPIServerHost = "AZURE_ACR_IDENTITY_BINDING_APISERVER_HOST"

	EnvIdentityBindingTokenFile = "AZURE_ACR_IDENTITY_BINDING_TOKEN_FILE" // #nosec G101 -- env var name, not a credential

	EnvIdentityBindingCACertPath = "AZURE_ACR_IDENTITY_BINDING_CA_CERT_PATH"

	EnvAKSIdentityBindingSNIName = "AZURE_KUBERNETES_SNI_NAME"

	EnvAKSIdentityBindingTokenProxy = "AZURE_KUBERNETES_TOKEN_PROXY" // #nosec G101 -- env var name, not a credential

	EnvAKSIdentityBindingCAFile = "AZURE_KUBERNETES_CA_FILE"

	EnvAKSFederatedTokenFile = "AZURE_FEDERATED_TOKEN_FILE" // #nosec G101 -- env var name, not a credential

	defaultKubernetesCACertPath = "/etc/kubernetes/certs/ca.crt"

	defaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known mount path, not a credential

	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// maxIdentityBindingResponseBytes bounds how much of the token endpoint
	// response is read into memory (1 MiB is far larger than any valid token
	// response but small enough to prevent memory exhaustion).
	maxIdentityBindingResponseBytes = 1 << 20

	// maxErrorBodyBytes bounds how much of a non-2xx response body is included
	// in an error message.
	maxErrorBodyBytes = 2048
)

// IdentityBindingConfig contains the resolved configuration required to
// authenticate to Azure Container Registry using Kubernetes identity binding.
//
// With identity binding the cluster API server itself acts as the token issuer:
// the projected service account token is exchanged, over a TLS connection whose
// SNI host resolves to the API server, for an AAD access token. This removes the
// dependency on the Entra Workload Identity federation endpoint.
//
// SNIName and APIServerHost are cluster-scoped infrastructure values injected by
// the platform (see LoadIdentityBindingConfigFromEnv); they are not surfaced to
// end users.
type IdentityBindingConfig struct {
	// SNIName is the server name presented for the TLS handshake and used to
	// build the token endpoint URL (https://<SNIName>).
	SNIName string
	// APIServerHost is the host (IP or FQDN) the SNIName is dialed against. All
	// requests are routed to this host regardless of the SNI name.
	APIServerHost string
	// TokenFilePath is the path to the projected service account token used as
	// the client assertion. Defaults to the standard projected token path.
	TokenFilePath string
	// CACertPath is the path to the cluster CA certificate used to validate the
	// TLS connection. Defaults to /etc/kubernetes/certs/ca.crt.
	CACertPath string
}

// LoadIdentityBindingConfigFromEnv builds an IdentityBindingConfig from the
// platform-injected environment variables. It returns (nil, nil) when identity
// binding is not configured (no SNI name present), so callers can treat a nil
// result as "identity binding disabled".
//
// The ratify-specific AZURE_ACR_IDENTITY_BINDING_* variables take precedence.
// When they are not set, the values injected by the AKS workload-identity
// webhook (AZURE_KUBERNETES_SNI_NAME, AZURE_KUBERNETES_TOKEN_PROXY,
// AZURE_KUBERNETES_CA_FILE, AZURE_FEDERATED_TOKEN_FILE) are used as fallbacks so
// identity binding works out of the box on AKS.
func LoadIdentityBindingConfigFromEnv() (*IdentityBindingConfig, error) {
	sniName := strings.TrimSpace(os.Getenv(EnvIdentityBindingSNIName))
	if sniName == "" {
		sniName = strings.TrimSpace(os.Getenv(EnvAKSIdentityBindingSNIName))
	}
	if sniName == "" {
		return nil, nil
	}
	if strings.HasPrefix(sniName, "https://") || strings.HasPrefix(sniName, "http://") {
		return nil, fmt.Errorf("%s must not contain a protocol prefix, got: %s", EnvIdentityBindingSNIName, sniName)
	}

	apiServerHost := strings.TrimSpace(os.Getenv(EnvIdentityBindingAPIServerHost))
	if apiServerHost == "" {
		// The AKS webhook injects the token endpoint as a full URL; the host is
		// the API server the SNI name is dialed against.
		if proxy := strings.TrimSpace(os.Getenv(EnvAKSIdentityBindingTokenProxy)); proxy != "" {
			host, err := hostFromURL(proxy)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", EnvAKSIdentityBindingTokenProxy, err)
			}
			apiServerHost = host
		}
	}
	if apiServerHost == "" {
		return nil, fmt.Errorf("%s (or %s) must be set when %s is provided", EnvIdentityBindingAPIServerHost, EnvAKSIdentityBindingTokenProxy, EnvIdentityBindingSNIName)
	}

	tokenFilePath := strings.TrimSpace(os.Getenv(EnvIdentityBindingTokenFile))
	if tokenFilePath == "" {
		tokenFilePath = strings.TrimSpace(os.Getenv(EnvAKSFederatedTokenFile))
	}

	caCertPath := strings.TrimSpace(os.Getenv(EnvIdentityBindingCACertPath))
	if caCertPath == "" {
		caCertPath = strings.TrimSpace(os.Getenv(EnvAKSIdentityBindingCAFile))
	}

	return &IdentityBindingConfig{
		SNIName:       sniName,
		APIServerHost: apiServerHost,
		TokenFilePath: tokenFilePath,
		CACertPath:    caCertPath,
	}, nil
}

// hostFromURL extracts the host (without scheme, port, or path) from a URL such
// as the AKS-injected token proxy endpoint (https://apiserver-fqdn[:port]).
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("no host in URL %q", raw)
	}
	return u.Hostname(), nil
}

// truncateForError returns body as a string, truncated to maxErrorBodyBytes so
// an oversized response cannot bloat an error message.
func truncateForError(body []byte) string {
	if len(body) > maxErrorBodyBytes {
		return string(body[:maxErrorBodyBytes]) + "... (truncated)"
	}
	return string(body)
}

// identityBindingCredential implements [azcore.TokenCredential] using the
// Kubernetes identity binding token exchange.
type identityBindingCredential struct {
	clientID      string
	endpoint      string
	sniName       string
	apiServerHost string
	tokenFilePath string
	caCertPath    string

	mu        sync.Mutex
	transport *http.Transport
}

// tokenResponse represents the response from the identity binding token
// exchange endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// newIdentityBindingCredential creates an [azcore.TokenCredential] that obtains
// AAD access tokens through the Kubernetes identity binding token exchange.
func newIdentityBindingCredential(clientID string, cfg IdentityBindingConfig) (azcore.TokenCredential, error) {
	sniName := strings.TrimSpace(cfg.SNIName)
	if sniName == "" {
		return nil, fmt.Errorf("identity binding SNI name is required")
	}
	if strings.HasPrefix(sniName, "https://") || strings.HasPrefix(sniName, "http://") {
		return nil, fmt.Errorf("identity binding SNI name must not contain a protocol prefix, got: %s", sniName)
	}

	apiServerHost := strings.TrimSpace(cfg.APIServerHost)
	if apiServerHost == "" {
		return nil, fmt.Errorf("identity binding API server host is required")
	}

	if clientID == "" {
		clientID = os.Getenv("AZURE_CLIENT_ID")
	}
	if clientID == "" {
		return nil, fmt.Errorf("identity binding requires a client ID (set clientID or the AZURE_CLIENT_ID environment variable)")
	}

	tokenFilePath := cfg.TokenFilePath
	if tokenFilePath == "" {
		tokenFilePath = defaultServiceAccountTokenPath
	}

	caCertPath := cfg.CACertPath
	if caCertPath == "" {
		caCertPath = defaultKubernetesCACertPath
	}

	return &identityBindingCredential{
		clientID:      clientID,
		endpoint:      "https://" + sniName,
		sniName:       sniName,
		apiServerHost: apiServerHost,
		tokenFilePath: tokenFilePath,
		caCertPath:    caCertPath,
	}, nil
}

// GetToken implements [azcore.TokenCredential]. It exchanges the projected
// service account token for an AAD access token scoped to the requested
// resource.
func (c *identityBindingCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(opts.Scopes) != 1 {
		return azcore.AccessToken{}, fmt.Errorf("expected exactly one scope, got %d", len(opts.Scopes))
	}
	scope := opts.Scopes[0]

	// Read the service account token on every call so that token rotation is
	// picked up transparently.
	rawAssertion, err := os.ReadFile(c.tokenFilePath)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to read service account token file %q: %w", c.tokenFilePath, err)
	}
	clientAssertion := strings.TrimSpace(string(rawAssertion))
	if clientAssertion == "" {
		return azcore.AccessToken{}, fmt.Errorf("service account token file %q is empty", c.tokenFilePath)
	}

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_assertion_type", clientAssertionType)
	formData.Set("scope", scope)
	formData.Set("client_assertion", clientAssertion)
	formData.Set("client_id", c.clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create identity binding token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	transport, err := c.getTransport()
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to build identity binding transport: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"component": "azure-identity-binding",
		"endpoint":  c.endpoint,
		"scope":     scope,
	}).Info("acquiring AAD token via Azure identity binding auth provider")

	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to execute identity binding token request: %w", err)
	}
	defer resp.Body.Close()

	// Bound the amount read from the response body to guard against an
	// oversized or misbehaving endpoint exhausting memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdentityBindingResponseBytes))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to read identity binding token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return azcore.AccessToken{}, fmt.Errorf("identity binding token request failed with status %d: %s", resp.StatusCode, truncateForError(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to parse identity binding token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return azcore.AccessToken{}, fmt.Errorf("identity binding token response did not contain an access token")
	}

	expiresOn := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	return azcore.AccessToken{
		Token:     tokenResp.AccessToken,
		ExpiresOn: expiresOn,
	}, nil
}

// getTransport lazily builds and caches an HTTP transport that dials the fixed
// API server host while presenting the configured SNI name and validating
// against the cluster CA.
func (c *identityBindingCredential) getTransport() (*http.Transport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.transport != nil {
		return c.transport, nil
	}

	caBytes, err := os.ReadFile(c.caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %q: %w", c.caCertPath, err)
	}
	if len(caBytes) == 0 {
		return nil, fmt.Errorf("CA file %q is empty", c.caCertPath)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to parse CA file %q: no valid certificates found", c.caCertPath)
	}

	c.transport = newIdentityBindingTransport(c.sniName, c.apiServerHost, caPool)
	return c.transport, nil
}

// newIdentityBindingTransport builds an HTTP transport whose dialer always
// connects to apiServerHost (IP or FQDN) while the TLS handshake presents
// sniName and is validated against caPool.
func newIdentityBindingTransport(sniName, apiServerHost string, caPool *x509.CertPool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Do not use any environment proxy: the endpoint is reached directly.
	transport.Proxy = nil

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address %s: %w", addr, err)
		}
		// Route to the API server host (IP or FQDN) regardless of the SNI host
		// in the request URL. A FQDN is resolved by the dialer at connect time.
		fixedAddr := net.JoinHostPort(apiServerHost, port)
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return dialer.DialContext(ctx, network, fixedAddr)
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	transport.TLSClientConfig.ServerName = sniName
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig.RootCAs = caPool

	return transport
}
