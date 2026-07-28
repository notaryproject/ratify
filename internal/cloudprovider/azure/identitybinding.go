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
	// defaultKubernetesCACertPath is the default path to the cluster CA
	// certificate used to validate the TLS connection to the identity binding
	// token endpoint.
	defaultKubernetesCACertPath = "/etc/kubernetes/certs/ca.crt"

	// federatedTokenFileEnvVar is injected by the Azure Workload Identity
	// mutating webhook and points at the projected service account token. The
	// same token is used as the client assertion for identity binding.
	federatedTokenFileEnvVar = "AZURE_FEDERATED_TOKEN_FILE"

	// clientAssertionType is the OAuth2 client assertion type for a JWT bearer
	// assertion.
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// IdentityBindingConfig contains the configuration required to authenticate to
// Azure Container Registry using Kubernetes identity binding.
//
// With identity binding the cluster API server itself acts as the token issuer:
// the projected service account token is exchanged, over a TLS connection whose
// SNI host resolves to the API server, for an AAD access token. This removes the
// dependency on the Entra Workload Identity federation endpoint.
type IdentityBindingConfig struct {
	// SNIName is the server name presented for the TLS handshake and used to
	// build the token endpoint URL (https://<SNIName>). It must not contain a
	// protocol prefix.
	SNIName string
	// APIServerIP is the IP address (or resolvable host) the SNIName is dialed
	// against. All requests are routed to this address regardless of DNS.
	APIServerIP string
	// TokenFilePath is the path to the projected service account token used as
	// the client assertion. Defaults to the AZURE_FEDERATED_TOKEN_FILE env var.
	TokenFilePath string
	// CACertPath is the path to the cluster CA certificate used to validate the
	// TLS connection. Defaults to /etc/kubernetes/certs/ca.crt.
	CACertPath string
}

// identityBindingCredential implements [azcore.TokenCredential] using the
// Kubernetes identity binding token exchange.
type identityBindingCredential struct {
	clientID      string
	tenantID      string
	endpoint      string
	sniName       string
	apiServerIP   string
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

// NewIdentityBindingCredential creates an [azcore.TokenCredential] that obtains
// AAD access tokens through the Kubernetes identity binding token exchange.
//
// clientID and tenantID fall back to the AZURE_CLIENT_ID and AZURE_TENANT_ID
// environment variables respectively when empty.
func NewIdentityBindingCredential(clientID, tenantID string, cfg IdentityBindingConfig) (azcore.TokenCredential, error) {
	sniName := strings.TrimSpace(cfg.SNIName)
	if sniName == "" {
		return nil, fmt.Errorf("identity binding SNI name is required")
	}
	if strings.HasPrefix(sniName, "https://") || strings.HasPrefix(sniName, "http://") {
		return nil, fmt.Errorf("identity binding SNI name must not contain a protocol prefix, got: %s", sniName)
	}

	apiServerIP := strings.TrimSpace(cfg.APIServerIP)
	if apiServerIP == "" {
		return nil, fmt.Errorf("identity binding API server IP is required")
	}

	if clientID == "" {
		clientID = os.Getenv("AZURE_CLIENT_ID")
	}
	if clientID == "" {
		return nil, fmt.Errorf("identity binding requires a client ID (set clientID or the AZURE_CLIENT_ID environment variable)")
	}
	if tenantID == "" {
		tenantID = os.Getenv("AZURE_TENANT_ID")
	}

	tokenFilePath := cfg.TokenFilePath
	if tokenFilePath == "" {
		tokenFilePath = os.Getenv(federatedTokenFileEnvVar)
	}
	if tokenFilePath == "" {
		return nil, fmt.Errorf("identity binding requires a service account token file (set tokenFilePath or the %s environment variable)", federatedTokenFileEnvVar)
	}

	caCertPath := cfg.CACertPath
	if caCertPath == "" {
		caCertPath = defaultKubernetesCACertPath
	}

	return &identityBindingCredential{
		clientID:      clientID,
		tenantID:      tenantID,
		endpoint:      "https://" + sniName,
		sniName:       sniName,
		apiServerIP:   apiServerIP,
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
	clientAssertion, err := os.ReadFile(c.tokenFilePath)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to read service account token file %q: %w", c.tokenFilePath, err)
	}
	if len(clientAssertion) == 0 {
		return azcore.AccessToken{}, fmt.Errorf("service account token file %q is empty", c.tokenFilePath)
	}

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_assertion_type", clientAssertionType)
	formData.Set("scope", scope)
	formData.Set("client_assertion", strings.TrimSpace(string(clientAssertion)))
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
	}).Debug("requesting token from identity binding endpoint")

	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to execute identity binding token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to read identity binding token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return azcore.AccessToken{}, fmt.Errorf("identity binding token request failed with status %d: %s", resp.StatusCode, string(body))
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
// API server IP while presenting the configured SNI name and validating against
// the cluster CA.
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

	c.transport = newIdentityBindingTransport(c.sniName, c.apiServerIP, caPool)
	return c.transport, nil
}

// newIdentityBindingTransport builds an HTTP transport whose dialer always
// connects to apiServerIP while the TLS handshake presents sniName and is
// validated against caPool.
func newIdentityBindingTransport(sniName, apiServerIP string, caPool *x509.CertPool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Do not use any environment proxy: the endpoint is reached directly.
	transport.Proxy = nil

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address %s: %w", addr, err)
		}
		fixedAddr := net.JoinHostPort(apiServerIP, port)
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
