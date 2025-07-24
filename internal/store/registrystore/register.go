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

package registrystore

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/notaryproject/ratify-go"
	factory "github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

const registryStoreType = "registry-store"

type options struct {
	// PlainHTTP indicates whether to use HTTP instead of HTTPS. Optional.
	PlainHTTP bool `json:"plainHttp,omitempty"`

	// UserAgent is the user agent to use when making requests to the registry.
	// Optional.
	UserAgent string `json:"userAgent,omitempty"`

	// MaxBlobBytes is the maximum size of a blob in bytes. Optional.
	MaxBlobBytes int64 `json:"maxBlobBytes,omitempty"`

	// MaxManifestBytes is the maximum size of a manifest in bytes. Optional.
	MaxManifestBytes int64 `json:"maxManifestBytes,omitempty"`

	// CredentialProvider is the credential provider configuration. Required.
	CredentialProvider credentialprovider.Options `json:"credential"`

	// AllowCosignTag enables fetching cosign signatures with
	// the tag format when listing referrers.
	AllowCosignTag bool `json:"allowCosignTag,omitempty"`

	// CAPem is a PEM encoded CA bundle to use for TLS connections to the
	// registry. This enables accessing registries that use self-signed
	// certificates or private CA certificates. Optional.
	CAPem string `json:"caPem,omitempty"`

	// CABase64 is a base64 encoded CA bundle to use for TLS connections to the
	// registry. Either CABase64 or CAPem can be used, but CAPem is preferred.
	// Optional.
	CABase64 string `json:"caBase64,omitempty"`
}

// createHTTPClient creates an HTTP client with optional CA PEM configuration
func createHTTPClient(caPem, caBase64 string) (*http.Client, error) {
	if caPem == "" && caBase64 == "" {
		// Use default HTTP client if no CA is provided
		return http.DefaultClient, nil
	}

	caCertPool := x509.NewCertPool()
	var caBundle []byte
	// If both CA PEM and CA Base64 are provided, prefer CA PEM
	if caPem != "" {
		caBundle = []byte(caPem)
	} else {
		// If CABase64 is provided, decode it and append to the cert pool
		var err error
		if caBundle, err = base64.StdEncoding.DecodeString(caBase64); err != nil {
			return nil, fmt.Errorf("failed to decode CA Base64: %w", err)
		}
	}
	if !caCertPool.AppendCertsFromPEM(caBundle) {
		return nil, fmt.Errorf("failed to parse CA certificate: invalid PEM format")
	}

	// Create a custom HTTP client with the TLS configuration
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func init() {
	// Register the registry store factory.
	factory.RegisterStoreFactory(registryStoreType, func(opts *factory.NewOptions) (ratify.Store, error) {
		raw, err := json.Marshal(opts.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal store parameters: %w", err)
		}
		var params options
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal store parameters: %w", err)
		}

		// Use the configured credential provider
		credProvider, err := credentialprovider.NewCredentialProvider(params.CredentialProvider)
		if err != nil {
			return nil, fmt.Errorf("failed to create credential provider: %w", err)
		}

		// Create HTTP client with optional CA bundle
		httpClient, err := createHTTPClient(params.CAPem, params.CABase64)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client: %w", err)
		}

		registryStoreOpts := ratify.RegistryStoreOptions{
			HTTPClient:         httpClient,
			PlainHTTP:          params.PlainHTTP,
			UserAgent:          params.UserAgent,
			MaxBlobBytes:       params.MaxBlobBytes,
			MaxManifestBytes:   params.MaxManifestBytes,
			AllowCosignTag:     params.AllowCosignTag,
			CredentialProvider: credProvider,
		}

		return ratify.NewRegistryStore(registryStoreOpts), nil
	})
}
