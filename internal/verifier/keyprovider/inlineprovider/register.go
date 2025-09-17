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

package inlineprovider

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

const inlineProviderName = "inline"

// InlineProvider is a key provider that loads certificates from a string
// containing PEM-encoded certificates and caches them in memory.
type InlineProvider struct {
	certificates []*x509.Certificate
	keys         []*keyprovider.PublicKey
}

// inlineOptions holds the options for the inline key provider.
type inlineOptions struct {
	// String containing PEM-encoded certificates. Optional.
	Certs string `json:"certs,omitempty"`

	// String containing PEM-encoded public keys. Optional.
	Keys string `json:"keys,omitempty"`
}

func init() {
	keyprovider.RegisterKeyProvider(inlineProviderName, func(options any) (keyprovider.KeyProvider, error) {
		raw, err := json.Marshal(options)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal options: %w", err)
		}

		// Try to unmarshal as a struct with certs field
		var opts inlineOptions
		if err := json.Unmarshal(raw, &opts); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}

		var certs []*x509.Certificate
		// Check if certs field exists and is not empty
		if opts.Certs != "" {
			// Parse certificates during initialization and cache them in memory
			parsedCerts, err := parseCertificatesFromPEM(opts.Certs)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificates: %w", err)
			}
			certs = parsedCerts
		}

		var keys []*keyprovider.PublicKey
		// Check if keys field exists and is not empty
		if opts.Keys != "" {
			// Parse public keys during initialization and cache them in memory
			parsedKeys, err := parsePublicKeysFromPEM(opts.Keys)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public keys: %w", err)
			}
			keys = parsedKeys
		}

		return &InlineProvider{
			certificates: certs,
			keys:         keys,
		}, nil
	})
}

// GetCertificates returns the cached x509.Certificate chain.
func (p *InlineProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	return p.certificates, nil
}

// GetKeys returns the cached PublicKey list.
func (p *InlineProvider) GetKeys(_ context.Context) ([]*keyprovider.PublicKey, error) {
	return p.keys, nil
}

// parseCertificatesFromPEM decodes PEM-encoded bytes into an x509.Certificate chain.
func parseCertificatesFromPEM(certificatesInPem string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode([]byte(strings.TrimSpace(certificatesInPem)))
	if block == nil && len(rest) > 0 {
		return nil, errors.New("failed to decode pem block")
	}

	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse x509 certificate")
			}
			certs = append(certs, cert)
		}
		block, rest = pem.Decode(rest)
		if block == nil && len(rest) > 0 {
			return nil, errors.New("failed to decode pem block while processing remaining data")
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in the pem block")
	}
	return certs, nil
}

// parsePublicKeysFromPEM decodes PEM-encoded bytes into PublicKey structs.
func parsePublicKeysFromPEM(keysInPem string) ([]*keyprovider.PublicKey, error) {
	var keys []*keyprovider.PublicKey
	block, rest := pem.Decode([]byte(strings.TrimSpace(keysInPem)))
	if block == nil && len(rest) > 0 {
		return nil, errors.New("failed to decode pem block")
	}

	for block != nil {
		if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" || block.Type == "EC PUBLIC KEY" {
			pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				// Try parsing as RSA public key if PKIX parsing fails
				if block.Type == "RSA PUBLIC KEY" {
					pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
					if err != nil {
						return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
					}
				} else {
					return nil, fmt.Errorf("failed to parse public key: %w", err)
				}
			}

			// Convert to keyprovider.PublicKey format
			keyProviderKey := &keyprovider.PublicKey{
				Key: pubKey,
			}
			keys = append(keys, keyProviderKey)
		}
		block, rest = pem.Decode(rest)
		if block == nil && len(rest) > 0 {
			return nil, errors.New("failed to decode pem block while processing remaining data")
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("no public keys found in the pem block")
	}
	return keys, nil
}
