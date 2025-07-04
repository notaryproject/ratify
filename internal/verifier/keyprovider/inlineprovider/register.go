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
}

func init() {
	keyprovider.RegisterKeyProvider(inlineProviderName, func(options any) (keyprovider.KeyProvider, error) {
		raw, err := json.Marshal(options)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal options: %w", err)
		}
		var certificatesInPem string
		if err := json.Unmarshal(raw, &certificatesInPem); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}

		// Parse certificates during initialization and cache them in memory
		certs, err := parseCertificatesFromPEM(certificatesInPem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificates: %w", err)
		}

		return &InlineProvider{
			certificates: certs,
		}, nil
	})
}

// GetCertificates returns the cached x509.Certificate chain.
func (p *InlineProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	return p.certificates, nil
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
