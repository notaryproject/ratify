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

package certificateprovider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/notaryproject/ratify/v2/errors"
)

// This is a map containing Cert store configuration including name, tenantID, and cert object information
type CertStoreConfig map[string]string

// This is a map of properties for fetched certificates
// The key and values are specific to each provider
type CertificatesStatus map[string]interface{}

// CertificateProvider is an interface that defines methods to be implemented by a each certificate provider
type CertificateProvider interface {
	// Returns an array of certificates and the provider specific cert attributes based on certificate properties defined in attrib map
	GetCertificates(ctx context.Context, attrib map[string]string) ([]*x509.Certificate, CertificatesStatus, error)
}

var certificateProviders = make(map[string]CertificateProvider)

// returns the internal certificate provider map
func GetCertificateProviders() map[string]CertificateProvider {
	return certificateProviders
}

// Register adds the factory to the built in providers map
func Register(name string, provider CertificateProvider) {
	if _, registered := certificateProviders[name]; registered {
		panic(fmt.Sprintf("cert provider named %s already registered", name))
	}

	certificateProviders[name] = provider
}

// Decode PEM-encoded bytes into an x509.Certificate chain.
func DecodeCertificates(value []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(value)
	if block == nil && len(rest) > 0 {
		return nil, errors.ErrorCodeCertInvalid.WithComponentType(errors.CertProvider).WithDetail("failed to decode pem block")
	}

	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.ErrorCodeCertInvalid.WithComponentType(errors.CertProvider).WithDetail("error parsing x509 certificate")
			}
			certs = append(certs, cert)
		}
		block, rest = pem.Decode(rest)
		if block == nil && len(rest) > 0 {
			return nil, errors.ErrorCodeCertInvalid.WithComponentType(errors.CertProvider).WithDetail("failed to decode pem block")
		}
	}

	if len(certs) == 0 {
		return nil, errors.ErrorCodeCertInvalid.WithComponentType(errors.CertProvider).WithDetail("no certificates found in the pem block")
	}
	return certs, nil
}
