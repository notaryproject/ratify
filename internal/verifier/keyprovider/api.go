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

package keyprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"
)

type PublicKey struct {
	// Key for key-based verification. Required.
	Key crypto.PublicKey

	// SignatureAlgorithm defines the algorithm used for signature verification.
	// Optional. If not provided, defaults to SHA256.
	SignatureAlgorithm crypto.Hash

	// ValidityPeriodStart defines the start time for the public key validity
	// period. Optional. If not provided, the key is considered valid from the
	// beginning of time.
	ValidityPeriodStart time.Time

	// ValidityPeriodEnd defines the end time for the public key validity period.
	// Optional. If not provided, the key is considered valid until the end of
	// time.
	ValidityPeriodEnd time.Time
}

// KeyProvider defines methods to fetch crypto material for signature
// verification.
type KeyProvider interface {
	// GetCertificates fetches certificates for certificate-based verification.
	GetCertificates(ctx context.Context) ([]*x509.Certificate, error)

	// GetKeys fetches public keys for key-based verification.
	GetKeys(ctx context.Context) ([]*PublicKey, error)
}

type keyProviderFactory func(options any) (KeyProvider, error)

var keyProviderFactories = make(map[string]keyProviderFactory)

// RegisterKeyProvider registers a key provider factory with the given name.
func RegisterKeyProvider(name string, factory keyProviderFactory) {
	keyProviderFactories[name] = factory
}

// CreateKeyProvider creates a new key provider instance.
func CreateKeyProvider(name string, options any) (KeyProvider, error) {
	factory, exists := keyProviderFactories[name]
	if !exists {
		return nil, fmt.Errorf("key provider %s not registered", name)
	}
	return factory(options)
}
