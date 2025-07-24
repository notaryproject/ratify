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

package notation

import (
	"context"
	"crypto/x509"

	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
	"github.com/sirupsen/logrus"
)

type trustStore struct {
	stores map[truststore.Type]map[string][]keyprovider.KeyProvider
}

func newTrustStore() *trustStore {
	return &trustStore{
		stores: make(map[truststore.Type]map[string][]keyprovider.KeyProvider),
	}
}

// GetCertificates implements [truststore.X509TrustStore] interface.
func (s *trustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	logrus.Debugf("Getting certificates from trust store %s", namedStore)
	if namedStores, ok := s.stores[storeType]; ok {
		if keyProviders, ok := namedStores[namedStore]; ok {
			var allCerts []*x509.Certificate
			for _, keyProvider := range keyProviders {
				certs, err := keyProvider.GetCertificates(ctx)
				if err != nil {
					logrus.Errorf("Failed to get certificates from key provider: %v", err)
					return nil, err
				}
				allCerts = append(allCerts, certs...)
			}
			logrus.Debugf("Found %d certificates in trust store %s", len(allCerts), namedStore)
			return allCerts, nil
		}
	}
	return nil, nil
}

// addKeyProvider adds a key provider to the trust store.
func (s *trustStore) addKeyProvider(storeType truststore.Type, namedStore string, keyProvider keyprovider.KeyProvider) {
	if s.stores[storeType] == nil {
		s.stores[storeType] = make(map[string][]keyprovider.KeyProvider)
	}
	s.stores[storeType][namedStore] = append(s.stores[storeType][namedStore], keyProvider)
}
