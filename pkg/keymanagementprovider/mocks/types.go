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

package mocks

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
)

type TestKeyManagementProvider struct {
	certificates        map[keymanagementprovider.KMPMapKey][]*x509.Certificate
	keys                map[keymanagementprovider.KMPMapKey]crypto.PublicKey
	status              keymanagementprovider.KeyManagementProviderStatus
	err                 error
	GetCertificatesFunc func(ctx context.Context) (map[keymanagementprovider.KMPMapKey][]*x509.Certificate, keymanagementprovider.KeyManagementProviderStatus, error)
	GetKeysFunc         func(ctx context.Context) (map[keymanagementprovider.KMPMapKey]crypto.PublicKey, keymanagementprovider.KeyManagementProviderStatus, error)
	IsRefreshableFunc   func() bool
}

func (c *TestKeyManagementProvider) GetCertificates(_ context.Context) (map[keymanagementprovider.KMPMapKey][]*x509.Certificate, keymanagementprovider.KeyManagementProviderStatus, error) {
	if c.GetCertificatesFunc != nil {
		return c.GetCertificatesFunc(context.Background())
	}
	return c.certificates, c.status, c.err
}

func (c *TestKeyManagementProvider) GetKeys(_ context.Context) (map[keymanagementprovider.KMPMapKey]crypto.PublicKey, keymanagementprovider.KeyManagementProviderStatus, error) {
	if c.GetKeysFunc != nil {
		return c.GetKeysFunc(context.Background())
	}
	return c.keys, c.status, c.err
}

func (c *TestKeyManagementProvider) IsRefreshable() bool {
	if c.IsRefreshableFunc != nil {
		return c.IsRefreshableFunc()
	}
	return false
}
