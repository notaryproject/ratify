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

package inline

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/config"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/factory"
)

const (
	// ValueParameter is the name of the parameter that contains the certificate (chain) as a string in PEM format
	ValueParameter                = "value"
	providerName           string = "inline"
	certificateContentType string = "certificate"
	certificatesMapKey     string = "certs"
	keyContentType         string = "key"
)

//nolint:revive
type InlineKMProviderConfig struct {
	Type        string `json:"type"`
	ContentType string `json:"contentType"`
	Value       string `json:"value"`
}

type inlineKMProvider struct {
	certs       map[keymanagementprovider.KMPMapKey][]*x509.Certificate
	keys        map[keymanagementprovider.KMPMapKey]crypto.PublicKey
	contentType string
}
type inlineKMProviderFactory struct{}

// init calls to register the provider
func init() {
	factory.Register(providerName, &inlineKMProviderFactory{})
}

// Create creates a new instance of the inline key management provider provider
// checks contentType is set to 'certificate' and value is set to a valid certificate
func (f *inlineKMProviderFactory) Create(_ string, keyManagementProviderConfig config.KeyManagementProviderConfig, _ string) (keymanagementprovider.KeyManagementProvider, error) {
	conf := InlineKMProviderConfig{}

	keyManagementProviderConfigBytes, err := json.Marshal(keyManagementProviderConfig)
	if err != nil {
		return nil, errors.ErrorCodeConfigInvalid.WithError(err).WithComponentType(errors.KeyManagementProvider)
	}

	if err := json.Unmarshal(keyManagementProviderConfigBytes, &conf); err != nil {
		return nil, errors.ErrorCodeConfigInvalid.NewError(errors.KeyManagementProvider, "", errors.EmptyLink, err, "failed to parse AKV key management provider configuration", errors.HideStackTrace)
	}

	if conf.ContentType == "" {
		return nil, errors.ErrorCodeConfigInvalid.WithComponentType(errors.KeyManagementProvider).WithDetail("contentType parameter is not set")
	}

	if conf.Value == "" {
		return nil, errors.ErrorCodeConfigInvalid.WithComponentType(errors.KeyManagementProvider).WithDetail("value parameter is not set")
	}

	var certMap map[keymanagementprovider.KMPMapKey][]*x509.Certificate
	var keyMap map[keymanagementprovider.KMPMapKey]crypto.PublicKey

	switch conf.ContentType {
	case certificateContentType:
		certs, err := keymanagementprovider.DecodeCertificates([]byte(conf.Value))
		if err != nil {
			return nil, err
		}
		certMap = map[keymanagementprovider.KMPMapKey][]*x509.Certificate{
			{}: certs,
		}
	case keyContentType:
		key, err := keymanagementprovider.DecodeKey([]byte(conf.Value))
		if err != nil {
			return nil, err
		}
		keyMap = map[keymanagementprovider.KMPMapKey]crypto.PublicKey{
			{}: key,
		}
	default:
		return nil, errors.ErrorCodeConfigInvalid.WithComponentType(errors.KeyManagementProvider).WithDetail(fmt.Sprintf("content type %s is not supported", conf.ContentType))
	}

	return &inlineKMProvider{certs: certMap, keys: keyMap, contentType: conf.ContentType}, nil
}

// GetCertificates returns previously fetched certificates
func (s *inlineKMProvider) GetCertificates(_ context.Context) (map[keymanagementprovider.KMPMapKey][]*x509.Certificate, keymanagementprovider.KeyManagementProviderStatus, error) {
	return s.certs, nil, nil
}

// GetKeys returns previously fetched keys
func (s *inlineKMProvider) GetKeys(_ context.Context) (map[keymanagementprovider.KMPMapKey]crypto.PublicKey, keymanagementprovider.KeyManagementProviderStatus, error) {
	return s.keys, nil, nil
}

func (s *inlineKMProvider) IsRefreshable() bool {
	return false
}
