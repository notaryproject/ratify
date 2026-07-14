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

package factory

import (
	"fmt"

	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/config"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/types"
)

// map of key management provider names to key management provider factories
var builtInKeyManagementProviders = make(map[string]KeyManagementProviderFactory)

// KeyManagementProviderFactory is an interface for creating key management provider providers
type KeyManagementProviderFactory interface {
	Create(version string, keyManagementProviderConfig config.KeyManagementProviderConfig, pluginDirectory string) (keymanagementprovider.KeyManagementProvider, error)
}

// Register registers a key management provider factory by name
func Register(name string, factory KeyManagementProviderFactory) {
	if factory == nil {
		panic("key management provider factory cannot be nil")
	}
	_, registered := builtInKeyManagementProviders[name]
	if registered {
		panic(fmt.Sprintf("key management provider factory named %s already registered", name))
	}

	builtInKeyManagementProviders[name] = factory
}

// CreateKeyManagementProviderFromConfig creates a key management provider from config
func CreateKeyManagementProviderFromConfig(keyManagementProviderConfig config.KeyManagementProviderConfig, configVersion string, pluginDirectory string) (keymanagementprovider.KeyManagementProvider, error) {
	keyManagementProvider, ok := keyManagementProviderConfig[types.Type]
	if !ok {
		return nil, fmt.Errorf("failed to find key management provider name in the certificate stores config with key %s", types.Type)
	}

	keyManagementProviderStr := fmt.Sprintf("%s", keyManagementProvider)
	if keyManagementProviderStr == "" {
		return nil, fmt.Errorf("key management provider type cannot be empty")
	}

	factory, ok := builtInKeyManagementProviders[keyManagementProviderStr]
	if !ok {
		return nil, fmt.Errorf("key management provider factory with name %s not found", keyManagementProviderStr)
	}

	return factory.Create(configVersion, keyManagementProviderConfig, pluginDirectory)
}
