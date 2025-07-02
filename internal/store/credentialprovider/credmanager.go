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

package credentialprovider

import (
	"fmt"

	"github.com/notaryproject/ratify-go"
)

// Options defines the options for creating a new credential
// provider.
// It is a map where the key is a string and the value can be of any type.
// It requires a "provider" key to specify the type of credential provider.
// Additional keys can be used to pass provider-specific options.
type Options map[string]any

// registeredProviders saves the registered credential provider factories.
var registeredProviders map[string]func(Options) (ratify.RegistryCredentialGetter, error)

// RegisterCredentialProviderFactory registers a credential provider factory to
// the system.
func RegisterCredentialProviderFactory(providerType string, create func(Options) (ratify.RegistryCredentialGetter, error)) {
	if providerType == "" {
		panic("credential provider type cannot be empty")
	}
	if create == nil {
		panic("credential provider factory cannot be nil")
	}
	if registeredProviders == nil {
		registeredProviders = make(map[string]func(Options) (ratify.RegistryCredentialGetter, error))
	}
	if _, registered := registeredProviders[providerType]; registered {
		panic(fmt.Sprintf("credential provider factory type %s already registered", providerType))
	}
	registeredProviders[providerType] = create
}

// NewCredentialProvider creates a new credential provider from
// CredentialProviderOptions.
func NewCredentialProvider(opts Options) (ratify.RegistryCredentialGetter, error) {
	if opts == nil {
		return nil, fmt.Errorf("credential provider options cannot be nil")
	}
	providerType, ok := opts["provider"]
	if !ok {
		return nil, fmt.Errorf("provider field is required in credential provider options")
	}
	providerTypeStr, ok := providerType.(string)
	if !ok {
		return nil, fmt.Errorf("provider field must be a string")
	}
	if providerTypeStr == "" {
		return nil, fmt.Errorf("provider field cannot be empty")
	}

	create, ok := registeredProviders[providerTypeStr]
	if !ok {
		return nil, fmt.Errorf("credential provider factory of type %s is not registered", providerTypeStr)
	}
	return create(opts)
}
