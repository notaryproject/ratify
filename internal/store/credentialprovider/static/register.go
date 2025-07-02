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

package static

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

// CredentialProvider is an implementation of [ratify.RegistryCredentialGetter]
// that provides static credentials for registry authentication.
type CredentialProvider struct {
	username string
	password string
}

// CredentialProviderOptions contains configuration options for the static
// credential provider
type CredentialProviderOptions struct {
	// Username is the username to login to the registry.
	// If not set, password will be used as a refresh token. Optional.
	Username string `json:"username,omitempty"`

	// Password is the password to login to the registry.
	// If username is not set, this will be used as a refresh token. Optional.
	Password string `json:"password,omitempty"`
}

func init() {
	// Register the static credential provider factory
	credentialprovider.RegisterCredentialProviderFactory("static", createStaticCredentialProvider)
}

// createStaticCredentialProvider creates a new static credential provider from
// CredentialProviderOptions
func createStaticCredentialProvider(opts credentialprovider.Options) (ratify.RegistryCredentialGetter, error) {
	// Marshal and unmarshal to convert to our expected structure
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	var inlineOpts CredentialProviderOptions
	if err := json.Unmarshal(raw, &inlineOpts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Create the inline credential provider with the configuration
	return &CredentialProvider{
		username: inlineOpts.Username,
		password: inlineOpts.Password,
	}, nil
}

// Get returns the static credentials for the registry.
// The serverAddress parameter is ignored as this provider returns the same
// credentials for all registries.
func (p *CredentialProvider) Get(_ context.Context, _ string) (ratify.RegistryCredential, error) {
	if p.username == "" {
		// If username is not set, use password as refresh token
		return ratify.RegistryCredential{
			RefreshToken: p.password,
		}, nil
	}

	// Return username/password credentials
	return ratify.RegistryCredential{
		Username: p.username,
		Password: p.password,
	}, nil
}
