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

package registrystore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/store/factory"
	provider "github.com/ratify-project/ratify/pkg/common/oras/authprovider"
	// Register built-in auth providers so they are available via
	// CreateAuthProviderFromConfig. The blank imports trigger each
	// package's init() which calls provider.Register().
	_ "github.com/ratify-project/ratify/pkg/common/oras/authprovider/azure"
)

const registryStoreType = "registry-store"

type credential struct {
	// Username is the username to login to the registry.
	// If not set, password will be used as a refresh token. Optional.
	Username string `json:"username,omitempty"`

	// Password is the password to login to the registry.
	// If username is not set, this will be used as a refresh token. Required.
	Password string `json:"password"`
}

type options struct {
	// PlainHTTP indicates whether to use HTTP instead of HTTPS.
	PlainHTTP bool `json:"plain_http,omitempty"`

	// UserAgent is the user agent to use when making requests to the registry.
	UserAgent string `json:"user_agent,omitempty"`

	// MaxBlobBytes is the maximum size of a blob in bytes.
	MaxBlobBytes int64 `json:"max_blob_bytes,omitempty"`

	// MaxManifestBytes is the maximum size of a manifest in bytes.
	MaxManifestBytes int64 `json:"max_manifest_bytes,omitempty"`

	// Credential is the credential to use when accessing the registry.
	// Takes precedence over AuthProvider if both are specified.
	Credential credential `json:"credential,omitempty"`

	// AuthProvider configures a named auth provider (e.g.
	// "azureWorkloadIdentity", "azureManagedIdentity", "dockerConfig")
	// to obtain registry credentials dynamically.
	// Ignored if Credential is set.
	AuthProvider provider.AuthProviderConfig `json:"authProvider,omitempty"`
}

func init() {
	// Register the registry store factory.
	factory.RegisterStoreFactory(registryStoreType, func(opts factory.NewStoreOptions) (ratify.Store, error) {
		raw, err := json.Marshal(opts.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal store parameters: %w", err)
		}
		var params options
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal store parameters: %w", err)
		}

		var credProvider ratify.RegistryCredentialGetter

		// Static credential takes precedence.
		if params.Credential.Password != "" {
			credProvider = &defaultCredGetter{
				username: params.Credential.Username,
				password: params.Credential.Password,
			}
		} else if params.AuthProvider != nil {
			// Use the named auth provider (azureWorkloadIdentity, etc.)
			ap, err := provider.CreateAuthProviderFromConfig(params.AuthProvider)
			if err != nil {
				return nil, fmt.Errorf("failed to create auth provider: %w", err)
			}
			credProvider = &authProviderAdapter{provider: ap}
		}

		registryStoreOpts := ratify.RegistryStoreOptions{
			PlainHTTP:          params.PlainHTTP,
			UserAgent:          params.UserAgent,
			MaxBlobBytes:       params.MaxBlobBytes,
			MaxManifestBytes:   params.MaxManifestBytes,
			CredentialProvider: credProvider,
		}

		return ratify.NewRegistryStore(registryStoreOpts), nil
	})
}

// defaultCredGetter is a simple implementation of [ratify.RegistryCredentialGetter]
// interface.
type defaultCredGetter struct {
	username string
	password string
}

// Get returns the credentials for the registry.
func (d *defaultCredGetter) Get(_ context.Context, _ string) (ratify.RegistryCredential, error) {
	if d.username == "" {
		return ratify.RegistryCredential{
			RefreshToken: d.password,
		}, nil
	}
	return ratify.RegistryCredential{
		Username: d.username,
		Password: d.password,
	}, nil
}

// authProviderAdapter adapts a v1 [provider.AuthProvider] to the v2
// [ratify.RegistryCredentialGetter] interface, bridging the existing Azure
// Workload Identity, Managed Identity, k8s Secrets, and other auth provider
// implementations into the v2 registry store.
type authProviderAdapter struct {
	provider provider.AuthProvider
}

// Get obtains credentials from the underlying auth provider for the given
// server address.
func (a *authProviderAdapter) Get(ctx context.Context, serverAddress string) (ratify.RegistryCredential, error) {
	authConfig, err := a.provider.Provide(ctx, serverAddress)
	if err != nil {
		return ratify.RegistryCredential{}, err
	}

	// Map v1 AuthConfig fields to v2 RegistryCredential.
	// IdentityToken maps to RefreshToken (OAuth2 refresh/identity token).
	if authConfig.IdentityToken != "" {
		return ratify.RegistryCredential{
			RefreshToken: authConfig.IdentityToken,
		}, nil
	}
	return ratify.RegistryCredential{
		Username: authConfig.Username,
		Password: authConfig.Password,
	}, nil
}
