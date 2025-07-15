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
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
	"github.com/notaryproject/ratify/v2/internal/store/factory"

	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/azure"  // Register the Azure credential provider factory
	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/static" // Register the static credential provider factory
)

const registryStoreType = "registry-store"

type options struct {
	// PlainHTTP indicates whether to use HTTP instead of HTTPS. Optional.
	PlainHTTP bool `json:"plainHttp,omitempty"`

	// UserAgent is the user agent to use when making requests to the registry.
	// Optional.
	UserAgent string `json:"userAgent,omitempty"`

	// MaxBlobBytes is the maximum size of a blob in bytes. Optional.
	MaxBlobBytes int64 `json:"maxBlobBytes,omitempty"`

	// MaxManifestBytes is the maximum size of a manifest in bytes. Optional.
	MaxManifestBytes int64 `json:"maxManifestBytes,omitempty"`

	// CredentialProvider is the credential provider configuration. Required.
	CredentialProvider credentialprovider.Options `json:"credential"`

	// AllowCosignTag enables fetching cosign signatures with
	// the tag format when listing referrers.
	AllowCosignTag bool `json:"allowCosignTag,omitempty"`
}

func init() {
	// Register the registry store factory.
	factory.RegisterStoreFactory(registryStoreType, func(opts *factory.NewStoreOptions) (ratify.Store, error) {
		raw, err := json.Marshal(opts.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal store parameters: %w", err)
		}
		var params options
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal store parameters: %w", err)
		}

		// Use the configured credential provider
		credProvider, err := credentialprovider.NewCredentialProvider(params.CredentialProvider)
		if err != nil {
			return nil, fmt.Errorf("failed to create credential provider: %w", err)
		}

		registryStoreOpts := ratify.RegistryStoreOptions{
			PlainHTTP:          params.PlainHTTP,
			UserAgent:          params.UserAgent,
			MaxBlobBytes:       params.MaxBlobBytes,
			MaxManifestBytes:   params.MaxManifestBytes,
			AllowCosignTag:     params.AllowCosignTag,
			CredentialProvider: credProvider,
		}

		return ratify.NewRegistryStore(registryStoreOpts), nil
	})
}
