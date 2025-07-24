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
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-verifier-go/notation"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

const (
	verifierTypeNotation = "notation"
	trustStoreName       = "ratify"
	typeKey              = "type"
)

// trustStoreOptions is a map of options for the trust stores. The value of the
// "type" key must be one of the following: "ca", "tsa", or "signingAuthority".
// If the "type" key is not present, the default type is "ca".
// Other keys in the map are used to create key providers. Each trust store can
// have multiple key providers.
type trustStoreOptions map[string]any

type options struct {
	// Scopes is a list of registry scopes to be used by the Notation
	// verifier. Optional. If not provided, the default scope is "*".
	Scopes []string `json:"scopes"`

	// TrustedIdentities is a list of trusted identities to be used by the
	// Notation verifier. Optional. If not provided, default identity is "*".
	TrustedIdentities []string `json:"trustedIdentities"`

	// Certificates is a list of certificates to be used by the Notation
	// verifier. Certificates would be loaded into trust store for Notation
	// verifier to access. Required.
	Certificates []trustStoreOptions `json:"certificates"`
}

func init() {
	verifier.RegisterVerifierFactory(verifierTypeNotation, func(opts *verifier.NewOptions, _ []string) (ratify.Verifier, error) {
		raw, err := json.Marshal(opts.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verifier parameters: %w", err)
		}

		var params options
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal verifier parameters: %w", err)
		}

		trustStore, types, err := initTrustStore(params.Certificates)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize trust store: %w", err)
		}

		notationOpts := &notation.VerifierOptions{
			Name:           opts.Name,
			TrustPolicyDoc: initTrustPolicyDocument(params.Scopes, params.TrustedIdentities, types),
			TrustStore:     trustStore,
		}

		return notation.NewVerifier(notationOpts)
	})
}

func initTrustStore(opts []trustStoreOptions) (truststore.X509TrustStore, []truststore.Type, error) {
	if len(opts) == 0 {
		return nil, nil, fmt.Errorf("no trust store options provided")
	}

	trustStore := newTrustStore()
	types := make(map[truststore.Type]struct{})
	for _, opt := range opts {
		var err error
		storeType := truststore.TypeCA
		if typeVal, ok := opt[typeKey]; ok {
			if storeType, err = getTrustStoreType(typeVal); err != nil {
				return nil, nil, fmt.Errorf("failed to get trust store type: %w", err)
			}
		}
		if _, exists := types[storeType]; exists {
			return nil, nil, fmt.Errorf("duplicate trust store type %s detected. Please check your configuration to ensure each trust store type is unique", storeType)
		}
		types[storeType] = struct{}{}

		for key, val := range opt {
			if key == typeKey {
				continue
			}
			provider, err := keyprovider.CreateKeyProvider(key, val)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get key provider %s: %w", key, err)
			}

			trustStore.addKeyProvider(storeType, trustStoreName, provider)
		}
	}
	names := make([]truststore.Type, 0, len(types))
	for storeType := range types {
		names = append(names, storeType)
	}
	return trustStore, names, nil
}

func getTrustStoreType(val any) (truststore.Type, error) {
	t, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("trust store type must be a string")
	}
	storeType := truststore.Type(t)
	if storeType != truststore.TypeCA && storeType != truststore.TypeTSA && storeType != truststore.TypeSigningAuthority {
		return "", fmt.Errorf("invalid trust store type %s", storeType)
	}
	return storeType, nil
}

func initTrustPolicyDocument(scopes, trustedIdentities []string, storeTypes []truststore.Type) *trustpolicy.Document {
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	if len(trustedIdentities) == 0 {
		trustedIdentities = []string{"*"}
	}
	trustStoreNames := make([]string, len(storeTypes))
	for i, storeType := range storeTypes {
		trustStoreNames[i] = fmt.Sprintf("%s:%s", storeType, trustStoreName)
	}
	return &trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:           "default",
				RegistryScopes: scopes,
				SignatureVerification: trustpolicy.SignatureVerification{
					VerificationLevel: "strict",
				},
				TrustStores:       trustStoreNames,
				TrustedIdentities: trustedIdentities,
			},
		},
	}
}
