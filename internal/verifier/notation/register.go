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
	"encoding/json"
	"fmt"
	"time"

	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-verifier-go/notation"
	"github.com/notaryproject/ratify/v2/internal/imageref"
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

	// CRL configures the CRL fetcher used for revocation checks. Optional.
	// Revocation is checked regardless: OCSP is tried first with CRL as the
	// fallback. If not provided, an uncached CRL fetcher is used.
	CRL *crlOptions `json:"crl,omitempty"`
}

type crlOptions struct {
	// CacheEnabled enables the file-backed CRL cache. Optional.
	CacheEnabled bool `json:"cacheEnabled"`

	// CacheDir is the CRL cache directory used when CacheEnabled is true.
	// Optional. Defaults to Notation's CRL cache directory under
	// $XDG_CACHE_HOME or $HOME.
	CacheDir string `json:"cacheDir"`

	// HTTPTimeout is the timeout of each CRL download, e.g. "3s". Optional.
	// Defaults to 3s.
	HTTPTimeout string `json:"httpTimeout"`
}

func (o *crlOptions) toNotationCRLOptions() (*notation.CRLOptions, error) {
	if o == nil {
		return nil, nil
	}
	var timeout time.Duration
	if o.HTTPTimeout != "" {
		var err error
		if timeout, err = time.ParseDuration(o.HTTPTimeout); err != nil {
			return nil, fmt.Errorf("invalid crl.httpTimeout %q: %w", o.HTTPTimeout, err)
		}
		if timeout <= 0 {
			return nil, fmt.Errorf("invalid crl.httpTimeout %q: must be positive", o.HTTPTimeout)
		}
	}
	return &notation.CRLOptions{
		CacheEnabled: o.CacheEnabled,
		CacheDir:     o.CacheDir,
		HTTPTimeout:  timeout,
	}, nil
}

func init() {
	verifier.Register(verifierTypeNotation, func(opts verifier.NewOptions, _ []string) (ratify.Verifier, error) {
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

		crlOpts, err := params.CRL.toNotationCRLOptions()
		if err != nil {
			return nil, err
		}

		notationOpts := &notation.VerifierOptions{
			Name:           opts.Name,
			TrustPolicyDoc: initTrustPolicyDocument(params.Scopes, params.TrustedIdentities, types),
			TrustStore:     trustStore,
			CRL:            crlOpts,
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
			if err := validateTrustStoreCertificates(provider); err != nil {
				return nil, nil, fmt.Errorf("failed to validate key provider %s certificates: %w", key, err)
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

func validateTrustStoreCertificates(provider keyprovider.KeyProvider) error {
	certs, err := provider.GetCertificates(context.Background())
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return nil
	}
	return truststore.ValidateCertificates(certs)
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
	// Normalize repository scopes so that they match the normalized
	// references of the artifacts being verified, e.g. "docker.io/nginx"
	// becomes "docker.io/library/nginx".
	scopes = imageref.NormalizeScopes(scopes)
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
