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

package cosign

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"slices"

	re "github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/pkg/keymanagementprovider"
	"github.com/ratify-project/ratify/utils"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type KeyConfig struct {
	Provider string `json:"provider,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	File     string `json:"file,omitempty"`
}

type KeylessConfig struct {
	CTLogVerify                 *bool  `json:"ctLogVerify,omitempty"`
	CertificateIdentity         string `json:"certificateIdentity,omitempty"`
	CertificateIdentityRegExp   string `json:"certificateIdentityRegExp,omitempty"`
	CertificateOIDCIssuer       string `json:"certificateOIDCIssuer,omitempty"`
	CertificateOIDCIssuerRegExp string `json:"certificateOIDCIssuerRegExp,omitempty"`
}

type TrustPolicyConfig struct {
	Version    string        `json:"version"`
	Name       string        `json:"name"`
	Scopes     []string      `json:"scopes"`
	Keys       []KeyConfig   `json:"keys,omitempty"`
	Keyless    KeylessConfig `json:"keyless,omitempty"`
	TLogVerify *bool         `json:"tLogVerify,omitempty"`
	RekorURL   string        `json:"rekorURL,omitempty"`
}

type PKKey struct {
	Provider string `json:"provider,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
}

type trustPolicy struct {
	scopes       []string
	localKeys    map[PKKey]keymanagementprovider.PublicKey
	config       TrustPolicyConfig
	verifierName string
	isKeyless    bool
}

type TrustPolicy interface {
	GetName() string
	GetKeys(ctx context.Context, namespace string) (map[PKKey]keymanagementprovider.PublicKey, error)
	GetScopes() []string
	GetCosignOpts(context.Context) (cosign.CheckOpts, error)
}

const (
	fileProviderName                string = "file"
	DefaultRekorURL                 string = "https://rekor.sigstore.dev"
	DefaultTLogVerify               bool   = true
	DefaultCTLogVerify              bool   = true
	DefaultTrustPolicyConfigVersion string = "1.0.0"
)

var SupportedTrustPolicyConfigVersions = []string{DefaultTrustPolicyConfigVersion}

// CreateTrustPolicy creates a trust policy from the given configuration
// returns an error if the configuration is invalid
// reads the public keys from the file path
func CreateTrustPolicy(config TrustPolicyConfig, verifierName string) (TrustPolicy, error) {
	// set the default trust policy version if not provided
	// currently only one version is supported
	if config.Version == "" {
		config.Version = DefaultTrustPolicyConfigVersion
	}

	if err := validate(config); err != nil {
		return nil, err
	}

	keyMap := make(map[PKKey]keymanagementprovider.PublicKey)
	for _, keyConfig := range config.Keys {
		// check if the key is defined by file path or by key management provider
		if keyConfig.File != "" {
			pubKey, err := loadKeyFromPath(keyConfig.File)
			if err != nil {
				return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy [%s]: failed to load the key from file %s", config.Name, keyConfig.File)).WithError(err).WithRemediation("Ensure that the key file path is correct and public key is correctly saved.")
			}
			keyMap[PKKey{Provider: fileProviderName, Name: keyConfig.File}] = keymanagementprovider.PublicKey{Key: pubKey, ProviderType: fileProviderName}
		}
	}

	if config.RekorURL == "" {
		config.RekorURL = DefaultRekorURL
	}

	if config.TLogVerify == nil {
		config.TLogVerify = utils.MakePtr(DefaultTLogVerify)
	}

	if config.Keyless != (KeylessConfig{}) && config.Keyless.CTLogVerify == nil {
		config.Keyless.CTLogVerify = utils.MakePtr(DefaultCTLogVerify)
	}

	return &trustPolicy{
		scopes:       config.Scopes,
		localKeys:    keyMap,
		config:       config,
		verifierName: verifierName,
		isKeyless:    config.Keyless != KeylessConfig{},
	}, nil
}

// GetName returns the name of the trust policy
func (tp *trustPolicy) GetName() string {
	return tp.config.Name
}

// GetKeys returns the public keys defined in the trust policy
func (tp *trustPolicy) GetKeys(ctx context.Context, _ string) (map[PKKey]keymanagementprovider.PublicKey, error) {
	keyMap := make(map[PKKey]keymanagementprovider.PublicKey)
	// preload the local keys into the map of keys to be returned
	for key, pubKey := range tp.localKeys {
		keyMap[key] = pubKey
	}

	for _, keyConfig := range tp.config.Keys {
		// if the key is defined by file path, it has already been loaded into the key map
		if keyConfig.File != "" {
			continue
		}
		// get the key management provider resource which contains a map of keys
		kmpResource, kmpErr := keymanagementprovider.GetKeysFromMap(ctx, keyConfig.Provider)
		if kmpErr != nil {
			return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy [%s]: failed to access key management provider %s", tp.config.Name, keyConfig.Provider)).WithError(kmpErr)
		}
		// get a specific key from the key management provider resource
		if keyConfig.Name != "" {
			pubKey, exists := kmpResource[keymanagementprovider.KMPMapKey{Name: keyConfig.Name, Version: keyConfig.Version}]
			if !exists {
				return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy [%s]: key %s with version %s not found in key management provider %s", tp.config.Name, keyConfig.Name, keyConfig.Version, keyConfig.Provider))
			}
			keyMap[PKKey{Provider: keyConfig.Provider, Name: keyConfig.Name, Version: keyConfig.Version}] = pubKey
		} else {
			// get all public keys from the key management provider
			for key, pubKey := range kmpResource {
				keyMap[PKKey{Provider: keyConfig.Provider, Name: key.Name, Version: key.Version}] = pubKey
			}
		}
	}
	return keyMap, nil
}

// GetScopes returns the scopes defined in the trust policy
func (tp *trustPolicy) GetScopes() []string {
	return tp.scopes
}

func (tp *trustPolicy) GetCosignOpts(ctx context.Context) (cosign.CheckOpts, error) {
	cosignOpts := cosign.CheckOpts{}
	var err error
	// if tlog verification is enabled, set the rekor client and public keys
	if tp.config.TLogVerify != nil && *tp.config.TLogVerify {
		cosignOpts.IgnoreTlog = false
		// create the rekor client
		cosignOpts.RekorClient, err = rekor.NewClient(tp.config.RekorURL)
		if err != nil {
			return cosignOpts, re.ErrorCodeConfigInvalid.WithDetail(fmt.Errorf("failed to create Rekor client from URL %s", tp.config.RekorURL)).WithRemediation("Ensure that the Rekor URL is valid.").WithError(err)
		}
		// Fetches the Rekor public keys from the Rekor server
		cosignOpts.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return cosignOpts, re.ErrorCodeVerifyPluginFailure.WithDetail("failed to fetch Rekor public keys").WithRemediation(fmt.Sprintf("Please check if the Rekor server %s is available", tp.config.RekorURL)).WithError(err)
		}
	} else {
		cosignOpts.IgnoreTlog = true
	}

	// if keyless verification is enabled, set the root certificates, intermediate certificates, and certificate transparency log public keys
	if tp.isKeyless {
		roots, err := fulcio.GetRoots()
		if err != nil || roots == nil {
			return cosignOpts, re.ErrorCodeVerifyPluginFailure.WithDetail("Failed to get fulcio root").WithError(err).WithRemediation("Please check if Fulcio is available")
		}
		cosignOpts.RootCerts = roots
		if tp.config.Keyless.CTLogVerify != nil && *tp.config.Keyless.CTLogVerify {
			cosignOpts.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
			if err != nil {
				return cosignOpts, re.ErrorCodeVerifyPluginFailure.WithDetail("Failed to fetch certificate transparency log public keys").WithError(err).WithRemediation("Please check if TUF root is available")
			}
		} else {
			cosignOpts.IgnoreSCT = true
		}
		cosignOpts.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return cosignOpts, re.ErrorCodeVerifyPluginFailure.WithDetail("Failed to get fulcio intermediate certificates").WithError(err).WithRemediation("Please check if Fulcio is available")
		}
		// Set the certificate identity and issuer for keyless verification
		cosignOpts.Identities = []cosign.Identity{
			{
				IssuerRegExp:  tp.config.Keyless.CertificateOIDCIssuerRegExp,
				Issuer:        tp.config.Keyless.CertificateOIDCIssuer,
				SubjectRegExp: tp.config.Keyless.CertificateIdentityRegExp,
				Subject:       tp.config.Keyless.CertificateIdentity,
			},
		}
	}

	return cosignOpts, nil
}

// validate checks if the trust policy configuration is valid
// returns an error if the configuration is invalid
func validate(config TrustPolicyConfig) error {
	// check if the trust policy version is supported
	if !slices.Contains(SupportedTrustPolicyConfigVersions, config.Version) {
		return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: unsupported version %s", config.Name, config.Version)).WithRemediation(fmt.Sprintf("Supported versions are: %v", SupportedTrustPolicyConfigVersions))
	}

	if config.Name == "" {
		return re.ErrorCodeConfigInvalid.WithDetail("name parameter is required in trust policy configuration").WithRemediation("Please provide a name for the trust policy.")
	}

	if len(config.Scopes) == 0 {
		return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("scopes parameter is required in trust policy configuration %s", config.Name)).WithRemediation("Please provide at least one scope for the trust policy.")
	}

	// keys or keyless must be defined
	if len(config.Keys) == 0 && config.Keyless == (KeylessConfig{}) {
		return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("keys or keyless parameter is required in trust policy configuration %s", config.Name))
	}

	// only one of keys or keyless can be defined
	if len(config.Keys) > 0 && config.Keyless != (KeylessConfig{}) {
		return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Only one of keys or keyless parameter is required in trust policy configuration %s", config.Name))
	}

	for _, keyConfig := range config.Keys {
		// check if the key is defined by file path or by key management provider
		if keyConfig.File == "" && keyConfig.Provider == "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: key management provider name is required when not using file path", config.Name))
		}
		// both file path and key management provider cannot be defined together
		if keyConfig.File != "" && keyConfig.Provider != "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: 'name' and 'file' cannot be configured together", config.Name))
		}
		// key name is required when key version is defined
		if keyConfig.Version != "" && keyConfig.Name == "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: key name is required when key version is defined", config.Name))
		}
	}

	// validate keyless configuration
	if config.Keyless != (KeylessConfig{}) {
		// validate certificate identity specified
		if config.Keyless.CertificateIdentity == "" && config.Keyless.CertificateIdentityRegExp == "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: certificate identity or identity regex pattern is required", config.Name))
		}
		// validate certificate OIDC issuer specified
		if config.Keyless.CertificateOIDCIssuer == "" && config.Keyless.CertificateOIDCIssuerRegExp == "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: certificate OIDC issuer or issuer regex pattern is required", config.Name))
		}
		// validate only expression or value is specified for certificate identity
		if config.Keyless.CertificateIdentity != "" && config.Keyless.CertificateIdentityRegExp != "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: only one of certificate identity or identity regex pattern should be specified", config.Name))
		}
		// validate only expression or value is specified for certificate OIDC issuer
		if config.Keyless.CertificateOIDCIssuer != "" && config.Keyless.CertificateOIDCIssuerRegExp != "" {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Invalid trust policy %s: only one of certificate OIDC issuer or issuer regex pattern should be specified", config.Name))
		}
	}

	return nil
}

// loadKeyFromPath loads a public key from a file path and returns it
// TODO: look into supporting cosign's blob.LoadFileOrURL to support URL + env variables
func loadKeyFromPath(filePath string) (crypto.PublicKey, error) {
	contents, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if len(contents) == 0 {
		return nil, fmt.Errorf("key file %s is empty", filePath)
	}

	return cryptoutils.UnmarshalPEMToPublicKey(contents)
}
