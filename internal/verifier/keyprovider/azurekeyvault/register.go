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

package azurekeyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"

	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/pkcs12"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/notaryproject/ratify/v2/internal/cloudprovider/azure"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
	"github.com/sirupsen/logrus"
)

const (
	PKCS12ContentType         = "application/x-pkcs12"
	PEMContentType            = "application/x-pem-file"
	azureKeyVaultProviderName = "azurekeyvault"
)

// CertificateSpec represents a certificate specification with name and optional
// version
type CertificateSpec struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// KeySpec represents a key specification with name and optional version.
type KeySpec struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Options represents the configuration options for Azure Key Vault provider.
// Notes: Either Certificates or Keys must be specified.
type Options struct {
	VaultURL     string            `json:"vaultURL"`
	ClientID     string            `json:"clientID,omitempty"`
	TenantID     string            `json:"tenantID,omitempty"`
	Certificates []CertificateSpec `json:"certificates,omitempty"`
	Keys         []KeySpec         `json:"keys,omitempty"`
}

// Provider is a key provider that fetches certificate chains from Azure Key
// Vault secrets and public keys from Azure Key Vault keys.
type Provider struct {
	secretsClient *azsecrets.Client
	keysClient    *azkeys.Client
	certSpecs     []CertificateSpec
	keySpecs      []KeySpec
	cachedCerts   []*x509.Certificate
	cachedKeys    []*keyprovider.PublicKey
	mu            sync.RWMutex
}

func init() {
	keyprovider.RegisterKeyProvider(azureKeyVaultProviderName, func(options any) (keyprovider.KeyProvider, error) {
		raw, err := json.Marshal(options)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal options: %w", err)
		}

		var opts Options
		if err := json.Unmarshal(raw, &opts); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}

		if opts.VaultURL == "" {
			return nil, fmt.Errorf("vaultURL is required")
		}

		if len(opts.Certificates) == 0 && len(opts.Keys) == 0 {
			return nil, fmt.Errorf("at least one certificate or key must be specified")
		}

		// Create Azure credential chain (workload identity first, then managed identity)
		credential, err := azure.CreateCredentialChain(opts.ClientID, opts.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure credential chain: %w", err)
		}

		// Create Azure Key Vault secrets client for full certificate chains
		secretsClient, err := azsecrets.NewClient(opts.VaultURL, credential, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure Key Vault secrets client: %w", err)
		}

		// Create Azure Key Vault keys client for public keys
		keysClient, err := azkeys.NewClient(opts.VaultURL, credential, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure Key Vault keys client: %w", err)
		}

		provider := &Provider{
			secretsClient: secretsClient,
			keysClient:    keysClient,
			certSpecs:     opts.Certificates,
			keySpecs:      opts.Keys,
		}

		// Fetch and cache certificates during initialization if specified
		cachedCerts, err := provider.fetchAllCertificates(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to fetch certificates during initialization: %w", err)
		}

		// Fetch and cache keys during initialization if specified
		cachedKeys, err := provider.fetchAllKeys(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to fetch keys during initialization: %w", err)
		}

		provider.mu.Lock()
		defer provider.mu.Unlock()
		provider.cachedCerts = cachedCerts
		provider.cachedKeys = cachedKeys

		return provider, nil
	})
}

// GetCertificates returns the cached certificate chains that were fetched
// during initialization
func (p *Provider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.cachedCerts) == 0 {
		return nil, fmt.Errorf("no cached certificates available")
	}

	logrus.Debugf("Returning %d cached certificate(s) from Azure Key Vault", len(p.cachedCerts))
	return p.cachedCerts, nil
}

// GetKeys returns the cached public keys that were fetched during
// initialization.
func (p *Provider) GetKeys(_ context.Context) ([]*keyprovider.PublicKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.cachedKeys) == 0 {
		return nil, fmt.Errorf("no cached public keys available")
	}
	logrus.Debugf("Returning %d cached public key(s) from Azure Key Vault", len(p.cachedKeys))
	return p.cachedKeys, nil
}

// fetchAllCertificates fetches all certificate chains from Azure Key Vault
// during initialization
func (p *Provider) fetchAllCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	var allCerts []*x509.Certificate
	if len(p.certSpecs) == 0 {
		return allCerts, nil
	}

	for _, certSpec := range p.certSpecs {
		logrus.Infof("Fetching certificate chain for %q from Azure Key Vault during initialization", certSpec.Name)

		certChain, err := p.fetchCertificateChain(ctx, certSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch certificate chain for %q: %w", certSpec.Name, err)
		}

		if len(certChain) > 0 {
			allCerts = append(allCerts, certChain...)
		}
	}

	if len(allCerts) == 0 {
		return nil, fmt.Errorf("no valid certificates found in Azure Key Vault")
	}

	logrus.Infof("Successfully fetched %d certificate(s) from Azure Key Vault during initialization", len(allCerts))
	return allCerts, nil
}

// fetchAllKeys fetches all public keys from Azure Key Vault.
func (p *Provider) fetchAllKeys(ctx context.Context) ([]*keyprovider.PublicKey, error) {
	var allKeys []*keyprovider.PublicKey
	if len(p.keySpecs) == 0 {
		return allKeys, nil
	}

	for _, keySpec := range p.keySpecs {
		logrus.Infof("Fetching public key for %q from Azure Key Vault during initialization", keySpec.Name)

		key, err := p.fetchKey(ctx, keySpec)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch public key for %q: %w", keySpec.Name, err)
		}

		if key != nil {
			allKeys = append(allKeys, key)
		}
	}

	if len(allKeys) == 0 {
		return nil, fmt.Errorf("no valid public keys found in Azure Key Vault")
	}

	logrus.Infof("Successfully fetched %d public key(s) from Azure Key Vault during initialization", len(allKeys))
	return allKeys, nil
}

// fetchKey fetches a public key from Azure Key Vault.
func (p *Provider) fetchKey(ctx context.Context, keySpec KeySpec) (*keyprovider.PublicKey, error) {
	// Fetch the key from Azure Key Vault
	// If version is empty, Azure Key Vault will return the latest version
	resp, err := p.keysClient.GetKey(ctx, keySpec.Name, keySpec.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %q of version %q: %w", keySpec.Name, keySpec.Version, err)
	}

	if !*resp.Attributes.Enabled {
		return nil, fmt.Errorf("key %q of version %q is disabled", keySpec.Name, keySpec.Version)
	}

	if resp.Key == nil {
		return nil, fmt.Errorf("no key data found for key %q of version %q", keySpec.Name, keySpec.Version)
	}

	// Extract the public key from the response
	publicKey, err := extractPublicKeyFromKeyResponse(resp.Key, keySpec)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from key %q of version %q: %w", keySpec.Name, keySpec.Version, err)
	}

	logrus.Infof("Successfully fetched public key for '%s' (version: %s)", keySpec.Name, keySpec.Version)
	return publicKey, nil
}

// fetchCertificateChain fetches a complete certificate chain from Azure Key
// Vault secrets
func (p *Provider) fetchCertificateChain(ctx context.Context, certSpec CertificateSpec) ([]*x509.Certificate, error) {
	// Try to get the full chain from secrets
	chain, err := p.fetchChainFromSecrets(ctx, certSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate chain from secrets: %w", err)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificate chain found for '%s'", certSpec.Name)
	}

	logrus.Infof("Successfully fetched certificate chain for '%s' with %d certificates", certSpec.Name, len(chain))
	return chain, nil
}

// fetchChainFromSecrets attempts to fetch a full certificate chain stored as a
// secret
func (p *Provider) fetchChainFromSecrets(ctx context.Context, certSpec CertificateSpec) ([]*x509.Certificate, error) {
	resp, err := p.secretsClient.GetSecret(ctx, certSpec.Name, certSpec.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates %q of version %q: %w", certSpec.Name, certSpec.Version, err)
	}

	return extractCertificateFromResponse(resp, certSpec)
}

func extractCertificateFromResponse(resp azsecrets.GetSecretResponse, certSpec CertificateSpec) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	var err error

	switch *resp.ContentType {
	case PKCS12ContentType:
		chain, err = parseCertificateInPKCS12(resp.Value, certSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#12 certificate chain from secret %q of version %q: %w", certSpec.Name, certSpec.Version, err)
		}
	case PEMContentType:
		chain, err = parseCertificateInPem([]byte(*resp.Value), certSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate chain from secret %q of version %q: %w", certSpec.Name, certSpec.Version, err)
		}
	default:
		return nil, fmt.Errorf("unexpected content type %q for secret %q, expected %q or %q", *resp.ContentType, certSpec.Name, PKCS12ContentType, PEMContentType)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificate chain found in secret with name: %q of version %q", certSpec.Name, certSpec.Version)
	}
	return chain, nil
}

// parseCertificateInPKCS12 parses a certificate chain from PKCS#12 data
func parseCertificateInPKCS12(value *string, certSpec CertificateSpec) ([]*x509.Certificate, error) {
	if value == nil {
		return nil, fmt.Errorf("PKCS#12 data cannot be nil for certificate %s, version %s", certSpec.Name, certSpec.Version)
	}

	pfxBytes, err := base64.StdEncoding.DecodeString(*value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 encoded PKCS#12 data for certificate %s, version %s: %w", certSpec.Name, certSpec.Version, err)
	}

	blocks, err := pkcs12.ToPEM(pfxBytes, "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12 data for certificate %s, version %s: %w", certSpec.Name, certSpec.Version, err)
	}

	var pemData []byte
	for _, block := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}

	return parseCertificateInPem(pemData, certSpec)
}

// parseCertificateInPem parses a certificate chain from PEM data
func parseCertificateInPem(pemData []byte, certSpec CertificateSpec) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(pemData) > 0 {
		block, remainder := pem.Decode(pemData)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate in chain for secret %q of version %q: %w", certSpec.Name, certSpec.Version, err)
			}
			certs = append(certs, cert)
		case "PRIVATE KEY":
			logrus.Warnf("certificate %s, version %s private key skipped. Please see doc to learn how to create a new certificate in keyvault with non exportable keys. https://learn.microsoft.com/en-us/azure/key-vault/certificates/how-to-export-certificate?tabs=azure-cli#exportable-and-non-exportable-keys", certSpec.Name, certSpec.Version)
		}

		pemData = remainder
	}

	return certs, nil
}

// extractPublicKeyFromKeyResponse extracts a public key from Azure Key Vault
// GetKey response
func extractPublicKeyFromKeyResponse(key *azkeys.JSONWebKey, keySpec KeySpec) (*keyprovider.PublicKey, error) {
	if key.Kty == nil {
		return nil, fmt.Errorf("key type (kty) is nil for key %q of version %q", keySpec.Name, keySpec.Version)
	}

	switch *key.Kty {
	case azkeys.KeyTypeECHSM:
		*key.Kty = azkeys.KeyTypeEC
	case azkeys.KeyTypeRSAHSM:
		*key.Kty = azkeys.KeyTypeRSA
	}

	jwkJSON, err := json.Marshal(*key)
	if err != nil {
		return nil, fmt.Errorf("encoding the jsonWebKey: %w", err)
	}

	jwk := jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding the jsonWebKey: %w", err)
	}

	// Convert JWK algorithm (JWA) to crypto.Hash for keyprovider.PublicKey.SignatureAlgorithm.
	// Default to SHA256 when algorithm is empty or unsupported.
	sigAlg, err := inferHashType(jwk.Key)
	if err != nil {
		return nil, fmt.Errorf("converting JWK algorithm to crypto.Hash for key %q of version %q: %w", keySpec.Name, keySpec.Version, err)
	}

	return &keyprovider.PublicKey{
		Key:                jwk.Key,
		SignatureAlgorithm: sigAlg,
	}, nil
}

// inferHashType infers the hash type from the public key type and size.
func inferHashType(publicKey crypto.PublicKey) (crypto.Hash, error) {
	var hashType crypto.Hash
	switch keyType := publicKey.(type) {
	case *rsa.PublicKey:
		switch keyType.Size() {
		case 256:
			hashType = crypto.SHA256
		case 384:
			hashType = crypto.SHA384
		case 512:
			hashType = crypto.SHA512
		default:
			return crypto.Hash(0), fmt.Errorf("RSA key check: unsupported key size: %d", keyType.Size())
		}
	case *ecdsa.PublicKey:
		switch keyType.Curve {
		case elliptic.P256():
			hashType = crypto.SHA256
		case elliptic.P384():
			hashType = crypto.SHA384
		case elliptic.P521():
			hashType = crypto.SHA512
		default:
			return crypto.Hash(0), fmt.Errorf("ECDSA key check: unsupported key curve [%s]", keyType.Params().Name)
		}
	default:
		return crypto.Hash(0), fmt.Errorf("unsupported public key type [%T]", publicKey)
	}
	return hashType, nil
}
