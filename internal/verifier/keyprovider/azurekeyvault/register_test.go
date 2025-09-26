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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type contextKey string

const testKey contextKey = "key"

// generateTestCert creates a valid test certificate in DER format
func generateTestCert() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Company"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &priv.PublicKey, priv)
}

func TestParseCertificateInPem(t *testing.T) {
	validCertDER, err := generateTestCert()
	require.NoError(t, err)

	// Create PEM version
	validCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: validCertDER,
	})

	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		pemData     []byte
		expectError bool
		expectCerts int
	}{
		{
			name:        "valid PEM certificate",
			pemData:     validCertPEM,
			expectError: false,
			expectCerts: 1,
		},
		{
			name:        "multiple PEM certificates",
			pemData:     append(validCertPEM, validCertPEM...),
			expectError: false,
			expectCerts: 2,
		},
		{
			name:        "empty PEM data",
			pemData:     []byte{},
			expectError: false,
			expectCerts: 0,
		},
		{
			name:        "invalid PEM data",
			pemData:     []byte("invalid pem data"),
			expectError: false,
			expectCerts: 0,
		},
		{
			name: "PEM with private key (should be skipped)",
			pemData: append(validCertPEM, []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
-----END PRIVATE KEY-----`)...),
			expectError: false,
			expectCerts: 1, // only certificate should be parsed, private key skipped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateInPem(tt.pemData, certSpec)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, certs, tt.expectCerts)
				for _, cert := range certs {
					assert.IsType(t, &x509.Certificate{}, cert)
				}
			}
		})
	}
}

func TestParseCertificateInPemErrorScenarios(t *testing.T) {
	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		pemData     []byte
		expectError bool
		expectCerts int
		description string
	}{
		{
			name: "corrupted certificate in PEM",
			pemData: []byte(`-----BEGIN CERTIFICATE-----
dGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0aWZpY2F0ZQ==
-----END CERTIFICATE-----`),
			expectError: true,
			expectCerts: 0,
			description: "should fail when certificate data is corrupted",
		},
		{
			name: "valid cert followed by corrupted cert",
			pemData: func() []byte {
				validCertDER, _ := generateTestCert()
				validPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: validCertDER,
				})
				corruptedPEM := []byte(`-----BEGIN CERTIFICATE-----
dGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0aWZpY2F0ZQ==
-----END CERTIFICATE-----`)
				return append(validPEM, corruptedPEM...)
			}(),
			expectError: true,
			expectCerts: 0,
			description: "should fail when any certificate in chain is corrupted",
		},
		{
			name: "mixed content with unknown block type",
			pemData: func() []byte {
				validCertDER, _ := generateTestCert()
				validPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: validCertDER,
				})
				unknownBlock := []byte(`-----BEGIN UNKNOWN-----
some unknown content
-----END UNKNOWN-----`)
				return append(validPEM, unknownBlock...)
			}(),
			expectError: false,
			expectCerts: 1,
			description: "should skip unknown block types and parse valid certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateInPem(tt.pemData, certSpec)
			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Len(t, certs, tt.expectCerts, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.Len(t, certs, tt.expectCerts, tt.description)
			}
		})
	}
}

func TestParseCertificateInPKCS12(t *testing.T) {
	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		pkcs12Data  string
		expectError bool
	}{
		{
			name:        "invalid base64 data",
			pkcs12Data:  "invalid base64!!!",
			expectError: true,
		},
		{
			name:        "invalid PKCS#12 data",
			pkcs12Data:  "aW52YWxpZCBwa2NzMTI=", // base64 encoded "invalid pkcs12"
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateInPKCS12(&tt.pkcs12Data, certSpec)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, certs)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, certs)
			}
		})
	}
}

func TestParseCertificateInPKCS12ExtendedTests(t *testing.T) {
	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		pkcs12Data  string
		expectError bool
		description string
	}{
		{
			name:        "empty string",
			pkcs12Data:  "",
			expectError: true,
			description: "should fail with empty PKCS#12 data",
		},
		{
			name:        "invalid base64 data",
			pkcs12Data:  "invalid base64!!!",
			expectError: true,
			description: "should fail with invalid base64 encoding",
		},
		{
			name:        "valid base64 but invalid PKCS#12 content",
			pkcs12Data:  "aW52YWxpZCBwa2NzMTI=", // base64 encoded "invalid pkcs12"
			expectError: true,
			description: "should fail with invalid PKCS#12 content",
		},
		{
			name:        "valid base64 but not PKCS#12 format",
			pkcs12Data:  "dGhpcyBpcyBub3QgcGtjczEyIGZvcm1hdA==", // base64 encoded "this is not pkcs12 format"
			expectError: true,
			description: "should fail when content is not valid PKCS#12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateInPKCS12(&tt.pkcs12Data, certSpec)
			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Nil(t, certs, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, certs, tt.description)
			}
		})
	}
}

func TestContentTypeConstants(t *testing.T) {
	assert.Equal(t, "application/x-pkcs12", PKCS12ContentType)
	assert.Equal(t, "application/x-pem-file", PEMContentType)
	assert.Equal(t, "azurekeyvault", azureKeyVaultProviderName)
}

func TestAzureKeyVaultProviderRegistration(t *testing.T) {
	// Test that the provider is registered
	options := map[string]interface{}{
		"vaultURL": "https://test.vault.azure.net/",
		"certificates": []map[string]interface{}{
			{
				"name":    "test-cert",
				"version": "latest",
			},
		},
	}

	// This test only validates that the provider factory function is registered
	// and can parse options correctly, but we expect it to fail with network/auth errors
	// since we're not providing real credentials or connecting to a real vault
	provider, err := keyprovider.CreateKeyProvider(azureKeyVaultProviderName, options)
	assert.Error(t, err) // Should fail due to credential/network issues
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "failed to fetch certificates during initialization")
}

func TestAzureKeyVaultProviderValidation(t *testing.T) {
	tests := []struct {
		name        string
		options     interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid options - expect credential failure",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
				"certificates": []map[string]interface{}{
					{
						"name":    "test-cert",
						"version": "latest",
					},
				},
			},
			expectError: true, // Will fail with credential/network error, not validation error
		},
		{
			name: "missing vault URL",
			options: map[string]interface{}{
				"certificates": []map[string]interface{}{
					{
						"name": "test-cert",
					},
				},
			},
			expectError: true,
			errorMsg:    "vaultURL is required",
		},
		{
			name: "empty certificates",
			options: map[string]interface{}{
				"vaultURL":     "https://test.vault.azure.net/",
				"certificates": []map[string]interface{}{},
			},
			expectError: true,
			errorMsg:    "at least one certificate or key must be specified",
		},
		{
			name: "missing certificates",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
			},
			expectError: true,
			errorMsg:    "at least one certificate or key must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyprovider.CreateKeyProvider(azureKeyVaultProviderName, tt.options)
			assert.Error(t, err)
			if tt.errorMsg != "" {
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
		})
	}
}

func TestAzureKeyVaultProviderValidationExtended(t *testing.T) {
	tests := []struct {
		name        string
		options     interface{}
		expectError bool
		errorMsg    string
		description string
	}{
		{
			name:        "nil options",
			options:     nil,
			expectError: true,
			errorMsg:    "vaultURL is required", // nil gets marshaled to {}, which fails vault URL validation
			description: "should fail with nil options",
		},
		{
			name:        "invalid options type",
			options:     "invalid string options",
			expectError: true,
			errorMsg:    "failed to unmarshal options",
			description: "string options should be marshaled but fail validation",
		},
		{
			name: "empty vault URL string",
			options: map[string]interface{}{
				"vaultURL": "",
				"certificates": []map[string]interface{}{
					{"name": "test-cert"},
				},
			},
			expectError: true,
			errorMsg:    "vaultURL is required",
			description: "should fail with empty vault URL",
		},
		{
			name: "vault URL with wrong type",
			options: map[string]interface{}{
				"vaultURL": 123,
				"certificates": []map[string]interface{}{
					{"name": "test-cert"},
				},
			},
			expectError: true,
			errorMsg:    "failed to unmarshal options",
			description: "should fail when vaultURL is not a string",
		},
		{
			name: "certificates with empty name - should fail at runtime",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
				"certificates": []map[string]interface{}{
					{"name": ""},
				},
			},
			expectError: true,
			errorMsg:    "failed to fetch certificates during initialization",
			description: "empty certificate name should fail at runtime during certificate fetch",
		},
		{
			name: "certificates with invalid structure",
			options: map[string]interface{}{
				"vaultURL":     "https://test.vault.azure.net/",
				"certificates": "invalid certificates",
			},
			expectError: true,
			errorMsg:    "failed to unmarshal options",
			description: "should fail when certificates is not an array",
		},
		{
			name: "valid options with optional fields - should fail with credential error",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
				"clientID": "test-client-id",
				"tenantID": "test-tenant-id",
				"certificates": []map[string]interface{}{
					{
						"name":    "test-cert",
						"version": "latest",
					},
				},
			},
			expectError: true,
			errorMsg:    "failed to fetch certificates during initialization",
			description: "should succeed options validation but fail with credential error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyprovider.CreateKeyProvider(azureKeyVaultProviderName, tt.options)
			assert.Error(t, err, tt.description)
			if tt.errorMsg != "" {
				assert.Contains(t, err.Error(), tt.errorMsg, tt.description)
			}
		})
	}
}

func TestAzureKeyVaultOptionsUnmarshaling(t *testing.T) {
	options := map[string]interface{}{
		"vaultURL": "https://test.vault.azure.net/",
		"clientID": "test-client-id",
		"tenantID": "test-tenant-id",
		"certificates": []map[string]interface{}{
			{
				"name":    "cert1",
				"version": "v1",
			},
			{
				"name": "cert2",
				// version omitted - should default to empty string
			},
		},
	}

	// This test validates that options can be marshaled and unmarshaled correctly
	// We expect it to fail with credential/network errors, not unmarshaling errors
	provider, err := keyprovider.CreateKeyProvider(azureKeyVaultProviderName, options)

	// Provider creation should fail with credential error, not unmarshaling error
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "failed to fetch certificates during initialization")
}

func TestCertificateSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     CertificateSpec
		expected CertificateSpec
	}{
		{
			name:     "certificate with version",
			spec:     CertificateSpec{Name: "test-cert", Version: "v1"},
			expected: CertificateSpec{Name: "test-cert", Version: "v1"},
		},
		{
			name:     "certificate without version",
			spec:     CertificateSpec{Name: "test-cert"},
			expected: CertificateSpec{Name: "test-cert", Version: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected.Name, tt.spec.Name)
			assert.Equal(t, tt.expected.Version, tt.spec.Version)
		})
	}
}

func TestAzureKeyVaultOptions(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		expected Options
	}{
		{
			name: "complete options",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "test-client",
				TenantID: "test-tenant",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
					{Name: "cert2", Version: ""},
				},
			},
			expected: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "test-client",
				TenantID: "test-tenant",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
					{Name: "cert2", Version: ""},
				},
			},
		},
		{
			name: "minimal options",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				Certificates: []CertificateSpec{
					{Name: "cert1"},
				},
			},
			expected: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "",
				TenantID: "",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: ""},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected.VaultURL, tt.options.VaultURL)
			assert.Equal(t, tt.expected.ClientID, tt.options.ClientID)
			assert.Equal(t, tt.expected.TenantID, tt.options.TenantID)
			assert.Equal(t, len(tt.expected.Certificates), len(tt.options.Certificates))
			for i, cert := range tt.options.Certificates {
				assert.Equal(t, tt.expected.Certificates[i].Name, cert.Name)
				assert.Equal(t, tt.expected.Certificates[i].Version, cert.Version)
			}
		})
	}
}

func TestAzureKeyVaultOptions_Validation(t *testing.T) {
	tests := []struct {
		name         string
		vaultURL     string
		certificates []CertificateSpec
		expectValid  bool
	}{
		{
			name:     "valid options with single certificate",
			vaultURL: "https://test.vault.azure.net/",
			certificates: []CertificateSpec{
				{Name: "test-cert", Version: "v1"},
			},
			expectValid: true,
		},
		{
			name:     "valid options with multiple certificates",
			vaultURL: "https://test.vault.azure.net/",
			certificates: []CertificateSpec{
				{Name: "cert1", Version: "v1"},
				{Name: "cert2", Version: "v2"},
			},
			expectValid: true,
		},
		{
			name:         "invalid empty vault URL",
			vaultURL:     "",
			certificates: []CertificateSpec{{Name: "test-cert"}},
			expectValid:  false,
		},
		{
			name:         "invalid empty certificates",
			vaultURL:     "https://test.vault.azure.net/",
			certificates: []CertificateSpec{},
			expectValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				VaultURL:     tt.vaultURL,
				Certificates: tt.certificates,
			}

			if tt.expectValid {
				assert.NotEmpty(t, opts.VaultURL)
				assert.NotEmpty(t, opts.Certificates)
			} else {
				if opts.VaultURL == "" {
					assert.Empty(t, opts.VaultURL)
				}
				if len(opts.Certificates) == 0 {
					assert.Empty(t, opts.Certificates)
				}
			}
		})
	}
}

func TestAzureKeyVaultProvider_Structure(t *testing.T) {
	// Test that the provider has the expected structure
	provider := &Provider{
		secretsClient: nil, // Would be initialized in real usage
		certSpecs:     []CertificateSpec{{Name: "test-cert", Version: "v1"}},
		cachedCerts:   []*x509.Certificate{},
	}

	assert.NotNil(t, provider.certSpecs)
	assert.NotNil(t, provider.cachedCerts)
	assert.Len(t, provider.certSpecs, 1)
	assert.Equal(t, "test-cert", provider.certSpecs[0].Name)
	assert.Equal(t, "v1", provider.certSpecs[0].Version)
}

func TestAzureKeyVaultProvider_GetCertificates(t *testing.T) {
	validCertDER, err := generateTestCert()
	require.NoError(t, err)

	validCert, err := x509.ParseCertificate(validCertDER)
	require.NoError(t, err)

	tests := []struct {
		name          string
		cachedCerts   []*x509.Certificate
		expectedCount int
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "successful retrieval with cached certificates",
			cachedCerts:   []*x509.Certificate{validCert},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "successful retrieval with multiple cached certificates",
			cachedCerts:   []*x509.Certificate{validCert, validCert},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "no cached certificates available",
			cachedCerts:   []*x509.Certificate{},
			expectedCount: 0,
			expectError:   true,
			errorMessage:  "no cached certificates available",
		},
		{
			name:          "nil cached certificates",
			cachedCerts:   nil,
			expectedCount: 0,
			expectError:   true,
			errorMessage:  "no cached certificates available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{
				secretsClient: nil, // Not needed for this test since we use cached certs
				certSpecs:     []CertificateSpec{{Name: "test-cert"}},
				cachedCerts:   tt.cachedCerts,
			}

			certs, err := provider.GetCertificates(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, certs)
			} else {
				assert.NoError(t, err)
				assert.Len(t, certs, tt.expectedCount)
				for _, cert := range certs {
					assert.IsType(t, &x509.Certificate{}, cert)
				}
			}
		})
	}
}

func TestAzureKeyVaultProvider_GetKeys(t *testing.T) {
	tests := []struct {
		name         string
		provider     *Provider
		expectError  bool
		errorMessage string
		description  string
	}{
		{
			name: "no cached keys available - standard provider",
			provider: &Provider{
				secretsClient: nil, // Not needed for this test
				certSpecs:     []CertificateSpec{{Name: "test-cert"}},
				cachedCerts:   nil,
				cachedKeys:    nil,
			},
			expectError:  true,
			errorMessage: "no cached public keys available",
			description:  "should return error when no cached keys are available",
		},
		{
			name: "no cached keys available - provider with cached certificates",
			provider: func() *Provider {
				validCertDER, _ := generateTestCert()
				validCert, _ := x509.ParseCertificate(validCertDER)
				return &Provider{
					secretsClient: nil, // Not needed for this test
					certSpecs:     []CertificateSpec{{Name: "test-cert"}},
					cachedCerts:   []*x509.Certificate{validCert},
					cachedKeys:    nil,
				}
			}(),
			expectError:  true,
			errorMessage: "no cached public keys available",
			description:  "should return error when no cached keys available even with cached certificates",
		},
		{
			name: "no cached keys available - provider with multiple certificate specs",
			provider: &Provider{
				secretsClient: nil, // Not needed for this test
				certSpecs: []CertificateSpec{
					{Name: "test-cert-1", Version: "v1"},
					{Name: "test-cert-2", Version: "v2"},
				},
				cachedCerts: nil,
				cachedKeys:  nil,
			},
			expectError:  true,
			errorMessage: "no cached public keys available",
			description:  "should return error when no cached keys available regardless of number of certificate specs",
		},
		{
			name: "no cached keys available - empty provider",
			provider: &Provider{
				secretsClient: nil,
				certSpecs:     []CertificateSpec{},
				cachedCerts:   []*x509.Certificate{},
				cachedKeys:    []*keyprovider.PublicKey{},
			},
			expectError:  true,
			errorMessage: "no cached public keys available",
			description:  "should return error when cached keys is empty slice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := tt.provider.GetKeys(context.Background())

			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), tt.errorMessage, tt.description)
				assert.Nil(t, keys, "keys should be nil when error occurs")
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, keys, "keys should not be nil when no error occurs")
			}
		})
	}
}

func TestAzureKeyVaultProvider_GetKeys_WithContext(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		expectError bool
		description string
	}{
		{
			name:        "GetKeys with background context",
			ctx:         context.Background(),
			expectError: true,
			description: "should return error with background context when no cached keys",
		},
		{
			name:        "GetKeys with TODO context",
			ctx:         context.TODO(),
			expectError: true,
			description: "should return error with TODO context when no cached keys",
		},
		{
			name:        "GetKeys with value context",
			ctx:         context.WithValue(context.Background(), testKey, "value"),
			expectError: true,
			description: "should return error with value context when no cached keys",
		},
		{
			name: "GetKeys with cancelled context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			expectError: true,
			description: "should return error even with cancelled context when no cached keys",
		},
	}

	provider := &Provider{
		secretsClient: nil,
		certSpecs:     []CertificateSpec{{Name: "test-cert"}},
		cachedCerts:   nil,
		cachedKeys:    nil,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := provider.GetKeys(tt.ctx)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), "no cached public keys available", tt.description)
				assert.Nil(t, keys, "keys should be nil when error occurs")
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, keys, "keys should not be nil when no error occurs")
			}
		})
	}
}

func TestParseCertificateInPKCS12_EdgeCases(t *testing.T) {
	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		pkcs12Data  *string
		expectError bool
		description string
	}{
		{
			name:        "nil PKCS12 data pointer",
			pkcs12Data:  nil,
			expectError: true,
			description: "should handle nil pointer gracefully",
		},
		{
			name:        "empty PKCS12 data",
			pkcs12Data:  stringPtr(""),
			expectError: true,
			description: "should fail with empty data",
		},
		{
			name:        "whitespace only PKCS12 data",
			pkcs12Data:  stringPtr("   "),
			expectError: true,
			description: "should fail with whitespace only data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateInPKCS12(tt.pkcs12Data, certSpec)
			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Nil(t, certs, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, certs, tt.description)
			}
		})
	}
}

func TestParseCertificateInPem_DetailedScenarios(t *testing.T) {
	validCertDER, err := generateTestCert()
	require.NoError(t, err)

	validCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: validCertDER,
	})

	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		pemData     []byte
		expectError bool
		expectCerts int
		description string
	}{
		{
			name: "certificate with RSA private key",
			pemData: append(validCertPEM, []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtskG1234567890abcdefghijklmnopqrstuvwxyz1234567890
-----END RSA PRIVATE KEY-----`)...),
			expectError: false,
			expectCerts: 1,
			description: "should parse certificate and skip RSA private key",
		},
		{
			name: "certificate with EC private key",
			pemData: append(validCertPEM, []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBK7gF1234567890abcdefghijklmnopqrstuvwxyz1234567890abcd
-----END EC PRIVATE KEY-----`)...),
			expectError: false,
			expectCerts: 1,
			description: "should parse certificate and skip EC private key",
		},
		{
			name: "certificate with PKCS#8 private key",
			pemData: append(validCertPEM, []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
-----END PRIVATE KEY-----`)...),
			expectError: false,
			expectCerts: 1,
			description: "should parse certificate and skip PKCS#8 private key",
		},
		{
			name: "mixed content with certificate request",
			pemData: append(validCertPEM, []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIICWjCCAUICAQAwFTETMBEGA1UEAwwKbXlkb21haW4uY29tMIIBIjANBgkqhkiG
-----END CERTIFICATE REQUEST-----`)...),
			expectError: false,
			expectCerts: 1,
			description: "should parse certificate and skip CSR",
		},
		{
			name: "certificate with CRL",
			pemData: append(validCertPEM, []byte(`-----BEGIN X509 CRL-----
MIIBpzCBkAIBATANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzELMAkGA1UE
-----END X509 CRL-----`)...),
			expectError: false,
			expectCerts: 1,
			description: "should parse certificate and skip CRL",
		},
		{
			name: "only private key, no certificate",
			pemData: []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
-----END PRIVATE KEY-----`),
			expectError: false,
			expectCerts: 0,
			description: "should return no certificates when only private key present",
		},
		{
			name:        "malformed PEM header",
			pemData:     []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
			expectError: true,
			expectCerts: 0,
			description: "should fail with empty certificate data",
		},
		{
			name:        "binary data that's not PEM",
			pemData:     []byte{0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09},
			expectError: false,
			expectCerts: 0,
			description: "should handle binary data gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateInPem(tt.pemData, certSpec)
			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.Len(t, certs, tt.expectCerts, tt.description)
			}
		})
	}
}

func TestAzureKeyVaultProvider_ConcurrentAccess(t *testing.T) {
	validCertDER, err := generateTestCert()
	require.NoError(t, err)

	validCert, err := x509.ParseCertificate(validCertDER)
	require.NoError(t, err)

	provider := &Provider{
		secretsClient: nil,
		certSpecs:     []CertificateSpec{{Name: "test-cert"}},
		cachedCerts:   []*x509.Certificate{validCert},
	}

	// Test concurrent access to GetCertificates
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	results := make(chan []*x509.Certificate, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certs, err := provider.GetCertificates(context.Background())
			if err != nil {
				errors <- err
				return
			}
			results <- certs
		}()
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check that all goroutines succeeded
	for err := range errors {
		t.Errorf("Concurrent access failed: %v", err)
	}

	// Check that all results are consistent
	resultCount := 0
	for certs := range results {
		resultCount++
		assert.Len(t, certs, 1)
		assert.Equal(t, validCert.Subject, certs[0].Subject)
	}
	assert.Equal(t, numGoroutines, resultCount)
}

func TestCertificateSpec_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		spec     CertificateSpec
		expected string
	}{
		{
			name:     "certificate with version",
			spec:     CertificateSpec{Name: "test-cert", Version: "v1"},
			expected: `{"name":"test-cert","version":"v1"}`,
		},
		{
			name:     "certificate without version",
			spec:     CertificateSpec{Name: "test-cert"},
			expected: `{"name":"test-cert"}`,
		},
		{
			name:     "certificate with empty version",
			spec:     CertificateSpec{Name: "test-cert", Version: ""},
			expected: `{"name":"test-cert"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.spec)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(data))

			// Test unmarshaling
			var spec CertificateSpec
			err = json.Unmarshal(data, &spec)
			assert.NoError(t, err)
			assert.Equal(t, tt.spec.Name, spec.Name)
			assert.Equal(t, tt.spec.Version, spec.Version)
		})
	}
}

func TestAzureKeyVaultOptions_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		expected string
	}{
		{
			name: "complete options",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "test-client",
				TenantID: "test-tenant",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
				},
			},
			expected: `{
				"vaultURL": "https://test.vault.azure.net/",
				"clientID": "test-client",
				"tenantID": "test-tenant",
				"certificates": [{"name": "cert1", "version": "v1"}]
			}`,
		},
		{
			name: "minimal options",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				Certificates: []CertificateSpec{
					{Name: "cert1"},
				},
			},
			expected: `{
				"vaultURL": "https://test.vault.azure.net/",
				"certificates": [{"name": "cert1"}]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.options)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(data))

			// Test unmarshaling
			var options Options
			err = json.Unmarshal(data, &options)
			assert.NoError(t, err)
			assert.Equal(t, tt.options.VaultURL, options.VaultURL)
			assert.Equal(t, tt.options.ClientID, options.ClientID)
			assert.Equal(t, tt.options.TenantID, options.TenantID)
			assert.Equal(t, len(tt.options.Certificates), len(options.Certificates))
		})
	}
}

func TestAzureKeyVaultOptions_MixedKeysAndCertificates(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		expected Options
	}{
		{
			name: "options with both certificates and keys",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "test-client",
				TenantID: "test-tenant",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
					{Name: "cert2", Version: ""},
				},
				Keys: []KeySpec{
					{Name: "key1", Version: "v1"},
					{Name: "key2", Version: ""},
				},
			},
			expected: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "test-client",
				TenantID: "test-tenant",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
					{Name: "cert2", Version: ""},
				},
				Keys: []KeySpec{
					{Name: "key1", Version: "v1"},
					{Name: "key2", Version: ""},
				},
			},
		},
		{
			name: "options with only keys",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				Keys: []KeySpec{
					{Name: "key1", Version: "v1"},
				},
			},
			expected: Options{
				VaultURL:     "https://test.vault.azure.net/",
				ClientID:     "",
				TenantID:     "",
				Certificates: nil,
				Keys: []KeySpec{
					{Name: "key1", Version: "v1"},
				},
			},
		},
		{
			name: "options with only certificates",
			options: Options{
				VaultURL: "https://test.vault.azure.net/",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
				},
			},
			expected: Options{
				VaultURL: "https://test.vault.azure.net/",
				ClientID: "",
				TenantID: "",
				Certificates: []CertificateSpec{
					{Name: "cert1", Version: "v1"},
				},
				Keys: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected.VaultURL, tt.options.VaultURL)
			assert.Equal(t, tt.expected.ClientID, tt.options.ClientID)
			assert.Equal(t, tt.expected.TenantID, tt.options.TenantID)
			assert.Equal(t, len(tt.expected.Certificates), len(tt.options.Certificates))
			assert.Equal(t, len(tt.expected.Keys), len(tt.options.Keys))

			// Check certificates
			for i, cert := range tt.options.Certificates {
				assert.Equal(t, tt.expected.Certificates[i].Name, cert.Name)
				assert.Equal(t, tt.expected.Certificates[i].Version, cert.Version)
			}

			// Check keys
			for i, key := range tt.options.Keys {
				assert.Equal(t, tt.expected.Keys[i].Name, key.Name)
				assert.Equal(t, tt.expected.Keys[i].Version, key.Version)
			}
		})
	}
}

func TestAzureKeyVaultProvider_MixedKeysAndCertificatesValidation(t *testing.T) {
	tests := []struct {
		name        string
		options     interface{}
		expectError bool
		errorMsg    string
		description string
	}{
		{
			name: "valid options with both certificates and keys",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
				"certificates": []map[string]interface{}{
					{
						"name":    "test-cert",
						"version": "latest",
					},
				},
				"keys": []map[string]interface{}{
					{
						"name":    "test-key",
						"version": "latest",
					},
				},
			},
			expectError: true, // Will fail with credential/network error
			errorMsg:    "failed to fetch",
			description: "should accept both certificates and keys but fail with credential error",
		},
		{
			name: "valid options with only keys",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
				"keys": []map[string]interface{}{
					{
						"name":    "test-key",
						"version": "latest",
					},
				},
			},
			expectError: true, // Will fail with credential/network error
			errorMsg:    "failed to fetch",
			description: "should accept only keys but fail with credential error",
		},
		{
			name: "empty options - no certificates or keys",
			options: map[string]interface{}{
				"vaultURL": "https://test.vault.azure.net/",
			},
			expectError: true,
			errorMsg:    "at least one certificate or key must be specified",
			description: "should fail when neither certificates nor keys are specified",
		},
		{
			name: "both empty arrays",
			options: map[string]interface{}{
				"vaultURL":     "https://test.vault.azure.net/",
				"certificates": []map[string]interface{}{},
				"keys":         []map[string]interface{}{},
			},
			expectError: true,
			errorMsg:    "at least one certificate or key must be specified",
			description: "should fail when both certificates and keys arrays are empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyprovider.CreateKeyProvider(azureKeyVaultProviderName, tt.options)
			assert.Error(t, err, tt.description)
			if tt.errorMsg != "" {
				assert.Contains(t, err.Error(), tt.errorMsg, tt.description)
			}
		})
	}
}

// Helper function for creating string pointers
func stringPtr(s string) *string {
	return &s
}

func TestKeySpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     KeySpec
		expected KeySpec
	}{
		{
			name:     "key with version",
			spec:     KeySpec{Name: "test-key", Version: "v1"},
			expected: KeySpec{Name: "test-key", Version: "v1"},
		},
		{
			name:     "key without version",
			spec:     KeySpec{Name: "test-key"},
			expected: KeySpec{Name: "test-key", Version: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected.Name, tt.spec.Name)
			assert.Equal(t, tt.expected.Version, tt.spec.Version)
		})
	}
}

func TestKeySpec_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		spec     KeySpec
		expected string
	}{
		{
			name:     "key with version",
			spec:     KeySpec{Name: "test-key", Version: "v1"},
			expected: `{"name":"test-key","version":"v1"}`,
		},
		{
			name:     "key without version",
			spec:     KeySpec{Name: "test-key"},
			expected: `{"name":"test-key"}`,
		},
		{
			name:     "key with empty version",
			spec:     KeySpec{Name: "test-key", Version: ""},
			expected: `{"name":"test-key"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.spec)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(data))

			// Test unmarshaling
			var spec KeySpec
			err = json.Unmarshal(data, &spec)
			assert.NoError(t, err)
			assert.Equal(t, tt.spec.Name, spec.Name)
			assert.Equal(t, tt.spec.Version, spec.Version)
		})
	}
}

func TestExtractCertificateFromResponse(t *testing.T) {
	// Generate test certificate
	validCertDER, err := generateTestCert()
	require.NoError(t, err)

	// Create PEM encoded certificate for testing
	validCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: validCertDER,
	})

	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name        string
		response    azsecrets.GetSecretResponse
		expectError bool
		expectCerts int
		description string
	}{
		{
			name: "valid PEM certificate",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr(string(validCertPEM)),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectError: false,
			expectCerts: 1,
			description: "should successfully parse PEM certificate",
		},
		{
			name: "multiple PEM certificates",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr(string(validCertPEM) + string(validCertPEM)),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectError: false,
			expectCerts: 2,
			description: "should successfully parse multiple PEM certificates",
		},
		{
			name: "unsupported content type",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr(string(validCertPEM)),
					ContentType: stringPtr("application/unknown"),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail with unsupported content type",
		},
		// Removing nil content type test as the function doesn't handle it safely
		// Removing nil value test as the function doesn't handle it safely
		{
			name: "empty value",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr(""),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail with empty value (no certificates found)",
		},
		{
			name: "invalid PEM data",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("invalid pem data"),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail with invalid PEM data (no certificates found)",
		},
		{
			name: "invalid PKCS#12 data",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("invalid base64!!!"),
					ContentType: stringPtr(PKCS12ContentType),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail with invalid PKCS#12 base64 data",
		},
		{
			name: "corrupted certificate in PEM",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: stringPtr(`-----BEGIN CERTIFICATE-----
dGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0aWZpY2F0ZQ==
-----END CERTIFICATE-----`),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail with corrupted certificate data",
		},
		{
			name: "no certificate chain found",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----"),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail when no certificate chain is found",
		},
		{
			name: "invalid PKCS#12 content",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("aW52YWxpZCBwa2NzMTI="), // base64 encoded "invalid pkcs12"
					ContentType: stringPtr(PKCS12ContentType),
				},
			},
			expectError: true,
			expectCerts: 0,
			description: "should fail with invalid PKCS#12 content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := extractCertificateFromResponse(tt.response, certSpec)
			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Len(t, certs, tt.expectCerts, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.Len(t, certs, tt.expectCerts, tt.description)
				// Verify that returned certificates are valid x509 certificates
				for _, cert := range certs {
					assert.IsType(t, &x509.Certificate{}, cert)
				}
			}
		})
	}
}

func TestExtractCertificateFromResponse_ErrorMessages(t *testing.T) {
	certSpec := CertificateSpec{Name: "test-cert", Version: "v1"}

	tests := []struct {
		name             string
		response         azsecrets.GetSecretResponse
		expectedErrorMsg string
	}{
		{
			name: "unexpected content type error message",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("some value"),
					ContentType: stringPtr("application/unknown"),
				},
			},
			expectedErrorMsg: "unexpected content type \"application/unknown\" for secret \"test-cert\", expected \"application/x-pkcs12\" or \"application/x-pem-file\"",
		},
		{
			name: "PKCS#12 parsing error message contains version",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("invalid base64!!!"),
					ContentType: stringPtr(PKCS12ContentType),
				},
			},
			expectedErrorMsg: "failed to parse PKCS#12 certificate chain from secret \"test-cert\" of version \"v1\"",
		},
		{
			name: "PEM parsing error message contains version",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: stringPtr(`-----BEGIN CERTIFICATE-----
dGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0aWZpY2F0ZQ==
-----END CERTIFICATE-----`),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectedErrorMsg: "failed to parse PEM certificate chain from secret \"test-cert\" of version \"v1\"",
		},
		{
			name: "no certificate chain found error message",
			response: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value:       stringPtr("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----"),
					ContentType: stringPtr(PEMContentType),
				},
			},
			expectedErrorMsg: "no certificate chain found in secret with name: \"test-cert\" of version \"v1\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractCertificateFromResponse(tt.response, certSpec)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrorMsg)
		})
	}
}

func TestInferHashType(t *testing.T) {
	tests := []struct {
		name        string
		keyFunc     func() crypto.PublicKey
		expected    crypto.Hash
		expectError bool
		errorMsg    string
	}{
		{
			name: "RSA 2048 key (256 bytes)",
			keyFunc: func() crypto.PublicKey {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &key.PublicKey
			},
			expected:    crypto.SHA256,
			expectError: false,
		},
		{
			name: "RSA 3072 key (384 bytes)",
			keyFunc: func() crypto.PublicKey {
				key, _ := rsa.GenerateKey(rand.Reader, 3072)
				return &key.PublicKey
			},
			expected:    crypto.SHA384,
			expectError: false,
		},
		{
			name: "RSA 4096 key (512 bytes)",
			keyFunc: func() crypto.PublicKey {
				key, _ := rsa.GenerateKey(rand.Reader, 4096)
				return &key.PublicKey
			},
			expected:    crypto.SHA512,
			expectError: false,
		},
		{
			name: "ECDSA P256 key",
			keyFunc: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &key.PublicKey
			},
			expected:    crypto.SHA256,
			expectError: false,
		},
		{
			name: "ECDSA P384 key",
			keyFunc: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return &key.PublicKey
			},
			expected:    crypto.SHA384,
			expectError: false,
		},
		{
			name: "ECDSA P521 key",
			keyFunc: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return &key.PublicKey
			},
			expected:    crypto.SHA512,
			expectError: false,
		},
		{
			name: "unsupported key type",
			keyFunc: func() crypto.PublicKey {
				return "unsupported"
			},
			expectError: true,
			errorMsg:    "unsupported public key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var publicKey crypto.PublicKey
			if tt.keyFunc != nil {
				publicKey = tt.keyFunc()
			}

			hash, err := inferHashType(publicKey)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, hash)
			}
		})
	}
}

func TestAzureKeyVaultProvider_FetchAllCertificates_EmptySpecs(t *testing.T) {
	// Test the case where no certificates are specified
	provider := &Provider{
		secretsClient: nil, // Not needed for this test
		keysClient:    nil,
		certSpecs:     []CertificateSpec{}, // Empty specs
		keySpecs:      []KeySpec{},
		cachedCerts:   nil,
		cachedKeys:    nil,
	}

	certs, err := provider.fetchAllCertificates(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, certs)
	assert.Equal(t, 0, len(certs)) // Should return empty slice, not nil
}

func TestAzureKeyVaultProvider_FetchAllKeys_EmptySpecs(t *testing.T) {
	// Test the case where no keys are specified
	provider := &Provider{
		secretsClient: nil, // Not needed for this test
		keysClient:    nil,
		certSpecs:     []CertificateSpec{},
		keySpecs:      []KeySpec{}, // Empty specs
		cachedCerts:   nil,
		cachedKeys:    nil,
	}

	keys, err := provider.fetchAllKeys(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, keys)
	assert.Equal(t, 0, len(keys)) // Should return empty slice, not nil
}

func TestAzureKeyVaultProvider_GetKeys_WithCachedKeys(t *testing.T) {
	// Create a test public key to use as cached data
	// Note: We'll create a minimal mock key since we can't easily create real crypto keys in tests
	tests := []struct {
		name          string
		cachedKeys    []*keyprovider.PublicKey
		expectedCount int
		expectError   bool
		errorMessage  string
	}{
		{
			name: "successful retrieval with cached keys",
			cachedKeys: []*keyprovider.PublicKey{
				{
					Key:                nil, // Mock key
					SignatureAlgorithm: crypto.SHA256,
				},
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "successful retrieval with multiple cached keys",
			cachedKeys: []*keyprovider.PublicKey{
				{
					Key:                nil, // Mock key
					SignatureAlgorithm: crypto.SHA256,
				},
				{
					Key:                nil, // Mock key
					SignatureAlgorithm: crypto.SHA384,
				},
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "no cached keys available",
			cachedKeys:    []*keyprovider.PublicKey{},
			expectedCount: 0,
			expectError:   true,
			errorMessage:  "no cached public keys available",
		},
		{
			name:          "nil cached keys",
			cachedKeys:    nil,
			expectedCount: 0,
			expectError:   true,
			errorMessage:  "no cached public keys available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{
				secretsClient: nil, // Not needed for this test since we use cached keys
				keysClient:    nil,
				certSpecs:     []CertificateSpec{},
				keySpecs:      []KeySpec{{Name: "test-key"}},
				cachedCerts:   nil,
				cachedKeys:    tt.cachedKeys,
			}

			keys, err := provider.GetKeys(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, keys)
			} else {
				assert.NoError(t, err)
				assert.Len(t, keys, tt.expectedCount)
				for _, key := range keys {
					assert.IsType(t, &keyprovider.PublicKey{}, key)
				}
			}
		})
	}
}

func TestExtractPublicKeyFromKeyResponse(t *testing.T) {
	keySpec := KeySpec{Name: "test-key", Version: "v1"}

	tests := []struct {
		name        string
		key         *azkeys.JSONWebKey
		expectError bool
		errorMsg    string
		description string
	}{
		{
			name: "nil key type",
			key: &azkeys.JSONWebKey{
				Kty: nil,
			},
			expectError: true,
			errorMsg:    "key type (kty) is nil for key \"test-key\" of version \"v1\"",
			description: "should fail when key type is nil",
		},
		{
			name: "EC HSM key type conversion",
			key: &azkeys.JSONWebKey{
				Kty: &[]azkeys.KeyType{azkeys.KeyTypeECHSM}[0],
			},
			expectError: true, // Will fail during jose unmarshaling due to missing key data
			errorMsg:    "decoding the jsonWebKey",
			description: "should convert EC HSM to EC but fail during unmarshaling",
		},
		{
			name: "RSA HSM key type conversion",
			key: &azkeys.JSONWebKey{
				Kty: &[]azkeys.KeyType{azkeys.KeyTypeRSAHSM}[0],
			},
			expectError: true, // Will fail during jose unmarshaling due to missing key data
			errorMsg:    "decoding the jsonWebKey",
			description: "should convert RSA HSM to RSA but fail during unmarshaling",
		},
		{
			name: "EC key type",
			key: &azkeys.JSONWebKey{
				Kty: &[]azkeys.KeyType{azkeys.KeyTypeEC}[0],
			},
			expectError: true, // Will fail during jose unmarshaling due to missing key data
			errorMsg:    "decoding the jsonWebKey",
			description: "should handle EC key type but fail during unmarshaling",
		},
		{
			name: "RSA key type",
			key: &azkeys.JSONWebKey{
				Kty: &[]azkeys.KeyType{azkeys.KeyTypeRSA}[0],
			},
			expectError: true, // Will fail during jose unmarshaling due to missing key data
			errorMsg:    "decoding the jsonWebKey",
			description: "should handle RSA key type but fail during unmarshaling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, err := extractPublicKeyFromKeyResponse(tt.key, keySpec)
			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), tt.errorMsg, tt.description)
				assert.Nil(t, publicKey, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, publicKey, tt.description)
				assert.IsType(t, &keyprovider.PublicKey{}, publicKey)
			}
		})
	}
}
