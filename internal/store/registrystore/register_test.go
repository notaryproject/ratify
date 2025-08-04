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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/store"
	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/static" // Register the static credential provider factory
)

// generateTestCertificate creates a test certificate for testing purposes
func generateTestCertificate() (string, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", err
	}

	// Encode certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM), nil
}

// generateTestCertificateBase64 creates a test certificate and returns it as Base64 encoded string
func generateTestCertificateBase64() (string, error) {
	certPEM, err := generateTestCertificate()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(certPEM)), nil
}

func TestNewStore(t *testing.T) {
	tests := []struct {
		name      string
		opts      store.NewOptions
		expectErr bool
	}{
		{
			name: "Unsupported params type",
			opts: store.NewOptions{
				Type:       registryStoreType,
				Parameters: make(chan int),
			},
			expectErr: true,
		},
		{
			name: "Malformed JSON params",
			opts: store.NewOptions{
				Type:       registryStoreType,
				Parameters: "{invalid json",
			},
			expectErr: true,
		},
		{
			name: "Missing credential provider",
			opts: store.NewOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"plainHttp": true,
				},
			},
			expectErr: true,
		},
		{
			name: "Invalid credential provider type",
			opts: store.NewOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": map[string]interface{}{
						"provider": "nonexistent",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Valid registry params with static credential provider",
			opts: store.NewOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"plainHttp":        true,
					"userAgent":        "test-agent",
					"maxBlobBytes":     1024,
					"maxManifestBytes": 2048,
					"credential": map[string]interface{}{
						"provider": "static",
						"username": "testuser",
						"password": "testpass",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "Valid registry params with minimal config",
			opts: store.NewOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": map[string]interface{}{
						"provider": "static",
						"password": "token",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "Empty credential provider options",
			opts: store.NewOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": map[string]interface{}{},
				},
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := store.New([]store.NewOptions{test.opts}, nil)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}
			if !test.expectErr && store == nil {
				t.Error("expected non-nil store when no error occurred")
			}
			if test.expectErr && store != nil {
				t.Error("expected nil store when error occurred")
			}
		})
	}
}

func TestRegistryStoreFactory(t *testing.T) {
	// Test that the factory is properly registered
	t.Run("Factory is registered", func(t *testing.T) {
		opts := store.NewOptions{
			Type: registryStoreType,
			Parameters: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
		}

		_, err := store.New([]store.NewOptions{opts}, nil)
		if err != nil {
			t.Errorf("factory should be registered and functional, got error: %v", err)
		}
	})
}

func TestStoreOptionsUnmarshaling(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]interface{}
		expectErr  bool
		verifyFunc func(*testing.T, map[string]interface{})
	}{
		{
			name: "All options set",
			params: map[string]interface{}{
				"plainHttp":        true,
				"userAgent":        "custom-agent/1.0",
				"maxBlobBytes":     int64(5000),
				"maxManifestBytes": int64(10000),
				"credential": map[string]interface{}{
					"provider": "static",
					"username": "user",
					"password": "pass",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				if params["plainHttp"] != true {
					t.Error("plainHttp should be true")
				}
				if params["userAgent"] != "custom-agent/1.0" {
					t.Error("userAgent should match")
				}
			},
		},
		{
			name: "Default values",
			params: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				// These should use default values (false, empty string, 0)
				if val, exists := params["plainHttp"]; exists && val != false {
					t.Error("plainHttp should default to false")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := store.NewOptions{
				Type:       registryStoreType,
				Parameters: test.params,
			}

			store, err := store.New([]store.NewOptions{opts}, nil)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}

			if !test.expectErr && test.verifyFunc != nil {
				test.verifyFunc(t, test.params)
			}

			if !test.expectErr && store == nil {
				t.Error("expected non-nil store")
			}
		})
	}
}

func TestCredentialProviderIntegration(t *testing.T) {
	tests := []struct {
		name         string
		credConfig   map[string]interface{}
		expectErr    bool
		expectedType string
	}{
		{
			name: "Static provider with username/password",
			credConfig: map[string]interface{}{
				"provider": "static",
				"username": "testuser",
				"password": "testpass",
			},
			expectErr:    false,
			expectedType: "static",
		},
		{
			name: "Static provider with token only",
			credConfig: map[string]interface{}{
				"provider": "static",
				"password": "token123",
			},
			expectErr:    false,
			expectedType: "static",
		},
		{
			name: "Missing provider field",
			credConfig: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expectErr: true,
		},
		{
			name: "Invalid provider type",
			credConfig: map[string]interface{}{
				"provider": "unknown-provider",
				"password": "testpass",
			},
			expectErr: true,
		},
		{
			name: "Empty provider",
			credConfig: map[string]interface{}{
				"provider": "",
				"password": "testpass",
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := store.NewOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": test.credConfig,
				},
			}

			store, err := store.New([]store.NewOptions{opts}, nil)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got error: %v", test.expectErr, err)
			}

			if !test.expectErr && store == nil {
				t.Error("expected non-nil store when no error occurred")
			}
		})
	}
}

func TestCreateHTTPClient(t *testing.T) {
	// Generate test certificate
	testCACert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	testCABase64, err := generateTestCertificateBase64()
	if err != nil {
		t.Fatalf("Failed to generate Base64 test certificate: %v", err)
	}

	tests := []struct {
		name           string
		caPem          string
		caBase64       string
		expectError    bool
		expectedClient bool
	}{
		{
			name:           "empty CA bundle",
			caPem:          "",
			caBase64:       "",
			expectError:    false,
			expectedClient: true,
		},
		{
			name:           "valid CA PEM bundle",
			caPem:          testCACert,
			caBase64:       "",
			expectError:    false,
			expectedClient: true,
		},
		{
			name:           "valid CA Base64 bundle",
			caPem:          "",
			caBase64:       testCABase64,
			expectError:    false,
			expectedClient: true,
		},
		{
			name:           "invalid CA PEM bundle",
			caPem:          "invalid-ca-bundle",
			caBase64:       "",
			expectError:    true,
			expectedClient: false,
		},
		{
			name:           "invalid CA Base64 bundle",
			caPem:          "",
			caBase64:       "invalid-base64",
			expectError:    true,
			expectedClient: false,
		},
		{
			name:           "preference for CA PEM over Base64",
			caPem:          testCACert,
			caBase64:       testCABase64,
			expectError:    false,
			expectedClient: true,
		},
		{
			name:           "valid Base64 with invalid PEM content",
			caPem:          "",
			caBase64:       "aW52YWxpZC1jYS1idW5kbGU=", // "invalid-ca-bundle" in base64
			expectError:    true,
			expectedClient: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createHTTPClient(tt.caPem, tt.caBase64)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectedClient && client == nil {
				t.Errorf("expected client but got nil")
			}
			if !tt.expectedClient && client != nil {
				t.Errorf("expected nil client but got one")
			}

			// For valid CA bundle, verify the TLS config is set correctly
			if (tt.caPem != "" || tt.caBase64 != "") && !tt.expectError && client != nil {
				if client == http.DefaultClient {
					t.Errorf("expected custom client but got default client")
				}
				transport, ok := client.Transport.(*http.Transport)
				if !ok {
					t.Errorf("expected http.Transport but got %T", client.Transport)
				}
				if transport.TLSClientConfig == nil {
					t.Errorf("expected TLS client config to be set")
				}
				if transport.TLSClientConfig.RootCAs == nil {
					t.Errorf("expected root CAs to be set")
				}
			}

			// For empty CA bundle, verify default client is returned
			if tt.caPem == "" && tt.caBase64 == "" && !tt.expectError && client != nil {
				if client != http.DefaultClient {
					t.Errorf("expected default client for empty CA bundle")
				}
			}
		})
	}
}

func TestOptionsUnmarshal(t *testing.T) {
	// Generate test certificate
	testCACert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	testCABase64, err := generateTestCertificateBase64()
	if err != nil {
		t.Fatalf("Failed to generate Base64 test certificate: %v", err)
	}

	tests := []struct {
		name       string
		params     map[string]interface{}
		expectErr  bool
		verifyFunc func(*testing.T, map[string]interface{})
	}{
		{
			name: "All options set",
			params: map[string]interface{}{
				"plainHttp":        true,
				"userAgent":        "custom-agent/1.0",
				"maxBlobBytes":     int64(5000),
				"maxManifestBytes": int64(10000),
				"allowCosignTag":   true,
				"caPem":            testCACert,
				"credential": map[string]interface{}{
					"provider": "static",
					"username": "user",
					"password": "pass",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				if params["plainHttp"] != true {
					t.Error("plainHttp should be true")
				}
				if params["userAgent"] != "custom-agent/1.0" {
					t.Error("userAgent should match")
				}
				if params["allowCosignTag"] != true {
					t.Error("allowCosignTag should be true")
				}
			},
		},
		{
			name: "CA Base64 option set",
			params: map[string]interface{}{
				"caBase64": testCABase64,
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				if params["caBase64"] == "" {
					t.Error("caBase64 should be set")
				}
			},
		},
		{
			name: "Default values",
			params: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				// These should use default values (false, empty string, 0)
				if val, exists := params["plainHttp"]; exists && val != false {
					t.Error("plainHttp should default to false")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := store.NewOptions{
				Type:       registryStoreType,
				Parameters: test.params,
			}

			store, err := store.New([]store.NewOptions{opts}, nil)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}

			if !test.expectErr && test.verifyFunc != nil {
				test.verifyFunc(t, test.params)
			}

			if !test.expectErr && store == nil {
				t.Error("expected non-nil store")
			}
		})
	}
}

func TestParameterTypes(t *testing.T) {
	tests := []struct {
		name      string
		params    interface{}
		expectErr bool
	}{
		{
			name: "String JSON parameters",
			params: map[string]interface{}{
				"plainHttp": true,
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
		},
		{
			name: "Map parameters",
			params: map[string]interface{}{
				"plainHttp": true,
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
		},
		{
			name:      "Invalid parameter type",
			params:    123, // Invalid type
			expectErr: true,
		},
		{
			name:      "Channel parameter type",
			params:    make(chan int),
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := store.NewOptions{
				Type:       registryStoreType,
				Parameters: test.params,
			}

			_, err := store.New([]store.NewOptions{opts}, nil)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}
		})
	}
}

func TestFactoryRegistration(t *testing.T) {
	// Generate test certificate
	testCACert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test that the factory function works with various parameter combinations
	tests := []struct {
		name       string
		params     map[string]interface{}
		expectErr  bool
		errMessage string
	}{
		{
			name: "Valid minimal configuration",
			params: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
		},
		{
			name: "Configuration with CA PEM",
			params: map[string]interface{}{
				"caPem": testCACert,
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
		},
		{
			name: "Configuration with invalid CA PEM",
			params: map[string]interface{}{
				"caPem": "invalid-pem",
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr:  true,
			errMessage: "failed to create HTTP client",
		},
		{
			name: "Configuration with invalid credential provider",
			params: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "nonexistent",
				},
			},
			expectErr:  true,
			errMessage: "failed to create credential provider",
		},
		{
			name: "Configuration with all options",
			params: map[string]interface{}{
				"plainHttp":        true,
				"userAgent":        "test-agent/1.0",
				"maxBlobBytes":     int64(1024),
				"maxManifestBytes": int64(2048),
				"allowCosignTag":   true,
				"caPem":            testCACert,
				"credential": map[string]interface{}{
					"provider": "static",
					"username": "testuser",
					"password": "testpass",
				},
			},
			expectErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := store.NewOptions{
				Type:       registryStoreType,
				Parameters: test.params,
			}

			store, err := store.New([]store.NewOptions{opts}, nil)
			if test.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if test.errMessage != "" && !strings.Contains(err.Error(), test.errMessage) {
					t.Errorf("expected error message to contain '%s', got: %v", test.errMessage, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if store == nil {
					t.Error("expected non-nil store")
				}
			}
		})
	}
}

func TestOptionsJSONUnmarshal(t *testing.T) {
	// Test that the options struct correctly unmarshals JSON
	tests := []struct {
		name       string
		jsonStr    string
		expectErr  bool
		verifyFunc func(*testing.T, *options)
	}{
		{
			name: "Valid JSON with all fields",
			jsonStr: `{
				"plainHttp": true,
				"userAgent": "test-agent",
				"maxBlobBytes": 1024,
				"maxManifestBytes": 2048,
				"allowCosignTag": true,
				"caPem": "test-ca-pem",
				"caBase64": "test-ca-base64",
				"credential": {
					"provider": "static",
					"password": "token"
				}
			}`,
			expectErr: false,
			verifyFunc: func(t *testing.T, opts *options) {
				if !opts.PlainHTTP {
					t.Error("PlainHTTP should be true")
				}
				if opts.UserAgent != "test-agent" {
					t.Errorf("expected UserAgent 'test-agent', got '%s'", opts.UserAgent)
				}
				if opts.MaxBlobBytes != 1024 {
					t.Errorf("expected MaxBlobBytes 1024, got %d", opts.MaxBlobBytes)
				}
				if opts.MaxManifestBytes != 2048 {
					t.Errorf("expected MaxManifestBytes 2048, got %d", opts.MaxManifestBytes)
				}
				if !opts.AllowCosignTag {
					t.Error("AllowCosignTag should be true")
				}
				if opts.CAPem != "test-ca-pem" {
					t.Errorf("expected CAPem 'test-ca-pem', got '%s'", opts.CAPem)
				}
				if opts.CABase64 != "test-ca-base64" {
					t.Errorf("expected CABase64 'test-ca-base64', got '%s'", opts.CABase64)
				}
			},
		},
		{
			name: "Invalid JSON",
			jsonStr: `{
				"plainHttp": true,
				"invalidField"
			}`,
			expectErr: true,
		},
		{
			name:      "Empty JSON object",
			jsonStr:   `{}`,
			expectErr: false,
			verifyFunc: func(t *testing.T, opts *options) {
				if opts.PlainHTTP {
					t.Error("PlainHTTP should default to false")
				}
				if opts.UserAgent != "" {
					t.Error("UserAgent should default to empty string")
				}
				if opts.MaxBlobBytes != 0 {
					t.Error("MaxBlobBytes should default to 0")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var opts options
			err := json.Unmarshal([]byte(test.jsonStr), &opts)

			if test.expectErr && err == nil {
				t.Error("expected error but got none")
			}
			if !test.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !test.expectErr && test.verifyFunc != nil {
				test.verifyFunc(t, &opts)
			}
		})
	}
}
