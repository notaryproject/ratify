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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"

	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

const testName = "notation-test"
const mockKeyProviderName = "mock-key-provider"

type mockKeyProvider struct {
	returnErr bool
}

func (m *mockKeyProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	if m.returnErr {
		return nil, fmt.Errorf("mock error")
	}
	return []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName: "test-cert",
			},
		}}, nil
}

func (m *mockKeyProvider) GetKeys(_ context.Context) ([]*keyprovider.PublicKey, error) {
	return nil, nil
}

func createMockKeyProvider(options any) (keyprovider.KeyProvider, error) {
	if options == nil {
		return &mockKeyProvider{}, nil
	}
	val, ok := options.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid options type")
	}
	_, ok = val["returnErr"]
	return &mockKeyProvider{
		returnErr: ok,
	}, nil
}

func TestNewVerifier(t *testing.T) {
	// Register the mock key provider
	keyprovider.RegisterKeyProvider(mockKeyProviderName, createMockKeyProvider)

	tests := []struct {
		name      string
		opts      verifier.NewOptions
		expectErr bool
	}{
		{
			name: "Unsupported params",
			opts: verifier.NewOptions{
				Type:       verifierTypeNotation,
				Name:       testName,
				Parameters: make(chan int),
			},
			expectErr: true,
		},
		{
			name: "Malformed params",
			opts: verifier.NewOptions{
				Type:       verifierTypeNotation,
				Name:       testName,
				Parameters: "{",
			},
			expectErr: true,
		},
		{
			name: "Missing trust store options",
			opts: verifier.NewOptions{
				Type:       verifierTypeNotation,
				Name:       testName,
				Parameters: options{},
			},
			expectErr: true,
		},
		{
			name: "Invalid trust store type",
			opts: verifier.NewOptions{
				Type: verifierTypeNotation,
				Name: testName,
				Parameters: options{
					Certificates: []trustStoreOptions{
						{
							"type": "invalid",
						},
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Duplicate trust store type",
			opts: verifier.NewOptions{
				Type: verifierTypeNotation,
				Name: testName,
				Parameters: options{
					Certificates: []trustStoreOptions{
						{
							"type":              "ca",
							mockKeyProviderName: nil,
						},
						{
							"type":              "ca",
							mockKeyProviderName: nil,
						},
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Non-registered key provider",
			opts: verifier.NewOptions{
				Type: verifierTypeNotation,
				Name: testName,
				Parameters: options{
					Certificates: []trustStoreOptions{
						{
							"type":           "ca",
							"non-registered": nil,
						},
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Key provider that would fail on GetCertificates (lazy loading)",
			opts: verifier.NewOptions{
				Type: verifierTypeNotation,
				Name: testName,
				Parameters: options{
					Certificates: []trustStoreOptions{
						{
							"type": "ca",
							mockKeyProviderName: map[string]any{
								"returnErr": true,
							},
						},
					},
				},
			},
			expectErr: false, // Should not fail during initialization with lazy loading
		},
		{
			name: "Valid notation options",
			opts: verifier.NewOptions{
				Type: verifierTypeNotation,
				Name: testName,
				Parameters: options{
					Certificates: []trustStoreOptions{
						{
							"type":              "ca",
							mockKeyProviderName: nil,
						},
					},
				},
			},
			expectErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.New(test.opts, nil)
			if test.expectErr != (err != nil) {
				t.Fatalf("Expected error: %v, got: %v", test.expectErr, err)
			}
		})
	}
}

func TestGetTrustStoreType(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		expected  truststore.Type
		expectErr bool
		errorMsg  string
	}{
		{
			name:      "Valid CA type",
			input:     "ca",
			expected:  truststore.TypeCA,
			expectErr: false,
		},
		{
			name:      "Valid TSA type",
			input:     "tsa",
			expected:  truststore.TypeTSA,
			expectErr: false,
		},
		{
			name:      "Valid SigningAuthority type",
			input:     "signingAuthority",
			expected:  truststore.TypeSigningAuthority,
			expectErr: false,
		},
		{
			name:      "Invalid string type",
			input:     "invalid",
			expected:  "",
			expectErr: true,
			errorMsg:  "invalid trust store type invalid",
		},
		{
			name:      "Non-string type - integer",
			input:     123,
			expected:  "",
			expectErr: true,
			errorMsg:  "trust store type must be a string",
		},
		{
			name:      "Non-string type - boolean",
			input:     true,
			expected:  "",
			expectErr: true,
			errorMsg:  "trust store type must be a string",
		},
		{
			name:      "Non-string type - nil",
			input:     nil,
			expected:  "",
			expectErr: true,
			errorMsg:  "trust store type must be a string",
		},
		{
			name:      "Non-string type - slice",
			input:     []string{"ca"},
			expected:  "",
			expectErr: true,
			errorMsg:  "trust store type must be a string",
		},
		{
			name:      "Non-string type - map",
			input:     map[string]string{"type": "ca"},
			expected:  "",
			expectErr: true,
			errorMsg:  "trust store type must be a string",
		},
		{
			name:      "Empty string",
			input:     "",
			expected:  "",
			expectErr: true,
			errorMsg:  "invalid trust store type ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := getTrustStoreType(test.input)

			if test.expectErr {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if err.Error() != test.errorMsg {
					t.Fatalf("Expected error message '%s', got '%s'", test.errorMsg, err.Error())
				}
				if result != test.expected {
					t.Fatalf("Expected result '%s', got '%s'", test.expected, result)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if result != test.expected {
					t.Fatalf("Expected result '%s', got '%s'", test.expected, result)
				}
			}
		})
	}
}
