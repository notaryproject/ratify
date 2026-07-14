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
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

type mockTrustPolicy struct {
	name                string
	scopes              []string
	keysMap             map[PKKey]keymanagementprovider.PublicKey
	shouldErrKeys       bool
	shouldErrCosignOpts bool
}

func (m *mockTrustPolicy) GetName() string {
	return m.name
}

func (m *mockTrustPolicy) GetScopes() []string {
	return m.scopes
}

func (m *mockTrustPolicy) GetKeys(_ context.Context, _ string) (map[PKKey]keymanagementprovider.PublicKey, error) {
	if m.shouldErrKeys {
		return nil, fmt.Errorf("error getting keys")
	}
	return m.keysMap, nil
}

func (m *mockTrustPolicy) GetCosignOpts(_ context.Context) (cosign.CheckOpts, error) {
	if m.shouldErrCosignOpts {
		return cosign.CheckOpts{}, fmt.Errorf("error getting cosign opts")
	}

	return cosign.CheckOpts{}, nil
}

func TestCreateTrustPolicy(t *testing.T) {
	tc := []struct {
		name    string
		cfg     TrustPolicyConfig
		wantErr bool
	}{
		{
			name:    "invalid config",
			cfg:     TrustPolicyConfig{},
			wantErr: true,
		},
		{
			name: "invalid local key path",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keys: []KeyConfig{
					{
						File: "invalid",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid local key path",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keys: []KeyConfig{
					{
						File: "../../../test/testdata/cosign.pub",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid keyless config with rekor specified",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keyless: KeylessConfig{
					CertificateIdentity:   "test-identity",
					CertificateOIDCIssuer: "https://test-issuer.com",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid config version",
			cfg: TrustPolicyConfig{
				Version: "0.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{
					CertificateIdentity:   "test-identity",
					CertificateOIDCIssuer: "https://test-issuer.com",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateTrustPolicy(tt.cfg, "test-verifier")
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestGetName tests the GetName function for Trust Policy
func TestGetName(t *testing.T) {
	trustPolicyConfig := TrustPolicyConfig{
		Name:    "test",
		Scopes:  []string{"*"},
		Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
	}
	trustPolicy, err := CreateTrustPolicy(trustPolicyConfig, "test-verifier")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if trustPolicy.GetName() != trustPolicyConfig.Name {
		t.Fatalf("expected %s, got %s", trustPolicyConfig.Name, trustPolicy.GetName())
	}
}

// TestGetScopes tests the GetScopes function for Trust Policy
func TestGetScopes(t *testing.T) {
	trustPolicyConfig := TrustPolicyConfig{
		Name:    "test",
		Scopes:  []string{"*"},
		Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
	}
	trustPolicy, err := CreateTrustPolicy(trustPolicyConfig, "test-verifier")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(trustPolicy.GetScopes()) != len(trustPolicyConfig.Scopes) {
		t.Fatalf("expected %v, got %v", trustPolicyConfig.Scopes, trustPolicy.GetScopes())
	}
	if trustPolicy.GetScopes()[0] != trustPolicyConfig.Scopes[0] {
		t.Fatalf("expected %s, got %s", trustPolicyConfig.Scopes[0], trustPolicy.GetScopes()[0])
	}
}

// TestGetKeys tests the GetKeys function for Trust Policy
func TestGetKeys(t *testing.T) {
	inputMap := map[keymanagementprovider.KMPMapKey]crypto.PublicKey{
		{Name: "key1"}: &ecdsa.PublicKey{},
	}
	keymanagementprovider.SaveSecrets("ns/kmp", "", inputMap, map[keymanagementprovider.KMPMapKey][]*x509.Certificate{})
	tc := []struct {
		name    string
		cfg     TrustPolicyConfig
		wantErr bool
	}{
		{
			name: "only local keys",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keys: []KeyConfig{
					{
						File: "../../../test/testdata/cosign.pub",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "nonexistent KMP",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "nonexistent",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "access nonexistent key from KMP",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "ns/kmp",
						Name:     "nonexistent",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid KMP",
			cfg: TrustPolicyConfig{
				Name:   "test",
				Scopes: []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "ns/kmp",
						Name:     "key1",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			trustPolicy, err := CreateTrustPolicy(tt.cfg, "test-verifier")
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			ctx := ctxUtils.SetContextWithNamespace(context.Background(), "ns")
			keys, err := trustPolicy.GetKeys(ctx, "")
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
			if err == nil && len(keys) != len(tt.cfg.Keys) {
				t.Fatalf("expected %v, got %v", tt.cfg.Keys, keys)
			}
		})
	}
}

// TestValidate tests the validate function
func TestValidate(t *testing.T) {
	tc := []struct {
		name         string
		policyConfig TrustPolicyConfig
		wantErr      bool
	}{
		{
			name:         "no version",
			policyConfig: TrustPolicyConfig{},
			wantErr:      true,
		},
		{
			name: "no name",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
			},
			wantErr: true,
		},
		{
			name: "no scopes",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
			},
			wantErr: true,
		},
		{
			name: "no keys or keyless defined",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "keys and keyless defined",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "kmp",
					},
				},
				Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
			},
			wantErr: true,
		},
		{
			name: "key provider and key path not defined",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keys:    []KeyConfig{{}},
			},
			wantErr: true,
		},
		{
			name: "key provider and key path both defined",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "kmp",
						File:     "path",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "key provider not defined but name defined",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keys: []KeyConfig{
					{
						Name: "key name",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "key provider name not defined but version defined",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "kmp",
						Version:  "key version",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keys: []KeyConfig{
					{
						Provider: "kmp",
						Name:     "key name",
						Version:  "key version",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "keyless but no certificate identity specified",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{CertificateOIDCIssuer: "test"},
			},
			wantErr: true,
		},
		{
			name: "keyless but both certificate identity and expression specified",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{CertificateIdentity: "test", CertificateIdentityRegExp: "test"},
			},
			wantErr: true,
		},
		{
			name: "keyless but no certificate oidc issuer specified",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{CertificateIdentity: "test"},
			},
			wantErr: true,
		},
		{
			name: "keyless but both certificate oidc issuer and expression specified",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{CertificateIdentity: "test", CertificateOIDCIssuer: "test", CertificateOIDCIssuerRegExp: "test"},
			},
			wantErr: true,
		},
		{
			name: "keyless but both certificate identity and expression specified",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{CertificateOIDCIssuer: "test", CertificateIdentity: "test", CertificateIdentityRegExp: "test"},
			},
			wantErr: true,
		},
		{
			name: "valid keyless",
			policyConfig: TrustPolicyConfig{
				Version: "1.0.0",
				Name:    "test",
				Scopes:  []string{"*"},
				Keyless: KeylessConfig{CertificateIdentity: "test", CertificateOIDCIssuer: "test"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			actual := validate(tt.policyConfig)
			if (actual != nil) != tt.wantErr {
				t.Fatalf("expected %v, got %v", tt.wantErr, actual)
			}
		})
	}
}

// TestLoadKeyFromPath tests the loadKeyFromPath function
func TestLoadKeyFromPath(t *testing.T) {
	cosignValidPath := "../../../test/testdata/cosign.pub"
	key, err := loadKeyFromPath(cosignValidPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key == nil {
		t.Fatalf("expected key, got nil")
	}
	switch keyType := key.(type) {
	case *ecdsa.PublicKey:
	default:
		t.Fatalf("expected ecdsa.PublicKey, got %v", keyType)
	}
}

func TestGetCosignOpts(t *testing.T) {
	testCases := []struct {
		name           string
		tlogVerify     bool
		rekorURL       string
		rekorPubKeyEnv string
		isKeyless      bool
		CTLogVerify    bool
		CTLogPubKeyEnv string
		expectedErr    bool
	}{
		{
			name:        "invalid rekor url",
			tlogVerify:  true,
			rekorURL:    string([]byte{0x7f}),
			expectedErr: true,
		},
		{
			name:           "failed to get rekor public key",
			tlogVerify:     true,
			rekorURL:       "https://rekor.sigstore.dev",
			rekorPubKeyEnv: "invalid",
			expectedErr:    true,
		},
		{
			name:           "failed to get CT log public key",
			tlogVerify:     false,
			isKeyless:      true,
			CTLogVerify:    true,
			CTLogPubKeyEnv: "invalid",
			expectedErr:    true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.rekorPubKeyEnv != "" {
				val := os.Getenv("SIGSTORE_REKOR_PUBLIC_KEY")
				os.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", tc.rekorPubKeyEnv)
				t.Cleanup(func() {
					os.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", val)
				})
			}

			if tc.CTLogPubKeyEnv != "" {
				val := os.Getenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE")
				os.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", tc.CTLogPubKeyEnv)
				t.Cleanup(func() {
					os.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", val)
				})
			}

			tp := trustPolicy{
				config: TrustPolicyConfig{
					TLogVerify: &tc.tlogVerify,
					RekorURL:   tc.rekorURL,
					Keyless: KeylessConfig{
						CTLogVerify: &tc.CTLogVerify,
					},
				},
				isKeyless: tc.isKeyless,
			}
			_, err := tp.GetCosignOpts(context.Background())
			if tc.expectedErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			}
		})
	}
}
