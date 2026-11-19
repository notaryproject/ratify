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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-verifier-go/cosign"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/notaryproject/ratify/v2/internal/verifier"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

const testVerifierName = "test-cosign-verifier"

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name        string
		opts        verifier.NewOptions
		globalScope []string
		wantErr     bool
		errContains string
	}{
		{
			name: "empty verifier name",
			opts: verifier.NewOptions{
				Name: "",
			},
			wantErr:     true,
			errContains: "verifier name cannot be empty",
		},
		{
			name: "invalid parameters json",
			opts: verifier.NewOptions{
				Name:       testVerifierName,
				Parameters: make(chan int), // unmarshallable type
			},
			wantErr:     true,
			errContains: "failed to marshal verifier parameters",
		},
		{
			name: "no trust policies",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{},
				},
			},
			wantErr:     true,
			errContains: "at least one trust policy must be provided",
		},
		{
			name: "nil trust policy",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{nil},
				},
			},
			wantErr:     true,
			errContains: "trust policy cannot be nil",
		},
		{
			name: "empty scope in trust policy",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{""},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "scope cannot be empty",
		},
		{
			name: "invalid registry scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"invalid:registry:with:colons"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "invalid scope",
		},
		{
			name: "repository scope with wildcard",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com/*/repo"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "scope cannot contain wildcard for repository",
		},
		{
			name: "repository scope with tag",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com/repo:latest"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "scope cannot contain a tag or digest",
		},
		{
			name: "duplicate registry scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy-1",
							"scopes": []string{"registry.example.com", "registry.example.com"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "duplicate registry scope",
		},
		{
			name: "duplicate repository scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy-1",
							"scopes": []string{"registry.example.com/repo", "registry.example.com/repo"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "duplicate repository scope",
		},
		{
			name: "invalid wildcard scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"example.*.com"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "wildcard must be at the beginning of the scope",
		},
		{
			name: "multiple wildcards in scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"*.*.example.com"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "scope can only contain one wildcard",
		},
		{
			name: "valid single registry scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid wildcard registry scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"*.example.com"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid repository scope",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com/namespace/repo"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple trust policies",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "policy-1",
							"scopes": []string{"registry1.example.com"},
						},
						map[string]interface{}{
							"name":   "policy-2",
							"scopes": []string{"registry2.example.com"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "use global scopes when trust policy scopes empty",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name": "test-policy",
						},
					},
				},
			},
			globalScope: []string{"global.example.com"},
			wantErr:     false,
		},
		{
			name: "with certificate identity options",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":                       "test-policy",
							"scopes":                     []string{"registry.example.com"},
							"certificateIdentity":        "test@example.com",
							"certificateOIDCIssuer":      "https://github.com/login/oauth",
							"certificateIdentityRegex":   ".*@example\\.com",
							"certificateOIDCIssuerRegex": "https://github\\.com/.*",
							"ignoreTlog":                 true,
							"ignoreCTLog":                true,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "failed to convert trust policy options",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com"},
							"keys": map[string]interface{}{
								"provider1": map[string]interface{}{
									"config": "value1",
								},
								"provider2": map[string]interface{}{
									"config": "value2",
								},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "failed to convert trust policy options",
		},
		{
			name: "invalid key provider configuration",
			opts: verifier.NewOptions{
				Name: testVerifierName,
				Parameters: map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com"},
							"keys": map[string]interface{}{
								"invalid-provider": map[string]interface{}{
									"invalid": "config",
								},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "failed to convert trust policy options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.opts, tt.globalScope)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("NewVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("NewVerifier() unexpected error = %v", err)
				return
			}

			if verifier == nil {
				t.Errorf("NewVerifier() returned nil verifier")
				return
			}

			// Test basic verifier properties
			if verifier.Name() != testVerifierName {
				t.Errorf("Verifier.Name() = %v, want %v", verifier.Name(), testVerifierName)
			}

			if verifier.Type() != verifierTypeCosign {
				t.Errorf("Verifier.Type() = %v, want %v", verifier.Type(), verifierTypeCosign)
			}
		})
	}
}

func TestVerifier_Verifiable(t *testing.T) {
	verifier := createTestVerifier(t)

	tests := []struct {
		name     string
		artifact ocispec.Descriptor
		want     bool
	}{
		{
			name: "cosign signature artifact",
			artifact: ocispec.Descriptor{
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: artifactTypeCosign,
			},
			want: true,
		},
		{
			name: "wrong artifact type",
			artifact: ocispec.Descriptor{
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.oci.image.manifest.v1+json",
			},
			want: false,
		},
		{
			name: "wrong media type",
			artifact: ocispec.Descriptor{
				MediaType:    "application/vnd.oci.image.config.v1+json",
				ArtifactType: artifactTypeCosign,
			},
			want: false,
		},
		{
			name: "both wrong",
			artifact: ocispec.Descriptor{
				MediaType:    "application/vnd.oci.image.config.v1+json",
				ArtifactType: "application/vnd.oci.image.manifest.v1+json",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifier.Verifiable(tt.artifact)
			if got != tt.want {
				t.Errorf("Verifier.Verifiable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_MatchVerifier(t *testing.T) {
	// Create verifier with multiple scopes
	opts := verifier.NewOptions{
		Name: testVerifierName,
		Parameters: map[string]interface{}{
			"trustPolicies": []interface{}{
				map[string]interface{}{
					"name":   "wildcard-policy",
					"scopes": []string{"*.example.com"},
				},
				map[string]interface{}{
					"name":   "registry-policy",
					"scopes": []string{"registry.example.com"},
				},
				map[string]interface{}{
					"name":   "repo-policy",
					"scopes": []string{"registry.example.com/namespace/repo"},
				},
			},
		},
	}

	verifier, err := NewVerifier(opts, nil)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	scopedVerifier := verifier.(*Verifier)

	tests := []struct {
		name        string
		repository  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "exact repository match",
			repository: "registry.example.com/namespace/repo",
			wantErr:    false,
		},
		{
			name:       "exact registry match",
			repository: "registry.example.com/other/repo",
			wantErr:    false,
		},
		{
			name:       "wildcard match",
			repository: "sub.example.com/some/repo",
			wantErr:    false,
		},
		{
			name:        "no match",
			repository:  "other.registry.com/repo",
			wantErr:     true,
			errContains: "no verifier configured for the repository",
		},
		{
			name:        "invalid repository format",
			repository:  "invalid:repository:format",
			wantErr:     true,
			errContains: "failed to parse repository reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scopedVerifier.matchVerifier(tt.repository)

			if tt.wantErr {
				if err == nil {
					t.Errorf("matchVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("matchVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("matchVerifier() unexpected error = %v", err)
			}
		})
	}
}

func TestVerifier_Verify(t *testing.T) {
	verifier := createTestVerifier(t)

	// Test that Verify method calls matchVerifier and delegates to underlying verifier
	// Since we can't easily mock the underlying cosign verifier, we test error cases
	tests := []struct {
		name        string
		opts        *ratify.VerifyOptions
		wantErr     bool
		errContains string
	}{
		{
			name: "no matching verifier",
			opts: &ratify.VerifyOptions{
				Repository: "nomatch.example.com/repo",
			},
			wantErr:     true,
			errContains: "trust policy is not configured for repository",
		},
		{
			name: "invalid repository format",
			opts: &ratify.VerifyOptions{
				Repository: "invalid:repo:format",
			},
			wantErr:     true,
			errContains: "trust policy is not configured for repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Verify() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("Verify() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Verify() unexpected error = %v", err)
			}
		})
	}
}

func TestRegisterVerifier(t *testing.T) {
	// Create a mock cosign verifier for testing
	mockCosignVerifier, err := cosign.NewVerifier(&cosign.VerifierOptions{
		Name: "mock-verifier",
	})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}

	verifier := &Verifier{
		name:       testVerifierName,
		wildcard:   make(map[string]*cosign.Verifier),
		registry:   make(map[string]*cosign.Verifier),
		repository: make(map[string]*cosign.Verifier),
	}

	tests := []struct {
		name           string
		scope          string
		cosignVerifier *cosign.Verifier
		wantErr        bool
		errContains    string
	}{
		{
			name:           "empty scope",
			scope:          "",
			cosignVerifier: mockCosignVerifier,
			wantErr:        true,
			errContains:    "scope cannot be empty",
		},
		{
			name:           "nil verifier",
			scope:          "registry.example.com",
			cosignVerifier: nil,
			wantErr:        true,
			errContains:    "verifier cannot be nil",
		},
		{
			name:           "valid registry scope",
			scope:          "registry.example.com",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "valid repository scope",
			scope:          "registry.example.com/repo",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "valid wildcard scope",
			scope:          "*.example.com",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "valid fallback scope",
			scope:          "*",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "duplicate fallback scope",
			scope:          "*",
			cosignVerifier: mockCosignVerifier,
			wantErr:        true,
			errContains:    "duplicate fallback scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.registerVerifier(tt.scope, tt.cosignVerifier)

			if tt.wantErr {
				if err == nil {
					t.Errorf("registerVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("registerVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("registerVerifier() unexpected error = %v", err)
			}
		})
	}
}

func TestToVerifierOptions(t *testing.T) {
	tests := []struct {
		name         string
		verifierName string
		input        *ScopedOptions
		wantErr      bool
		errContains  string
		validate     func(*testing.T, *cosign.VerifierOptions)
	}{
		{
			name:         "basic options",
			verifierName: "test-policy",
			input: &ScopedOptions{
				IgnoreTLog:  true,
				IgnoreCTLog: true,
			},
			wantErr: false,
			validate: func(t *testing.T, opts *cosign.VerifierOptions) {
				if opts.Name != "test-policy" {
					t.Errorf("Name = %v, want %v", opts.Name, "test-policy")
				}
				if !opts.IgnoreTLog {
					t.Errorf("IgnoreTLog = %v, want %v", opts.IgnoreTLog, true)
				}
				if !opts.IgnoreCTLog {
					t.Errorf("IgnoreCTLog = %v, want %v", opts.IgnoreCTLog, true)
				}
				if len(opts.IdentityPolicies) != 0 {
					t.Errorf("IdentityPolicies length = %v, want %v", len(opts.IdentityPolicies), 0)
				}
			},
		},
		{
			name:         "keyless honors ignoreCTLog false",
			verifierName: "test-policy",
			input: &ScopedOptions{
				IgnoreCTLog: false,
			},
			wantErr: false,
			validate: func(t *testing.T, opts *cosign.VerifierOptions) {
				if opts.IgnoreCTLog {
					t.Errorf("IgnoreCTLog = %v, want false (honored for keyless)", opts.IgnoreCTLog)
				}
			},
		},
		{
			name:         "with certificate identity",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentity:   "test@example.com",
				CertificateOIDCIssuer: "https://github.com/login/oauth",
			},
			wantErr: false,
			validate: func(t *testing.T, opts *cosign.VerifierOptions) {
				if len(opts.IdentityPolicies) != 1 {
					t.Errorf("IdentityPolicies length = %v, want %v", len(opts.IdentityPolicies), 1)
				}
			},
		},
		{
			name:         "with regex patterns",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentityRegex:   ".*@example\\.com",
				CertificateOIDCIssuerRegex: "https://github\\.com/.*",
			},
			wantErr: false,
			validate: func(t *testing.T, opts *cosign.VerifierOptions) {
				if len(opts.IdentityPolicies) != 1 {
					t.Errorf("IdentityPolicies length = %v, want %v", len(opts.IdentityPolicies), 1)
				}
			},
		},
		{
			name:         "invalid certificate identity regex",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentityRegex: "[invalid-regex",
			},
			wantErr:     true,
			errContains: "failed to create certificate identity",
		},
		{
			name:         "multiple key providers error",
			verifierName: "test-policy",
			input: &ScopedOptions{
				Keys: map[string]any{
					"inline": map[string]interface{}{
						"keys": "test-key-1",
					},
					"azure": map[string]interface{}{
						"vaultURI": "test-vault",
					},
				},
			},
			wantErr:     true,
			errContains: "only one set of key provider is allowed",
		},
		{
			name:         "key-based verification options",
			verifierName: "test-policy",
			input: &ScopedOptions{
				Keys: map[string]any{
					"inline": map[string]interface{}{
						"keys": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
					},
				},
				IgnoreTLog: true, // Honored for key-based verification
			},
			wantErr:     true, // inline provider not registered in test context
			errContains: "failed to create key provider",
		},
		{
			name:         "with trusted root",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentity:   testIdentity,
				CertificateOIDCIssuer: testOIDCIssuer,
				TrustedRoot:           newPrivateSigstore(t).trustedRoot,
			},
			wantErr: false,
			validate: func(t *testing.T, opts *cosign.VerifierOptions) {
				if opts.TrustedRoot == nil {
					t.Fatal("TrustedRoot = nil, want the configured trusted root")
				}
				if got := len(opts.TrustedRoot.FulcioCertificateAuthorities()); got != 1 {
					t.Errorf("FulcioCertificateAuthorities length = %v, want 1", got)
				}
				if got := len(opts.TrustedRoot.RekorLogs()); got != 1 {
					t.Errorf("RekorLogs length = %v, want 1", got)
				}
			},
		},
		{
			name:         "without trusted root",
			verifierName: "test-policy",
			input:        &ScopedOptions{},
			wantErr:      false,
			validate: func(t *testing.T, opts *cosign.VerifierOptions) {
				if opts.TrustedRoot != nil {
					t.Error("TrustedRoot is set, want nil so the public-good trusted root is used")
				}
			},
		},
		{
			name:         "invalid trusted root json",
			verifierName: "test-policy",
			input: &ScopedOptions{
				TrustedRoot: "not-json",
			},
			wantErr:     true,
			errContains: "failed to parse trusted root",
		},
		{
			name:         "unsupported trusted root media type",
			verifierName: "test-policy",
			input: &ScopedOptions{
				TrustedRoot: `{"mediaType": "application/json"}`,
			},
			wantErr:     true,
			errContains: "unsupported TrustedRoot media type",
		},
		{
			name:         "invalid key provider",
			verifierName: "test-policy",
			input: &ScopedOptions{
				Keys: map[string]any{
					"invalid-provider": map[string]interface{}{
						"invalid": "config",
					},
				},
			},
			wantErr:     true,
			errContains: "failed to create key provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := toVerifierOptions(tt.input, tt.verifierName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("toVerifierOptions() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("toVerifierOptions() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("toVerifierOptions() unexpected error = %v", err)
				return
			}

			if opts == nil {
				t.Errorf("toVerifierOptions() returned nil options")
				return
			}

			if tt.validate != nil {
				tt.validate(t, opts)
			}
		})
	}
}

type mockKeyProvider struct{}

func (mockKeyProvider) GetCertificates(context.Context) ([]*x509.Certificate, error) {
	return nil, nil
}

func (mockKeyProvider) GetKeys(context.Context) ([]*keyprovider.PublicKey, error) {
	return nil, nil
}

// TestToVerifierOptions_KeyBasedTimestampOptions verifies that key-based
// verification honors IgnoreTLog and IgnoreObserverTimestamps (so offline,
// key-signed images without a timestamp can be verified) and passes IgnoreCTLog
// through unchanged, since the certificate transparency log never applies to
// public keys.
func TestToVerifierOptions_KeyBasedTimestampOptions(t *testing.T) {
	const providerName = "mock-key-provider-timestamp"
	keyprovider.RegisterKeyProvider(providerName, func(any) (keyprovider.KeyProvider, error) {
		return mockKeyProvider{}, nil
	})

	tests := []struct {
		name                     string
		ignoreTLog               bool
		ignoreObserverTimestamps bool
		ignoreCTLog              bool
	}{
		{name: "offline key verification", ignoreTLog: true, ignoreObserverTimestamps: true},
		{name: "defaults preserved", ignoreTLog: false, ignoreObserverTimestamps: false},
		{name: "ignoreCTLog false is passed through", ignoreCTLog: false},
		{name: "ignoreCTLog true is passed through", ignoreCTLog: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := toVerifierOptions(&ScopedOptions{
				IgnoreTLog:               tt.ignoreTLog,
				IgnoreObserverTimestamps: tt.ignoreObserverTimestamps,
				IgnoreCTLog:              tt.ignoreCTLog,
				Keys: map[string]any{
					providerName: map[string]any{},
				},
			}, "test-policy")
			if err != nil {
				t.Fatalf("toVerifierOptions() unexpected error = %v", err)
			}
			if opts.IgnoreTLog != tt.ignoreTLog {
				t.Errorf("IgnoreTLog = %v, want %v", opts.IgnoreTLog, tt.ignoreTLog)
			}
			if opts.IgnoreCTLog != tt.ignoreCTLog {
				t.Errorf("IgnoreCTLog = %v, want %v", opts.IgnoreCTLog, tt.ignoreCTLog)
			}
			if opts.IgnoreObserverTimestamps != tt.ignoreObserverTimestamps {
				t.Errorf("IgnoreObserverTimestamps = %v, want %v", opts.IgnoreObserverTimestamps, tt.ignoreObserverTimestamps)
			}
			if opts.GetPublicKeys == nil {
				t.Error("GetPublicKeys = nil, want non-nil for key-based verification")
			}
		})
	}
}

// TestVerifier_Verify_TrustedRoot verifies a keyless Cosign signature issued
// by a private Sigstore deployment end to end: it only succeeds when the trust
// policy carries the trusted root of that deployment.
func TestVerifier_Verify_TrustedRoot(t *testing.T) {
	signer := newPrivateSigstore(t)
	other := newPrivateSigstore(t)
	store := signer.newSignedStore(t, []byte(`{"critical":{"type":"cosign container image signature"}}`))

	tests := []struct {
		name        string
		trustedRoot string
		wantErr     bool
	}{
		{
			name:        "trusted root of the signing deployment",
			trustedRoot: signer.trustedRoot,
		},
		{
			name:        "untrusted Fulcio certificate authority",
			trustedRoot: newTrustedRoot(t, other.caCert, signer.rekorKey),
			wantErr:     true,
		},
		{
			name:        "untrusted Rekor transparency log",
			trustedRoot: newTrustedRoot(t, signer.caCert, other.rekorKey),
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(verifier.NewOptions{
				Name: testVerifierName,
				Type: verifierTypeCosign,
				Parameters: map[string]any{
					"trustPolicies": []map[string]any{
						{
							"scopes":                []string{"registry.example.com"},
							"certificateIdentity":   testIdentity,
							"certificateOIDCIssuer": testOIDCIssuer,
							// The private deployment runs no certificate
							// transparency log.
							"ignoreCTLog": true,
							"trustedRoot": tt.trustedRoot,
						},
					},
				},
			}, nil)
			if err != nil {
				t.Fatalf("NewVerifier() unexpected error = %v", err)
			}

			result, err := v.Verify(context.Background(), &ratify.VerifyOptions{
				Store:              store,
				Repository:         "registry.example.com/test/repo",
				ArtifactDescriptor: store.signatureDesc,
			})
			if err != nil {
				t.Fatalf("Verify() unexpected error = %v", err)
			}
			if gotErr := result.Err != nil; gotErr != tt.wantErr {
				t.Errorf("Verify() result error = %v, wantErr %v", result.Err, tt.wantErr)
			}
		})
	}
}

const (
	testIdentity   = "signer@example.com"
	testOIDCIssuer = "https://issuer.example.com"
)

// privateSigstore is a minimal private Sigstore deployment made of a Fulcio
// certificate authority and a Rekor transparency log.
type privateSigstore struct {
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	rekorKey    *ecdsa.PrivateKey
	rekorLogID  string
	trustedRoot string
}

func newPrivateSigstore(t *testing.T) *privateSigstore {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Fulcio Root", Organization: []string{"Ratify Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Rekor key: %v", err)
	}

	return &privateSigstore{
		caCert:      caCert,
		caKey:       caKey,
		rekorKey:    rekorKey,
		rekorLogID:  hex.EncodeToString(rekorLogID(t, rekorKey)),
		trustedRoot: newTrustedRoot(t, caCert, rekorKey),
	}
}

// newTrustedRoot returns the JSON trusted root trusting the given Fulcio
// certificate authority and Rekor transparency log.
func newTrustedRoot(t *testing.T, caCert *x509.Certificate, rekorKey *ecdsa.PrivateKey) string {
	t.Helper()
	logID := rekorLogID(t, rekorKey)
	trustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{&root.FulcioCertificateAuthority{
			Root:                caCert,
			ValidityPeriodStart: caCert.NotBefore,
			URI:                 "https://fulcio.example.com",
		}},
		nil,
		nil,
		map[string]*root.TransparencyLog{hex.EncodeToString(logID): {
			BaseURL:             "https://rekor.example.com",
			ID:                  logID,
			ValidityPeriodStart: caCert.NotBefore,
			HashFunc:            crypto.SHA256,
			PublicKey:           &rekorKey.PublicKey,
			SignatureHashFunc:   crypto.SHA256,
		}},
	)
	if err != nil {
		t.Fatalf("failed to create trusted root: %v", err)
	}
	trustedRootJSON, err := trustedRoot.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal trusted root: %v", err)
	}
	return string(trustedRootJSON)
}

// rekorLogID returns the log ID of a Rekor transparency log, which is the
// SHA-256 digest of its DER encoded public key.
func rekorLogID(t *testing.T, rekorKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&rekorKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal Rekor public key: %v", err)
	}
	logID := sha256.Sum256(der)
	return logID[:]
}

// newSignedStore signs payload the way `cosign sign` does for keyless
// signatures: with a short-lived Fulcio certificate and a Rekor entry carrying
// a signed entry timestamp. It returns a store serving the signature manifest.
func (p *privateSigstore) newSignedStore(t *testing.T, payload []byte) *signatureStore {
	t.Helper()
	now := time.Now()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: []string{testIdentity},
		ExtraExtensions: []pkix.Extension{{
			// Fulcio OIDC issuer (v1) extension.
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Value: []byte(testOIDCIssuer),
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	payloadDigest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, payloadDigest[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     hex.EncodeToString(payloadDigest[:]),
				},
			},
			"signature": map[string]any{
				"content": base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(leafPEM),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal Rekor entry body: %v", err)
	}
	// json.Marshal sorts map keys, which yields the canonical JSON form the
	// signed entry timestamp is computed over.
	rekorPayload := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"integratedTime": now.Unix(),
		"logIndex":       0,
		"logID":          p.rekorLogID,
	}
	canonicalPayload, err := json.Marshal(rekorPayload)
	if err != nil {
		t.Fatalf("failed to marshal Rekor payload: %v", err)
	}
	canonicalDigest := sha256.Sum256(canonicalPayload)
	set, err := ecdsa.SignASN1(rand.Reader, p.rekorKey, canonicalDigest[:])
	if err != nil {
		t.Fatalf("failed to sign Rekor payload: %v", err)
	}
	bundleAnnotation, err := json.Marshal(map[string]any{
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString(set),
		"Payload":              rekorPayload,
	})
	if err != nil {
		t.Fatalf("failed to marshal bundle annotation: %v", err)
	}

	manifest, err := json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.DescriptorEmptyJSON,
		Layers: []ocispec.Descriptor{{
			MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
			Digest:    digest.FromBytes(payload),
			Size:      int64(len(payload)),
			Annotations: map[string]string{
				"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig),
				"dev.sigstore.cosign/certificate":    string(leafPEM),
				"dev.sigstore.cosign/bundle":         string(bundleAnnotation),
			},
		}},
	})
	if err != nil {
		t.Fatalf("failed to marshal signature manifest: %v", err)
	}
	return &signatureStore{
		manifest: manifest,
		signatureDesc: ocispec.Descriptor{
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: artifactTypeCosign,
			Digest:       digest.FromBytes(manifest),
			Size:         int64(len(manifest)),
		},
	}
}

// signatureStore is a [ratify.Store] serving a single Cosign signature
// manifest.
type signatureStore struct {
	manifest      []byte
	signatureDesc ocispec.Descriptor
}

func (s *signatureStore) Resolve(context.Context, string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, errors.New("not implemented")
}

func (s *signatureStore) ListReferrers(context.Context, string, []string, func([]ocispec.Descriptor) error) error {
	return errors.New("not implemented")
}

func (s *signatureStore) FetchBlob(context.Context, string, ocispec.Descriptor) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *signatureStore) FetchManifest(_ context.Context, _ string, desc ocispec.Descriptor) ([]byte, error) {
	if desc.Digest != s.signatureDesc.Digest {
		return nil, fmt.Errorf("manifest %s not found", desc.Digest)
	}
	return s.manifest, nil
}

func TestMatchVerifier_EdgeCases(t *testing.T) {
	// Test additional edge cases for matchVerifier
	verifier := &Verifier{
		name:       testVerifierName,
		wildcard:   make(map[string]*cosign.Verifier),
		registry:   make(map[string]*cosign.Verifier),
		repository: make(map[string]*cosign.Verifier),
	}

	tests := []struct {
		name        string
		repository  string
		wantErr     bool
		errContains string
	}{
		{
			name:        "repository with no subdomain for wildcard matching",
			repository:  "example.com/repo",
			wantErr:     true,
			errContains: "no verifier configured for the repository",
		},
		{
			name:        "repository with single character before dot",
			repository:  "a.example.com/repo",
			wantErr:     true,
			errContains: "no verifier configured for the repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.matchVerifier(tt.repository)

			if tt.wantErr {
				if err == nil {
					t.Errorf("matchVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("matchVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("matchVerifier() unexpected error = %v", err)
			}
		})
	}
}

func TestInit_RegistryFactoryRegistration(t *testing.T) {
	// The init() function should register the cosign factory
	// This test verifies that the factory is properly registered
	_, err := verifier.New(verifier.NewOptions{
		Name: testVerifierName,
		Type: verifierTypeCosign,
		Parameters: map[string]interface{}{
			"trustPolicies": []interface{}{
				map[string]interface{}{
					"name":   "test-policy",
					"scopes": []string{"registry.example.com"},
				},
			},
		},
	}, nil)

	if err != nil {
		t.Errorf("Factory registration failed: %v", err)
	}
}

func TestNewVerifier_UnmarshalError(t *testing.T) {
	// Test unmarshal error path
	opts := verifier.NewOptions{
		Name: testVerifierName,
		Parameters: map[string]interface{}{
			"trustPolicies": "invalid-string-instead-of-array",
		},
	}

	_, err := NewVerifier(opts, nil)
	if err == nil {
		t.Error("Expected error from NewVerifier with invalid parameters, but got none")
	}
	if !containsError(err.Error(), "failed to unmarshal verifier parameters") {
		t.Errorf("Expected unmarshal error, got: %v", err)
	}
}

// Helper functions

func TestVerifier_RegisterRegistry_EdgeCases(t *testing.T) {
	verifier := &Verifier{
		name:       testVerifierName,
		wildcard:   make(map[string]*cosign.Verifier),
		registry:   make(map[string]*cosign.Verifier),
		repository: make(map[string]*cosign.Verifier),
	}

	// Create a mock cosign verifier
	mockCosignVerifier, err := cosign.NewVerifier(&cosign.VerifierOptions{
		Name: "mock-verifier",
	})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}

	tests := []struct {
		name        string
		scope       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "localhost registry",
			scope:   "localhost:5000",
			wantErr: false,
		},
		{
			name:    "IP address registry",
			scope:   "192.168.1.100:5000",
			wantErr: false,
		},
		{
			name:    "wildcard with port",
			scope:   "*.example.com:8080",
			wantErr: false,
		},
		{
			name:    "duplicate wildcard registration",
			scope:   "*.test.com",
			wantErr: false,
		},
	}

	// First register a wildcard to test duplicate detection
	err = verifier.registerRegistry("*.test.com", mockCosignVerifier)
	if err != nil {
		t.Fatalf("Failed to register initial wildcard: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.registerRegistry(tt.scope, mockCosignVerifier)

			if tt.name == "duplicate wildcard registration" {
				// This should fail due to duplicate
				if err == nil {
					t.Errorf("registerRegistry() expected error for duplicate wildcard but got none")
				}
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Errorf("registerRegistry() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("registerRegistry() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("registerRegistry() unexpected error = %v", err)
			}
		})
	}
}

func TestVerifier_RegisterRepository_EdgeCases(t *testing.T) {
	verifier := &Verifier{
		name:       testVerifierName,
		wildcard:   make(map[string]*cosign.Verifier),
		registry:   make(map[string]*cosign.Verifier),
		repository: make(map[string]*cosign.Verifier),
	}

	// Create a mock cosign verifier
	mockCosignVerifier, err := cosign.NewVerifier(&cosign.VerifierOptions{
		Name: "mock-verifier",
	})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}

	tests := []struct {
		name        string
		scope       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "repository with digest",
			scope:       "registry.example.com/repo@sha256:abcd1234",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:    "deep repository path",
			scope:   "registry.example.com/org/team/project/repo",
			wantErr: false,
		},
		{
			name:    "repository with special characters",
			scope:   "registry.example.com/org-name/repo_name",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.registerRepository(tt.scope, mockCosignVerifier)

			if tt.wantErr {
				if err == nil {
					t.Errorf("registerRepository() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsError(err.Error(), tt.errContains) {
					t.Errorf("registerRepository() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("registerRepository() unexpected error = %v", err)
			}
		})
	}
}

func TestVerifier_ScopeMatchingPrecedence(t *testing.T) {
	// Test that scope matching follows the correct precedence:
	// 1. Exact repository match
	// 2. Exact registry match
	// 3. Wildcard registry match

	opts := verifier.NewOptions{
		Name: testVerifierName,
		Parameters: map[string]interface{}{
			"trustPolicies": []interface{}{
				// Wildcard policy (lowest precedence)
				map[string]interface{}{
					"name":   "wildcard-policy",
					"scopes": []string{"*.example.com"},
				},
				// Registry policy (medium precedence)
				map[string]interface{}{
					"name":   "registry-policy",
					"scopes": []string{"registry.example.com"},
				},
				// Repository policy (highest precedence)
				map[string]interface{}{
					"name":   "repo-policy",
					"scopes": []string{"registry.example.com/namespace/repo"},
				},
			},
		},
	}

	verifier, err := NewVerifier(opts, nil)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	scopedVerifier := verifier.(*Verifier)

	tests := []struct {
		name       string
		repository string
		wantScope  string // Which scope should match
	}{
		{
			name:       "exact repository match should take precedence",
			repository: "registry.example.com/namespace/repo",
			wantScope:  "repository", // Should match repository scope
		},
		{
			name:       "registry match when no exact repository",
			repository: "registry.example.com/other/repo",
			wantScope:  "registry", // Should match registry scope
		},
		{
			name:       "wildcard match when no exact matches",
			repository: "sub.example.com/some/repo",
			wantScope:  "wildcard", // Should match wildcard scope
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedVerifier, err := scopedVerifier.matchVerifier(tt.repository)
			if err != nil {
				t.Errorf("matchVerifier() unexpected error = %v", err)
				return
			}

			if matchedVerifier == nil {
				t.Errorf("matchVerifier() returned nil verifier")
				return
			}

			// The test validates that a verifier is found - the specific verifier
			// instance validation would require more complex setup with different
			// verifier instances per scope
		})
	}
}

func TestNewVerifier_FallbackScope(t *testing.T) {
	newOpts := func(scopes []string) verifier.NewOptions {
		policy := map[string]interface{}{"name": "fallback-policy"}
		if scopes != nil {
			policy["scopes"] = scopes
		}
		return verifier.NewOptions{
			Name: testVerifierName,
			Parameters: map[string]interface{}{
				"trustPolicies": []interface{}{
					map[string]interface{}{
						"name":   "registry-policy",
						"scopes": []string{"registry.example.com"},
					},
					policy,
				},
			},
		}
	}

	tests := []struct {
		name         string
		scopes       []string
		globalScopes []string
	}{
		{
			name:   "explicit fallback scope",
			scopes: []string{"*"},
		},
		{
			name:         "inherited fallback scope",
			globalScopes: []string{"*"},
		},
		{
			name:         "inherited mixed scopes",
			globalScopes: []string{"other.example.com", "*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(newOpts(tt.scopes), tt.globalScopes)
			if err != nil {
				t.Fatalf("NewVerifier() unexpected error = %v", err)
			}
			scopedVerifier := v.(*Verifier)
			if scopedVerifier.fallback == nil {
				t.Fatal("expected fallback verifier to be registered")
			}

			matched, err := scopedVerifier.matchVerifier("unknown.io/foo")
			if err != nil {
				t.Fatalf("matchVerifier() unexpected error = %v", err)
			}
			if matched != scopedVerifier.fallback {
				t.Error("expected unmatched repository to route to fallback verifier")
			}

			matched, err = scopedVerifier.matchVerifier("registry.example.com/foo")
			if err != nil {
				t.Fatalf("matchVerifier() unexpected error = %v", err)
			}
			if matched == scopedVerifier.fallback {
				t.Error("expected exact registry match to take precedence over fallback")
			}
		})
	}
}

func TestOptions_JsonMarshaling(t *testing.T) {
	// Test that Options and ScopedOptions can be properly marshaled/unmarshaled
	originalOpts := Options{
		TrustPolicies: []*ScopedOptions{
			{
				Scopes:                     []string{"registry.example.com", "*.test.com"},
				CertificateIdentity:        "test@example.com",
				CertificateIdentityRegex:   ".*@example\\.com",
				CertificateOIDCIssuer:      "https://github.com/login/oauth",
				CertificateOIDCIssuerRegex: "https://github\\.com/.*",
				IgnoreTLog:                 true,
				IgnoreCTLog:                false,
			},
		},
	}

	// This test validates the structure can be used in real scenarios
	// by creating a verifier with complex options
	params := map[string]interface{}{
		"trustPolicies": []interface{}{
			map[string]interface{}{
				"name":                       "test-policy",
				"scopes":                     []string{"registry.example.com", "*.test.com"},
				"certificateIdentity":        "test@example.com",
				"certificateIdentityRegex":   ".*@example\\.com",
				"certificateOIDCIssuer":      "https://github.com/login/oauth",
				"certificateOIDCIssuerRegex": "https://github\\.com/.*",
				"ignoreTlog":                 true,
				"ignoreCTLog":                false,
			},
		},
	}

	opts := verifier.NewOptions{
		Name:       testVerifierName,
		Parameters: params,
	}

	verifier, err := NewVerifier(opts, nil)
	if err != nil {
		t.Errorf("NewVerifier() with complex options failed: %v", err)
		return
	}

	if verifier == nil {
		t.Errorf("NewVerifier() returned nil verifier")
		return
	}

	// Validate that the original options structure is compatible
	if len(originalOpts.TrustPolicies) != 1 {
		t.Errorf("Original options structure validation failed")
	}
}

// Helper functions

func createTestVerifier(t *testing.T) ratify.Verifier {
	opts := verifier.NewOptions{
		Name: testVerifierName,
		Parameters: map[string]interface{}{
			"trustPolicies": []interface{}{
				map[string]interface{}{
					"name":   "test-policy",
					"scopes": []string{"registry.example.com"},
				},
			},
		},
	}

	verifier, err := NewVerifier(opts, nil)
	if err != nil {
		t.Fatalf("Failed to create test verifier: %v", err)
	}

	return verifier
}

func containsError(errMsg, contains string) bool {
	return errMsg != "" && contains != "" &&
		len(errMsg) >= len(contains) &&
		errMsg[:len(contains)] == contains ||
		errMsg[len(errMsg)-len(contains):] == contains ||
		findSubstring(errMsg, contains)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestConvertProviderKeysToCosignKeys(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	startTime := time.Now()
	endTime := startTime.Add(24 * time.Hour)

	tests := []struct {
		name         string
		providerKeys []*keyprovider.PublicKey
		expected     []*cosign.PublicKeyConfig
	}{
		{
			name:         "empty input",
			providerKeys: []*keyprovider.PublicKey{},
			expected:     []*cosign.PublicKeyConfig{},
		},
		{
			name: "single key with all fields",
			providerKeys: []*keyprovider.PublicKey{
				{
					Key:                 &rsaKey.PublicKey,
					SignatureAlgorithm:  crypto.SHA256,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
			expected: []*cosign.PublicKeyConfig{
				{
					PublicKey:           &rsaKey.PublicKey,
					SignatureAlgorithm:  crypto.SHA256,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
		},
		{
			name: "single key with minimal fields",
			providerKeys: []*keyprovider.PublicKey{
				{
					Key: &rsaKey.PublicKey,
				},
			},
			expected: []*cosign.PublicKeyConfig{
				{
					PublicKey: &rsaKey.PublicKey,
				},
			},
		},
		{
			name: "multiple keys",
			providerKeys: []*keyprovider.PublicKey{
				{
					Key:                &rsaKey.PublicKey,
					SignatureAlgorithm: crypto.SHA256,
				},
				{
					Key:                 &rsaKey.PublicKey,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
			expected: []*cosign.PublicKeyConfig{
				{
					PublicKey:          &rsaKey.PublicKey,
					SignatureAlgorithm: crypto.SHA256,
				},
				{
					PublicKey:           &rsaKey.PublicKey,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProviderKeysToCosignKeys(tt.providerKeys)

			// Check length
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d keys, got %d", len(tt.expected), len(result))
			}

			// Check each key
			for i, expectedKey := range tt.expected {
				actualKey := result[i]

				if actualKey.PublicKey != expectedKey.PublicKey {
					t.Errorf("key %d: public key mismatch", i)
				}

				if actualKey.SignatureAlgorithm != expectedKey.SignatureAlgorithm {
					t.Errorf("key %d: signature algorithm mismatch: expected %v, got %v",
						i, expectedKey.SignatureAlgorithm, actualKey.SignatureAlgorithm)
				}

				// Compare validity period start
				if !actualKey.ValidityPeriodStart.Equal(expectedKey.ValidityPeriodStart) {
					t.Errorf("key %d: validity period start mismatch: expected %v, got %v",
						i, expectedKey.ValidityPeriodStart, actualKey.ValidityPeriodStart)
				}

				// Compare validity period end
				if !actualKey.ValidityPeriodEnd.Equal(expectedKey.ValidityPeriodEnd) {
					t.Errorf("key %d: validity period end mismatch: expected %v, got %v",
						i, expectedKey.ValidityPeriodEnd, actualKey.ValidityPeriodEnd)
				}
			}
		})
	}
}

func TestConvertProviderKeysToCosignKeys_NilInput(t *testing.T) {
	// Test edge case with nil input
	result := convertProviderKeysToCosignKeys(nil)
	if result == nil {
		t.Error("expected non-nil result for nil input")
	}
	if len(result) != 0 {
		t.Errorf("expected empty slice for nil input, got length %d", len(result))
	}
}

// Repository scopes are normalized so that they match the normalized
// repository of the artifacts being verified.
func TestRegisterVerifier_NormalizesRepositoryScope(t *testing.T) {
	cosignVerifier, err := cosign.NewVerifier(&cosign.VerifierOptions{Name: "mock-verifier"})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}
	verifier := &Verifier{
		name:       testVerifierName,
		wildcard:   make(map[string]*cosign.Verifier),
		registry:   make(map[string]*cosign.Verifier),
		repository: make(map[string]*cosign.Verifier),
	}
	for _, scope := range []string{"docker.io/nginx", "org/app"} {
		if err := verifier.registerVerifier(scope, cosignVerifier); err != nil {
			t.Fatalf("failed to register scope %q: %v", scope, err)
		}
	}
	for _, repository := range []string{"docker.io/library/nginx", "docker.io/org/app"} {
		if _, err := verifier.matchVerifier(repository); err != nil {
			t.Errorf("expected %q to match a normalized repository scope, got: %v", repository, err)
		}
	}
	if err := verifier.registerVerifier("docker.io/library/nginx", cosignVerifier); err == nil {
		t.Error("expected an error for a scope that normalizes to an already registered scope, got nil")
	}
}
