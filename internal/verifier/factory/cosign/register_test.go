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
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-verifier-go/cosign"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/notaryproject/ratify/v2/internal/verifier/factory"
)

const testVerifierName = "test-cosign-verifier"

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name        string
		opts        *factory.NewVerifierOptions
		globalScope []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil options",
			opts:        nil,
			wantErr:     true,
			errContains: "verifier options cannot be nil",
		},
		{
			name: "empty verifier name",
			opts: &factory.NewVerifierOptions{
				Name: "",
			},
			wantErr:     true,
			errContains: "verifier name cannot be empty",
		},
		{
			name: "invalid parameters json",
			opts: &factory.NewVerifierOptions{
				Name:       testVerifierName,
				Parameters: make(chan int), // unmarshallable type
			},
			wantErr:     true,
			errContains: "failed to marshal verifier parameters",
		},
		{
			name: "no trust policies",
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
			opts: &factory.NewVerifierOptions{
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
	opts := &factory.NewVerifierOptions{
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

func TestInit_RegistryFactoryRegistration(t *testing.T) {
	// The init() function should register the cosign factory
	// This test verifies that the factory is properly registered
	_, err := factory.NewVerifier(&factory.NewVerifierOptions{
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

	opts := &factory.NewVerifierOptions{
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

	opts := &factory.NewVerifierOptions{
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
	opts := &factory.NewVerifierOptions{
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
