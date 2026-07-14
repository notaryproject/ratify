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
	"testing"
)

// TestCreateTrustPolicies tests the CreateTrustPolicies function
func TestCreateTrustPolicies(t *testing.T) {
	tc := []struct {
		name          string
		policyConfigs []TrustPolicyConfig
		wantErr       bool
	}{
		{
			name: "valid policy",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name:          "nil policy",
			policyConfigs: nil,
			wantErr:       true,
		},
		{
			name:          "empty policy",
			policyConfigs: []TrustPolicyConfig{},
			wantErr:       true,
		},
		{
			name: "valid multiple policies",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v2"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid policy scopes",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid policy duplicate names",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid policy invalid trust policy config",
			policyConfigs: []TrustPolicyConfig{
				{
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateTrustPolicies(tt.policyConfigs, "test-verifier")
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTrustPolicies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGetScopedPolicy tests the GetScopedPolicy functions
func TestGetScopedPolicy(t *testing.T) {
	tc := []struct {
		name           string
		policyConfigs  []TrustPolicyConfig
		reference      string
		wantErr        bool
		wantPolicyName string
	}{
		{
			name: "valid policy",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v2"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			reference:      "ghcr.io/ratify-project/ratify:v1",
			wantErr:        false,
			wantPolicyName: "test",
		},
		{
			name: "valid policy wildcards",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify2:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			reference:      "ghcr.io/ratify-project/ratify:v1",
			wantErr:        false,
			wantPolicyName: "test",
		},
		{
			name: "no matching policy",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify2:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			reference:      "ghcr.io/ratify-project/ratify3:v1",
			wantErr:        true,
			wantPolicyName: "",
		},
		{
			name: "default to global wildcard policy if exists",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "global",
					Scopes:  []string{"*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify2:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			reference:      "ghcr.io/ratify-project/ratify3:v1",
			wantErr:        false,
			wantPolicyName: "global",
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := CreateTrustPolicies(tt.policyConfigs, "test-verifier")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			policy, err := policies.GetScopedPolicy(tt.reference)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetScopedPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && policy.GetName() != tt.wantPolicyName {
				t.Errorf("GetScopedPolicy() policy name = %v, want %v", policy.GetName(), tt.wantPolicyName)
			}
		})
	}
}

// TestValidateScopes tests the validateScopes function
func TestValidateScopes(t *testing.T) {
	tc := []struct {
		name          string
		policyConfigs []TrustPolicyConfig
		wantErr       bool
	}{
		{
			name: "valid absolute scope",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple valid absolute scopes",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1", "ghcr.io/ratify-project/ratify:v2"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid wild card scope",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple valid wild card scopes",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid global wild card scope",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid global wild card scope with other scopes",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"*", "somescope"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid absolute scope duplicate",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1", "ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid absolute scope duplicate across policies",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid global wildcard scope with duplicate wild card scope",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid wild card scope duplicate",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:*", "ghcr.io/ratify-project/ratify:*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid wild card scope prefix",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"*.azurecr.io"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid wild card character middle of scope",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/*/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid wildcard overlap scopes",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/*", "ghcr.io/ratify-project/*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "valid wildcard no overlap wildcard scopes",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/test/*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid wildcard and absolute overlap",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid wildcard and absolute overlap reverse order",
			policyConfigs: []TrustPolicyConfig{
				{
					Name:    "test",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:v1"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
				{
					Name:    "test-2",
					Scopes:  []string{"ghcr.io/ratify-project/ratify:*"},
					Keyless: KeylessConfig{CertificateIdentity: "test-identity", CertificateOIDCIssuer: "https://test-issuer.com"},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			policies := make([]TrustPolicy, 0, len(tt.policyConfigs))
			for _, policyConfig := range tt.policyConfigs {
				policy, err := CreateTrustPolicy(policyConfig, "test-verifier")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				policies = append(policies, policy)
			}
			err := validateScopes(policies)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
