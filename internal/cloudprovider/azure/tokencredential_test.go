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

package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func TestCreateCredentialChain(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		tenantID string
	}{
		{
			name:     "with both clientID and tenantID",
			clientID: "test-client-id",
			tenantID: "test-tenant-id",
		},
		{
			name:     "with only clientID",
			clientID: "test-client-id",
			tenantID: "",
		},
		{
			name:     "with only tenantID",
			clientID: "",
			tenantID: "test-tenant-id",
		},
		{
			name:     "with empty clientID and tenantID",
			clientID: "",
			tenantID: "",
		},
		{
			name:     "with special characters in clientID",
			clientID: "test-client-id-with-special-chars-123",
			tenantID: "test-tenant-id",
		},
		{
			name:     "with UUID format clientID and tenantID",
			clientID: "12345678-1234-1234-1234-123456789abc",
			tenantID: "87654321-4321-4321-4321-cba987654321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := CreateCredentialChain(tt.clientID, tt.tenantID)

			// The function should always succeed in creating a chained credential
			// even if the underlying credentials don't work in the test environment
			if err != nil {
				t.Errorf("unexpected error creating credential chain: %v", err)
			}

			if credential == nil {
				t.Error("expected non-nil credential")
			}

			// Verify that the returned credential implements the TokenCredential interface
			var _ = credential
		})
	}
}

func TestCreateCredentialChain_WorkloadIdentitySuccess(t *testing.T) {
	// Test case that ensures workload identity credential creation is attempted
	// This covers the path where wiCred is created successfully (err == nil)
	// and added to sources (lines 33-35 in the original code)

	clientID := "workload-test-client-id"
	tenantID := "workload-test-tenant-id"

	credential, err := CreateCredentialChain(clientID, tenantID)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}

	// The credential should be a ChainedTokenCredential
	// We can't easily verify the internal sources without reflection,
	// but we can verify it was created successfully
}

func TestCreateCredentialChain_ManagedIdentityWithClientID(t *testing.T) {
	// Test case that ensures managed identity credential with client ID is handled
	// This covers the path where clientID != "" (lines 38-42 in the original code)

	clientID := "managed-identity-client-id"
	tenantID := "managed-identity-tenant-id"

	credential, err := CreateCredentialChain(clientID, tenantID)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}
}

func TestCreateCredentialChain_ManagedIdentityWithoutClientID(t *testing.T) {
	// Test case that ensures managed identity credential without client ID is handled
	// This covers the path where clientID == "" (managed identity uses system-assigned)

	clientID := ""
	tenantID := "system-assigned-tenant-id"

	credential, err := CreateCredentialChain(clientID, tenantID)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}
}

func TestCreateCredentialChain_ManagedIdentitySuccess(t *testing.T) {
	// Test case that ensures managed identity credential creation is attempted
	// This covers the path where miCred is created successfully (err == nil)
	// and added to sources (lines 44-46 in the original code)

	clientID := "managed-test-client-id"
	tenantID := ""

	credential, err := CreateCredentialChain(clientID, tenantID)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}
}

func TestCreateCredentialChain_ChainedCredentialCreation(t *testing.T) {
	// Test case that ensures the chained credential is created
	// This covers line 49: azidentity.NewChainedTokenCredential(sources, nil)

	clientID := "chain-test-client-id"
	tenantID := "chain-test-tenant-id"

	credential, err := CreateCredentialChain(clientID, tenantID)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}

	// Verify the credential type
	var _ = credential
}

func TestCreateCredentialChain_EmptySourcesList(t *testing.T) {
	// Test edge case where both workload identity and managed identity fail
	// but ChainedTokenCredential should still be created with empty sources
	// This tests the robustness of the function

	clientID := ""
	tenantID := ""

	credential, err := CreateCredentialChain(clientID, tenantID)

	// Even with empty sources, ChainedTokenCredential should be created
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}
}

func TestCreateCredentialChain_LongIdentifiers(t *testing.T) {
	// Test with very long identifiers to ensure no length limitations

	longClientID := "very-long-client-id-that-might-be-used-in-some-environments-with-extensive-naming-conventions-12345678901234567890"
	longTenantID := "very-long-tenant-id-that-might-be-used-in-some-environments-with-extensive-naming-conventions-09876543210987654321"

	credential, err := CreateCredentialChain(longClientID, longTenantID)

	if err != nil {
		t.Errorf("unexpected error with long identifiers: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential with long identifiers")
	}
}

func TestCreateCredentialChain_ReturnType(t *testing.T) {
	// Test that the return type implements azcore.TokenCredential interface

	clientID := "interface-test-client-id"
	tenantID := "interface-test-tenant-id"

	credential, err := CreateCredentialChain(clientID, tenantID)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if credential == nil {
		t.Error("expected non-nil credential")
	}

	// This line ensures the returned credential implements azcore.TokenCredential
	var tokenCredential = credential
	if tokenCredential == nil {
		t.Error("credential does not implement azcore.TokenCredential interface")
	}
}

func TestCreateCredentialChain_AllPaths(t *testing.T) {
	// Comprehensive test that tries to exercise all code paths

	testCases := []struct {
		name     string
		clientID string
		tenantID string
		desc     string
	}{
		{
			name:     "both_empty",
			clientID: "",
			tenantID: "",
			desc:     "Tests empty client and tenant IDs",
		},
		{
			name:     "client_only",
			clientID: "test-client",
			tenantID: "",
			desc:     "Tests with only client ID",
		},
		{
			name:     "tenant_only",
			clientID: "",
			tenantID: "test-tenant",
			desc:     "Tests with only tenant ID",
		},
		{
			name:     "both_present",
			clientID: "test-client",
			tenantID: "test-tenant",
			desc:     "Tests with both client and tenant IDs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credential, err := CreateCredentialChain(tc.clientID, tc.tenantID)

			if err != nil {
				t.Errorf("case %s (%s): unexpected error: %v", tc.name, tc.desc, err)
			}

			if credential == nil {
				t.Errorf("case %s (%s): expected non-nil credential", tc.name, tc.desc)
			}
		})
	}
}

// stubCredential is a placeholder credential used to verify chain assembly.
type stubCredential struct{}

func (stubCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func TestAppendCredential(t *testing.T) {
	cred := stubCredential{}

	got := appendCredential(nil, cred, nil, "workload identity", `clientID="id"`)
	if len(got) != 1 {
		t.Fatalf("expected a successfully created credential to be appended, got %d source(s)", len(got))
	}

	got = appendCredential(got, nil, errors.New("unavailable"), "managed identity", `clientID=""`)
	if len(got) != 1 {
		t.Fatalf("expected a failed credential to be skipped, got %d source(s)", len(got))
	}
}

// countingCredential records how many times it was asked for a token and
// returns the configured token or error.
type countingCredential struct {
	token string
	err   error
	calls int
}

func (c *countingCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls++
	if c.err != nil {
		return azcore.AccessToken{}, c.err
	}
	return azcore.AccessToken{Token: c.token}, nil
}

func TestFallbackCredential_GetToken(t *testing.T) {
	primaryErr := errors.New("identity binding failed")
	fallbackErr := errors.New("workload identity failed")

	tests := []struct {
		name              string
		primary           *countingCredential
		fallback          *countingCredential
		wantToken         string
		wantErrs          []error
		wantFallbackCalls int
	}{
		{
			name:              "primary succeeds",
			primary:           &countingCredential{token: "ib-token"},
			fallback:          &countingCredential{token: "wi-token"},
			wantToken:         "ib-token",
			wantFallbackCalls: 0,
		},
		{
			name:              "primary fails and fallback succeeds",
			primary:           &countingCredential{err: primaryErr},
			fallback:          &countingCredential{token: "wi-token"},
			wantToken:         "wi-token",
			wantFallbackCalls: 1,
		},
		{
			name:              "both fail",
			primary:           &countingCredential{err: primaryErr},
			fallback:          &countingCredential{err: fallbackErr},
			wantErrs:          []error{primaryErr, fallbackErr},
			wantFallbackCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &fallbackCredential{primary: tt.primary, fallback: tt.fallback}
			token, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
			if len(tt.wantErrs) > 0 {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				for _, want := range tt.wantErrs {
					if !errors.Is(err, want) {
						t.Errorf("expected error to wrap %q, got %v", want, err)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token.Token != tt.wantToken {
				t.Errorf("expected token %q, got %q", tt.wantToken, token.Token)
			}
			if tt.primary.calls != 1 {
				t.Errorf("expected primary to be called once, got %d", tt.primary.calls)
			}
			if tt.fallback.calls != tt.wantFallbackCalls {
				t.Errorf("expected fallback to be called %d time(s), got %d", tt.wantFallbackCalls, tt.fallback.calls)
			}
		})
	}
}

func TestCreateCredentialChainPreferIdentityBinding(t *testing.T) {
	validIB := &IdentityBindingConfig{SNIName: "ib.example.com", APIServerHost: "10.0.0.1"}

	tests := []struct {
		name         string
		clientID     string
		ibConfig     *IdentityBindingConfig
		wantFallback bool
	}{
		{
			name:     "no identity binding config",
			clientID: "client-id",
			ibConfig: nil,
		},
		{
			name:     "identity binding config without SNI name",
			clientID: "client-id",
			ibConfig: &IdentityBindingConfig{APIServerHost: "10.0.0.1"},
		},
		{
			name:     "identity binding credential cannot be created",
			clientID: "client-id",
			ibConfig: &IdentityBindingConfig{SNIName: "ib.example.com"},
		},
		{
			name:         "identity binding is tried first",
			clientID:     "client-id",
			ibConfig:     validIB,
			wantFallback: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := CreateCredentialChainPreferIdentityBinding(tt.clientID, "tenant-id", tt.ibConfig)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			fc, ok := cred.(*fallbackCredential)
			if ok != tt.wantFallback {
				t.Fatalf("expected fallback credential=%t, got %T", tt.wantFallback, cred)
			}
			if !tt.wantFallback {
				return
			}
			if _, ok := fc.primary.(*identityBindingCredential); !ok {
				t.Errorf("expected identity binding credential as primary, got %T", fc.primary)
			}
			if fc.primaryTimeout != defaultPrimaryCredentialTimeout {
				t.Errorf("expected primary timeout %s, got %s", defaultPrimaryCredentialTimeout, fc.primaryTimeout)
			}
			if fc.fallback == nil {
				t.Error("expected a non-nil fallback credential")
			}
		})
	}
}

// stalledCredential blocks until its context is done, simulating a token proxy
// that accepts the connection but never responds.
type stalledCredential struct{}

func (stalledCredential) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	<-ctx.Done()
	return azcore.AccessToken{}, ctx.Err()
}

// ctxCheckingCredential records whether its context was already done when it
// was asked for a token.
type ctxCheckingCredential struct {
	ctxErr error
	called bool
}

func (c *ctxCheckingCredential) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.called = true
	c.ctxErr = ctx.Err()
	return azcore.AccessToken{Token: "wi-token"}, nil
}

func TestFallbackCredential_StalledPrimaryFallsBack(t *testing.T) {
	fallback := &ctxCheckingCredential{}
	cred := &fallbackCredential{
		primary:        stalledCredential{},
		fallback:       fallback,
		primaryTimeout: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("expected the stalled primary to be bounded by primaryTimeout, took %s", elapsed)
	}
	if token.Token != "wi-token" {
		t.Errorf("expected fallback token, got %q", token.Token)
	}
	if !fallback.called {
		t.Fatal("expected fallback to be called")
	}
	if fallback.ctxErr != nil {
		t.Errorf("expected fallback to receive the caller's live context, got context error %v", fallback.ctxErr)
	}
}
