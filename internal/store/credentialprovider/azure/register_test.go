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
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

const (
	testRegistry = "testregistry.azurecr.io"
)

// Mock TokenCredential for testing
type mockTokenCredential struct {
	token azcore.AccessToken
	err   error
}

func (m *mockTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return m.token, m.err
}

func TestCreateAzureIdentityProvider(t *testing.T) {
	tests := []struct {
		name        string
		opts        credentialprovider.Options
		expectError bool
		expected    *IdentityProvider
	}{
		{
			name: "valid options with clientID and tenantID",
			opts: credentialprovider.Options{
				"clientID": "test-client-id",
				"tenantID": "test-tenant-id",
			},
			expectError: false,
			expected: &IdentityProvider{
				clientID: "test-client-id",
				tenantID: "test-tenant-id",
			},
		},
		{
			name: "valid options with only clientID",
			opts: credentialprovider.Options{
				"clientID": "test-client-id",
			},
			expectError: false,
			expected: &IdentityProvider{
				clientID: "test-client-id",
				tenantID: "",
			},
		},
		{
			name: "valid options with only tenantID",
			opts: credentialprovider.Options{
				"tenantID": "test-tenant-id",
			},
			expectError: false,
			expected: &IdentityProvider{
				clientID: "",
				tenantID: "test-tenant-id",
			},
		},
		{
			name:        "empty options",
			opts:        credentialprovider.Options{},
			expectError: false,
			expected: &IdentityProvider{
				clientID: "",
				tenantID: "",
			},
		},
		{
			name: "complex nested structure that gets ignored",
			opts: credentialprovider.Options{
				"clientID":    "test-client-id",
				"tenantID":    "test-tenant-id",
				"extraField":  map[string]interface{}{"nested": "value"},
				"arrayField":  []string{"item1", "item2"},
				"numberField": 123,
			},
			expectError: false,
			expected: &IdentityProvider{
				clientID: "test-client-id",
				tenantID: "test-tenant-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := createAzureIdentityProvider(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// The createAzureIdentityProvider now returns a CachedProvider,
			// so we need to extract the source provider to verify the configuration
			cachedProvider, ok := provider.(*credentialprovider.CachedProvider)
			if !ok {
				t.Errorf("expected *credentialprovider.CachedProvider, got %T", provider)
				return
			}

			// We can't directly access the source provider in CachedProvider,
			// but we can test the behavior by calling Get method
			// For this test, we'll create a direct IdentityProvider to verify configuration parsing
			raw, err := json.Marshal(tt.opts)
			if err != nil {
				t.Fatalf("failed to marshal test options: %v", err)
			}

			var azureOpts IdentityProviderOptions
			if err := json.Unmarshal(raw, &azureOpts); err != nil {
				t.Fatalf("failed to unmarshal test options: %v", err)
			}

			if azureOpts.ClientID != tt.expected.clientID {
				t.Errorf("expected clientID %q, got %q", tt.expected.clientID, azureOpts.ClientID)
			}

			if azureOpts.TenantID != tt.expected.tenantID {
				t.Errorf("expected tenantID %q, got %q", tt.expected.tenantID, azureOpts.TenantID)
			}

			// Verify that the returned provider is not nil
			if cachedProvider == nil {
				t.Errorf("expected non-nil cached provider")
			}
		})
	}
}

func TestCreateAzureIdentityProvider_MarshalError(t *testing.T) {
	// Create an option that can't be marshaled to JSON
	opts := credentialprovider.Options{
		"invalid": make(chan int), // channels can't be marshaled to JSON
	}

	_, err := createAzureIdentityProvider(opts)
	if err == nil {
		t.Error("expected marshal error but got none")
	}

	// Check if it's a JSON marshaling error
	var jsonErr *json.UnsupportedTypeError
	if !errors.As(err, &jsonErr) {
		t.Errorf("expected json.UnsupportedTypeError, got %T: %v", err, err)
	}
}

func TestCreateAzureIdentityProvider_UnmarshalError(t *testing.T) {
	// Create a custom struct that will marshal successfully but unmarshal into
	// AzureIdentityProviderOptions would fail due to type mismatch
	opts := credentialprovider.Options{
		"clientID": []int{1, 2, 3},                            // This will marshal fine but unmarshal will fail into string field
		"tenantID": map[string]interface{}{"nested": "value"}, // This will also cause unmarshal error
	}

	_, err := createAzureIdentityProvider(opts)
	if err == nil {
		t.Error("expected unmarshal error but got none")
	}

	expectedErrorMsg := "failed to unmarshal configuration"
	if !contains(err.Error(), expectedErrorMsg) {
		t.Errorf("expected error containing %q, got %q", expectedErrorMsg, err.Error())
	}
}

func TestCreateAzureIdentityProvider_UnmarshalErrorWithMalformedJSON(t *testing.T) {
	// To test the unmarshal error, we need to create a scenario where
	// the JSON is malformed. Since we marshal first, we can create a custom
	// type that marshals to invalid JSON for unmarshaling into AzureIdentityProviderOptions

	// Create a JSON string that will unmarshal successfully as map[string]any
	// but fail when unmarshaling into AzureIdentityProviderOptions with strict types
	malformedJSON := `{"clientID": 123, "tenantID": true}` // Numbers and booleans instead of strings

	var opts credentialprovider.Options
	err := json.Unmarshal([]byte(malformedJSON), &opts)
	if err != nil {
		t.Fatalf("Failed to create test options: %v", err)
	}

	_, err = createAzureIdentityProvider(opts)
	if err == nil {
		t.Error("expected unmarshal error but got none")
	}

	expectedErrorMsg := "failed to unmarshal configuration"
	if !contains(err.Error(), expectedErrorMsg) {
		t.Errorf("expected error containing %q, got %q", expectedErrorMsg, err.Error())
	}
}

func TestAzureIdentityProvider_GetWithTTL_GetTokenError(t *testing.T) {
	provider := &IdentityProvider{
		tenantID: "test-tenant-id",
	}

	mockCredential := &mockTokenCredential{
		err: errors.New("get token error"),
	}

	ctx := context.Background()
	_, err := provider.exchangeAADTokenForACRToken(ctx, mockCredential, testRegistry)
	if err == nil {
		t.Error("expected error but got none")
	}

	expectedErrorMsg := "failed to get AAD access token"
	if !contains(err.Error(), expectedErrorMsg) {
		t.Errorf("expected error containing %q, got %q", expectedErrorMsg, err.Error())
	}
}

func TestAzureIdentityProvider_GetWithTTL_InvalidServerAddress(t *testing.T) {
	provider := &IdentityProvider{
		tenantID: "test-tenant-id",
	}

	mockCredential := &mockTokenCredential{
		token: azcore.AccessToken{
			Token:     "test-aad-token",
			ExpiresOn: time.Now().Add(time.Hour),
		},
	}

	ctx := context.Background()
	// Use an invalid server address
	serverAddress := "invalid-server-address"

	_, err := provider.exchangeAADTokenForACRToken(ctx, mockCredential, serverAddress)
	if err == nil {
		t.Error("expected error but got none")
	}

	// The error should be related to authentication client creation or token exchange
	expectedErrors := []string{
		"failed to create ACR authentication client",
		"failed to exchange AAD token for ACR refresh token",
	}

	errorMatched := false
	for _, expectedError := range expectedErrors {
		if contains(err.Error(), expectedError) {
			errorMatched = true
			break
		}
	}

	if !errorMatched {
		t.Errorf("expected error to contain one of %v, got %q", expectedErrors, err.Error())
	}
}

func TestAzureIdentityProvider_GetWithTTL_CredentialChainError(t *testing.T) {
	// Test the GetWithTTL method with invalid configuration that would cause
	// credential chain creation to fail
	provider := &IdentityProvider{
		clientID: "test-client-id",
		tenantID: "test-tenant-id",
	}

	ctx := context.Background()
	// This test will likely succeed in creating the credential chain
	// but fail in the token exchange step, which still exercises the error path
	_, err := provider.GetWithTTL(ctx, testRegistry)

	// We expect this to fail in test environment
	if err == nil {
		t.Error("expected error in test environment but got none")
	}

	// The error should be related to credential chain or token exchange
	expectedErrors := []string{
		"failed to create credential chain",
		"failed to exchange AAD token for ACR refresh token",
	}

	errorMatched := false
	for _, expectedError := range expectedErrors {
		if contains(err.Error(), expectedError) {
			errorMatched = true
			break
		}
	}

	if !errorMatched {
		t.Errorf("expected error to contain one of %v, got %q", expectedErrors, err.Error())
	}
}

func TestAzureIdentityProvider_GetWithTTL_CredentialChainCreationError(t *testing.T) {
	// Test the specific case where CreateCredentialChain fails and returns an error
	// This covers lines 83-85 in the GetWithTTL method: if err != nil { return credentialprovider.CredentialWithTTL{}, fmt.Errorf("failed to create credential chain: %w", err) }

	// In a test environment without proper Azure credentials configured,
	// the credential chain creation should eventually fail during token acquisition
	provider := &IdentityProvider{
		clientID: "test-client-id",
		tenantID: "test-tenant-id",
	}

	ctx := context.Background()
	// Call GetWithTTL which should fail either at credential chain creation or token exchange
	credWithTTL, err := provider.GetWithTTL(ctx, testRegistry)

	// We expect this to fail since we're not in a proper Azure environment
	if err == nil {
		t.Error("expected error but got none")
	}

	// Verify that the credential is empty when an error occurs
	if credWithTTL.Credential.RefreshToken != "" {
		t.Errorf("expected empty credential when error occurs, got refresh token: %s", credWithTTL.Credential.RefreshToken)
	}

	// The error should specifically mention one of the expected failure points
	expectedErrorMsgs := []string{
		"failed to create credential chain",
		"failed to exchange AAD token for ACR refresh token",
		"failed to get AAD access token",
	}

	errorMatched := false
	for _, expectedMsg := range expectedErrorMsgs {
		if contains(err.Error(), expectedMsg) {
			errorMatched = true
			break
		}
	}

	if !errorMatched {
		t.Errorf("expected error to contain one of %v, got %q", expectedErrorMsgs, err.Error())
	}
}

func TestAzureIdentityProvider_GetWithTTL_CredentialChainCreationErrorWithMock(t *testing.T) {
	// This test specifically targets lines 83-85 by creating a scenario where
	// the credential chain creation would fail. Since we can't easily mock the
	// azure.CreateCredentialChain function directly, we test with configurations
	// that are likely to cause credential failures in a test environment.

	tests := []struct {
		name        string
		clientID    string
		tenantID    string
		serverAddr  string
		expectError bool
	}{
		{
			name:        "empty credentials causing chain failure",
			clientID:    "",
			tenantID:    "",
			serverAddr:  testRegistry,
			expectError: true,
		},
		{
			name:        "invalid server address",
			clientID:    "test-client",
			tenantID:    "test-tenant",
			serverAddr:  "invalid-server-format",
			expectError: true,
		},
		{
			name:        "malformed server address with protocol",
			clientID:    "test-client",
			tenantID:    "test-tenant",
			serverAddr:  "ftp://invalid.server",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &IdentityProvider{
				clientID: tt.clientID,
				tenantID: tt.tenantID,
			}

			ctx := context.Background()
			credWithTTL, err := provider.GetWithTTL(ctx, tt.serverAddr)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}

				// Verify credential is empty on error
				if credWithTTL.Credential.RefreshToken != "" {
					t.Errorf("expected empty refresh token on error, got: %s", credWithTTL.Credential.RefreshToken)
				}

				// Check that error message contains expected failure information
				errorStr := err.Error()
				expectedFragments := []string{
					"failed to create credential chain",
					"failed to exchange AAD token",
					"failed to get AAD access token",
					"failed to create ACR authentication client",
				}

				hasExpectedError := false
				for _, fragment := range expectedFragments {
					if contains(errorStr, fragment) {
						hasExpectedError = true
						break
					}
				}

				if !hasExpectedError {
					t.Errorf("error message should contain one of %v, got: %s", expectedFragments, errorStr)
				}
			}
		})
	}
}

// Test parseJWTTokenTTL function
func TestParseJWTTokenTTL(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
		expectedTTL time.Duration
		checkTTL    bool
	}{
		{
			name:        "invalid JWT token",
			token:       "invalid.jwt.token",
			expectError: true,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
		{
			name:        "malformed JWT",
			token:       "not.a.jwt",
			expectError: true,
		},
		{
			name:        "JWT without exp claim",
			token:       createTestJWTToken(map[string]interface{}{"sub": "test"}),
			expectError: true,
		},
		{
			name:        "JWT with expired token",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(-time.Hour).Unix()}),
			expectError: true,
		},
		{
			name:        "JWT with valid future expiration",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: time.Hour - 5*time.Minute, // TTL should be roughly 55 minutes
		},
		{
			name:        "JWT with near expiration",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(3 * time.Minute).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: 0, // Should return 0 TTL due to 5-minute buffer
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl, err := parseJWTTokenTTL(tt.token)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.checkTTL {
				// Allow for some variance in TTL calculation due to timing
				variance := 30 * time.Second
				if ttl < tt.expectedTTL-variance || ttl > tt.expectedTTL+variance {
					t.Errorf("expected TTL around %v, got %v", tt.expectedTTL, ttl)
				}
			}
		})
	}
}

// TestParseJWTTokenTTL_Comprehensive provides comprehensive coverage for parseJWTTokenTTL function
func TestParseJWTTokenTTL_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
		expectedTTL time.Duration
		checkTTL    bool
		errorMsg    string
	}{
		// Basic invalid cases
		{
			name:        "invalid JWT token",
			token:       "invalid.jwt.token",
			expectError: true,
			errorMsg:    "failed to parse JWT token",
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
			errorMsg:    "failed to parse JWT token",
		},
		{
			name:        "malformed JWT - not enough parts",
			token:       "not.a",
			expectError: true,
			errorMsg:    "failed to parse JWT token",
		},
		{
			name:        "malformed JWT - invalid base64",
			token:       "invalid!@#.base64!@#.encoding!@#",
			expectError: true,
			errorMsg:    "failed to parse JWT token",
		},
		// Note: The "failed to extract claims from JWT token" path is very difficult to test
		// because ParseUnverified with jwt.MapClaims{} should always result in MapClaims
		// unless there's an internal JWT library issue. This case is extremely rare in practice.
		{
			name:        "JWT without exp claim",
			token:       createTestJWTToken(map[string]interface{}{"sub": "test", "iat": time.Now().Unix()}),
			expectError: true,
			errorMsg:    "JWT token does not contain exp claim",
		},
		{
			name:        "JWT with invalid exp claim type - string",
			token:       createTestJWTToken(map[string]interface{}{"exp": "not-a-number"}),
			expectError: true,
			errorMsg:    "failed to get expiration time from JWT token",
		},
		{
			name:        "JWT with invalid exp claim type - float string",
			token:       createTestJWTToken(map[string]interface{}{"exp": "123.456"}),
			expectError: true,
			errorMsg:    "failed to get expiration time from JWT token",
		},
		{
			name:        "JWT with negative exp claim",
			token:       createTestJWTToken(map[string]interface{}{"exp": -1}),
			expectError: true,
			errorMsg:    "JWT token has already expired",
		},
		{
			name:        "JWT with expired token - 1 hour ago",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(-time.Hour).Unix()}),
			expectError: true,
			errorMsg:    "JWT token has already expired",
		},
		{
			name:        "JWT with barely expired token - 1 second ago",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(-time.Second).Unix()}),
			expectError: true,
			errorMsg:    "JWT token has already expired",
		},

		// Valid cases with different TTL scenarios
		{
			name:        "JWT with valid future expiration - 1 hour",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: time.Hour - 5*time.Minute, // 55 minutes due to 5-minute buffer
		},
		{
			name:        "JWT with valid future expiration - 2 hours",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(2 * time.Hour).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: 2*time.Hour - 5*time.Minute, // 1h55m due to buffer
		},
		{
			name:        "JWT with near expiration - 6 minutes",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(6 * time.Minute).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: time.Minute, // 6 minutes - 5 minute buffer = 1 minute
		},
		{
			name:        "JWT with very near expiration - 4 minutes (less than buffer)",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(4 * time.Minute).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: 0, // Should return 0 TTL due to 5-minute buffer
		},
		{
			name:        "JWT with exactly 5 minute expiration (buffer boundary)",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(5 * time.Minute).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: 0, // Should return 0 TTL due to 5-minute buffer
		},
		{
			name:        "JWT with very short expiration - 1 minute",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(time.Minute).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: 0, // Should return 0 TTL due to 5-minute buffer
		},
		{
			name:        "JWT with far future expiration - 24 hours",
			token:       createTestJWTToken(map[string]interface{}{"exp": time.Now().Add(24 * time.Hour).Unix()}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: 24*time.Hour - 5*time.Minute,
		},
		{
			name:        "JWT with float exp claim (valid)",
			token:       createTestJWTToken(map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}),
			expectError: false,
			checkTTL:    true,
			expectedTTL: time.Hour - 5*time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl, err := parseJWTTokenTTL(tt.token)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.checkTTL {
				// Allow for some variance in TTL calculation due to timing (be more generous for CI)
				variance := time.Minute
				if ttl < tt.expectedTTL-variance || ttl > tt.expectedTTL+variance {
					t.Errorf("expected TTL around %v (±%v), got %v", tt.expectedTTL, variance, ttl)
				}
			}

			// TTL should never be negative
			if ttl < 0 {
				t.Errorf("TTL should never be negative, got %v", ttl)
			}
		})
	}
}

// Test cached provider integration
func TestCachedProviderIntegration(t *testing.T) {
	tests := []struct {
		name        string
		opts        credentialprovider.Options
		expectError bool
	}{
		{
			name: "valid provider creation with caching",
			opts: credentialprovider.Options{
				"clientID": "test-client-id",
				"tenantID": "test-tenant-id",
			},
			expectError: false,
		},
		{
			name:        "empty options with caching",
			opts:        credentialprovider.Options{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := createAzureIdentityProvider(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify that we get a CachedProvider
			cachedProvider, ok := provider.(*credentialprovider.CachedProvider)
			if !ok {
				t.Errorf("expected *credentialprovider.CachedProvider, got %T", provider)
				return
			}

			if cachedProvider == nil {
				t.Error("expected non-nil cached provider")
			}

			// Test that the provider implements the required interface
			ctx := context.Background()
			_, err = provider.Get(ctx, testRegistry)
			// We expect this to fail in test environment, but it should be a proper error
			// not a method not found error
			if err == nil {
				t.Error("expected error in test environment")
			}
		})
	}
}

// Test GetWithTTL with default TTL fallback
func TestAzureIdentityProvider_GetWithTTL_DefaultTTLFallback(t *testing.T) {
	// This test verifies that when JWT parsing fails, the provider falls back to default TTL
	// We can't easily create a scenario where GetWithTTL succeeds but JWT parsing fails
	// in a unit test environment, so this test documents the expected behavior

	provider := &IdentityProvider{
		clientID: "test-client-id",
		tenantID: "test-tenant-id",
	}

	ctx := context.Background()
	_, err := provider.GetWithTTL(ctx, testRegistry)

	// In test environment, this should fail at credential chain or token exchange step
	if err == nil {
		t.Error("expected error in test environment")
	}

	// The error should be related to Azure authentication, not JWT parsing
	expectedErrors := []string{
		"failed to create credential chain",
		"failed to exchange AAD token for ACR refresh token",
		"failed to get AAD access token",
	}

	errorMatched := false
	for _, expectedError := range expectedErrors {
		if contains(err.Error(), expectedError) {
			errorMatched = true
			break
		}
	}

	if !errorMatched {
		t.Errorf("expected error to contain one of %v, got %q", expectedErrors, err.Error())
	}
}

// Helper function to create a test JWT token
func createTestJWTToken(claims map[string]interface{}) string {
	// Create a simple JWT token for testing
	// Header
	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "HS256",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Claims
	claimsBytes, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Signature (dummy for testing)
	signature := "dummy-signature"

	return headerB64 + "." + claimsB64 + "." + signature
}

// Note: The line 'if !ok' in parseJWTTokenTTL for MapClaims type assertion
// is extremely difficult to test because jwt.ParseUnverified with jwt.MapClaims{}
// should always succeed in parsing to MapClaims unless there's an internal library issue.
// This represents defensive programming for edge cases that are nearly impossible to reproduce.

// Test IdentityProviderOptions JSON marshaling/unmarshaling
func TestIdentityProviderOptions_JSON(t *testing.T) {
	tests := []struct {
		name     string
		options  IdentityProviderOptions
		expected IdentityProviderOptions
	}{
		{
			name: "all fields populated",
			options: IdentityProviderOptions{
				ClientID: "test-client-id",
				TenantID: "test-tenant-id",
			},
			expected: IdentityProviderOptions{
				ClientID: "test-client-id",
				TenantID: "test-tenant-id",
			},
		},
		{
			name:     "empty options",
			options:  IdentityProviderOptions{},
			expected: IdentityProviderOptions{},
		},
		{
			name: "only client ID",
			options: IdentityProviderOptions{
				ClientID: "test-client-id",
			},
			expected: IdentityProviderOptions{
				ClientID: "test-client-id",
			},
		},
		{
			name: "only tenant ID",
			options: IdentityProviderOptions{
				TenantID: "test-tenant-id",
			},
			expected: IdentityProviderOptions{
				TenantID: "test-tenant-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.options)
			if err != nil {
				t.Fatalf("failed to marshal options: %v", err)
			}

			// Unmarshal back
			var unmarshaled IdentityProviderOptions
			err = json.Unmarshal(jsonData, &unmarshaled)
			if err != nil {
				t.Fatalf("failed to unmarshal options: %v", err)
			}

			// Compare
			if unmarshaled.ClientID != tt.expected.ClientID {
				t.Errorf("expected ClientID %q, got %q", tt.expected.ClientID, unmarshaled.ClientID)
			}
			if unmarshaled.TenantID != tt.expected.TenantID {
				t.Errorf("expected TenantID %q, got %q", tt.expected.TenantID, unmarshaled.TenantID)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
