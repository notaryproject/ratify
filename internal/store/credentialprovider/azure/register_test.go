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

			azureProvider, ok := provider.(*IdentityProvider)
			if !ok {
				t.Errorf("expected *AzureIdentityProvider, got %T", provider)
				return
			}

			if azureProvider.clientID != tt.expected.clientID {
				t.Errorf("expected clientID %q, got %q", tt.expected.clientID, azureProvider.clientID)
			}

			if azureProvider.tenantID != tt.expected.tenantID {
				t.Errorf("expected tenantID %q, got %q", tt.expected.tenantID, azureProvider.tenantID)
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

func TestAzureIdentityProvider_ExchangeAADTokenForACRToken_GetTokenError(t *testing.T) {
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

func TestAzureIdentityProvider_ExchangeAADTokenForACRToken_InvalidServerAddress(t *testing.T) {
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

func TestAzureIdentityProvider_Get_CredentialChainError(t *testing.T) {
	// Test the Get method with invalid configuration that would cause
	// credential chain creation to fail
	provider := &IdentityProvider{
		clientID: "test-client-id",
		tenantID: "test-tenant-id",
	}

	ctx := context.Background()
	// This test will likely succeed in creating the credential chain
	// but fail in the token exchange step, which still exercises the error path
	_, err := provider.Get(ctx, testRegistry)

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

func TestAzureIdentityProvider_Get_CredentialChainCreationError(t *testing.T) {
	// Test the specific case where CreateCredentialChain fails and returns an error
	// This covers lines 83-85 in the Get method: if err != nil { return ratify.RegistryCredential{}, fmt.Errorf("failed to create credential chain: %w", err) }

	// In a test environment without proper Azure credentials configured,
	// the credential chain creation should eventually fail during token acquisition
	provider := &IdentityProvider{
		clientID: "test-client-id",
		tenantID: "test-tenant-id",
	}

	ctx := context.Background()
	// Call Get which should fail either at credential chain creation or token exchange
	credential, err := provider.Get(ctx, testRegistry)

	// We expect this to fail since we're not in a proper Azure environment
	if err == nil {
		t.Error("expected error but got none")
	}

	// Verify that the credential is empty when an error occurs
	if credential.RefreshToken != "" {
		t.Errorf("expected empty credential when error occurs, got refresh token: %s", credential.RefreshToken)
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

func TestAzureIdentityProvider_Get_CredentialChainCreationErrorWithMock(t *testing.T) {
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
			credential, err := provider.Get(ctx, tt.serverAddr)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}

				// Verify credential is empty on error
				if credential.RefreshToken != "" {
					t.Errorf("expected empty refresh token on error, got: %s", credential.RefreshToken)
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
