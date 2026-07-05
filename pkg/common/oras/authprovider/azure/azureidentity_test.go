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
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	ratifyerrors "github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/pkg/common/oras/authprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock types for external dependencies
type MockManagedIdentityTokenGetter struct {
	mock.Mock
}

// Mock ManagedIdentityTokenGetter.GetManagedIdentityToken
func (m *MockManagedIdentityTokenGetter) GetManagedIdentityToken(ctx context.Context, clientID string) (azcore.AccessToken, error) {
	args := m.Called(ctx, clientID)
	return args.Get(0).(azcore.AccessToken), args.Error(1)
}

// Verifies that Enabled checks if tenantID is empty or AAD token is empty
func TestAzureMSIEnabled_ExpectedResults(t *testing.T) {
	azAuthProvider := MIAuthProvider{
		tenantID: "test_tenant",
		clientID: "test_client",
		identityToken: azcore.AccessToken{
			Token: "test_token",
		},
	}

	ctx := context.Background()

	if !azAuthProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned true but returned false")
	}

	azAuthProvider.tenantID = ""
	if azAuthProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned false but returned true for empty tenantID")
	}

	azAuthProvider.identityToken.Token = ""
	if azAuthProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned false but returned true for empty AAD access token")
	}
}

// Verifies that tenant id, client id, token file path, and authority host
// environment variables are properly set
func TestAzureMSIValidation_EnvironmentVariables_ExpectedResults(t *testing.T) {
	authProviderConfig := map[string]interface{}{
		"name": "azureManagedIdentity",
	}

	err := os.Setenv("AZURE_TENANT_ID", "")
	if err != nil {
		t.Fatal("failed to set env variable AZURE_TENANT_ID")
	}

	err = os.Setenv("AZURE_CLIENT_ID", "")
	if err != nil {
		t.Fatal("failed to set env variable AZURE_CLIENT_ID")
	}

	_, err = authprovider.CreateAuthProviderFromConfig(authProviderConfig)

	expectedErr := ratifyerrors.ErrorCodeAuthDenied.WithDetail("AZURE_TENANT_ID environment variable is empty")
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("create auth provider should have failed: expected err %s, but got err %s", expectedErr, err)
	}

	err = os.Setenv("AZURE_TENANT_ID", "tenant id")
	if err != nil {
		t.Fatal("failed to set env variable AZURE_TENANT_ID")
	}

	_, err = authprovider.CreateAuthProviderFromConfig(authProviderConfig)

	expectedErr = ratifyerrors.ErrorCodeAuthDenied.WithDetail("AZURE_CLIENT_ID environment variable is empty")
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("create auth provider should have failed: expected err %s, but got err %s", expectedErr, err)
	}
}

// Test for invalid configuration when tenant ID is missing
func TestAzureManagedIdentityProviderFactory_Create_NoTenantID(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")

	// Initialize factory
	factory := &azureManagedIdentityProviderFactory{}

	// Attempt to create MIAuthProvider with empty configuration
	_, err := factory.Create(map[string]interface{}{})

	// Validate the error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_TENANT_ID environment variable is empty")
}

// Test for missing client ID
func TestAzureManagedIdentityProviderFactory_Create_NoClientID(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "tenantID")
	t.Setenv("AZURE_CLIENT_ID", "")

	// Initialize factory
	factory := &azureManagedIdentityProviderFactory{}

	// Attempt to create MIAuthProvider with empty client ID
	_, err := factory.Create(map[string]interface{}{})

	// Validate the error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_CLIENT_ID environment variable is empty")
}

// Test successful token refresh
func TestMIAuthProvider_Provide_TokenRefreshSuccess(t *testing.T) {
	// Mock dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockManagedIdentityTokenGetter := new(MockManagedIdentityTokenGetter)
	mockAuthClient := new(MockAuthClient)

	// Define token values
	expiredToken := azcore.AccessToken{Token: "expired_token", ExpiresOn: time.Now().Add(-10 * time.Minute)}
	newTokenString := "refreshed"
	newAADToken := azcore.AccessToken{Token: "new_token", ExpiresOn: time.Now().Add(10 * time.Minute)}
	refreshToken := azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse{
		ACRRefreshToken: azcontainerregistry.ACRRefreshToken{RefreshToken: &newTokenString},
	}

	// Setup mock expectations
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockAuthClientFactory.On("CreateAuthClient", "https://example.azurecr.io", mock.Anything).Return(mockAuthClient, nil)
	mockAuthClient.On("ExchangeAADAccessTokenForACRRefreshToken", mock.Anything, azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken), "example.azurecr.io", mock.Anything).Return(refreshToken, nil)
	mockManagedIdentityTokenGetter.On("GetManagedIdentityToken", mock.Anything, "clientID").Return(newAADToken, nil)

	// Initialize provider with expired token
	provider := MIAuthProvider{
		identityToken:           expiredToken,
		clientID:                "clientID",
		tenantID:                "tenantID",
		authClientFactory:       mockAuthClientFactory,
		registryHostGetter:      mockRegistryHostGetter,
		getManagedIdentityToken: mockManagedIdentityTokenGetter,
		endpoints:               []string{"example.azurecr.io"},
	}

	// Call Provide method
	ctx := context.Background()
	authConfig, err := provider.Provide(ctx, "artifact_name")

	// Validate success and token refresh
	assert.NoError(t, err)
	assert.Equal(t, "refreshed", authConfig.Password)
}

// Test failed token refresh
func TestMIAuthProvider_Provide_TokenRefreshFailure(t *testing.T) {
	// Mock dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockManagedIdentityTokenGetter := new(MockManagedIdentityTokenGetter)

	// Define token values
	expiredToken := azcore.AccessToken{Token: "expired_token", ExpiresOn: time.Now().Add(-10 * time.Minute)}

	// Setup mock expectations
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockManagedIdentityTokenGetter.On("GetManagedIdentityToken", mock.Anything, "clientID").Return(azcore.AccessToken{}, errors.New("token refresh failed"))

	// Initialize provider with expired token
	provider := MIAuthProvider{
		identityToken:           expiredToken,
		clientID:                "clientID",
		tenantID:                "tenantID",
		authClientFactory:       mockAuthClientFactory,
		registryHostGetter:      mockRegistryHostGetter,
		getManagedIdentityToken: mockManagedIdentityTokenGetter,
		endpoints:               []string{"example.azurecr.io"},
	}

	// Call Provide method
	ctx := context.Background()
	_, err := provider.Provide(ctx, "artifact_name")

	// Validate failure
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not refresh azure managed identity token")
}

// Test for invalid hostname retrieval
func TestMIAuthProvider_Provide_InvalidHostName(t *testing.T) {
	// Mock dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockManagedIdentityTokenGetter := new(MockManagedIdentityTokenGetter)

	// Define valid token
	validToken := azcore.AccessToken{Token: "valid_token", ExpiresOn: time.Now().Add(10 * time.Minute)}

	// Setup mock expectations for invalid hostname
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("", errors.New("invalid hostname"))

	// Initialize provider with valid token
	provider := MIAuthProvider{
		identityToken:           validToken,
		clientID:                "clientID",
		tenantID:                "tenantID",
		authClientFactory:       mockAuthClientFactory,
		registryHostGetter:      mockRegistryHostGetter,
		getManagedIdentityToken: mockManagedIdentityTokenGetter,
	}

	// Call Provide method
	ctx := context.Background()
	_, err := provider.Provide(ctx, "artifact_name")

	// Validate failure
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HOST_NAME_INVALID")
}

// Unit tests
func TestGetManagedIdentityToken(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"
	expectedToken := azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}

	mockGetter := new(MockManagedIdentityTokenGetter)
	mockGetter.On("GetManagedIdentityToken", ctx, clientID).Return(expectedToken, nil)

	token, err := mockGetter.GetManagedIdentityToken(ctx, clientID)
	assert.Nil(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestGetManagedIdentityToken_Error(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"

	// Mock the newCredentialFunc to return an error
	mockNewCredentialFunc := func(_ *azidentity.ManagedIdentityCredentialOptions) (*azidentity.ManagedIdentityCredential, error) {
		return nil, assert.AnError
	}

	token, err := getManagedIdentityToken(ctx, clientID, mockNewCredentialFunc)
	assert.NotNil(t, err)
	assert.Equal(t, azcore.AccessToken{}, token)
}

// TestMIAuthProvider_Create_InitializesRegistryHostGetter verifies that the
// factory function initializes registryHostGetter, preventing nil pointer
// dereference panics in Provide(). See https://github.com/notaryproject/ratify/issues/2504
func TestMIAuthProvider_Create_InitializesRegistryHostGetter(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "test-tenant")
	t.Setenv("AZURE_CLIENT_ID", "test-client")

	// Mock the token acquisition to avoid real Azure calls in CI
	originalFunc := getManagedIdentityTokenFunc
	getManagedIdentityTokenFunc = func(_ context.Context, _ string, _ func(opts *azidentity.ManagedIdentityCredentialOptions) (*azidentity.ManagedIdentityCredential, error)) (azcore.AccessToken, error) {
		return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(1 * time.Hour)}, nil
	}
	defer func() { getManagedIdentityTokenFunc = originalFunc }()

	factory := &azureManagedIdentityProviderFactory{}
	p, err := factory.Create(authprovider.AuthProviderConfig{})
	assert.NoError(t, err)
	assert.NotNil(t, p)

	miProvider, ok := p.(*MIAuthProvider)
	assert.True(t, ok)
	assert.NotNil(t, miProvider.registryHostGetter, "registryHostGetter must be initialized to prevent nil pointer panic in Provide()")
}
