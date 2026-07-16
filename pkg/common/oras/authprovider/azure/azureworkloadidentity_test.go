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

	ratifyerrors "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	azcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// MockAADAccessTokenGetter for retrieving AAD access token
type MockAADAccessTokenGetter struct {
	mock.Mock
}

func (m *MockAADAccessTokenGetter) GetAADAccessToken(ctx context.Context, tenantID, clientID, resource string) (confidential.AuthResult, error) {
	args := m.Called(ctx, tenantID, clientID, resource)
	return args.Get(0).(confidential.AuthResult), args.Error(1)
}

// MockMetricsReporter for reporting metrics
type MockMetricsReporter struct {
	mock.Mock
}

func (m *MockMetricsReporter) ReportMetrics(ctx context.Context, duration int64, artifactHostName string) {
	m.Called(ctx, duration, artifactHostName)
}

// Test for successful Provide function
func TestWIAuthProvider_Provide_Success(t *testing.T) {
	// Mock all dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockAADAccessTokenGetter := new(MockAADAccessTokenGetter)
	mockMetricsReporter := new(MockMetricsReporter)
	mockAuthClient := new(MockAuthClient)

	// Mock AAD token
	initialToken := confidential.AuthResult{AccessToken: "initial_token", ExpiresOn: time.Now().Add(10 * time.Minute)}
	refreshTokenString := "new_refresh_token"
	refreshToken := azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse{
		ACRRefreshToken: azcontainerregistry.ACRRefreshToken{RefreshToken: &refreshTokenString},
	}

	// Set expectations for mocked functions
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockAuthClientFactory.On("CreateAuthClient", "https://example.azurecr.io", mock.Anything).Return(mockAuthClient, nil)
	mockAuthClient.On("ExchangeAADAccessTokenForACRRefreshToken", mock.Anything, azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken), "example.azurecr.io", mock.Anything).Return(refreshToken, nil)
	mockAADAccessTokenGetter.On("GetAADAccessToken", mock.Anything, "tenantID", "clientID", mock.Anything).Return(initialToken, nil)
	mockMetricsReporter.On("ReportMetrics", mock.Anything, mock.Anything, "example.azurecr.io").Return()

	// Create WIAuthProvider
	provider := WIAuthProvider{
		aadToken:           initialToken,
		tenantID:           "tenantID",
		clientID:           "clientID",
		authClientFactory:  mockAuthClientFactory,
		registryHostGetter: mockRegistryHostGetter,
		getAADAccessToken:  mockAADAccessTokenGetter,
		reportMetrics:      mockMetricsReporter,
	}

	// Call Provide method
	ctx := context.Background()
	authConfig, err := provider.Provide(ctx, "artifact_name")

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "new_refresh_token", authConfig.Password)
}

// Test for AAD token refresh logic
func TestWIAuthProvider_Provide_RefreshToken(t *testing.T) {
	// Mock all dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockAADAccessTokenGetter := new(MockAADAccessTokenGetter)
	mockMetricsReporter := new(MockMetricsReporter)
	mockAuthClient := new(MockAuthClient)

	// Mock expired AAD token, and refreshed token
	expiredToken := confidential.AuthResult{AccessToken: "expired_token", ExpiresOn: time.Now().Add(-10 * time.Minute)}
	newToken := confidential.AuthResult{AccessToken: "new_token", ExpiresOn: time.Now().Add(10 * time.Minute)}
	refreshTokenString := "refreshed_token"
	refreshToken := azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse{
		ACRRefreshToken: azcontainerregistry.ACRRefreshToken{RefreshToken: &refreshTokenString},
	}

	// Set expectations for mocked functions
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockAuthClientFactory.On("CreateAuthClient", "https://example.azurecr.io", mock.Anything).Return(mockAuthClient, nil)
	mockAuthClient.On("ExchangeAADAccessTokenForACRRefreshToken", mock.Anything, azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken), "example.azurecr.io", mock.Anything).Return(refreshToken, nil)
	mockAADAccessTokenGetter.On("GetAADAccessToken", mock.Anything, "tenantID", "clientID", mock.Anything).Return(newToken, nil)
	mockMetricsReporter.On("ReportMetrics", mock.Anything, mock.Anything, "example.azurecr.io").Return()

	// Create WIAuthProvider with expired token
	provider := WIAuthProvider{
		aadToken:           expiredToken,
		tenantID:           "tenantID",
		clientID:           "clientID",
		authClientFactory:  mockAuthClientFactory,
		registryHostGetter: mockRegistryHostGetter,
		getAADAccessToken:  mockAADAccessTokenGetter,
		reportMetrics:      mockMetricsReporter,
	}

	// Call Provide method
	ctx := context.Background()
	authConfig, err := provider.Provide(ctx, "artifact_name")

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "refreshed_token", authConfig.Password)
}

// Test for failure when GetAADAccessToken fails
func TestWIAuthProvider_Provide_AADTokenFailure(t *testing.T) {
	// Mock all dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockAADAccessTokenGetter := new(MockAADAccessTokenGetter)
	mockMetricsReporter := new(MockMetricsReporter)

	// Mock expired AAD token, and failure to refresh
	expiredToken := confidential.AuthResult{AccessToken: "expired_token", ExpiresOn: time.Now().Add(-10 * time.Minute)}

	// Set expectations for mocked functions
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockAADAccessTokenGetter.On("GetAADAccessToken", mock.Anything, "tenantID", "clientID", mock.Anything).Return(confidential.AuthResult{}, errors.New("token refresh failed"))

	// Create WIAuthProvider with expired token
	provider := WIAuthProvider{
		aadToken:           expiredToken,
		tenantID:           "tenantID",
		clientID:           "clientID",
		authClientFactory:  mockAuthClientFactory,
		registryHostGetter: mockRegistryHostGetter,
		getAADAccessToken:  mockAADAccessTokenGetter,
		reportMetrics:      mockMetricsReporter,
	}

	// Call Provide method
	ctx := context.Background()
	_, err := provider.Provide(ctx, "artifact_name")

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not refresh AAD token")
}

// Test when tenant ID is missing from the environment
func TestAzureWIProviderFactory_Create_NoTenantID(t *testing.T) {
	// Clear the tenant ID environment variable
	t.Setenv("AZURE_TENANT_ID", "")

	// Initialize provider factory
	factory := &AzureWIProviderFactory{}

	// Call Create with minimal configuration
	_, err := factory.Create(map[string]interface{}{})

	// Expect error related to missing tenant ID
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "azure tenant id environment variable is empty")
}

// Test when client ID is missing from the environment
func TestAzureWIProviderFactory_Create_NoClientID(t *testing.T) {
	// Set tenant ID but leave client ID empty
	t.Setenv("AZURE_TENANT_ID", "tenantID")
	t.Setenv("AZURE_CLIENT_ID", "")

	// Initialize provider factory
	factory := &AzureWIProviderFactory{}

	// Call Create with minimal configuration
	_, err := factory.Create(map[string]interface{}{})

	// Expect error related to missing client ID
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no client ID provided and AZURE_CLIENT_ID environment variable is empty")
}

// Test for successful token refresh
func TestWIAuthProvider_Provide_TokenRefresh_Success(t *testing.T) {
	// Mock dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockAADAccessTokenGetter := new(MockAADAccessTokenGetter)
	mockMetricsReporter := new(MockMetricsReporter)
	mockAuthClient := new(MockAuthClient)

	// Mock expired AAD token and refreshed token
	expiredToken := confidential.AuthResult{AccessToken: "expired_token", ExpiresOn: time.Now().Add(-10 * time.Minute)}
	refreshTokenString := "refreshed_token"
	newToken := confidential.AuthResult{AccessToken: "new_token", ExpiresOn: time.Now().Add(10 * time.Minute)}
	refreshToken := azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse{
		ACRRefreshToken: azcontainerregistry.ACRRefreshToken{RefreshToken: &refreshTokenString},
	}

	// Set expectations
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockAuthClientFactory.On("CreateAuthClient", "https://example.azurecr.io", mock.Anything).Return(mockAuthClient, nil)
	mockAuthClient.On("ExchangeAADAccessTokenForACRRefreshToken", mock.Anything, azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken), "example.azurecr.io", mock.Anything).Return(refreshToken, nil)
	mockAADAccessTokenGetter.On("GetAADAccessToken", mock.Anything, "tenantID", "clientID", mock.Anything).Return(newToken, nil)
	mockMetricsReporter.On("ReportMetrics", mock.Anything, mock.Anything, "example.azurecr.io").Return()

	// Create WIAuthProvider with expired token
	provider := WIAuthProvider{
		aadToken:           expiredToken,
		tenantID:           "tenantID",
		clientID:           "clientID",
		authClientFactory:  mockAuthClientFactory,
		registryHostGetter: mockRegistryHostGetter,
		getAADAccessToken:  mockAADAccessTokenGetter,
		reportMetrics:      mockMetricsReporter,
	}

	// Call Provide method
	ctx := context.Background()
	authConfig, err := provider.Provide(ctx, "artifact_name")

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "refreshed_token", authConfig.Password)
}

// Test when token refresh fails
func TestWIAuthProvider_Provide_TokenRefreshFailure(t *testing.T) {
	// Mock dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockAADAccessTokenGetter := new(MockAADAccessTokenGetter)
	mockMetricsReporter := new(MockMetricsReporter)

	// Mock expired AAD token and failure to refresh
	expiredToken := confidential.AuthResult{AccessToken: "expired_token", ExpiresOn: time.Now().Add(-10 * time.Minute)}

	// Set expectations
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("example.azurecr.io", nil)
	mockAADAccessTokenGetter.On("GetAADAccessToken", mock.Anything, "tenantID", "clientID", mock.Anything).Return(confidential.AuthResult{}, errors.New("token refresh failed"))

	// Create WIAuthProvider with expired token
	provider := WIAuthProvider{
		aadToken:           expiredToken,
		tenantID:           "tenantID",
		clientID:           "clientID",
		authClientFactory:  mockAuthClientFactory,
		registryHostGetter: mockRegistryHostGetter,
		getAADAccessToken:  mockAADAccessTokenGetter,
		reportMetrics:      mockMetricsReporter,
	}

	// Call Provide method
	ctx := context.Background()
	_, err := provider.Provide(ctx, "artifact_name")

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not refresh AAD token")
}

// Test for handling empty AccessToken
func TestWIAuthProvider_Enabled_NoAccessToken(t *testing.T) {
	// Create a provider with no AccessToken
	provider := WIAuthProvider{
		tenantID: "tenantID",
		clientID: "clientID",
		aadToken: confidential.AuthResult{AccessToken: ""},
	}

	// Assert that provider is not enabled
	enabled := provider.Enabled(context.Background())
	assert.False(t, enabled)
}

// Test for invalid hostname retrieval
func TestWIAuthProvider_Provide_InvalidHostName(t *testing.T) {
	// Mock dependencies
	mockAuthClientFactory := new(MockAuthClientFactory)
	mockRegistryHostGetter := new(MockRegistryHostGetter)
	mockAADAccessTokenGetter := new(MockAADAccessTokenGetter)
	mockMetricsReporter := new(MockMetricsReporter)

	// Mock valid AAD token
	validToken := confidential.AuthResult{AccessToken: "valid_token", ExpiresOn: time.Now().Add(10 * time.Minute)}

	// Set expectations for an invalid hostname
	mockRegistryHostGetter.On("GetRegistryHost", "artifact_name").Return("", errors.New("invalid hostname"))

	// Create WIAuthProvider with valid token
	provider := WIAuthProvider{
		aadToken:           validToken,
		tenantID:           "tenantID",
		clientID:           "clientID",
		authClientFactory:  mockAuthClientFactory,
		registryHostGetter: mockRegistryHostGetter,
		getAADAccessToken:  mockAADAccessTokenGetter,
		reportMetrics:      mockMetricsReporter,
	}

	// Call Provide method
	ctx := context.Background()
	_, err := provider.Provide(ctx, "artifact_name")

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HOST_NAME_INVALID")
}

// Verifies that Enabled checks if tenantID is empty or AAD token is empty
func TestAzureWIEnabled_ExpectedResults(t *testing.T) {
	azAuthProvider := WIAuthProvider{
		tenantID: "test_tenant",
		clientID: "test_client",
		aadToken: confidential.AuthResult{
			AccessToken: "test_token",
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

	azAuthProvider.clientID = ""
	if azAuthProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned false but returned true for empty clientID")
	}

	azAuthProvider.aadToken.AccessToken = ""
	if azAuthProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned false but returned true for empty AAD access token")
	}
}

func TestGetEarliestExpiration(t *testing.T) {
	var aadExpiry = time.Now().Add(12 * time.Hour)

	if getACRExpiryIfEarlier(aadExpiry).Equal(aadExpiry) {
		t.Fatal("expected acr token expiry time")
	}

	aadExpiry = time.Now().Add(12 * time.Minute)

	if getACRExpiryIfEarlier(aadExpiry) != aadExpiry {
		t.Fatal("expected aad token expiry time")
	}
}

// Verifies that tenant id, client id, token file path, and authority host
// environment variables are properly set
func TestAzureWIValidation_EnvironmentVariables_ExpectedResults(t *testing.T) {
	authProviderConfig := map[string]interface{}{
		"name": "azureWorkloadIdentity",
	}

	err := os.Setenv("AZURE_TENANT_ID", "")
	if err != nil {
		t.Fatal("failed to set env variable AZURE_TENANT_ID")
	}

	_, err = authprovider.CreateAuthProviderFromConfig(authProviderConfig)

	expectedErr := ratifyerrors.ErrorCodeAuthDenied.WithDetail("azure tenant id environment variable is empty")
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("create auth provider should have failed: expected err %s, but got err %s", expectedErr, err)
	}

	err = os.Setenv("AZURE_TENANT_ID", "tenant id")
	if err != nil {
		t.Fatal("failed to set env variable AZURE_TENANT_ID")
	}

	authProviderConfigWithClientID := map[string]interface{}{
		"name":     "azureWorkloadIdentity",
		"clientID": "client id from config",
	}

	_, err = authprovider.CreateAuthProviderFromConfig(authProviderConfigWithClientID)

	expectedErr = ratifyerrors.ErrorCodeAuthDenied.WithDetail("required environment variables not set, AZURE_FEDERATED_TOKEN_FILE: , AZURE_AUTHORITY_HOST: ")
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("create auth provider should have failed: expected err %s, but got err %s", expectedErr, err)
	}

	_, err = authprovider.CreateAuthProviderFromConfig(authProviderConfig)

	expectedErr = ratifyerrors.ErrorCodeAuthDenied.WithDetail("no client ID provided and AZURE_CLIENT_ID environment variable is empty")
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("create auth provider should have failed: expected err %s, but got err %s", expectedErr, err)
	}

	err = os.Setenv("AZURE_CLIENT_ID", "client id")
	if err != nil {
		t.Fatal("failed to set env variable AZURE_CLIENT_ID")
	}

	defer os.Unsetenv("AZURE_CLIENT_ID")
	defer os.Unsetenv("AZURE_TENANT_ID")

	_, err = authprovider.CreateAuthProviderFromConfig(authProviderConfig)

	expectedErr = ratifyerrors.ErrorCodeAuthDenied.WithDetail("required environment variables not set, AZURE_FEDERATED_TOKEN_FILE: , AZURE_AUTHORITY_HOST: ")
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("create auth provider should have failed: expected err %s, but got err %s", expectedErr, err)
	}
}
