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
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/golang-jwt/jwt/v5"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/cloudprovider/azure"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

const (
	// GrantTypeAccessToken is the grant type for AAD access token
	GrantTypeAccessToken = "access_token"

	// AADResource is the Azure Container Registry resource scope
	AADResource = "https://containerregistry.azure.net/.default"

	// DefaultACRTokenTTL is the default TTL for ACR refresh tokens
	// ACR refresh tokens typically expire in 3 hours, we set a shorter TTL for safety
	DefaultACRTokenTTL = 3*time.Hour - 5*time.Minute
)

// IdentityProvider is an implementation of [credentialprovider.CredentialSourceProvider]
// that retrieves credentials from Azure Container Registry.
type IdentityProvider struct {
	clientID string
	tenantID string
}

// IdentityProviderOptions contains configuration options for the Azure identity
// provider.
type IdentityProviderOptions struct {
	// ClientID is the Azure AD client ID (application ID) for user-assigned
	// managed identity or service principal authentication
	ClientID string `json:"clientID,omitempty"`
	// TenantID is the Azure AD tenant ID where the application is registered
	TenantID string `json:"tenantID,omitempty"`
}

func init() {
	// Register the Azure identity provider factory
	credentialprovider.RegisterCredentialProviderFactory("azure", createAzureIdentityProvider)
}

// createAzureIdentityProvider creates a new Azure identity provider from
// CredentialProviderOptions
func createAzureIdentityProvider(opts credentialprovider.Options) (ratify.RegistryCredentialGetter, error) {
	// Marshal and unmarshal to convert to our expected structure
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	var azureOpts IdentityProviderOptions
	if err := json.Unmarshal(raw, &azureOpts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Create the Azure identity provider with the configuration
	azureProvider := &IdentityProvider{
		clientID: azureOpts.ClientID,
		tenantID: azureOpts.TenantID,
	}

	// Wrap with caching provider
	return credentialprovider.NewCachedProvider(azureProvider)
}

// GetWithTTL implements credentialprovider.CredentialSourceProvider interface.
// It retrieves the registry credentials from Azure with TTL information.
func (p *IdentityProvider) GetWithTTL(ctx context.Context, serverAddress string) (credentialprovider.CredentialWithTTL, error) {
	// Step 1: Create a ChainedTokenCredential in the order: workload identity,
	// managed identity.
	chain, err := azure.CreateCredentialChain(p.clientID, p.tenantID)
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("failed to create credential chain: %w", err)
	}

	// Step 2: Exchange an AAD token for an ACR refresh token using ExchangeAADAccessTokenForACRRefreshToken
	acrRefreshToken, err := p.exchangeAADTokenForACRToken(ctx, chain, serverAddress)
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("failed to exchange AAD token for ACR refresh token: %w", err)
	}

	// Step 3: Parse the JWT token to extract the actual TTL
	ttl, err := parseJWTTokenTTL(acrRefreshToken)
	if err != nil {
		// If JWT parsing fails, fall back to the default TTL
		ttl = DefaultACRTokenTTL
	}

	return credentialprovider.CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			RefreshToken: acrRefreshToken,
		},
		TTL: ttl,
	}, nil
}

// exchangeAADTokenForACRToken exchanges an AAD access token for an ACR refresh
// token.
func (p *IdentityProvider) exchangeAADTokenForACRToken(ctx context.Context, credential azcore.TokenCredential, serverAddress string) (string, error) {
	// Get an AAD access token
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{AADResource},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get AAD access token: %w", err)
	}

	// Create ACR authentication client
	serverURL := "https://" + serverAddress
	client, err := azcontainerregistry.NewAuthenticationClient(serverURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create ACR authentication client: %w", err)
	}

	// Exchange AAD token for ACR refresh token
	response, err := client.ExchangeAADAccessTokenForACRRefreshToken(
		ctx,
		azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken),
		serverAddress,
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: &token.Token,
			Tenant:      &p.tenantID,
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to exchange AAD token for ACR refresh token: %w", err)
	}

	if response.RefreshToken == nil {
		return "", fmt.Errorf("received nil refresh token from ACR")
	}

	return *response.RefreshToken, nil
}

// parseJWTTokenTTL parses a JWT token and extracts the TTL based on the exp
// claim.
func parseJWTTokenTTL(token string) (time.Duration, error) {
	// Parse the JWT token without verification since we only need the claims
	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return 0, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("failed to extract claims from JWT token")
	}

	expTime, err := claims.GetExpirationTime()
	if err != nil {
		return 0, fmt.Errorf("failed to get expiration time from JWT token: %w", err)
	}
	if expTime == nil {
		return 0, fmt.Errorf("JWT token does not contain exp claim")
	}

	// Convert exp (Unix timestamp) to time and calculate TTL
	now := time.Now()

	// If token is already expired, return 0 TTL
	if expTime.Before(now) {
		return 0, fmt.Errorf("JWT token has already expired")
	}

	// Calculate TTL with a small buffer (subtract 1 minute for safety)
	ttl := expTime.Sub(now) - 5*time.Minute
	if ttl < 0 {
		ttl = 0
	}

	return ttl, nil
}
