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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/cloudprovider/azure"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

const (
	// GrantTypeAccessToken is the grant type for AAD access token
	GrantTypeAccessToken = "access_token"

	// AADResource is the Azure Container Registry resource scope
	AADResource = "https://containerregistry.azure.net/.default"
)

// IdentityProvider is an implementation of [ratify.RegistryCredentialGetter]
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
	return &IdentityProvider{
		clientID: azureOpts.ClientID,
		tenantID: azureOpts.TenantID,
	}, nil
}

// Get retrieves the registry credentials from Azure.
func (p *IdentityProvider) Get(ctx context.Context, serverAddress string) (ratify.RegistryCredential, error) {
	// Step 1: Create a ChainedTokenCredential in the order: workload identity,
	// managed identity.
	chain, err := azure.CreateCredentialChain(p.clientID, p.tenantID)
	if err != nil {
		return ratify.RegistryCredential{}, fmt.Errorf("failed to create credential chain: %w", err)
	}

	// Step 2: Exchange an AAD token for an ACR refresh token using ExchangeAADAccessTokenForACRRefreshToken
	acrRefreshToken, err := p.exchangeAADTokenForACRToken(ctx, chain, serverAddress)
	if err != nil {
		return ratify.RegistryCredential{}, fmt.Errorf("failed to exchange AAD token for ACR refresh token: %w", err)
	}

	// Step 3: Create a ratify.RegistryCredential from the ACR token
	return ratify.RegistryCredential{
		RefreshToken: acrRefreshToken,
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
