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
	"os"
	"time"

	re "github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/internal/logger"
	provider "github.com/ratify-project/ratify/pkg/common/oras/authprovider"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
)

// ManagedIdentityTokenGetter defines an interface for getting a managed identity token.
type ManagedIdentityTokenGetter interface {
	GetManagedIdentityToken(ctx context.Context, clientID string) (azcore.AccessToken, error)
}

// defaultManagedIdentityTokenGetterImpl is the default implementation of getManagedIdentityToken.
type defaultManagedIdentityTokenGetterImpl struct{}

func (g *defaultManagedIdentityTokenGetterImpl) GetManagedIdentityToken(ctx context.Context, clientID string) (azcore.AccessToken, error) {
	return getManagedIdentityToken(ctx, clientID, azidentity.NewManagedIdentityCredential)
}

// getManagedIdentityTokenFunc is a package-level variable to allow test injection.
var getManagedIdentityTokenFunc = getManagedIdentityToken

func getManagedIdentityToken(ctx context.Context, clientID string, newCredentialFunc func(opts *azidentity.ManagedIdentityCredentialOptions) (*azidentity.ManagedIdentityCredential, error)) (azcore.AccessToken, error) {
	id := azidentity.ClientID(clientID)
	opts := azidentity.ManagedIdentityCredentialOptions{ID: id}
	cred, err := newCredentialFunc(&opts)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	scopes := []string{AADResource}
	if cred != nil {
		return cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
	}
	return azcore.AccessToken{}, re.ErrorCodeConfigInvalid.WithComponentType(re.AuthProvider).WithDetail("config is nil pointer for GetServicePrincipalToken")
}

type azureManagedIdentityProviderFactory struct{}

type MIAuthProvider struct {
	identityToken           azcore.AccessToken
	clientID                string
	tenantID                string
	authClientFactory       AuthClientFactory
	registryHostGetter      RegistryHostGetter
	getManagedIdentityToken ManagedIdentityTokenGetter
	endpoints               []string
}

type azureManagedIdentityAuthProviderConf struct {
	Name      string   `json:"name"`
	ClientID  string   `json:"clientID"`
	Endpoints []string `json:"endpoints,omitempty"`
}

const (
	azureManagedIdentityAuthProviderName string = "azureManagedIdentity"
)

// init calls Register for our Azure Workload Identity provider
func init() {
	provider.Register(azureManagedIdentityAuthProviderName, &azureManagedIdentityProviderFactory{})
}

// Create returns an MIAuthProvider
func (s *azureManagedIdentityProviderFactory) Create(authProviderConfig provider.AuthProviderConfig) (provider.AuthProvider, error) {
	conf := azureManagedIdentityAuthProviderConf{}
	authProviderConfigBytes, err := json.Marshal(authProviderConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
	}

	if err := json.Unmarshal(authProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.AzureManagedIdentityLink, err, "failed to parse azure managed identity auth provider configuration.", re.HideStackTrace)
	}

	tenant := os.Getenv("AZURE_TENANT_ID")
	if tenant == "" {
		return nil, re.ErrorCodeEnvNotSet.WithDetail("AZURE_TENANT_ID environment variable is empty").WithComponentType(re.AuthProvider)
	}
	client := os.Getenv("AZURE_CLIENT_ID")
	if client == "" {
		client = conf.ClientID
		if client == "" {
			return nil, re.ErrorCodeEnvNotSet.WithDetail("AZURE_CLIENT_ID environment variable is empty").WithComponentType(re.AuthProvider)
		}
	}

	endpoints, err := parseEndpoints(conf.Endpoints)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithError(err)
	}

	// retrieve an AAD Access token
	token, err := getManagedIdentityTokenFunc(context.Background(), client, azidentity.NewManagedIdentityCredential)
	if err != nil {
		return nil, re.ErrorCodeAuthDenied.NewError(re.AuthProvider, "", re.AzureManagedIdentityLink, err, "", re.HideStackTrace)
	}

	return &MIAuthProvider{
		identityToken:           token,
		clientID:                client,
		tenantID:                tenant,
		authClientFactory:       &defaultAuthClientFactoryImpl{},          // Concrete implementation
		registryHostGetter:      &defaultRegistryHostGetterImpl{},         // Concrete implementation
		getManagedIdentityToken: &defaultManagedIdentityTokenGetterImpl{}, // Concrete implementation
		endpoints:               endpoints,
	}, nil
}

// Enabled checks for non empty tenant ID and AAD access token
func (d *MIAuthProvider) Enabled(_ context.Context) bool {
	if d.clientID == "" {
		return false
	}

	if d.tenantID == "" {
		return false
	}

	if d.identityToken.Token == "" {
		return false
	}

	return true
}

// Provide returns the credentials for a specified artifact.
// Uses Managed Identity to retrieve an AAD access token which can be
// exchanged for a valid ACR refresh token for login.
func (d *MIAuthProvider) Provide(ctx context.Context, artifact string) (provider.AuthConfig, error) {
	if !d.Enabled(ctx) {
		return provider.AuthConfig{}, fmt.Errorf("azure managed identity provider is not properly enabled")
	}

	// parse the artifact reference string to extract the registry host name
	artifactHostName, err := d.registryHostGetter.GetRegistryHost(artifact)
	if err != nil {
		return provider.AuthConfig{}, re.ErrorCodeHostNameInvalid.WithComponentType(re.AuthProvider)
	}

	if err := validateHost(artifactHostName, d.endpoints); err != nil {
		return provider.AuthConfig{}, re.ErrorCodeHostNameInvalid.WithError(err)
	}

	// need to refresh AAD token if it's expired
	if time.Now().Add(time.Minute * 5).After(d.identityToken.ExpiresOn) {
		newToken, err := d.getManagedIdentityToken.GetManagedIdentityToken(ctx, d.clientID)
		if err != nil {
			return provider.AuthConfig{}, re.ErrorCodeAuthDenied.NewError(re.AuthProvider, "", re.AzureManagedIdentityLink, err, "could not refresh azure managed identity token", re.HideStackTrace)
		}
		d.identityToken = newToken
		logger.GetLogger(ctx, logOpt).Info("successfully refreshed azure managed identity token")
	}

	// add protocol to generate complete URI
	serverURL := "https://" + artifactHostName

	// TODO: Consider adding authentication client options for multicloud scenarios
	var options *azcontainerregistry.AuthenticationClientOptions
	client, err := d.authClientFactory.CreateAuthClient(serverURL, options)
	if err != nil {
		return provider.AuthConfig{}, re.ErrorCodeAuthDenied.WithError(err).WithDetail("failed to create authentication client for container registry by azure managed identity token")
	}

	response, err := client.ExchangeAADAccessTokenForACRRefreshToken(
		ctx,
		azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken),
		artifactHostName,
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: &d.identityToken.Token,
			Tenant:      &d.tenantID,
		},
	)
	if err != nil {
		return provider.AuthConfig{}, re.ErrorCodeAuthDenied.NewError(re.AuthProvider, "", re.AzureManagedIdentityLink, err, "failed to get refresh token for container registry by azure managed identity token", re.HideStackTrace)
	}
	rt := response.ACRRefreshToken

	refreshTokenExpiry := getACRExpiryIfEarlier(d.identityToken.ExpiresOn)
	authConfig := provider.AuthConfig{
		Username:  dockerTokenLoginUsernameGUID,
		Password:  *rt.RefreshToken,
		Provider:  d,
		ExpiresOn: refreshTokenExpiry,
	}

	return authConfig, nil
}
