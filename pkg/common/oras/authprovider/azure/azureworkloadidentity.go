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
	"os"
	"time"

	azcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	provider "github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider"
	"github.com/notaryproject/ratify/v2/pkg/utils/azureauth"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// AADAccessTokenGetter defines an interface for getting an AAD access token.
type AADAccessTokenGetter interface {
	GetAADAccessToken(ctx context.Context, tenantID, clientID, resource string) (confidential.AuthResult, error)
}

// defaultAADAccessTokenGetterImpl is the default implementation of AADAccessTokenGetter.
type defaultAADAccessTokenGetterImpl struct{}

func (g *defaultAADAccessTokenGetterImpl) GetAADAccessToken(ctx context.Context, tenantID, clientID, resource string) (confidential.AuthResult, error) {
	return defaultGetAADAccessToken(ctx, tenantID, clientID, resource)
}

func defaultGetAADAccessToken(ctx context.Context, tenantID, clientID, resource string) (confidential.AuthResult, error) {
	return azureauth.GetAADAccessToken(ctx, tenantID, clientID, resource)
}

// MetricsReporter defines an interface for reporting metrics.
type MetricsReporter interface {
	ReportMetrics(ctx context.Context, duration int64, artifactHostName string)
}

// defaultMetricsReporterImpl is the default implementation of MetricsReporter.
type defaultMetricsReporterImpl struct{}

func (r *defaultMetricsReporterImpl) ReportMetrics(ctx context.Context, duration int64, artifactHostName string) {
	defaultReportMetrics(ctx, duration, artifactHostName)
}

func defaultReportMetrics(ctx context.Context, duration int64, artifactHostName string) {
	logger.GetLogger(ctx, logOpt).Infof("Metrics Report: Duration=%dms, Host=%s", duration, artifactHostName)
}

type AzureWIProviderFactory struct{} //nolint:revive // ignore linter to have unique type name

type WIAuthProvider struct {
	aadToken           confidential.AuthResult
	tenantID           string
	clientID           string
	authClientFactory  AuthClientFactory
	registryHostGetter RegistryHostGetter
	getAADAccessToken  AADAccessTokenGetter
	reportMetrics      MetricsReporter
}

type azureWIAuthProviderConf struct {
	Name     string `json:"name"`
	ClientID string `json:"clientID,omitempty"`
}

const (
	azureWIAuthProviderName string = "azureWorkloadIdentity"
)

// init calls Register for our Azure Workload Identity provider
func init() {
	provider.Register(azureWIAuthProviderName, &AzureWIProviderFactory{})
}

// Create returns an AzureWIAuthProvider
func (s *AzureWIProviderFactory) Create(authProviderConfig provider.AuthProviderConfig) (provider.AuthProvider, error) {
	conf := azureWIAuthProviderConf{}
	authProviderConfigBytes, err := json.Marshal(authProviderConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithComponentType(re.AuthProvider).WithError(err)
	}

	if err := json.Unmarshal(authProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.EmptyLink, err, "failed to parse auth provider configuration", re.HideStackTrace)
	}

	tenant := os.Getenv("AZURE_TENANT_ID")

	if tenant == "" {
		return nil, re.ErrorCodeEnvNotSet.WithComponentType(re.AuthProvider).WithDetail("azure tenant id environment variable is empty")
	}
	clientID := conf.ClientID
	if clientID == "" {
		clientID = os.Getenv("AZURE_CLIENT_ID")
		if clientID == "" {
			return nil, re.ErrorCodeEnvNotSet.WithComponentType(re.AuthProvider).WithDetail("no client ID provided and AZURE_CLIENT_ID environment variable is empty")
		}
	}

	// retrieve an AAD Access token
	token, err := defaultGetAADAccessToken(context.Background(), tenant, clientID, AADResource)
	if err != nil {
		return nil, re.ErrorCodeAuthDenied.NewError(re.AuthProvider, "", re.AzureWorkloadIdentityLink, err, "", re.HideStackTrace)
	}

	return &WIAuthProvider{
		aadToken:           token,
		tenantID:           tenant,
		clientID:           clientID,
		authClientFactory:  &defaultAuthClientFactoryImpl{},    // Concrete implementation
		registryHostGetter: &defaultRegistryHostGetterImpl{},   // Concrete implementation
		getAADAccessToken:  &defaultAADAccessTokenGetterImpl{}, // Concrete implementation
		reportMetrics:      &defaultMetricsReporterImpl{},
	}, nil
}

// Enabled checks for non empty tenant ID and AAD access token
func (d *WIAuthProvider) Enabled(_ context.Context) bool {
	if d.tenantID == "" || d.clientID == "" {
		return false
	}

	if d.aadToken.AccessToken == "" {
		return false
	}

	return true
}

// Provide returns the credentials for a specified artifact.
// Uses Azure Workload Identity to retrieve an AAD access token which can be
// exchanged for a valid ACR refresh token for login.
func (d *WIAuthProvider) Provide(ctx context.Context, artifact string) (provider.AuthConfig, error) {
	if !d.Enabled(ctx) {
		return provider.AuthConfig{}, re.ErrorCodeConfigInvalid.WithComponentType(re.AuthProvider).WithDetail("azure workload identity auth provider is not properly enabled")
	}

	// parse the artifact reference string to extract the registry host name
	artifactHostName, err := d.registryHostGetter.GetRegistryHost(artifact)
	if err != nil {
		return provider.AuthConfig{}, re.ErrorCodeHostNameInvalid.WithComponentType(re.AuthProvider)
	}

	// need to refresh AAD token if it's expired
	if time.Now().Add(time.Minute * 5).After(d.aadToken.ExpiresOn) {
		newToken, err := d.getAADAccessToken.GetAADAccessToken(ctx, d.tenantID, d.clientID, AADResource)
		if err != nil {
			return provider.AuthConfig{}, re.ErrorCodeAuthDenied.NewError(re.AuthProvider, "", re.AzureWorkloadIdentityLink, nil, "could not refresh AAD token", re.HideStackTrace)
		}
		d.aadToken = newToken
		logger.GetLogger(ctx, logOpt).Info("successfully refreshed AAD token")
	}

	// add protocol to generate complete URI
	serverURL := "https://" + artifactHostName

	// TODO: Consider adding authentication client options for multicloud scenarios
	var options *azcontainerregistry.AuthenticationClientOptions
	client, err := d.authClientFactory.CreateAuthClient(serverURL, options)
	if err != nil {
		return provider.AuthConfig{}, re.ErrorCodeAuthDenied.WithError(err).WithDetail("failed to create authentication client for container registry by azure managed identity token")
	}

	startTime := time.Now()
	response, err := client.ExchangeAADAccessTokenForACRRefreshToken(
		ctx,
		azcontainerregistry.PostContentSchemaGrantType(GrantTypeAccessToken),
		artifactHostName,
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: &d.aadToken.AccessToken,
			Tenant:      &d.tenantID,
		},
	)
	if err != nil {
		return provider.AuthConfig{}, re.ErrorCodeAuthDenied.NewError(re.AuthProvider, "", re.AzureWorkloadIdentityLink, err, "failed to get refresh token for container registry", re.HideStackTrace)
	}
	rt := response.ACRRefreshToken

	d.reportMetrics.ReportMetrics(ctx, time.Since(startTime).Milliseconds(), artifactHostName)

	refreshTokenExpiry := getACRExpiryIfEarlier(d.aadToken.ExpiresOn)
	authConfig := provider.AuthConfig{
		Username:  dockerTokenLoginUsernameGUID,
		Password:  *rt.RefreshToken,
		Provider:  d,
		ExpiresOn: refreshTokenExpiry,
	}

	return authConfig, nil
}

// Compare addExpiry with default ACR refresh token expiry
func getACRExpiryIfEarlier(aadExpiry time.Time) time.Time {
	// set default refresh token expiry to default ACR expiry - 5 minutes
	acrExpiration := time.Now().Add(defaultACRExpiryDuration - 5*time.Minute)

	if acrExpiration.Before(aadExpiry) {
		return acrExpiration
	}
	return aadExpiry
}
