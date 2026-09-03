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

package alibabacloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cr20181201 "github.com/alibabacloud-go/cr-20181201/v2/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

var logOpt = logger.Option{ComponentType: logger.AuthProvider}

const (
	// providerName is the registered type name for the Alibaba Cloud ACR
	// credential provider.
	providerName = "alibabacloud"

	// acrEndpointTemplate is the Alibaba Cloud Container Registry API endpoint
	// template. See
	// https://help.aliyun.com/zh/acr/developer-reference/api-cr-2018-12-01-endpoint
	acrEndpointTemplate = "cr.%s.aliyuncs.com"

	// envACRInstanceID is an optional environment fallback for the default ACR
	// Enterprise Edition instance ID.
	envACRInstanceID = "ALIBABA_CLOUD_ACR_INSTANCE_ID"

	// tokenRefreshBuffer is subtracted from the ACR token expiry so a cached
	// credential is refreshed before it actually expires.
	tokenRefreshBuffer = 5 * time.Minute
)

// acrTokenGetter abstracts fetching an ACR authorization token so it can be
// mocked in tests.
type acrTokenGetter interface {
	getACRToken(ctx context.Context, serverAddress, instanceID string) (*cr20181201.GetAuthorizationTokenResponseBody, error)
}

// acrClient is the subset of the Alibaba Cloud ACR client used by this package.
// It is satisfied by *cr20181201.Client and allows mocking in tests.
type acrClient interface {
	GetAuthorizationTokenWithOptions(request *cr20181201.GetAuthorizationTokenRequest, runtime *util.RuntimeOptions) (*cr20181201.GetAuthorizationTokenResponse, error)
}

// IdentityProvider is an implementation of
// [credentialprovider.CredentialSourceProvider] that retrieves credentials for
// Alibaba Cloud Container Registry (ACR).
//
// Authentication uses RAM Roles for Service Accounts (RRSA): the
// ALIBABA_CLOUD_ROLE_ARN, ALIBABA_CLOUD_OIDC_PROVIDER_ARN and
// ALIBABA_CLOUD_OIDC_TOKEN_FILE environment variables injected into the pod are
// consumed by the Alibaba Cloud credentials SDK to obtain STS credentials,
// which are then exchanged for a short-lived ACR authorization token.
type IdentityProvider struct {
	// defaultInstanceID is the ACR Enterprise Edition instance ID used when a
	// registry host does not map to a configured instance.
	defaultInstanceID string

	// instanceIDs maps an ACR EE instance name (parsed from the registry host)
	// to its instance ID.
	instanceIDs map[string]string

	// tokenGetter fetches the ACR authorization token. It is a field so tests
	// can substitute a mock.
	tokenGetter acrTokenGetter
}

// instanceConfig maps an ACR Enterprise Edition instance name to its instance
// ID.
type instanceConfig struct {
	// InstanceName is the ACR EE instance name, matching the label that
	// precedes "-registry" in the registry host (e.g. "dahu" in
	// dahu-registry.cn-hangzhou.cr.aliyuncs.com).
	InstanceName string `json:"instanceName"`
	// InstanceID is the ACR EE instance ID.
	InstanceID string `json:"instanceId"`
}

// IdentityProviderOptions contains configuration options for the Alibaba Cloud
// ACR identity provider.
type IdentityProviderOptions struct {
	// DefaultInstanceID is the ACR Enterprise Edition instance ID used when the
	// registry host does not match a configured instance. When empty, the
	// ALIBABA_CLOUD_ACR_INSTANCE_ID environment variable is used as a fallback.
	DefaultInstanceID string `json:"defaultInstanceId,omitempty"`
	// InstanceConfigs optionally maps ACR EE instance names to instance IDs for
	// multi-instance clusters.
	InstanceConfigs []instanceConfig `json:"acrInstancesConfig,omitempty"`
}

func init() {
	// Register the Alibaba Cloud ACR credential provider factory.
	credentialprovider.RegisterCredentialProviderFactory(providerName, createAlibabaCloudProvider)
}

// createAlibabaCloudProvider creates a new Alibaba Cloud ACR identity provider
// from the given credential provider options.
func createAlibabaCloudProvider(opts credentialprovider.Options) (ratify.RegistryCredentialGetter, error) {
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	var acrOpts IdentityProviderOptions
	if err := json.Unmarshal(raw, &acrOpts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	instanceIDs := make(map[string]string, len(acrOpts.InstanceConfigs))
	for _, ic := range acrOpts.InstanceConfigs {
		instanceIDs[ic.InstanceName] = ic.InstanceID
	}

	defaultInstanceID := acrOpts.DefaultInstanceID
	if defaultInstanceID == "" {
		defaultInstanceID = os.Getenv(envACRInstanceID)
	}
	if defaultInstanceID == "" && len(instanceIDs) == 0 {
		return nil, fmt.Errorf("no ACR instance ID provided: set defaultInstanceId, acrInstancesConfig, or the %s environment variable", envACRInstanceID)
	}

	provider := &IdentityProvider{
		defaultInstanceID: defaultInstanceID,
		instanceIDs:       instanceIDs,
		tokenGetter:       &defaultACRTokenGetter{newClient: defaultACRClient},
	}

	return credentialprovider.NewCachedProvider(provider)
}

// GetWithTTL implements [credentialprovider.CredentialSourceProvider]. It
// retrieves an ACR authorization token for the registry identified by
// serverAddress and returns it along with its remaining lifetime.
func (p *IdentityProvider) GetWithTTL(ctx context.Context, serverAddress string) (credentialprovider.CredentialWithTTL, error) {
	log := logger.GetLogger(ctx, logOpt)

	meta, err := parseACRHost(serverAddress)
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, err
	}

	instanceID := p.defaultInstanceID
	if id, ok := p.instanceIDs[meta.instanceName]; ok {
		instanceID = id
	}
	if instanceID == "" {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("no ACR instance ID configured for registry %q", serverAddress)
	}
	log.Debugf("resolving ACR credential for %s (region=%s, instance=%s)", serverAddress, meta.region, instanceID)

	body, err := p.tokenGetter.getACRToken(ctx, serverAddress, instanceID)
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("failed to get ACR authorization token for %s: %w", serverAddress, err)
	}
	if body == nil {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("received nil ACR authorization token for %s", serverAddress)
	}

	ttl := resolveTokenTTL(log, serverAddress, tea.Int64Value(body.ExpireTime))

	return credentialprovider.CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: tea.StringValue(body.TempUsername),
			Password: tea.StringValue(body.AuthorizationToken),
		},
		TTL: ttl,
	}, nil
}

// defaultACRTokenGetter is the production implementation of acrTokenGetter that
// talks to the Alibaba Cloud ACR API using RRSA credentials.
type defaultACRTokenGetter struct {
	// newClient builds an ACR client for the resolved region. It is a field so
	// tests can substitute a mock.
	newClient func(region string) (acrClient, error)
}

// getACRToken exchanges the pod's RRSA credentials for a short-lived ACR
// authorization token for the given instance.
func (g *defaultACRTokenGetter) getACRToken(_ context.Context, serverAddress, instanceID string) (*cr20181201.GetAuthorizationTokenResponseBody, error) {
	meta, err := parseACRHost(serverAddress)
	if err != nil {
		return nil, err
	}

	client, err := g.newClient(meta.region)
	if err != nil {
		return nil, err
	}

	request := &cr20181201.GetAuthorizationTokenRequest{
		InstanceId: tea.String(instanceID),
	}
	response, err := client.GetAuthorizationTokenWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("received empty ACR authorization token response")
	}
	return response.Body, nil
}

// defaultACRClient builds an Alibaba Cloud ACR client for the given region using
// RRSA credentials resolved from the environment.
func defaultACRClient(region string) (acrClient, error) {
	// credentials.NewCredential(nil) resolves RRSA credentials from the
	// ALIBABA_CLOUD_ROLE_ARN, ALIBABA_CLOUD_OIDC_PROVIDER_ARN and
	// ALIBABA_CLOUD_OIDC_TOKEN_FILE environment variables.
	cred, err := credentials.NewCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to init Alibaba Cloud SDK credential: %w", err)
	}

	config := &openapi.Config{
		Credential: cred,
		Endpoint:   tea.String(fmt.Sprintf(acrEndpointTemplate, region)),
		RegionId:   tea.String(region),
	}
	client, err := cr20181201.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to init Alibaba Cloud ACR client: %w", err)
	}
	return client, nil
}

// ttlLogger is the subset of the logger used by resolveTokenTTL. It keeps the
// helper testable without a full logger instance.
type ttlLogger interface {
	Warnf(format string, args ...interface{})
}

// resolveTokenTTL reports how long an ACR authorization token may be cached. An
// ACR token is typically valid for one hour; a small refresh buffer is
// subtracted so the credential is refreshed before it expires. A missing expiry,
// or one that falls within the refresh buffer, yields a zero TTL so the caching
// layer does not store a credential that is expired or about to expire.
func resolveTokenTTL(log ttlLogger, serverAddress string, expireTimeMillis int64) time.Duration {
	if expireTimeMillis <= 0 {
		log.Warnf("ACR did not return an expiry for %s; the credential will not be cached", serverAddress)
		return 0
	}
	ttl := time.Until(time.UnixMilli(expireTimeMillis)) - tokenRefreshBuffer
	if ttl < 0 {
		log.Warnf("ACR token for %s expires within the refresh buffer; it will not be cached", serverAddress)
		return 0
	}
	return ttl
}
