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
	re "github.com/notaryproject/ratify/v2/errors"

	provider "github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	EnvRoleArn              = "ALIBABA_CLOUD_ROLE_ARN"
	EnvOidcProviderArn      = "ALIBABA_CLOUD_OIDC_PROVIDER_ARN"
	EnvOidcTokenFile        = "ALIBABA_CLOUD_OIDC_TOKEN_FILE"
	AlibabaCloudACREndpoint = "cr.%s.aliyuncs.com"
)

type AlibabaCloudAcrBasicProviderFactory struct{} //nolint:revive // ignore linter to have unique type name

type acrInstancesConfig struct {
	InstanceName string `json:"instanceName"`
	InstanceID   string `json:"instanceId"`
}

type alibabacloudAcrBasicAuthProvider struct {
	acrInstancesConfig map[string]string
	providerName       string
	getAcrAuthToken    AcrAuthTokenGetter
}

type alibabacloudAcrBasicAuthProviderConf struct {
	Name               string               `json:"name"`
	DefaultInstanceID  string               `json:"defaultInstanceId"`
	AcrInstancesConfig []acrInstancesConfig `json:"acrInstancesConfig,omitempty"`
}

const (
	alibabacloudAcrAuthProviderName = "alibabacloudAcrBasic"
)

// init calls Register for AlibabaCloud RRSA Basic Auth provider
func init() {
	provider.Register(alibabacloudAcrAuthProviderName, &AlibabaCloudAcrBasicProviderFactory{})
}

// AcrAuthTokenGetter defines an interface for getting acr authentication token.
type AcrAuthTokenGetter interface {
	GetAcrAuthToken(artifact string, acrInstanceConfig map[string]string) (*cr20181201.GetAuthorizationTokenResponseBody, error)
}

// defaultAcrAuthTokenGetterImpl is the default implementation of getAcrAuthToken.
type defaultAcrAuthTokenGetterImpl struct{}

func (g *defaultAcrAuthTokenGetterImpl) GetAcrAuthToken(artifact string, acrInstanceConfig map[string]string) (*cr20181201.GetAuthorizationTokenResponseBody, error) {
	return getAcrAuthToken(artifact, acrInstanceConfig)
}

// Get ACR auth token from RRSA config
func getAcrAuthToken(artifact string, acrInstanceConfig map[string]string) (*cr20181201.GetAuthorizationTokenResponseBody, error) {
	// Verify RRSA ENV is present

	envRoleArn := os.Getenv(EnvRoleArn)
	envOidcProviderArn := os.Getenv(EnvOidcProviderArn)
	envOidcTokenFile := os.Getenv(EnvOidcTokenFile)

	if envRoleArn == "" || envOidcProviderArn == "" || envOidcTokenFile == "" {
		return nil, fmt.Errorf("required environment variables not set, ALIBABA_CLOUD_ROLE_ARN: %s, ALIBABA_CLOUD_OIDC_PROVIDER_ARN: %s, ALIBABA_CLOUD_OIDC_TOKEN_FILE: %s", envRoleArn, envOidcProviderArn, envOidcTokenFile)
	}

	// registry/region from image
	registry, err := provider.GetRegistryHostName(artifact)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry from image: %w", err)
	}
	registryMetaInfo, err := getRegionFromArtifact(registry)
	if err != nil || registryMetaInfo.Region == "" {
		return nil, err
	}
	region := registryMetaInfo.Region
	instanceName := registryMetaInfo.InstanceName
	logrus.Infof("Alibaba Cloud ACR basic artifact=%s, registry=%s, region=%s, instance=%s", artifact, registry, region, instanceName)

	cred, err := credentials.NewCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to init alibaba cloud sdk credential: %w", err)
	}
	config := &openapi.Config{
		Credential: cred,
	}
	instanceID := acrInstanceConfig[defaultInstance]
	if insID, ok := acrInstanceConfig[instanceName]; ok {
		instanceID = insID
	}
	if instanceID == "" {
		return nil, fmt.Errorf("no instance id found for the given artifact")
	}
	// Endpoint refer to https://help.aliyun.com/zh/acr/developer-reference/api-cr-2018-12-01-endpoint
	config.Endpoint = tea.String(fmt.Sprintf(AlibabaCloudACREndpoint, region))
	config.RegionId = tea.String(region)
	crClient, err := cr20181201.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to init alibaba cloud acr client: %w", err)
	}

	getAuthorizationTokenRequest := &cr20181201.GetAuthorizationTokenRequest{}
	getAuthorizationTokenRequest.InstanceId = tea.String(instanceID)
	runtime := &util.RuntimeOptions{}

	tokenResponse, err := crClient.GetAuthorizationTokenWithOptions(getAuthorizationTokenRequest, runtime)
	if err != nil || tokenResponse.Body == nil {
		return nil, fmt.Errorf("failed to get acr authorization token: %w", err)
	}
	return tokenResponse.Body, nil
}

// Create returns an Alibaba CloudAcrBasicProvider
func (d *AlibabaCloudAcrBasicProviderFactory) Create(authProviderConfig provider.AuthProviderConfig) (provider.AuthProvider, error) {
	conf := alibabacloudAcrBasicAuthProviderConf{}
	authProviderConfigBytes, err := json.Marshal(authProviderConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
	}

	if err = json.Unmarshal(authProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, alibabacloudAcrAuthProviderName, re.AuthProviderLink, err, "failed to parse alibaba cloud auth provider configuration", re.HideStackTrace)
	}
	var acrInstancesConfig = make(map[string]string, 0)
	if len(conf.AcrInstancesConfig) > 0 {
		for _, ic := range conf.AcrInstancesConfig {
			acrInstancesConfig[ic.InstanceName] = ic.InstanceID
		}
	}
	//get ACR EE instance id
	instanceID := conf.DefaultInstanceID
	if instanceID == "" {
		instanceID = os.Getenv("ALIBABA_CLOUD_ACR_INSTANCE_ID")
		if instanceID == "" && len(acrInstancesConfig) == 0 {
			return nil, re.ErrorCodeEnvNotSet.WithComponentType(re.AuthProvider).WithDetail("no instance ID provided and ALIBABA_CLOUD_ACR_INSTANCE_ID environment variable is empty")
		}
	}
	acrInstancesConfig[defaultInstance] = instanceID

	return &alibabacloudAcrBasicAuthProvider{
		acrInstancesConfig: acrInstancesConfig,
		providerName:       alibabacloudAcrAuthProviderName,
		getAcrAuthToken:    &defaultAcrAuthTokenGetterImpl{},
	}, nil
}

// Enabled checks for non-empty AlibabaCloud RAM creds
func (d *alibabacloudAcrBasicAuthProvider) Enabled(_ context.Context) bool {
	if d.providerName == "" {
		logrus.Error("basic Alibaba Cloud ACR providerName was empty")
		return false
	}

	return true
}

// Provide returns the credentials for a specified artifact.
// Uses AlibabaCloud RRSA to retrieve creds from RRSA credential chain
func (d *alibabacloudAcrBasicAuthProvider) Provide(ctx context.Context, artifact string) (provider.AuthConfig, error) {
	if !d.Enabled(ctx) {
		return provider.AuthConfig{}, re.ErrorCodeConfigInvalid.WithComponentType(re.AuthProvider).WithDetail("Alibaba Cloud RRSA basic auth provider is not properly enabled")
	}

	// need to first creat or refresh AlibabaCloud ACR credentials
	authToken, err := d.getAcrAuthToken.GetAcrAuthToken(artifact, d.acrInstancesConfig)
	if err != nil {
		return provider.AuthConfig{}, errors.Wrapf(err, "could not get ACR auth token for %s", artifact)
	}
	logrus.Debugf("successfully refreshed ACR auth token for %s", artifact)

	// Get ACR basic auth creds from AuthData response
	tmpUsr := tea.StringValue(authToken.TempUsername)
	passwd := tea.StringValue(authToken.AuthorizationToken)
	authConfig := provider.AuthConfig{
		Username:  tmpUsr,
		Password:  passwd,
		Provider:  d,
		ExpiresOn: time.UnixMilli(tea.Int64Value(authToken.ExpireTime)),
	}

	return authConfig, nil
}
