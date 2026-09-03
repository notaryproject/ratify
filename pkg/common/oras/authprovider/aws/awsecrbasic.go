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

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	provider "github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider"
	"github.com/notaryproject/ratify/v2/pkg/utils/awsauth"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type AwsEcrBasicProviderFactory struct{} //nolint:revive // ignore linter to have unique type name
type awsEcrBasicAuthProvider struct {
	ecrAuthToken EcrAuthToken
	providerName string
}

type awsEcrBasicAuthProviderConf struct {
	Name string `json:"name"`
}

const (
	awsEcrAuthProviderName string = "awsEcrBasic"
	awsSessionName         string = "ratifyEcrBasicAuth"
)

// init calls Register for AWS IRSA Basic Auth provider
func init() {
	provider.Register(awsEcrAuthProviderName, &AwsEcrBasicProviderFactory{})
}

// Get ECR auth token from IRSA config
func (d *awsEcrBasicAuthProvider) getEcrAuthToken(artifact string) (EcrAuthToken, error) {
	region := os.Getenv("AWS_REGION")
	roleArn := os.Getenv("AWS_ROLE_ARN")
	tokenFilePath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	apiOverrideEndpoint := os.Getenv("AWS_API_OVERRIDE_ENDPOINT")
	apiOverridePartition := os.Getenv("AWS_API_OVERRIDE_PARTITION")
	apiOverrideRegion := os.Getenv("AWS_API_OVERRIDE_REGION")

	// Verify IRSA ENV is present
	if region == "" || roleArn == "" || tokenFilePath == "" {
		return EcrAuthToken{}, fmt.Errorf("required environment variables not set, AWS_REGION: %s, AWS_ROLE_ARN: %s, AWS_WEB_IDENTITY_TOKEN_FILE: %s", region, roleArn, tokenFilePath)
	}

	ctx := context.Background()
	// TODO: Update to use regional endpoint
	// nolint:staticcheck
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, _ ...interface{}) (aws.Endpoint, error) {
		if service == ecr.ServiceID && region == apiOverrideRegion {
			logrus.Info("AWS ECR basic auth using custom endpoint resolver...")
			logrus.Infof("AWS ECR basic auth API override endpoint: %s", apiOverrideEndpoint)
			logrus.Infof("AWS ECR basic auth API override partition: %s", apiOverridePartition)
			logrus.Infof("AWS ECR basic auth API override region: %s", apiOverrideRegion)
			// TODO: Update to use regional endpoint
			// nolint:staticcheck
			return aws.Endpoint{
				URL:           apiOverrideEndpoint,
				PartitionID:   apiOverridePartition,
				SigningRegion: apiOverrideRegion,
			}, nil
		}
		// returning EndpointNotFoundError will allow the service to fall back to its default resolution
		// TODO: Update to use regional endpoint
		// nolint:staticcheck
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})
	// TODO: Update to use regional endpoint
	// nolint:staticcheck
	cfg, err := config.LoadDefaultConfig(ctx, config.WithEndpointResolverWithOptions(resolver),
		config.WithWebIdentityRoleCredentialOptions(func(options *stscreds.WebIdentityRoleOptions) {
			options.RoleSessionName = awsSessionName
		}))

	if err != nil {
		return EcrAuthToken{}, fmt.Errorf("failed to load default AWS basic auth config: %w", err)
	}

	// registry/region from image
	registry, err := provider.GetRegistryHostName(artifact)
	if err != nil {
		return EcrAuthToken{}, fmt.Errorf("failed to get registry from image: %w", err)
	}
	region = awsauth.RegionFromRegistry(registry)
	if region == "" {
		return EcrAuthToken{}, fmt.Errorf("failed to get region from image")
	}

	logrus.Debugf("AWS ECR basic artifact=%s, registry=%s, region=%s", artifact, registry, region)
	cfg.Region = region

	ecrClient := ecr.NewFromConfig(cfg)
	authOutput, err := ecrClient.GetAuthorizationToken(ctx, nil)
	if err != nil {
		return EcrAuthToken{}, fmt.Errorf("could not retrieve ECR auth token collection: %w", err)
	}

	d.ecrAuthToken.AuthData[registry] = authOutput.AuthorizationData[0]

	return d.ecrAuthToken, nil
}

// Create returns an AwsEcrBasicProvider
func (s *AwsEcrBasicProviderFactory) Create(authProviderConfig provider.AuthProviderConfig) (provider.AuthProvider, error) {
	conf := awsEcrBasicAuthProviderConf{}
	authProviderConfigBytes, err := json.Marshal(authProviderConfig)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(authProviderConfigBytes, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse auth provider configuration: %w", err)
	}

	ecrAuthToken := EcrAuthToken{}
	ecrAuthToken.AuthData = make(map[string]types.AuthorizationData)

	return &awsEcrBasicAuthProvider{
		ecrAuthToken: ecrAuthToken,
		providerName: awsEcrAuthProviderName,
	}, nil
}

// Enabled checks for non-empty AWS IAM creds
func (d *awsEcrBasicAuthProvider) Enabled(_ context.Context) bool {
	if d.providerName == "" {
		logrus.Error("basic ECR providerName was empty")
		return false
	}

	return true
}

// Provide returns the credentials for a specified artifact.
// Uses AWS IRSA to retrieve creds from IRSA credential chain
func (d *awsEcrBasicAuthProvider) Provide(ctx context.Context, artifact string) (provider.AuthConfig, error) {
	logrus.Debugf("artifact = %s", artifact)

	if !d.Enabled(ctx) {
		return provider.AuthConfig{}, fmt.Errorf("AWS IRSA basic auth provider is not properly enabled")
	}

	registry, err := provider.GetRegistryHostName(artifact)
	if err != nil {
		return provider.AuthConfig{}, errors.Wrapf(err, "could not get ECR registry from %s", artifact)
	}

	if !d.ecrAuthToken.exists(registry) {
		logrus.Debugf("ecrAuthToken for %s does not exist", registry)
		_, err = d.getEcrAuthToken(artifact)
		if err != nil {
			return provider.AuthConfig{}, errors.Wrapf(err, "could not get ECR auth token for %s", artifact)
		}
	}

	// need to refresh AWS ECR credentials
	t := time.Now().Add(time.Minute * 5)
	if t.After(d.ecrAuthToken.Expiry(registry)) || time.Now().After(d.ecrAuthToken.Expiry(registry)) {
		_, err = d.getEcrAuthToken(artifact)
		if err != nil {
			return provider.AuthConfig{}, errors.Wrapf(err, "could not refresh ECR auth token for %s", artifact)
		}

		logrus.Debugf("successfully refreshed ECR auth token for %s", artifact)
	}

	// Get ECR basic auth creds from auth data token
	var creds []string
	creds, err = d.ecrAuthToken.BasicAuthCreds(registry)
	if err != nil {
		return provider.AuthConfig{}, errors.Wrapf(err, "could not retrieve ECR credentials for %s", artifact)
	}

	authConfig := provider.AuthConfig{
		Username:  creds[0],
		Password:  creds[1],
		Provider:  d,
		ExpiresOn: d.ecrAuthToken.Expiry(registry),
	}

	return authConfig, nil
}
