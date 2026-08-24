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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

var logOpt = logger.Option{ComponentType: logger.AuthProvider}

const (
	// providerName is the registered type name for the AWS ECR credential
	// provider.
	providerName = "aws"

	// sessionName is the STS role session name used when assuming a role via
	// IAM Roles for Service Accounts (IRSA).
	sessionName = "ratifyEcrAuth"

	// tokenRefreshBuffer is subtracted from the ECR token expiry so a cached
	// credential is refreshed before it actually expires.
	tokenRefreshBuffer = 5 * time.Minute
)

// authTokenGetter abstracts the ECR GetAuthorizationToken call so it can be
// mocked in tests.
type authTokenGetter interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// IdentityProvider is an implementation of
// [credentialprovider.CredentialSourceProvider] that retrieves credentials for
// AWS Elastic Container Registry (ECR).
//
// Credentials are resolved from the default AWS credential chain, which on a
// Kubernetes cluster is typically IAM Roles for Service Accounts (IRSA): the
// AWS_REGION, AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE environment
// variables injected into the pod.
type IdentityProvider struct {
	// region optionally overrides the AWS region. When empty, the region is
	// derived from the ECR registry host of each request.
	region string

	// newClient builds an ECR client for the resolved region. It is a field so
	// tests can substitute a mock.
	newClient func(ctx context.Context, region string) (authTokenGetter, error)
}

// IdentityProviderOptions contains configuration options for the AWS ECR
// identity provider.
type IdentityProviderOptions struct {
	// Region optionally pins the AWS region used to call ECR. When empty, the
	// region is parsed from the registry host (e.g. the "us-east-1" in
	// 123456789012.dkr.ecr.us-east-1.amazonaws.com).
	Region string `json:"region,omitempty"`
}

func init() {
	// Register the AWS ECR credential provider factory.
	credentialprovider.RegisterCredentialProviderFactory(providerName, createAWSProvider)
}

// createAWSProvider creates a new AWS ECR identity provider from the given
// credential provider options.
func createAWSProvider(opts credentialprovider.Options) (ratify.RegistryCredentialGetter, error) {
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	var awsOpts IdentityProviderOptions
	if err := json.Unmarshal(raw, &awsOpts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	provider := &IdentityProvider{
		region:    awsOpts.Region,
		newClient: defaultECRClient,
	}

	return credentialprovider.NewCachedProvider(provider)
}

// defaultECRClient loads the default AWS configuration for the given region and
// returns an ECR client. The default configuration resolves credentials from
// the standard chain, including IRSA web identity tokens.
func defaultECRClient(ctx context.Context, region string) (authTokenGetter, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithWebIdentityRoleCredentialOptions(func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionName
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}
	return ecr.NewFromConfig(cfg), nil
}

// GetWithTTL implements [credentialprovider.CredentialSourceProvider]. It
// retrieves an ECR authorization token for the registry identified by
// serverAddress and returns it along with its remaining lifetime.
func (p *IdentityProvider) GetWithTTL(ctx context.Context, serverAddress string) (credentialprovider.CredentialWithTTL, error) {
	log := logger.GetLogger(ctx, logOpt)

	region := p.region
	if region == "" {
		var err error
		region, err = regionFromRegistry(serverAddress)
		if err != nil {
			return credentialprovider.CredentialWithTTL{}, err
		}
	}
	log.Debugf("resolving ECR credential for %s (region=%s)", serverAddress, region)

	client, err := p.newClient(ctx, region)
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, err
	}

	output, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("failed to get ECR authorization token for %s: %w", serverAddress, err)
	}
	if len(output.AuthorizationData) == 0 {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("ECR returned no authorization data for %s", serverAddress)
	}

	authData := output.AuthorizationData[0]
	username, password, err := decodeAuthToken(aws.ToString(authData.AuthorizationToken))
	if err != nil {
		return credentialprovider.CredentialWithTTL{}, fmt.Errorf("failed to decode ECR authorization token for %s: %w", serverAddress, err)
	}

	ttl := resolveTokenTTL(log, serverAddress, authData.ExpiresAt)

	return credentialprovider.CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: username,
			Password: password,
		},
		TTL: ttl,
	}, nil
}

// decodeAuthToken decodes the base64-encoded "username:password" ECR
// authorization token.
func decodeAuthToken(token string) (username, password string, err error) {
	if token == "" {
		return "", "", fmt.Errorf("empty authorization token")
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", fmt.Errorf("could not base64-decode authorization token: %w", err)
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("authorization token is not in username:password format")
	}
	return parts[0], parts[1], nil
}

// ttlLogger is the subset of the logger used by resolveTokenTTL. It keeps the
// helper testable without a full logger instance.
type ttlLogger interface {
	Warnf(format string, args ...interface{})
}

// resolveTokenTTL reports how long an ECR authorization token may be cached. An
// ECR token is typically valid for 12 hours; a small buffer is subtracted so
// the credential is refreshed before it expires. A missing or already-expired
// expiry yields a zero TTL so the caching layer discards it.
func resolveTokenTTL(log ttlLogger, serverAddress string, expiresAt *time.Time) time.Duration {
	if expiresAt == nil {
		log.Warnf("ECR did not return an expiry for %s; the credential will not be cached", serverAddress)
		return 0
	}
	ttl := time.Until(*expiresAt) - tokenRefreshBuffer
	if ttl < 0 {
		log.Warnf("ECR returned an already-expired token for %s; it will not be cached", serverAddress)
		return 0
	}
	return ttl
}

// regionFromRegistry parses the AWS region from an ECR registry host of the
// form <account>.dkr.ecr.<region>.amazonaws.com(.cn).
func regionFromRegistry(registry string) (string, error) {
	parts := strings.Split(registry, ".")
	if len(parts) >= 6 && parts[1] == "dkr" && parts[2] == "ecr" {
		if region := parts[3]; region != "" {
			return region, nil
		}
	}
	return "", fmt.Errorf("could not determine AWS region from registry %q; set the provider's region option explicitly", registry)
}
