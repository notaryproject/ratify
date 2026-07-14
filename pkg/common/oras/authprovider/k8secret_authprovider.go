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

package authprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/utils"

	"github.com/docker/cli/cli/config"
	core "k8s.io/api/core/v1"
	e "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type k8SecretProviderFactory struct{}
type k8SecretAuthProvider struct {
	ratifyNamespace  string
	config           k8SecretAuthProviderConf
	clusterClientSet kubernetes.Interface
}

type secretConfig struct {
	SecretName string `json:"secretName"`
	Namespace  string `json:"namespace,omitempty"`
}

type k8SecretAuthProviderConf struct {
	Name               string         `json:"name"`
	ServiceAccountName string         `json:"serviceAccountName,omitempty"`
	Secrets            []secretConfig `json:"secrets,omitempty"`
}

const defaultName = "default"
const secretTimeout = time.Hour * 12

// init calls Register for our k8Secrets provider
func init() {
	Register("k8Secrets", &k8SecretProviderFactory{})
}

// Create returns a k8AuthProvider instance after parsing auth config and resolving
// named K8s secrets
func (s *k8SecretProviderFactory) Create(authProviderConfig AuthProviderConfig) (AuthProvider, error) {
	conf := k8SecretAuthProviderConf{}
	authProviderConfigBytes, err := json.Marshal(authProviderConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.EmptyLink, err, "failed to marshal authentication provider config", re.HideStackTrace)
	}

	if err := json.Unmarshal(authProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.EmptyLink, err, "failed to parse authentication provider configuration", re.HideStackTrace)
	}

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.EmptyLink, err, "failed to generate cluster configuration", re.HideStackTrace)
	}

	clientSet, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.EmptyLink, err, "failed to create kubernetes client set from config", re.HideStackTrace)
	}

	if conf.ServiceAccountName == "" {
		conf.ServiceAccountName = defaultName
	}

	// get name of namespace ratify is running in
	namespace := os.Getenv(utils.RatifyNamespaceEnvVar)
	if namespace == "" {
		return nil, re.ErrorCodeEnvNotSet.WithComponentType(re.AuthProvider).WithDetail(fmt.Sprintf("environment variable %s not set", utils.RatifyNamespaceEnvVar))
	}

	return &k8SecretAuthProvider{
		ratifyNamespace:  namespace,
		config:           conf,
		clusterClientSet: clientSet,
	}, nil
}

// Enabled checks if ratify namespace, config, or cluster client set is nil
func (d *k8SecretAuthProvider) Enabled(_ context.Context) bool {
	if d.ratifyNamespace == "" || d.clusterClientSet == nil {
		return false
	}

	return true
}

// Provide finds secret corresponding to artifact's registry host name, extracts
// the authentication credentials from K8s secret, and returns AuthConfig
func (d *k8SecretAuthProvider) Provide(ctx context.Context, artifact string) (AuthConfig, error) {
	if !d.Enabled(ctx) {
		return AuthConfig{}, fmt.Errorf("K8s auth provider not properly enabled")
	}

	hostName, err := GetRegistryHostName(artifact)
	if err != nil {
		return AuthConfig{}, re.ErrorCodeHostNameInvalid.WithError(err).WithComponentType(re.AuthProvider)
	}

	logger.GetLogger(ctx, logOpt).Debugf("attempting to resolve credentials for registry hostname: %s", hostName)
	// iterate through config secrets, resolve each secret, and store in map
	for _, k8secret := range d.config.Secrets {
		// default value of secret is assumed to be ratify namespace
		if k8secret.Namespace == "" {
			k8secret.Namespace = d.ratifyNamespace
		}

		secret, err := d.clusterClientSet.CoreV1().Secrets(k8secret.Namespace).Get(ctx, k8secret.SecretName, meta.GetOptions{})
		if e.IsNotFound(err) {
			logger.GetLogger(ctx, logOpt).Debugf("secret %s not found in namespace %s", k8secret.SecretName, k8secret.Namespace)
			continue
		} else if err != nil {
			return AuthConfig{}, re.ErrorCodeGetClusterResourceFailure.NewError(re.AuthProvider, "", re.EmptyLink, err, fmt.Sprintf("failed to pull secret %s from cluster.", k8secret.SecretName), re.HideStackTrace)
		}

		// only docker config json secret type allowed
		if secret.Type == core.SecretTypeDockerConfigJson {
			authConfig, err := d.resolveCredentialFromSecret(ctx, hostName, secret)
			if err != nil && !errors.Is(err, re.ErrorCodeNoMatchingCredential) {
				return AuthConfig{}, err
			}
			// if a resolved AuthConfig is returned
			if err == nil {
				return authConfig, nil
			}
		} else {
			return AuthConfig{}, fmt.Errorf("secret with unsupported type %s provided in config", secret.Type)
		}
	}

	// get the the service account for ratify
	serviceAccount, err := d.clusterClientSet.CoreV1().ServiceAccounts(d.ratifyNamespace).Get(ctx, d.config.ServiceAccountName, meta.GetOptions{})
	if err != nil {
		return AuthConfig{}, re.ErrorCodeGetClusterResourceFailure.WithError(err).WithComponentType(re.AuthProvider)
	}

	// extract the imagePullSecrets linked to service account
	for _, imagePullSecret := range serviceAccount.ImagePullSecrets {
		secret, err := d.clusterClientSet.CoreV1().Secrets(d.ratifyNamespace).Get(ctx, imagePullSecret.Name, meta.GetOptions{})
		if e.IsNotFound(err) {
			logger.GetLogger(ctx, logOpt).Debugf("image pull secret %s not found in namespace %s", imagePullSecret.Name, d.ratifyNamespace)
			continue
		} else if err != nil {
			return AuthConfig{}, re.ErrorCodeGetClusterResourceFailure.WithError(err).WithComponentType(re.AuthProvider)
		}

		// only dockercfg or docker config json secret type allowed
		if secret.Type == core.SecretTypeDockercfg || secret.Type == core.SecretTypeDockerConfigJson {
			authConfig, err := d.resolveCredentialFromSecret(ctx, hostName, secret)
			if err != nil && !errors.Is(err, re.ErrorCodeNoMatchingCredential) {
				return AuthConfig{}, err
			}
			// if a resolved AuthConfig is returned
			if err == nil {
				return authConfig, nil
			}
		} else {
			logger.GetLogger(ctx, logOpt).Debugf("image pull secret %s of type %s not supported", imagePullSecret.Name, secret.Type)
		}
	}

	return AuthConfig{}, fmt.Errorf("could not find credentials for %s", artifact)
}

func (d *k8SecretAuthProvider) resolveCredentialFromSecret(ctx context.Context, hostName string, secret *core.Secret) (AuthConfig, error) {
	dockercfg, exists := secret.Data[core.DockerConfigJsonKey]
	if !exists {
		return AuthConfig{}, re.ErrorCodeConfigInvalid.WithDetail("could not extract auth configs from docker config")
	}

	configFile, err := config.LoadFromReader(bytes.NewReader(dockercfg))
	if err != nil {
		return AuthConfig{}, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
	}

	authConfig, exist := configFile.AuthConfigs[hostName]
	if !exist {
		logger.GetLogger(ctx, logOpt).Debugf("host name %s not found in image pull secret %s", hostName, secret.Name)
		hostnames := []string{}
		for k := range configFile.AuthConfigs {
			hostnames = append(hostnames, k)
		}
		logger.GetLogger(ctx, logOpt).Debugf("list of host names in image pull secret %s: %v", secret.Name, hostnames)
		return AuthConfig{}, re.ErrorCodeNoMatchingCredential
	}

	return AuthConfig{
		Username:      authConfig.Username,
		Password:      authConfig.Password,
		IdentityToken: authConfig.IdentityToken,
		Provider:      d,
		ExpiresOn:     time.Now().Add(secretTimeout),
	}, nil
}
