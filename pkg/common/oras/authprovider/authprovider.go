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
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
)

// This config represents the credentials that should be used
// when pulling artifacts from specific repositories.
type AuthConfig struct {
	Username      string
	Password      string
	IdentityToken string
	Email         string
	Provider      AuthProvider `json:"-"` // Provider is not serialized
	ExpiresOn     time.Time
}

type AuthProvider interface {
	// Enabled returns true if the config provider is properly enabled
	// It will verify necessary values provided in config file to
	// create the AuthProvider
	Enabled(ctx context.Context) bool
	// Provide returns AuthConfig for registry.
	Provide(ctx context.Context, artifact string) (AuthConfig, error)
}

type defaultProviderFactory struct{}
type defaultAuthProvider struct {
	configPath string
}

type defaultAuthProviderConf struct {
	Name       string `json:"name"`
	ConfigPath string `json:"configPath,omitempty"`
}

const DefaultAuthProviderName string = "dockerConfig"
const DefaultDockerAuthTTL = 1 * time.Hour

var logOpt = logger.Option{ComponentType: logger.AuthProvider}

// init calls Register for our default provider, which simply reads the .dockercfg file.
func init() {
	Register(DefaultAuthProviderName, &defaultProviderFactory{})
}

// Create returns an empty defaultAuthProvider instance if the AuthProviderConfig is nil.
// Otherwise it returns the defaultAuthProvider with configPath set
func (s *defaultProviderFactory) Create(authProviderConfig AuthProviderConfig) (AuthProvider, error) {
	if authProviderConfig == nil {
		return &defaultAuthProvider{configPath: ""}, nil
	}

	conf := defaultAuthProviderConf{}
	authProviderConfigBytes, err := json.Marshal(authProviderConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
	}

	if err := json.Unmarshal(authProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.AuthProvider, "", re.AuthProviderLink, err, "failed to parse auth provider configuration", re.HideStackTrace)
	}

	return &defaultAuthProvider{
		configPath: conf.ConfigPath,
	}, nil
}

// Enabled always returns true for defaultAuthProvider
func (d *defaultAuthProvider) Enabled(_ context.Context) bool {
	return true
}

// Provide reads docker config file and returns corresponding credentials from file if exists
func (d *defaultAuthProvider) Provide(ctx context.Context, artifact string) (AuthConfig, error) {
	// load docker config file at default path if config file path not specified
	var cfg *configfile.ConfigFile
	if d.configPath == "" {
		var err error
		if cfg, err = config.Load(config.Dir()); err != nil {
			return AuthConfig{}, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
		}
	} else {
		cfg = configfile.New(d.configPath)
		if _, err := os.Stat(d.configPath); err != nil {
			return AuthConfig{}, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
		}
		file, err := os.Open(d.configPath)
		if err != nil {
			return AuthConfig{}, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
		}
		defer file.Close()
		if err := cfg.LoadFromReader(file); err != nil {
			return AuthConfig{}, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.AuthProvider)
		}
	}

	artifactHostName, err := GetRegistryHostName(artifact)
	if err != nil {
		return AuthConfig{}, re.ErrorCodeHostNameInvalid.WithError(err).WithComponentType(re.AuthProvider)
	}

	dockerAuthConfig, exists := cfg.AuthConfigs[artifactHostName]
	if !exists {
		logger.GetLogger(ctx, logOpt).Debugf("no credentials found for registry hostname: %s", artifactHostName)
		hostnames := []string{}
		for k := range cfg.AuthConfigs {
			hostnames = append(hostnames, k)
		}
		logger.GetLogger(ctx, logOpt).Debugf("list of registry host names in config : %v", hostnames)
		return AuthConfig{}, nil
	}
	if dockerAuthConfig == (types.AuthConfig{}) {
		return AuthConfig{}, nil
	}
	authConfig := AuthConfig{
		Username:      dockerAuthConfig.Username,
		Password:      dockerAuthConfig.Password,
		IdentityToken: dockerAuthConfig.IdentityToken,
		ExpiresOn:     time.Now().Add(DefaultDockerAuthTTL),
		Provider:      d,
	}

	return authConfig, nil
}

func GetRegistryHostName(artifact string) (string, error) {
	if strings.Contains(artifact, "://") {
		return "", errors.New("invalid artifact reference")
	}

	u, err := url.Parse("dummy://" + artifact)
	if err != nil {
		return "", err
	}

	if u.Scheme != "dummy" {
		return "", errors.New("invalid artifact reference: scheme missing")
	}

	if u.Host == "" {
		return "", errors.New("invalid artifact reference: host could not be extracted")
	}

	return u.Host, nil
}
