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
	"os"
	"path/filepath"
	"testing"
	"time"

	re "github.com/notaryproject/ratify/v2/errors"
)

const (
	testUserName                 = "joejoe"
	testPassword                 = "hello"
	dockerTokenLoginUsernameGUID = "00000000-0000-0000-0000-000000000000"
	identityTokenOpaque          = "OPAQUE_TOKEN" // #nosec
	// #nosec G101
	secretContent = `{
		"auths": {
			"index.docker.io": {
				"auth": "am9lam9lOmhlbGxv"
			}
		}
	}`
	// #nosec G101
	secretContentIdentityToken = `{
		"auths": {
			"index.docker.io": {
				"auth": "MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOg==",
				"identitytoken": "OPAQUE_TOKEN"
			}
		}
	}`
)

type TestAuthProvider struct{}

func (ap *TestAuthProvider) Enabled(_ context.Context) bool {
	return true
}

func (ap *TestAuthProvider) Provide(_ context.Context, _ string) (AuthConfig, error) {
	return AuthConfig{
		Username: "test",
		Password: "testpw",
	}, nil
}

// Checks for creation of defaultAuthProvider with invalid config input
func TestProvide_CreationOfAuthProvider_ExpectedResults(t *testing.T) {
	var testProviderFactory defaultProviderFactory
	tests := []struct {
		name       string
		configMap  map[string]interface{}
		isNegative bool
		expect     error
	}{
		{
			name: "input type for unmarshal is unsupported",
			configMap: map[string]interface{}{
				"key1": 1,
				"key2": true,
				"key3": make(chan int),
			},
			isNegative: true,
			expect:     re.ErrorCodeConfigInvalid,
		},
		{
			name: "input type can not be transformed accordingly",
			configMap: map[string]interface{}{
				"Name": 1,
			},
			isNegative: true,
			expect:     re.ErrorCodeConfigInvalid,
		},
		{
			name: "successfully creation of authProvider",
			configMap: map[string]interface{}{
				"Name":       "sample",
				"ConfigPath": "/tmp",
			},
			isNegative: false,
			expect:     nil,
		},
	}
	for _, testCase := range tests {
		_, err := testProviderFactory.Create(AuthProviderConfig(testCase.configMap))
		if testCase.isNegative != (err != nil) {
			t.Errorf("Expected %v in case %v, but got %v", testCase.expect, testCase.name, err)
		}
	}
}

// Checks for correct credential resolution when external docker config
// path is provided
func TestProvide_ExternalDockerConfigPath_ExpectedResults(t *testing.T) {
	tmpHome, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatalf("unexpected error when creating temporary directory: %v", err)
	}
	defer os.RemoveAll(tmpHome)

	fn := filepath.Join(tmpHome, "config.json")

	err = os.WriteFile(fn, []byte(secretContent), 0600)
	if err != nil {
		t.Fatalf("unexpected error when writing config file: %v", err)
	}

	defaultProvider := defaultAuthProvider{
		configPath: fn,
	}

	authConfig, err := defaultProvider.Provide(context.Background(), "index.docker.io/v1/test:v1")
	if err != nil {
		t.Fatalf("unexpected error in Provide: %v", err)
	}

	if authConfig.Username != testUserName || authConfig.Password != testPassword {
		t.Fatalf("incorrect username %v or password %v returned", authConfig.Username, authConfig.Password)
	}

	if time.Now().Add(DefaultDockerAuthTTL - time.Minute).After(authConfig.ExpiresOn) {
		t.Fatalf("incorrect expiration time %v returned", authConfig.ExpiresOn)
	}
}

func TestProvide_ExternalDockerConfigPathWithIdentityToken_ExpectedResults(t *testing.T) {
	tmpHome, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatalf("unexpected error when creating temporary directory: %v", err)
	}
	defer os.RemoveAll(tmpHome)

	fn := filepath.Join(tmpHome, "config.json")

	err = os.WriteFile(fn, []byte(secretContentIdentityToken), 0600)
	if err != nil {
		t.Fatalf("unexpected error when writing config file: %v", err)
	}

	defaultProvider := defaultAuthProvider{
		configPath: fn,
	}

	authConfig, err := defaultProvider.Provide(context.Background(), "index.docker.io/v1/test:v1")
	if err != nil {
		t.Fatalf("unexpected error in Provide: %v", err)
	}

	if authConfig.Username != dockerTokenLoginUsernameGUID || authConfig.IdentityToken != identityTokenOpaque {
		t.Fatalf("incorrect username %v or identitytoken %v returned", authConfig.Username, authConfig.IdentityToken)
	}
}
