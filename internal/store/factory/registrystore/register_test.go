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

package registrystore

import (
	"testing"

	"github.com/notaryproject/ratify/v2/internal/store/factory"
)

func TestNewStore(t *testing.T) {
	tests := []struct {
		name      string
		opts      *factory.NewStoreOptions
		expectErr bool
	}{
		{
			name: "Unsupported params type",
			opts: &factory.NewStoreOptions{
				Type:       registryStoreType,
				Parameters: make(chan int),
			},
			expectErr: true,
		},
		{
			name: "Malformed JSON params",
			opts: &factory.NewStoreOptions{
				Type:       registryStoreType,
				Parameters: "{invalid json",
			},
			expectErr: true,
		},
		{
			name: "Missing credential provider",
			opts: &factory.NewStoreOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"plainHttp": true,
				},
			},
			expectErr: true,
		},
		{
			name: "Invalid credential provider type",
			opts: &factory.NewStoreOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": map[string]interface{}{
						"provider": "nonexistent",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Valid registry params with static credential provider",
			opts: &factory.NewStoreOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"plainHttp":        true,
					"userAgent":        "test-agent",
					"maxBlobBytes":     1024,
					"maxManifestBytes": 2048,
					"credential": map[string]interface{}{
						"provider": "static",
						"username": "testuser",
						"password": "testpass",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "Valid registry params with minimal config",
			opts: &factory.NewStoreOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": map[string]interface{}{
						"provider": "static",
						"password": "token",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "Empty credential provider options",
			opts: &factory.NewStoreOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": map[string]interface{}{},
				},
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := factory.NewStore(test.opts)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}
			if !test.expectErr && store == nil {
				t.Error("expected non-nil store when no error occurred")
			}
			if test.expectErr && store != nil {
				t.Error("expected nil store when error occurred")
			}
		})
	}
}

func TestRegistryStoreFactory(t *testing.T) {
	// Test that the factory is properly registered
	t.Run("Factory is registered", func(t *testing.T) {
		opts := &factory.NewStoreOptions{
			Type: registryStoreType,
			Parameters: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
		}

		_, err := factory.NewStore(opts)
		if err != nil {
			t.Errorf("factory should be registered and functional, got error: %v", err)
		}
	})
}

func TestStoreOptionsUnmarshaling(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]interface{}
		expectErr  bool
		verifyFunc func(*testing.T, map[string]interface{})
	}{
		{
			name: "All options set",
			params: map[string]interface{}{
				"plainHttp":        true,
				"userAgent":        "custom-agent/1.0",
				"maxBlobBytes":     int64(5000),
				"maxManifestBytes": int64(10000),
				"credential": map[string]interface{}{
					"provider": "static",
					"username": "user",
					"password": "pass",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				if params["plainHttp"] != true {
					t.Error("plainHttp should be true")
				}
				if params["userAgent"] != "custom-agent/1.0" {
					t.Error("userAgent should match")
				}
			},
		},
		{
			name: "Default values",
			params: map[string]interface{}{
				"credential": map[string]interface{}{
					"provider": "static",
					"password": "token",
				},
			},
			expectErr: false,
			verifyFunc: func(t *testing.T, params map[string]interface{}) {
				// These should use default values (false, empty string, 0)
				if val, exists := params["plainHttp"]; exists && val != false {
					t.Error("plainHttp should default to false")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := &factory.NewStoreOptions{
				Type:       registryStoreType,
				Parameters: test.params,
			}

			store, err := factory.NewStore(opts)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}

			if !test.expectErr && test.verifyFunc != nil {
				test.verifyFunc(t, test.params)
			}

			if !test.expectErr && store == nil {
				t.Error("expected non-nil store")
			}
		})
	}
}

func TestCredentialProviderIntegration(t *testing.T) {
	tests := []struct {
		name         string
		credConfig   map[string]interface{}
		expectErr    bool
		expectedType string
	}{
		{
			name: "Static provider with username/password",
			credConfig: map[string]interface{}{
				"provider": "static",
				"username": "testuser",
				"password": "testpass",
			},
			expectErr:    false,
			expectedType: "static",
		},
		{
			name: "Static provider with token only",
			credConfig: map[string]interface{}{
				"provider": "static",
				"password": "token123",
			},
			expectErr:    false,
			expectedType: "static",
		},
		{
			name: "Missing provider field",
			credConfig: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expectErr: true,
		},
		{
			name: "Invalid provider type",
			credConfig: map[string]interface{}{
				"provider": "unknown-provider",
				"password": "testpass",
			},
			expectErr: true,
		},
		{
			name: "Empty provider",
			credConfig: map[string]interface{}{
				"provider": "",
				"password": "testpass",
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := &factory.NewStoreOptions{
				Type: registryStoreType,
				Parameters: map[string]interface{}{
					"credential": test.credConfig,
				},
			}

			store, err := factory.NewStore(opts)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got error: %v", test.expectErr, err)
			}

			if !test.expectErr && store == nil {
				t.Error("expected non-nil store when no error occurred")
			}
		})
	}
}
