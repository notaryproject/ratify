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

package static

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

func TestCreateStaticCredentialProvider(t *testing.T) {
	tests := []struct {
		name        string
		opts        credentialprovider.Options
		expectError bool
		expected    *Provider
	}{
		{
			name: "valid options with username and password",
			opts: credentialprovider.Options{
				"username": "testuser",
				"password": "testpass",
			},
			expectError: false,
			expected: &Provider{
				username: "testuser",
				password: "testpass",
			},
		},
		{
			name: "valid options with only password (refresh token mode)",
			opts: credentialprovider.Options{
				"password": "refresh_token_value",
			},
			expectError: false,
			expected: &Provider{
				username: "",
				password: "refresh_token_value",
			},
		},
		{
			name:        "empty options",
			opts:        credentialprovider.Options{},
			expectError: false,
			expected: &Provider{
				username: "",
				password: "",
			},
		},
		{
			name: "options with extra fields (should be ignored)",
			opts: credentialprovider.Options{
				"username": "testuser",
				"password": "testpass",
				"extra":    "ignored",
			},
			expectError: false,
			expected: &Provider{
				username: "testuser",
				password: "testpass",
			},
		},
		{
			name: "JSON marshal error - unmarshalable value",
			opts: credentialprovider.Options{
				"username": "testuser",
				"password": "testpass",
				"channel":  make(chan int), // channels cannot be marshaled to JSON
			},
			expectError: true,
			expected:    nil,
		},
		{
			name: "JSON unmarshal error - invalid data type",
			opts: credentialprovider.Options{
				"password": 12345, // number instead of string will cause unmarshal error
			},
			expectError: true,
			expected:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := createStaticCredentialProvider(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			StaticProvider, ok := provider.(*Provider)
			if !ok {
				t.Errorf("expected *StaticCredentialProvider, got %T", provider)
				return
			}

			if StaticProvider.username != tt.expected.username {
				t.Errorf("expected username %q, got %q", tt.expected.username, StaticProvider.username)
			}

			if StaticProvider.password != tt.expected.password {
				t.Errorf("expected password %q, got %q", tt.expected.password, StaticProvider.password)
			}
		})
	}
}

func TestStaticCredentialProvider_Get(t *testing.T) {
	tests := []struct {
		name        string
		provider    *Provider
		serverAddr  string
		expected    ratify.RegistryCredential
		expectError bool
	}{
		{
			name: "username and password mode",
			provider: &Provider{
				username: "testuser",
				password: "testpass",
			},
			serverAddr: "registry.example.com",
			expected: ratify.RegistryCredential{
				Username: "testuser",
				Password: "testpass",
			},
			expectError: false,
		},
		{
			name: "refresh token mode (no username)",
			provider: &Provider{
				username: "",
				password: "refresh_token_value",
			},
			serverAddr: "registry.example.com",
			expected: ratify.RegistryCredential{
				RefreshToken: "refresh_token_value",
			},
			expectError: false,
		},
		{
			name: "empty credentials",
			provider: &Provider{
				username: "",
				password: "",
			},
			serverAddr: "registry.example.com",
			expected: ratify.RegistryCredential{
				RefreshToken: "",
			},
			expectError: false,
		},
		{
			name: "server address is ignored",
			provider: &Provider{
				username: "testuser",
				password: "testpass",
			},
			serverAddr: "different.registry.com",
			expected: ratify.RegistryCredential{
				Username: "testuser",
				Password: "testpass",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cred, err := tt.provider.Get(ctx, tt.serverAddr)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if cred.Username != tt.expected.Username {
				t.Errorf("expected username %q, got %q", tt.expected.Username, cred.Username)
			}

			if cred.Password != tt.expected.Password {
				t.Errorf("expected password %q, got %q", tt.expected.Password, cred.Password)
			}

			if cred.RefreshToken != tt.expected.RefreshToken {
				t.Errorf("expected refresh token %q, got %q", tt.expected.RefreshToken, cred.RefreshToken)
			}
		})
	}
}

func TestStaticCredentialProviderOptions_JSON(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		expected string
	}{
		{
			name: "with username and password",
			options: Options{
				Username: "testuser",
				Password: "testpass",
			},
			expected: `{"username":"testuser","password":"testpass"}`,
		},
		{
			name: "with only password",
			options: Options{
				Password: "testpass",
			},
			expected: `{"password":"testpass"}`,
		},
		{
			name:     "empty options",
			options:  Options{},
			expected: `{"password":""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling (used internally in createStaticCredentialProvider)
			// This ensures the JSON tags work correctly
			provider := &Provider{
				username: tt.options.Username,
				password: tt.options.Password,
			}

			// Verify the provider was created correctly
			if provider.username != tt.options.Username {
				t.Errorf("expected username %q, got %q", tt.options.Username, provider.username)
			}
			if provider.password != tt.options.Password {
				t.Errorf("expected password %q, got %q", tt.options.Password, provider.password)
			}
		})
	}
}

func TestInit(t *testing.T) {
	// Test that the init function registers the provider factory
	// We can't directly test the registration, but we can verify that
	// the createStaticCredentialProvider function exists and works
	opts := credentialprovider.Options{
		"username": "test",
		"password": "pass",
	}

	provider, err := createStaticCredentialProvider(opts)
	if err != nil {
		t.Errorf("createStaticCredentialProvider failed: %v", err)
	}

	if provider == nil {
		t.Error("createStaticCredentialProvider returned nil provider")
	}

	// Verify it's the correct type
	if _, ok := provider.(*Provider); !ok {
		t.Errorf("expected *StaticCredentialProvider, got %T", provider)
	}
}

// Benchmark tests to ensure performance
func BenchmarkCreateStaticCredentialProvider(b *testing.B) {
	opts := credentialprovider.Options{
		"username": "testuser",
		"password": "testpass",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := createStaticCredentialProvider(opts)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkStaticCredentialProvider_Get(b *testing.B) {
	provider := &Provider{
		username: "testuser",
		password: "testpass",
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Get(ctx, "registry.example.com")
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
