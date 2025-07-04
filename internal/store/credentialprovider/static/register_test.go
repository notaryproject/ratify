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
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

func TestCreateStaticCredentialProvider(t *testing.T) {
	tests := []struct {
		name        string
		opts        credentialprovider.Options
		expectError bool
		expectedErr string
	}{
		{
			name: "valid options with username and password",
			opts: credentialprovider.Options{
				"username": "testuser",
				"password": "testpass",
			},
			expectError: false,
		},
		{
			name: "valid options with only password (refresh token mode)",
			opts: credentialprovider.Options{
				"password": "refresh_token_value",
			},
			expectError: false,
		},
		{
			name:        "empty options",
			opts:        credentialprovider.Options{},
			expectError: false,
		},
		{
			name: "options with extra fields (should be ignored)",
			opts: credentialprovider.Options{
				"username": "testuser",
				"password": "testpass",
				"extra":    "ignored",
			},
			expectError: false,
		},
		{
			name: "JSON marshal error - unmarshalable value",
			opts: credentialprovider.Options{
				"username": "testuser",
				"password": "testpass",
				"channel":  make(chan int), // channels cannot be marshaled to JSON
			},
			expectError: true,
			expectedErr: "failed to marshal configuration",
		},
		{
			name: "JSON unmarshal error - invalid data type",
			opts: credentialprovider.Options{
				"password": 12345, // number instead of string will cause unmarshal error
			},
			expectError: true,
			expectedErr: "failed to unmarshal configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := createStaticCredentialProvider(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.expectedErr != "" && !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("expected error to contain %q, got %q", tt.expectedErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if provider == nil {
				t.Error("expected provider, got nil")
				return
			}

			// Verify it's a CachedProvider by calling Get method
			ctx := context.Background()
			_, err = provider.Get(ctx, "test.registry.com")
			if err != nil {
				t.Errorf("unexpected error calling Get: %v", err)
			}
		})
	}
}

func TestProvider_GetWithTTL(t *testing.T) {
	tests := []struct {
		name        string
		provider    *Provider
		serverAddr  string
		expected    ratify.RegistryCredential
		expectedTTL time.Duration
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
			expectedTTL: 0,
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
			expectedTTL: 0,
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
			expectedTTL: 0,
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
			expectedTTL: 0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			credWithTTL, err := tt.provider.GetWithTTL(ctx, tt.serverAddr)

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

			cred := credWithTTL.Credential

			if cred.Username != tt.expected.Username {
				t.Errorf("expected username %q, got %q", tt.expected.Username, cred.Username)
			}

			if cred.Password != tt.expected.Password {
				t.Errorf("expected password %q, got %q", tt.expected.Password, cred.Password)
			}

			if cred.RefreshToken != tt.expected.RefreshToken {
				t.Errorf("expected refresh token %q, got %q", tt.expected.RefreshToken, cred.RefreshToken)
			}

			if credWithTTL.TTL != tt.expectedTTL {
				t.Errorf("expected TTL %v, got %v", tt.expectedTTL, credWithTTL.TTL)
			}
		})
	}
}

func TestOptions_JSON(t *testing.T) {
	tests := []struct {
		name    string
		options Options
	}{
		{
			name: "with username and password",
			options: Options{
				Username: "testuser",
				Password: "testpass",
			},
		},
		{
			name: "with only password",
			options: Options{
				Password: "testpass",
			},
		},
		{
			name:    "empty options",
			options: Options{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that Options can be used to create a provider through the factory
			opts := credentialprovider.Options{
				"username": tt.options.Username,
				"password": tt.options.Password,
			}

			provider, err := createStaticCredentialProvider(opts)
			if err != nil {
				t.Errorf("failed to create provider: %v", err)
				return
			}

			if provider == nil {
				t.Error("expected provider, got nil")
				return
			}

			// Verify the provider works
			ctx := context.Background()
			cred, err := provider.Get(ctx, "test.registry.com")
			if err != nil {
				t.Errorf("unexpected error calling Get: %v", err)
				return
			}

			// Verify credentials match expectations
			if tt.options.Username == "" {
				// Refresh token mode
				if cred.RefreshToken != tt.options.Password {
					t.Errorf("expected refresh token %q, got %q", tt.options.Password, cred.RefreshToken)
				}
			} else {
				// Username/password mode
				if cred.Username != tt.options.Username {
					t.Errorf("expected username %q, got %q", tt.options.Username, cred.Username)
				}
				if cred.Password != tt.options.Password {
					t.Errorf("expected password %q, got %q", tt.options.Password, cred.Password)
				}
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

	// Verify it's a CachedProvider by testing its interface
	ctx := context.Background()
	_, err = provider.Get(ctx, "test.registry.com")
	if err != nil {
		t.Errorf("provider.Get failed: %v", err)
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

func BenchmarkProvider_GetWithTTL(b *testing.B) {
	provider := &Provider{
		username: "testuser",
		password: "testpass",
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.GetWithTTL(ctx, "registry.example.com")
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkCachedProvider_Get(b *testing.B) {
	opts := credentialprovider.Options{
		"username": "testuser",
		"password": "testpass",
	}

	provider, err := createStaticCredentialProvider(opts)
	if err != nil {
		b.Fatalf("failed to create provider: %v", err)
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

// Additional comprehensive tests for edge cases and integration scenarios

func TestProvider_GetWithTTL_ContextCancellation(t *testing.T) {
	provider := &Provider{
		username: "testuser",
		password: "testpass",
	}

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// The static provider doesn't actually use context, so it should still work
	credWithTTL, err := provider.GetWithTTL(ctx, "registry.example.com")
	if err != nil {
		t.Errorf("unexpected error with cancelled context: %v", err)
	}

	if credWithTTL.Credential.Username != "testuser" {
		t.Errorf("expected username %q, got %q", "testuser", credWithTTL.Credential.Username)
	}
}

func TestProvider_GetWithTTL_TTLConstant(t *testing.T) {
	provider := &Provider{
		username: "testuser",
		password: "testpass",
	}

	ctx := context.Background()
	credWithTTL, err := provider.GetWithTTL(ctx, "registry.example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Static credential provider returns TTL of 0 (no expiration)
	expectedTTL := time.Duration(0)
	if credWithTTL.TTL != expectedTTL {
		t.Errorf("expected TTL %v, got %v", expectedTTL, credWithTTL.TTL)
	}
}

func TestCachedProvider_Integration(t *testing.T) {
	opts := credentialprovider.Options{
		"username": "testuser",
		"password": "testpass",
	}

	provider, err := createStaticCredentialProvider(opts)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	serverAddr := "registry.example.com"

	// First call should fetch credentials
	cred1, err := provider.Get(ctx, serverAddr)
	if err != nil {
		t.Errorf("unexpected error on first call: %v", err)
	}

	// Second call should return cached credentials (should be identical)
	cred2, err := provider.Get(ctx, serverAddr)
	if err != nil {
		t.Errorf("unexpected error on second call: %v", err)
	}

	// Verify credentials are identical
	if cred1.Username != cred2.Username {
		t.Errorf("cached credentials differ: username %q vs %q", cred1.Username, cred2.Username)
	}
	if cred1.Password != cred2.Password {
		t.Errorf("cached credentials differ: password %q vs %q", cred1.Password, cred2.Password)
	}
	if cred1.RefreshToken != cred2.RefreshToken {
		t.Errorf("cached credentials differ: refresh token %q vs %q", cred1.RefreshToken, cred2.RefreshToken)
	}
}

func TestProvider_EmptyStringValues(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		expected ratify.RegistryCredential
	}{
		{
			name:     "both empty",
			username: "",
			password: "",
			expected: ratify.RegistryCredential{
				RefreshToken: "",
			},
		},
		{
			name:     "empty username, non-empty password",
			username: "",
			password: "token123",
			expected: ratify.RegistryCredential{
				RefreshToken: "token123",
			},
		},
		{
			name:     "non-empty username, empty password",
			username: "user123",
			password: "",
			expected: ratify.RegistryCredential{
				Username: "user123",
				Password: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{
				username: tt.username,
				password: tt.password,
			}

			ctx := context.Background()
			credWithTTL, err := provider.GetWithTTL(ctx, "test.registry.com")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			cred := credWithTTL.Credential

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

func TestProvider_DifferentServerAddresses(t *testing.T) {
	provider := &Provider{
		username: "testuser",
		password: "testpass",
	}

	ctx := context.Background()
	servers := []string{
		"registry.example.com",
		"registry.example.com:443",
		"different.registry.com",
		"localhost:5000",
		"",
	}

	expected := ratify.RegistryCredential{
		Username: "testuser",
		Password: "testpass",
	}

	for _, server := range servers {
		t.Run("server_"+server, func(t *testing.T) {
			credWithTTL, err := provider.GetWithTTL(ctx, server)
			if err != nil {
				t.Errorf("unexpected error for server %q: %v", server, err)
				return
			}

			cred := credWithTTL.Credential

			if cred.Username != expected.Username {
				t.Errorf("expected username %q, got %q for server %q", expected.Username, cred.Username, server)
			}
			if cred.Password != expected.Password {
				t.Errorf("expected password %q, got %q for server %q", expected.Password, cred.Password, server)
			}
		})
	}
}

func TestCreateStaticCredentialProvider_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "special characters in username",
			username: "user@domain.com",
			password: "pass123",
		},
		{
			name:     "special characters in password",
			username: "user",
			password: "p@$$w0rd!@#$%^&*()",
		},
		{
			name:     "unicode characters",
			username: "用户",
			password: "密码123",
		},
		{
			name:     "spaces and tabs",
			username: "user with spaces",
			password: "pass\twith\ttabs",
		},
		{
			name:     "newlines in values",
			username: "user\nwith\nnewlines",
			password: "pass\nwith\nnewlines",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := credentialprovider.Options{
				"username": tt.username,
				"password": tt.password,
			}

			provider, err := createStaticCredentialProvider(opts)
			if err != nil {
				t.Errorf("unexpected error creating provider: %v", err)
				return
			}

			ctx := context.Background()
			cred, err := provider.Get(ctx, "test.registry.com")
			if err != nil {
				t.Errorf("unexpected error getting credentials: %v", err)
				return
			}

			if cred.Username != tt.username {
				t.Errorf("expected username %q, got %q", tt.username, cred.Username)
			}
			if cred.Password != tt.password {
				t.Errorf("expected password %q, got %q", tt.password, cred.Password)
			}
		})
	}
}
