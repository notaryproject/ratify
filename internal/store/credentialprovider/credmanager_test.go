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

package credentialprovider

import (
	"context"
	"fmt"
	"testing"

	"github.com/notaryproject/ratify-go"
)

// mockCredentialProvider is a mock implementation of ratify.RegistryCredentialGetter for testing
type mockCredentialProvider struct {
	username string
	password string
	err      error
}

func (m *mockCredentialProvider) Get(_ context.Context, _ string) (ratify.RegistryCredential, error) {
	if m.err != nil {
		return ratify.RegistryCredential{}, m.err
	}
	return ratify.RegistryCredential{
		Username: m.username,
		Password: m.password,
	}, nil
}

// mockCredentialProviderFactory creates a mock credential provider
func mockCredentialProviderFactory(opts Options) (ratify.RegistryCredentialGetter, error) {
	username, _ := opts["username"].(string)
	password, _ := opts["password"].(string)
	shouldError, _ := opts["error"].(bool)

	provider := &mockCredentialProvider{
		username: username,
		password: password,
	}

	if shouldError {
		provider.err = fmt.Errorf("mock error")
	}

	return provider, nil
}

// mockFailingCredentialProviderFactory creates a factory that always fails
func mockFailingCredentialProviderFactory(_ Options) (ratify.RegistryCredentialGetter, error) {
	return nil, fmt.Errorf("factory creation failed")
}

// resetRegisteredProviders clears the registered providers map for testing
func resetRegisteredProviders() {
	registeredProviders = nil
}

func TestRegisterCredentialProviderFactory(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		create       func(Options) (ratify.RegistryCredentialGetter, error)
		expectPanic  bool
		panicMessage string
	}{
		{
			name:         "valid registration",
			providerType: "test-provider",
			create:       mockCredentialProviderFactory,
			expectPanic:  false,
		},
		{
			name:         "empty provider type should panic",
			providerType: "",
			create:       mockCredentialProviderFactory,
			expectPanic:  true,
			panicMessage: "credential provider type cannot be empty",
		},
		{
			name:         "nil create function should panic",
			providerType: "test-provider",
			create:       nil,
			expectPanic:  true,
			panicMessage: "credential provider factory cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the registered providers before each test
			resetRegisteredProviders()

			if tt.expectPanic {
				defer func() {
					if r := recover(); r != nil {
						if r != tt.panicMessage {
							t.Errorf("expected panic message %q, got %q", tt.panicMessage, r)
						}
					} else {
						t.Errorf("expected panic but none occurred")
					}
				}()
			}

			RegisterCredentialProviderFactory(tt.providerType, tt.create)

			if !tt.expectPanic {
				// Verify the provider was registered
				if registeredProviders == nil {
					t.Errorf("registeredProviders should not be nil after registration")
					return
				}
				if _, exists := registeredProviders[tt.providerType]; !exists {
					t.Errorf("provider type %s should be registered", tt.providerType)
				}
			}
		})
	}
}

func TestRegisterCredentialProviderFactory_DuplicateRegistration(t *testing.T) {
	resetRegisteredProviders()

	// First registration should succeed
	RegisterCredentialProviderFactory("test-provider", mockCredentialProviderFactory)

	// Second registration of the same provider type should panic
	defer func() {
		if r := recover(); r != nil {
			expected := "credential provider factory type test-provider already registered"
			if r != expected {
				t.Errorf("expected panic message %q, got %q", expected, r)
			}
		} else {
			t.Errorf("expected panic for duplicate registration but none occurred")
		}
	}()

	RegisterCredentialProviderFactory("test-provider", mockCredentialProviderFactory)
}

func TestNewCredentialProvider(t *testing.T) {
	tests := []struct {
		name        string
		opts        Options
		setupFunc   func()
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil options should return error",
			opts:        nil,
			expectError: true,
			errorMsg:    "credential provider options cannot be nil",
		},
		{
			name:        "missing provider field should return error",
			opts:        Options{},
			expectError: true,
			errorMsg:    "provider field is required in credential provider options",
		},
		{
			name: "non-string provider field should return error",
			opts: Options{
				"provider": 123,
			},
			expectError: true,
			errorMsg:    "provider field must be a string",
		},
		{
			name: "empty provider field should return error",
			opts: Options{
				"provider": "",
			},
			expectError: true,
			errorMsg:    "provider field cannot be empty",
		},
		{
			name: "unregistered provider type should return error",
			opts: Options{
				"provider": "unregistered-provider",
			},
			setupFunc: func() {
				resetRegisteredProviders()
			},
			expectError: true,
			errorMsg:    "credential provider factory of type unregistered-provider is not registered",
		},
		{
			name: "valid provider creation should succeed",
			opts: Options{
				"provider": "test-provider",
				"username": "testuser",
				"password": "testpass",
			},
			setupFunc: func() {
				resetRegisteredProviders()
				RegisterCredentialProviderFactory("test-provider", mockCredentialProviderFactory)
			},
			expectError: false,
		},
		{
			name: "provider factory returning error should propagate error",
			opts: Options{
				"provider": "failing-provider",
			},
			setupFunc: func() {
				resetRegisteredProviders()
				RegisterCredentialProviderFactory("failing-provider", mockFailingCredentialProviderFactory)
			},
			expectError: true,
			errorMsg:    "factory creation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
			}

			provider, err := NewCredentialProvider(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if err.Error() != tt.errorMsg {
					t.Errorf("expected error message %q, got %q", tt.errorMsg, err.Error())
				}
				if provider != nil {
					t.Errorf("expected nil provider when error occurs, got %v", provider)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if provider == nil {
					t.Errorf("expected non-nil provider but got nil")
				}
			}
		})
	}
}

func TestNewCredentialProvider_Integration(t *testing.T) {
	// Test the full integration with a working provider
	resetRegisteredProviders()
	RegisterCredentialProviderFactory("mock-provider", mockCredentialProviderFactory)

	opts := Options{
		"provider": "mock-provider",
		"username": "testuser",
		"password": "testpass",
	}

	provider, err := NewCredentialProvider(opts)
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	// Test that the provider actually works
	ctx := context.Background()
	cred, err := provider.Get(ctx, "registry.example.com")
	if err != nil {
		t.Fatalf("unexpected error getting credentials: %v", err)
	}

	if cred.Username != "testuser" {
		t.Errorf("expected username %q, got %q", "testuser", cred.Username)
	}
	if cred.Password != "testpass" {
		t.Errorf("expected password %q, got %q", "testpass", cred.Password)
	}
}

func TestNewCredentialProvider_ProviderError(t *testing.T) {
	// Test that errors from the provider are properly handled
	resetRegisteredProviders()
	RegisterCredentialProviderFactory("error-provider", mockCredentialProviderFactory)

	opts := Options{
		"provider": "error-provider",
		"error":    true, // This will cause the mock provider to return an error
	}

	provider, err := NewCredentialProvider(opts)
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	// Test that the provider returns the expected error
	ctx := context.Background()
	_, err = provider.Get(ctx, "registry.example.com")
	if err == nil {
		t.Errorf("expected error from provider but got none")
	} else if err.Error() != "mock error" {
		t.Errorf("expected error message %q, got %q", "mock error", err.Error())
	}
}

// Benchmark tests to ensure performance
func BenchmarkRegisterCredentialProviderFactory(b *testing.B) {
	for i := 0; i < b.N; i++ {
		resetRegisteredProviders()
		RegisterCredentialProviderFactory("test-provider", mockCredentialProviderFactory)
	}
}

func BenchmarkNewCredentialProvider(b *testing.B) {
	resetRegisteredProviders()
	RegisterCredentialProviderFactory("test-provider", mockCredentialProviderFactory)

	opts := Options{
		"provider": "test-provider",
		"username": "testuser",
		"password": "testpass",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewCredentialProvider(opts)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// Test concurrent access to ensure thread safety
func TestConcurrentRegistration(t *testing.T) {
	resetRegisteredProviders()

	done := make(chan bool, 2)

	// Register different providers concurrently
	go func() {
		defer func() {
			done <- true
		}()
		RegisterCredentialProviderFactory("provider1", mockCredentialProviderFactory)
	}()

	go func() {
		defer func() {
			done <- true
		}()
		RegisterCredentialProviderFactory("provider2", mockCredentialProviderFactory)
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Verify that at least some providers were registered
	if registeredProviders == nil {
		t.Errorf("registeredProviders should not be nil after concurrent registration")
	}
}

func TestConcurrentProviderCreation(t *testing.T) {
	resetRegisteredProviders()
	RegisterCredentialProviderFactory("concurrent-provider", mockCredentialProviderFactory)

	done := make(chan bool, 10)

	// Create providers concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			opts := Options{
				"provider": "concurrent-provider",
				"username": fmt.Sprintf("user%d", id),
				"password": fmt.Sprintf("pass%d", id),
			}

			provider, err := NewCredentialProvider(opts)
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", id, err)
				return
			}

			if provider == nil {
				t.Errorf("goroutine %d: expected non-nil provider", id)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
