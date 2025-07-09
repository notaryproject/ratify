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
	"errors"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
)

const testServerAddress = "registry.example.com"

// mockCredentialSourceProvider is a mock implementation of CredentialSourceProvider
type mockCredentialSourceProvider struct {
	credentials map[string]CredentialWithTTL
	callCount   map[string]int
	shouldError bool
	errorMsg    string
}

func newMockCredentialSourceProvider() *mockCredentialSourceProvider {
	return &mockCredentialSourceProvider{
		credentials: make(map[string]CredentialWithTTL),
		callCount:   make(map[string]int),
	}
}

func (m *mockCredentialSourceProvider) GetWithTTL(_ context.Context, serverAddress string) (CredentialWithTTL, error) {
	m.callCount[serverAddress]++

	if m.shouldError {
		return CredentialWithTTL{}, errors.New(m.errorMsg)
	}

	if cred, exists := m.credentials[serverAddress]; exists {
		return cred, nil
	}

	// Return a default credential if not found
	return CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: "testuser",
			Password: "testpass",
		},
		TTL: 300 * time.Second,
	}, nil
}

func (m *mockCredentialSourceProvider) setCredential(serverAddress string, cred CredentialWithTTL) {
	m.credentials[serverAddress] = cred
}

func (m *mockCredentialSourceProvider) setError(shouldError bool, errorMsg string) {
	m.shouldError = shouldError
	m.errorMsg = errorMsg
}

func (m *mockCredentialSourceProvider) getCallCount(serverAddress string) int {
	return m.callCount[serverAddress]
}

func TestNewCachedProvider(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()

	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	if provider == nil {
		t.Fatal("Expected non-nil provider")
	}

	if provider.source != mockSource {
		t.Error("Expected source to be set correctly")
	}

	if provider.cache == nil {
		t.Error("Expected cache to be initialized")
	}
}

func TestCachedProvider_Get_CacheMiss(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	expectedCred := CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: "user1",
			Password: "pass1",
		},
		TTL: 600 * time.Second,
	}
	mockSource.setCredential(testServerAddress, expectedCred)

	ctx := context.Background()
	credential, err := provider.Get(ctx, testServerAddress)
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}

	if credential.Username != expectedCred.Credential.Username {
		t.Errorf("Expected username %s, got %s", expectedCred.Credential.Username, credential.Username)
	}

	if credential.Password != expectedCred.Credential.Password {
		t.Errorf("Expected password %s, got %s", expectedCred.Credential.Password, credential.Password)
	}

	// Verify source was called once
	if mockSource.getCallCount(testServerAddress) != 1 {
		t.Errorf("Expected source to be called once, got %d calls", mockSource.getCallCount(testServerAddress))
	}
}

func TestCachedProvider_Get_CacheHit(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	expectedCred := CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: "user1",
			Password: "pass1",
		},
		TTL: 600 * time.Second,
	}
	mockSource.setCredential(testServerAddress, expectedCred)

	ctx := context.Background()

	// First call - should hit source
	credential1, err := provider.Get(ctx, testServerAddress)
	if err != nil {
		t.Fatalf("Failed to get credential on first call: %v", err)
	}

	// Second call - should hit cache
	credential2, err := provider.Get(ctx, testServerAddress)
	if err != nil {
		t.Fatalf("Failed to get credential on second call: %v", err)
	}

	// Verify credentials are the same
	if credential1.Username != credential2.Username || credential1.Password != credential2.Password {
		t.Error("Expected same credentials from cache")
	}

	// Verify source was called only once (cache hit on second call)
	if mockSource.getCallCount(testServerAddress) != 1 {
		t.Errorf("Expected source to be called once, got %d calls", mockSource.getCallCount(testServerAddress))
	}
}

func TestCachedProvider_Get_SourceError(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	mockSource.setError(true, "source provider error")

	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	ctx := context.Background()

	_, err = provider.Get(ctx, testServerAddress)
	if err == nil {
		t.Fatal("Expected error when source provider fails")
	}

	if err.Error() != "source provider error" {
		t.Errorf("Expected 'source provider error', got '%s'", err.Error())
	}
}

func TestCachedProvider_Get_ZeroTTL(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	// Set credential with zero TTL (should not be cached)
	credWithZeroTTL := CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: "user1",
			Password: "pass1",
		},
		TTL: 0,
	}
	mockSource.setCredential(testServerAddress, credWithZeroTTL)

	ctx := context.Background()

	// First call
	_, err = provider.Get(ctx, testServerAddress)
	if err != nil {
		t.Fatalf("Failed to get credential on first call: %v", err)
	}

	// Second call - should hit source again since TTL is 0
	_, err = provider.Get(ctx, testServerAddress)
	if err != nil {
		t.Fatalf("Failed to get credential on second call: %v", err)
	}

	// Verify source was called twice (no caching with zero TTL)
	if mockSource.getCallCount(testServerAddress) != 2 {
		t.Errorf("Expected source to be called twice with zero TTL, got %d calls", mockSource.getCallCount(testServerAddress))
	}
}

func TestCachedProvider_Get_MultipleServers(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	server1 := "registry1.example.com"
	server2 := "registry2.example.com"

	cred1 := CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: "user1",
			Password: "pass1",
		},
		TTL: 300 * time.Second,
	}

	cred2 := CredentialWithTTL{
		Credential: ratify.RegistryCredential{
			Username: "user2",
			Password: "pass2",
		},
		TTL: 300 * time.Second,
	}

	mockSource.setCredential(server1, cred1)
	mockSource.setCredential(server2, cred2)

	ctx := context.Background()

	// Get credentials for both servers
	credential1, err := provider.Get(ctx, server1)
	if err != nil {
		t.Fatalf("Failed to get credential for server1: %v", err)
	}

	credential2, err := provider.Get(ctx, server2)
	if err != nil {
		t.Fatalf("Failed to get credential for server2: %v", err)
	}

	// Verify different credentials are returned
	if credential1.Username == credential2.Username {
		t.Error("Expected different credentials for different servers")
	}

	// Get credentials again (should hit cache)
	_, err = provider.Get(ctx, server1)
	if err != nil {
		t.Fatalf("Failed to get cached credential for server1: %v", err)
	}

	_, err = provider.Get(ctx, server2)
	if err != nil {
		t.Fatalf("Failed to get cached credential for server2: %v", err)
	}

	// Verify each source was called only once
	if mockSource.getCallCount(server1) != 1 {
		t.Errorf("Expected server1 source to be called once, got %d calls", mockSource.getCallCount(server1))
	}

	if mockSource.getCallCount(server2) != 1 {
		t.Errorf("Expected server2 source to be called once, got %d calls", mockSource.getCallCount(server2))
	}
}

func TestCachedProvider_Get_ContextCancellation(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = provider.Get(ctx, testServerAddress)
	// The behavior depends on the cache implementation, but it should handle context cancellation gracefully
	// We're mainly testing that it doesn't panic
}

func TestCachedProvider_Get_EmptyServerAddress(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	ctx := context.Background()

	// Test with empty server address
	credential, err := provider.Get(ctx, "")
	if err != nil {
		t.Fatalf("Failed to get credential with empty server address: %v", err)
	}

	// Should still return the default credential from mock
	if credential.Username != "testuser" {
		t.Errorf("Expected default username 'testuser', got '%s'", credential.Username)
	}
}

func TestCachedProvider_Interface_Compliance(t *testing.T) {
	mockSource := newMockCredentialSourceProvider()
	provider, err := NewCachedProvider(mockSource)
	if err != nil {
		t.Fatalf("Failed to create cached provider: %v", err)
	}

	// Verify that CachedProvider implements ratify.RegistryCredentialGetter interface
	var _ ratify.RegistryCredentialGetter = provider
}
