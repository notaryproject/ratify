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

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

const (
	mockVerifierName       = "mock-verifier-name"
	mockVerifierType       = "mock-verifier-type"
	mockStoreType          = "mock-store"
	mockPolicyEnforcerType = "mock-policy-enforcer"
	validConfig            = `{"executors":[{"scopes":["example.com"],"verifiers":[{"name":"mock-verifier-name","type":"mock-verifier-type"}],"stores":[{"type":"mock-store"}]}]}`
)

type mockVerifier struct{}

func (m *mockVerifier) Name() string {
	return mockVerifierName
}
func (m *mockVerifier) Type() string {
	return mockVerifierType
}
func (m *mockVerifier) Verifiable(_ ocispec.Descriptor) bool {
	return true
}

func (m *mockVerifier) Verify(_ context.Context, _ *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	return &ratify.VerificationResult{}, nil
}

func createMockVerifier(_ *verifier.NewOptions, _ []string) (ratify.Verifier, error) {
	return &mockVerifier{}, nil
}

type mockStore struct{}

func (m *mockStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return nil, nil
}

func (m *mockStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return nil, nil
}

func newMockStore(_ *store.NewOptions) (ratify.Store, error) {
	return &mockStore{}, nil
}

func createPolicyEnforcer(_ policyenforcer.NewOptions) (ratify.PolicyEnforcer, error) {
	return nil, errors.New("mock policy enforcer not implemented")
}

func TestNewWatcher(t *testing.T) {
	store.RegisterStoreFactory(mockStoreType, newMockStore)
	verifier.RegisterVerifierFactory(mockVerifierType, createMockVerifier)
	policyenforcer.Register(mockPolicyEnforcerType, createPolicyEnforcer)

	t.Run("empty config path", func(t *testing.T) {
		watcher, err := NewWatcher("")
		assert.Error(t, err)
		assert.Nil(t, watcher)
	})

	t.Run("invalid config path", func(t *testing.T) {
		watcher, err := NewWatcher("/invalid/path/to/config.json")
		assert.Error(t, err)
		assert.Nil(t, watcher)
	})

	t.Run("invalid json format", func(t *testing.T) {
		invalidConfigPath := filepath.Join(t.TempDir(), "invalid_config.json")
		err := os.WriteFile(invalidConfigPath, []byte(`{"Field1": "value1", "Field2":}`), 0600)
		assert.NoError(t, err)

		watcher, err := NewWatcher(invalidConfigPath)
		assert.Error(t, err)
		assert.Nil(t, watcher)
	})

	t.Run("failed to create Executor", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		failingConfig := `{"verifiers":[{"name":"mock-verifier-name","type":"mock-verifier-type"}],"stores":{"test":{"type":"mock-store"}},"policyEnforcer":{"type":"mock-policy-enforcer"}}`
		err := os.WriteFile(configPath, []byte(failingConfig), 0600)
		assert.NoError(t, err)

		watcher, err := NewWatcher(configPath)
		assert.Error(t, err)
		assert.Nil(t, watcher)
	})

	t.Run("valid config path", func(t *testing.T) {
		validConfigPath := filepath.Join(t.TempDir(), "valid_config.json")
		err := os.WriteFile(validConfigPath, []byte(validConfig), 0600)
		assert.NoError(t, err)

		watcher, err := NewWatcher(validConfigPath)
		assert.NoError(t, err)
		assert.NotNil(t, watcher)
		assert.Equal(t, validConfigPath, watcher.executorConfigPath)

		// Clean up the watcher
		watcher.watcher.Close()
	})
}

func TestStartAndStopWatcher(t *testing.T) {
	t.Run("failed to add watcher", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		err := os.WriteFile(configPath, []byte(validConfig), 0600)
		assert.NoError(t, err)

		watcher, err := NewWatcher(configPath)
		assert.NoError(t, err)
		assert.NotNil(t, watcher)

		watcher.executorConfigPath = "/invalid/path/to/config.json"
		err = watcher.Start()
		assert.Error(t, err)
		defer watcher.Stop()
	})

	t.Run("start and stop watcher", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		err := os.WriteFile(configPath, []byte(validConfig), 0600)
		assert.NoError(t, err)

		watcher, err := NewWatcher(configPath)
		assert.NoError(t, err)
		assert.NotNil(t, watcher)

		err = watcher.Start()
		assert.NoError(t, err)
		defer func() {
			time.Sleep(500 * time.Millisecond)
			watcher.Stop()
		}()

		time.Sleep(500 * time.Millisecond) // Allow some time for the watcher to start

		// Simulate a file change
		_ = os.WriteFile(configPath, []byte(validConfig), 0600)
		assert.NoError(t, err)

		_ = os.Remove(configPath)
	})
}

func TestGetExecutor(t *testing.T) {
	t.Run("get executor with valid config", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		err := os.WriteFile(configPath, []byte(validConfig), 0600)
		assert.NoError(t, err)

		watcher, err := NewWatcher(configPath)
		assert.NoError(t, err)
		assert.NotNil(t, watcher)

		executor := watcher.GetExecutor()
		assert.NotNil(t, executor)
	})
}
