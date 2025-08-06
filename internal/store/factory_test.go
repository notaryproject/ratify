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

package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testType = "test-type"
	testName = "test-name"
)

func createStore(_ NewOptions) (ratify.Store, error) {
	return nil, nil
}

func TestRegisterStoreFactory(t *testing.T) {
	t.Run("Registering an empty type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering an empty type, but did not panic")
			}
		}()
		Register("", createStore)
	})

	t.Run("Registering a nil factory function", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering a nil factory function, but did not panic")
			}
		}()
		Register(testType, nil)
	})

	t.Run("Registering a valid factory function", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Did not expect panic when registering a valid factory function, but got: %v", r)
			}
			delete(registry, testType)
		}()
		Register(testType, createStore)
	})

	t.Run("Registering a duplicate factory function", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering a duplicate factory function, but did not panic")
			}
			delete(registry, testType)
		}()
		Register(testType, createStore)
		Register(testType, createStore)
	})
}

func TestNewStore(t *testing.T) {
	t.Run("Empty store options", func(t *testing.T) {
		_, err := newStore(NewOptions{})
		if err == nil {
			t.Errorf("Expected error when creating a store with empty options, but got nil")
		}
	})

	t.Run("Unregistered store type", func(t *testing.T) {
		_, err := newStore(NewOptions{Type: "unregistered"})
		if err == nil {
			t.Errorf("Expected error when creating a store with unregistered type, but got nil")
		}
	})

	t.Run("Valid store options", func(t *testing.T) {
		Register(testType, createStore)
		defer delete(registry, testType)

		_, err := newStore(NewOptions{Type: testType})
		if err != nil {
			t.Errorf("Did not expect error when creating a store with valid options, but got: %v", err)
		}
	})
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

func newMockStore(_ NewOptions) (ratify.Store, error) {
	return &mockStore{}, nil
}

func newMockStoreWithErr(_ NewOptions) (ratify.Store, error) {
	return nil, fmt.Errorf("mock store error")
}

func TestNew(t *testing.T) {
	Register("mock-store", newMockStore)
	Register("mock-store-with-error", newMockStoreWithErr)
	tests := []struct {
		name          string
		opts          []NewOptions
		globalScopes  []string
		expectedError bool
	}{
		{
			name:          "empty store options",
			opts:          []NewOptions{},
			expectedError: true,
		},
		{
			name: "unregistered store options",
			opts: []NewOptions{
				{
					Type:       "mock",
					Parameters: map[string]any{},
				},
			},
			expectedError: true,
		},
		{
			name: "valid store options",
			opts: []NewOptions{
				{
					Type:       "mock-store",
					Parameters: map[string]any{},
				},
			},
			globalScopes:  []string{"example.com"},
			expectedError: false,
		},
		{
			name: "invalid store scope",
			opts: []NewOptions{
				{
					Type:       "mock-store",
					Parameters: map[string]any{},
				},
			},
			globalScopes:  []string{"*"},
			expectedError: true,
		},
		{
			name: "multiple stores clear global scopes",
			opts: []NewOptions{
				{
					Type:   "mock-store",
					Scopes: []string{"example1.com"},
				},
				{
					Type:   "mock-store",
					Scopes: []string{"example2.com"},
				},
			},
			globalScopes:  []string{"global.com"},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts, tt.globalScopes)
			if (err != nil) != tt.expectedError {
				t.Errorf("NewStore() error = %v, expectedError %v", err, tt.expectedError)
			}
		})
	}
}
