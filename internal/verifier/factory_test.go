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

package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testType = "test-type"
	testName = "test-name"
	mockName = "mock-name"
	mockType = "mock-type"
)

type mockVerifier struct{}

func (m *mockVerifier) Name() string {
	return mockName
}
func (m *mockVerifier) Type() string {
	return mockType
}
func (m *mockVerifier) Verifiable(_ ocispec.Descriptor) bool {
	return true
}

func (m *mockVerifier) Verify(_ context.Context, _ *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	return &ratify.VerificationResult{}, nil
}

func createMockVerifier(_ context.Context, _ plugin.VerifierOptions) (ratify.Verifier, error) {
	return &mockVerifier{}, nil
}

func TestNewVerifier(t *testing.T) {
	var gotOpts plugin.VerifierOptions
	registerTestVerifier(t, testType, func(_ context.Context, opts plugin.VerifierOptions) (ratify.Verifier, error) {
		gotOpts = opts
		return &mockVerifier{}, nil
	})

	t.Run("Creating a verifier with empty name or type", func(t *testing.T) {
		_, err := New(NewOptions{Name: "", Type: testType}, nil)
		if err == nil {
			t.Errorf("Expected error when creating a verifier with empty name, but got none")
		}

		_, err = New(NewOptions{Name: testName, Type: ""}, nil)
		if err == nil {
			t.Errorf("Expected error when creating a verifier with empty type, but got none")
		}
	})

	t.Run("Creating a verifier with unregistered type", func(t *testing.T) {
		_, err := New(NewOptions{Name: testName, Type: "unregistered-type"}, nil)
		if err == nil {
			t.Errorf("Expected error when creating a verifier with unregistered type, but got none")
		}
		assert.ErrorIs(t, err, plugin.ErrNotRegistered)
	})

	t.Run("Creating a verifier with unmarshalable parameters", func(t *testing.T) {
		_, err := New(NewOptions{Name: testName, Type: testType, Parameters: make(chan int)}, nil)
		assert.ErrorContains(t, err, "failed to marshal parameters")
	})

	t.Run("Creating a verifier with registered type", func(t *testing.T) {
		opts := NewOptions{
			Name:       testName,
			Type:       testType,
			Parameters: map[string]any{"key": "value"},
		}
		globalScopes := []string{"example.com"}
		v, err := New(opts, globalScopes)
		if err != nil {
			t.Errorf("Did not expect error when creating a verifier with registered type, but got: %v", err)
		}
		assert.NotNil(t, v)

		// The options are passed through to the plugin factory.
		assert.Equal(t, testName, gotOpts.Name)
		assert.Equal(t, globalScopes, gotOpts.Scopes)
		assert.JSONEq(t, `{"key":"value"}`, string(gotOpts.Parameters))
		assert.Same(t, plugin.Default, gotOpts.Registry)
	})

	t.Run("Creating a verifier with nil parameters", func(t *testing.T) {
		_, err := New(NewOptions{Name: testName, Type: testType}, nil)
		require.NoError(t, err)
		assert.Nil(t, gotOpts.Parameters)
	})
}

func TestNewVerifier_FactoryError(t *testing.T) {
	factoryErr := errors.New("factory error")
	registerTestVerifier(t, "failing-type", func(_ context.Context, _ plugin.VerifierOptions) (ratify.Verifier, error) {
		return nil, factoryErr
	})

	v, err := New(NewOptions{Name: testName, Type: "failing-type"}, nil)
	assert.Nil(t, v)
	assert.ErrorIs(t, err, factoryErr)
	assert.ErrorContains(t, err, `failed to create verifier "test-name" of type "failing-type"`)
}

func TestNewVerifier_RawMessageParameters(t *testing.T) {
	var got json.RawMessage
	registerTestVerifier(t, "raw-type", func(_ context.Context, opts plugin.VerifierOptions) (ratify.Verifier, error) {
		got = opts.Parameters
		return &mockVerifier{}, nil
	})

	raw := json.RawMessage(`{"a":1}`)
	_, err := New(NewOptions{Name: testName, Type: "raw-type", Parameters: raw}, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

func TestNewVerifiers(t *testing.T) {
	registerTestVerifier(t, mockType, createMockVerifier)
	tests := []struct {
		name          string
		opts          []NewOptions
		expectErr     bool
		expectedCount int
	}{
		{
			name:          "no options provided",
			opts:          []NewOptions{},
			expectErr:     true,
			expectedCount: 0,
		},
		{
			name: "error during NewVerifier",
			opts: []NewOptions{
				{
					Name:       "notation-1",
					Type:       "notation",
					Parameters: map[string]interface{}{},
				},
			},
			expectErr: true,
		},
		{
			name: "single valid option",
			opts: []NewOptions{
				{
					Name: mockName,
					Type: mockType,
				},
			},
			expectErr:     false,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifiers, err := NewVerifiers(tt.opts, nil)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, verifiers)
			} else {
				assert.NoError(t, err)
				assert.Len(t, verifiers, tt.expectedCount)
				for _, verifier := range verifiers {
					assert.Implements(t, (*ratify.Verifier)(nil), verifier)
				}
			}
		})
	}
}
