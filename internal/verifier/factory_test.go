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
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

const (
	testType = "test-type"
	testName = "test-name"
	mockName = "mock-name"
	mockType = "mock-type"
)

func createVerifier(_ NewOptions, _ []string) (ratify.Verifier, error) {
	return nil, nil
}
func TestRegisterVerifierFactory(t *testing.T) {
	t.Run("Registering an empty type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering an empty type, but did not panic")
			}
		}()
		Register("", createVerifier)
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
			delete(registeredVerifiers, "test-type")
		}()
		Register(testType, createVerifier)
	})

	t.Run("Registering a duplicate type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering a duplicate type, but did not panic")
			}
			delete(registeredVerifiers, testType)
		}()
		Register(testType, createVerifier)
		Register(testType, createVerifier)
	})
}

func TestNewVerifier(t *testing.T) {
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
	})

	t.Run("Creating a verifier with registered type", func(t *testing.T) {
		Register(testType, createVerifier)
		defer func() {
			delete(registeredVerifiers, testType)
		}()

		opts := NewOptions{Name: testName, Type: testType}
		_, err := New(opts, nil)
		if err != nil {
			t.Errorf("Did not expect error when creating a verifier with registered type, but got: %v", err)
		}
	})
}

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

func createMockVerifier(_ NewOptions, _ []string) (ratify.Verifier, error) {
	return &mockVerifier{}, nil
}

func TestNewVerifiers(t *testing.T) {
	Register("mock-type", createMockVerifier)
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
