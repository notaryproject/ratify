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
	"github.com/notaryproject/ratify/v2/internal/verifier/factory"
	"github.com/stretchr/testify/assert"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
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

func createMockVerifier(_ *factory.NewVerifierOptions, _ []string) (ratify.Verifier, error) {
	return &mockVerifier{}, nil
}

func TestNewVerifiers(t *testing.T) {
	factory.RegisterVerifierFactory("mock-type", createMockVerifier)
	tests := []struct {
		name          string
		opts          []*factory.NewVerifierOptions
		expectErr     bool
		expectedCount int
	}{
		{
			name:          "no options provided",
			opts:          []*factory.NewVerifierOptions{},
			expectErr:     true,
			expectedCount: 0,
		},
		{
			name: "error during NewVerifier",
			opts: []*factory.NewVerifierOptions{
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
			opts: []*factory.NewVerifierOptions{
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
