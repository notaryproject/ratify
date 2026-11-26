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
	"errors"
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
)

const stubType = "stub-type"

type reportedDuration struct {
	namespace string
	verifier  string
	success   bool
	isError   bool
}

// captureVerifierDurations swaps the metric reporter for one that records
// every call, and restores it when the test ends.
func captureVerifierDurations(t *testing.T) *[]reportedDuration {
	t.Helper()
	var got []reportedDuration
	orig := reportVerifierDuration
	reportVerifierDuration = func(ctx context.Context, _ int64, verifierName string, success bool, isError bool) {
		got = append(got, reportedDuration{
			namespace: ctxUtils.GetNamespace(ctx),
			verifier:  verifierName,
			success:   success,
			isError:   isError,
		})
	}
	t.Cleanup(func() { reportVerifierDuration = orig })
	return &got
}

// stubVerifier returns the configured result and error from Verify.
type stubVerifier struct {
	result *ratify.VerificationResult
	err    error
}

func (s *stubVerifier) Name() string {
	return mockName
}

func (s *stubVerifier) Type() string {
	return stubType
}

func (s *stubVerifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == stubType
}

func (s *stubVerifier) Verify(_ context.Context, _ *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	return s.result, s.err
}

func TestInstrumentedVerifierVerify(t *testing.T) {
	verifyErr := errors.New("verify error")
	tests := []struct {
		name    string
		stub    *stubVerifier
		success bool
		isError bool
	}{
		{
			name:    "verification succeeded",
			stub:    &stubVerifier{result: &ratify.VerificationResult{}},
			success: true,
		},
		{
			name: "verification failed",
			stub: &stubVerifier{result: &ratify.VerificationResult{Err: errors.New("untrusted signature")}},
		},
		{
			name:    "verifier error",
			stub:    &stubVerifier{err: verifyErr},
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := captureVerifierDurations(t)
			v := &instrumentedVerifier{Verifier: tt.stub}
			ctx := ctxUtils.SetContextWithNamespace(context.Background(), "team-a")

			result, err := v.Verify(ctx, &ratify.VerifyOptions{})
			assert.Same(t, tt.stub.result, result)
			assert.Equal(t, tt.stub.err, err)
			assert.Equal(t, []reportedDuration{{
				namespace: "team-a",
				verifier:  mockName,
				success:   tt.success,
				isError:   tt.isError,
			}}, *got)
		})
	}
}

func TestNewInstrumentsVerifier(t *testing.T) {
	stub := &stubVerifier{result: &ratify.VerificationResult{}}
	Register(stubType, func(_ NewOptions, _ []string) (ratify.Verifier, error) {
		return stub, nil
	})
	defer delete(registeredVerifiers, stubType)

	v, err := New(NewOptions{Name: mockName, Type: stubType}, nil)
	assert.NoError(t, err)
	assert.IsType(t, &instrumentedVerifier{}, v)
	assert.Equal(t, mockName, v.Name())
	assert.Equal(t, stubType, v.Type())
	assert.True(t, v.Verifiable(ocispec.Descriptor{ArtifactType: stubType}))
	assert.False(t, v.Verifiable(ocispec.Descriptor{ArtifactType: mockType}))

	got := captureVerifierDurations(t)
	_, err = v.Verify(context.Background(), &ratify.VerifyOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []reportedDuration{{verifier: mockName, success: true}}, *got)
}

func TestNewDoesNotWrapFailedVerifier(t *testing.T) {
	createErr := errors.New("create error")
	Register(stubType, func(_ NewOptions, _ []string) (ratify.Verifier, error) {
		return nil, createErr
	})
	defer delete(registeredVerifiers, stubType)

	v, err := New(NewOptions{Name: mockName, Type: stubType}, nil)
	assert.ErrorIs(t, err, createErr)
	assert.Nil(t, v)
}
