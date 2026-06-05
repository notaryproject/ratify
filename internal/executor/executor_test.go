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

package executor

import (
	"context"
	"sync"
	"testing"

	"github.com/notaryproject/ratify-go"

	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	mockVerifierName       = "mock-verifier-name"
	mockVerifierType       = "mock-verifier-type"
	mockStoreType          = "mock-store"
	mockPolicyEnforcerType = "mock-policy-enforcer"
)

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

func newMockStore(_ store.NewOptions) (ratify.Store, error) {
	return &mockStore{}, nil
}

type mockPolicyEnforcer struct{}

func (m *mockPolicyEnforcer) Evaluator(_ context.Context, _ string) (ratify.Evaluator, error) {
	return nil, nil
}

func createPolicyEnforcer(_ policyenforcer.NewOptions) (ratify.PolicyEnforcer, error) {
	return &mockPolicyEnforcer{}, nil
}

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

func createMockVerifier(_ verifier.NewOptions, _ []string) (ratify.Verifier, error) {
	return &mockVerifier{}, nil
}

func TestNewExecutor(t *testing.T) {
	registerMocks()

	tests := []struct {
		name           string
		opts           Options
		expectErr      bool
		expectExecutor bool
	}{
		{
			name:           "failed to create verifiers",
			opts:           Options{},
			expectErr:      true,
			expectExecutor: false,
		},
		{
			name: "empty global scopes",
			opts: Options{
				Executors: []ScopedOptions{{}},
			},
			expectErr:      true,
			expectExecutor: false,
		},
		{
			name: "invalid executor scopes",
			opts: Options{
				Executors: []ScopedOptions{
					{
						Scopes: []string{"*"},
						Verifiers: []verifier.NewOptions{
							{
								Name: mockVerifierName,
								Type: mockVerifierType,
							},
						},
						Stores: []store.NewOptions{
							{
								Type:   mockStoreType,
								Scopes: []string{"testrepo"},
							},
						},
						Policy: &policyenforcer.NewOptions{
							Type: mockPolicyEnforcerType,
						},
					},
				},
			},
			expectErr:      true,
			expectExecutor: false,
		},
		{
			name: "failed to create store",
			opts: Options{
				Executors: []ScopedOptions{
					{
						Scopes: []string{"testrepo"},
						Verifiers: []verifier.NewOptions{
							{
								Name: mockVerifierName,
								Type: mockVerifierType,
							},
						},
					},
				},
			},
			expectErr:      true,
			expectExecutor: false,
		},
		{
			name: "failed to create policy enforcer",
			opts: Options{
				Executors: []ScopedOptions{
					{
						Scopes: []string{"test"},
						Verifiers: []verifier.NewOptions{
							{
								Name: mockVerifierName,
								Type: mockVerifierType,
							},
						},
						Stores: []store.NewOptions{
							{
								Type:   mockStoreType,
								Scopes: []string{"test"},
							},
						},
						Policy: &policyenforcer.NewOptions{
							Type: "invalid-policy-enforcer-type",
						},
					},
				},
			},
			expectErr:      true,
			expectExecutor: false,
		},
		{
			name: "valid options",
			opts: Options{
				Executors: []ScopedOptions{
					{
						Scopes: []string{"test"},
						Verifiers: []verifier.NewOptions{
							{
								Name: mockVerifierName,
								Type: mockVerifierType,
							},
						},
						Stores: []store.NewOptions{
							{
								Type:   mockStoreType,
								Scopes: []string{"test"},
							},
						},
						Policy: &policyenforcer.NewOptions{
							Type: mockPolicyEnforcerType,
						},
					},
				},
			},
			expectErr:      false,
			expectExecutor: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, err := NewScopedExecutor(test.opts)
			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}
			if (executor != nil) != test.expectExecutor {
				t.Errorf("expected executor: %v, got: %v", test.expectExecutor, executor != nil)
			}
		})
	}
}

func TestRegisterExecutor(t *testing.T) {
	tests := []struct {
		name             string
		scope            string
		executor         *ratify.Executor
		registerError    bool
		wildcardScoped   bool
		registryScoped   bool
		repositoryScoped bool
	}{
		{
			name:          "Register executor with global wildcard scope",
			scope:         "*",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:          "Register executor with empty scope",
			scope:         "",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:          "Register nil executor",
			scope:         "registry.example.com",
			registerError: true,
		},
		{
			name:           "Register executor with registry scope",
			scope:          "registry.example.com",
			executor:       &ratify.Executor{},
			registerError:  false,
			registryScoped: true,
		},
		{
			name:          "Register repository scoped executor with wildcard scope",
			scope:         "registry.example.com/repository*",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:          "Register repository scoped executor with invalid registry",
			scope:         ":invalid/repository",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:          "Register repository scoped executor with tag",
			scope:         "registry.example.com/repository:tag",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:             "Register executor with repository scope",
			scope:            "registry.example.com/repository",
			executor:         &ratify.Executor{},
			registerError:    false,
			repositoryScoped: true,
		},
		{
			name:          "Register registry scoped executor with invalid registry",
			scope:         ":invalid",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:          "Register registry scoped executor with multiple wildcards",
			scope:         "*.example.com.*",
			executor:      &ratify.Executor{},
			registerError: true,
		},
		{
			name:           "Register wildcard scoped executor",
			scope:          "*.example.com",
			executor:       &ratify.Executor{},
			registerError:  false,
			wildcardScoped: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scopedExecutor := &ScopedExecutor{}
			err := scopedExecutor.registerExecutor(test.scope, test.executor)
			if (err != nil) != test.registerError {
				t.Errorf("expected register error: %v, got: %v", test.registerError, err)
			}

			if !test.registerError {
				if test.wildcardScoped && len(scopedExecutor.wildcard) == 0 {
					t.Errorf("expected wildcard scoped executors to be registered, but got none")
				}
				if test.registryScoped && len(scopedExecutor.registry) == 0 {
					t.Errorf("expected registry scoped executors to be registered, but got none")
				}
				if test.repositoryScoped && len(scopedExecutor.repository) == 0 {
					t.Errorf("expected repository scoped executors to be registered, but got none")
				}
			}
		})
	}
}

func TestMatchExecutor(t *testing.T) {
	e1 := &ratify.Executor{}
	e2 := &ratify.Executor{}
	e3 := &ratify.Executor{}
	scopedExecutor := &ScopedExecutor{
		wildcard: map[string]*ratify.Executor{
			"example.com": e1,
		},
		registry: map[string]*ratify.Executor{
			"registry.example.com": e2,
		},
		repository: map[string]*ratify.Executor{
			"registry.example.com/repository/foo": e3,
		},
	}
	tests := []struct {
		name             string
		artifact         string
		expectedExecutor *ratify.Executor
		expectedError    bool
	}{
		{
			name:             "Invalid artifact",
			artifact:         "invalid-artifact",
			expectedExecutor: nil,
			expectedError:    true,
		},
		{
			name:             "Match wildcard executor",
			artifact:         "foo.example.com/bar:v1",
			expectedExecutor: e1,
			expectedError:    false,
		},
		{
			name:             "Match registry executor",
			artifact:         "registry.example.com/foo:v1",
			expectedExecutor: e2,
			expectedError:    false,
		},
		{
			name:             "Match repository executor",
			artifact:         "registry.example.com/repository/foo:v1",
			expectedExecutor: e3,
			expectedError:    false,
		},
		{
			name:             "No match",
			artifact:         "unknown.com/foo:v1",
			expectedExecutor: nil,
			expectedError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, err := scopedExecutor.matchExecutor(test.artifact)
			if (err != nil) != test.expectedError {
				t.Errorf("expected error: %v, got: %v", test.expectedError, err)
			}
			if executor != test.expectedExecutor {
				t.Errorf("expected executor: %v, got: %v", test.expectedExecutor, executor)
			}
		})
	}
}

func TestValidateArtifact(t *testing.T) {
	scopedExecutor := &ScopedExecutor{
		wildcard: map[string]*ratify.Executor{
			"example.com": {},
		},
	}

	if _, err := scopedExecutor.ValidateArtifact(context.Background(), "unknown.com/foo:v1"); err == nil {
		t.Error("expected error for unknown artifact, got nil")
	}

	if _, err := scopedExecutor.ValidateArtifact(context.Background(), "test.example.com/foo:v1"); err == nil {
		t.Error("expected error for artifact with wildcard scope, got nil")
	}
}

func TestResolve(t *testing.T) {
	scopedExecutor := &ScopedExecutor{
		wildcard: map[string]*ratify.Executor{
			"example.com": {
				Store: &mockStore{},
			},
		},
	}

	if _, err := scopedExecutor.Resolve(context.Background(), "unknown.com/foo:v1"); err == nil {
		t.Error("expected error for invalid artifact, got nil")
	}

	if _, err := scopedExecutor.Resolve(context.Background(), "test.example.com/foo:v1"); err != nil {
		t.Error("expected no error for valid artifact with wildcard scope, got:", err)
	}
}

// benchScopedExecutor returns a ScopedExecutor populated with executors for
// each scope tier, used by the routing benchmarks below.
func benchScopedExecutor() *ScopedExecutor {
	return &ScopedExecutor{
		wildcard: map[string]*ratify.Executor{
			"example.com": {},
		},
		registry: map[string]*ratify.Executor{
			"registry.example.com": {},
		},
		repository: map[string]*ratify.Executor{
			"registry.example.com/repository/foo": {},
		},
	}
}

// BenchmarkMatchExecutor measures the scope-routing hot path that runs on every
// validation request. Each sub-benchmark targets a different precedence tier
// (repository, registry, wildcard) plus the no-match failure path.
func BenchmarkMatchExecutor(b *testing.B) {
	scopedExecutor := benchScopedExecutor()
	cases := []struct {
		name     string
		artifact string
	}{
		{"repository", "registry.example.com/repository/foo:v1"},
		{"registry", "registry.example.com/foo:v1"},
		{"wildcard", "foo.example.com/bar:v1"},
		{"no-match", "unknown.com/foo:v1"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				//nolint:errcheck // error path is intentionally exercised by the no-match case
				_, _ = scopedExecutor.matchExecutor(c.artifact)
			}
		})
	}
}

// registerMocksOnce guards the one-time registration of the in-package mocks.
// The underlying factory Register functions panic on duplicate registration,
// so all callers (tests and benchmarks) funnel through registerMocks to ensure
// the mocks are registered exactly once per test binary.
var registerMocksOnce sync.Once

// registerMocks registers the in-package store, verifier and policy-enforcer
// mocks exactly once, regardless of how many tests or benchmark iterations
// invoke it. Using sync.Once avoids relying on recover/panic-message matching
// to tolerate duplicate registration.
func registerMocks() {
	registerMocksOnce.Do(func() {
		store.Register(mockStoreType, newMockStore)
		verifier.Register(mockVerifierType, createMockVerifier)
		policyenforcer.Register(mockPolicyEnforcerType, createPolicyEnforcer)
	})
}

// BenchmarkValidateArtifact measures the end-to-end validation path through a
// fully wired ScopedExecutor backed by the in-package mocks (store, verifier
// and policy enforcer). It is intended as an observability signal for the
// whole request flow and is intentionally NOT part of the regression gate,
// since its result depends on mock behavior rather than a single hot function.
func BenchmarkValidateArtifact(b *testing.B) {
	registerMocks()

	scopedExecutor, err := NewScopedExecutor(Options{
		Executors: []ScopedOptions{
			{
				Scopes: []string{"test"},
				Verifiers: []verifier.NewOptions{
					{
						Name: mockVerifierName,
						Type: mockVerifierType,
					},
				},
				Stores: []store.NewOptions{
					{
						Type:   mockStoreType,
						Scopes: []string{"test"},
					},
				},
				Policy: &policyenforcer.NewOptions{
					Type: mockPolicyEnforcerType,
				},
			},
		},
	})
	if err != nil {
		b.Fatalf("failed to create scoped executor: %v", err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//nolint:errcheck // the mock validation result/error is not asserted in a benchmark
		_, _ = scopedExecutor.ValidateArtifact(ctx, "test/foo:v1")
	}
}
