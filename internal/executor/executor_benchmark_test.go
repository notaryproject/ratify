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
	"testing"

	"github.com/notaryproject/ratify-go"

	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
)

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
