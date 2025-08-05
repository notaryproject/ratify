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

package controller

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify-go"
	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	e "github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	mockVerifierName = "mock-verifier-name"
	mockVerifierType = "mock-verifier-type"
	mockStoreType    = "mock-store-type"
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

func createMockVerifier(verifier.NewOptions, []string) (ratify.Verifier, error) {
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

func newMockStore(_ store.NewOptions) (ratify.Store, error) {
	return &mockStore{}, nil
}

func init() {
	// Register mock verifier and store factories for testing
	verifier.Register(mockVerifierType, createMockVerifier)
	store.Register(mockStoreType, newMockStore)
}

// helper returns a minimal, but valid, Executor CRD object that satisfies
// convertOptions’ validation rules (verifiers and stores must be non-nil).
func newValidExecutor() *configv2alpha1.Executor {
	return &configv2alpha1.Executor{
		Spec: configv2alpha1.ExecutorSpec{
			Scopes: []string{"example.com"},
			Verifiers: []*configv2alpha1.VerifierOptions{
				{
					Name: mockVerifierName,
					Type: mockVerifierType,
				},
			},
			Stores: []*configv2alpha1.StoreOptions{
				{
					Type: mockStoreType,
				},
			},
		},
	}
}

func TestUpsertExecutor_NilOptions(t *testing.T) {
	mgr := executorManager{opts: map[string]e.ScopedOptions{}}
	if err := mgr.upsertExecutor("default", "nil-exec", nil); err == nil {
		t.Fatalf("expected error when opts is nil")
	}
}

func TestUpsertExecutor_InsertAndCreateExecutor(t *testing.T) {
	mgr := executorManager{opts: map[string]e.ScopedOptions{}}

	if err := mgr.upsertExecutor("default", "exec1", newValidExecutor()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := len(mgr.opts); got != 1 {
		t.Fatalf("expected 1 entry in opts map, got %d", got)
	}

	if exec := mgr.GetExecutor(); exec == nil {
		t.Fatalf("expected non-nil executor after upsert")
	}
}

func TestUpsertExecutor_InvalidOpts(t *testing.T) {
	mgr := executorManager{opts: map[string]e.ScopedOptions{}}
	executorOpts := newValidExecutor()
	executorOpts.Spec.Verifiers = nil // Invalid because verifiers cannot be empty
	if err := mgr.upsertExecutor("default", "invalid-exec", executorOpts); err == nil {
		t.Fatalf("expected error when verifiers are nil, got nil")
	}

	executorOpts = newValidExecutor()
	executorOpts.Spec.Stores = nil // Invalid because stores cannot be empty
	if err := mgr.upsertExecutor("default", "invalid-exec", executorOpts); err == nil {
		t.Fatalf("expected error when stores are nil, got nil")
	}
}

func TestUpsertExecutor_UpdateExistingEntry(t *testing.T) {
	mgr := executorManager{opts: map[string]e.ScopedOptions{}}

	if err := mgr.upsertExecutor("default", "exec1", newValidExecutor()); err != nil {
		t.Fatalf("initial upsert failed: %v", err)
	}

	// perform an update with (slightly) different spec
	updated := newValidExecutor()
	updated.Spec.Scopes = []string{"example2.com"}

	if err := mgr.upsertExecutor("default", "exec1", updated); err != nil {
		t.Fatalf("update upsert failed: %v", err)
	}

	if got := len(mgr.opts); got != 1 {
		t.Fatalf("expected opts map size to remain 1 after update, got %d", got)
	}

	if exec := mgr.GetExecutor(); exec == nil {
		t.Fatalf("expected executor to still be non-nil after update")
	}
}

func TestDeleteExecutor_NotFound(t *testing.T) {
	mgr := executorManager{opts: map[string]e.ScopedOptions{}}

	if err := mgr.deleteExecutor("default", "nonexistent"); err == nil {
		t.Fatalf("expected error when deleting non-existing executor, got nil")
	}

	if got := len(mgr.opts); got != 0 {
		t.Fatalf("expected opts map size to remain 0, got %d", got)
	}
}

// TestDeleteExecutor_RemoveExistingEntry ensures that deleting an existing
// executor succeeds and updates the internal state correctly.
func TestDeleteExecutor_RemoveExistingEntry(t *testing.T) {
	mgr := executorManager{opts: map[string]e.ScopedOptions{}}

	// Add two executors so that after deletion at least one remains.
	if err := mgr.upsertExecutor("default", "exec1", newValidExecutor()); err != nil {
		t.Fatalf("failed to upsert exec1: %v", err)
	}
	executor2 := newValidExecutor()
	executor2.Spec.Scopes = []string{"example2.com"}
	if err := mgr.upsertExecutor("default", "exec2", executor2); err != nil {
		t.Fatalf("failed to upsert exec2: %v", err)
	}

	if got := len(mgr.opts); got != 2 {
		t.Fatalf("expected 2 executors before deletion, got %d", got)
	}

	// Delete one of the executors.
	if err := mgr.deleteExecutor("default", "exec1"); err != nil {
		t.Fatalf("unexpected error during delete: %v", err)
	}

	if got := len(mgr.opts); got != 1 {
		t.Fatalf("expected 1 executor after deletion, got %d", got)
	}

	if mgr.GetExecutor() == nil {
		t.Fatalf("expected non-nil executor after deletion")
	}
}
