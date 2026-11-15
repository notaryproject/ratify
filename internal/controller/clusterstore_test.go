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
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/notaryproject/ratify-go"
	configv2beta1 "github.com/notaryproject/ratify/v2/api/v2beta1"
	e "github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/notaryproject/ratify/v2/internal/store"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	namedStoreType       = "named-store-type"
	namedStoreAnnotation = "store"
)

// namedStore is a [ratify.Store] that returns its name from every call, so
// that tests can tell which store served a request.
type namedStore struct {
	name string
}

func (s *namedStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{Annotations: map[string]string{namedStoreAnnotation: s.name}}, nil
}

func (s *namedStore) ListReferrers(_ context.Context, _ string, _ []string, fn func(referrers []ocispec.Descriptor) error) error {
	return fn([]ocispec.Descriptor{{Annotations: map[string]string{namedStoreAnnotation: s.name}}})
}

func (s *namedStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return []byte(s.name), nil
}

func (s *namedStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return []byte(s.name), nil
}

func newNamedStore(opts store.NewOptions) (ratify.Store, error) {
	raw, err := json.Marshal(opts.Parameters)
	if err != nil {
		return nil, err
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return nil, err
	}
	return &namedStore{name: name}, nil
}

func init() {
	store.Register(namedStoreType, newNamedStore)
}

// newExecutorWithNamedStore returns an ExecutorSpec scoped to the given scope
// whose single store is a namedStore with the given name.
func newExecutorWithNamedStore(scope, name string) *configv2beta1.ExecutorSpec {
	spec := newValidExecutor()
	spec.Scopes = []string{scope}
	spec.Stores = []*configv2beta1.StoreOptions{
		{
			Type:       namedStoreType,
			Parameters: runtime.RawExtension{Raw: []byte(`"` + name + `"`)},
		},
	}
	return spec
}

// newExecutorWithoutStores returns an ExecutorSpec scoped to the given scope
// without stores.
func newExecutorWithoutStores(scope string) *configv2beta1.ExecutorSpec {
	spec := newValidExecutor()
	spec.Scopes = []string{scope}
	spec.Stores = nil
	return spec
}

// TestClusterStore_RoutesToClusterStore ensures that every call of a
// namespaced executor without stores is served by the store of the matching
// cluster-scoped executor, and that the namespaced executor follows updates of
// the cluster-scoped executor without being rebuilt.
func TestClusterStore_RoutesToClusterStore(t *testing.T) {
	mgr := newTestManager()
	ctx := context.Background()
	if err := mgr.upsertExecutor(clusterScopeNamespace, "cluster-a", newExecutorWithNamedStore("a.example.com", "store-a")); err != nil {
		t.Fatalf("failed to upsert cluster executor: %v", err)
	}
	if err := mgr.upsertExecutor(clusterScopeNamespace, "cluster-b", newExecutorWithNamedStore("b.example.com", "store-b")); err != nil {
		t.Fatalf("failed to upsert cluster executor: %v", err)
	}
	if err := mgr.upsertExecutor("team-a", "exec1", newExecutorWithoutStores("*")); err != nil {
		t.Fatalf("failed to upsert namespaced executor: %v", err)
	}
	namespacedExecutor := mgr.GetExecutor("team-a")
	if namespacedExecutor == mgr.GetExecutor(clusterScopeNamespace) {
		t.Fatalf("expected the namespaced executor to differ from the cluster-scoped executor")
	}
	inherited, err := namespacedExecutor.Store("a.example.com/foo:v1")
	if err != nil {
		t.Fatalf("failed to get the store of the namespaced executor: %v", err)
	}

	desc, err := namespacedExecutor.Resolve(ctx, "[team-a]a.example.com/foo:v1")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := desc.Annotations[namedStoreAnnotation]; got != "store-a" {
		t.Errorf("Resolve() served by %q, want %q", got, "store-a")
	}

	var referrers []ocispec.Descriptor
	err = inherited.ListReferrers(ctx, "b.example.com/foo:v1", nil, func(r []ocispec.Descriptor) error {
		referrers = append(referrers, r...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListReferrers() error = %v", err)
	}
	if len(referrers) != 1 || referrers[0].Annotations[namedStoreAnnotation] != "store-b" {
		t.Errorf("ListReferrers() = %v, want a single referrer served by %q", referrers, "store-b")
	}

	blob, err := inherited.FetchBlob(ctx, "a.example.com/foo", ocispec.Descriptor{})
	if err != nil {
		t.Fatalf("FetchBlob() error = %v", err)
	}
	if string(blob) != "store-a" {
		t.Errorf("FetchBlob() served by %q, want %q", blob, "store-a")
	}

	manifest, err := inherited.FetchManifest(ctx, "b.example.com/foo", ocispec.Descriptor{})
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if string(manifest) != "store-b" {
		t.Errorf("FetchManifest() served by %q, want %q", manifest, "store-b")
	}

	// Updating the cluster-scoped executor takes effect for the namespaced
	// executor immediately.
	if err := mgr.upsertExecutor(clusterScopeNamespace, "cluster-a", newExecutorWithNamedStore("a.example.com", "store-a-updated")); err != nil {
		t.Fatalf("failed to update cluster executor: %v", err)
	}
	if mgr.GetExecutor("team-a") != namespacedExecutor {
		t.Fatalf("expected the namespaced executor not to be rebuilt")
	}
	desc, err = namespacedExecutor.Resolve(ctx, "a.example.com/foo:v1")
	if err != nil {
		t.Fatalf("Resolve() after update error = %v", err)
	}
	if got := desc.Annotations[namedStoreAnnotation]; got != "store-a-updated" {
		t.Errorf("Resolve() after update served by %q, want %q", got, "store-a-updated")
	}
}

// TestClusterStore_OwnStoresPreferred ensures that a namespaced executor with
// its own stores does not use the cluster-wide stores.
func TestClusterStore_OwnStoresPreferred(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.upsertExecutor(clusterScopeNamespace, "cluster", newExecutorWithNamedStore("example.com", "cluster-store")); err != nil {
		t.Fatalf("failed to upsert cluster executor: %v", err)
	}
	if err := mgr.upsertExecutor("team-a", "exec1", newExecutorWithNamedStore("example.com", "team-store")); err != nil {
		t.Fatalf("failed to upsert namespaced executor: %v", err)
	}

	desc, err := mgr.GetExecutor("team-a").Resolve(context.Background(), "example.com/foo:v1")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := desc.Annotations[namedStoreAnnotation]; got != "team-store" {
		t.Errorf("Resolve() served by %q, want %q", got, "team-store")
	}
}

// TestClusterStore_NoClusterStore ensures that a namespaced executor without
// stores reports an error when no cluster-scoped executor serves the artifact,
// and that the error does not wrap ErrNoExecutorMatched, which would make the
// mutation webhook skip the artifact.
func TestClusterStore_NoClusterStore(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		clusterScope   string
		wantErrMessage string
	}{
		{
			name:           "no cluster-scoped executor",
			wantErrMessage: "no cluster-scoped Executor is configured",
		},
		{
			name:           "no matching cluster-scoped executor",
			clusterScope:   "other.example.com",
			wantErrMessage: "no cluster-scoped Executor is scoped to it",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newTestManager()
			if tt.clusterScope != "" {
				if err := mgr.upsertExecutor(clusterScopeNamespace, "cluster", newExecutorWithNamedStore(tt.clusterScope, "cluster-store")); err != nil {
					t.Fatalf("failed to upsert cluster executor: %v", err)
				}
			}
			if err := mgr.upsertExecutor("team-a", "exec1", newExecutorWithoutStores("example.com")); err != nil {
				t.Fatalf("failed to upsert namespaced executor: %v", err)
			}
			inherited, err := mgr.GetExecutor("team-a").Store("example.com/foo:v1")
			if err != nil {
				t.Fatalf("failed to get the store of the namespaced executor: %v", err)
			}

			calls := map[string]func() error{
				"Resolve": func() error {
					_, err := mgr.GetExecutor("team-a").Resolve(ctx, "example.com/foo:v1")
					return err
				},
				"ListReferrers": func() error {
					return inherited.ListReferrers(ctx, "example.com/foo:v1", nil, func([]ocispec.Descriptor) error { return nil })
				},
				"FetchBlob": func() error {
					_, err := inherited.FetchBlob(ctx, "example.com/foo", ocispec.Descriptor{})
					return err
				},
				"FetchManifest": func() error {
					_, err := inherited.FetchManifest(ctx, "example.com/foo", ocispec.Descriptor{})
					return err
				},
			}
			for name, call := range calls {
				err := call()
				if err == nil {
					t.Fatalf("%s() expected error, got nil", name)
				}
				if !strings.Contains(err.Error(), tt.wantErrMessage) {
					t.Errorf("%s() error = %v, want it to contain %q", name, err, tt.wantErrMessage)
				}
				if errors.Is(err, e.ErrNoExecutorMatched) {
					t.Errorf("%s() error = %v, want it not to wrap ErrNoExecutorMatched", name, err)
				}
			}
		})
	}
}

// TestClusterStore_InvalidReference ensures that an invalid reference is
// reported as is.
func TestClusterStore_InvalidReference(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.upsertExecutor(clusterScopeNamespace, "cluster", newExecutorWithNamedStore("example.com", "cluster-store")); err != nil {
		t.Fatalf("failed to upsert cluster executor: %v", err)
	}
	s := &clusterStore{manager: &mgr}
	if _, err := s.FetchManifest(context.Background(), "example.com/INVALID", ocispec.Descriptor{}); err == nil {
		t.Fatal("FetchManifest() expected error for an invalid repository, got nil")
	}
}
