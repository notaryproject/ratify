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
	"errors"
	"fmt"

	"github.com/notaryproject/ratify-go"
	e "github.com/notaryproject/ratify/v2/internal/executor"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// clusterStore is a [ratify.Store] that serves the namespaced executors
// without stores of their own. It routes every request to the store that the
// cluster-scoped executor uses for the same artifact. The cluster-scoped
// executor is looked up on each request, so namespaced executors always use
// the latest cluster-wide stores without being rebuilt when the cluster-scoped
// Executor resources change.
type clusterStore struct {
	manager *executorManager
}

// Resolve resolves to a descriptor for the given artifact reference.
func (s *clusterStore) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	store, err := s.store(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return store.Resolve(ctx, ref)
}

// ListReferrers returns the immediate set of supply chain artifacts for the
// given subject reference.
func (s *clusterStore) ListReferrers(ctx context.Context, ref string, artifactTypes []string, fn func(referrers []ocispec.Descriptor) error) error {
	store, err := s.store(ref)
	if err != nil {
		return err
	}
	return store.ListReferrers(ctx, ref, artifactTypes, fn)
}

// FetchBlob returns the blob by the given reference.
func (s *clusterStore) FetchBlob(ctx context.Context, repo string, desc ocispec.Descriptor) ([]byte, error) {
	store, err := s.store(repo)
	if err != nil {
		return nil, err
	}
	return store.FetchBlob(ctx, repo, desc)
}

// FetchManifest returns the referenced manifest as given by the descriptor.
func (s *clusterStore) FetchManifest(ctx context.Context, repo string, desc ocispec.Descriptor) ([]byte, error) {
	store, err := s.store(repo)
	if err != nil {
		return nil, err
	}
	return store.FetchManifest(ctx, repo, desc)
}

// store returns the cluster-wide store for the given artifact reference or
// repository.
func (s *clusterStore) store(ref string) (ratify.Store, error) {
	executor := s.manager.GetExecutor(clusterScopeNamespace)
	if executor == nil {
		return nil, fmt.Errorf("no stores configured for %q: the executor has no stores and no cluster-scoped Executor is configured to inherit them from", ref)
	}
	store, err := executor.Store(ref)
	if err != nil {
		if errors.Is(err, e.ErrNoExecutorMatched) {
			// Do not wrap ErrNoExecutorMatched: the namespaced executor is
			// scoped to the artifact, so the mutation webhook must report the
			// missing store instead of skipping the artifact.
			return nil, fmt.Errorf("no stores configured for %q: the executor has no stores and no cluster-scoped Executor is scoped to it", ref)
		}
		return nil, err
	}
	return store, nil
}
