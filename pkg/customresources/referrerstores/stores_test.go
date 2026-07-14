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

package referrerstores

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	rs "github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/opencontainers/go-digest"
)

type mockStore struct {
	name string
}

func (s mockStore) Name() string {
	return s.name
}

func (s mockStore) ListReferrers(_ context.Context, _ common.Reference, _ []string, _ string, _ *ocispecs.SubjectDescriptor) (rs.ListReferrersResult, error) {
	return rs.ListReferrersResult{}, nil
}

func (s mockStore) GetBlobContent(_ context.Context, _ common.Reference, _ digest.Digest) ([]byte, error) {
	return nil, nil
}

func (s mockStore) GetReferenceManifest(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	return ocispecs.ReferenceManifest{}, nil
}

func (s mockStore) GetConfig() *config.StoreConfig {
	return nil
}

func (s mockStore) GetSubjectDescriptor(_ context.Context, _ common.Reference) (*ocispecs.SubjectDescriptor, error) {
	return nil, nil
}

const (
	namespace1 = constants.EmptyNamespace
	namespace2 = "namespace2"
	name1      = "name1"
	name2      = "name2"
)

var (
	store1 = mockStore{name: name1}
	store2 = mockStore{name: name2}
)

func TestStoresOperations(t *testing.T) {
	stores := NewActiveStores()
	stores.AddStore(namespace1, store1.Name(), store1)
	stores.AddStore(namespace1, store2.Name(), store2)
	stores.AddStore(namespace2, store1.Name(), store1)
	stores.AddStore(namespace2, store2.Name(), store2)

	if len(stores.GetStores(namespace1)) != 2 {
		t.Fatalf("Expected 2 stores in namespace %s, got %d", namespace1, len(stores.GetStores(namespace1)))
	}
	if len(stores.GetStores(namespace2)) != 2 {
		t.Fatalf("Expected 2 stores in namespace %s, got %d", namespace2, len(stores.GetStores(namespace2)))
	}

	stores.DeleteStore(namespace2, store1.Name())
	if len(stores.GetStores(namespace2)) != 1 {
		t.Fatalf("Expected 1 store in namespace %s, got %d", namespace2, len(stores.GetStores(namespace2)))
	}

	stores.DeleteStore(namespace2, store2.Name())
	if len(stores.GetStores(namespace2)) != 2 {
		t.Fatalf("Expected 2 stores in namespace %s, got %d", namespace2, len(stores.GetStores(namespace2)))
	}

	stores.DeleteStore(namespace1, store1.Name())
	if len(stores.GetStores(namespace1)) != 1 {
		t.Fatalf("Expected 1 store in namespace %s, got %d", namespace1, len(stores.GetStores(namespace1)))
	}

	stores.DeleteStore(namespace1, store2.Name())
	if len(stores.GetStores(namespace1)) != 0 {
		t.Fatalf("Expected 0 stores in namespace %s, got %d", namespace1, len(stores.GetStores(namespace1)))
	}
}
