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
	"sync"

	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
)

// ActiveStores implements the ReferrerStoreManager interface.
type ActiveStores struct {
	// The structure of the map is as follows:
	// The first level maps from scope to stores
	// The second level maps from store name to store
	// Example:
	// {
	//   "namespace1": {
	//     "store1": store1,
	//     "store2": store2
	//   }
	// }
	// Note: Scope is utilized for organizing and isolating stores. In a Kubernetes (K8s) environment, the scope can be either a namespace or an empty string ("") for cluster-wide stores.
	ScopedStores sync.Map
}

func NewActiveStores() ReferrerStoreManager {
	return &ActiveStores{}
}

// GetStores fulfills the ReferrerStoreManager interface.
// It returns all the stores in the ActiveStores for the given scope. If no stores are found for the given scope, it returns cluster-wide stores.
func (s *ActiveStores) GetStores(scope string) []referrerstore.ReferrerStore {
	stores := []referrerstore.ReferrerStore{}
	if scopedStore, ok := s.ScopedStores.Load(scope); ok {
		for _, store := range scopedStore.(map[string]referrerstore.ReferrerStore) {
			stores = append(stores, store)
		}
	}
	if len(stores) == 0 && scope != constants.EmptyNamespace {
		if clusterStore, ok := s.ScopedStores.Load(constants.EmptyNamespace); ok {
			for _, store := range clusterStore.(map[string]referrerstore.ReferrerStore) {
				stores = append(stores, store)
			}
		}
	}
	return stores
}

// AddStore fulfills the ReferrerStoreManager interface.
// It adds the given store under the given scope.
func (s *ActiveStores) AddStore(scope, storeName string, store referrerstore.ReferrerStore) {
	scopedStore, _ := s.ScopedStores.LoadOrStore(scope, make(map[string]referrerstore.ReferrerStore))
	scopedStore.(map[string]referrerstore.ReferrerStore)[storeName] = store
}

// DeleteStore fulfills the ReferrerStoreManager interface.
// It deletes the store with the given name under the given scope.
func (s *ActiveStores) DeleteStore(scope, storeName string) {
	if scopedStore, ok := s.ScopedStores.Load(scope); ok {
		delete(scopedStore.(map[string]referrerstore.ReferrerStore), storeName)
	}
}
