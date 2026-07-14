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
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
)

// ReferrerStoreManager is an interface that defines the methods for managing referrer stores across different scopes.
type ReferrerStoreManager interface {
	// Stores returns the list of referrer stores for the given scope.
	GetStores(scope string) []referrerstore.ReferrerStore

	// AddStore adds the given store under the given scope.
	AddStore(scope, storeName string, store referrerstore.ReferrerStore)

	// DeleteStore deletes the policy from the given scope.
	DeleteStore(scope, storeName string)
}
