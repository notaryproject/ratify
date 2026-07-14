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

package policies

import "github.com/notaryproject/ratify/v2/pkg/policyprovider"

// PolicyManager is an interface that defines the methods for managing policies across different scopes.
type PolicyManager interface {
	// GetPolicy returns the policy for the given scope.
	GetPolicy(scope string) policyprovider.PolicyProvider

	// AddPolicy adds the given policy under the given scope.
	AddPolicy(scope, policyName string, policy policyprovider.PolicyProvider)

	// DeletePolicy deletes the policy from the given scope.
	DeletePolicy(scope, policyName string)
}
