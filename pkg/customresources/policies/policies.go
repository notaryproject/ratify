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

import (
	"sync"

	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider"
)

// PolicyWrapper wraps policy provider with its policy name.
type PolicyWrapper struct {
	Name   string
	Policy policyprovider.PolicyProvider
}

// ActivePolicies implements PolicyManager interface.
type ActivePolicies struct {
	// scopedPolicies is a mapping from scope to a policy.
	// Note: Scope is utilized for organizing and isolating policies. In a Kubernetes (K8s) environment, the scope can be either a namespace or an empty string ("") for cluster-wide policy.
	scopedPolicies sync.Map
}

func NewActivePolicies() PolicyManager {
	return &ActivePolicies{}
}

// GetPolicy fulfills the PolicyManager interface.
// It returns the policy for the given scope. If no policy is found for the given scope, it returns cluster-wide policy.
func (p *ActivePolicies) GetPolicy(scope string) policyprovider.PolicyProvider {
	if scopedPolicy, ok := p.scopedPolicies.Load(scope); ok {
		return scopedPolicy.(PolicyWrapper).Policy
	}

	if scope != constants.EmptyNamespace {
		if policy, ok := p.scopedPolicies.Load(constants.EmptyNamespace); ok {
			return policy.(PolicyWrapper).Policy
		}
	}
	return nil
}

// AddPolicy fulfills the PolicyManager interface.
// It adds the given policy under the given scope.
func (p *ActivePolicies) AddPolicy(scope, policyName string, policy policyprovider.PolicyProvider) {
	p.scopedPolicies.Store(scope, PolicyWrapper{
		Name:   policyName,
		Policy: policy,
	})
}

// DeletePolicy fulfills the PolicyManager interface.
// It deletes the policy from the given scope.
func (p *ActivePolicies) DeletePolicy(scope, policyName string) {
	if policy, ok := p.scopedPolicies.Load(scope); ok {
		if policy.(PolicyWrapper).Name == policyName {
			p.scopedPolicies.Delete(scope)
		}
	}
}
