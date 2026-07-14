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

package cosign

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	re "github.com/notaryproject/ratify/v2/errors"
)

type TrustPolicies struct {
	policies []TrustPolicy
}

const GlobalWildcardCharacter = '*'

var validScopeRegex = regexp.MustCompile(`^[a-z0-9\.\-:@\/]*\*?$`)

// CreateTrustPolicies creates a set of trust policies from the given configuration
func CreateTrustPolicies(configs []TrustPolicyConfig, verifierName string) (*TrustPolicies, error) {
	if len(configs) == 0 {
		return nil, re.ErrorCodeConfigInvalid.WithDetail("Failed to create trust policies: policy configuration not found").WithRemediation("Ensure that the trust policy configuration is correct.")
	}

	policies := make([]TrustPolicy, 0, len(configs))
	names := make(map[string]struct{})
	for _, policyConfig := range configs {
		if _, ok := names[policyConfig.Name]; ok {
			return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: duplicate policy name %s", policyConfig.Name)).WithRemediation("Ensure that trust policy names are unique.")
		}
		names[policyConfig.Name] = struct{}{}
		policy, err := CreateTrustPolicy(policyConfig, verifierName)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	if err := validateScopes(policies); err != nil {
		return nil, err
	}

	return &TrustPolicies{
		policies: policies,
	}, nil
}

// GetScopedPolicy returns the policy that applies to the given reference
// TODO: add link to scopes docs when published
func (tps *TrustPolicies) GetScopedPolicy(reference string) (TrustPolicy, error) {
	var globalPolicy TrustPolicy
	for _, policy := range tps.policies {
		scopes := policy.GetScopes()
		for _, scope := range scopes {
			if scope == string(GlobalWildcardCharacter) {
				// if global wildcard character is used, save the policy and continue
				globalPolicy = policy
				continue
			}
			if strings.HasSuffix(scope, string(GlobalWildcardCharacter)) {
				if strings.HasPrefix(reference, strings.TrimSuffix(scope, string(GlobalWildcardCharacter))) {
					return policy, nil
				}
			} else if reference == scope {
				return policy, nil
			}
		}
	}
	// if no scoped policy is found, return the global policy if it exists
	if globalPolicy != nil {
		return globalPolicy, nil
	}
	return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("No policy found for the artifact %s", reference))
}

// validateScopes validates the scopes in the trust policies
func validateScopes(policies []TrustPolicy) error {
	scopesMap := make(map[string]struct{})
	hasGlobalWildcard := false
	for _, policy := range policies {
		policyName := policy.GetName()
		scopes := policy.GetScopes()
		if len(scopes) == 0 {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: scope parameter is required for trust policy %s", policyName))
		}
		// check for global wildcard character along with other scopes in the same policy
		if len(scopes) > 1 && slices.Contains(scopes, string(GlobalWildcardCharacter)) {
			return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: global wildcard character %c cannot be used with other scopes within the same trust policy %s", GlobalWildcardCharacter, policyName))
		}
		// check for duplicate global wildcard characters across policies
		if slices.Contains(scopes, string(GlobalWildcardCharacter)) {
			if hasGlobalWildcard {
				return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: global wildcard character %c can only be used once", GlobalWildcardCharacter))
			}
			hasGlobalWildcard = true
			continue
		}
		for _, scope := range scopes {
			// check for empty scope
			if scope == "" {
				return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: scope value cannot be empty in trust policy %s", policyName))
			}
			// check scope is formatted correctly
			if !validScopeRegex.MatchString(scope) {
				return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: invalid scope %s for trust policy %s", scope, policyName))
			}
			// check for duplicate scopes
			if _, ok := scopesMap[scope]; ok {
				return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: duplicate scope %s for trust policy %s", scope, policyName))
			}
			// check wildcard overlaps
			for existingScope := range scopesMap {
				isConflict := false
				trimmedScope := strings.TrimSuffix(scope, string(GlobalWildcardCharacter))
				trimmedExistingScope := strings.TrimSuffix(existingScope, string(GlobalWildcardCharacter))
				if existingScope[len(existingScope)-1] == GlobalWildcardCharacter && scope[len(scope)-1] == GlobalWildcardCharacter {
					// if both scopes have wildcard characters, check if they overlap
					if len(scope) < len(existingScope) {
						isConflict = strings.HasPrefix(trimmedExistingScope, trimmedScope)
					} else {
						isConflict = strings.HasPrefix(trimmedScope, trimmedExistingScope)
					}
				} else if existingScope[len(existingScope)-1] == GlobalWildcardCharacter {
					// if existing scope has wildcard character, check if it overlaps with the new absolute scope
					isConflict = strings.HasPrefix(scope, trimmedExistingScope)
				} else if scope[len(scope)-1] == GlobalWildcardCharacter {
					// if new scope has wildcard character, check if it overlaps with the existing absolute scope
					isConflict = strings.HasPrefix(existingScope, trimmedScope)
				}
				if isConflict {
					return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create trust policies: overlapping scopes %s and %s for trust policy %s", scope, existingScope, policyName))
				}
			}
			scopesMap[scope] = struct{}{}
		}
	}
	return nil
}
