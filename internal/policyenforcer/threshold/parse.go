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

package threshold

import (
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/encoding/jsonutil"
	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
)

// policyType is the type identifier for the threshold policy enforcer.
const policyType = "threshold-policy"

// init registers the threshold-policy factory via side effects.
// This ensures that the threshold-policy type is available for use in the
// policy enforcer factory.
func init() {
	policyenforcer.Register(policyType, func(opts policyenforcer.NewOptions) (ratify.PolicyEnforcer, error) {
		parameters, ok := opts.Parameters.(map[string]any)
		if !ok {
			if err := jsonutil.Copy(&parameters, opts.Parameters); err != nil {
				return nil, fmt.Errorf("failed to parse policy parameters: %w", err)
			}
		}
		policy, err := parseOrNil[map[string]any](parameters, "policy")
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy parameters: %w", err)
		}
		rule, err := parseRule(policy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy parameters: %w", err)
		}
		return ratify.NewThresholdPolicyEnforcer(rule)
	})
}

// parseRule parses a rule from the provided map and returns a
// [ratify.ThresholdPolicyRule]. It recursively parses nested rules.
func parseRule(raw map[string]any) (*ratify.ThresholdPolicyRule, error) {
	if raw == nil {
		return nil, fmt.Errorf("policy rule is required")
	}

	var rule ratify.ThresholdPolicyRule
	var err error
	rule.Verifier, err = parseOrNil[string](raw, "verifierName")
	if err != nil {
		return nil, err
	}
	rule.Threshold, err = parseOrNil[int](raw, "threshold")
	if err != nil {
		return nil, err
	}
	rawRules, err := parseOrNil[[]map[string]any](raw, "rules")
	if err != nil {
		return nil, err
	}
	for _, rawRule := range rawRules {
		nestedRule, err := parseRule(rawRule)
		if err != nil {
			return nil, fmt.Errorf("failed to parse nested rule: %w", err)
		}
		rule.Rules = append(rule.Rules, nestedRule)
	}

	return &rule, nil
}

// parseOrNil is a helper function to parse a value from a map and return
// an error if the value is not of the expected type. If the key does not exist,
// it returns a zero value of the expected type and no error.
func parseOrNil[T any](m map[string]any, key string) (T, error) {
	raw := m[key]
	if raw == nil {
		var zero T
		return zero, nil
	}
	value, ok := raw.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("option %q requires a value of type %T, got %T", key, zero, raw)
	}
	return value, nil
}
