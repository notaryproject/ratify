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

package policyenforcer

import (
	"errors"
	"fmt"

	"github.com/notaryproject/ratify-go"
)

// NewOptions contains the options for creating a new [ratify.PolicyEnforcer].
type NewOptions struct {
	// Type represents a specific implementation of a policy enforcer. Required.
	Type string `json:"type"`

	// Parameters is additional parameters for the policy enforcer. Optional.
	Parameters any `json:"parameters,omitempty"`
}

// registry saves the registered policy enforcer factories.
var registry = make(map[string]func(opts NewOptions) (ratify.PolicyEnforcer, error))

// RegisterPolicyEnforcer registers a policy enforcer factory to the system.
func Register(policyType string, create func(opts NewOptions) (ratify.PolicyEnforcer, error)) {
	if policyType == "" {
		panic("policy type cannot be empty")
	}
	if create == nil {
		panic("policy create cannot be nil")
	}
	if _, registered := registry[policyType]; registered {
		panic("policy factory already registered")
	}
	registry[policyType] = create
}

// New creates a new [ratify.PolicyEnforcer] instance based on the provided
// options.
func New(opts NewOptions) (ratify.PolicyEnforcer, error) {
	if opts.Type == "" {
		return nil, errors.New("policy type is not provided in the policy options")
	}
	create, ok := registry[opts.Type]
	if !ok {
		return nil, fmt.Errorf("policy factory of type %s is not registered", opts.Type)
	}
	return create(opts)
}
