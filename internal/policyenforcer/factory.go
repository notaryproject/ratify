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
	"context"
	"errors"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"

	"github.com/notaryproject/ratify/v2/internal/encoding/jsonutil"
)

// NewOptions contains the options for creating a new [ratify.PolicyEnforcer].
type NewOptions struct {
	// Type represents a specific implementation of a policy enforcer. Required.
	Type string `json:"type"`

	// Parameters is additional parameters for the policy enforcer. Optional.
	Parameters any `json:"parameters,omitempty"`
}

// New creates a new [ratify.PolicyEnforcer] instance of a type registered to
// the [plugin.Default] registry.
func New(opts NewOptions) (ratify.PolicyEnforcer, error) {
	if opts.Type == "" {
		return nil, errors.New("policy type is not provided in the policy options")
	}
	params, err := jsonutil.RawMessage(opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy enforcer parameters: %w", err)
	}
	return plugin.Default.NewPolicyEnforcer(context.Background(), opts.Type, plugin.PolicyEnforcerOptions{Parameters: params})
}
