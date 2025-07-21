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

package verifier

import (
	"fmt"

	"github.com/notaryproject/ratify-go"
)

// NewOptions holds the options to create a [ratify.Verifier].
type NewOptions struct {
	// Name is the unique identifier of a verifier instance. Required.
	Name string `json:"name"`

	// Type represents a specific implementation of a verifier. Required.
	// Note: there could be multiple verifiers of the same type with different
	//       names.
	Type string `json:"type"`

	// Parameters is additional parameters of the verifier. Optional.
	Parameters any `json:"parameters,omitempty"`
}

// registeredVerifiers saves the registered verifier factories.
var registeredVerifiers map[string]func(*NewOptions, []string) (ratify.Verifier, error)

// RegisterVerifierFactory registers a verifier factory to the system.
func RegisterVerifierFactory(verifierType string, create func(*NewOptions, []string) (ratify.Verifier, error)) {
	if verifierType == "" {
		panic("verifier type cannot be empty. Please provide a non-empty string representing a valid verifier.")
	}
	if create == nil {
		panic("verifier factory cannot be nil")
	}
	if registeredVerifiers == nil {
		registeredVerifiers = make(map[string]func(*NewOptions, []string) (ratify.Verifier, error))
	}
	if _, registered := registeredVerifiers[verifierType]; registered {
		panic(fmt.Sprintf("verifier factory named %s already registered", verifierType))
	}
	registeredVerifiers[verifierType] = create
}

// New creates a [ratify.Verifier] instance if it belongs to a registered type.
func New(opts *NewOptions, globalScopes []string) (ratify.Verifier, error) {
	if opts.Name == "" || opts.Type == "" {
		return nil, fmt.Errorf("name or type is not provided in the verifier options")
	}
	create, ok := registeredVerifiers[opts.Type]
	if !ok {
		return nil, fmt.Errorf("verifier factory of type %s is not registered", opts.Type)
	}
	return create(opts, globalScopes)
}

// NewVerifiers creates a slice of [ratify.Verifier] instances based on the
// provided options.
func NewVerifiers(opts []*NewOptions, globalScopes []string) ([]ratify.Verifier, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no verifier options provided")
	}
	verifiers := make([]ratify.Verifier, len(opts))
	for idx, opt := range opts {
		verifier, err := New(opt, globalScopes)
		if err != nil {
			return nil, err
		}
		verifiers[idx] = verifier
	}
	return verifiers, nil
}
