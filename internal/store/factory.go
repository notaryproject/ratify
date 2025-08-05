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

package store

import (
	"fmt"

	"github.com/notaryproject/ratify-go"
)

// NewOptions defines the options for creating a new [ratify.Store].
type NewOptions struct {
	// Type represents a specific implementation of a store. Required.
	Type string `json:"type"`

	// Scopes defines the scopes for the store. Optional.
	Scopes []string `json:"scopes,omitempty"`

	// Parameters is additional parameters for the store. Optional.
	Parameters any `json:"parameters,omitempty"`
}

// registry saves the registered store factories.
var registry map[string]func(NewOptions) (ratify.Store, error)

// Register registers a store factory to the system.
func Register(storeType string, create func(NewOptions) (ratify.Store, error)) {
	if storeType == "" {
		panic("store type cannot be empty")
	}
	if create == nil {
		panic("store create cannot be nil")
	}
	if registry == nil {
		registry = make(map[string]func(NewOptions) (ratify.Store, error))
	}
	if _, registered := registry[storeType]; registered {
		panic(fmt.Sprintf("store factory type %s already registered", storeType))
	}
	registry[storeType] = create
}

// New creates a new [ratify.StoreMux] instance where each store is registered
// for its respective scopes.
func New(opts []NewOptions, globalScopes []string) (ratify.Store, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no store options provided")
	}
	storeMux := ratify.NewStoreMux()
	for _, storeOptions := range opts {
		if len(storeOptions.Scopes) == 0 {
			// if no scopes are provided, use the global scopes of the executor.
			storeOptions.Scopes = globalScopes
		}
		store, err := newStore(storeOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create store for type %q: %w", storeOptions.Type, err)
		}
		for _, scope := range storeOptions.Scopes {
			if err = storeMux.Register(scope, store); err != nil {
				return nil, fmt.Errorf("failed to register store for scope %q: %w", scope, err)
			}
		}
	}

	return storeMux, nil
}

// newStore creates a new [ratify.Store] instance based on the provided options
// and will be used to register the store in the [ratify.StoreMux].
func newStore(opts NewOptions) (ratify.Store, error) {
	if opts.Type == "" {
		return nil, fmt.Errorf("store type is not provided in the store options")
	}
	create, ok := registry[opts.Type]
	if !ok {
		return nil, fmt.Errorf("store factory of type %s is not registered", opts.Type)
	}
	return create(opts)
}
