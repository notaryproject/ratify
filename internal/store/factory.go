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
	"context"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/imageref"
	"github.com/notaryproject/ratify-go/plugin"

	"github.com/notaryproject/ratify/v2/internal/encoding/jsonutil"
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

// New creates a new [ratify.StoreMux] instance where each store is registered
// for its respective scopes.
func New(opts []NewOptions, globalScopes []string) (ratify.Store, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no store options provided")
	}

	if len(opts) == 1 && len(opts[0].Scopes) == 0 && len(globalScopes) == 0 {
		store, err := newStore(opts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to create store for type %q: %w", opts[0].Type, err)
		}
		storeMux := ratify.NewStoreMux()
		if err = storeMux.RegisterFallback(store); err != nil {
			return nil, fmt.Errorf("failed to register fallback store: %w", err)
		}
		return storeMux, nil
	}

	// If there is more than one store option, clear the global scopes as
	// multiple stores should not share the same global scopes.
	if len(opts) > 1 {
		globalScopes = []string{}
	}

	storeMux := ratify.NewStoreMux()
	hasFallback := false
	for _, storeOptions := range opts {
		scopes := storeOptions.Scopes
		if len(scopes) == 0 {
			// if no scopes are provided, use the global scopes of the executor.
			scopes = globalScopes
		}

		store, err := newStore(storeOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create store for type %q: %w", storeOptions.Type, err)
		}

		if len(scopes) == 0 {
			return nil, fmt.Errorf("store options must contain at least one scope")
		}
		// Normalize repository scopes so that they match the normalized
		// references that the executor routes to the store.
		for _, scope := range imageref.NormalizeScopes(scopes) {
			if scope == "*" {
				if hasFallback {
					return nil, fmt.Errorf("fallback store already registered")
				}
				hasFallback = true
				if err = storeMux.RegisterFallback(store); err != nil {
					return nil, fmt.Errorf("failed to register fallback store: %w", err)
				}
				continue
			}
			if err = storeMux.Register(scope, store); err != nil {
				return nil, fmt.Errorf("failed to register store for scope %q: %w", scope, err)
			}
		}
	}

	return storeMux, nil
}

// newStore creates a new [ratify.Store] instance of a type registered to the
// [plugin.Default] registry. It will be used to register the store in the
// [ratify.StoreMux].
func newStore(opts NewOptions) (ratify.Store, error) {
	if opts.Type == "" {
		return nil, fmt.Errorf("store type is not provided in the store options")
	}
	params, err := jsonutil.RawMessage(opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal store parameters: %w", err)
	}
	return plugin.Default.NewStore(context.Background(), opts.Type, plugin.StoreOptions{Parameters: params})
}
