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

package factory

import (
	"fmt"

	"github.com/notaryproject/ratify-go"
)

// NewStoreOptions defines the options for creating a new store.
type NewStoreOptions struct {
	// Type represents a specific implementation of a store. Required.
	Type string `json:"type"`

	// Parameters is additional parameters for the store. Optional.
	Parameters any `json:"parameters,omitempty"`
}

// registeredStores saves the registered store factories.
var registeredStores map[string]func(NewStoreOptions) (ratify.Store, error)

// RegisterStore registers a store factory to the system.
func RegisterStoreFactory(storeType string, create func(NewStoreOptions) (ratify.Store, error)) {
	if storeType == "" {
		panic("store type cannot be empty")
	}
	if create == nil {
		panic("store factory cannot be nil")
	}
	if registeredStores == nil {
		registeredStores = make(map[string]func(NewStoreOptions) (ratify.Store, error))
	}
	if _, registered := registeredStores[storeType]; registered {
		panic(fmt.Sprintf("store factory type %s already registered", storeType))
	}
	registeredStores[storeType] = create
}

// NewStore creates a new Store instance based on the provided options.
func NewStore(opts NewStoreOptions) (ratify.Store, error) {
	if opts.Type == "" {
		return nil, fmt.Errorf("store type is not provided in the store options")
	}
	storeFactory, ok := registeredStores[opts.Type]
	if !ok {
		return nil, fmt.Errorf("store factory of type %s is not registered", opts.Type)
	}
	return storeFactory(opts)
}
