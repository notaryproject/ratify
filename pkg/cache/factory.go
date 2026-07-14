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

package cache

import (
	"context"
	"fmt"
)

// CacheFactory is an interface that defines the methods that a cache provider factory must implement
type CacheFactory interface { //nolint:revive // ignore linter to have unique type name
	Create(ctx context.Context, cacheName string, cacheSize int) (CacheProvider, error)
}

var cacheProviderFactories = make(map[string]CacheFactory)
var memoryCache CacheProvider

// Register adds the factory to the built in providers map
func Register(name string, factory CacheFactory) {
	if _, registered := cacheProviderFactories[name]; registered {
		panic(fmt.Sprintf("cache provider named %s already registered", name))
	}

	cacheProviderFactories[name] = factory
}

// NewCacheProvider creates a new cache provider based on the name
func NewCacheProvider(ctx context.Context, cacheType string, cacheName string, cacheSize int) (CacheProvider, error) {
	factory, ok := cacheProviderFactories[cacheType]
	if !ok {
		return nil, fmt.Errorf("cache provider %s not found", cacheType)
	}

	var err error
	memoryCache, err = factory.Create(ctx, cacheName, cacheSize)
	if err != nil {
		return nil, err
	}
	return memoryCache, nil
}

func GetCacheProvider() CacheProvider {
	return memoryCache
}
