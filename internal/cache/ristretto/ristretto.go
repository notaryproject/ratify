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

package ristretto

import (
	"context"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/notaryproject/ratify/v2/internal/cache"
	"github.com/sirupsen/logrus"
)

const (
	defaultMaxSize  = 100000000 // 100MB
	defaultCountNum = 100000
)

type ristrettoCache struct {
	cache *ristretto.Cache[string, any]
	ttl   time.Duration
}

// NewRistrettoCache creates a new Ristretto cache with the specified TTL.
func NewRistrettoCache(ttl time.Duration) (cache.Cache, error) {
	if ttl < 0 {
		return nil, cache.ErrInvalidTTL
	}

	memoryCache, err := ristretto.NewCache(&ristretto.Config[string, any]{
		NumCounters: defaultCountNum, // number of keys to track frequency.
		MaxCost:     defaultMaxSize,  // Max size in Megabytes.
		BufferItems: 64,              // number of keys per Get buffer. 64 is recommended by the ristretto library.
	})
	if err != nil {
		logrus.Errorf("could not create ristretto cache, err: %s", err)
		return nil, err
	}

	return &ristrettoCache{
		cache: memoryCache,
		ttl:   ttl,
	}, nil
}

// Get returns the value associated with the key, or an error if not found.
func (r *ristrettoCache) Get(_ context.Context, key string) (any, error) {
	cacheValue, found := r.cache.Get(key)
	if found {
		return cacheValue, nil
	}
	return nil, cache.ErrNotFound
}

// Set stores a value with the specified key.
func (r *ristrettoCache) Set(_ context.Context, key string, value any) error {
	saved := r.cache.SetWithTTL(key, value, 1, r.ttl)
	r.cache.Wait()
	if saved {
		return nil
	}
	return cache.ErrAddFailed
}

// Delete removes the specified key/value from the cache.
func (r *ristrettoCache) Delete(_ context.Context, key string) error {
	r.cache.Del(key)
	// Note: ristretto does not return a bool for delete.
	// Delete ops are eventually consistent and we don't want to block on them.
	return nil
}
