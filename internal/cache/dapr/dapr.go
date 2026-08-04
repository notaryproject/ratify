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

package dapr

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/dapr/go-sdk/client"
	"github.com/notaryproject/ratify/v2/internal/cache"
	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/notaryproject/ratify/v2/pkg/featureflag"
)

// DefaultCacheName is the default Dapr state store component name.
const DefaultCacheName = "dapr-redis"

// stateClient captures the subset of the Dapr client used by the cache. It
// keeps the implementation testable without a running Dapr sidecar and is
// satisfied by client.Client.
type stateClient interface {
	GetState(ctx context.Context, storeName, key string, meta map[string]string) (*client.StateItem, error)
	SaveState(ctx context.Context, storeName, key string, data []byte, meta map[string]string, so ...client.StateOption) error
	DeleteState(ctx context.Context, storeName, key string, meta map[string]string) error
}

// Cache is a distributed cache backed by a Dapr state store. Values are
// JSON-encoded so that any type T can be shared across replicas, enabling the
// high-availability deployment mode.
type Cache[T any] struct {
	daprClient stateClient
	cacheName  string
	ttl        time.Duration
}

// NewCache creates a new Dapr-backed cache with the specified state store name
// and default TTL. It requires the high-availability feature flag to be
// enabled and a reachable Dapr sidecar.
func NewCache[T any](cacheName string, ttl time.Duration) (cache.Cache[T], error) {
	if !featureflag.HighAvailability.Enabled {
		return nil, fmt.Errorf("dapr cache provider is not enabled: set the environment variable RATIFY_EXPERIMENTAL_HIGH_AVAILABILITY=1 to enable it")
	}
	if ttl < 0 {
		return nil, cache.ErrInvalidTTL
	}
	if cacheName == "" {
		cacheName = DefaultCacheName
	}

	daprClient, err := client.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create dapr client: %w", err)
	}

	return &Cache[T]{
		daprClient: daprClient,
		cacheName:  cacheName,
		ttl:        ttl,
	}, nil
}

// Get returns the value associated with the key, or an error if not found.
func (d *Cache[T]) Get(ctx context.Context, key string) (T, error) {
	var zero T
	item, err := d.daprClient.GetState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), nil)
	if err != nil {
		return zero, err
	}
	if item == nil || len(item.Value) == 0 {
		return zero, cache.ErrNotFound
	}

	var value T
	if err := json.Unmarshal(item.Value, &value); err != nil {
		return zero, fmt.Errorf("failed to unmarshal cached value: %w", err)
	}
	return value, nil
}

// Set stores a value with the specified key. A non-positive ttl falls back to
// the cache's configured default TTL.
func (d *Cache[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = d.ttl
	}

	bytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value for dapr cache: %w", err)
	}

	var md map[string]string
	if ttl > 0 {
		// Round up to the nearest second using integer duration math so that
		// any positive TTL maps to at least 1 second (avoids sending
		// ttlInSeconds=0, which would disable expiry, for sub-second TTLs).
		seconds := int64((ttl + time.Second - 1) / time.Second)
		md = map[string]string{"ttlInSeconds": strconv.FormatInt(seconds, 10)}
	}

	if err := d.daprClient.SaveState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), bytes, md); err != nil {
		return fmt.Errorf("failed to save value to dapr cache: %w", err)
	}
	return nil
}

// Delete removes the specified key/value from the cache.
func (d *Cache[T]) Delete(ctx context.Context, key string) error {
	if err := d.daprClient.DeleteState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), nil); err != nil {
		return fmt.Errorf("failed to delete value from dapr cache: %w", err)
	}
	return nil
}
