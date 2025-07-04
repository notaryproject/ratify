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

package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/notaryproject/ratify/v2/internal/cache"
)

const defaultMaxSize = 100

// cacheItem represents a cached item with its value and expiration time
type cacheItem[T any] struct {
	value      T
	expiration time.Time
}

// isExpired checks if the cache item has expired
func (item *cacheItem[T]) isExpired() bool {
	return !item.expiration.IsZero() && time.Now().After(item.expiration)
}

// Cache is a simple in-memory cache implementation using RWMutex and map
type Cache[T any] struct {
	mu      sync.RWMutex
	items   map[string]*cacheItem[T]
	maxSize int
}

// NewCache creates a new in-memory cache with the specified TTL.
func NewCache[T any](maxSize int) (cache.Cache[T], error) {
	if maxSize < 0 {
		return nil, cache.ErrInvalidMaxSize
	}
	if maxSize == 0 {
		maxSize = defaultMaxSize // Set a default max size if 0 is provided
	}
	return &Cache[T]{
		items:   make(map[string]*cacheItem[T]),
		maxSize: maxSize,
	}, nil
}

// Get returns the value associated with the key, or an error if not found.
func (c *Cache[T]) Get(_ context.Context, key string) (T, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var zero T
	item, exists := c.items[key]
	if !exists {
		return zero, cache.ErrNotFound
	}

	if item.isExpired() {
		// Item has expired, but we don't remove it here to avoid upgrading to
		// write lock. It will be cleaned up on the next write operation.
		return zero, cache.ErrNotFound
	}

	return item.value, nil
}

// Set stores a value with the specified key.
func (c *Cache[T]) Set(_ context.Context, key string, value T, ttl time.Duration) error {
	if ttl <= 0 {
		return cache.ErrInvalidTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &cacheItem[T]{
		value:      value,
		expiration: time.Now().Add(ttl),
	}

	// Clean up expired items while we have the write lock
	c.cleanupExpiredItems()
	return nil
}

// cleanupExpiredItems removes expired items from the cache.
// This method should be called while holding a write lock.
func (c *Cache[T]) cleanupExpiredItems() {
	if len(c.items) <= c.maxSize {
		return // No need to clean up if we are within the max size limit.
	}

	now := time.Now()
	for key, item := range c.items {
		if !item.expiration.IsZero() && now.After(item.expiration) {
			delete(c.items, key)
		}
	}
}

// Delete removes the specified key/value from the cache.
func (c *Cache[T]) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
	return nil
}
