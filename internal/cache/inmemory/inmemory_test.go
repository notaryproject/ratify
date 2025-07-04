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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/cache"
)

const (
	testValue = "test-value"
	testKey   = "test-key"
)

func TestNewCache(t *testing.T) {
	tests := []struct {
		name    string
		maxSize int
		wantErr bool
	}{
		{
			name:    "valid max size",
			maxSize: 50,
			wantErr: false,
		},
		{
			name:    "zero max size uses default",
			maxSize: 0,
			wantErr: false,
		},
		{
			name:    "negative max size returns error",
			maxSize: -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewCache[string](tt.maxSize)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				if !errors.Is(err, cache.ErrInvalidMaxSize) {
					t.Errorf("expected ErrInvalidMaxSize, got %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if c == nil {
				t.Error("expected cache instance, got nil")
			}

			// Check that zero maxSize uses default
			if tt.maxSize == 0 {
				cacheImpl := c.(*Cache[string])
				if cacheImpl.maxSize != defaultMaxSize {
					t.Errorf("expected maxSize to be %d, got %d", defaultMaxSize, cacheImpl.maxSize)
				}
			}
		})
	}
}

func TestCacheSetAndGet(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ttl := 1 * time.Hour

	err = c.Set(ctx, testKey, testValue, ttl)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}

	got, err := c.Get(ctx, testKey)
	if err != nil {
		t.Errorf("failed to get value: %v", err)
	}
	if got != testValue {
		t.Errorf("expected %s, got %s", testValue, got)
	}
}

func TestCacheSetInvalidTTL(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{
			name: "zero TTL",
			ttl:  0,
		},
		{
			name: "negative TTL",
			ttl:  -1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.Set(ctx, "key", "value", tt.ttl)
			if err == nil {
				t.Error("expected error but got none")
			}
			if !errors.Is(err, cache.ErrInvalidTTL) {
				t.Errorf("expected ErrInvalidTTL, got %v", err)
			}
		})
	}
}

func TestCacheGetNotFound(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Test getting a non-existent key
	_, err = c.Get(ctx, "non-existent-key")
	if err == nil {
		t.Error("expected error but got none")
	}
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCacheGetExpired(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ttl := 1 * time.Millisecond

	err = c.Set(ctx, testKey, testValue, ttl)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to get the expired value
	_, err = c.Get(ctx, testKey)
	if err == nil {
		t.Error("expected error but got none")
	}
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCacheDelete(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ttl := 1 * time.Hour

	err = c.Set(ctx, testKey, testValue, ttl)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}

	// Verify it exists
	got, err := c.Get(ctx, testKey)
	if err != nil {
		t.Errorf("failed to get value: %v", err)
	}
	if got != testValue {
		t.Errorf("expected %s, got %s", testValue, got)
	}

	// Delete the key
	err = c.Delete(ctx, testKey)
	if err != nil {
		t.Errorf("failed to delete key: %v", err)
	}

	// Verify it's gone
	_, err = c.Get(ctx, testKey)
	if err == nil {
		t.Error("expected error but got none")
	}
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCacheDeleteNonExistent(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Delete a non-existent key (should not error)
	err = c.Delete(ctx, "non-existent-key")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCacheCleanupExpiredItems(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](2) // Small max size to trigger cleanup
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Set expired items
	ttl := 1 * time.Millisecond
	err = c.Set(ctx, "expired1", "value1", ttl)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}
	err = c.Set(ctx, "expired2", "value2", ttl)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Set a new item that will trigger cleanup
	err = c.Set(ctx, "new", "value", 1*time.Hour)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}

	// Verify expired items are cleaned up
	cacheImpl := c.(*Cache[string])
	cacheImpl.mu.RLock()
	itemCount := len(cacheImpl.items)
	cacheImpl.mu.RUnlock()

	if itemCount > 1 {
		t.Errorf("expected cleanup to remove expired items, but cache has %d items", itemCount)
	}
}

func TestCacheCleanupSkipsWhenWithinLimit(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[string](10) // Large max size
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Set a few items with short TTL
	ttl := 1 * time.Millisecond
	for i := 0; i < 3; i++ {
		err = c.Set(ctx, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), ttl)
		if err != nil {
			t.Errorf("failed to set value: %v", err)
		}
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Set a new item - cleanup should not run since we're within the limit
	err = c.Set(ctx, "new", "value", 1*time.Hour)
	if err != nil {
		t.Errorf("failed to set value: %v", err)
	}

	// Verify expired items are still there (cleanup was skipped)
	cacheImpl := c.(*Cache[string])
	cacheImpl.mu.RLock()
	itemCount := len(cacheImpl.items)
	cacheImpl.mu.RUnlock()

	if itemCount != 4 { // 3 expired + 1 new
		t.Errorf("expected 4 items in cache, got %d", itemCount)
	}
}

func TestCacheItemIsExpired(t *testing.T) {
	// Test with zero expiration (never expires)
	item := &cacheItem[string]{
		value:      "test",
		expiration: time.Time{}, // Zero time
	}
	if item.isExpired() {
		t.Error("expected item with zero expiration to not be expired")
	}

	// Test with future expiration
	item.expiration = time.Now().Add(1 * time.Hour)
	if item.isExpired() {
		t.Error("expected item with future expiration to not be expired")
	}

	// Test with past expiration
	item.expiration = time.Now().Add(-1 * time.Hour)
	if !item.isExpired() {
		t.Error("expected item with past expiration to be expired")
	}
}

func TestCacheConcurrency(t *testing.T) {
	ctx := context.Background()
	c, err := NewCache[int](100)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Test concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				value := id*numOperations + j
				err := c.Set(ctx, key, value, 1*time.Hour)
				if err != nil {
					t.Errorf("failed to set value: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				expectedValue := id*numOperations + j
				value, err := c.Get(ctx, key)
				if err != nil {
					t.Errorf("failed to get value: %v", err)
				}
				if value != expectedValue {
					t.Errorf("expected %d, got %d", expectedValue, value)
				}
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent deletes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				err := c.Delete(ctx, key)
				if err != nil {
					t.Errorf("failed to delete key: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	// Verify all items are deleted
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < numOperations; j++ {
			key := fmt.Sprintf("key-%d-%d", i, j)
			_, err := c.Get(ctx, key)
			if !errors.Is(err, cache.ErrNotFound) {
				t.Errorf("expected ErrNotFound for key %s, got %v", key, err)
			}
		}
	}
}

func TestCacheWithDifferentTypes(t *testing.T) {
	ctx := context.Background()

	// Test with int
	intCache, err := NewCache[int](10)
	if err != nil {
		t.Fatalf("failed to create int cache: %v", err)
	}

	err = intCache.Set(ctx, "int-key", 42, 1*time.Hour)
	if err != nil {
		t.Errorf("failed to set int value: %v", err)
	}

	intVal, err := intCache.Get(ctx, "int-key")
	if err != nil {
		t.Errorf("failed to get int value: %v", err)
	}
	if intVal != 42 {
		t.Errorf("expected 42, got %d", intVal)
	}

	// Test with struct
	type TestStruct struct {
		Name string
		Age  int
	}

	structCache, err := NewCache[TestStruct](10)
	if err != nil {
		t.Fatalf("failed to create struct cache: %v", err)
	}

	testStruct := TestStruct{Name: "John", Age: 30}
	err = structCache.Set(ctx, "struct-key", testStruct, 1*time.Hour)
	if err != nil {
		t.Errorf("failed to set struct value: %v", err)
	}

	structVal, err := structCache.Get(ctx, "struct-key")
	if err != nil {
		t.Errorf("failed to get struct value: %v", err)
	}
	if structVal.Name != "John" || structVal.Age != 30 {
		t.Errorf("expected {Name: John, Age: 30}, got %+v", structVal)
	}
}
