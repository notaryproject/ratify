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
	"errors"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/cache"
)

const (
	testKey   = "testKey"
	testValue = "testValue"
)

func TestNewRistrettoCache(t *testing.T) {
	tests := []struct {
		name        string
		ttl         time.Duration
		expectError bool
		errorType   error
	}{
		{
			name:        "negative TTL should return error",
			ttl:         -1 * time.Second,
			expectError: true,
			errorType:   cache.ErrInvalidTTL,
		},
		{
			name:        "zero TTL should be valid",
			ttl:         0,
			expectError: false,
		},
		{
			name:        "positive TTL should be valid",
			ttl:         1 * time.Second,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := NewCache[string](tt.ttl)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.errorType)
				}
				if !errors.Is(err, tt.errorType) {
					t.Errorf("expected error %v, got %v", tt.errorType, err)
				}
				if cache != nil {
					t.Errorf("expected nil cache when error occurs, got %v", cache)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if cache == nil {
					t.Errorf("expected non-nil cache, got nil")
				}
			}
		})
	}
}

func TestRistrettoCacheGet(t *testing.T) {
	cacheInstance, err := NewCache[string](1 * time.Second)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Test getting non-existent key
	val, err := cacheInstance.Get(ctx, "nonexistent")
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if val != "" { // For string type, zero value is empty string
		t.Errorf("expected empty string, got %v", val)
	}

	// Set a value and then get it
	err = cacheInstance.Set(ctx, testKey, testValue, 0)
	if err != nil {
		t.Fatalf("failed to set value: %v", err)
	}

	val, err = cacheInstance.Get(ctx, testKey)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if val != testValue {
		t.Errorf("expected %v, got %v", testValue, val)
	}
}

func TestRistrettoCacheSet(t *testing.T) {
	// Test with string type
	t.Run("string cache", func(t *testing.T) {
		cacheInstance, err := NewCache[string](1 * time.Second)
		if err != nil {
			t.Fatalf("failed to create cache: %v", err)
		}

		ctx := context.Background()

		err = cacheInstance.Set(ctx, "stringKey", "stringValue", 5*time.Second)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		val, err := cacheInstance.Get(ctx, "stringKey")
		if err != nil {
			t.Errorf("failed to get value after set: %v", err)
		}
		if val != "stringValue" {
			t.Errorf("expected %v, got %v", "stringValue", val)
		}
	})

	// Test with int type
	t.Run("int cache", func(t *testing.T) {
		cacheInstance, err := NewCache[int](1 * time.Second)
		if err != nil {
			t.Fatalf("failed to create cache: %v", err)
		}

		ctx := context.Background()

		err = cacheInstance.Set(ctx, "intKey", 42, 5*time.Second)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		val, err := cacheInstance.Get(ctx, "intKey")
		if err != nil {
			t.Errorf("failed to get value after set: %v", err)
		}
		if val != 42 {
			t.Errorf("expected %v, got %v", 42, val)
		}
	})

	// Test with struct type
	t.Run("struct cache", func(t *testing.T) {
		type TestStruct struct {
			Name string
		}
		cacheInstance, err := NewCache[TestStruct](1 * time.Second)
		if err != nil {
			t.Fatalf("failed to create cache: %v", err)
		}

		ctx := context.Background()
		testStruct := TestStruct{Name: "test"}

		err = cacheInstance.Set(ctx, "structKey", testStruct, 5*time.Second)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		val, err := cacheInstance.Get(ctx, "structKey")
		if err != nil {
			t.Errorf("failed to get value after set: %v", err)
		}
		if val != testStruct {
			t.Errorf("expected %v, got %v", testStruct, val)
		}
	})
}

func TestRistrettoCacheDelete(t *testing.T) {
	cacheInstance, err := NewCache[string](1 * time.Second)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Set a value
	err = cacheInstance.Set(ctx, testKey, testValue, 0)
	if err != nil {
		t.Fatalf("failed to set value: %v", err)
	}

	// Verify it exists
	val, err := cacheInstance.Get(ctx, testKey)
	if err != nil {
		t.Fatalf("failed to get value: %v", err)
	}
	if val != testValue {
		t.Fatalf("expected %v, got %v", testValue, val)
	}

	// Delete the key
	err = cacheInstance.Delete(ctx, testKey)
	if err != nil {
		t.Errorf("expected no error from delete, got %v", err)
	}

	// Verify it's gone
	val, err = cacheInstance.Get(ctx, testKey)
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
	if val != "" { // For string type, zero value is empty string
		t.Errorf("expected empty string after delete, got %v", val)
	}

	// Delete non-existent key should not error
	err = cacheInstance.Delete(ctx, "nonexistent")
	if err != nil {
		t.Errorf("expected no error when deleting non-existent key, got %v", err)
	}
}

func TestRistrettoCacheExpiration(t *testing.T) {
	cacheInstance, err := NewCache[string](100 * time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Set a value
	err = cacheInstance.Set(ctx, testKey, testValue, 0)
	if err != nil {
		t.Fatalf("failed to set value: %v", err)
	}

	// Verify it exists immediately
	val, err := cacheInstance.Get(ctx, testKey)
	if err != nil {
		t.Fatalf("failed to get value: %v", err)
	}
	if val != testValue {
		t.Fatalf("expected %v, got %v", testValue, val)
	}

	// Wait for expiration (TTL + buffer)
	time.Sleep(200 * time.Millisecond)

	// Verify it's expired
	val, err = cacheInstance.Get(ctx, testKey)
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound after expiration, got %v", err)
	}
	if val != "" { // For string type, zero value is empty string
		t.Errorf("expected empty string after expiration, got %v", val)
	}
}

func TestRistrettoCacheMultipleKeys(t *testing.T) {
	// Using any type to store different value types
	cacheInstance, err := NewCache[any](10 * time.Second)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Set multiple key-value pairs
	testData := map[string]any{
		"key1": "value1",
		"key2": 42,
		"key3": "simple_string",
	}

	for key, value := range testData {
		err := cacheInstance.Set(ctx, key, value, 0)
		if err != nil {
			t.Errorf("failed to set %s: %v", key, err)
		}
	}

	// Verify all values can be retrieved
	for key, expectedValue := range testData {
		val, err := cacheInstance.Get(ctx, key)
		if err != nil {
			t.Errorf("failed to get %s: %v", key, err)
		}
		if val != expectedValue {
			t.Errorf("for key %s, expected %v, got %v", key, expectedValue, val)
		}
	}

	// Delete one key
	err = cacheInstance.Delete(ctx, "key2")
	if err != nil {
		t.Errorf("failed to delete key2: %v", err)
	}

	// Verify deleted key is gone but others remain
	val, err := cacheInstance.Get(ctx, "key2")
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound for deleted key, got %v", err)
	}
	if val != nil { // For any type, zero value is nil
		t.Errorf("expected nil for deleted key, got %v", val)
	}

	for _, key := range []string{"key1", "key3"} {
		val, err := cacheInstance.Get(ctx, key)
		if err != nil {
			t.Errorf("failed to get remaining key %s: %v", key, err)
		}
		if val != testData[key] {
			t.Errorf("for key %s, expected %v, got %v", key, testData[key], val)
		}
	}
}
