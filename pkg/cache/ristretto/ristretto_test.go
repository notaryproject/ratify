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
	"encoding/json"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/dgraph-io/ristretto/z"
	"github.com/notaryproject/ratify/v2/pkg/cache"
)

// TestKeytoHash_Expected tests the keyToHash function
func TestKeytoHash_Expected(t *testing.T) {
	key := "test"
	hash1, hash2 := keyToHash(nil)
	if hash1 != 0 || hash2 != 0 {
		t.Errorf("Expected hash1 and hash2 to be 0, but got %d and %d", hash1, hash2)
	}
	hash1, hash2 = keyToHash([]byte(key))
	if hash1 != 0 || hash2 != 0 {
		t.Errorf("Expected hash1 and hash2 to be 0, but got %d and %d", hash1, hash2)
	}
	hash1, hash2 = keyToHash(key)
	actualHash1 := z.MemHashString(key)
	actualHash2 := xxhash.Sum64String(key)

	if hash1 != actualHash1 || hash2 != actualHash2 {
		t.Errorf("Expected hash1 and hash2 to be %d and %d, but got %d and %d", actualHash1, actualHash2, hash1, hash2)
	}
}

// TestSet_Expected tests the Set function
func TestSet_Expected(t *testing.T) {
	ctx := context.Background()
	var err error
	// first attempt to get the cache provider if it's already been initialized
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, RistrettoCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}
	ok := cacheProvider.Set(ctx, "test", "test")
	if !ok {
		t.Errorf("Expected ok to be true")
	}
	// wait for the cache to be set
	time.Sleep(1 * time.Second)
	ristrettoCache := cacheProvider.(*ristrettoCache)
	val, found := ristrettoCache.memoryCache.Get("test")
	if val == nil || !found {
		t.Errorf("Expected value to be set in memory cache")
	}
	var outputVal string
	err = json.Unmarshal([]byte(val.(string)), &outputVal)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	if outputVal != "test" {
		t.Errorf("Expected value to be test, but got %s", val.(string))
	}
}

// TestSetWithTTL_Expected tests the SetWithTTL function
func TestSetWithTTL_Expected(t *testing.T) {
	ctx := context.Background()
	var err error
	// first attempt to get the cache provider if it's already been initialized
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, RistrettoCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}
	ok := cacheProvider.SetWithTTL(ctx, "test_ttl", "test", 3*time.Second)
	if !ok {
		t.Errorf("Expected ok to be true")
	}
	// wait for the cache to be set
	time.Sleep(1 * time.Second)
	ristrettoCache := cacheProvider.(*ristrettoCache)
	val, found := ristrettoCache.memoryCache.Get("test_ttl")
	if val == nil || !found {
		t.Errorf("Expected value to be set in memory cache")
	}
	// wait for the cache entry to expire
	time.Sleep(3 * time.Second)
	val, found = ristrettoCache.memoryCache.Get("test_ttl")
	if val != nil || found {
		t.Errorf("Expected value to be deleted from memory cache")
	}
}

// TestSetWithTTL_InvalidTTL tests the SetWithTTL function with an invalid TTL
func TestSetWithTTL_InvalidTTL(t *testing.T) {
	ctx := context.Background()
	var err error
	// first attempt to get the cache provider if it's already been initialized
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, RistrettoCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}
	ok := cacheProvider.SetWithTTL(ctx, "test_ttl", "test", -10)
	if ok {
		t.Errorf("Expected ok to be false")
	}
}

// TestGet_Expected tests the Get function
func TestGet_Expected(t *testing.T) {
	ctx := context.Background()
	var err error
	// first attempt to get the cache provider if it's already been initialized
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, RistrettoCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}
	ristrettoCache := cacheProvider.(*ristrettoCache)
	success := ristrettoCache.memoryCache.Set("test-get", "test-get-val", 1)
	if !success {
		t.Errorf("Expected success to be true")
	}
	// wait for the cache to be set
	time.Sleep(1 * time.Second)
	val, ok := cacheProvider.Get(ctx, "test-get")
	if !ok {
		t.Errorf("Expected ok to be true")
	}
	if val != "test-get-val" {
		t.Errorf("Expected value to be test-get-val, but got %s", val)
	}
}

// TestDelete_Expected tests the Delete function
func TestDelete_Expected(t *testing.T) {
	ctx := context.Background()
	var err error
	// first attempt to get the cache provider if it's already been initialized
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, RistrettoCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}
	ristrettoCache := cacheProvider.(*ristrettoCache)
	success := ristrettoCache.memoryCache.Set("test-delete", "test-delete-val", 1)
	if !success {
		t.Errorf("Expected success to be true")
	}
	// wait for the cache to be set
	time.Sleep(1 * time.Second)
	cacheProvider.Delete(ctx, "test-delete")
	// wait for the cache entry to delete
	time.Sleep(1 * time.Second)
	val, found := ristrettoCache.memoryCache.Get("test-delete")
	if val != nil || found {
		t.Errorf("Expected value to be deleted from memory cache")
	}
}
